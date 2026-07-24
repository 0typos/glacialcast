use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use glacialcast_dash::{
    DASH_FORMAT_VERSION, EpochKeys, MAX_CURSOR_PAYLOAD, MAX_MEDIA_PAYLOAD, authenticate_object,
    verify_object_authentication,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};
use std::io;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

pub mod daemon;

pub const PROTOCOL_VERSION: u16 = 4;
pub const MAX_FRAME_LEN: usize = 32 * 1024 * 1024;
pub const PORTABLE_DASH_MAGIC: &[u8; 4] = b"GCO1";
const MAX_PORTABLE_DASH_HEADER_LEN: usize = 64 * 1024;
const MAX_NOISE_PLAINTEXT_LEN: usize = 60 * 1024;
const NOISE_SEGMENT_MAGIC: &[u8; 4] = b"GCN1";
const NOISE_SEGMENT_HEADER_LEN: usize = 12;
pub const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";
pub const NOISE_KEY_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("message exceeds max frame length: {0}")]
    FrameTooLarge(usize),
    #[error("malformed frame")]
    MalformedFrame,
    #[error("noise error: {0}")]
    Noise(String),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("serialization error: {0}")]
    Postcard(#[from] postcard::Error),
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("crypto error")]
    Crypto,
    #[error("viewer key must decode to 32 bytes, got {0}")]
    InvalidKeyLength(usize),
    #[error("Noise key must contain 32 bytes, got {0}")]
    InvalidNoiseKeyLength(usize),
    #[error("unsupported DASH object format version {0}")]
    UnsupportedDashVersion(u16),
    #[error("DASH object payload length does not match its header")]
    DashPayloadLength,
    #[error("DASH object payload exceeds its size limit")]
    DashPayloadTooLarge,
    #[error("DASH object payload hash does not match its header")]
    DashPayloadHash,
    #[error("DASH object has invalid metadata: {0}")]
    InvalidDashMetadata(&'static str),
    #[error("DASH object authentication failed")]
    DashAuthentication,
    #[error("portable DASH object is malformed")]
    InvalidPortableDashObject,
}

pub type Result<T> = std::result::Result<T, ProtocolError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamHello {
    pub protocol_version: u16,
    pub client_id: String,
    pub auth_token: Option<String>,
    pub display_name: String,
    pub source: CaptureSource,
    pub media_kind: StreamMediaKind,
    pub frame_encrypted: bool,
    pub resend_low: Option<u64>,
    pub resend_high: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum StreamMediaKind {
    Image,
    Video,
    Dash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureSource {
    pub backend: String,
    pub description: String,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientMessage {
    Hello(StreamHello),
    Frame(FrameMessage),
    VideoChunk(VideoChunkMessage),
    DashObject(DashObject),
    Cursor(CursorMessage),
    BufferStatus(BufferStatus),
    Ping { now_ms: i64 },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DashObjectKind {
    Epoch,
    Initialization,
    Media,
    Cursor,
    Index,
    End,
}

impl DashObjectKind {
    pub fn code(self) -> u8 {
        match self {
            Self::Epoch => 0,
            Self::Initialization => 1,
            Self::Media => 2,
            Self::Cursor => 3,
            Self::Index => 4,
            Self::End => 5,
        }
    }

    pub fn max_payload_len(self) -> usize {
        match self {
            Self::Media => MAX_MEDIA_PAYLOAD,
            Self::Cursor => MAX_CURSOR_PAYLOAD,
            Self::Initialization => 4 * 1024 * 1024,
            Self::Epoch | Self::Index => 1024 * 1024,
            Self::End => 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DashObjectHeader {
    pub format_version: u16,
    pub stream_id: Uuid,
    pub epoch_id: Uuid,
    pub kind: DashObjectKind,
    pub sequence: u64,
    pub segment_number: u64,
    pub chunk_index: u16,
    pub timestamp: u64,
    pub duration: u64,
    pub random_access: bool,
    pub mime: String,
    pub payload_len: u32,
    pub payload_sha256: [u8; 32],
    pub authentication_tag: [u8; 32],
}

impl DashObjectHeader {
    pub fn authentication_bytes(&self) -> Result<Vec<u8>> {
        if self.mime.len() > u16::MAX as usize {
            return Err(ProtocolError::InvalidDashMetadata("MIME type is too long"));
        }
        let mut bytes = Vec::with_capacity(160 + self.mime.len());
        bytes.extend_from_slice(b"glacial-dash-object-v1");
        bytes.extend_from_slice(&self.format_version.to_be_bytes());
        bytes.extend_from_slice(self.stream_id.as_bytes());
        bytes.extend_from_slice(self.epoch_id.as_bytes());
        bytes.push(self.kind.code());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.segment_number.to_be_bytes());
        bytes.extend_from_slice(&self.chunk_index.to_be_bytes());
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.extend_from_slice(&self.duration.to_be_bytes());
        bytes.push(u8::from(self.random_access));
        bytes.extend_from_slice(&(self.mime.len() as u16).to_be_bytes());
        bytes.extend_from_slice(self.mime.as_bytes());
        bytes.extend_from_slice(&self.payload_len.to_be_bytes());
        bytes.extend_from_slice(&self.payload_sha256);
        Ok(bytes)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DashObject {
    pub header: DashObjectHeader,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct NewDashObject<'a> {
    pub stream_id: Uuid,
    pub epoch_id: Uuid,
    pub kind: DashObjectKind,
    pub sequence: u64,
    pub segment_number: u64,
    pub chunk_index: u16,
    pub timestamp: u64,
    pub duration: u64,
    pub random_access: bool,
    pub mime: &'a str,
    pub payload: Vec<u8>,
}

impl DashObject {
    pub fn authenticated(input: NewDashObject<'_>, keys: &EpochKeys) -> Result<Self> {
        let payload_len =
            u32::try_from(input.payload.len()).map_err(|_| ProtocolError::DashPayloadTooLarge)?;
        let payload_sha256: [u8; 32] = Sha256::digest(&input.payload).into();
        let mut header = DashObjectHeader {
            format_version: DASH_FORMAT_VERSION,
            stream_id: input.stream_id,
            epoch_id: input.epoch_id,
            kind: input.kind,
            sequence: input.sequence,
            segment_number: input.segment_number,
            chunk_index: input.chunk_index,
            timestamp: input.timestamp,
            duration: input.duration,
            random_access: input.random_access,
            mime: input.mime.to_string(),
            payload_len,
            payload_sha256,
            authentication_tag: [0; 32],
        };
        let authentication_bytes = header.authentication_bytes()?;
        header.authentication_tag = authenticate_object(
            &keys.authentication_key,
            &authentication_bytes,
            &input.payload,
        );
        let object = Self {
            header,
            payload: input.payload,
        };
        object.validate()?;
        Ok(object)
    }

    pub fn validate(&self) -> Result<()> {
        if self.header.format_version != DASH_FORMAT_VERSION {
            return Err(ProtocolError::UnsupportedDashVersion(
                self.header.format_version,
            ));
        }
        if self.header.stream_id.is_nil() {
            return Err(ProtocolError::InvalidDashMetadata(
                "stream ID must not be nil",
            ));
        }
        if self.header.epoch_id.is_nil() {
            return Err(ProtocolError::InvalidDashMetadata(
                "epoch ID must not be nil",
            ));
        }
        if self.header.mime.len() > 127 || !self.header.mime.is_ascii() {
            return Err(ProtocolError::InvalidDashMetadata(
                "MIME type must be short ASCII",
            ));
        }
        if self.payload.len() != self.header.payload_len as usize {
            return Err(ProtocolError::DashPayloadLength);
        }
        if self.payload.len() > self.header.kind.max_payload_len() {
            return Err(ProtocolError::DashPayloadTooLarge);
        }
        let actual_hash: [u8; 32] = Sha256::digest(&self.payload).into();
        if actual_hash != self.header.payload_sha256 {
            return Err(ProtocolError::DashPayloadHash);
        }
        match self.header.kind {
            DashObjectKind::Initialization
                if self.header.segment_number != 0
                    || self.header.chunk_index != 0
                    || self.header.duration != 0 =>
            {
                return Err(ProtocolError::InvalidDashMetadata(
                    "initialization object has media timing",
                ));
            }
            DashObjectKind::Media if self.header.duration == 0 => {
                return Err(ProtocolError::InvalidDashMetadata(
                    "media object duration must not be zero",
                ));
            }
            DashObjectKind::End if !self.payload.is_empty() => {
                return Err(ProtocolError::InvalidDashMetadata(
                    "end object must not contain a payload",
                ));
            }
            _ => {}
        }
        Ok(())
    }

    pub fn verify_authentication(&self, keys: &EpochKeys) -> Result<()> {
        self.validate()?;
        let authentication_bytes = self.header.authentication_bytes()?;
        if !verify_object_authentication(
            &keys.authentication_key,
            &authentication_bytes,
            &self.payload,
            &self.header.authentication_tag,
        ) {
            return Err(ProtocolError::DashAuthentication);
        }
        Ok(())
    }

    pub fn to_portable_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let header = serde_json::to_vec(&self.header)
            .map_err(|_| ProtocolError::InvalidPortableDashObject)?;
        if header.len() > MAX_PORTABLE_DASH_HEADER_LEN {
            return Err(ProtocolError::InvalidPortableDashObject);
        }
        let header_len =
            u32::try_from(header.len()).map_err(|_| ProtocolError::InvalidPortableDashObject)?;
        let mut bytes = Vec::with_capacity(8 + header.len() + self.payload.len());
        bytes.extend_from_slice(PORTABLE_DASH_MAGIC);
        bytes.extend_from_slice(&header_len.to_be_bytes());
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    pub fn from_portable_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 || &bytes[..4] != PORTABLE_DASH_MAGIC {
            return Err(ProtocolError::InvalidPortableDashObject);
        }
        let header_len = u32::from_be_bytes(
            bytes[4..8]
                .try_into()
                .map_err(|_| ProtocolError::InvalidPortableDashObject)?,
        ) as usize;
        if header_len == 0 || header_len > MAX_PORTABLE_DASH_HEADER_LEN {
            return Err(ProtocolError::InvalidPortableDashObject);
        }
        let payload_offset = 8usize
            .checked_add(header_len)
            .ok_or(ProtocolError::InvalidPortableDashObject)?;
        let header_bytes = bytes
            .get(8..payload_offset)
            .ok_or(ProtocolError::InvalidPortableDashObject)?;
        let payload = bytes
            .get(payload_offset..)
            .ok_or(ProtocolError::InvalidPortableDashObject)?
            .to_vec();
        let header: DashObjectHeader = serde_json::from_slice(header_bytes)
            .map_err(|_| ProtocolError::InvalidPortableDashObject)?;
        let object = Self { header, payload };
        object.validate()?;
        Ok(object)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerMessage {
    HelloAck {
        accepted: bool,
        reason: Option<String>,
        stream_id: Option<Uuid>,
        last_frame_seq: u64,
        server_time_ms: i64,
    },
    Ack {
        through_seq: u64,
    },
    ResendRequest {
        from_seq: u64,
        to_seq: u64,
    },
    Backpressure {
        pause_ms: u64,
        reason: String,
    },
    KeyframeRequest {
        stream_id: Uuid,
        reason: String,
    },
    Pong {
        now_ms: i64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameMessage {
    pub stream_id: Uuid,
    pub seq: u64,
    pub captured_at_ms: i64,
    pub width: u32,
    pub height: u32,
    pub mime: String,
    pub key_id: String,
    pub nonce: [u8; 12],
    pub content_hash: u32,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum VideoCodec {
    H264,
    Vp8,
    Av1,
}

impl VideoCodec {
    pub fn webrtc_mime(self) -> &'static str {
        match self {
            Self::H264 => "video/H264",
            Self::Vp8 => "video/VP8",
            Self::Av1 => "video/AV1",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum VideoPacketization {
    AnnexB,
    RtpPayload,
}

#[derive(Debug, Clone, Default)]
pub struct H264ParameterSetCache {
    sps: Option<Vec<u8>>,
    pps: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H264AccessUnitInfo {
    pub nal_types: Vec<u8>,
    pub has_sps: bool,
    pub has_pps: bool,
    pub has_idr: bool,
}

impl H264AccessUnitInfo {
    pub fn is_decodable_random_access_point(&self) -> bool {
        self.has_sps && self.has_pps && self.has_idr
    }
}

impl H264ParameterSetCache {
    pub fn normalize_access_unit(&mut self, payload: Vec<u8>, _keyframe_hint: bool) -> Vec<u8> {
        let starts = h264_start_codes(&payload);
        if starts.is_empty() {
            return payload;
        }

        let mut has_sps = false;
        let mut has_pps = false;
        let mut has_idr = false;
        let mut first_vcl_start = None;

        for (index, start) in starts.iter().copied().enumerate() {
            let Some(nal_type) = h264_nal_type_at(&payload, start) else {
                continue;
            };
            if first_vcl_start.is_none() && h264_is_vcl(nal_type) {
                first_vcl_start = Some(start);
            }

            let next_start = starts.get(index + 1).copied().unwrap_or(payload.len());
            match nal_type {
                7 => {
                    self.sps = Some(payload[start..next_start].to_vec());
                    has_sps = true;
                }
                8 => {
                    self.pps = Some(payload[start..next_start].to_vec());
                    has_pps = true;
                }
                5 => has_idr = true,
                _ => {}
            }
        }

        if !has_idr || (has_sps && has_pps) {
            return payload;
        }

        let (Some(sps), Some(pps)) = (&self.sps, &self.pps) else {
            return payload;
        };

        let insert_at = first_vcl_start.unwrap_or(0);
        let mut normalized = Vec::with_capacity(payload.len() + sps.len() + pps.len());
        normalized.extend_from_slice(&payload[..insert_at]);
        if !has_sps {
            normalized.extend_from_slice(sps);
        }
        if !has_pps {
            normalized.extend_from_slice(pps);
        }
        normalized.extend_from_slice(&payload[insert_at..]);
        normalized
    }
}

pub fn inspect_h264_access_unit(access_unit: &[u8]) -> H264AccessUnitInfo {
    let nal_types = h264_access_unit_nal_types(access_unit);
    H264AccessUnitInfo {
        has_sps: nal_types.contains(&7),
        has_pps: nal_types.contains(&8),
        has_idr: nal_types.contains(&5),
        nal_types,
    }
}

pub fn h264_access_unit_has_idr(access_unit: &[u8]) -> bool {
    inspect_h264_access_unit(access_unit).has_idr
}

pub fn h264_access_unit_has_parameter_sets(access_unit: &[u8]) -> bool {
    let info = inspect_h264_access_unit(access_unit);
    info.has_sps && info.has_pps
}

pub fn h264_access_unit_nal_types(access_unit: &[u8]) -> Vec<u8> {
    h264_start_codes(access_unit)
        .into_iter()
        .filter_map(|start| h264_nal_type_at(access_unit, start))
        .collect()
}

fn h264_is_vcl(nal_type: u8) -> bool {
    matches!(nal_type, 1..=5)
}

fn h264_start_codes(bytes: &[u8]) -> Vec<usize> {
    let mut starts = Vec::new();
    let mut i = 0usize;
    while i + 3 < bytes.len() {
        if bytes[i] == 0 && bytes[i + 1] == 0 && bytes[i + 2] == 1 {
            starts.push(i);
            i += 3;
        } else if i + 4 < bytes.len()
            && bytes[i] == 0
            && bytes[i + 1] == 0
            && bytes[i + 2] == 0
            && bytes[i + 3] == 1
        {
            starts.push(i);
            i += 4;
        } else {
            i += 1;
        }
    }
    starts
}

fn h264_nal_type_at(bytes: &[u8], start: usize) -> Option<u8> {
    let offset = if bytes.get(start..start + 4) == Some(&[0, 0, 0, 1]) {
        start + 4
    } else if bytes.get(start..start + 3) == Some(&[0, 0, 1]) {
        start + 3
    } else {
        return None;
    };
    bytes.get(offset).map(|byte| byte & 0x1f)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoChunkMessage {
    pub stream_id: Uuid,
    pub seq: u64,
    pub captured_at_ms: i64,
    pub pts_ms: i64,
    pub duration_ms: u64,
    pub width: u32,
    pub height: u32,
    pub source_width: u32,
    pub source_height: u32,
    pub codec: VideoCodec,
    pub packetization: VideoPacketization,
    pub keyframe: bool,
    pub mime: String,
    pub key_id: String,
    pub nonce: [u8; 12],
    pub content_hash: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorBitmap {
    pub width: u32,
    pub height: u32,
    pub hotspot_x: i32,
    pub hotspot_y: i32,
    pub png_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CursorMessage {
    pub stream_id: Uuid,
    pub seq: u64,
    pub captured_at_ms: i64,
    pub x: f32,
    pub y: f32,
    pub source_width: u32,
    pub source_height: u32,
    pub bitmap: Option<CursorBitmap>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferStatus {
    pub stream_id: Uuid,
    pub lowest_seq: Option<u64>,
    pub highest_seq: Option<u64>,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlEvent {
    pub event: String,
    pub stream_id: Uuid,
    pub seq: Option<u64>,
    pub captured_at_ms: Option<i64>,
    pub frame: Option<FrameManifest>,
    pub video: Option<VideoChunkManifest>,
    pub cursor: Option<CursorMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicStream {
    pub stream_id: Uuid,
    pub display_name: String,
    pub source: CaptureSource,
    pub media_kind: StreamMediaKind,
    pub frame_encrypted: bool,
    pub active: bool,
    pub last_seen_at_ms: Option<i64>,
    pub last_frame_seq: Option<u64>,
    pub last_frame_at_ms: Option<i64>,
    pub retained_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameManifest {
    pub stream_id: Uuid,
    pub seq: u64,
    pub captured_at_ms: i64,
    pub width: u32,
    pub height: u32,
    pub mime: String,
    pub key_id: String,
    pub nonce: [u8; 12],
    pub content_hash: u32,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoChunkManifest {
    pub stream_id: Uuid,
    pub seq: u64,
    pub captured_at_ms: i64,
    pub pts_ms: i64,
    pub duration_ms: u64,
    pub width: u32,
    pub height: u32,
    pub source_width: u32,
    pub source_height: u32,
    pub codec: VideoCodec,
    pub packetization: VideoPacketization,
    pub keyframe: bool,
    pub mime: String,
    pub key_id: String,
    pub nonce: [u8; 12],
    pub content_hash: u32,
    pub size_bytes: u64,
}

pub struct ProtectedFrame {
    pub nonce: [u8; 12],
    pub content_hash: u32,
    pub payload: Vec<u8>,
    pub key_id: String,
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub fn random_viewer_key_b64() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode_key_b64(key: &str) -> Result<[u8; 32]> {
    let decoded = URL_SAFE_NO_PAD.decode(key)?;
    if decoded.len() != 32 {
        return Err(ProtocolError::InvalidKeyLength(decoded.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

pub fn encrypt_frame(
    viewer_key: &[u8; 32],
    key_id: impl Into<String>,
    plaintext: &[u8],
) -> Result<ProtectedFrame> {
    let cipher = Aes256Gcm::new(viewer_key.into());
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let payload = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| ProtocolError::Crypto)?;
    Ok(ProtectedFrame {
        nonce,
        content_hash: fast_content_hash(plaintext),
        payload,
        key_id: key_id.into(),
    })
}

pub fn clear_frame(plaintext: &[u8]) -> ProtectedFrame {
    ProtectedFrame {
        nonce: [0; 12],
        content_hash: fast_content_hash(plaintext),
        payload: plaintext.to_vec(),
        key_id: String::new(),
    }
}

pub fn protect_frame(viewer_key: Option<&[u8; 32]>, plaintext: &[u8]) -> Result<ProtectedFrame> {
    match viewer_key {
        Some(key) => encrypt_frame(key, "v1", plaintext),
        None => Ok(clear_frame(plaintext)),
    }
}

pub fn frame_is_encrypted(key_id: &str) -> bool {
    !key_id.is_empty()
}

pub fn decrypt_frame(
    viewer_key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(viewer_key.into());
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| ProtocolError::Crypto)
}

pub fn fast_content_hash(data: &[u8]) -> u32 {
    const FNV_OFFSET: u32 = 0x811c_9dc5;
    const FNV_PRIME: u32 = 0x0100_0193;

    let mut hash = FNV_OFFSET;
    for byte in data {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

pub fn parse_human_bytes(value: &str) -> std::result::Result<u64, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("byte size must not be empty".to_string());
    }
    let split = value
        .find(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .unwrap_or(value.len());
    let (number, unit) = value.split_at(split);
    let number = number
        .parse::<f64>()
        .map_err(|_| format!("invalid byte size number {number:?}"))?;
    if !number.is_finite() || number < 0.0 {
        return Err("byte size must be a non-negative finite number".to_string());
    }
    let multiplier = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1.0,
        "k" | "kb" => 1_000.0,
        "m" | "mb" => 1_000_000.0,
        "g" | "gb" => 1_000_000_000.0,
        "t" | "tb" => 1_000_000_000_000.0,
        "ki" | "kib" => 1024.0,
        "mi" | "mib" => 1024.0 * 1024.0,
        "gi" | "gib" => 1024.0 * 1024.0 * 1024.0,
        "ti" | "tib" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        other => return Err(format!("unsupported byte size unit {other:?}")),
    };
    let bytes = number * multiplier;
    if bytes > u64::MAX as f64 {
        return Err("byte size is too large".to_string());
    }
    Ok(bytes.round() as u64)
}

pub async fn write_clear_frame<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    if data.len() > MAX_FRAME_LEN {
        return Err(ProtocolError::FrameTooLarge(data.len()));
    }
    writer.write_u32(data.len() as u32).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_clear_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let len = reader.read_u32().await? as usize;
    if len > MAX_FRAME_LEN {
        return Err(ProtocolError::FrameTooLarge(len));
    }
    let mut data = vec![0u8; len];
    reader.read_exact(&mut data).await?;
    Ok(data)
}

pub fn noise_params() -> Result<NoiseParams> {
    NOISE_PATTERN
        .parse()
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoiseKeypair {
    pub private: [u8; NOISE_KEY_LEN],
    pub public: [u8; NOISE_KEY_LEN],
}

impl NoiseKeypair {
    pub fn validate(&self) -> Result<()> {
        let mut initiator = build_noise_initiator(&self.public)?;
        let mut responder = build_noise_responder(&self.private)?;
        let mut message = [0u8; 128];
        let mut payload = [0u8; 128];
        let len = initiator
            .write_message(&[], &mut message)
            .map_err(|err| ProtocolError::Noise(format!("{err:?}")))?;
        responder
            .read_message(&message[..len], &mut payload)
            .map_err(|err| ProtocolError::Noise(format!("{err:?}")))?;
        let len = responder
            .write_message(&[], &mut message)
            .map_err(|err| ProtocolError::Noise(format!("{err:?}")))?;
        initiator
            .read_message(&message[..len], &mut payload)
            .map_err(|err| ProtocolError::Noise(format!("{err:?}")))?;
        Ok(())
    }
}

pub fn generate_noise_keypair() -> Result<NoiseKeypair> {
    let keypair = Builder::new(noise_params()?)
        .generate_keypair()
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))?;
    let keypair = NoiseKeypair {
        private: keypair
            .private
            .try_into()
            .map_err(|key: Vec<u8>| ProtocolError::InvalidNoiseKeyLength(key.len()))?,
        public: keypair
            .public
            .try_into()
            .map_err(|key: Vec<u8>| ProtocolError::InvalidNoiseKeyLength(key.len()))?,
    };
    keypair.validate()?;
    Ok(keypair)
}

pub fn encode_noise_public_key(key: &[u8; NOISE_KEY_LEN]) -> String {
    URL_SAFE_NO_PAD.encode(key)
}

pub fn decode_noise_public_key(encoded: &str) -> Result<[u8; NOISE_KEY_LEN]> {
    let key = URL_SAFE_NO_PAD.decode(encoded.trim())?;
    let length = key.len();
    key.try_into()
        .map_err(|_| ProtocolError::InvalidNoiseKeyLength(length))
}

pub fn build_noise_initiator(remote_public_key: &[u8; NOISE_KEY_LEN]) -> Result<HandshakeState> {
    Builder::new(noise_params()?)
        .remote_public_key(remote_public_key)
        .build_initiator()
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))
}

pub fn build_noise_responder(local_private_key: &[u8; NOISE_KEY_LEN]) -> Result<HandshakeState> {
    Builder::new(noise_params()?)
        .local_private_key(local_private_key)
        .build_responder()
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))
}

pub async fn initiator_handshake<S>(
    stream: &mut S,
    remote_public_key: &[u8; NOISE_KEY_LEN],
) -> Result<TransportState>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut noise = build_noise_initiator(remote_public_key)?;
    let mut buf = vec![0u8; 65535];
    let len = noise
        .write_message(&[], &mut buf)
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))?;
    write_clear_frame(stream, &buf[..len]).await?;

    let msg = read_clear_frame(stream).await?;
    noise
        .read_message(&msg, &mut buf)
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))?;
    noise
        .into_transport_mode()
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))
}

pub async fn responder_handshake<S>(
    stream: &mut S,
    local_private_key: &[u8; NOISE_KEY_LEN],
) -> Result<TransportState>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut noise = build_noise_responder(local_private_key)?;
    let mut buf = vec![0u8; 65535];
    let msg = read_clear_frame(stream).await?;
    noise
        .read_message(&msg, &mut buf)
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))?;
    let len = noise
        .write_message(&[], &mut buf)
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))?;
    write_clear_frame(stream, &buf[..len]).await?;
    noise
        .into_transport_mode()
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))
}

pub struct NoiseSocket<S> {
    stream: S,
    transport: TransportState,
}

impl<S> NoiseSocket<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: S, transport: TransportState) -> Self {
        Self { stream, transport }
    }

    pub async fn write<T: Serialize>(&mut self, message: &T) -> Result<()> {
        let plain = postcard::to_stdvec(message)?;
        if plain.len() > MAX_FRAME_LEN {
            return Err(ProtocolError::FrameTooLarge(plain.len()));
        }

        let chunk_len = MAX_NOISE_PLAINTEXT_LEN - NOISE_SEGMENT_HEADER_LEN;
        let mut offset = 0usize;
        loop {
            let end = offset.saturating_add(chunk_len).min(plain.len());
            let segment = noise_segment(plain.len(), offset, &plain[offset..end])?;
            let mut encrypted = vec![0u8; segment.len() + 16];
            let len = self
                .transport
                .write_message(&segment, &mut encrypted)
                .map_err(|err| ProtocolError::Noise(format!("{err:?}")))?;
            write_clear_frame(&mut self.stream, &encrypted[..len]).await?;
            if end == plain.len() {
                return Ok(());
            }
            offset = end;
        }
    }

    pub async fn read<T: for<'de> Deserialize<'de>>(&mut self) -> Result<T> {
        let mut expected_total = None;
        let mut plain_message = Vec::new();
        loop {
            let encrypted = read_clear_frame(&mut self.stream).await?;
            let mut segment = vec![0u8; encrypted.len()];
            let len = self
                .transport
                .read_message(&encrypted, &mut segment)
                .map_err(|err| ProtocolError::Noise(format!("{err:?}")))?;
            let (total_len, offset, chunk) = parse_noise_segment(&segment[..len])?;
            if total_len > MAX_FRAME_LEN {
                return Err(ProtocolError::FrameTooLarge(total_len));
            }
            match expected_total {
                Some(expected) if expected != total_len => {
                    return Err(ProtocolError::MalformedFrame);
                }
                None => {
                    expected_total = Some(total_len);
                    plain_message.reserve(total_len);
                }
                _ => {}
            }
            if offset != plain_message.len() || offset.saturating_add(chunk.len()) > total_len {
                return Err(ProtocolError::MalformedFrame);
            }
            if chunk.is_empty() && plain_message.len() < total_len {
                return Err(ProtocolError::MalformedFrame);
            }
            plain_message.extend_from_slice(chunk);
            if plain_message.len() == total_len {
                let (message, remainder) = postcard::take_from_bytes(&plain_message)?;
                if !remainder.is_empty() {
                    return Err(ProtocolError::MalformedFrame);
                }
                return Ok(message);
            }
        }
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

fn noise_segment(total_len: usize, offset: usize, chunk: &[u8]) -> Result<Vec<u8>> {
    if total_len > u32::MAX as usize
        || offset > u32::MAX as usize
        || offset.saturating_add(chunk.len()) > total_len
    {
        return Err(ProtocolError::MalformedFrame);
    }
    let mut segment = Vec::with_capacity(NOISE_SEGMENT_HEADER_LEN + chunk.len());
    segment.extend_from_slice(NOISE_SEGMENT_MAGIC);
    segment.extend_from_slice(&(total_len as u32).to_be_bytes());
    segment.extend_from_slice(&(offset as u32).to_be_bytes());
    segment.extend_from_slice(chunk);
    Ok(segment)
}

fn parse_noise_segment(segment: &[u8]) -> Result<(usize, usize, &[u8])> {
    if segment.len() < NOISE_SEGMENT_HEADER_LEN || &segment[..4] != NOISE_SEGMENT_MAGIC {
        return Err(ProtocolError::MalformedFrame);
    }
    let total_len = u32::from_be_bytes(
        segment[4..8]
            .try_into()
            .map_err(|_| ProtocolError::MalformedFrame)?,
    ) as usize;
    let offset = u32::from_be_bytes(
        segment[8..12]
            .try_into()
            .map_err(|_| ProtocolError::MalformedFrame)?,
    ) as usize;
    Ok((total_len, offset, &segment[NOISE_SEGMENT_HEADER_LEN..]))
}

pub fn encode_ws_event(event: &ControlEvent) -> String {
    serde_json::to_string(event).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_encryption_round_trips_with_aes_gcm() {
        let key = decode_key_b64(&random_viewer_key_b64()).unwrap();
        let plaintext = b"compressed screenshot bytes";
        let encrypted = encrypt_frame(&key, "v1", plaintext).unwrap();

        assert_eq!(encrypted.key_id, "v1");
        assert_ne!(encrypted.payload, plaintext);
        assert_eq!(
            decrypt_frame(&key, &encrypted.nonce, &encrypted.payload).unwrap(),
            plaintext
        );
        assert_eq!(encrypted.content_hash, fast_content_hash(plaintext));
    }

    #[test]
    fn clear_frame_leaves_payload_unencrypted() {
        let plaintext = b"jpeg bytes";
        let clear = clear_frame(plaintext);

        assert_eq!(clear.key_id, "");
        assert_eq!(clear.nonce, [0; 12]);
        assert_eq!(clear.payload, plaintext);
        assert_eq!(clear.content_hash, fast_content_hash(plaintext));
        assert!(!frame_is_encrypted(&clear.key_id));
    }

    #[test]
    fn human_byte_sizes_parse_common_units() {
        assert_eq!(parse_human_bytes("50MB").unwrap(), 50_000_000);
        assert_eq!(parse_human_bytes("50MiB").unwrap(), 50 * 1024 * 1024);
        assert_eq!(parse_human_bytes("1.5KB").unwrap(), 1500);
    }

    #[test]
    fn viewer_key_decode_rejects_wrong_length() {
        let short = URL_SAFE_NO_PAD.encode([7u8; 31]);
        assert!(matches!(
            decode_key_b64(&short),
            Err(ProtocolError::InvalidKeyLength(31))
        ));
    }

    #[test]
    fn noise_server_public_key_round_trips_and_pins_the_private_key() {
        let keypair = generate_noise_keypair().unwrap();
        let encoded = encode_noise_public_key(&keypair.public);
        assert_eq!(decode_noise_public_key(&encoded).unwrap(), keypair.public);

        let other = generate_noise_keypair().unwrap();
        assert!(
            NoiseKeypair {
                private: keypair.private,
                public: other.public,
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn h264_parameter_set_cache_prepends_missing_keyframe_headers() {
        let mut cache = H264ParameterSetCache::default();
        let first_keyframe = vec![
            0, 0, 0, 1, 9, 0x10, // AUD
            0, 0, 1, 7, 1, 2, 3, // SPS
            0, 0, 1, 8, 4, 5, // PPS
            0, 0, 1, 5, 6, 7, 8, // IDR
        ];
        let normalized = cache.normalize_access_unit(first_keyframe.clone(), true);
        assert_eq!(normalized, first_keyframe);

        let late_keyframe = vec![
            0, 0, 0, 1, 9, 0x10, // AUD
            0, 0, 1, 5, 9, 10, 11, // IDR
        ];
        let normalized = cache.normalize_access_unit(late_keyframe, true);

        assert!(h264_access_unit_has_idr(&normalized));
        assert!(h264_access_unit_has_parameter_sets(&normalized));
        assert_eq!(h264_access_unit_nal_types(&normalized), vec![9, 7, 8, 5]);
        assert!(normalized.starts_with(&[0, 0, 0, 1, 9, 0x10]));
        assert_eq!(
            normalized,
            vec![
                0, 0, 0, 1, 9, 0x10, // AUD
                0, 0, 1, 7, 1, 2, 3, // cached SPS
                0, 0, 1, 8, 4, 5, // cached PPS
                0, 0, 1, 5, 9, 10, 11, // IDR
            ]
        );
    }

    #[test]
    fn h264_parameter_set_cache_leaves_non_keyframes_unchanged() {
        let mut cache = H264ParameterSetCache::default();
        let non_keyframe = vec![0, 0, 1, 1, 1, 2, 3];

        assert_eq!(
            cache.normalize_access_unit(non_keyframe.clone(), false),
            non_keyframe
        );
    }

    #[test]
    fn h264_inspection_rejects_aud_and_non_idr_as_random_access() {
        let retained_wayland_shape = vec![
            0, 0, 0, 1, 9, 0x10, // AUD
            0, 0, 1, 1, 0x88, 0x84, // non-IDR slice
        ];

        let info = inspect_h264_access_unit(&retained_wayland_shape);
        assert_eq!(info.nal_types, vec![9, 1]);
        assert!(!info.has_sps);
        assert!(!info.has_pps);
        assert!(!info.has_idr);
        assert!(!info.is_decodable_random_access_point());
    }

    #[test]
    fn h264_normalization_uses_nal_contents_instead_of_keyframe_hint() {
        let mut cache = H264ParameterSetCache::default();
        let headers = vec![
            0, 0, 1, 7, 1, 2, 3, // SPS
            0, 0, 1, 8, 4, 5, // PPS
            0, 0, 1, 5, 6, 7, // IDR
        ];
        cache.normalize_access_unit(headers, false);

        let hinted_non_idr = vec![0, 0, 1, 1, 9, 10];
        assert_eq!(
            cache.normalize_access_unit(hinted_non_idr.clone(), true),
            hinted_non_idr
        );

        let unhinted_idr = vec![0, 0, 1, 5, 11, 12];
        let normalized = cache.normalize_access_unit(unhinted_idr, false);
        assert!(inspect_h264_access_unit(&normalized).is_decodable_random_access_point());
    }

    #[test]
    fn dash_object_authenticates_header_and_opaque_payload() {
        let stream_id = Uuid::from_u128(1);
        let epoch_id = Uuid::from_u128(2);
        let keys = EpochKeys::derive(&[7u8; 32], stream_id, epoch_id).unwrap();
        let object = DashObject::authenticated(
            NewDashObject {
                stream_id,
                epoch_id,
                kind: DashObjectKind::Media,
                sequence: 9,
                segment_number: 3,
                chunk_index: 1,
                timestamp: 270_000,
                duration: 90_000,
                random_access: false,
                mime: "video/iso.segment",
                payload: vec![1, 2, 3, 4],
            },
            &keys,
        )
        .unwrap();

        object.validate().unwrap();
        object.verify_authentication(&keys).unwrap();
        let portable = object.to_portable_bytes().unwrap();
        assert!(portable.starts_with(PORTABLE_DASH_MAGIC));
        let restored = DashObject::from_portable_bytes(&portable).unwrap();
        assert_eq!(restored, object);
        restored.verify_authentication(&keys).unwrap();

        let mut tampered = object.clone();
        tampered.header.timestamp += 1;
        assert!(matches!(
            tampered.verify_authentication(&keys),
            Err(ProtocolError::DashAuthentication)
        ));
    }

    #[test]
    fn dash_object_validation_rejects_size_hash_and_timing_mismatches() {
        let stream_id = Uuid::from_u128(1);
        let epoch_id = Uuid::from_u128(2);
        let keys = EpochKeys::derive(&[7u8; 32], stream_id, epoch_id).unwrap();
        let object = DashObject::authenticated(
            NewDashObject {
                stream_id,
                epoch_id,
                kind: DashObjectKind::Media,
                sequence: 1,
                segment_number: 1,
                chunk_index: 0,
                timestamp: 0,
                duration: 90_000,
                random_access: true,
                mime: "video/iso.segment",
                payload: vec![1, 2, 3],
            },
            &keys,
        )
        .unwrap();

        let mut wrong_length = object.clone();
        wrong_length.header.payload_len += 1;
        assert!(matches!(
            wrong_length.validate(),
            Err(ProtocolError::DashPayloadLength)
        ));

        let mut wrong_hash = object.clone();
        wrong_hash.payload[0] ^= 0xff;
        assert!(matches!(
            wrong_hash.validate(),
            Err(ProtocolError::DashPayloadHash)
        ));

        let mut no_duration = object;
        no_duration.header.duration = 0;
        no_duration.header.payload_sha256 = Sha256::digest(&no_duration.payload).into();
        assert!(matches!(
            no_duration.validate(),
            Err(ProtocolError::InvalidDashMetadata(_))
        ));
    }

    #[tokio::test]
    async fn noise_socket_round_trips_large_message_in_segments() {
        let (mut client_stream, mut server_stream) = tokio::io::duplex(1024);
        let keypair = generate_noise_keypair().unwrap();
        let client = tokio::spawn(async move {
            let transport = initiator_handshake(&mut client_stream, &keypair.public)
                .await
                .unwrap();
            let mut socket = NoiseSocket::new(client_stream, transport);
            let payload = vec![42u8; 200_000];
            socket
                .write(&ClientMessage::Frame(FrameMessage {
                    stream_id: Uuid::nil(),
                    seq: 7,
                    captured_at_ms: 1,
                    width: 2560,
                    height: 1440,
                    mime: "image/jpeg".to_string(),
                    key_id: "v1".to_string(),
                    nonce: [0; 12],
                    content_hash: 1,
                    ciphertext: payload,
                }))
                .await
                .unwrap();
        });
        let server = tokio::spawn(async move {
            let transport = responder_handshake(&mut server_stream, &keypair.private)
                .await
                .unwrap();
            let mut socket = NoiseSocket::new(server_stream, transport);
            match socket.read::<ClientMessage>().await.unwrap() {
                ClientMessage::Frame(frame) => {
                    assert_eq!(frame.seq, 7);
                    assert_eq!(frame.ciphertext, vec![42u8; 200_000]);
                }
                other => panic!("unexpected message: {other:?}"),
            }
        });

        client.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn noise_socket_round_trips_frame_status_ack_then_cursors() {
        let (mut client_stream, mut server_stream) = tokio::io::duplex(1024);
        let stream_id = Uuid::new_v4();
        let keypair = generate_noise_keypair().unwrap();
        let client = tokio::spawn(async move {
            let transport = initiator_handshake(&mut client_stream, &keypair.public)
                .await
                .unwrap();
            let mut socket = NoiseSocket::new(client_stream, transport);
            socket
                .write(&ClientMessage::Frame(FrameMessage {
                    stream_id,
                    seq: 1,
                    captured_at_ms: 1,
                    width: 1280,
                    height: 720,
                    mime: "image/jpeg".to_string(),
                    key_id: String::new(),
                    nonce: [0; 12],
                    content_hash: 1,
                    ciphertext: vec![42u8; 93_249],
                }))
                .await
                .unwrap();
            socket
                .write(&ClientMessage::BufferStatus(BufferStatus {
                    stream_id,
                    lowest_seq: Some(1),
                    highest_seq: Some(1),
                    bytes: 93_249,
                }))
                .await
                .unwrap();
            match socket.read::<ServerMessage>().await.unwrap() {
                ServerMessage::Ack { through_seq } => assert_eq!(through_seq, 1),
                other => panic!("unexpected server message: {other:?}"),
            }
            for seq in 1..=3 {
                socket
                    .write(&ClientMessage::Cursor(CursorMessage {
                        stream_id,
                        seq,
                        captured_at_ms: seq as i64,
                        x: 10.0 + seq as f32,
                        y: 20.0 + seq as f32,
                        source_width: 1280,
                        source_height: 720,
                        bitmap: None,
                    }))
                    .await
                    .unwrap();
            }
        });
        let server = tokio::spawn(async move {
            let transport = responder_handshake(&mut server_stream, &keypair.private)
                .await
                .unwrap();
            let mut socket = NoiseSocket::new(server_stream, transport);
            match socket.read::<ClientMessage>().await.unwrap() {
                ClientMessage::Frame(frame) => {
                    assert_eq!(frame.seq, 1);
                    assert_eq!(frame.ciphertext.len(), 93_249);
                }
                other => panic!("unexpected message: {other:?}"),
            }
            socket
                .write(&ServerMessage::Ack { through_seq: 1 })
                .await
                .unwrap();
            match socket.read::<ClientMessage>().await.unwrap() {
                ClientMessage::BufferStatus(status) => {
                    assert_eq!(status.stream_id, stream_id);
                    assert_eq!(status.highest_seq, Some(1));
                }
                other => panic!("unexpected message: {other:?}"),
            }
            for seq in 1..=3 {
                match socket.read::<ClientMessage>().await.unwrap() {
                    ClientMessage::Cursor(cursor) => {
                        assert_eq!(cursor.stream_id, stream_id);
                        assert_eq!(cursor.seq, seq);
                    }
                    other => panic!("unexpected message: {other:?}"),
                }
            }
        });

        client.await.unwrap();
        server.await.unwrap();
    }
}
