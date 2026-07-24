use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};
use std::io;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

pub mod daemon;

pub const PROTOCOL_VERSION: u16 = 2;
pub const MAX_FRAME_LEN: usize = 32 * 1024 * 1024;
const MAX_NOISE_PLAINTEXT_LEN: usize = 60 * 1024;
const NOISE_SEGMENT_MAGIC: &[u8; 4] = b"GCN1";
const NOISE_SEGMENT_HEADER_LEN: usize = 12;
pub const NOISE_PATTERN: &str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";

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
    Bincode(#[from] Box<bincode::ErrorKind>),
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("crypto error")]
    Crypto,
    #[error("viewer key must decode to 32 bytes, got {0}")]
    InvalidKeyLength(usize),
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
    Cursor(CursorMessage),
    BufferStatus(BufferStatus),
    Ping { now_ms: i64 },
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

pub fn build_noise_initiator() -> Result<HandshakeState> {
    Builder::new(noise_params()?)
        .build_initiator()
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))
}

pub fn build_noise_responder() -> Result<HandshakeState> {
    Builder::new(noise_params()?)
        .build_responder()
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))
}

pub async fn initiator_handshake<S>(stream: &mut S) -> Result<TransportState>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut noise = build_noise_initiator()?;
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

pub async fn responder_handshake<S>(stream: &mut S) -> Result<TransportState>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut noise = build_noise_responder()?;
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
        let plain = bincode::serialize(message)?;
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
                return bincode::deserialize(&plain_message).map_err(Into::into);
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

    #[tokio::test]
    async fn noise_socket_round_trips_large_message_in_segments() {
        let (mut client_stream, mut server_stream) = tokio::io::duplex(1024);
        let client = tokio::spawn(async move {
            let transport = initiator_handshake(&mut client_stream).await.unwrap();
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
            let transport = responder_handshake(&mut server_stream).await.unwrap();
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
        let client = tokio::spawn(async move {
            let transport = initiator_handshake(&mut client_stream).await.unwrap();
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
            let transport = responder_handshake(&mut server_stream).await.unwrap();
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
