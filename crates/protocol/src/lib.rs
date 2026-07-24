//! Versioned publisher, relay, portable-object, and daemon protocols.
//!
//! Publisher traffic is serialized with Postcard only after both peers agree
//! on [`PROTOCOL_VERSION`], segmented into bounded records, and carried through
//! a pinned Noise NK transport. DASH objects expose only routing and retention
//! metadata; their media and cursor payloads remain encrypted and are
//! authenticated end to end by keys the relay does not possess.
//!
//! The portable `GCO1` representation contains the same authenticated object
//! and can be copied independently to an offline viewer. All inbound lengths
//! are checked before allocation, and parsers reject trailing or noncanonical
//! data.

#![deny(missing_docs)]

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

/// Helpers shared by the client and server daemon-control implementations.
pub mod daemon;

/// Publisher/relay message schema version.
pub const PROTOCOL_VERSION: u16 = 5;
/// Absolute maximum serialized message size accepted by [`NoiseSocket`].
pub const MAX_FRAME_LEN: usize = 32 * 1024 * 1024;
const MAX_WIRE_PACKET_LEN: usize = 65_535;
/// Magic prefix for a portable [`DashObject`] file.
pub const PORTABLE_DASH_MAGIC: &[u8; 4] = b"GCO1";
const MAX_PORTABLE_DASH_HEADER_LEN: usize = 64 * 1024;
const MAX_NOISE_PLAINTEXT_LEN: usize = 60 * 1024;
const NOISE_SEGMENT_MAGIC: &[u8; 4] = b"GCN1";
const NOISE_SEGMENT_HEADER_LEN: usize = 12;
/// Noise protocol pattern used for pinned-server publisher ingest.
pub const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";
/// Byte length of Noise X25519 public and private keys.
pub const NOISE_KEY_LEN: usize = 32;

#[derive(Debug, Error)]
/// Errors produced by protocol framing, validation, serialization, or crypto.
pub enum ProtocolError {
    /// A declared or encoded frame exceeded the applicable maximum.
    #[error("message exceeds max frame length: {0}")]
    FrameTooLarge(usize),
    /// Framing, segmentation, or canonical-message validation failed.
    #[error("malformed frame")]
    MalformedFrame,
    /// The Noise state machine rejected an operation.
    #[error("noise error: {0}")]
    Noise(String),
    /// The underlying asynchronous stream failed.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    /// A Postcard message could not be encoded or decoded.
    #[error("serialization error: {0}")]
    Postcard(#[from] postcard::Error),
    /// An unpadded URL-safe base64 value could not be decoded.
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    /// A cryptographic primitive failed.
    #[error("crypto error")]
    Crypto,
    /// A decoded viewer key had the reported length instead of 32 bytes.
    #[error("viewer key must decode to 32 bytes, got {0}")]
    InvalidKeyLength(usize),
    /// A decoded Noise key had the reported length instead of [`NOISE_KEY_LEN`].
    #[error("Noise key must contain 32 bytes, got {0}")]
    InvalidNoiseKeyLength(usize),
    /// A DASH object used an unsupported format version.
    #[error("unsupported DASH object format version {0}")]
    UnsupportedDashVersion(u16),
    /// A DASH object's actual and declared payload lengths differed.
    #[error("DASH object payload length does not match its header")]
    DashPayloadLength,
    /// A DASH object exceeded the maximum for its object kind.
    #[error("DASH object payload exceeds its size limit")]
    DashPayloadTooLarge,
    /// A DASH object's payload did not match its declared SHA-256 digest.
    #[error("DASH object payload hash does not match its header")]
    DashPayloadHash,
    /// Public routing metadata violated the invariant named in the value.
    #[error("DASH object has invalid metadata: {0}")]
    InvalidDashMetadata(&'static str),
    /// End-to-end DASH object authentication failed.
    #[error("DASH object authentication failed")]
    DashAuthentication,
    /// A portable `GCO1` object violated its framing or object invariants.
    #[error("portable DASH object is malformed")]
    InvalidPortableDashObject,
}

/// Result type returned by protocol operations.
pub type Result<T> = std::result::Result<T, ProtocolError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Publisher identity and resume range sent as the first Noise message.
pub struct StreamHello {
    /// Message schema version, which must equal [`PROTOCOL_VERSION`].
    pub protocol_version: u16,
    /// Client-supplied identity used only when ingest authentication is optional.
    pub client_id: String,
    /// Publisher credential sent inside the authenticated Noise channel.
    pub auth_token: Option<String>,
    /// Human-readable stream label shown to authorized viewers.
    pub display_name: String,
    /// Public capture-source metadata.
    pub source: CaptureSource,
    /// Lowest object sequence still available for retransmission.
    pub resend_low: Option<u64>,
    /// Highest object sequence still available for retransmission.
    pub resend_high: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Non-secret metadata describing the captured source.
pub struct CaptureSource {
    /// Capture backend identifier, such as `portal` or `dash-test`.
    pub backend: String,
    /// Human-readable monitor, window, or test-source description.
    pub description: String,
    /// Source width in pixels.
    pub width: u32,
    /// Source height in pixels.
    pub height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Message sent from a publisher to the relay over [`NoiseSocket`].
pub enum ClientMessage {
    /// Opens or resumes a publisher stream and authenticates the publisher.
    Hello(StreamHello),
    /// Publishes one authenticated, opaque DASH object.
    DashObject(DashObject),
    /// Checks liveness using the publisher's current Unix time.
    Ping {
        /// Publisher Unix timestamp in milliseconds.
        now_ms: i64,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
/// Semantic role of a versioned DASH stream object.
pub enum DashObjectKind {
    /// Authenticated epoch descriptor.
    Epoch,
    /// CENC fragmented-MP4 initialization segment.
    Initialization,
    /// One independently appendable encrypted media fragment.
    Media,
    /// One encrypted batch of independent cursor events.
    Cursor,
    /// Authenticated presentation index metadata.
    Index,
    /// Clean epoch termination marker.
    End,
}

impl DashObjectKind {
    /// Returns the stable numeric code included in object authentication.
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

    /// Returns the maximum payload size accepted for this object kind.
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
/// Public routing, timing, integrity, and authentication data for a DASH object.
pub struct DashObjectHeader {
    /// DASH object format version.
    pub format_version: u16,
    /// Durable relay-assigned stream identity.
    pub stream_id: Uuid,
    /// Capture and encryption epoch identity.
    pub epoch_id: Uuid,
    /// Semantic object role.
    pub kind: DashObjectKind,
    /// Monotonic sequence within the stream.
    pub sequence: u64,
    /// Random-access segment group, or zero for epoch-level metadata.
    pub segment_number: u64,
    /// Fragment index within a media segment.
    pub chunk_index: u16,
    /// Start in the shared 90 kHz media timeline.
    pub timestamp: u64,
    /// Duration in the shared 90 kHz media timeline.
    pub duration: u64,
    /// Whether this object starts at a decodable random-access point.
    pub random_access: bool,
    /// Short ASCII media type used by HTTP responses.
    pub mime: String,
    /// Exact opaque payload length.
    pub payload_len: u32,
    /// SHA-256 digest of the opaque payload.
    pub payload_sha256: [u8; 32],
    /// End-to-end HMAC-SHA-256 tag over the canonical header and payload.
    pub authentication_tag: [u8; 32],
}

impl DashObjectHeader {
    /// Encodes the canonical header bytes covered by object authentication.
    ///
    /// The authentication tag itself is deliberately excluded.
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
/// One authenticated opaque object relayed and retained by GlacialCast.
pub struct DashObject {
    /// Public metadata needed for routing, retention, and integrity checks.
    pub header: DashObjectHeader,
    /// Encrypted media/cursor bytes or authenticated epoch/index metadata.
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
/// Borrowed construction inputs for [`DashObject::authenticated`].
pub struct NewDashObject<'a> {
    /// Durable relay-assigned stream identity.
    pub stream_id: Uuid,
    /// Capture and encryption epoch identity.
    pub epoch_id: Uuid,
    /// Semantic object role.
    pub kind: DashObjectKind,
    /// Monotonic sequence within the stream.
    pub sequence: u64,
    /// Random-access segment group, or zero for epoch-level metadata.
    pub segment_number: u64,
    /// Fragment index within a media segment.
    pub chunk_index: u16,
    /// Start in the shared 90 kHz media timeline.
    pub timestamp: u64,
    /// Duration in the shared 90 kHz media timeline.
    pub duration: u64,
    /// Whether the object starts at a decodable random-access point.
    pub random_access: bool,
    /// Short ASCII media type.
    pub mime: &'a str,
    /// Opaque payload to hash and authenticate.
    pub payload: Vec<u8>,
}

impl DashObject {
    /// Builds, validates, hashes, and authenticates a new object.
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

    /// Validates public metadata, kind-specific invariants, length, and hash.
    ///
    /// This does not verify [`DashObjectHeader::authentication_tag`]; call
    /// [`Self::verify_authentication`] when epoch keys are available.
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
        if self.header.sequence == 0 {
            return Err(ProtocolError::InvalidDashMetadata(
                "sequence must not be zero",
            ));
        }
        if self.header.mime.is_empty()
            || self.header.mime.len() > 127
            || !self.header.mime.is_ascii()
        {
            return Err(ProtocolError::InvalidDashMetadata(
                "MIME type must be nonempty short ASCII",
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
            DashObjectKind::Epoch
                if self.header.segment_number != 0
                    || self.header.chunk_index != 0
                    || self.header.timestamp != 0
                    || self.header.duration != 0
                    || self.payload.is_empty() =>
            {
                return Err(ProtocolError::InvalidDashMetadata(
                    "epoch object has invalid metadata",
                ));
            }
            DashObjectKind::Initialization
                if self.header.segment_number != 0
                    || self.header.chunk_index != 0
                    || self.header.timestamp != 0
                    || self.header.duration != 0
                    || self.payload.is_empty() =>
            {
                return Err(ProtocolError::InvalidDashMetadata(
                    "initialization object has invalid metadata",
                ));
            }
            DashObjectKind::Media
                if self.header.segment_number == 0
                    || self.header.duration == 0
                    || self.payload.is_empty() =>
            {
                return Err(ProtocolError::InvalidDashMetadata(
                    "media object has invalid metadata",
                ));
            }
            DashObjectKind::Cursor
                if self.header.segment_number == 0
                    || self.header.duration == 0
                    || self.payload.is_empty() =>
            {
                return Err(ProtocolError::InvalidDashMetadata(
                    "cursor object has invalid metadata",
                ));
            }
            DashObjectKind::End
                if self.header.chunk_index != 0
                    || self.header.duration != 0
                    || !self.payload.is_empty() =>
            {
                return Err(ProtocolError::InvalidDashMetadata(
                    "end object has invalid metadata",
                ));
            }
            _ => {}
        }
        Ok(())
    }

    /// Validates this object and verifies its end-to-end authentication tag.
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

    /// Serializes this object as a bounded, independently transferable `GCO1` file.
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

    /// Parses a `GCO1` file and validates its public metadata, length, and hash.
    ///
    /// End-to-end authentication remains a separate operation because the
    /// offline transport does not possess the viewer-derived epoch keys.
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
/// Message sent from the relay to a publisher over [`NoiseSocket`].
pub enum ServerMessage {
    /// Accepts or rejects the initial [`StreamHello`] and reports resume state.
    HelloAck {
        /// Whether the relay accepted the publisher.
        accepted: bool,
        /// Bounded human-readable rejection reason, if any.
        reason: Option<String>,
        /// Durable assigned stream identity when accepted.
        stream_id: Option<Uuid>,
        /// Highest sequence durably retained or previously acknowledged.
        last_sequence: u64,
        /// Relay Unix timestamp in milliseconds.
        server_time_ms: i64,
    },
    /// Confirms durable storage through a sequence number.
    Ack {
        /// Highest contiguous durably stored sequence.
        through_seq: u64,
    },
    /// Requests retransmission of an inclusive object-sequence range.
    ResendRequest {
        /// First sequence requested.
        from_seq: u64,
        /// Last sequence requested.
        to_seq: u64,
    },
    /// Asks a publisher to pause before sending more objects.
    Backpressure {
        /// Requested pause duration in milliseconds.
        pause_ms: u64,
        /// Human-readable reason suitable for diagnostics.
        reason: String,
    },
    /// Replies to [`ClientMessage::Ping`].
    Pong {
        /// Relay Unix timestamp in milliseconds.
        now_ms: i64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Browser control-channel notification about a stream lifecycle change.
pub struct ControlEvent {
    /// Event name, such as `stream_updated` or `stream_deleted`.
    pub event: String,
    /// Stream affected by the event.
    pub stream_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Authorized, non-secret stream summary returned by the relay API.
pub struct PublicStream {
    /// Durable relay-assigned stream identity.
    pub stream_id: Uuid,
    /// Publisher-provided human-readable label.
    pub display_name: String,
    /// Public capture-source metadata.
    pub source: CaptureSource,
    /// Whether a publisher currently owns an ingest connection.
    pub active: bool,
    /// Last publisher activity as Unix milliseconds.
    pub last_seen_at_ms: Option<i64>,
    /// Highest retained or durably observed DASH object sequence.
    pub last_object_sequence: Option<u64>,
    /// Approximate bytes retained for this stream.
    pub retained_bytes: u64,
}

/// Returns the current Unix timestamp in milliseconds.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Decodes an unpadded URL-safe base64 viewer key and enforces 32 bytes.
pub fn decode_key_b64(key: &str) -> Result<[u8; 32]> {
    let decoded = URL_SAFE_NO_PAD.decode(key)?;
    if decoded.len() != 32 {
        return Err(ProtocolError::InvalidKeyLength(decoded.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

/// Parses a non-negative decimal byte size with SI or IEC suffixes.
///
/// Accepted examples include `512MiB`, `1.5GB`, and `4096`.
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

/// Writes one length-prefixed unencrypted handshake packet.
///
/// The packet is bounded by Noise's 65,535-byte wire-message limit.
pub async fn write_clear_frame<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    if data.len() > MAX_WIRE_PACKET_LEN {
        return Err(ProtocolError::FrameTooLarge(data.len()));
    }
    writer.write_u32(data.len() as u32).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads one bounded length-prefixed unencrypted handshake packet.
pub async fn read_clear_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let len = reader.read_u32().await? as usize;
    if len > MAX_WIRE_PACKET_LEN {
        return Err(ProtocolError::FrameTooLarge(len));
    }
    let mut data = vec![0u8; len];
    reader.read_exact(&mut data).await?;
    Ok(data)
}

/// Parses the fixed Noise NK parameter suite used by GlacialCast ingest.
pub fn noise_params() -> Result<NoiseParams> {
    NOISE_PATTERN
        .parse()
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Persistent X25519 identity used by the Noise responder.
pub struct NoiseKeypair {
    /// Secret X25519 key; store only in a private regular file.
    pub private: [u8; NOISE_KEY_LEN],
    /// Public X25519 key pinned by publishers.
    pub public: [u8; NOISE_KEY_LEN],
}

impl NoiseKeypair {
    /// Proves that the public and private halves complete a Noise NK handshake.
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

/// Generates and validates a new cryptographically random Noise identity.
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

/// Encodes a Noise public key as unpadded URL-safe base64.
pub fn encode_noise_public_key(key: &[u8; NOISE_KEY_LEN]) -> String {
    URL_SAFE_NO_PAD.encode(key)
}

/// Decodes an unpadded URL-safe base64 Noise public key.
pub fn decode_noise_public_key(encoded: &str) -> Result<[u8; NOISE_KEY_LEN]> {
    let key = URL_SAFE_NO_PAD.decode(encoded.trim())?;
    let length = key.len();
    key.try_into()
        .map_err(|_| ProtocolError::InvalidNoiseKeyLength(length))
}

/// Builds the publisher side of a Noise NK handshake pinned to the relay key.
pub fn build_noise_initiator(remote_public_key: &[u8; NOISE_KEY_LEN]) -> Result<HandshakeState> {
    Builder::new(noise_params()?)
        .remote_public_key(remote_public_key)
        .build_initiator()
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))
}

/// Builds the relay side of a Noise NK handshake using its private identity.
pub fn build_noise_responder(local_private_key: &[u8; NOISE_KEY_LEN]) -> Result<HandshakeState> {
    Builder::new(noise_params()?)
        .local_private_key(local_private_key)
        .build_responder()
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))
}

/// Performs the publisher side of the Noise NK handshake.
///
/// No credential or stream object should be sent until this returns a
/// [`TransportState`], because the handshake authenticates the pinned relay.
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

/// Performs the relay side of the Noise NK handshake.
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

/// Bounded Postcard message transport over an established Noise session.
pub struct NoiseSocket<S> {
    stream: S,
    transport: TransportState,
}

impl<S> NoiseSocket<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Wraps an asynchronous byte stream and established Noise transport.
    pub fn new(stream: S, transport: TransportState) -> Self {
        Self { stream, transport }
    }

    /// Serializes and writes one message, segmenting it across Noise records.
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

    /// Reads and canonically decodes one message up to [`MAX_FRAME_LEN`].
    pub async fn read<T: for<'de> Deserialize<'de>>(&mut self) -> Result<T> {
        self.read_limited(MAX_FRAME_LEN).await
    }

    /// Reads one message while applying a caller-specific preallocation limit.
    ///
    /// `max_len` is capped at [`MAX_FRAME_LEN`]. The declared total is checked
    /// before reserving message storage.
    pub async fn read_limited<T: for<'de> Deserialize<'de>>(
        &mut self,
        max_len: usize,
    ) -> Result<T> {
        let max_len = max_len.min(MAX_FRAME_LEN);
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
            if total_len > max_len {
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

    /// Consumes the wrapper and returns the underlying byte stream.
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

/// Serializes a browser control event as JSON.
///
/// `ControlEvent` contains only serializable fields; the defensive fallback
/// returns an empty JSON object if that invariant changes.
pub fn encode_ws_event(event: &ControlEvent) -> String {
    serde_json::to_string(event).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn media_fixture() -> (DashObject, EpochKeys) {
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
        (object, keys)
    }

    fn noise_transport_pair() -> (TransportState, TransportState) {
        let keypair = generate_noise_keypair().unwrap();
        let mut initiator = build_noise_initiator(&keypair.public).unwrap();
        let mut responder = build_noise_responder(&keypair.private).unwrap();
        let mut message = [0u8; 128];
        let mut payload = [0u8; 128];
        let length = initiator.write_message(&[], &mut message).unwrap();
        responder
            .read_message(&message[..length], &mut payload)
            .unwrap();
        let length = responder.write_message(&[], &mut message).unwrap();
        initiator
            .read_message(&message[..length], &mut payload)
            .unwrap();
        (
            initiator.into_transport_mode().unwrap(),
            responder.into_transport_mode().unwrap(),
        )
    }

    async fn read_client_message_segments(segments: Vec<Vec<u8>>) -> Result<ClientMessage> {
        read_client_message_segments_limited(segments, MAX_FRAME_LEN).await
    }

    async fn read_client_message_segments_limited(
        segments: Vec<Vec<u8>>,
        max_len: usize,
    ) -> Result<ClientMessage> {
        let (mut writer, reader) = tokio::io::duplex(4096);
        let (mut initiator, responder) = noise_transport_pair();
        let send = tokio::spawn(async move {
            for segment in segments {
                let mut encrypted = vec![0; segment.len() + 16];
                let length = initiator.write_message(&segment, &mut encrypted).unwrap();
                write_clear_frame(&mut writer, &encrypted[..length])
                    .await
                    .unwrap();
            }
        });
        let mut socket = NoiseSocket::new(reader, responder);
        let result = socket.read_limited::<ClientMessage>(max_len).await;
        send.await.unwrap();
        result
    }

    #[test]
    fn human_byte_sizes_parse_common_units() {
        assert_eq!(parse_human_bytes("50MB").unwrap(), 50_000_000);
        assert_eq!(parse_human_bytes("50MiB").unwrap(), 50 * 1024 * 1024);
        assert_eq!(parse_human_bytes("1.5KB").unwrap(), 1500);
    }

    #[test]
    fn human_byte_sizes_reject_malformed_negative_and_overflowing_values() {
        for value in ["", "-1", "NaN", "1.2.3MiB", "10XB", "1e1000TB"] {
            assert!(parse_human_bytes(value).is_err(), "accepted {value:?}");
        }
        assert_eq!(parse_human_bytes("0").unwrap(), 0);
        assert_eq!(
            parse_human_bytes(" 2 GiB ").unwrap(),
            2 * 1024 * 1024 * 1024
        );
    }

    #[test]
    fn viewer_key_decode_rejects_wrong_length() {
        let short = URL_SAFE_NO_PAD.encode([7u8; 31]);
        assert!(matches!(
            decode_key_b64(&short),
            Err(ProtocolError::InvalidKeyLength(31))
        ));
    }

    #[tokio::test]
    async fn clear_frame_rejects_oversized_wire_packet_before_reading_payload() {
        let advertised_length = (MAX_WIRE_PACKET_LEN as u32 + 1).to_be_bytes();
        assert!(matches!(
            read_clear_frame(&mut advertised_length.as_slice()).await,
            Err(ProtocolError::FrameTooLarge(length)) if length == MAX_WIRE_PACKET_LEN + 1
        ));
    }

    #[tokio::test]
    async fn clear_frame_round_trips_boundaries_and_reports_truncation() {
        for payload in [Vec::new(), vec![7], vec![9; MAX_WIRE_PACKET_LEN]] {
            let mut wire = Vec::new();
            write_clear_frame(&mut wire, &payload).await.unwrap();
            assert_eq!(
                read_clear_frame(&mut wire.as_slice()).await.unwrap(),
                payload
            );
        }
        assert!(matches!(
            write_clear_frame(&mut Vec::new(), &vec![0; MAX_WIRE_PACKET_LEN + 1]).await,
            Err(ProtocolError::FrameTooLarge(_))
        ));

        let truncated = [0, 0, 0, 2, 1];
        assert!(matches!(
            read_clear_frame(&mut truncated.as_slice()).await,
            Err(ProtocolError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof
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

    #[test]
    fn dash_object_validation_rejects_unusable_routing_metadata() {
        let (object, _) = media_fixture();
        let assert_metadata_error = |mutated: DashObject| {
            assert!(matches!(
                mutated.validate(),
                Err(ProtocolError::InvalidDashMetadata(_))
            ));
        };

        let mut invalid = object.clone();
        invalid.header.stream_id = Uuid::nil();
        assert_metadata_error(invalid);
        let mut invalid = object.clone();
        invalid.header.epoch_id = Uuid::nil();
        assert_metadata_error(invalid);
        let mut invalid = object.clone();
        invalid.header.sequence = 0;
        assert_metadata_error(invalid);
        let mut invalid = object.clone();
        invalid.header.mime.clear();
        assert_metadata_error(invalid);
        let mut invalid = object.clone();
        invalid.header.mime = "é".to_string();
        assert_metadata_error(invalid);
        let mut invalid = object.clone();
        invalid.header.mime = "x".repeat(128);
        assert_metadata_error(invalid);
        let mut invalid = object.clone();
        invalid.header.segment_number = 0;
        assert_metadata_error(invalid);
        let mut invalid = object;
        invalid.payload.clear();
        invalid.header.payload_len = 0;
        invalid.header.payload_sha256 = Sha256::digest([]).into();
        assert_metadata_error(invalid);
    }

    #[test]
    fn dash_object_kind_specific_metadata_is_enforced() {
        let (media, keys) = media_fixture();
        let create = |kind, payload: Vec<u8>| {
            DashObject::authenticated(
                NewDashObject {
                    stream_id: media.header.stream_id,
                    epoch_id: media.header.epoch_id,
                    kind,
                    sequence: 2,
                    segment_number: match kind {
                        DashObjectKind::Media | DashObjectKind::Cursor => 1,
                        _ => 0,
                    },
                    chunk_index: 0,
                    timestamp: 0,
                    duration: match kind {
                        DashObjectKind::Media | DashObjectKind::Cursor => 1,
                        _ => 0,
                    },
                    random_access: true,
                    mime: "application/octet-stream",
                    payload,
                },
                &keys,
            )
        };

        create(DashObjectKind::Epoch, vec![1]).unwrap();
        create(DashObjectKind::Initialization, vec![1]).unwrap();
        create(DashObjectKind::Media, vec![1]).unwrap();
        create(DashObjectKind::Cursor, vec![1]).unwrap();
        create(DashObjectKind::Index, vec![1]).unwrap();
        create(DashObjectKind::End, Vec::new()).unwrap();
        assert!(create(DashObjectKind::Epoch, Vec::new()).is_err());
        assert!(create(DashObjectKind::Initialization, Vec::new()).is_err());
        assert!(create(DashObjectKind::Media, Vec::new()).is_err());
        assert!(create(DashObjectKind::Cursor, Vec::new()).is_err());
        assert!(create(DashObjectKind::End, vec![1]).is_err());
    }

    #[test]
    fn portable_dash_object_rejects_every_truncation_and_trailing_payload() {
        let (object, _) = media_fixture();
        let portable = object.to_portable_bytes().unwrap();
        for end in 0..portable.len() {
            assert!(
                DashObject::from_portable_bytes(&portable[..end]).is_err(),
                "accepted portable object truncated at byte {end}"
            );
        }
        let mut trailing = portable;
        trailing.push(0);
        assert!(matches!(
            DashObject::from_portable_bytes(&trailing),
            Err(ProtocolError::DashPayloadLength)
        ));
    }

    #[test]
    fn portable_dash_object_rejects_invalid_magic_header_lengths_and_json() {
        let (object, _) = media_fixture();
        let mut portable = object.to_portable_bytes().unwrap();
        portable[..4].copy_from_slice(b"NOPE");
        assert!(matches!(
            DashObject::from_portable_bytes(&portable),
            Err(ProtocolError::InvalidPortableDashObject)
        ));

        for header_length in [0u32, MAX_PORTABLE_DASH_HEADER_LEN as u32 + 1] {
            let mut malformed = Vec::from(&PORTABLE_DASH_MAGIC[..]);
            malformed.extend_from_slice(&header_length.to_be_bytes());
            assert!(matches!(
                DashObject::from_portable_bytes(&malformed),
                Err(ProtocolError::InvalidPortableDashObject)
            ));
        }

        let mut invalid_json = Vec::from(&PORTABLE_DASH_MAGIC[..]);
        invalid_json.extend_from_slice(&1u32.to_be_bytes());
        invalid_json.push(b'{');
        assert!(matches!(
            DashObject::from_portable_bytes(&invalid_json),
            Err(ProtocolError::InvalidPortableDashObject)
        ));
    }

    #[test]
    fn portable_dash_object_preserves_authentication_failure() {
        let (mut object, keys) = media_fixture();
        object.header.authentication_tag[0] ^= 1;
        let restored =
            DashObject::from_portable_bytes(&object.to_portable_bytes().unwrap()).unwrap();
        assert!(matches!(
            restored.verify_authentication(&keys),
            Err(ProtocolError::DashAuthentication)
        ));
    }

    #[test]
    fn noise_segment_codec_rejects_malformed_offsets_and_headers() {
        assert!(noise_segment(2, 0, &[1, 2]).is_ok());
        assert!(matches!(
            noise_segment(1, 1, &[1]),
            Err(ProtocolError::MalformedFrame)
        ));
        for segment in [&b""[..], &b"GCN1"[..], &b"NOPE\0\0\0\0\0\0\0\0"[..]] {
            assert!(matches!(
                parse_noise_segment(segment),
                Err(ProtocolError::MalformedFrame)
            ));
        }
    }

    #[tokio::test]
    async fn noise_socket_rejects_inconsistent_segment_totals() {
        let segments = vec![
            noise_segment(2, 0, &[1]).unwrap(),
            noise_segment(3, 1, &[2]).unwrap(),
        ];
        assert!(matches!(
            read_client_message_segments(segments).await,
            Err(ProtocolError::MalformedFrame)
        ));
    }

    #[tokio::test]
    async fn noise_socket_rejects_gaps_replays_and_zero_progress() {
        for segments in [
            vec![noise_segment(2, 1, &[1]).unwrap()],
            vec![
                noise_segment(2, 0, &[1]).unwrap(),
                noise_segment(2, 0, &[2]).unwrap(),
            ],
            vec![noise_segment(1, 0, &[]).unwrap()],
        ] {
            assert!(matches!(
                read_client_message_segments(segments).await,
                Err(ProtocolError::MalformedFrame)
            ));
        }
    }

    #[tokio::test]
    async fn noise_socket_rejects_oversized_and_noncanonical_messages() {
        let oversized = noise_segment(MAX_FRAME_LEN + 1, 0, &[1]).unwrap();
        assert!(matches!(
            read_client_message_segments(vec![oversized]).await,
            Err(ProtocolError::FrameTooLarge(length)) if length == MAX_FRAME_LEN + 1
        ));

        let mut encoded = postcard::to_stdvec(&ClientMessage::Ping { now_ms: 7 }).unwrap();
        encoded.push(0);
        let segment = noise_segment(encoded.len(), 0, &encoded).unwrap();
        assert!(matches!(
            read_client_message_segments(vec![segment]).await,
            Err(ProtocolError::MalformedFrame)
        ));
    }

    #[tokio::test]
    async fn noise_socket_applies_caller_specific_message_limits_before_allocation() {
        let message = postcard::to_stdvec(&ClientMessage::Ping { now_ms: 7 }).unwrap();
        let segment = noise_segment(message.len(), 0, &message).unwrap();
        assert!(matches!(
            read_client_message_segments_limited(vec![segment], message.len() - 1).await,
            Err(ProtocolError::FrameTooLarge(length)) if length == message.len()
        ));
    }

    #[tokio::test]
    async fn noise_socket_round_trips_segmented_dash_object_and_ack() {
        let (mut client_stream, mut server_stream) = tokio::io::duplex(1024);
        let stream_id = Uuid::new_v4();
        let epoch_id = Uuid::new_v4();
        let keys = EpochKeys::derive(&[9u8; 32], stream_id, epoch_id).unwrap();
        let object = DashObject::authenticated(
            NewDashObject {
                stream_id,
                epoch_id,
                kind: DashObjectKind::Media,
                sequence: 7,
                segment_number: 2,
                chunk_index: 0,
                timestamp: 180_000,
                duration: 90_000,
                random_access: true,
                mime: "video/iso.segment",
                payload: vec![42u8; 200_000],
            },
            &keys,
        )
        .unwrap();
        let keypair = generate_noise_keypair().unwrap();
        let client = tokio::spawn(async move {
            let transport = initiator_handshake(&mut client_stream, &keypair.public)
                .await
                .unwrap();
            let mut socket = NoiseSocket::new(client_stream, transport);
            socket
                .write(&ClientMessage::DashObject(object))
                .await
                .unwrap();
            assert!(matches!(
                socket.read::<ServerMessage>().await.unwrap(),
                ServerMessage::Ack { through_seq: 7 }
            ));
        });
        let server = tokio::spawn(async move {
            let transport = responder_handshake(&mut server_stream, &keypair.private)
                .await
                .unwrap();
            let mut socket = NoiseSocket::new(server_stream, transport);
            match socket.read::<ClientMessage>().await.unwrap() {
                ClientMessage::DashObject(object) => {
                    assert_eq!(object.header.sequence, 7);
                    assert_eq!(object.payload, vec![42u8; 200_000]);
                }
                other => panic!("unexpected message: {other:?}"),
            }
            socket
                .write(&ServerMessage::Ack { through_seq: 7 })
                .await
                .unwrap();
        });

        client.await.unwrap();
        server.await.unwrap();
    }
}
