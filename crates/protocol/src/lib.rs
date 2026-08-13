//! Native publisher, relay, viewer, and daemon protocols.
//!
//! Application messages use bounded canonical Postcard records over mutually
//! authenticated Noise XX sessions. Stream media and cursor payloads are
//! separately signed and end-to-end encrypted, so the relay cannot decrypt
//! content. All inbound lengths are checked before allocation.

#![deny(missing_docs)]

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};
use std::io;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

mod auth_words;
/// Helpers shared by the client and server daemon-control implementations.
pub mod config_path;
pub mod credential;
pub mod cursor;
pub mod daemon;
mod entropy;
pub mod envelope;
pub mod identity;
pub mod native;
pub mod pairing;
pub mod private_state;
pub mod trust;
pub mod wire;

/// Publisher/relay/viewer application protocol version.
pub const PROTOCOL_VERSION: u16 = 9;
/// Absolute maximum serialized message size accepted by [`NoiseSocket`].
pub const MAX_FRAME_LEN: usize = 32 * 1024 * 1024;
const MAX_WIRE_PACKET_LEN: usize = 65_535;
const MAX_NOISE_PLAINTEXT_LEN: usize = 60 * 1024;
const NOISE_SEGMENT_MAGIC: &[u8; 4] = b"GCN1";
const NOISE_SEGMENT_HEADER_LEN: usize = 12;
/// Mutual-static Noise pattern used by publisher, relay, and viewer links.
pub const NOISE_XX_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
/// Byte length of Noise X25519 public and private keys.
pub const NOISE_KEY_LEN: usize = 32;

/// Errors produced by native framing, serialization, and transport security.
#[derive(Debug, Error)]
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
    /// The underlying asynchronous stream or private-state operation failed.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    /// A Postcard message could not be encoded or decoded.
    #[error("serialization error: {0}")]
    Postcard(#[from] postcard::Error),
    /// An unpadded URL-safe base64 value could not be decoded.
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    /// A decoded Noise key had the wrong length.
    #[error("Noise key must contain 32 bytes, got {0}")]
    InvalidNoiseKeyLength(usize),
}

/// Result type returned by native framing and Noise operations.
pub type Result<T> = std::result::Result<T, ProtocolError>;

/// Returns the current Unix timestamp in milliseconds.
#[allow(
    clippy::cast_possible_truncation,
    reason = "milliseconds since 1970 exceed i64 around the year 292 million"
)]
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Parses a non-negative decimal byte size with SI or IEC suffixes.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the value is refused above u64::MAX and below zero before rounding"
)]
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

/// Writes one length-prefixed, bounded Noise handshake packet.
pub async fn write_clear_frame<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    if data.len() > MAX_WIRE_PACKET_LEN {
        return Err(ProtocolError::FrameTooLarge(data.len()));
    }
    let length = u32::try_from(data.len()).map_err(|_| ProtocolError::FrameTooLarge(data.len()))?;
    writer.write_u32(length).await?;
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

/// Parses the mutual-static Noise XX suite used by native transports.
pub fn noise_xx_params() -> Result<NoiseParams> {
    NOISE_XX_PATTERN
        .parse()
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Persistent X25519 identity used by native Noise XX sessions.
pub struct NoiseKeypair {
    /// Secret X25519 key; store only in a private regular file.
    pub private: [u8; NOISE_KEY_LEN],
    /// Public X25519 key pinned by publishers.
    pub public: [u8; NOISE_KEY_LEN],
}

impl NoiseKeypair {
    /// Verifies that the public key is derived from the private key using a full XX handshake.
    pub fn validate_xx(&self) -> Result<()> {
        let peer = Builder::new(noise_xx_params()?)
            .generate_keypair()
            .map_err(|err| ProtocolError::Noise(format!("{err:?}")))?;
        let peer_private: [u8; NOISE_KEY_LEN] = peer
            .private
            .try_into()
            .map_err(|key: Vec<u8>| ProtocolError::InvalidNoiseKeyLength(key.len()))?;
        let mut initiator = build_noise_xx_initiator(&self.private)?;
        let mut responder = build_noise_xx_responder(&peer_private)?;
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
        let len = initiator
            .write_message(&[], &mut message)
            .map_err(|err| ProtocolError::Noise(format!("{err:?}")))?;
        responder
            .read_message(&message[..len], &mut payload)
            .map_err(|err| ProtocolError::Noise(format!("{err:?}")))?;
        let learned = responder
            .get_remote_static()
            .ok_or_else(|| ProtocolError::Noise("Noise XX omitted initiator static key".into()))?;
        if learned != self.public {
            return Err(ProtocolError::Noise(
                "Noise private and public keys do not match".into(),
            ));
        }
        Ok(())
    }
}

/// Generates and validates a new cryptographically random Noise identity.
pub fn generate_noise_keypair() -> Result<NoiseKeypair> {
    let keypair = Builder::new(noise_xx_params()?)
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
    keypair.validate_xx()?;
    Ok(keypair)
}

/// Loads or creates a private persistent Noise XX identity.
///
/// The file is a bounded canonical private-state record and is never followed
/// through a symlink. A concurrently created valid identity is adopted.
///
/// # Errors
///
/// Returns an error for unsafe file metadata, malformed key material, or a
/// create/read/synchronization failure.
pub fn load_or_create_noise_keypair(path: &std::path::Path) -> Result<NoiseKeypair> {
    const MAGIC: &[u8; 5] = b"GCXX1";
    const FILE_LEN: usize = MAGIC.len() + NOISE_KEY_LEN * 2;
    let decode = |bytes: &[u8]| -> Result<NoiseKeypair> {
        if bytes.len() != FILE_LEN || !bytes.starts_with(MAGIC) {
            return Err(ProtocolError::Noise("invalid Noise identity file".into()));
        }
        let keypair = NoiseKeypair {
            private: bytes[MAGIC.len()..MAGIC.len() + NOISE_KEY_LEN]
                .try_into()
                .expect("validated Noise private-key length"),
            public: bytes[MAGIC.len() + NOISE_KEY_LEN..]
                .try_into()
                .expect("validated Noise public-key length"),
        };
        keypair.validate_xx()?;
        Ok(keypair)
    };
    match private_state::read_private(path, FILE_LEN) {
        Ok(bytes) => return decode(&bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let keypair = generate_noise_keypair()?;
    let mut encoded = Vec::with_capacity(FILE_LEN);
    encoded.extend_from_slice(MAGIC);
    encoded.extend_from_slice(&keypair.private);
    encoded.extend_from_slice(&keypair.public);
    match private_state::create_private(path, &encoded) {
        Ok(()) => Ok(keypair),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            decode(&private_state::read_private(path, FILE_LEN)?)
        }
        Err(error) => Err(error.into()),
    }
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

/// Builds the initiating side of a mutual-static Noise XX handshake.
pub fn build_noise_xx_initiator(local_private_key: &[u8; NOISE_KEY_LEN]) -> Result<HandshakeState> {
    Builder::new(noise_xx_params()?)
        .local_private_key(local_private_key)
        .and_then(|builder| builder.build_initiator())
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))
}

/// Builds the responding side of a mutual-static Noise XX handshake.
pub fn build_noise_xx_responder(local_private_key: &[u8; NOISE_KEY_LEN]) -> Result<HandshakeState> {
    Builder::new(noise_xx_params()?)
        .local_private_key(local_private_key)
        .and_then(|builder| builder.build_responder())
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))
}

fn remote_noise_static(noise: &HandshakeState, role: &str) -> Result<[u8; NOISE_KEY_LEN]> {
    let key = noise
        .get_remote_static()
        .ok_or_else(|| ProtocolError::Noise(format!("Noise XX omitted {role} static key")))?;
    key.try_into()
        .map_err(|_| ProtocolError::InvalidNoiseKeyLength(key.len()))
}

/// Performs the initiating side of a mutual-static Noise XX handshake.
///
/// `verify_remote` runs after the responder proves possession of its static
/// key and before this function sends the final handshake message. Returning
/// an error therefore prevents untrusted or changed relays from completing a
/// session. The returned key is the authenticated responder static key.
///
/// # Errors
///
/// Returns an error for framing, Noise, I/O, missing remote identity, or a
/// rejected remote identity.
pub async fn initiator_handshake_xx<S, F>(
    stream: &mut S,
    local_private_key: &[u8; NOISE_KEY_LEN],
    verify_remote: F,
) -> Result<(TransportState, [u8; NOISE_KEY_LEN])>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(&[u8; NOISE_KEY_LEN]) -> Result<()>,
{
    let mut noise = build_noise_xx_initiator(local_private_key)?;
    let mut buf = vec![0u8; MAX_WIRE_PACKET_LEN];
    let len = noise
        .write_message(&[], &mut buf)
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))?;
    write_clear_frame(stream, &buf[..len]).await?;

    let message = read_clear_frame(stream).await?;
    noise
        .read_message(&message, &mut buf)
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))?;
    let remote_static = remote_noise_static(&noise, "responder")?;
    verify_remote(&remote_static)?;

    let len = noise
        .write_message(&[], &mut buf)
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))?;
    write_clear_frame(stream, &buf[..len]).await?;
    let transport = noise
        .into_transport_mode()
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))?;
    Ok((transport, remote_static))
}

/// Performs the responding side of a mutual-static Noise XX handshake.
///
/// The returned key is the authenticated initiator static key and must be
/// bound to a valid role credential before application messages are accepted.
///
/// # Errors
///
/// Returns an error for framing, Noise, I/O, or a missing remote identity.
pub async fn responder_handshake_xx<S>(
    stream: &mut S,
    local_private_key: &[u8; NOISE_KEY_LEN],
) -> Result<(TransportState, [u8; NOISE_KEY_LEN])>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut noise = build_noise_xx_responder(local_private_key)?;
    let mut buf = vec![0u8; MAX_WIRE_PACKET_LEN];
    let message = read_clear_frame(stream).await?;
    noise
        .read_message(&message, &mut buf)
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))?;

    let len = noise
        .write_message(&[], &mut buf)
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))?;
    write_clear_frame(stream, &buf[..len]).await?;

    let message = read_clear_frame(stream).await?;
    noise
        .read_message(&message, &mut buf)
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))?;
    let remote_static = remote_noise_static(&noise, "initiator")?;
    let transport = noise
        .into_transport_mode()
        .map_err(|err| ProtocolError::Noise(format!("{err:?}")))?;
    Ok((transport, remote_static))
}

/// Bounded Postcard message transport over an established Noise XX session.
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
            let segment = parse_noise_segment(&segment[..len])?;
            let total_len = segment.total_len;
            let offset = segment.offset;
            let chunk = segment.chunk;
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

#[allow(
    clippy::cast_possible_truncation,
    reason = "both lengths are refused above u32::MAX immediately below"
)]
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

/// Borrowed fields decoded from one `GCN1` Noise transport segment.
///
/// This low-level view exists for conformance testing and independent
/// implementations. [`NoiseSocket`] additionally enforces continuity,
/// consistent totals, caller allocation limits, and canonical Postcard
/// decoding across a complete segmented message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoiseSegment<'a> {
    /// Declared byte length of the complete plaintext message.
    pub total_len: usize,
    /// Byte offset at which this segment's chunk begins.
    pub offset: usize,
    /// Borrowed plaintext bytes carried by this segment.
    pub chunk: &'a [u8],
}

/// Parses the bounded header of one `GCN1` Noise transport segment.
///
/// This function rejects an incorrect magic value, a truncated header, and a
/// chunk whose offset and length exceed the declared total. It does not enforce
/// cross-segment continuity; [`NoiseSocket`] performs that stateful check.
pub fn parse_noise_segment(segment: &[u8]) -> Result<NoiseSegment<'_>> {
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
    let chunk = &segment[NOISE_SEGMENT_HEADER_LEN..];
    if offset > total_len || offset.saturating_add(chunk.len()) > total_len {
        return Err(ProtocolError::MalformedFrame);
    }
    Ok(NoiseSegment {
        total_len,
        offset,
        chunk,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_byte_sizes_are_bounded_and_support_iec_units() {
        assert_eq!(parse_human_bytes("1.5 MiB").unwrap(), 1_572_864);
        assert_eq!(parse_human_bytes("2GB").unwrap(), 2_000_000_000);
        assert!(parse_human_bytes("-1").is_err());
        assert!(parse_human_bytes("1XB").is_err());
    }

    #[test]
    fn noise_segments_reject_truncation_and_trailing_bounds() {
        assert!(parse_noise_segment(b"GCN1").is_err());
        let mut segment = noise_segment(3, 0, b"abc").unwrap();
        assert_eq!(parse_noise_segment(&segment).unwrap().chunk, b"abc");
        segment[8..12].copy_from_slice(&4u32.to_be_bytes());
        assert!(parse_noise_segment(&segment).is_err());
    }

    #[test]
    fn generated_noise_identity_validates_for_xx() {
        generate_noise_keypair().unwrap().validate_xx().unwrap();
    }
}
