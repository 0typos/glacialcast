//! Signed, end-to-end encrypted native stream objects.

use crate::identity::{
    IDENTITY_ID_LEN, IdentityError, IdentityPublic, IdentitySecret, SignatureBytes, verify,
};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Native encrypted stream-object format version.
pub const STREAM_FORMAT_VERSION: u16 = 2;
/// Timestamp clock used by every native media and cursor object.
pub const STREAM_TIMESCALE: u32 = 90_000;
/// Maximum encoded stream descriptor length.
pub const MAX_DESCRIPTOR_LEN: usize = 64 * 1024;
/// Maximum encrypted H.264 access-unit length, including the AEAD tag.
pub const MAX_MEDIA_CIPHERTEXT_LEN: usize = 16 * 1024 * 1024 + 16;
/// Maximum encrypted cursor-batch length, including the AEAD tag.
pub const MAX_CURSOR_CIPHERTEXT_LEN: usize = 4 * 1024 * 1024 + 16;
/// Maximum encrypted epoch configuration length, including the AEAD tag.
pub const MAX_EPOCH_CIPHERTEXT_LEN: usize = 1024 * 1024 + 16;
/// Maximum canonical encoded native object length.
pub const MAX_NATIVE_OBJECT_LEN: usize = MAX_MEDIA_CIPHERTEXT_LEN + 64 * 1024;
/// Content-encryption key length in bytes.
pub const CONTENT_KEY_LEN: usize = 32;
/// ChaCha20-Poly1305 nonce length in bytes.
pub const CONTENT_NONCE_LEN: usize = 12;

const DESCRIPTOR_DOMAIN: &[u8] = b"glacialcast-stream-descriptor-v2";
const OBJECT_DOMAIN: &[u8] = b"glacialcast-stream-object-v2";
const MAX_STREAM_NAME_LEN: usize = 128;
const MAX_SOURCE_LABEL_LEN: usize = 256;
const MAX_CODEC_CONFIG_LEN: usize = 64 * 1024;
const AEAD_TAG_LEN: usize = 16;

/// Errors produced by native stream encryption and validation.
#[derive(Debug, Error)]
pub enum NativeStreamError {
    /// A descriptor or object used an unsupported format version.
    #[error("unsupported native stream version {0}")]
    UnsupportedVersion(u16),
    /// A public field violated the named native-stream invariant.
    #[error("invalid native stream metadata: {0}")]
    InvalidMetadata(&'static str),
    /// A payload or canonical object exceeded its kind-specific bound.
    #[error("native stream payload exceeds its bound")]
    PayloadTooLarge,
    /// An object sequence did not strictly increase under one encryptor.
    #[error("native stream sequence did not strictly increase")]
    SequenceRegression,
    /// A signed descriptor or object claim did not verify.
    #[error("native stream signature verification failed")]
    InvalidSignature,
    /// The ciphertext hash did not match the received bytes.
    #[error("native stream ciphertext hash mismatch")]
    CiphertextHash,
    /// The object could not be authenticated or decrypted.
    #[error("native stream decryption failed")]
    Decryption,
    /// The object did not belong to the expected publisher or stream.
    #[error("native stream context mismatch")]
    WrongContext,
    /// Identity validation or signing failed.
    #[error(transparent)]
    Identity(#[from] IdentityError),
    /// Canonical Postcard encoding or decoding failed.
    #[error("native stream serialization failed: {0}")]
    Postcard(#[from] postcard::Error),
}

/// Codec carried by a native epoch or media object.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum CodecId {
    /// H.264 access units and parameter sets in Annex-B byte-stream format.
    H264AnnexB,
}

/// Kind of encrypted native object.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NativeObjectKind {
    /// Codec configuration and coded dimensions for a new epoch.
    Epoch,
    /// One timestamped encoded video access unit.
    Media,
    /// One compact cursor event batch.
    Cursor,
}

/// Public, signed metadata describing one publisher stream.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StreamDescriptorBody {
    /// Native stream format version.
    pub version: u16,
    /// Persistent publisher identity.
    pub publisher: IdentityPublic,
    /// Stable publisher-local stream identifier.
    pub stream_id: Uuid,
    /// Human-readable stream name visible to an admitted relay client.
    pub name: String,
    /// Informational capture-source label visible to the relay.
    pub source_label: String,
    /// Ordered codecs the publisher may use for this stream.
    pub codecs: Vec<CodecId>,
    /// Whether encrypted cursor objects may accompany video.
    pub cursor: bool,
    /// Descriptor creation time as Unix milliseconds.
    pub created_at_ms: i64,
}

/// Publisher-signed native stream descriptor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StreamDescriptor {
    /// Canonical descriptor fields covered by `signature`.
    pub body: StreamDescriptorBody,
    /// Ed25519 signature made by `body.publisher`.
    pub signature: SignatureBytes,
}

impl StreamDescriptor {
    /// Creates and signs one stream descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid metadata, identity, or serialization.
    pub fn new(
        publisher: &IdentitySecret,
        stream_id: Uuid,
        name: String,
        source_label: String,
        cursor: bool,
        created_at_ms: i64,
    ) -> Result<Self, NativeStreamError> {
        let body = StreamDescriptorBody {
            version: STREAM_FORMAT_VERSION,
            publisher: publisher.public()?,
            stream_id,
            name,
            source_label,
            codecs: vec![CodecId::H264AnnexB],
            cursor,
            created_at_ms,
        };
        validate_descriptor_body(&body)?;
        let signature = publisher.sign(DESCRIPTOR_DOMAIN, &body)?;
        Ok(Self { body, signature })
    }

    /// Validates the descriptor metadata and publisher signature.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed metadata or an invalid signature.
    pub fn verify(&self) -> Result<(), NativeStreamError> {
        validate_descriptor_body(&self.body)?;
        verify(
            &self.body.publisher,
            DESCRIPTOR_DOMAIN,
            &self.body,
            &self.signature,
        )
        .map_err(|error| match error {
            IdentityError::InvalidSignature => NativeStreamError::InvalidSignature,
            other => NativeStreamError::Identity(other),
        })
    }

    /// Canonically encodes this bounded descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error if validation, signing, encoding, or bounds fail.
    pub fn encode(&self) -> Result<Vec<u8>, NativeStreamError> {
        self.verify()?;
        let encoded = postcard::to_stdvec(self)?;
        if encoded.len() > MAX_DESCRIPTOR_LEN {
            return Err(NativeStreamError::PayloadTooLarge);
        }
        Ok(encoded)
    }

    /// Decodes one canonical descriptor, rejecting truncation and trailing data.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized, malformed, noncanonical, or unsigned
    /// descriptor.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeStreamError> {
        if bytes.len() > MAX_DESCRIPTOR_LEN {
            return Err(NativeStreamError::PayloadTooLarge);
        }
        let (descriptor, remainder) = postcard::take_from_bytes::<Self>(bytes)?;
        if !remainder.is_empty() {
            return Err(NativeStreamError::InvalidMetadata(
                "trailing descriptor data",
            ));
        }
        descriptor.verify()?;
        if descriptor.encode()? != bytes {
            return Err(NativeStreamError::InvalidMetadata(
                "noncanonical descriptor",
            ));
        }
        Ok(descriptor)
    }
}

fn validate_descriptor_body(body: &StreamDescriptorBody) -> Result<(), NativeStreamError> {
    if body.version != STREAM_FORMAT_VERSION {
        return Err(NativeStreamError::UnsupportedVersion(body.version));
    }
    body.publisher.validate()?;
    if body.stream_id.is_nil() {
        return Err(NativeStreamError::InvalidMetadata("nil stream ID"));
    }
    validate_label(&body.name, MAX_STREAM_NAME_LEN, "invalid stream name")?;
    validate_label(
        &body.source_label,
        MAX_SOURCE_LABEL_LEN,
        "invalid source label",
    )?;
    if body.codecs != [CodecId::H264AnnexB] {
        return Err(NativeStreamError::InvalidMetadata(
            "unsupported or duplicate codec list",
        ));
    }
    Ok(())
}

fn validate_label(value: &str, max: usize, error: &'static str) -> Result<(), NativeStreamError> {
    if value.is_empty()
        || value.len() > max
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(NativeStreamError::InvalidMetadata(error));
    }
    Ok(())
}

/// Canonical public header authenticated as AEAD associated data and signed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NativeObjectHeader {
    /// Native object format version.
    pub version: u16,
    /// Publisher identity fingerprint.
    pub publisher_id: [u8; IDENTITY_ID_LEN],
    /// Stable stream identifier.
    pub stream_id: Uuid,
    /// Capture/codec epoch identifier.
    pub epoch_id: Uuid,
    /// Keyframe-group number within the epoch.
    pub key_group: u64,
    /// Monotonic sequence across the stream.
    pub sequence: u64,
    /// Presentation timestamp in [`STREAM_TIMESCALE`] ticks.
    pub timestamp: u64,
    /// Duration in [`STREAM_TIMESCALE`] ticks.
    pub duration: u32,
    /// Encrypted payload kind.
    pub kind: NativeObjectKind,
    /// Whether this object begins independently decodable video.
    pub random_access: bool,
    /// Codec for epoch/media payloads; absent for cursors.
    pub codec: Option<CodecId>,
    /// Exact ciphertext byte length including the AEAD tag.
    pub ciphertext_len: u32,
    /// Random content-key identifier delivered in viewer envelopes.
    pub key_id: [u8; 16],
    /// Unique ChaCha20-Poly1305 nonce; its final eight bytes encode `sequence`.
    pub nonce: [u8; CONTENT_NONCE_LEN],
}

/// Fields supplied when sealing one object under an active keyframe group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewNativeObject {
    /// Monotonic stream sequence.
    pub sequence: u64,
    /// Presentation timestamp in 90 kHz ticks.
    pub timestamp: u64,
    /// Duration in 90 kHz ticks.
    pub duration: u32,
    /// Payload kind.
    pub kind: NativeObjectKind,
    /// Whether media begins with an IDR access unit.
    pub random_access: bool,
    /// Codec for epoch/media payloads.
    pub codec: Option<CodecId>,
}

#[derive(Serialize)]
struct NativeObjectClaim<'a> {
    header: &'a NativeObjectHeader,
    ciphertext_hash: &'a [u8; 32],
}

/// Signed encrypted native stream object stored opaquely by a relay.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NativeObject {
    /// Public routing, ordering, and cryptographic metadata.
    pub header: NativeObjectHeader,
    /// SHA-256 of `ciphertext` covered by `signature`.
    pub ciphertext_hash: [u8; 32],
    /// Publisher signature over the canonical header and ciphertext hash.
    pub signature: SignatureBytes,
    /// End-to-end encrypted payload; the relay never receives its key.
    pub ciphertext: Vec<u8>,
}

impl NativeObject {
    /// Validates public shape, bounds, nonce structure, and ciphertext hash.
    ///
    /// This relay-safe check does not require a publisher key and therefore
    /// does not authenticate authorship. Viewers must call [`Self::verify_public`].
    ///
    /// # Errors
    ///
    /// Returns an error for malformed metadata, length, bounds, or corruption.
    pub fn validate_shape(&self) -> Result<(), NativeStreamError> {
        validate_header(&self.header)?;
        let actual_len = usize::try_from(self.header.ciphertext_len)
            .map_err(|_| NativeStreamError::PayloadTooLarge)?;
        if self.ciphertext.len() != actual_len {
            return Err(NativeStreamError::InvalidMetadata(
                "ciphertext length mismatch",
            ));
        }
        let actual_hash: [u8; 32] = Sha256::digest(&self.ciphertext).into();
        if actual_hash != self.ciphertext_hash {
            return Err(NativeStreamError::CiphertextHash);
        }
        Ok(())
    }

    /// Validates public metadata, length, hash, publisher binding, and signature.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, substituted, corrupted, or unsigned
    /// objects. This does not decrypt the payload.
    pub fn verify_public(&self, publisher: &IdentityPublic) -> Result<(), NativeStreamError> {
        self.validate_shape()?;
        if self.header.publisher_id != publisher.id()? {
            return Err(NativeStreamError::WrongContext);
        }
        let claim = NativeObjectClaim {
            header: &self.header,
            ciphertext_hash: &self.ciphertext_hash,
        };
        verify(publisher, OBJECT_DOMAIN, &claim, &self.signature).map_err(|error| match error {
            IdentityError::InvalidSignature => NativeStreamError::InvalidSignature,
            other => NativeStreamError::Identity(other),
        })
    }

    /// Opens and validates one native payload for the expected group key.
    ///
    /// # Errors
    ///
    /// Returns an error for any public validation, key mismatch, AEAD failure,
    /// or malformed kind-specific plaintext.
    pub fn open(
        &self,
        publisher: &IdentityPublic,
        key: &ContentKey,
        expected_key_id: &[u8; 16],
    ) -> Result<Vec<u8>, NativeStreamError> {
        self.verify_public(publisher)?;
        if &self.header.key_id != expected_key_id {
            return Err(NativeStreamError::WrongContext);
        }
        let associated_data = postcard::to_stdvec(&self.header)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&self.header.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| NativeStreamError::Decryption)?;
        validate_plaintext(self.header.kind, &plaintext)?;
        if self.header.kind == NativeObjectKind::Media
            && self.header.random_access != contains_h264_idr(&plaintext)
        {
            return Err(NativeStreamError::InvalidMetadata(
                "media random-access flag does not match H.264 access unit",
            ));
        }
        Ok(plaintext)
    }

    /// Canonically encodes this object after public verification.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid signatures, metadata, hashes, or bounds.
    pub fn encode(&self, publisher: &IdentityPublic) -> Result<Vec<u8>, NativeStreamError> {
        self.verify_public(publisher)?;
        let encoded = postcard::to_stdvec(self)?;
        if encoded.len() > MAX_NATIVE_OBJECT_LEN {
            return Err(NativeStreamError::PayloadTooLarge);
        }
        Ok(encoded)
    }

    /// Decodes one canonical bounded object and verifies its public claim.
    ///
    /// # Errors
    ///
    /// Returns an error for bounds, truncation, trailing/noncanonical data,
    /// malformed metadata, corruption, or an invalid publisher signature.
    pub fn decode(bytes: &[u8], publisher: &IdentityPublic) -> Result<Self, NativeStreamError> {
        if bytes.len() > MAX_NATIVE_OBJECT_LEN {
            return Err(NativeStreamError::PayloadTooLarge);
        }
        let (object, remainder) = postcard::take_from_bytes::<Self>(bytes)?;
        if !remainder.is_empty() {
            return Err(NativeStreamError::InvalidMetadata(
                "trailing native object data",
            ));
        }
        object.verify_public(publisher)?;
        if postcard::to_stdvec(&object)? != bytes {
            return Err(NativeStreamError::InvalidMetadata(
                "noncanonical native object",
            ));
        }
        Ok(object)
    }
}

fn max_ciphertext(kind: NativeObjectKind) -> usize {
    match kind {
        NativeObjectKind::Epoch => MAX_EPOCH_CIPHERTEXT_LEN,
        NativeObjectKind::Media => MAX_MEDIA_CIPHERTEXT_LEN,
        NativeObjectKind::Cursor => MAX_CURSOR_CIPHERTEXT_LEN,
    }
}

fn validate_header(header: &NativeObjectHeader) -> Result<(), NativeStreamError> {
    if header.version != STREAM_FORMAT_VERSION {
        return Err(NativeStreamError::UnsupportedVersion(header.version));
    }
    if header.publisher_id == [0; IDENTITY_ID_LEN]
        || header.stream_id.is_nil()
        || header.epoch_id.is_nil()
        || header.key_group == 0
        || header.sequence == 0
        || header.duration == 0
        || header.key_id == [0; 16]
    {
        return Err(NativeStreamError::InvalidMetadata(
            "zero native object identifier or duration",
        ));
    }
    let nonce_sequence = u64::from_be_bytes(
        header.nonce[4..]
            .try_into()
            .map_err(|_| NativeStreamError::InvalidMetadata("invalid nonce"))?,
    );
    if nonce_sequence != header.sequence {
        return Err(NativeStreamError::InvalidMetadata(
            "nonce does not bind sequence",
        ));
    }
    let length =
        usize::try_from(header.ciphertext_len).map_err(|_| NativeStreamError::PayloadTooLarge)?;
    if length < AEAD_TAG_LEN || length > max_ciphertext(header.kind) {
        return Err(NativeStreamError::PayloadTooLarge);
    }
    match header.kind {
        NativeObjectKind::Epoch => {
            if !header.random_access || header.codec != Some(CodecId::H264AnnexB) {
                return Err(NativeStreamError::InvalidMetadata(
                    "invalid epoch codec or random-access flag",
                ));
            }
        }
        NativeObjectKind::Media => {
            if header.codec != Some(CodecId::H264AnnexB) {
                return Err(NativeStreamError::InvalidMetadata("invalid media codec"));
            }
        }
        NativeObjectKind::Cursor => {
            if header.random_access || header.codec.is_some() {
                return Err(NativeStreamError::InvalidMetadata(
                    "cursor object declares video metadata",
                ));
            }
        }
    }
    Ok(())
}

/// Decrypted H.264 epoch configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct H264EpochPayload {
    /// Coded width in pixels.
    pub width: u32,
    /// Coded height in pixels.
    pub height: u32,
    /// Annex-B SPS/PPS byte stream required before media access units.
    pub codec_config: Vec<u8>,
}

impl H264EpochPayload {
    /// Encodes validated epoch configuration for encryption.
    ///
    /// # Errors
    ///
    /// Returns an error for unusable dimensions, non-Annex-B data, or bounds.
    pub fn encode(&self) -> Result<Vec<u8>, NativeStreamError> {
        validate_epoch(self)?;
        postcard::to_stdvec(self).map_err(NativeStreamError::from)
    }

    /// Decodes one canonical epoch payload.
    ///
    /// # Errors
    ///
    /// Returns an error for truncation, trailing data, invalid dimensions, or
    /// invalid Annex-B configuration.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeStreamError> {
        let (payload, remainder) = postcard::take_from_bytes::<Self>(bytes)?;
        if !remainder.is_empty() {
            return Err(NativeStreamError::InvalidMetadata(
                "trailing epoch payload data",
            ));
        }
        validate_epoch(&payload)?;
        if postcard::to_stdvec(&payload)? != bytes {
            return Err(NativeStreamError::InvalidMetadata(
                "noncanonical epoch payload",
            ));
        }
        Ok(payload)
    }
}

fn validate_epoch(payload: &H264EpochPayload) -> Result<(), NativeStreamError> {
    if payload.width == 0
        || payload.height == 0
        || payload.width > 16_384
        || payload.height > 16_384
        || payload.codec_config.len() > MAX_CODEC_CONFIG_LEN
        || !is_annex_b(&payload.codec_config)
    {
        return Err(NativeStreamError::InvalidMetadata(
            "invalid H.264 epoch configuration",
        ));
    }
    Ok(())
}

fn is_annex_b(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0, 0, 1]) || bytes.starts_with(&[0, 0, 0, 1])
}

fn contains_h264_idr(bytes: &[u8]) -> bool {
    let mut offset = 0usize;
    while offset + 4 <= bytes.len() {
        let nal_offset = if bytes[offset..].starts_with(&[0, 0, 0, 1]) {
            Some(offset + 4)
        } else if bytes[offset..].starts_with(&[0, 0, 1]) {
            Some(offset + 3)
        } else {
            None
        };
        if let Some(nal_offset) = nal_offset
            && nal_offset < bytes.len()
            && bytes[nal_offset] & 0x1f == 5
        {
            return true;
        }
        offset += 1;
    }
    false
}

fn validate_plaintext(kind: NativeObjectKind, plaintext: &[u8]) -> Result<(), NativeStreamError> {
    if plaintext.is_empty() || plaintext.len().saturating_add(AEAD_TAG_LEN) > max_ciphertext(kind) {
        return Err(NativeStreamError::PayloadTooLarge);
    }
    match kind {
        NativeObjectKind::Epoch => {
            H264EpochPayload::decode(plaintext)?;
        }
        NativeObjectKind::Media if !is_annex_b(plaintext) => {
            return Err(NativeStreamError::InvalidMetadata(
                "media payload is not H.264 Annex-B",
            ));
        }
        NativeObjectKind::Media | NativeObjectKind::Cursor => {}
    }
    Ok(())
}

/// Zeroizing 256-bit content-encryption key for one keyframe group.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ContentKey([u8; CONTENT_KEY_LEN]);

impl ContentKey {
    /// Generates an independent nonzero content key.
    #[must_use]
    pub fn generate() -> Self {
        let mut key = [0u8; CONTENT_KEY_LEN];
        while key == [0; CONTENT_KEY_LEN] {
            rand::rngs::OsRng.fill_bytes(&mut key);
        }
        Self(key)
    }

    /// Imports a content key obtained from an authenticated viewer envelope.
    ///
    /// # Errors
    ///
    /// Returns an error for the all-zero value.
    pub fn from_bytes(bytes: [u8; CONTENT_KEY_LEN]) -> Result<Self, NativeStreamError> {
        if bytes == [0; CONTENT_KEY_LEN] {
            return Err(NativeStreamError::InvalidMetadata("zero content key"));
        }
        Ok(Self(bytes))
    }

    /// Copies the key for HPKE envelope creation or private persistence.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; CONTENT_KEY_LEN] {
        self.0
    }

    fn as_bytes(&self) -> &[u8; CONTENT_KEY_LEN] {
        &self.0
    }
}

/// Stateful object sealer that proves nonce uniqueness by sequence monotonicity.
pub struct GroupEncryptor {
    publisher_id: [u8; IDENTITY_ID_LEN],
    stream_id: Uuid,
    epoch_id: Uuid,
    key_group: u64,
    key_id: [u8; 16],
    nonce_prefix: [u8; 4],
    last_sequence: u64,
    media_started: bool,
    key: ContentKey,
}

impl GroupEncryptor {
    /// Starts a new independently keyed group.
    ///
    /// # Errors
    ///
    /// Returns an error for nil identifiers, group zero, or invalid publisher
    /// identity.
    pub fn generate(
        publisher: &IdentityPublic,
        stream_id: Uuid,
        epoch_id: Uuid,
        key_group: u64,
        prior_sequence: u64,
    ) -> Result<Self, NativeStreamError> {
        if stream_id.is_nil() || epoch_id.is_nil() || key_group == 0 {
            return Err(NativeStreamError::InvalidMetadata(
                "nil group stream or epoch identifier",
            ));
        }
        let mut key_id = [0u8; 16];
        while key_id == [0; 16] {
            rand::rngs::OsRng.fill_bytes(&mut key_id);
        }
        let mut nonce_prefix = [0u8; 4];
        rand::rngs::OsRng.fill_bytes(&mut nonce_prefix);
        Self::restore(
            publisher,
            stream_id,
            epoch_id,
            key_group,
            key_id,
            nonce_prefix,
            prior_sequence,
            false,
            ContentKey::generate().to_bytes(),
        )
    }

    /// Restores a group from publisher-only crash-safe state.
    ///
    /// The caller must persist the key, key ID, nonce prefix, and last sequence
    /// atomically. Reusing a prefix/key pair with a lower last sequence would
    /// reuse an AEAD nonce and is therefore forbidden operationally.
    ///
    /// # Errors
    ///
    /// Returns an error for nil/zero identifiers or invalid key material.
    #[allow(
        clippy::too_many_arguments,
        reason = "every cryptographic recovery invariant is explicit at this boundary"
    )]
    pub fn restore(
        publisher: &IdentityPublic,
        stream_id: Uuid,
        epoch_id: Uuid,
        key_group: u64,
        key_id: [u8; 16],
        nonce_prefix: [u8; 4],
        last_sequence: u64,
        media_started: bool,
        content_key: [u8; CONTENT_KEY_LEN],
    ) -> Result<Self, NativeStreamError> {
        if stream_id.is_nil() || epoch_id.is_nil() || key_group == 0 || key_id == [0; 16] {
            return Err(NativeStreamError::InvalidMetadata(
                "nil or zero group recovery identifier",
            ));
        }
        Ok(Self {
            publisher_id: publisher.id()?,
            stream_id,
            epoch_id,
            key_group,
            key_id,
            nonce_prefix,
            last_sequence,
            media_started,
            key: ContentKey::from_bytes(content_key)?,
        })
    }

    /// Returns the identifier paired with this group's viewer envelopes.
    #[must_use]
    pub fn key_id(&self) -> [u8; 16] {
        self.key_id
    }

    /// Copies the group key for one viewer envelope or private retained history.
    #[must_use]
    pub fn content_key(&self) -> [u8; CONTENT_KEY_LEN] {
        self.key.to_bytes()
    }

    /// Seals and signs one strictly increasing native object.
    ///
    /// # Errors
    ///
    /// Returns an error for sequence reuse/regression, malformed plaintext or
    /// metadata, oversized ciphertext, crypto, identity, or serialization.
    pub fn seal(
        &mut self,
        publisher: &IdentitySecret,
        object: NewNativeObject,
        plaintext: &[u8],
    ) -> Result<NativeObject, NativeStreamError> {
        if object.sequence <= self.last_sequence {
            return Err(NativeStreamError::SequenceRegression);
        }
        if publisher.public()?.id()? != self.publisher_id {
            return Err(NativeStreamError::WrongContext);
        }
        validate_plaintext(object.kind, plaintext)?;
        if object.kind == NativeObjectKind::Media {
            let contains_idr = contains_h264_idr(plaintext);
            if object.random_access != contains_idr || (!self.media_started && !contains_idr) {
                return Err(NativeStreamError::InvalidMetadata(
                    "keyframe group does not begin with a declared H.264 IDR",
                ));
            }
        }
        let ciphertext_len = plaintext
            .len()
            .checked_add(AEAD_TAG_LEN)
            .and_then(|length| u32::try_from(length).ok())
            .ok_or(NativeStreamError::PayloadTooLarge)?;
        let mut nonce = [0u8; CONTENT_NONCE_LEN];
        nonce[..4].copy_from_slice(&self.nonce_prefix);
        nonce[4..].copy_from_slice(&object.sequence.to_be_bytes());
        let header = NativeObjectHeader {
            version: STREAM_FORMAT_VERSION,
            publisher_id: self.publisher_id,
            stream_id: self.stream_id,
            epoch_id: self.epoch_id,
            key_group: self.key_group,
            sequence: object.sequence,
            timestamp: object.timestamp,
            duration: object.duration,
            kind: object.kind,
            random_access: object.random_access,
            codec: object.codec,
            ciphertext_len,
            key_id: self.key_id,
            nonce,
        };
        validate_header(&header)?;
        let associated_data = postcard::to_stdvec(&header)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(self.key.as_bytes()));
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| NativeStreamError::Decryption)?;
        let ciphertext_hash: [u8; 32] = Sha256::digest(&ciphertext).into();
        let claim = NativeObjectClaim {
            header: &header,
            ciphertext_hash: &ciphertext_hash,
        };
        let signature = publisher.sign(OBJECT_DOMAIN, &claim)?;
        self.last_sequence = object.sequence;
        if object.kind == NativeObjectKind::Media {
            self.media_started = true;
        }
        Ok(NativeObject {
            header,
            ciphertext_hash,
            signature,
            ciphertext,
        })
    }
}

/// Monotonic live-tail guard preventing old signed objects from appearing live.
#[derive(Clone, Debug)]
pub struct LiveSequenceGuard {
    publisher_id: [u8; IDENTITY_ID_LEN],
    stream_id: Uuid,
    last_sequence: u64,
}

impl LiveSequenceGuard {
    /// Creates a live guard at an explicitly trusted subscription anchor.
    #[must_use]
    pub fn new(publisher_id: [u8; IDENTITY_ID_LEN], stream_id: Uuid, anchor_sequence: u64) -> Self {
        Self {
            publisher_id,
            stream_id,
            last_sequence: anchor_sequence,
        }
    }

    /// Accepts only the expected stream and a strictly newer sequence.
    ///
    /// # Errors
    ///
    /// Returns an error for cross-stream substitution, duplicates, or replay.
    pub fn accept(&mut self, object: &NativeObject) -> Result<(), NativeStreamError> {
        if object.header.publisher_id != self.publisher_id
            || object.header.stream_id != self.stream_id
        {
            return Err(NativeStreamError::WrongContext);
        }
        if object.header.sequence <= self.last_sequence {
            return Err(NativeStreamError::SequenceRegression);
        }
        self.last_sequence = object.header.sequence;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    fn media(sequence: u64, random_access: bool) -> NewNativeObject {
        NewNativeObject {
            sequence,
            timestamp: sequence * u64::from(STREAM_TIMESCALE),
            duration: STREAM_TIMESCALE,
            kind: NativeObjectKind::Media,
            random_access,
            codec: Some(CodecId::H264AnnexB),
        }
    }

    #[test]
    fn descriptor_round_trip_rejects_tampering_and_trailing_data() {
        let publisher = IdentitySecret::generate();
        let descriptor = StreamDescriptor::new(
            &publisher,
            Uuid::from_u128(1),
            "primary".into(),
            "DP-1".into(),
            true,
            1_000,
        )
        .unwrap();
        let encoded = descriptor.encode().unwrap();
        assert_eq!(StreamDescriptor::decode(&encoded).unwrap(), descriptor);
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(StreamDescriptor::decode(&trailing).is_err());
        let mut tampered = descriptor;
        tampered.body.name = "other".into();
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn encrypted_object_round_trip_binds_every_context_field() {
        let publisher = IdentitySecret::generate();
        let public = publisher.public().unwrap();
        let stream_id = Uuid::from_u128(1);
        let epoch_id = Uuid::from_u128(2);
        let mut group = GroupEncryptor::generate(&public, stream_id, epoch_id, 1, 0).unwrap();
        let key = ContentKey::from_bytes(group.content_key()).unwrap();
        let key_id = group.key_id();
        let object = group
            .seal(&publisher, media(1, true), &[0, 0, 0, 1, 0x65, 1, 2])
            .unwrap();
        assert_eq!(
            object.open(&public, &key, &key_id).unwrap(),
            [0, 0, 0, 1, 0x65, 1, 2]
        );
        let encoded = object.encode(&public).unwrap();
        assert_eq!(NativeObject::decode(&encoded, &public).unwrap(), object);
        for end in 0..encoded.len() {
            assert!(NativeObject::decode(&encoded[..end], &public).is_err());
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(NativeObject::decode(&trailing, &public).is_err());

        for mutate in [
            |header: &mut NativeObjectHeader| header.stream_id = Uuid::from_u128(3),
            |header: &mut NativeObjectHeader| header.epoch_id = Uuid::from_u128(3),
            |header: &mut NativeObjectHeader| header.key_group = 2,
            |header: &mut NativeObjectHeader| header.timestamp += 1,
        ] {
            let mut changed = object.clone();
            mutate(&mut changed.header);
            assert!(changed.open(&public, &key, &key_id).is_err());
        }
        let mut changed = object.clone();
        changed.ciphertext[0] ^= 1;
        assert!(changed.open(&public, &key, &key_id).is_err());
    }

    #[test]
    fn group_encryptor_refuses_nonce_reuse_and_invalid_payload_kinds() {
        let publisher = IdentitySecret::generate();
        let public = publisher.public().unwrap();
        let mut non_idr_group =
            GroupEncryptor::generate(&public, Uuid::from_u128(3), Uuid::from_u128(4), 1, 0)
                .unwrap();
        assert!(
            non_idr_group
                .seal(&publisher, media(1, false), &[0, 0, 1, 0x41])
                .is_err()
        );
        let mut group =
            GroupEncryptor::generate(&public, Uuid::from_u128(1), Uuid::from_u128(2), 1, 0)
                .unwrap();
        group
            .seal(&publisher, media(1, true), &[0, 0, 1, 0x65])
            .unwrap();
        assert!(matches!(
            group.seal(&publisher, media(1, true), &[0, 0, 1, 0x65]),
            Err(NativeStreamError::SequenceRegression)
        ));
        assert!(
            group
                .seal(&publisher, media(2, false), b"not-annex-b")
                .is_err()
        );
    }

    #[test]
    fn live_guard_rejects_duplicates_replay_and_cross_stream_objects() {
        let publisher = IdentitySecret::generate();
        let public = publisher.public().unwrap();
        let publisher_id = public.id().unwrap();
        let stream_id = Uuid::from_u128(1);
        let mut group =
            GroupEncryptor::generate(&public, stream_id, Uuid::from_u128(2), 1, 9).unwrap();
        let object = group
            .seal(&publisher, media(10, true), &[0, 0, 1, 0x65])
            .unwrap();
        let mut guard = LiveSequenceGuard::new(publisher_id, stream_id, 9);
        guard.accept(&object).unwrap();
        assert!(guard.accept(&object).is_err());
        let mut substituted = object;
        substituted.header.stream_id = Uuid::from_u128(3);
        assert!(
            LiveSequenceGuard::new(publisher_id, stream_id, 9)
                .accept(&substituted)
                .is_err()
        );
    }

    #[test]
    fn epoch_payload_rejects_truncation_trailing_and_non_annex_b() {
        let epoch = H264EpochPayload {
            width: 1920,
            height: 1080,
            codec_config: vec![0, 0, 0, 1, 0x67],
        };
        let encoded = epoch.encode().unwrap();
        assert_eq!(H264EpochPayload::decode(&encoded).unwrap(), epoch);
        for end in 0..encoded.len() {
            assert!(H264EpochPayload::decode(&encoded[..end]).is_err());
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(H264EpochPayload::decode(&trailing).is_err());
        assert!(
            H264EpochPayload {
                width: 1,
                height: 1,
                codec_config: vec![1, 2, 3],
            }
            .encode()
            .is_err()
        );
    }

    #[test]
    fn native_v8_golden_vector_is_stable_and_decodable() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/protocol-v8.json")).unwrap();
        let publisher = IdentitySecret::from_private_bytes([1; 32], [2; 32]).unwrap();
        let public = publisher.public().unwrap();
        let descriptor = StreamDescriptor::new(
            &publisher,
            Uuid::from_u128(1),
            "screen".into(),
            "DP-1".into(),
            true,
            1_000,
        )
        .unwrap();
        let mut group = GroupEncryptor::restore(
            &public,
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            1,
            [4; 16],
            [5; 4],
            0,
            false,
            [3; 32],
        )
        .unwrap();
        let object = group
            .seal(&publisher, media(1, true), &[0, 0, 1, 0x65, 1, 2])
            .unwrap();
        assert_eq!(vector["schema"], "glacialcast-native-protocol-golden-v1");
        assert_eq!(vector["protocol_version"], crate::PROTOCOL_VERSION);
        assert_eq!(vector["stream_format_version"], STREAM_FORMAT_VERSION);
        assert_eq!(
            vector["descriptor_b64"].as_str().unwrap(),
            URL_SAFE_NO_PAD.encode(descriptor.encode().unwrap())
        );
        assert_eq!(
            vector["native_object_b64"].as_str().unwrap(),
            URL_SAFE_NO_PAD.encode(object.encode(&public).unwrap())
        );
        let encoded_descriptor = URL_SAFE_NO_PAD
            .decode(vector["descriptor_b64"].as_str().unwrap())
            .unwrap();
        StreamDescriptor::decode(&encoded_descriptor).unwrap();
        let encoded_object = URL_SAFE_NO_PAD
            .decode(vector["native_object_b64"].as_str().unwrap())
            .unwrap();
        NativeObject::decode(&encoded_object, &public).unwrap();
    }
}
