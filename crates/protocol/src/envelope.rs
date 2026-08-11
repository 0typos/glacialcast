//! Publisher-signed HPKE envelopes for per-viewer content keys.

use crate::identity::{
    IDENTITY_KEY_LEN, IdentityError, IdentityPublic, IdentitySecret, SignatureBytes, canonical,
    verify,
};
use hpke::{
    Deserializable, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
    kem::X25519HkdfSha256, single_shot_open, single_shot_seal,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Native viewer key-envelope format version.
pub const KEY_ENVELOPE_VERSION: u16 = 1;
/// Content-encryption key size in bytes.
pub const CONTENT_KEY_LEN: usize = 32;
/// Maximum canonical encoded key-envelope length.
pub const MAX_KEY_ENVELOPE_LEN: usize = 1024;

const ENVELOPE_DOMAIN: &[u8] = b"glacialcast-key-envelope-v1";
const HPKE_INFO_PREFIX: &[u8] = b"glacialcast-hpke-content-key-v1";
const HPKE_ENCAPSULATED_KEY_LEN: usize = 32;
const HPKE_CIPHERTEXT_LEN: usize = CONTENT_KEY_LEN + 16;

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

/// Errors produced while sealing or opening viewer content-key envelopes.
#[derive(Debug, Error)]
pub enum EnvelopeError {
    /// The envelope uses an unsupported version.
    #[error("unsupported key envelope version {0}")]
    UnsupportedVersion(u16),
    /// Envelope identity, size, or key-group metadata is invalid.
    #[error("invalid key envelope metadata: {0}")]
    InvalidMetadata(&'static str),
    /// The envelope is addressed to a different viewer identity.
    #[error("key envelope recipient does not match this viewer")]
    WrongRecipient,
    /// The envelope was signed by or names a different publisher.
    #[error("key envelope publisher does not match the pinned publisher")]
    WrongPublisher,
    /// HPKE encapsulation, decapsulation, sealing, or opening failed.
    #[error("key envelope cryptography failed")]
    Hpke,
    /// An identity or publisher signature was invalid.
    #[error(transparent)]
    Identity(#[from] IdentityError),
}

/// Public routing and key-group fields authenticated by HPKE and publisher signature.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyEnvelopeHeader {
    /// Key-envelope format version.
    pub version: u16,
    /// Fingerprint of the publisher signing this envelope.
    pub publisher_id: [u8; IDENTITY_KEY_LEN],
    /// Fingerprint of the viewer allowed to open this envelope.
    pub recipient_id: [u8; IDENTITY_KEY_LEN],
    /// Stream whose content key is enclosed.
    pub stream_id: Uuid,
    /// Capture epoch containing the key group.
    pub epoch_id: Uuid,
    /// Monotonic keyframe-group number within the epoch.
    pub key_group_id: u64,
    /// Random identifier carried by encrypted stream objects in this group.
    pub key_id: [u8; 16],
}

impl KeyEnvelopeHeader {
    fn validate(&self) -> Result<(), EnvelopeError> {
        if self.version != KEY_ENVELOPE_VERSION {
            return Err(EnvelopeError::UnsupportedVersion(self.version));
        }
        if self.stream_id.is_nil() || self.epoch_id.is_nil() || self.key_group_id == 0 {
            return Err(EnvelopeError::InvalidMetadata(
                "invalid stream key-group identity",
            ));
        }
        if self.publisher_id == [0; IDENTITY_KEY_LEN]
            || self.recipient_id == [0; IDENTITY_KEY_LEN]
            || self.key_id == [0; 16]
        {
            return Err(EnvelopeError::InvalidMetadata(
                "zero identity or key identifier",
            ));
        }
        Ok(())
    }
}

/// Viewer-addressed encrypted content key signed by its publisher.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyEnvelope {
    /// Authenticated routing and key-group metadata.
    pub header: KeyEnvelopeHeader,
    /// RFC 9180 X25519 encapsulated key.
    pub encapsulated_key: [u8; HPKE_ENCAPSULATED_KEY_LEN],
    /// HPKE ChaCha20-Poly1305 ciphertext containing one 32-byte content key.
    pub ciphertext: Vec<u8>,
    /// Ed25519 signature by `header.publisher_id` over all preceding fields.
    pub publisher_signature: SignatureBytes,
}

#[derive(Serialize)]
struct UnsignedEnvelope<'a> {
    header: &'a KeyEnvelopeHeader,
    encapsulated_key: &'a [u8; HPKE_ENCAPSULATED_KEY_LEN],
    ciphertext: &'a [u8],
}

fn hpke_context(header: &KeyEnvelopeHeader) -> Result<(Vec<u8>, Vec<u8>), EnvelopeError> {
    let aad = canonical(header)?;
    let mut info = Vec::with_capacity(HPKE_INFO_PREFIX.len() + aad.len());
    info.extend_from_slice(HPKE_INFO_PREFIX);
    info.extend_from_slice(&aad);
    Ok((info, aad))
}

impl KeyEnvelope {
    /// Validates the relay-visible envelope shape without trusting its signature.
    ///
    /// Viewers and relays that know the publisher identity should additionally
    /// call [`Self::verify_public`].
    ///
    /// # Errors
    ///
    /// Returns an error for invalid header metadata or ciphertext length.
    pub fn validate_shape(&self) -> Result<(), EnvelopeError> {
        self.header.validate()?;
        if self.ciphertext.len() != HPKE_CIPHERTEXT_LEN {
            return Err(EnvelopeError::InvalidMetadata(
                "unexpected HPKE ciphertext length",
            ));
        }
        Ok(())
    }

    /// Encrypts one content key to a viewer and signs the resulting envelope.
    ///
    /// The supplied header fields are completed with the publisher and viewer
    /// fingerprints and are bound as HPKE associated data.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identity/header data, HPKE failure, or
    /// canonical serialization/signing failure.
    pub fn seal(
        publisher: &IdentitySecret,
        recipient: &IdentityPublic,
        stream_id: Uuid,
        epoch_id: Uuid,
        key_group_id: u64,
        key_id: [u8; 16],
        content_key: &[u8; CONTENT_KEY_LEN],
    ) -> Result<Self, EnvelopeError> {
        let publisher_public = publisher.public()?;
        recipient.validate()?;
        let header = KeyEnvelopeHeader {
            version: KEY_ENVELOPE_VERSION,
            publisher_id: publisher_public.id()?,
            recipient_id: recipient.id()?,
            stream_id,
            epoch_id,
            key_group_id,
            key_id,
        };
        header.validate()?;
        let (info, aad) = hpke_context(&header)?;
        let recipient_key = recipient.kem_public_key()?;
        let (encapsulated_key, ciphertext) = single_shot_seal::<Aead, Kdf, Kem>(
            &OpModeS::Base,
            &recipient_key,
            &info,
            content_key,
            &aad,
        )
        .map_err(|_| EnvelopeError::Hpke)?;
        if ciphertext.len() != HPKE_CIPHERTEXT_LEN {
            return Err(EnvelopeError::InvalidMetadata(
                "unexpected HPKE ciphertext length",
            ));
        }
        let encapsulated_key = encapsulated_key
            .to_bytes()
            .as_slice()
            .try_into()
            .expect("X25519 encapsulated keys are 32 bytes");
        let unsigned = UnsignedEnvelope {
            header: &header,
            encapsulated_key: &encapsulated_key,
            ciphertext: &ciphertext,
        };
        let publisher_signature = publisher.sign(ENVELOPE_DOMAIN, &unsigned)?;
        Ok(Self {
            header,
            encapsulated_key,
            ciphertext,
            publisher_signature,
        })
    }

    /// Verifies and opens this envelope for the intended viewer.
    ///
    /// `publisher` must be the identity pinned during pairing. Publisher
    /// signature and all identity bindings are checked before HPKE opening.
    ///
    /// # Errors
    ///
    /// Returns an error for wrong identities, malformed lengths or metadata,
    /// invalid publisher signature, or HPKE authentication failure.
    pub fn open(
        &self,
        recipient: &IdentitySecret,
        publisher: &IdentityPublic,
    ) -> Result<[u8; CONTENT_KEY_LEN], EnvelopeError> {
        self.verify_public(publisher)?;
        let recipient_public = recipient.public()?;
        if self.header.recipient_id != recipient_public.id()? {
            return Err(EnvelopeError::WrongRecipient);
        }
        let (info, aad) = hpke_context(&self.header)?;
        let private_key = recipient.kem_private_key()?;
        let encapsulated_key = <Kem as hpke::Kem>::EncappedKey::from_bytes(&self.encapsulated_key)
            .map_err(|_| EnvelopeError::Hpke)?;
        let plaintext = single_shot_open::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &private_key,
            &encapsulated_key,
            &info,
            &self.ciphertext,
            &aad,
        )
        .map_err(|_| EnvelopeError::Hpke)?;
        plaintext
            .try_into()
            .map_err(|_| EnvelopeError::InvalidMetadata("unexpected content key length"))
    }

    /// Verifies envelope shape, publisher binding, and signature without opening it.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid metadata, ciphertext length, publisher, or
    /// signature.
    pub fn verify_public(&self, publisher: &IdentityPublic) -> Result<(), EnvelopeError> {
        self.validate_shape()?;
        publisher.validate()?;
        if self.header.publisher_id != publisher.id()? {
            return Err(EnvelopeError::WrongPublisher);
        }
        let unsigned = UnsignedEnvelope {
            header: &self.header,
            encapsulated_key: &self.encapsulated_key,
            ciphertext: &self.ciphertext,
        };
        verify(
            publisher,
            ENVELOPE_DOMAIN,
            &unsigned,
            &self.publisher_signature,
        )?;
        Ok(())
    }

    /// Canonically encodes this verified envelope.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid envelope data, serialization, or bounds.
    pub fn encode(&self, publisher: &IdentityPublic) -> Result<Vec<u8>, EnvelopeError> {
        self.verify_public(publisher)?;
        let encoded = canonical(self)?;
        if encoded.len() > MAX_KEY_ENVELOPE_LEN {
            return Err(EnvelopeError::InvalidMetadata("key envelope too large"));
        }
        Ok(encoded)
    }

    /// Decodes one canonical bounded envelope and verifies its publisher claim.
    ///
    /// # Errors
    ///
    /// Returns an error for bounds, truncation, trailing/noncanonical data, or
    /// invalid metadata and signatures.
    pub fn decode(bytes: &[u8], publisher: &IdentityPublic) -> Result<Self, EnvelopeError> {
        if bytes.len() > MAX_KEY_ENVELOPE_LEN {
            return Err(EnvelopeError::InvalidMetadata("key envelope too large"));
        }
        let (envelope, remainder) = postcard::take_from_bytes::<Self>(bytes)
            .map_err(IdentityError::from)
            .map_err(EnvelopeError::from)?;
        if !remainder.is_empty() {
            return Err(EnvelopeError::InvalidMetadata("trailing key envelope data"));
        }
        envelope.verify_public(publisher)?;
        if canonical(&envelope)? != bytes {
            return Err(EnvelopeError::InvalidMetadata("noncanonical key envelope"));
        }
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(
        publisher: &IdentitySecret,
        viewer: &IdentitySecret,
    ) -> (KeyEnvelope, [u8; CONTENT_KEY_LEN]) {
        let content_key = [42; CONTENT_KEY_LEN];
        let envelope = KeyEnvelope::seal(
            publisher,
            &viewer.public().unwrap(),
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            3,
            [4; 16],
            &content_key,
        )
        .unwrap();
        (envelope, content_key)
    }

    #[test]
    fn viewer_envelope_round_trips_and_binds_every_identity() {
        let publisher = IdentitySecret::generate();
        let viewer = IdentitySecret::generate();
        let other_viewer = IdentitySecret::generate();
        let other_publisher = IdentitySecret::generate();
        let (envelope, content_key) = envelope(&publisher, &viewer);
        assert_eq!(
            envelope
                .open(&viewer, &publisher.public().unwrap())
                .unwrap(),
            content_key
        );
        assert!(
            envelope
                .open(&other_viewer, &publisher.public().unwrap())
                .is_err()
        );
        assert!(
            envelope
                .open(&viewer, &other_publisher.public().unwrap())
                .is_err()
        );
    }

    #[test]
    fn envelope_rejects_ciphertext_signature_and_group_tampering() {
        let publisher = IdentitySecret::generate();
        let viewer = IdentitySecret::generate();
        let (original, _) = envelope(&publisher, &viewer);

        let mut ciphertext = original.clone();
        ciphertext.ciphertext[0] ^= 1;
        assert!(
            ciphertext
                .open(&viewer, &publisher.public().unwrap())
                .is_err()
        );

        let mut signature = original.clone();
        let mut bytes = signature.publisher_signature.to_bytes();
        bytes[0] ^= 1;
        signature.publisher_signature = SignatureBytes::from_bytes(bytes);
        assert!(
            signature
                .open(&viewer, &publisher.public().unwrap())
                .is_err()
        );

        let mut group = original;
        group.header.key_group_id += 1;
        assert!(group.open(&viewer, &publisher.public().unwrap()).is_err());
    }
}
