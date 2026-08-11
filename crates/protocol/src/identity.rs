//! Persistent publisher and viewer application identities.

use crate::private_state::{create_private, read_private};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hpke::{Deserializable, Kem as _, Serializable, kem::X25519HkdfSha256};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, io, path::Path};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Native application-identity format version.
pub const IDENTITY_VERSION: u16 = 1;
/// Size of a native identity fingerprint in bytes.
pub const IDENTITY_ID_LEN: usize = 32;
/// Size of Ed25519 and X25519 encoded keys in bytes.
pub const IDENTITY_KEY_LEN: usize = 32;
/// Size of an Ed25519 signature in bytes.
pub const SIGNATURE_LEN: usize = 64;

const IDENTITY_FILE_MAGIC: &[u8; 5] = b"GCIK1";
const MAX_IDENTITY_FILE_LEN: usize = 256;
const SIGNATURE_PREFIX: &[u8] = b"glacialcast-signature-v1";
const IDENTITY_FINGERPRINT_PREFIX: &[u8] = b"glacialcast-identity-v1";

type Kem = X25519HkdfSha256;

/// Fixed-width Ed25519 signature with canonical Postcard serialization.
///
/// Serde does not implement fixed-array encoding above 32 elements, so this
/// value stores two consecutive 32-byte halves instead of a variable-length
/// byte vector.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignatureBytes {
    first: [u8; 32],
    second: [u8; 32],
}

impl SignatureBytes {
    /// Constructs a signature from the standard 64-byte Ed25519 encoding.
    #[must_use]
    pub fn from_bytes(bytes: [u8; SIGNATURE_LEN]) -> Self {
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        first.copy_from_slice(&bytes[..32]);
        second.copy_from_slice(&bytes[32..]);
        Self { first, second }
    }

    /// Returns the standard 64-byte Ed25519 encoding.
    #[must_use]
    pub fn to_bytes(self) -> [u8; SIGNATURE_LEN] {
        let mut bytes = [0u8; SIGNATURE_LEN];
        bytes[..32].copy_from_slice(&self.first);
        bytes[32..].copy_from_slice(&self.second);
        bytes
    }
}

/// Errors produced by native identity and signature operations.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// An identity or state file uses an unsupported version.
    #[error("unsupported identity version {0}")]
    UnsupportedVersion(u16),
    /// An encoded key is malformed or inconsistent with its public identity.
    #[error("invalid identity key material")]
    InvalidKey,
    /// A signature did not authenticate the expected domain and value.
    #[error("identity signature verification failed")]
    InvalidSignature,
    /// A canonical value could not be serialized.
    #[error("identity serialization failed: {0}")]
    Postcard(#[from] postcard::Error),
    /// Private identity state could not be read or durably written.
    #[error("identity state I/O failed: {0}")]
    Io(#[from] io::Error),
}

/// Public application identity pinned during publisher/viewer pairing.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdentityPublic {
    /// Identity format version, currently [`IDENTITY_VERSION`].
    pub version: u16,
    /// Ed25519 public key used for signed protocol claims.
    pub signing_key: [u8; IDENTITY_KEY_LEN],
    /// X25519 HPKE recipient key used for viewer key envelopes.
    pub kem_key: [u8; IDENTITY_KEY_LEN],
}

impl IdentityPublic {
    /// Validates the version and encoded public keys.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported version or malformed Ed25519 or
    /// HPKE public key.
    pub fn validate(&self) -> Result<(), IdentityError> {
        if self.version != IDENTITY_VERSION {
            return Err(IdentityError::UnsupportedVersion(self.version));
        }
        VerifyingKey::from_bytes(&self.signing_key).map_err(|_| IdentityError::InvalidKey)?;
        if self.kem_key == [0; IDENTITY_KEY_LEN] {
            return Err(IdentityError::InvalidKey);
        }
        <Kem as hpke::Kem>::PublicKey::from_bytes(&self.kem_key)
            .map_err(|_| IdentityError::InvalidKey)?;
        Ok(())
    }

    /// Returns the canonical SHA-256 identity fingerprint.
    ///
    /// # Errors
    ///
    /// Returns an error if the identity is invalid or cannot be serialized.
    pub fn id(&self) -> Result<[u8; IDENTITY_ID_LEN], IdentityError> {
        self.validate()?;
        let encoded = postcard::to_stdvec(self)?;
        let mut digest = Sha256::new();
        digest.update(IDENTITY_FINGERPRINT_PREFIX);
        digest.update(encoded);
        Ok(digest.finalize().into())
    }

    pub(crate) fn verifying_key(&self) -> Result<VerifyingKey, IdentityError> {
        self.validate()?;
        VerifyingKey::from_bytes(&self.signing_key).map_err(|_| IdentityError::InvalidKey)
    }

    pub(crate) fn kem_public_key(&self) -> Result<<Kem as hpke::Kem>::PublicKey, IdentityError> {
        self.validate()?;
        <Kem as hpke::Kem>::PublicKey::from_bytes(&self.kem_key)
            .map_err(|_| IdentityError::InvalidKey)
    }
}

#[derive(Deserialize, Serialize)]
struct StoredIdentity {
    version: u16,
    signing_secret: [u8; IDENTITY_KEY_LEN],
    kem_secret: [u8; IDENTITY_KEY_LEN],
}

/// Private native application identity.
///
/// Secret bytes are zeroized on drop and omitted from debug output. Persist
/// this value only through [`load_or_create_identity`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IdentitySecret {
    signing_secret: [u8; IDENTITY_KEY_LEN],
    kem_secret: [u8; IDENTITY_KEY_LEN],
}

impl fmt::Debug for IdentitySecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentitySecret")
            .field("signing_secret", &"[REDACTED]")
            .field("kem_secret", &"[REDACTED]")
            .finish()
    }
}

impl IdentitySecret {
    /// Imports separate Ed25519 and X25519 private keys from secure state.
    ///
    /// Callers must obtain these bytes from a private authenticated source;
    /// this function performs structural validation but cannot establish their
    /// provenance.
    ///
    /// # Errors
    ///
    /// Returns an error for all-zero or malformed key material.
    pub fn from_private_bytes(
        signing_secret: [u8; IDENTITY_KEY_LEN],
        kem_secret: [u8; IDENTITY_KEY_LEN],
    ) -> Result<Self, IdentityError> {
        if signing_secret == [0; IDENTITY_KEY_LEN] || kem_secret == [0; IDENTITY_KEY_LEN] {
            return Err(IdentityError::InvalidKey);
        }
        let identity = Self {
            signing_secret,
            kem_secret,
        };
        identity.public()?;
        Ok(identity)
    }

    /// Generates independent random Ed25519 signing and X25519 HPKE keys.
    #[must_use]
    pub fn generate() -> Self {
        let mut signing_secret = [0u8; IDENTITY_KEY_LEN];
        while signing_secret == [0; IDENTITY_KEY_LEN] {
            rand::rngs::OsRng.fill_bytes(&mut signing_secret);
        }
        let (kem_secret, _) = Kem::gen_keypair();
        let kem_secret = kem_secret
            .to_bytes()
            .as_slice()
            .try_into()
            .expect("X25519 private keys are 32 bytes");
        Self {
            signing_secret,
            kem_secret,
        }
    }

    /// Derives the public identity corresponding to these private keys.
    ///
    /// # Errors
    ///
    /// Returns an error if persisted HPKE key material is malformed.
    pub fn public(&self) -> Result<IdentityPublic, IdentityError> {
        let signing_key = SigningKey::from_bytes(&self.signing_secret)
            .verifying_key()
            .to_bytes();
        let kem_secret = <Kem as hpke::Kem>::PrivateKey::from_bytes(&self.kem_secret)
            .map_err(|_| IdentityError::InvalidKey)?;
        let kem_key = Kem::sk_to_pk(&kem_secret)
            .to_bytes()
            .as_slice()
            .try_into()
            .expect("X25519 public keys are 32 bytes");
        if kem_key == [0; IDENTITY_KEY_LEN] {
            return Err(IdentityError::InvalidKey);
        }
        Ok(IdentityPublic {
            version: IDENTITY_VERSION,
            signing_key,
            kem_key,
        })
    }

    pub(crate) fn sign<T: Serialize>(
        &self,
        domain: &[u8],
        value: &T,
    ) -> Result<SignatureBytes, IdentityError> {
        let digest = signing_digest(domain, value)?;
        Ok(SignatureBytes::from_bytes(
            SigningKey::from_bytes(&self.signing_secret)
                .sign(&digest)
                .to_bytes(),
        ))
    }

    pub(crate) fn kem_private_key(&self) -> Result<<Kem as hpke::Kem>::PrivateKey, IdentityError> {
        <Kem as hpke::Kem>::PrivateKey::from_bytes(&self.kem_secret)
            .map_err(|_| IdentityError::InvalidKey)
    }

    fn encode(&self) -> Result<Vec<u8>, IdentityError> {
        let stored = StoredIdentity {
            version: IDENTITY_VERSION,
            signing_secret: self.signing_secret,
            kem_secret: self.kem_secret,
        };
        let mut bytes = Vec::from(IDENTITY_FILE_MAGIC.as_slice());
        bytes.extend_from_slice(&postcard::to_stdvec(&stored)?);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, IdentityError> {
        let payload = bytes
            .strip_prefix(IDENTITY_FILE_MAGIC)
            .ok_or(IdentityError::InvalidKey)?;
        let (stored, remainder) = postcard::take_from_bytes::<StoredIdentity>(payload)?;
        if !remainder.is_empty() {
            return Err(IdentityError::InvalidKey);
        }
        if stored.version != IDENTITY_VERSION {
            return Err(IdentityError::UnsupportedVersion(stored.version));
        }
        if stored.signing_secret == [0; IDENTITY_KEY_LEN]
            || stored.kem_secret == [0; IDENTITY_KEY_LEN]
        {
            return Err(IdentityError::InvalidKey);
        }
        Self::from_private_bytes(stored.signing_secret, stored.kem_secret)
    }
}

pub(crate) fn verify<T: Serialize>(
    identity: &IdentityPublic,
    domain: &[u8],
    value: &T,
    signature: &SignatureBytes,
) -> Result<(), IdentityError> {
    let digest = signing_digest(domain, value)?;
    identity
        .verifying_key()?
        .verify(&digest, &Signature::from_bytes(&signature.to_bytes()))
        .map_err(|_| IdentityError::InvalidSignature)
}

pub(crate) fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, IdentityError> {
    postcard::to_stdvec(value).map_err(IdentityError::from)
}

pub(crate) fn signing_digest<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<[u8; 32], IdentityError> {
    let encoded = canonical(value)?;
    let domain_len = u16::try_from(domain.len()).map_err(|_| IdentityError::InvalidKey)?;
    let mut digest = Sha256::new();
    digest.update(SIGNATURE_PREFIX);
    digest.update(domain_len.to_be_bytes());
    digest.update(domain);
    digest.update(
        u64::try_from(encoded.len())
            .expect("usize fits in u64 on supported Linux targets")
            .to_be_bytes(),
    );
    digest.update(encoded);
    Ok(digest.finalize().into())
}

/// Loads an existing private identity or creates one at a new path.
///
/// Concurrent creators converge on the identity that won `create_new`. Existing
/// malformed, oversized, linked, symlinked, or overly permissive files fail
/// closed and are never replaced.
///
/// # Errors
///
/// Returns an error for invalid key/state encoding or an underlying private-file
/// operation failure.
pub fn load_or_create_identity(path: &Path) -> Result<IdentitySecret, IdentityError> {
    match read_private(path, MAX_IDENTITY_FILE_LEN) {
        Ok(bytes) => return IdentitySecret::decode(&bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let identity = IdentitySecret::generate();
    let encoded = identity.encode()?;
    match create_private(path, &encoded) {
        Ok(()) => Ok(identity),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let bytes = read_private(path, MAX_IDENTITY_FILE_LEN)?;
            IdentitySecret::decode(&bytes)
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    use uuid::Uuid;

    #[test]
    fn identity_signatures_are_bound_to_domain_value_and_key() {
        let first = IdentitySecret::generate();
        let second = IdentitySecret::generate();
        let value = (7u64, "viewer");
        let signature = first.sign(b"pair-request", &value).unwrap();
        verify(
            &first.public().unwrap(),
            b"pair-request",
            &value,
            &signature,
        )
        .unwrap();
        assert!(verify(&first.public().unwrap(), b"pair-offer", &value, &signature).is_err());
        assert!(
            verify(
                &first.public().unwrap(),
                b"pair-request",
                &(8u64, "viewer"),
                &signature
            )
            .is_err()
        );
        assert!(
            verify(
                &second.public().unwrap(),
                b"pair-request",
                &value,
                &signature
            )
            .is_err()
        );
    }

    #[test]
    fn persisted_identity_is_private_stable_and_canonical() {
        let root = std::env::temp_dir().join(format!("glacialcast-identity-{}", Uuid::new_v4()));
        let path = root.join("device.key");
        let created = load_or_create_identity(&path).unwrap();
        let public = created.public().unwrap();
        let loaded = load_or_create_identity(&path).unwrap();
        assert_eq!(loaded.public().unwrap(), public);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let mut bytes = read_private(&path, MAX_IDENTITY_FILE_LEN).unwrap();
        bytes.push(0);
        fs::write(&path, bytes).unwrap();
        assert!(load_or_create_identity(&path).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn persisted_identity_rejects_zero_private_keys() {
        let mut bytes = Vec::from(IDENTITY_FILE_MAGIC.as_slice());
        bytes.extend_from_slice(
            &postcard::to_stdvec(&StoredIdentity {
                version: IDENTITY_VERSION,
                signing_secret: [0; IDENTITY_KEY_LEN],
                kem_secret: [0; IDENTITY_KEY_LEN],
            })
            .unwrap(),
        );
        assert!(matches!(
            IdentitySecret::decode(&bytes),
            Err(IdentityError::InvalidKey)
        ));
    }

    #[test]
    fn identity_fingerprint_changes_with_either_public_key() {
        let first = IdentitySecret::generate().public().unwrap();
        let second = IdentitySecret::generate().public().unwrap();
        assert_ne!(first.id().unwrap(), second.id().unwrap());
        let mut changed = first;
        changed.kem_key = second.kem_key;
        assert_ne!(first.id().unwrap(), changed.id().unwrap());
    }
}
