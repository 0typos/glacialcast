//! GlacialCast-native role credentials and signed revocation lists.

use crate::{
    entropy,
    identity::{
        IDENTITY_KEY_LEN, IdentityError, IdentityPublic, IdentitySecret, SignatureBytes,
        signing_digest, verify,
    },
    private_state::{create_private, read_private},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, io, path::Path};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Native credential and revocation-list format version.
pub const CREDENTIAL_VERSION: u16 = 1;
/// Maximum UTF-8 length of a credential subject or request label.
pub const MAX_CREDENTIAL_SUBJECT_LEN: usize = 128;
/// Maximum serials accepted in one signed revocation list.
pub const MAX_REVOKED_SERIALS: usize = 16_384;

const REQUEST_DOMAIN: &[u8] = b"glacialcast-credential-request-v1";
const CREDENTIAL_DOMAIN: &[u8] = b"glacialcast-native-credential-v1";
const REVOCATION_DOMAIN: &[u8] = b"glacialcast-native-crl-v1";
const AUTHORITY_ID_DOMAIN: &[u8] = b"glacialcast-native-ca-v1";
const AUTHORITY_FILE_MAGIC: &[u8; 5] = b"GCCA1";
const MAX_AUTHORITY_FILE_LEN: usize = 128;
const CLOCK_SKEW_MS: i64 = 5 * 60 * 1_000;
const MAX_CREDENTIAL_LIFETIME_MS: i64 = 10 * 366 * 24 * 60 * 60 * 1_000;

/// Role authorized by a native relay credential.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CredentialRole {
    /// May authenticate to the relay's publisher endpoint.
    Publisher,
    /// May authenticate to the relay's viewer endpoint.
    Viewer,
}

/// Errors produced by native credential operations.
#[derive(Debug, Error)]
pub enum CredentialError {
    /// A credential structure used an unsupported version.
    #[error("unsupported native credential version {0}")]
    UnsupportedVersion(u16),
    /// A subject, time range, request lifetime, key, or sorted-set invariant failed.
    #[error("invalid native credential metadata: {0}")]
    InvalidMetadata(&'static str),
    /// A request or credential signature was invalid.
    #[error("native credential signature verification failed")]
    InvalidSignature,
    /// The credential was signed by a different authority.
    #[error("native credential issuer does not match the configured authority")]
    WrongIssuer,
    /// The credential role did not authorize this endpoint.
    #[error("native credential has the wrong role")]
    WrongRole,
    /// The credential is not valid yet.
    #[error("native credential is not valid yet")]
    NotYetValid,
    /// The credential or request has expired.
    #[error("native credential has expired")]
    Expired,
    /// The credential is present in a valid signed revocation list.
    #[error("native credential has been revoked")]
    Revoked,
    /// The credential does not bind the Noise static key used by this session.
    #[error("native credential does not match the Noise session key")]
    WrongNoiseKey,
    /// An embedded application identity was invalid.
    #[error(transparent)]
    Identity(#[from] IdentityError),
    /// A native credential value could not be encoded or decoded.
    #[error("native credential serialization failed: {0}")]
    Postcard(#[from] postcard::Error),
    /// Private CA state could not be read or durably written.
    #[error("native CA state I/O failed: {0}")]
    Io(#[from] io::Error),
}

fn validate_subject(subject: &str) -> Result<(), CredentialError> {
    if subject.is_empty()
        || subject.len() > MAX_CREDENTIAL_SUBJECT_LEN
        || subject.trim() != subject
        || subject.chars().any(char::is_control)
    {
        return Err(CredentialError::InvalidMetadata("invalid subject"));
    }
    Ok(())
}

fn validate_time_range(not_before_ms: i64, not_after_ms: i64) -> Result<(), CredentialError> {
    let lifetime = not_after_ms
        .checked_sub(not_before_ms)
        .ok_or(CredentialError::InvalidMetadata("validity range overflows"))?;
    if lifetime <= 0 || lifetime > MAX_CREDENTIAL_LIFETIME_MS {
        return Err(CredentialError::InvalidMetadata("invalid validity range"));
    }
    Ok(())
}

/// Public certificate-authority identity configured at a relay or publisher.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertificateAuthorityPublic {
    /// Native credential format version.
    pub version: u16,
    /// Ed25519 public key that signs credentials and revocation lists.
    pub signing_key: [u8; IDENTITY_KEY_LEN],
}

impl CertificateAuthorityPublic {
    /// Validates and fingerprints this authority.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported version or malformed public key.
    pub fn id(&self) -> Result<[u8; 32], CredentialError> {
        if self.version != CREDENTIAL_VERSION {
            return Err(CredentialError::UnsupportedVersion(self.version));
        }
        VerifyingKey::from_bytes(&self.signing_key)
            .map_err(|_| CredentialError::InvalidMetadata("invalid CA public key"))?;
        let encoded = postcard::to_stdvec(self)?;
        let mut digest = Sha256::new();
        digest.update(AUTHORITY_ID_DOMAIN);
        digest.update(encoded);
        Ok(digest.finalize().into())
    }

    fn verifying_key(&self) -> Result<VerifyingKey, CredentialError> {
        self.id()?;
        VerifyingKey::from_bytes(&self.signing_key)
            .map_err(|_| CredentialError::InvalidMetadata("invalid CA public key"))
    }

    /// Encodes the non-secret authority value canonically.
    ///
    /// # Errors
    ///
    /// Returns an error if the public key is invalid or serialization fails.
    pub fn encode(&self) -> Result<Vec<u8>, CredentialError> {
        self.id()?;
        postcard::to_stdvec(self).map_err(CredentialError::from)
    }

    /// Decodes one canonical non-secret authority value.
    ///
    /// # Errors
    ///
    /// Returns an error for truncation, trailing data, an unsupported version,
    /// or malformed public key.
    pub fn decode(bytes: &[u8]) -> Result<Self, CredentialError> {
        let (authority, remainder) =
            postcard::take_from_bytes::<CertificateAuthorityPublic>(bytes)?;
        if !remainder.is_empty() {
            return Err(CredentialError::InvalidMetadata("trailing CA data"));
        }
        authority.id()?;
        Ok(authority)
    }
}

/// Offline Ed25519 authority used to issue native credentials.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CertificateAuthoritySecret {
    signing_secret: [u8; IDENTITY_KEY_LEN],
}

impl fmt::Debug for CertificateAuthoritySecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertificateAuthoritySecret")
            .field("signing_secret", &"[REDACTED]")
            .finish()
    }
}

impl CertificateAuthoritySecret {
    /// Generates a random Ed25519 certificate authority.
    #[must_use]
    pub fn generate() -> Self {
        let signing_secret = entropy::random_nonzero();
        Self { signing_secret }
    }

    /// Returns the public authority value safe to install at a relay.
    #[must_use]
    pub fn public(&self) -> CertificateAuthorityPublic {
        CertificateAuthorityPublic {
            version: CREDENTIAL_VERSION,
            signing_key: SigningKey::from_bytes(&self.signing_secret)
                .verifying_key()
                .to_bytes(),
        }
    }

    fn sign<T: Serialize>(
        &self,
        domain: &[u8],
        value: &T,
    ) -> Result<SignatureBytes, CredentialError> {
        let digest = signing_digest(domain, value)?;
        Ok(SignatureBytes::from_bytes(
            SigningKey::from_bytes(&self.signing_secret)
                .sign(&digest)
                .to_bytes(),
        ))
    }

    /// Issues a credential from a valid proof-of-possession request.
    ///
    /// `not_after_ms` is an absolute Unix timestamp in milliseconds. The
    /// resulting credential begins at `now_ms` and is bound to the request's
    /// role, identity, subject, and Noise static key.
    ///
    /// # Errors
    ///
    /// Returns an error if the request is invalid or expired, the requested
    /// certificate validity is unsafe, or signing/serialization fails.
    pub fn issue(
        &self,
        request: &CredentialRequest,
        now_ms: i64,
        not_after_ms: i64,
        max_request_lifetime_ms: i64,
    ) -> Result<NativeCredential, CredentialError> {
        request.verify(now_ms, max_request_lifetime_ms)?;
        validate_time_range(now_ms, not_after_ms)?;
        let serial = entropy::random_nonzero();
        let body = NativeCredentialBody {
            version: CREDENTIAL_VERSION,
            issuer_id: self.public().id()?,
            serial,
            request_id: request.id()?,
            subject: request.body.subject.clone(),
            role: request.body.role,
            not_before_ms: now_ms,
            not_after_ms,
            noise_static_key: request.body.noise_static_key,
            identity: request.body.identity,
        };
        let signature = self.sign(CREDENTIAL_DOMAIN, &body)?;
        Ok(NativeCredential { body, signature })
    }

    /// Signs a canonical, sorted revocation list.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid validity range, too many serials,
    /// duplicate serials, or serialization/signing failure.
    pub fn sign_revocations(
        &self,
        generated_at_ms: i64,
        expires_at_ms: i64,
        mut serials: Vec<[u8; 16]>,
    ) -> Result<RevocationList, CredentialError> {
        validate_time_range(generated_at_ms, expires_at_ms)?;
        if serials.len() > MAX_REVOKED_SERIALS {
            return Err(CredentialError::InvalidMetadata("too many revoked serials"));
        }
        serials.sort_unstable();
        if serials.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CredentialError::InvalidMetadata("duplicate revoked serial"));
        }
        let body = RevocationListBody {
            version: CREDENTIAL_VERSION,
            issuer_id: self.public().id()?,
            generated_at_ms,
            expires_at_ms,
            serials,
        };
        let signature = self.sign(REVOCATION_DOMAIN, &body)?;
        Ok(RevocationList { body, signature })
    }

    fn encode(&self) -> Result<Vec<u8>, CredentialError> {
        let mut encoded = Vec::from(AUTHORITY_FILE_MAGIC.as_slice());
        encoded.extend_from_slice(&postcard::to_stdvec(&(
            CREDENTIAL_VERSION,
            self.signing_secret,
        ))?);
        Ok(encoded)
    }

    fn decode(bytes: &[u8]) -> Result<Self, CredentialError> {
        let payload = bytes
            .strip_prefix(AUTHORITY_FILE_MAGIC)
            .ok_or(CredentialError::InvalidMetadata("invalid CA file magic"))?;
        let ((version, signing_secret), remainder) =
            postcard::take_from_bytes::<(u16, [u8; IDENTITY_KEY_LEN])>(payload)?;
        if !remainder.is_empty() {
            return Err(CredentialError::InvalidMetadata("trailing CA key data"));
        }
        if version != CREDENTIAL_VERSION {
            return Err(CredentialError::UnsupportedVersion(version));
        }
        if signing_secret == [0; IDENTITY_KEY_LEN] {
            return Err(CredentialError::InvalidMetadata("zero CA private key"));
        }
        let authority = Self { signing_secret };
        authority.public().id()?;
        Ok(authority)
    }
}

/// Creates a new offline CA private-key file, refusing an existing path.
///
/// # Errors
///
/// Returns an error for invalid output paths or any create, write, or sync
/// failure. Existing files are never replaced.
pub fn create_certificate_authority(
    path: &Path,
) -> Result<CertificateAuthorityPublic, CredentialError> {
    let authority = CertificateAuthoritySecret::generate();
    create_private(path, &authority.encode()?)?;
    Ok(authority.public())
}

/// Loads one private offline certificate authority.
///
/// # Errors
///
/// Returns an error for unsafe file metadata, malformed key data, unsupported
/// versions, or I/O failure.
pub fn load_certificate_authority(
    path: &Path,
) -> Result<CertificateAuthoritySecret, CredentialError> {
    CertificateAuthoritySecret::decode(&read_private(path, MAX_AUTHORITY_FILE_LEN)?)
}

/// Signed proof-of-possession request submitted to an offline CA.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CredentialRequest {
    /// Canonical request fields covered by `signature`.
    pub body: CredentialRequestBody,
    /// Ed25519 signature made by `body.identity`.
    pub signature: SignatureBytes,
}

/// Canonical fields in a native credential request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CredentialRequestBody {
    /// Native credential format version.
    pub version: u16,
    /// Human-readable device subject shown to operators.
    pub subject: String,
    /// Requested relay role.
    pub role: CredentialRole,
    /// Noise static public key the issued credential must bind.
    pub noise_static_key: [u8; IDENTITY_KEY_LEN],
    /// Application signing and key-encapsulation identity.
    pub identity: IdentityPublic,
    /// Random request nonce preventing accidental duplicate requests.
    pub nonce: [u8; 16],
    /// Request creation time as Unix milliseconds.
    pub issued_at_ms: i64,
    /// Request expiry as Unix milliseconds.
    pub expires_at_ms: i64,
}

impl CredentialRequest {
    /// Encodes this proof-of-possession request canonically.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization fails.
    pub fn encode(&self) -> Result<Vec<u8>, CredentialError> {
        postcard::to_stdvec(self).map_err(CredentialError::from)
    }

    /// Decodes a canonical request and rejects trailing bytes.
    ///
    /// Freshness is checked separately by [`Self::verify`].
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, trailing, or non-canonical input.
    pub fn decode(bytes: &[u8]) -> Result<Self, CredentialError> {
        let (request, remainder) = postcard::take_from_bytes::<Self>(bytes)?;
        if !remainder.is_empty() || request.encode()? != bytes {
            return Err(CredentialError::InvalidMetadata(
                "trailing or non-canonical credential request",
            ));
        }
        Ok(request)
    }

    /// Creates and signs a native credential request.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid subject, Noise key, validity range, identity,
    /// or serialization/signing failure.
    pub fn new(
        identity: &IdentitySecret,
        subject: String,
        role: CredentialRole,
        noise_static_key: [u8; IDENTITY_KEY_LEN],
        issued_at_ms: i64,
        expires_at_ms: i64,
    ) -> Result<Self, CredentialError> {
        validate_subject(&subject)?;
        validate_time_range(issued_at_ms, expires_at_ms)?;
        if noise_static_key == [0; IDENTITY_KEY_LEN] {
            return Err(CredentialError::InvalidMetadata("zero Noise static key"));
        }
        let nonce = entropy::random_nonzero();
        let body = CredentialRequestBody {
            version: CREDENTIAL_VERSION,
            subject,
            role,
            noise_static_key,
            identity: identity.public()?,
            nonce,
            issued_at_ms,
            expires_at_ms,
        };
        let signature = identity.sign(REQUEST_DOMAIN, &body)?;
        Ok(Self { body, signature })
    }

    /// Validates proof of possession, metadata, freshness, and lifetime.
    ///
    /// `max_lifetime_ms` is the caller's configured request-expiration ceiling.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, future, expired, overlong, or incorrectly
    /// signed requests.
    pub fn verify(&self, now_ms: i64, max_lifetime_ms: i64) -> Result<(), CredentialError> {
        if self.body.version != CREDENTIAL_VERSION {
            return Err(CredentialError::UnsupportedVersion(self.body.version));
        }
        validate_subject(&self.body.subject)?;
        self.body.identity.validate()?;
        if self.body.noise_static_key == [0; IDENTITY_KEY_LEN] || self.body.nonce == [0; 16] {
            return Err(CredentialError::InvalidMetadata(
                "zero Noise static key or request nonce",
            ));
        }
        validate_time_range(self.body.issued_at_ms, self.body.expires_at_ms)?;
        let lifetime = self
            .body
            .expires_at_ms
            .checked_sub(self.body.issued_at_ms)
            .ok_or(CredentialError::InvalidMetadata(
                "request lifetime overflows",
            ))?;
        if max_lifetime_ms <= 0 || lifetime > max_lifetime_ms {
            return Err(CredentialError::InvalidMetadata(
                "request lifetime exceeds policy",
            ));
        }
        if self.body.issued_at_ms > now_ms.saturating_add(CLOCK_SKEW_MS) {
            return Err(CredentialError::NotYetValid);
        }
        if self.body.expires_at_ms <= now_ms {
            return Err(CredentialError::Expired);
        }
        verify(
            &self.body.identity,
            REQUEST_DOMAIN,
            &self.body,
            &self.signature,
        )
        .map_err(|error| match error {
            IdentityError::InvalidSignature => CredentialError::InvalidSignature,
            other => CredentialError::Identity(other),
        })
    }

    /// Returns the signed request's canonical SHA-256 identifier.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical serialization fails.
    pub fn id(&self) -> Result<[u8; 32], CredentialError> {
        let encoded = postcard::to_stdvec(self)?;
        Ok(Sha256::digest(encoded).into())
    }
}

/// Native role credential presented after a Noise XX handshake.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NativeCredential {
    /// Canonical credential fields covered by `signature`.
    pub body: NativeCredentialBody,
    /// Ed25519 issuer signature.
    pub signature: SignatureBytes,
}

/// Canonical fields in a native role credential.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NativeCredentialBody {
    /// Native credential format version.
    pub version: u16,
    /// SHA-256 identifier of the issuing authority.
    pub issuer_id: [u8; 32],
    /// Unique revocable credential serial.
    pub serial: [u8; 16],
    /// Identifier of the signed request from which this was issued.
    pub request_id: [u8; 32],
    /// Human-readable subject.
    pub subject: String,
    /// Relay role granted to this identity.
    pub role: CredentialRole,
    /// First valid Unix timestamp in milliseconds.
    pub not_before_ms: i64,
    /// Exclusive expiry Unix timestamp in milliseconds.
    pub not_after_ms: i64,
    /// Noise XX static public key this credential authenticates.
    pub noise_static_key: [u8; IDENTITY_KEY_LEN],
    /// Application signing and key-encapsulation identity.
    pub identity: IdentityPublic,
}

impl NativeCredential {
    /// Encodes this credential canonically for a private credential file.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization fails.
    pub fn encode(&self) -> Result<Vec<u8>, CredentialError> {
        postcard::to_stdvec(self).map_err(CredentialError::from)
    }

    /// Decodes a canonical credential and rejects trailing data.
    ///
    /// Issuer and time validation is performed by [`Self::verify_at`].
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, trailing, or non-canonical data.
    pub fn decode(bytes: &[u8]) -> Result<Self, CredentialError> {
        let (credential, remainder) = postcard::take_from_bytes::<Self>(bytes)?;
        if !remainder.is_empty() || credential.encode()? != bytes {
            return Err(CredentialError::InvalidMetadata(
                "trailing or non-canonical credential data",
            ));
        }
        Ok(credential)
    }

    /// Verifies issuer, signature, role, session key, validity, and revocation.
    ///
    /// # Errors
    ///
    /// Returns an error when any credential invariant or expected binding does
    /// not match. A supplied revocation list must itself be valid and current.
    pub fn verify_at(
        &self,
        authority: &CertificateAuthorityPublic,
        revocations: Option<&RevocationList>,
        expected_role: CredentialRole,
        noise_static_key: &[u8; IDENTITY_KEY_LEN],
        now_ms: i64,
    ) -> Result<(), CredentialError> {
        if self.body.version != CREDENTIAL_VERSION {
            return Err(CredentialError::UnsupportedVersion(self.body.version));
        }
        validate_subject(&self.body.subject)?;
        validate_time_range(self.body.not_before_ms, self.body.not_after_ms)?;
        self.body.identity.validate()?;
        if self.body.request_id == [0; 32]
            || self.body.serial == [0; 16]
            || self.body.noise_static_key == [0; IDENTITY_KEY_LEN]
        {
            return Err(CredentialError::InvalidMetadata(
                "zero request, serial, or Noise identity",
            ));
        }
        if self.body.issuer_id != authority.id()? {
            return Err(CredentialError::WrongIssuer);
        }
        let digest = signing_digest(CREDENTIAL_DOMAIN, &self.body)?;
        authority
            .verifying_key()?
            .verify(&digest, &Signature::from_bytes(&self.signature.to_bytes()))
            .map_err(|_| CredentialError::InvalidSignature)?;
        if self.body.role != expected_role {
            return Err(CredentialError::WrongRole);
        }
        if &self.body.noise_static_key != noise_static_key {
            return Err(CredentialError::WrongNoiseKey);
        }
        if now_ms < self.body.not_before_ms {
            return Err(CredentialError::NotYetValid);
        }
        if now_ms >= self.body.not_after_ms {
            return Err(CredentialError::Expired);
        }
        if let Some(revocations) = revocations {
            revocations.verify_at(authority, now_ms)?;
            if revocations
                .body
                .serials
                .binary_search(&self.body.serial)
                .is_ok()
            {
                return Err(CredentialError::Revoked);
            }
        }
        Ok(())
    }
}

/// Signed canonical credential revocation list.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevocationList {
    /// Canonical revocation fields covered by `signature`.
    pub body: RevocationListBody,
    /// Ed25519 issuer signature.
    pub signature: SignatureBytes,
}

/// Canonical fields in a native credential revocation list.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevocationListBody {
    /// Native credential format version.
    pub version: u16,
    /// SHA-256 identifier of the issuing authority.
    pub issuer_id: [u8; 32],
    /// Revocation-list creation time as Unix milliseconds.
    pub generated_at_ms: i64,
    /// Exclusive expiry as Unix milliseconds.
    pub expires_at_ms: i64,
    /// Sorted, unique revoked credential serials.
    pub serials: Vec<[u8; 16]>,
}

impl RevocationList {
    /// Encodes this signed list in its canonical native representation.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization fails.
    pub fn encode(&self) -> Result<Vec<u8>, CredentialError> {
        postcard::to_stdvec(self).map_err(CredentialError::from)
    }

    /// Decodes a canonical signed list and rejects trailing bytes.
    ///
    /// Signature and time validity are checked separately by [`Self::verify_at`].
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, non-canonical, or trailing data.
    pub fn decode(bytes: &[u8]) -> Result<Self, CredentialError> {
        let (list, remainder) = postcard::take_from_bytes::<Self>(bytes)?;
        if !remainder.is_empty() {
            return Err(CredentialError::InvalidMetadata(
                "trailing revocation-list data",
            ));
        }
        if list.encode()? != bytes {
            return Err(CredentialError::InvalidMetadata(
                "non-canonical revocation-list data",
            ));
        }
        Ok(list)
    }

    /// Verifies issuer, signature, validity, bounds, and sorted-set invariants.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid or stale list.
    pub fn verify_at(
        &self,
        authority: &CertificateAuthorityPublic,
        now_ms: i64,
    ) -> Result<(), CredentialError> {
        if self.body.version != CREDENTIAL_VERSION {
            return Err(CredentialError::UnsupportedVersion(self.body.version));
        }
        validate_time_range(self.body.generated_at_ms, self.body.expires_at_ms)?;
        if self.body.serials.len() > MAX_REVOKED_SERIALS {
            return Err(CredentialError::InvalidMetadata("too many revoked serials"));
        }
        if self.body.serials.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(CredentialError::InvalidMetadata(
                "revoked serials are not sorted and unique",
            ));
        }
        if self.body.issuer_id != authority.id()? {
            return Err(CredentialError::WrongIssuer);
        }
        let digest = signing_digest(REVOCATION_DOMAIN, &self.body)?;
        authority
            .verifying_key()?
            .verify(&digest, &Signature::from_bytes(&self.signature.to_bytes()))
            .map_err(|_| CredentialError::InvalidSignature)?;
        if now_ms < self.body.generated_at_ms {
            return Err(CredentialError::NotYetValid);
        }
        if now_ms >= self.body.expires_at_ms {
            return Err(CredentialError::Expired);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    use uuid::Uuid;

    const DAY_MS: i64 = 24 * 60 * 60 * 1_000;

    fn request(identity: &IdentitySecret, role: CredentialRole) -> CredentialRequest {
        CredentialRequest::new(
            identity,
            "test device".to_string(),
            role,
            [9; IDENTITY_KEY_LEN],
            1_000,
            1_000 + DAY_MS,
        )
        .unwrap()
    }

    #[test]
    fn credential_binds_role_noise_key_identity_and_issuer() {
        let authority = CertificateAuthoritySecret::generate();
        let other_authority = CertificateAuthoritySecret::generate();
        let identity = IdentitySecret::generate();
        let request = request(&identity, CredentialRole::Viewer);
        let credential = authority
            .issue(&request, 2_000, 2_000 + DAY_MS, DAY_MS)
            .unwrap();
        credential
            .verify_at(
                &authority.public(),
                None,
                CredentialRole::Viewer,
                &[9; IDENTITY_KEY_LEN],
                3_000,
            )
            .unwrap();
        assert!(
            credential
                .verify_at(
                    &authority.public(),
                    None,
                    CredentialRole::Publisher,
                    &[9; IDENTITY_KEY_LEN],
                    3_000,
                )
                .is_err()
        );
        assert!(
            credential
                .verify_at(
                    &authority.public(),
                    None,
                    CredentialRole::Viewer,
                    &[8; IDENTITY_KEY_LEN],
                    3_000,
                )
                .is_err()
        );
        assert!(
            credential
                .verify_at(
                    &other_authority.public(),
                    None,
                    CredentialRole::Viewer,
                    &[9; IDENTITY_KEY_LEN],
                    3_000,
                )
                .is_err()
        );
    }

    #[test]
    fn request_and_credential_expiry_fail_closed() {
        let authority = CertificateAuthoritySecret::generate();
        let identity = IdentitySecret::generate();
        let request = request(&identity, CredentialRole::Viewer);
        assert!(request.verify(1_500, DAY_MS).is_ok());
        assert!(matches!(
            request.verify(1_000 + DAY_MS, DAY_MS),
            Err(CredentialError::Expired)
        ));
        assert!(
            authority
                .issue(&request, 1_000 + DAY_MS, 1_000 + DAY_MS * 2, DAY_MS)
                .is_err()
        );

        let credential = authority.issue(&request, 2_000, 3_000, DAY_MS).unwrap();
        assert!(matches!(
            credential.verify_at(
                &authority.public(),
                None,
                CredentialRole::Viewer,
                &[9; IDENTITY_KEY_LEN],
                3_000,
            ),
            Err(CredentialError::Expired)
        ));
    }

    #[test]
    fn zero_request_nonce_is_rejected_before_signature_verification() {
        let identity = IdentitySecret::generate();
        let mut request = request(&identity, CredentialRole::Viewer);
        request.body.nonce = [0; 16];
        assert!(matches!(
            request.verify(1_500, DAY_MS),
            Err(CredentialError::InvalidMetadata(_))
        ));
    }

    #[test]
    fn signed_revocation_list_revokes_only_listed_serials() {
        let authority = CertificateAuthoritySecret::generate();
        let identity = IdentitySecret::generate();
        let credential = authority
            .issue(
                &request(&identity, CredentialRole::Viewer),
                2_000,
                2_000 + DAY_MS,
                DAY_MS,
            )
            .unwrap();
        let revocations = authority
            .sign_revocations(2_000, 2_000 + DAY_MS, vec![credential.body.serial])
            .unwrap();
        assert!(matches!(
            credential.verify_at(
                &authority.public(),
                Some(&revocations),
                CredentialRole::Viewer,
                &[9; IDENTITY_KEY_LEN],
                3_000,
            ),
            Err(CredentialError::Revoked)
        ));
        let mut tampered = revocations;
        tampered.body.serials.clear();
        assert!(tampered.verify_at(&authority.public(), 3_000).is_err());
    }

    #[test]
    fn revocation_list_codec_rejects_truncation_and_trailing_data() {
        let authority = CertificateAuthoritySecret::generate();
        let list = authority
            .sign_revocations(1_000, 1_000 + DAY_MS, vec![[3; 16]])
            .unwrap();
        let encoded = list.encode().unwrap();
        assert_eq!(RevocationList::decode(&encoded).unwrap(), list);
        for truncated in 0..encoded.len() {
            assert!(RevocationList::decode(&encoded[..truncated]).is_err());
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(RevocationList::decode(&trailing).is_err());
    }

    #[test]
    fn authority_file_is_private_persistent_and_never_replaced() {
        let root = std::env::temp_dir().join(format!("glacialcast-ca-{}", Uuid::new_v4()));
        let path = root.join("issuer.key");
        let public = create_certificate_authority(&path).unwrap();
        assert_eq!(load_certificate_authority(&path).unwrap().public(), public);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(create_certificate_authority(&path).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
