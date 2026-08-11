//! Independent public or native-credential admission for relay endpoints.

use glacialcast_protocol::{
    credential::{CertificateAuthorityPublic, CredentialError, CredentialRole, RevocationList},
    wire::{RelayAccessMode, SessionHello},
};
use std::sync::{Arc, RwLock};
use thiserror::Error;

/// Relay admission policy applied after Noise XX authentication.
#[derive(Clone, Debug)]
pub enum NativeAccessPolicy {
    /// Admit any structurally valid publisher or viewer identity.
    Public,
    /// Require a credential from the configured relay-access CA.
    Signed {
        /// Public relay-access certificate authority.
        authority: CertificateAuthorityPublic,
        /// Optional current signed credential revocation list.
        revocations: Arc<RwLock<Option<RevocationList>>>,
    },
}

/// Successful native relay admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeAdmission {
    /// Policy announced in the relay welcome.
    pub mode: RelayAccessMode,
    /// Exclusive credential expiry; absent in public mode.
    pub expires_at_ms: Option<i64>,
    /// Signed credential serial; absent in public mode.
    pub credential_serial: Option<[u8; 16]>,
}

/// Errors produced while admitting a native Noise peer.
#[derive(Debug, Error)]
pub enum NativeAccessError {
    /// Session hello requested the other listener's role.
    #[error("native session requested the wrong endpoint role")]
    WrongRole,
    /// Signed mode requires a credential.
    #[error("native relay credential is required")]
    MissingCredential,
    /// Credential issuer, signature, role, key binding, validity, or revocation failed.
    #[error("native relay credential rejected: {0}")]
    Credential(#[from] CredentialError),
    /// In-process policy state was poisoned and cannot fail open.
    #[error("native relay access policy is unavailable")]
    Unavailable,
}

impl NativeAccessPolicy {
    /// Validates one hello against its authenticated Noise static key and role.
    ///
    /// In signed mode, catalog access and every other application operation
    /// must wait until this method succeeds. Relay-access credentials do not
    /// imply publisher E2EE viewer approval.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong role, missing credential, invalid signature,
    /// expiry, revocation, or Noise/application identity substitution.
    pub fn admit(
        &self,
        hello: &SessionHello,
        expected_role: CredentialRole,
        authenticated_noise_key: &[u8; 32],
        now_ms: i64,
    ) -> Result<NativeAdmission, NativeAccessError> {
        if hello.role != expected_role {
            return Err(NativeAccessError::WrongRole);
        }
        match self {
            Self::Public => Ok(NativeAdmission {
                mode: RelayAccessMode::Public,
                expires_at_ms: None,
                credential_serial: None,
            }),
            Self::Signed {
                authority,
                revocations,
            } => {
                let credential = hello
                    .credential
                    .as_ref()
                    .ok_or(NativeAccessError::MissingCredential)?;
                if credential.body.identity != hello.identity {
                    return Err(NativeAccessError::Credential(
                        CredentialError::InvalidMetadata(
                            "credential application identity differs from session",
                        ),
                    ));
                }
                let revocations = revocations
                    .read()
                    .map_err(|_| NativeAccessError::Unavailable)?;
                credential.verify_at(
                    authority,
                    revocations.as_ref(),
                    expected_role,
                    authenticated_noise_key,
                    now_ms,
                )?;
                Ok(NativeAdmission {
                    mode: RelayAccessMode::Signed,
                    expires_at_ms: Some(credential.body.not_after_ms),
                    credential_serial: Some(credential.body.serial),
                })
            }
        }
    }

    /// Replaces the current signed revocation list after full verification.
    ///
    /// # Errors
    ///
    /// Returns an error for public mode, an invalid list, or poisoned policy state.
    pub fn replace_revocations(
        &self,
        revocations: Option<RevocationList>,
        now_ms: i64,
    ) -> Result<(), NativeAccessError> {
        let Self::Signed {
            authority,
            revocations: current,
        } = self
        else {
            return Err(NativeAccessError::Unavailable);
        };
        if let Some(list) = &revocations {
            list.verify_at(authority, now_ms)?;
        }
        *current
            .write()
            .map_err(|_| NativeAccessError::Unavailable)? = revocations;
        Ok(())
    }

    /// Rechecks expiry and live revocation state for an admitted session.
    ///
    /// # Errors
    ///
    /// Returns an error once the credential expires, is revoked, or policy
    /// state becomes unavailable.
    pub fn ensure_active(
        &self,
        admission: NativeAdmission,
        now_ms: i64,
    ) -> Result<(), NativeAccessError> {
        match self {
            Self::Public => Ok(()),
            Self::Signed {
                authority,
                revocations,
            } => {
                if admission
                    .expires_at_ms
                    .is_none_or(|expiry| now_ms >= expiry)
                {
                    return Err(CredentialError::Expired.into());
                }
                let serial = admission
                    .credential_serial
                    .ok_or(NativeAccessError::Unavailable)?;
                let current = revocations
                    .read()
                    .map_err(|_| NativeAccessError::Unavailable)?;
                if let Some(list) = current.as_ref() {
                    list.verify_at(authority, now_ms)?;
                    if list.body.serials.binary_search(&serial).is_ok() {
                        return Err(CredentialError::Revoked.into());
                    }
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use glacialcast_protocol::{
        PROTOCOL_VERSION,
        credential::{CertificateAuthoritySecret, CredentialRequest},
        identity::IdentitySecret,
    };

    const DAY_MS: i64 = 24 * 60 * 60 * 1_000;

    fn signed_hello(
        role: CredentialRole,
    ) -> (
        NativeAccessPolicy,
        SessionHello,
        [u8; 32],
        CertificateAuthoritySecret,
    ) {
        let authority = CertificateAuthoritySecret::generate();
        let identity = IdentitySecret::generate();
        let noise_key = [9; 32];
        let request = CredentialRequest::new(
            &identity,
            "device".into(),
            role,
            noise_key,
            1_000,
            1_000 + DAY_MS,
        )
        .unwrap();
        let credential = authority
            .issue(&request, 2_000, 2_000 + DAY_MS, DAY_MS)
            .unwrap();
        (
            NativeAccessPolicy::Signed {
                authority: authority.public(),
                revocations: Arc::new(RwLock::new(None)),
            },
            SessionHello {
                protocol_version: PROTOCOL_VERSION,
                role,
                identity: identity.public().unwrap(),
                credential: Some(credential),
            },
            noise_key,
            authority,
        )
    }

    #[test]
    fn signed_mode_binds_role_noise_key_expiry_and_revocation() {
        let (policy, hello, noise_key, authority) = signed_hello(CredentialRole::Viewer);
        let admission = policy
            .admit(&hello, CredentialRole::Viewer, &noise_key, 3_000)
            .unwrap();
        assert_eq!(admission.mode, RelayAccessMode::Signed);
        assert!(
            policy
                .admit(&hello, CredentialRole::Publisher, &noise_key, 3_000)
                .is_err()
        );
        assert!(
            policy
                .admit(&hello, CredentialRole::Viewer, &[8; 32], 3_000)
                .is_err()
        );
        assert!(
            policy
                .admit(&hello, CredentialRole::Viewer, &noise_key, 2_000 + DAY_MS,)
                .is_err()
        );

        let credential = hello.credential.as_ref().unwrap();
        let revocations = authority
            .sign_revocations(2_000, 2_000 + DAY_MS, vec![credential.body.serial])
            .unwrap();
        let revoked = NativeAccessPolicy::Signed {
            authority: authority.public(),
            revocations: Arc::new(RwLock::new(Some(revocations))),
        };
        assert!(
            revoked
                .admit(&hello, CredentialRole::Viewer, &noise_key, 3_000)
                .is_err()
        );
    }

    #[test]
    fn signed_mode_requires_credentials_while_public_mode_does_not() {
        let (signed, mut hello, noise_key, _) = signed_hello(CredentialRole::Viewer);
        hello.credential = None;
        assert!(
            signed
                .admit(&hello, CredentialRole::Viewer, &noise_key, 3_000)
                .is_err()
        );
        assert!(
            NativeAccessPolicy::Public
                .admit(&hello, CredentialRole::Viewer, &noise_key, 3_000)
                .is_ok()
        );
    }

    #[test]
    fn admitted_session_is_rejected_after_live_revocation() {
        let (policy, hello, noise_key, authority) = signed_hello(CredentialRole::Viewer);
        let admission = policy
            .admit(&hello, CredentialRole::Viewer, &noise_key, 3_000)
            .unwrap();
        assert!(policy.ensure_active(admission, 3_000).is_ok());

        let serial = hello.credential.as_ref().unwrap().body.serial;
        let revocations = authority
            .sign_revocations(3_000, 3_000 + DAY_MS, vec![serial])
            .unwrap();
        policy
            .replace_revocations(Some(revocations), 3_000)
            .unwrap();

        assert!(matches!(
            policy.ensure_active(admission, 3_000),
            Err(NativeAccessError::Credential(CredentialError::Revoked))
        ));
    }
}
