//! SSH-style trust-on-first-use storage for relay Noise identities.

use crate::private_state::{read_private, replace_private};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io, net::SocketAddr, path::PathBuf};
use thiserror::Error;

/// Known-relay private-state format version.
pub const KNOWN_RELAYS_VERSION: u16 = 1;
/// Maximum canonical relay endpoints stored in one known-relays file.
pub const MAX_KNOWN_RELAYS: usize = 4_096;

const MAX_KNOWN_RELAYS_FILE_LEN: usize = 512 * 1024;

/// Result of checking a relay key against the known-relays store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayTrustOutcome {
    /// The key matched an existing endpoint pin.
    Known,
    /// The endpoint was unseen and this key was durably learned.
    Learned,
}

/// Errors produced by relay endpoint normalization and TOFU storage.
#[derive(Debug, Error)]
pub enum RelayTrustError {
    /// The endpoint was empty, malformed, unbounded, or had no valid port.
    #[error("invalid relay endpoint")]
    InvalidEndpoint,
    /// A relay presented a different key than the one already learned.
    #[error("relay identity changed for {endpoint}; forget or explicitly replace the old pin")]
    KeyChanged {
        /// Canonical endpoint whose pin did not match.
        endpoint: String,
    },
    /// The known-relays file used an unsupported version.
    #[error("unsupported known-relays version {0}")]
    UnsupportedVersion(u16),
    /// The file was malformed, noncanonical, duplicated, or exceeded bounds.
    #[error("invalid known-relays state: {0}")]
    InvalidState(&'static str),
    /// The private state file could not be safely read or written.
    #[error("known-relays state I/O failed: {0}")]
    Io(#[from] io::Error),
    /// The known-relays state could not be encoded or decoded.
    #[error("known-relays serialization failed: {0}")]
    Postcard(#[from] postcard::Error),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct KnownRelayEntry {
    endpoint: String,
    noise_static_key: [u8; 32],
}

#[derive(Debug, Deserialize, Serialize)]
struct KnownRelayFile {
    version: u16,
    entries: Vec<KnownRelayEntry>,
}

/// Private durable TOFU database keyed by canonical relay endpoint.
#[derive(Debug)]
pub struct KnownRelays {
    path: PathBuf,
    entries: BTreeMap<String, [u8; 32]>,
}

/// Normalizes one relay endpoint for TOFU lookup.
///
/// IP socket addresses use the standard `SocketAddr` representation. DNS
/// hostnames are ASCII-lowercased, have one trailing dot removed, and retain
/// their explicit numeric port.
///
/// # Errors
///
/// Returns an error for missing/zero ports, invalid hostname characters,
/// whitespace, empty labels, or endpoints longer than 512 bytes.
pub fn canonical_relay_endpoint(endpoint: &str) -> Result<String, RelayTrustError> {
    if endpoint.is_empty() || endpoint.len() > 512 || endpoint.trim() != endpoint {
        return Err(RelayTrustError::InvalidEndpoint);
    }
    if let Ok(address) = endpoint.parse::<SocketAddr>() {
        if address.port() == 0 {
            return Err(RelayTrustError::InvalidEndpoint);
        }
        return Ok(address.to_string());
    }
    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or(RelayTrustError::InvalidEndpoint)?;
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(RelayTrustError::InvalidEndpoint)?;
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || host.starts_with('.')
        || host.ends_with('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(RelayTrustError::InvalidEndpoint);
    }
    Ok(format!("{host}:{port}"))
}

impl KnownRelays {
    /// Opens a known-relays file, treating a missing file as an empty database.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe file metadata, oversized or malformed data,
    /// unsupported versions, duplicate/noncanonical endpoints, or zero keys.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, RelayTrustError> {
        let path = path.into();
        let bytes = match read_private(&path, MAX_KNOWN_RELAYS_FILE_LEN) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let mut entries = BTreeMap::new();
        if let Some(bytes) = bytes {
            let (file, remainder) = postcard::take_from_bytes::<KnownRelayFile>(&bytes)?;
            if !remainder.is_empty() {
                return Err(RelayTrustError::InvalidState("trailing data"));
            }
            if file.version != KNOWN_RELAYS_VERSION {
                return Err(RelayTrustError::UnsupportedVersion(file.version));
            }
            if file.entries.len() > MAX_KNOWN_RELAYS {
                return Err(RelayTrustError::InvalidState("too many relay entries"));
            }
            let mut previous: Option<&str> = None;
            for entry in &file.entries {
                let canonical = canonical_relay_endpoint(&entry.endpoint)?;
                if canonical != entry.endpoint
                    || previous.is_some_and(|previous| previous >= entry.endpoint.as_str())
                    || entry.noise_static_key == [0; 32]
                {
                    return Err(RelayTrustError::InvalidState(
                        "entries are not canonical, sorted, unique, and nonzero",
                    ));
                }
                previous = Some(&entry.endpoint);
                entries.insert(entry.endpoint.clone(), entry.noise_static_key);
            }
        }
        Ok(Self { path, entries })
    }

    /// Checks a relay key, durably learning it only for a previously unseen endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`RelayTrustError::KeyChanged`] without modifying state if an
    /// existing pin differs, or an error if a new pin cannot be persisted.
    pub fn verify_or_learn(
        &mut self,
        endpoint: &str,
        noise_static_key: [u8; 32],
    ) -> Result<RelayTrustOutcome, RelayTrustError> {
        let endpoint = canonical_relay_endpoint(endpoint)?;
        if noise_static_key == [0; 32] {
            return Err(RelayTrustError::InvalidState("zero relay key"));
        }
        match self.entries.get(&endpoint) {
            Some(expected) if expected == &noise_static_key => Ok(RelayTrustOutcome::Known),
            Some(_) => Err(RelayTrustError::KeyChanged { endpoint }),
            None => {
                if self.entries.len() >= MAX_KNOWN_RELAYS {
                    return Err(RelayTrustError::InvalidState("too many relay entries"));
                }
                self.entries.insert(endpoint.clone(), noise_static_key);
                self.persist()?;
                Ok(RelayTrustOutcome::Learned)
            }
        }
    }

    /// Explicitly removes one relay pin so a later connection may learn again.
    ///
    /// Returns whether a pin existed.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid endpoint or if the updated state cannot
    /// be durably persisted. The caller must discard this instance after a
    /// persistence error because a final directory-sync failure has inherently
    /// uncertain durability.
    pub fn forget(&mut self, endpoint: &str) -> Result<bool, RelayTrustError> {
        let endpoint = canonical_relay_endpoint(endpoint)?;
        if self.entries.remove(&endpoint).is_none() {
            return Ok(false);
        }
        self.persist()?;
        Ok(true)
    }

    /// Returns the learned key for a canonicalizable endpoint, if present.
    ///
    /// # Errors
    ///
    /// Returns an error if the endpoint is malformed.
    pub fn get(&self, endpoint: &str) -> Result<Option<[u8; 32]>, RelayTrustError> {
        let endpoint = canonical_relay_endpoint(endpoint)?;
        Ok(self.entries.get(&endpoint).copied())
    }

    fn persist(&self) -> Result<(), RelayTrustError> {
        let file = KnownRelayFile {
            version: KNOWN_RELAYS_VERSION,
            entries: self
                .entries
                .iter()
                .map(|(endpoint, noise_static_key)| KnownRelayEntry {
                    endpoint: endpoint.clone(),
                    noise_static_key: *noise_static_key,
                })
                .collect(),
        };
        let encoded = postcard::to_stdvec(&file)?;
        if encoded.len() > MAX_KNOWN_RELAYS_FILE_LEN {
            return Err(RelayTrustError::InvalidState(
                "known-relays file is too large",
            ));
        }
        replace_private(&self.path, &encoded, MAX_KNOWN_RELAYS_FILE_LEN)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };
    use uuid::Uuid;

    fn path() -> PathBuf {
        std::env::temp_dir()
            .join(format!("glacialcast-known-relays-{}", Uuid::new_v4()))
            .join("known-relays.bin")
    }

    #[test]
    fn endpoint_normalization_is_stable_and_strict() {
        assert_eq!(
            canonical_relay_endpoint("Relay.Example.:8899").unwrap(),
            "relay.example:8899"
        );
        assert_eq!(
            canonical_relay_endpoint("[::1]:8899").unwrap(),
            "[::1]:8899"
        );
        for invalid in [
            "",
            "relay",
            "relay:0",
            " relay:1",
            "-relay:1",
            "relay..lan:1",
        ] {
            assert!(
                canonical_relay_endpoint(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn tofu_learns_matches_hard_fails_and_forgets_explicitly() {
        let path = path();
        let mut known = KnownRelays::open(&path).unwrap();
        assert_eq!(
            known
                .verify_or_learn("Relay.Example:8899", [1; 32])
                .unwrap(),
            RelayTrustOutcome::Learned
        );
        assert_eq!(
            known
                .verify_or_learn("relay.example:8899", [1; 32])
                .unwrap(),
            RelayTrustOutcome::Known
        );
        assert!(matches!(
            known.verify_or_learn("relay.example:8899", [2; 32]),
            Err(RelayTrustError::KeyChanged { .. })
        ));
        drop(known);

        let mut reopened = KnownRelays::open(&path).unwrap();
        assert_eq!(reopened.get("relay.example:8899").unwrap(), Some([1; 32]));
        assert!(reopened.forget("relay.example:8899").unwrap());
        assert_eq!(
            reopened
                .verify_or_learn("relay.example:8899", [2; 32])
                .unwrap(),
            RelayTrustOutcome::Learned
        );
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn known_relays_rejects_public_permissions_and_symlinks() {
        let path = path();
        let mut known = KnownRelays::open(&path).unwrap();
        known.verify_or_learn("relay:8899", [1; 32]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(KnownRelays::open(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let link = path.with_extension("link");
        symlink(&path, &link).unwrap();
        assert!(KnownRelays::open(&link).is_err());
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
