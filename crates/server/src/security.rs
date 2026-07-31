//! Viewer access control, signed sessions, origin checks, and abuse limits.
//!
//! Access tokens map to viewer or administrator principals and optional
//! publisher scopes. Browser authority is carried by short-lived signed
//! cookies and a session-bound CSRF value; bearer tokens remain available for
//! non-browser tools. Credential comparison and session tags use constant-time
//! verification, and changing a principal's credentials or scope changes its
//! session version.

use crate::IDENTITY_LABEL_SEPARATOR;

use anyhow::{Context, Result, bail};
use axum::http::{HeaderMap, header};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    io::{Read, Write},
    net::IpAddr,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use uuid::Uuid;

const SESSION_KEY_MAGIC: &[u8; 5] = b"GCSK1";
const SESSION_KEY_LEN: usize = 32;
const SESSION_NONCE_LEN: usize = 16;
const SESSION_COOKIE: &str = "glacialcast_session";
const SECURE_SESSION_COOKIE: &str = "__Host-glacialcast_session";
const MIN_ACCESS_TOKEN_LEN: usize = 32;
const MAX_ACCESS_TOKEN_LEN: usize = 512;
const MAX_PRINCIPAL_NAME_LEN: usize = 64;
const MAX_PUBLISHER_NAME_LEN: usize = 128;
const MANAGED_ACCESS_VERSION: u16 = 1;
const MAX_MANAGED_ACCESS_FILE_LEN: u64 = 1024 * 1024;
const MAX_MANAGED_VIEWERS: usize = 4096;
const MAX_MANAGED_PUBLISHERS_PER_VIEWER: usize = 256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AccessRole {
    Viewer,
    Admin,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfiguredAccessToken {
    pub name: String,
    pub token: String,
    #[serde(default)]
    pub previous_tokens: Vec<String>,
    #[serde(default = "default_access_role")]
    pub role: AccessRole,
    #[serde(default)]
    pub publishers: Vec<String>,
}

impl fmt::Debug for ConfiguredAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfiguredAccessToken")
            .field("name", &self.name)
            .field("token", &"[REDACTED]")
            .field("previous_tokens", &self.previous_tokens.len())
            .field("role", &self.role)
            .field("publishers", &self.publishers)
            .finish()
    }
}

fn default_access_role() -> AccessRole {
    AccessRole::Viewer
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AccessConfig {
    pub tokens: Vec<ConfiguredAccessToken>,
}

#[derive(Debug, Clone)]
pub struct Principal {
    pub name: String,
    pub role: AccessRole,
    all_publishers: bool,
    publishers: HashSet<String>,
    auth_version: [u8; 16],
}

impl Principal {
    /// Reports whether this principal may view a stream published under
    /// `publisher`.
    ///
    /// A publisher capturing several outputs registers each as
    /// `<principal>:<label>`, so a scope naming the principal authorizes all of
    /// its outputs. Matching stops at the first separator rather than using a
    /// prefix test, so a scope of `desk` never authorizes `desk-other`.
    pub fn can_view_publisher(&self, publisher: &str) -> bool {
        if self.role == AccessRole::Admin || self.all_publishers {
            return true;
        }
        if self.publishers.contains(publisher) {
            return true;
        }
        publisher
            .split_once(IDENTITY_LABEL_SEPARATOR)
            .is_some_and(|(principal, _)| self.publishers.contains(principal))
    }

    pub fn is_admin(&self) -> bool {
        self.role == AccessRole::Admin
    }
}

#[derive(Clone)]
pub struct AccessControl {
    principals: HashMap<String, Principal>,
    credentials: Vec<Credential>,
    local_anonymous: bool,
    managed: Option<Arc<Mutex<ManagedAccessState>>>,
}

#[derive(Clone)]
struct Credential {
    token_hash: [u8; 32],
    principal_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagedViewerSummary {
    pub name: String,
    pub publishers: Vec<String>,
    pub created_at_ms: i64,
}

#[derive(Clone, Serialize)]
pub struct ManagedViewerEnrollment {
    pub viewer: ManagedViewerSummary,
    pub access_token: String,
}

impl fmt::Debug for ManagedViewerEnrollment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedViewerEnrollment")
            .field("viewer", &self.viewer)
            .field("access_token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug)]
pub enum ManagedViewerMutationError {
    Invalid(String),
    Storage(anyhow::Error),
}

impl fmt::Display for ManagedViewerMutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::Storage(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ManagedViewerMutationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Invalid(_) => None,
            Self::Storage(error) => Some(error.as_ref()),
        }
    }
}

#[derive(Debug, Clone)]
struct ManagedViewer {
    summary: ManagedViewerSummary,
    token_hash: [u8; 32],
    principal: Principal,
}

struct ManagedAccessState {
    path: PathBuf,
    viewers: BTreeMap<String, ManagedViewer>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedAccessFile {
    version: u16,
    viewers: Vec<ManagedAccessRecord>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedAccessRecord {
    name: String,
    publishers: Vec<String>,
    created_at_ms: i64,
    token_hash_b64: String,
}

impl AccessControl {
    pub fn from_config(config: AccessConfig, allow_local_anonymous: bool) -> Result<Self> {
        if !allow_local_anonymous && config.tokens.is_empty() {
            bail!("Internet mode requires at least one configured access token");
        }

        let mut principals = HashMap::new();
        let mut credentials: Vec<Credential> = Vec::new();
        for configured in config.tokens {
            let name = configured.name.trim();
            validate_identifier("access token name", name, MAX_PRINCIPAL_NAME_LEN)?;
            if principals.contains_key(name) {
                bail!("duplicate access token name {name}");
            }

            let mut publishers = HashSet::new();
            let mut all_publishers = false;
            for publisher in configured.publishers {
                let publisher = publisher.trim();
                if publisher == "*" {
                    all_publishers = true;
                    continue;
                }
                validate_identifier("publisher identity", publisher, MAX_PUBLISHER_NAME_LEN)?;
                publishers.insert(publisher.to_string());
            }
            if configured.role == AccessRole::Viewer && !all_publishers && publishers.is_empty() {
                bail!("viewer access token {name} must name at least one publisher or use \"*\"");
            }

            let mut tokens = Vec::with_capacity(1 + configured.previous_tokens.len());
            tokens.push(configured.token);
            tokens.extend(configured.previous_tokens);
            let mut principal_token_hashes = Vec::with_capacity(tokens.len());
            for token in tokens {
                validate_secret("access token", name, &token)?;
                let token_hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
                if credentials
                    .iter()
                    .any(|credential| bool::from(credential.token_hash.ct_eq(&token_hash)))
                {
                    bail!("duplicate access token value for {name}");
                }
                principal_token_hashes.push(token_hash);
                credentials.push(Credential {
                    token_hash,
                    principal_name: name.to_string(),
                });
            }
            principal_token_hashes.sort_unstable();
            let mut version = Sha256::new();
            version.update(b"glacialcast-access-principal-v1");
            version.update(name.as_bytes());
            version.update([match configured.role {
                AccessRole::Viewer => 0,
                AccessRole::Admin => 1,
            }]);
            version.update([u8::from(all_publishers)]);
            let mut ordered_publishers: Vec<_> = publishers.iter().collect();
            ordered_publishers.sort_unstable();
            for publisher in ordered_publishers {
                version.update((publisher.len() as u64).to_be_bytes());
                version.update(publisher.as_bytes());
            }
            for token_hash in principal_token_hashes {
                version.update(token_hash);
            }
            let auth_version = &version.finalize()[..16];
            let principal = Principal {
                name: name.to_string(),
                role: configured.role,
                all_publishers,
                publishers,
                auth_version: auth_version
                    .try_into()
                    .expect("SHA-256 version prefix has 16 bytes"),
            };
            principals.insert(name.to_string(), principal);
        }

        let local_anonymous = allow_local_anonymous && principals.is_empty();
        Ok(Self {
            principals,
            credentials,
            local_anonymous,
            managed: None,
        })
    }

    pub fn from_config_with_managed_file(
        config: AccessConfig,
        allow_local_anonymous: bool,
        managed_path: PathBuf,
    ) -> Result<Self> {
        let mut access = Self::from_config(config, allow_local_anonymous)?;
        let state = ManagedAccessState::load(managed_path, &access.principals)?;
        access.managed = Some(Arc::new(Mutex::new(state)));
        Ok(access)
    }

    pub fn authenticate_token(&self, token: &str) -> Option<Principal> {
        if token.len() > MAX_ACCESS_TOKEN_LEN {
            return None;
        }
        let presented: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut matched = None;
        for credential in &self.credentials {
            if bool::from(credential.token_hash.ct_eq(&presented)) {
                matched = self.principals.get(&credential.principal_name).cloned();
            }
        }
        if let Some(managed) = &self.managed {
            let managed = managed.lock().ok()?;
            for viewer in managed.viewers.values() {
                if bool::from(viewer.token_hash.ct_eq(&presented)) {
                    matched = Some(viewer.principal.clone());
                }
            }
        }
        matched
    }

    pub fn principal(&self, name: &str) -> Option<Principal> {
        self.principals.get(name).cloned().or_else(|| {
            self.managed
                .as_ref()?
                .lock()
                .ok()?
                .viewers
                .get(name)
                .map(|viewer| viewer.principal.clone())
        })
    }

    pub fn local_principal(&self) -> Option<Principal> {
        self.local_anonymous.then(|| Principal {
            name: "local".to_string(),
            role: AccessRole::Admin,
            all_publishers: true,
            publishers: HashSet::new(),
            auth_version: [0; 16],
        })
    }

    pub fn managed_viewers(&self) -> Result<Vec<ManagedViewerSummary>> {
        let managed = self
            .managed
            .as_ref()
            .context("managed viewer enrollment is unavailable")?
            .lock()
            .map_err(|_| anyhow::anyhow!("managed access state mutex poisoned"))?;
        Ok(managed
            .viewers
            .values()
            .map(|viewer| viewer.summary.clone())
            .collect())
    }

    pub fn enroll_viewer(
        &self,
        name: &str,
        publishers: Vec<String>,
    ) -> std::result::Result<ManagedViewerEnrollment, ManagedViewerMutationError> {
        validate_identifier("viewer name", name, MAX_PRINCIPAL_NAME_LEN)
            .map_err(|error| ManagedViewerMutationError::Invalid(error.to_string()))?;
        if self.principals.contains_key(name) {
            return Err(ManagedViewerMutationError::Invalid(
                "viewer name conflicts with a configured access principal".to_string(),
            ));
        }
        let publishers = validated_publishers(publishers)
            .map_err(|error| ManagedViewerMutationError::Invalid(error.to_string()))?;
        let mut token_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut token_bytes);
        let access_token = format!("gca_{}", URL_SAFE_NO_PAD.encode(token_bytes));
        let token_hash: [u8; 32] = Sha256::digest(access_token.as_bytes()).into();
        let summary = ManagedViewerSummary {
            name: name.to_string(),
            publishers,
            created_at_ms: glacialcast_protocol::now_ms(),
        };
        let principal =
            managed_principal(&summary, token_hash).map_err(ManagedViewerMutationError::Storage)?;
        let viewer = ManagedViewer {
            summary: summary.clone(),
            token_hash,
            principal,
        };

        let managed = self.managed.as_ref().ok_or_else(|| {
            ManagedViewerMutationError::Storage(anyhow::anyhow!(
                "managed viewer enrollment is unavailable"
            ))
        })?;
        let mut managed = managed.lock().map_err(|_| {
            ManagedViewerMutationError::Storage(anyhow::anyhow!(
                "managed access state mutex poisoned"
            ))
        })?;
        if managed.viewers.contains_key(name) {
            return Err(ManagedViewerMutationError::Invalid(format!(
                "managed viewer {name} already exists"
            )));
        }
        if managed.viewers.len() >= MAX_MANAGED_VIEWERS {
            return Err(ManagedViewerMutationError::Invalid(format!(
                "managed viewer limit of {MAX_MANAGED_VIEWERS} has been reached"
            )));
        }
        let mut next = managed.viewers.clone();
        next.insert(name.to_string(), viewer);
        managed
            .persist(&next)
            .map_err(ManagedViewerMutationError::Storage)?;
        managed.viewers = next;
        Ok(ManagedViewerEnrollment {
            viewer: summary,
            access_token,
        })
    }

    pub fn revoke_viewer(&self, name: &str) -> Result<bool> {
        let managed = self
            .managed
            .as_ref()
            .context("managed viewer enrollment is unavailable")?;
        let mut managed = managed
            .lock()
            .map_err(|_| anyhow::anyhow!("managed access state mutex poisoned"))?;
        if !managed.viewers.contains_key(name) {
            return Ok(false);
        }
        let mut next = managed.viewers.clone();
        next.remove(name);
        managed.persist(&next)?;
        managed.viewers = next;
        Ok(true)
    }
}

impl ManagedAccessState {
    fn load(path: PathBuf, configured: &HashMap<String, Principal>) -> Result<Self> {
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    path,
                    viewers: BTreeMap::new(),
                });
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspecting managed access file {}", path.display()));
            }
        }
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .with_context(|| format!("opening managed access file {}", path.display()))?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "managed access file {} must be a private regular file",
                path.display()
            );
        }
        if metadata.len() > MAX_MANAGED_ACCESS_FILE_LEN {
            bail!(
                "managed access file {} exceeds its size limit",
                path.display()
            );
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        Read::take(&mut file, MAX_MANAGED_ACCESS_FILE_LEN.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_MANAGED_ACCESS_FILE_LEN {
            bail!(
                "managed access file {} exceeds its size limit",
                path.display()
            );
        }
        if bytes.len() as u64 != metadata.len() {
            bail!(
                "managed access file {} changed while it was being read",
                path.display()
            );
        }
        let stored: ManagedAccessFile = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing managed access file {}", path.display()))?;
        if stored.version != MANAGED_ACCESS_VERSION {
            bail!(
                "managed access file {} has unsupported version {}",
                path.display(),
                stored.version
            );
        }
        if stored.viewers.len() > MAX_MANAGED_VIEWERS {
            bail!(
                "managed access file {} exceeds the viewer limit of {}",
                path.display(),
                MAX_MANAGED_VIEWERS
            );
        }
        let mut viewers = BTreeMap::new();
        for record in stored.viewers {
            validate_identifier("managed viewer name", &record.name, MAX_PRINCIPAL_NAME_LEN)?;
            if configured.contains_key(&record.name) || viewers.contains_key(&record.name) {
                bail!(
                    "managed viewer name {} is duplicated or configured",
                    record.name
                );
            }
            if record.created_at_ms <= 0 {
                bail!(
                    "managed viewer {} has an invalid creation time",
                    record.name
                );
            }
            let publishers = validated_publishers(record.publishers)?;
            let token_hash: [u8; 32] = URL_SAFE_NO_PAD
                .decode(&record.token_hash_b64)
                .context("decoding managed viewer token hash")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("managed viewer token hash must contain 32 bytes"))?;
            let summary = ManagedViewerSummary {
                name: record.name.clone(),
                publishers,
                created_at_ms: record.created_at_ms,
            };
            viewers.insert(
                record.name,
                ManagedViewer {
                    principal: managed_principal(&summary, token_hash)?,
                    summary,
                    token_hash,
                },
            );
        }
        Ok(Self { path, viewers })
    }

    fn persist(&self, viewers: &BTreeMap<String, ManagedViewer>) -> Result<()> {
        let parent = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating managed access directory {}", parent.display()))?;
        let stored = ManagedAccessFile {
            version: MANAGED_ACCESS_VERSION,
            viewers: viewers
                .values()
                .map(|viewer| ManagedAccessRecord {
                    name: viewer.summary.name.clone(),
                    publishers: viewer.summary.publishers.clone(),
                    created_at_ms: viewer.summary.created_at_ms,
                    token_hash_b64: URL_SAFE_NO_PAD.encode(viewer.token_hash),
                })
                .collect(),
        };
        let bytes =
            serde_json::to_vec_pretty(&stored).context("serializing managed access file")?;
        if bytes.len() as u64 > MAX_MANAGED_ACCESS_FILE_LEN {
            bail!(
                "managed access state exceeds its {} byte size limit",
                MAX_MANAGED_ACCESS_FILE_LEN
            );
        }
        let temporary = parent.join(format!(
            ".{}-{}.tmp",
            self.path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("access-enrollments"),
            Uuid::new_v4()
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .with_context(|| format!("creating {}", temporary.display()))?;
        file.write_all(&bytes)
            .with_context(|| format!("writing {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("syncing {}", temporary.display()))?;
        std::fs::rename(&temporary, &self.path).with_context(|| {
            format!(
                "publishing managed access file {} as {}",
                temporary.display(),
                self.path.display()
            )
        })?;
        std::fs::File::open(parent)
            .with_context(|| format!("opening managed access directory {}", parent.display()))?
            .sync_all()
            .with_context(|| format!("syncing managed access directory {}", parent.display()))
    }
}

fn validated_publishers(publishers: Vec<String>) -> Result<Vec<String>> {
    if publishers.len() > MAX_MANAGED_PUBLISHERS_PER_VIEWER {
        bail!(
            "managed viewer exceeds the publisher limit of {}",
            MAX_MANAGED_PUBLISHERS_PER_VIEWER
        );
    }
    let mut normalized = HashSet::new();
    for publisher in publishers {
        let publisher = publisher.trim();
        if publisher == "*" {
            normalized.insert(publisher.to_string());
            continue;
        }
        validate_identifier("publisher identity", publisher, MAX_PUBLISHER_NAME_LEN)?;
        normalized.insert(publisher.to_string());
    }
    if normalized.is_empty() {
        bail!("managed viewer must name at least one publisher or use \"*\"");
    }
    let mut normalized = normalized.into_iter().collect::<Vec<_>>();
    normalized.sort_unstable();
    Ok(normalized)
}

fn managed_principal(summary: &ManagedViewerSummary, token_hash: [u8; 32]) -> Result<Principal> {
    let all_publishers = summary.publishers.iter().any(|publisher| publisher == "*");
    let publishers = summary
        .publishers
        .iter()
        .filter(|publisher| publisher.as_str() != "*")
        .cloned()
        .collect::<HashSet<_>>();
    let mut version = Sha256::new();
    version.update(b"glacialcast-managed-viewer-v1");
    version.update(summary.name.as_bytes());
    version.update(summary.created_at_ms.to_be_bytes());
    for publisher in &summary.publishers {
        version.update((publisher.len() as u64).to_be_bytes());
        version.update(publisher.as_bytes());
    }
    version.update(token_hash);
    let auth_version: [u8; 16] = version.finalize()[..16]
        .try_into()
        .expect("SHA-256 version prefix has 16 bytes");
    Ok(Principal {
        name: summary.name.clone(),
        role: AccessRole::Viewer,
        all_publishers,
        publishers,
        auth_version,
    })
}

fn validate_identifier(field: &str, value: &str, max_len: usize) -> Result<()> {
    if value.is_empty() || value.len() > max_len {
        bail!("{field} must contain 1 to {max_len} bytes");
    }
    if !value.is_ascii()
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    {
        bail!("{field} may contain only ASCII letters, digits, dot, dash, and underscore");
    }
    Ok(())
}

fn validate_secret(kind: &str, name: &str, secret: &str) -> Result<()> {
    if !(MIN_ACCESS_TOKEN_LEN..=MAX_ACCESS_TOKEN_LEN).contains(&secret.len()) {
        bail!(
            "{kind} for {name} must contain {MIN_ACCESS_TOKEN_LEN} to {MAX_ACCESS_TOKEN_LEN} bytes"
        );
    }
    if secret.trim() != secret || secret.bytes().any(|byte| byte.is_ascii_control()) {
        bail!("{kind} for {name} must not contain surrounding whitespace or control bytes");
    }
    Ok(())
}

#[derive(Clone)]
pub struct SessionSigner {
    key: [u8; SESSION_KEY_LEN],
    ttl_seconds: u64,
    secure_cookie: bool,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedRequest {
    pub principal: Principal,
    pub csrf: Option<String>,
}

impl SessionSigner {
    pub fn load_or_create(path: &Path, ttl_seconds: u64, secure_cookie: bool) -> Result<Self> {
        if !(300..=604_800).contains(&ttl_seconds) {
            bail!("session TTL must be between 300 and 604800 seconds");
        }
        let key = load_or_create_secret_file(path)?;
        Ok(Self {
            key,
            ttl_seconds,
            secure_cookie,
        })
    }

    pub fn create_session(&self, principal: &Principal) -> Result<(String, String)> {
        let expires = unix_time_seconds()?
            .checked_add(self.ttl_seconds)
            .context("session expiration overflow")?;
        let mut nonce = [0_u8; SESSION_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let unsigned = format!(
            "v1.{}.{}.{}.{}",
            URL_SAFE_NO_PAD.encode(principal.name.as_bytes()),
            expires,
            URL_SAFE_NO_PAD.encode(nonce),
            URL_SAFE_NO_PAD.encode(principal.auth_version),
        );
        let signature = self.sign(b"session:", unsigned.as_bytes());
        let value = format!("{unsigned}.{}", URL_SAFE_NO_PAD.encode(signature));
        let csrf = URL_SAFE_NO_PAD.encode(self.sign(b"csrf:", value.as_bytes()));
        Ok((value, csrf))
    }

    pub fn authenticate(
        &self,
        headers: &HeaderMap,
        access: &AccessControl,
    ) -> Option<AuthenticatedRequest> {
        if let Some(token) = bearer_token(headers) {
            return access
                .authenticate_token(token)
                .map(|principal| AuthenticatedRequest {
                    principal,
                    csrf: None,
                });
        }

        let cookie = cookie_value(headers, self.cookie_name())?;
        let (principal_name, auth_version) = self.verify_session(cookie)?;
        let principal = access.principal(&principal_name)?;
        if !bool::from(principal.auth_version.ct_eq(&auth_version)) {
            return None;
        }
        let csrf = URL_SAFE_NO_PAD.encode(self.sign(b"csrf:", cookie.as_bytes()));
        Some(AuthenticatedRequest {
            principal,
            csrf: Some(csrf),
        })
    }

    pub fn session_cookie(&self, value: &str) -> String {
        let secure = if self.secure_cookie { "; Secure" } else { "" };
        format!(
            "{}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
            self.cookie_name(),
            self.ttl_seconds,
            secure
        )
    }

    pub fn expired_cookie(&self) -> String {
        let secure = if self.secure_cookie { "; Secure" } else { "" };
        format!(
            "{}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
            self.cookie_name(),
            secure,
        )
    }

    fn cookie_name(&self) -> &'static str {
        if self.secure_cookie {
            SECURE_SESSION_COOKIE
        } else {
            SESSION_COOKIE
        }
    }

    pub fn verify_csrf(&self, request: &AuthenticatedRequest, headers: &HeaderMap) -> bool {
        let Some(expected) = request.csrf.as_deref() else {
            // Bearer authorization is not ambient browser authority and is not
            // vulnerable to cross-site request forgery.
            return true;
        };
        let Ok(presented) = headers
            .get("x-glacialcast-csrf")
            .ok_or(())
            .and_then(|value| value.to_str().map_err(|_| ()))
        else {
            return false;
        };
        bool::from(expected.as_bytes().ct_eq(presented.as_bytes()))
    }

    fn verify_session(&self, value: &str) -> Option<(String, [u8; 16])> {
        if value.len() > 1024 {
            return None;
        }
        let fields: Vec<&str> = value.split('.').collect();
        if fields.len() != 6 || fields[0] != "v1" {
            return None;
        }
        let unsigned = fields[..5].join(".");
        let signature = URL_SAFE_NO_PAD.decode(fields[5]).ok()?;
        if signature.len() != 32 {
            return None;
        }
        let expected = self.sign(b"session:", unsigned.as_bytes());
        if !bool::from(expected.as_slice().ct_eq(signature.as_slice())) {
            return None;
        }
        let expires = fields[2].parse::<u64>().ok()?;
        let now = unix_time_seconds().ok()?;
        if expires <= now || expires > now.checked_add(self.ttl_seconds)? {
            return None;
        }
        let nonce = URL_SAFE_NO_PAD.decode(fields[3]).ok()?;
        if nonce.len() != SESSION_NONCE_LEN {
            return None;
        }
        let name = String::from_utf8(URL_SAFE_NO_PAD.decode(fields[1]).ok()?).ok()?;
        validate_identifier("session principal", &name, MAX_PRINCIPAL_NAME_LEN).ok()?;
        let auth_version: [u8; 16] = URL_SAFE_NO_PAD.decode(fields[4]).ok()?.try_into().ok()?;
        Some((name, auth_version))
    }

    fn sign(&self, domain: &[u8], data: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts 32-byte keys");
        mac.update(domain);
        mac.update(data);
        mac.finalize().into_bytes().into()
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    for header_value in headers.get_all(header::COOKIE) {
        let value = header_value.to_str().ok()?;
        for cookie in value.split(';') {
            let Some((cookie_name, cookie_value)) = cookie.trim().split_once('=') else {
                continue;
            };
            if cookie_name == name {
                return Some(cookie_value);
            }
        }
    }
    None
}

pub fn validate_request_origin(headers: &HeaderMap, public_origin: Option<&str>) -> bool {
    let Ok(origin) = headers
        .get(header::ORIGIN)
        .ok_or(())
        .and_then(|value| value.to_str().map_err(|_| ()))
    else {
        return false;
    };
    if let Some(expected) = public_origin {
        return bool::from(origin.as_bytes().ct_eq(expected.as_bytes()));
    }
    let Ok(host) = headers
        .get(header::HOST)
        .ok_or(())
        .and_then(|value| value.to_str().map_err(|_| ()))
    else {
        return false;
    };
    origin == format!("http://{host}") || origin == format!("https://{host}")
}

pub fn normalize_public_origin(value: Option<String>) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim_end_matches('/');
    let uri: axum::http::Uri = value.parse().context("parsing security.public_origin")?;
    if uri.scheme_str() != Some("https")
        || uri.authority().is_none()
        || uri.path() != "/"
        || uri.query().is_some()
        || uri.authority().is_some_and(|authority| {
            authority.as_str().contains('@') || authority.as_str().contains(char::is_whitespace)
        })
    {
        bail!("security.public_origin must be an HTTPS origin without credentials or a path");
    }
    Ok(Some(value.to_string()))
}

#[derive(Clone)]
pub struct FixedWindowLimiter {
    inner: Arc<Mutex<LimiterState>>,
    limit: u32,
    window: Duration,
    max_keys: usize,
}

#[derive(Default)]
struct LimiterState {
    entries: HashMap<String, WindowEntry>,
}

struct WindowEntry {
    started: Instant,
    count: u32,
}

impl FixedWindowLimiter {
    pub fn new(limit: u32, window: Duration, max_keys: usize) -> Result<Self> {
        if limit == 0 || window.is_zero() || max_keys == 0 {
            bail!("rate limiter values must be nonzero");
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(LimiterState::default())),
            limit,
            window,
            max_keys,
        })
    }

    pub fn check(&self, key: impl Into<String>) -> bool {
        let now = Instant::now();
        let Ok(mut state) = self.inner.lock() else {
            return false;
        };
        state
            .entries
            .retain(|_, entry| now.duration_since(entry.started) < self.window);
        let key = key.into();
        if let Some(entry) = state.entries.get_mut(&key) {
            if entry.count >= self.limit {
                return false;
            }
            entry.count += 1;
            return true;
        }
        if state.entries.len() >= self.max_keys {
            return false;
        }
        state.entries.insert(
            key,
            WindowEntry {
                started: now,
                count: 1,
            },
        );
        true
    }
}

/// Resolves the address a request came from, honouring a trusted proxy.
///
/// Returns the peer address unless `trust_forwarded_for` says a trusted proxy
/// terminates connections in front of this listener, which is only ever true in
/// the Internet profile.
///
/// The **rightmost** `X-Forwarded-For` entry is the answer, not the leftmost.
/// A proxy appends the address of the connection it accepted, so the last entry
/// is the only one it wrote itself; everything to its left arrived in the
/// client's own request and is forgeable. Reading the leftmost entry let any
/// client choose the address this server rate-limits and logs it by, which
/// defeated the per-address login limiter entirely and put attacker-chosen
/// addresses in the audit log.
///
/// Exactly one trusted proxy is assumed, matching the deployment this ships
/// with. Behind two, the last entry is the inner proxy rather than the client,
/// which over-attributes traffic to one address rather than trusting a forged
/// one -- the limits bind tighter, not looser.
pub fn client_ip(headers: &HeaderMap, peer: IpAddr, trust_forwarded_for: bool) -> IpAddr {
    if !trust_forwarded_for {
        return peer;
    }
    // Repeated field lines are one list in order, so a client that sends its
    // own header makes the proxy's value a second line rather than extending
    // the first. Reading only the first line would read only the client's.
    let mut addresses: Vec<IpAddr> = Vec::new();
    for value in headers.get_all("x-forwarded-for") {
        let Ok(value) = value.to_str() else {
            return peer;
        };
        if value.len() > 512 || value.trim() != value {
            return peer;
        }
        for entry in value.split(',') {
            let Ok(address) = entry.trim().parse::<IpAddr>() else {
                return peer;
            };
            addresses.push(address);
            if addresses.len() > 16 {
                return peer;
            }
        }
    }
    addresses.last().copied().unwrap_or(peer)
}

fn unix_time_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs())
}

fn load_or_create_secret_file(path: &Path) -> Result<[u8; SESSION_KEY_LEN]> {
    match read_secret_file(path) {
        Ok(key) => return Ok(key),
        Err(err) if path.exists() => return Err(err),
        Err(_) => {}
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating session key directory {}", parent.display()))?;
    }
    let mut key = [0_u8; SESSION_KEY_LEN];
    OsRng.fill_bytes(&mut key);
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            return read_secret_file(path);
        }
        Err(err) => {
            return Err(err).with_context(|| format!("creating session key {}", path.display()));
        }
    };
    file.write_all(SESSION_KEY_MAGIC)?;
    file.write_all(&key)?;
    file.sync_all()?;
    Ok(key)
}

fn read_secret_file(path: &Path) -> Result<[u8; SESSION_KEY_LEN]> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening session key {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        bail!(
            "session key {} must be a private regular file",
            path.display()
        );
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if bytes.len() != SESSION_KEY_MAGIC.len() + SESSION_KEY_LEN
        || !bytes.starts_with(SESSION_KEY_MAGIC)
    {
        bail!("session key {} has an invalid format", path.display());
    }
    Ok(bytes[SESSION_KEY_MAGIC.len()..]
        .try_into()
        .expect("validated session key length"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn access_config() -> AccessConfig {
        AccessConfig {
            tokens: vec![
                ConfiguredAccessToken {
                    name: "viewer-one".to_string(),
                    token: TOKEN.to_string(),
                    previous_tokens: vec!["previous-0123456789abcdef01234567".to_string()],
                    role: AccessRole::Viewer,
                    publishers: vec!["workstation".to_string()],
                },
                ConfiguredAccessToken {
                    name: "operator".to_string(),
                    token: "admin-0123456789abcdef0123456789ab".to_string(),
                    previous_tokens: Vec::new(),
                    role: AccessRole::Admin,
                    publishers: Vec::new(),
                },
            ],
        }
    }

    fn signer() -> (SessionSigner, std::path::PathBuf) {
        let path =
            std::env::temp_dir().join(format!("glacialcast-session-{}.key", uuid::Uuid::new_v4()));
        (
            SessionSigner::load_or_create(&path, 3600, true).unwrap(),
            path,
        )
    }

    #[test]
    fn access_tokens_are_scoped_and_support_rotation() {
        let access = AccessControl::from_config(access_config(), false).unwrap();
        let viewer = access.authenticate_token(TOKEN).unwrap();
        assert!(viewer.can_view_publisher("workstation"));
        assert!(!viewer.can_view_publisher("other"));
        // A publisher casting several screens registers one stream per output
        // as `<principal>:<label>`, and the principal's scope covers them all.
        assert!(viewer.can_view_publisher("workstation:DP-1"));
        assert!(viewer.can_view_publisher("workstation:HDMI-A-1"));
        // Matching stops at the separator: a neighbouring principal whose name
        // merely starts with the scope must stay out of reach.
        assert!(!viewer.can_view_publisher("workstation-other"));
        assert!(!viewer.can_view_publisher("workstation-other:DP-1"));
        assert!(!viewer.can_view_publisher("other:workstation"));
        assert!(!viewer.is_admin());
        assert_eq!(
            access
                .authenticate_token("previous-0123456789abcdef01234567")
                .unwrap()
                .name,
            "viewer-one"
        );
        assert!(
            access
                .authenticate_token("wrong-0123456789abcdef0123456789a")
                .is_none()
        );
        assert!(
            access
                .authenticate_token(&"x".repeat(MAX_ACCESS_TOKEN_LEN + 1))
                .is_none()
        );
    }

    #[test]
    fn access_configuration_rejects_weak_or_ambiguous_credentials() {
        let configured = ConfiguredAccessToken {
            name: "redacted".to_string(),
            token: "current-secret".to_string(),
            previous_tokens: vec!["previous-secret".to_string()],
            role: AccessRole::Viewer,
            publishers: vec!["workstation".to_string()],
        };
        let debug = format!("{configured:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("current-secret"));
        assert!(!debug.contains("previous-secret"));

        let mut missing_scope = access_config();
        missing_scope.tokens[0].publishers.clear();
        assert!(AccessControl::from_config(missing_scope, false).is_err());

        let mut weak = access_config();
        weak.tokens[0].token = "weak".to_string();
        assert!(AccessControl::from_config(weak, false).is_err());

        let mut duplicate = access_config();
        duplicate.tokens[1].token = TOKEN.to_string();
        assert!(AccessControl::from_config(duplicate, false).is_err());
    }

    #[test]
    fn managed_viewers_persist_hashes_and_revoke_tokens_and_sessions() {
        let root =
            std::env::temp_dir().join(format!("glacialcast-managed-access-{}", Uuid::new_v4()));
        let managed_path = root.join("access-enrollments.json");
        let access = AccessControl::from_config_with_managed_file(
            access_config(),
            false,
            managed_path.clone(),
        )
        .unwrap();
        let enrollment = access
            .enroll_viewer(
                "field-viewer",
                vec!["workstation".to_string(), "workstation".to_string()],
            )
            .unwrap();
        assert_eq!(enrollment.viewer.publishers, ["workstation"]);
        assert!(enrollment.access_token.starts_with("gca_"));
        let debug = format!("{enrollment:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&enrollment.access_token));
        assert_eq!(
            access
                .authenticate_token(&enrollment.access_token)
                .unwrap()
                .name,
            "field-viewer"
        );
        let stored = std::fs::read_to_string(&managed_path).unwrap();
        assert!(!stored.contains(&enrollment.access_token));
        assert!(stored.contains("token_hash_b64"));
        assert_eq!(
            std::fs::metadata(&managed_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let (signer, session_path) = signer();
        let principal = access.authenticate_token(&enrollment.access_token).unwrap();
        let (cookie, _) = signer.create_session(&principal).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("{}={cookie}", signer.cookie_name())
                .parse()
                .unwrap(),
        );
        let reloaded =
            AccessControl::from_config_with_managed_file(access_config(), false, managed_path)
                .unwrap();
        assert!(signer.authenticate(&headers, &reloaded).is_some());
        assert!(reloaded.revoke_viewer("field-viewer").unwrap());
        assert!(!reloaded.revoke_viewer("field-viewer").unwrap());
        assert!(
            reloaded
                .authenticate_token(&enrollment.access_token)
                .is_none()
        );
        assert!(signer.authenticate(&headers, &reloaded).is_none());

        std::fs::remove_file(session_path).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn managed_viewer_enrollment_rejects_bad_scope_conflicts_and_symlinks() {
        let root =
            std::env::temp_dir().join(format!("glacialcast-managed-access-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let managed_path = root.join("access-enrollments.json");
        let access = AccessControl::from_config_with_managed_file(
            access_config(),
            false,
            managed_path.clone(),
        )
        .unwrap();
        assert!(matches!(
            access.enroll_viewer("operator", vec!["*".to_string()]),
            Err(ManagedViewerMutationError::Invalid(_))
        ));
        assert!(matches!(
            access.enroll_viewer("new-viewer", Vec::new()),
            Err(ManagedViewerMutationError::Invalid(_))
        ));
        assert!(matches!(
            access.enroll_viewer("new viewer", vec!["*".to_string()]),
            Err(ManagedViewerMutationError::Invalid(_))
        ));
        assert!(matches!(
            access.enroll_viewer(
                "wide-viewer",
                vec!["workstation".to_string(); MAX_MANAGED_PUBLISHERS_PER_VIEWER + 1],
            ),
            Err(ManagedViewerMutationError::Invalid(_))
        ));

        let summary = ManagedViewerSummary {
            name: "limit-template".to_string(),
            publishers: vec!["workstation".to_string()],
            created_at_ms: glacialcast_protocol::now_ms(),
        };
        let token_hash = [7; 32];
        let template = ManagedViewer {
            principal: managed_principal(&summary, token_hash).unwrap(),
            summary,
            token_hash,
        };
        {
            let mut managed = access.managed.as_ref().unwrap().lock().unwrap();
            for index in 0..MAX_MANAGED_VIEWERS {
                managed
                    .viewers
                    .insert(format!("limit-{index:04}"), template.clone());
            }
        }
        assert!(matches!(
            access.enroll_viewer("over-limit", vec!["*".to_string()]),
            Err(ManagedViewerMutationError::Invalid(message))
                if message.contains("viewer limit")
        ));
        assert!(!managed_path.exists());

        let link = root.join("managed-link.json");
        std::os::unix::fs::symlink(&managed_path, &link).unwrap();
        assert!(
            AccessControl::from_config_with_managed_file(access_config(), false, link).is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn managed_access_refuses_oversized_state_before_publication() {
        let root =
            std::env::temp_dir().join(format!("glacialcast-managed-size-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("access-enrollments.json");
        let summary = ManagedViewerSummary {
            name: "oversized".to_string(),
            publishers: vec!["x".repeat(MAX_PUBLISHER_NAME_LEN); 9000],
            created_at_ms: glacialcast_protocol::now_ms(),
        };
        let token_hash = [9; 32];
        let viewer = ManagedViewer {
            principal: managed_principal(&summary, token_hash).unwrap(),
            summary,
            token_hash,
        };
        let state = ManagedAccessState {
            path: path.clone(),
            viewers: BTreeMap::new(),
        };
        let viewers = BTreeMap::from([("oversized".to_string(), viewer)]);
        let error = state.persist(&viewers).unwrap_err();
        assert!(error.to_string().contains("size limit"));
        assert!(!path.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn signed_session_authenticates_and_detects_tampering() {
        let access = AccessControl::from_config(access_config(), false).unwrap();
        let principal = access.authenticate_token(TOKEN).unwrap();
        let (signer, path) = signer();
        let (cookie, csrf) = signer.create_session(&principal).unwrap();
        let set_cookie = signer.session_cookie(&cookie);
        assert!(set_cookie.starts_with("__Host-glacialcast_session="));
        assert!(set_cookie.contains("; Secure"));
        assert!(!set_cookie.contains("Domain="));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("{}={cookie}", signer.cookie_name())
                .parse()
                .unwrap(),
        );
        headers.insert("x-glacialcast-csrf", csrf.parse().unwrap());
        let reloaded = SessionSigner::load_or_create(&path, 3600, true).unwrap();
        let request = reloaded.authenticate(&headers, &access).unwrap();
        assert_eq!(request.principal.name, "viewer-one");
        assert!(reloaded.verify_csrf(&request, &headers));

        let mut tampered = headers.clone();
        tampered.insert(
            header::COOKIE,
            format!("{}={cookie}x", signer.cookie_name())
                .parse()
                .unwrap(),
        );
        assert!(signer.authenticate(&tampered, &access).is_none());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn changing_credentials_or_scope_revokes_existing_sessions() {
        let access = AccessControl::from_config(access_config(), false).unwrap();
        let principal = access.authenticate_token(TOKEN).unwrap();
        let (signer, path) = signer();
        let (cookie, _) = signer.create_session(&principal).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("{}={cookie}", signer.cookie_name())
                .parse()
                .unwrap(),
        );
        assert!(signer.authenticate(&headers, &access).is_some());

        let mut changed = access_config();
        changed.tokens[0].previous_tokens.clear();
        let changed = AccessControl::from_config(changed, false).unwrap();
        assert!(signer.authenticate(&headers, &changed).is_none());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn bearer_authentication_does_not_require_csrf() {
        let access = AccessControl::from_config(access_config(), false).unwrap();
        let (signer, path) = signer();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {TOKEN}").parse().unwrap(),
        );
        let request = signer.authenticate(&headers, &access).unwrap();
        assert!(request.csrf.is_none());
        assert!(signer.verify_csrf(&request, &headers));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn origin_validation_is_exact() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "127.0.0.1:8899".parse().unwrap());
        headers.insert(header::ORIGIN, "http://127.0.0.1:8899".parse().unwrap());
        assert!(validate_request_origin(&headers, None));
        assert!(!validate_request_origin(
            &headers,
            Some("https://cast.example")
        ));
        headers.insert(header::ORIGIN, "https://cast.example".parse().unwrap());
        assert!(validate_request_origin(
            &headers,
            Some("https://cast.example")
        ));
    }

    #[test]
    fn public_origin_requires_https_without_a_path() {
        assert_eq!(
            normalize_public_origin(Some("https://cast.example/".to_string())).unwrap(),
            Some("https://cast.example".to_string())
        );
        assert!(normalize_public_origin(Some("http://cast.example".to_string())).is_err());
        assert!(normalize_public_origin(Some("https://cast.example/path".to_string())).is_err());
        assert!(normalize_public_origin(Some("https://user@cast.example".to_string())).is_err());
    }

    #[test]
    fn fixed_window_limiter_bounds_keys_and_requests() {
        let limiter = FixedWindowLimiter::new(2, Duration::from_secs(60), 2).unwrap();
        assert!(limiter.check("one"));
        assert!(limiter.check("one"));
        assert!(!limiter.check("one"));
        assert!(limiter.check("two"));
        assert!(!limiter.check("three"));
    }

    #[test]
    fn forwarded_client_address_requires_one_trusted_ip() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let forwarded: IpAddr = "203.0.113.8".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.8".parse().unwrap());
        assert_eq!(client_ip(&headers, peer, false), peer);
        assert_eq!(client_ip(&headers, peer, true), forwarded);
        headers.insert("x-forwarded-for", "invalid, 203.0.113.8".parse().unwrap());
        assert_eq!(client_ip(&headers, peer, true), peer);
    }

    #[test]
    fn a_client_cannot_choose_the_address_it_is_limited_and_logged_by() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        // What the proxy actually saw, appended after whatever the client sent.
        let proxy_saw: IpAddr = "203.0.113.8".parse().unwrap();

        // One header, client value first. Reading the leftmost entry here is
        // what let a caller rotate the key the login limiter counts by.
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.2, 203.0.113.8".parse().unwrap(),
        );
        assert_eq!(client_ip(&headers, peer, true), proxy_saw);

        // Two header lines, which is what a client sending its own header
        // produces when the proxy adds rather than replaces. Reading only the
        // first line would read only the client's.
        let mut headers = HeaderMap::new();
        headers.append("x-forwarded-for", "198.51.100.2".parse().unwrap());
        headers.append("x-forwarded-for", "203.0.113.8".parse().unwrap());
        assert_eq!(client_ip(&headers, peer, true), proxy_saw);

        // A forged chain long enough to hide the real entry is refused outright
        // rather than attributed to whatever sits at the end of it.
        let mut headers = HeaderMap::new();
        let flood = std::iter::repeat_n("198.51.100.2", 17)
            .collect::<Vec<_>>()
            .join(", ");
        headers.insert("x-forwarded-for", flood.parse().unwrap());
        assert_eq!(client_ip(&headers, peer, true), peer);

        // And none of this applies without a proxy in front: the peer wins.
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.2".parse().unwrap());
        assert_eq!(client_ip(&headers, peer, false), peer);
    }
}
