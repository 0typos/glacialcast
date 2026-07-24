use anyhow::{Context, Result, bail};
use axum::http::{HeaderMap, header};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    io::{Read, Write},
    net::IpAddr,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;

const SESSION_KEY_MAGIC: &[u8; 5] = b"GCSK1";
const SESSION_KEY_LEN: usize = 32;
const SESSION_NONCE_LEN: usize = 16;
const SESSION_COOKIE: &str = "glacialcast_session";
const SECURE_SESSION_COOKIE: &str = "__Host-glacialcast_session";
const MIN_ACCESS_TOKEN_LEN: usize = 32;
const MAX_ACCESS_TOKEN_LEN: usize = 512;
const MAX_PRINCIPAL_NAME_LEN: usize = 64;
const MAX_PUBLISHER_NAME_LEN: usize = 128;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AccessRole {
    Viewer,
    Admin,
}

#[derive(Debug, Clone, Deserialize)]
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
    pub fn can_view_publisher(&self, publisher: &str) -> bool {
        self.role == AccessRole::Admin || self.all_publishers || self.publishers.contains(publisher)
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
}

#[derive(Clone)]
struct Credential {
    token_hash: [u8; 32],
    principal_name: String,
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
        })
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
        matched
    }

    pub fn principal(&self, name: &str) -> Option<Principal> {
        self.principals.get(name).cloned()
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

pub fn client_ip(headers: &HeaderMap, peer: IpAddr, trust_forwarded_for: bool) -> IpAddr {
    if !trust_forwarded_for {
        return peer;
    }
    let Some(value) = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
    else {
        return peer;
    };
    if value.len() > 512 || value.trim() != value {
        return peer;
    }
    let addresses: Option<Vec<IpAddr>> = value
        .split(',')
        .map(|value| value.trim().parse::<IpAddr>().ok())
        .collect();
    let Some(addresses) = addresses else {
        return peer;
    };
    if addresses.is_empty() || addresses.len() > 16 {
        return peer;
    }
    addresses[0]
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
        headers.insert(
            "x-forwarded-for",
            "198.51.100.2, 203.0.113.8".parse().unwrap(),
        );
        assert_eq!(
            client_ip(&headers, peer, true),
            "198.51.100.2".parse::<IpAddr>().unwrap()
        );
        headers.insert("x-forwarded-for", "invalid, 203.0.113.8".parse().unwrap());
        assert_eq!(client_ip(&headers, peer, true), peer);
    }
}
