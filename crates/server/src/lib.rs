//! GlacialCast authenticated relay and bounded-history HTTP service.
//!
//! Publishers connect to the dedicated Noise-encrypted ingest listener.
//! Browsers use the HTTP API, which stays on loopback in Internet mode behind
//! the documented HTTPS reverse proxy. The relay authenticates and authorizes
//! opaque stream objects but never receives the viewer-derived content keys.
//! Work, connection counts, message sizes, and retained history are bounded.

#![deny(missing_docs)]

mod dash_store;
mod security;
mod storage;
mod tls;
mod traffic;

#[doc(hidden)]
pub use dash_store::fuzz_catalog_journal_record;

use crate::{
    dash_store::DashStore,
    security::{
        AccessConfig, AccessControl, AccessRole, AuthenticatedRequest, FixedWindowLimiter,
        ManagedViewerEnrollment, ManagedViewerMutationError, ManagedViewerSummary, Principal,
        SessionSigner, client_ip, normalize_public_origin, validate_request_origin,
    },
    storage::Store,
    traffic::{TrafficMetrics, TrafficSnapshot},
};
use anyhow::{Context, Result};
use axum::{
    Json, Router,
    body::Body,
    extract::{
        ConnectInfo, DefaultBodyLimit, Path, Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware,
    response::{IntoResponse, Redirect, Response},
    routing::{delete, get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use glacialcast_dash::EpochDescriptor;
use glacialcast_protocol::{
    ClientMessage, ControlEvent, DashObject, DashObjectHeader, DashObjectKind, NOISE_KEY_LEN,
    NoiseKeypair, ServerMessage, StreamHello,
    config_path::{self, ConfigSource},
    daemon::{
        daemonize_if_requested, install_signal_handlers, manager_command, serve_control_socket,
        wait_for_shutdown,
    },
    encode_noise_public_key, encode_ws_event, generate_noise_keypair, now_ms, parse_human_bytes,
    responder_handshake,
    viewer_key::SALT_LEN,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    io::{IsTerminal, Read, Write},
    net::SocketAddr,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path as FsPath, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore, broadcast, watch},
};
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Bound when the listener is meant to be reached only from this host.
const LOOPBACK_HOST: [u8; 4] = [127, 0, 0, 1];
/// Bound when `--trusted-lan` opens the listener to the local network.
const LAN_HOST: [u8; 4] = [0, 0, 0, 0];
const DEFAULT_CONTROL_PORT: u16 = 8899;
const DEFAULT_INGEST_PORT: u16 = 8900;

#[derive(Debug, Parser)]
#[command(version)]
struct Args {
    /// Configuration file. Without it the standard locations are searched:
    /// `$XDG_CONFIG_HOME/glacialcast/server.toml`, `/etc/glacialcast/server.toml`,
    /// then `server.toml` in the working directory.
    #[arg(long, env = "GLACIALCAST_CONFIG")]
    config: Option<PathBuf>,
    /// Ignores every configuration file and runs on built-in defaults.
    ///
    /// For a test or a deliberately minimal deployment that must not inherit
    /// whatever happens to sit in a standard location on the host.
    #[arg(long, conflicts_with = "config")]
    no_config: bool,
    /// HTTP listener for the viewer and the dashboard.
    ///
    /// Defaults to `127.0.0.1:8899`, or to `0.0.0.0:8899` under `--trusted-lan`.
    #[arg(long, env = "GLACIALCAST_CONTROL_ADDR")]
    control_addr: Option<SocketAddr>,
    /// Publisher ingest listener.
    ///
    /// Defaults to `127.0.0.1:8900`, or to `0.0.0.0:8900` under `--trusted-lan`.
    #[arg(long, env = "GLACIALCAST_INGEST_ADDR")]
    ingest_addr: Option<SocketAddr>,
    /// Serves a local network that is trusted: binds both listeners to every
    /// interface, serves plaintext HTTP, and accepts publishers that present no
    /// ingest token.
    ///
    /// This is the operator asserting the network is not hostile. Any host that
    /// can reach the ingest port may then publish a stream. What it does not
    /// give away: stream contents stay end-to-end encrypted, so a listener
    /// without the viewer key sees ciphertext, and publishers still pin the
    /// relay's Noise identity with `--ingest-server-key`.
    ///
    /// Refused together with an Internet `security.public_origin`. An address
    /// given explicitly still wins over the defaults above.
    #[arg(long, env = "GLACIALCAST_TRUSTED_LAN")]
    trusted_lan: bool,
    /// PEM certificate chain to serve HTTPS with. Requires `--tls-key`.
    ///
    /// Supply one issued by a certificate authority the viewers already trust
    /// and they see no warning. Without it, `--trusted-lan` generates a
    /// self-signed pair instead.
    #[arg(long, env = "GLACIALCAST_TLS_CERT", requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    /// PEM private key for `--tls-cert`.
    #[arg(long, env = "GLACIALCAST_TLS_KEY", requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    /// Extra name or address a generated certificate should cover. Repeatable.
    ///
    /// Loopback, this host's name, and the address it reaches the network by
    /// are covered already; this is for a DNS name they do not know about.
    #[arg(long = "tls-name", value_name = "NAME")]
    tls_names: Vec<String>,
    /// Serves plaintext HTTP under `--trusted-lan` instead of generating a
    /// certificate.
    ///
    /// Browsers withhold the cryptography encrypted playback needs on a plain
    /// `http://` address that is not loopback, so viewers reaching this over
    /// the network will not be able to play. For a relay that is only ever
    /// reached through a tunnel, or fronted by something else terminating TLS.
    #[arg(long, conflicts_with_all = ["tls_cert", "tls_key"])]
    no_tls: bool,
    #[arg(long, env = "GLACIALCAST_DATA_DIR", default_value = "data")]
    data_dir: PathBuf,
    #[arg(long, env = "GLACIALCAST_INGEST_KEY_FILE")]
    ingest_key_file: Option<PathBuf>,
    #[arg(long, env = "GLACIALCAST_ALLOW_INSECURE_HTTP")]
    allow_insecure_http: bool,
    #[arg(long)]
    print_ingest_server_key: bool,
    #[arg(
        long,
        env = "GLACIALCAST_RETENTION_BYTES_PER_STREAM",
        value_parser = parse_human_bytes,
        default_value = "512MiB"
    )]
    retention_bytes_per_stream: u64,
    #[arg(long, env = "GLACIALCAST_RETENTION_SECONDS", default_value_t = 1800)]
    retention_seconds: u64,
    #[arg(long)]
    daemon: bool,
    #[arg(long, hide = true)]
    daemon_child: bool,
    #[arg(long)]
    daemon_socket: Option<PathBuf>,
    #[arg(long)]
    daemon_stop: bool,
    #[arg(long)]
    daemon_status: bool,
    #[arg(long)]
    log_file: Option<PathBuf>,
}

/// Where the two listeners bind, and what the deployment profile implies about
/// the credentials reaching them.
#[derive(Debug, PartialEq, Eq)]
struct ListenerPlan {
    control_addr: SocketAddr,
    ingest_addr: SocketAddr,
    /// Whether a configured ingest token must clear the 32-byte floor that
    /// exists because an Internet-facing token is guessed at from anywhere.
    require_strong_ingest: bool,
    /// Whether the HTTP listener terminates TLS itself.
    ///
    /// This is what makes a local-network deployment reachable by a browser at
    /// all: encrypted playback needs a secure context, and a plain `http://`
    /// address that is not loopback is not one.
    serve_tls: bool,
}

/// Resolves the listener addresses and enforces the rules tying a deployment
/// profile to the network it is exposed on.
///
/// `--trusted-lan` is the operator asserting the local network is not hostile.
/// It supplies the wildcard defaults, stands in for `--allow-insecure-http`,
/// and waives both the ingest token that a non-loopback ingest listener
/// otherwise demands and the token-strength floor above. An address given
/// explicitly still wins over the defaults it carries.
///
/// `--trusted-lan` and Internet mode are refused together: one serves plaintext
/// to a local segment and the other insists every public byte crossed TLS at a
/// named origin, so the combination has no coherent reading.
///
/// # Errors
///
/// Returns an error when `--trusted-lan` is combined with an Internet
/// `security.public_origin`; when a non-loopback HTTP listener is requested
/// without either relaxation; when Internet mode is given a non-loopback HTTP
/// listener; or when a non-loopback ingest listener is left without both an
/// ingest token and `--trusted-lan`.
fn plan_listeners(
    args: &Args,
    internet_mode: bool,
    ingest_require_token: bool,
) -> Result<ListenerPlan> {
    if args.trusted_lan && internet_mode {
        anyhow::bail!(
            "--trusted-lan serves plaintext HTTP to a local network and cannot be combined with security.public_origin"
        );
    }
    // A trusted LAN deployment is unreachable until it binds past loopback, so
    // the flag carries the wildcard defaults rather than making every operator
    // restate them alongside it.
    let host = if args.trusted_lan {
        LAN_HOST
    } else {
        LOOPBACK_HOST
    };
    let control_addr = args
        .control_addr
        .unwrap_or_else(|| SocketAddr::from((host, DEFAULT_CONTROL_PORT)));
    let ingest_addr = args
        .ingest_addr
        .unwrap_or_else(|| SocketAddr::from((host, DEFAULT_INGEST_PORT)));
    // A certificate, or a profile that generates one. Internet mode keeps its
    // loopback listener behind a proxy that terminates TLS, so it never does
    // this itself.
    let serve_tls = !internet_mode
        && (args.tls_cert.is_some()
            || (args.trusted_lan && !args.no_tls && !args.allow_insecure_http));
    // TLS answers the plaintext objection outright; the older flag remains the
    // way to say "serve plaintext anyway".
    let allow_insecure_http = serve_tls || args.allow_insecure_http || args.trusted_lan;
    if !control_addr.ip().is_loopback() && !allow_insecure_http {
        anyhow::bail!(
            "refusing a non-loopback HTTP listener; bind --control-addr to loopback behind an HTTPS reverse proxy, or pass --trusted-lan (or --allow-insecure-http) to serve a local network in plaintext"
        );
    }
    if internet_mode && !control_addr.ip().is_loopback() {
        anyhow::bail!(
            "Internet mode requires a loopback HTTP listener behind the configured HTTPS origin"
        );
    }
    if !ingest_addr.ip().is_loopback() && !ingest_require_token && !args.trusted_lan {
        anyhow::bail!(
            "a non-loopback ingest listener requires ingest.require_token = true, or --trusted-lan to accept publishers that present no token"
        );
    }
    Ok(ListenerPlan {
        control_addr,
        ingest_addr,
        require_strong_ingest: internet_mode
            || (!ingest_addr.ip().is_loopback() && !args.trusted_lan),
        serve_tls,
    })
}

#[derive(Clone)]
struct AppState {
    store: Store,
    dash_store: DashStore,
    events: broadcast::Sender<ControlEvent>,
    dash_events: broadcast::Sender<DashObjectHeader>,
    auth: AuthConfig,
    access: AccessControl,
    sessions: SessionSigner,
    public_origin: Option<String>,
    trust_forwarded_for: bool,
    login_limiter: FixedWindowLimiter,
    global_login_limiter: FixedWindowLimiter,
    request_limiter: FixedWindowLimiter,
    websocket_attempt_limiter: FixedWindowLimiter,
    ingest_attempt_limiter: FixedWindowLimiter,
    websocket_slots: Arc<Semaphore>,
    ingest_slots: Arc<Semaphore>,
    websocket_principals: KeyedConnectionTracker,
    ingest_peers: KeyedConnectionTracker,
    ingest_handshake_timeout: Duration,
    ingest_idle_timeout: Duration,
    metrics: Arc<ServerMetrics>,
    traffic: TrafficMetrics,
    retention_bytes_per_stream: u64,
    retention_seconds: u64,
    /// Whether this relay accepts epochs published without encryption.
    ///
    /// Enforced here rather than trusted to the publisher: a publisher that
    /// wants to send in the clear is exactly the one that cannot be relied on
    /// to refuse itself.
    allow_unencrypted: bool,
    active_ingests: Arc<AsyncMutex<HashMap<Uuid, Uuid>>>,
    ingest_private_key: [u8; NOISE_KEY_LEN],
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ServerConfig {
    ingest: IngestConfig,
    access: AccessConfig,
    security: SecurityConfig,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct SecurityConfig {
    public_origin: Option<String>,
    session_secret_file: Option<PathBuf>,
    session_ttl_seconds: u64,
    trust_forwarded_for: bool,
    limits: LimitsConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            public_origin: None,
            session_secret_file: None,
            session_ttl_seconds: 12 * 60 * 60,
            trust_forwarded_for: false,
            limits: LimitsConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct LimitsConfig {
    max_http_in_flight: usize,
    max_websockets: usize,
    max_websockets_per_principal: usize,
    max_ingest_connections: usize,
    max_ingest_connections_per_ip: usize,
    login_attempts_per_minute: u32,
    global_login_attempts_per_minute: u32,
    authenticated_requests_per_minute: u32,
    websocket_attempts_per_minute: u32,
    ingest_attempts_per_minute: u32,
    http_timeout_seconds: u64,
    ingest_handshake_timeout_seconds: u64,
    ingest_idle_timeout_seconds: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_http_in_flight: 128,
            max_websockets: 64,
            max_websockets_per_principal: 9,
            max_ingest_connections: 16,
            max_ingest_connections_per_ip: 4,
            login_attempts_per_minute: 10,
            global_login_attempts_per_minute: 1000,
            authenticated_requests_per_minute: 30_000,
            websocket_attempts_per_minute: 120,
            ingest_attempts_per_minute: 60,
            http_timeout_seconds: 30,
            ingest_handshake_timeout_seconds: 10,
            ingest_idle_timeout_seconds: 120,
        }
    }
}

#[derive(Default)]
struct ServerMetrics {
    http_requests: AtomicU64,
    http_overloaded: AtomicU64,
    http_timed_out: AtomicU64,
    login_successes: AtomicU64,
    login_failures: AtomicU64,
    login_rate_limited: AtomicU64,
    request_rate_limited: AtomicU64,
    active_websockets: AtomicU64,
    websocket_rejected: AtomicU64,
    active_ingest_connections: AtomicU64,
    ingest_rejected: AtomicU64,
    ingest_auth_failures: AtomicU64,
}

/// Loads the configuration named by `source`.
///
/// A file the operator named must exist: silently falling back to defaults
/// there would start a relay with, among other things, no ingest tokens,
/// because of a typo in a unit file.
fn load_server_config_from(source: &ConfigSource) -> Result<ServerConfig> {
    let Some(path) = source.path() else {
        return Ok(ServerConfig::default());
    };
    if source.must_exist() && !path.exists() {
        anyhow::bail!(
            "server config {} does not exist.\nSearched when none is given: {}",
            path.display(),
            config_path::search_paths("server.toml")
                .iter()
                .map(|candidate| candidate.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    load_server_config(&path.to_path_buf())
}

fn load_server_config(path: &PathBuf) -> Result<ServerConfig> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ServerConfig::default());
        }
        Err(err) => {
            return Err(err)
                .with_context(|| format!("inspecting server config {}", path.display()));
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening server config {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        anyhow::bail!(
            "server config {} must be a private regular file with mode 0600",
            path.display()
        );
    }
    let mut raw = String::new();
    file.read_to_string(&mut raw)
        .with_context(|| format!("reading server config {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("parsing server config {}", path.display()))
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct IngestConfig {
    require_token: bool,
    tokens: Vec<ConfiguredIngestToken>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfiguredIngestToken {
    name: String,
    token: String,
    #[serde(default)]
    previous_tokens: Vec<String>,
}

#[derive(Clone)]
struct AuthConfig {
    require_token: bool,
    credentials: Vec<IngestCredential>,
}

#[derive(Clone)]
struct IngestCredential {
    token_hash: [u8; 32],
    name: String,
}

struct AuthenticatedClient {
    identity: String,
}

const INGEST_KEY_MAGIC: &[u8; 5] = b"GCNK1";

fn load_or_create_ingest_key(path: &FsPath) -> Result<NoiseKeypair> {
    match read_ingest_key(path) {
        Ok(keypair) => return Ok(keypair),
        Err(err) if path.exists() => return Err(err),
        Err(_) => {}
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating ingest key directory {}", parent.display()))?;
    }
    let keypair = generate_noise_keypair().context("generating Noise server identity")?;
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            return read_ingest_key(path);
        }
        Err(err) => {
            return Err(err).with_context(|| format!("creating ingest key {}", path.display()));
        }
    };
    file.write_all(INGEST_KEY_MAGIC)?;
    file.write_all(&keypair.private)?;
    file.write_all(&keypair.public)?;
    file.sync_all()?;
    Ok(keypair)
}

fn read_ingest_key(path: &FsPath) -> Result<NoiseKeypair> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening ingest key {}", path.display()))?;
    let metadata = file.metadata()?;
    if metadata.permissions().mode() & 0o077 != 0 {
        anyhow::bail!(
            "ingest key {} must not be accessible by group or other users",
            path.display()
        );
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if bytes.len() != INGEST_KEY_MAGIC.len() + NOISE_KEY_LEN * 2
        || !bytes.starts_with(INGEST_KEY_MAGIC)
    {
        anyhow::bail!("ingest key {} has an invalid format", path.display());
    }
    let private = bytes[INGEST_KEY_MAGIC.len()..INGEST_KEY_MAGIC.len() + NOISE_KEY_LEN]
        .try_into()
        .expect("validated private key slice length");
    let public = bytes[INGEST_KEY_MAGIC.len() + NOISE_KEY_LEN..]
        .try_into()
        .expect("validated public key slice length");
    let keypair = NoiseKeypair { private, public };
    keypair
        .validate()
        .with_context(|| format!("validating ingest key {}", path.display()))?;
    Ok(keypair)
}

impl AuthConfig {
    fn from_config(config: IngestConfig, require_strong_tokens: bool) -> Result<Self> {
        if config.require_token && config.tokens.is_empty() {
            anyhow::bail!("server config requires ingest tokens but none were configured");
        }

        let mut credentials: Vec<IngestCredential> = Vec::new();
        let mut names = HashSet::new();
        for configured in config.tokens {
            let name = configured.name.trim();
            if name.is_empty() {
                anyhow::bail!("configured ingest token name must not be empty");
            }
            if !names.insert(name.to_string()) {
                anyhow::bail!("duplicate ingest token name {name}");
            }
            let mut tokens = Vec::with_capacity(1 + configured.previous_tokens.len());
            tokens.push(configured.token);
            tokens.extend(configured.previous_tokens);
            for value in tokens {
                if value.is_empty() || value.len() > 512 {
                    anyhow::bail!("configured ingest token for {name} has an invalid length");
                }
                if require_strong_tokens && value.len() < 32 {
                    anyhow::bail!(
                        "Internet-facing ingest token for {name} must contain at least 32 bytes"
                    );
                }
                if value.trim() != value || value.bytes().any(|byte| byte.is_ascii_control()) {
                    anyhow::bail!("configured ingest token for {name} contains invalid whitespace");
                }
                let token_hash = hash_token(&value);
                if credentials
                    .iter()
                    .any(|credential| bool::from(credential.token_hash.ct_eq(&token_hash)))
                {
                    anyhow::bail!("duplicate ingest token value for {name}");
                }
                credentials.push(IngestCredential {
                    token_hash,
                    name: name.to_string(),
                });
            }
        }

        Ok(Self {
            require_token: config.require_token,
            credentials,
        })
    }

    fn authenticate(&self, presented_token: Option<&str>, client_id: &str) -> Result<String> {
        let client_id = client_id.trim();
        if client_id.is_empty() {
            anyhow::bail!("client_id must not be empty");
        }

        match presented_token {
            Some(token) if !token.is_empty() => {
                let hash = hash_token(token);
                let mut identity = None;
                for credential in &self.credentials {
                    if bool::from(credential.token_hash.ct_eq(&hash)) {
                        identity = Some(credential.name.clone());
                    }
                }
                identity.ok_or_else(|| anyhow::anyhow!("invalid ingest token"))
            }
            _ if self.require_token => anyhow::bail!("ingest token required"),
            _ => Ok(client_id.to_string()),
        }
    }
}

/// Parses the process configuration and runs the authenticated relay.
///
/// This is the installed binary's entry point. It returns after a requested
/// daemon-management action, graceful shutdown, or a fatal configuration,
/// storage, listener, or runtime error.
pub fn run() -> Result<()> {
    let args = Args::parse();
    let daemon_socket = server_daemon_socket(&args);

    if args.daemon_stop || args.daemon_status {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("building manager runtime")?;
        let command = if args.daemon_stop {
            "signal TERM"
        } else {
            "status"
        };
        let response = runtime.block_on(manager_command(&daemon_socket, command))?;
        print!("{response}");
        return Ok(());
    }

    if daemonize_if_requested(
        args.daemon,
        args.daemon_child,
        &daemon_socket,
        "--daemon-socket",
        "--daemon-child",
        args.log_file.as_deref(),
    )? {
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "glacialcast_server=info,tower_http=info".into()),
        )
        // Diagnostics go to stderr so stdout carries only what a caller asked
        // to capture. `--print-ingest-server-key` is read straight into a shell
        // variable, and a log line landing in the middle of it produced a key
        // that failed to decode several steps later.
        .with_writer(std::io::stderr)
        // Journald, a redirected file, and a daemon log all read better
        // without terminal colour escapes.
        .with_ansi(std::io::stderr().is_terminal())
        .init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building server runtime")?;
    runtime.block_on(run_server(args, daemon_socket))
}

fn server_daemon_socket(args: &Args) -> PathBuf {
    args.daemon_socket
        .clone()
        .unwrap_or_else(|| PathBuf::from("/tmp/glacialcast-server.sock"))
}

async fn run_server(args: Args, daemon_socket: PathBuf) -> Result<()> {
    let serve_control = args.daemon_child || args.daemon_socket.is_some();
    let config_source = if args.no_config {
        ConfigSource::Defaults
    } else {
        config_path::resolve(args.config.clone(), "server.toml")
    };
    let config = load_server_config_from(&config_source)?;
    // Which file a service actually read is the first thing anyone needs when
    // a unit behaves unexpectedly, and the last thing they can work out from
    // the outside.
    info!(
        config = config_source.path().map_or_else(
            || "<defaults>".to_string(),
            |path| path.display().to_string()
        ),
        origin = config_source.origin(),
        "loaded server configuration"
    );
    let SecurityConfig {
        public_origin: configured_public_origin,
        session_secret_file,
        session_ttl_seconds,
        trust_forwarded_for,
        limits,
    } = config.security;
    validate_limits(&limits)?;
    let public_origin = normalize_public_origin(configured_public_origin)?;
    let internet_mode = public_origin.is_some();
    let ListenerPlan {
        control_addr,
        ingest_addr,
        require_strong_ingest,
        serve_tls,
    } = plan_listeners(&args, internet_mode, config.ingest.require_token)?;
    if trust_forwarded_for && !internet_mode {
        anyhow::bail!("security.trust_forwarded_for requires an HTTPS public_origin");
    }
    if internet_mode && !config.ingest.require_token {
        anyhow::bail!("Internet mode requires ingest.require_token = true");
    }
    tokio::fs::create_dir_all(&args.data_dir)
        .await
        .with_context(|| format!("creating data dir {}", args.data_dir.display()))?;
    if internet_mode {
        std::fs::set_permissions(&args.data_dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("securing data dir {}", args.data_dir.display()))?;
    }
    let ingest_key_path = args
        .ingest_key_file
        .clone()
        .unwrap_or_else(|| args.data_dir.join("ingest-noise.key"));
    let ingest_key = load_or_create_ingest_key(&ingest_key_path)?;
    let ingest_server_key = encode_noise_public_key(&ingest_key.public);
    if args.print_ingest_server_key {
        println!("{ingest_server_key}");
        return Ok(());
    }

    let store = Store::open(args.data_dir.clone())?;
    let dash_store = DashStore::open(
        args.data_dir.join("dash"),
        args.retention_bytes_per_stream,
        Duration::from_secs(args.retention_seconds),
    )?;
    let (events, _) = broadcast::channel(1024);
    let (dash_events, _) = broadcast::channel(1024);
    let session_key_path =
        session_secret_file.unwrap_or_else(|| args.data_dir.join("http-session.key"));
    let metrics = Arc::new(ServerMetrics::default());
    let http_slots = Arc::new(Semaphore::new(limits.max_http_in_flight));
    let websocket_slots = Arc::new(Semaphore::new(limits.max_websockets));
    let ingest_slots = Arc::new(Semaphore::new(limits.max_ingest_connections));
    let state = AppState {
        store,
        dash_store,
        events,
        dash_events,
        auth: AuthConfig::from_config(config.ingest, require_strong_ingest)?,
        access: AccessControl::from_config_with_managed_file(
            config.access,
            !internet_mode,
            args.data_dir.join("access-enrollments.json"),
        )?,
        sessions: SessionSigner::load_or_create(
            &session_key_path,
            session_ttl_seconds,
            internet_mode,
        )?,
        public_origin,
        trust_forwarded_for,
        login_limiter: FixedWindowLimiter::new(
            limits.login_attempts_per_minute,
            Duration::from_secs(60),
            10_000,
        )?,
        global_login_limiter: FixedWindowLimiter::new(
            limits.global_login_attempts_per_minute,
            Duration::from_secs(60),
            1,
        )?,
        request_limiter: FixedWindowLimiter::new(
            limits.authenticated_requests_per_minute,
            Duration::from_secs(60),
            10_000,
        )?,
        websocket_attempt_limiter: FixedWindowLimiter::new(
            limits.websocket_attempts_per_minute,
            Duration::from_secs(60),
            10_000,
        )?,
        ingest_attempt_limiter: FixedWindowLimiter::new(
            limits.ingest_attempts_per_minute,
            Duration::from_secs(60),
            10_000,
        )?,
        websocket_slots,
        ingest_slots,
        websocket_principals: KeyedConnectionTracker::new(
            limits.max_websockets_per_principal,
            10_000,
        )?,
        ingest_peers: KeyedConnectionTracker::new(limits.max_ingest_connections_per_ip, 10_000)?,
        ingest_handshake_timeout: Duration::from_secs(limits.ingest_handshake_timeout_seconds),
        ingest_idle_timeout: Duration::from_secs(limits.ingest_idle_timeout_seconds),
        metrics: metrics.clone(),
        traffic: TrafficMetrics::default(),
        retention_bytes_per_stream: args.retention_bytes_per_stream,
        retention_seconds: args.retention_seconds,
        // Only a relay explicitly serving a trusted local network takes them,
        // and never one with a public origin: Internet mode is refused
        // alongside --trusted-lan already, so this cannot both be set.
        allow_unencrypted: args.trusted_lan && !internet_mode,
        active_ingests: Arc::new(AsyncMutex::new(HashMap::new())),
        ingest_private_key: ingest_key.private,
    };
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    tokio::spawn(install_signal_handlers(shutdown_tx.clone()));
    let retention_store = state.dash_store.clone();
    let mut retention_shutdown = shutdown_rx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = wait_for_shutdown(&mut retention_shutdown) => return,
                _ = interval.tick() => {
                    let store = retention_store.clone();
                    match tokio::task::spawn_blocking(move || store.enforce_retention_now()).await {
                        Ok(Ok(0)) => {}
                        Ok(Ok(removed)) => {
                            info!(removed, "expired retained DASH objects");
                        }
                        Ok(Err(err)) => {
                            error!(?err, "periodic DASH retention failed");
                        }
                        Err(err) => {
                            error!(?err, "periodic DASH retention task panicked");
                        }
                    }
                }
            }
        }
    });
    if serve_control {
        let control_shutdown = shutdown_tx.clone();
        tokio::spawn(async move {
            if let Err(err) = serve_control_socket(daemon_socket, control_shutdown).await {
                error!(?err, "daemon control socket stopped");
            }
        });
    }

    let ingest_state = state.clone();
    let ingest_shutdown = shutdown_rx.clone();
    tokio::spawn(async move {
        if let Err(err) = run_ingest(ingest_addr, ingest_state, ingest_shutdown).await {
            error!(?err, "ingest listener stopped");
        }
    });

    let app = Router::new()
        // Watching is what this server is for, so the multi-stream view is the
        // landing page and the operations dashboard lives one click away.
        .route("/", get(watch_viewer))
        .route("/streams", get(index))
        .route("/login", get(login_page))
        .route("/dash/{stream_id}", get(dash_viewer))
        // Kept so links handed out before the move still land somewhere useful.
        .route("/watch", get(|| async { Redirect::permanent("/") }))
        .route("/favicon.ico", get(favicon))
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/session", get(session))
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/api/admin/metrics", get(admin_metrics))
        .route(
            "/api/admin/enrollments",
            get(list_enrollments).post(enroll_viewer),
        )
        .route("/api/admin/enrollments/{name}", delete(revoke_viewer))
        .route("/api/streams", get(list_streams))
        .route("/api/streams/{stream_id}", delete(delete_stream))
        .route("/api/ws", get(control_ws))
        .route(
            "/api/dash/streams/{stream_id}/manifest.mpd",
            get(dash_manifest),
        )
        .route(
            "/api/dash/streams/{stream_id}/objects",
            get(list_dash_objects),
        )
        .route(
            "/api/dash/streams/{stream_id}/objects/{sequence}",
            get(get_dash_object),
        )
        .route(
            "/api/dash/streams/{stream_id}/epochs/{epoch_id}/init.mp4",
            get(get_dash_initialization),
        )
        .route(
            "/api/dash/streams/{stream_id}/epochs/{epoch_id}/media/{segment_file}",
            get(get_dash_segment),
        )
        .route("/api/dash/streams/{stream_id}/live", get(dash_live_ws))
        .route("/assets/index.css", get(index_css))
        .route("/assets/index.js", get(index_js))
        .route("/assets/login.css", get(login_css))
        .route("/assets/login.js", get(login_js))
        .route("/assets/dash-viewer.css", get(dash_viewer_css))
        .route("/assets/dash-viewer-core.js", get(dash_viewer_core_js))
        .route("/assets/dash-viewer.js", get(dash_viewer_js))
        .route("/assets/dash-viewer-page.js", get(dash_viewer_page_js))
        .route("/assets/viewer-key.js", get(viewer_key_js))
        .route("/assets/watch.js", get(watch_js))
        .route("/assets/watch.css", get(watch_css))
        .with_state(state)
        .layer(DefaultBodyLimit::max(4096))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(move |request, next| {
            let http_slots = http_slots.clone();
            let metrics = metrics.clone();
            async move {
                bounded_http_request(
                    request,
                    next,
                    internet_mode,
                    limits.http_timeout_seconds,
                    http_slots,
                    metrics,
                )
                .await
            }
        }));

    if args.trusted_lan {
        warn!(
            control = %control_addr,
            ingest = %ingest_addr,
            "serving a trusted LAN; any host that can reach the ingest port may publish a stream, and stream contents stay end-to-end encrypted"
        );
        // Plaintext past loopback is now a choice rather than the only option,
        // and it is one that stops browsers playing: a plain `http://` origin
        // that is not loopback is not a secure context, so Web Crypto and
        // Encrypted Media Extensions are both withheld.
        if !serve_tls && !control_addr.ip().is_loopback() {
            warn!(
                port = control_addr.port(),
                "browsers reaching this relay at a plaintext address other than loopback cannot \
                 play: encrypted playback needs a secure context. Publishing works; for viewing, \
                 drop --no-tls to serve HTTPS here, or forward this port over SSH to the viewer's \
                 own loopback"
            );
        }
    }

    let scheme = if serve_tls { "https" } else { "http" };
    info!(
        control = %control_addr,
        ingest = %ingest_addr,
        scheme,
        ingest_server_key,
        "glacialcast server listening"
    );

    if serve_tls {
        let material = tls::load_or_create(
            &args.data_dir,
            args.tls_cert.as_deref(),
            args.tls_key.as_deref(),
            control_addr,
            &args.tls_names,
        )?;
        if material.generated {
            // A certificate that signs for itself is not one any browser has a
            // reason to trust, so the first visit stops on a warning. Saying so
            // here, with the fingerprint the browser will show and the address
            // the certificate is actually for, is the difference between an
            // operator accepting a known certificate and clicking through an
            // unknown one out of habit.
            warn!(
                fingerprint = %material.fingerprint,
                valid_for = %material.names.join(", "),
                "serving HTTPS with a self-signed certificate; each browser shows a warning once, \
                 and the fingerprint above is the one it will display. Pass --tls-cert and \
                 --tls-key to use a certificate your viewers already trust"
            );
        }
        // Wrapped in axum's own tap adapter, which is the shape its blanket
        // `Connected` implementation is written against: without it, connect
        // info is only wired up for a plain `TcpListener`, and the handlers
        // that log or rate-limit by peer address would not compile.
        let listener = axum::serve::ListenerExt::tap_io(
            tls::TlsListener::bind(control_addr, &material).await?,
            |_| {},
        );
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            wait_for_shutdown(&mut shutdown_rx).await;
        })
        .await?;
    } else {
        let listener = TcpListener::bind(control_addr).await?;
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            wait_for_shutdown(&mut shutdown_rx).await;
        })
        .await?;
    }
    let _ = shutdown_tx.send(true);
    Ok(())
}

fn validate_limits(limits: &LimitsConfig) -> Result<()> {
    if limits.max_http_in_flight == 0
        || limits.max_websockets == 0
        || limits.max_websockets_per_principal == 0
        || limits.max_websockets_per_principal > limits.max_websockets
        || limits.max_ingest_connections == 0
        || limits.max_ingest_connections_per_ip == 0
        || limits.max_ingest_connections_per_ip > limits.max_ingest_connections
        || limits.login_attempts_per_minute == 0
        || limits.global_login_attempts_per_minute < limits.login_attempts_per_minute
        || limits.authenticated_requests_per_minute == 0
        || limits.websocket_attempts_per_minute == 0
        || limits.ingest_attempts_per_minute == 0
        || !(1..=300).contains(&limits.http_timeout_seconds)
        || !(1..=60).contains(&limits.ingest_handshake_timeout_seconds)
        || !(30..=3600).contains(&limits.ingest_idle_timeout_seconds)
    {
        anyhow::bail!("security limit values are zero, inconsistent, or outside safe bounds");
    }
    Ok(())
}

async fn bounded_http_request(
    request: axum::extract::Request,
    next: middleware::Next,
    hsts: bool,
    timeout_seconds: u64,
    slots: Arc<Semaphore>,
    metrics: Arc<ServerMetrics>,
) -> Response {
    metrics.http_requests.fetch_add(1, Ordering::Relaxed);
    let Ok(_permit) = slots.try_acquire_owned() else {
        metrics.http_overloaded.fetch_add(1, Ordering::Relaxed);
        return security_headers(
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::RETRY_AFTER, "1")],
                "server busy",
            )
                .into_response(),
            hsts,
        );
    };
    let response =
        match tokio::time::timeout(Duration::from_secs(timeout_seconds), next.run(request)).await {
            Ok(response) => response,
            Err(_) => {
                metrics.http_timed_out.fetch_add(1, Ordering::Relaxed);
                (StatusCode::GATEWAY_TIMEOUT, "request timed out").into_response()
            }
        };
    security_headers(response, hsts)
}

fn security_headers(mut response: Response, hsts: bool) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static(
            "camera=(), microphone=(), geolocation=(), display-capture=(), usb=()",
        ),
    );
    headers.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    if hsts {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    if !headers.contains_key(header::CACHE_CONTROL) {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

async fn index(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if request_identity(&state, &headers).is_err() {
        return Redirect::to("/login").into_response();
    }
    static_response(
        "text/html; charset=utf-8",
        include_str!("../static/index.html"),
    )
}

async fn login_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if request_identity(&state, &headers).is_ok() {
        return Redirect::to("/").into_response();
    }
    static_response(
        "text/html; charset=utf-8",
        include_str!("../static/login.html"),
    )
}

async fn dash_viewer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(stream_id): Path<Uuid>,
) -> Response {
    let Ok(identity) = request_identity(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if authorize_stream(&state, &identity.principal, stream_id).is_err() {
        return StatusCode::NOT_FOUND.into_response();
    }
    static_response(
        "text/html; charset=utf-8",
        include_str!("../static/dash-viewer.html"),
    )
}

/// Serves the multi-stream viewer.
///
/// The page itself carries no stream data: it lists what the relay authorizes
/// this principal to see and unlocks each tile from the browser-held keyring,
/// so no per-stream authorization decision is needed here beyond being signed
/// in.
async fn watch_viewer(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if request_identity(&state, &headers).is_err() {
        return Redirect::to("/login").into_response();
    }
    static_response(
        "text/html; charset=utf-8",
        include_str!("../static/watch.html"),
    )
}

async fn favicon() -> StatusCode {
    StatusCode::NO_CONTENT
}

fn static_response(content_type: &'static str, body: &'static str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(body))
        .expect("static response headers are valid")
}

async fn index_css() -> Response {
    static_response(
        "text/css; charset=utf-8",
        include_str!("../static/index.css"),
    )
}

async fn index_js() -> Response {
    static_response(
        "text/javascript; charset=utf-8",
        include_str!("../static/index.js"),
    )
}

async fn login_css() -> Response {
    static_response(
        "text/css; charset=utf-8",
        include_str!("../static/login.css"),
    )
}

async fn login_js() -> Response {
    static_response(
        "text/javascript; charset=utf-8",
        include_str!("../static/login.js"),
    )
}

async fn dash_viewer_css() -> Response {
    static_response(
        "text/css; charset=utf-8",
        include_str!("../static/dash-viewer.css"),
    )
}

async fn dash_viewer_js() -> Response {
    static_response(
        "text/javascript; charset=utf-8",
        include_str!("../static/dash-viewer.js"),
    )
}

async fn watch_js() -> Response {
    static_response(
        "text/javascript; charset=utf-8",
        include_str!("../static/watch.js"),
    )
}

async fn viewer_key_js() -> Response {
    static_response(
        "text/javascript; charset=utf-8",
        include_str!("../static/viewer-key.js"),
    )
}

async fn watch_css() -> Response {
    static_response(
        "text/css; charset=utf-8",
        include_str!("../static/watch.css"),
    )
}

async fn dash_viewer_page_js() -> Response {
    static_response(
        "text/javascript; charset=utf-8",
        include_str!("../static/dash-viewer-page.js"),
    )
}

async fn dash_viewer_core_js() -> Response {
    static_response(
        "text/javascript; charset=utf-8",
        include_str!("../static/dash-viewer-core.js"),
    )
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    token: String,
}

#[derive(Debug, Serialize)]
struct SessionResponse {
    name: String,
    role: AccessRole,
    csrf_token: Option<String>,
}

async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Result<Response, AppError> {
    if !validate_request_origin(&headers, state.public_origin.as_deref()) {
        return Err(AppError::Forbidden);
    }
    let remote_ip = client_ip(&headers, peer.ip(), state.trust_forwarded_for);
    if !state.login_limiter.check(remote_ip.to_string())
        || !state.global_login_limiter.check("global")
    {
        state
            .metrics
            .login_rate_limited
            .fetch_add(1, Ordering::Relaxed);
        warn!(%remote_ip, "viewer login rate limited");
        return Err(AppError::TooManyRequests);
    }
    let Some(principal) = state.access.authenticate_token(&request.token) else {
        state.metrics.login_failures.fetch_add(1, Ordering::Relaxed);
        warn!(%remote_ip, "viewer login failed");
        tokio::time::sleep(Duration::from_millis(250)).await;
        return Err(AppError::Unauthorized);
    };
    let (cookie, csrf_token) = state.sessions.create_session(&principal)?;
    state
        .metrics
        .login_successes
        .fetch_add(1, Ordering::Relaxed);
    info!(
        principal = %principal.name,
        role = ?principal.role,
        %remote_ip,
        "viewer login succeeded"
    );
    Ok((
        [(header::SET_COOKIE, state.sessions.session_cookie(&cookie))],
        Json(SessionResponse {
            name: principal.name,
            role: principal.role,
            csrf_token: Some(csrf_token),
        }),
    )
        .into_response())
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, AppError> {
    let request = request_identity(&state, &headers)?;
    require_mutation_authority(&state, &headers, &request)?;
    info!(principal = %request.principal.name, "viewer logged out");
    Ok((
        [(header::SET_COOKIE, state.sessions.expired_cookie())],
        StatusCode::NO_CONTENT,
    )
        .into_response())
}

async fn session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SessionResponse>, AppError> {
    let request = request_identity(&state, &headers)?;
    Ok(Json(SessionResponse {
        name: request.principal.name,
        role: request.principal.role,
        csrf_token: request.csrf,
    }))
}

async fn health_live() -> &'static str {
    "ok\n"
}

async fn health_ready(State(state): State<AppState>) -> Response {
    match state
        .store
        .healthcheck()
        .and_then(|()| state.dash_store.summaries().map(|_| ()))
    {
        Ok(()) => (StatusCode::OK, "ready\n").into_response(),
        Err(err) => {
            error!(?err, "readiness check failed");
            (StatusCode::SERVICE_UNAVAILABLE, "not ready\n").into_response()
        }
    }
}

#[derive(Serialize)]
struct MetricsResponse {
    http_requests: u64,
    http_overloaded: u64,
    http_timed_out: u64,
    login_successes: u64,
    login_failures: u64,
    login_rate_limited: u64,
    request_rate_limited: u64,
    active_websockets: u64,
    websocket_rejected: u64,
    active_ingest_connections: u64,
    ingest_rejected: u64,
    ingest_auth_failures: u64,
    retention_bytes_per_stream: u64,
    retention_seconds: u64,
    managed_viewers: usize,
    traffic: TrafficSnapshot,
}

async fn admin_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<MetricsResponse>, AppError> {
    let identity = request_identity(&state, &headers)?;
    if !identity.principal.is_admin() {
        return Err(AppError::Forbidden);
    }
    let metrics = &state.metrics;
    Ok(Json(MetricsResponse {
        http_requests: metrics.http_requests.load(Ordering::Relaxed),
        http_overloaded: metrics.http_overloaded.load(Ordering::Relaxed),
        http_timed_out: metrics.http_timed_out.load(Ordering::Relaxed),
        login_successes: metrics.login_successes.load(Ordering::Relaxed),
        login_failures: metrics.login_failures.load(Ordering::Relaxed),
        login_rate_limited: metrics.login_rate_limited.load(Ordering::Relaxed),
        request_rate_limited: metrics.request_rate_limited.load(Ordering::Relaxed),
        active_websockets: metrics.active_websockets.load(Ordering::Relaxed),
        websocket_rejected: metrics.websocket_rejected.load(Ordering::Relaxed),
        active_ingest_connections: metrics.active_ingest_connections.load(Ordering::Relaxed),
        ingest_rejected: metrics.ingest_rejected.load(Ordering::Relaxed),
        ingest_auth_failures: metrics.ingest_auth_failures.load(Ordering::Relaxed),
        retention_bytes_per_stream: state.retention_bytes_per_stream,
        retention_seconds: state.retention_seconds,
        managed_viewers: state.access.managed_viewers()?.len(),
        traffic: state.traffic.snapshot(),
    }))
}

#[derive(Debug, Deserialize)]
struct EnrollViewerRequest {
    name: String,
    publishers: Vec<String>,
}

async fn list_enrollments(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ManagedViewerSummary>>, AppError> {
    let identity = request_identity(&state, &headers)?;
    if !identity.principal.is_admin() {
        return Err(AppError::Forbidden);
    }
    Ok(Json(state.access.managed_viewers()?))
}

async fn enroll_viewer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<EnrollViewerRequest>,
) -> Result<(StatusCode, Json<ManagedViewerEnrollment>), AppError> {
    let identity = request_identity(&state, &headers)?;
    if !identity.principal.is_admin() {
        return Err(AppError::Forbidden);
    }
    require_mutation_authority(&state, &headers, &identity)?;
    let enrollment = state
        .access
        .enroll_viewer(request.name.trim(), request.publishers)
        .map_err(|error| match error {
            ManagedViewerMutationError::Invalid(message) => AppError::BadRequest(message),
            ManagedViewerMutationError::Storage(error) => AppError::Anyhow(error),
        })?;
    info!(
        principal = %identity.principal.name,
        viewer = %enrollment.viewer.name,
        "administrator enrolled managed viewer"
    );
    Ok((StatusCode::CREATED, Json(enrollment)))
}

async fn revoke_viewer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<StatusCode, AppError> {
    let identity = request_identity(&state, &headers)?;
    if !identity.principal.is_admin() {
        return Err(AppError::Forbidden);
    }
    require_mutation_authority(&state, &headers, &identity)?;
    if !state.access.revoke_viewer(name.trim())? {
        return Err(AppError::NotFound);
    }
    info!(
        principal = %identity.principal.name,
        viewer = %name,
        "administrator revoked managed viewer"
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn list_streams(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<axum::Json<Vec<glacialcast_protocol::PublicStream>>, AppError> {
    let identity = request_identity(&state, &headers)?;
    let records = state.store.list_stream_records()?;
    let mut streams: Vec<_> = records
        .into_iter()
        .filter(|record| {
            identity
                .principal
                .can_view_publisher(record.client_id.as_str())
        })
        .map(|record| record.stream)
        .collect();
    let dash_summaries = state.dash_store.summaries()?;
    for stream in &mut streams {
        if let Some(summary) = dash_summaries.get(&stream.stream_id) {
            stream.retained_bytes = stream.retained_bytes.max(summary.bytes);
            stream.last_object_sequence = summary.last_sequence;
        }
    }
    Ok(axum::Json(streams))
}

async fn delete_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(stream_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let identity = request_identity(&state, &headers)?;
    if !identity.principal.is_admin() {
        return Err(AppError::Forbidden);
    }
    require_mutation_authority(&state, &headers, &identity)?;
    if state.store.delete_stream(stream_id)? {
        state.dash_store.delete_stream(stream_id)?;
        state.traffic.forget_stream(stream_id);
        publish_stream_event(&state, "stream_deleted", stream_id);
        info!(
            principal = %identity.principal.name,
            %stream_id,
            "administrator deleted stream"
        );
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound)
    }
}

async fn dash_manifest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(stream_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let identity = request_identity(&state, &headers)?;
    authorize_stream(&state, &identity.principal, stream_id)?;
    let manifest = state
        .dash_store
        .manifest(stream_id, true)?
        .ok_or(AppError::NotFound)?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/dash+xml")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(manifest))
        .expect("static DASH response headers are valid"))
}

async fn list_dash_objects(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(stream_id): Path<Uuid>,
    Query(query): Query<DashObjectListQuery>,
) -> Result<Json<Vec<DashObjectHeader>>, AppError> {
    let identity = request_identity(&state, &headers)?;
    authorize_stream(&state, &identity.principal, stream_id)?;
    Ok(Json(
        state
            .dash_store
            .list(stream_id)?
            .into_iter()
            .filter(|object| {
                query
                    .after_sequence
                    .is_none_or(|sequence| object.header.sequence > sequence)
            })
            .map(|object| object.header)
            .collect(),
    ))
}

#[derive(Debug, Default, Deserialize)]
struct DashObjectListQuery {
    after_sequence: Option<u64>,
}

async fn get_dash_object(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((stream_id, sequence)): Path<(Uuid, u64)>,
) -> Result<Response, AppError> {
    let identity = request_identity(&state, &headers)?;
    authorize_stream(&state, &identity.principal, stream_id)?;
    let object = state
        .dash_store
        .get(stream_id, sequence)?
        .ok_or(AppError::NotFound)?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(
            header::CACHE_CONTROL,
            "private, max-age=31536000, immutable",
        )
        .body(Body::from(object.payload))
        .expect("static DASH response headers are valid"))
}

async fn get_dash_initialization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((stream_id, epoch_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, AppError> {
    let identity = request_identity(&state, &headers)?;
    authorize_stream(&state, &identity.principal, stream_id)?;
    let initialization = state
        .dash_store
        .initialization(stream_id, epoch_id)?
        .ok_or(AppError::NotFound)?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "video/mp4")
        .header(
            header::CACHE_CONTROL,
            "private, max-age=31536000, immutable",
        )
        .body(Body::from(initialization))
        .expect("static DASH response headers are valid"))
}

async fn get_dash_segment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((stream_id, epoch_id, segment_file)): Path<(Uuid, Uuid, String)>,
) -> Result<Response, AppError> {
    let identity = request_identity(&state, &headers)?;
    authorize_stream(&state, &identity.principal, stream_id)?;
    let segment_number = segment_file
        .strip_suffix(".m4s")
        .ok_or_else(|| anyhow::anyhow!("DASH segment path must end in .m4s"))?
        .parse::<u64>()
        .context("parsing DASH segment number")?;
    let segment = state
        .dash_store
        .media_segment(stream_id, epoch_id, segment_number)?
        .ok_or(AppError::NotFound)?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "video/iso.segment")
        .header(
            header::CACHE_CONTROL,
            "private, max-age=31536000, immutable",
        )
        .body(Body::from(segment))
        .expect("static DASH response headers are valid"))
}

async fn dash_live_ws(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(stream_id): Path<Uuid>,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    let identity = request_identity(&state, &headers)?;
    authorize_stream(&state, &identity.principal, stream_id)?;
    if !validate_request_origin(&headers, state.public_origin.as_deref()) {
        return Err(AppError::Forbidden);
    }
    let guard = websocket_guard(&state, &identity.principal.name)?;
    Ok(ws
        .on_upgrade(move |socket| dash_live_socket(socket, state, stream_id, guard))
        .into_response())
}

async fn dash_live_socket(
    socket: WebSocket,
    state: AppState,
    stream_id: Uuid,
    _guard: ConnectionGuard,
) {
    let mut rx = state.dash_events.subscribe();
    let (mut sender, mut receiver) = socket.split();
    let send_task = tokio::spawn(async move {
        loop {
            let header = match rx.recv().await {
                Ok(header) => header,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            };
            if header.stream_id != stream_id {
                continue;
            }
            let Ok(json) = serde_json::to_string(&header) else {
                continue;
            };
            if sender.send(Message::Text(json.into())).await.is_err() {
                break;
            }
        }
    });

    while let Some(Ok(message)) = receiver.next().await {
        if matches!(message, Message::Close(_)) {
            break;
        }
    }
    send_task.abort();
}

async fn control_ws(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    let identity = request_identity(&state, &headers)?;
    if !validate_request_origin(&headers, state.public_origin.as_deref()) {
        return Err(AppError::Forbidden);
    }
    let guard = websocket_guard(&state, &identity.principal.name)?;
    Ok(ws
        .on_upgrade(move |socket| control_socket(socket, state, identity.principal, guard))
        .into_response())
}

async fn control_socket(
    socket: WebSocket,
    state: AppState,
    principal: Principal,
    _guard: ConnectionGuard,
) {
    let mut rx = state.events.subscribe();
    let (mut sender, mut receiver) = socket.split();
    let send_task = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            let allowed = state
                .store
                .client_id_for_stream(event.stream_id)
                .ok()
                .flatten()
                .is_some_and(|publisher| principal.can_view_publisher(&publisher));
            if !allowed {
                continue;
            }
            if sender
                .send(Message::Text(encode_ws_event(&event).into()))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    while let Some(Ok(message)) = receiver.next().await {
        if matches!(message, Message::Close(_)) {
            break;
        }
    }

    send_task.abort();
}

fn request_identity(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedRequest, AppError> {
    let request = state
        .sessions
        .authenticate(headers, &state.access)
        .or_else(|| {
            state
                .access
                .local_principal()
                .map(|principal| AuthenticatedRequest {
                    principal,
                    csrf: None,
                })
        })
        .ok_or(AppError::Unauthorized)?;
    if !state.request_limiter.check(request.principal.name.as_str()) {
        state
            .metrics
            .request_rate_limited
            .fetch_add(1, Ordering::Relaxed);
        return Err(AppError::TooManyRequests);
    }
    Ok(request)
}

fn authorize_stream(
    state: &AppState,
    principal: &Principal,
    stream_id: Uuid,
) -> Result<(), AppError> {
    let publisher = state
        .store
        .client_id_for_stream(stream_id)?
        .ok_or(AppError::NotFound)?;
    if !principal.can_view_publisher(&publisher) {
        // Do not disclose the existence of streams outside the principal's
        // configured publisher scope.
        return Err(AppError::NotFound);
    }
    Ok(())
}

fn require_mutation_authority(
    state: &AppState,
    headers: &HeaderMap,
    request: &AuthenticatedRequest,
) -> Result<(), AppError> {
    if !validate_request_origin(headers, state.public_origin.as_deref())
        || !state.sessions.verify_csrf(request, headers)
    {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

struct ConnectionGuard {
    _permit: OwnedSemaphorePermit,
    _keyed: KeyedConnectionGuard,
    metrics: Arc<ServerMetrics>,
    kind: ConnectionKind,
}

#[derive(Clone, Copy)]
enum ConnectionKind {
    WebSocket,
    Ingest,
}

impl ConnectionGuard {
    fn new(
        permit: OwnedSemaphorePermit,
        keyed: KeyedConnectionGuard,
        metrics: Arc<ServerMetrics>,
        kind: ConnectionKind,
    ) -> Self {
        match kind {
            ConnectionKind::WebSocket => {
                metrics.active_websockets.fetch_add(1, Ordering::Relaxed);
            }
            ConnectionKind::Ingest => {
                metrics
                    .active_ingest_connections
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        Self {
            _permit: permit,
            _keyed: keyed,
            metrics,
            kind,
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        match self.kind {
            ConnectionKind::WebSocket => {
                self.metrics
                    .active_websockets
                    .fetch_sub(1, Ordering::Relaxed);
            }
            ConnectionKind::Ingest => {
                self.metrics
                    .active_ingest_connections
                    .fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
}

#[derive(Clone)]
struct KeyedConnectionTracker {
    counts: Arc<StdMutex<HashMap<String, usize>>>,
    per_key_limit: usize,
    max_keys: usize,
}

impl KeyedConnectionTracker {
    fn new(per_key_limit: usize, max_keys: usize) -> Result<Self> {
        if per_key_limit == 0 || max_keys == 0 {
            anyhow::bail!("connection tracker limits must be nonzero");
        }
        Ok(Self {
            counts: Arc::new(StdMutex::new(HashMap::new())),
            per_key_limit,
            max_keys,
        })
    }

    fn try_acquire(&self, key: impl Into<String>) -> Option<KeyedConnectionGuard> {
        let key = key.into();
        let mut counts = self.counts.lock().ok()?;
        let existing = counts.get(&key).copied().unwrap_or(0);
        if existing >= self.per_key_limit || (existing == 0 && counts.len() >= self.max_keys) {
            return None;
        }
        counts.insert(key.clone(), existing + 1);
        drop(counts);
        Some(KeyedConnectionGuard {
            tracker: self.clone(),
            key,
        })
    }
}

struct KeyedConnectionGuard {
    tracker: KeyedConnectionTracker,
    key: String,
}

impl Drop for KeyedConnectionGuard {
    fn drop(&mut self) {
        let Ok(mut counts) = self.tracker.counts.lock() else {
            return;
        };
        let Some(count) = counts.get_mut(&self.key) else {
            return;
        };
        *count -= 1;
        if *count == 0 {
            counts.remove(&self.key);
        }
    }
}

fn websocket_guard(state: &AppState, principal_name: &str) -> Result<ConnectionGuard, AppError> {
    if !state.websocket_attempt_limiter.check(principal_name) {
        state
            .metrics
            .websocket_rejected
            .fetch_add(1, Ordering::Relaxed);
        return Err(AppError::TooManyRequests);
    }
    let keyed = state
        .websocket_principals
        .try_acquire(principal_name)
        .ok_or_else(|| {
            state
                .metrics
                .websocket_rejected
                .fetch_add(1, Ordering::Relaxed);
            AppError::TooManyRequests
        })?;
    let permit = state
        .websocket_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            state
                .metrics
                .websocket_rejected
                .fetch_add(1, Ordering::Relaxed);
            AppError::TooManyRequests
        })?;
    Ok(ConnectionGuard::new(
        permit,
        keyed,
        state.metrics.clone(),
        ConnectionKind::WebSocket,
    ))
}

/// Refuses an epoch published without encryption unless this relay takes them.
///
/// The descriptor is plaintext JSON carried in the epoch object, so the relay
/// can read the claim without any viewer key -- which is the whole point: an
/// unencrypted epoch has no key, and the relay has never had one anyway.
///
/// An epoch whose descriptor cannot be parsed is left alone. The relay treats
/// object payloads as opaque everywhere else, and a descriptor it cannot read
/// is not a claim to be unencrypted; refusing on a parse failure would make the
/// relay reject objects it has no business interpreting.
///
/// # Errors
///
/// Returns an error when the epoch declares itself unencrypted and this relay
/// is not serving a trusted local network.
fn refuse_unencrypted_epoch(object: &DashObject, allow_unencrypted: bool) -> Result<()> {
    if allow_unencrypted || object.header.kind != DashObjectKind::Epoch {
        return Ok(());
    }
    let Ok(descriptor) = EpochDescriptor::from_json(&object.payload) else {
        return Ok(());
    };
    if descriptor.encrypted {
        return Ok(());
    }
    anyhow::bail!(
        "refusing an unencrypted epoch: this relay serves streams end-to-end encrypted. \
         Start it with --trusted-lan to accept publishers that send in the clear"
    )
}

async fn run_ingest(
    addr: SocketAddr,
    state: AppState,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "ingest listener ready");
    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => accepted?,
            _ = wait_for_shutdown(&mut shutdown_rx) => break,
        };
        let peer_key = peer.ip().to_string();
        if !state.ingest_attempt_limiter.check(&peer_key) {
            state
                .metrics
                .ingest_rejected
                .fetch_add(1, Ordering::Relaxed);
            warn!(%peer, "ingest connection rate limit reached");
            continue;
        }
        let Some(keyed) = state.ingest_peers.try_acquire(peer_key) else {
            state
                .metrics
                .ingest_rejected
                .fetch_add(1, Ordering::Relaxed);
            warn!(%peer, "ingest per-address connection limit reached");
            continue;
        };
        let permit = match state.ingest_slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                state
                    .metrics
                    .ingest_rejected
                    .fetch_add(1, Ordering::Relaxed);
                warn!(%peer, "ingest connection limit reached");
                continue;
            }
        };
        if let Err(err) = stream.set_nodelay(true) {
            debug!(%peer, ?err, "could not enable TCP_NODELAY for ingest");
        }
        let guard =
            ConnectionGuard::new(permit, keyed, state.metrics.clone(), ConnectionKind::Ingest);
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_ingest(stream, state, guard).await {
                warn!(%peer, ?err, "ingest connection failed");
            }
        });
    }
    Ok(())
}

async fn handle_ingest(
    mut stream: TcpStream,
    state: AppState,
    _guard: ConnectionGuard,
) -> Result<()> {
    let transport = tokio::time::timeout(
        state.ingest_handshake_timeout,
        responder_handshake(&mut stream, &state.ingest_private_key),
    )
    .await
    .context("Noise handshake timed out")??;
    let mut socket = glacialcast_protocol::NoiseSocket::new(stream, transport);
    let hello = match tokio::time::timeout(
        state.ingest_handshake_timeout,
        socket.read_limited::<ClientMessage>(16 * 1024),
    )
    .await
    .context("publisher hello timed out")??
    {
        ClientMessage::Hello(hello) => hello,
        _ => {
            socket
                .write(&ServerMessage::HelloAck {
                    accepted: false,
                    reason: Some("expected publisher hello".to_string()),
                    stream_id: None,
                    last_sequence: 0,
                    server_time_ms: now_ms(),
                })
                .await?;
            return Ok(());
        }
    };

    let authenticated = match authenticate_hello(&state, &hello).await {
        Ok(authenticated) => authenticated,
        Err(err) => {
            state
                .metrics
                .ingest_auth_failures
                .fetch_add(1, Ordering::Relaxed);
            warn!(?err, "publisher authentication failed");
            tokio::time::sleep(Duration::from_millis(250)).await;
            socket
                .write(&ServerMessage::HelloAck {
                    accepted: false,
                    reason: Some("publisher authentication failed".to_string()),
                    stream_id: None,
                    last_sequence: 0,
                    server_time_ms: now_ms(),
                })
                .await?;
            return Ok(());
        }
    };
    let viewer_key_salt = validate_viewer_key_salt(hello.viewer_key_salt.as_deref())?;
    let stream_id = state.store.ensure_stream_for_client(
        &authenticated.identity,
        &hello.display_name,
        &hello.source,
        viewer_key_salt,
    )?;
    let last_seq = state.dash_store.last_sequence(stream_id)?.unwrap_or(0);
    socket
        .write(&ServerMessage::HelloAck {
            accepted: true,
            reason: None,
            stream_id: Some(stream_id),
            last_sequence: last_seq,
            server_time_ms: now_ms(),
        })
        .await?;
    let connection_id = Uuid::new_v4();
    state
        .active_ingests
        .lock()
        .await
        .insert(stream_id, connection_id);
    publish_stream_event(&state, "stream_connected", stream_id);
    let result = ingest_loop(
        &state,
        &mut socket,
        stream_id,
        last_seq,
        state.ingest_idle_timeout,
    )
    .await;
    let mut active_ingests = state.active_ingests.lock().await;
    let owns_connection = active_ingests.get(&stream_id) == Some(&connection_id);
    if owns_connection {
        active_ingests.remove(&stream_id);
    }
    drop(active_ingests);
    if owns_connection {
        state.store.mark_stream_inactive(stream_id)?;
        publish_stream_event(&state, "stream_disconnected", stream_id);
    }
    if let Err(err) = &result {
        debug!(%stream_id, ?err, "ingest loop ended with error");
    }
    if result
        .as_ref()
        .is_err_and(|err| err.to_string().contains("unexpected end of file"))
    {
        return Ok(());
    }
    result
}

async fn ingest_loop(
    state: &AppState,
    socket: &mut glacialcast_protocol::NoiseSocket<TcpStream>,
    stream_id: Uuid,
    mut last_seq: u64,
    idle_timeout: Duration,
) -> Result<()> {
    loop {
        let message = tokio::time::timeout(idle_timeout, socket.read::<ClientMessage>())
            .await
            .context("publisher connection idle timeout")?;
        match message {
            Ok(ClientMessage::DashObject(object)) => {
                object.validate().context("validating DASH ingest object")?;
                if !state.store.stream_exists(stream_id)? {
                    anyhow::bail!("stream was deleted");
                }
                if object.header.stream_id != stream_id {
                    anyhow::bail!("DASH object stream_id does not match assigned stream");
                }
                let expected_sequence = last_seq
                    .checked_add(1)
                    .context("DASH sequence space exhausted")?;
                if object.header.sequence > expected_sequence {
                    socket
                        .write(&ServerMessage::ResendRequest {
                            from_seq: expected_sequence,
                            to_seq: object.header.sequence,
                        })
                        .await?;
                    continue;
                }
                refuse_unencrypted_epoch(&object, state.allow_unencrypted)?;
                let is_new = object.header.sequence == expected_sequence;
                let object_kind = object.header.kind;
                let object_bytes = u64::from(object.header.payload_len);
                // Off the runtime: storing an object writes the payload and
                // appends to the journal, and fsyncs both. On the async path
                // that parked a worker thread for the length of a disk flush,
                // once per object per publisher, delaying every websocket and
                // HTTP request sharing that thread. Retention already runs this
                // way; the hot path is the one that needed it.
                let store = state.dash_store.clone();
                let stored = tokio::task::spawn_blocking(move || store.store(object))
                    .await
                    .context("joining the DASH store task")??;
                last_seq = last_seq.max(stored.header.sequence);
                if is_new {
                    state.traffic.record(stream_id, object_kind, object_bytes);
                }
                let _ = state.dash_events.send(stored.header);
                socket
                    .write(&ServerMessage::Ack {
                        through_seq: last_seq,
                    })
                    .await?;
            }
            Ok(ClientMessage::Ping { .. }) => {
                socket
                    .write(&ServerMessage::Pong { now_ms: now_ms() })
                    .await?;
            }
            Ok(ClientMessage::Hello(_)) => {}
            Err(err) => return Err(err.into()),
        }
    }
}

fn publish_stream_event(state: &AppState, event: &str, stream_id: Uuid) {
    let _ = state.events.send(ControlEvent {
        event: event.to_string(),
        stream_id,
    });
}

async fn authenticate_hello(state: &AppState, hello: &StreamHello) -> Result<AuthenticatedClient> {
    if hello.protocol_version != glacialcast_protocol::PROTOCOL_VERSION {
        anyhow::bail!("unsupported protocol version {}", hello.protocol_version);
    }
    if hello.display_name.trim().is_empty() || hello.display_name.len() > 256 {
        anyhow::bail!("display_name must contain 1 to 256 bytes");
    }
    if hello.source.backend.trim().is_empty() || hello.source.backend.len() > 128 {
        anyhow::bail!("source backend must contain 1 to 128 bytes");
    }
    if hello.source.description.trim().is_empty() || hello.source.description.len() > 1024 {
        anyhow::bail!("source description must contain 1 to 1024 bytes");
    }
    if hello.source.width == 0
        || hello.source.height == 0
        || hello.source.width > 16_384
        || hello.source.height > 16_384
    {
        anyhow::bail!("source dimensions must be between 1 and 16384");
    }
    if matches!(
        (hello.resend_low, hello.resend_high),
        (Some(low), Some(high)) if low > high
    ) {
        anyhow::bail!("resend range is inverted");
    }

    let principal = state
        .auth
        .authenticate(hello.auth_token.as_deref(), &hello.client_id)?;
    let identity = match hello.source_label.as_deref() {
        Some(label) => format!(
            "{principal}{IDENTITY_LABEL_SEPARATOR}{}",
            validate_source_label(label)?
        ),
        None => principal,
    };
    Ok(AuthenticatedClient { identity })
}

/// Separates the authenticated principal from a publisher-chosen output label.
///
/// Viewer scopes are matched against the principal alone, so this character
/// must never appear inside either half.
pub(crate) const IDENTITY_LABEL_SEPARATOR: char = ':';

/// The longest accepted per-output label.
const MAX_SOURCE_LABEL_LEN: usize = 64;

/// Validates a publisher-supplied output label.
///
/// The label is concatenated onto an authenticated principal to build the
/// durable stream identity, so a label containing the separator would let one
/// publisher impersonate another principal's stream. Only unreserved ASCII is
/// accepted for the same reason.
fn validate_source_label(label: &str) -> Result<&str> {
    if label.is_empty() || label.len() > MAX_SOURCE_LABEL_LEN {
        anyhow::bail!("source label must contain 1 to {MAX_SOURCE_LABEL_LEN} bytes");
    }
    // No '.' and no separator: the label is concatenated onto an
    // authenticated principal, and keeping it free of both path syntax and the
    // separator means it can never forge another principal's identity nor be
    // mistaken for a path component by anything downstream.
    if !label
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        anyhow::bail!("source label may only contain ASCII letters, digits, '-', and '_'");
    }
    Ok(label)
}

/// Validates a publisher-supplied viewer-key salt.
///
/// The salt is not a secret, but it is publisher-controlled data that the relay
/// stores and hands back to every viewer, so it is bounded to exactly what a
/// salt can be: unpadded URL-safe base64 decoding to [`SALT_LEN`] bytes.
/// Anything else is rejected rather than stored and echoed.
fn validate_viewer_key_salt(salt: Option<&str>) -> Result<Option<&str>> {
    let Some(salt) = salt else {
        return Ok(None);
    };
    let decoded = URL_SAFE_NO_PAD
        .decode(salt)
        .context("viewer key salt must be unpadded URL-safe base64")?;
    if decoded.len() != SALT_LEN {
        anyhow::bail!(
            "viewer key salt must decode to {SALT_LEN} bytes, got {}",
            decoded.len()
        );
    }
    Ok(Some(salt))
}

fn hash_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token_config(require_token: bool) -> IngestConfig {
        IngestConfig {
            require_token,
            tokens: vec![ConfiguredIngestToken {
                name: "laptop".to_string(),
                token: "secret".to_string(),
                previous_tokens: Vec::new(),
            }],
        }
    }

    /// Parses from an explicit argv so the flag wiring is covered too, and so a
    /// `GLACIALCAST_*` variable in the developer's shell cannot decide the
    /// result.
    fn server_args(flags: &[&str]) -> Args {
        let mut argv = vec!["glacialcast-server"];
        argv.extend_from_slice(flags);
        Args::parse_from(argv)
    }

    fn epoch_object(encrypted: bool) -> DashObject {
        use glacialcast_dash::{EpochKeys, MEDIA_TIMESCALE};
        let stream_id = Uuid::new_v4();
        let epoch_id = Uuid::new_v4();
        let keys = EpochKeys::derive(&[9u8; 32], stream_id, epoch_id).unwrap();
        let descriptor = EpochDescriptor {
            format_version: 1,
            stream_id,
            epoch_id,
            key_id: *epoch_id.as_bytes(),
            width: 1920,
            height: 1080,
            codec: "avc1.42c028".to_string(),
            timescale: MEDIA_TIMESCALE,
            segment_frames: 5,
            availability_start_time: "2026-01-01T00:00:00.000Z".to_string(),
            encrypted,
        };
        DashObject::authenticated(
            glacialcast_protocol::NewDashObject {
                stream_id,
                epoch_id,
                kind: DashObjectKind::Epoch,
                sequence: 1,
                segment_number: 0,
                chunk_index: 0,
                timestamp: 0,
                duration: 0,
                random_access: true,
                mime: "application/vnd.glacialcast.epoch+json",
                payload: descriptor.to_json().unwrap(),
            },
            &keys,
        )
        .unwrap()
    }

    #[test]
    fn a_publisher_cannot_send_in_the_clear_to_an_encrypted_relay() {
        // The publisher declares this, so the relay has to be the one that
        // refuses: a publisher choosing to send in the clear is exactly the one
        // that will not refuse itself.
        let error = refuse_unencrypted_epoch(&epoch_object(false), false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("refusing an unencrypted epoch"), "{error}");
        assert!(error.contains("--trusted-lan"), "{error}");

        // A relay serving a trusted LAN takes it.
        assert!(refuse_unencrypted_epoch(&epoch_object(false), true).is_ok());
        // And an encrypted epoch is accepted either way.
        assert!(refuse_unencrypted_epoch(&epoch_object(true), false).is_ok());
        assert!(refuse_unencrypted_epoch(&epoch_object(true), true).is_ok());
    }

    #[test]
    fn an_unreadable_descriptor_is_not_treated_as_a_claim() {
        // Payloads are opaque to the relay everywhere else. A descriptor it
        // cannot parse is not a claim to be unencrypted, and refusing on a
        // parse failure would have the relay rejecting objects it has no
        // business interpreting.
        let mut object = epoch_object(true);
        object.payload = b"not json at all".to_vec();
        assert!(refuse_unencrypted_epoch(&object, false).is_ok());

        // A non-epoch object is never inspected, whatever it carries.
        let mut media = epoch_object(false);
        media.header.kind = DashObjectKind::Media;
        assert!(refuse_unencrypted_epoch(&media, false).is_ok());
    }

    #[test]
    fn listeners_stay_on_loopback_without_a_profile() {
        let plan = plan_listeners(&server_args(&[]), false, false).unwrap();
        assert_eq!(plan.control_addr, "127.0.0.1:8899".parse().unwrap());
        assert_eq!(plan.ingest_addr, "127.0.0.1:8900".parse().unwrap());
        // A loopback ingest listener is reachable only from this host, so no
        // token is demanded and none has a strength floor to clear.
        assert!(!plan.require_strong_ingest);
    }

    #[test]
    fn trusted_lan_opens_both_listeners_and_waives_the_ingest_token() {
        // The point of the flag: this is the whole publisher-side setup, with
        // no server.toml and no shared secret.
        let plan = plan_listeners(&server_args(&["--trusted-lan"]), false, false).unwrap();
        assert_eq!(plan.control_addr, "0.0.0.0:8899".parse().unwrap());
        assert_eq!(plan.ingest_addr, "0.0.0.0:8900".parse().unwrap());
        // The floor exists for tokens guessed at from the Internet, and this
        // listener is not on it.
        assert!(!plan.require_strong_ingest);
    }

    #[test]
    fn an_explicit_address_wins_over_the_profile_default() {
        let plan = plan_listeners(
            &server_args(&["--trusted-lan", "--control-addr", "127.0.0.1:9100"]),
            false,
            false,
        )
        .unwrap();
        assert_eq!(plan.control_addr, "127.0.0.1:9100".parse().unwrap());
        // Only the address that was named moves; the other keeps the default
        // the profile carries.
        assert_eq!(plan.ingest_addr, "0.0.0.0:8900".parse().unwrap());
    }

    #[test]
    fn a_non_loopback_listener_is_refused_without_a_profile() {
        // Neither relaxation is in play, so both listeners must be refused
        // rather than quietly served in plaintext or without a token.
        let plaintext = plan_listeners(
            &server_args(&["--control-addr", "0.0.0.0:8899"]),
            false,
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(
            plaintext.contains("refusing a non-loopback HTTP listener"),
            "{plaintext}"
        );

        let untokened = plan_listeners(
            &server_args(&["--ingest-addr", "0.0.0.0:8900"]),
            false,
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(
            untokened.contains("requires ingest.require_token"),
            "{untokened}"
        );
    }

    #[test]
    fn trusted_lan_is_refused_alongside_internet_mode() {
        // The two profiles describe opposite networks. Letting this through
        // would serve a public origin's traffic in plaintext and accept
        // publishers off the Internet with no token at all.
        let error = plan_listeners(&server_args(&["--trusted-lan"]), true, true)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("cannot be combined with security.public_origin"),
            "{error}"
        );
    }

    #[test]
    fn internet_mode_keeps_its_loopback_and_strength_requirements() {
        // The trusted-LAN work must not have loosened the Internet profile.
        let error = plan_listeners(
            &server_args(&["--control-addr", "0.0.0.0:8899", "--allow-insecure-http"]),
            true,
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("Internet mode requires a loopback HTTP listener"),
            "{error}"
        );

        let plan = plan_listeners(&server_args(&[]), true, true).unwrap();
        assert!(plan.require_strong_ingest);
    }

    #[test]
    fn allow_insecure_http_alone_still_demands_an_ingest_token() {
        // The older flag only ever spoke for the HTTP listener. Reading it as a
        // blanket trusted-LAN assertion would waive a token the operator never
        // agreed to waive.
        let error = plan_listeners(
            &server_args(&[
                "--allow-insecure-http",
                "--control-addr",
                "0.0.0.0:8899",
                "--ingest-addr",
                "0.0.0.0:8900",
            ]),
            false,
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("requires ingest.require_token"), "{error}");
    }

    #[test]
    fn source_labels_cannot_forge_another_principal() {
        assert_eq!(validate_source_label("DP-1").unwrap(), "DP-1");
        assert_eq!(validate_source_label("HDMI-A-1").unwrap(), "HDMI-A-1");
        // The durable identity is `<principal>:<label>` and viewer scopes match
        // on the part before the separator, so a label carrying one would let
        // this publisher register under a principal it never authenticated as.
        assert!(validate_source_label("a:admin").is_err());
        assert!(validate_source_label("../secrets").is_err());
        assert!(validate_source_label("with space").is_err());
        assert!(validate_source_label("new\nline").is_err());
        assert!(validate_source_label("").is_err());
        assert!(validate_source_label(&"x".repeat(65)).is_err());
        assert!(validate_source_label(&"x".repeat(64)).is_ok());
    }

    #[test]
    fn optional_auth_accepts_client_id_without_token() {
        let auth = AuthConfig::from_config(token_config(false), false).unwrap();
        assert_eq!(auth.authenticate(None, "desk").unwrap(), "desk");
    }

    #[test]
    fn configured_token_maps_to_client_identity() {
        let auth = AuthConfig::from_config(token_config(false), false).unwrap();
        assert_eq!(
            auth.authenticate(Some("secret"), "spoofed").unwrap(),
            "laptop"
        );
    }

    #[test]
    fn required_auth_rejects_missing_token() {
        let auth = AuthConfig::from_config(token_config(true), false).unwrap();
        assert!(auth.authenticate(None, "desk").is_err());
    }

    #[test]
    fn invalid_token_is_rejected_even_when_optional() {
        let auth = AuthConfig::from_config(token_config(false), false).unwrap();
        assert!(auth.authenticate(Some("wrong"), "desk").is_err());
    }

    #[test]
    fn internet_ingest_requires_strong_tokens_and_supports_rotation() {
        assert!(AuthConfig::from_config(token_config(true), true).is_err());
        let mut config = token_config(true);
        config.tokens[0].token = "current-0123456789abcdef0123456789".to_string();
        config.tokens[0].previous_tokens = vec!["previous-0123456789abcdef01234567".to_string()];
        let auth = AuthConfig::from_config(config, true).unwrap();
        assert_eq!(
            auth.authenticate(Some("current-0123456789abcdef0123456789"), "ignored")
                .unwrap(),
            "laptop"
        );
        assert_eq!(
            auth.authenticate(Some("previous-0123456789abcdef01234567"), "ignored")
                .unwrap(),
            "laptop"
        );
    }

    #[test]
    fn keyed_connection_tracker_enforces_per_key_and_memory_limits() {
        let tracker = KeyedConnectionTracker::new(2, 2).unwrap();
        let first = tracker.try_acquire("one").unwrap();
        let second = tracker.try_acquire("one").unwrap();
        assert!(tracker.try_acquire("one").is_none());
        let other = tracker.try_acquire("two").unwrap();
        assert!(tracker.try_acquire("three").is_none());
        drop(first);
        assert!(tracker.try_acquire("one").is_some());
        drop(second);
        drop(other);
        assert!(tracker.try_acquire("three").is_some());
    }

    #[test]
    fn security_limits_reject_unsafe_or_inconsistent_values() {
        let mut limits = LimitsConfig::default();
        assert!(validate_limits(&limits).is_ok());
        limits.max_websockets_per_principal = limits.max_websockets + 1;
        assert!(validate_limits(&limits).is_err());
        limits = LimitsConfig::default();
        limits.max_ingest_connections_per_ip = 0;
        assert!(validate_limits(&limits).is_err());
        limits = LimitsConfig::default();
        limits.ingest_idle_timeout_seconds = 29;
        assert!(validate_limits(&limits).is_err());
    }

    #[test]
    fn server_config_must_be_private_regular_and_rejects_unknown_keys() {
        let root =
            std::env::temp_dir().join(format!("glacialcast-server-config-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("server.toml");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(b"[ingest]\nrequire_token = false\n")
            .unwrap();
        drop(file);
        assert!(!load_server_config(&path).unwrap().ingest.require_token);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_server_config(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, "unknown_security_setting = true\n").unwrap();
        assert!(load_server_config(&path).is_err());

        let link = root.join("server-link.toml");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(load_server_config(&link).is_err());
        let dangling = root.join("server-dangling.toml");
        std::os::unix::fs::symlink(root.join("missing.toml"), &dangling).unwrap();
        assert!(load_server_config(&dangling).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ingest_noise_identity_is_private_and_persistent() {
        let dir = std::env::temp_dir().join(format!("glacialcast-noise-key-{}", Uuid::new_v4()));
        let path = dir.join("identity.key");
        let created = load_or_create_ingest_key(&path).unwrap();
        let loaded = load_or_create_ingest_key(&path).unwrap();
        assert_eq!(created, loaded);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn ingest_noise_identity_rejects_public_permissions() {
        let dir = std::env::temp_dir().join(format!("glacialcast-noise-key-{}", Uuid::new_v4()));
        let path = dir.join("identity.key");
        load_or_create_ingest_key(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_ingest_key(&path).is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }
}

#[derive(Debug)]
enum AppError {
    NotFound,
    BadRequest(String),
    Unauthorized,
    Forbidden,
    TooManyRequests,
    Anyhow(anyhow::Error),
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(value: E) -> Self {
        Self::Anyhow(value.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::NotFound => (StatusCode::NOT_FOUND, "not found").into_response(),
            AppError::BadRequest(message) => (StatusCode::BAD_REQUEST, message).into_response(),
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Bearer")],
                "authentication required",
            )
                .into_response(),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "forbidden").into_response(),
            AppError::TooManyRequests => (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, "60")],
                "rate limit exceeded",
            )
                .into_response(),
            AppError::Anyhow(err) => {
                error!(?err, "request failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
            }
        }
    }
}
