mod dash_store;
mod storage;

use crate::{dash_store::DashStore, storage::Store};
use anyhow::{Context, Result};
use axum::{
    Json, Router,
    body::Body,
    extract::{
        Path, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{delete, get},
};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use glacialcast_protocol::{
    ClientMessage, ControlEvent, DashObjectHeader, NOISE_KEY_LEN, NoiseKeypair, ServerMessage,
    StreamHello,
    daemon::{
        daemonize_if_requested, install_signal_handlers, manager_command, serve_control_socket,
        wait_for_shutdown,
    },
    encode_noise_public_key, encode_ws_event, generate_noise_keypair, now_ms, parse_human_bytes,
    responder_handshake,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    io::{Read, Write},
    net::SocketAddr,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path as FsPath, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex as AsyncMutex, broadcast, watch},
};
use tower_http::services::ServeDir;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, env = "GLACIALCAST_CONFIG", default_value = "server.toml")]
    config: PathBuf,
    #[arg(
        long,
        env = "GLACIALCAST_CONTROL_ADDR",
        default_value = "127.0.0.1:8899"
    )]
    control_addr: SocketAddr,
    #[arg(
        long,
        env = "GLACIALCAST_INGEST_ADDR",
        default_value = "127.0.0.1:8900"
    )]
    ingest_addr: SocketAddr,
    #[arg(long, env = "GLACIALCAST_DATA_DIR", default_value = "data")]
    data_dir: PathBuf,
    #[arg(long, env = "GLACIALCAST_INGEST_KEY_FILE")]
    ingest_key_file: Option<PathBuf>,
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
}

#[derive(Clone)]
struct AppState {
    store: Store,
    dash_store: DashStore,
    events: broadcast::Sender<ControlEvent>,
    dash_events: broadcast::Sender<DashObjectHeader>,
    auth: AuthConfig,
    active_ingests: Arc<AsyncMutex<HashMap<Uuid, Uuid>>>,
    ingest_private_key: [u8; NOISE_KEY_LEN],
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ServerConfig {
    ingest: IngestConfig,
}

fn load_server_config(path: &PathBuf) -> Result<ServerConfig> {
    if !path.exists() {
        return Ok(ServerConfig::default());
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading server config {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("parsing server config {}", path.display()))
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct IngestConfig {
    require_token: bool,
    tokens: Vec<ConfiguredIngestToken>,
}

#[derive(Debug, Clone, Deserialize)]
struct ConfiguredIngestToken {
    name: String,
    token: String,
}

#[derive(Clone)]
struct AuthConfig {
    require_token: bool,
    token_hash_to_name: HashMap<String, String>,
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
    fn from_config(config: IngestConfig) -> Result<Self> {
        if config.require_token && config.tokens.is_empty() {
            anyhow::bail!("server config requires ingest tokens but none were configured");
        }

        let mut token_hash_to_name = HashMap::new();
        let mut names = HashSet::new();
        for token in config.tokens {
            let name = token.name.trim();
            let value = token.token.trim();
            if name.is_empty() {
                anyhow::bail!("configured ingest token name must not be empty");
            }
            if value.is_empty() {
                anyhow::bail!("configured ingest token for {name} must not be empty");
            }
            if !names.insert(name.to_string()) {
                anyhow::bail!("duplicate ingest token name {name}");
            }
            if token_hash_to_name
                .insert(hash_token(value), name.to_string())
                .is_some()
            {
                anyhow::bail!("duplicate ingest token value for {name}");
            }
        }

        Ok(Self {
            require_token: config.require_token,
            token_hash_to_name,
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
                self.token_hash_to_name
                    .get(&hash)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("invalid ingest token"))
            }
            _ if self.require_token => anyhow::bail!("ingest token required"),
            _ => Ok(client_id.to_string()),
        }
    }
}

fn main() -> Result<()> {
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
    )? {
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "glacialcast_server=info,tower_http=info".into()),
        )
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
    let config = load_server_config(&args.config)?;
    tokio::fs::create_dir_all(&args.data_dir)
        .await
        .with_context(|| format!("creating data dir {}", args.data_dir.display()))?;
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
    let state = AppState {
        store,
        dash_store,
        events,
        dash_events,
        auth: AuthConfig::from_config(config.ingest)?,
        active_ingests: Arc::new(AsyncMutex::new(HashMap::new())),
        ingest_private_key: ingest_key.private,
    };
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    tokio::spawn(install_signal_handlers(shutdown_tx.clone()));
    if serve_control {
        let control_shutdown = shutdown_tx.clone();
        tokio::spawn(async move {
            if let Err(err) = serve_control_socket(daemon_socket, control_shutdown).await {
                error!(?err, "daemon control socket stopped");
            }
        });
    }

    let ingest_addr = args.ingest_addr;
    let ingest_state = state.clone();
    let ingest_shutdown = shutdown_rx.clone();
    tokio::spawn(async move {
        if let Err(err) = run_ingest(ingest_addr, ingest_state, ingest_shutdown).await {
            error!(?err, "ingest listener stopped");
        }
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/dash/{stream_id}", get(dash_viewer))
        .route("/favicon.ico", get(favicon))
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
        .nest_service("/assets", ServeDir::new("crates/server/static"))
        .with_state(state);

    info!(
        control = %args.control_addr,
        ingest = %args.ingest_addr,
        ingest_server_key,
        "glacialcast server listening"
    );
    let listener = TcpListener::bind(args.control_addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            wait_for_shutdown(&mut shutdown_rx).await;
        })
        .await?;
    let _ = shutdown_tx.send(true);
    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn dash_viewer(Path(_stream_id): Path<Uuid>) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(
            "content-security-policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data: blob:; media-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'self'",
        )
        .header("x-content-type-options", "nosniff")
        .header("referrer-policy", "no-referrer")
        .body(Body::from(include_str!("../static/dash-viewer.html")))
        .expect("static DASH viewer response headers are valid")
}

async fn favicon() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn list_streams(
    State(state): State<AppState>,
) -> Result<axum::Json<Vec<glacialcast_protocol::PublicStream>>, AppError> {
    let mut streams = state.store.list_streams()?;
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
    Path(stream_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    if state.store.delete_stream(stream_id)? {
        state.dash_store.delete_stream(stream_id)?;
        publish_stream_event(&state, "stream_deleted", stream_id);
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound)
    }
}

async fn dash_manifest(
    State(state): State<AppState>,
    Path(stream_id): Path<Uuid>,
) -> Result<Response, AppError> {
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
    Path(stream_id): Path<Uuid>,
) -> Result<Json<Vec<DashObjectHeader>>, AppError> {
    Ok(Json(
        state
            .dash_store
            .list(stream_id)?
            .into_iter()
            .map(|object| object.header)
            .collect(),
    ))
}

async fn get_dash_object(
    State(state): State<AppState>,
    Path((stream_id, sequence)): Path<(Uuid, u64)>,
) -> Result<Response, AppError> {
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
    Path((stream_id, epoch_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, AppError> {
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
    Path((stream_id, epoch_id, segment_file)): Path<(Uuid, Uuid, String)>,
) -> Result<Response, AppError> {
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
    Path(stream_id): Path<Uuid>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| dash_live_socket(socket, state, stream_id))
}

async fn dash_live_socket(socket: WebSocket, state: AppState, stream_id: Uuid) {
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

async fn control_ws(State(state): State<AppState>, ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(move |socket| control_socket(socket, state))
}

async fn control_socket(socket: WebSocket, state: AppState) {
    let mut rx = state.events.subscribe();
    let (mut sender, mut receiver) = socket.split();
    let send_task = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
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
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_ingest(stream, state).await {
                warn!(%peer, ?err, "ingest connection failed");
            }
        });
    }
    Ok(())
}

async fn handle_ingest(mut stream: TcpStream, state: AppState) -> Result<()> {
    let transport = responder_handshake(&mut stream, &state.ingest_private_key).await?;
    let mut socket = glacialcast_protocol::NoiseSocket::new(stream, transport);
    let hello = match socket.read::<ClientMessage>().await? {
        ClientMessage::Hello(hello) => hello,
        other => {
            socket
                .write(&ServerMessage::HelloAck {
                    accepted: false,
                    reason: Some(format!("expected hello, got {other:?}")),
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
            socket
                .write(&ServerMessage::HelloAck {
                    accepted: false,
                    reason: Some(err.to_string()),
                    stream_id: None,
                    last_sequence: 0,
                    server_time_ms: now_ms(),
                })
                .await?;
            return Ok(());
        }
    };
    let stream_id = state.store.ensure_stream_for_client(
        &authenticated.identity,
        &hello.display_name,
        &hello.source,
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
    let result = ingest_loop(&state, &mut socket, stream_id, &hello, last_seq).await;
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
    hello: &StreamHello,
    mut last_seq: u64,
) -> Result<()> {
    if let Some(high) = hello.resend_high
        && high > last_seq
    {
        socket
            .write(&ServerMessage::ResendRequest {
                from_seq: last_seq + 1,
                to_seq: high,
            })
            .await?;
    }

    loop {
        let message = socket.read::<ClientMessage>().await;
        match message {
            Ok(ClientMessage::DashObject(object)) => {
                object.validate().context("validating DASH ingest object")?;
                if !state.store.stream_exists(stream_id)? {
                    anyhow::bail!("stream was deleted");
                }
                if object.header.stream_id != stream_id {
                    anyhow::bail!("DASH object stream_id does not match assigned stream");
                }
                if object.header.sequence > last_seq + 1 && last_seq > 0 {
                    socket
                        .write(&ServerMessage::ResendRequest {
                            from_seq: last_seq + 1,
                            to_seq: object.header.sequence - 1,
                        })
                        .await?;
                }
                let stored = state.dash_store.store(object)?;
                last_seq = last_seq.max(stored.header.sequence);
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

    let identity = state
        .auth
        .authenticate(hello.auth_token.as_deref(), &hello.client_id)?;
    Ok(AuthenticatedClient { identity })
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
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
            }],
        }
    }

    #[test]
    fn optional_auth_accepts_client_id_without_token() {
        let auth = AuthConfig::from_config(token_config(false)).unwrap();
        assert_eq!(auth.authenticate(None, "desk").unwrap(), "desk");
    }

    #[test]
    fn configured_token_maps_to_client_identity() {
        let auth = AuthConfig::from_config(token_config(false)).unwrap();
        assert_eq!(
            auth.authenticate(Some("secret"), "spoofed").unwrap(),
            "laptop"
        );
    }

    #[test]
    fn required_auth_rejects_missing_token() {
        let auth = AuthConfig::from_config(token_config(true)).unwrap();
        assert!(auth.authenticate(None, "desk").is_err());
    }

    #[test]
    fn invalid_token_is_rejected_even_when_optional() {
        let auth = AuthConfig::from_config(token_config(false)).unwrap();
        assert!(auth.authenticate(Some("wrong"), "desk").is_err());
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
            AppError::Anyhow(err) => {
                error!(?err, "request failed");
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
            }
        }
    }
}
