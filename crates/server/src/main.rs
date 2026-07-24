mod dash_store;
mod storage;

use crate::{
    dash_store::DashStore,
    storage::{Store, StoredFrame, StoredVideoChunk},
};
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
    ClientMessage, ControlEvent, DashObjectHeader, FrameManifest, ServerMessage, StreamHello,
    StreamMediaKind, VideoChunkManifest,
    daemon::{
        daemonize_if_requested, install_signal_handlers, manager_command, serve_control_socket,
        wait_for_shutdown,
    },
    encode_ws_event, frame_is_encrypted, now_ms, parse_human_bytes, responder_handshake,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::PathBuf,
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

    let store = Store::open(args.data_dir.clone(), args.retention_bytes_per_stream)?;
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
        .route("/api/streams/{stream_id}/frames", get(list_frames))
        .route("/api/streams/{stream_id}/frames/{seq}", get(get_frame))
        .route("/api/streams/{stream_id}/video", get(list_video_chunks))
        .route("/api/streams/{stream_id}/video/{seq}", get(get_video_chunk))
        .route("/api/streams/{stream_id}/cursors", get(list_cursors))
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

    info!(control = %args.control_addr, ingest = %args.ingest_addr, "glacialcast server listening");
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
            stream.last_frame_seq = match (stream.last_frame_seq, summary.last_sequence) {
                (Some(left), Some(right)) => Some(left.max(right)),
                (left, right) => left.or(right),
            };
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

async fn list_frames(
    State(state): State<AppState>,
    Path(stream_id): Path<Uuid>,
) -> Result<axum::Json<Vec<glacialcast_protocol::FrameManifest>>, AppError> {
    Ok(axum::Json(state.store.list_frames(stream_id)?))
}

async fn list_video_chunks(
    State(state): State<AppState>,
    Path(stream_id): Path<Uuid>,
) -> Result<axum::Json<Vec<glacialcast_protocol::VideoChunkManifest>>, AppError> {
    Ok(axum::Json(state.store.list_video_chunks(stream_id)?))
}

async fn list_cursors(
    State(state): State<AppState>,
    Path(stream_id): Path<Uuid>,
) -> Result<axum::Json<Vec<glacialcast_protocol::CursorMessage>>, AppError> {
    Ok(axum::Json(state.store.list_cursors(stream_id, 5000)?))
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

async fn get_frame(
    State(state): State<AppState>,
    Path((stream_id, seq)): Path<(Uuid, u64)>,
) -> Result<Response, AppError> {
    let payload = state
        .store
        .get_frame_payload(stream_id, seq)?
        .ok_or(AppError::NotFound)?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header("x-glacialcast-mime", payload.frame.mime)
        .body(Body::from(payload.bytes))
        .unwrap())
}

async fn get_video_chunk(
    State(state): State<AppState>,
    Path((stream_id, seq)): Path<(Uuid, u64)>,
) -> Result<Response, AppError> {
    let payload = state
        .store
        .get_video_chunk_payload(stream_id, seq)?
        .ok_or(AppError::NotFound)?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header("x-glacialcast-mime", payload.chunk.mime)
        .body(Body::from(payload.bytes))
        .unwrap())
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
    let transport = responder_handshake(&mut stream).await?;
    let mut socket = glacialcast_protocol::NoiseSocket::new(stream, transport);
    let hello = match socket.read::<ClientMessage>().await? {
        ClientMessage::Hello(hello) => hello,
        other => {
            socket
                .write(&ServerMessage::HelloAck {
                    accepted: false,
                    reason: Some(format!("expected hello, got {other:?}")),
                    stream_id: None,
                    last_frame_seq: 0,
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
                    last_frame_seq: 0,
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
        hello.media_kind,
        hello.frame_encrypted,
    )?;
    let last_seq = state
        .store
        .last_frame_seq(stream_id)?
        .into_iter()
        .chain(state.dash_store.last_sequence(stream_id)?)
        .max()
        .unwrap_or(0);
    socket
        .write(&ServerMessage::HelloAck {
            accepted: true,
            reason: None,
            stream_id: Some(stream_id),
            last_frame_seq: last_seq,
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
            Ok(ClientMessage::Frame(frame)) => {
                debug!(stream_id = %stream_id, seq = frame.seq, bytes = frame.ciphertext.len(), "ingest received image frame");
                if !state.store.stream_exists(stream_id)? {
                    anyhow::bail!("stream was deleted");
                }
                if hello.media_kind != StreamMediaKind::Image {
                    anyhow::bail!("image frame received for a non-image stream");
                }
                if frame.stream_id != stream_id {
                    anyhow::bail!("frame stream_id does not match assigned stream");
                }
                if frame.seq > last_seq + 1 && last_seq > 0 {
                    socket
                        .write(&ServerMessage::ResendRequest {
                            from_seq: last_seq + 1,
                            to_seq: frame.seq - 1,
                        })
                        .await?;
                }
                let stored = StoredFrame::from_message(&frame);
                state.store.store_frame(stored, &frame.ciphertext)?;
                last_seq = last_seq.max(frame.seq);
                publish_frame_event(state, &frame);
                socket
                    .write(&ServerMessage::Ack {
                        through_seq: last_seq,
                    })
                    .await?;
                debug!(stream_id = %stream_id, through_seq = last_seq, "ingest sent image ack");
            }
            Ok(ClientMessage::VideoChunk(chunk)) => {
                debug!(stream_id = %stream_id, seq = chunk.seq, bytes = chunk.payload.len(), "ingest received video chunk");
                if !state.store.stream_exists(stream_id)? {
                    anyhow::bail!("stream was deleted");
                }
                if hello.media_kind != StreamMediaKind::Video {
                    anyhow::bail!("video chunk received for a non-video stream");
                }
                if chunk.stream_id != stream_id {
                    anyhow::bail!("video chunk stream_id does not match assigned stream");
                }
                if frame_is_encrypted(&chunk.key_id) {
                    anyhow::bail!("video chunks must not use application-level frame encryption");
                }
                if chunk.seq > last_seq + 1 && last_seq > 0 {
                    socket
                        .write(&ServerMessage::ResendRequest {
                            from_seq: last_seq + 1,
                            to_seq: chunk.seq - 1,
                        })
                        .await?;
                }
                let stored = StoredVideoChunk::from_message(&chunk);
                state.store.store_video_chunk(stored, &chunk.payload)?;
                last_seq = last_seq.max(chunk.seq);
                publish_video_event(state, &chunk);
                socket
                    .write(&ServerMessage::Ack {
                        through_seq: last_seq,
                    })
                    .await?;
                debug!(stream_id = %stream_id, through_seq = last_seq, "ingest sent video ack");
            }
            Ok(ClientMessage::DashObject(object)) => {
                object.validate().context("validating DASH ingest object")?;
                if !state.store.stream_exists(stream_id)? {
                    anyhow::bail!("stream was deleted");
                }
                if hello.media_kind != StreamMediaKind::Dash {
                    anyhow::bail!("DASH object received for a non-DASH stream");
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
            Ok(ClientMessage::Cursor(cursor)) => {
                debug!(stream_id = %stream_id, seq = cursor.seq, x = cursor.x, y = cursor.y, "ingest received cursor");
                if !state.store.stream_exists(stream_id)? {
                    anyhow::bail!("stream was deleted");
                }
                if cursor.stream_id != stream_id {
                    anyhow::bail!("cursor stream_id does not match assigned stream");
                }
                state.store.store_cursor(&cursor)?;
                publish_cursor_event(state, &cursor);
            }
            Ok(ClientMessage::BufferStatus(status)) => {
                debug!(
                    stream_id = %stream_id,
                    lowest_seq = ?status.lowest_seq,
                    highest_seq = ?status.highest_seq,
                    bytes = status.bytes,
                    "ingest received buffer status"
                );
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
    publish_stream_event_with_seq(state, event, stream_id, None, None);
}

fn publish_stream_event_with_seq(
    state: &AppState,
    event: &str,
    stream_id: Uuid,
    seq: Option<u64>,
    captured_at_ms: Option<i64>,
) {
    let _ = state.events.send(ControlEvent {
        event: event.to_string(),
        stream_id,
        seq,
        captured_at_ms,
        frame: None,
        video: None,
        cursor: None,
    });
}

fn publish_frame_event(state: &AppState, frame: &glacialcast_protocol::FrameMessage) {
    let manifest = FrameManifest {
        stream_id: frame.stream_id,
        seq: frame.seq,
        captured_at_ms: frame.captured_at_ms,
        width: frame.width,
        height: frame.height,
        mime: frame.mime.clone(),
        key_id: frame.key_id.clone(),
        nonce: frame.nonce,
        content_hash: frame.content_hash,
        size_bytes: frame.ciphertext.len() as u64,
    };
    let _ = state.events.send(ControlEvent {
        event: "frame".to_string(),
        stream_id: frame.stream_id,
        seq: Some(frame.seq),
        captured_at_ms: Some(frame.captured_at_ms),
        frame: Some(manifest),
        video: None,
        cursor: None,
    });
}

fn publish_video_event(state: &AppState, chunk: &glacialcast_protocol::VideoChunkMessage) {
    let manifest = VideoChunkManifest {
        stream_id: chunk.stream_id,
        seq: chunk.seq,
        captured_at_ms: chunk.captured_at_ms,
        pts_ms: chunk.pts_ms,
        duration_ms: chunk.duration_ms,
        width: chunk.width,
        height: chunk.height,
        source_width: chunk.source_width,
        source_height: chunk.source_height,
        codec: chunk.codec,
        packetization: chunk.packetization,
        keyframe: chunk.keyframe,
        mime: chunk.mime.clone(),
        key_id: chunk.key_id.clone(),
        nonce: chunk.nonce,
        content_hash: chunk.content_hash,
        size_bytes: chunk.payload.len() as u64,
    };
    let _ = state.events.send(ControlEvent {
        event: "video".to_string(),
        stream_id: chunk.stream_id,
        seq: Some(chunk.seq),
        captured_at_ms: Some(chunk.captured_at_ms),
        frame: None,
        video: Some(manifest),
        cursor: None,
    });
}

fn publish_cursor_event(state: &AppState, cursor: &glacialcast_protocol::CursorMessage) {
    let _ = state.events.send(ControlEvent {
        event: "cursor".to_string(),
        stream_id: cursor.stream_id,
        seq: Some(cursor.seq),
        captured_at_ms: Some(cursor.captured_at_ms),
        frame: None,
        video: None,
        cursor: Some(cursor.clone()),
    });
}

async fn authenticate_hello(state: &AppState, hello: &StreamHello) -> Result<AuthenticatedClient> {
    if hello.protocol_version != glacialcast_protocol::PROTOCOL_VERSION {
        anyhow::bail!("unsupported protocol version {}", hello.protocol_version);
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
