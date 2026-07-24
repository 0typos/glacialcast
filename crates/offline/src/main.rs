use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    body::Body,
    extract::{
        Path, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use clap::{Parser, Subcommand};
use futures_util::{SinkExt, StreamExt};
use glacialcast_dash::{EpochDescriptor, MpdConfig, SegmentTimelineEntry, build_mpd};
use glacialcast_protocol::{DashObject, DashObjectHeader, DashObjectKind, MAX_FRAME_LEN};
use reqwest::Client;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs::{File, OpenOptions},
    io::Write,
    net::SocketAddr,
    path::{Path as FsPath, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{net::TcpListener, sync::RwLock};
use tracing::{info, warn};
use uuid::Uuid;

const VIEWER_HTML: &str = include_str!("../../server/static/dash-viewer.html");
const VIEWER_CSS: &str = include_str!("../../server/static/dash-viewer.css");
const VIEWER_CORE_JS: &str = include_str!("../../server/static/dash-viewer-core.js");
const VIEWER_JS: &str = include_str!("../../server/static/dash-viewer.js");
const MAX_PORTABLE_FILE_LEN: u64 = MAX_FRAME_LEN as u64 + 128 * 1024;

#[derive(Debug, Parser)]
#[command(about = "Mirror and view GlacialCast encrypted DASH object files")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Download opaque stream objects into portable .gco files.
    Mirror {
        #[arg(long, default_value = "http://127.0.0.1:8899")]
        server: String,
        #[arg(long)]
        stream_id: Uuid,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 500)]
        poll_ms: u64,
        #[arg(long)]
        follow: bool,
    },
    /// Serve portable .gco files to a local browser without Internet access.
    Serve {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8910")]
        listen: SocketAddr,
    },
}

#[derive(Clone)]
struct OfflineState {
    root: PathBuf,
    catalog: Arc<RwLock<OfflineCatalog>>,
}

#[derive(Default)]
struct OfflineCatalog {
    files: BTreeMap<PathBuf, (Uuid, u64)>,
    objects: BTreeMap<(Uuid, u64), DashObject>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "glacialcast_offline=info".into()),
        )
        .init();
    match Args::parse().command {
        Command::Mirror {
            server,
            stream_id,
            output,
            poll_ms,
            follow,
        } => mirror(&server, stream_id, &output, poll_ms, follow).await,
        Command::Serve { input, listen } => serve(input, listen).await,
    }
}

async fn mirror(
    server: &str,
    stream_id: Uuid,
    output: &FsPath,
    poll_ms: u64,
    follow: bool,
) -> Result<()> {
    if poll_ms == 0 {
        bail!("--poll-ms must be at least 1");
    }
    std::fs::create_dir_all(output)
        .with_context(|| format!("creating offline object directory {}", output.display()))?;
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("building relay HTTP client")?;
    let server = server.trim_end_matches('/');

    loop {
        let mirrored = mirror_once(&client, server, stream_id, output).await?;
        info!(stream_id = %stream_id, mirrored, "offline mirror pass complete");
        if !follow {
            return Ok(());
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = tokio::time::sleep(Duration::from_millis(poll_ms)) => {}
        }
    }
}

async fn mirror_once(
    client: &Client,
    server: &str,
    stream_id: Uuid,
    output: &FsPath,
) -> Result<usize> {
    let list_url = format!("{server}/api/dash/streams/{stream_id}/objects");
    let mut headers = client
        .get(&list_url)
        .send()
        .await
        .with_context(|| format!("requesting {list_url}"))?
        .error_for_status()
        .with_context(|| format!("listing stream {stream_id}"))?
        .json::<Vec<DashObjectHeader>>()
        .await
        .context("decoding relay object list")?;
    headers.sort_by_key(|header| header.sequence);

    let mut mirrored = 0usize;
    for object_header in headers {
        if object_header.stream_id != stream_id {
            bail!("relay returned an object for the wrong stream");
        }
        let path = portable_object_path(output, object_header.sequence);
        if path.exists() {
            let existing = read_portable_object(&path)?;
            if existing.header != object_header {
                bail!(
                    "existing portable object {} conflicts with relay metadata",
                    path.display()
                );
            }
            continue;
        }
        let object_url = format!(
            "{server}/api/dash/streams/{stream_id}/objects/{}",
            object_header.sequence
        );
        let response = client
            .get(&object_url)
            .send()
            .await
            .with_context(|| format!("requesting {object_url}"))?;
        if response.status() == StatusCode::NOT_FOUND {
            warn!(
                sequence = object_header.sequence,
                "object expired from relay during mirror pass"
            );
            continue;
        }
        let payload = response
            .error_for_status()
            .with_context(|| format!("downloading object {}", object_header.sequence))?
            .bytes()
            .await
            .context("reading relay object payload")?
            .to_vec();
        let object = DashObject {
            header: object_header,
            payload,
        };
        object
            .validate()
            .context("validating downloaded portable object")?;
        write_portable_object(output, &path, &object)?;
        mirrored += 1;
    }
    Ok(mirrored)
}

fn portable_object_path(output: &FsPath, sequence: u64) -> PathBuf {
    output.join(format!("{sequence:020}.gco"))
}

fn write_portable_object(directory: &FsPath, path: &FsPath, object: &DashObject) -> Result<()> {
    let bytes = object
        .to_portable_bytes()
        .context("encoding portable DASH object")?;
    let temporary = directory.join(format!(
        ".{:020}-{}.part",
        object.header.sequence,
        Uuid::new_v4()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .with_context(|| format!("creating {}", temporary.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("writing {}", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", temporary.display()))?;
    std::fs::rename(&temporary, path).with_context(|| {
        format!(
            "publishing portable object {} as {}",
            temporary.display(),
            path.display()
        )
    })?;
    File::open(directory)
        .with_context(|| format!("opening {}", directory.display()))?
        .sync_all()
        .with_context(|| format!("syncing {}", directory.display()))
}

fn read_portable_object(path: &FsPath) -> Result<DashObject> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("reading metadata for {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("portable object is not a regular file: {}", path.display());
    }
    if metadata.len() > MAX_PORTABLE_FILE_LEN {
        bail!("portable object {} exceeds its size limit", path.display());
    }
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    DashObject::from_portable_bytes(&bytes)
        .with_context(|| format!("decoding portable object {}", path.display()))
}

async fn serve(input: PathBuf, listen: SocketAddr) -> Result<()> {
    if !input.is_dir() {
        bail!("offline input is not a directory: {}", input.display());
    }
    if !listen.ip().is_loopback() {
        warn!(
            %listen,
            "offline viewer is not bound to loopback; viewer-key entry is only intended for a trusted host"
        );
    }
    let catalog = OfflineCatalog::load(&input)?;
    let state = OfflineState {
        root: input,
        catalog: Arc::new(RwLock::new(catalog)),
    };
    let watcher_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(250));
        loop {
            interval.tick().await;
            if let Err(err) = refresh_catalog(&watcher_state).await {
                warn!(?err, "offline object directory refresh failed");
            }
        }
    });
    let app = Router::new()
        .route("/", get(index))
        .route("/favicon.ico", get(|| async { StatusCode::NO_CONTENT }))
        .route("/dash/{stream_id}", get(viewer))
        .route("/assets/dash-viewer.css", get(viewer_css))
        .route("/assets/dash-viewer-core.js", get(viewer_core_js))
        .route("/assets/dash-viewer.js", get(viewer_js))
        .route("/api/dash/streams/{stream_id}/objects", get(list_objects))
        .route(
            "/api/dash/streams/{stream_id}/objects/{sequence}",
            get(get_object),
        )
        .route(
            "/api/dash/streams/{stream_id}/manifest.mpd",
            get(get_manifest),
        )
        .route(
            "/api/dash/streams/{stream_id}/epochs/{epoch_id}/init.mp4",
            get(get_initialization),
        )
        .route(
            "/api/dash/streams/{stream_id}/epochs/{epoch_id}/media/{segment_file}",
            get(get_segment),
        )
        .route("/api/dash/streams/{stream_id}/live", get(live_websocket))
        .with_state(state);
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding offline viewer to {listen}"))?;
    info!(%listen, "offline viewer ready");
    axum::serve(listener, app)
        .await
        .context("serving offline viewer")
}

async fn load_stream(state: &OfflineState, stream_id: Uuid) -> Result<Vec<DashObject>> {
    Ok(state
        .catalog
        .read()
        .await
        .objects
        .iter()
        .filter(|((candidate, _), _)| *candidate == stream_id)
        .map(|(_, object)| object.clone())
        .collect())
}

async fn load_all(state: &OfflineState) -> Result<Vec<DashObject>> {
    Ok(state
        .catalog
        .read()
        .await
        .objects
        .values()
        .cloned()
        .collect())
}

impl OfflineCatalog {
    fn load(root: &FsPath) -> Result<Self> {
        let mut catalog = Self::default();
        for path in portable_paths(root)? {
            catalog.insert_file(path)?;
        }
        Ok(catalog)
    }

    fn insert_file(&mut self, path: PathBuf) -> Result<()> {
        let object = read_portable_object(&path)?;
        let key = (object.header.stream_id, object.header.sequence);
        if self.objects.contains_key(&key) {
            bail!(
                "portable directory contains duplicate stream/sequence objects in {}",
                path.display()
            );
        }
        self.objects.insert(key, object);
        self.files.insert(path, key);
        Ok(())
    }
}

async fn refresh_catalog(state: &OfflineState) -> Result<()> {
    let root = state.root.clone();
    let known = state
        .catalog
        .read()
        .await
        .files
        .keys()
        .cloned()
        .collect::<HashSet<_>>();
    let (current, additions) = tokio::task::spawn_blocking(move || {
        let current = portable_paths(&root)?.into_iter().collect::<HashSet<_>>();
        let additions = current
            .difference(&known)
            .map(|path| {
                let object = read_portable_object(path)?;
                Ok((path.clone(), object))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok::<_, anyhow::Error>((current, additions))
    })
    .await
    .context("offline object refresh task failed")??;

    let mut catalog = state.catalog.write().await;
    let removed = catalog
        .files
        .keys()
        .filter(|path| !current.contains(*path))
        .cloned()
        .collect::<Vec<_>>();
    let mut unique_keys = catalog
        .files
        .iter()
        .filter(|(path, _)| current.contains(*path))
        .map(|(_, key)| *key)
        .collect::<HashSet<_>>();
    for (path, object) in &additions {
        let key = (object.header.stream_id, object.header.sequence);
        if !unique_keys.insert(key) {
            bail!(
                "portable directory contains duplicate stream/sequence objects in {}",
                path.display()
            );
        }
    }
    for path in removed {
        if let Some(key) = catalog.files.remove(&path) {
            catalog.objects.remove(&key);
        }
    }
    for (path, object) in additions {
        let key = (object.header.stream_id, object.header.sequence);
        catalog.objects.insert(key, object);
        catalog.files.insert(path, key);
    }
    Ok(())
}

fn portable_paths(root: &FsPath) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(root).with_context(|| format!("reading {}", root.display()))? {
        let entry = entry.with_context(|| format!("reading an entry in {}", root.display()))?;
        let path = entry.path();
        if entry.file_type()?.is_file()
            && path.extension().and_then(|value| value.to_str()) == Some("gco")
        {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

async fn index(State(state): State<OfflineState>) -> Result<Html<String>, OfflineError> {
    let streams = load_all(&state)
        .await?
        .into_iter()
        .map(|object| object.header.stream_id)
        .collect::<BTreeSet<_>>();
    let links = if streams.is_empty() {
        "<p>No portable <code>.gco</code> objects were found.</p>".to_string()
    } else {
        streams
            .into_iter()
            .map(|stream| format!("<li><a href=\"/dash/{stream}\">{stream}</a></li>"))
            .collect::<Vec<_>>()
            .join("")
    };
    Ok(Html(format!(
        "<!doctype html><meta charset=\"utf-8\"><title>GlacialCast Offline</title>\
         <style>body{{font:16px system-ui;max-width:60rem;margin:3rem auto;padding:0 1rem;\
         background:#0b1117;color:#e8eef5}}a{{color:#55ddb0}}</style>\
         <h1>GlacialCast Offline</h1><ul>{links}</ul>"
    )))
}

async fn viewer(Path(_stream_id): Path<Uuid>) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .header("referrer-policy", "no-referrer")
        .body(Body::from(VIEWER_HTML))
        .expect("static viewer response headers are valid")
}

async fn viewer_css() -> Response {
    static_response("text/css; charset=utf-8", VIEWER_CSS)
}

async fn viewer_js() -> Response {
    static_response("text/javascript; charset=utf-8", VIEWER_JS)
}

async fn viewer_core_js() -> Response {
    static_response("text/javascript; charset=utf-8", VIEWER_CORE_JS)
}

fn static_response(content_type: &'static str, body: &'static str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .body(Body::from(body))
        .expect("static asset response headers are valid")
}

async fn list_objects(
    State(state): State<OfflineState>,
    Path(stream_id): Path<Uuid>,
) -> Result<Json<Vec<DashObjectHeader>>, OfflineError> {
    let objects = load_stream(&state, stream_id).await?;
    if objects.is_empty() {
        return Err(OfflineError::NotFound);
    }
    Ok(Json(
        objects.into_iter().map(|object| object.header).collect(),
    ))
}

async fn get_object(
    State(state): State<OfflineState>,
    Path((stream_id, sequence)): Path<(Uuid, u64)>,
) -> Result<Response, OfflineError> {
    let object = load_stream(&state, stream_id)
        .await?
        .into_iter()
        .find(|object| object.header.sequence == sequence)
        .ok_or(OfflineError::NotFound)?;
    Ok(binary_response("application/octet-stream", object.payload))
}

async fn get_manifest(
    State(state): State<OfflineState>,
    Path(stream_id): Path<Uuid>,
) -> Result<Response, OfflineError> {
    let objects = load_stream(&state, stream_id).await?;
    let descriptor_object = objects
        .iter()
        .rev()
        .find(|object| object.header.kind == DashObjectKind::Epoch)
        .ok_or(OfflineError::NotFound)?;
    let descriptor = EpochDescriptor::from_json(&descriptor_object.payload)
        .context("decoding offline epoch descriptor")?;
    let mut segments = BTreeMap::<u64, SegmentTimelineEntry>::new();
    for object in objects.iter().filter(|object| {
        object.header.kind == DashObjectKind::Media && object.header.epoch_id == descriptor.epoch_id
    }) {
        let entry = segments
            .entry(object.header.segment_number)
            .or_insert(SegmentTimelineEntry {
                number: object.header.segment_number,
                start: object.header.timestamp,
                duration: 0,
            });
        entry.start = entry.start.min(object.header.timestamp);
        entry.duration = entry.duration.saturating_add(object.header.duration);
    }
    let segments = segments.into_values().collect::<Vec<_>>();
    if segments.is_empty() {
        return Err(OfflineError::NotFound);
    }
    let depth = segments
        .last()
        .map(|segment| {
            segment
                .start
                .saturating_add(segment.duration)
                .div_ceil(u64::from(glacialcast_dash::MEDIA_TIMESCALE))
        })
        .unwrap_or(1)
        .max(1);
    let mpd = build_mpd(&MpdConfig {
        stream_id,
        epoch_id: descriptor.epoch_id,
        key_id: descriptor.key_id,
        width: descriptor.width,
        height: descriptor.height,
        codec: &descriptor.codec,
        availability_start_time: &descriptor.availability_start_time,
        time_shift_buffer_depth_seconds: depth,
        segments: &segments,
        dynamic: false,
    });
    Ok(binary_response("application/dash+xml", mpd.into_bytes()))
}

async fn get_initialization(
    State(state): State<OfflineState>,
    Path((stream_id, epoch_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, OfflineError> {
    let object = load_stream(&state, stream_id)
        .await?
        .into_iter()
        .rev()
        .find(|object| {
            object.header.epoch_id == epoch_id
                && object.header.kind == DashObjectKind::Initialization
        })
        .ok_or(OfflineError::NotFound)?;
    Ok(binary_response("video/mp4", object.payload))
}

async fn get_segment(
    State(state): State<OfflineState>,
    Path((stream_id, epoch_id, segment_file)): Path<(Uuid, Uuid, String)>,
) -> Result<Response, OfflineError> {
    let segment_number = segment_file
        .strip_suffix(".m4s")
        .ok_or(OfflineError::NotFound)?
        .parse::<u64>()
        .map_err(|_| OfflineError::NotFound)?;
    let mut objects = load_stream(&state, stream_id)
        .await?
        .into_iter()
        .filter(|object| {
            object.header.epoch_id == epoch_id
                && object.header.kind == DashObjectKind::Media
                && object.header.segment_number == segment_number
        })
        .collect::<Vec<_>>();
    objects.sort_by_key(|object| (object.header.chunk_index, object.header.sequence));
    if objects.is_empty() {
        return Err(OfflineError::NotFound);
    }
    if objects.windows(2).any(|pair| {
        pair[0]
            .header
            .chunk_index
            .checked_add(1)
            .is_none_or(|expected| pair[1].header.chunk_index != expected)
    }) {
        return Err(
            anyhow::anyhow!("offline media segment has duplicate or missing chunks").into(),
        );
    }
    let mut segment = Vec::new();
    for object in objects {
        segment.extend_from_slice(&object.payload);
    }
    Ok(binary_response("video/iso.segment", segment))
}

fn binary_response(content_type: &'static str, bytes: Vec<u8>) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .body(Body::from(bytes))
        .expect("binary response headers are valid")
}

async fn live_websocket(
    State(state): State<OfflineState>,
    Path(stream_id): Path<Uuid>,
    websocket: WebSocketUpgrade,
) -> impl IntoResponse {
    websocket.on_upgrade(move |socket| live_socket(socket, state, stream_id))
}

async fn live_socket(socket: WebSocket, state: OfflineState, stream_id: Uuid) {
    let (mut sender, mut receiver) = socket.split();
    let mut seen = HashSet::new();
    let mut interval = tokio::time::interval(Duration::from_millis(250));
    loop {
        tokio::select! {
            incoming = receiver.next() => {
                if incoming.is_none()
                    || matches!(incoming, Some(Ok(Message::Close(_))) | Some(Err(_)))
                {
                    return;
                }
            }
            _ = interval.tick() => {
                let objects = match load_stream(&state, stream_id).await {
                    Ok(objects) => objects,
                    Err(err) => {
                        warn!(?err, %stream_id, "offline live object scan failed");
                        continue;
                    }
                };
                for object in objects {
                    if !seen.insert(object.header.sequence) {
                        continue;
                    }
                    let json = match serde_json::to_string(&object.header) {
                        Ok(json) => json,
                        Err(err) => {
                            warn!(?err, "offline live header serialization failed");
                            continue;
                        }
                    };
                    if sender.send(Message::Text(json.into())).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
enum OfflineError {
    NotFound,
    Internal(anyhow::Error),
}

impl<E> From<E> for OfflineError
where
    E: Into<anyhow::Error>,
{
    fn from(error: E) -> Self {
        Self::Internal(error.into())
    }
}

impl IntoResponse for OfflineError {
    fn into_response(self) -> Response {
        match self {
            Self::NotFound => (StatusCode::NOT_FOUND, "not found").into_response(),
            Self::Internal(error) => {
                warn!(?error, "offline viewer request failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "offline viewer error").into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use glacialcast_dash::{DASH_FORMAT_VERSION, EpochKeys, MEDIA_TIMESCALE};
    use glacialcast_protocol::NewDashObject;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("glacialcast-offline-test-{}", Uuid::new_v4()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &FsPath {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn test_object(
        stream_id: Uuid,
        epoch_id: Uuid,
        kind: DashObjectKind,
        sequence: u64,
        segment_number: u64,
        chunk_index: u16,
        payload: Vec<u8>,
    ) -> DashObject {
        let keys = EpochKeys::derive(&[4; 32], stream_id, epoch_id).unwrap();
        DashObject::authenticated(
            NewDashObject {
                stream_id,
                epoch_id,
                kind,
                sequence,
                segment_number,
                chunk_index,
                timestamp: match kind {
                    DashObjectKind::Epoch | DashObjectKind::Initialization => 0,
                    _ => sequence * 100,
                },
                duration: match kind {
                    DashObjectKind::Media | DashObjectKind::Cursor => 100,
                    _ => 0,
                },
                random_access: true,
                mime: match kind {
                    DashObjectKind::Epoch => "application/vnd.glacialcast.epoch+json",
                    DashObjectKind::Initialization => "video/mp4",
                    DashObjectKind::Media => "video/iso.segment",
                    DashObjectKind::Cursor => "application/vnd.glacialcast.cursor",
                    _ => "application/octet-stream",
                },
                payload,
            },
            &keys,
        )
        .unwrap()
    }

    fn store_object(directory: &TestDirectory, name: &str, object: &DashObject) -> PathBuf {
        let path = directory.path().join(name);
        write_portable_object(directory.path(), &path, object).unwrap();
        path
    }

    fn offline_state(directory: &TestDirectory) -> OfflineState {
        OfflineState {
            root: directory.0.clone(),
            catalog: Arc::new(RwLock::new(OfflineCatalog::load(directory.path()).unwrap())),
        }
    }

    #[test]
    fn portable_catalog_loads_valid_objects_by_stream_and_sequence() {
        let directory = TestDirectory::new();
        let stream_id = Uuid::new_v4();
        let epoch_id = Uuid::new_v4();
        for sequence in [3, 1, 2] {
            let object = test_object(
                stream_id,
                epoch_id,
                DashObjectKind::Cursor,
                sequence,
                1,
                0,
                vec![sequence as u8],
            );
            let path = portable_object_path(directory.path(), sequence);
            write_portable_object(directory.path(), &path, &object).unwrap();
        }

        let catalog = OfflineCatalog::load(directory.path()).unwrap();
        assert_eq!(catalog.files.len(), 3);
        assert_eq!(
            catalog
                .objects
                .keys()
                .copied()
                .collect::<Vec<(Uuid, u64)>>(),
            vec![(stream_id, 1), (stream_id, 2), (stream_id, 3)]
        );
    }

    #[test]
    fn portable_catalog_rejects_duplicate_stream_sequences() {
        let directory = TestDirectory::new();
        let stream_id = Uuid::new_v4();
        let epoch_id = Uuid::new_v4();
        let object = test_object(
            stream_id,
            epoch_id,
            DashObjectKind::Cursor,
            1,
            1,
            0,
            vec![1],
        );
        store_object(&directory, "one.gco", &object);
        store_object(&directory, "duplicate.gco", &object);
        let error = OfflineCatalog::load(directory.path()).err().unwrap();
        assert!(error.to_string().contains("duplicate stream/sequence"));
    }

    #[test]
    fn portable_catalog_rejects_corrupt_and_oversized_files() {
        let corrupt = TestDirectory::new();
        std::fs::write(corrupt.path().join("bad.gco"), b"not portable").unwrap();
        assert!(OfflineCatalog::load(corrupt.path()).is_err());

        let oversized = TestDirectory::new();
        let file = File::create(oversized.path().join("huge.gco")).unwrap();
        file.set_len(MAX_PORTABLE_FILE_LEN + 1).unwrap();
        drop(file);
        let error = OfflineCatalog::load(oversized.path()).err().unwrap();
        assert!(error.to_string().contains("exceeds its size limit"));
    }

    #[cfg(unix)]
    #[test]
    fn portable_catalog_ignores_symlinks_and_temporary_files() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        let stream_id = Uuid::new_v4();
        let epoch_id = Uuid::new_v4();
        let object = test_object(
            stream_id,
            epoch_id,
            DashObjectKind::Cursor,
            1,
            1,
            0,
            vec![1],
        );
        let target = store_object(&directory, "one.gco", &object);
        symlink(&target, directory.path().join("alias.gco")).unwrap();
        std::fs::write(directory.path().join("unfinished.part"), b"partial").unwrap();

        let paths = portable_paths(directory.path()).unwrap();
        assert_eq!(paths, vec![target]);
        assert!(read_portable_object(&directory.path().join("alias.gco")).is_err());
    }

    #[tokio::test]
    async fn catalog_refresh_adds_removes_and_rejects_duplicates_atomically() {
        let directory = TestDirectory::new();
        let stream_id = Uuid::new_v4();
        let epoch_id = Uuid::new_v4();
        let first = test_object(
            stream_id,
            epoch_id,
            DashObjectKind::Cursor,
            1,
            1,
            0,
            vec![1],
        );
        let first_path = store_object(&directory, "one.gco", &first);
        let state = offline_state(&directory);

        let second = test_object(
            stream_id,
            epoch_id,
            DashObjectKind::Cursor,
            2,
            1,
            0,
            vec![2],
        );
        store_object(&directory, "two.gco", &second);
        refresh_catalog(&state).await.unwrap();
        assert_eq!(load_stream(&state, stream_id).await.unwrap().len(), 2);

        std::fs::remove_file(first_path).unwrap();
        refresh_catalog(&state).await.unwrap();
        assert_eq!(
            load_stream(&state, stream_id)
                .await
                .unwrap()
                .into_iter()
                .map(|object| object.header.sequence)
                .collect::<Vec<_>>(),
            vec![2]
        );

        store_object(&directory, "duplicate.gco", &second);
        assert!(refresh_catalog(&state).await.is_err());
        assert_eq!(load_stream(&state, stream_id).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn offline_handlers_list_fetch_and_order_media_chunks() {
        let directory = TestDirectory::new();
        let stream_id = Uuid::new_v4();
        let epoch_id = Uuid::new_v4();
        for (sequence, chunk_index, payload) in [(1, 2, b"c"), (2, 0, b"a"), (3, 1, b"b")] {
            let object = test_object(
                stream_id,
                epoch_id,
                DashObjectKind::Media,
                sequence,
                1,
                chunk_index,
                payload.to_vec(),
            );
            store_object(&directory, &format!("{sequence}.gco"), &object);
        }
        let state = offline_state(&directory);

        let headers = list_objects(State(state.clone()), Path(stream_id))
            .await
            .unwrap()
            .0;
        assert_eq!(
            headers
                .iter()
                .map(|header| header.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        let object_response = get_object(State(state.clone()), Path((stream_id, 2)))
            .await
            .unwrap();
        let object_body = axum::body::to_bytes(object_response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&object_body[..], b"a");
        let segment_response = get_segment(
            State(state.clone()),
            Path((stream_id, epoch_id, "1.m4s".to_string())),
        )
        .await
        .unwrap();
        let segment_body = axum::body::to_bytes(segment_response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&segment_body[..], b"abc");
        assert!(matches!(
            get_segment(State(state), Path((stream_id, epoch_id, "bad".to_string()))).await,
            Err(OfflineError::NotFound)
        ));
    }

    #[tokio::test]
    async fn offline_segment_rejects_duplicate_or_missing_chunk_indices() {
        for chunks in [[0, 0], [0, 2]] {
            let directory = TestDirectory::new();
            let stream_id = Uuid::new_v4();
            let epoch_id = Uuid::new_v4();
            for (offset, chunk_index) in chunks.into_iter().enumerate() {
                let sequence = offset as u64 + 1;
                let object = test_object(
                    stream_id,
                    epoch_id,
                    DashObjectKind::Media,
                    sequence,
                    1,
                    chunk_index,
                    vec![sequence as u8],
                );
                store_object(&directory, &format!("{sequence}.gco"), &object);
            }
            let result = get_segment(
                State(offline_state(&directory)),
                Path((stream_id, epoch_id, "1.m4s".to_string())),
            )
            .await;
            assert!(matches!(result, Err(OfflineError::Internal(_))));
        }
    }

    #[tokio::test]
    async fn offline_manifest_uses_latest_authenticated_epoch() {
        let directory = TestDirectory::new();
        let stream_id = Uuid::new_v4();
        let epoch_id = Uuid::new_v4();
        let keys = EpochKeys::derive(&[4; 32], stream_id, epoch_id).unwrap();
        let descriptor = EpochDescriptor {
            format_version: DASH_FORMAT_VERSION,
            stream_id,
            epoch_id,
            key_id: keys.key_id,
            width: 320,
            height: 180,
            codec: "avc1.42c01f".to_string(),
            timescale: MEDIA_TIMESCALE,
            segment_frames: 1,
            availability_start_time: "2026-01-01T00:00:00Z".to_string(),
        };
        let epoch = test_object(
            stream_id,
            epoch_id,
            DashObjectKind::Epoch,
            1,
            0,
            0,
            descriptor.to_json().unwrap(),
        );
        let media = test_object(stream_id, epoch_id, DashObjectKind::Media, 2, 1, 0, vec![1]);
        store_object(&directory, "epoch.gco", &epoch);
        store_object(&directory, "media.gco", &media);
        let response = get_manifest(State(offline_state(&directory)), Path(stream_id))
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let manifest = std::str::from_utf8(&body).unwrap();
        assert!(manifest.contains("type=\"static\""));
        assert!(manifest.contains(&epoch_id.to_string()));
    }

    #[tokio::test]
    async fn embedded_viewer_serves_core_before_runtime() {
        let html = viewer(Path(Uuid::new_v4())).await;
        let body = axum::body::to_bytes(html.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.find("dash-viewer-core.js").unwrap() < html.find("dash-viewer.js").unwrap());

        let core = viewer_core_js().await;
        assert_eq!(
            core.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/javascript; charset=utf-8"
        );
        let body = axum::body::to_bytes(core.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(body.windows(16).any(|window| window == b"parseCursorBatch"));
    }
}
