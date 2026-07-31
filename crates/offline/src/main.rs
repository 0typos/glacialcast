//! Portable GlacialCast object mirroring and disconnected browser playback.
//!
//! `mirror` downloads authorized opaque DASH objects and publishes each as an
//! atomic `GCO1` file. `serve` watches a received directory, reconstructs the
//! constrained DASH endpoints, and embeds the complete viewer for a local
//! Firefox or Chromium installation. The viewer key remains in the browser,
//! and the service refuses non-loopback exposure unless explicitly allowed.

#![deny(missing_docs)]

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
#[cfg(test)]
use glacialcast_protocol::transfer::{LEGACY_TRANSFER_MANIFEST_VERSION, LegacyTransferManifest};
use glacialcast_protocol::{
    DashObject, DashObjectHeader, DashObjectKind, MAX_FRAME_LEN,
    transfer::{
        TRANSFER_CHUNK_VERSION, TRANSFER_MANIFEST_VERSION, TransferChunk, TransferChunkDescriptor,
        TransferManifest, TransferObject, TransferRoot, parse_transfer_chunk, parse_transfer_root,
    },
};
use reqwest::Client;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs::{File, OpenOptions},
    io::{IsTerminal, Read, Write},
    net::SocketAddr,
    os::unix::fs::OpenOptionsExt,
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
const VIEWER_PAGE_JS: &str = include_str!("../../server/static/dash-viewer-page.js");
const VIEWER_KEY_JS: &str = include_str!("../../server/static/viewer-key.js");
const MAX_PORTABLE_FILE_LEN: u64 = MAX_FRAME_LEN as u64 + 128 * 1024;
const TRANSFER_MANIFEST_FILE: &str = "glacialcast-transfer.json";
const TRANSFER_CHUNK_OBJECTS: u64 = 1024;
const MAX_TRANSFER_MANIFEST_LEN: u64 = 16 * 1024 * 1024;
const MAX_TRANSFER_CHUNK_LEN: u64 = 16 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(
    about = "Mirror and view GlacialCast encrypted DASH object files",
    version
)]
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
        #[arg(long, env = "GLACIALCAST_ACCESS_TOKEN", allow_hyphen_values = true)]
        access_token: Option<String>,
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
        /// Explicitly permit exposing the key-entry viewer beyond this machine.
        #[arg(long)]
        allow_non_loopback: bool,
    },
    /// Verify a portable transfer manifest and every declared object.
    Verify {
        #[arg(long)]
        input: PathBuf,
        /// Emit a machine-readable verification report.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Default)]
struct TransferIndex {
    objects: BTreeMap<u64, TransferObject>,
    chunks: BTreeMap<u64, TransferChunkDescriptor>,
    dirty_chunks: BTreeSet<u64>,
}

#[derive(Debug, Serialize)]
struct TransferVerification {
    complete: bool,
    stream_id: Uuid,
    expected_objects: usize,
    verified_objects: usize,
    missing: Vec<String>,
    unexpected: Vec<String>,
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
        // Diagnostics go to stderr so a caller can capture stdout alone.
        .with_writer(std::io::stderr)
        // Transfer runs are commonly piped into a file or a log collector,
        // which should not receive terminal colour escapes.
        .with_ansi(std::io::stderr().is_terminal())
        .init();
    match Args::parse().command {
        Command::Mirror {
            server,
            access_token,
            stream_id,
            output,
            poll_ms,
            follow,
        } => {
            mirror(
                &server,
                access_token.as_deref(),
                stream_id,
                &output,
                poll_ms,
                follow,
            )
            .await
        }
        Command::Serve {
            input,
            listen,
            allow_non_loopback,
        } => serve(input, listen, allow_non_loopback).await,
        Command::Verify { input, json } => {
            let report = verify_transfer(&input)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "stream {}: verified {}/{} objects",
                    report.stream_id, report.verified_objects, report.expected_objects
                );
                for filename in &report.missing {
                    println!("missing: {filename}");
                }
                for filename in &report.unexpected {
                    println!("unexpected: {filename}");
                }
            }
            if !report.complete {
                bail!("portable transfer is incomplete");
            }
            Ok(())
        }
    }
}

async fn mirror(
    server: &str,
    access_token: Option<&str>,
    stream_id: Uuid,
    output: &FsPath,
    poll_ms: u64,
    follow: bool,
) -> Result<()> {
    if poll_ms == 0 {
        bail!("--poll-ms must be at least 1");
    }
    let parsed_server = reqwest::Url::parse(server).context("parsing --server URL")?;
    let secure_transport = parsed_server.scheme() == "https";
    let loopback = parsed_server
        .host_str()
        .and_then(|host| host.parse::<std::net::IpAddr>().ok())
        .is_some_and(|address| address.is_loopback())
        || parsed_server.host_str() == Some("localhost");
    if !secure_transport && !loopback {
        bail!("remote relay mirroring requires an HTTPS --server URL");
    }
    if parsed_server.username() != ""
        || parsed_server.password().is_some()
        || parsed_server.query().is_some()
        || parsed_server.fragment().is_some()
    {
        bail!("--server must not contain credentials, a query, or a fragment");
    }
    std::fs::create_dir_all(output)
        .with_context(|| format!("creating offline object directory {}", output.display()))?;
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("building relay HTTP client")?;
    let server = server.trim_end_matches('/');
    let mut index = TransferIndex::load(output, stream_id)?;
    let mut after_sequence = None;

    loop {
        let mirrored = mirror_once(
            &client,
            server,
            access_token,
            stream_id,
            output,
            &mut index,
            after_sequence,
        )
        .await?;
        if after_sequence.is_none() || mirrored > 0 {
            index.publish(output, stream_id)?;
        }
        info!(stream_id = %stream_id, mirrored, "offline mirror pass complete");
        if !follow {
            return Ok(());
        }
        after_sequence = index
            .objects
            .last_key_value()
            .map(|(sequence, _)| *sequence);
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = tokio::time::sleep(Duration::from_millis(poll_ms)) => {}
        }
    }
}

async fn mirror_once(
    client: &Client,
    server: &str,
    access_token: Option<&str>,
    stream_id: Uuid,
    output: &FsPath,
    index: &mut TransferIndex,
    after_sequence: Option<u64>,
) -> Result<usize> {
    let list_url = format!("{server}/api/dash/streams/{stream_id}/objects");
    let mut list_request = client.get(&list_url);
    if let Some(sequence) = after_sequence {
        list_request = list_request.query(&[("after_sequence", sequence)]);
    }
    if let Some(token) = access_token {
        list_request = list_request.bearer_auth(token);
    }
    let mut headers = list_request
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
        if let Some(existing) = index.objects.get(&object_header.sequence) {
            if existing.header != object_header {
                bail!(
                    "existing portable object {} conflicts with relay metadata",
                    path.display()
                );
            }
            let metadata = std::fs::symlink_metadata(&path)
                .with_context(|| format!("inspecting portable object {}", path.display()))?;
            if !metadata.file_type().is_file() || metadata.len() != existing.length {
                bail!(
                    "indexed portable object {} is missing or has changed length",
                    path.display()
                );
            }
            continue;
        }
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                let existing = transfer_object_from_path(&path)?;
                if existing.header != object_header {
                    bail!(
                        "existing portable object {} conflicts with relay metadata",
                        path.display()
                    );
                }
                index.insert(existing)?;
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspecting portable object {}", path.display()));
            }
        }
        let object_url = format!(
            "{server}/api/dash/streams/{stream_id}/objects/{}",
            object_header.sequence
        );
        let mut object_request = client.get(&object_url);
        if let Some(token) = access_token {
            object_request = object_request.bearer_auth(token);
        }
        let response = object_request
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
        let transferred = write_portable_object(output, &path, &object)?;
        index.insert(transferred)?;
        mirrored += 1;
    }
    Ok(mirrored)
}

#[cfg(test)]
fn write_transfer_manifest(root: &FsPath, stream_id: Uuid) -> Result<()> {
    let mut index = TransferIndex::load(root, stream_id)?;
    index.publish(root, stream_id)
}

impl TransferIndex {
    fn load(root: &FsPath, stream_id: Uuid) -> Result<Self> {
        let mut index = Self::default();
        for path in portable_paths(root)? {
            let object = transfer_object_from_path(&path)?;
            if object.header.stream_id != stream_id {
                bail!(
                    "portable object {} belongs to stream {}, expected {}",
                    path.display(),
                    object.header.stream_id,
                    stream_id
                );
            }
            index.insert(object)?;
        }
        Ok(index)
    }

    fn insert(&mut self, object: TransferObject) -> Result<()> {
        let sequence = object.header.sequence;
        if let Some(existing) = self.objects.get(&sequence) {
            if existing == &object {
                return Ok(());
            }
            bail!("portable transfer contains conflicting sequence {sequence}");
        }
        self.objects.insert(sequence, object);
        self.dirty_chunks.insert(transfer_chunk_id(sequence));
        Ok(())
    }

    fn publish(&mut self, root: &FsPath, stream_id: Uuid) -> Result<()> {
        let dirty = self.dirty_chunks.iter().copied().collect::<Vec<_>>();
        for chunk_id in dirty {
            let start = chunk_id
                .saturating_mul(TRANSFER_CHUNK_OBJECTS)
                .saturating_add(1);
            let end = start.saturating_add(TRANSFER_CHUNK_OBJECTS - 1);
            let objects = self
                .objects
                .range(start..=end)
                .map(|(_, object)| object.clone())
                .collect::<Vec<_>>();
            if objects.is_empty() {
                self.chunks.remove(&chunk_id);
                continue;
            }
            let chunk = TransferChunk {
                version: TRANSFER_CHUNK_VERSION,
                stream_id,
                objects,
            };
            let bytes =
                serde_json::to_vec(&chunk).context("serializing transfer manifest chunk")?;
            if bytes.len() as u64 > MAX_TRANSFER_CHUNK_LEN {
                bail!("transfer manifest chunk exceeds its size limit");
            }
            let digest = sha256_hex(&bytes);
            let filename = format!("glacialcast-transfer-chunk-{chunk_id:020}-{digest}.json");
            let path = root.join(&filename);
            write_immutable_transfer_chunk(root, &path, &bytes)?;
            let first_sequence = chunk
                .objects
                .first()
                .expect("nonempty transfer chunk")
                .header
                .sequence;
            let last_sequence = chunk
                .objects
                .last()
                .expect("nonempty transfer chunk")
                .header
                .sequence;
            self.chunks.insert(
                chunk_id,
                TransferChunkDescriptor {
                    filename,
                    length: bytes.len() as u64,
                    sha256: digest,
                    first_sequence,
                    last_sequence,
                    object_count: chunk.objects.len() as u64,
                },
            );
        }

        let manifest = TransferManifest {
            version: TRANSFER_MANIFEST_VERSION,
            stream_id,
            generated_at_ms: glacialcast_protocol::now_ms(),
            chunks: self.chunks.values().cloned().collect(),
        };
        let bytes = serde_json::to_vec(&manifest).context("serializing transfer manifest")?;
        if bytes.len() as u64 > MAX_TRANSFER_MANIFEST_LEN {
            bail!("transfer manifest index exceeds its size limit");
        }
        atomic_write(root, &root.join(TRANSFER_MANIFEST_FILE), &bytes)?;
        remove_unreferenced_transfer_chunks(root, &manifest.chunks)?;
        self.dirty_chunks.clear();
        Ok(())
    }
}

fn transfer_chunk_id(sequence: u64) -> u64 {
    sequence.saturating_sub(1) / TRANSFER_CHUNK_OBJECTS
}

fn transfer_object_from_path(path: &FsPath) -> Result<TransferObject> {
    let (object, bytes) = read_portable_file(path)?;
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("portable object filename is not UTF-8")?
        .to_string();
    Ok(TransferObject {
        filename,
        length: bytes.len() as u64,
        sha256: sha256_hex(&bytes),
        header: object.header,
    })
}

fn write_immutable_transfer_chunk(directory: &FsPath, path: &FsPath, bytes: &[u8]) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.len() != bytes.len() as u64 {
                bail!(
                    "existing transfer chunk is not the expected regular file: {}",
                    path.display()
                );
            }
            let existing =
                read_bounded_regular_file(path, MAX_TRANSFER_CHUNK_LEN, "transfer chunk")?;
            if existing != bytes {
                bail!("existing transfer chunk conflicts with its content hash");
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            atomic_write(directory, path, bytes)
        }
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
}

fn remove_unreferenced_transfer_chunks(
    root: &FsPath,
    chunks: &[TransferChunkDescriptor],
) -> Result<()> {
    let referenced = chunks
        .iter()
        .map(|chunk| chunk.filename.as_str())
        .collect::<HashSet<_>>();
    let mut removed = false;
    for entry in std::fs::read_dir(root).with_context(|| format!("reading {}", root.display()))? {
        let entry = entry.with_context(|| format!("reading an entry in {}", root.display()))?;
        let filename = entry.file_name();
        let Some(filename) = filename.to_str() else {
            continue;
        };
        if !transfer_chunk_filename(filename) || referenced.contains(filename) {
            continue;
        }
        if entry.file_type()?.is_dir() {
            bail!(
                "managed transfer chunk path is unexpectedly a directory: {}",
                entry.path().display()
            );
        }
        std::fs::remove_file(entry.path())
            .with_context(|| format!("removing stale transfer chunk {}", entry.path().display()))?;
        removed = true;
    }
    if removed {
        File::open(root)
            .with_context(|| format!("opening {}", root.display()))?
            .sync_all()
            .with_context(|| format!("syncing {}", root.display()))?;
    }
    Ok(())
}

fn transfer_chunk_filename(filename: &str) -> bool {
    let Some(body) = filename
        .strip_prefix("glacialcast-transfer-chunk-")
        .and_then(|filename| filename.strip_suffix(".json"))
    else {
        return false;
    };
    let Some((chunk, digest)) = body.split_once('-') else {
        return false;
    };
    chunk.len() == 20
        && chunk.bytes().all(|byte| byte.is_ascii_digit())
        && digest.len() == 64
        && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn verify_transfer(root: &FsPath) -> Result<TransferVerification> {
    if !root.is_dir() {
        bail!("portable transfer is not a directory: {}", root.display());
    }
    let manifest_path = root.join(TRANSFER_MANIFEST_FILE);
    let manifest_bytes = read_bounded_regular_file(
        &manifest_path,
        MAX_TRANSFER_MANIFEST_LEN,
        "transfer manifest",
    )?;
    let (manifest_stream_id, manifest_objects) = decode_transfer_manifest(root, &manifest_bytes)?;

    let mut expected_names = HashSet::new();
    let mut sequences = HashSet::new();
    let mut missing = Vec::new();
    let mut verified_objects = 0usize;
    for declared in &manifest_objects {
        let expected_filename = format!("{:020}.gco", declared.header.sequence);
        if declared.filename != expected_filename
            || !expected_names.insert(declared.filename.clone())
            || !sequences.insert(declared.header.sequence)
        {
            bail!(
                "transfer manifest contains an invalid or duplicate object {}",
                declared.filename
            );
        }
        if declared.header.stream_id != manifest_stream_id {
            bail!("transfer manifest contains an object for a different stream");
        }
        let path = root.join(&declared.filename);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(declared.filename.clone());
                continue;
            }
            Err(error) => {
                return Err(error).with_context(|| format!("inspecting {}", path.display()));
            }
        };
        if !metadata.file_type().is_file() {
            bail!("declared object is not a regular file: {}", path.display());
        }
        if metadata.len() != declared.length || metadata.len() > MAX_PORTABLE_FILE_LEN {
            bail!("declared object length mismatch: {}", path.display());
        }
        let bytes = read_bounded_regular_file(&path, MAX_PORTABLE_FILE_LEN, "portable object")?;
        if sha256_hex(&bytes) != declared.sha256 {
            bail!("declared object checksum mismatch: {}", path.display());
        }
        let object = DashObject::from_portable_bytes(&bytes)
            .with_context(|| format!("decoding declared object {}", path.display()))?;
        if object.header != declared.header {
            bail!("declared object metadata mismatch: {}", path.display());
        }
        verified_objects += 1;
    }

    let mut unexpected = Vec::new();
    for entry in
        std::fs::read_dir(root).with_context(|| format!("reading transfer {}", root.display()))?
    {
        let entry = entry.with_context(|| format!("reading an entry in {}", root.display()))?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("gco") {
            continue;
        }
        let filename = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("portable object filename is not UTF-8"))?;
        if !entry.file_type()?.is_file() {
            bail!("portable object is not a regular file: {}", path.display());
        }
        if !expected_names.contains(&filename) {
            unexpected.push(filename);
        }
    }
    missing.sort();
    unexpected.sort();
    Ok(TransferVerification {
        complete: missing.is_empty() && unexpected.is_empty(),
        stream_id: manifest_stream_id,
        expected_objects: manifest_objects.len(),
        verified_objects,
        missing,
        unexpected,
    })
}

fn decode_transfer_manifest(
    root: &FsPath,
    manifest_bytes: &[u8],
) -> Result<(Uuid, Vec<TransferObject>)> {
    match parse_transfer_root(manifest_bytes)? {
        TransferRoot::Legacy(manifest) => Ok((manifest.stream_id, manifest.objects)),
        TransferRoot::Chunked(manifest) => {
            let mut objects = Vec::new();
            let mut chunk_names = HashSet::new();
            let mut previous_sequence = None;
            for declared in &manifest.chunks {
                if !transfer_chunk_filename(&declared.filename)
                    || !chunk_names.insert(declared.filename.clone())
                    || declared.length == 0
                    || declared.length > MAX_TRANSFER_CHUNK_LEN
                    || declared.object_count == 0
                    || declared.object_count > TRANSFER_CHUNK_OBJECTS
                    || declared.first_sequence > declared.last_sequence
                    || previous_sequence.is_some_and(|sequence| sequence >= declared.first_sequence)
                {
                    bail!(
                        "transfer manifest contains an invalid chunk {}",
                        declared.filename
                    );
                }
                let path = root.join(&declared.filename);
                let bytes =
                    read_bounded_regular_file(&path, MAX_TRANSFER_CHUNK_LEN, "transfer chunk")?;
                if bytes.len() as u64 != declared.length {
                    bail!(
                        "transfer manifest chunk is not a regular file of the declared length: {}",
                        path.display()
                    );
                }
                let digest = sha256_hex(&bytes);
                if digest != declared.sha256 {
                    bail!(
                        "transfer manifest chunk checksum mismatch: {}",
                        path.display()
                    );
                }
                let chunk = parse_transfer_chunk(&bytes)
                    .with_context(|| format!("decoding transfer chunk {}", path.display()))?;
                if chunk.stream_id != manifest.stream_id
                    || chunk.objects.len() as u64 != declared.object_count
                    || chunk.objects.first().map(|object| object.header.sequence)
                        != Some(declared.first_sequence)
                    || chunk.objects.last().map(|object| object.header.sequence)
                        != Some(declared.last_sequence)
                {
                    bail!(
                        "transfer manifest chunk metadata mismatch: {}",
                        path.display()
                    );
                }
                let chunk_id = transfer_chunk_id(declared.first_sequence);
                let expected_filename =
                    format!("glacialcast-transfer-chunk-{chunk_id:020}-{digest}.json");
                if declared.filename != expected_filename
                    || chunk
                        .objects
                        .iter()
                        .any(|object| transfer_chunk_id(object.header.sequence) != chunk_id)
                {
                    bail!("transfer manifest chunk has an invalid sequence range");
                }
                for pair in chunk.objects.windows(2) {
                    if pair[0].header.sequence >= pair[1].header.sequence {
                        bail!("transfer manifest chunk sequences are not strictly ordered");
                    }
                }
                previous_sequence = Some(declared.last_sequence);
                objects.extend(chunk.objects);
            }
            Ok((manifest.stream_id, objects))
        }
    }
}

fn atomic_write(directory: &FsPath, path: &FsPath, bytes: &[u8]) -> Result<()> {
    let temporary = directory.join(format!(".transfer-{}.part", Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&temporary)
        .with_context(|| format!("creating {}", temporary.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", temporary.display()))?;
    std::fs::rename(&temporary, path).with_context(|| {
        format!(
            "publishing transfer manifest {} as {}",
            temporary.display(),
            path.display()
        )
    })?;
    File::open(directory)
        .with_context(|| format!("opening {}", directory.display()))?
        .sync_all()
        .with_context(|| format!("syncing {}", directory.display()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn portable_object_path(output: &FsPath, sequence: u64) -> PathBuf {
    output.join(format!("{sequence:020}.gco"))
}

fn write_portable_object(
    directory: &FsPath,
    path: &FsPath,
    object: &DashObject,
) -> Result<TransferObject> {
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
        .with_context(|| format!("syncing {}", directory.display()))?;
    Ok(TransferObject {
        filename: path
            .file_name()
            .and_then(|value| value.to_str())
            .context("portable object filename is not UTF-8")?
            .to_string(),
        length: bytes.len() as u64,
        sha256: sha256_hex(&bytes),
        header: object.header.clone(),
    })
}

fn read_portable_object(path: &FsPath) -> Result<DashObject> {
    read_portable_file(path).map(|(object, _)| object)
}

fn read_portable_file(path: &FsPath) -> Result<(DashObject, Vec<u8>)> {
    let bytes = read_bounded_regular_file(path, MAX_PORTABLE_FILE_LEN, "portable object")?;
    let object = DashObject::from_portable_bytes(&bytes)
        .with_context(|| format!("decoding portable object {}", path.display()))?;
    Ok((object, bytes))
}

fn read_bounded_regular_file(path: &FsPath, max_len: u64, kind: &str) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening {kind} {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting open {kind} {}", path.display()))?;
    if !metadata.is_file() {
        bail!("{kind} is not a regular file: {}", path.display());
    }
    if metadata.len() > max_len {
        bail!("{kind} {} exceeds its size limit", path.display());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::take(&mut file, max_len.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {kind} {}", path.display()))?;
    if bytes.len() as u64 != metadata.len() {
        bail!("{kind} {} changed while it was being read", path.display());
    }
    Ok(bytes)
}

fn validate_offline_listener(listen: SocketAddr, allow_non_loopback: bool) -> Result<()> {
    if !listen.ip().is_loopback() && !allow_non_loopback {
        bail!(
            "refusing to expose the offline viewer on {listen}; use --allow-non-loopback only on a trusted network"
        );
    }
    Ok(())
}

async fn serve(input: PathBuf, listen: SocketAddr, allow_non_loopback: bool) -> Result<()> {
    validate_offline_listener(listen, allow_non_loopback)?;
    if !input.is_dir() {
        bail!("offline input is not a directory: {}", input.display());
    }
    let transfer_manifest = input.join(TRANSFER_MANIFEST_FILE);
    match std::fs::symlink_metadata(&transfer_manifest) {
        Ok(_) => {
            let report = verify_transfer(&input)?;
            if !report.complete {
                warn!(
                    missing = report.missing.len(),
                    unexpected = report.unexpected.len(),
                    "serving an incomplete transfer while objects continue to arrive"
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspecting {}", transfer_manifest.display()));
        }
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
        .route("/assets/dash-viewer-page.js", get(viewer_page_js))
        .route("/assets/viewer-key.js", get(viewer_key_js))
        .route("/api/streams", get(list_streams))
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

/// Lists the mirrored streams in the shape the viewer reads from a relay.
///
/// The viewer asks `/api/streams` for one thing beyond identity: the
/// publisher's key-derivation salt, so a shared phrase can be resolved. A
/// portable transfer does not carry the salt, so it is `null` here and a raw
/// viewer key is what unlocks a mirror. Before this endpoint existed the page's
/// lookup got a 404 -- harmless to a raw key, but Chromium reports every 404
/// response as a console error, which failed the browser gate on a fetch the
/// code had already handled.
async fn list_streams(
    State(state): State<OfflineState>,
) -> Result<Json<Vec<serde_json::Value>>, OfflineError> {
    let streams = load_all(&state)
        .await?
        .into_iter()
        .map(|object| object.header.stream_id)
        .collect::<BTreeSet<_>>();
    Ok(Json(
        streams
            .into_iter()
            .map(|stream_id| {
                serde_json::json!({
                    "stream_id": stream_id,
                    "display_name": stream_id.to_string(),
                    "active": false,
                    "viewer_key_salt": serde_json::Value::Null,
                })
            })
            .collect(),
    ))
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
        .header(
            "content-security-policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        )
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

async fn viewer_page_js() -> Response {
    static_response("text/javascript; charset=utf-8", VIEWER_PAGE_JS)
}

async fn viewer_key_js() -> Response {
    static_response("text/javascript; charset=utf-8", VIEWER_KEY_JS)
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
        let end = entry.start.saturating_add(entry.duration).max(
            object
                .header
                .timestamp
                .saturating_add(object.header.duration),
        );
        entry.start = entry.start.min(object.header.timestamp);
        entry.duration = end.saturating_sub(entry.start);
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

    #[test]
    fn transfer_manifest_verifies_out_of_order_files_and_reports_missing_objects() {
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
        write_transfer_manifest(directory.path(), stream_id).unwrap();
        let report = verify_transfer(directory.path()).unwrap();
        assert!(report.complete);
        assert_eq!(report.expected_objects, 3);
        assert_eq!(report.verified_objects, 3);

        let second = portable_object_path(directory.path(), 2);
        let holding = directory.path().join("second.holding");
        std::fs::rename(&second, &holding).unwrap();
        let report = verify_transfer(directory.path()).unwrap();
        assert!(!report.complete);
        assert_eq!(report.verified_objects, 2);
        assert_eq!(report.missing, ["00000000000000000002.gco"]);
        std::fs::rename(holding, second).unwrap();
        assert!(verify_transfer(directory.path()).unwrap().complete);
    }

    #[test]
    fn transfer_manifest_v2_chunks_large_sequence_ranges_incrementally() {
        let directory = TestDirectory::new();
        let stream_id = Uuid::new_v4();
        let epoch_id = Uuid::new_v4();
        let mut index = TransferIndex::default();
        for sequence in [1, TRANSFER_CHUNK_OBJECTS, TRANSFER_CHUNK_OBJECTS + 1] {
            let object = test_object(
                stream_id,
                epoch_id,
                DashObjectKind::Cursor,
                sequence,
                sequence,
                0,
                vec![sequence as u8],
            );
            index
                .insert(TransferObject {
                    filename: format!("{sequence:020}.gco"),
                    length: 1,
                    sha256: "00".repeat(32),
                    header: object.header,
                })
                .unwrap();
        }

        index.publish(directory.path(), stream_id).unwrap();
        let manifest: TransferManifest = serde_json::from_slice(
            &std::fs::read(directory.path().join(TRANSFER_MANIFEST_FILE)).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest.version, TRANSFER_MANIFEST_VERSION);
        assert_eq!(manifest.chunks.len(), 2);
        let (_, objects) = decode_transfer_manifest(
            directory.path(),
            &std::fs::read(directory.path().join(TRANSFER_MANIFEST_FILE)).unwrap(),
        )
        .unwrap();
        assert_eq!(
            objects
                .iter()
                .map(|object| object.header.sequence)
                .collect::<Vec<_>>(),
            [1, TRANSFER_CHUNK_OBJECTS, TRANSFER_CHUNK_OBJECTS + 1]
        );

        let unchanged_chunk = manifest.chunks[0].filename.clone();
        let old_chunk = manifest.chunks[1].filename.clone();
        let next_sequence = TRANSFER_CHUNK_OBJECTS + 2;
        let object = test_object(
            stream_id,
            epoch_id,
            DashObjectKind::Cursor,
            next_sequence,
            next_sequence,
            0,
            vec![2],
        );
        index
            .insert(TransferObject {
                filename: format!("{next_sequence:020}.gco"),
                length: 1,
                sha256: "11".repeat(32),
                header: object.header,
            })
            .unwrap();
        index.publish(directory.path(), stream_id).unwrap();
        let updated: TransferManifest = serde_json::from_slice(
            &std::fs::read(directory.path().join(TRANSFER_MANIFEST_FILE)).unwrap(),
        )
        .unwrap();
        assert_eq!(updated.chunks[0].filename, unchanged_chunk);
        assert_ne!(updated.chunks[1].filename, old_chunk);
        assert!(!directory.path().join(old_chunk).exists());
    }

    #[test]
    fn transfer_manifest_writer_rejects_an_oversized_chunk_before_publication() {
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
        let mut index = TransferIndex::default();
        index
            .insert(TransferObject {
                filename: "x".repeat(MAX_TRANSFER_CHUNK_LEN as usize),
                length: 1,
                sha256: "00".repeat(32),
                header: object.header,
            })
            .unwrap();
        assert!(index.publish(directory.path(), stream_id).is_err());
        assert!(!directory.path().join(TRANSFER_MANIFEST_FILE).exists());
    }

    #[test]
    fn transfer_verifier_remains_compatible_with_v1_manifests() {
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
        let path = portable_object_path(directory.path(), 1);
        let transferred = write_portable_object(directory.path(), &path, &object).unwrap();
        let manifest = LegacyTransferManifest {
            version: LEGACY_TRANSFER_MANIFEST_VERSION,
            stream_id,
            generated_at_ms: glacialcast_protocol::now_ms(),
            objects: vec![transferred],
        };
        let bytes = serde_json::to_vec(&manifest).unwrap();
        atomic_write(
            directory.path(),
            &directory.path().join(TRANSFER_MANIFEST_FILE),
            &bytes,
        )
        .unwrap();
        assert!(verify_transfer(directory.path()).unwrap().complete);
    }

    #[test]
    fn transfer_verification_rejects_checksum_changes_and_unexpected_objects() {
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
        let first_path = portable_object_path(directory.path(), 1);
        write_portable_object(directory.path(), &first_path, &first).unwrap();
        write_transfer_manifest(directory.path(), stream_id).unwrap();

        let unexpected = test_object(
            stream_id,
            epoch_id,
            DashObjectKind::Cursor,
            2,
            1,
            0,
            vec![2],
        );
        let unexpected_path = portable_object_path(directory.path(), 2);
        write_portable_object(directory.path(), &unexpected_path, &unexpected).unwrap();
        let report = verify_transfer(directory.path()).unwrap();
        assert!(!report.complete);
        assert_eq!(report.unexpected, ["00000000000000000002.gco"]);
        std::fs::remove_file(unexpected_path).unwrap();

        let mut bytes = std::fs::read(&first_path).unwrap();
        let last = bytes.last_mut().unwrap();
        *last ^= 1;
        std::fs::write(&first_path, bytes).unwrap();
        let error = verify_transfer(directory.path()).unwrap_err();
        assert!(error.to_string().contains("checksum mismatch"));
    }

    #[cfg(unix)]
    #[test]
    fn transfer_verification_never_follows_manifest_chunk_or_object_symlinks() {
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
        let object_path = portable_object_path(directory.path(), 1);
        write_portable_object(directory.path(), &object_path, &object).unwrap();
        write_transfer_manifest(directory.path(), stream_id).unwrap();

        let manifest_path = directory.path().join(TRANSFER_MANIFEST_FILE);
        let manifest: TransferManifest =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        let real_manifest = directory.path().join("manifest.backing");
        std::fs::rename(&manifest_path, &real_manifest).unwrap();
        symlink(&real_manifest, &manifest_path).unwrap();
        assert!(verify_transfer(directory.path()).is_err());
        std::fs::remove_file(&manifest_path).unwrap();
        std::fs::rename(&real_manifest, &manifest_path).unwrap();

        let chunk_path = directory.path().join(&manifest.chunks[0].filename);
        let real_chunk = directory.path().join("chunk.backing");
        std::fs::rename(&chunk_path, &real_chunk).unwrap();
        symlink(&real_chunk, &chunk_path).unwrap();
        assert!(verify_transfer(directory.path()).is_err());
        std::fs::remove_file(&chunk_path).unwrap();
        std::fs::rename(&real_chunk, &chunk_path).unwrap();

        let real_object = directory.path().join("object.backing");
        std::fs::rename(&object_path, &real_object).unwrap();
        symlink(&real_object, &object_path).unwrap();
        assert!(verify_transfer(directory.path()).is_err());
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
    async fn offline_manifest_includes_sparse_frame_time_in_segment_duration() {
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
            segment_frames: 4,
            availability_start_time: "2026-01-01T00:00:00Z".to_string(),
        };
        store_object(
            &directory,
            "epoch.gco",
            &test_object(
                stream_id,
                epoch_id,
                DashObjectKind::Epoch,
                1,
                0,
                0,
                descriptor.to_json().unwrap(),
            ),
        );
        for (sequence, chunk_index, timestamp) in [(2, 0, 0), (3, 1, 900_000)] {
            let media = DashObject::authenticated(
                NewDashObject {
                    stream_id,
                    epoch_id,
                    kind: DashObjectKind::Media,
                    sequence,
                    segment_number: 1,
                    chunk_index,
                    timestamp,
                    duration: 90_000,
                    random_access: chunk_index == 0,
                    mime: "video/iso.segment",
                    payload: vec![sequence as u8],
                },
                &keys,
            )
            .unwrap();
            store_object(&directory, &format!("media-{sequence}.gco"), &media);
        }

        let response = get_manifest(State(offline_state(&directory)), Path(stream_id))
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let manifest = std::str::from_utf8(&body).unwrap();
        assert!(manifest.contains("<S t=\"0\" d=\"990000\"/>"));
    }

    #[tokio::test]
    async fn embedded_viewer_serves_core_before_runtime() {
        let html = viewer(Path(Uuid::new_v4())).await;
        assert!(
            html.headers()
                .get("content-security-policy")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'")
        );
        let body = axum::body::to_bytes(html.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.find("dash-viewer-core.js").unwrap() < html.find("dash-viewer.js").unwrap());
        assert!(
            html.find("dash-viewer.js").unwrap() < html.find("dash-viewer-page.js").unwrap(),
            "the page script must load after the player it mounts"
        );
        let page = viewer_page_js().await;
        assert_eq!(page.status(), StatusCode::OK);

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

    #[test]
    fn offline_viewer_requires_explicit_non_loopback_exposure() {
        assert!(validate_offline_listener("127.0.0.1:8910".parse().unwrap(), false).is_ok());
        assert!(validate_offline_listener("0.0.0.0:8910".parse().unwrap(), false).is_err());
        assert!(validate_offline_listener("0.0.0.0:8910".parse().unwrap(), true).is_ok());
    }
}
