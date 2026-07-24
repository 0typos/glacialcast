use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use clap::{Parser, ValueEnum};
use futures_util::StreamExt;
use glacialcast_dash::{
    CursorBatch as DashCursorBatch, CursorBitmap as DashCursorBitmap,
    CursorContext as DashCursorContext, CursorEvent as DashCursorEvent, DASH_FORMAT_VERSION,
    DEFAULT_SEGMENT_FRAMES, EpochDescriptor, EpochKeys, FragmentInput, MEDIA_TIMESCALE,
    build_encrypted_fragment, build_encrypted_init_segment, encrypt_cursor_batch,
};
use glacialcast_protocol::{
    CaptureSource, ClientMessage, DashObject, DashObjectKind, NewDashObject, NoiseSocket,
    PROTOCOL_VERSION, ServerMessage, StreamHello,
    daemon::{
        daemonize_if_requested, install_signal_handlers, manager_command,
        sanitize_socket_component, serve_control_socket, wait_for_shutdown,
    },
    decode_key_b64, decode_noise_public_key, initiator_handshake, now_ms, parse_human_bytes,
};
use image::{
    ColorType, ImageBuffer, ImageEncoder, Rgb, RgbaImage, codecs::png::PngEncoder,
    imageops::FilterType,
};
use pipewire as pw;
use pw::{properties::properties, spa};
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use std::{
    collections::VecDeque,
    net::SocketAddr,
    os::fd::{FromRawFd, OwnedFd, RawFd},
    path::PathBuf,
    ptr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    net::TcpStream,
    sync::watch,
    time::{MissedTickBehavior, timeout},
};
use tracing::{debug, info, warn};
use uuid::Uuid;
use zbus::{
    Connection, Proxy,
    proxy::SignalStream,
    zvariant::{OwnedFd as ZbusOwnedFd, OwnedObjectPath, OwnedValue, Value},
};

mod dash_encoder;

use dash_encoder::{
    DashDmaBufFrame, DashEncoderMode, DashFrameRelease, DashH264Encoder, DashInputFrame,
    should_capture_dmabuf,
};

const PORTAL_SOURCE_MONITOR: u32 = 1;
const PORTAL_SOURCE_WINDOW: u32 = 2;
const PORTAL_CURSOR_HIDDEN: u32 = 1;
const PORTAL_CURSOR_EMBEDDED: u32 = 2;
const PORTAL_CURSOR_METADATA: u32 = 4;
const PORTAL_PERSIST_DO_NOT: u32 = 0;
const DRM_FORMAT_MOD_LINEAR: u64 = 0;
const DRM_FORMAT_MOD_INVALID: i64 = 0x00ff_ffff_ffff_ffff;
const SPA_DATA_FLAG_MAPPABLE: u32 = 1 << 3;
const DMA_BUF_IOCTL_SYNC: libc::c_ulong = 0x4008_6200;
const DMA_BUF_SYNC_READ: u64 = 1 << 0;
const DMA_BUF_SYNC_END: u64 = 1 << 2;
const PIPEWIRE_CURSOR_DEFAULT_BITMAP_SIDE: usize = 64;
const PIPEWIRE_CURSOR_METADATA_GRACE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
struct CursorBitmap {
    width: u32,
    height: u32,
    hotspot_x: i32,
    hotspot_y: i32,
    png_b64: String,
}

#[derive(Debug, Clone)]
struct CursorMessage {
    x: f32,
    y: f32,
    source_width: u32,
    source_height: u32,
    bitmap: Option<CursorBitmap>,
}

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "client.toml")]
    config: PathBuf,
    #[arg(long, default_value = "127.0.0.1:8900")]
    ingest_addr: SocketAddr,
    #[arg(long, allow_hyphen_values = true)]
    ingest_token: Option<String>,
    #[arg(
        long,
        env = "GLACIALCAST_INGEST_SERVER_KEY",
        allow_hyphen_values = true
    )]
    ingest_server_key: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    viewer_key: Option<String>,
    #[arg(long, conflicts_with = "viewer_key")]
    no_viewer_key: bool,
    #[arg(long)]
    client_id: Option<String>,
    #[arg(long)]
    display_name: Option<String>,
    #[arg(long, value_enum, default_value_t = CaptureMode::DashWayland)]
    capture: CaptureMode,
    #[arg(long, value_enum, default_value_t = PortalSourceMode::Monitor)]
    portal_source: PortalSourceMode,
    #[arg(long, value_enum, default_value_t = ScreenCastBackend::Portal)]
    screencast_backend: ScreenCastBackend,
    #[arg(long)]
    monitor_name: Option<String>,
    #[arg(long, value_enum, default_value_t = PortalCursorMode::Auto)]
    portal_cursor: PortalCursorMode,
    #[arg(long)]
    require_cursor_metadata: bool,
    #[arg(long, default_value_t = 1280)]
    width: u32,
    #[arg(long, default_value_t = 720)]
    height: u32,
    #[arg(long, default_value_t = 1600)]
    max_frame_width: u32,
    #[arg(long, default_value_t = 900)]
    max_frame_height: u32,
    #[arg(long, value_parser = parse_update_rate, default_value = "1")]
    fps: f64,
    #[arg(long, default_value_t = 30)]
    cursor_hz: u64,
    #[arg(long, default_value_t = 250_000)]
    video_bitrate: u32,
    #[arg(long, default_value_t = DEFAULT_SEGMENT_FRAMES)]
    segment_frames: u16,
    #[arg(long, value_enum, default_value_t = DashEncoderMode::Auto)]
    dash_encoder: DashEncoderMode,
    #[arg(long, default_value = "/dev/dri/renderD128")]
    vaapi_device: PathBuf,
    #[arg(long)]
    openh264_library: Option<PathBuf>,
    #[arg(long, value_parser = parse_human_bytes, default_value = "128MiB")]
    resend_bytes: u64,
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

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ClientConfig {
    client_id: Option<String>,
    ingest_token: Option<String>,
    ingest_server_key: Option<String>,
    viewer_key_b64: Option<String>,
    display_name: Option<String>,
}

struct ClientIdentity {
    client_id: String,
    auth_token: Option<String>,
    ingest_server_key: Option<[u8; 32]>,
    viewer_key_b64: Option<String>,
    display_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CaptureMode {
    DashTest,
    DashWayland,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum PortalSourceMode {
    Monitor,
    Window,
    Any,
}

impl PortalSourceMode {
    fn mask(self) -> u32 {
        match self {
            Self::Monitor => PORTAL_SOURCE_MONITOR,
            Self::Window => PORTAL_SOURCE_WINDOW,
            Self::Any => PORTAL_SOURCE_MONITOR | PORTAL_SOURCE_WINDOW,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ScreenCastBackend {
    Portal,
    Mutter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum PortalCursorMode {
    Auto,
    Metadata,
    Embedded,
    Hidden,
}

impl PortalCursorMode {
    fn portal_value(self) -> Option<u32> {
        match self {
            Self::Auto => None,
            Self::Metadata => Some(PORTAL_CURSOR_METADATA),
            Self::Embedded => Some(PORTAL_CURSOR_EMBEDDED),
            Self::Hidden => Some(PORTAL_CURSOR_HIDDEN),
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let identity = resolve_client_identity(&args)?;
    let daemon_socket = client_daemon_socket(&args, &identity);

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
                .unwrap_or_else(|_| "glacialcast_client=info".into()),
        )
        .init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building client runtime")?;
    runtime.block_on(run_client(args, identity, daemon_socket))
}

fn client_daemon_socket(args: &Args, identity: &ClientIdentity) -> PathBuf {
    args.daemon_socket.clone().unwrap_or_else(|| {
        let client_id = sanitize_socket_component(&identity.client_id);
        PathBuf::from(format!("/tmp/glacialcast-client-{client_id}.sock"))
    })
}

async fn run_client(args: Args, identity: ClientIdentity, daemon_socket: PathBuf) -> Result<()> {
    let serve_control = args.daemon_child || args.daemon_socket.is_some();
    info!(
        client_id = %identity.client_id,
        e2e_encrypted = identity.viewer_key_b64.is_some(),
        "stream credentials ready"
    );

    let viewer_key = identity
        .viewer_key_b64
        .as_deref()
        .context("encrypted DASH capture requires --viewer-key or viewer_key_b64 in client.toml")
        .and_then(|key| {
            decode_key_b64(key).context("viewer key must be URL-safe base64 for 32 bytes")
        })?;
    identity.ingest_server_key.as_ref().context(
        "ingest server key is required; pass --ingest-server-key or set ingest_server_key in client.toml",
    )?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(install_signal_handlers(shutdown_tx.clone()));
    if serve_control {
        let control_shutdown = shutdown_tx.clone();
        tokio::spawn(async move {
            if let Err(err) = serve_control_socket(daemon_socket, control_shutdown).await {
                warn!(?err, "daemon control socket stopped");
            }
        });
    }

    let mut capture: Box<dyn Capture> = match args.capture {
        CaptureMode::DashTest => Box::new(TestPatternCapture::new(args.width, args.height)),
        CaptureMode::DashWayland => Box::new(WaylandPipewireCapture::new(&args)),
    };
    let mut resend = DashResendBuffer::new(args.resend_bytes);
    run_dash_client(
        &args,
        &identity,
        &viewer_key,
        capture.as_mut(),
        &mut resend,
        shutdown_rx,
    )
    .await
}

async fn sleep_or_shutdown(duration: Duration, shutdown_rx: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(duration) => false,
        _ = wait_for_shutdown(shutdown_rx) => true,
    }
}

async fn run_dash_client(
    args: &Args,
    identity: &ClientIdentity,
    viewer_key: &[u8; 32],
    capture: &mut dyn Capture,
    resend: &mut DashResendBuffer,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        let source = match capture.source().await {
            Ok(source) => source,
            Err(err) => {
                if is_fatal_capture_error(&err) {
                    return Err(err.context("fatal DASH capture setup error"));
                }
                warn!(?err, "DASH capture source unavailable; retrying in 1s");
                let mut retry_shutdown = shutdown_rx.clone();
                if sleep_or_shutdown(Duration::from_secs(1), &mut retry_shutdown).await {
                    return Ok(());
                }
                continue;
            }
        };
        match run_dash_connection(
            args,
            identity,
            viewer_key,
            &source,
            capture,
            resend,
            shutdown_rx.clone(),
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(err) => {
                if is_fatal_capture_error(&err) || is_fatal_dash_error(&err) {
                    return Err(err.context("fatal encrypted DASH publisher error"));
                }
                warn!(?err, "DASH connection dropped; retrying in 1s");
                let mut retry_shutdown = shutdown_rx.clone();
                if sleep_or_shutdown(Duration::from_secs(1), &mut retry_shutdown).await {
                    return Ok(());
                }
            }
        }
    }
}

fn is_fatal_dash_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        let message = cause.to_string();
        message.contains("OpenH264")
            || message.contains("openh264")
            || message.contains("VA-API H.264")
            || message.contains("required VA-API")
            || message.contains("encoder dimensions changed")
            || message.contains("requires non-zero, even dimensions")
            || message.contains("segment-frames")
            || message.contains("does not fit MPEG-DASH")
    })
}

async fn run_dash_connection(
    args: &Args,
    identity: &ClientIdentity,
    viewer_key: &[u8; 32],
    source: &CaptureSource,
    capture: &mut dyn Capture,
    resend: &mut DashResendBuffer,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    if args.segment_frames == 0 {
        bail!("--segment-frames must be at least 1");
    }
    let ingest_server_key = identity.ingest_server_key.as_ref().context(
        "ingest server key is required; pass --ingest-server-key or set ingest_server_key in client.toml",
    )?;
    let mut stream = TcpStream::connect(args.ingest_addr).await?;
    let transport = initiator_handshake(&mut stream, ingest_server_key).await?;
    let mut socket = NoiseSocket::new(stream, transport);
    let (low, high) = resend.range();
    socket
        .write(&ClientMessage::Hello(StreamHello {
            protocol_version: PROTOCOL_VERSION,
            client_id: identity.client_id.clone(),
            auth_token: identity.auth_token.clone(),
            display_name: identity.display_name.clone(),
            source: source.clone(),
            resend_low: low,
            resend_high: high,
        }))
        .await?;
    let (stream_id, server_last_sequence) = match socket.read::<ServerMessage>().await? {
        ServerMessage::HelloAck {
            accepted: true,
            stream_id: Some(stream_id),
            last_sequence,
            ..
        } => (stream_id, last_sequence),
        ServerMessage::HelloAck { reason, .. } => bail!("server rejected hello: {reason:?}"),
        other => bail!("server sent unexpected first response: {other:?}"),
    };
    resend.drop_other_streams(stream_id);
    resend.ack(server_last_sequence);
    let mut sequence = server_last_sequence;
    if let Some(highest) = resend.range().1
        && highest > server_last_sequence
    {
        let pending = resend.objects(server_last_sequence + 1, highest);
        for object in pending {
            socket
                .write(&ClientMessage::DashObject(object))
                .await
                .context("resending unacknowledged DASH object")?;
            sequence = wait_for_dash_ack(&mut socket, resend).await?.max(sequence);
        }
    }
    sequence = sequence.max(resend.range().1.unwrap_or(0));

    let first_frame = normalize_dash_input(
        capture
            .capture_dash_frame(args.max_frame_width, args.max_frame_height)
            .await?,
        None,
    );
    let width = first_frame.width();
    let height = first_frame.height();
    let frame_duration = ((f64::from(MEDIA_TIMESCALE) / args.fps).round() as u64)
        .clamp(1, u64::from(u32::MAX)) as u32;
    let epoch_id = Uuid::new_v4();
    let keys = EpochKeys::derive(viewer_key, stream_id, epoch_id)
        .context("deriving encrypted DASH epoch keys")?;
    let mut encoder = DashH264Encoder::new(
        args.dash_encoder,
        &args.vaapi_device,
        args.openh264_library.as_deref(),
        width,
        height,
        args.fps,
        args.video_bitrate,
        args.segment_frames,
    )?;
    let first_encoded = encoder.encode(&first_frame, false)?;
    if !first_encoded.keyframe {
        bail!("H.264 encoder did not begin the epoch with a random-access frame");
    }
    let avc_config = first_encoded
        .config
        .clone()
        .context("H.264 encoder did not provide an AVC decoder configuration")?;
    let codec = avc_config
        .codec_string()
        .context("building AVC codec string")?;
    let descriptor = EpochDescriptor {
        format_version: DASH_FORMAT_VERSION,
        stream_id,
        epoch_id,
        key_id: keys.key_id,
        width: u16::try_from(width).context("video width does not fit MPEG-DASH metadata")?,
        height: u16::try_from(height).context("video height does not fit MPEG-DASH metadata")?,
        codec,
        timescale: MEDIA_TIMESCALE,
        segment_frames: args.segment_frames,
        availability_start_time: chrono::Utc::now()
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    };
    let epoch_started = Instant::now();
    send_new_dash_object(
        &mut socket,
        resend,
        next_dash_object(
            &mut sequence,
            &keys,
            DashObjectSpec {
                stream_id,
                epoch_id,
                kind: DashObjectKind::Epoch,
                segment_number: 0,
                chunk_index: 0,
                timestamp: 0,
                duration: 0,
                random_access: true,
                mime: "application/vnd.glacialcast.epoch+json",
                payload: descriptor
                    .to_json()
                    .context("serializing DASH epoch descriptor")?,
            },
        )?,
    )
    .await?;
    send_new_dash_object(
        &mut socket,
        resend,
        next_dash_object(
            &mut sequence,
            &keys,
            DashObjectSpec {
                stream_id,
                epoch_id,
                kind: DashObjectKind::Initialization,
                segment_number: 0,
                chunk_index: 0,
                timestamp: 0,
                duration: 0,
                random_access: true,
                mime: "video/mp4",
                payload: build_encrypted_init_segment(&avc_config, keys.key_id)
                    .context("building encrypted DASH initialization segment")?,
            },
        )?,
    )
    .await?;
    let first_media = build_dash_media_object(
        &mut sequence,
        &keys,
        stream_id,
        epoch_id,
        0,
        frame_duration,
        args.segment_frames,
        &first_encoded,
    )?;
    let first_bytes = first_media.payload.len();
    send_new_dash_object(&mut socket, resend, first_media).await?;
    info!(
        %stream_id,
        %epoch_id,
        width,
        height,
        fps = args.fps,
        bitrate = args.video_bitrate,
        encoder = encoder.backend_name(),
        bytes = first_bytes,
        "encrypted MPEG-DASH publisher started"
    );

    let frame_interval = Duration::from_secs_f64(1.0 / args.fps);
    let mut frame_tick =
        tokio::time::interval_at(tokio::time::Instant::now() + frame_interval, frame_interval);
    frame_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let cursor_interval = Duration::from_secs_f64(1.0 / args.cursor_hz.max(1) as f64);
    let mut cursor_tick = tokio::time::interval(cursor_interval);
    cursor_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut cursor_flush_tick = tokio::time::interval(Duration::from_millis(200));
    cursor_flush_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut media_index = 1u64;
    let mut cursor_sequence = 0u64;
    let mut pending_cursor_events = Vec::new();
    let mut cursor_bitmap_state = DashCursorBitmapState::default();

    loop {
        tokio::select! {
            _ = wait_for_shutdown(&mut shutdown_rx) => {
                flush_dash_cursor_batch(
                    &mut socket,
                    resend,
                    &mut sequence,
                    &keys,
                    stream_id,
                    epoch_id,
                    width,
                    height,
                    frame_duration,
                    args.segment_frames,
                    &mut pending_cursor_events,
                ).await?;
                info!(%stream_id, "shutdown requested; closing encrypted DASH stream");
                return Ok(());
            }
            _ = frame_tick.tick() => {
                let publish_started = Instant::now();
                let frame = normalize_dash_input(
                    capture.capture_dash_frame(args.max_frame_width, args.max_frame_height).await?,
                    Some((width, height)),
                );
                let segment_start =
                    media_index.is_multiple_of(u64::from(args.segment_frames));
                let encoded = encoder.encode(&frame, segment_start)?;
                if segment_start && !encoded.keyframe {
                    bail!("H.264 encoder did not produce an IDR at the segment boundary");
                }
                let object = build_dash_media_object(
                    &mut sequence,
                    &keys,
                    stream_id,
                    epoch_id,
                    media_index,
                    frame_duration,
                    args.segment_frames,
                    &encoded,
                )?;
                let bytes = object.payload.len();
                let sent_sequence = object.header.sequence;
                send_new_dash_object(&mut socket, resend, object).await?;
                let capture_to_ack_ms = publish_started.elapsed().as_millis();
                debug!(
                    %stream_id,
                    sequence = sent_sequence,
                    media_index,
                    keyframe = encoded.keyframe,
                    bytes,
                    capture_to_ack_ms,
                    "sent encrypted DASH media fragment"
                );
                media_index = media_index.saturating_add(1);
            }
            _ = cursor_tick.tick() => {
                cursor_sequence = cursor_sequence.saturating_add(1);
                if let Some(cursor) = capture.cursor(cursor_sequence).await? {
                    let timestamp = duration_to_media_ticks(epoch_started.elapsed());
                    pending_cursor_events.push(cursor_to_dash_event(
                        cursor,
                        timestamp,
                        width,
                        height,
                        &mut cursor_bitmap_state,
                    )?);
                }
            }
            _ = cursor_flush_tick.tick() => {
                flush_dash_cursor_batch(
                    &mut socket,
                    resend,
                    &mut sequence,
                    &keys,
                    stream_id,
                    epoch_id,
                    width,
                    height,
                    frame_duration,
                    args.segment_frames,
                    &mut pending_cursor_events,
                ).await?;
            }
        }
    }
}

struct DashObjectSpec<'a> {
    stream_id: Uuid,
    epoch_id: Uuid,
    kind: DashObjectKind,
    segment_number: u64,
    chunk_index: u16,
    timestamp: u64,
    duration: u64,
    random_access: bool,
    mime: &'a str,
    payload: Vec<u8>,
}

fn next_dash_object(
    sequence: &mut u64,
    keys: &EpochKeys,
    spec: DashObjectSpec<'_>,
) -> Result<DashObject> {
    *sequence = sequence.checked_add(1).context("DASH sequence exhausted")?;
    DashObject::authenticated(
        NewDashObject {
            stream_id: spec.stream_id,
            epoch_id: spec.epoch_id,
            kind: spec.kind,
            sequence: *sequence,
            segment_number: spec.segment_number,
            chunk_index: spec.chunk_index,
            timestamp: spec.timestamp,
            duration: spec.duration,
            random_access: spec.random_access,
            mime: spec.mime,
            payload: spec.payload,
        },
        keys,
    )
    .context("authenticating DASH object")
}

#[allow(clippy::too_many_arguments)]
fn build_dash_media_object(
    sequence: &mut u64,
    keys: &EpochKeys,
    stream_id: Uuid,
    epoch_id: Uuid,
    media_index: u64,
    frame_duration: u32,
    segment_frames: u16,
    encoded: &dash_encoder::EncodedH264Frame,
) -> Result<DashObject> {
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    let timestamp = media_index.saturating_mul(u64::from(frame_duration));
    let fragment = build_encrypted_fragment(
        &keys.cenc_key,
        FragmentInput {
            sequence: u32::try_from(media_index.saturating_add(1))
                .context("DASH epoch has too many media fragments")?,
            decode_time: timestamp,
            duration: frame_duration,
            keyframe: encoded.keyframe,
            annex_b: &encoded.annex_b,
            iv,
        },
    )
    .context("building encrypted DASH media fragment")?;
    let segment_frames = u64::from(segment_frames);
    next_dash_object(
        sequence,
        keys,
        DashObjectSpec {
            stream_id,
            epoch_id,
            kind: DashObjectKind::Media,
            segment_number: media_index / segment_frames + 1,
            chunk_index: (media_index % segment_frames) as u16,
            timestamp,
            duration: u64::from(frame_duration),
            random_access: encoded.keyframe,
            mime: "video/iso.segment",
            payload: fragment.bytes,
        },
    )
}

fn normalize_dash_input(input: DashInputFrame, target: Option<(u32, u32)>) -> DashInputFrame {
    let (width, height) = target.unwrap_or_else(|| {
        let even_width = if input.width() < 2 {
            2
        } else {
            input.width() & !1
        };
        let even_height = if input.height() < 2 {
            2
        } else {
            input.height() & !1
        };
        (even_width, even_height)
    });
    input.with_output_size(width, height)
}

fn fit_even_dimensions(width: u32, height: u32, max_width: u32, max_height: u32) -> (u32, u32) {
    let max_width = max_width.max(2);
    let max_height = max_height.max(2);
    let scale =
        (max_width as f64 / width.max(1) as f64).min(max_height as f64 / height.max(1) as f64);
    let scale = scale.min(1.0);
    let width = ((width.max(1) as f64 * scale).floor() as u32)
        .max(2)
        .min(max_width)
        & !1;
    let height = ((height.max(1) as f64 * scale).floor() as u32)
        .max(2)
        .min(max_height)
        & !1;
    (width.max(2), height.max(2))
}

fn duration_to_media_ticks(duration: Duration) -> u64 {
    let ticks = duration
        .as_nanos()
        .saturating_mul(u128::from(MEDIA_TIMESCALE))
        / 1_000_000_000;
    ticks.min(u128::from(u64::MAX)) as u64
}

fn cursor_to_dash_event(
    cursor: CursorMessage,
    timestamp: u64,
    output_width: u32,
    output_height: u32,
    bitmap_state: &mut DashCursorBitmapState,
) -> Result<DashCursorEvent> {
    let source_width = cursor.source_width.max(1);
    let source_height = cursor.source_height.max(1);
    let x = (cursor.x * output_width as f32 / source_width as f32).clamp(0.0, output_width as f32);
    let y =
        (cursor.y * output_height as f32 / source_height as f32).clamp(0.0, output_height as f32);
    let (bitmap_id, bitmap) = match cursor.bitmap {
        Some(bitmap) if bitmap_state.last.as_ref() == Some(&bitmap) => {
            (bitmap_state.current_id, None)
        }
        Some(bitmap) => {
            let png = BASE64_STANDARD
                .decode(&bitmap.png_b64)
                .context("decoding PipeWire cursor bitmap")?;
            let rgba: RgbaImage = image::load_from_memory(&png)
                .context("decoding PipeWire cursor PNG")?
                .to_rgba8();
            if rgba.width() != bitmap.width || rgba.height() != bitmap.height {
                bail!("PipeWire cursor bitmap dimensions do not match its PNG");
            }
            bitmap_state.current_id = bitmap_state.current_id.wrapping_add(1).max(1);
            bitmap_state.last = Some(bitmap.clone());
            (
                bitmap_state.current_id,
                Some(DashCursorBitmap {
                    width: bitmap.width,
                    height: bitmap.height,
                    hotspot_x: bitmap.hotspot_x,
                    hotspot_y: bitmap.hotspot_y,
                    rgba: rgba.into_raw(),
                }),
            )
        }
        None => (bitmap_state.current_id, None),
    };
    Ok(DashCursorEvent {
        timestamp,
        x_micropixels: (f64::from(x) * 1_000_000.0).round() as i64,
        y_micropixels: (f64::from(y) * 1_000_000.0).round() as i64,
        visible: true,
        bitmap_id,
        bitmap,
    })
}

#[derive(Default)]
struct DashCursorBitmapState {
    current_id: u64,
    last: Option<CursorBitmap>,
}

#[allow(clippy::too_many_arguments)]
async fn flush_dash_cursor_batch(
    socket: &mut NoiseSocket<TcpStream>,
    resend: &mut DashResendBuffer,
    sequence: &mut u64,
    keys: &EpochKeys,
    stream_id: Uuid,
    epoch_id: Uuid,
    width: u32,
    height: u32,
    frame_duration: u32,
    segment_frames: u16,
    events: &mut Vec<DashCursorEvent>,
) -> Result<()> {
    if events.is_empty() {
        return Ok(());
    }
    let start_timestamp = events.first().map_or(0, |event| event.timestamp);
    let end_timestamp = events
        .last()
        .map_or(start_timestamp, |event| event.timestamp);
    let next_sequence = sequence.checked_add(1).context("DASH sequence exhausted")?;
    let batch = DashCursorBatch {
        source_width: width,
        source_height: height,
        events: std::mem::take(events),
    };
    let encrypted = encrypt_cursor_batch(
        keys,
        DashCursorContext {
            stream_id,
            epoch_id,
            sequence: next_sequence,
            start_timestamp,
            source_width: width,
            source_height: height,
        },
        &batch,
    )
    .context("encrypting cursor batch")?;
    let segment_duration = u64::from(frame_duration).saturating_mul(u64::from(segment_frames));
    let object = next_dash_object(
        sequence,
        keys,
        DashObjectSpec {
            stream_id,
            epoch_id,
            kind: DashObjectKind::Cursor,
            segment_number: start_timestamp / segment_duration.max(1) + 1,
            chunk_index: 0,
            timestamp: start_timestamp,
            duration: end_timestamp.saturating_sub(start_timestamp).max(1),
            random_access: true,
            mime: "application/vnd.glacialcast.cursor",
            payload: encrypted
                .to_bytes()
                .context("serializing encrypted cursor batch")?,
        },
    )?;
    send_new_dash_object(socket, resend, object).await
}

async fn send_new_dash_object(
    socket: &mut NoiseSocket<TcpStream>,
    resend: &mut DashResendBuffer,
    object: DashObject,
) -> Result<()> {
    let stream_id = object.header.stream_id;
    resend.push(object.clone());
    socket.write(&ClientMessage::DashObject(object)).await?;
    debug!(%stream_id, buffered_bytes = resend.bytes, "DASH object queued for acknowledgement");
    wait_for_dash_ack(socket, resend).await?;
    Ok(())
}

async fn wait_for_dash_ack(
    socket: &mut NoiseSocket<TcpStream>,
    resend: &mut DashResendBuffer,
) -> Result<u64> {
    loop {
        match socket.read::<ServerMessage>().await? {
            ServerMessage::Ack { through_seq } => {
                resend.ack(through_seq);
                return Ok(through_seq);
            }
            ServerMessage::ResendRequest { from_seq, to_seq } => {
                let objects = resend.objects(from_seq, to_seq);
                let expected = to_seq.saturating_sub(from_seq).saturating_add(1);
                if objects.len() as u64 != expected {
                    bail!(
                        "server requested DASH objects {from_seq}..={to_seq}, but the resend buffer no longer contains all of them"
                    );
                }
                for object in objects {
                    socket.write(&ClientMessage::DashObject(object)).await?;
                }
            }
            ServerMessage::Backpressure { pause_ms, reason } => {
                warn!(pause_ms, %reason, "server requested DASH publisher backpressure");
                tokio::time::sleep(Duration::from_millis(pause_ms)).await;
            }
            ServerMessage::Pong { .. } | ServerMessage::HelloAck { .. } => {}
        }
    }
}

fn is_fatal_capture_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        let message = cause.to_string();
        message.contains("non-mappable DMA-BUF")
            || message.contains("GPU import/readback is required")
            || message.contains("requires GPU readback")
            || message.contains("GPU readback failed")
            || message.contains("CPU-readable PipeWire buffers")
            || message.contains("no more input formats")
            || message.contains("error alloc buffers: Invalid argument")
            || message.contains("requested portal cursor mode Metadata is not available")
            || message
                .contains("does not include SPA_META_Cursor while --require-cursor-metadata is set")
    })
}

fn resolve_client_identity(args: &Args) -> Result<ClientIdentity> {
    let config = load_client_config(&args.config)?;
    let client_id = args
        .client_id
        .clone()
        .or(config.client_id)
        .unwrap_or_else(hostname);
    let client_id = non_empty_trimmed("client_id", client_id)?;
    let auth_token = args
        .ingest_token
        .clone()
        .or(config.ingest_token)
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty());
    let ingest_server_key = args
        .ingest_server_key
        .clone()
        .or(config.ingest_server_key)
        .map(|key| decode_noise_public_key(&key))
        .transpose()
        .context("ingest_server_key must be URL-safe base64 for a 32-byte Noise public key")?;
    let viewer_key_b64 = if args.no_viewer_key {
        None
    } else {
        args.viewer_key
            .clone()
            .or(config.viewer_key_b64)
            .map(|key| non_empty_trimmed("viewer_key_b64", key))
            .transpose()?
    };
    let display_name = args
        .display_name
        .clone()
        .or(config.display_name)
        .unwrap_or_else(|| "Glacialcast client".to_string());
    let display_name = non_empty_trimmed("display_name", display_name)?;

    Ok(ClientIdentity {
        client_id,
        auth_token,
        ingest_server_key,
        viewer_key_b64,
        display_name,
    })
}

fn non_empty_trimmed(field: &str, value: String) -> Result<String> {
    let value = value.trim().to_string();
    if value.is_empty() {
        bail!("{field} must not be empty");
    }
    Ok(value)
}

fn load_client_config(path: &PathBuf) -> Result<ClientConfig> {
    if !path.exists() {
        return Ok(ClientConfig::default());
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading client config {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("parsing client config {}", path.display()))
}

fn parse_update_rate(value: &str) -> std::result::Result<f64, String> {
    let fps = value
        .trim()
        .parse::<f64>()
        .map_err(|_| format!("invalid update rate {value:?}"))?;
    if !(0.5..=15.0).contains(&fps) {
        return Err("update rate must be between 0.5 and 15 updates per second".to_string());
    }
    Ok(fps)
}

struct PipewireThreadStop {
    mainloop_ptr: Arc<AtomicUsize>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl PipewireThreadStop {
    fn stop(&mut self) {
        let ptr = self.mainloop_ptr.swap(0, Ordering::SeqCst);
        if ptr != 0 {
            unsafe {
                pw::sys::pw_main_loop_quit(ptr as *mut _);
            }
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for PipewireThreadStop {
    fn drop(&mut self) {
        self.stop();
    }
}

#[async_trait]
trait Capture: Send {
    async fn source(&mut self) -> Result<CaptureSource>;
    async fn capture_rgb(
        &mut self,
        max_width: u32,
        max_height: u32,
    ) -> Result<ImageBuffer<Rgb<u8>, Vec<u8>>>;
    async fn capture_dash_frame(
        &mut self,
        max_width: u32,
        max_height: u32,
    ) -> Result<DashInputFrame> {
        Ok(DashInputFrame::Rgb(
            self.capture_rgb(max_width, max_height).await?,
        ))
    }
    async fn cursor(&mut self, seq: u64) -> Result<Option<CursorMessage>>;
}

struct TestPatternCapture {
    width: u32,
    height: u32,
    tick: u32,
}

impl TestPatternCapture {
    fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            tick: 0,
        }
    }

    fn next_rgb(&mut self) -> ImageBuffer<Rgb<u8>, Vec<u8>> {
        self.tick = self.tick.wrapping_add(1);
        let mut image = ImageBuffer::<Rgb<u8>, Vec<u8>>::new(self.width, self.height);
        for (x, y, pixel) in image.enumerate_pixels_mut() {
            let r = ((x + self.tick * 17) % 255) as u8;
            let g = ((y + self.tick * 29) % 255) as u8;
            let b = (((x / 8) + (y / 8) + self.tick * 11) % 255) as u8;
            *pixel = Rgb([r, g, b]);
        }
        image
    }
}

#[async_trait]
impl Capture for TestPatternCapture {
    async fn source(&mut self) -> Result<CaptureSource> {
        Ok(CaptureSource {
            backend: "test-pattern".to_string(),
            description: "Generated moving color bars".to_string(),
            width: self.width,
            height: self.height,
        })
    }

    async fn capture_rgb(
        &mut self,
        max_width: u32,
        max_height: u32,
    ) -> Result<ImageBuffer<Rgb<u8>, Vec<u8>>> {
        Ok(resize_rgb_image_to_fit(
            self.next_rgb(),
            max_width,
            max_height,
        ))
    }

    async fn cursor(&mut self, seq: u64) -> Result<Option<CursorMessage>> {
        let t = seq as f32 / 30.0;
        Ok(Some(CursorMessage {
            x: ((t.sin() + 1.0) * 0.5) * self.width as f32,
            y: ((t.cos() + 1.0) * 0.5) * self.height as f32,
            source_width: self.width,
            source_height: self.height,
            bitmap: None,
        }))
    }
}

struct WaylandPipewireCapture {
    fps: f64,
    cursor_hz: u64,
    portal_source: PortalSourceMode,
    screencast_backend: ScreenCastBackend,
    monitor_name: Option<String>,
    portal_cursor: PortalCursorMode,
    require_cursor_metadata: bool,
    prefer_dmabuf: bool,
    inner: Option<NativePipewireCapture>,
}

impl WaylandPipewireCapture {
    fn new(args: &Args) -> Self {
        Self {
            fps: args.fps,
            cursor_hz: args.cursor_hz,
            portal_source: args.portal_source,
            screencast_backend: args.screencast_backend,
            monitor_name: args.monitor_name.clone(),
            portal_cursor: args.portal_cursor,
            require_cursor_metadata: args.require_cursor_metadata,
            prefer_dmabuf: args.capture == CaptureMode::DashWayland
                && should_capture_dmabuf(args.dash_encoder, &args.vaapi_device),
            inner: None,
        }
    }

    async fn ensure_started(&mut self) -> Result<&mut NativePipewireCapture> {
        if self.inner.is_none() {
            self.inner = Some(
                NativePipewireCapture::start(NativePipewireCaptureConfig {
                    fps: self.fps,
                    cursor_hz: self.cursor_hz,
                    portal_source: self.portal_source,
                    screencast_backend: self.screencast_backend,
                    monitor_name: self.monitor_name.as_deref(),
                    portal_cursor: self.portal_cursor,
                    require_cursor_metadata: self.require_cursor_metadata,
                    prefer_dmabuf: self.prefer_dmabuf,
                })
                .await?,
            );
        }
        Ok(self.inner.as_mut().expect("capture initialized"))
    }
}

#[async_trait]
impl Capture for WaylandPipewireCapture {
    async fn source(&mut self) -> Result<CaptureSource> {
        Ok(self.ensure_started().await?.source.clone())
    }

    async fn capture_rgb(
        &mut self,
        max_width: u32,
        max_height: u32,
    ) -> Result<ImageBuffer<Rgb<u8>, Vec<u8>>> {
        let capture = self.ensure_started().await?;
        match capture.next_rgb(max_width, max_height).await {
            Ok(image) => Ok(image),
            Err(err) => {
                self.inner = None;
                Err(err)
            }
        }
    }

    async fn capture_dash_frame(
        &mut self,
        max_width: u32,
        max_height: u32,
    ) -> Result<DashInputFrame> {
        let capture = self.ensure_started().await?;
        match capture.next_dash_frame(max_width, max_height).await {
            Ok(frame) => Ok(frame),
            Err(err) => {
                self.inner = None;
                Err(err)
            }
        }
    }

    async fn cursor(&mut self, _seq: u64) -> Result<Option<CursorMessage>> {
        Ok(self
            .ensure_started()
            .await?
            .next_cursor_sample()
            .map(|sample| sample.to_message()))
    }
}

struct NativePipewireCapture {
    source: CaptureSource,
    latest: NativePipewireFrames,
    cursor_latest: watch::Receiver<Option<PipewireCursorSample>>,
    pipewire_error: Arc<Mutex<Option<String>>>,
    last_encoded_serial: u64,
    last_cursor_serial: u64,
    _screencast_session: ScreenCastSession,
    _pipewire_thread: PipewireThreadStop,
}

enum NativePipewireFrames {
    Cpu(watch::Receiver<Option<RawFrame>>),
    DmaBuf(watch::Receiver<Option<PipewireVideoFrame>>),
}

struct NativePipewireCaptureConfig<'a> {
    fps: f64,
    cursor_hz: u64,
    portal_source: PortalSourceMode,
    screencast_backend: ScreenCastBackend,
    monitor_name: Option<&'a str>,
    portal_cursor: PortalCursorMode,
    require_cursor_metadata: bool,
    prefer_dmabuf: bool,
}

impl NativePipewireCapture {
    async fn start(config: NativePipewireCaptureConfig<'_>) -> Result<Self> {
        let NativePipewireCaptureConfig {
            fps,
            cursor_hz,
            portal_source,
            screencast_backend,
            monitor_name,
            portal_cursor,
            require_cursor_metadata,
            prefer_dmabuf,
        } = config;
        let capture = open_screencast_capture(
            screencast_backend,
            portal_source,
            monitor_name,
            portal_cursor,
        )
        .await?;
        let (cursor_tx, cursor_rx) = watch::channel(None);
        let pipewire_error = Arc::new(Mutex::new(None));
        let thread_stop = Arc::new(AtomicUsize::new(0));
        let thread_config = PipewireThreadConfig {
            node_id: capture.node_id,
            width: capture.width,
            height: capture.height,
            remote: capture.remote.try_clone()?,
            fps,
            cursor_hz,
            require_cursor_metadata,
            pipewire_error: pipewire_error.clone(),
            mainloop_ptr_out: thread_stop.clone(),
        };
        let (latest, pipewire_thread) = if prefer_dmabuf {
            let (tx, rx) = watch::channel(None);
            let thread = start_pipewire_video_thread(thread_config, tx, cursor_tx)?;
            (NativePipewireFrames::DmaBuf(rx), thread)
        } else {
            let (tx, rx) = watch::channel(None);
            let thread = start_pipewire_thread(thread_config, tx, cursor_tx)?;
            (NativePipewireFrames::Cpu(rx), thread)
        };

        info!(
            node_id = capture.node_id,
            width = capture.width,
            height = capture.height,
            backend = ?screencast_backend,
            dmabuf = prefer_dmabuf,
            "Wayland/PipeWire native capture started"
        );

        Ok(Self {
            source: CaptureSource {
                backend: match screencast_backend {
                    ScreenCastBackend::Portal => "xdg-desktop-portal+pipewire-rs",
                    ScreenCastBackend::Mutter => "mutter-screencast+pipewire-rs",
                }
                .to_string(),
                description: capture.description,
                width: capture.width,
                height: capture.height,
            },
            latest,
            cursor_latest: cursor_rx,
            pipewire_error,
            last_encoded_serial: 0,
            last_cursor_serial: 0,
            _screencast_session: capture.session,
            _pipewire_thread: pipewire_thread,
        })
    }

    fn next_cursor_sample(&mut self) -> Option<PipewireCursorSample> {
        let sample = self.cursor_latest.borrow().clone()?;
        if sample.serial == self.last_cursor_serial {
            return None;
        }
        self.last_cursor_serial = sample.serial;
        Some(sample)
    }

    async fn next_rgb(
        &mut self,
        max_width: u32,
        max_height: u32,
    ) -> Result<ImageBuffer<Rgb<u8>, Vec<u8>>> {
        let frame = self.next_frame().await?;
        Ok(resize_rgb_image_to_fit(
            raw_frame_to_rgb_image(&frame)?,
            max_width,
            max_height,
        ))
    }

    async fn next_frame(&mut self) -> Result<RawFrame> {
        let NativePipewireFrames::Cpu(latest) = &mut self.latest else {
            bail!("CPU image capture was requested from a DMA-BUF PipeWire stream");
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(err) = self
                .pipewire_error
                .lock()
                .expect("PipeWire error mutex poisoned")
                .clone()
            {
                bail!("PipeWire stream failed: {err}");
            }

            if let Some(frame) = latest.borrow().clone()
                && frame.serial != self.last_encoded_serial
            {
                self.last_encoded_serial = frame.serial;
                return Ok(frame);
            }

            if Instant::now() >= deadline {
                bail!("timed out waiting for a PipeWire frame from portal stream");
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let _ = timeout(remaining, latest.changed()).await;
        }
    }

    async fn next_dash_frame(&mut self, max_width: u32, max_height: u32) -> Result<DashInputFrame> {
        if matches!(&self.latest, NativePipewireFrames::Cpu(_)) {
            return Ok(DashInputFrame::Rgb(
                self.next_rgb(max_width, max_height).await?,
            ));
        }
        let NativePipewireFrames::DmaBuf(latest) = &mut self.latest else {
            unreachable!("PipeWire frame source was checked above");
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(err) = self
                .pipewire_error
                .lock()
                .expect("PipeWire error mutex poisoned")
                .clone()
            {
                bail!("PipeWire stream failed: {err}");
            }
            if let Some(frame) = latest.borrow().clone()
                && frame.serial() != self.last_encoded_serial
            {
                self.last_encoded_serial = frame.serial();
                return match frame {
                    PipewireVideoFrame::Cpu(frame) => {
                        Ok(DashInputFrame::Rgb(resize_rgb_image_to_fit(
                            raw_frame_to_rgb_image(&frame)?,
                            max_width,
                            max_height,
                        )))
                    }
                    PipewireVideoFrame::DmaBuf(frame) => {
                        let (output_width, output_height) =
                            fit_even_dimensions(frame.width, frame.height, max_width, max_height);
                        Ok(DashInputFrame::DmaBuf(DashDmaBufFrame {
                            fd: Arc::clone(&frame.fd),
                            release: frame.release.clone(),
                            offset: frame.offset,
                            size: frame.size,
                            stride: usize::try_from(frame.stride)
                                .context("PipeWire DMA-BUF stride is negative")?,
                            drm_format: frame.drm_format,
                            modifier: frame.modifier,
                            source_width: frame.width,
                            source_height: frame.height,
                            output_width,
                            output_height,
                        }))
                    }
                };
            }
            if Instant::now() >= deadline {
                bail!("timed out waiting for a PipeWire frame from portal stream");
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let _ = timeout(remaining, latest.changed()).await;
        }
    }
}

#[derive(Clone)]
struct RawFrame {
    serial: u64,
    width: u32,
    height: u32,
    stride: usize,
    format: RawFrameFormat,
    data: Vec<u8>,
}

#[derive(Clone)]
struct PipewireCursorSample {
    serial: u64,
    x: f32,
    y: f32,
    source_width: u32,
    source_height: u32,
    bitmap: Option<CursorBitmap>,
}

impl PipewireCursorSample {
    fn to_message(&self) -> CursorMessage {
        CursorMessage {
            x: self.x,
            y: self.y,
            source_width: self.source_width,
            source_height: self.source_height,
            bitmap: self.bitmap.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PipewireCursorState {
    id: u32,
    x: i32,
    y: i32,
    hotspot_x: i32,
    hotspot_y: i32,
    bitmap: Option<CursorBitmap>,
}

struct DequeuedPipewireBuffer<'a> {
    stream: &'a pw::stream::Stream,
    buffer: *mut pw::sys::pw_buffer,
}

impl<'a> DequeuedPipewireBuffer<'a> {
    fn dequeue(stream: &'a pw::stream::Stream) -> Option<Self> {
        let buffer = unsafe { stream.dequeue_raw_buffer() };
        (!buffer.is_null()).then_some(Self { stream, buffer })
    }

    fn spa_buffer_ptr(&self) -> *mut spa::sys::spa_buffer {
        unsafe {
            self.buffer
                .as_ref()
                .and_then(|buffer| buffer.buffer.as_mut())
        }
        .map_or(ptr::null_mut(), |buffer| buffer as *mut _)
    }

    fn datas_mut(&mut self) -> &mut [spa::buffer::Data] {
        let buffer = self.spa_buffer_ptr();
        if buffer.is_null() {
            return &mut [];
        }
        unsafe {
            if (*buffer).n_datas == 0 || (*buffer).datas.is_null() {
                &mut []
            } else {
                std::slice::from_raw_parts_mut(
                    (*buffer).datas as *mut spa::buffer::Data,
                    (*buffer).n_datas as usize,
                )
            }
        }
    }

    fn defer_queue(self) -> *mut pw::sys::pw_buffer {
        let buffer = self.buffer;
        std::mem::forget(self);
        buffer
    }
}

impl Drop for DequeuedPipewireBuffer<'_> {
    fn drop(&mut self) {
        unsafe {
            self.stream.queue_raw_buffer(self.buffer);
        }
    }
}

fn maybe_emit_pipewire_cursor(
    user_data: &mut PipewireUserData,
    buffer: *const spa::sys::spa_buffer,
    source_width: u32,
    source_height: u32,
) -> bool {
    let _ = log_pipewire_buffer_metas_once(buffer, &mut user_data.cursor_meta_logged, "PipeWire");
    match pipewire_cursor_metadata_gate(
        buffer,
        user_data.require_cursor_metadata,
        &mut user_data.cursor_meta_verified,
        &mut user_data.cursor_meta_missing_since,
        Instant::now(),
    ) {
        PipewireCursorMetadataGate::Ready => {}
        PipewireCursorMetadataGate::Pending => return false,
        PipewireCursorMetadataGate::Fatal => {
            record_pipewire_error(
                user_data,
                "PipeWire buffer does not include SPA_META_Cursor while --require-cursor-metadata is set"
                    .to_string(),
            );
            return false;
        }
    }
    if let Some(sample) = pipewire_cursor_sample(
        buffer,
        source_width,
        source_height,
        &mut user_data.cursor_serial,
        &mut user_data.last_cursor_state,
        &mut user_data.last_cursor_sent_at,
        user_data.min_cursor_interval,
    ) {
        let _ = user_data.cursor_latest.send(Some(sample));
    }
    true
}

fn maybe_emit_pipewire_video_cursor(
    user_data: &mut PipewireVideoUserData,
    buffer: *const spa::sys::spa_buffer,
    source_width: u32,
    source_height: u32,
) -> bool {
    let _ =
        log_pipewire_buffer_metas_once(buffer, &mut user_data.cursor_meta_logged, "PipeWire video");
    match pipewire_cursor_metadata_gate(
        buffer,
        user_data.require_cursor_metadata,
        &mut user_data.cursor_meta_verified,
        &mut user_data.cursor_meta_missing_since,
        Instant::now(),
    ) {
        PipewireCursorMetadataGate::Ready => {}
        PipewireCursorMetadataGate::Pending => return false,
        PipewireCursorMetadataGate::Fatal => {
            record_pipewire_video_error(
                user_data,
                "PipeWire video buffer does not include SPA_META_Cursor while --require-cursor-metadata is set"
                    .to_string(),
            );
            return false;
        }
    }
    if let Some(sample) = pipewire_cursor_sample(
        buffer,
        source_width,
        source_height,
        &mut user_data.cursor_serial,
        &mut user_data.last_cursor_state,
        &mut user_data.last_cursor_sent_at,
        user_data.min_cursor_interval,
    ) {
        let _ = user_data.cursor_latest.send(Some(sample));
    }
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipewireCursorMetadataGate {
    Ready,
    Pending,
    Fatal,
}

fn pipewire_cursor_metadata_gate(
    buffer: *const spa::sys::spa_buffer,
    required: bool,
    verified: &mut bool,
    missing_since: &mut Option<Instant>,
    now: Instant,
) -> PipewireCursorMetadataGate {
    if !required || *verified {
        return PipewireCursorMetadataGate::Ready;
    }
    if pipewire_buffer_has_cursor_meta(buffer) {
        *verified = true;
        *missing_since = None;
        return PipewireCursorMetadataGate::Ready;
    }
    let first_missing = *missing_since.get_or_insert(now);
    if now.duration_since(first_missing) >= PIPEWIRE_CURSOR_METADATA_GRACE {
        PipewireCursorMetadataGate::Fatal
    } else {
        PipewireCursorMetadataGate::Pending
    }
}

fn pipewire_cursor_sample(
    buffer: *const spa::sys::spa_buffer,
    source_width: u32,
    source_height: u32,
    cursor_serial: &mut u64,
    last_cursor_state: &mut Option<PipewireCursorState>,
    last_cursor_sent_at: &mut Option<Instant>,
    min_cursor_interval: Duration,
) -> Option<PipewireCursorSample> {
    let mut state = pipewire_cursor_state(buffer)?;
    if state.bitmap.is_none()
        && let Some(previous) = last_cursor_state.as_ref()
        && previous.id == state.id
    {
        state.bitmap = previous.bitmap.clone();
    }
    if last_cursor_state
        .as_ref()
        .is_some_and(|last| *last == state)
    {
        return None;
    }
    let now = Instant::now();
    if let Some(last_sent) = *last_cursor_sent_at
        && now.duration_since(last_sent) < min_cursor_interval
    {
        return None;
    }
    *cursor_serial = cursor_serial.wrapping_add(1);
    let sample = PipewireCursorSample {
        serial: *cursor_serial,
        x: state.x.clamp(0, source_width.min(i32::MAX as u32) as i32) as f32,
        y: state.y.clamp(0, source_height.min(i32::MAX as u32) as i32) as f32,
        source_width,
        source_height,
        bitmap: state.bitmap.clone(),
    };
    *last_cursor_state = Some(state);
    *last_cursor_sent_at = Some(now);
    Some(sample)
}

fn pipewire_cursor_state(buffer: *const spa::sys::spa_buffer) -> Option<PipewireCursorState> {
    if buffer.is_null() {
        return None;
    }
    unsafe {
        if (*buffer).n_metas == 0 || (*buffer).metas.is_null() {
            return None;
        }
        let metas = std::slice::from_raw_parts((*buffer).metas, (*buffer).n_metas as usize);
        for meta in metas {
            if meta.type_ != spa::sys::SPA_META_Cursor
                || meta.data.is_null()
                || meta.size < std::mem::size_of::<spa::sys::spa_meta_cursor>() as u32
            {
                continue;
            }
            let cursor = &*(meta.data as *const spa::sys::spa_meta_cursor);
            if cursor.id == 0 {
                continue;
            }
            return Some(PipewireCursorState {
                id: cursor.id,
                x: cursor.position.x,
                y: cursor.position.y,
                hotspot_x: cursor.hotspot.x,
                hotspot_y: cursor.hotspot.y,
                bitmap: pipewire_cursor_bitmap(meta, cursor),
            });
        }
    }
    None
}

fn pipewire_cursor_bitmap(
    meta: &spa::sys::spa_meta,
    cursor: &spa::sys::spa_meta_cursor,
) -> Option<CursorBitmap> {
    let cursor_meta_size = std::mem::size_of::<spa::sys::spa_meta_cursor>();
    let bitmap_meta_size = std::mem::size_of::<spa::sys::spa_meta_bitmap>();
    let meta_size = meta.size as usize;
    let bitmap_offset = cursor.bitmap_offset as usize;
    if meta.data.is_null()
        || bitmap_offset < cursor_meta_size
        || bitmap_offset.checked_add(bitmap_meta_size)? > meta_size
    {
        return None;
    }

    unsafe {
        let meta_base = meta.data.cast::<u8>();
        let bitmap = &*(meta_base
            .add(bitmap_offset)
            .cast::<spa::sys::spa_meta_bitmap>());
        let width = bitmap.size.width;
        let height = bitmap.size.height;
        if bitmap.format == spa::sys::SPA_VIDEO_FORMAT_UNKNOWN
            || width == 0
            || height == 0
            || bitmap.stride <= 0
            || bitmap.offset < bitmap_meta_size as u32
        {
            return None;
        }
        let width = width as usize;
        let height = height as usize;
        let stride = bitmap.stride as usize;
        let row_bytes = width.checked_mul(4)?;
        if stride < row_bytes {
            return None;
        }
        let data_start = bitmap_offset.checked_add(bitmap.offset as usize)?;
        let data_end = data_start.checked_add(stride.checked_mul(height.saturating_sub(1))?)?;
        let data_end = data_end.checked_add(row_bytes)?;
        if data_end > meta_size {
            return None;
        }
        let bytes = std::slice::from_raw_parts(meta_base.add(data_start), data_end - data_start);
        let mut rgba = Vec::with_capacity(width.checked_mul(height)?.checked_mul(4)?);
        for row in 0..height {
            let start = row.checked_mul(stride)?;
            let row_bytes = &bytes[start..start + row_bytes];
            for pixel in row_bytes.chunks_exact(4) {
                rgba.extend_from_slice(&cursor_pixel_as_rgba(bitmap.format, pixel)?);
            }
        }
        let png_b64 = encode_cursor_png_b64(width as u32, height as u32, &rgba)?;
        Some(CursorBitmap {
            width: width as u32,
            height: height as u32,
            hotspot_x: cursor.hotspot.x,
            hotspot_y: cursor.hotspot.y,
            png_b64,
        })
    }
}

fn cursor_pixel_as_rgba(format: spa::sys::spa_video_format, pixel: &[u8]) -> Option<[u8; 4]> {
    match format {
        x if x == spa::sys::SPA_VIDEO_FORMAT_RGBA => Some([pixel[0], pixel[1], pixel[2], pixel[3]]),
        x if x == spa::sys::SPA_VIDEO_FORMAT_BGRA => Some([pixel[2], pixel[1], pixel[0], pixel[3]]),
        x if x == spa::sys::SPA_VIDEO_FORMAT_ARGB => Some([pixel[1], pixel[2], pixel[3], pixel[0]]),
        x if x == spa::sys::SPA_VIDEO_FORMAT_ABGR => Some([pixel[3], pixel[2], pixel[1], pixel[0]]),
        x if x == spa::sys::SPA_VIDEO_FORMAT_RGBx => Some([pixel[0], pixel[1], pixel[2], 255]),
        x if x == spa::sys::SPA_VIDEO_FORMAT_BGRx => Some([pixel[2], pixel[1], pixel[0], 255]),
        x if x == spa::sys::SPA_VIDEO_FORMAT_xRGB => Some([pixel[1], pixel[2], pixel[3], 255]),
        x if x == spa::sys::SPA_VIDEO_FORMAT_xBGR => Some([pixel[3], pixel[2], pixel[1], 255]),
        _ => None,
    }
}

fn encode_cursor_png_b64(width: u32, height: u32, rgba: &[u8]) -> Option<String> {
    let mut png = Vec::new();
    PngEncoder::new(&mut png)
        .write_image(rgba, width, height, ColorType::Rgba8.into())
        .ok()?;
    Some(BASE64_STANDARD.encode(png))
}

fn log_pipewire_buffer_metas_once(
    buffer: *const spa::sys::spa_buffer,
    logged: &mut bool,
    label: &str,
) -> Option<bool> {
    if *logged || buffer.is_null() {
        return None;
    }
    *logged = true;
    let summary = pipewire_buffer_meta_summary(buffer);
    let has_cursor_meta = pipewire_buffer_has_cursor_meta(buffer);
    if has_cursor_meta {
        debug!(%label, %summary, "inspected first PipeWire buffer metadata");
    } else {
        warn!(
            %label,
            %summary,
            "first PipeWire buffer does not include SPA_META_Cursor; separate cursor overlay is unavailable until cursor metadata appears"
        );
    }
    Some(has_cursor_meta)
}

fn pipewire_buffer_has_cursor_meta(buffer: *const spa::sys::spa_buffer) -> bool {
    if buffer.is_null() {
        return false;
    }
    unsafe {
        if (*buffer).n_metas == 0 || (*buffer).metas.is_null() {
            return false;
        }
        let metas = std::slice::from_raw_parts((*buffer).metas, (*buffer).n_metas as usize);
        metas
            .iter()
            .any(|meta| meta.type_ == spa::sys::SPA_META_Cursor)
    }
}

fn pipewire_buffer_meta_summary(buffer: *const spa::sys::spa_buffer) -> String {
    if buffer.is_null() {
        return "null buffer".to_string();
    }
    unsafe {
        if (*buffer).n_metas == 0 || (*buffer).metas.is_null() {
            return format!(
                "n_metas={} metas_null={}",
                (*buffer).n_metas,
                (*buffer).metas.is_null()
            );
        }
        let metas = std::slice::from_raw_parts((*buffer).metas, (*buffer).n_metas as usize);
        metas
            .iter()
            .map(|meta| {
                format!(
                    "{}({}) size={} data_null={}",
                    pipewire_meta_type_name(meta.type_),
                    meta.type_,
                    meta.size,
                    meta.data.is_null()
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn pipewire_meta_type_name(type_: u32) -> &'static str {
    match type_ {
        x if x == spa::sys::SPA_META_Header => "Header",
        x if x == spa::sys::SPA_META_VideoCrop => "VideoCrop",
        x if x == spa::sys::SPA_META_VideoDamage => "VideoDamage",
        x if x == spa::sys::SPA_META_Bitmap => "Bitmap",
        x if x == spa::sys::SPA_META_Cursor => "Cursor",
        x if x == spa::sys::SPA_META_Control => "Control",
        x if x == spa::sys::SPA_META_Busy => "Busy",
        _ => "Unknown",
    }
}

#[derive(Clone)]
enum PipewireVideoFrame {
    Cpu(RawFrame),
    DmaBuf(DmaBufFrame),
}

impl PipewireVideoFrame {
    fn serial(&self) -> u64 {
        match self {
            Self::Cpu(frame) => frame.serial,
            Self::DmaBuf(frame) => frame.serial,
        }
    }
}

#[derive(Clone)]
struct DmaBufFrame {
    serial: u64,
    width: u32,
    height: u32,
    fd: Arc<OwnedFd>,
    release: DashFrameRelease,
    offset: usize,
    size: usize,
    stride: i32,
    drm_format: u32,
    modifier: u64,
}

struct PipewireBufferLease {
    sender: pw::channel::Sender<usize>,
    buffer: usize,
    released: AtomicBool,
}

impl PipewireBufferLease {
    fn new(sender: pw::channel::Sender<usize>, buffer: *mut pw::sys::pw_buffer) -> Self {
        Self {
            sender,
            buffer: buffer as usize,
            released: AtomicBool::new(false),
        }
    }

    fn release(&self) {
        if !self.released.swap(true, Ordering::AcqRel) {
            let _ = self.sender.send(self.buffer);
        }
    }
}

impl Drop for PipewireBufferLease {
    fn drop(&mut self) {
        self.release();
    }
}

#[derive(Clone, Copy, Debug)]
enum RawFrameFormat {
    Rgb,
    Rgba,
    Rgbx,
    Bgr,
    Bgra,
    Bgrx,
    Xrgb,
    Xbgr,
    Argb,
    Abgr,
    Yuy2,
    I420,
}

struct ScreenCastCapture {
    node_id: u32,
    width: u32,
    height: u32,
    description: String,
    remote: PipewireRemote,
    session: ScreenCastSession,
}

enum PipewireRemote {
    PortalFd(OwnedFd),
    Default,
}

impl PipewireRemote {
    fn try_clone(&self) -> Result<Self> {
        match self {
            Self::PortalFd(fd) => Ok(Self::PortalFd(fd.try_clone()?)),
            Self::Default => Ok(Self::Default),
        }
    }
}

enum ScreenCastSession {
    Portal {
        _connection: Connection,
        _session_handle: OwnedObjectPath,
        _fd: OwnedFd,
    },
    Mutter {
        _connection: Connection,
        _session_handle: OwnedObjectPath,
    },
}

async fn open_screencast_capture(
    backend: ScreenCastBackend,
    source_mode: PortalSourceMode,
    monitor_name: Option<&str>,
    cursor_preference: PortalCursorMode,
) -> Result<ScreenCastCapture> {
    match backend {
        ScreenCastBackend::Portal => open_screencast_portal(source_mode, cursor_preference).await,
        ScreenCastBackend::Mutter => {
            open_mutter_screencast(source_mode, monitor_name, cursor_preference).await
        }
    }
}

async fn open_mutter_screencast(
    source_mode: PortalSourceMode,
    monitor_name: Option<&str>,
    cursor_preference: PortalCursorMode,
) -> Result<ScreenCastCapture> {
    if source_mode != PortalSourceMode::Monitor {
        bail!("--screencast-backend mutter currently requires --portal-source monitor");
    }
    let connector = monitor_name
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .context("--screencast-backend mutter requires --monitor-name <connector>")?;
    let connection = Connection::session().await?;
    info!("connected to D-Bus session bus for Mutter ScreenCast");
    let root_proxy = Proxy::new(
        &connection,
        "org.gnome.Mutter.ScreenCast",
        "/org/gnome/Mutter/ScreenCast",
        "org.gnome.Mutter.ScreenCast",
    )
    .await?;
    let version = root_proxy.get_property::<i32>("Version").await.unwrap_or(1);
    let cursor_mode = select_mutter_cursor_mode(version, cursor_preference)?;
    let options = std::collections::HashMap::<&str, Value<'_>>::new();
    let session_handle: OwnedObjectPath = root_proxy.call("CreateSession", &(options)).await?;
    let session_proxy = Proxy::new(
        &connection,
        "org.gnome.Mutter.ScreenCast",
        session_handle.clone(),
        "org.gnome.Mutter.ScreenCast.Session",
    )
    .await?;
    let mut record_options = std::collections::HashMap::<&str, Value<'_>>::new();
    record_options.insert("cursor-mode", Value::from(cursor_mode));
    if version >= 4 {
        record_options.insert("is-recording", Value::from(true));
    }
    let stream_handle: OwnedObjectPath = session_proxy
        .call("RecordMonitor", &(connector, record_options))
        .await?;
    let stream_proxy = Proxy::new(
        &connection,
        "org.gnome.Mutter.ScreenCast",
        stream_handle,
        "org.gnome.Mutter.ScreenCast.Stream",
    )
    .await?;
    let mut signals = stream_proxy.receive_signal("PipeWireStreamAdded").await?;
    let _: () = session_proxy.call("Start", &()).await?;
    let message = timeout(Duration::from_secs(5), signals.next())
        .await
        .context("timed out waiting for Mutter PipeWireStreamAdded signal")?
        .context("Mutter ScreenCast stream closed before PipeWireStreamAdded")?;
    let (node_id,): (u32,) = message.body().deserialize()?;
    let props = stream_proxy
        .get_property::<std::collections::HashMap<String, OwnedValue>>("Parameters")
        .await
        .unwrap_or_default();
    let prop_summary = portal_prop_summary(&props);
    let (width, height) = props
        .get("size")
        .and_then(|value| value.try_clone().ok())
        .and_then(|value| <(i32, i32)>::try_from(value).ok())
        .map(|(w, h)| (w.max(1) as u32, h.max(1) as u32))
        .unwrap_or((1, 1));
    info!(
        node_id,
        connector,
        width,
        height,
        version,
        cursor_mode,
        props = %prop_summary,
        "opened Mutter ScreenCast PipeWire stream"
    );
    Ok(ScreenCastCapture {
        node_id,
        width,
        height,
        description: format!(
            "PipeWire node {node_id} via Mutter ScreenCast connector {connector} ({prop_summary})"
        ),
        remote: PipewireRemote::Default,
        session: ScreenCastSession::Mutter {
            _connection: connection,
            _session_handle: session_handle,
        },
    })
}

async fn open_screencast_portal(
    source_mode: PortalSourceMode,
    cursor_preference: PortalCursorMode,
) -> Result<ScreenCastCapture> {
    let connection = Connection::session().await?;
    info!("connected to D-Bus session bus for XDG ScreenCast portal");
    let proxy = Proxy::new(
        &connection,
        "org.freedesktop.portal.Desktop",
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.ScreenCast",
    )
    .await?;
    let available_source_types = proxy
        .get_property::<u32>("AvailableSourceTypes")
        .await
        .unwrap_or(PORTAL_SOURCE_MONITOR | PORTAL_SOURCE_WINDOW);
    let available_cursor_modes = proxy
        .get_property::<u32>("AvailableCursorModes")
        .await
        .unwrap_or(PORTAL_CURSOR_HIDDEN);
    let source_mask = source_mode.mask() & available_source_types;
    if source_mask == 0 {
        bail!(
            "portal source mode {source_mode:?} is not available; portal advertised source mask {available_source_types}"
        );
    }
    let cursor_mode = select_portal_cursor_mode(available_cursor_modes, cursor_preference)?;
    if cursor_mode == PORTAL_CURSOR_HIDDEN {
        warn!(
            available_cursor_modes,
            cursor_mode,
            cursor_preference = ?cursor_preference,
            "portal cursor mode is hidden; no Wayland cursor will be visible in frames or overlay messages"
        );
    }
    info!(
        available_source_types,
        source_mask,
        available_cursor_modes,
        cursor_mode,
        cursor_preference = ?cursor_preference,
        "XDG ScreenCast portal capabilities selected"
    );

    let session_token = portal_token("glacialcast_session");
    let session_handle = {
        let request_token = portal_token("glacialcast_request");
        let (_request_proxy, signals) =
            prepare_portal_response(&connection, &request_token).await?;
        info!("creating XDG ScreenCast portal session");
        let mut options = std::collections::HashMap::<&str, Value<'_>>::new();
        options.insert("handle_token", Value::from(request_token));
        options.insert("session_handle_token", Value::from(session_token));
        let _handle: OwnedObjectPath = proxy.call("CreateSession", &(options)).await?;
        let results = wait_portal_response(signals).await?;
        let value = results
            .get("session_handle")
            .context("CreateSession response did not include session_handle")?
            .try_clone()?;
        let session_handle: String = value.try_into()?;
        OwnedObjectPath::try_from(session_handle.as_str())
            .context("portal returned invalid session object path")?
    };

    {
        let request_token = portal_token("glacialcast_request");
        let (_request_proxy, signals) =
            prepare_portal_response(&connection, &request_token).await?;
        info!("selecting XDG ScreenCast sources; portal chooser appears during Start");
        let mut options = std::collections::HashMap::<&str, Value<'_>>::new();
        options.insert("handle_token", Value::from(request_token));
        options.insert("types", Value::from(source_mask));
        options.insert("multiple", Value::from(false));
        options.insert("cursor_mode", Value::from(cursor_mode));
        options.insert("persist_mode", Value::from(PORTAL_PERSIST_DO_NOT));
        let _handle: OwnedObjectPath = proxy
            .call("SelectSources", &(session_handle.clone(), options))
            .await?;
        let _ = wait_portal_response(signals).await?;
    }

    let results = {
        let request_token = portal_token("glacialcast_request");
        let (_request_proxy, signals) =
            prepare_portal_response(&connection, &request_token).await?;
        info!("starting XDG ScreenCast session; accept the desktop chooser to continue");
        let mut options = std::collections::HashMap::<&str, Value<'_>>::new();
        options.insert("handle_token", Value::from(request_token));
        let _handle: OwnedObjectPath = proxy
            .call("Start", &(session_handle.clone(), "", options))
            .await?;
        wait_portal_response(signals).await?
    };

    let streams_value = results
        .get("streams")
        .context("Start response did not include streams")?
        .try_clone()?;
    let streams: Vec<(u32, std::collections::HashMap<String, OwnedValue>)> =
        streams_value.try_into()?;
    let (node_id, props) = streams
        .into_iter()
        .next()
        .context("portal returned no PipeWire streams")?;
    let prop_summary = portal_prop_summary(&props);
    let (width, height) = props
        .get("size")
        .and_then(|value| value.try_clone().ok())
        .and_then(|value| <(i32, i32)>::try_from(value).ok())
        .map(|(w, h)| (w.max(1) as u32, h.max(1) as u32))
        .unwrap_or((1, 1));

    let fd: ZbusOwnedFd = proxy
        .call(
            "OpenPipeWireRemote",
            &(
                session_handle.clone(),
                std::collections::HashMap::<&str, Value<'_>>::new(),
            ),
        )
        .await?;
    let fd = OwnedFd::from(fd);
    let cursor_description = match cursor_mode {
        PORTAL_CURSOR_EMBEDDED => "embedded cursor requested",
        PORTAL_CURSOR_METADATA => "cursor metadata requested",
        _ => "cursor hidden by portal",
    };
    let description = format!(
        "PipeWire node {node_id} via raw XDG Desktop Portal ({cursor_description}; {prop_summary})"
    );
    info!(
        node_id,
        width,
        height,
        props = %prop_summary,
        "opened PipeWire remote from portal"
    );

    let remote = PipewireRemote::PortalFd(fd.try_clone()?);
    Ok(ScreenCastCapture {
        node_id,
        width,
        height,
        description,
        remote,
        session: ScreenCastSession::Portal {
            _connection: connection,
            _session_handle: session_handle,
            _fd: fd,
        },
    })
}

fn select_portal_cursor_mode(
    available_cursor_modes: u32,
    preference: PortalCursorMode,
) -> Result<u32> {
    if let Some(cursor_mode) = preference.portal_value() {
        if available_cursor_modes & cursor_mode != 0 {
            return Ok(cursor_mode);
        }
        bail!(
            "requested portal cursor mode {preference:?} is not available; portal advertised cursor mode mask {available_cursor_modes}"
        );
    }
    if available_cursor_modes & PORTAL_CURSOR_METADATA != 0 {
        Ok(PORTAL_CURSOR_METADATA)
    } else if available_cursor_modes & PORTAL_CURSOR_EMBEDDED != 0 {
        Ok(PORTAL_CURSOR_EMBEDDED)
    } else {
        Ok(PORTAL_CURSOR_HIDDEN)
    }
}

fn select_mutter_cursor_mode(version: i32, preference: PortalCursorMode) -> Result<u32> {
    if version < 2 && !matches!(preference, PortalCursorMode::Hidden) {
        bail!("Mutter ScreenCast API version {version} does not support cursor-mode metadata");
    }
    Ok(match preference {
        PortalCursorMode::Auto | PortalCursorMode::Metadata => 2,
        PortalCursorMode::Embedded => 1,
        PortalCursorMode::Hidden => 0,
    })
}

fn portal_prop_summary(props: &std::collections::HashMap<String, OwnedValue>) -> String {
    let mut entries = props
        .iter()
        .map(|(key, value)| format!("{key}={value:?}"))
        .collect::<Vec<_>>();
    entries.sort();
    entries.join(", ")
}

async fn prepare_portal_response(
    connection: &Connection,
    handle_token: &str,
) -> Result<(Proxy<'static>, SignalStream<'static>)> {
    let handle = portal_request_path(connection, handle_token)?;
    let request = Proxy::new(
        connection,
        "org.freedesktop.portal.Desktop",
        handle,
        "org.freedesktop.portal.Request",
    )
    .await?;
    let signals = request.receive_signal("Response").await?;
    Ok((request, signals))
}

async fn wait_portal_response(
    mut signals: SignalStream<'static>,
) -> Result<std::collections::HashMap<String, OwnedValue>> {
    let message = signals
        .next()
        .await
        .context("portal request closed without a Response signal")?;
    let (response, results): (u32, std::collections::HashMap<String, OwnedValue>) =
        message.body().deserialize()?;
    if response != 0 {
        bail!("portal request failed or was cancelled with response code {response}");
    }
    Ok(results)
}

fn portal_request_path(connection: &Connection, handle_token: &str) -> Result<OwnedObjectPath> {
    let unique_name = connection
        .unique_name()
        .context("D-Bus connection does not have a unique name")?;
    let sender = unique_name.trim_start_matches(':').replace('.', "_");
    let path = format!("/org/freedesktop/portal/desktop/request/{sender}/{handle_token}");
    OwnedObjectPath::try_from(path).context("failed to construct portal request object path")
}

fn portal_token(prefix: &str) -> String {
    format!("{prefix}_{}_{}", std::process::id(), now_ms())
}

struct PipewireThreadConfig {
    node_id: u32,
    width: u32,
    height: u32,
    remote: PipewireRemote,
    fps: f64,
    cursor_hz: u64,
    require_cursor_metadata: bool,
    pipewire_error: Arc<Mutex<Option<String>>>,
    mainloop_ptr_out: Arc<AtomicUsize>,
}

fn start_pipewire_thread(
    config: PipewireThreadConfig,
    latest: watch::Sender<Option<RawFrame>>,
    cursor_latest: watch::Sender<Option<PipewireCursorSample>>,
) -> Result<PipewireThreadStop> {
    let thread_error = Arc::new(Mutex::new(None::<String>));
    let thread_error_for_spawn = thread_error.clone();
    let mainloop_ptr = config.mainloop_ptr_out.clone();
    let handle = std::thread::Builder::new()
        .name("glacialcast-pipewire".to_string())
        .spawn(move || {
            if let Err(err) = run_pipewire_loop(config, latest, cursor_latest) {
                let mut slot = thread_error_for_spawn.lock().expect("error mutex poisoned");
                *slot = Some(err.to_string());
            }
        })?;
    std::thread::sleep(Duration::from_millis(25));
    let mut stop = PipewireThreadStop {
        mainloop_ptr,
        handle: Some(handle),
    };
    if let Some(err) = thread_error.lock().expect("error mutex poisoned").clone() {
        stop.stop();
        bail!("PipeWire thread failed to start: {err}");
    }
    Ok(stop)
}

fn start_pipewire_video_thread(
    config: PipewireThreadConfig,
    latest: watch::Sender<Option<PipewireVideoFrame>>,
    cursor_latest: watch::Sender<Option<PipewireCursorSample>>,
) -> Result<PipewireThreadStop> {
    let thread_error = Arc::new(Mutex::new(None::<String>));
    let thread_error_for_spawn = thread_error.clone();
    let mainloop_ptr = config.mainloop_ptr_out.clone();
    let handle = std::thread::Builder::new()
        .name("glacialcast-pipewire-video".to_string())
        .spawn(move || {
            if let Err(err) = run_pipewire_video_loop(config, latest, cursor_latest) {
                let mut slot = thread_error_for_spawn.lock().expect("error mutex poisoned");
                *slot = Some(err.to_string());
            }
        })?;
    std::thread::sleep(Duration::from_millis(25));
    let mut stop = PipewireThreadStop {
        mainloop_ptr,
        handle: Some(handle),
    };
    if let Some(err) = thread_error.lock().expect("error mutex poisoned").clone() {
        stop.stop();
        bail!("PipeWire video thread failed to start: {err}");
    }
    Ok(stop)
}

fn run_pipewire_loop(
    config: PipewireThreadConfig,
    latest: watch::Sender<Option<RawFrame>>,
    cursor_latest: watch::Sender<Option<PipewireCursorSample>>,
) -> Result<()> {
    let PipewireThreadConfig {
        node_id,
        width,
        height,
        remote,
        fps,
        cursor_hz,
        require_cursor_metadata,
        pipewire_error,
        mainloop_ptr_out,
    } = config;
    let use_target_object = matches!(&remote, PipewireRemote::PortalFd(_));
    pw::init();

    let mainloop = pw::main_loop::MainLoopBox::new(None)?;
    let context = pw::context::ContextBox::new(mainloop.loop_(), None)?;
    let core = match remote {
        PipewireRemote::PortalFd(fd) => context.connect_fd(fd, None)?,
        PipewireRemote::Default => context.connect(None)?,
    };
    let portal_target = discover_portal_target_object(&mainloop, &core, node_id)?;
    let mainloop_ptr = mainloop.as_raw_ptr() as usize;
    mainloop_ptr_out.store(mainloop_ptr, Ordering::SeqCst);
    let data = PipewireUserData {
        format: Default::default(),
        latest,
        cursor_latest,
        error: pipewire_error,
        expected_width: width,
        expected_height: height,
        min_frame_interval: Duration::from_secs_f64(1.0 / fps.clamp(0.5, 15.0)),
        min_cursor_interval: cursor_interval(cursor_hz),
        require_cursor_metadata,
        last_frame_copied_at: None,
        last_cursor_sent_at: None,
        last_cursor_state: None,
        cursor_meta_missing_since: None,
        cursor_meta_verified: false,
        mainloop_ptr,
        unmapped_buffer_logged: false,
        cursor_meta_logged: false,
        serial: 0,
        cursor_serial: 0,
    };

    let mut stream_properties = properties! {
            *pw::keys::MEDIA_TYPE => "Video",
            *pw::keys::MEDIA_CATEGORY => "Capture",
            *pw::keys::MEDIA_ROLE => "Screen",
    };
    if use_target_object && let Some(target_object) = &portal_target.target_object {
        stream_properties.insert("target.object", target_object.clone());
    }
    let stream = pw::stream::StreamBox::new(&core, "glacialcast-screen", stream_properties)?;

    let _listener = stream
        .add_local_listener_with_user_data(data)
        .state_changed(|_, user_data, old, new| {
            info!(?old, ?new, "PipeWire stream state changed");
            if let pw::stream::StreamState::Error(error) = new {
                record_pipewire_error(user_data, error);
            }
        })
        .param_changed(move |stream, user_data, id, param| {
            let Some(param) = param else {
                return;
            };
            if id != pw::spa::param::ParamType::Format.as_raw() {
                return;
            }

            let Ok((media_type, media_subtype)) = pw::spa::param::format_utils::parse_format(param)
            else {
                return;
            };
            if media_type != pw::spa::param::format::MediaType::Video
                || media_subtype != pw::spa::param::format::MediaSubtype::Raw
            {
                return;
            }

            if let Err(err) = user_data.format.parse(param) {
                warn!(?err, "failed to parse PipeWire video format");
                return;
            }
            let size = user_data.format.size();
            let framerate = user_data.format.framerate();
            if size.width != user_data.expected_width || size.height != user_data.expected_height {
                let message = format!(
                    "portal selected {}x{} node {node_id}, but PipeWire negotiated {}x{}; refusing likely wrong source",
                    user_data.expected_width, user_data.expected_height, size.width, size.height
                );
                warn!(message, "PipeWire negotiated an unexpected source size");
                record_pipewire_error(user_data, message);
                return;
            }
            let modifier = user_data.format.modifier();
            match build_buffers_param_pod(
                user_data.format.format(),
                size.width,
                size.height,
                modifier,
            ) {
                Ok(buffer_param_bytes) => {
                    update_pipewire_buffer_params_with_cursor_meta(
                        stream,
                        buffer_param_bytes,
                        "PipeWire",
                    );
                }
                Err(err) => warn!(?err, "failed to serialize PipeWire buffer params"),
            }
            if format_param_has_video_modifier(param)
                && modifier != DRM_FORMAT_MOD_LINEAR
                && modifier != DRM_FORMAT_MOD_INVALID as u64
            {
                warn!(
                    modifier,
                    "PipeWire negotiated a non-linear DMA-BUF modifier; CPU readback may require GPU import"
                );
            }
            info!(
                format = ?user_data.format.format(),
                width = size.width,
                height = size.height,
                framerate = %format!("{}/{}", framerate.num, framerate.denom),
                flags = ?user_data.format.flags(),
                modifier,
                has_modifier = format_param_has_video_modifier(param),
                "negotiated PipeWire video format"
            );
        })
        .process(move |stream, user_data| {
            let Some(mut buffer) = DequeuedPipewireBuffer::dequeue(stream) else {
                return;
            };
            let video_size = user_data.format.size();
            if video_size.width == 0 || video_size.height == 0 {
                return;
            }
            if !maybe_emit_pipewire_cursor(
                user_data,
                buffer.spa_buffer_ptr(),
                video_size.width,
                video_size.height,
            ) {
                return;
            }
            let datas = buffer.datas_mut();
            if datas.is_empty() {
                return;
            }
            let data = &mut datas[0];
            let Some(format) = raw_frame_format_for_video_format(user_data.format.format()) else {
                warn!(
                    format = ?user_data.format.format(),
                    "unsupported PipeWire video format"
                );
                return;
            };
            let (offset, chunk_size, stride) = {
                let chunk = data.chunk();
                if chunk.stride() <= 0 {
                    return;
                }
                (
                    chunk.offset() as usize,
                    chunk.size() as usize,
                    chunk.stride() as usize,
                )
            };
            let size = if chunk_size == 0 {
                let Some(size) = expected_frame_size_from_stride(
                    format,
                    stride,
                    video_size.width,
                    video_size.height,
                ) else {
                    return;
                };
                size
            } else {
                chunk_size
            };
            let data_type = data.type_();
            let data_flags = data.flags();
            let fd = data.fd();
            let map_offset = data.as_raw().mapoffset as usize;
            if data_type == spa::buffer::DataType::DmaBuf
                && user_data.format.modifier() != DRM_FORMAT_MOD_LINEAR
                && user_data.format.modifier() != DRM_FORMAT_MOD_INVALID as u64
            {
                let message = format!(
                    "PipeWire returned a DMA-BUF with non-linear modifier {} after CPU-readable PipeWire buffers were requested; this requires a real DMA-BUF media backend",
                    user_data.format.modifier()
                );
                warn!(
                    ?data_type,
                    ?data_flags,
                    fd,
                    map_offset,
                    offset,
                    size,
                    chunk_size,
                    stride,
                    %message,
                    "PipeWire did not provide CPU-readable capture data"
                );
                record_pipewire_error(user_data, message);
                return;
            }
            if data_type == spa::buffer::DataType::DmaBuf
                && !data_is_mappable(data)
                && !user_data.unmapped_buffer_logged
            {
                user_data.unmapped_buffer_logged = true;
                warn!(
                    ?data_type,
                    ?data_flags,
                    fd,
                    map_offset,
                    offset,
                    size,
                    chunk_size,
                    stride,
                    modifier = user_data.format.modifier(),
                    "PipeWire DMA-BUF is missing the mappable flag; attempting CPU mmap before falling back"
                );
            }
            let now = Instant::now();
            if let Some(last_frame_copied_at) = user_data.last_frame_copied_at
                && now.duration_since(last_frame_copied_at) < user_data.min_frame_interval
            {
                return;
            }
            user_data.last_frame_copied_at = Some(now);

            let frame_data = match data.data() {
                Some(bytes) => {
                    if offset.saturating_add(size) > bytes.len() {
                        return;
                    }
                    bytes[offset..offset + size].to_vec()
                }
                None => {
                    let Some(fd_offset) = map_offset.checked_add(offset) else {
                        return;
                    };
                    let Some(mapped) =
                        mmap_fd_slice(fd, fd_offset, size, data_type == spa::buffer::DataType::DmaBuf)
                    else {
                        let message = format!(
                            "PipeWire delivered an fd buffer that could not be read from CPU memory for node {node_id}"
                        );
                        warn!(
                            ?data_type,
                            ?data_flags,
                            fd,
                            map_offset,
                            offset,
                            size,
                            chunk_size,
                            stride,
                            modifier = user_data.format.modifier(),
                            %message
                        );
                        if data_type == spa::buffer::DataType::DmaBuf {
                            record_pipewire_error(user_data, message);
                        }
                        return;
                    };
                    if !user_data.unmapped_buffer_logged {
                        user_data.unmapped_buffer_logged = true;
                        info!(
                            ?data_type,
                            ?data_flags,
                            fd,
                            map_offset,
                            offset,
                            size,
                            stride,
                            mappable = data_is_mappable(data),
                            "PipeWire delivered an unmapped fd buffer; copied it with mmap"
                        );
                    }
                    mapped
                }
            };
            user_data.serial = user_data.serial.wrapping_add(1);
            let frame = RawFrame {
                serial: user_data.serial,
                width: video_size.width,
                height: video_size.height,
                stride,
                format,
                data: frame_data,
            };
            let _ = user_data.latest.send(Some(frame));
        })
        .register()?;

    let pipewire_fps = pipewire_capture_rate(fps, cursor_hz);
    let derived_format_pods = build_pipewire_format_pods_from_node_formats(
        &portal_target.enum_format_pods,
        pipewire_fps,
    )?;
    let format_param_bytes = if derived_format_pods.is_empty() {
        vec![build_default_pipewire_format_pod(
            width,
            height,
            pipewire_fps,
        )?]
    } else {
        info!(
            advertised_count = portal_target.enum_format_pods.len(),
            offered_count = derived_format_pods.len(),
            "using PipeWire formats derived from selected portal node"
        );
        derived_format_pods
    };
    let mut params = format_param_bytes
        .iter()
        .map(|bytes| {
            spa::pod::Pod::from_bytes(bytes).context("failed to build PipeWire format pod")
        })
        .collect::<Result<Vec<_>>>()?;

    let stream_flags = pw::stream::StreamFlags::AUTOCONNECT | pw::stream::StreamFlags::MAP_BUFFERS;
    info!(
        ?stream_flags,
        node_id,
        target_object = ?portal_target.target_object,
        pipewire_fps,
        frame_fps = fps,
        cursor_hz,
        "connecting PipeWire portal stream"
    );
    stream.connect(
        spa::utils::Direction::Input,
        if use_target_object && portal_target.target_object.is_some() {
            None
        } else {
            Some(node_id)
        },
        stream_flags,
        &mut params,
    )?;

    mainloop.run();
    mainloop_ptr_out.store(0, Ordering::SeqCst);
    Ok(())
}

fn run_pipewire_video_loop(
    config: PipewireThreadConfig,
    latest: watch::Sender<Option<PipewireVideoFrame>>,
    cursor_latest: watch::Sender<Option<PipewireCursorSample>>,
) -> Result<()> {
    let PipewireThreadConfig {
        node_id,
        width,
        height,
        remote,
        fps,
        cursor_hz,
        require_cursor_metadata,
        pipewire_error,
        mainloop_ptr_out,
    } = config;
    let use_target_object = matches!(&remote, PipewireRemote::PortalFd(_));
    pw::init();

    let mainloop = pw::main_loop::MainLoopBox::new(None)?;
    let context = pw::context::ContextBox::new(mainloop.loop_(), None)?;
    let core = match remote {
        PipewireRemote::PortalFd(fd) => context.connect_fd(fd, None)?,
        PipewireRemote::Default => context.connect(None)?,
    };
    let portal_target = discover_portal_target_object(&mainloop, &core, node_id)?;
    let mainloop_ptr = mainloop.as_raw_ptr() as usize;
    mainloop_ptr_out.store(mainloop_ptr, Ordering::SeqCst);
    let data = PipewireVideoUserData {
        format: Default::default(),
        latest,
        cursor_latest,
        error: pipewire_error,
        expected_width: width,
        expected_height: height,
        min_frame_interval: Duration::from_secs_f64(1.0 / fps.clamp(0.5, 15.0)),
        min_cursor_interval: cursor_interval(cursor_hz),
        require_cursor_metadata,
        last_frame_copied_at: None,
        last_cursor_sent_at: None,
        last_cursor_state: None,
        cursor_meta_missing_since: None,
        cursor_meta_verified: false,
        mainloop_ptr,
        first_frame_logged: false,
        cursor_meta_logged: false,
        serial: 0,
        cursor_serial: 0,
    };

    let mut stream_properties = properties! {
            *pw::keys::MEDIA_TYPE => "Video",
            *pw::keys::MEDIA_CATEGORY => "Capture",
            *pw::keys::MEDIA_ROLE => "Screen",
    };
    if use_target_object && let Some(target_object) = &portal_target.target_object {
        stream_properties.insert("target.object", target_object.clone());
    }
    let stream = pw::stream::StreamBox::new(&core, "glacialcast-screen-video", stream_properties)?;
    let (buffer_release_tx, buffer_release_rx) = pw::channel::channel::<usize>();
    let stream_ptr = stream.as_raw_ptr() as usize;
    let _buffer_release = buffer_release_rx.attach(mainloop.loop_(), move |buffer| unsafe {
        pw::sys::pw_stream_queue_buffer(
            stream_ptr as *mut pw::sys::pw_stream,
            buffer as *mut pw::sys::pw_buffer,
        );
    });
    let buffer_release_for_process = buffer_release_tx.clone();

    let _listener = stream
        .add_local_listener_with_user_data(data)
        .state_changed(|_, user_data, old, new| {
            info!(?old, ?new, "PipeWire video stream state changed");
            if let pw::stream::StreamState::Error(error) = new {
                record_pipewire_video_error(user_data, error);
            }
        })
        .param_changed(move |stream, user_data, id, param| {
            let Some(param) = param else {
                return;
            };
            if id != pw::spa::param::ParamType::Format.as_raw() {
                return;
            }

            let Ok((media_type, media_subtype)) = pw::spa::param::format_utils::parse_format(param)
            else {
                return;
            };
            if media_type != pw::spa::param::format::MediaType::Video
                || media_subtype != pw::spa::param::format::MediaSubtype::Raw
            {
                return;
            }

            if let Err(err) = user_data.format.parse(param) {
                warn!(?err, "failed to parse PipeWire video format");
                return;
            }
            let size = user_data.format.size();
            if size.width != user_data.expected_width || size.height != user_data.expected_height {
                let message = format!(
                    "portal selected {}x{} node {node_id}, but PipeWire video negotiated {}x{}; refusing likely wrong source",
                    user_data.expected_width, user_data.expected_height, size.width, size.height
                );
                warn!(message, "PipeWire video negotiated an unexpected source size");
                record_pipewire_video_error(user_data, message);
                return;
            }
            if drm_fourcc_for_video_format(user_data.format.format()).is_none() {
                let message = format!(
                    "PipeWire video negotiated unsupported DMA-BUF raw format {:?}",
                    user_data.format.format()
                );
                warn!(%message);
                record_pipewire_video_error(user_data, message);
                return;
            }
            match build_buffers_param_pod(
                user_data.format.format(),
                size.width,
                size.height,
                user_data.format.modifier(),
            ) {
                Ok(buffer_param_bytes) => {
                    update_pipewire_buffer_params_with_cursor_meta(
                        stream,
                        buffer_param_bytes,
                        "PipeWire video",
                    );
                }
                Err(err) => warn!(?err, "failed to serialize PipeWire video buffer params"),
            }
            let framerate = user_data.format.framerate();
            info!(
                format = ?user_data.format.format(),
                width = size.width,
                height = size.height,
                framerate = %format!("{}/{}", framerate.num, framerate.denom),
                flags = ?user_data.format.flags(),
                modifier = user_data.format.modifier(),
                has_modifier = format_param_has_video_modifier(param),
                "negotiated PipeWire video DMA-BUF format"
            );
        })
        .process(move |stream, user_data| {
            let Some(mut buffer) = DequeuedPipewireBuffer::dequeue(stream) else {
                return;
            };
            let video_size = user_data.format.size();
            if video_size.width == 0 || video_size.height == 0 {
                return;
            }
            if !maybe_emit_pipewire_video_cursor(
                user_data,
                buffer.spa_buffer_ptr(),
                video_size.width,
                video_size.height,
            ) {
                return;
            }
            let datas = buffer.datas_mut();
            if datas.is_empty() {
                return;
            }
            let data = &mut datas[0];
            let video_format = user_data.format.format();
            let Some(raw_format) = raw_frame_format_for_video_format(video_format) else {
                warn!(format = ?video_format, "unsupported PipeWire video format");
                return;
            };
            let Some(drm_format) = drm_fourcc_for_video_format(video_format) else {
                warn!(format = ?video_format, "unsupported PipeWire DRM video format");
                return;
            };
            let (offset, chunk_size, stride) = {
                let chunk = data.chunk();
                if chunk.stride() <= 0 {
                    return;
                }
                (
                    chunk.offset() as usize,
                    chunk.size() as usize,
                    chunk.stride() as usize,
                )
            };
            let data_type = data.type_();
            let expected_size =
                expected_frame_size_from_stride(raw_format, stride, video_size.width, video_size.height);
            let size = match (data_type, expected_size) {
                (spa::buffer::DataType::DmaBuf, Some(expected)) if chunk_size < expected => expected,
                (_, Some(expected)) if chunk_size == 0 => expected,
                _ => chunk_size,
            };
            let now = Instant::now();
            if let Some(last_frame_copied_at) = user_data.last_frame_copied_at
                && now.duration_since(last_frame_copied_at) < user_data.min_frame_interval
            {
                return;
            }
            user_data.last_frame_copied_at = Some(now);

            let fd = data.fd();
            let map_offset = data.as_raw().mapoffset as usize;
            let total_offset = match map_offset.checked_add(offset) {
                Some(offset) => offset,
                None => return,
            };
            user_data.serial = user_data.serial.wrapping_add(1);
            if data_type == spa::buffer::DataType::DmaBuf {
                let Some(owned_fd) = dup_fd(fd) else {
                    warn!(fd, "failed to duplicate PipeWire DMA-BUF fd");
                    return;
                };
                if !user_data.first_frame_logged {
                    user_data.first_frame_logged = true;
                    info!(
                        fd,
                        offset = total_offset,
                        size,
                        stride,
                        modifier = user_data.format.modifier(),
                        drm_format = drm_fourcc_name(drm_format),
                        "PipeWire video delivered DMA-BUF frame for VAAPI import"
                    );
                }
                let buffer_ptr = buffer.defer_queue();
                let lease = Arc::new(PipewireBufferLease::new(
                    buffer_release_for_process.clone(),
                    buffer_ptr,
                ));
                let release = DashFrameRelease::new({
                    let lease = Arc::clone(&lease);
                    move || lease.release()
                });
                let frame = DmaBufFrame {
                    serial: user_data.serial,
                    width: video_size.width,
                    height: video_size.height,
                    fd: Arc::new(owned_fd),
                    release,
                    offset: total_offset,
                    size,
                    stride: stride as i32,
                    drm_format,
                    modifier: user_data.format.modifier(),
                };
                let _ = user_data.latest.send(Some(PipewireVideoFrame::DmaBuf(frame)));
                return;
            }

            let frame_data = match data.data() {
                Some(bytes) => {
                    if offset.saturating_add(size) > bytes.len() {
                        return;
                    }
                    bytes[offset..offset + size].to_vec()
                }
                None => {
                    let Some(mapped) = mmap_fd_slice(fd, total_offset, size, false) else {
                        warn!(
                            ?data_type,
                            fd,
                            offset = total_offset,
                            size,
                            "PipeWire video delivered non-DMA-BUF memory that could not be read"
                        );
                        return;
                    };
                    mapped
                }
            };
            if !user_data.first_frame_logged {
                user_data.first_frame_logged = true;
                info!(
                    ?data_type,
                    offset = total_offset,
                    size,
                    stride,
                    "PipeWire video delivered CPU-readable frame"
                );
            }
            let frame = RawFrame {
                serial: user_data.serial,
                width: video_size.width,
                height: video_size.height,
                stride,
                format: raw_format,
                data: frame_data,
            };
            let _ = user_data.latest.send(Some(PipewireVideoFrame::Cpu(frame)));
        })
        .register()?;

    let pipewire_fps = pipewire_capture_rate(fps, cursor_hz);
    let format_param_bytes =
        build_pipewire_video_format_pods_from_node_formats(&portal_target.enum_format_pods)?;
    let format_param_bytes = if format_param_bytes.is_empty() {
        vec![build_default_pipewire_format_pod(
            width,
            height,
            pipewire_fps,
        )?]
    } else {
        info!(
            advertised_count = portal_target.enum_format_pods.len(),
            offered_count = format_param_bytes.len(),
            "using PipeWire DMA-BUF formats from selected portal node"
        );
        format_param_bytes
    };
    let mut params = format_param_bytes
        .iter()
        .map(|bytes| {
            spa::pod::Pod::from_bytes(bytes).context("failed to build PipeWire video format pod")
        })
        .collect::<Result<Vec<_>>>()?;

    let stream_flags = pw::stream::StreamFlags::AUTOCONNECT;
    info!(
        ?stream_flags,
        node_id,
        target_object = ?portal_target.target_object,
        pipewire_fps,
        frame_fps = fps,
        cursor_hz,
        "connecting PipeWire portal video stream"
    );
    stream.connect(
        spa::utils::Direction::Input,
        if use_target_object && portal_target.target_object.is_some() {
            None
        } else {
            Some(node_id)
        },
        stream_flags,
        &mut params,
    )?;

    mainloop.run();
    mainloop_ptr_out.store(0, Ordering::SeqCst);
    Ok(())
}

fn build_pipewire_format_pods_from_node_formats(
    advertised_pods: &[Vec<u8>],
    fps: f64,
) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut cpu_count = 0usize;
    let mut skipped_modifier_count = 0usize;
    for bytes in advertised_pods {
        let Some(pod) = spa::pod::Pod::from_bytes(bytes) else {
            continue;
        };
        let Ok((media_type, media_subtype)) = spa::param::format_utils::parse_format(pod) else {
            continue;
        };
        if media_type != spa::param::format::MediaType::Video
            || media_subtype != spa::param::format::MediaSubtype::Raw
        {
            continue;
        }
        let mut info = spa::param::video::VideoInfoRaw::new();
        if info.parse(pod).is_err() {
            continue;
        }
        let format = info.format();
        if raw_frame_format_for_video_format(format).is_none() {
            warn!(?format, "skipping unsupported PipeWire video format");
            continue;
        }
        let size = info.size();
        if size.width == 0 || size.height == 0 {
            continue;
        }
        let modifier = if format_param_has_video_modifier(pod) {
            match preferred_cpu_readable_modifier(pod) {
                Some(modifier) => Some(modifier),
                None => {
                    skipped_modifier_count += 1;
                    warn!(
                        format = ?format,
                        "skipping PipeWire format because its advertised modifiers are not CPU-readable"
                    );
                    continue;
                }
            }
        } else {
            None
        };
        if modifier == Some(DRM_FORMAT_MOD_INVALID as u64) {
            out.push(build_exact_cpu_pipewire_format_pod(
                format,
                size.width,
                size.height,
                fps,
                None,
            )?);
            cpu_count += 1;
        }
        out.push(build_exact_cpu_pipewire_format_pod(
            format,
            size.width,
            size.height,
            fps,
            modifier,
        )?);
        cpu_count += 1;
    }
    if !out.is_empty() {
        info!(
            cpu_count,
            skipped_modifier_count, "prepared PipeWire format offers from selected portal node"
        );
    }
    Ok(out)
}

fn build_pipewire_video_format_pods_from_node_formats(
    advertised_pods: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for bytes in advertised_pods {
        let Some(pod) = spa::pod::Pod::from_bytes(bytes) else {
            continue;
        };
        let Ok((media_type, media_subtype)) = spa::param::format_utils::parse_format(pod) else {
            continue;
        };
        if media_type != spa::param::format::MediaType::Video
            || media_subtype != spa::param::format::MediaSubtype::Raw
        {
            continue;
        }
        let mut info = spa::param::video::VideoInfoRaw::new();
        if info.parse(pod).is_err() {
            continue;
        }
        if drm_fourcc_for_video_format(info.format()).is_none() {
            warn!(
                format = ?info.format(),
                "skipping PipeWire format that cannot be represented as DRM PRIME"
            );
            continue;
        }
        out.push(bytes.clone());
    }
    Ok(out)
}

fn build_exact_cpu_pipewire_format_pod(
    format: spa::param::video::VideoFormat,
    width: u32,
    height: u32,
    fps: f64,
    modifier: Option<u64>,
) -> Result<Vec<u8>> {
    let fps = fps_fraction(fps);
    let mut obj = pw::spa::pod::object!(
        pw::spa::utils::SpaTypes::ObjectParamFormat,
        pw::spa::param::ParamType::EnumFormat,
        pw::spa::pod::property!(
            pw::spa::param::format::FormatProperties::MediaType,
            Id,
            pw::spa::param::format::MediaType::Video
        ),
        pw::spa::pod::property!(
            pw::spa::param::format::FormatProperties::MediaSubtype,
            Id,
            pw::spa::param::format::MediaSubtype::Raw
        ),
        pw::spa::pod::property!(
            pw::spa::param::format::FormatProperties::VideoFormat,
            Id,
            format
        ),
        pw::spa::pod::property!(
            pw::spa::param::format::FormatProperties::VideoSize,
            Rectangle,
            pw::spa::utils::Rectangle {
                width: width.max(1),
                height: height.max(1)
            }
        ),
        pw::spa::pod::property!(
            pw::spa::param::format::FormatProperties::VideoFramerate,
            Choice,
            Range,
            Fraction,
            fps,
            pw::spa::utils::Fraction { num: 0, denom: 1 },
            pw::spa::utils::Fraction { num: 240, denom: 1 }
        ),
    );
    if let Some(modifier) = modifier {
        let mut prop = spa::pod::Property::new(
            spa::param::format::FormatProperties::VideoModifier.as_raw(),
            spa::pod::Value::Choice(spa::pod::ChoiceValue::Long(spa::utils::Choice(
                spa::utils::ChoiceFlags::empty(),
                spa::utils::ChoiceEnum::Enum {
                    default: modifier as i64,
                    alternatives: vec![modifier as i64],
                },
            ))),
        );
        prop.flags = spa::pod::PropertyFlags::MANDATORY;
        obj.properties.push(prop);
    }
    serialize_pod_object(obj)
}

fn build_default_pipewire_format_pod(width: u32, height: u32, fps: f64) -> Result<Vec<u8>> {
    let fps = fps_fraction(fps);
    let obj = pw::spa::pod::object!(
        pw::spa::utils::SpaTypes::ObjectParamFormat,
        pw::spa::param::ParamType::EnumFormat,
        pw::spa::pod::property!(
            pw::spa::param::format::FormatProperties::MediaType,
            Id,
            pw::spa::param::format::MediaType::Video
        ),
        pw::spa::pod::property!(
            pw::spa::param::format::FormatProperties::MediaSubtype,
            Id,
            pw::spa::param::format::MediaSubtype::Raw
        ),
        pw::spa::pod::property!(
            pw::spa::param::format::FormatProperties::VideoFormat,
            Choice,
            Enum,
            Id,
            pw::spa::param::video::VideoFormat::RGB,
            pw::spa::param::video::VideoFormat::RGB,
            pw::spa::param::video::VideoFormat::BGR,
            pw::spa::param::video::VideoFormat::RGBA,
            pw::spa::param::video::VideoFormat::BGRA,
            pw::spa::param::video::VideoFormat::RGBx,
            pw::spa::param::video::VideoFormat::BGRx,
            pw::spa::param::video::VideoFormat::xRGB,
            pw::spa::param::video::VideoFormat::xBGR,
            pw::spa::param::video::VideoFormat::ARGB,
            pw::spa::param::video::VideoFormat::ABGR,
            pw::spa::param::video::VideoFormat::YUY2,
            pw::spa::param::video::VideoFormat::I420,
        ),
        pw::spa::pod::property!(
            pw::spa::param::format::FormatProperties::VideoSize,
            Choice,
            Range,
            Rectangle,
            pw::spa::utils::Rectangle {
                width: width.max(1),
                height: height.max(1)
            },
            pw::spa::utils::Rectangle {
                width: 1,
                height: 1
            },
            pw::spa::utils::Rectangle {
                width: 16384,
                height: 16384
            }
        ),
        pw::spa::pod::property!(
            pw::spa::param::format::FormatProperties::VideoFramerate,
            Choice,
            Range,
            Fraction,
            fps,
            pw::spa::utils::Fraction { num: 0, denom: 1 },
            pw::spa::utils::Fraction { num: 240, denom: 1 }
        ),
    );
    serialize_pod_object(obj)
}

fn fps_fraction(fps: f64) -> pw::spa::utils::Fraction {
    let denominator = 1000u32;
    let numerator = (fps.clamp(0.5, 60.0) * f64::from(denominator))
        .round()
        .max(1.0) as u32;
    let divisor = gcd(numerator, denominator).max(1);
    pw::spa::utils::Fraction {
        num: numerator / divisor,
        denom: denominator / divisor,
    }
}

fn gcd(mut a: u32, mut b: u32) -> u32 {
    while b != 0 {
        let next = a % b;
        a = b;
        b = next;
    }
    a
}

fn pipewire_capture_rate(frame_fps: f64, cursor_hz: u64) -> f64 {
    frame_fps.max(cursor_hz.max(1) as f64).clamp(0.5, 60.0)
}

fn cursor_interval(cursor_hz: u64) -> Duration {
    Duration::from_secs_f64(1.0 / cursor_hz.max(1) as f64)
}

fn serialize_pod_object(obj: spa::pod::Object) -> Result<Vec<u8>> {
    Ok(pw::spa::pod::serialize::PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &pw::spa::pod::Value::Object(obj),
    )?
    .0
    .into_inner())
}

fn update_pipewire_buffer_params_with_cursor_meta(
    stream: &pw::stream::Stream,
    buffer_param_bytes: Vec<u8>,
    label: &str,
) {
    let mut param_bytes = vec![buffer_param_bytes];
    match build_pipewire_cursor_meta_param_pod() {
        Ok(bytes) => param_bytes.push(bytes),
        Err(err) => warn!(?err, %label, "failed to serialize PipeWire cursor metadata params"),
    }
    let mut params = Vec::with_capacity(param_bytes.len());
    for bytes in &param_bytes {
        if let Some(param) = spa::pod::Pod::from_bytes(bytes) {
            params.push(param);
        } else {
            warn!(%label, "failed to build PipeWire update params pod");
        }
    }
    if let Err(err) = stream.update_params(&mut params) {
        warn!(?err, %label, "failed to update PipeWire buffer params");
    }
}

fn build_pipewire_cursor_meta_param_pod() -> Result<Vec<u8>> {
    let obj = spa::pod::Object {
        type_: spa::utils::SpaTypes::ObjectParamMeta.as_raw(),
        id: spa::param::ParamType::Meta.as_raw(),
        properties: vec![
            spa::pod::Property::new(
                spa::sys::SPA_PARAM_META_type,
                spa::pod::Value::Id(spa::utils::Id(spa::sys::SPA_META_Cursor)),
            ),
            spa::pod::Property::new(
                spa::sys::SPA_PARAM_META_size,
                spa::pod::Value::Int(pipewire_cursor_meta_size(
                    PIPEWIRE_CURSOR_DEFAULT_BITMAP_SIDE,
                )),
            ),
        ],
    };
    serialize_pod_object(obj)
}

fn pipewire_cursor_meta_size(bitmap_side: usize) -> i32 {
    std::mem::size_of::<spa::sys::spa_meta_cursor>()
        .saturating_add(std::mem::size_of::<spa::sys::spa_meta_bitmap>())
        .saturating_add(bitmap_side.saturating_mul(bitmap_side).saturating_mul(4))
        .min(i32::MAX as usize) as i32
}

fn format_param_has_video_modifier(param: &spa::pod::Pod) -> bool {
    let Ok(object) = <&spa::pod::PodObject>::try_from(param) else {
        return false;
    };
    object
        .find_prop(spa::utils::Id(
            spa::param::format::FormatProperties::VideoModifier.as_raw(),
        ))
        .is_some()
}

fn preferred_cpu_readable_modifier(param: &spa::pod::Pod) -> Option<u64> {
    let modifiers = video_modifier_values(param);
    if modifiers.contains(&DRM_FORMAT_MOD_LINEAR) {
        Some(DRM_FORMAT_MOD_LINEAR)
    } else if modifiers.contains(&(DRM_FORMAT_MOD_INVALID as u64)) {
        Some(DRM_FORMAT_MOD_INVALID as u64)
    } else {
        None
    }
}

fn video_modifier_values(param: &spa::pod::Pod) -> Vec<u64> {
    let Ok(object) = <&spa::pod::PodObject>::try_from(param) else {
        return Vec::new();
    };
    let Some(prop) = object.find_prop(spa::utils::Id(
        spa::param::format::FormatProperties::VideoModifier.as_raw(),
    )) else {
        return Vec::new();
    };
    let Ok((_, value)) = spa::pod::deserialize::PodDeserializer::deserialize_from::<spa::pod::Value>(
        prop.value().as_bytes(),
    ) else {
        return Vec::new();
    };
    modifier_values_from_pod_value(value)
}

fn modifier_values_from_pod_value(value: spa::pod::Value) -> Vec<u64> {
    match value {
        spa::pod::Value::Long(value) => vec![value as u64],
        spa::pod::Value::Choice(spa::pod::ChoiceValue::Long(choice)) => {
            modifier_values_from_choice(choice.1)
        }
        _ => Vec::new(),
    }
}

fn modifier_values_from_choice(choice: spa::utils::ChoiceEnum<i64>) -> Vec<u64> {
    match choice {
        spa::utils::ChoiceEnum::None(value) => vec![value as u64],
        spa::utils::ChoiceEnum::Range { default, min, max } => {
            vec![default as u64, min as u64, max as u64]
        }
        spa::utils::ChoiceEnum::Step {
            default, min, max, ..
        } => vec![default as u64, min as u64, max as u64],
        spa::utils::ChoiceEnum::Enum {
            default,
            mut alternatives,
        } => {
            alternatives.push(default);
            alternatives.into_iter().map(|value| value as u64).collect()
        }
        spa::utils::ChoiceEnum::Flags { default, mut flags } => {
            flags.push(default);
            flags.into_iter().map(|value| value as u64).collect()
        }
    }
}

fn build_buffers_param_pod(
    format: spa::param::video::VideoFormat,
    width: u32,
    height: u32,
    modifier: u64,
) -> Result<Vec<u8>> {
    const PARAM_BUFFERS_BUFFERS: u32 = 1;
    const PARAM_BUFFERS_BLOCKS: u32 = 2;
    const PARAM_BUFFERS_SIZE: u32 = 3;
    const PARAM_BUFFERS_STRIDE: u32 = 4;
    const PARAM_BUFFERS_ALIGN: u32 = 5;
    const PARAM_BUFFERS_DATA_TYPE: u32 = 6;

    let stride = expected_frame_stride(format, width).unwrap_or_else(|| width.saturating_mul(4));
    let size = expected_frame_size(format, width, height).unwrap_or_else(|| {
        stride
            .max(1)
            .saturating_mul(height.max(1))
            .min(i32::MAX as u32)
    });
    let memfd_mask = 1 << spa::buffer::DataType::MemFd.as_raw();
    let memptr_mask = 1 << spa::buffer::DataType::MemPtr.as_raw();
    let dmabuf_mask = 1 << spa::buffer::DataType::DmaBuf.as_raw();
    let requires_dmabuf =
        modifier != DRM_FORMAT_MOD_LINEAR && modifier != DRM_FORMAT_MOD_INVALID as u64;
    let implicit_modifier = modifier == DRM_FORMAT_MOD_INVALID as u64;
    let (default_data_type, data_type_flags) = if requires_dmabuf || implicit_modifier {
        (dmabuf_mask, vec![dmabuf_mask])
    } else {
        (memfd_mask, vec![memfd_mask, memptr_mask, dmabuf_mask])
    };
    let obj = spa::pod::Object {
        type_: spa::utils::SpaTypes::ObjectParamBuffers.as_raw(),
        id: spa::param::ParamType::Buffers.as_raw(),
        properties: vec![
            spa::pod::Property::new(
                PARAM_BUFFERS_BUFFERS,
                spa::pod::Value::Choice(spa::pod::ChoiceValue::Int(spa::utils::Choice(
                    spa::utils::ChoiceFlags::empty(),
                    spa::utils::ChoiceEnum::Range {
                        default: 8,
                        min: 2,
                        max: 16,
                    },
                ))),
            ),
            spa::pod::Property::new(PARAM_BUFFERS_BLOCKS, spa::pod::Value::Int(1)),
            spa::pod::Property::new(PARAM_BUFFERS_SIZE, spa::pod::Value::Int(size as i32)),
            spa::pod::Property::new(PARAM_BUFFERS_STRIDE, spa::pod::Value::Int(stride as i32)),
            spa::pod::Property::new(PARAM_BUFFERS_ALIGN, spa::pod::Value::Int(16)),
            spa::pod::Property::new(
                PARAM_BUFFERS_DATA_TYPE,
                spa::pod::Value::Choice(spa::pod::ChoiceValue::Int(spa::utils::Choice(
                    spa::utils::ChoiceFlags::empty(),
                    spa::utils::ChoiceEnum::Flags {
                        default: default_data_type,
                        flags: data_type_flags,
                    },
                ))),
            ),
        ],
    };
    serialize_pod_object(obj)
}

#[repr(C)]
struct DmaBufSync {
    flags: u64,
}

fn mmap_fd_slice(fd: RawFd, offset: usize, size: usize, sync_dmabuf: bool) -> Option<Vec<u8>> {
    if fd < 0 {
        return None;
    }
    if size == 0 {
        return Some(Vec::new());
    }
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page_size = if page_size > 0 {
        page_size as usize
    } else {
        4096
    };
    let aligned_offset = offset - (offset % page_size);
    let delta = offset - aligned_offset;
    let map_len = delta.checked_add(size)?;
    let map_offset = libc::off_t::try_from(aligned_offset).ok()?;
    if sync_dmabuf {
        sync_dmabuf_read(fd, false);
    }
    let ptr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            map_len,
            libc::PROT_READ,
            libc::MAP_SHARED,
            fd,
            map_offset,
        )
    };
    if ptr == libc::MAP_FAILED {
        if sync_dmabuf {
            sync_dmabuf_read(fd, true);
        }
        return None;
    }
    let out = unsafe { std::slice::from_raw_parts((ptr as *const u8).add(delta), size).to_vec() };
    let _ = unsafe { libc::munmap(ptr, map_len) };
    if sync_dmabuf {
        sync_dmabuf_read(fd, true);
    }
    Some(out)
}

fn dup_fd(fd: RawFd) -> Option<OwnedFd> {
    if fd < 0 {
        return None;
    }
    let duplicated = unsafe { libc::dup(fd) };
    if duplicated < 0 {
        return None;
    }
    Some(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

fn sync_dmabuf_read(fd: RawFd, end: bool) {
    let flags = DMA_BUF_SYNC_READ | if end { DMA_BUF_SYNC_END } else { 0 };
    let sync = DmaBufSync { flags };
    let _ = unsafe { libc::ioctl(fd, DMA_BUF_IOCTL_SYNC, &sync) };
}

fn data_is_mappable(data: &spa::buffer::Data) -> bool {
    data.as_raw().flags & SPA_DATA_FLAG_MAPPABLE != 0
}

fn expected_frame_stride(format: spa::param::video::VideoFormat, width: u32) -> Option<u32> {
    let bytes_per_pixel = match raw_frame_format_for_video_format(format)? {
        RawFrameFormat::Rgb | RawFrameFormat::Bgr => 3,
        RawFrameFormat::Rgba
        | RawFrameFormat::Rgbx
        | RawFrameFormat::Bgra
        | RawFrameFormat::Bgrx
        | RawFrameFormat::Xrgb
        | RawFrameFormat::Xbgr
        | RawFrameFormat::Argb
        | RawFrameFormat::Abgr => 4,
        RawFrameFormat::Yuy2 => 2,
        RawFrameFormat::I420 => 1,
    };
    width.checked_mul(bytes_per_pixel)
}

fn expected_frame_size(
    format: spa::param::video::VideoFormat,
    width: u32,
    height: u32,
) -> Option<u32> {
    match raw_frame_format_for_video_format(format)? {
        RawFrameFormat::I420 => width.checked_mul(height)?.checked_mul(3)?.checked_div(2),
        _ => expected_frame_stride(format, width)?.checked_mul(height),
    }
}

fn expected_frame_size_from_stride(
    format: RawFrameFormat,
    stride: usize,
    width: u32,
    height: u32,
) -> Option<usize> {
    let width = width as usize;
    let height = height as usize;
    match format {
        RawFrameFormat::I420 => {
            let y_size = stride.checked_mul(height)?;
            let uv_stride = stride.div_ceil(2).max(width.div_ceil(2));
            y_size.checked_add(uv_stride.checked_mul(height.div_ceil(2))?.checked_mul(2)?)
        }
        _ => stride.checked_mul(height),
    }
}

fn discover_portal_target_object(
    mainloop: &pw::main_loop::MainLoop,
    core: &pw::core::Core,
    node_id: u32,
) -> Result<PipewirePortalTarget> {
    let registry = core.get_registry()?;
    let done = Arc::new(AtomicBool::new(false));
    let visible_nodes = Arc::new(Mutex::new(Vec::<PipewireNodeGlobal>::new()));
    let pending = core.sync(0)?;
    let mainloop_ptr = mainloop.as_raw_ptr() as usize;

    let done_for_listener = done.clone();
    let _core_listener = core
        .add_listener_local()
        .done(move |id, seq| {
            if id == pw::core::PW_ID_CORE && seq == pending {
                done_for_listener.store(true, Ordering::SeqCst);
                unsafe {
                    pw::sys::pw_main_loop_quit(mainloop_ptr as *mut _);
                }
            }
        })
        .register();

    let visible_nodes_for_listener = visible_nodes.clone();
    let _registry_listener = registry
        .add_listener_local()
        .global(move |global| {
            if global.type_ != pw::types::ObjectType::Node {
                return;
            }
            let props = global
                .props
                .as_ref()
                .map(|props| {
                    props
                        .as_ref()
                        .iter()
                        .map(|(key, value)| (key.to_string(), value.to_string()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            info!(
                global_id = global.id,
                props = %format_prop_pairs(&props),
                "PipeWire portal remote node visible"
            );
            visible_nodes_for_listener
                .lock()
                .expect("PipeWire node list mutex poisoned")
                .push(PipewireNodeGlobal {
                    id: global.id,
                    permissions: global.permissions,
                    version: global.version,
                    props,
                });
        })
        .register();

    while !done.load(Ordering::SeqCst) {
        mainloop.run();
    }

    let nodes = visible_nodes
        .lock()
        .expect("PipeWire node list mutex poisoned");
    let selected = nodes
        .iter()
        .find(|node| node.id == node_id)
        .or_else(|| (nodes.len() == 1).then_some(&nodes[0]))
        .cloned();
    drop(nodes);
    let Some(selected) = selected else {
        warn!(
            node_id,
            "portal PipeWire remote did not expose the returned node id"
        );
        return Ok(PipewirePortalTarget::default());
    };
    let target = prop_value(&selected.props, "object.serial")
        .or_else(|| prop_value(&selected.props, "node.name"))
        .or_else(|| prop_value(&selected.props, "object.path"))
        .map(str::to_string);
    info!(
        node_id,
        selected_global_id = selected.id,
        target_object = ?target,
        "selected PipeWire portal target"
    );
    let enum_format_pods = enumerate_node_enum_formats(mainloop, core, &registry, &selected)?;
    Ok(PipewirePortalTarget {
        target_object: target,
        enum_format_pods,
    })
}

#[derive(Default)]
struct PipewirePortalTarget {
    target_object: Option<String>,
    enum_format_pods: Vec<Vec<u8>>,
}

#[derive(Clone)]
struct PipewireNodeGlobal {
    id: u32,
    permissions: pw::permissions::PermissionFlags,
    version: u32,
    props: Vec<(String, String)>,
}

fn enumerate_node_enum_formats(
    mainloop: &pw::main_loop::MainLoop,
    core: &pw::core::Core,
    registry: &pw::registry::Registry,
    selected: &PipewireNodeGlobal,
) -> Result<Vec<Vec<u8>>> {
    let global = pw::registry::GlobalObject::<pw::properties::PropertiesBox> {
        id: selected.id,
        permissions: selected.permissions,
        type_: pw::types::ObjectType::Node,
        version: selected.version,
        props: None,
    };
    let node: pw::node::Node = registry.bind(&global)?;
    let enum_format_pods = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let enum_format_pods_for_listener = enum_format_pods.clone();
    let _node_listener = node
        .add_listener_local()
        .param(move |_seq, id, index, next, param| {
            let Some(param) = param else {
                return;
            };
            if id != spa::param::ParamType::EnumFormat {
                return;
            }
            info!(
                index,
                next,
                summary = %describe_format_param(param),
                "selected PipeWire node advertised EnumFormat"
            );
            enum_format_pods_for_listener
                .lock()
                .expect("PipeWire EnumFormat mutex poisoned")
                .push(param.as_bytes().to_vec());
        })
        .register();

    node.enum_params(77, Some(spa::param::ParamType::EnumFormat), 0, u32::MAX);
    let done = Arc::new(AtomicBool::new(false));
    let pending = core.sync(0)?;
    let mainloop_ptr = mainloop.as_raw_ptr() as usize;
    let done_for_listener = done.clone();
    let _core_listener = core
        .add_listener_local()
        .done(move |id, seq| {
            if id == pw::core::PW_ID_CORE && seq == pending {
                done_for_listener.store(true, Ordering::SeqCst);
                unsafe {
                    pw::sys::pw_main_loop_quit(mainloop_ptr as *mut _);
                }
            }
        })
        .register();

    while !done.load(Ordering::SeqCst) {
        mainloop.run();
    }

    let enum_format_pods = enum_format_pods
        .lock()
        .expect("PipeWire EnumFormat mutex poisoned")
        .clone();
    if enum_format_pods.is_empty() {
        warn!(
            node_id = selected.id,
            "selected PipeWire node did not advertise EnumFormat params"
        );
    }
    Ok(enum_format_pods)
}

fn describe_format_param(param: &spa::pod::Pod) -> String {
    let mut parts = Vec::new();
    if let Ok((media_type, media_subtype)) = spa::param::format_utils::parse_format(param) {
        parts.push(format!("media={media_type:?}/{media_subtype:?}"));
        if media_type == spa::param::format::MediaType::Video
            && media_subtype == spa::param::format::MediaSubtype::Raw
        {
            let mut info = spa::param::video::VideoInfoRaw::new();
            if info.parse(param).is_ok() {
                let size = info.size();
                let framerate = info.framerate();
                parts.push(format!(
                    "raw={:?} {}x{} {}/{}",
                    info.format(),
                    size.width,
                    size.height,
                    framerate.num,
                    framerate.denom
                ));
            }
        }
    }

    if let Ok(object) = <&spa::pod::PodObject>::try_from(param) {
        let props = object
            .props()
            .map(|prop| {
                let key = format_property_key(prop.key());
                let value = describe_pod_value(prop.value());
                let flags = prop.flags();
                if flags.is_empty() {
                    format!("{key}:{value}")
                } else {
                    format!("{key}({flags:?}):{value}")
                }
            })
            .collect::<Vec<_>>();
        if !props.is_empty() {
            parts.push(format!("props=[{}]", props.join(", ")));
        }
    }

    if parts.is_empty() {
        format!(
            "pod_type={:?} bytes={}",
            param.type_(),
            param.as_bytes().len()
        )
    } else {
        parts.join("; ")
    }
}

fn format_property_key(key: spa::utils::Id) -> String {
    let raw = key.0;
    if raw == spa::param::format::FormatProperties::MediaType.as_raw() {
        "mediaType".to_string()
    } else if raw == spa::param::format::FormatProperties::MediaSubtype.as_raw() {
        "mediaSubtype".to_string()
    } else if raw == spa::param::format::FormatProperties::VideoFormat.as_raw() {
        "videoFormat".to_string()
    } else if raw == spa::param::format::FormatProperties::VideoModifier.as_raw() {
        "videoModifier".to_string()
    } else if raw == spa::param::format::FormatProperties::VideoSize.as_raw() {
        "videoSize".to_string()
    } else if raw == spa::param::format::FormatProperties::VideoFramerate.as_raw() {
        "videoFramerate".to_string()
    } else if raw == spa::param::format::FormatProperties::VideoMaxFramerate.as_raw() {
        "videoMaxFramerate".to_string()
    } else {
        raw.to_string()
    }
}

fn describe_pod_value(pod: &spa::pod::Pod) -> String {
    match spa::pod::deserialize::PodDeserializer::deserialize_from::<spa::pod::Value>(
        pod.as_bytes(),
    ) {
        Ok((_, value)) => format!("{value:?}"),
        Err(_) => format!("{:?}/{} bytes", pod.type_(), pod.as_bytes().len()),
    }
}

fn prop_value<'a>(props: &'a [(String, String)], key: &str) -> Option<&'a str> {
    props
        .iter()
        .find_map(|(candidate, value)| (candidate == key).then_some(value.as_str()))
}

fn format_prop_pairs(props: &[(String, String)]) -> String {
    let mut entries = props
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>();
    entries.sort();
    entries.join(", ")
}

struct PipewireUserData {
    format: spa::param::video::VideoInfoRaw,
    latest: watch::Sender<Option<RawFrame>>,
    cursor_latest: watch::Sender<Option<PipewireCursorSample>>,
    error: Arc<Mutex<Option<String>>>,
    expected_width: u32,
    expected_height: u32,
    min_frame_interval: Duration,
    min_cursor_interval: Duration,
    require_cursor_metadata: bool,
    last_frame_copied_at: Option<Instant>,
    last_cursor_sent_at: Option<Instant>,
    last_cursor_state: Option<PipewireCursorState>,
    cursor_meta_missing_since: Option<Instant>,
    cursor_meta_verified: bool,
    mainloop_ptr: usize,
    unmapped_buffer_logged: bool,
    cursor_meta_logged: bool,
    serial: u64,
    cursor_serial: u64,
}

struct PipewireVideoUserData {
    format: spa::param::video::VideoInfoRaw,
    latest: watch::Sender<Option<PipewireVideoFrame>>,
    cursor_latest: watch::Sender<Option<PipewireCursorSample>>,
    error: Arc<Mutex<Option<String>>>,
    expected_width: u32,
    expected_height: u32,
    min_frame_interval: Duration,
    min_cursor_interval: Duration,
    require_cursor_metadata: bool,
    last_frame_copied_at: Option<Instant>,
    last_cursor_sent_at: Option<Instant>,
    last_cursor_state: Option<PipewireCursorState>,
    cursor_meta_missing_since: Option<Instant>,
    cursor_meta_verified: bool,
    mainloop_ptr: usize,
    first_frame_logged: bool,
    cursor_meta_logged: bool,
    serial: u64,
    cursor_serial: u64,
}

fn record_pipewire_error(user_data: &PipewireUserData, message: String) {
    let mut slot = user_data
        .error
        .lock()
        .expect("PipeWire error mutex poisoned");
    *slot = Some(message);
    unsafe {
        pw::sys::pw_main_loop_quit(user_data.mainloop_ptr as *mut _);
    }
}

fn record_pipewire_video_error(user_data: &PipewireVideoUserData, message: String) {
    let mut slot = user_data
        .error
        .lock()
        .expect("PipeWire error mutex poisoned");
    *slot = Some(message);
    unsafe {
        pw::sys::pw_main_loop_quit(user_data.mainloop_ptr as *mut _);
    }
}

fn raw_frame_to_rgb_image(frame: &RawFrame) -> Result<ImageBuffer<Rgb<u8>, Vec<u8>>> {
    let mut image = ImageBuffer::<Rgb<u8>, Vec<u8>>::new(frame.width, frame.height);
    for y in 0..frame.height as usize {
        for x in 0..frame.width as usize {
            if let Some(rgb) = raw_pixel_rgb(frame, x, y) {
                image.put_pixel(x as u32, y as u32, Rgb(rgb));
            }
        }
    }
    Ok(image)
}

fn resize_rgb_image_to_fit(
    image: ImageBuffer<Rgb<u8>, Vec<u8>>,
    max_width: u32,
    max_height: u32,
) -> ImageBuffer<Rgb<u8>, Vec<u8>> {
    let max_width = max_width.max(1);
    let max_height = max_height.max(1);
    if image.width() <= max_width && image.height() <= max_height {
        return image;
    }
    let width_ratio = max_width as f32 / image.width().max(1) as f32;
    let height_ratio = max_height as f32 / image.height().max(1) as f32;
    let scale = width_ratio.min(height_ratio).min(1.0);
    let target_width = ((image.width() as f32 * scale).round() as u32).max(1);
    let target_height = ((image.height() as f32 * scale).round() as u32).max(1);
    image::imageops::resize(&image, target_width, target_height, FilterType::Triangle)
}

fn raw_pixel_rgb(frame: &RawFrame, x: usize, y: usize) -> Option<[u8; 3]> {
    match frame.format {
        RawFrameFormat::Rgb => packed_rgb(&frame.data, y, frame.stride, x, 3, [0, 1, 2]),
        RawFrameFormat::Bgr => packed_rgb(&frame.data, y, frame.stride, x, 3, [2, 1, 0]),
        RawFrameFormat::Rgba | RawFrameFormat::Rgbx => {
            packed_rgb(&frame.data, y, frame.stride, x, 4, [0, 1, 2])
        }
        RawFrameFormat::Bgra | RawFrameFormat::Bgrx => {
            packed_rgb(&frame.data, y, frame.stride, x, 4, [2, 1, 0])
        }
        RawFrameFormat::Xrgb | RawFrameFormat::Argb => {
            packed_rgb(&frame.data, y, frame.stride, x, 4, [1, 2, 3])
        }
        RawFrameFormat::Xbgr | RawFrameFormat::Abgr => {
            packed_rgb(&frame.data, y, frame.stride, x, 4, [3, 2, 1])
        }
        RawFrameFormat::Yuy2 => yuy2_rgb(frame, x, y),
        RawFrameFormat::I420 => i420_rgb(frame, x, y),
    }
}

fn raw_frame_format_for_video_format(
    format: spa::param::video::VideoFormat,
) -> Option<RawFrameFormat> {
    match format {
        spa::param::video::VideoFormat::RGB => Some(RawFrameFormat::Rgb),
        spa::param::video::VideoFormat::BGR => Some(RawFrameFormat::Bgr),
        spa::param::video::VideoFormat::RGBA => Some(RawFrameFormat::Rgba),
        spa::param::video::VideoFormat::BGRA => Some(RawFrameFormat::Bgra),
        spa::param::video::VideoFormat::RGBx => Some(RawFrameFormat::Rgbx),
        spa::param::video::VideoFormat::BGRx => Some(RawFrameFormat::Bgrx),
        spa::param::video::VideoFormat::xRGB => Some(RawFrameFormat::Xrgb),
        spa::param::video::VideoFormat::xBGR => Some(RawFrameFormat::Xbgr),
        spa::param::video::VideoFormat::ARGB => Some(RawFrameFormat::Argb),
        spa::param::video::VideoFormat::ABGR => Some(RawFrameFormat::Abgr),
        spa::param::video::VideoFormat::YUY2 => Some(RawFrameFormat::Yuy2),
        spa::param::video::VideoFormat::I420 => Some(RawFrameFormat::I420),
        _ => None,
    }
}

const fn drm_fourcc(a: u8, b: u8, c: u8, d: u8) -> u32 {
    (a as u32) | ((b as u32) << 8) | ((c as u32) << 16) | ((d as u32) << 24)
}

fn drm_fourcc_for_video_format(format: spa::param::video::VideoFormat) -> Option<u32> {
    match format {
        spa::param::video::VideoFormat::BGRx => Some(drm_fourcc(b'X', b'R', b'2', b'4')),
        spa::param::video::VideoFormat::BGRA => Some(drm_fourcc(b'A', b'R', b'2', b'4')),
        spa::param::video::VideoFormat::RGBx => Some(drm_fourcc(b'X', b'B', b'2', b'4')),
        spa::param::video::VideoFormat::RGBA => Some(drm_fourcc(b'A', b'B', b'2', b'4')),
        spa::param::video::VideoFormat::xRGB => Some(drm_fourcc(b'B', b'G', b'R', b'X')),
        spa::param::video::VideoFormat::xBGR => Some(drm_fourcc(b'R', b'G', b'B', b'X')),
        spa::param::video::VideoFormat::ARGB => Some(drm_fourcc(b'B', b'G', b'R', b'A')),
        spa::param::video::VideoFormat::ABGR => Some(drm_fourcc(b'R', b'G', b'B', b'A')),
        spa::param::video::VideoFormat::RGB => Some(drm_fourcc(b'R', b'G', b'2', b'4')),
        spa::param::video::VideoFormat::BGR => Some(drm_fourcc(b'B', b'G', b'2', b'4')),
        spa::param::video::VideoFormat::YUY2 => Some(drm_fourcc(b'Y', b'U', b'Y', b'V')),
        _ => None,
    }
}

fn drm_fourcc_name(format: u32) -> String {
    let bytes = format.to_le_bytes();
    bytes
        .iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            }
        })
        .collect()
}

fn packed_rgb(
    data: &[u8],
    y: usize,
    stride: usize,
    x: usize,
    bytes_per_pixel: usize,
    channels: [usize; 3],
) -> Option<[u8; 3]> {
    let base = y
        .checked_mul(stride)?
        .checked_add(x.checked_mul(bytes_per_pixel)?)?;
    let last = base.checked_add(*channels.iter().max()?)?;
    if last >= data.len() {
        return None;
    }
    Some([
        data[base + channels[0]],
        data[base + channels[1]],
        data[base + channels[2]],
    ])
}

fn yuy2_rgb(frame: &RawFrame, x: usize, y: usize) -> Option<[u8; 3]> {
    let base = y
        .checked_mul(frame.stride)?
        .checked_add((x / 2).checked_mul(4)?)?;
    if base + 3 >= frame.data.len() {
        return None;
    }
    let y_sample = frame.data[base + if x.is_multiple_of(2) { 0 } else { 2 }];
    let u = frame.data[base + 1];
    let v = frame.data[base + 3];
    Some(yuv_to_rgb(y_sample, u, v))
}

fn i420_rgb(frame: &RawFrame, x: usize, y: usize) -> Option<[u8; 3]> {
    let y_stride = frame.stride.max(frame.width as usize);
    let uv_stride = y_stride.div_ceil(2);
    let height = frame.height as usize;
    let uv_height = height.div_ceil(2);
    let y_offset = y.checked_mul(y_stride)?.checked_add(x)?;
    let u_plane = y_stride.checked_mul(height)?;
    let v_plane = u_plane.checked_add(uv_stride.checked_mul(uv_height)?)?;
    let uv_offset = (y / 2).checked_mul(uv_stride)?.checked_add(x / 2)?;
    let u_offset = u_plane.checked_add(uv_offset)?;
    let v_offset = v_plane.checked_add(uv_offset)?;
    if y_offset >= frame.data.len() || u_offset >= frame.data.len() || v_offset >= frame.data.len()
    {
        return None;
    }
    Some(yuv_to_rgb(
        frame.data[y_offset],
        frame.data[u_offset],
        frame.data[v_offset],
    ))
}

fn yuv_to_rgb(y: u8, u: u8, v: u8) -> [u8; 3] {
    let c = (y as i32 - 16).max(0);
    let d = u as i32 - 128;
    let e = v as i32 - 128;
    [
        clamp_u8((298 * c + 409 * e + 128) >> 8),
        clamp_u8((298 * c - 100 * d - 208 * e + 128) >> 8),
        clamp_u8((298 * c + 516 * d + 128) >> 8),
    ]
}

fn clamp_u8(value: i32) -> u8 {
    value.clamp(0, 255) as u8
}

struct DashResendBuffer {
    max_bytes: u64,
    bytes: u64,
    objects: VecDeque<DashObject>,
}

impl DashResendBuffer {
    fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            bytes: 0,
            objects: VecDeque::new(),
        }
    }

    fn push(&mut self, object: DashObject) {
        self.bytes = self.bytes.saturating_add(object.payload.len() as u64);
        self.objects.push_back(object);
        while self.bytes > self.max_bytes && self.objects.len() > 1 {
            if let Some(old) = self.objects.pop_front() {
                self.bytes = self.bytes.saturating_sub(old.payload.len() as u64);
            }
        }
    }

    fn ack(&mut self, through_seq: u64) {
        while self
            .objects
            .front()
            .is_some_and(|object| object.header.sequence <= through_seq)
        {
            if let Some(old) = self.objects.pop_front() {
                self.bytes = self.bytes.saturating_sub(old.payload.len() as u64);
            }
        }
    }

    fn drop_other_streams(&mut self, stream_id: Uuid) {
        self.objects
            .retain(|object| object.header.stream_id == stream_id);
        self.bytes = self
            .objects
            .iter()
            .map(|object| object.payload.len() as u64)
            .sum();
    }

    fn objects(&self, from_seq: u64, to_seq: u64) -> Vec<DashObject> {
        self.objects
            .iter()
            .filter(|object| object.header.sequence >= from_seq && object.header.sequence <= to_seq)
            .cloned()
            .collect()
    }

    fn range(&self) -> (Option<u64>, Option<u64>) {
        (
            self.objects.front().map(|object| object.header.sequence),
            self.objects.back().map(|object| object.header.sequence),
        )
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "glacialcast-client".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_line_accepts_url_safe_keys_that_begin_with_hyphens() {
        let args = Args::try_parse_from([
            "glacialcast-client",
            "--ingest-token",
            "-token",
            "--ingest-server-key",
            "-server-key",
            "--viewer-key",
            "-viewer-key",
        ])
        .unwrap();
        assert_eq!(args.ingest_token.as_deref(), Some("-token"));
        assert_eq!(args.ingest_server_key.as_deref(), Some("-server-key"));
        assert_eq!(args.viewer_key.as_deref(), Some("-viewer-key"));
    }

    #[test]
    fn unavailable_required_portal_cursor_metadata_is_fatal() {
        let err = anyhow::anyhow!(
            "requested portal cursor mode Metadata is not available; portal advertised cursor mode mask 3"
        );
        assert!(is_fatal_capture_error(&err));
    }

    #[test]
    fn missing_required_pipewire_cursor_metadata_is_fatal() {
        let err = anyhow::anyhow!(
            "PipeWire buffer does not include SPA_META_Cursor while --require-cursor-metadata is set"
        );
        assert!(is_fatal_capture_error(&err));
    }

    #[test]
    fn fractional_update_rate_accepts_half_to_fifteen() {
        assert_eq!(parse_update_rate("0.5").unwrap(), 0.5);
        assert_eq!(parse_update_rate("15").unwrap(), 15.0);
        assert!(parse_update_rate("0.25").is_err());
        assert!(parse_update_rate("16").is_err());
    }

    #[test]
    fn pipewire_capture_rate_tracks_cursor_rate_above_frame_rate() {
        assert_eq!(pipewire_capture_rate(1.0, 30), 30.0);
        assert_eq!(pipewire_capture_rate(15.0, 10), 15.0);
        assert_eq!(pipewire_capture_rate(15.0, 120), 60.0);
    }

    #[test]
    fn dash_dmabuf_dimensions_preserve_aspect_ratio_and_encoder_constraints() {
        assert_eq!(fit_even_dimensions(3840, 2160, 1280, 720), (1280, 720));
        assert_eq!(fit_even_dimensions(1920, 1200, 1280, 720), (1152, 720));
        assert_eq!(fit_even_dimensions(1279, 719, 1280, 720), (1278, 718));
        assert_eq!(fit_even_dimensions(1, 1, 1, 1), (2, 2));
    }

    #[test]
    fn portal_cursor_mode_prefers_metadata_and_accepts_explicit_embedded() {
        let available = PORTAL_CURSOR_HIDDEN | PORTAL_CURSOR_EMBEDDED | PORTAL_CURSOR_METADATA;
        assert_eq!(
            select_portal_cursor_mode(available, PortalCursorMode::Auto).unwrap(),
            PORTAL_CURSOR_METADATA
        );
        assert_eq!(
            select_portal_cursor_mode(available, PortalCursorMode::Embedded).unwrap(),
            PORTAL_CURSOR_EMBEDDED
        );
        assert_eq!(
            select_portal_cursor_mode(available, PortalCursorMode::Hidden).unwrap(),
            PORTAL_CURSOR_HIDDEN
        );
    }

    #[test]
    fn portal_cursor_mode_rejects_unavailable_explicit_mode() {
        assert!(
            select_portal_cursor_mode(PORTAL_CURSOR_EMBEDDED, PortalCursorMode::Metadata).is_err()
        );
    }

    #[test]
    fn mutter_cursor_mode_uses_mutter_numbering() {
        assert_eq!(
            select_mutter_cursor_mode(4, PortalCursorMode::Metadata).unwrap(),
            2
        );
        assert_eq!(
            select_mutter_cursor_mode(4, PortalCursorMode::Embedded).unwrap(),
            1
        );
        assert_eq!(
            select_mutter_cursor_mode(4, PortalCursorMode::Hidden).unwrap(),
            0
        );
        assert!(select_mutter_cursor_mode(1, PortalCursorMode::Metadata).is_err());
    }

    #[test]
    fn pipewire_cursor_meta_request_reserves_bitmap_space() {
        assert!(
            pipewire_cursor_meta_size(PIPEWIRE_CURSOR_DEFAULT_BITMAP_SIDE)
                >= (std::mem::size_of::<spa::sys::spa_meta_cursor>()
                    + std::mem::size_of::<spa::sys::spa_meta_bitmap>()
                    + PIPEWIRE_CURSOR_DEFAULT_BITMAP_SIDE * PIPEWIRE_CURSOR_DEFAULT_BITMAP_SIDE * 4)
                    as i32
        );
    }

    #[test]
    fn pipewire_cursor_meta_request_has_size_property() {
        let bytes = build_pipewire_cursor_meta_param_pod().unwrap();
        let pod = spa::pod::Pod::from_bytes(&bytes).unwrap();
        let object = <&spa::pod::PodObject>::try_from(pod).unwrap();
        let meta_type = object
            .find_prop(spa::utils::Id(spa::sys::SPA_PARAM_META_type))
            .expect("cursor meta request type property");
        assert_eq!(
            meta_type.value().get_id().unwrap(),
            spa::utils::Id(spa::sys::SPA_META_Cursor)
        );
        assert!(
            object
                .find_prop(spa::utils::Id(spa::sys::SPA_PARAM_META_size))
                .is_some()
        );
        assert!(pipewire_cursor_meta_size(PIPEWIRE_CURSOR_DEFAULT_BITMAP_SIDE) > 0);
    }

    #[test]
    fn pipewire_cursor_metadata_decodes_and_rate_limits() {
        let mut cursor = spa::sys::spa_meta_cursor {
            id: 7,
            flags: 0,
            position: spa::sys::spa_point { x: 25, y: 40 },
            hotspot: spa::sys::spa_point { x: 0, y: 0 },
            bitmap_offset: 0,
        };
        let mut meta = spa::sys::spa_meta {
            type_: spa::sys::SPA_META_Cursor,
            size: std::mem::size_of::<spa::sys::spa_meta_cursor>() as u32,
            data: (&mut cursor as *mut spa::sys::spa_meta_cursor).cast(),
        };
        let buffer = spa::sys::spa_buffer {
            n_metas: 1,
            n_datas: 0,
            metas: &mut meta,
            datas: ptr::null_mut(),
        };
        let mut serial = 0;
        let mut last_state = None;
        let mut last_sent = None;

        let first = pipewire_cursor_sample(
            &buffer,
            100,
            80,
            &mut serial,
            &mut last_state,
            &mut last_sent,
            Duration::from_secs(10),
        )
        .expect("first cursor sample");
        assert_eq!(first.serial, 1);
        assert_eq!(first.x, 25.0);
        assert_eq!(first.y, 40.0);
        assert!(first.bitmap.is_none());

        cursor.position.x = 30;
        assert_eq!(cursor.position.x, 30);
        assert!(
            pipewire_cursor_sample(
                &buffer,
                100,
                80,
                &mut serial,
                &mut last_state,
                &mut last_sent,
                Duration::from_secs(10),
            )
            .is_none()
        );
    }

    #[test]
    fn pipewire_cursor_metadata_decodes_bitmap_and_hotspot() {
        #[repr(C)]
        struct CursorMetaFixture {
            cursor: spa::sys::spa_meta_cursor,
            bitmap: spa::sys::spa_meta_bitmap,
            pixels: [u8; 16],
        }

        let bitmap_offset = std::mem::offset_of!(CursorMetaFixture, bitmap);
        let pixel_offset = std::mem::offset_of!(CursorMetaFixture, pixels) - bitmap_offset;
        let rgba_pixels = [
            255, 0, 0, 255, 0, 255, 0, 128, 0, 0, 255, 64, 255, 255, 255, 0,
        ];
        let mut fixture = CursorMetaFixture {
            cursor: spa::sys::spa_meta_cursor {
                id: 11,
                flags: 0,
                position: spa::sys::spa_point { x: 25, y: 40 },
                hotspot: spa::sys::spa_point { x: 3, y: 4 },
                bitmap_offset: bitmap_offset as u32,
            },
            bitmap: spa::sys::spa_meta_bitmap {
                format: spa::sys::SPA_VIDEO_FORMAT_RGBA,
                size: spa::sys::spa_rectangle {
                    width: 2,
                    height: 2,
                },
                stride: 8,
                offset: pixel_offset as u32,
            },
            pixels: rgba_pixels,
        };
        let mut meta = spa::sys::spa_meta {
            type_: spa::sys::SPA_META_Cursor,
            size: std::mem::size_of::<CursorMetaFixture>() as u32,
            data: (&mut fixture.cursor as *mut spa::sys::spa_meta_cursor).cast(),
        };
        let buffer = spa::sys::spa_buffer {
            n_metas: 1,
            n_datas: 0,
            metas: &mut meta,
            datas: ptr::null_mut(),
        };

        let state = pipewire_cursor_state(&buffer).expect("cursor state");
        let bitmap = state.bitmap.expect("cursor bitmap");
        assert_eq!(state.hotspot_x, 3);
        assert_eq!(state.hotspot_y, 4);
        assert_eq!(bitmap.width, 2);
        assert_eq!(bitmap.height, 2);
        assert_eq!(bitmap.hotspot_x, 3);
        assert_eq!(bitmap.hotspot_y, 4);
        let png = BASE64_STANDARD.decode(bitmap.png_b64).unwrap();
        let decoded = image::load_from_memory(&png).unwrap().to_rgba8();
        assert_eq!(decoded.as_raw(), &rgba_pixels);
    }

    #[test]
    fn dash_cursor_sends_bitmap_pixels_only_when_the_bitmap_changes() {
        let rgba = [255, 0, 0, 255, 0, 255, 0, 255];
        let bitmap = CursorBitmap {
            width: 2,
            height: 1,
            hotspot_x: 1,
            hotspot_y: 0,
            png_b64: encode_cursor_png_b64(2, 1, &rgba).unwrap(),
        };
        let message = |bitmap| CursorMessage {
            x: 10.0,
            y: 20.0,
            source_width: 100,
            source_height: 100,
            bitmap,
        };
        let mut state = DashCursorBitmapState::default();
        let first =
            cursor_to_dash_event(message(Some(bitmap.clone())), 10, 100, 100, &mut state).unwrap();
        let repeated =
            cursor_to_dash_event(message(Some(bitmap)), 20, 100, 100, &mut state).unwrap();
        let position_only = cursor_to_dash_event(message(None), 30, 100, 100, &mut state).unwrap();

        assert!(first.bitmap.is_some());
        assert!(repeated.bitmap.is_none());
        assert_eq!(repeated.bitmap_id, first.bitmap_id);
        assert_eq!(position_only.bitmap_id, first.bitmap_id);
    }

    #[test]
    fn pipewire_cursor_metadata_ignores_zero_id() {
        let mut cursor = spa::sys::spa_meta_cursor {
            id: 0,
            flags: 0,
            position: spa::sys::spa_point { x: 12, y: 18 },
            hotspot: spa::sys::spa_point { x: 0, y: 0 },
            bitmap_offset: 0,
        };
        let mut meta = spa::sys::spa_meta {
            type_: spa::sys::SPA_META_Cursor,
            size: std::mem::size_of::<spa::sys::spa_meta_cursor>() as u32,
            data: (&mut cursor as *mut spa::sys::spa_meta_cursor).cast(),
        };
        let buffer = spa::sys::spa_buffer {
            n_metas: 1,
            n_datas: 0,
            metas: &mut meta,
            datas: ptr::null_mut(),
        };

        assert_eq!(pipewire_cursor_state(&buffer), None);
    }

    #[test]
    fn pipewire_buffer_cursor_meta_detection_distinguishes_busy_meta() {
        let mut busy_meta = spa::sys::spa_meta {
            type_: spa::sys::SPA_META_Busy,
            size: 8,
            data: ptr::null_mut(),
        };
        let busy_buffer = spa::sys::spa_buffer {
            n_metas: 1,
            n_datas: 0,
            metas: &mut busy_meta,
            datas: ptr::null_mut(),
        };
        assert!(!pipewire_buffer_has_cursor_meta(&busy_buffer));

        let mut metas = [
            spa::sys::spa_meta {
                type_: spa::sys::SPA_META_Busy,
                size: 8,
                data: ptr::null_mut(),
            },
            spa::sys::spa_meta {
                type_: spa::sys::SPA_META_Cursor,
                size: std::mem::size_of::<spa::sys::spa_meta_cursor>() as u32,
                data: ptr::null_mut(),
            },
        ];
        let cursor_buffer = spa::sys::spa_buffer {
            n_metas: metas.len() as u32,
            n_datas: 0,
            metas: metas.as_mut_ptr(),
            datas: ptr::null_mut(),
        };
        assert!(pipewire_buffer_has_cursor_meta(&cursor_buffer));
    }

    #[test]
    fn required_pipewire_cursor_metadata_waits_during_grace() {
        let mut busy_meta = spa::sys::spa_meta {
            type_: spa::sys::SPA_META_Busy,
            size: 8,
            data: ptr::null_mut(),
        };
        let buffer = spa::sys::spa_buffer {
            n_metas: 1,
            n_datas: 0,
            metas: &mut busy_meta,
            datas: ptr::null_mut(),
        };
        let now = Instant::now();
        let mut verified = false;
        let mut missing_since = None;

        assert_eq!(
            pipewire_cursor_metadata_gate(&buffer, true, &mut verified, &mut missing_since, now,),
            PipewireCursorMetadataGate::Pending
        );
        assert!(!verified);
        assert!(missing_since.is_some());
    }

    #[test]
    fn required_pipewire_cursor_metadata_fails_after_grace() {
        let mut busy_meta = spa::sys::spa_meta {
            type_: spa::sys::SPA_META_Busy,
            size: 8,
            data: ptr::null_mut(),
        };
        let buffer = spa::sys::spa_buffer {
            n_metas: 1,
            n_datas: 0,
            metas: &mut busy_meta,
            datas: ptr::null_mut(),
        };
        let now = Instant::now();
        let mut verified = false;
        let mut missing_since = Some(now - PIPEWIRE_CURSOR_METADATA_GRACE);

        assert_eq!(
            pipewire_cursor_metadata_gate(&buffer, true, &mut verified, &mut missing_since, now,),
            PipewireCursorMetadataGate::Fatal
        );
        assert!(!verified);
    }

    #[test]
    fn required_pipewire_cursor_metadata_recovers_when_meta_appears() {
        let mut cursor_meta = spa::sys::spa_meta {
            type_: spa::sys::SPA_META_Cursor,
            size: std::mem::size_of::<spa::sys::spa_meta_cursor>() as u32,
            data: ptr::null_mut(),
        };
        let buffer = spa::sys::spa_buffer {
            n_metas: 1,
            n_datas: 0,
            metas: &mut cursor_meta,
            datas: ptr::null_mut(),
        };
        let now = Instant::now();
        let mut verified = false;
        let mut missing_since = Some(now - Duration::from_secs(1));

        assert_eq!(
            pipewire_cursor_metadata_gate(&buffer, true, &mut verified, &mut missing_since, now,),
            PipewireCursorMetadataGate::Ready
        );
        assert!(verified);
        assert!(missing_since.is_none());
    }

    #[test]
    fn pipewire_buffer_meta_inspection_reports_cursor_presence_once() {
        let mut busy_meta = spa::sys::spa_meta {
            type_: spa::sys::SPA_META_Busy,
            size: 8,
            data: ptr::null_mut(),
        };
        let busy_buffer = spa::sys::spa_buffer {
            n_metas: 1,
            n_datas: 0,
            metas: &mut busy_meta,
            datas: ptr::null_mut(),
        };
        let mut logged = false;
        assert_eq!(
            log_pipewire_buffer_metas_once(&busy_buffer, &mut logged, "test"),
            Some(false)
        );
        assert_eq!(
            log_pipewire_buffer_metas_once(&busy_buffer, &mut logged, "test"),
            None
        );

        let mut cursor_meta = spa::sys::spa_meta {
            type_: spa::sys::SPA_META_Cursor,
            size: std::mem::size_of::<spa::sys::spa_meta_cursor>() as u32,
            data: ptr::null_mut(),
        };
        let cursor_buffer = spa::sys::spa_buffer {
            n_metas: 1,
            n_datas: 0,
            metas: &mut cursor_meta,
            datas: ptr::null_mut(),
        };
        let mut logged = false;
        assert_eq!(
            log_pipewire_buffer_metas_once(&cursor_buffer, &mut logged, "test"),
            Some(true)
        );
    }

    #[test]
    fn exact_cpu_pipewire_format_preserves_invalid_modifier() {
        let bytes = build_exact_cpu_pipewire_format_pod(
            spa::param::video::VideoFormat::BGRx,
            100,
            80,
            20.0,
            Some(DRM_FORMAT_MOD_INVALID as u64),
        )
        .unwrap();
        let pod = spa::pod::Pod::from_bytes(&bytes).unwrap();

        assert!(format_param_has_video_modifier(pod));
        assert_eq!(
            preferred_cpu_readable_modifier(pod),
            Some(DRM_FORMAT_MOD_INVALID as u64)
        );
    }

    #[test]
    fn cpu_pipewire_formats_try_modifierless_before_implicit_dmabuf() {
        let advertised = build_exact_cpu_pipewire_format_pod(
            spa::param::video::VideoFormat::BGRx,
            100,
            80,
            20.0,
            Some(DRM_FORMAT_MOD_INVALID as u64),
        )
        .unwrap();

        let offers = build_pipewire_format_pods_from_node_formats(&[advertised], 15.0).unwrap();
        assert_eq!(offers.len(), 2);

        let shm_offer = spa::pod::Pod::from_bytes(&offers[0]).unwrap();
        assert!(!format_param_has_video_modifier(shm_offer));

        let implicit_dmabuf_offer = spa::pod::Pod::from_bytes(&offers[1]).unwrap();
        assert!(format_param_has_video_modifier(implicit_dmabuf_offer));
        assert_eq!(
            preferred_cpu_readable_modifier(implicit_dmabuf_offer),
            Some(DRM_FORMAT_MOD_INVALID as u64)
        );
    }

    #[test]
    fn implicit_modifier_buffers_require_dmabuf() {
        let bytes = build_buffers_param_pod(
            spa::param::video::VideoFormat::BGRx,
            100,
            80,
            DRM_FORMAT_MOD_INVALID as u64,
        )
        .unwrap();
        let pod = spa::pod::Pod::from_bytes(&bytes).unwrap();
        let (default, flags) = buffers_data_type_default_and_flags(pod);
        let dmabuf_mask = 1 << spa::buffer::DataType::DmaBuf.as_raw();

        assert_eq!(default, dmabuf_mask);
        assert_eq!(flags, vec![dmabuf_mask]);
    }

    fn buffers_data_type_default_and_flags(param: &spa::pod::Pod) -> (i32, Vec<i32>) {
        const PARAM_BUFFERS_DATA_TYPE: u32 = 6;
        let object = <&spa::pod::PodObject>::try_from(param).unwrap();
        let prop = object
            .find_prop(spa::utils::Id(PARAM_BUFFERS_DATA_TYPE))
            .unwrap();
        let (_, value) =
            spa::pod::deserialize::PodDeserializer::deserialize_from::<spa::pod::Value>(
                prop.value().as_bytes(),
            )
            .unwrap();
        match value {
            spa::pod::Value::Choice(spa::pod::ChoiceValue::Int(choice)) => match choice.1 {
                spa::utils::ChoiceEnum::Flags { default, flags } => (default, flags),
                other => panic!("unexpected data type choice: {other:?}"),
            },
            other => panic!("unexpected data type value: {other:?}"),
        }
    }
}
