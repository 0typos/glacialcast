//! GlacialCast Wayland capture and DASH publisher.
//!
//! The client captures a portal/PipeWire or deterministic test source, samples
//! video at a deliberately low cadence, and processes cursor metadata on an
//! independent higher-rate timeline. It packages H.264 into CENC fragmented
//! MP4, encrypts cursor batches, authenticates complete stream objects, and
//! publishes them through a relay-pinned Noise NK connection.
//!
//! Capture buffers remain leased until CPU or DMA-BUF conversion is complete.
//! The relay receives neither the viewer key nor plaintext pixels or cursor
//! contents.

#![deny(missing_docs)]
#![allow(
    dead_code,
    reason = "legacy DASH helpers remain temporarily while native capture parity is verified"
)]

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use clap::{Parser, ValueEnum};
use futures_util::StreamExt;
use glacialcast_protocol::{
    CaptureSource, ClientMessage, DashObject, DashObjectKind, NewDashObject, NoiseSocket,
    PROTOCOL_VERSION, ServerMessage, StreamHello,
    config_path::{self, ConfigSource},
    daemon::{
        daemonize_if_requested, install_signal_handlers, manager_command,
        sanitize_socket_component, serve_control_socket, wait_for_shutdown,
    },
    decode_key_b64, decode_noise_public_key, encode_key_b64, initiator_handshake, now_ms,
    parse_human_bytes, viewer_key,
};
use glacialcast_stream::{
    CursorBatch as DashCursorBatch, CursorBitmap as DashCursorBitmap,
    CursorContext as DashCursorContext, CursorEvent as DashCursorEvent, DASH_FORMAT_VERSION,
    EpochDescriptor, EpochKeys, FragmentInput, MEDIA_TIMESCALE, build_fragment, build_init_segment,
    encode_plain_cursor_batch, encrypt_cursor_batch,
};
use image::{ImageBuffer, Rgb, imageops::FilterType};
use pipewire as pw;
use pw::{properties::properties, spa};
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
#[cfg(any())]
use std::os::fd::BorrowedFd;
use std::{
    collections::VecDeque,
    io::{IsTerminal, Read, Write},
    os::fd::{FromRawFd, OwnedFd, RawFd},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    ptr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
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
#[cfg(any())]
mod egl_readback;
mod native_admin;
mod native_publish;

use dash_encoder::{
    DashDmaBufFrame, DashEncoderMode, DashFrameRelease, DashH264Encoder, DashInputFrame,
    should_capture_dmabuf,
};
#[cfg(any())]
use egl_readback::{DmaBufPlane, EglReadback, ReadbackLayout};

const PORTAL_SOURCE_MONITOR: u32 = 1;
const PORTAL_SOURCE_WINDOW: u32 = 2;
const PORTAL_CURSOR_HIDDEN: u32 = 1;
const PORTAL_CURSOR_EMBEDDED: u32 = 2;
const PORTAL_CURSOR_METADATA: u32 = 4;
const PORTAL_PERSIST_DO_NOT: u32 = 0;
/// Ask the portal to remember the grant until the application revokes it.
const PORTAL_PERSIST_UNTIL_REVOKED: u32 = 2;
const DRM_FORMAT_MOD_LINEAR: u64 = 0;
const DRM_FORMAT_MOD_INVALID: i64 = 0x00ff_ffff_ffff_ffff;
const SPA_DATA_FLAG_MAPPABLE: u32 = 1 << 3;
const DMA_BUF_IOCTL_SYNC: libc::c_ulong = 0x4008_6200;
const DMA_BUF_SYNC_READ: u64 = 1 << 0;
const DMA_BUF_SYNC_END: u64 = 1 << 2;
const PIPEWIRE_CURSOR_MIN_BITMAP_SIDE: usize = 1;
const PIPEWIRE_CURSOR_DEFAULT_BITMAP_SIDE: usize = 64;
// WebRTC and niri accept cursor metadata through 384×384. Advertising a range
// lets producers that reserve the full capacity negotiate with this consumer.
const PIPEWIRE_CURSOR_NEGOTIATED_MAX_BITMAP_SIDE: usize = 384;
const PIPEWIRE_CURSOR_MAX_BITMAP_SIDE: usize = 512;
const CURSOR_BITMAP_REFRESH_TICKS: u64 = MEDIA_TIMESCALE as u64 * 60;
const PIPEWIRE_CURSOR_METADATA_GRACE: Duration = Duration::from_secs(5);
const MAX_SERVER_CONTROL_MESSAGE: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct CursorBitmap {
    width: u32,
    height: u32,
    hotspot_x: i32,
    hotspot_y: i32,
    rgba: Arc<[u8]>,
}

#[derive(Debug, Clone)]
struct CursorMessage {
    x: f32,
    y: f32,
    visible: bool,
    source_width: u32,
    source_height: u32,
    bitmap: Option<Arc<CursorBitmap>>,
}

#[derive(Debug, Parser)]
#[command(version)]
struct Args {
    /// Configuration file. Without it the standard locations are searched:
    /// `$XDG_CONFIG_HOME/glacialcast/client.toml`, `/etc/glacialcast/client.toml`,
    /// then `client.toml` in the working directory.
    #[arg(long, env = "GLACIALCAST_CONFIG")]
    config: Option<PathBuf>,
    /// Ignores every configuration file and runs on built-in defaults.
    ///
    /// For a test or a deliberately minimal deployment that must not inherit
    /// whatever happens to sit in a standard location on the host.
    #[arg(long, conflicts_with = "config")]
    no_config: bool,
    #[arg(long, default_value = "127.0.0.1:8900")]
    ingest_addr: String,
    #[arg(long, allow_hyphen_values = true, hide = true)]
    ingest_token: Option<String>,
    #[arg(
        long,
        env = "GLACIALCAST_INGEST_SERVER_KEY",
        allow_hyphen_values = true
    )]
    ingest_server_key: Option<String>,
    /// Native relay-access publisher credential.
    #[arg(long)]
    native_credential: Option<PathBuf>,
    /// Publisher key history size bound (default `100MiB`).
    #[arg(long, value_parser = parse_human_bytes)]
    history_bytes: Option<u64>,
    /// Publisher key history age bound in seconds (default 24 hours).
    #[arg(long)]
    history_seconds: Option<u64>,
    #[arg(long, allow_hyphen_values = true, hide = true)]
    viewer_key: Option<String>,
    /// Viewer key as a word phrase, instead of letting one be generated.
    #[arg(
        long,
        allow_hyphen_values = true,
        conflicts_with = "viewer_key",
        hide = true
    )]
    viewer_key_phrase: Option<String>,
    #[arg(long, conflicts_with = "viewer_key", hide = true)]
    no_viewer_key: bool,
    #[arg(long, hide = true)]
    viewer_key_file: Option<PathBuf>,
    /// Replaces the stored viewer key with a fresh key phrase.
    ///
    /// Every key already shared for this publisher stops working.
    #[arg(
        long,
        conflicts_with_all = ["viewer_key", "no_viewer_key"],
        hide = true
    )]
    new_viewer_key: bool,
    #[arg(long, hide = true)]
    print_viewer_key: bool,
    #[arg(long, hide = true)]
    viewer_url: Option<String>,
    #[arg(long)]
    client_id: Option<String>,
    #[arg(long)]
    display_name: Option<String>,
    #[arg(long, value_enum, default_value_t = CaptureMode::Wayland)]
    capture: CaptureMode,
    #[arg(long, value_enum, default_value_t = TestPatternMode::Motion)]
    test_pattern: TestPatternMode,
    #[arg(long, value_enum, default_value_t = PortalSourceMode::Monitor)]
    portal_source: PortalSourceMode,
    #[arg(long, value_enum, default_value_t = ScreenCastBackend::Auto)]
    screencast_backend: ScreenCastBackend,
    #[arg(long)]
    monitor_name: Vec<String>,
    #[arg(long, conflicts_with = "monitor_name")]
    all_monitors: bool,
    #[arg(long)]
    list_monitors: bool,
    #[arg(long)]
    portal_token_file: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = PortalCursorMode::Auto)]
    portal_cursor: PortalCursorMode,
    #[arg(long)]
    require_cursor_metadata: bool,
    #[arg(long, default_value_t = 1280)]
    width: u32,
    #[arg(long, default_value_t = 720)]
    height: u32,
    #[arg(long, default_value_t = 2560)]
    max_frame_width: u32,
    #[arg(long, default_value_t = 1440)]
    max_frame_height: u32,
    /// Captured updates per second, between 0.5 and 15.
    #[arg(long, value_parser = parse_update_rate, default_value = "5")]
    fps: f64,
    /// Longest time an unchanged picture is held before being re-sent, in
    /// seconds. Fractions are accepted.
    ///
    /// This bounds latency after an unchanged picture and limits idle traffic.
    #[arg(long, value_parser = parse_idle_heartbeat_seconds, default_value_t = 0.5)]
    idle_heartbeat_seconds: f64,
    /// Publishes without encryption, so no viewing key is needed to watch.
    ///
    /// The relay refuses these streams unless it is serving a trusted local
    /// network, and every host that can reach it can then watch, and can inject
    /// frames a viewer cannot tell from yours. Media and cursor data leave this
    /// machine readable by the relay and by anything between.
    ///
    /// It exists because Apple's browsers cannot play encrypted streams at all:
    /// WebKit offers only FairPlay, never the Clear Key scheme this uses, so an
    /// iPhone or iPad has no way to decrypt one. Unencrypted is the only form
    /// they can play.
    #[arg(long, hide = true)]
    no_encryption: bool,
    #[arg(long, default_value_t = 60)]
    cursor_hz: u64,
    #[arg(long, value_parser = parse_cursor_flush_ms, default_value_t = 25)]
    cursor_flush_ms: u64,
    #[arg(long, default_value_t = 2_500_000)]
    video_bitrate: u32,
    #[arg(long, hide = true)]
    segment_frames: Option<u16>,
    #[arg(long = "encoder", alias = "dash-encoder", value_enum, default_value_t = DashEncoderMode::Auto)]
    encoder: DashEncoderMode,
    #[arg(long, default_value = "/dev/dri/renderD128")]
    vaapi_device: PathBuf,
    #[arg(long)]
    openh264_library: Option<PathBuf>,
    #[arg(
        long,
        value_parser = parse_human_bytes,
        default_value = "128MiB",
        hide = true
    )]
    resend_bytes: u64,
    #[arg(long)]
    foreground: bool,
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

impl Args {
    /// Frames per media segment, holding segment duration near four seconds.
    ///
    /// Segment boundaries force an IDR, and an IDR costs far more than a
    /// predicted frame. Holding the frame count fixed while the frame rate
    /// rises therefore multiplies keyframes and with them the bitrate: at five
    /// frames per second the shipped four-frame segment measured 13 MB/min
    /// across three screens against 2.4 MB/min once the duration was restored.
    fn segment_frames(&self) -> u16 {
        self.segment_frames.unwrap_or_else(|| {
            let frames = (self.fps * f64::from(SEGMENT_TARGET_SECONDS)).round();
            (frames as u16).clamp(1, MAX_SEGMENT_FRAMES)
        })
    }
}

/// Segment duration the publisher aims for, in seconds.
const SEGMENT_TARGET_SECONDS: u16 = 4;
/// Upper bound on frames per segment, so a high frame rate cannot produce a
/// segment the viewer must buffer for an unreasonable time before it decodes.
const MAX_SEGMENT_FRAMES: u16 = 120;

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ClientConfig {
    client_id: Option<String>,
    ingest_token: Option<String>,
    ingest_server_key: Option<String>,
    viewer_key_b64: Option<String>,
    /// Viewer key as a word phrase, which is what a person is given.
    ///
    /// Takes the place of a generated one, so several publishers can share a
    /// key deliberately and an operator can choose a memorable one. The salt is
    /// still generated per publisher and published as stream metadata, so a
    /// phrase reused across deployments does not produce the same key material
    /// in each.
    viewer_key_phrase: Option<String>,
    display_name: Option<String>,
    viewer_url: Option<String>,
    /// Publishes every connected output rather than the primary one.
    all_monitors: Option<bool>,
    /// Maximum encoded content whose group keys remain available to newly approved viewers.
    history_bytes: Option<u64>,
    /// Maximum age in seconds of group keys offered to newly approved viewers.
    history_seconds: Option<u64>,
}

/// Salt used when a phrase is supplied but no key file is kept.
///
/// Deterministic on purpose: with `--no-viewer-key` there is nowhere to persist
/// a random salt, and a phrase that derived a different key on every start
/// would be unusable. A publisher that keeps a key file gets a random salt
/// instead, which is the normal case.
const DERIVED_PHRASE_FALLBACK_SALT: [u8; viewer_key::SALT_LEN] = *b"glacialcast-derv";

/// The phrase shipped in the example configuration.
///
/// Present so an install works immediately, and therefore public: anyone who
/// can reach the relay and has read the documentation can decrypt a stream
/// published under it. The publisher warns on every start until it is changed,
/// because a default secret that is never mentioned again is one that stays.
const EXAMPLE_VIEWER_KEY_PHRASE: &str = "demo-only-weak-amend-now-open-free";

/// Identifies one published stream to the relay.
///
/// A publisher casting several screens shares one client identity across them
/// and distinguishes each stream by its label.
#[derive(Clone, Copy)]
struct StreamIdentity<'a> {
    client: &'a ClientIdentity,
    /// Per-output label, or `None` when this process publishes one stream.
    label: Option<&'a str>,
}

struct ClientIdentity {
    client_id: String,
    auth_token: Option<String>,
    ingest_server_key: Option<[u8; 32]>,
    viewer_key_b64: Option<String>,
    /// The viewer key in the form shared with people, which is a key phrase
    /// unless the key was supplied directly as base64.
    viewer_key_shareable: Option<String>,
    /// Public salt the relay republishes so a viewer can derive the key from
    /// the phrase. `None` for a raw key, which needs no derivation.
    viewer_key_salt_b64: Option<String>,
    display_name: String,
    /// Where a generated viewer key is kept so restarts republish the same
    /// key, or `None` when the key came from configuration or the command line.
    viewer_key_file: Option<PathBuf>,
    /// Operator-supplied viewer page address, printed with the sharing summary.
    viewer_url: Option<String>,
    /// Configuration actually read, so the summary and the log can say which
    /// file a detached publisher is running on.
    config_path: Option<PathBuf>,
    /// Publish every output, from `all_monitors` in the configuration file.
    /// The `--all-monitors` flag turns it on independently.
    all_monitors: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CaptureMode {
    Test,
    Wayland,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum TestPatternMode {
    Static,
    Typing,
    Scroll,
    Motion,
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
    Auto,
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

/// Parses the process configuration and runs the capture publisher.
///
/// This is the installed binary's entry point. The publisher detaches into the
/// background unless `--foreground` is given, after printing the viewer key
/// that the operator shares out of band. It returns after a requested
/// daemon-management action, clean shutdown, or a fatal configuration,
/// capture, encoding, or transport error.
pub fn run() -> Result<()> {
    if native_admin::is_admin_command() {
        return native_admin::run();
    }
    let mut args = Args::parse();
    let config_source = if args.no_config {
        ConfigSource::Defaults
    } else {
        config_path::resolve(args.config.clone(), "client.toml")
    };
    let config = load_client_config_from(&config_source)?;
    args.history_bytes = Some(
        args.history_bytes
            .or(config.history_bytes)
            .unwrap_or(100 * 1024 * 1024),
    );
    args.history_seconds = Some(
        args.history_seconds
            .or(config.history_seconds)
            .unwrap_or(24 * 60 * 60),
    );
    if args.history_bytes == Some(0) || args.history_seconds == Some(0) {
        bail!("history byte and time limits must be positive");
    }
    if args.no_encryption {
        bail!("native GlacialCast streams are always end-to-end encrypted");
    }
    if args.print_viewer_key {
        bail!("native viewers pair by identity; there is no shared viewer key to print");
    }
    args.no_viewer_key = true;
    let identity = resolve_client_identity(&args)?;
    let daemon_socket = client_daemon_socket(&args, &identity);

    if args.list_monitors {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("building monitor listing runtime")?;
        return runtime.block_on(print_monitor_list(&args));
    }

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

    let detach = !args.foreground && !args.daemon_child;
    let log_file = args
        .log_file
        .clone()
        .unwrap_or_else(|| default_log_file(&identity.client_id));
    if detach {
        print_sharing_summary(&identity, &daemon_socket, &log_file, false);
    }
    if daemonize_if_requested(
        detach,
        args.daemon_child,
        &daemon_socket,
        "--daemon-socket",
        "--daemon-child",
        Some(&log_file),
    )? {
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "glacialcast_publisher=info".into()),
        )
        // Diagnostics go to stderr, leaving stdout for values a caller
        // captures, such as `--print-viewer-key`.
        .with_writer(std::io::stderr)
        // A detached publisher writes this stream to a log file, so colour it
        // only when a human is actually watching a terminal.
        .with_ansi(std::io::stderr().is_terminal())
        .init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building client runtime")?;
    runtime.block_on(run_client(args, identity, daemon_socket))
}

/// Prints everything an operator needs to invite viewers, before detaching.
///
/// The viewer key is written to standard output only, never to the log file or
/// to the relay, because the relay must not be able to decrypt the stream.
fn print_sharing_summary(
    identity: &ClientIdentity,
    daemon_socket: &std::path::Path,
    log_file: &std::path::Path,
    _unencrypted: bool,
) {
    println!("GlacialCast publisher \"{}\"", identity.display_name);
    if let Some(viewer_url) = &identity.viewer_url {
        println!("  viewer page  {viewer_url}");
    }
    println!("  viewer access  identity pairing (no shared passphrase)");
    if let Some(path) = &identity.config_path {
        println!("  config       {}", path.display());
    }
    if let Some(path) = &identity.viewer_key_file {
        println!("  key file     {}", path.display());
    }
    println!("  log file     {}", log_file.display());
    println!("  control      {}", daemon_socket.display());
    println!();
    println!(
        "Streams are end-to-end encrypted. Run `gcpub requests`, compare the displayed\n\
         authentication string with the viewer, then approve it; the relay never receives\n\
         a content key. `gcpub approve-all` accepts every currently confirmed request."
    );
}

/// Builds the one-click invitation link for this publisher's viewer key.
///
/// The key goes in the URL fragment, after the `#`. Browsers do not send the
/// fragment to the server, so the relay never receives the key even though the
/// link points at the relay; a query parameter would arrive and be logged.
///
/// Anyone holding the link can watch, exactly as anyone holding the key can, so
/// it belongs in the same secure channel as the key itself.
fn invite_link(identity: &ClientIdentity) -> Option<String> {
    let base = identity.viewer_url.as_deref()?.trim_end_matches('/');
    let key = identity.viewer_key_shareable.as_deref()?;
    Some(format!("{base}/#k={}", url_encode_fragment(key)))
}

/// Percent-encodes the characters that would end a URL fragment or be read as
/// structure inside it. A generated key phrase is words and hyphens, and a raw
/// viewer key is URL-safe base64, so this normally changes nothing — but a
/// hand-chosen phrase is arbitrary text and must not be able to break the link.
fn url_encode_fragment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn client_daemon_socket(args: &Args, identity: &ClientIdentity) -> PathBuf {
    args.daemon_socket.clone().unwrap_or_else(|| {
        let client_id = sanitize_socket_component(&identity.client_id);
        PathBuf::from(format!("/tmp/gcpub-{client_id}.sock"))
    })
}

async fn run_client(args: Args, identity: ClientIdentity, daemon_socket: PathBuf) -> Result<()> {
    let serve_control = args.daemon_child || args.daemon_socket.is_some();
    info!(
        client_id = %identity.client_id,
        // The identity holds a viewer key whether or not this run uses one, so
        // the flag is what says whether anything is encrypted end to end.
        e2e_encrypted = true,
        config = identity
            .config_path
            .as_ref()
            .map_or_else(|| "<defaults>".to_string(), |path| path.display().to_string()),
        "stream credentials ready"
    );

    // A stream published in the clear has no viewer key, so requiring one was a
    // contradiction: `--no-encryption --no-viewer-key` printed a summary saying
    // the key was not used, daemonized looking healthy, and then died here --
    // in the child's log, where nobody was looking. The flag decides; a key
    // that happens to be configured is simply left unused.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(install_signal_handlers(shutdown_tx.clone()));
    let _approval_worker = tokio::spawn(native_admin::run_live_approvals(
        args.ingest_addr.clone(),
        client_state_dir(),
        args.native_credential.clone(),
        identity.ingest_server_key,
        shutdown_rx.clone(),
    ));
    if serve_control {
        let control_shutdown = shutdown_tx.clone();
        tokio::spawn(async move {
            if let Err(err) = serve_control_socket(daemon_socket, control_shutdown).await {
                warn!(?err, "daemon control socket stopped");
            }
        });
    }

    if update_rate_outlasts_firefox(args.fps) {
        // The idle heartbeat bounds coalesced samples, but nothing can shorten
        // the frame period itself: at this rate every sample approaches or
        // exceeds the roughly one-second duration that stalls in Firefox
        // (measured: 0.95s plays, 1.0s stalls). Warn rather than refuse --
        // capture validation and Chromium-only deployments legitimately run
        // this slow -- but say it here, at startup, not as a stalled tile.
        warn!(
            fps = args.fps,
            "at this update rate every media sample lasts close to a second or more, \
             which Firefox will not decode; viewers there will see a stalled tile. \
             Use --fps 1.25 or higher if Firefox playback matters"
        );
    }
    let targets = resolve_publish_targets(&args, &identity).await?;
    info!(
        streams = targets.len(),
        labels = ?targets.iter().map(|target| target.label.as_deref()).collect::<Vec<_>>(),
        "publishing capture targets"
    );

    // Each target runs on its own thread. Giving every stream its own encoder
    // worker keeps one slow encode from delaying another output's cadence.
    let args = Arc::new(args);
    let identity = Arc::new(identity);
    let mut publishers = Vec::new();
    for target in targets {
        let args = Arc::clone(&args);
        let identity = Arc::clone(&identity);
        let shutdown_rx = shutdown_rx.clone();
        let name = target
            .label
            .clone()
            .unwrap_or_else(|| "default".to_string());
        let handle = std::thread::Builder::new()
            .name(format!("glacialcast-publish-{name}"))
            .spawn(move || -> Result<()> {
                // Two threads, not one, because the cursor timeline has to be
                // able to run while video work is running.
                //
                // On a current-thread runtime the capture loop and the cursor
                // task share the only thread that can poll them, so every
                // readback and encode delays cursor sampling by however long it
                // takes. Measured on three 2560x1440 outputs at the shipped
                // defaults, that put the worst cursor tick 12-17ms late in every
                // five-second window -- about one missed tick per five seconds,
                // which is where the occasional two-frame painted gap came from.
                //
                // `block_on` keeps the capture loop on this thread, where the
                // capture handle's non-Send state belongs; spawned tasks, which
                // is what the cursor timeline is, get the worker.
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .thread_name(format!("glacialcast-cursor-{name}"))
                    .enable_all()
                    .build()
                    .context("building publisher runtime")?;
                let label = target.label.clone();
                let mut capture: Box<dyn Capture> = match args.capture {
                    CaptureMode::Test => Box::new(TestPatternCapture::new(
                        args.width,
                        args.height,
                        args.test_pattern,
                    )),
                    CaptureMode::Wayland => Box::new(WaylandPipewireCapture::new(&args, target)),
                };
                let mut reconnect_attempt = 0u32;
                loop {
                    let result = runtime.block_on(native_publish::run_native_client(
                        &args,
                        StreamIdentity {
                            client: &identity,
                            label: label.as_deref(),
                        },
                        capture.as_mut(),
                        shutdown_rx.clone(),
                    ));
                    match result {
                        Ok(()) => break Ok(()),
                        Err(_) if *shutdown_rx.borrow() => break Ok(()),
                        Err(error) => {
                            let delay = reconnect_delay(reconnect_attempt);
                            reconnect_attempt = reconnect_attempt.saturating_add(1);
                            warn!(
                                stream = %name,
                                error = %format!("{error:#}"),
                                retry_ms = delay.as_millis(),
                                "native publication disconnected; retrying with a fresh epoch"
                            );
                            let stopped = runtime.block_on(async {
                                let mut retry_shutdown = shutdown_rx.clone();
                                tokio::select! {
                                    _ = tokio::time::sleep(delay) => false,
                                    _ = retry_shutdown.changed() => true,
                                }
                            });
                            if stopped {
                                break Ok(());
                            }
                        }
                    }
                }
            })
            .context("spawning publisher thread")?;
        publishers.push(handle);
    }

    let results = tokio::task::spawn_blocking(move || {
        publishers
            .into_iter()
            .map(|handle| match handle.join() {
                Ok(result) => result,
                Err(_) => Err(anyhow::anyhow!("publisher thread panicked")),
            })
            .collect::<Vec<_>>()
    })
    .await
    .context("joining publisher threads")?;

    let mut first_error = None;
    for result in results {
        if let Err(err) = result {
            warn!(error = %format!("{err:#}"), "capture publisher stopped with an error");
            if first_error.is_none() {
                first_error = Some(err);
            }
        }
    }
    match first_error {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

fn reconnect_delay(attempt: u32) -> Duration {
    Duration::from_millis(250u64.saturating_mul(1u64 << attempt.min(5)))
}

/// One capture source this process publishes as its own stream.
struct PublishTarget {
    /// Per-output label appended to the durable relay identity, or `None` when
    /// this process publishes a single stream under the bare identity.
    label: Option<String>,
    /// The interface that opens this target.
    backend: ScreenCastBackend,
    /// Monitor connector for the Mutter interface; the portal chooser decides
    /// its own source, so this is `None` there.
    connector: Option<String>,
    /// A session opened before the publisher threads started.
    ///
    /// One portal dialog grants every selected output at once, so the portal
    /// path opens its session up front and hands each thread one already-open
    /// stream. The Mutter path opens its own session per output instead.
    opened: Option<ScreenCastCapture>,
}

/// Resolves which sources this process will publish.
///
/// A single target keeps the historical unlabelled identity so existing
/// deployments recover the same relay stream. Publishing several outputs
/// labels each one, because the relay keys durable streams on that identity and
/// unlabelled outputs would collide on a single record.
async fn resolve_publish_targets(
    args: &Args,
    identity: &ClientIdentity,
) -> Result<Vec<PublishTarget>> {
    if args.capture != CaptureMode::Wayland {
        return Ok(vec![PublishTarget {
            label: None,
            backend: args.screencast_backend,
            connector: None,
            opened: None,
        }]);
    }
    let backend = match args.screencast_backend {
        ScreenCastBackend::Auto => resolve_screencast_backend(args.portal_source).await,
        selected => selected,
    };
    if backend != ScreenCastBackend::Mutter {
        if !args.monitor_name.is_empty() {
            bail!(
                "--monitor-name needs the compositor's ScreenCast interface; the desktop \
                 portal chooses its own sources in its dialog"
            );
        }
        if args.all_monitors || identity.all_monitors {
            // Silently ignoring it would look like the setting worked. The
            // portal's own chooser decides how many sources a session grants,
            // and this process only learns the answer afterwards.
            warn!(
                "all_monitors has no effect on the desktop portal: its chooser decides \
                 which outputs are shared. Select them in the dialog, or use a compositor \
                 with a ScreenCast interface this can drive directly"
            );
        }
        // One dialog grants the whole selection, so the session is opened here
        // rather than once per publisher thread.
        let restore = PortalRestoreToken::load(
            args.portal_token_file
                .clone()
                .unwrap_or_else(|| default_portal_token_file(&identity.client_id)),
        );
        let captures =
            open_screencast_portal_sources(args.portal_source, args.portal_cursor, Some(&restore))
                .await?;
        let labelled = captures.len() > 1;
        return Ok(captures
            .into_iter()
            .enumerate()
            .map(|(index, capture)| PublishTarget {
                label: labelled.then(|| format!("source-{}", index + 1)),
                backend,
                connector: None,
                opened: Some(capture),
            })
            .collect());
    }

    let connectors = if args.all_monitors || identity.all_monitors {
        let connection = Connection::session().await?;
        let all = list_mutter_connectors(&connection).await?;
        if all.is_empty() {
            bail!("--all-monitors found no connected monitor to record");
        }
        all
    } else if args.monitor_name.is_empty() {
        let connection = Connection::session().await?;
        vec![default_mutter_connector(&connection).await?]
    } else {
        args.monitor_name.clone()
    };

    let labelled = connectors.len() > 1;
    Ok(connectors
        .into_iter()
        .map(|connector| PublishTarget {
            label: labelled.then(|| sanitize_source_label(&connector)),
            backend,
            connector: Some(connector),
            opened: None,
        })
        .collect())
}

/// A portal grant this publisher may reuse instead of prompting again.
///
/// The portal issues an opaque token when it agrees to remember a selection.
/// It is stored with mode 0600 next to the viewer key: it is not a content
/// secret, but anyone holding it can resume this publisher's screen-capture
/// grant, so it does not belong in a world-readable file.
struct PortalRestoreToken {
    path: PathBuf,
    value: Option<String>,
}

/// The longest token this client will store or present.
///
/// The portal chooses the format, so the only safe assumption is that it is
/// bounded and printable; a file that fails either check is ignored rather
/// than replayed.
const MAX_PORTAL_RESTORE_TOKEN_LEN: usize = 512;

impl PortalRestoreToken {
    /// Loads any token previously stored for `client_id`.
    ///
    /// A missing, unreadable, or malformed file is not an error: the portal
    /// simply prompts, which is the behaviour without a token at all.
    fn load(path: PathBuf) -> Self {
        let value = std::fs::read_to_string(&path).ok().and_then(|raw| {
            let token = raw.trim().to_string();
            let acceptable = !token.is_empty()
                && token.len() <= MAX_PORTAL_RESTORE_TOKEN_LEN
                && token
                    .chars()
                    .all(|ch| !ch.is_control() && !ch.is_whitespace());
            if acceptable {
                Some(token)
            } else {
                warn!(path = %path.display(), "ignoring a malformed portal restore token");
                None
            }
        });
        Self { path, value }
    }

    fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }

    /// Replaces the stored token, reporting rather than failing on error.
    ///
    /// Losing a token costs one dialog on the next start, which must never be
    /// escalated into a failure to publish.
    fn save(&self, token: &str) {
        if token.len() > MAX_PORTAL_RESTORE_TOKEN_LEN {
            warn!("portal returned an implausibly long restore token; not storing it");
            return;
        }
        if let Err(err) = self.write(token) {
            warn!(
                path = %self.path.display(),
                error = %format!("{err:#}"),
                "could not store the portal restore token; the next start will prompt"
            );
        }
    }

    fn write(&self, token: &str) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temporary = self.path.with_extension("tmp");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(token.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        std::fs::rename(&temporary, &self.path)?;
        Ok(())
    }
}

/// Returns the default portal restore-token path for `client_id`.
fn default_portal_token_file(client_id: &str) -> PathBuf {
    let component = sanitize_socket_component(client_id);
    let component = if component.is_empty() {
        "client".to_string()
    } else {
        component
    };
    client_state_dir().join(format!("portal-{component}.token"))
}

/// Reduces a connector name to the characters the relay accepts in a label.
fn sanitize_source_label(connector: &str) -> String {
    let label: String = connector
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .take(64)
        .collect();
    let label = label.trim_matches('-').to_string();
    if label.is_empty() {
        "output".to_string()
    } else {
        label
    }
}

/// Stops the cursor sampling task when its connection ends.
struct CursorTaskGuard(Option<tokio::task::JoinHandle<()>>);

impl Drop for CursorTaskGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

async fn sleep_or_shutdown(duration: Duration, shutdown_rx: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(duration) => false,
        _ = wait_for_shutdown(shutdown_rx) => true,
    }
}

async fn run_dash_client(
    args: &Args,
    identity: StreamIdentity<'_>,
    viewer_key: Option<&[u8; 32]>,
    capture: &mut dyn Capture,
    resend: &mut DashResendBuffer,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let mut retry_delay = Duration::from_secs(1);
    loop {
        // Opening a source can block indefinitely on a desktop chooser that
        // nobody answers, so shutdown has to win the race. Otherwise SIGTERM
        // and `--daemon-stop` are ignored for as long as the dialog is open.
        let opened = {
            let mut source_shutdown = shutdown_rx.clone();
            tokio::select! {
                opened = capture.source() => opened,
                _ = wait_for_shutdown(&mut source_shutdown) => {
                    info!("shutdown requested while opening the capture source");
                    return Ok(());
                }
            }
        };
        let source = match opened {
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
        let connection_started = Instant::now();
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
                    return Err(err.context("fatal DASH publisher error"));
                }
                if connection_started.elapsed() >= Duration::from_secs(60) {
                    retry_delay = Duration::from_secs(1);
                }
                let jitter = Duration::from_millis(u64::from(OsRng.next_u32() % 500));
                let wait = retry_delay.saturating_add(jitter);
                warn!(?err, retry_ms = wait.as_millis(), "DASH connection dropped");
                let mut retry_shutdown = shutdown_rx.clone();
                if sleep_or_shutdown(wait, &mut retry_shutdown).await {
                    return Ok(());
                }
                retry_delay = retry_delay.saturating_mul(2).min(Duration::from_secs(30));
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
            || message.contains("server rejected hello")
    })
    // A policy refusal is decided per object and will be decided the same way
    // next time. Retrying it forever hides the reason behind a generic
    // "connection dropped" and leaves the stream flapping. Matched by type
    // rather than by text: the entries above are messages from foreign
    // libraries, where a substring is the only handle there is, but this one is
    // ours -- and rewording it must not quietly restore the retry loop.
    || err.chain().any(|cause| cause.is::<RelayRefused>())
}

/// Marks an error as the relay declining an object on policy.
///
/// Carries no detail of its own: the operator-facing sentence is the relay's,
/// attached as context. This exists so the retry loop can recognise the
/// refusal without matching on that sentence.
#[derive(Debug)]
struct RelayRefused;

impl std::fmt::Display for RelayRefused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the relay refused this object")
    }
}

impl std::error::Error for RelayRefused {}

async fn run_dash_connection(
    args: &Args,
    identity: StreamIdentity<'_>,
    viewer_key: Option<&[u8; 32]>,
    source: &CaptureSource,
    capture: &mut dyn Capture,
    resend: &mut DashResendBuffer,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    if args.segment_frames() == 0 {
        bail!("--segment-frames must be at least 1");
    }
    let ingest_server_key = identity.client.ingest_server_key.as_ref().context(
        "ingest server key is required; pass --ingest-server-key or set ingest_server_key in client.toml",
    )?;
    let mut stream = timeout(
        Duration::from_secs(15),
        TcpStream::connect(args.ingest_addr.as_str()),
    )
    .await
    .context("ingest connection timed out")??;
    stream.set_nodelay(true)?;
    let transport = timeout(
        Duration::from_secs(10),
        initiator_handshake(&mut stream, ingest_server_key),
    )
    .await
    .context("Noise handshake timed out")??;
    let mut socket = NoiseSocket::new(stream, transport);
    let (low, high) = resend.range();
    socket
        .write(&ClientMessage::Hello(StreamHello {
            protocol_version: PROTOCOL_VERSION,
            client_id: identity.client.client_id.clone(),
            auth_token: identity.client.auth_token.clone(),
            // A publisher casting several screens shows one entry per screen
            // in the viewer, so the label has to reach the name a viewer reads.
            display_name: match identity.label {
                Some(label) => format!("{} ({label})", identity.client.display_name),
                None => identity.client.display_name.clone(),
            },
            source: source.clone(),
            source_label: identity.label.map(str::to_string),
            viewer_key_salt: identity.client.viewer_key_salt_b64.clone(),
            resend_low: low,
            resend_high: high,
        }))
        .await?;
    let (stream_id, server_last_sequence) = match socket
        .read_limited::<ServerMessage>(MAX_SERVER_CONTROL_MESSAGE)
        .await?
    {
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
            let expected_sequence = object.header.sequence;
            socket
                .write(&ClientMessage::DashObject(object))
                .await
                .context("resending unacknowledged DASH object")?;
            sequence = wait_for_dash_ack(&mut socket, resend, expected_sequence)
                .await?
                .max(sequence);
        }
    }
    sequence = sequence.max(resend.range().1.unwrap_or(0));

    let first_capture = normalize_captured_dash_frame(
        capture
            .capture_dash_frame(args.max_frame_width, args.max_frame_height)
            .await?,
        None,
    );
    let first_frame = first_capture.frame;
    let width = first_frame.width();
    let height = first_frame.height();
    let frame_duration = ((f64::from(MEDIA_TIMESCALE) / args.fps).round() as u64)
        .clamp(1, u64::from(u32::MAX)) as u32;
    let epoch_id = Uuid::new_v4();
    // One place decides, and everything downstream reads it from the absence of
    // a key rather than from a flag it could disagree with. There may be no key
    // to derive from at all: an unencrypted publisher is not required to have
    // one configured.
    let keys = viewer_key
        .map(|key| {
            EpochKeys::derive(key, stream_id, epoch_id)
                .context("deriving encrypted DASH epoch keys")
        })
        .transpose()?;
    let epoch_keys = keys.as_ref();
    let encoder = EncoderActor::spawn(EncoderConfig {
        mode: args.encoder,
        vaapi_device: args.vaapi_device.clone(),
        openh264_library: args.openh264_library.clone(),
        width,
        height,
        fps: args.fps,
        bitrate: args.video_bitrate,
        segment_frames: args.segment_frames(),
    })?;
    let mut last_frame_fingerprint = first_frame.content_fingerprint();
    let first_encoded = encoder.encode(first_frame.clone(), false).await?;
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
        // Always the epoch's own bytes, which is what EpochKeys derives it from
        // and what the descriptor's validation requires. An unencrypted epoch
        // has no key to identify, and carries the same shape rather than a
        // second one for readers to handle.
        key_id: *epoch_id.as_bytes(),
        width: u16::try_from(width).context("video width does not fit MPEG-DASH metadata")?,
        height: u16::try_from(height).context("video height does not fit MPEG-DASH metadata")?,
        codec,
        timescale: MEDIA_TIMESCALE,
        segment_frames: args.segment_frames(),
        availability_start_time: chrono::Utc::now()
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        encrypted: epoch_keys.is_some(),
    };
    let epoch_started = Instant::now();
    send_new_dash_object(
        &mut socket,
        resend,
        next_dash_object(
            &mut sequence,
            epoch_keys,
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
            epoch_keys,
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
                payload: build_init_segment(&avc_config, epoch_keys.map(|keys| keys.key_id))
                    .context("building the DASH initialization segment")?,
            },
        )?,
    )
    .await?;
    let first_media = build_dash_media_object(
        &mut sequence,
        epoch_keys,
        stream_id,
        epoch_id,
        0,
        0,
        frame_duration,
        args.segment_frames(),
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
        encrypted = epoch_keys.is_some(),
        "MPEG-DASH publisher started"
    );

    let frame_interval = Duration::from_secs_f64(1.0 / args.fps);
    let mut frame_tick =
        tokio::time::interval_at(tokio::time::Instant::now() + frame_interval, frame_interval);
    frame_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let cursor_interval = Duration::from_secs_f64(1.0 / args.cursor_hz.max(1) as f64);
    let mut cursor_tick = tokio::time::interval(cursor_interval);
    cursor_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut cursor_ticks: u64 = 0;
    let mut cursor_samples: u64 = 0;
    let mut cursor_reported = Instant::now();
    let cursor_flush_interval = Duration::from_millis(args.cursor_flush_ms.max(1));
    let mut last_cursor_flush = Instant::now();
    let mut media_index = 1u64;
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "the parser bounds the heartbeat to [0.2, 300] seconds"
    )]
    let heartbeat_ticks = (args.idle_heartbeat_seconds * f64::from(MEDIA_TIMESCALE)).round() as u64;
    let mut media_cadence = AdaptiveMediaCadence::new(u64::from(frame_duration), heartbeat_ticks);
    let mut pending_media: Option<PendingEncodedMedia> = None;
    let mut cursor_sequence = 0u64;
    let mut pending_cursor_events = Vec::new();
    let mut cursor_bitmap_state = DashCursorBitmapState::default();

    // Sample the cursor on its own task when the capture can supply a feed.
    // Video work holds this loop for as long as it takes to unpack, scale and
    // encode a frame; sampling from here would inherit every one of those
    // stalls and stamp the samples late as well. The task only ever produces
    // finished batches, which this loop forwards as soon as it is free, and
    // the viewer's play-out buffer absorbs that delivery jitter.
    let (cursor_batch_tx, mut cursor_batch_rx) = tokio::sync::mpsc::channel(64);
    let cursor_task = match capture.cursor_source().await? {
        Some(mut source) => {
            let interval = cursor_interval;
            let flush_every = cursor_flush_interval;
            Some(tokio::spawn(async move {
                let mut ticker = tokio::time::interval(interval);
                ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
                let mut bitmap_state = DashCursorBitmapState::default();
                let mut pending: Vec<DashCursorEvent> = Vec::new();
                let mut last_flush = Instant::now();
                // How late this task's ticks actually fire. The whole point of
                // running the cursor on its own task is that video work cannot
                // delay it; lateness here is the direct measurement of whether
                // that holds, and it is reported rather than assumed.
                let mut last_tick = Instant::now();
                let mut worst_lateness = Duration::ZERO;
                let mut lateness_reported = Instant::now();
                loop {
                    ticker.tick().await;
                    let now = Instant::now();
                    worst_lateness = worst_lateness.max(
                        now.saturating_duration_since(last_tick)
                            .saturating_sub(interval),
                    );
                    last_tick = now;
                    if lateness_reported.elapsed() >= CAPTURE_RATE_WINDOW {
                        debug!(
                            worst_tick_lateness_ms = worst_lateness.as_millis(),
                            "cursor timeline scheduling"
                        );
                        worst_lateness = Duration::ZERO;
                        lateness_reported = now;
                    }
                    if let Some(cursor) = source.next() {
                        let timestamp = duration_to_media_ticks(epoch_started.elapsed());
                        match cursor_to_dash_event(
                            cursor,
                            timestamp,
                            width,
                            height,
                            &mut bitmap_state,
                        ) {
                            Ok(event) => pending.push(event),
                            Err(err) => {
                                warn!(?err, "dropping an unrepresentable cursor sample");
                            }
                        }
                    }
                    if last_flush.elapsed() >= flush_every && !pending.is_empty() {
                        last_flush = Instant::now();
                        if cursor_batch_tx
                            .send(std::mem::take(&mut pending))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }))
        }
        None => None,
    };
    let sampling_cursor_inline = cursor_task.is_none();
    let _cursor_task = CursorTaskGuard(cursor_task);

    loop {
        tokio::select! {
            _ = wait_for_shutdown(&mut shutdown_rx) => {
                if let Some(duration) =
                    media_cadence.finish(duration_to_media_ticks(epoch_started.elapsed()))
                    && let Some(pending) = pending_media.take()
                {
                    publish_encoded_media(
                        &mut socket,
                        resend,
                        &mut sequence,
                        epoch_keys,
                        stream_id,
                        epoch_id,
                        &mut media_index,
                        pending.timestamp,
                        duration,
                        args.segment_frames(),
                        pending.encoded,
                    ).await?;
                }
                flush_dash_cursor_batch(
                    &mut socket,
                    resend,
                    &mut sequence,
                    epoch_keys,
                    stream_id,
                    epoch_id,
                    width,
                    height,
                    frame_duration,
                    args.segment_frames(),
                    &mut pending_cursor_events,
                ).await?;
                info!(%stream_id, "shutdown requested; closing DASH stream");
                return Ok(());
            }
            _ = frame_tick.tick() => {
                let publish_started = Instant::now();
                // Waiting for a new frame here is fine now that the cursor
                // samples on its own task: this await no longer holds the
                // cursor timeline, only the delivery of already-timestamped
                // batches, which the viewer's play-out buffer absorbs.
                //
                // It must be an unbounded wait. The cadence is a state machine
                // driven by actual frames, so a tick that gives up without one
                // either corrupts it or, if skipped outright, stops the
                // heartbeat and lets a still screen go silent entirely.
                // Waiting for a frame can take most of a second on a screen
                // with nothing moving on it. Cursor batches are already
                // timestamped by then and only need putting on the wire, so
                // service them while waiting rather than letting them queue
                // behind the video timeline -- that queueing is what a viewer
                // sees as a pointer trailing well behind the real one.
                let raw = loop {
                    tokio::select! {
                        biased;
                        Some(events) = cursor_batch_rx.recv() => {
                            pending_cursor_events.extend(events);
                            flush_dash_cursor_batch(
                                &mut socket,
                                resend,
                                &mut sequence,
                                epoch_keys,
                                stream_id,
                                epoch_id,
                                width,
                                height,
                                frame_duration,
                                args.segment_frames(),
                                &mut pending_cursor_events,
                            ).await?;
                        }
                        frame = capture
                            .capture_dash_frame(args.max_frame_width, args.max_frame_height) => {
                            break frame?;
                        }
                    }
                };
                let dequeued_at = Instant::now();
                let capture = normalize_captured_dash_frame(raw, Some((width, height)));
                let normalized_at = Instant::now();
                let fingerprint = capture.frame.content_fingerprint();
                let fingerprinted_at = Instant::now();
                let changed = frame_changed(
                    capture.change,
                    last_frame_fingerprint.as_ref(),
                    fingerprint.as_ref(),
                );
                let decision = media_cadence.observe(
                    duration_to_media_ticks(epoch_started.elapsed()),
                    changed,
                );
                if let Some(duration) = decision.flush_pending_duration {
                    let pending = pending_media
                        .take()
                        .context("adaptive cadence lost its pending encoded frame")?;
                    publish_encoded_media(
                        &mut socket,
                        resend,
                        &mut sequence,
                        epoch_keys,
                        stream_id,
                        epoch_id,
                        &mut media_index,
                        pending.timestamp,
                        duration,
                        args.segment_frames(),
                        pending.encoded,
                    ).await?;
                }
                if let Some(timestamp) = decision.publish_current_timestamp {
                    let encoded = encode_media_frame(
                        &encoder,
                        capture.frame,
                        media_index,
                        args.segment_frames(),
                    ).await?;
                    publish_encoded_media(
                        &mut socket,
                        resend,
                        &mut sequence,
                        epoch_keys,
                        stream_id,
                        epoch_id,
                        &mut media_index,
                        timestamp,
                        frame_duration,
                        args.segment_frames(),
                        encoded,
                    ).await?;
                    last_frame_fingerprint = fingerprint;
                } else if let Some(timestamp) = decision.encode_pending_timestamp {
                    let encoded = encode_media_frame(
                        &encoder,
                        capture.frame,
                        media_index,
                        args.segment_frames(),
                    ).await?;
                    pending_media = Some(PendingEncodedMedia { timestamp, encoded });
                } else {
                    capture.frame.discard();
                }
                debug!(
                    %stream_id,
                    changed,
                    media_index,
                    capture_to_ack_ms = publish_started.elapsed().as_millis(),
                    // Everything after the dequeue runs on the same task as the
                    // cursor timeline, so these are the windows in which cursor
                    // samples cannot be forwarded.
                    wait_ms = dequeued_at.duration_since(publish_started).as_millis(),
                    resize_ms = normalized_at.duration_since(dequeued_at).as_millis(),
                    fingerprint_ms = fingerprinted_at.duration_since(normalized_at).as_millis(),
                    encode_publish_ms = fingerprinted_at.elapsed().as_millis(),
                    pending = pending_media.is_some(),
                    "processed adaptive DASH media cadence"
                );
            }
            Some(events) = cursor_batch_rx.recv() => {
                pending_cursor_events.extend(events);
                flush_dash_cursor_batch(
                    &mut socket,
                    resend,
                    &mut sequence,
                    epoch_keys,
                    stream_id,
                    epoch_id,
                    width,
                    height,
                    frame_duration,
                    args.segment_frames(),
                    &mut pending_cursor_events,
                ).await?;
            }
            _ = cursor_tick.tick(), if sampling_cursor_inline => {
                cursor_sequence = cursor_sequence.saturating_add(1);
                cursor_ticks += 1;
                if cursor_reported.elapsed() >= Duration::from_secs(5) {
                    debug!(
                        %stream_id,
                        ticks_per_second = cursor_ticks / 5,
                        samples_per_second = cursor_samples / 5,
                        "cursor timeline throughput"
                    );
                    cursor_ticks = 0;
                    cursor_samples = 0;
                    cursor_reported = Instant::now();
                }
                if let Some(cursor) = capture.cursor(cursor_sequence).await? {
                    cursor_samples += 1;
                    let timestamp = duration_to_media_ticks(epoch_started.elapsed());
                    pending_cursor_events.push(cursor_to_dash_event(
                        cursor,
                        timestamp,
                        width,
                        height,
                        &mut cursor_bitmap_state,
                    )?);
                }
                // Flushing here rather than from its own timer is deliberate.
                // `select!` completes one branch per iteration, so a separate
                // flush tick competes with this sampler for iterations and, at
                // 60 Hz against a loop that also encodes video, loses almost
                // every time: samples pile up and ship in rare huge batches,
                // which the viewer can only render as a frozen cursor.
                if last_cursor_flush.elapsed() >= cursor_flush_interval {
                    last_cursor_flush = Instant::now();
                    flush_dash_cursor_batch(
                        &mut socket,
                        resend,
                        &mut sequence,
                        epoch_keys,
                        stream_id,
                        epoch_id,
                        width,
                        height,
                        frame_duration,
                        args.segment_frames(),
                        &mut pending_cursor_events,
                    ).await?;
                }
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

struct PendingEncodedMedia {
    timestamp: u64,
    encoded: dash_encoder::EncodedH264Frame,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct MediaCadenceDecision {
    flush_pending_duration: Option<u32>,
    publish_current_timestamp: Option<u64>,
    encode_pending_timestamp: Option<u64>,
}

#[derive(Debug)]
struct AdaptiveMediaCadence {
    frame_duration: u64,
    heartbeat_ticks: u64,
    media_end: u64,
    pending_timestamp: Option<u64>,
}

impl AdaptiveMediaCadence {
    fn new(frame_duration: u64, heartbeat_ticks: u64) -> Self {
        Self {
            frame_duration,
            heartbeat_ticks: heartbeat_ticks.max(frame_duration).min(u64::from(u32::MAX)),
            media_end: frame_duration,
            pending_timestamp: None,
        }
    }

    fn observe(&mut self, timestamp: u64, changed: bool) -> MediaCadenceDecision {
        if changed {
            let mut decision = MediaCadenceDecision::default();
            if let Some(pending_timestamp) = self.pending_timestamp.take() {
                let duration = timestamp
                    .saturating_sub(pending_timestamp)
                    .clamp(1, u64::from(u32::MAX)) as u32;
                decision.flush_pending_duration = Some(duration);
                self.media_end = pending_timestamp.saturating_add(u64::from(duration));
            }
            let current_timestamp = timestamp.max(self.media_end);
            decision.publish_current_timestamp = Some(current_timestamp);
            self.media_end = current_timestamp.saturating_add(self.frame_duration);
            return decision;
        }

        if self.pending_timestamp.is_none() && timestamp >= self.media_end {
            self.pending_timestamp = Some(self.media_end);
            return MediaCadenceDecision {
                encode_pending_timestamp: self.pending_timestamp,
                ..MediaCadenceDecision::default()
            };
        }
        let Some(pending_timestamp) = self.pending_timestamp else {
            return MediaCadenceDecision::default();
        };
        if timestamp.saturating_sub(pending_timestamp) < self.heartbeat_ticks {
            return MediaCadenceDecision::default();
        }
        let duration = timestamp
            .saturating_sub(pending_timestamp)
            .clamp(1, u64::from(u32::MAX)) as u32;
        self.media_end = pending_timestamp.saturating_add(u64::from(duration));
        self.pending_timestamp = Some(self.media_end);
        MediaCadenceDecision {
            flush_pending_duration: Some(duration),
            encode_pending_timestamp: self.pending_timestamp,
            ..MediaCadenceDecision::default()
        }
    }

    fn finish(&mut self, timestamp: u64) -> Option<u32> {
        let pending_timestamp = self.pending_timestamp.take()?;
        let duration = timestamp
            .max(pending_timestamp.saturating_add(1))
            .saturating_sub(pending_timestamp)
            .clamp(1, u64::from(u32::MAX)) as u32;
        self.media_end = pending_timestamp.saturating_add(u64::from(duration));
        Some(duration)
    }
}

fn frame_changed(
    change: FrameChange,
    previous_fingerprint: Option<&[u8; 32]>,
    current_fingerprint: Option<&[u8; 32]>,
) -> bool {
    if let (Some(previous), Some(current)) = (previous_fingerprint, current_fingerprint) {
        return previous != current;
    }
    match change {
        FrameChange::Changed => true,
        FrameChange::Unchanged => false,
        FrameChange::Unknown => true,
    }
}

/// Builds the next object in sequence, authenticated when the epoch has a key.
///
/// `keys` is `None` for an epoch published without encryption: there is no
/// viewer key, so there is nothing to authenticate with. The payload hash is
/// still written and still checked on the way out.
fn next_dash_object(
    sequence: &mut u64,
    keys: Option<&EpochKeys>,
    spec: DashObjectSpec<'_>,
) -> Result<DashObject> {
    *sequence = sequence.checked_add(1).context("DASH sequence exhausted")?;
    let input = NewDashObject {
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
    };
    match keys {
        Some(keys) => DashObject::authenticated(input, keys).context("authenticating DASH object"),
        None => DashObject::unauthenticated(input).context("building unauthenticated DASH object"),
    }
}

/// Runs the H.264 encoder on a thread of its own.
///
/// The VA-API encoder holds thread-affine handles and is deliberately not
/// `Send`, so it cannot simply be moved onto a blocking pool. Owning it on a
/// dedicated thread and talking to it over channels keeps every millisecond of
/// encoding off the runtime thread, which is what lets the cursor task be
/// scheduled while a frame is encoded.
struct EncoderActor {
    requests: std::sync::mpsc::Sender<EncodeRequest>,
    thread: Option<std::thread::JoinHandle<()>>,
    backend_name: &'static str,
}

impl EncoderActor {
    /// Names the encoder backend the thread actually built.
    fn backend_name(&self) -> &'static str {
        self.backend_name
    }
}

/// One frame to encode, with the channel its result comes back on.
struct EncodeRequest {
    frame: DashInputFrame,
    segment_start: bool,
    reply: tokio::sync::oneshot::Sender<Result<dash_encoder::EncodedH264Frame>>,
}

impl EncoderActor {
    /// Starts the encoder on its own thread.
    ///
    /// Construction happens on that thread too, because the encoder is not
    /// `Send` and so cannot be built here and moved across.
    fn spawn(config: EncoderConfig) -> Result<Self> {
        let (requests, rx) = std::sync::mpsc::channel::<EncodeRequest>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<&'static str>>();
        let thread = std::thread::Builder::new()
            .name("glacialcast-encode".to_string())
            .spawn(move || {
                let mut encoder = match DashH264Encoder::new(
                    config.mode,
                    &config.vaapi_device,
                    config.openh264_library.as_deref(),
                    config.width,
                    config.height,
                    config.fps,
                    config.bitrate,
                    config.segment_frames,
                ) {
                    Ok(encoder) => {
                        let _ = ready_tx.send(Ok(encoder.backend_name()));
                        encoder
                    }
                    Err(err) => {
                        let _ = ready_tx.send(Err(err));
                        return;
                    }
                };
                while let Ok(request) = rx.recv() {
                    let result = encoder
                        .encode(&request.frame, request.segment_start)
                        .and_then(|encoded| {
                            if request.segment_start && !encoded.keyframe {
                                bail!(
                                    "H.264 encoder did not produce an IDR at the segment boundary"
                                );
                            }
                            Ok(encoded)
                        });
                    // A caller that went away simply drops the result.
                    let _ = request.reply.send(result);
                }
            })
            .context("spawning encoder thread")?;
        let backend_name = ready_rx
            .recv()
            .context("encoder thread stopped before reporting readiness")??;
        Ok(Self {
            requests,
            thread: Some(thread),
            backend_name,
        })
    }

    /// Encodes one frame, awaiting the dedicated thread rather than blocking.
    async fn encode(
        &self,
        frame: DashInputFrame,
        segment_start: bool,
    ) -> Result<dash_encoder::EncodedH264Frame> {
        let (reply, response) = tokio::sync::oneshot::channel();
        self.requests
            .send(EncodeRequest {
                frame,
                segment_start,
                reply,
            })
            .map_err(|_| anyhow::anyhow!("encoder thread stopped"))?;
        response
            .await
            .context("encoder thread dropped the request")?
    }
}

impl Drop for EncoderActor {
    fn drop(&mut self) {
        // Closing the request channel ends the loop; join so the encoder is
        // fully torn down before the capture it borrows from goes away.
        let (dead, _) = std::sync::mpsc::channel();
        let _ = std::mem::replace(&mut self.requests, dead);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Everything the encoder thread needs to build its encoder.
struct EncoderConfig {
    mode: DashEncoderMode,
    vaapi_device: PathBuf,
    openh264_library: Option<PathBuf>,
    width: u32,
    height: u32,
    fps: f64,
    bitrate: u32,
    segment_frames: u16,
}

async fn encode_media_frame(
    encoder: &EncoderActor,
    frame: DashInputFrame,
    media_index: u64,
    segment_frames: u16,
) -> Result<dash_encoder::EncodedH264Frame> {
    let segment_start = media_index.is_multiple_of(u64::from(segment_frames));
    encoder.encode(frame, segment_start).await
}

#[allow(clippy::too_many_arguments)]
async fn publish_encoded_media(
    socket: &mut NoiseSocket<TcpStream>,
    resend: &mut DashResendBuffer,
    sequence: &mut u64,
    keys: Option<&EpochKeys>,
    stream_id: Uuid,
    epoch_id: Uuid,
    media_index: &mut u64,
    timestamp: u64,
    duration: u32,
    segment_frames: u16,
    encoded: dash_encoder::EncodedH264Frame,
) -> Result<()> {
    let object = build_dash_media_object(
        sequence,
        keys,
        stream_id,
        epoch_id,
        *media_index,
        timestamp,
        duration,
        segment_frames,
        &encoded,
    )?;
    let bytes = object.payload.len();
    let sent_sequence = object.header.sequence;
    send_new_dash_object(socket, resend, object).await?;
    debug!(
        %stream_id,
        sequence = sent_sequence,
        media_index = *media_index,
        timestamp,
        duration,
        keyframe = encoded.keyframe,
        bytes,
        "sent DASH media fragment"
    );
    *media_index = media_index.saturating_add(1);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_dash_media_object(
    sequence: &mut u64,
    keys: Option<&EpochKeys>,
    stream_id: Uuid,
    epoch_id: Uuid,
    media_index: u64,
    timestamp: u64,
    frame_duration: u32,
    segment_frames: u16,
    encoded: &dash_encoder::EncodedH264Frame,
) -> Result<DashObject> {
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    let fragment = build_fragment(
        keys.map(|keys| &keys.cenc_key),
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
    .context("building the DASH media fragment")?;
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

fn normalize_captured_dash_frame(
    capture: CapturedDashFrame,
    target: Option<(u32, u32)>,
) -> CapturedDashFrame {
    CapturedDashFrame {
        frame: normalize_dash_input(capture.frame, target),
        change: capture.change,
    }
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
    let x_micropixels =
        scaled_cursor_coordinate(cursor.x, source_width, output_width, cursor.visible);
    let y_micropixels =
        scaled_cursor_coordinate(cursor.y, source_height, output_height, cursor.visible);
    let (bitmap_id, bitmap) = match cursor.bitmap {
        Some(bitmap) if bitmap_state.last.as_ref() == Some(&bitmap) => {
            let refresh_due = bitmap_state
                .last_sent_timestamp
                .is_none_or(|last| timestamp.saturating_sub(last) >= CURSOR_BITMAP_REFRESH_TICKS);
            if refresh_due {
                bitmap_state.last_sent_timestamp = Some(timestamp);
                (bitmap_state.current_id, Some(dash_cursor_bitmap(&bitmap)?))
            } else {
                (bitmap_state.current_id, None)
            }
        }
        Some(bitmap) => {
            bitmap_state.current_id = bitmap_state.current_id.wrapping_add(1).max(1);
            bitmap_state.last = Some(Arc::clone(&bitmap));
            bitmap_state.last_sent_timestamp = Some(timestamp);
            (bitmap_state.current_id, Some(dash_cursor_bitmap(&bitmap)?))
        }
        None => (bitmap_state.current_id, None),
    };
    Ok(DashCursorEvent {
        timestamp,
        x_micropixels,
        y_micropixels,
        visible: cursor.visible,
        bitmap_id,
        bitmap,
    })
}

fn scaled_cursor_coordinate(
    value: f32,
    source_extent: u32,
    output_extent: u32,
    visible: bool,
) -> i64 {
    if !visible || !value.is_finite() || output_extent == 0 {
        return 0;
    }
    let scaled = f64::from(value) * f64::from(output_extent) / f64::from(source_extent.max(1));
    (scaled.clamp(0.0, f64::from(output_extent)) * 1_000_000.0).round() as i64
}

fn dash_cursor_bitmap(bitmap: &CursorBitmap) -> Result<DashCursorBitmap> {
    let expected_len = usize::try_from(bitmap.width)
        .ok()
        .and_then(|width| {
            usize::try_from(bitmap.height)
                .ok()
                .and_then(|height| width.checked_mul(height))
        })
        .and_then(|pixels| pixels.checked_mul(4))
        .context("PipeWire cursor bitmap dimensions overflow")?;
    if bitmap.rgba.len() != expected_len {
        bail!("PipeWire cursor bitmap dimensions do not match its RGBA payload");
    }
    Ok(DashCursorBitmap {
        width: bitmap.width,
        height: bitmap.height,
        hotspot_x: bitmap.hotspot_x,
        hotspot_y: bitmap.hotspot_y,
        rgba: bitmap.rgba.to_vec(),
    })
}

#[derive(Default)]
struct DashCursorBitmapState {
    current_id: u64,
    last: Option<Arc<CursorBitmap>>,
    last_sent_timestamp: Option<u64>,
}

#[allow(clippy::too_many_arguments)]
async fn flush_dash_cursor_batch(
    socket: &mut NoiseSocket<TcpStream>,
    resend: &mut DashResendBuffer,
    sequence: &mut u64,
    keys: Option<&EpochKeys>,
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
    let context = DashCursorContext {
        stream_id,
        epoch_id,
        sequence: next_sequence,
        start_timestamp,
        source_width: width,
        source_height: height,
    };
    // Same validation either way; an epoch with no key simply has nothing to
    // seal the batch with, so it carries the encoded form directly.
    let payload = match keys {
        Some(keys) => encrypt_cursor_batch(keys, context, &batch)
            .context("encrypting cursor batch")?
            .to_bytes()
            .context("serializing encrypted cursor batch")?,
        None => encode_plain_cursor_batch(context, &batch).context("encoding cursor batch")?,
    };
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
            payload,
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
    let expected_sequence = object.header.sequence;
    resend.push(object.clone());
    socket.write(&ClientMessage::DashObject(object)).await?;
    debug!(%stream_id, buffered_bytes = resend.bytes, "DASH object queued for acknowledgement");
    wait_for_dash_ack(socket, resend, expected_sequence).await?;
    Ok(())
}

async fn wait_for_dash_ack(
    socket: &mut NoiseSocket<TcpStream>,
    resend: &mut DashResendBuffer,
    expected_sequence: u64,
) -> Result<u64> {
    loop {
        match socket
            .read_limited::<ServerMessage>(MAX_SERVER_CONTROL_MESSAGE)
            .await?
        {
            ServerMessage::Ack { through_seq } => {
                resend.ack(through_seq);
                if through_seq >= expected_sequence {
                    return Ok(through_seq);
                }
                debug!(
                    through_seq,
                    expected_sequence, "ignoring stale DASH acknowledgement"
                );
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
            ServerMessage::Refused { sequence, reason } => {
                // The relay has declined this object on policy, not on
                // capacity, so every reconnect would produce the same refusal.
                // Carrying the relay's own sentence out to the operator is the
                // entire point of the message.
                return Err(anyhow::Error::new(RelayRefused)
                    .context(format!("relay refused object {sequence}: {reason}")));
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
    let config_source = if args.no_config {
        ConfigSource::Defaults
    } else {
        config_path::resolve(args.config.clone(), "client.toml")
    };
    let config = load_client_config_from(&config_source)?;
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
    let configured_viewer_key = args
        .viewer_key
        .clone()
        .or(config.viewer_key_b64)
        .map(|key| non_empty_trimmed("viewer_key_b64", key))
        .transpose()?;
    let viewer_key_file = if args.no_viewer_key || configured_viewer_key.is_some() {
        None
    } else {
        Some(
            args.viewer_key_file
                .clone()
                .unwrap_or_else(|| default_viewer_key_file(&client_id)),
        )
    };
    let configured_phrase = args
        .viewer_key_phrase
        .clone()
        .or(config.viewer_key_phrase)
        .map(|phrase| non_empty_trimmed("viewer_key_phrase", phrase))
        .transpose()?;
    let viewer_key = match (&configured_viewer_key, &configured_phrase, &viewer_key_file) {
        (Some(key), _, _) => Some(ViewerKeyMaterial::from_raw_b64(key.clone())),
        // A chosen phrase still needs a salt, and it must be the same one on
        // every restart or viewers would have to be told the key again. The
        // salt file serves that purpose; only the phrase within it is replaced.
        (None, Some(phrase), path) => {
            let salt = match path {
                Some(path) => load_or_create_viewer_key(path, args.new_viewer_key)?
                    .salt_b64
                    .and_then(|encoded| viewer_key::decode_salt(&encoded)),
                None => None,
            }
            .unwrap_or(DERIVED_PHRASE_FALLBACK_SALT);
            Some(ViewerKeyMaterial::from_phrase(phrase, &salt)?)
        }
        (None, None, Some(path)) => Some(load_or_create_viewer_key(path, args.new_viewer_key)?),
        (None, None, None) => None,
    };
    if let Some(phrase) = &configured_phrase
        && viewer_key::normalize_phrase(phrase).ok().as_deref()
            == viewer_key::normalize_phrase(EXAMPLE_VIEWER_KEY_PHRASE)
                .ok()
                .as_deref()
    {
        // Printed rather than logged, so it reaches an operator running this by
        // hand as well as one reading a journal.
        eprintln!(
            "WARNING: publishing under the example viewer key phrase. It is in the \n\
             shipped configuration and the documentation, so anyone who can reach \n\
             the relay can decrypt this stream. Set viewer_key_phrase in \n\
             client.toml, or remove it to have a private one generated."
        );
    }
    let viewer_key_b64 = viewer_key.as_ref().map(|key| key.key_b64.clone());
    let viewer_key_shareable = viewer_key.as_ref().map(|key| key.shareable.clone());
    let viewer_key_salt_b64 = viewer_key.as_ref().and_then(|key| key.salt_b64.clone());
    let display_name = args
        .display_name
        .clone()
        .or(config.display_name)
        .unwrap_or_else(|| "Glacialcast client".to_string());
    let display_name = non_empty_trimmed("display_name", display_name)?;
    let viewer_url = args
        .viewer_url
        .clone()
        .or(config.viewer_url)
        .map(|url| non_empty_trimmed("viewer_url", url))
        .transpose()?;

    Ok(ClientIdentity {
        client_id,
        auth_token,
        ingest_server_key,
        viewer_key_b64,
        viewer_key_shareable,
        viewer_key_salt_b64,
        display_name,
        viewer_key_file,
        viewer_url,
        config_path: config_source.path().map(std::path::Path::to_path_buf),
        all_monitors: config.all_monitors.unwrap_or(false),
    })
}

/// Returns the per-user directory that holds generated client state.
///
/// Generated material is kept out of the working directory because the
/// publisher detaches by default and may be started from anywhere.
fn client_state_dir() -> PathBuf {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .map(|home| home.join(".local").join("state"))
        })
        .unwrap_or_else(std::env::temp_dir);
    base.join("glacialcast")
}

/// Returns the default persisted viewer-key path for `client_id`.
fn default_viewer_key_file(client_id: &str) -> PathBuf {
    let component = sanitize_socket_component(client_id);
    let component = if component.is_empty() {
        "client".to_string()
    } else {
        component
    };
    client_state_dir().join(format!("viewer-{component}.key"))
}

/// Returns the default detached-publisher log path for `client_id`.
fn default_log_file(client_id: &str) -> PathBuf {
    let component = sanitize_socket_component(client_id);
    let component = if component.is_empty() {
        "client".to_string()
    } else {
        component
    };
    client_state_dir().join(format!("client-{component}.log"))
}

/// Reads the persisted viewer key, creating a fresh one when absent.
///
/// The key is 32 random bytes rendered as URL-safe base64 without padding.
/// Persisting it is what makes the published key stable: restarting the
/// publisher, or reconnecting after a relay outage, republishes under the same
/// key so viewers do not need a new secret. The file must be a private regular
/// file with mode 0600 and is created that way.
///
/// # Errors
///
/// Returns an error when the file exists but is group- or world-accessible, is
/// not a regular file, or does not contain exactly one 32-byte key.
/// A viewer key, in both the form shared with people and the form used as key
/// material.
///
/// These differ because a key phrase is what someone can actually retype from a
/// message, while the 32 bytes derived from it are what the media is encrypted
/// under. Keeping both together means the summary can never print a phrase that
/// does not produce the key in use.
#[derive(Debug, Clone)]
struct ViewerKeyMaterial {
    /// The form handed to viewers: a key phrase, or raw base64 for a key that
    /// predates phrases or was supplied on the command line.
    shareable: String,
    /// URL-safe base64 of the 32 key bytes.
    key_b64: String,
    /// Public per-publisher salt, present only for a derived key.
    salt_b64: Option<String>,
}

impl ViewerKeyMaterial {
    /// Wraps a raw 32-byte key given as URL-safe base64.
    fn from_raw_b64(key_b64: String) -> Self {
        Self {
            shareable: key_b64.clone(),
            key_b64,
            salt_b64: None,
        }
    }

    /// Derives key material from a phrase and its salt.
    fn from_phrase(phrase: &str, salt: &[u8; viewer_key::SALT_LEN]) -> Result<Self> {
        let canonical =
            viewer_key::normalize_phrase(phrase).map_err(|error| anyhow::anyhow!("{error}"))?;
        let key = viewer_key::derive_viewer_key_normalized(&canonical, salt);
        Ok(Self {
            shareable: canonical,
            key_b64: encode_key_b64(&key),
            salt_b64: Some(viewer_key::encode_salt(salt)),
        })
    }
}

/// Loads the persisted viewer key, creating a fresh key phrase if there is none.
///
/// `regenerate` replaces an existing key, which invalidates every key already
/// shared for this publisher.
fn load_or_create_viewer_key(
    path: &std::path::Path,
    regenerate: bool,
) -> Result<ViewerKeyMaterial> {
    if !regenerate {
        match read_viewer_key(path) {
            Ok(material) => return Ok(material),
            Err(err) if path.exists() => return Err(err),
            Err(_) => {}
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating viewer key directory {}", parent.display()))?;
    }
    let phrase = viewer_key::generate_phrase().context("generating a viewer key phrase")?;
    let salt = viewer_key::generate_salt().context("generating a viewer key salt")?;
    let material = ViewerKeyMaterial::from_phrase(&phrase, &salt)?;
    let contents = format!(
        "{VIEWER_KEY_PHRASE_PREFIX}{}\n{VIEWER_KEY_SALT_PREFIX}{}\n",
        material.shareable,
        material.salt_b64.as_deref().unwrap_or_default(),
    );

    let mut options = std::fs::OpenOptions::new();
    options
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    if regenerate {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            // Another publisher for the same client id won the race; its key is
            // the one to publish under.
            return read_viewer_key(path);
        }
        Err(err) => {
            return Err(err).with_context(|| format!("creating viewer key {}", path.display()));
        }
    };
    file.write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
        .with_context(|| format!("writing viewer key {}", path.display()))?;
    Ok(material)
}

/// Marks the key-phrase line of a viewer key file.
const VIEWER_KEY_PHRASE_PREFIX: &str = "phrase ";
/// Marks the salt line of a viewer key file.
const VIEWER_KEY_SALT_PREFIX: &str = "salt ";

/// Reads and validates a persisted viewer key.
///
/// Two formats are accepted: the current phrase-and-salt pair, and a bare
/// base64 key from before phrases existed. The older form keeps working
/// untouched, because rewriting it would silently change the key every viewer
/// already holds.
fn read_viewer_key(path: &std::path::Path) -> Result<ViewerKeyMaterial> {
    let raw = read_viewer_key_file(path)?;
    let mut phrase = None;
    let mut salt = None;
    for line in raw.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix(VIEWER_KEY_PHRASE_PREFIX) {
            phrase = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix(VIEWER_KEY_SALT_PREFIX) {
            salt = Some(value.trim().to_string());
        }
    }

    match (phrase, salt) {
        (Some(phrase), Some(salt_b64)) => {
            let salt = viewer_key::decode_salt(&salt_b64).with_context(|| {
                format!(
                    "viewer key {} salt must be URL-safe base64 for {} bytes",
                    path.display(),
                    viewer_key::SALT_LEN
                )
            })?;
            ViewerKeyMaterial::from_phrase(&phrase, &salt)
                .with_context(|| format!("viewer key {} has an invalid phrase", path.display()))
        }
        (None, None) => {
            let key = non_empty_trimmed("viewer key", raw)?;
            decode_key_b64(&key).with_context(|| {
                format!(
                    "viewer key {} must be URL-safe base64 for 32 bytes",
                    path.display()
                )
            })?;
            Ok(ViewerKeyMaterial::from_raw_b64(key))
        }
        _ => bail!(
            "viewer key {} must contain both a phrase and a salt",
            path.display()
        ),
    }
}

/// Opens a viewer key file, enforcing that it is private and regular.
fn read_viewer_key_file(path: &std::path::Path) -> Result<String> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening viewer key {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        bail!(
            "viewer key {} must be a private regular file with mode 0600",
            path.display()
        );
    }
    let mut raw = String::new();
    file.read_to_string(&mut raw)
        .with_context(|| format!("reading viewer key {}", path.display()))?;
    Ok(raw)
}

fn non_empty_trimmed(field: &str, value: String) -> Result<String> {
    let value = value.trim().to_string();
    if value.is_empty() {
        bail!("{field} must not be empty");
    }
    Ok(value)
}

/// Loads the configuration named by `source`.
///
/// A file the operator named must exist. Falling back to defaults there would
/// publish with a generated client id and no ingest token because of a typo in
/// a unit file, which looks like a working service until nobody can find the
/// stream.
fn load_client_config_from(source: &ConfigSource) -> Result<ClientConfig> {
    let Some(path) = source.path() else {
        return Ok(ClientConfig::default());
    };
    if source.must_exist() && !path.exists() {
        bail!(
            "client config {} does not exist.\nSearched when none is given: {}",
            path.display(),
            config_path::search_paths("client.toml")
                .iter()
                .map(|candidate| candidate.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    load_client_config(&path.to_path_buf())
}

fn load_client_config(path: &PathBuf) -> Result<ClientConfig> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ClientConfig::default());
        }
        Err(err) => {
            return Err(err)
                .with_context(|| format!("inspecting client config {}", path.display()));
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening client config {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        bail!(
            "client config {} must be a private regular file with mode 0600",
            path.display()
        );
    }
    let mut raw = String::new();
    file.read_to_string(&mut raw)
        .with_context(|| format!("reading client config {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("parsing client config {}", path.display()))
}

/// Whether the frame period alone reaches the sample duration that stalls Firefox.
///
/// The cliff sits at roughly one second (0.95s plays, 1.0s stalls, and the
/// boundary drifts between runs), so this warns from 0.8s nominal -- capture
/// jitter stretches real inter-frame gaps past the nominal period.
fn update_rate_outlasts_firefox(fps: f64) -> bool {
    fps.recip() > 0.8
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

/// Parses the cursor batch flush interval in milliseconds.
///
/// The lower bound keeps a publisher from turning every cursor sample into its
/// own relay object, and the upper bound keeps live cursor latency bounded.
fn parse_cursor_flush_ms(value: &str) -> std::result::Result<u64, String> {
    let milliseconds = value
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("invalid cursor flush interval {value:?}"))?;
    if !(20..=1000).contains(&milliseconds) {
        return Err("cursor flush interval must be between 20 and 1000 milliseconds".to_string());
    }
    Ok(milliseconds)
}

fn parse_idle_heartbeat_seconds(value: &str) -> std::result::Result<f64, String> {
    let seconds = value
        .trim()
        .parse::<f64>()
        .map_err(|_| format!("invalid idle heartbeat {value:?}"))?;
    if !seconds.is_finite() || !(0.2..=300.0).contains(&seconds) {
        return Err("idle heartbeat must be between 0.2 and 300 seconds".to_string());
    }
    Ok(seconds)
}

struct PipewireThreadStop {
    mainloop_ptr: Arc<Mutex<Option<usize>>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl PipewireThreadStop {
    fn stop(&mut self) {
        let mut mainloop_ptr = self
            .mainloop_ptr
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(ptr) = mainloop_ptr.take() {
            // SAFETY: the PipeWire thread clears this slot while holding the
            // same mutex before it drops the main loop. Holding the lock here
            // therefore keeps `ptr` alive for the duration of the call.
            unsafe {
                pw::sys::pw_main_loop_quit(ptr as *mut _);
            }
        }
        drop(mainloop_ptr);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct PublishedPipewireMainloop {
    slot: Arc<Mutex<Option<usize>>>,
}

impl PublishedPipewireMainloop {
    fn new(slot: Arc<Mutex<Option<usize>>>, ptr: usize) -> Self {
        *slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(ptr);
        Self { slot }
    }
}

impl Drop for PublishedPipewireMainloop {
    fn drop(&mut self) {
        *self
            .slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
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
    ) -> Result<CapturedDashFrame> {
        Ok(CapturedDashFrame {
            frame: DashInputFrame::Rgb(self.capture_rgb(max_width, max_height).await?),
            change: FrameChange::Unknown,
        })
    }
    async fn cursor(&mut self, seq: u64) -> Result<Option<CursorMessage>>;

    /// Returns a cursor feed that can be polled from another task.
    ///
    /// `None` keeps the caller sampling inline, which is what the synthetic
    /// test source does because it derives the cursor from its own frame
    /// counter rather than from capture metadata.
    async fn cursor_source(&mut self) -> Result<Option<PipewireCursorSource>> {
        Ok(None)
    }
}

struct CapturedDashFrame {
    frame: DashInputFrame,
    change: FrameChange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameChange {
    Changed,
    Unchanged,
    Unknown,
}

struct TestPatternCapture {
    width: u32,
    height: u32,
    tick: u32,
    mode: TestPatternMode,
}

impl TestPatternCapture {
    fn new(width: u32, height: u32, mode: TestPatternMode) -> Self {
        Self {
            width,
            height,
            tick: 0,
            mode,
        }
    }

    fn next_rgb(&mut self) -> ImageBuffer<Rgb<u8>, Vec<u8>> {
        self.tick = self.tick.wrapping_add(1);
        let mut image = ImageBuffer::<Rgb<u8>, Vec<u8>>::new(self.width, self.height);
        for (x, y, pixel) in image.enumerate_pixels_mut() {
            *pixel = test_pattern_pixel(self.mode, self.tick, x, y);
        }
        image
    }

    fn frame_changed(&self) -> bool {
        match self.mode {
            TestPatternMode::Static => self.tick == 1,
            TestPatternMode::Typing => self.tick == 1 || self.tick.is_multiple_of(4),
            TestPatternMode::Scroll | TestPatternMode::Motion => true,
        }
    }
}

#[async_trait]
impl Capture for TestPatternCapture {
    async fn source(&mut self) -> Result<CaptureSource> {
        Ok(CaptureSource {
            backend: "test-pattern".to_string(),
            description: format!("Generated {:?} low-bandwidth profile", self.mode),
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

    async fn capture_dash_frame(
        &mut self,
        max_width: u32,
        max_height: u32,
    ) -> Result<CapturedDashFrame> {
        let image = resize_rgb_image_to_fit(self.next_rgb(), max_width, max_height);
        Ok(CapturedDashFrame {
            frame: DashInputFrame::Rgb(image),
            change: if self.frame_changed() {
                FrameChange::Changed
            } else {
                FrameChange::Unchanged
            },
        })
    }

    async fn cursor(&mut self, seq: u64) -> Result<Option<CursorMessage>> {
        let t = seq as f32 / 30.0;
        Ok(Some(CursorMessage {
            x: ((t.sin() + 1.0) * 0.5) * self.width as f32,
            y: ((t.cos() + 1.0) * 0.5) * self.height as f32,
            visible: test_pattern_cursor_visible(seq),
            source_width: self.width,
            source_height: self.height,
            bitmap: None,
        }))
    }
}

fn test_pattern_pixel(mode: TestPatternMode, tick: u32, x: u32, y: u32) -> Rgb<u8> {
    match mode {
        TestPatternMode::Static => Rgb([
            (x % 251) as u8,
            (y % 241) as u8,
            (((x / 8) + (y / 8)) % 239) as u8,
        ]),
        TestPatternMode::Typing => {
            let typed = (tick / 4).saturating_mul(24);
            if (64..88).contains(&y) && (64..64u32.saturating_add(typed)).contains(&x) {
                Rgb([235, 235, 225])
            } else {
                Rgb([24, 28, 34])
            }
        }
        TestPatternMode::Scroll => {
            let shifted_y = y.wrapping_add(tick.saturating_mul(12));
            let band = (shifted_y / 48) % 4;
            Rgb([
                (40 + band * 35) as u8,
                ((x / 8 + band * 17) % 255) as u8,
                (90 + band * 25) as u8,
            ])
        }
        TestPatternMode::Motion => Rgb([
            ((x + tick * 17) % 255) as u8,
            ((y + tick * 29) % 255) as u8,
            (((x / 8) + (y / 8) + tick * 11) % 255) as u8,
        ]),
    }
}

fn test_pattern_cursor_visible(sequence: u64) -> bool {
    sequence % 30 < 20
}

struct WaylandPipewireCapture {
    /// A session already granted before this capture started, used by the
    /// portal path where one dialog approves every selected output.
    opened: Option<ScreenCastCapture>,
    fps: f64,
    cursor_hz: u64,
    /// Frame size the encoder wants, so the readback can shrink on the GPU
    /// rather than moving full-size pixels the CPU is about to discard.
    target_width: u32,
    target_height: u32,
    portal_source: PortalSourceMode,
    screencast_backend: ScreenCastBackend,
    monitor_name: Option<String>,
    portal_cursor: PortalCursorMode,
    require_cursor_metadata: bool,
    prefer_dmabuf: bool,
    gpu_device: PathBuf,
    inner: Option<NativePipewireCapture>,
}

impl WaylandPipewireCapture {
    fn new(args: &Args, target: PublishTarget) -> Self {
        Self {
            opened: target.opened,
            fps: args.fps,
            cursor_hz: args.cursor_hz,
            portal_source: args.portal_source,
            screencast_backend: target.backend,
            monitor_name: target.connector,
            portal_cursor: args.portal_cursor,
            require_cursor_metadata: args.require_cursor_metadata,
            target_width: args.max_frame_width,
            target_height: args.max_frame_height,
            prefer_dmabuf: args.capture == CaptureMode::Wayland
                && should_capture_dmabuf(args.encoder, &args.vaapi_device),
            gpu_device: args.vaapi_device.clone(),
            inner: None,
        }
    }

    async fn ensure_started(&mut self) -> Result<&mut NativePipewireCapture> {
        if self.inner.is_none() {
            // A grant opened before the publisher threads started is consumed
            // once. Reconnecting after that reopens through the normal path,
            // which is also what re-prompts if the portal grant has lapsed.
            self.inner = Some(
                NativePipewireCapture::start(
                    NativePipewireCaptureConfig {
                        fps: self.fps,
                        cursor_hz: self.cursor_hz,
                        target_width: self.target_width,
                        target_height: self.target_height,
                        portal_source: self.portal_source,
                        screencast_backend: self.screencast_backend,
                        monitor_name: self.monitor_name.as_deref(),
                        portal_cursor: self.portal_cursor,
                        require_cursor_metadata: self.require_cursor_metadata,
                        prefer_dmabuf: self.prefer_dmabuf,
                        gpu_device: &self.gpu_device,
                    },
                    self.opened.take(),
                )
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
    ) -> Result<CapturedDashFrame> {
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

    async fn cursor_source(&mut self) -> Result<Option<PipewireCursorSource>> {
        let inner = self.ensure_started().await?;
        Ok(Some(PipewireCursorSource {
            latest: inner.cursor_latest.clone(),
            last_serial: inner.last_cursor_serial,
        }))
    }
}

/// A cursor feed that can be driven independently of video capture.
///
/// Cursor metadata rides on capture buffers, but reading it needs nothing from
/// the capture object itself: the PipeWire thread publishes each sample to a
/// watch channel. Handing a receiver to its own task is what keeps cursor
/// sampling off the timeline that unpacks, scales, and encodes video.
struct PipewireCursorSource {
    latest: watch::Receiver<Option<PipewireCursorSample>>,
    last_serial: u64,
}

impl PipewireCursorSource {
    /// Returns the newest sample if it has not been returned already.
    fn next(&mut self) -> Option<CursorMessage> {
        let sample = self.latest.borrow().clone()?;
        if sample.serial == self.last_serial {
            return None;
        }
        self.last_serial = sample.serial;
        Some(sample.to_message())
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
    /// Frame size the encoder wants, so the readback can shrink on the GPU
    /// rather than moving full-size pixels the CPU is about to discard.
    target_width: u32,
    target_height: u32,
    portal_source: PortalSourceMode,
    screencast_backend: ScreenCastBackend,
    monitor_name: Option<&'a str>,
    portal_cursor: PortalCursorMode,
    require_cursor_metadata: bool,
    prefer_dmabuf: bool,
    gpu_device: &'a std::path::Path,
}

impl NativePipewireCapture {
    async fn start(
        config: NativePipewireCaptureConfig<'_>,
        opened: Option<ScreenCastCapture>,
    ) -> Result<Self> {
        let NativePipewireCaptureConfig {
            fps,
            cursor_hz,
            target_width,
            target_height,
            portal_source,
            screencast_backend,
            monitor_name,
            portal_cursor,
            require_cursor_metadata,
            prefer_dmabuf,
            gpu_device,
        } = config;
        let capture = match opened {
            Some(capture) => capture,
            None => {
                open_screencast_capture(
                    screencast_backend,
                    portal_source,
                    monitor_name,
                    portal_cursor,
                )
                .await?
            }
        };
        let (cursor_tx, cursor_rx) = watch::channel(None);
        let pipewire_error = Arc::new(Mutex::new(None));
        let thread_stop = Arc::new(Mutex::new(None));
        let thread_config = PipewireThreadConfig {
            node_id: capture.node_id,
            width: capture.width,
            height: capture.height,
            target_width,
            target_height,
            remote: capture.remote.try_clone()?,
            fps,
            cursor_hz,
            require_cursor_metadata,
            gpu_device: gpu_device.to_path_buf(),
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
            requested_backend = ?screencast_backend,
            backend = ?capture.backend,
            dmabuf = prefer_dmabuf,
            "Wayland/PipeWire native capture started"
        );

        Ok(Self {
            source: CaptureSource {
                backend: match capture.backend {
                    ScreenCastBackend::Mutter => "mutter-screencast+pipewire-rs",
                    ScreenCastBackend::Auto | ScreenCastBackend::Portal => {
                        "xdg-desktop-portal+pipewire-rs"
                    }
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
        // Unpacking and scaling a full-resolution frame is tens of
        // milliseconds of pure CPU. The cursor now samples on its own task, so
        // getting this off the runtime thread is what lets that task actually
        // be scheduled while a video frame is being prepared.
        tokio::task::spawn_blocking(move || {
            Ok(resize_rgb_image_to_fit(
                raw_frame_to_rgb_image(&frame)?,
                max_width,
                max_height,
            ))
        })
        .await
        .context("frame conversion task panicked")?
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

    async fn next_dash_frame(
        &mut self,
        max_width: u32,
        max_height: u32,
    ) -> Result<CapturedDashFrame> {
        if matches!(&self.latest, NativePipewireFrames::Cpu(_)) {
            let frame = self.next_frame().await?;
            let change = frame_change_from_damage(frame.damage);
            return Ok(CapturedDashFrame {
                frame: DashInputFrame::Rgb(resize_rgb_image_to_fit(
                    raw_frame_to_rgb_image(&frame)?,
                    max_width,
                    max_height,
                )),
                change,
            });
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
                    PipewireVideoFrame::Cpu(frame) => Ok(CapturedDashFrame {
                        change: frame_change_from_damage(frame.damage),
                        frame: DashInputFrame::Rgb(resize_rgb_image_to_fit(
                            raw_frame_to_rgb_image(&frame)?,
                            max_width,
                            max_height,
                        )),
                    }),
                    PipewireVideoFrame::DmaBuf(frame) => {
                        let (output_width, output_height) =
                            fit_even_dimensions(frame.width, frame.height, max_width, max_height);
                        Ok(CapturedDashFrame {
                            change: frame_change_from_damage(frame.damage),
                            frame: DashInputFrame::DmaBuf(DashDmaBufFrame {
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
                            }),
                        })
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
    damage: Option<bool>,
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
    visible: bool,
    source_width: u32,
    source_height: u32,
    bitmap: Option<Arc<CursorBitmap>>,
}

impl PipewireCursorSample {
    fn to_message(&self) -> CursorMessage {
        CursorMessage {
            x: self.x,
            y: self.y,
            visible: self.visible,
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
    bitmap: Option<Arc<CursorBitmap>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PipewireCursorUpdate {
    Unchanged,
    Hidden,
    Visible(PipewireCursorState),
}

struct DequeuedPipewireBuffer<'a> {
    stream: &'a pw::stream::Stream,
    buffer: *mut pw::sys::pw_buffer,
}

impl<'a> DequeuedPipewireBuffer<'a> {
    fn dequeue(stream: &'a pw::stream::Stream) -> Option<Self> {
        // SAFETY: this wrapper queues every non-null buffer exactly once in
        // `Drop`, unless ownership is explicitly transferred by `defer_queue`.
        let buffer = unsafe { stream.dequeue_raw_buffer() };
        (!buffer.is_null()).then_some(Self { stream, buffer })
    }

    fn spa_buffer_ptr(&self) -> *mut spa::sys::spa_buffer {
        // SAFETY: `self.buffer` is a non-null dequeued PipeWire buffer that
        // remains owned by this guard; PipeWire owns its nested SPA buffer.
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
        // SAFETY: the SPA buffer remains exclusively dequeued through
        // `&mut self`; PipeWire supplies `n_datas` elements at `datas`.
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
        // SAFETY: `buffer` came from this stream and has not been queued or
        // transferred, because `defer_queue` forgets the guard.
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
    let sample = pipewire_cursor_sample(
        buffer,
        source_width,
        source_height,
        &mut user_data.cursor_serial,
        &mut user_data.last_cursor_state,
    );
    let changed = sample.is_some();
    if let Some(sample) = sample {
        let _ = user_data.cursor_latest.send(Some(sample));
    }
    report_capture_rate(&mut user_data.rate_meter, changed, "PipeWire");
    true
}

/// Emits the periodic capture-rate line for one delivered buffer.
fn report_capture_rate(meter: &mut CaptureRateMeter, cursor_changed: bool, label: &str) {
    if let Some(rates) = meter.record(Instant::now(), cursor_changed) {
        debug!(
            label,
            buffer_hz = format!("{:.1}", rates.buffer_hz),
            cursor_hz = format!("{:.1}", rates.cursor_hz),
            max_cursor_gap_ms = rates.max_cursor_gap.as_millis(),
            "compositor capture rate"
        );
    }
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
    let sample = pipewire_cursor_sample(
        buffer,
        source_width,
        source_height,
        &mut user_data.cursor_serial,
        &mut user_data.last_cursor_state,
    );
    let changed = sample.is_some();
    if let Some(sample) = sample {
        let _ = user_data.cursor_latest.send(Some(sample));
    }
    report_capture_rate(&mut user_data.rate_meter, changed, "PipeWire video");
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
    if !required {
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
) -> Option<PipewireCursorSample> {
    match pipewire_cursor_update(buffer) {
        PipewireCursorUpdate::Unchanged => None,
        PipewireCursorUpdate::Hidden => {
            let previous = last_cursor_state.take()?;
            *cursor_serial = cursor_serial.wrapping_add(1).max(1);
            Some(PipewireCursorSample {
                serial: *cursor_serial,
                x: clamped_cursor_position(previous.x, source_width),
                y: clamped_cursor_position(previous.y, source_height),
                visible: false,
                source_width,
                source_height,
                bitmap: None,
            })
        }
        PipewireCursorUpdate::Visible(mut state) => {
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
            *cursor_serial = cursor_serial.wrapping_add(1).max(1);
            let sample = PipewireCursorSample {
                serial: *cursor_serial,
                x: clamped_cursor_position(state.x, source_width),
                y: clamped_cursor_position(state.y, source_height),
                visible: true,
                source_width,
                source_height,
                bitmap: state.bitmap.clone(),
            };
            *last_cursor_state = Some(state);
            Some(sample)
        }
    }
}

fn clamped_cursor_position(position: i32, extent: u32) -> f32 {
    position.clamp(0, extent.min(i32::MAX as u32) as i32) as f32
}

fn frame_change_from_damage(damage: Option<bool>) -> FrameChange {
    match damage {
        Some(true) => FrameChange::Changed,
        Some(false) => FrameChange::Unchanged,
        None => FrameChange::Unknown,
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum AccumulatedFrameDamage {
    #[default]
    Empty,
    Unchanged,
    Unknown,
    Changed,
}

impl AccumulatedFrameDamage {
    fn observe(&mut self, damage: Option<bool>) {
        *self = match (*self, damage) {
            (Self::Changed, _) | (_, Some(true)) => Self::Changed,
            (Self::Unknown, _) | (_, None) => Self::Unknown,
            (Self::Empty | Self::Unchanged, Some(false)) => Self::Unchanged,
        };
    }

    fn take(&mut self) -> Option<bool> {
        match std::mem::take(self) {
            Self::Changed => Some(true),
            Self::Unchanged => Some(false),
            Self::Empty | Self::Unknown => None,
        }
    }
}

fn pipewire_video_damage(buffer: *const spa::sys::spa_buffer) -> Option<bool> {
    if buffer.is_null() {
        return None;
    }
    // SAFETY: PipeWire owns `buffer` for the active process callback. Metadata
    // pointers and byte lengths are validated before constructing a bounded
    // array of `spa_meta_region` values.
    unsafe {
        if (*buffer).n_metas == 0 || (*buffer).metas.is_null() {
            return None;
        }
        let metas = std::slice::from_raw_parts((*buffer).metas, (*buffer).n_metas as usize);
        let meta = metas
            .iter()
            .find(|meta| meta.type_ == spa::sys::SPA_META_VideoDamage)?;
        let region_size = std::mem::size_of::<spa::sys::spa_meta_region>();
        if meta.data.is_null()
            || region_size == 0
            || !(meta.size as usize).is_multiple_of(region_size)
        {
            return None;
        }
        let regions = std::slice::from_raw_parts(
            meta.data.cast::<spa::sys::spa_meta_region>(),
            meta.size as usize / region_size,
        );
        Some(
            regions.first().is_some_and(|region| {
                region.region.size.width != 0 && region.region.size.height != 0
            }),
        )
    }
}

fn pipewire_cursor_update(buffer: *const spa::sys::spa_buffer) -> PipewireCursorUpdate {
    if buffer.is_null() {
        return PipewireCursorUpdate::Unchanged;
    }
    // SAFETY: PipeWire owns `buffer` for the duration of the process callback.
    // Null pointers, counts, metadata sizes, and cursor data are checked before
    // each dereference or slice construction.
    unsafe {
        if (*buffer).n_metas == 0 || (*buffer).metas.is_null() {
            return PipewireCursorUpdate::Unchanged;
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
                return PipewireCursorUpdate::Hidden;
            }
            return PipewireCursorUpdate::Visible(PipewireCursorState {
                id: cursor.id,
                x: cursor.position.x,
                y: cursor.position.y,
                bitmap: pipewire_cursor_bitmap(meta, cursor),
            });
        }
    }
    PipewireCursorUpdate::Unchanged
}

fn pipewire_cursor_bitmap(
    meta: &spa::sys::spa_meta,
    cursor: &spa::sys::spa_meta_cursor,
) -> Option<Arc<CursorBitmap>> {
    let cursor_meta_size = std::mem::size_of::<spa::sys::spa_meta_cursor>();
    let bitmap_meta_size = std::mem::size_of::<spa::sys::spa_meta_bitmap>();
    let meta_size = meta.size as usize;
    let bitmap_offset = cursor.bitmap_offset as usize;
    if meta.data.is_null()
        || bitmap_offset < cursor_meta_size
        || bitmap_offset.checked_add(bitmap_meta_size)? > meta_size
        // The offset is written by the producing compositor, so it is no more
        // trusted than the sizes and strides checked around it. A reference
        // must be aligned as well as in bounds, and every other field here is
        // already treated as hostile; this one was not.
        || !bitmap_offset.is_multiple_of(std::mem::align_of::<spa::sys::spa_meta_bitmap>())
    {
        return None;
    }

    // SAFETY: `meta.data` is callback-owned PipeWire storage of `meta_size`
    // bytes, and PipeWire aligns it. The bitmap header and every strided pixel
    // row are checked to lie within that allocation, and `bitmap_offset` is
    // checked to be a multiple of the header's alignment, before a reference or
    // slice is formed.
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
            || width as usize > PIPEWIRE_CURSOR_MAX_BITMAP_SIDE
            || height as usize > PIPEWIRE_CURSOR_MAX_BITMAP_SIDE
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
        let hotspot_x = cursor.hotspot.x.clamp(0, width.saturating_sub(1) as i32);
        let hotspot_y = cursor.hotspot.y.clamp(0, height.saturating_sub(1) as i32);
        Some(Arc::new(CursorBitmap {
            width: width as u32,
            height: height as u32,
            hotspot_x,
            hotspot_y,
            rgba: rgba.into(),
        }))
    }
}

fn cursor_pixel_as_rgba(format: spa::sys::spa_video_format, pixel: &[u8]) -> Option<[u8; 4]> {
    let [first, second, third, fourth] = *pixel else {
        return None;
    };
    match format {
        x if x == spa::sys::SPA_VIDEO_FORMAT_RGBA => Some([first, second, third, fourth]),
        x if x == spa::sys::SPA_VIDEO_FORMAT_BGRA => Some([third, second, first, fourth]),
        x if x == spa::sys::SPA_VIDEO_FORMAT_ARGB => Some([second, third, fourth, first]),
        x if x == spa::sys::SPA_VIDEO_FORMAT_ABGR => Some([fourth, third, second, first]),
        x if x == spa::sys::SPA_VIDEO_FORMAT_RGBx => Some([first, second, third, 255]),
        x if x == spa::sys::SPA_VIDEO_FORMAT_BGRx => Some([third, second, first, 255]),
        x if x == spa::sys::SPA_VIDEO_FORMAT_xRGB => Some([second, third, fourth, 255]),
        x if x == spa::sys::SPA_VIDEO_FORMAT_xBGR => Some([fourth, third, second, 255]),
        _ => None,
    }
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
    // SAFETY: PipeWire owns `buffer` for the active callback; the metadata
    // pointer is checked before constructing its `n_metas`-element slice.
    unsafe {
        if (*buffer).n_metas == 0 || (*buffer).metas.is_null() {
            return false;
        }
        let metas = std::slice::from_raw_parts((*buffer).metas, (*buffer).n_metas as usize);
        metas.iter().any(|meta| {
            meta.type_ == spa::sys::SPA_META_Cursor
                && !meta.data.is_null()
                && meta.size >= std::mem::size_of::<spa::sys::spa_meta_cursor>() as u32
        })
    }
}

fn pipewire_buffer_meta_summary(buffer: *const spa::sys::spa_buffer) -> String {
    if buffer.is_null() {
        return "null buffer".to_string();
    }
    // SAFETY: PipeWire owns `buffer` for the active callback; the metadata
    // pointer is checked before constructing its `n_metas`-element slice.
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
    damage: Option<bool>,
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
    /// The interface that actually opened the session, which differs from the
    /// requested value when the operator asked for automatic selection.
    backend: ScreenCastBackend,
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
    /// A portal grant. One dialog can approve several outputs, so the session
    /// is shared by every capture taken from it and closes when the last one
    /// is dropped. The handle is held, never read: dropping it revokes the
    /// grant and tears down the PipeWire nodes.
    Portal(#[allow(dead_code)] Arc<PortalSession>),
    Mutter {
        _connection: Connection,
        _session_handle: OwnedObjectPath,
    },
}

/// A live XDG ScreenCast grant.
struct PortalSession {
    _connection: Connection,
    _session_handle: OwnedObjectPath,
    _fd: OwnedFd,
}

async fn open_screencast_capture(
    backend: ScreenCastBackend,
    source_mode: PortalSourceMode,
    monitor_name: Option<&str>,
    cursor_preference: PortalCursorMode,
) -> Result<ScreenCastCapture> {
    let backend = match backend {
        ScreenCastBackend::Auto => resolve_screencast_backend(source_mode).await,
        selected => selected,
    };
    match backend {
        ScreenCastBackend::Portal | ScreenCastBackend::Auto => {
            open_screencast_portal(source_mode, cursor_preference).await
        }
        ScreenCastBackend::Mutter => {
            open_mutter_screencast(source_mode, monitor_name, cursor_preference).await
        }
    }
}

/// Chooses the ScreenCast interface that fits the running compositor.
///
/// niri implements the Mutter ScreenCast API as its own native interface, and
/// using it directly lets a detached publisher select a monitor without a
/// desktop dialog. Every other desktop keeps the XDG portal, whose permission
/// prompt is the sanctioned consent step there: GNOME exposes the same Mutter
/// API, but reaching past its portal would bypass that prompt.
async fn resolve_screencast_backend(source_mode: PortalSourceMode) -> ScreenCastBackend {
    if source_mode != PortalSourceMode::Monitor || !session_desktop_is_niri() {
        return ScreenCastBackend::Portal;
    }
    match mutter_screencast_version().await {
        Ok(version) => {
            info!(
                version,
                "niri session detected; using its Mutter-compatible ScreenCast interface"
            );
            ScreenCastBackend::Mutter
        }
        Err(err) => {
            warn!(
                ?err,
                "niri session detected but its ScreenCast interface is unavailable; using the XDG portal"
            );
            ScreenCastBackend::Portal
        }
    }
}

/// Reports whether the session identifies itself as niri.
fn session_desktop_is_niri() -> bool {
    std::env::var("XDG_CURRENT_DESKTOP")
        .unwrap_or_default()
        .split(':')
        .any(|entry| entry.eq_ignore_ascii_case("niri"))
}

/// Identifies one physical output as `(connector, vendor, product, serial)`.
type MutterMonitorSpec = (String, String, String, String);
/// One advertised output mode; only the identifier and extent are used here.
type MutterMode = (
    String,
    i32,
    i32,
    f64,
    f64,
    Vec<f64>,
    std::collections::HashMap<String, OwnedValue>,
);
/// A physical output with its modes and properties.
type MutterMonitor = (
    MutterMonitorSpec,
    Vec<MutterMode>,
    std::collections::HashMap<String, OwnedValue>,
);
/// A laid-out region of the desktop, which may drive several outputs.
type MutterLogicalMonitor = (
    i32,
    i32,
    f64,
    u32,
    bool,
    Vec<MutterMonitorSpec>,
    std::collections::HashMap<String, OwnedValue>,
);
/// The reply of `org.gnome.Mutter.DisplayConfig.GetCurrentState`.
type MutterCurrentState = (
    u32,
    Vec<MutterMonitor>,
    Vec<MutterLogicalMonitor>,
    std::collections::HashMap<String, OwnedValue>,
);

/// Picks the output to record when the operator named none.
///
/// The primary logical monitor wins, then the first laid-out logical monitor,
/// then the first physical output. Selecting explicitly with `--monitor-name`
/// is still the only way to guarantee a particular output across replugs.
async fn default_mutter_connector(connection: &Connection) -> Result<String> {
    let (monitors, logical_monitors) = read_mutter_display_state(connection).await?;
    let from_logical = logical_monitors
        .iter()
        .find(|logical| logical.4)
        .or_else(|| logical_monitors.first())
        .and_then(|logical| logical.5.first())
        .map(|spec| spec.0.clone());
    let connector = from_logical
        .or_else(|| monitors.first().map(|monitor| monitor.0.0.clone()))
        .context("the compositor reported no connected monitor to record")?;
    info!(
        connector,
        monitor_count = monitors.len(),
        "selected a monitor to record; pass --monitor-name to choose another"
    );
    Ok(connector)
}

/// Reads the compositor's monitor and layout tables.
async fn read_mutter_display_state(
    connection: &Connection,
) -> Result<(Vec<MutterMonitor>, Vec<MutterLogicalMonitor>)> {
    let proxy = Proxy::new(
        connection,
        "org.gnome.Mutter.DisplayConfig",
        "/org/gnome/Mutter/DisplayConfig",
        "org.gnome.Mutter.DisplayConfig",
    )
    .await
    .context("connecting to the compositor display configuration")?;
    let (_, monitors, logical_monitors, _): MutterCurrentState = proxy
        .call("GetCurrentState", &())
        .await
        .context("reading the compositor display configuration")?;
    Ok((monitors, logical_monitors))
}

/// Lists every laid-out monitor connector, primary output first.
async fn list_mutter_connectors(connection: &Connection) -> Result<Vec<String>> {
    let (monitors, logical_monitors) = read_mutter_display_state(connection).await?;
    // Only laid-out outputs can be recorded; a connected but disabled monitor
    // appears in `monitors` without a logical monitor.
    let mut connectors: Vec<String> = logical_monitors
        .iter()
        .flat_map(|logical| logical.5.iter().map(|spec| spec.0.clone()))
        .collect();
    if let Some(primary) = logical_monitors
        .iter()
        .find(|logical| logical.4)
        .and_then(|logical| logical.5.first())
        .map(|spec| spec.0.clone())
        && let Some(index) = connectors.iter().position(|entry| *entry == primary)
    {
        connectors.swap(0, index);
    }
    if connectors.is_empty() {
        connectors.extend(monitors.iter().map(|monitor| monitor.0.0.clone()));
    }
    connectors.dedup();
    Ok(connectors)
}

/// Prints the recordable monitors for `--list-monitors`.
async fn print_monitor_list(args: &Args) -> Result<()> {
    let backend = match args.screencast_backend {
        ScreenCastBackend::Auto => resolve_screencast_backend(args.portal_source).await,
        selected => selected,
    };
    if backend != ScreenCastBackend::Mutter {
        println!(
            "This desktop selects capture sources in its portal dialog, so there is no list \
             to print. Start the publisher and choose there."
        );
        return Ok(());
    }
    let connection = Connection::session().await?;
    let (monitors, logical_monitors) = read_mutter_display_state(&connection).await?;
    let primary = logical_monitors
        .iter()
        .find(|logical| logical.4)
        .and_then(|logical| logical.5.first())
        .map(|spec| spec.0.clone());
    for connector in list_mutter_connectors(&connection).await? {
        let described = monitors
            .iter()
            .find(|monitor| monitor.0.0 == connector)
            .map(|monitor| format!("{} {}", monitor.0.1, monitor.0.2))
            .unwrap_or_default();
        let marker = if primary.as_deref() == Some(connector.as_str()) {
            " (primary)"
        } else {
            ""
        };
        println!("{connector}\t{described}{marker}");
    }
    Ok(())
}

/// Returns the advertised Mutter ScreenCast interface version.
async fn mutter_screencast_version() -> Result<i32> {
    let connection = Connection::session().await?;
    let proxy = Proxy::new(
        &connection,
        "org.gnome.Mutter.ScreenCast",
        "/org/gnome/Mutter/ScreenCast",
        "org.gnome.Mutter.ScreenCast",
    )
    .await?;
    proxy
        .get_property::<i32>("Version")
        .await
        .context("reading Mutter ScreenCast version")
}

async fn open_mutter_screencast(
    source_mode: PortalSourceMode,
    monitor_name: Option<&str>,
    cursor_preference: PortalCursorMode,
) -> Result<ScreenCastCapture> {
    if source_mode != PortalSourceMode::Monitor {
        bail!("--screencast-backend mutter currently requires --portal-source monitor");
    }
    let connection = Connection::session().await?;
    info!("connected to D-Bus session bus for Mutter ScreenCast");
    let requested = monitor_name.map(str::trim).filter(|name| !name.is_empty());
    let discovered = match requested {
        Some(_) => None,
        None => Some(default_mutter_connector(&connection).await?),
    };
    let connector = requested.unwrap_or_else(|| {
        discovered
            .as_deref()
            .expect("a connector is discovered when none was requested")
    });
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
        backend: ScreenCastBackend::Mutter,
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
    let mut captures = open_screencast_portal_sources(source_mode, cursor_preference, None).await?;
    Ok(captures.remove(0))
}

/// Opens one XDG ScreenCast grant and returns a capture per approved output.
///
/// The portal dialog approves the whole selection at once, so several outputs
/// share a single session and a single PipeWire remote. When `restore_token` is
/// set the portal may skip the dialog entirely; a stale or rejected token
/// simply falls back to prompting, which is why it is passed as a hint rather
/// than required to succeed.
async fn open_screencast_portal_sources(
    source_mode: PortalSourceMode,
    cursor_preference: PortalCursorMode,
    restore_token: Option<&PortalRestoreToken>,
) -> Result<Vec<ScreenCastCapture>> {
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
        // Several outputs may be approved in one dialog; every returned stream
        // is published, so a selection of three screens yields three streams.
        options.insert("multiple", Value::from(true));
        options.insert("cursor_mode", Value::from(cursor_mode));
        match restore_token.and_then(|token| token.value()) {
            Some(token) => {
                options.insert("persist_mode", Value::from(PORTAL_PERSIST_UNTIL_REVOKED));
                options.insert("restore_token", Value::from(token.to_string()));
            }
            None => {
                let persist = if restore_token.is_some() {
                    PORTAL_PERSIST_UNTIL_REVOKED
                } else {
                    PORTAL_PERSIST_DO_NOT
                };
                options.insert("persist_mode", Value::from(persist));
            }
        }
        let _handle: OwnedObjectPath = proxy
            .call("SelectSources", &(session_handle.clone(), options))
            .await?;
        let _ = wait_portal_response(signals).await?;
    }

    let results = {
        let request_token = portal_token("glacialcast_request");
        let (_request_proxy, signals) =
            prepare_portal_response(&connection, &request_token).await?;
        if restore_token.and_then(PortalRestoreToken::value).is_some() {
            info!("starting XDG ScreenCast session with a stored grant; no chooser expected");
        } else {
            info!("starting XDG ScreenCast session; accept the desktop chooser to continue");
        }
        let mut options = std::collections::HashMap::<&str, Value<'_>>::new();
        options.insert("handle_token", Value::from(request_token));
        let _handle: OwnedObjectPath = proxy
            .call("Start", &(session_handle.clone(), "", options))
            .await?;
        wait_portal_response(signals).await?
    };

    // A grant the portal agreed to remember comes back with a token to present
    // next time. Storing it is what lets a detached publisher restart without
    // another dialog.
    if let Some(store) = restore_token {
        match results
            .get("restore_token")
            .and_then(|value| value.try_clone().ok())
            .and_then(|value| String::try_from(value).ok())
        {
            Some(token) if !token.is_empty() => store.save(&token),
            _ => info!("portal did not return a restore token; it will prompt again"),
        }
    }

    let streams_value = results
        .get("streams")
        .context("Start response did not include streams")?
        .try_clone()?;
    let streams: Vec<(u32, std::collections::HashMap<String, OwnedValue>)> =
        streams_value.try_into()?;
    if streams.is_empty() {
        bail!("portal returned no PipeWire streams");
    }

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

    let session = Arc::new(PortalSession {
        _fd: fd.try_clone()?,
        _connection: connection,
        _session_handle: session_handle,
    });
    let mut captures = Vec::with_capacity(streams.len());
    for (node_id, props) in streams {
        let prop_summary = portal_prop_summary(&props);
        let (width, height) = props
            .get("size")
            .and_then(|value| value.try_clone().ok())
            .and_then(|value| <(i32, i32)>::try_from(value).ok())
            .map(|(w, h)| (w.max(1) as u32, h.max(1) as u32))
            .unwrap_or((1, 1));
        info!(
            node_id,
            width,
            height,
            props = %prop_summary,
            "opened PipeWire remote from portal"
        );
        captures.push(ScreenCastCapture {
            node_id,
            width,
            height,
            description: format!(
                "PipeWire node {node_id} via raw XDG Desktop Portal                  ({cursor_description}; {prop_summary})"
            ),
            backend: ScreenCastBackend::Portal,
            remote: PipewireRemote::PortalFd(fd.try_clone()?),
            session: ScreenCastSession::Portal(Arc::clone(&session)),
        });
    }
    Ok(captures)
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
    target_width: u32,
    target_height: u32,
    remote: PipewireRemote,
    fps: f64,
    cursor_hz: u64,
    require_cursor_metadata: bool,
    gpu_device: PathBuf,
    pipewire_error: Arc<Mutex<Option<String>>>,
    mainloop_ptr_out: Arc<Mutex<Option<usize>>>,
}

/// How long the PipeWire loop has to publish the pointer that stops it.
///
/// Generous, because exceeding it fails the capture: this is the difference
/// between a slow machine and a loop that never came up, and only the second
/// deserves an error.
const PIPEWIRE_START_TIMEOUT: Duration = Duration::from_secs(5);

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
    // Wait for the loop to publish the pointer that stops it, rather than
    // sleeping a fixed 25ms and hoping. A slower start left this holding `None`
    // -- so `stop()` had nothing to signal, the thread outlived the capture it
    // belonged to, and the failure was a leak rather than an error.
    let deadline = Instant::now() + PIPEWIRE_START_TIMEOUT;
    let started = loop {
        if thread_error.lock().expect("error mutex poisoned").is_some() {
            break false;
        }
        if mainloop_ptr
            .lock()
            .expect("mainloop pointer mutex poisoned")
            .is_some()
        {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    let mut stop = PipewireThreadStop {
        mainloop_ptr,
        handle: Some(handle),
    };
    if let Some(err) = thread_error.lock().expect("error mutex poisoned").clone() {
        stop.stop();
        bail!("PipeWire thread failed to start: {err}");
    }
    if !started {
        stop.stop();
        bail!(
            "PipeWire thread did not start within {}ms",
            PIPEWIRE_START_TIMEOUT.as_millis()
        );
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
        target_width,
        target_height,
        remote,
        fps,
        cursor_hz,
        require_cursor_metadata,
        gpu_device,
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
    let _published_mainloop =
        PublishedPipewireMainloop::new(mainloop_ptr_out.clone(), mainloop_ptr);
    let data = PipewireUserData {
        target_width,
        target_height,
        format: Default::default(),
        latest,
        cursor_latest,
        error: pipewire_error,
        expected_width: width,
        expected_height: height,
        min_frame_interval: Duration::from_secs_f64(1.0 / fps.clamp(0.5, 15.0)),
        require_cursor_metadata,
        last_frame_copied_at: None,
        last_cursor_state: None,
        cursor_meta_missing_since: None,
        cursor_meta_verified: false,
        pending_video_damage: AccumulatedFrameDamage::default(),
        mainloop_ptr,
        gpu_readback: GpuReadback::new(gpu_device),
        unmapped_buffer_logged: false,
        cursor_meta_logged: false,
        rate_meter: CaptureRateMeter::new(Instant::now()),
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
                    update_pipewire_buffer_params_with_metadata(
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
            user_data
                .pending_video_damage
                .observe(pipewire_video_damage(buffer.spa_buffer_ptr()));
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
            let modifier = user_data.format.modifier();
            let needs_gpu_readback = dmabuf_requires_gpu_readback(
                data_type == spa::buffer::DataType::DmaBuf,
                data_is_mappable(data),
                modifier,
            );
            let now = Instant::now();
            if let Some(last_frame_copied_at) = user_data.last_frame_copied_at
                && now.duration_since(last_frame_copied_at) < user_data.min_frame_interval
            {
                return;
            }
            user_data.last_frame_copied_at = Some(now);

            let (frame_data, frame_stride, frame_format, frame_width, frame_height) =
                if needs_gpu_readback {
                let Some(fd_offset) = map_offset.checked_add(offset) else {
                    return;
                };
                // Shrinking on the GPU means glReadPixels only transfers the
                // pixels that survive scaling. The driver may decline, in which
                // case the readback comes back at source size and the CPU path
                // scales it exactly as before.
                let (target_width, target_height) = fit_even_dimensions(
                    video_size.width,
                    video_size.height,
                    user_data.target_width,
                    user_data.target_height,
                );
                match user_data.gpu_readback.copy_dmabuf_scaled(
                    fd,
                    fd_offset,
                    video_size.width,
                    video_size.height,
                    stride,
                    user_data.format.format(),
                    modifier,
                    target_width,
                    target_height,
                ) {
                    Ok(readback) => {
                        if !user_data.unmapped_buffer_logged {
                            user_data.unmapped_buffer_logged = true;
                            info!(
                                ?data_type,
                                ?data_flags,
                                fd,
                                map_offset,
                                offset,
                                source_stride = stride,
                                mapped_stride = readback.stride,
                                readback_format = ?readback.format,
                                readback_path = readback.path,
                                modifier,
                                "copied PipeWire DMA-BUF through driver-backed GPU readback"
                            );
                        }
                        (
                            readback.data,
                            readback.stride,
                            readback.format,
                            readback.width,
                            readback.height,
                        )
                    }
                    Err(err) => {
                        let message = format!(
                            "PipeWire DMA-BUF requires GPU readback, but no driver path produced linear pixels for node {node_id}: {err:#}"
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
                            modifier,
                            %message
                        );
                        record_pipewire_error(user_data, message);
                        return;
                    }
                }
            } else {
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
                        mmap_fd_slice(fd, fd_offset, size, false)
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
                        record_pipewire_error(user_data, message);
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
                (
                    frame_data,
                    stride,
                    format,
                    video_size.width,
                    video_size.height,
                )
            };
            user_data.serial = user_data.serial.wrapping_add(1);
            let frame = RawFrame {
                serial: user_data.serial,
                damage: user_data.pending_video_damage.take(),
                width: frame_width,
                height: frame_height,
                stride: frame_stride,
                format: frame_format,
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
        // This loop forwards the DMA-BUF to the encoder, which scales it
        // itself through VA-API video processing, so there is nothing to
        // shrink during readback here.
        target_width: _target_width,
        target_height: _target_height,
        remote,
        fps,
        cursor_hz,
        require_cursor_metadata,
        gpu_device: _,
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
    let _published_mainloop =
        PublishedPipewireMainloop::new(mainloop_ptr_out.clone(), mainloop_ptr);
    let data = PipewireVideoUserData {
        format: Default::default(),
        latest,
        cursor_latest,
        error: pipewire_error,
        expected_width: width,
        expected_height: height,
        min_frame_interval: Duration::from_secs_f64(1.0 / fps.clamp(0.5, 15.0)),
        require_cursor_metadata,
        last_frame_copied_at: None,
        last_cursor_state: None,
        cursor_meta_missing_since: None,
        cursor_meta_verified: false,
        pending_video_damage: AccumulatedFrameDamage::default(),
        mainloop_ptr,
        first_frame_logged: false,
        cursor_meta_logged: false,
        rate_meter: CaptureRateMeter::new(Instant::now()),
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
    let _buffer_release = buffer_release_rx.attach(mainloop.loop_(), move |buffer| {
        // SAFETY: the channel is attached to the owning PipeWire main loop;
        // `stream` outlives this receiver and each value is a buffer explicitly
        // deferred from that same stream.
        unsafe {
            pw::sys::pw_stream_queue_buffer(
                stream_ptr as *mut pw::sys::pw_stream,
                buffer as *mut pw::sys::pw_buffer,
            );
        }
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
                    update_pipewire_buffer_params_with_metadata(
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
            user_data
                .pending_video_damage
                .observe(pipewire_video_damage(buffer.spa_buffer_ptr()));
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
                    damage: user_data.pending_video_damage.take(),
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
                damage: user_data.pending_video_damage.take(),
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
            match preferred_safe_readback_modifier(pod) {
                Some(modifier) => Some(modifier),
                None => {
                    skipped_modifier_count += 1;
                    warn!(
                        format = ?format,
                        "skipping PipeWire format because its advertised modifiers have no safe readback path"
                    );
                    continue;
                }
            }
        } else {
            None
        };
        // A modifier-less offer asks for shared memory, the only buffer this
        // CPU readback path can read without driver help. Offer it first for
        // every advertised format: when it is emitted only alongside an
        // implicit modifier, a compositor advertising nothing but opaque vendor
        // modifiers is left with no CPU-readable option to accept at all.
        out.push(build_exact_cpu_pipewire_format_pod(
            format,
            size.width,
            size.height,
            fps,
            None,
        )?);
        cpu_count += 1;
        if modifier.is_some() {
            out.push(build_exact_cpu_pipewire_format_pod(
                format,
                size.width,
                size.height,
                fps,
                modifier,
            )?);
            cpu_count += 1;
        }
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
        // Screen capture negotiates a variable framerate, so this cap rather
        // than `VideoFramerate` is what bounds delivery. Without it a 144 Hz
        // panel would hand over 144 buffers per second to feed a timeline that
        // consumes at most `fps`.
        pw::spa::pod::property!(
            pw::spa::param::format::FormatProperties::VideoMaxFramerate,
            Choice,
            Range,
            Fraction,
            fps,
            pw::spa::utils::Fraction { num: 1, denom: 1 },
            fps
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
        // Screen capture negotiates a variable framerate, so this cap rather
        // than `VideoFramerate` is what bounds delivery. Without it a 144 Hz
        // panel would hand over 144 buffers per second to feed a timeline that
        // consumes at most `fps`.
        pw::spa::pod::property!(
            pw::spa::param::format::FormatProperties::VideoMaxFramerate,
            Choice,
            Range,
            Fraction,
            fps,
            pw::spa::utils::Fraction { num: 1, denom: 1 },
            fps
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

/// Returns the PipeWire delivery rate that satisfies both timelines.
///
/// The cursor overlay is sampled from buffer metadata, so the stream has to be
/// fed at least as fast as the cursor rate even though video is published far
/// more slowly. The upper bound keeps a high-refresh panel from spending the
/// capture thread on buffers no timeline consumes.
fn pipewire_capture_rate(frame_fps: f64, cursor_hz: u64) -> f64 {
    frame_fps.max(cursor_hz.max(1) as f64).clamp(0.5, 120.0)
}

fn serialize_pod_object(obj: spa::pod::Object) -> Result<Vec<u8>> {
    Ok(pw::spa::pod::serialize::PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &pw::spa::pod::Value::Object(obj),
    )?
    .0
    .into_inner())
}

fn update_pipewire_buffer_params_with_metadata(
    stream: &pw::stream::Stream,
    buffer_param_bytes: Vec<u8>,
    label: &str,
) {
    let mut param_bytes = vec![buffer_param_bytes];
    match build_pipewire_cursor_meta_param_pod() {
        Ok(bytes) => param_bytes.push(bytes),
        Err(err) => warn!(?err, %label, "failed to serialize PipeWire cursor metadata params"),
    }
    match build_pipewire_damage_meta_param_pod() {
        Ok(bytes) => param_bytes.push(bytes),
        Err(err) => warn!(?err, %label, "failed to serialize PipeWire damage metadata params"),
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

fn build_pipewire_damage_meta_param_pod() -> Result<Vec<u8>> {
    const DAMAGE_REGION_CAPACITY: usize = 16;
    let size = std::mem::size_of::<spa::sys::spa_meta_region>()
        .saturating_mul(DAMAGE_REGION_CAPACITY)
        .min(i32::MAX as usize) as i32;
    let obj = spa::pod::Object {
        type_: spa::utils::SpaTypes::ObjectParamMeta.as_raw(),
        id: spa::param::ParamType::Meta.as_raw(),
        properties: vec![
            spa::pod::Property::new(
                spa::sys::SPA_PARAM_META_type,
                spa::pod::Value::Id(spa::utils::Id(spa::sys::SPA_META_VideoDamage)),
            ),
            spa::pod::Property::new(spa::sys::SPA_PARAM_META_size, spa::pod::Value::Int(size)),
        ],
    };
    serialize_pod_object(obj)
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
                spa::pod::Value::Choice(spa::pod::ChoiceValue::Int(spa::utils::Choice(
                    spa::utils::ChoiceFlags::empty(),
                    spa::utils::ChoiceEnum::Range {
                        default: pipewire_cursor_meta_size(PIPEWIRE_CURSOR_DEFAULT_BITMAP_SIDE),
                        min: pipewire_cursor_meta_size(PIPEWIRE_CURSOR_MIN_BITMAP_SIDE),
                        max: pipewire_cursor_meta_size(PIPEWIRE_CURSOR_NEGOTIATED_MAX_BITMAP_SIDE),
                    },
                ))),
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

fn preferred_safe_readback_modifier(param: &spa::pod::Pod) -> Option<u64> {
    let modifiers = video_modifier_values(param);
    preferred_safe_readback_modifier_from_values(&modifiers)
}

fn preferred_safe_readback_modifier_from_values(modifiers: &[u64]) -> Option<u64> {
    if modifiers.contains(&DRM_FORMAT_MOD_LINEAR) {
        Some(DRM_FORMAT_MOD_LINEAR)
    } else if let Some(modifier) = modifiers
        .iter()
        .copied()
        .find(|modifier| *modifier != DRM_FORMAT_MOD_INVALID as u64)
    {
        Some(modifier)
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

fn dmabuf_requires_gpu_readback(is_dmabuf: bool, mappable: bool, modifier: u64) -> bool {
    is_dmabuf && (!mappable || modifier != DRM_FORMAT_MOD_LINEAR)
}

/// Linear pixels recovered from one compositor DMA-BUF.
struct DmaBufReadback {
    /// Untiled pixel rows.
    data: Vec<u8>,
    /// Distance in bytes between consecutive rows of `data`.
    stride: usize,
    /// Extent of `data`, which is the requested target only when the driver
    /// scaled during readback; otherwise it is the source extent.
    width: u32,
    /// Height of `data`, on the same terms as `width`.
    height: u32,
    /// Byte order of `data`, which need not match the negotiated PipeWire
    /// format because the GPU path reads whatever the driver renders best.
    format: RawFrameFormat,
    /// Which driver path produced the pixels, for one-time operator logging.
    path: &'static str,
}

/// Reads compositor DMA-BUFs back into linear CPU pixels.
///
/// Two driver paths are tried in order. `gbm_bo_map` is cheap and correct on
/// Mesa, which detiles during the transfer. Drivers that refuse to map a
/// foreign buffer object — the proprietary NVIDIA stack returns `EAGAIN`
/// indefinitely — are served by importing the descriptor as an `EGLImage` and
/// reading a framebuffer instead. Whichever path fails first is latched off so
/// a permanently unsupported path is not retried once per frame.
#[cfg(any())]
struct GpuReadback {
    // Declared before `device` so the EGL context is torn down while the GBM
    // device it was created from is still alive.
    egl: Option<EglReadback>,
    device_path: PathBuf,
    device: Option<gbm::Device<std::fs::File>>,
    gbm_unusable: bool,
    egl_unusable: bool,
}

#[cfg(any())]
impl GpuReadback {
    fn new(device_path: PathBuf) -> Self {
        Self {
            egl: None,
            device_path,
            device: None,
            gbm_unusable: false,
            egl_unusable: false,
        }
    }

    fn device(&mut self) -> Result<&gbm::Device<std::fs::File>> {
        if self.device.is_none() {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.device_path)
                .with_context(|| {
                    format!("opening GBM readback device {}", self.device_path.display())
                })?;
            let device = gbm::Device::new(file).with_context(|| {
                format!(
                    "creating GBM readback device {}",
                    self.device_path.display()
                )
            })?;
            info!(
                device = %self.device_path.display(),
                backend = device.backend_name(),
                "initialized GBM DMA-BUF readback"
            );
            self.device = Some(device);
        }
        Ok(self.device.as_ref().expect("GBM device initialized"))
    }

    /// Returns the EGL importer, creating it on first use.
    ///
    /// The context is created on, and stays bound to, the PipeWire loop thread
    /// that owns this value.
    fn egl(&mut self) -> Result<&mut EglReadback> {
        if self.egl.is_none() {
            let device_ptr = {
                use gbm::AsRaw;
                self.device()?.as_raw_mut().cast::<std::ffi::c_void>()
            };
            // SAFETY: `self.device` owns the GBM device the pointer refers to,
            // it is declared after `self.egl` so it outlives the EGL context,
            // and neither field is replaced while the context exists.
            let readback = unsafe { EglReadback::new(device_ptr) }?;
            info!(
                device = %self.device_path.display(),
                driver = readback.describe(),
                "initialized EGL DMA-BUF readback"
            );
            self.egl = Some(readback);
        }
        Ok(self.egl.as_mut().expect("EGL readback initialized"))
    }

    #[allow(clippy::too_many_arguments)]
    /// Reads a DMA-BUF back, shrinking it on the GPU when a smaller target is
    /// asked for and the driver supports it.
    #[allow(clippy::too_many_arguments)]
    fn copy_dmabuf_scaled(
        &mut self,
        fd: RawFd,
        offset: usize,
        width: u32,
        height: u32,
        stride: usize,
        video_format: spa::param::video::VideoFormat,
        modifier: u64,
        target_width: u32,
        target_height: u32,
    ) -> Result<DmaBufReadback> {
        self.copy_dmabuf_inner(
            fd,
            offset,
            width,
            height,
            stride,
            video_format,
            modifier,
            target_width,
            target_height,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn copy_dmabuf_inner(
        &mut self,
        fd: RawFd,
        offset: usize,
        width: u32,
        height: u32,
        stride: usize,
        video_format: spa::param::video::VideoFormat,
        modifier: u64,
        target_width: u32,
        target_height: u32,
    ) -> Result<DmaBufReadback> {
        let gbm_error = if self.gbm_unusable {
            None
        } else {
            match self.copy_dmabuf_with_gbm(
                fd,
                offset,
                width,
                height,
                stride,
                video_format,
                modifier,
            ) {
                Ok((data, stride)) => {
                    let format =
                        raw_frame_format_for_video_format(video_format).with_context(|| {
                            format!("unsupported PipeWire video format {video_format:?}")
                        })?;
                    // GBM maps the buffer as it is; scaling stays on the CPU
                    // for this path, so the extent is the source extent.
                    return Ok(DmaBufReadback {
                        data,
                        stride,
                        width,
                        height,
                        format,
                        path: "gbm",
                    });
                }
                Err(err) => {
                    self.gbm_unusable = true;
                    warn!(
                        modifier,
                        error = %format!("{err:#}"),
                        "GBM cannot map this compositor DMA-BUF; falling back to EGL readback"
                    );
                    Some(err)
                }
            }
        };
        if self.egl_unusable {
            bail!(
                "no driver-backed readback path remains for modifier {modifier:#018x}; refusing raw DMA-BUF mapping because it can publish tiled or corrupt pixels"
            );
        }
        match self.copy_dmabuf_with_egl(
            fd,
            offset,
            width,
            height,
            stride,
            video_format,
            modifier,
            target_width,
            target_height,
        ) {
            Ok(readback) => Ok(readback),
            Err(egl_error) => {
                self.egl_unusable = true;
                let egl_error = egl_error.context(format!(
                    "EGL readback failed for modifier {modifier:#018x}; refusing raw DMA-BUF mapping because it can publish tiled or corrupt pixels"
                ));
                Err(match gbm_error {
                    Some(gbm_error) => {
                        egl_error.context(format!("GBM readback also failed: {gbm_error:#}"))
                    }
                    None => egl_error,
                })
            }
        }
    }

    /// Imports the descriptor as an `EGLImage` and reads linear pixels back.
    #[allow(clippy::too_many_arguments)]
    fn copy_dmabuf_with_egl(
        &mut self,
        fd: RawFd,
        offset: usize,
        width: u32,
        height: u32,
        stride: usize,
        video_format: spa::param::video::VideoFormat,
        modifier: u64,
        target_width: u32,
        target_height: u32,
    ) -> Result<DmaBufReadback> {
        let fourcc = drm_fourcc_for_video_format(video_format)
            .with_context(|| format!("no DRM fourcc mapping for {video_format:?}"))?;
        let plane = DmaBufPlane {
            fd,
            offset: u32::try_from(offset).context("DMA-BUF offset exceeds EGL limits")?,
            stride: u32::try_from(stride).context("DMA-BUF stride exceeds EGL limits")?,
            width,
            height,
            fourcc,
            modifier,
        };
        let readback = self
            .egl()?
            .read_dmabuf_scaled(&plane, target_width, target_height)?;
        Ok(DmaBufReadback {
            data: readback.data,
            stride: readback.stride,
            width: readback.width,
            height: readback.height,
            format: match readback.layout {
                ReadbackLayout::Rgba => RawFrameFormat::Rgbx,
                ReadbackLayout::Bgra => RawFrameFormat::Bgrx,
            },
            path: "egl",
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn copy_dmabuf_with_gbm(
        &mut self,
        fd: RawFd,
        offset: usize,
        width: u32,
        height: u32,
        stride: usize,
        video_format: spa::param::video::VideoFormat,
        modifier: u64,
    ) -> Result<(Vec<u8>, usize)> {
        if fd < 0 {
            bail!("PipeWire supplied an invalid DMA-BUF descriptor");
        }
        let drm_fourcc = drm_fourcc_for_video_format(video_format)
            .with_context(|| format!("no DRM fourcc mapping for {video_format:?}"))?;
        let gbm_format = gbm::Format::try_from(drm_fourcc).map_err(|_| {
            anyhow::anyhow!(
                "GBM does not recognize DRM format {} ({drm_fourcc:#010x})",
                drm_fourcc_name(drm_fourcc)
            )
        })?;
        let stride = u32::try_from(stride).context("DMA-BUF stride exceeds GBM limits")?;
        // SAFETY: PipeWire owns this descriptor and keeps it valid while the
        // process callback and imported buffer object are alive.
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(fd) };
        let device = self.device()?;
        let buffer = if modifier == DRM_FORMAT_MOD_INVALID as u64 {
            if offset != 0 {
                bail!("implicit-modifier DMA-BUF has unsupported non-zero plane offset {offset}");
            }
            device
                .import_buffer_object_from_dma_buf::<()>(
                    borrowed_fd,
                    width,
                    height,
                    stride,
                    gbm_format,
                    gbm::BufferObjectFlags::empty(),
                )
                .context("importing implicit-modifier DMA-BUF into GBM")?
        } else {
            let offset = i32::try_from(offset).context("DMA-BUF offset exceeds GBM limits")?;
            let stride = i32::try_from(stride).context("DMA-BUF stride exceeds GBM limits")?;
            device
                .import_buffer_object_from_dma_buf_with_modifiers::<()>(
                    1,
                    [Some(borrowed_fd), None, None, None],
                    width,
                    height,
                    gbm_format,
                    gbm::BufferObjectFlags::empty(),
                    [stride, 0, 0, 0],
                    [offset, 0, 0, 0],
                    gbm::Modifier::from(modifier),
                )
                .context("importing explicit-modifier DMA-BUF into GBM")?
        };
        let deadline = Instant::now() + Duration::from_millis(100);
        loop {
            let mapped = buffer
                .map(device, 0, 0, width, height, |mapped| {
                    (mapped.buffer().to_vec(), mapped.stride() as usize)
                })
                .map_err(|_| anyhow::anyhow!("GBM buffer belongs to a different device"))?;
            match mapped {
                Ok(readback) => return Ok(readback),
                Err(err)
                    if err.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(err) => return Err(err).context("mapping imported DMA-BUF through GBM"),
            }
        }
    }
}

/// CPU-only build placeholder for compositor DMA-BUFs that are not mappable.
struct GpuReadback;

impl GpuReadback {
    fn new(_device_path: PathBuf) -> Self {
        Self
    }

    #[allow(clippy::too_many_arguments)]
    fn copy_dmabuf_scaled(
        &mut self,
        _fd: RawFd,
        _offset: usize,
        _width: u32,
        _height: u32,
        _stride: usize,
        _video_format: spa::param::video::VideoFormat,
        _modifier: u64,
        _target_width: u32,
        _target_height: u32,
    ) -> Result<DmaBufReadback> {
        bail!("non-mappable DMA-BUF capture requires a runtime GPU readback backend")
    }
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
    let requested_end = offset.checked_add(size)?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `stat` points to writable storage for one `libc::stat`, and `fd`
    // remains borrowed from the PipeWire buffer for the duration of this call.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } == 0 {
        // SAFETY: a successful `fstat` initialized the output structure.
        let extent = unsafe { stat.assume_init() }.st_size;
        if let Ok(extent) = usize::try_from(extent)
            && extent > 0
            && requested_end > extent
        {
            return None;
        }
    }
    // SAFETY: `sysconf` has no pointer arguments and `_SC_PAGESIZE` is a valid
    // query on the supported Unix platforms.
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
    // SAFETY: the offset is page-aligned, the length is non-zero and checked,
    // and the borrowed descriptor remains valid until after `munmap`.
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
    // SAFETY: the requested slice is contained in the successful mapping.
    let out = unsafe { std::slice::from_raw_parts((ptr as *const u8).add(delta), size).to_vec() };
    // SAFETY: `ptr` and `map_len` are exactly the mapping returned above.
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
    // SAFETY: `dup(2)` accepts an integer descriptor and returns an error for
    // an invalid one; no pointer or Rust borrow crosses the FFI boundary.
    let duplicated = unsafe { libc::dup(fd) };
    if duplicated < 0 {
        return None;
    }
    // SAFETY: a non-negative result from `dup` is a new descriptor owned by
    // the caller and may be transferred into exactly one `OwnedFd`.
    Some(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

fn sync_dmabuf_read(fd: RawFd, end: bool) {
    let flags = DMA_BUF_SYNC_READ | if end { DMA_BUF_SYNC_END } else { 0 };
    let sync = DmaBufSync { flags };
    // SAFETY: `sync` has the kernel ABI layout and remains alive for the ioctl;
    // an invalid or non-DMA-BUF descriptor is reported as a syscall error.
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
                // SAFETY: the listener and captured pointer are scoped within
                // `discover_portal_target_object`, before `mainloop` is dropped.
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
                // SAFETY: the listener and captured pointer are scoped within
                // this enumeration, before `mainloop` is dropped.
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
    /// Frame size the encoder wants, used to shrink during readback.
    target_width: u32,
    target_height: u32,
    format: spa::param::video::VideoInfoRaw,
    latest: watch::Sender<Option<RawFrame>>,
    cursor_latest: watch::Sender<Option<PipewireCursorSample>>,
    error: Arc<Mutex<Option<String>>>,
    expected_width: u32,
    expected_height: u32,
    min_frame_interval: Duration,
    require_cursor_metadata: bool,
    last_frame_copied_at: Option<Instant>,
    last_cursor_state: Option<PipewireCursorState>,
    cursor_meta_missing_since: Option<Instant>,
    cursor_meta_verified: bool,
    pending_video_damage: AccumulatedFrameDamage,
    mainloop_ptr: usize,
    gpu_readback: GpuReadback,
    unmapped_buffer_logged: bool,
    cursor_meta_logged: bool,
    rate_meter: CaptureRateMeter,
    serial: u64,
    cursor_serial: u64,
}

/// How long the capture rate meter averages before reporting.
const CAPTURE_RATE_WINDOW: Duration = Duration::from_secs(5);

/// Measures how fast a compositor actually feeds the capture stream.
///
/// The cursor overlay can only be as smooth as the rate PipeWire delivers
/// buffers carrying `SPA_META_Cursor`, and that rate is negotiated with the
/// compositor rather than chosen by this process. Reporting both the buffer
/// rate and the rate at which the cursor actually moved separates "the
/// compositor is slow" from "the cursor simply did not move".
struct CaptureRateMeter {
    window_started: Instant,
    buffers: u32,
    cursor_samples: u32,
    last_cursor_sample: Option<Instant>,
    max_cursor_gap: Duration,
}

/// One window's worth of what the compositor delivered.
struct CaptureRates {
    buffer_hz: f64,
    cursor_hz: f64,
    /// Longest interval between two cursor-carrying buffers in the window.
    ///
    /// The average rate hides a pause: thirty samples a second with a
    /// third-of-a-second hole in the middle averages the same as thirty evenly
    /// spaced ones, and only one of those looks smooth. This is also the number
    /// that separates a stall this process caused from one it merely relayed,
    /// because nothing downstream can be smoother than its input.
    max_cursor_gap: Duration,
}

impl CaptureRateMeter {
    fn new(now: Instant) -> Self {
        Self {
            window_started: now,
            buffers: 0,
            cursor_samples: 0,
            last_cursor_sample: None,
            max_cursor_gap: Duration::ZERO,
        }
    }

    /// Records one delivered buffer and returns the closed window's rates once
    /// `CAPTURE_RATE_WINDOW` has elapsed.
    fn record(&mut self, now: Instant, cursor_changed: bool) -> Option<CaptureRates> {
        self.buffers = self.buffers.saturating_add(1);
        if cursor_changed {
            self.cursor_samples = self.cursor_samples.saturating_add(1);
            if let Some(previous) = self.last_cursor_sample {
                self.max_cursor_gap = self
                    .max_cursor_gap
                    .max(now.saturating_duration_since(previous));
            }
            self.last_cursor_sample = Some(now);
        }
        let elapsed = now.saturating_duration_since(self.window_started);
        if elapsed < CAPTURE_RATE_WINDOW {
            return None;
        }
        let seconds = elapsed.as_secs_f64();
        let rates = CaptureRates {
            buffer_hz: f64::from(self.buffers) / seconds,
            cursor_hz: f64::from(self.cursor_samples) / seconds,
            max_cursor_gap: self.max_cursor_gap,
        };
        let last_cursor_sample = self.last_cursor_sample;
        *self = Self::new(now);
        // Carried across the boundary so a gap spanning two windows is still
        // measured rather than reset to zero halfway through.
        self.last_cursor_sample = last_cursor_sample;
        Some(rates)
    }
}

struct PipewireVideoUserData {
    format: spa::param::video::VideoInfoRaw,
    latest: watch::Sender<Option<PipewireVideoFrame>>,
    cursor_latest: watch::Sender<Option<PipewireCursorSample>>,
    error: Arc<Mutex<Option<String>>>,
    expected_width: u32,
    expected_height: u32,
    min_frame_interval: Duration,
    require_cursor_metadata: bool,
    last_frame_copied_at: Option<Instant>,
    last_cursor_state: Option<PipewireCursorState>,
    cursor_meta_missing_since: Option<Instant>,
    cursor_meta_verified: bool,
    pending_video_damage: AccumulatedFrameDamage,
    mainloop_ptr: usize,
    first_frame_logged: bool,
    cursor_meta_logged: bool,
    rate_meter: CaptureRateMeter,
    serial: u64,
    cursor_serial: u64,
}

fn record_pipewire_error(user_data: &PipewireUserData, message: String) {
    let mut slot = user_data
        .error
        .lock()
        .expect("PipeWire error mutex poisoned");
    *slot = Some(message);
    // SAFETY: user data and its main-loop pointer are created and destroyed on
    // the same capture thread, and callbacks cannot outlive that main loop.
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
    // SAFETY: user data and its main-loop pointer are created and destroyed on
    // the same capture thread, and callbacks cannot outlive that main loop.
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
    std::env::var("HOSTNAME").unwrap_or_else(|_| "gcpub".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_reconnect_backoff_is_fast_then_bounded() {
        assert_eq!(reconnect_delay(0), Duration::from_millis(250));
        assert_eq!(reconnect_delay(5), Duration::from_secs(8));
        assert_eq!(reconnect_delay(u32::MAX), Duration::from_secs(8));
    }

    fn invite_identity(viewer_url: Option<&str>, key: Option<&str>) -> ClientIdentity {
        ClientIdentity {
            client_id: "invite".to_string(),
            auth_token: None,
            ingest_server_key: None,
            viewer_key_b64: None,
            viewer_key_shareable: key.map(str::to_string),
            viewer_key_salt_b64: None,
            display_name: "Invite".to_string(),
            viewer_key_file: None,
            viewer_url: viewer_url.map(str::to_string),
            config_path: None,
            all_monitors: false,
        }
    }

    #[test]
    fn invite_link_carries_the_key_in_the_fragment() {
        // After the '#', so browsers never send the key to the relay.
        let identity = invite_identity(Some("https://cast.example.com"), Some("tomb-bold-egg"));
        assert_eq!(
            invite_link(&identity).as_deref(),
            Some("https://cast.example.com/#k=tomb-bold-egg"),
        );
    }

    #[test]
    fn invite_link_does_not_double_the_separator() {
        let identity = invite_identity(Some("https://cast.example.com/"), Some("tomb-bold-egg"));
        assert_eq!(
            invite_link(&identity).as_deref(),
            Some("https://cast.example.com/#k=tomb-bold-egg"),
        );
    }

    #[test]
    fn invite_link_needs_both_a_url_and_a_key() {
        assert_eq!(invite_link(&invite_identity(None, Some("phrase"))), None);
        assert_eq!(
            invite_link(&invite_identity(Some("https://cast.example.com"), None)),
            None,
        );
    }

    #[test]
    fn invite_link_encodes_a_hand_chosen_phrase() {
        // A configured phrase is arbitrary text and must not be able to break out
        // of the fragment or introduce another parameter.
        let identity = invite_identity(Some("https://cast.example.com"), Some("two words&k=x #y"));
        assert_eq!(
            invite_link(&identity).as_deref(),
            Some("https://cast.example.com/#k=two%20words%26k%3Dx%20%23y"),
        );
    }

    #[test]
    fn invite_link_leaves_generated_keys_untouched() {
        // Generated phrases are words and hyphens, and raw viewer keys are
        // URL-safe base64: encoding must be a no-op for both.
        assert_eq!(
            url_encode_fragment("tomb-bold-egg-inch-fuse-man-eager"),
            "tomb-bold-egg-inch-fuse-man-eager"
        );
        assert_eq!(
            url_encode_fragment("QCOivvKXAHqxDo6Wogi8d81yx14wCM-2NkaXvJjOSiM"),
            "QCOivvKXAHqxDo6Wogi8d81yx14wCM-2NkaXvJjOSiM",
        );
    }

    fn resend_object(stream_id: Uuid, sequence: u64, payload_len: usize) -> DashObject {
        let epoch_id = Uuid::from_u128(1);
        let keys = EpochKeys::derive(&[7; 32], stream_id, epoch_id).unwrap();
        DashObject::authenticated(
            NewDashObject {
                stream_id,
                epoch_id,
                kind: DashObjectKind::Media,
                sequence,
                segment_number: sequence,
                chunk_index: 0,
                timestamp: sequence,
                duration: 1,
                random_access: true,
                mime: "video/iso.segment",
                payload: vec![sequence as u8; payload_len],
            },
            &keys,
        )
        .unwrap()
    }

    #[test]
    fn resend_buffer_bounds_history_but_always_keeps_latest_object() {
        let stream_id = Uuid::from_u128(2);
        let mut resend = DashResendBuffer::new(5);
        resend.push(resend_object(stream_id, 1, 3));
        resend.push(resend_object(stream_id, 2, 3));
        assert_eq!(resend.range(), (Some(2), Some(2)));
        assert_eq!(resend.bytes, 3);

        resend.push(resend_object(stream_id, 3, 10));
        assert_eq!(resend.range(), (Some(3), Some(3)));
        assert_eq!(resend.bytes, 10);
    }

    #[test]
    fn dmabuf_readback_only_bypasses_gpu_for_linear_mappable_memory() {
        assert!(!dmabuf_requires_gpu_readback(
            true,
            true,
            DRM_FORMAT_MOD_LINEAR
        ));
        assert!(dmabuf_requires_gpu_readback(
            true,
            false,
            DRM_FORMAT_MOD_LINEAR
        ));
        assert!(dmabuf_requires_gpu_readback(
            true,
            true,
            DRM_FORMAT_MOD_INVALID as u64
        ));
        assert!(dmabuf_requires_gpu_readback(true, true, 0x10));
        assert!(!dmabuf_requires_gpu_readback(
            false,
            false,
            DRM_FORMAT_MOD_INVALID as u64
        ));
    }

    #[test]
    fn explicit_modifier_is_preferred_to_implicit_when_linear_is_unavailable() {
        const EXPLICIT_MODIFIER: u64 = 0x0300_0000_0060_6010;
        assert_eq!(
            preferred_safe_readback_modifier_from_values(&[
                DRM_FORMAT_MOD_INVALID as u64,
                EXPLICIT_MODIFIER,
            ]),
            Some(EXPLICIT_MODIFIER)
        );
        assert_eq!(
            preferred_safe_readback_modifier_from_values(&[
                EXPLICIT_MODIFIER,
                DRM_FORMAT_MOD_INVALID as u64,
                DRM_FORMAT_MOD_LINEAR,
            ]),
            Some(DRM_FORMAT_MOD_LINEAR)
        );
    }

    #[test]
    fn resend_buffer_ack_and_range_selection_are_inclusive() {
        let stream_id = Uuid::from_u128(3);
        let mut resend = DashResendBuffer::new(1024);
        for sequence in 1..=4 {
            resend.push(resend_object(stream_id, sequence, sequence as usize));
        }
        assert_eq!(
            resend
                .objects(2, 3)
                .into_iter()
                .map(|object| object.header.sequence)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        resend.ack(0);
        assert_eq!(resend.range(), (Some(1), Some(4)));
        resend.ack(2);
        assert_eq!(resend.range(), (Some(3), Some(4)));
        assert_eq!(resend.bytes, 7);
        resend.ack(u64::MAX);
        assert_eq!(resend.range(), (None, None));
        assert_eq!(resend.bytes, 0);
    }

    #[test]
    fn resend_buffer_drops_objects_assigned_to_a_previous_stream() {
        let retained_stream = Uuid::from_u128(4);
        let old_stream = Uuid::from_u128(5);
        let mut resend = DashResendBuffer::new(1024);
        resend.push(resend_object(old_stream, 1, 4));
        resend.push(resend_object(retained_stream, 2, 5));
        resend.push(resend_object(old_stream, 3, 6));

        resend.drop_other_streams(retained_stream);
        assert_eq!(resend.range(), (Some(2), Some(2)));
        assert_eq!(resend.bytes, 5);
    }

    #[test]
    fn command_line_accepts_url_safe_keys_that_begin_with_hyphens() {
        let args = Args::try_parse_from([
            "gcpub",
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
    fn client_config_must_be_private_regular_and_rejects_unknown_keys() {
        let root = std::env::temp_dir().join(format!("gcpub-config-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("client.toml");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(
            &mut file,
            b"client_id = \"desk\"\ndisplay_name = \"Desktop\"\n",
        )
        .unwrap();
        drop(file);
        assert_eq!(
            load_client_config(&path).unwrap().client_id.as_deref(),
            Some("desk")
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_client_config(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, "unknown_security_setting = true\n").unwrap();
        assert!(load_client_config(&path).is_err());

        let link = root.join("client-link.toml");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(load_client_config(&link).is_err());
        let dangling = root.join("client-dangling.toml");
        std::os::unix::fs::symlink(root.join("missing.toml"), &dangling).unwrap();
        assert!(load_client_config(&dangling).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    /// A capture whose source never opens, standing in for a desktop chooser
    /// that nobody answers.
    struct NeverOpeningCapture;

    #[async_trait]
    impl Capture for NeverOpeningCapture {
        async fn source(&mut self) -> Result<CaptureSource> {
            std::future::pending::<()>().await;
            unreachable!("pending future never resolves")
        }

        async fn capture_rgb(
            &mut self,
            _max_width: u32,
            _max_height: u32,
        ) -> Result<ImageBuffer<Rgb<u8>, Vec<u8>>> {
            unreachable!("the source never opens")
        }

        async fn cursor(&mut self, _seq: u64) -> Result<Option<CursorMessage>> {
            unreachable!("the source never opens")
        }
    }

    #[test]
    fn shutdown_interrupts_a_capture_source_waiting_on_a_desktop_chooser() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let args = Args::parse_from(["gcpub"]);
            let identity = ClientIdentity {
                client_id: "chooser".to_string(),
                auth_token: None,
                ingest_server_key: None,
                viewer_key_b64: None,
                viewer_key_shareable: None,
                viewer_key_salt_b64: None,
                display_name: "Chooser".to_string(),
                viewer_key_file: None,
                viewer_url: None,
                config_path: None,
                all_monitors: false,
            };
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let mut capture = NeverOpeningCapture;
            let mut resend = DashResendBuffer::new(1024);
            let publisher = run_dash_client(
                &args,
                StreamIdentity {
                    client: &identity,
                    label: None,
                },
                Some(&[7u8; 32]),
                &mut capture,
                &mut resend,
                shutdown_rx,
            );
            tokio::pin!(publisher);
            tokio::select! {
                result = &mut publisher => panic!("publisher returned early: {result:?}"),
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
            shutdown_tx.send(true).unwrap();
            timeout(Duration::from_secs(5), publisher)
                .await
                .expect("shutdown must interrupt an unanswered chooser")
                .expect("interrupted startup is a clean exit");
        });
    }

    #[test]
    fn generated_viewer_key_is_private_and_stable_across_restarts() {
        let root = std::env::temp_dir().join(format!("glacialcast-viewer-key-{}", Uuid::new_v4()));
        let path = root.join("viewer.key");

        let created = load_or_create_viewer_key(&path, false).unwrap();
        assert_eq!(decode_key_b64(&created.key_b64).unwrap().len(), 32);
        assert_eq!(
            created.shareable.split('-').count(),
            viewer_key::PHRASE_WORDS,
            "a fresh key is shared as a phrase, not as raw base64"
        );
        assert!(created.salt_b64.is_some());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "a generated viewer key must not be readable by other users"
        );
        // Restarting the publisher must republish under the same key so the
        // secret already shared with viewers keeps working.
        let reloaded = load_or_create_viewer_key(&path, false).unwrap();
        assert_eq!(reloaded.key_b64, created.key_b64);
        assert_eq!(reloaded.shareable, created.shareable);
        assert_eq!(reloaded.salt_b64, created.salt_b64);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            load_or_create_viewer_key(&path, false).is_err(),
            "a group- or world-readable viewer key must be rejected, not reused"
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, "not-a-32-byte-key\n").unwrap();
        assert!(
            load_or_create_viewer_key(&path, false).is_err(),
            "a malformed viewer key must be rejected, not silently replaced"
        );

        std::fs::write(&path, "").unwrap();
        assert!(load_or_create_viewer_key(&path, false).is_err());

        std::fs::remove_dir_all(root).unwrap();
    }

    /// A publisher that has already shared a raw base64 key must keep using it.
    /// Rewriting it into a phrase would silently invalidate every key already
    /// handed out.
    #[test]
    fn a_pre_phrase_viewer_key_file_keeps_working_untouched() {
        let root = std::env::temp_dir().join(format!("glacialcast-legacy-key-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("viewer.key");
        let legacy = encode_key_b64(&[9u8; 32]);
        std::fs::write(&path, format!("{legacy}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let loaded = load_or_create_viewer_key(&path, false).unwrap();
        assert_eq!(loaded.key_b64, legacy);
        assert_eq!(loaded.shareable, legacy);
        assert_eq!(
            loaded.salt_b64, None,
            "a raw key needs no salt, because nothing is derived from it"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap().trim(),
            legacy,
            "loading must not rewrite an existing key file"
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn regenerating_replaces_the_shared_key() {
        let root = std::env::temp_dir().join(format!("glacialcast-rotate-key-{}", Uuid::new_v4()));
        let path = root.join("viewer.key");

        let first = load_or_create_viewer_key(&path, false).unwrap();
        let second = load_or_create_viewer_key(&path, true).unwrap();
        assert_ne!(first.shareable, second.shareable);
        assert_ne!(first.key_b64, second.key_b64);
        // The replacement must survive, or the next start would go back to the
        // key the operator just retired.
        assert_eq!(
            load_or_create_viewer_key(&path, false).unwrap().key_b64,
            second.key_b64
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn generated_state_paths_sanitize_the_client_identity() {
        let key = default_viewer_key_file("desk/../../etc");
        let log = default_log_file("desk/../../etc");
        assert_eq!(
            key.file_name().unwrap().to_string_lossy(),
            "viewer-desk-------etc.key"
        );
        assert_eq!(
            log.file_name().unwrap().to_string_lossy(),
            "client-desk-------etc.log"
        );
        assert_eq!(key.parent(), log.parent());
        assert_eq!(
            default_viewer_key_file("///").file_name().unwrap(),
            "viewer-client.key"
        );
    }

    #[test]
    fn published_pipewire_mainloop_clears_pointer_before_owner_drop() {
        let slot = Arc::new(Mutex::new(None));
        {
            let _published = PublishedPipewireMainloop::new(slot.clone(), 42);
            assert_eq!(*slot.lock().unwrap(), Some(42));
        }
        assert_eq!(*slot.lock().unwrap(), None);
    }

    #[test]
    fn fd_mapping_rejects_a_slice_beyond_the_reported_extent() {
        let path = std::env::temp_dir().join(format!("glacialcast-mmap-test-{}", Uuid::new_v4()));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.set_len(4096).unwrap();
        let fd = std::os::fd::AsRawFd::as_raw_fd(&file);

        assert_eq!(mmap_fd_slice(fd, 4000, 96, false).unwrap().len(), 96);
        assert!(mmap_fd_slice(fd, 4000, 97, false).is_none());
        assert!(mmap_fd_slice(fd, usize::MAX, 1, false).is_none());

        drop(file);
        std::fs::remove_file(path).unwrap();
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
        // Low rates stay allowed for capture validation, but the frame period
        // they imply is one Firefox cannot decode, and the warning keys off
        // this predicate.
        assert!(update_rate_outlasts_firefox(0.5));
        assert!(update_rate_outlasts_firefox(1.0));
        assert!(!update_rate_outlasts_firefox(1.3));
        assert!(!update_rate_outlasts_firefox(5.0));
        assert_eq!(parse_update_rate("15").unwrap(), 15.0);
        assert!(parse_update_rate("0.25").is_err());
        assert!(parse_update_rate("16").is_err());
    }

    #[test]
    fn idle_heartbeat_is_bounded() {
        // Fractions matter: the default must sit under the one-second sample
        // duration that stalls in Firefox.
        assert!((parse_idle_heartbeat_seconds("0.5").unwrap() - 0.5).abs() < f64::EPSILON);
        assert!((parse_idle_heartbeat_seconds("1").unwrap() - 1.0).abs() < f64::EPSILON);
        assert!((parse_idle_heartbeat_seconds("300").unwrap() - 300.0).abs() < f64::EPSILON);
        assert!(parse_idle_heartbeat_seconds("0.1").is_err());
        assert!(parse_idle_heartbeat_seconds("0").is_err());
        assert!(parse_idle_heartbeat_seconds("301").is_err());
        assert!(parse_idle_heartbeat_seconds("NaN").is_err());
    }

    #[test]
    fn adaptive_media_cadence_coalesces_idle_time_and_flushes_before_changes() {
        let mut cadence = AdaptiveMediaCadence::new(90_000, 900_000);
        assert_eq!(
            cadence.observe(90_000, false),
            MediaCadenceDecision {
                encode_pending_timestamp: Some(90_000),
                ..MediaCadenceDecision::default()
            }
        );
        assert_eq!(
            cadence.observe(540_000, false),
            MediaCadenceDecision::default()
        );
        assert_eq!(
            cadence.observe(990_000, false),
            MediaCadenceDecision {
                flush_pending_duration: Some(900_000),
                encode_pending_timestamp: Some(990_000),
                ..MediaCadenceDecision::default()
            }
        );
        assert_eq!(
            cadence.observe(1_080_000, true),
            MediaCadenceDecision {
                flush_pending_duration: Some(90_000),
                publish_current_timestamp: Some(1_080_000),
                ..MediaCadenceDecision::default()
            }
        );
        assert_eq!(cadence.finish(1_170_000), None);
    }

    #[test]
    fn adaptive_media_cadence_never_overlaps_a_previous_sample() {
        let mut cadence = AdaptiveMediaCadence::new(90_000, 900_000);
        assert_eq!(
            cadence.observe(89_000, true).publish_current_timestamp,
            Some(90_000)
        );
        assert_eq!(
            cadence.observe(150_000, true).publish_current_timestamp,
            Some(180_000)
        );
    }

    #[test]
    fn rgb_fingerprint_defends_against_incorrect_change_hints() {
        let first = [1; 32];
        let second = [2; 32];
        assert!(!frame_changed(
            FrameChange::Unknown,
            Some(&first),
            Some(&first)
        ));
        assert!(frame_changed(
            FrameChange::Unknown,
            Some(&first),
            Some(&second)
        ));
        assert!(frame_changed(
            FrameChange::Unchanged,
            Some(&first),
            Some(&second)
        ));
        assert!(!frame_changed(
            FrameChange::Changed,
            Some(&first),
            Some(&first)
        ));
        assert!(frame_changed(FrameChange::Changed, None, None));
        assert!(frame_changed(FrameChange::Unknown, None, None));
    }

    #[test]
    fn pipewire_damage_accumulates_across_video_throttling() {
        let mut damage = AccumulatedFrameDamage::default();

        damage.observe(Some(false));
        assert_eq!(damage.take(), Some(false));

        damage.observe(Some(false));
        damage.observe(Some(true));
        damage.observe(Some(false));
        assert_eq!(damage.take(), Some(true));

        damage.observe(None);
        damage.observe(Some(false));
        assert_eq!(damage.take(), None);
        assert_eq!(damage.take(), None);
    }

    #[test]
    fn test_patterns_model_static_typing_scroll_and_motion_damage() {
        let mut static_pattern = TestPatternCapture::new(96, 96, TestPatternMode::Static);
        let static_first = static_pattern.next_rgb();
        let static_second = static_pattern.next_rgb();
        assert_eq!(static_first, static_second);
        assert!(!static_pattern.frame_changed());

        let mut typing = TestPatternCapture::new(96, 96, TestPatternMode::Typing);
        let first = typing.next_rgb();
        let second = typing.next_rgb();
        assert_eq!(first, second);
        typing.next_rgb();
        let fourth = typing.next_rgb();
        assert_ne!(second, fourth);
        assert!(typing.frame_changed());

        for mode in [TestPatternMode::Scroll, TestPatternMode::Motion] {
            let mut pattern = TestPatternCapture::new(96, 96, mode);
            let first = pattern.next_rgb();
            let second = pattern.next_rgb();
            assert_ne!(first, second);
            assert!(pattern.frame_changed());
        }
    }

    #[test]
    fn pipewire_capture_rate_tracks_cursor_rate_above_frame_rate() {
        assert_eq!(pipewire_capture_rate(1.0, 30), 30.0);
        assert_eq!(pipewire_capture_rate(15.0, 10), 15.0);
        // The default cursor rate must survive intact: niri delivers cursor
        // metadata at the panel rate, and clamping here would discard half of
        // it before the publisher ever sees it.
        assert_eq!(pipewire_capture_rate(1.0, 60), 60.0);
        assert_eq!(pipewire_capture_rate(15.0, 240), 120.0);
    }

    #[test]
    fn capture_rate_meter_reports_once_per_window() {
        let start = Instant::now();
        let mut meter = CaptureRateMeter::new(start);
        assert!(meter.record(start + Duration::from_secs(1), true).is_none());
        let rates = meter
            .record(start + CAPTURE_RATE_WINDOW, false)
            .expect("the window closes once it is full");
        assert!((rates.buffer_hz - 0.4).abs() < 1e-9, "{}", rates.buffer_hz);
        assert!((rates.cursor_hz - 0.2).abs() < 1e-9, "{}", rates.cursor_hz);
        // A closed window restarts empty rather than accumulating forever.
        assert!(
            meter
                .record(start + CAPTURE_RATE_WINDOW + Duration::from_secs(1), true)
                .is_none()
        );
    }

    /// An average rate hides a pause, and a pause is what a person sees. The
    /// gap has to survive a window boundary too, or a stall straddling one
    /// would be reported as two short ones.
    #[test]
    fn capture_rate_meter_measures_the_worst_pause_across_windows() {
        let start = Instant::now();
        let mut meter = CaptureRateMeter::new(start);
        let step = Duration::from_millis(20);
        meter.record(start, true);
        meter.record(start + step, true);
        // One 500 ms hole, with steady sampling either side of it, so the
        // reported gap has to be the hole rather than the sampling interval.
        meter.record(start + Duration::from_millis(520), true);
        let mut at = Duration::from_millis(520);
        let mut closed = None;
        while closed.is_none() {
            at += step;
            closed = meter.record(start + at, true);
        }
        let rates = closed.expect("the window closes once it is full");
        assert_eq!(rates.max_cursor_gap, Duration::from_millis(500));

        // The next window starts fresh, but still remembers when the last
        // sample was, so a gap straddling the boundary is measured whole
        // rather than as two shorter ones.
        at += Duration::from_millis(300);
        let mut closed = meter.record(start + at, true);
        while closed.is_none() {
            at += step;
            closed = meter.record(start + at, true);
        }
        let next = closed.expect("the second window closes too");
        assert!(
            next.max_cursor_gap >= Duration::from_millis(300),
            "a gap across the window boundary was lost: {:?}",
            next.max_cursor_gap
        );
    }

    #[test]
    fn portal_restore_tokens_round_trip_and_reject_junk() {
        let root = std::env::temp_dir().join(format!("glacialcast-portal-{}", Uuid::new_v4()));
        let path = root.join("portal.token");

        // Nothing stored yet means "prompt", not an error.
        assert_eq!(PortalRestoreToken::load(path.clone()).value(), None);

        PortalRestoreToken::load(path.clone()).save("opaque-token-value");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "the grant token must not be readable by other users"
        );
        assert_eq!(
            PortalRestoreToken::load(path.clone()).value(),
            Some("opaque-token-value")
        );

        // Replacing it is atomic and leaves no temporary behind.
        PortalRestoreToken::load(path.clone()).save("second-token");
        assert_eq!(
            PortalRestoreToken::load(path.clone()).value(),
            Some("second-token")
        );
        assert!(!path.with_extension("tmp").exists());

        // A malformed file falls back to prompting rather than replaying junk.
        std::fs::write(&path, "  \n").unwrap();
        assert_eq!(PortalRestoreToken::load(path.clone()).value(), None);
        std::fs::write(&path, "has space").unwrap();
        assert_eq!(PortalRestoreToken::load(path.clone()).value(), None);
        std::fs::write(&path, "x".repeat(MAX_PORTAL_RESTORE_TOKEN_LEN + 1)).unwrap();
        assert_eq!(PortalRestoreToken::load(path.clone()).value(), None);

        // An implausibly long token from the portal is not stored at all.
        std::fs::remove_file(&path).unwrap();
        PortalRestoreToken::load(path.clone()).save(&"y".repeat(MAX_PORTAL_RESTORE_TOKEN_LEN + 1));
        assert!(!path.exists());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn portal_token_paths_sanitize_the_client_identity() {
        assert_eq!(
            default_portal_token_file("desk/../etc")
                .file_name()
                .unwrap(),
            "portal-desk----etc.token"
        );
        assert_eq!(
            default_portal_token_file("///").file_name().unwrap(),
            "portal-client.token"
        );
    }

    #[test]
    fn source_labels_are_reduced_to_relay_safe_characters() {
        assert_eq!(sanitize_source_label("DP-3"), "DP-3");
        assert_eq!(sanitize_source_label("HDMI-A-1"), "HDMI-A-1");
        // The relay splits the durable identity on the first colon, so a
        // connector containing one must never survive into a label.
        assert_eq!(sanitize_source_label("desk:evil"), "desk-evil");
        assert_eq!(sanitize_source_label("../../etc"), "etc");
        assert_eq!(sanitize_source_label(""), "output");
        assert_eq!(sanitize_source_label("---"), "output");
        assert!(sanitize_source_label(&"x".repeat(200)).len() <= 64);
    }

    #[test]
    fn segment_length_tracks_the_frame_rate() {
        let args_at = |fps: f64| Args::parse_from(["gcpub", "--fps", &fps.to_string()]);
        // Segment boundaries force an IDR, so the frame count has to rise with
        // the frame rate or the keyframe rate rises instead and takes the
        // bitrate with it.
        assert_eq!(args_at(1.0).segment_frames(), 4);
        assert_eq!(args_at(5.0).segment_frames(), 20);
        assert_eq!(args_at(15.0).segment_frames(), 60);
        assert_eq!(args_at(0.5).segment_frames(), 2);

        // An explicit choice still wins.
        let explicit = Args::parse_from(["gcpub", "--fps", "5", "--segment-frames", "4"]);
        assert_eq!(explicit.segment_frames(), 4);
    }

    #[test]
    fn cursor_flush_interval_is_bounded() {
        assert_eq!(parse_cursor_flush_ms("100"), Ok(100));
        assert_eq!(parse_cursor_flush_ms(" 20 "), Ok(20));
        assert!(parse_cursor_flush_ms("19").is_err());
        assert!(parse_cursor_flush_ms("1001").is_err());
        assert!(parse_cursor_flush_ms("soon").is_err());
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
    fn pipewire_cursor_meta_request_negotiates_ecosystem_bitmap_range() {
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
        let size = object
            .find_prop(spa::utils::Id(spa::sys::SPA_PARAM_META_size))
            .expect("cursor meta request size property");
        let mut size_bytes = size.value().as_bytes().to_vec();
        size_bytes.resize(size_bytes.len().next_multiple_of(8), 0);
        let (_, value) =
            spa::pod::deserialize::PodDeserializer::deserialize_from::<spa::pod::Value>(
                &size_bytes,
            )
            .unwrap();
        let spa::pod::Value::Choice(spa::pod::ChoiceValue::Int(choice)) = value else {
            panic!("cursor meta size must be an integer choice range");
        };
        assert_eq!(
            choice.1,
            spa::utils::ChoiceEnum::Range {
                default: pipewire_cursor_meta_size(PIPEWIRE_CURSOR_DEFAULT_BITMAP_SIDE),
                min: pipewire_cursor_meta_size(PIPEWIRE_CURSOR_MIN_BITMAP_SIDE),
                max: pipewire_cursor_meta_size(PIPEWIRE_CURSOR_NEGOTIATED_MAX_BITMAP_SIDE),
            }
        );
    }

    #[test]
    fn pipewire_damage_meta_request_has_type_and_capacity() {
        let bytes = build_pipewire_damage_meta_param_pod().unwrap();
        let pod = spa::pod::Pod::from_bytes(&bytes).unwrap();
        let object = <&spa::pod::PodObject>::try_from(pod).unwrap();
        let meta_type = object
            .find_prop(spa::utils::Id(spa::sys::SPA_PARAM_META_type))
            .expect("damage meta request type property");
        assert_eq!(
            meta_type.value().get_id().unwrap(),
            spa::utils::Id(spa::sys::SPA_META_VideoDamage)
        );
        assert!(
            object
                .find_prop(spa::utils::Id(spa::sys::SPA_PARAM_META_size))
                .is_some()
        );
    }

    #[test]
    fn pipewire_damage_metadata_distinguishes_idle_changed_and_unknown_buffers() {
        let damage = |width, height, complete: bool| {
            let mut region = spa::sys::spa_meta_region {
                region: spa::sys::spa_region {
                    position: spa::sys::spa_point { x: 0, y: 0 },
                    size: spa::sys::spa_rectangle { width, height },
                },
            };
            let mut meta = spa::sys::spa_meta {
                type_: spa::sys::SPA_META_VideoDamage,
                size: std::mem::size_of::<spa::sys::spa_meta_region>() as u32
                    - u32::from(!complete),
                data: (&mut region as *mut spa::sys::spa_meta_region).cast(),
            };
            let buffer = spa::sys::spa_buffer {
                n_metas: 1,
                n_datas: 0,
                metas: &mut meta,
                datas: ptr::null_mut(),
            };
            pipewire_video_damage(&buffer)
        };

        assert_eq!(damage(0, 0, true), Some(false));
        assert_eq!(damage(12, 8, true), Some(true));
        assert_eq!(damage(12, 8, false), None);
        assert_eq!(pipewire_video_damage(ptr::null()), None);
    }

    #[test]
    fn pipewire_cursor_metadata_coalesces_duplicates_without_losing_changes() {
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

        let first = pipewire_cursor_sample(&buffer, 100, 80, &mut serial, &mut last_state)
            .expect("first cursor sample");
        assert_eq!(first.serial, 1);
        assert_eq!(first.x, 25.0);
        assert_eq!(first.y, 40.0);
        assert!(first.visible);
        assert!(first.bitmap.is_none());
        assert!(pipewire_cursor_sample(&buffer, 100, 80, &mut serial, &mut last_state).is_none());

        // SAFETY: `meta.data` points to the live `cursor` fixture.
        unsafe {
            (*meta.data.cast::<spa::sys::spa_meta_cursor>()).position.x = 30;
        }
        let moved = pipewire_cursor_sample(&buffer, 100, 80, &mut serial, &mut last_state)
            .expect("changed cursor sample");
        assert_eq!(moved.serial, 2);
        assert_eq!(moved.x, 30.0);
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

        let PipewireCursorUpdate::Visible(state) = pipewire_cursor_update(&buffer) else {
            panic!("expected visible cursor state");
        };
        let bitmap = state.bitmap.expect("cursor bitmap");
        assert_eq!(bitmap.width, 2);
        assert_eq!(bitmap.height, 2);
        assert_eq!(bitmap.hotspot_x, 1);
        assert_eq!(bitmap.hotspot_y, 1);
        assert_eq!(bitmap.rgba.as_ref(), &rgba_pixels);

        let mut serial = 0;
        let mut last_state = None;
        let first = pipewire_cursor_sample(&buffer, 100, 80, &mut serial, &mut last_state)
            .expect("bitmap cursor sample");
        // SAFETY: `meta.data` points to the live cursor fixture.
        unsafe {
            let cursor = &mut *meta.data.cast::<spa::sys::spa_meta_cursor>();
            cursor.position.x = 26;
            cursor.bitmap_offset = 0;
        }
        let moved = pipewire_cursor_sample(&buffer, 100, 80, &mut serial, &mut last_state)
            .expect("position-only cursor sample");
        assert!(Arc::ptr_eq(
            first.bitmap.as_ref().unwrap(),
            moved.bitmap.as_ref().unwrap()
        ));
    }

    #[test]
    fn dash_cursor_sends_bitmap_pixels_on_change_and_periodic_refresh() {
        let rgba = [255, 0, 0, 255, 0, 255, 0, 255];
        let bitmap = Arc::new(CursorBitmap {
            width: 2,
            height: 1,
            hotspot_x: 1,
            hotspot_y: 0,
            rgba: Arc::from(rgba),
        });
        let message = |bitmap| CursorMessage {
            x: 10.0,
            y: 20.0,
            visible: true,
            source_width: 100,
            source_height: 100,
            bitmap,
        };
        let mut state = DashCursorBitmapState::default();
        let first =
            cursor_to_dash_event(message(Some(Arc::clone(&bitmap))), 10, 100, 100, &mut state)
                .unwrap();
        let repeated =
            cursor_to_dash_event(message(Some(Arc::clone(&bitmap))), 20, 100, 100, &mut state)
                .unwrap();
        let refreshed = cursor_to_dash_event(
            message(Some(bitmap)),
            CURSOR_BITMAP_REFRESH_TICKS + 10,
            100,
            100,
            &mut state,
        )
        .unwrap();
        let position_only = cursor_to_dash_event(
            message(None),
            CURSOR_BITMAP_REFRESH_TICKS + 20,
            100,
            100,
            &mut state,
        )
        .unwrap();

        assert!(first.bitmap.is_some());
        assert!(repeated.bitmap.is_none());
        assert!(refreshed.bitmap.is_some());
        assert_eq!(repeated.bitmap_id, first.bitmap_id);
        assert_eq!(refreshed.bitmap_id, first.bitmap_id);
        assert_eq!(position_only.bitmap_id, first.bitmap_id);
    }

    #[test]
    fn dash_cursor_scales_clamps_and_hides_coordinates() {
        let message = |x, y, visible| CursorMessage {
            x,
            y,
            visible,
            source_width: 200,
            source_height: 100,
            bitmap: None,
        };
        let mut state = DashCursorBitmapState::default();

        let scaled =
            cursor_to_dash_event(message(50.0, 25.0, true), 1, 100, 200, &mut state).unwrap();
        assert_eq!(scaled.x_micropixels, 25_000_000);
        assert_eq!(scaled.y_micropixels, 50_000_000);
        assert!(scaled.visible);

        let clamped =
            cursor_to_dash_event(message(-10.0, f32::INFINITY, true), 2, 100, 200, &mut state)
                .unwrap();
        assert_eq!(clamped.x_micropixels, 0);
        assert_eq!(clamped.y_micropixels, 0);

        let hidden =
            cursor_to_dash_event(message(50.0, 25.0, false), 3, 100, 200, &mut state).unwrap();
        assert_eq!(hidden.x_micropixels, 0);
        assert_eq!(hidden.y_micropixels, 0);
        assert!(!hidden.visible);
    }

    #[test]
    fn test_pattern_cursor_cycles_through_visible_and_hidden_states() {
        assert!(test_pattern_cursor_visible(1));
        assert!(test_pattern_cursor_visible(19));
        assert!(!test_pattern_cursor_visible(20));
        assert!(!test_pattern_cursor_visible(29));
        assert!(test_pattern_cursor_visible(30));
    }

    #[test]
    fn dash_cursor_rejects_inconsistent_bitmap_dimensions() {
        let cursor = CursorMessage {
            x: 0.0,
            y: 0.0,
            visible: true,
            source_width: 1,
            source_height: 1,
            bitmap: Some(Arc::new(CursorBitmap {
                width: 2,
                height: 2,
                hotspot_x: 0,
                hotspot_y: 0,
                rgba: Arc::from([0u8; 15]),
            })),
        };
        assert!(
            cursor_to_dash_event(cursor, 0, 1, 1, &mut DashCursorBitmapState::default()).is_err()
        );
    }

    #[test]
    fn pipewire_cursor_pixel_formats_convert_without_panicking_on_short_input() {
        let pixel = [10, 20, 30, 40];
        for (format, expected) in [
            (spa::sys::SPA_VIDEO_FORMAT_RGBA, [10, 20, 30, 40]),
            (spa::sys::SPA_VIDEO_FORMAT_BGRA, [30, 20, 10, 40]),
            (spa::sys::SPA_VIDEO_FORMAT_ARGB, [20, 30, 40, 10]),
            (spa::sys::SPA_VIDEO_FORMAT_ABGR, [40, 30, 20, 10]),
            (spa::sys::SPA_VIDEO_FORMAT_RGBx, [10, 20, 30, 255]),
            (spa::sys::SPA_VIDEO_FORMAT_BGRx, [30, 20, 10, 255]),
            (spa::sys::SPA_VIDEO_FORMAT_xRGB, [20, 30, 40, 255]),
            (spa::sys::SPA_VIDEO_FORMAT_xBGR, [40, 30, 20, 255]),
        ] {
            assert_eq!(cursor_pixel_as_rgba(format, &pixel), Some(expected));
        }
        assert_eq!(
            cursor_pixel_as_rgba(spa::sys::SPA_VIDEO_FORMAT_RGBA, &[1, 2, 3]),
            None
        );
        assert_eq!(
            cursor_pixel_as_rgba(spa::sys::SPA_VIDEO_FORMAT_UNKNOWN, &pixel),
            None
        );
    }

    #[test]
    fn pipewire_cursor_bitmap_rejects_malformed_layouts_and_excessive_dimensions() {
        #[repr(C)]
        struct CursorMetaFixture {
            cursor: spa::sys::spa_meta_cursor,
            bitmap: spa::sys::spa_meta_bitmap,
            pixels: [u8; 16],
        }

        let bitmap_offset = std::mem::offset_of!(CursorMetaFixture, bitmap);
        let pixel_offset = std::mem::offset_of!(CursorMetaFixture, pixels) - bitmap_offset;
        let mut fixture = CursorMetaFixture {
            cursor: spa::sys::spa_meta_cursor {
                id: 1,
                flags: 0,
                position: spa::sys::spa_point { x: 0, y: 0 },
                hotspot: spa::sys::spa_point { x: 0, y: 0 },
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
            pixels: [0; 16],
        };
        let meta = spa::sys::spa_meta {
            type_: spa::sys::SPA_META_Cursor,
            size: std::mem::size_of::<CursorMetaFixture>() as u32,
            data: (&mut fixture.cursor as *mut spa::sys::spa_meta_cursor).cast(),
        };

        fixture.bitmap.stride = 7;
        assert!(pipewire_cursor_bitmap(&meta, &fixture.cursor).is_none());
        fixture.bitmap.stride = 8;
        fixture.bitmap.offset = 0;
        assert!(pipewire_cursor_bitmap(&meta, &fixture.cursor).is_none());
        fixture.bitmap.offset = pixel_offset as u32;
        fixture.bitmap.size.width = PIPEWIRE_CURSOR_MAX_BITMAP_SIDE as u32 + 1;
        assert!(pipewire_cursor_bitmap(&meta, &fixture.cursor).is_none());
        fixture.bitmap.size.width = 2;
        fixture.cursor.bitmap_offset = 1;
        assert!(pipewire_cursor_bitmap(&meta, &fixture.cursor).is_none());
    }

    #[test]
    fn pipewire_cursor_metadata_zero_id_hides_a_visible_cursor_once() {
        let mut cursor = spa::sys::spa_meta_cursor {
            id: 7,
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

        let mut serial = 0;
        let mut last_state = None;
        assert!(
            pipewire_cursor_sample(&buffer, 100, 80, &mut serial, &mut last_state)
                .unwrap()
                .visible
        );

        // SAFETY: `meta.data` points to the live `cursor` fixture.
        unsafe {
            (*meta.data.cast::<spa::sys::spa_meta_cursor>()).id = 0;
        }
        let hidden = pipewire_cursor_sample(&buffer, 100, 80, &mut serial, &mut last_state)
            .expect("cursor hidden update");
        assert!(!hidden.visible);
        assert!(hidden.bitmap.is_none());
        assert!(pipewire_cursor_sample(&buffer, 100, 80, &mut serial, &mut last_state).is_none());
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

        let mut cursor = spa::sys::spa_meta_cursor {
            id: 0,
            flags: 0,
            position: spa::sys::spa_point { x: 0, y: 0 },
            hotspot: spa::sys::spa_point { x: 0, y: 0 },
            bitmap_offset: 0,
        };
        let mut metas = [
            spa::sys::spa_meta {
                type_: spa::sys::SPA_META_Busy,
                size: 8,
                data: ptr::null_mut(),
            },
            spa::sys::spa_meta {
                type_: spa::sys::SPA_META_Cursor,
                size: std::mem::size_of::<spa::sys::spa_meta_cursor>() as u32,
                data: (&mut cursor as *mut spa::sys::spa_meta_cursor).cast(),
            },
        ];
        let cursor_buffer = spa::sys::spa_buffer {
            n_metas: metas.len() as u32,
            n_datas: 0,
            metas: metas.as_mut_ptr(),
            datas: ptr::null_mut(),
        };
        assert!(pipewire_buffer_has_cursor_meta(&cursor_buffer));

        // SAFETY: `cursor_buffer.metas` points to the two-element `metas` fixture.
        unsafe {
            (*cursor_buffer.metas.add(1)).data = ptr::null_mut();
        }
        assert!(!pipewire_buffer_has_cursor_meta(&cursor_buffer));
        // SAFETY: the fixture and cursor both remain live for this assertion.
        unsafe {
            (*cursor_buffer.metas.add(1)).data =
                (&mut cursor as *mut spa::sys::spa_meta_cursor).cast();
            (*cursor_buffer.metas.add(1)).size =
                std::mem::size_of::<spa::sys::spa_meta_cursor>() as u32 - 1;
        }
        assert!(!pipewire_buffer_has_cursor_meta(&cursor_buffer));
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
        let mut cursor = spa::sys::spa_meta_cursor {
            id: 0,
            flags: 0,
            position: spa::sys::spa_point { x: 0, y: 0 },
            hotspot: spa::sys::spa_point { x: 0, y: 0 },
            bitmap_offset: 0,
        };
        let mut cursor_meta = spa::sys::spa_meta {
            type_: spa::sys::SPA_META_Cursor,
            size: std::mem::size_of::<spa::sys::spa_meta_cursor>() as u32,
            data: (&mut cursor as *mut spa::sys::spa_meta_cursor).cast(),
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
    fn required_pipewire_cursor_metadata_fails_if_allocation_disappears() {
        let mut cursor = spa::sys::spa_meta_cursor {
            id: 0,
            flags: 0,
            position: spa::sys::spa_point { x: 0, y: 0 },
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
        let now = Instant::now();
        let mut verified = false;
        let mut missing_since = None;
        assert_eq!(
            pipewire_cursor_metadata_gate(&buffer, true, &mut verified, &mut missing_since, now),
            PipewireCursorMetadataGate::Ready
        );

        // SAFETY: `buffer.metas` points to the live one-element metadata fixture.
        unsafe {
            (*buffer.metas).data = ptr::null_mut();
        }
        assert_eq!(
            pipewire_cursor_metadata_gate(
                &buffer,
                true,
                &mut verified,
                &mut missing_since,
                now + Duration::from_millis(1)
            ),
            PipewireCursorMetadataGate::Pending
        );
        assert_eq!(
            pipewire_cursor_metadata_gate(
                &buffer,
                true,
                &mut verified,
                &mut missing_since,
                now + PIPEWIRE_CURSOR_METADATA_GRACE + Duration::from_millis(1)
            ),
            PipewireCursorMetadataGate::Fatal
        );
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

        let mut cursor = spa::sys::spa_meta_cursor {
            id: 0,
            flags: 0,
            position: spa::sys::spa_point { x: 0, y: 0 },
            hotspot: spa::sys::spa_point { x: 0, y: 0 },
            bitmap_offset: 0,
        };
        let mut cursor_meta = spa::sys::spa_meta {
            type_: spa::sys::SPA_META_Cursor,
            size: std::mem::size_of::<spa::sys::spa_meta_cursor>() as u32,
            data: (&mut cursor as *mut spa::sys::spa_meta_cursor).cast(),
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
            preferred_safe_readback_modifier(pod),
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
            preferred_safe_readback_modifier(implicit_dmabuf_offer),
            Some(DRM_FORMAT_MOD_INVALID as u64)
        );
    }

    #[test]
    fn cpu_pipewire_formats_offer_shared_memory_for_vendor_only_modifiers() {
        // niri on NVIDIA advertises block-linear modifiers and no linear or
        // implicit alternative. Withholding the modifier-less offer here left
        // PipeWire with only a tiled DMA-BUF that GBM readback cannot map.
        const EXPLICIT_MODIFIER: u64 = 0x0300_0000_0060_6010;
        let advertised = build_exact_cpu_pipewire_format_pod(
            spa::param::video::VideoFormat::BGRx,
            100,
            80,
            20.0,
            Some(EXPLICIT_MODIFIER),
        )
        .unwrap();

        let offers = build_pipewire_format_pods_from_node_formats(&[advertised], 15.0).unwrap();
        assert_eq!(offers.len(), 2);

        let shm_offer = spa::pod::Pod::from_bytes(&offers[0]).unwrap();
        assert!(!format_param_has_video_modifier(shm_offer));

        let dmabuf_offer = spa::pod::Pod::from_bytes(&offers[1]).unwrap();
        assert_eq!(
            preferred_safe_readback_modifier(dmabuf_offer),
            Some(EXPLICIT_MODIFIER)
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
