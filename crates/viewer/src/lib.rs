//! Native multi-stream GlacialCast viewer.

#![deny(missing_docs)]

use anyhow::{Context, Result};
use clap::Parser;
use eframe::egui;
use glacialcast_protocol::{
    NoiseKeypair, NoiseSocket, PROTOCOL_VERSION,
    credential::{CredentialRequest, CredentialRole, NativeCredential},
    cursor::{CursorContext, decode_cursor_batch},
    identity::{IdentityPublic, IdentitySecret, load_or_create_identity},
    initiator_handshake_xx, load_or_create_noise_keypair,
    native::{
        CodecId, ContentKey, H264EpochPayload, LiveSequenceGuard, NativeObject, NativeObjectKind,
    },
    pairing::{PairOffer, PairRequest, ViewerConfirmation, authentication_string},
    private_state::{PrivateLockMode, lock_private, read_private, replace_private},
    trust::KnownRelays,
    wire::{CatalogEntry, RelayViewerMessage, SessionHello, SubscriptionStart, ViewerMessage},
};
use openh264::{decoder::Decoder, formats::YUVSource, nal_units};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    io::IsTerminal,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::TcpStream, runtime::Runtime, sync::mpsc};
use uuid::Uuid;

const DEFAULT_VIEWER_PORT: u16 = 8899;
const MAX_CREDENTIAL_FILE: usize = 64 * 1024;
const PAIRING_STATE_VERSION: u16 = 1;
const MAX_PAIRING_STATE_BYTES: usize = 4 * 1024 * 1024;
const MAX_PENDING_OBJECTS: usize = 256;
const MAX_PENDING_CIPHERTEXT_BYTES: usize = 32 * 1024 * 1024;
const MAX_CACHED_KEYS: usize = 8_192;
const VERIFIED_PUBLISHERS_VERSION: u16 = 1;
const MAX_VERIFIED_PUBLISHERS_BYTES: usize = 4 * 1024 * 1024;
const NETWORK_TIMEOUT: Duration = Duration::from_secs(15);
type PendingPairings = HashMap<[u8; 32], (PairRequest, Option<PairOffer>)>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct GroupKey {
    stream_id: Uuid,
    epoch_id: Uuid,
    key_group: u64,
    key_id: [u8; 16],
}

impl GroupKey {
    fn for_object(object: &NativeObject) -> Self {
        Self {
            stream_id: object.header.stream_id,
            epoch_id: object.header.epoch_id,
            key_group: object.header.key_group,
            key_id: object.header.key_id,
        }
    }
}

#[derive(Default)]
struct KeyCache {
    keys: HashMap<GroupKey, [u8; 32]>,
    order: VecDeque<GroupKey>,
}

impl KeyCache {
    fn insert(&mut self, group: GroupKey, key: [u8; 32]) {
        if self.keys.insert(group, key).is_none() {
            self.order.push_back(group);
        }
        while self.keys.len() > MAX_CACHED_KEYS {
            if let Some(oldest) = self.order.pop_front() {
                self.keys.remove(&oldest);
            }
        }
    }

    fn get(&self, group: &GroupKey) -> Option<[u8; 32]> {
        self.keys.get(group).copied()
    }
}

#[derive(Debug, Parser)]
#[command(version, about = "View GlacialCast streams from a native relay")]
struct Args {
    /// Relay endpoint (`host[:port]`) or a `glacialcast://` invite.
    relay: String,
    /// Private viewer state directory.
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Optional relay-access credential file for a signed relay.
    #[arg(long)]
    credential: Option<PathBuf>,
    /// Explicit relay Noise key pin (URL-safe base64).
    #[arg(long)]
    server_key: Option<String>,
    /// Forget this relay's learned key and exit.
    #[arg(long)]
    forget_relay: bool,
    /// Forget the verified publisher identity for one stream and exit.
    #[arg(long, value_name = "STREAM_UUID")]
    forget_publisher: Option<Uuid>,
    /// Verify the relay, print its catalog, and exit without opening a window.
    #[arg(long)]
    headless: bool,
    /// Pair under automatic publisher policy and decode one frame from this stream.
    #[arg(long, value_name = "STREAM_UUID")]
    verify_stream: Option<Uuid>,
    /// Write a viewer request for an offline relay-access CA and exit.
    #[arg(long)]
    credential_request: Option<PathBuf>,
    /// Subject label placed in `--credential-request`.
    #[arg(long, default_value = "gcview")]
    credential_subject: String,
}

#[derive(Clone)]
struct ConnectionProfile {
    endpoint: String,
    state_dir: PathBuf,
    identity: Arc<IdentitySecret>,
    noise: NoiseKeypair,
    credential: Option<NativeCredential>,
    explicit_pin: Option<[u8; 32]>,
}

#[derive(Clone)]
struct Frame {
    stream_id: Uuid,
    width: usize,
    height: usize,
    rgb: Vec<u8>,
    sequence: u64,
    key_group: u64,
}

struct CursorUpdate {
    stream_id: Uuid,
    x_micropixels: i64,
    y_micropixels: i64,
    visible: bool,
    bitmap: Option<glacialcast_protocol::cursor::CursorBitmap>,
}

enum Event {
    Status(String),
    Catalog(Vec<CatalogEntry>),
    Frame(Frame),
    Cursor(CursorUpdate),
    StreamStatus(Uuid, String),
    StreamError(Uuid, String),
    PairingPrompt([u8; 32], String),
    PairingApproved(Uuid, IdentityPublic),
}

enum Command {
    Refresh,
    Subscribe(Uuid, IdentityPublic, SubscriptionStart),
    Pair(Uuid, IdentityPublic),
    ConfirmPairing([u8; 32], bool),
}

struct Tile {
    catalog: CatalogEntry,
    texture: Option<egui::TextureHandle>,
    frame_size: [usize; 2],
    cursor_texture: Option<egui::TextureHandle>,
    cursor_size: [usize; 2],
    cursor_hotspot: [i32; 2],
    cursor_position: [f32; 2],
    cursor_visible: bool,
    sequence: u64,
    status: String,
    seek_timestamp: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct PairingState {
    version: u16,
    pending: Vec<(PairRequest, Option<PairOffer>)>,
}

#[derive(Debug, Deserialize, Serialize)]
struct VerifiedPublishersState {
    version: u16,
    publishers: Vec<(Uuid, IdentityPublic)>,
}

struct ViewerApp {
    events: mpsc::UnboundedReceiver<Event>,
    commands: mpsc::UnboundedSender<Command>,
    tiles: Vec<Tile>,
    status: String,
    selected: usize,
    fullscreen: Option<Uuid>,
    layout: usize,
    pairing_prompt: Option<([u8; 32], String)>,
}

impl ViewerApp {
    fn new(
        events: mpsc::UnboundedReceiver<Event>,
        commands: mpsc::UnboundedSender<Command>,
    ) -> Self {
        let _ = commands.send(Command::Refresh);
        Self {
            events,
            commands,
            tiles: Vec::new(),
            status: "Connecting…".into(),
            selected: 0,
            fullscreen: None,
            layout: 4,
            pairing_prompt: None,
        }
    }

    fn drain_events(&mut self, context: &egui::Context) {
        while let Ok(event) = self.events.try_recv() {
            match event {
                Event::Status(status) => self.status = status,
                Event::Catalog(entries) => {
                    let visible_ids: std::collections::HashSet<_> = entries
                        .iter()
                        .map(|entry| entry.descriptor.body.stream_id)
                        .collect();
                    for entry in entries {
                        if let Some(tile) = self.tiles.iter_mut().find(|tile| {
                            tile.catalog.descriptor.body.stream_id
                                == entry.descriptor.body.stream_id
                        }) {
                            if let Some(bounds) = entry.retained {
                                tile.seek_timestamp = tile
                                    .seek_timestamp
                                    .clamp(bounds.oldest_timestamp, bounds.newest_timestamp);
                            }
                            if !entry.publisher_online {
                                tile.status = "Retained; publisher offline".into();
                            } else if tile.status == "Retained; publisher offline" {
                                tile.status = "Available live".into();
                            }
                            tile.catalog = entry;
                        } else {
                            let seek_timestamp =
                                entry.retained.map_or(0, |bounds| bounds.newest_timestamp);
                            self.tiles.push(Tile {
                                status: if entry.publisher_online {
                                    "Available live".into()
                                } else {
                                    "Retained; publisher offline".into()
                                },
                                catalog: entry,
                                texture: None,
                                frame_size: [0, 0],
                                cursor_texture: None,
                                cursor_size: [0, 0],
                                cursor_hotspot: [0, 0],
                                cursor_position: [0.0, 0.0],
                                cursor_visible: false,
                                sequence: 0,
                                seek_timestamp,
                            });
                        }
                    }
                    self.tiles.retain(|tile| {
                        visible_ids.contains(&tile.catalog.descriptor.body.stream_id)
                    });
                    self.tiles
                        .sort_by_key(|tile| tile.catalog.descriptor.body.stream_id);
                    self.selected = self.selected.min(self.tiles.len().saturating_sub(1));
                    self.status = format!("{} stream(s) visible", self.tiles.len());
                }
                Event::Frame(frame) => {
                    if let Some(tile) = self
                        .tiles
                        .iter_mut()
                        .find(|tile| tile.catalog.descriptor.body.stream_id == frame.stream_id)
                    {
                        let image =
                            egui::ColorImage::from_rgb([frame.width, frame.height], &frame.rgb);
                        tile.texture = Some(context.load_texture(
                            frame.stream_id.to_string(),
                            image,
                            egui::TextureOptions::LINEAR,
                        ));
                        tile.sequence = frame.sequence;
                        tile.frame_size = [frame.width, frame.height];
                    }
                }
                Event::Cursor(cursor) => {
                    if let Some(tile) = self
                        .tiles
                        .iter_mut()
                        .find(|tile| tile.catalog.descriptor.body.stream_id == cursor.stream_id)
                    {
                        tile.cursor_position = [
                            cursor.x_micropixels as f32 / 1_000_000.0,
                            cursor.y_micropixels as f32 / 1_000_000.0,
                        ];
                        tile.cursor_visible = cursor.visible;
                        if let Some(bitmap) = cursor.bitmap {
                            let size = [bitmap.width as usize, bitmap.height as usize];
                            let image =
                                egui::ColorImage::from_rgba_unmultiplied(size, &bitmap.rgba);
                            tile.cursor_texture = Some(context.load_texture(
                                format!("{}-cursor", cursor.stream_id),
                                image,
                                egui::TextureOptions::LINEAR,
                            ));
                            tile.cursor_size = size;
                            tile.cursor_hotspot = [bitmap.hotspot_x, bitmap.hotspot_y];
                        }
                    }
                }
                Event::StreamStatus(stream_id, status) => {
                    if let Some(tile) = self
                        .tiles
                        .iter_mut()
                        .find(|tile| tile.catalog.descriptor.body.stream_id == stream_id)
                    {
                        tile.status = status;
                    }
                }
                Event::StreamError(stream_id, error) => {
                    if let Some(tile) = self
                        .tiles
                        .iter_mut()
                        .find(|tile| tile.catalog.descriptor.body.stream_id == stream_id)
                    {
                        tile.status = error;
                    }
                }
                Event::PairingPrompt(request_id, authentication) => {
                    self.pairing_prompt = Some((request_id, authentication));
                    context.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
                        egui::UserAttentionType::Informational,
                    ));
                }
                Event::PairingApproved(stream_id, publisher) => {
                    let _ = self.commands.send(Command::Subscribe(
                        stream_id,
                        publisher,
                        SubscriptionStart::Live,
                    ));
                    context.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
                        egui::UserAttentionType::Informational,
                    ));
                }
            }
        }
    }

    fn keyboard(&mut self, context: &egui::Context) {
        context.input(|input| {
            if input.key_pressed(egui::Key::Escape) {
                self.fullscreen = None;
            }
            if input.key_pressed(egui::Key::Enter) && !self.tiles.is_empty() {
                self.fullscreen = Some(self.tiles[self.selected].catalog.descriptor.body.stream_id);
            }
            if input.key_pressed(egui::Key::ArrowRight) && !self.tiles.is_empty() {
                self.selected = (self.selected + 1) % self.tiles.len();
                if self.fullscreen.is_some() {
                    self.fullscreen =
                        Some(self.tiles[self.selected].catalog.descriptor.body.stream_id);
                }
            }
            if input.key_pressed(egui::Key::ArrowLeft) && !self.tiles.is_empty() {
                self.selected = self.selected.checked_sub(1).unwrap_or(self.tiles.len() - 1);
                if self.fullscreen.is_some() {
                    self.fullscreen =
                        Some(self.tiles[self.selected].catalog.descriptor.body.stream_id);
                }
            }
        });
    }
}

impl eframe::App for ViewerApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let context = ui.ctx().clone();
        self.drain_events(&context);
        self.keyboard(&context);
        context.request_repaint_after(Duration::from_millis(100));
        egui::Frame::central_panel(ui.style()).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("GlacialCast");
                for count in [1, 2, 4, 6] {
                    ui.selectable_value(&mut self.layout, count, count.to_string());
                }
                if ui.button("Refresh").clicked() {
                    let _ = self.commands.send(Command::Refresh);
                }
                ui.label(&self.status);
            });
            ui.separator();
            let visible: Vec<usize> = if let Some(fullscreen) = self.fullscreen {
                self.tiles
                    .iter()
                    .position(|tile| tile.catalog.descriptor.body.stream_id == fullscreen)
                    .into_iter()
                    .collect()
            } else {
                (0..self.tiles.len().min(self.layout)).collect()
            };
            let columns = match visible.len() {
                0 | 1 => 1,
                2 => 2,
                3 | 4 => 2,
                _ => 3,
            };
            let rows = visible.len().div_ceil(columns).max(1);
            let available = ui.available_size_before_wrap();
            let tile_size = egui::vec2(
                ((available.x - 8.0 * (columns.saturating_sub(1) as f32)) / columns as f32)
                    .max(240.0),
                ((available.y - 8.0 * (rows.saturating_sub(1) as f32)) / rows as f32 - 70.0)
                    .max(120.0),
            );
            egui::Grid::new("streams")
                .num_columns(columns)
                .spacing([8.0, 8.0])
                .show(ui, |ui| {
                    for (position, index) in visible.into_iter().enumerate() {
                        let tile = &mut self.tiles[index];
                        let descriptor = &tile.catalog.descriptor.body;
                        ui.vertical(|ui| {
                            ui.horizontal(|ui| {
                                if ui.selectable_label(self.selected == index, &descriptor.name).clicked() {
                                    self.selected = index;
                                }
                                ui.label(&tile.status);
                                if ui.button("History").clicked() {
                                    tile.status = "Connecting…".into();
                                    let _ = self.commands.send(Command::Subscribe(
                                        descriptor.stream_id,
                                        descriptor.publisher,
                                        SubscriptionStart::OldestRetained,
                                    ));
                                }
                                if ui.button("Live").clicked() {
                                    tile.status = "Connecting to live edge…".into();
                                    let _ = self.commands.send(Command::Subscribe(
                                        descriptor.stream_id,
                                        descriptor.publisher,
                                        SubscriptionStart::Live,
                                    ));
                                }
                                if ui.button("Pair").clicked() {
                                    let _ = self
                                        .commands
                                        .send(Command::Pair(descriptor.stream_id, descriptor.publisher));
                                }
                                if ui.button("⛶").clicked() {
                                    self.fullscreen = Some(descriptor.stream_id);
                                }
                            });
                            if let Some(bounds) = descriptor_retained(&tile.catalog) {
                                ui.horizontal(|ui| {
                                    ui.label("Retained");
                                    ui.add(
                                        egui::Slider::new(
                                            &mut tile.seek_timestamp,
                                            bounds.oldest_timestamp..=bounds.newest_timestamp,
                                        )
                                        .show_value(false),
                                    );
                                    if ui.button("Go").clicked() {
                                        tile.status = "Seeking retained history…".into();
                                        let _ = self.commands.send(Command::Subscribe(
                                            descriptor.stream_id,
                                            descriptor.publisher,
                                            SubscriptionStart::Timestamp(tile.seek_timestamp),
                                        ));
                                    }
                                });
                            }
                            if let Some(texture) = &tile.texture {
                                let (rect, _) = ui.allocate_exact_size(tile_size, egui::Sense::hover());
                                ui.painter().image(
                                    texture.id(),
                                    rect,
                                    egui::Rect::from_min_max(egui::Pos2::ZERO, egui::pos2(1.0, 1.0)),
                                    egui::Color32::WHITE,
                                );
                                if tile.cursor_visible
                                    && let Some(cursor) = &tile.cursor_texture
                                    && tile.frame_size[0] > 0
                                    && tile.frame_size[1] > 0
                                {
                                    let scale_x = rect.width() / tile.frame_size[0] as f32;
                                    let scale_y = rect.height() / tile.frame_size[1] as f32;
                                    let position = rect.min
                                        + egui::vec2(
                                            (tile.cursor_position[0] - tile.cursor_hotspot[0] as f32) * scale_x,
                                            (tile.cursor_position[1] - tile.cursor_hotspot[1] as f32) * scale_y,
                                        );
                                    let cursor_rect = egui::Rect::from_min_size(
                                        position,
                                        egui::vec2(
                                            tile.cursor_size[0] as f32 * scale_x,
                                            tile.cursor_size[1] as f32 * scale_y,
                                        ),
                                    );
                                    ui.painter().image(
                                        cursor.id(),
                                        cursor_rect,
                                        egui::Rect::from_min_max(egui::Pos2::ZERO, egui::pos2(1.0, 1.0)),
                                        egui::Color32::WHITE,
                                    );
                                }
                            } else {
                                ui.allocate_ui(tile_size, |ui| { ui.centered_and_justified(|ui| { ui.label("Encrypted stream — approve this viewer on the publisher if playback stays locked"); }); });
                            }
                        });
                        if (position + 1) % columns == 0 {
                            ui.end_row();
                        }
                    }
                });
            if let Some((request_id, authentication)) = self.pairing_prompt.clone() {
                egui::Window::new("Verify publisher")
                    .collapsible(false)
                    .show(&context, |ui| {
                        ui.label("Compare this value with the publisher. Do they match?");
                        ui.heading(authentication);
                        ui.horizontal(|ui| {
                            if ui.button("Yes, they match").clicked() {
                                let _ = self.commands.send(Command::ConfirmPairing(request_id, true));
                                self.pairing_prompt = None;
                            }
                            if ui.button("No").clicked() {
                                let _ = self.commands.send(Command::ConfirmPairing(request_id, false));
                                self.pairing_prompt = None;
                            }
                        });
                    });
            }
        });
    }
}

fn descriptor_retained(entry: &CatalogEntry) -> Option<glacialcast_protocol::wire::RetainedBounds> {
    entry.retained
}

/// Starts the native viewer window and background relay workers.
///
/// # Errors
///
/// Returns an error for invalid state, command-line input, or window startup.
pub fn run() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "glacialcast_viewer=info".into()),
        )
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();
    let (endpoint, invite_pin) = parse_relay(&args.relay)?;
    let state_dir = args.state_dir.unwrap_or_else(default_state_dir);
    std::fs::create_dir_all(&state_dir)?;
    let mut known = KnownRelays::open(state_dir.join("known-relays.bin"))?;
    if args.forget_relay {
        known.forget(&endpoint)?;
        return Ok(());
    }
    let explicit_pin = args
        .server_key
        .as_deref()
        .map(glacialcast_protocol::decode_noise_public_key)
        .transpose()?
        .or(invite_pin);
    let identity = Arc::new(load_or_create_identity(&state_dir.join("identity.key"))?);
    let noise = load_or_create_noise_keypair(&state_dir.join("noise.key"))?;
    if let Some(output) = &args.credential_request {
        let now = glacialcast_protocol::now_ms();
        let request = CredentialRequest::new(
            &identity,
            args.credential_subject,
            CredentialRole::Viewer,
            noise.public,
            now,
            now.saturating_add(24 * 60 * 60 * 1_000),
        )?;
        glacialcast_protocol::private_state::create_private(output, &request.encode()?)?;
        println!("wrote viewer credential request {}", output.display());
        return Ok(());
    }
    let credential = args
        .credential
        .as_deref()
        .map(|path| NativeCredential::decode(&read_private(path, MAX_CREDENTIAL_FILE)?))
        .transpose()?;
    let profile = ConnectionProfile {
        endpoint,
        state_dir,
        identity,
        noise,
        credential,
        explicit_pin,
    };
    if let Some(stream_id) = args.forget_publisher {
        forget_verified_publisher(&profile, stream_id)?;
        return Ok(());
    }
    let _viewer_lock = lock_private(
        &profile.state_dir.join("viewer-process.lock"),
        PrivateLockMode::TryExclusive,
    )
    .context("another gcview process already owns this viewer state directory")?;
    if let Some(stream_id) = args.verify_stream {
        let runtime = Runtime::new()?;
        return runtime.block_on(headless_verify_stream(&profile, stream_id));
    }
    if args.headless {
        let runtime = Runtime::new()?;
        return runtime.block_on(headless_catalog(&profile));
    }
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let (command_tx, command_rx) = mpsc::unbounded_channel();
    std::thread::Builder::new()
        .name("gcview-network".into())
        .spawn(move || {
            let runtime = Runtime::new().expect("viewer Tokio runtime");
            runtime.block_on(command_worker(profile, event_tx, command_rx));
        })?;
    eframe::run_native(
        "GlacialCast Viewer",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([1280.0, 800.0]),
            ..Default::default()
        },
        Box::new(move |_| Ok(Box::new(ViewerApp::new(event_rx, command_tx)))),
    )
    .map_err(|error| anyhow::anyhow!(error.to_string()))
}

async fn headless_verify_stream(profile: &ConnectionProfile, stream_id: Uuid) -> Result<()> {
    let mut catalog_socket = connect(profile).await?;
    write_viewer(&mut catalog_socket, &ViewerMessage::Catalog).await?;
    let catalog = match read_viewer(&mut catalog_socket).await? {
        RelayViewerMessage::Catalog(catalog) => catalog,
        RelayViewerMessage::Error(error) => anyhow::bail!("catalog rejected: {}", error.detail),
        _ => anyhow::bail!("unexpected catalog response"),
    };
    let publisher = catalog
        .iter()
        .find(|entry| entry.descriptor.body.stream_id == stream_id)
        .map(|entry| entry.descriptor.body.publisher)
        .context("requested verification stream is not in the catalog")?;
    let request = begin_pairing(profile, stream_id, publisher).await?;
    let request_id = request.id()?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let mut socket = connect(profile).await?;
            write_viewer(&mut socket, &ViewerMessage::FetchInbox).await?;
            let mut approved = false;
            loop {
                match read_viewer(&mut socket).await? {
                    RelayViewerMessage::PairDecision(decision)
                        if decision.body.request_id == request_id =>
                    {
                        decision.verify(&request, &publisher)?;
                        if !decision.body.approved || decision.body.stream_id != stream_id {
                            anyhow::bail!("publisher rejected stream verification request");
                        }
                        remember_verified_publisher(profile, stream_id, publisher)?;
                        approved = true;
                    }
                    RelayViewerMessage::PairOffer(_)
                    | RelayViewerMessage::PairDecision(_)
                    | RelayViewerMessage::KeyEnvelope(_) => {}
                    RelayViewerMessage::InboxComplete => break,
                    RelayViewerMessage::Error(error) => {
                        anyhow::bail!("pairing inbox rejected: {}", error.detail)
                    }
                    _ => anyhow::bail!("unexpected pairing inbox response"),
                }
            }
            if approved {
                return Result::<()>::Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("timed out waiting for automatic publisher approval")??;

    let keys = Arc::new(Mutex::new(KeyCache::default()));
    let (events, mut received) = mpsc::unbounded_channel();
    tokio::time::timeout(Duration::from_secs(15), async {
        let subscription = subscribe(
            profile,
            &events,
            &keys,
            stream_id,
            publisher,
            SubscriptionStart::Live,
        );
        tokio::pin!(subscription);
        let mut first_group = None;
        loop {
            tokio::select! {
                result = &mut subscription => return result,
                event = received.recv() => match event {
                    Some(Event::Frame(frame))
                        if frame.stream_id == stream_id && !frame.rgb.is_empty() =>
                    {
                        if first_group.is_some_and(|group| group != frame.key_group) {
                            println!(
                                "verified\t{}\t{}x{}\tsequence={}\trotated-group={}",
                                stream_id,
                                frame.width,
                                frame.height,
                                frame.sequence,
                                frame.key_group,
                            );
                            return Ok(());
                        }
                        first_group.get_or_insert(frame.key_group);
                    }
                    Some(Event::StreamError(_, ref error)) => anyhow::bail!(error.clone()),
                    Some(_) => {}
                    None => anyhow::bail!("headless verification event channel closed"),
                }
            }
        }
    })
    .await
    .context("timed out waiting for a decoded stream frame")??;
    Ok(())
}

async fn headless_catalog(profile: &ConnectionProfile) -> Result<()> {
    let mut socket = connect(profile).await?;
    write_viewer(&mut socket, &ViewerMessage::Catalog).await?;
    match read_viewer(&mut socket).await? {
        RelayViewerMessage::Catalog(catalog) => {
            for entry in catalog {
                println!(
                    "{}\t{}\t{}",
                    entry.descriptor.body.stream_id,
                    if entry.publisher_online {
                        "live"
                    } else {
                        "offline"
                    },
                    entry.descriptor.body.name
                );
            }
            Ok(())
        }
        RelayViewerMessage::Error(error) => {
            anyhow::bail!("catalog rejected: {:?}: {}", error.code, error.detail)
        }
        _ => anyhow::bail!("unexpected catalog response"),
    }
}

async fn command_worker(
    profile: ConnectionProfile,
    events: mpsc::UnboundedSender<Event>,
    mut commands: mpsc::UnboundedReceiver<Command>,
) {
    let keys = Arc::new(Mutex::new(KeyCache::default()));
    let pairing_path = profile.state_dir.join("pending-pairings.bin");
    let mut pending = match load_pairing_state(&pairing_path) {
        Ok(pending) => pending,
        Err(error) => {
            let _ = events.send(Event::Status(format!(
                "Pending pairing state is unusable: {error:#}"
            )));
            HashMap::new()
        }
    };
    let mut subscriptions: HashMap<Uuid, tokio::task::JoinHandle<()>> = HashMap::new();
    let mut refresh_interval = tokio::time::interval(Duration::from_secs(5));
    refresh_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let command = tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { return; };
                command
            }
            _ = refresh_interval.tick() => {
                refresh_all(&profile, &events, &keys, &mut pending).await;
                continue;
            }
        };
        match command {
            Command::Refresh => {
                refresh_all(&profile, &events, &keys, &mut pending).await;
            }
            Command::Subscribe(stream_id, publisher, start) => {
                if let Some(previous) = subscriptions.remove(&stream_id) {
                    previous.abort();
                }
                let profile = profile.clone();
                let events = events.clone();
                let keys = keys.clone();
                let task = tokio::spawn(async move {
                    if let Err(error) =
                        subscribe(&profile, &events, &keys, stream_id, publisher, start).await
                    {
                        let _ = events.send(Event::StreamError(
                            stream_id,
                            format!("Playback failed: {error:#}"),
                        ));
                    }
                });
                subscriptions.insert(stream_id, task);
            }
            Command::Pair(stream_id, publisher) => {
                match begin_pairing(&profile, stream_id, publisher).await {
                    Ok(request) => {
                        if let Ok(request_id) = request.id() {
                            pending.insert(request_id, (request, None));
                            save_pairing_state(&pairing_path, &pending).ok();
                            let _ = events.send(Event::Status(
                                "Pairing request queued; waiting for publisher".into(),
                            ));
                        }
                    }
                    Err(error) => {
                        let _ = events.send(Event::Status(format!("Pairing failed: {error:#}")));
                    }
                }
            }
            Command::ConfirmPairing(request_id, approved) => {
                if approved {
                    let result = async {
                        let (request, offer) = pending
                            .get(&request_id)
                            .context("pairing request is no longer pending")?;
                        let offer = offer.as_ref().context("publisher offer is not available")?;
                        confirm_pairing(&profile, request, offer).await
                    }
                    .await;
                    match result {
                        Ok(()) => {
                            let _ = events.send(Event::Status(
                                "Viewer confirmation queued; waiting for publisher approval".into(),
                            ));
                        }
                        Err(error) => {
                            let _ = events.send(Event::Status(format!(
                                "Pair confirmation failed: {error:#}"
                            )));
                        }
                    }
                } else {
                    pending.remove(&request_id);
                    save_pairing_state(&pairing_path, &pending).ok();
                    let _ = events.send(Event::Status("Pairing comparison rejected".into()));
                }
            }
        }
    }
}

async fn refresh_all(
    profile: &ConnectionProfile,
    events: &mpsc::UnboundedSender<Event>,
    keys: &Arc<Mutex<KeyCache>>,
    pending: &mut PendingPairings,
) {
    if let Err(error) = refresh(profile, events, keys).await {
        let _ = events.send(Event::Status(format!("Connection failed: {error:#}")));
    }
    if let Err(error) = refresh_pairing(profile, events, pending).await {
        let _ = events.send(Event::Status(format!("Pairing refresh failed: {error:#}")));
    }
}

async fn begin_pairing(
    profile: &ConnectionProfile,
    stream_id: Uuid,
    publisher: IdentityPublic,
) -> Result<PairRequest> {
    if let Some(expected) = verified_publishers(profile)?.get(&stream_id)
        && expected.id()? != publisher.id()?
    {
        anyhow::bail!("refusing to pair with a changed publisher identity");
    }
    let now = glacialcast_protocol::now_ms();
    let request = PairRequest::new_with_credential(
        &profile.identity,
        publisher,
        stream_id,
        "gcview device".into(),
        profile.credential.clone(),
        now,
        now.saturating_add(24 * 60 * 60 * 1_000),
    )?;
    let mut socket = connect(profile).await?;
    write_viewer(
        &mut socket,
        &ViewerMessage::PairRequest(Box::new(request.clone())),
    )
    .await?;
    match read_viewer(&mut socket).await? {
        RelayViewerMessage::PairingQueued { request_id } if request_id == request.id()? => {
            Ok(request)
        }
        RelayViewerMessage::Error(error) => {
            anyhow::bail!("relay rejected pairing: {}", error.detail)
        }
        _ => anyhow::bail!("unexpected pairing response"),
    }
}

async fn refresh_pairing(
    profile: &ConnectionProfile,
    events: &mpsc::UnboundedSender<Event>,
    pending: &mut HashMap<[u8; 32], (PairRequest, Option<PairOffer>)>,
) -> Result<()> {
    let mut socket = connect(profile).await?;
    write_viewer(&mut socket, &ViewerMessage::FetchInbox).await?;
    loop {
        match read_viewer(&mut socket).await? {
            RelayViewerMessage::PairOffer(offer) => {
                let prompt =
                    if let Some((request, stored)) = pending.get_mut(&offer.body.request_id) {
                        offer.verify(
                            request,
                            glacialcast_protocol::now_ms(),
                            24 * 60 * 60 * 1_000,
                        )?;
                        let authentication = authentication_string(request, &offer)?;
                        *stored = Some(offer);
                        Some((request.id()?, authentication))
                    } else {
                        None
                    };
                if let Some((request_id, authentication)) = prompt {
                    save_pairing_state(&profile.state_dir.join("pending-pairings.bin"), pending)?;
                    let _ = events.send(Event::PairingPrompt(request_id, authentication));
                }
            }
            RelayViewerMessage::PairDecision(decision) => {
                if let Some((request, _)) = pending.get(&decision.body.request_id) {
                    decision.verify(request, &request.body.publisher)?;
                    if decision.body.approved {
                        remember_verified_publisher(
                            profile,
                            request.body.stream_id,
                            request.body.publisher,
                        )?;
                    }
                    let status = if decision.body.approved {
                        "Publisher approved this viewer"
                    } else {
                        "Publisher rejected this viewer"
                    };
                    let _ = events.send(Event::Status(status.into()));
                    if decision.body.approved {
                        let _ = events.send(Event::PairingApproved(
                            request.body.stream_id,
                            request.body.publisher,
                        ));
                    }
                }
                pending.remove(&decision.body.request_id);
                save_pairing_state(&profile.state_dir.join("pending-pairings.bin"), pending)?;
            }
            RelayViewerMessage::InboxComplete => return Ok(()),
            RelayViewerMessage::KeyEnvelope(_) => {}
            RelayViewerMessage::Error(error) => {
                anyhow::bail!("pairing inbox rejected: {}", error.detail)
            }
            _ => anyhow::bail!("unexpected pairing inbox response"),
        }
    }
}

fn load_pairing_state(path: &Path) -> Result<PendingPairings> {
    let bytes = match read_private(path, MAX_PAIRING_STATE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => return Err(error.into()),
    };
    let (state, remainder) = postcard::take_from_bytes::<PairingState>(&bytes)?;
    if !remainder.is_empty()
        || state.version != PAIRING_STATE_VERSION
        || postcard::to_stdvec(&state)? != bytes
    {
        anyhow::bail!("pending pairing state is invalid or non-canonical");
    }
    let mut pending = HashMap::new();
    for pair in state.pending {
        let id = pair.0.id()?;
        if pending.insert(id, pair).is_some() {
            anyhow::bail!("pending pairing state contains duplicate requests");
        }
    }
    Ok(pending)
}

fn save_pairing_state(path: &Path, pending: &PendingPairings) -> Result<()> {
    let mut entries: Vec<_> = pending.values().cloned().collect();
    entries.sort_by_key(|(request, _)| request.id().unwrap_or([0; 32]));
    let encoded = postcard::to_stdvec(&PairingState {
        version: PAIRING_STATE_VERSION,
        pending: entries,
    })?;
    replace_private(path, &encoded, MAX_PAIRING_STATE_BYTES)?;
    Ok(())
}

fn verified_publishers(profile: &ConnectionProfile) -> Result<HashMap<Uuid, IdentityPublic>> {
    let _lock = lock_private(
        &profile.state_dir.join(".verified-publishers.lock"),
        PrivateLockMode::Shared,
    )?;
    load_verified_publishers_unlocked(&profile.state_dir.join("verified-publishers.bin"))
}

fn remember_verified_publisher(
    profile: &ConnectionProfile,
    stream_id: Uuid,
    publisher: IdentityPublic,
) -> Result<()> {
    let _lock = lock_private(
        &profile.state_dir.join(".verified-publishers.lock"),
        PrivateLockMode::Exclusive,
    )?;
    let path = profile.state_dir.join("verified-publishers.bin");
    let mut publishers = load_verified_publishers_unlocked(&path)?;
    if let Some(existing) = publishers.get(&stream_id)
        && existing.id()? != publisher.id()?
    {
        anyhow::bail!("verified publisher identity changed for stream {stream_id}");
    }
    publishers.insert(stream_id, publisher);
    let mut entries: Vec<_> = publishers.into_iter().collect();
    entries.sort_by_key(|(stream_id, _)| *stream_id);
    let encoded = postcard::to_stdvec(&VerifiedPublishersState {
        version: VERIFIED_PUBLISHERS_VERSION,
        publishers: entries,
    })?;
    if encoded.len() > MAX_VERIFIED_PUBLISHERS_BYTES {
        anyhow::bail!("verified publisher state exceeds its file bound");
    }
    replace_private(&path, &encoded, MAX_VERIFIED_PUBLISHERS_BYTES)?;
    Ok(())
}

fn forget_verified_publisher(profile: &ConnectionProfile, stream_id: Uuid) -> Result<()> {
    let _lock = lock_private(
        &profile.state_dir.join(".verified-publishers.lock"),
        PrivateLockMode::Exclusive,
    )?;
    let path = profile.state_dir.join("verified-publishers.bin");
    let mut publishers = load_verified_publishers_unlocked(&path)?;
    publishers.remove(&stream_id);
    let mut entries: Vec<_> = publishers.into_iter().collect();
    entries.sort_by_key(|(stream_id, _)| *stream_id);
    let encoded = postcard::to_stdvec(&VerifiedPublishersState {
        version: VERIFIED_PUBLISHERS_VERSION,
        publishers: entries,
    })?;
    replace_private(&path, &encoded, MAX_VERIFIED_PUBLISHERS_BYTES)?;
    Ok(())
}

fn load_verified_publishers_unlocked(path: &Path) -> Result<HashMap<Uuid, IdentityPublic>> {
    let bytes = match read_private(path, MAX_VERIFIED_PUBLISHERS_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => return Err(error.into()),
    };
    let (state, remainder) = postcard::take_from_bytes::<VerifiedPublishersState>(&bytes)?;
    if !remainder.is_empty()
        || state.version != VERIFIED_PUBLISHERS_VERSION
        || state.publishers.len() > 65_536
        || postcard::to_stdvec(&state)? != bytes
    {
        anyhow::bail!("verified publisher state is invalid or non-canonical");
    }
    let mut publishers = HashMap::new();
    let mut previous = None;
    for (stream_id, publisher) in state.publishers {
        if previous.is_some_and(|previous| previous >= stream_id)
            || publishers.insert(stream_id, publisher).is_some()
        {
            anyhow::bail!("verified publisher state is not strictly ordered");
        }
        previous = Some(stream_id);
    }
    Ok(publishers)
}

async fn confirm_pairing(
    profile: &ConnectionProfile,
    request: &PairRequest,
    offer: &PairOffer,
) -> Result<()> {
    let confirmation = ViewerConfirmation::approve(
        &profile.identity,
        request,
        offer,
        glacialcast_protocol::now_ms(),
    )?;
    let mut socket = connect(profile).await?;
    write_viewer(&mut socket, &ViewerMessage::PairConfirmation(confirmation)).await?;
    match read_viewer(&mut socket).await? {
        RelayViewerMessage::PairingQueued { request_id } if request_id == request.id()? => Ok(()),
        RelayViewerMessage::Error(error) => {
            anyhow::bail!("relay rejected confirmation: {}", error.detail)
        }
        _ => anyhow::bail!("unexpected confirmation response"),
    }
}

async fn connect(profile: &ConnectionProfile) -> Result<NoiseSocket<TcpStream>> {
    let mut stream = tokio::time::timeout(NETWORK_TIMEOUT, TcpStream::connect(&profile.endpoint))
        .await
        .context("viewer relay connection timed out")?
        .with_context(|| format!("connecting to {}", profile.endpoint))?;
    let expected = if let Some(pin) = profile.explicit_pin {
        Some(pin)
    } else {
        KnownRelays::open(profile.state_dir.join("known-relays.bin"))?.get(&profile.endpoint)?
    };
    let (transport, remote) = tokio::time::timeout(
        NETWORK_TIMEOUT,
        initiator_handshake_xx(
            &mut stream,
            &profile.noise.private,
            |actual| match expected {
                Some(expected) if actual != &expected => {
                    Err(glacialcast_protocol::ProtocolError::Noise(
                        "relay identity does not match its pin".into(),
                    ))
                }
                _ => Ok(()),
            },
        ),
    )
    .await
    .context("viewer relay handshake timed out")??;
    if profile.explicit_pin.is_none() {
        KnownRelays::open(profile.state_dir.join("known-relays.bin"))?
            .verify_or_learn(&profile.endpoint, remote)?;
    }
    let mut socket = NoiseSocket::new(stream, transport);
    write_viewer(
        &mut socket,
        &ViewerMessage::Hello(SessionHello {
            protocol_version: PROTOCOL_VERSION,
            role: CredentialRole::Viewer,
            identity: profile.identity.public()?,
            credential: profile.credential.clone(),
        }),
    )
    .await?;
    match read_viewer(&mut socket).await? {
        RelayViewerMessage::Welcome(_) => Ok(socket),
        RelayViewerMessage::Error(error) => {
            anyhow::bail!("relay rejected viewer: {:?}: {}", error.code, error.detail)
        }
        _ => anyhow::bail!("relay did not send a welcome first"),
    }
}

async fn write_viewer(socket: &mut NoiseSocket<TcpStream>, message: &ViewerMessage) -> Result<()> {
    tokio::time::timeout(NETWORK_TIMEOUT, socket.write(message))
        .await
        .context("viewer relay write timed out")??;
    Ok(())
}

async fn read_viewer(socket: &mut NoiseSocket<TcpStream>) -> Result<RelayViewerMessage> {
    tokio::time::timeout(NETWORK_TIMEOUT, socket.read::<RelayViewerMessage>())
        .await
        .context("viewer relay response timed out")?
        .map_err(Into::into)
}

async fn refresh(
    profile: &ConnectionProfile,
    events: &mpsc::UnboundedSender<Event>,
    keys: &Arc<Mutex<KeyCache>>,
) -> Result<()> {
    let mut socket = connect(profile).await?;
    write_viewer(&mut socket, &ViewerMessage::Catalog).await?;
    let mut catalog = match read_viewer(&mut socket).await? {
        RelayViewerMessage::Catalog(catalog) => catalog,
        RelayViewerMessage::Error(error) => anyhow::bail!("catalog rejected: {}", error.detail),
        _ => anyhow::bail!("unexpected catalog response"),
    };
    let verified = verified_publishers(profile)?;
    let mut hidden_mismatches = 0usize;
    catalog.retain(|entry| {
        let stream_id = entry.descriptor.body.stream_id;
        let matches = verified
            .get(&stream_id)
            .is_none_or(|expected| expected.id().ok() == entry.descriptor.body.publisher.id().ok());
        if !matches {
            hidden_mismatches = hidden_mismatches.saturating_add(1);
        }
        matches
    });
    let publishers: HashMap<[u8; 32], IdentityPublic> = catalog
        .iter()
        .map(|entry| {
            Ok((
                entry.descriptor.body.publisher.id()?,
                entry.descriptor.body.publisher,
            ))
        })
        .collect::<Result<_>>()?;
    write_viewer(&mut socket, &ViewerMessage::FetchInbox).await?;
    loop {
        match read_viewer(&mut socket).await? {
            RelayViewerMessage::KeyEnvelope(envelope) => {
                if let Some(publisher) = publishers.get(&envelope.header.publisher_id) {
                    let content_key = envelope.open(&profile.identity, publisher)?;
                    keys.lock()
                        .map_err(|_| anyhow::anyhow!("key cache poisoned"))?
                        .insert(
                            GroupKey {
                                stream_id: envelope.header.stream_id,
                                epoch_id: envelope.header.epoch_id,
                                key_group: envelope.header.key_group_id,
                                key_id: envelope.header.key_id,
                            },
                            content_key,
                        );
                }
            }
            RelayViewerMessage::InboxComplete => break,
            RelayViewerMessage::PairOffer(_) | RelayViewerMessage::PairDecision(_) => {}
            RelayViewerMessage::Error(error) => anyhow::bail!("inbox rejected: {}", error.detail),
            _ => anyhow::bail!("unexpected inbox response"),
        }
    }
    let _ = events.send(Event::Catalog(catalog));
    if hidden_mismatches > 0 {
        let _ = events.send(Event::Status(format!(
            "Hidden {hidden_mismatches} stream(s) whose publisher identity changed"
        )));
    }
    Ok(())
}

async fn subscribe(
    profile: &ConnectionProfile,
    events: &mpsc::UnboundedSender<Event>,
    keys: &Arc<Mutex<KeyCache>>,
    stream_id: Uuid,
    publisher: IdentityPublic,
    start: SubscriptionStart,
) -> Result<()> {
    let mut last_decrypted = 0u64;
    let mut attempt = 0u32;
    loop {
        let before = last_decrypted;
        let resume = if last_decrypted == 0 {
            start
        } else {
            SubscriptionStart::Sequence(last_decrypted.saturating_add(1))
        };
        match subscribe_once(
            profile,
            events,
            keys,
            stream_id,
            publisher,
            resume,
            &mut last_decrypted,
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(error) => {
                if last_decrypted > before {
                    attempt = 0;
                }
                let delay = reconnect_delay(attempt);
                attempt = attempt.saturating_add(1);
                let _ = events.send(Event::StreamError(
                    stream_id,
                    format!(
                        "Disconnected; retrying in {:.1}s ({error:#})",
                        delay.as_secs_f32()
                    ),
                ));
                let _ = refresh(profile, events, keys).await;
                tokio::time::sleep(delay).await;
            }
        }
    }
}

fn reconnect_delay(attempt: u32) -> Duration {
    Duration::from_millis(250u64.saturating_mul(1u64 << attempt.min(5)))
}

async fn subscribe_once(
    profile: &ConnectionProfile,
    events: &mpsc::UnboundedSender<Event>,
    keys: &Arc<Mutex<KeyCache>>,
    stream_id: Uuid,
    publisher: IdentityPublic,
    start: SubscriptionStart,
    last_decrypted: &mut u64,
) -> Result<()> {
    if let Some(expected) = verified_publishers(profile)?.get(&stream_id)
        && expected.id()? != publisher.id()?
    {
        anyhow::bail!("catalog publisher does not match the verified stream identity");
    }
    let mut socket = connect(profile).await?;
    let publisher_id = publisher.id()?;
    write_viewer(
        &mut socket,
        &ViewerMessage::Subscribe {
            publisher_id,
            stream_id,
            start,
        },
    )
    .await?;
    let (first_sequence, starts_live) = match read_viewer(&mut socket).await? {
        RelayViewerMessage::SubscriptionStarted {
            first_sequence,
            live,
            ..
        } => (first_sequence, live),
        RelayViewerMessage::Error(error) => {
            anyhow::bail!("subscription rejected: {}", error.detail)
        }
        _ => anyhow::bail!("unexpected subscription response"),
    };
    let _ = events.send(Event::StreamStatus(
        stream_id,
        if starts_live {
            "Waiting for live media".into()
        } else {
            "Playing retained history".into()
        },
    ));
    let mut guard =
        LiveSequenceGuard::new(publisher_id, stream_id, first_sequence.saturating_sub(1));
    let mut decoder = Decoder::new()?;
    let mut source_size = None;
    let mut pending = VecDeque::new();
    let mut pending_bytes = 0usize;
    loop {
        match read_viewer(&mut socket).await? {
            RelayViewerMessage::Object(object) => {
                guard.accept(&object)?;
                pending_bytes = pending_bytes.saturating_add(object.ciphertext.len());
                pending.push_back(object);
                if pending.len() > MAX_PENDING_OBJECTS
                    || pending_bytes > MAX_PENDING_CIPHERTEXT_BYTES
                {
                    anyhow::bail!("publisher key envelope did not arrive within buffer limits");
                }
                if let Some(sequence) = drain_pending_objects(
                    &mut decoder,
                    events,
                    &publisher,
                    keys,
                    &mut pending,
                    &mut pending_bytes,
                    &mut source_size,
                )? {
                    *last_decrypted = sequence;
                }
            }
            RelayViewerMessage::KeyEnvelope(envelope) => {
                if envelope.header.publisher_id != publisher_id
                    || envelope.header.stream_id != stream_id
                    || envelope.header.recipient_id != profile.identity.public()?.id()?
                {
                    anyhow::bail!("subscription delivered a misrouted key envelope");
                }
                let content_key = envelope.open(&profile.identity, &publisher)?;
                let group_key = GroupKey {
                    stream_id,
                    epoch_id: envelope.header.epoch_id,
                    key_group: envelope.header.key_group_id,
                    key_id: envelope.header.key_id,
                };
                keys.lock()
                    .map_err(|_| anyhow::anyhow!("key cache poisoned"))?
                    .insert(group_key, content_key);
                if let Some(sequence) = drain_pending_objects(
                    &mut decoder,
                    events,
                    &publisher,
                    keys,
                    &mut pending,
                    &mut pending_bytes,
                    &mut source_size,
                )? {
                    *last_decrypted = sequence;
                }
            }
            RelayViewerMessage::Live { .. } => {
                let _ = events.send(Event::StreamStatus(stream_id, "Live".into()));
            }
            RelayViewerMessage::Pong { .. } => {}
            RelayViewerMessage::Error(error) => {
                anyhow::bail!("relay stream error: {}", error.detail)
            }
            _ => anyhow::bail!("unexpected subscription message"),
        }
    }
}

fn drain_pending_objects(
    decoder: &mut Decoder,
    events: &mpsc::UnboundedSender<Event>,
    publisher: &IdentityPublic,
    keys: &Arc<Mutex<KeyCache>>,
    pending: &mut VecDeque<NativeObject>,
    pending_bytes: &mut usize,
    source_size: &mut Option<(u32, u32)>,
) -> Result<Option<u64>> {
    let mut last_decrypted = None;
    loop {
        let Some(object) = pending.front() else {
            return Ok(last_decrypted);
        };
        let key = keys
            .lock()
            .map_err(|_| anyhow::anyhow!("key cache poisoned"))?
            .get(&GroupKey::for_object(object));
        let Some(key) = key else {
            return Ok(last_decrypted);
        };
        let object = pending.pop_front().expect("pending front exists");
        *pending_bytes = pending_bytes.saturating_sub(object.ciphertext.len());
        let sequence = object.header.sequence;
        decode_object(decoder, events, publisher, object, key, source_size)?;
        last_decrypted = Some(sequence);
    }
}

fn decode_object(
    decoder: &mut Decoder,
    events: &mpsc::UnboundedSender<Event>,
    publisher: &IdentityPublic,
    object: NativeObject,
    key: [u8; 32],
    source_size: &mut Option<(u32, u32)>,
) -> Result<()> {
    let plaintext = object.open(
        publisher,
        &ContentKey::from_bytes(key)?,
        &object.header.key_id,
    )?;
    if object.header.kind == NativeObjectKind::Cursor {
        let (source_width, source_height) = source_size
            .as_ref()
            .copied()
            .context("cursor arrived before epoch")?;
        let batch = decode_cursor_batch(
            CursorContext {
                stream_id: object.header.stream_id,
                epoch_id: object.header.epoch_id,
                sequence: object.header.sequence,
                start_timestamp: object.header.timestamp,
                source_width,
                source_height,
            },
            &plaintext,
        )?;
        for cursor in batch.events {
            let _ = events.send(Event::Cursor(CursorUpdate {
                stream_id: object.header.stream_id,
                x_micropixels: cursor.x_micropixels,
                y_micropixels: cursor.y_micropixels,
                visible: cursor.visible,
                bitmap: cursor.bitmap,
            }));
        }
        return Ok(());
    }
    let annex_b = match object.header.kind {
        NativeObjectKind::Epoch if object.header.codec == Some(CodecId::H264AnnexB) => {
            let epoch = H264EpochPayload::decode(&plaintext)?;
            *source_size = Some((epoch.width, epoch.height));
            epoch.codec_config
        }
        NativeObjectKind::Media if object.header.codec == Some(CodecId::H264AnnexB) => plaintext,
        NativeObjectKind::Cursor | NativeObjectKind::Epoch | NativeObjectKind::Media => {
            return Ok(());
        }
    };
    for unit in nal_units(&annex_b) {
        if let Some(yuv) = decoder.decode(unit)? {
            let (width, height) = yuv.dimensions();
            let mut rgb = vec![0; yuv.rgb8_len()];
            yuv.write_rgb8(&mut rgb);
            let _ = events.send(Event::Frame(Frame {
                stream_id: object.header.stream_id,
                width,
                height,
                rgb,
                sequence: object.header.sequence,
                key_group: object.header.key_group,
            }));
        }
    }
    Ok(())
}

fn parse_relay(input: &str) -> Result<(String, Option<[u8; 32]>)> {
    let value = input.strip_prefix("glacialcast://").unwrap_or(input);
    let (authority, query) = value.split_once('?').unwrap_or((value, ""));
    let endpoint = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:{DEFAULT_VIEWER_PORT}")
    };
    glacialcast_protocol::trust::canonical_relay_endpoint(&endpoint)?;
    let pin = query
        .split('&')
        .find_map(|part| part.strip_prefix("key="))
        .map(glacialcast_protocol::decode_noise_public_key)
        .transpose()?;
    Ok((endpoint, pin))
}

fn default_state_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| Path::new(&home).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("glacialcast/viewer")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_profile(root: PathBuf) -> ConnectionProfile {
        ConnectionProfile {
            endpoint: "127.0.0.1:1".into(),
            state_dir: root,
            identity: Arc::new(IdentitySecret::generate()),
            noise: glacialcast_protocol::generate_noise_keypair().unwrap(),
            credential: None,
            explicit_pin: None,
        }
    }

    #[test]
    fn relay_argument_accepts_host_port_and_invite_pin() {
        assert_eq!(
            parse_relay("relay.example").unwrap().0,
            "relay.example:8899"
        );
        let key = glacialcast_protocol::encode_noise_public_key(&[7; 32]);
        let (_, pin) = parse_relay(&format!("glacialcast://relay.example:99?key={key}")).unwrap();
        assert_eq!(pin, Some([7; 32]));
        assert!(parse_relay("bad host").is_err());
    }

    #[test]
    fn verified_publishers_persist_and_identity_changes_fail_closed() {
        let root = std::env::temp_dir().join(format!("gcview-trust-{}", Uuid::new_v4()));
        let profile = test_profile(root.clone());
        let stream_id = Uuid::from_u128(1);
        let first = IdentitySecret::generate().public().unwrap();
        let second = IdentitySecret::generate().public().unwrap();
        remember_verified_publisher(&profile, stream_id, first).unwrap();
        assert_eq!(
            verified_publishers(&profile)
                .unwrap()
                .get(&stream_id)
                .unwrap()
                .id()
                .unwrap(),
            first.id().unwrap()
        );
        assert!(remember_verified_publisher(&profile, stream_id, second).is_err());
        assert_eq!(
            verified_publishers(&profile)
                .unwrap()
                .get(&stream_id)
                .unwrap()
                .id()
                .unwrap(),
            first.id().unwrap()
        );
        forget_verified_publisher(&profile, stream_id).unwrap();
        assert!(verified_publishers(&profile).unwrap().is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn key_cache_and_reconnect_backoff_are_bounded() {
        let mut cache = KeyCache::default();
        for index in 0..=MAX_CACHED_KEYS {
            cache.insert(
                GroupKey {
                    stream_id: Uuid::from_u128(1),
                    epoch_id: Uuid::from_u128(2),
                    key_group: u64::try_from(index).unwrap(),
                    key_id: [u8::try_from(index % 256).unwrap(); 16],
                },
                [u8::try_from(index % 256).unwrap(); 32],
            );
        }
        assert_eq!(cache.keys.len(), MAX_CACHED_KEYS);
        assert!(cache.keys.keys().all(|group| group.key_group != 0));
        assert_eq!(reconnect_delay(0), Duration::from_millis(250));
        assert_eq!(reconnect_delay(99), Duration::from_secs(8));
    }

    #[test]
    fn native_cursor_object_decodes_into_a_render_update() {
        use glacialcast_protocol::{
            cursor::{CursorBatch, CursorContext, CursorEvent, encode_cursor_batch},
            native::{GroupEncryptor, NewNativeObject},
        };

        let publisher = IdentitySecret::generate();
        let publisher_public = publisher.public().unwrap();
        let stream_id = Uuid::from_u128(1);
        let epoch_id = Uuid::from_u128(2);
        let mut group =
            GroupEncryptor::generate(&publisher_public, stream_id, epoch_id, 1, 0).unwrap();
        let payload = encode_cursor_batch(
            CursorContext {
                stream_id,
                epoch_id,
                sequence: 1,
                start_timestamp: 90,
                source_width: 640,
                source_height: 480,
            },
            &CursorBatch {
                source_width: 640,
                source_height: 480,
                events: vec![CursorEvent {
                    timestamp: 90,
                    x_micropixels: 12_000_000,
                    y_micropixels: 34_000_000,
                    visible: true,
                    bitmap_id: 0,
                    bitmap: None,
                }],
            },
        )
        .unwrap();
        let key = group.content_key();
        let object = group
            .seal(
                &publisher,
                NewNativeObject {
                    sequence: 1,
                    timestamp: 90,
                    duration: 1,
                    kind: NativeObjectKind::Cursor,
                    random_access: false,
                    codec: None,
                },
                &payload,
            )
            .unwrap();
        let (events, mut receiver) = mpsc::unbounded_channel();
        decode_object(
            &mut Decoder::new().unwrap(),
            &events,
            &publisher_public,
            object,
            key,
            &mut Some((640, 480)),
        )
        .unwrap();
        match receiver.try_recv().unwrap() {
            Event::Cursor(cursor) => {
                assert!(cursor.visible);
                assert_eq!(cursor.x_micropixels, 12_000_000);
                assert_eq!(cursor.y_micropixels, 34_000_000);
            }
            _ => panic!("expected cursor update"),
        }
    }
}
