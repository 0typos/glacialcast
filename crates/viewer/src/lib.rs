//! Native multi-stream GlacialCast viewer.

#![deny(missing_docs)]

use anyhow::{Context, Result};
use clap::Parser;
use eframe::egui;
use glacialcast_protocol::{
    NoiseKeypair, NoiseSocket, PROTOCOL_VERSION,
    credential::{CredentialRequest, CredentialRole, NativeCredential},
    identity::{IdentityPublic, IdentitySecret, load_or_create_identity},
    initiator_handshake_xx, load_or_create_noise_keypair,
    native::{
        CodecId, ContentKey, H264EpochPayload, LiveSequenceGuard, NativeObject, NativeObjectKind,
    },
    pairing::{PairOffer, PairRequest, ViewerConfirmation, authentication_string},
    private_state::{read_private, replace_private},
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
    /// Verify the relay, print its catalog, and exit without opening a window.
    #[arg(long)]
    headless: bool,
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
}

enum Event {
    Status(String),
    Catalog(Vec<CatalogEntry>),
    Frame(Frame),
    StreamError(Uuid, String),
    PairingPrompt([u8; 32], String),
}

enum Command {
    Refresh,
    Subscribe(Uuid, IdentityPublic, SubscriptionStart),
    Pair(IdentityPublic),
    ConfirmPairing([u8; 32], bool),
}

struct Tile {
    catalog: CatalogEntry,
    texture: Option<egui::TextureHandle>,
    sequence: u64,
    status: String,
    seek_timestamp: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct PairingState {
    version: u16,
    pending: Vec<(PairRequest, Option<PairOffer>)>,
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
                            tile.catalog = entry;
                        } else {
                            let seek_timestamp =
                                entry.retained.map_or(0, |bounds| bounds.newest_timestamp);
                            self.tiles.push(Tile {
                                catalog: entry,
                                texture: None,
                                sequence: 0,
                                status: "Available".into(),
                                seek_timestamp,
                            });
                        }
                    }
                    self.tiles
                        .sort_by_key(|tile| tile.catalog.descriptor.body.stream_id);
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
                        tile.status = "Live".into();
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
                _ => 2,
            };
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
                                        .send(Command::Pair(descriptor.publisher));
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
                            let available = ui.available_size_before_wrap();
                            let size = egui::vec2(available.x.max(240.0), (available.y / 2.0).max(160.0));
                            if let Some(texture) = &tile.texture {
                                ui.add(egui::Image::new(texture).fit_to_exact_size(size));
                            } else {
                                ui.allocate_ui(size, |ui| { ui.centered_and_justified(|ui| { ui.label("Encrypted stream — approve this viewer on the publisher if playback stays locked"); }); });
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

async fn headless_catalog(profile: &ConnectionProfile) -> Result<()> {
    let mut socket = connect(profile).await?;
    socket.write(&ViewerMessage::Catalog).await?;
    match socket.read::<RelayViewerMessage>().await? {
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
    let keys = Arc::new(Mutex::new(HashMap::new()));
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
    while let Some(command) = commands.recv().await {
        match command {
            Command::Refresh => {
                if let Err(error) = refresh(&profile, &events, &keys).await {
                    let _ = events.send(Event::Status(format!("Connection failed: {error:#}")));
                }
                if let Err(error) = refresh_pairing(&profile, &events, &mut pending).await {
                    let _ =
                        events.send(Event::Status(format!("Pairing refresh failed: {error:#}")));
                }
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
            Command::Pair(publisher) => match begin_pairing(&profile, publisher).await {
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
            },
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

async fn begin_pairing(
    profile: &ConnectionProfile,
    publisher: IdentityPublic,
) -> Result<PairRequest> {
    let now = glacialcast_protocol::now_ms();
    let request = PairRequest::new_with_credential(
        &profile.identity,
        publisher,
        "gcview device".into(),
        profile.credential.clone(),
        now,
        now.saturating_add(24 * 60 * 60 * 1_000),
    )?;
    let mut socket = connect(profile).await?;
    socket
        .write(&ViewerMessage::PairRequest(Box::new(request.clone())))
        .await?;
    match socket.read::<RelayViewerMessage>().await? {
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
    socket.write(&ViewerMessage::FetchInbox).await?;
    loop {
        match socket.read::<RelayViewerMessage>().await? {
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
                    let status = if decision.body.approved {
                        "Publisher approved this viewer"
                    } else {
                        "Publisher rejected this viewer"
                    };
                    let _ = events.send(Event::Status(status.into()));
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
    socket
        .write(&ViewerMessage::PairConfirmation(confirmation))
        .await?;
    match socket.read::<RelayViewerMessage>().await? {
        RelayViewerMessage::PairingQueued { request_id } if request_id == request.id()? => Ok(()),
        RelayViewerMessage::Error(error) => {
            anyhow::bail!("relay rejected confirmation: {}", error.detail)
        }
        _ => anyhow::bail!("unexpected confirmation response"),
    }
}

async fn connect(profile: &ConnectionProfile) -> Result<NoiseSocket<TcpStream>> {
    let mut stream = TcpStream::connect(&profile.endpoint)
        .await
        .with_context(|| format!("connecting to {}", profile.endpoint))?;
    let expected = if let Some(pin) = profile.explicit_pin {
        Some(pin)
    } else {
        KnownRelays::open(profile.state_dir.join("known-relays.bin"))?.get(&profile.endpoint)?
    };
    let (transport, remote) = initiator_handshake_xx(
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
    )
    .await?;
    if profile.explicit_pin.is_none() {
        KnownRelays::open(profile.state_dir.join("known-relays.bin"))?
            .verify_or_learn(&profile.endpoint, remote)?;
    }
    let mut socket = NoiseSocket::new(stream, transport);
    socket
        .write(&ViewerMessage::Hello(SessionHello {
            protocol_version: PROTOCOL_VERSION,
            role: CredentialRole::Viewer,
            identity: profile.identity.public()?,
            credential: profile.credential.clone(),
        }))
        .await?;
    match socket.read::<RelayViewerMessage>().await? {
        RelayViewerMessage::Welcome(_) => Ok(socket),
        RelayViewerMessage::Error(error) => {
            anyhow::bail!("relay rejected viewer: {:?}: {}", error.code, error.detail)
        }
        _ => anyhow::bail!("relay did not send a welcome first"),
    }
}

async fn refresh(
    profile: &ConnectionProfile,
    events: &mpsc::UnboundedSender<Event>,
    keys: &Arc<Mutex<HashMap<GroupKey, [u8; 32]>>>,
) -> Result<()> {
    let mut socket = connect(profile).await?;
    socket.write(&ViewerMessage::Catalog).await?;
    let catalog = match socket.read::<RelayViewerMessage>().await? {
        RelayViewerMessage::Catalog(catalog) => catalog,
        RelayViewerMessage::Error(error) => anyhow::bail!("catalog rejected: {}", error.detail),
        _ => anyhow::bail!("unexpected catalog response"),
    };
    let publishers: HashMap<[u8; 32], IdentityPublic> = catalog
        .iter()
        .map(|entry| {
            Ok((
                entry.descriptor.body.publisher.id()?,
                entry.descriptor.body.publisher,
            ))
        })
        .collect::<Result<_>>()?;
    socket.write(&ViewerMessage::FetchInbox).await?;
    loop {
        match socket.read::<RelayViewerMessage>().await? {
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
    Ok(())
}

async fn subscribe(
    profile: &ConnectionProfile,
    events: &mpsc::UnboundedSender<Event>,
    keys: &Arc<Mutex<HashMap<GroupKey, [u8; 32]>>>,
    stream_id: Uuid,
    publisher: IdentityPublic,
    start: SubscriptionStart,
) -> Result<()> {
    let mut socket = connect(profile).await?;
    let publisher_id = publisher.id()?;
    socket
        .write(&ViewerMessage::Subscribe {
            publisher_id,
            stream_id,
            start,
        })
        .await?;
    let first_sequence = match socket.read::<RelayViewerMessage>().await? {
        RelayViewerMessage::SubscriptionStarted { first_sequence, .. } => first_sequence,
        RelayViewerMessage::Error(error) => {
            anyhow::bail!("subscription rejected: {}", error.detail)
        }
        _ => anyhow::bail!("unexpected subscription response"),
    };
    let mut guard =
        LiveSequenceGuard::new(publisher_id, stream_id, first_sequence.saturating_sub(1));
    let mut decoder = Decoder::new()?;
    let mut pending = VecDeque::new();
    let mut pending_bytes = 0usize;
    loop {
        match socket.read::<RelayViewerMessage>().await? {
            RelayViewerMessage::Object(object) => {
                guard.accept(&object)?;
                pending_bytes = pending_bytes.saturating_add(object.ciphertext.len());
                pending.push_back(object);
                if pending.len() > MAX_PENDING_OBJECTS
                    || pending_bytes > MAX_PENDING_CIPHERTEXT_BYTES
                {
                    anyhow::bail!("publisher key envelope did not arrive within buffer limits");
                }
                drain_pending_objects(
                    &mut decoder,
                    events,
                    &publisher,
                    keys,
                    &mut pending,
                    &mut pending_bytes,
                )?;
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
                drain_pending_objects(
                    &mut decoder,
                    events,
                    &publisher,
                    keys,
                    &mut pending,
                    &mut pending_bytes,
                )?;
            }
            RelayViewerMessage::Live { .. } | RelayViewerMessage::Pong { .. } => {}
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
    keys: &Arc<Mutex<HashMap<GroupKey, [u8; 32]>>>,
    pending: &mut VecDeque<NativeObject>,
    pending_bytes: &mut usize,
) -> Result<()> {
    loop {
        let Some(object) = pending.front() else {
            return Ok(());
        };
        let key = keys
            .lock()
            .map_err(|_| anyhow::anyhow!("key cache poisoned"))?
            .get(&GroupKey::for_object(object))
            .copied();
        let Some(key) = key else {
            return Ok(());
        };
        let object = pending.pop_front().expect("pending front exists");
        *pending_bytes = pending_bytes.saturating_sub(object.ciphertext.len());
        decode_object(decoder, events, publisher, object, key)?;
    }
}

fn decode_object(
    decoder: &mut Decoder,
    events: &mpsc::UnboundedSender<Event>,
    publisher: &IdentityPublic,
    object: NativeObject,
    key: [u8; 32],
) -> Result<()> {
    let plaintext = object.open(
        publisher,
        &ContentKey::from_bytes(key)?,
        &object.header.key_id,
    )?;
    let annex_b = match object.header.kind {
        NativeObjectKind::Epoch if object.header.codec == Some(CodecId::H264AnnexB) => {
            H264EpochPayload::decode(&plaintext)?.codec_config
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
}
