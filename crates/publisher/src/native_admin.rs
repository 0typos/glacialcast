//! Publisher-side durable viewer approval administration.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use glacialcast_protocol::{
    NoiseKeypair, NoiseSocket, PROTOCOL_VERSION,
    credential::{
        CertificateAuthorityPublic, CredentialRequest, CredentialRole, NativeCredential,
        RevocationList,
    },
    envelope::KeyEnvelope,
    identity::{IdentityPublic, IdentitySecret, load_or_create_identity},
    initiator_handshake_xx, load_or_create_noise_keypair,
    pairing::{
        PairDecisionReason, PairOffer, PairRequest, PublisherDecision, ViewerConfirmation,
        authentication_string,
    },
    private_state::{PrivateLockMode, lock_private, read_private, replace_private},
    trust::KnownRelays,
    wire::{PublisherMessage, RelayPublisherMessage, SessionHello},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::PathBuf};
use tokio::{net::TcpStream, sync::watch};
use tracing::{info, warn};
use uuid::Uuid;

const STATE_VERSION: u16 = 3;
const MAX_STATE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;
const PAIR_LIFETIME_MS: i64 = 24 * 60 * 60 * 1_000;
const NETWORK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

#[derive(Clone, Copy, Debug, Default, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum ViewerPolicy {
    #[default]
    Required,
    Open,
    TrustedCa,
}

#[derive(Debug, Parser)]
#[command(version, about = "Manage native GlacialCast viewer approvals")]
struct AdminArgs {
    /// Publisher policy file (defaults to `<state-dir>/config.toml`).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Publisher listener in host[:port] form.
    #[arg(long, default_value = "127.0.0.1:8900")]
    relay: String,
    /// Private publisher state directory.
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Explicit relay Noise key pin.
    #[arg(long)]
    server_key: Option<String>,
    /// Optional signed-relay publisher credential.
    #[arg(long)]
    credential: Option<PathBuf>,
    /// Viewer approval policy, overriding `config.toml`.
    #[arg(long, value_enum)]
    policy: Option<ViewerPolicy>,
    #[command(subcommand)]
    command: AdminCommand,
}

#[derive(Debug, Subcommand)]
enum AdminCommand {
    /// Fetch and display pending requests.
    Requests,
    /// Approve one confirmed request by ID or unique prefix.
    Approve { request: String },
    /// Approve every currently confirmed request.
    ApproveAll,
    /// Reject one request by ID or unique prefix.
    Deny { request: String },
    /// Permanently revoke a viewer by identity ID or unique prefix.
    Revoke {
        viewer: String,
        /// Stream whose grant is permanently revoked.
        #[arg(long)]
        stream: Uuid,
    },
    /// List approved and revoked viewer identities.
    Viewers,
    /// Create a publisher request for an offline relay-access CA.
    CredentialRequest {
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "gcpub")]
        subject: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PendingPairing {
    request: PairRequest,
    offer: PairOffer,
    confirmation: Option<ViewerConfirmation>,
    source_addr: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct PublisherState {
    version: u16,
    pending: Vec<PendingPairing>,
    approved: Vec<StreamGrant>,
    revoked: Vec<RevokedGrant>,
    offer_outbox: Vec<[u8; 32]>,
    decision_outbox: Vec<PublisherDecision>,
    history_outbox: Vec<StreamGrant>,
}

#[derive(Debug, Deserialize, Serialize)]
struct PublisherStateV2 {
    version: u16,
    pending: Vec<PendingPairing>,
    approved: Vec<StreamGrant>,
    revoked: Vec<RevokedGrant>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct StreamGrant {
    stream_id: Uuid,
    viewer: IdentityPublic,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct RevokedGrant {
    stream_id: Uuid,
    viewer_id: [u8; 32],
}

impl Default for PublisherState {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            pending: Vec::new(),
            approved: Vec::new(),
            revoked: Vec::new(),
            offer_outbox: Vec::new(),
            decision_outbox: Vec::new(),
            history_outbox: Vec::new(),
        }
    }
}

struct Profile {
    relay: String,
    state_dir: PathBuf,
    identity: IdentitySecret,
    noise: NoiseKeypair,
    credential: Option<NativeCredential>,
    pin: Option<[u8; 32]>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PublisherConfig {
    viewers: ViewerConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ViewerConfig {
    policy: ViewerPolicy,
    trusted_authority_file: Option<PathBuf>,
    trusted_revocations_file: Option<PathBuf>,
}

struct ApprovalPolicy {
    mode: ViewerPolicy,
    authority: Option<CertificateAuthorityPublic>,
    revocations: Option<RevocationList>,
}

pub(super) fn is_admin_command() -> bool {
    std::env::args().skip(1).any(|argument| {
        matches!(
            argument.as_str(),
            "requests"
                | "approve"
                | "approve-all"
                | "deny"
                | "revoke"
                | "viewers"
                | "credential-request"
        )
    })
}

pub(super) fn run() -> Result<()> {
    let args = AdminArgs::parse();
    let state_dir = args.state_dir.unwrap_or_else(super::client_state_dir);
    std::fs::create_dir_all(&state_dir)?;
    let config = load_config(args.config.as_deref(), &state_dir)?;
    let policy = load_policy(args.policy.unwrap_or(config.viewers.policy), config.viewers)?;
    let profile = Profile {
        relay: normalize_relay(&args.relay),
        identity: load_or_create_identity(&state_dir.join("native-identity.key"))?,
        noise: load_or_create_noise_keypair(&state_dir.join("native-noise.key"))?,
        credential: args
            .credential
            .as_deref()
            .map(|path| NativeCredential::decode(&read_private(path, MAX_CREDENTIAL_BYTES)?))
            .transpose()?,
        pin: args
            .server_key
            .as_deref()
            .map(glacialcast_protocol::decode_noise_public_key)
            .transpose()?,
        state_dir,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(execute(profile, policy, args.command))
}

pub(super) async fn run_live_approvals(
    relay: String,
    state_dir: PathBuf,
    credential_path: Option<PathBuf>,
    pin: Option<[u8; 32]>,
    mut shutdown: watch::Receiver<bool>,
) {
    let identity = match load_or_create_identity(&state_dir.join("native-identity.key")) {
        Ok(identity) => identity,
        Err(error) => {
            warn!(error = %format!("{error:#}"), "viewer approval worker could not load publisher identity");
            return;
        }
    };
    let noise = match load_or_create_noise_keypair(&state_dir.join("native-noise.key")) {
        Ok(noise) => noise,
        Err(error) => {
            warn!(error = %format!("{error:#}"), "viewer approval worker could not load Noise identity");
            return;
        }
    };
    let credential = match credential_path
        .as_deref()
        .map(|path| NativeCredential::decode(&read_private(path, MAX_CREDENTIAL_BYTES)?))
        .transpose()
    {
        Ok(credential) => credential,
        Err(error) => {
            warn!(error = %format!("{error:#}"), "viewer approval worker could not load relay credential");
            return;
        }
    };
    let profile = Profile {
        relay: normalize_relay(&relay),
        state_dir: state_dir.clone(),
        identity,
        noise,
        credential,
        pin,
    };
    let state_path = state_dir.join("publisher-state.bin");
    let state_lock_path = state_dir.join(".publisher-state.lock");
    loop {
        if *shutdown.borrow() {
            return;
        }
        let result = async {
            let _state_lock = lock_private(&state_lock_path, PrivateLockMode::Exclusive)?;
            let config = load_config(None, &state_dir)?;
            let policy = load_policy(config.viewers.policy, config.viewers)?;
            let mut state = load_state_unlocked(&state_path)?;
            flush_outbox(&profile, &mut state, &state_path).await?;
            let pending_before = state.pending.len();
            let grants_before = state.approved.len();
            refresh_requests(&profile, &mut state, &policy).await?;
            save_state_unlocked(&state_path, &state)?;
            flush_outbox(&profile, &mut state, &state_path).await?;
            flush_history_outbox(&profile, &mut state, &state_path).await;
            if state.pending.len() > pending_before {
                info!(
                    new_requests = state.pending.len() - pending_before,
                    "viewer approval requests are waiting; run `gcpub requests`"
                );
            }
            if state.approved.len() > grants_before {
                info!(
                    new_grants = state.approved.len() - grants_before,
                    "viewer access approved by publisher policy"
                );
            }
            Result::<()>::Ok(())
        }
        .await;
        if let Err(error) = result {
            warn!(error = %format!("{error:#}"), "viewer approval synchronization failed; retrying");
        }
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
            changed = shutdown.changed() => {
                let _ = changed;
                return;
            }
        }
    }
}

async fn execute(profile: Profile, policy: ApprovalPolicy, command: AdminCommand) -> Result<()> {
    if let AdminCommand::CredentialRequest { output, subject } = &command {
        let now = glacialcast_protocol::now_ms();
        let request = CredentialRequest::new(
            &profile.identity,
            subject.clone(),
            CredentialRole::Publisher,
            profile.noise.public,
            now,
            now.saturating_add(PAIR_LIFETIME_MS),
        )?;
        glacialcast_protocol::private_state::create_private(output, &request.encode()?)?;
        println!("wrote publisher credential request {}", output.display());
        return Ok(());
    }
    let state_path = profile.state_dir.join("publisher-state.bin");
    let _state_lock = lock_private(
        &profile.state_dir.join(".publisher-state.lock"),
        PrivateLockMode::Exclusive,
    )?;
    let mut state = load_state_unlocked(&state_path)?;
    let offline_command = matches!(
        &command,
        AdminCommand::Viewers | AdminCommand::Revoke { .. }
    );
    if !offline_command {
        flush_outbox(&profile, &mut state, &state_path).await?;
        refresh_requests(&profile, &mut state, &policy).await?;
        save_state_unlocked(&state_path, &state)?;
        flush_outbox(&profile, &mut state, &state_path).await?;
    }
    match command {
        AdminCommand::Requests => print_requests(&state)?,
        AdminCommand::Approve { request } => {
            decide(&profile, &mut state, &request, true).await?;
        }
        AdminCommand::ApproveAll => {
            let ids: Vec<String> = state
                .pending
                .iter()
                .filter(|pending| pending.confirmation.is_some())
                .map(|pending| hex(&pending.request.id().expect("validated request")))
                .collect();
            for request in ids {
                decide(&profile, &mut state, &request, true).await?;
            }
            println!("approved every currently confirmed request");
        }
        AdminCommand::Deny { request } => {
            decide(&profile, &mut state, &request, false).await?;
        }
        AdminCommand::Revoke { viewer, stream } => {
            let index = unique_grant(&state.approved, stream, &viewer)?;
            let removed = state.approved.remove(index);
            let viewer_id = removed.viewer.id()?;
            let revoked = RevokedGrant {
                stream_id: stream,
                viewer_id,
            };
            if !state.revoked.contains(&revoked) {
                state.revoked.push(revoked);
                state.revoked.sort_unstable();
            }
            state.history_outbox.retain(|grant| {
                grant.stream_id != stream || grant.viewer.id().ok() != Some(viewer_id)
            });
            println!(
                "revoked {} from {}; active publication must rotate its group immediately",
                hex(&viewer_id),
                stream
            );
        }
        AdminCommand::Viewers => {
            for grant in &state.approved {
                println!("approved {} {}", grant.stream_id, hex(&grant.viewer.id()?));
            }
            for grant in &state.revoked {
                println!("revoked  {} {}", grant.stream_id, hex(&grant.viewer_id));
            }
        }
        AdminCommand::CredentialRequest { .. } => unreachable!("handled before loading state"),
    }
    save_state_unlocked(&state_path, &state)?;
    if offline_command {
        return Ok(());
    }
    flush_outbox(&profile, &mut state, &state_path).await?;
    flush_history_outbox(&profile, &mut state, &state_path).await;
    Ok(())
}

async fn refresh_requests(
    profile: &Profile,
    state: &mut PublisherState,
    policy: &ApprovalPolicy,
) -> Result<()> {
    let (mut socket, relay_key) = connect(profile).await?;
    write_publisher(&mut socket, &PublisherMessage::FetchPairingInbox).await?;
    let mut requests = Vec::new();
    let mut confirmations = Vec::new();
    loop {
        match read_relay(&mut socket).await? {
            RelayPublisherMessage::PairRequest {
                request,
                source_addr,
                ..
            } => {
                requests.push((*request, source_addr.to_string()));
            }
            RelayPublisherMessage::ViewerConfirmation(confirmation) => {
                confirmations.push(confirmation)
            }
            RelayPublisherMessage::PairingInboxComplete => break,
            RelayPublisherMessage::Error(error) => {
                anyhow::bail!("relay pairing inbox failed: {}", error.detail)
            }
            _ => anyhow::bail!("unexpected publisher inbox response"),
        }
    }
    let revoked: BTreeSet<RevokedGrant> = state.revoked.iter().copied().collect();
    for (request, source_addr) in requests {
        request.verify(glacialcast_protocol::now_ms(), PAIR_LIFETIME_MS)?;
        let request_id = request.id()?;
        if revoked.contains(&RevokedGrant {
            stream_id: request.body.stream_id,
            viewer_id: request.body.viewer.id()?,
        }) {
            continue;
        }
        if state
            .pending
            .iter()
            .any(|pending| pending.request.id().ok() == Some(request_id))
        {
            continue;
        }
        let policy_reason = match policy.mode {
            ViewerPolicy::Open => Some(PairDecisionReason::OpenPolicy),
            ViewerPolicy::TrustedCa => {
                let Some(credential) = request.body.viewer_credential.as_ref() else {
                    continue;
                };
                let Some(authority) = policy.authority.as_ref() else {
                    continue;
                };
                if credential
                    .verify_at(
                        authority,
                        policy.revocations.as_ref(),
                        CredentialRole::Viewer,
                        &credential.body.noise_static_key,
                        glacialcast_protocol::now_ms(),
                    )
                    .is_err()
                {
                    continue;
                }
                Some(PairDecisionReason::TrustedViewerCa)
            }
            ViewerPolicy::Required => None,
        };
        if let Some(reason) = policy_reason {
            let decision = PublisherDecision::approve_by_policy(
                &profile.identity,
                &request,
                reason,
                glacialcast_protocol::now_ms(),
            )?;
            add_approved(state, request.body.stream_id, request.body.viewer)?;
            queue_decision(state, decision)?;
            continue;
        }
        let now = glacialcast_protocol::now_ms();
        let offer = PairOffer::new(
            &profile.identity,
            &request,
            Sha256::digest(relay_key).into(),
            now,
            request.body.expires_at_ms,
            PAIR_LIFETIME_MS,
        )?;
        state.pending.push(PendingPairing {
            request,
            offer,
            confirmation: None,
            source_addr,
        });
        if !state.offer_outbox.contains(&request_id) {
            state.offer_outbox.push(request_id);
            state.offer_outbox.sort_unstable();
        }
    }
    for confirmation in confirmations {
        if let Some(pending) = state
            .pending
            .iter_mut()
            .find(|pending| pending.request.id().ok() == Some(confirmation.body.request_id))
        {
            confirmation.verify(&pending.request, &pending.offer)?;
            pending.confirmation = Some(confirmation);
        }
    }
    state
        .pending
        .sort_by_key(|pending| pending.request.id().unwrap_or([0; 32]));
    Ok(())
}

fn load_config(
    path: Option<&std::path::Path>,
    state_dir: &std::path::Path,
) -> Result<PublisherConfig> {
    let path = path
        .map(PathBuf::from)
        .unwrap_or_else(|| state_dir.join("config.toml"));
    if !path.exists() {
        return Ok(PublisherConfig::default());
    }
    let bytes = read_private(&path, 1024 * 1024)
        .with_context(|| format!("reading publisher config {}", path.display()))?;
    toml::from_str(std::str::from_utf8(&bytes).context("publisher config is not UTF-8")?)
        .with_context(|| format!("parsing publisher config {}", path.display()))
}

fn load_policy(mode: ViewerPolicy, config: ViewerConfig) -> Result<ApprovalPolicy> {
    let authority = config
        .trusted_authority_file
        .as_deref()
        .map(|path| CertificateAuthorityPublic::decode(&read_private(path, MAX_CREDENTIAL_BYTES)?))
        .transpose()?;
    let revocations = config
        .trusted_revocations_file
        .as_deref()
        .map(|path| RevocationList::decode(&read_private(path, MAX_CREDENTIAL_BYTES)?))
        .transpose()?;
    if matches!(mode, ViewerPolicy::TrustedCa) && authority.is_none() {
        anyhow::bail!("trusted_ca policy requires viewers.trusted_authority_file");
    }
    if let (Some(authority), Some(revocations)) = (&authority, &revocations) {
        revocations.verify_at(authority, glacialcast_protocol::now_ms())?;
    }
    Ok(ApprovalPolicy {
        mode,
        authority,
        revocations,
    })
}

async fn decide(
    profile: &Profile,
    state: &mut PublisherState,
    prefix: &str,
    approve: bool,
) -> Result<()> {
    let index = unique_request(&state.pending, prefix)?;
    let pending = state.pending[index].clone();
    let decision = if approve {
        let confirmation = pending.confirmation.as_ref().context(
            "viewer has not confirmed the authentication string; approval cannot be skipped",
        )?;
        PublisherDecision::approve_manual(
            &profile.identity,
            &pending.request,
            &pending.offer,
            confirmation,
            glacialcast_protocol::now_ms(),
        )?
    } else {
        PublisherDecision::reject(
            &profile.identity,
            &pending.request,
            glacialcast_protocol::now_ms(),
        )?
    };
    if approve {
        add_approved(
            state,
            pending.request.body.stream_id,
            pending.request.body.viewer,
        )?;
        println!(
            "approved {} for {}",
            hex(&pending.request.body.viewer.id()?),
            pending.request.body.stream_id
        );
    } else {
        println!("denied {}", hex(&pending.request.id()?));
    }
    queue_decision(state, decision)?;
    state.pending.remove(index);
    let request_id = pending.request.id()?;
    state.offer_outbox.retain(|queued| queued != &request_id);
    Ok(())
}

fn queue_decision(state: &mut PublisherState, decision: PublisherDecision) -> Result<()> {
    let request_id = decision.body.request_id;
    if let Some(existing) = state
        .decision_outbox
        .iter()
        .find(|queued| queued.body.request_id == request_id)
    {
        if existing != &decision {
            anyhow::bail!("publisher decision outbox contains conflicting content");
        }
        return Ok(());
    }
    state.decision_outbox.push(decision);
    state
        .decision_outbox
        .sort_by_key(|queued| queued.body.request_id);
    Ok(())
}

async fn flush_outbox(
    profile: &Profile,
    state: &mut PublisherState,
    state_path: &std::path::Path,
) -> Result<()> {
    if state.offer_outbox.is_empty() && state.decision_outbox.is_empty() {
        return Ok(());
    }
    let (mut socket, _) = connect(profile).await?;
    while let Some(request_id) = state.offer_outbox.first().copied() {
        let offer = state
            .pending
            .iter()
            .find(|pending| pending.request.id().ok() == Some(request_id))
            .map(|pending| pending.offer.clone())
            .context("publisher offer outbox lost its pending request")?;
        write_publisher(&mut socket, &PublisherMessage::PairOffer(offer)).await?;
        expect_pairing_ack(&mut socket, request_id).await?;
        state.offer_outbox.remove(0);
        save_state_unlocked(state_path, state)?;
    }
    while let Some(decision) = state.decision_outbox.first().cloned() {
        let request_id = decision.body.request_id;
        write_publisher(&mut socket, &PublisherMessage::PairDecision(decision)).await?;
        expect_pairing_ack(&mut socket, request_id).await?;
        state.decision_outbox.remove(0);
        save_state_unlocked(state_path, state)?;
    }
    Ok(())
}

async fn flush_history_outbox(
    profile: &Profile,
    state: &mut PublisherState,
    state_path: &std::path::Path,
) {
    for grant in state.history_outbox.clone() {
        match publish_history_envelopes(profile, grant.stream_id, &grant.viewer).await {
            Ok(()) => {
                let viewer_id = grant.viewer.id().ok();
                state.history_outbox.retain(|queued| {
                    queued.stream_id != grant.stream_id || queued.viewer.id().ok() != viewer_id
                });
                if let Err(error) = save_state_unlocked(state_path, state) {
                    warn!(error = %format!("{error:#}"), "could not commit retained-key outbox progress");
                    return;
                }
            }
            Err(error) => warn!(
                stream = %grant.stream_id,
                viewer = %grant.viewer.id().map(|id| hex(&id)).unwrap_or_else(|_| "invalid".into()),
                error = %format!("{error:#}"),
                "retained-key authorization is still queued"
            ),
        }
    }
}

async fn publish_history_envelopes(
    profile: &Profile,
    stream_id: Uuid,
    viewer: &IdentityPublic,
) -> Result<()> {
    let groups =
        super::native_publish::load_key_history(&profile.state_dir.join("key-history.bin"))?;
    let (mut socket, _) = connect(profile).await?;
    publish_history_groups(&mut socket, &profile.identity, viewer, stream_id, &groups).await
}

async fn publish_history_groups(
    socket: &mut NoiseSocket<TcpStream>,
    publisher: &IdentitySecret,
    viewer: &IdentityPublic,
    stream_id: Uuid,
    groups: &[super::native_publish::RetainedGroupKey],
) -> Result<()> {
    // Zero-byte groups are excluded rather than offered: a group only counts
    // content after its epoch object is acknowledged, so a zero-byte entry is
    // either mid-rotation or was abandoned before publishing anything. The
    // relay holds no ciphertext for it and refuses its envelope, and one
    // refusal used to wedge every grant behind it in a permanent retry loop.
    // A mid-rotation group is delivered moments later by the live path.
    let groups: Vec<_> = groups
        .iter()
        .rev()
        .filter(|group| group.stream_id == stream_id && group.has_published_content())
        .collect();
    if groups.is_empty() {
        return Ok(());
    }
    for group in groups {
        write_publisher(
            socket,
            &PublisherMessage::KeyEnvelope(KeyEnvelope::seal(
                publisher,
                viewer,
                group.stream_id,
                group.epoch_id,
                group.key_group_id,
                group.key_id,
                &group.content_key,
            )?),
        )
        .await?;
    }
    write_publisher(
        socket,
        &PublisherMessage::Ping {
            now_ms: glacialcast_protocol::now_ms(),
        },
    )
    .await?;
    match read_relay(socket).await? {
        RelayPublisherMessage::Pong { .. } => Ok(()),
        RelayPublisherMessage::Error(error) => {
            anyhow::bail!("relay rejected retained key envelope: {}", error.detail)
        }
        _ => anyhow::bail!("relay did not confirm retained key-envelope processing"),
    }
}

fn add_approved(state: &mut PublisherState, stream_id: Uuid, viewer: IdentityPublic) -> Result<()> {
    let id = viewer.id()?;
    if state
        .revoked
        .binary_search(&RevokedGrant {
            stream_id,
            viewer_id: id,
        })
        .is_ok()
    {
        anyhow::bail!("viewer is permanently revoked for this stream");
    }
    if !state
        .approved
        .iter()
        .any(|grant| grant.stream_id == stream_id && grant.viewer.id().ok() == Some(id))
    {
        let grant = StreamGrant { stream_id, viewer };
        state.approved.push(grant.clone());
        state
            .approved
            .sort_by_key(|grant| (grant.stream_id, grant.viewer.id().unwrap_or([0; 32])));
        state.history_outbox.push(grant);
        state
            .history_outbox
            .sort_by_key(|grant| (grant.stream_id, grant.viewer.id().unwrap_or([0; 32])));
    }
    Ok(())
}

fn print_requests(state: &PublisherState) -> Result<()> {
    if state.pending.is_empty() {
        println!("no pending viewer requests");
    }
    for pending in &state.pending {
        println!(
            "{}  {:<10}  {:<20}  {}  {}  {}",
            &hex(&pending.request.id()?)[..12],
            if pending.confirmation.is_some() {
                "confirmed"
            } else {
                "waiting"
            },
            pending.request.body.device_label,
            pending.request.body.stream_id,
            pending.source_addr,
            authentication_string(&pending.request, &pending.offer)?,
        );
    }
    Ok(())
}

async fn connect(profile: &Profile) -> Result<(NoiseSocket<TcpStream>, [u8; 32])> {
    let mut stream = tokio::time::timeout(NETWORK_TIMEOUT, TcpStream::connect(&profile.relay))
        .await
        .context("publisher relay connection timed out")??;
    let known_path = profile.state_dir.join("known-relays.bin");
    let expected = profile
        .pin
        .or(KnownRelays::open(&known_path)?.get(&profile.relay)?);
    let (transport, remote) = tokio::time::timeout(
        NETWORK_TIMEOUT,
        initiator_handshake_xx(
            &mut stream,
            &profile.noise.private,
            |actual| match expected {
                Some(expected) if actual != &expected => Err(
                    glacialcast_protocol::ProtocolError::Noise("relay identity changed".into()),
                ),
                _ => Ok(()),
            },
        ),
    )
    .await
    .context("publisher relay handshake timed out")??;
    if profile.pin.is_none() {
        KnownRelays::open(known_path)?.verify_or_learn(&profile.relay, remote)?;
    }
    let mut socket = NoiseSocket::new(stream, transport);
    write_publisher(
        &mut socket,
        &PublisherMessage::Hello(SessionHello {
            protocol_version: PROTOCOL_VERSION,
            role: CredentialRole::Publisher,
            identity: profile.identity.public()?,
            credential: profile.credential.clone(),
        }),
    )
    .await?;
    match read_relay(&mut socket).await? {
        RelayPublisherMessage::Welcome(_) => Ok((socket, remote)),
        RelayPublisherMessage::Error(error) => {
            anyhow::bail!("relay rejected publisher: {}", error.detail)
        }
        _ => anyhow::bail!("relay did not welcome publisher"),
    }
}

async fn expect_pairing_ack(socket: &mut NoiseSocket<TcpStream>, expected: [u8; 32]) -> Result<()> {
    match read_relay(socket).await? {
        RelayPublisherMessage::PairingAck { request_id } if request_id == expected => Ok(()),
        RelayPublisherMessage::Error(error) => {
            anyhow::bail!("relay rejected pairing record: {}", error.detail)
        }
        _ => anyhow::bail!("unexpected pairing acknowledgement"),
    }
}

async fn write_publisher(
    socket: &mut NoiseSocket<TcpStream>,
    message: &PublisherMessage,
) -> Result<()> {
    tokio::time::timeout(NETWORK_TIMEOUT, socket.write(message))
        .await
        .context("publisher relay write timed out")??;
    Ok(())
}

async fn read_relay(socket: &mut NoiseSocket<TcpStream>) -> Result<RelayPublisherMessage> {
    tokio::time::timeout(NETWORK_TIMEOUT, socket.read::<RelayPublisherMessage>())
        .await
        .context("publisher relay response timed out")?
        .map_err(Into::into)
}

fn load_state_unlocked(path: &std::path::Path) -> Result<PublisherState> {
    match read_private(path, MAX_STATE_BYTES) {
        Ok(bytes) => {
            if let Ok((state, remainder)) = postcard::take_from_bytes::<PublisherState>(&bytes)
                && remainder.is_empty()
                && state.version == STATE_VERSION
                && postcard::to_stdvec(&state)? == bytes
            {
                validate_state(&state)?;
                return Ok(state);
            }
            let (state, remainder) = postcard::take_from_bytes::<PublisherStateV2>(&bytes)?;
            if !remainder.is_empty() || state.version != 2 || postcard::to_stdvec(&state)? != bytes
            {
                anyhow::bail!("publisher state is invalid or non-canonical");
            }
            let migrated = PublisherState {
                version: STATE_VERSION,
                pending: state.pending,
                history_outbox: state.approved.clone(),
                approved: state.approved,
                revoked: state.revoked,
                offer_outbox: Vec::new(),
                decision_outbox: Vec::new(),
            };
            validate_state(&migrated)?;
            Ok(migrated)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(PublisherState::default()),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn load_state(path: &std::path::Path) -> Result<PublisherState> {
    let lock_path = path.with_file_name(".publisher-state.lock");
    let _lock = lock_private(&lock_path, PrivateLockMode::Shared)?;
    load_state_unlocked(path)
}

fn save_state_unlocked(path: &std::path::Path, state: &PublisherState) -> Result<()> {
    validate_state(state)?;
    let encoded = postcard::to_stdvec(state)?;
    if encoded.len() > MAX_STATE_BYTES {
        anyhow::bail!("publisher state exceeds its bound");
    }
    replace_private(path, &encoded, MAX_STATE_BYTES)?;
    Ok(())
}

fn validate_state(state: &PublisherState) -> Result<()> {
    const MAX_RECORDS: usize = 65_536;
    if state.pending.len() > MAX_RECORDS
        || state.approved.len() > MAX_RECORDS
        || state.revoked.len() > MAX_RECORDS
        || state.offer_outbox.len() > MAX_RECORDS
        || state.decision_outbox.len() > MAX_RECORDS
        || state.history_outbox.len() > MAX_RECORDS
        || !state.offer_outbox.windows(2).all(|pair| pair[0] < pair[1])
        || !state
            .decision_outbox
            .windows(2)
            .all(|pair| pair[0].body.request_id < pair[1].body.request_id)
        || !state.history_outbox.windows(2).all(|pair| {
            (pair[0].stream_id, pair[0].viewer.id().unwrap_or([0; 32]))
                < (pair[1].stream_id, pair[1].viewer.id().unwrap_or([0; 32]))
        })
        || state.offer_outbox.iter().any(|request_id| {
            !state
                .pending
                .iter()
                .any(|pending| pending.request.id().ok() == Some(*request_id))
        })
    {
        anyhow::bail!("publisher state has invalid bounds, ordering, or outbox references");
    }
    Ok(())
}

fn unique_request(pending: &[PendingPairing], prefix: &str) -> Result<usize> {
    unique_index(
        pending.iter().map(|item| {
            item.request
                .id()
                .map(|id| hex(&id))
                .map_err(anyhow::Error::from)
        }),
        prefix,
    )
}

fn unique_grant(grants: &[StreamGrant], stream_id: Uuid, prefix: &str) -> Result<usize> {
    if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("ID prefix must be hexadecimal");
    }
    let prefix = prefix.to_ascii_lowercase();
    let matches: Vec<usize> = grants
        .iter()
        .enumerate()
        .filter(|(_, grant)| grant.stream_id == stream_id)
        .filter_map(|(index, grant)| {
            grant
                .viewer
                .id()
                .ok()
                .filter(|id| hex(id).starts_with(&prefix))
                .map(|_| index)
        })
        .collect();
    match matches.as_slice() {
        [index] => Ok(*index),
        [] => anyhow::bail!("no matching ID"),
        _ => anyhow::bail!("ID prefix is ambiguous"),
    }
}

pub(super) fn approved_viewers(
    path: &std::path::Path,
    stream_id: Uuid,
) -> Result<Vec<IdentityPublic>> {
    Ok(load_state(path)?
        .approved
        .into_iter()
        .filter(|grant| grant.stream_id == stream_id)
        .map(|grant| grant.viewer)
        .collect())
}

fn unique_index<I>(values: I, prefix: &str) -> Result<usize>
where
    I: IntoIterator<Item = Result<String>>,
{
    if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("ID prefix must be hexadecimal");
    }
    let prefix = prefix.to_ascii_lowercase();
    let matches: Vec<usize> = values
        .into_iter()
        .enumerate()
        .filter_map(|(index, value)| {
            value
                .ok()
                .filter(|value| value.starts_with(&prefix))
                .map(|_| index)
        })
        .collect();
    match matches.as_slice() {
        [index] => Ok(*index),
        [] => anyhow::bail!("no matching ID"),
        _ => anyhow::bail!("ID prefix is ambiguous"),
    }
}

fn normalize_relay(relay: &str) -> String {
    if relay.contains(':') {
        relay.to_string()
    } else {
        format!("{relay}:8900")
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use glacialcast_protocol::private_state::replace_private;

    #[test]
    fn request_prefixes_must_be_unique_and_hexadecimal() {
        let publisher = IdentitySecret::generate();
        let viewer = IdentitySecret::generate();
        let now = glacialcast_protocol::now_ms();
        let request = PairRequest::new(
            &viewer,
            publisher.public().unwrap(),
            Uuid::from_u128(1),
            "device".into(),
            now,
            now + PAIR_LIFETIME_MS,
        )
        .unwrap();
        let offer = PairOffer::new(
            &publisher,
            &request,
            [1; 32],
            now,
            now + PAIR_LIFETIME_MS,
            PAIR_LIFETIME_MS,
        )
        .unwrap();
        let pending = vec![PendingPairing {
            request,
            offer,
            confirmation: None,
            source_addr: "127.0.0.1:1".into(),
        }];
        let id = hex(&pending[0].request.id().unwrap());
        assert_eq!(unique_request(&pending, &id[..12]).unwrap(), 0);
        assert!(unique_request(&pending, "not-hex").is_err());
    }

    #[test]
    fn publisher_config_defaults_to_required_and_trusted_ca_needs_an_authority() {
        let config: PublisherConfig = toml::from_str("").unwrap();
        assert!(matches!(config.viewers.policy, ViewerPolicy::Required));
        assert!(load_policy(ViewerPolicy::Required, config.viewers).is_ok());

        let config: PublisherConfig =
            toml::from_str("[viewers]\npolicy = \"trusted_ca\"\n").unwrap();
        assert!(load_policy(config.viewers.policy, config.viewers).is_err());
        assert!(toml::from_str::<PublisherConfig>("unknown = true").is_err());
    }

    #[test]
    fn approvals_and_permanent_revocations_are_scoped_to_one_stream() {
        let viewer = IdentitySecret::generate().public().unwrap();
        let first = Uuid::from_u128(1);
        let second = Uuid::from_u128(2);
        let mut state = PublisherState::default();
        add_approved(&mut state, first, viewer).unwrap();
        assert_eq!(
            state
                .approved
                .iter()
                .filter(|grant| grant.stream_id == first)
                .count(),
            1
        );
        assert!(state.approved.iter().all(|grant| grant.stream_id != second));

        let viewer_id = viewer.id().unwrap();
        state.approved.clear();
        state.revoked.push(RevokedGrant {
            stream_id: first,
            viewer_id,
        });
        assert!(add_approved(&mut state, first, viewer).is_err());
        add_approved(&mut state, second, viewer).unwrap();
    }

    #[test]
    fn version_two_state_migrates_and_queues_existing_grants_for_history() {
        let root = std::env::temp_dir().join(format!("gcpub-state-v2-{}", Uuid::new_v4()));
        let path = root.join("publisher-state.bin");
        let viewer = IdentitySecret::generate().public().unwrap();
        let old = PublisherStateV2 {
            version: 2,
            pending: Vec::new(),
            approved: vec![StreamGrant {
                stream_id: Uuid::from_u128(1),
                viewer,
            }],
            revoked: Vec::new(),
        };
        replace_private(&path, &postcard::to_stdvec(&old).unwrap(), MAX_STATE_BYTES).unwrap();

        let migrated = load_state(&path).unwrap();
        assert_eq!(migrated.version, STATE_VERSION);
        assert_eq!(migrated.approved.len(), 1);
        assert!(migrated.offer_outbox.is_empty());
        assert!(migrated.decision_outbox.is_empty());
        assert_eq!(migrated.history_outbox.len(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn approval_and_exact_decision_survive_before_relay_acknowledgement() {
        let root = std::env::temp_dir().join(format!("gcpub-state-outbox-{}", Uuid::new_v4()));
        let path = root.join("publisher-state.bin");
        let publisher = IdentitySecret::generate();
        let viewer = IdentitySecret::generate();
        let stream_id = Uuid::from_u128(9);
        let now = glacialcast_protocol::now_ms();
        let request = PairRequest::new(
            &viewer,
            publisher.public().unwrap(),
            stream_id,
            "viewer".into(),
            now,
            now + PAIR_LIFETIME_MS,
        )
        .unwrap();
        let decision = PublisherDecision::approve_by_policy(
            &publisher,
            &request,
            PairDecisionReason::OpenPolicy,
            now,
        )
        .unwrap();
        let mut state = PublisherState::default();
        add_approved(&mut state, stream_id, viewer.public().unwrap()).unwrap();
        queue_decision(&mut state, decision.clone()).unwrap();
        save_state_unlocked(&path, &state).unwrap();

        let recovered = load_state(&path).unwrap();
        assert_eq!(recovered.approved.len(), 1);
        assert_eq!(recovered.decision_outbox, vec![decision]);
        assert_eq!(recovered.history_outbox.len(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }
}
