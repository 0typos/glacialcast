//! Publisher-side durable viewer approval administration.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use glacialcast_protocol::{
    NoiseKeypair, NoiseSocket, PROTOCOL_VERSION,
    credential::{CredentialRole, NativeCredential},
    identity::{IdentityPublic, IdentitySecret, load_or_create_identity},
    initiator_handshake_xx, load_or_create_noise_keypair,
    pairing::{
        PairDecisionReason, PairOffer, PairRequest, PublisherDecision, ViewerConfirmation,
        authentication_string,
    },
    private_state::{read_private, replace_private},
    trust::KnownRelays,
    wire::{PublisherMessage, RelayPublisherMessage, SessionHello},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::PathBuf};
use tokio::net::TcpStream;

const STATE_VERSION: u16 = 1;
const MAX_STATE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;
const PAIR_LIFETIME_MS: i64 = 24 * 60 * 60 * 1_000;

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
    /// Viewer approval policy. `trusted-ca` is reserved until viewer credentials enter pairing requests.
    #[arg(long, value_enum, default_value_t)]
    policy: ViewerPolicy,
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
    Revoke { viewer: String },
    /// List approved and revoked viewer identities.
    Viewers,
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
    pub(super) approved: Vec<IdentityPublic>,
    revoked: Vec<[u8; 32]>,
}

impl Default for PublisherState {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            pending: Vec::new(),
            approved: Vec::new(),
            revoked: Vec::new(),
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

pub(super) fn is_admin_command() -> bool {
    std::env::args().skip(1).any(|argument| {
        matches!(
            argument.as_str(),
            "requests" | "approve" | "approve-all" | "deny" | "revoke" | "viewers"
        )
    })
}

pub(super) fn run() -> Result<()> {
    let args = AdminArgs::parse();
    let state_dir = args.state_dir.unwrap_or_else(super::client_state_dir);
    std::fs::create_dir_all(&state_dir)?;
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
    runtime.block_on(execute(profile, args.policy, args.command))
}

async fn execute(profile: Profile, policy: ViewerPolicy, command: AdminCommand) -> Result<()> {
    let state_path = profile.state_dir.join("publisher-state.bin");
    let mut state = load_state(&state_path)?;
    if !matches!(command, AdminCommand::Viewers | AdminCommand::Revoke { .. }) {
        refresh_requests(&profile, &mut state, policy).await?;
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
        AdminCommand::Revoke { viewer } => {
            let index = unique_identity(&state.approved, &viewer)?;
            let removed = state.approved.remove(index);
            let viewer_id = removed.id()?;
            if !state.revoked.contains(&viewer_id) {
                state.revoked.push(viewer_id);
                state.revoked.sort_unstable();
            }
            println!(
                "revoked {}; active publication must rotate its group immediately",
                hex(&viewer_id)
            );
        }
        AdminCommand::Viewers => {
            for viewer in &state.approved {
                println!("approved {}", hex(&viewer.id()?));
            }
            for viewer in &state.revoked {
                println!("revoked  {}", hex(viewer));
            }
        }
    }
    save_state(&state_path, &state)
}

async fn refresh_requests(
    profile: &Profile,
    state: &mut PublisherState,
    policy: ViewerPolicy,
) -> Result<()> {
    if matches!(policy, ViewerPolicy::TrustedCa) {
        anyhow::bail!(
            "trusted-ca policy requires viewer credentials in pairing requests and is not enabled yet"
        );
    }
    let (mut socket, relay_key) = connect(profile).await?;
    socket.write(&PublisherMessage::FetchPairingInbox).await?;
    let mut requests = Vec::new();
    let mut confirmations = Vec::new();
    loop {
        match socket.read::<RelayPublisherMessage>().await? {
            RelayPublisherMessage::PairRequest {
                request,
                source_addr,
                ..
            } => {
                requests.push((request, source_addr.to_string()));
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
    let revoked: BTreeSet<[u8; 32]> = state.revoked.iter().copied().collect();
    for (request, source_addr) in requests {
        request.verify(glacialcast_protocol::now_ms(), PAIR_LIFETIME_MS)?;
        let request_id = request.id()?;
        if revoked.contains(&request.body.viewer.id()?) {
            continue;
        }
        if state
            .pending
            .iter()
            .any(|pending| pending.request.id().ok() == Some(request_id))
        {
            continue;
        }
        if matches!(policy, ViewerPolicy::Open) {
            let decision = PublisherDecision::approve_by_policy(
                &profile.identity,
                &request,
                PairDecisionReason::OpenPolicy,
                glacialcast_protocol::now_ms(),
            )?;
            socket
                .write(&PublisherMessage::PairDecision(decision))
                .await?;
            expect_pairing_ack(&mut socket, request_id).await?;
            add_approved(state, request.body.viewer)?;
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
        socket
            .write(&PublisherMessage::PairOffer(offer.clone()))
            .await?;
        expect_pairing_ack(&mut socket, request_id).await?;
        state.pending.push(PendingPairing {
            request,
            offer,
            confirmation: None,
            source_addr,
        });
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
    let request_id = pending.request.id()?;
    let (mut socket, _) = connect(profile).await?;
    socket
        .write(&PublisherMessage::PairDecision(decision))
        .await?;
    expect_pairing_ack(&mut socket, request_id).await?;
    if approve {
        add_approved(state, pending.request.body.viewer)?;
        println!("approved {}", hex(&pending.request.body.viewer.id()?));
    } else {
        println!("denied {}", hex(&request_id));
    }
    state.pending.remove(index);
    Ok(())
}

fn add_approved(state: &mut PublisherState, viewer: IdentityPublic) -> Result<()> {
    let id = viewer.id()?;
    if state.revoked.binary_search(&id).is_ok() {
        anyhow::bail!("viewer is permanently revoked");
    }
    if !state
        .approved
        .iter()
        .any(|approved| approved.id().ok() == Some(id))
    {
        state.approved.push(viewer);
        state
            .approved
            .sort_by_key(|approved| approved.id().unwrap_or([0; 32]));
    }
    Ok(())
}

fn print_requests(state: &PublisherState) -> Result<()> {
    if state.pending.is_empty() {
        println!("no pending viewer requests");
    }
    for pending in &state.pending {
        println!(
            "{}  {:<10}  {:<20}  {}  {}",
            &hex(&pending.request.id()?)[..12],
            if pending.confirmation.is_some() {
                "confirmed"
            } else {
                "waiting"
            },
            pending.request.body.device_label,
            pending.source_addr,
            authentication_string(&pending.request, &pending.offer)?,
        );
    }
    Ok(())
}

async fn connect(profile: &Profile) -> Result<(NoiseSocket<TcpStream>, [u8; 32])> {
    let mut stream = TcpStream::connect(&profile.relay).await?;
    let known_path = profile.state_dir.join("known-relays.bin");
    let expected = profile
        .pin
        .or(KnownRelays::open(&known_path)?.get(&profile.relay)?);
    let (transport, remote) = initiator_handshake_xx(
        &mut stream,
        &profile.noise.private,
        |actual| match expected {
            Some(expected) if actual != &expected => Err(
                glacialcast_protocol::ProtocolError::Noise("relay identity changed".into()),
            ),
            _ => Ok(()),
        },
    )
    .await?;
    if profile.pin.is_none() {
        KnownRelays::open(known_path)?.verify_or_learn(&profile.relay, remote)?;
    }
    let mut socket = NoiseSocket::new(stream, transport);
    socket
        .write(&PublisherMessage::Hello(SessionHello {
            protocol_version: PROTOCOL_VERSION,
            role: CredentialRole::Publisher,
            identity: profile.identity.public()?,
            credential: profile.credential.clone(),
        }))
        .await?;
    match socket.read::<RelayPublisherMessage>().await? {
        RelayPublisherMessage::Welcome(_) => Ok((socket, remote)),
        RelayPublisherMessage::Error(error) => {
            anyhow::bail!("relay rejected publisher: {}", error.detail)
        }
        _ => anyhow::bail!("relay did not welcome publisher"),
    }
}

async fn expect_pairing_ack(socket: &mut NoiseSocket<TcpStream>, expected: [u8; 32]) -> Result<()> {
    match socket.read::<RelayPublisherMessage>().await? {
        RelayPublisherMessage::PairingAck { request_id } if request_id == expected => Ok(()),
        RelayPublisherMessage::Error(error) => {
            anyhow::bail!("relay rejected pairing record: {}", error.detail)
        }
        _ => anyhow::bail!("unexpected pairing acknowledgement"),
    }
}

pub(super) fn load_state(path: &std::path::Path) -> Result<PublisherState> {
    match read_private(path, MAX_STATE_BYTES) {
        Ok(bytes) => {
            let (state, remainder) = postcard::take_from_bytes::<PublisherState>(&bytes)?;
            if !remainder.is_empty()
                || state.version != STATE_VERSION
                || postcard::to_stdvec(&state)? != bytes
            {
                anyhow::bail!("publisher state is invalid or non-canonical");
            }
            Ok(state)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(PublisherState::default()),
        Err(error) => Err(error.into()),
    }
}

fn save_state(path: &std::path::Path, state: &PublisherState) -> Result<()> {
    let encoded = postcard::to_stdvec(state)?;
    if encoded.len() > MAX_STATE_BYTES {
        anyhow::bail!("publisher state exceeds its bound");
    }
    replace_private(path, &encoded, MAX_STATE_BYTES)?;
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

fn unique_identity(identities: &[IdentityPublic], prefix: &str) -> Result<usize> {
    unique_index(
        identities.iter().map(|identity| {
            identity
                .id()
                .map(|id| hex(&id))
                .map_err(anyhow::Error::from)
        }),
        prefix,
    )
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

    #[test]
    fn request_prefixes_must_be_unique_and_hexadecimal() {
        let publisher = IdentitySecret::generate();
        let viewer = IdentitySecret::generate();
        let now = glacialcast_protocol::now_ms();
        let request = PairRequest::new(
            &viewer,
            publisher.public().unwrap(),
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
}
