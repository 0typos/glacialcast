//! Native Annex-B capture publication with per-viewer key envelopes.

use super::{
    Args, Capture, EncoderActor, EncoderConfig, StreamIdentity, dash_encoder::DashEncoderMode,
    native_admin,
};
use anyhow::{Context, Result};
use glacialcast_protocol::{
    NoiseSocket, PROTOCOL_VERSION,
    credential::{CredentialRole, NativeCredential},
    envelope::KeyEnvelope,
    identity::{IdentitySecret, load_or_create_identity},
    initiator_handshake_xx, load_or_create_noise_keypair,
    native::{
        CodecId, GroupEncryptor, H264EpochPayload, NativeObjectKind, NewNativeObject,
        StreamDescriptor,
    },
    private_state::{read_private, replace_private},
    trust::KnownRelays,
    wire::{PublisherMessage, PublisherResumeStream, RelayPublisherMessage, SessionHello},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path, time::Duration};
use tokio::{net::TcpStream, sync::watch};
use uuid::Uuid;

const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;
const MEDIA_TIMESCALE: u64 = 90_000;
const KEY_HISTORY_VERSION: u16 = 1;
const MAX_KEY_HISTORY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct RetainedGroupKey {
    pub(super) stream_id: Uuid,
    pub(super) epoch_id: Uuid,
    pub(super) key_group_id: u64,
    pub(super) key_id: [u8; 16],
    pub(super) content_key: [u8; 32],
    created_at_ms: i64,
    content_bytes: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct KeyHistory {
    version: u16,
    groups: Vec<RetainedGroupKey>,
}

impl Default for KeyHistory {
    fn default() -> Self {
        Self {
            version: KEY_HISTORY_VERSION,
            groups: Vec::new(),
        }
    }
}

pub(super) fn load_key_history(path: &Path) -> Result<Vec<RetainedGroupKey>> {
    match read_private(path, MAX_KEY_HISTORY_BYTES) {
        Ok(bytes) => {
            let (history, remainder) = postcard::take_from_bytes::<KeyHistory>(&bytes)?;
            if !remainder.is_empty()
                || history.version != KEY_HISTORY_VERSION
                || postcard::to_stdvec(&history)? != bytes
                || history.groups.len() > 65_536
            {
                anyhow::bail!("publisher key history is invalid or non-canonical");
            }
            Ok(history.groups)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error.into()),
    }
}

fn save_key_history(path: &Path, groups: &[RetainedGroupKey]) -> Result<()> {
    let history = KeyHistory {
        version: KEY_HISTORY_VERSION,
        groups: groups.to_vec(),
    };
    let encoded = postcard::to_stdvec(&history)?;
    if encoded.len() > MAX_KEY_HISTORY_BYTES {
        anyhow::bail!("publisher key history exceeds its file bound");
    }
    replace_private(path, &encoded, MAX_KEY_HISTORY_BYTES)?;
    Ok(())
}

fn prune_key_history(
    groups: &mut Vec<RetainedGroupKey>,
    now_ms: i64,
    max_content_bytes: u64,
    max_age_ms: i64,
) {
    groups.retain(|group| now_ms.saturating_sub(group.created_at_ms) <= max_age_ms);
    let mut retained_bytes = 0u64;
    let mut keep_from = groups.len();
    for (index, group) in groups.iter().enumerate().rev() {
        let next = retained_bytes.saturating_add(group.content_bytes);
        if next > max_content_bytes && keep_from < groups.len() {
            break;
        }
        retained_bytes = next;
        keep_from = index;
    }
    if keep_from > 0 {
        groups.drain(..keep_from);
    }
}

pub(super) async fn run_native_client(
    args: &Args,
    stream_identity: StreamIdentity<'_>,
    capture: &mut dyn Capture,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let source = capture.source().await?;
    let state_dir = super::client_state_dir();
    let publisher = load_or_create_identity(&state_dir.join("native-identity.key"))?;
    let noise = load_or_create_noise_keypair(&state_dir.join("native-noise.key"))?;
    let credential = args
        .native_credential
        .as_deref()
        .map(|path| NativeCredential::decode(&read_private(path, MAX_CREDENTIAL_BYTES)?))
        .transpose()?;
    let endpoint = normalize_endpoint(&args.ingest_addr);
    let mut stream = TcpStream::connect(&endpoint).await?;
    let known_path = state_dir.join("known-relays.bin");
    let explicit_pin = stream_identity.client.ingest_server_key;
    let expected = explicit_pin.or(KnownRelays::open(&known_path)?.get(&endpoint)?);
    let (transport, remote) =
        initiator_handshake_xx(&mut stream, &noise.private, |actual| match expected {
            Some(expected) if actual != &expected => Err(
                glacialcast_protocol::ProtocolError::Noise("relay identity changed".into()),
            ),
            _ => Ok(()),
        })
        .await?;
    if explicit_pin.is_none() {
        KnownRelays::open(known_path)?.verify_or_learn(&endpoint, remote)?;
    }
    let mut socket = NoiseSocket::new(stream, transport);
    socket
        .write(&PublisherMessage::Hello(SessionHello {
            protocol_version: PROTOCOL_VERSION,
            role: CredentialRole::Publisher,
            identity: publisher.public()?,
            credential,
        }))
        .await?;
    match socket.read::<RelayPublisherMessage>().await? {
        RelayPublisherMessage::Welcome(_) => {}
        RelayPublisherMessage::Error(error) => {
            anyhow::bail!("relay rejected publisher: {}", error.detail)
        }
        _ => anyhow::bail!("relay did not welcome publisher"),
    }

    let label = stream_identity.label.unwrap_or("default");
    let stream_id = stable_stream_id(&publisher, label)?;
    let epoch_id = Uuid::new_v4();
    socket
        .write(&PublisherMessage::Resume {
            publisher_id: publisher.public()?.id()?,
            streams: vec![PublisherResumeStream {
                stream_id,
                next_sequence: 1,
                epoch_id,
                key_group: 1,
            }],
        })
        .await?;
    let committed = match socket.read::<RelayPublisherMessage>().await? {
        RelayPublisherMessage::ResumeState(states) => {
            states
                .first()
                .filter(|state| state.stream_id == stream_id)
                .context("relay omitted resumed stream")?
                .committed_through
        }
        RelayPublisherMessage::Error(error) => anyhow::bail!("resume rejected: {}", error.detail),
        _ => anyhow::bail!("unexpected resume response"),
    };
    let descriptor = StreamDescriptor::new(
        &publisher,
        stream_id,
        match stream_identity.label {
            Some(label) => format!("{} ({label})", stream_identity.client.display_name),
            None => stream_identity.client.display_name.clone(),
        },
        source.backend,
        true,
        glacialcast_protocol::now_ms(),
    )?;
    socket
        .write(&PublisherMessage::Descriptor(descriptor))
        .await?;

    let first = capture
        .capture_dash_frame(args.max_frame_width, args.max_frame_height)
        .await?
        .frame;
    let width = first.width();
    let height = first.height();
    let group_frames = ((args.fps * 4.0).round() as u64).clamp(1, u64::from(u16::MAX)) as u16;
    let encoder = EncoderActor::spawn(EncoderConfig {
        mode: match args.encoder {
            DashEncoderMode::Vaapi => DashEncoderMode::Openh264,
            mode => mode,
        },
        vaapi_device: args.vaapi_device.clone(),
        openh264_library: args.openh264_library.clone(),
        width,
        height,
        fps: args.fps,
        bitrate: args.video_bitrate,
        segment_frames: group_frames,
    })?;
    let approval_path = state_dir.join("publisher-state.bin");
    let history_path = state_dir.join("key-history.bin");
    let mut approved = native_admin::approved_viewers(&approval_path, stream_id)?;
    let mut key_history = load_key_history(&history_path)?;
    let history_bytes = args
        .history_bytes
        .context("history byte limit was not resolved")?;
    let history_age_ms = i64::try_from(
        args.history_seconds
            .context("history time limit was not resolved")?
            .saturating_mul(1_000),
    )
    .unwrap_or(i64::MAX);
    let duration =
        ((MEDIA_TIMESCALE as f64 / args.fps).round() as u64).clamp(1, u64::from(u32::MAX)) as u32;
    let mut sequence = committed;
    let mut timestamp = 0u64;
    let mut frame_index = 0u64;
    let mut next_frame = Some(first);
    let mut group_id = 0u64;
    let mut group: Option<GroupEncryptor> = None;

    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let latest_approved = native_admin::approved_viewers(&approval_path, stream_id)?;
        let previous_ids: BTreeSet<[u8; 32]> = approved
            .iter()
            .map(IdentityPublicExt::checked_id)
            .collect::<Result<_>>()?;
        let latest_ids: BTreeSet<[u8; 32]> = latest_approved
            .iter()
            .map(IdentityPublicExt::checked_id)
            .collect::<Result<_>>()?;
        let revoked = previous_ids.iter().any(|id| !latest_ids.contains(id));
        let newly_approved: Vec<_> = latest_approved
            .iter()
            .filter(|viewer| viewer.id().is_ok_and(|id| !previous_ids.contains(&id)))
            .copied()
            .collect();
        let starts_group =
            group.is_none() || revoked || frame_index.is_multiple_of(u64::from(group_frames));
        if starts_group {
            group_id = group_id.saturating_add(1);
            let next_group = GroupEncryptor::generate(
                &publisher.public()?,
                stream_id,
                epoch_id,
                group_id,
                sequence,
            )?;
            key_history.push(RetainedGroupKey {
                stream_id,
                epoch_id,
                key_group_id: group_id,
                key_id: next_group.key_id(),
                content_key: next_group.content_key(),
                created_at_ms: glacialcast_protocol::now_ms(),
                content_bytes: 0,
            });
            prune_key_history(
                &mut key_history,
                glacialcast_protocol::now_ms(),
                history_bytes,
                history_age_ms,
            );
            save_key_history(&history_path, &key_history)?;
            group = Some(next_group);
        } else if let Some(current_group) = &group {
            for viewer in &newly_approved {
                socket
                    .write(&PublisherMessage::KeyEnvelope(KeyEnvelope::seal(
                        &publisher,
                        viewer,
                        stream_id,
                        epoch_id,
                        group_id,
                        current_group.key_id(),
                        &current_group.content_key(),
                    )?))
                    .await?;
            }
        }
        approved = latest_approved;
        let frame = match next_frame.take() {
            Some(frame) => frame,
            None => {
                tokio::select! {
                    frame = capture.capture_dash_frame(args.max_frame_width, args.max_frame_height) => frame?.frame,
                    changed = shutdown.changed() => {
                        let _ = changed;
                        return Ok(());
                    }
                }
            }
        };
        let encoded = encoder.encode(frame, starts_group).await?;
        if starts_group && !encoded.keyframe {
            anyhow::bail!("H.264 key group did not begin with an IDR");
        }
        let group = group.as_mut().expect("group created above");
        if starts_group {
            let config = encoded.config.as_ref().context("IDR omitted SPS/PPS")?;
            let mut annex_b_config = Vec::new();
            for parameter_set in [&config.sps, &config.pps] {
                annex_b_config.extend_from_slice(&[0, 0, 0, 1]);
                annex_b_config.extend_from_slice(parameter_set);
            }
            sequence = sequence.saturating_add(1);
            let epoch = group.seal(
                &publisher,
                NewNativeObject {
                    sequence,
                    timestamp,
                    duration: 1,
                    kind: NativeObjectKind::Epoch,
                    random_access: true,
                    codec: Some(CodecId::H264AnnexB),
                },
                &H264EpochPayload {
                    width,
                    height,
                    codec_config: annex_b_config,
                }
                .encode()?,
            )?;
            publish(&mut socket, epoch, sequence).await?;
            for viewer in &approved {
                let envelope = KeyEnvelope::seal(
                    &publisher,
                    viewer,
                    stream_id,
                    epoch_id,
                    group_id,
                    group.key_id(),
                    &group.content_key(),
                )?;
                socket
                    .write(&PublisherMessage::KeyEnvelope(envelope))
                    .await?;
            }
        }
        sequence = sequence.saturating_add(1);
        let media = group.seal(
            &publisher,
            NewNativeObject {
                sequence,
                timestamp,
                duration,
                kind: NativeObjectKind::Media,
                random_access: encoded.keyframe,
                codec: Some(CodecId::H264AnnexB),
            },
            &encoded.annex_b,
        )?;
        publish(&mut socket, media, sequence).await?;
        if let Some(retained) = key_history.last_mut()
            && retained.stream_id == stream_id
            && retained.epoch_id == epoch_id
            && retained.key_group_id == group_id
        {
            retained.content_bytes = retained
                .content_bytes
                .saturating_add(u64::try_from(encoded.annex_b.len()).unwrap_or(u64::MAX));
        }
        prune_key_history(
            &mut key_history,
            glacialcast_protocol::now_ms(),
            history_bytes,
            history_age_ms,
        );
        save_key_history(&history_path, &key_history)?;
        frame_index = frame_index.saturating_add(1);
        timestamp = timestamp.saturating_add(u64::from(duration));
        tokio::time::sleep(Duration::from_secs_f64(1.0 / args.fps)).await;
    }
}

trait IdentityPublicExt {
    fn checked_id(&self) -> Result<[u8; 32]>;
}

impl IdentityPublicExt for glacialcast_protocol::identity::IdentityPublic {
    fn checked_id(&self) -> Result<[u8; 32]> {
        Ok(self.id()?)
    }
}

async fn publish(
    socket: &mut NoiseSocket<TcpStream>,
    object: glacialcast_protocol::native::NativeObject,
    expected: u64,
) -> Result<()> {
    let stream_id = object.header.stream_id;
    socket.write(&PublisherMessage::Object(object)).await?;
    match socket.read::<RelayPublisherMessage>().await? {
        RelayPublisherMessage::PublishAck {
            stream_id: acknowledged,
            committed_through,
        } if acknowledged == stream_id && committed_through == expected => Ok(()),
        RelayPublisherMessage::Error(error) => {
            anyhow::bail!("relay refused object: {}", error.detail)
        }
        _ => anyhow::bail!("unexpected publication acknowledgement"),
    }
}

fn stable_stream_id(publisher: &IdentitySecret, label: &str) -> Result<Uuid> {
    let mut hash = Sha256::new();
    hash.update(b"glacialcast-native-stream-id-v1");
    hash.update(publisher.public()?.id()?);
    hash.update(label.as_bytes());
    let digest: [u8; 32] = hash.finalize().into();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(Uuid::from_bytes(bytes))
}

fn normalize_endpoint(endpoint: &str) -> String {
    if endpoint.contains(':') {
        endpoint.to_string()
    } else {
        format!("{endpoint}:8900")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn stable_stream_ids_are_label_and_publisher_specific() {
        let first = IdentitySecret::generate();
        let second = IdentitySecret::generate();
        assert_eq!(
            stable_stream_id(&first, "one").unwrap(),
            stable_stream_id(&first, "one").unwrap()
        );
        assert_ne!(
            stable_stream_id(&first, "one").unwrap(),
            stable_stream_id(&first, "two").unwrap()
        );
        assert_ne!(
            stable_stream_id(&first, "one").unwrap(),
            stable_stream_id(&second, "one").unwrap()
        );
    }

    #[test]
    fn key_history_is_private_and_prunes_oldest_groups_by_age_and_bytes() {
        const HISTORY_BYTES: u64 = 100 * 1024 * 1024;
        const HISTORY_AGE_MS: i64 = 24 * 60 * 60 * 1_000;
        let root = std::env::temp_dir().join(format!("gcpub-key-history-{}", Uuid::new_v4()));
        let path = root.join("history.bin");
        let now = 2 * HISTORY_AGE_MS;
        let group = |id: u64, created_at_ms: i64, content_bytes: u64| RetainedGroupKey {
            stream_id: Uuid::from_u128(1),
            epoch_id: Uuid::from_u128(2),
            key_group_id: id,
            key_id: [u8::try_from(id).unwrap(); 16],
            content_key: [u8::try_from(id).unwrap(); 32],
            created_at_ms,
            content_bytes,
        };
        let mut groups = vec![
            group(1, 0, 1),
            group(2, now - 1_000, HISTORY_BYTES - 1),
            group(3, now, 1),
        ];
        prune_key_history(&mut groups, now, HISTORY_BYTES, HISTORY_AGE_MS);
        assert_eq!(
            groups
                .iter()
                .map(|group| group.key_group_id)
                .collect::<Vec<_>>(),
            [2, 3]
        );
        save_key_history(&path, &groups).unwrap();
        assert_eq!(load_key_history(&path).unwrap().len(), 2);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_key_history(&path).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
