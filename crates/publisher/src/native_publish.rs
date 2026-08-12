//! Native Annex-B capture publication with per-viewer key envelopes.

use super::{Args, Capture, EncoderActor, EncoderConfig, StreamIdentity, native_admin};
use anyhow::{Context, Result};
use glacialcast_protocol::{
    NoiseSocket, PROTOCOL_VERSION,
    credential::{CredentialRole, NativeCredential},
    cursor::{CursorBatch, CursorContext, encode_cursor_batch},
    envelope::KeyEnvelope,
    identity::{IdentitySecret, load_or_create_identity},
    initiator_handshake_xx, load_or_create_noise_keypair,
    native::{
        CodecId, GroupEncryptor, H264EpochPayload, NativeObjectKind, NewNativeObject,
        StreamDescriptor,
    },
    private_state::{PrivateLockMode, lock_private, read_private, replace_private},
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
const NETWORK_TIMEOUT: Duration = Duration::from_secs(15);

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

impl RetainedGroupKey {
    /// True once at least one acknowledged ciphertext byte exists under this
    /// group, which is what makes an envelope for it worth sending: the relay
    /// refuses envelopes for groups it holds no ciphertext for.
    pub(super) fn has_published_content(&self) -> bool {
        self.content_bytes > 0
    }
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

fn history_lock_path(path: &Path) -> Result<std::path::PathBuf> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("key history path has no UTF-8 file name")?;
    Ok(path.with_file_name(format!(".{name}.lock")))
}

fn load_key_history_unlocked(path: &Path) -> Result<Vec<RetainedGroupKey>> {
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

pub(super) fn load_key_history(path: &Path) -> Result<Vec<RetainedGroupKey>> {
    let lock_path = history_lock_path(path)?;
    let _lock = lock_private(&lock_path, PrivateLockMode::Shared)?;
    load_key_history_unlocked(path)
}

fn save_key_history_unlocked(path: &Path, groups: &[RetainedGroupKey]) -> Result<()> {
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

fn replace_stream_key_history(
    path: &Path,
    stream_id: Uuid,
    stream_groups: &[RetainedGroupKey],
) -> Result<()> {
    let lock_path = history_lock_path(path)?;
    let _lock = lock_private(&lock_path, PrivateLockMode::Exclusive)?;
    let mut groups = load_key_history_unlocked(path)?;
    groups.retain(|group| group.stream_id != stream_id);
    groups.extend_from_slice(stream_groups);
    groups.sort_by_key(|group| {
        (
            group.stream_id,
            group.created_at_ms,
            group.epoch_id,
            group.key_group_id,
        )
    });
    save_key_history_unlocked(path, &groups)
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
    let mut stream = tokio::time::timeout(NETWORK_TIMEOUT, TcpStream::connect(&endpoint))
        .await
        .context("publisher relay connection timed out")??;
    let known_path = state_dir.join("known-relays.bin");
    let explicit_pin = stream_identity.client.ingest_server_key;
    let expected = explicit_pin.or(KnownRelays::open(&known_path)?.get(&endpoint)?);
    let (transport, remote) = tokio::time::timeout(
        NETWORK_TIMEOUT,
        initiator_handshake_xx(&mut stream, &noise.private, |actual| match expected {
            Some(expected) if actual != &expected => Err(
                glacialcast_protocol::ProtocolError::Noise("relay identity changed".into()),
            ),
            _ => Ok(()),
        }),
    )
    .await
    .context("publisher relay handshake timed out")??;
    if explicit_pin.is_none() {
        KnownRelays::open(known_path)?.verify_or_learn(&endpoint, remote)?;
    }
    let mut socket = NoiseSocket::new(stream, transport);
    write_publisher(
        &mut socket,
        &PublisherMessage::Hello(SessionHello {
            protocol_version: PROTOCOL_VERSION,
            role: CredentialRole::Publisher,
            identity: publisher.public()?,
            credential,
        }),
    )
    .await?;
    match read_relay(&mut socket).await? {
        RelayPublisherMessage::Welcome(_) => {}
        RelayPublisherMessage::Error(error) => {
            anyhow::bail!("relay rejected publisher: {}", error.detail)
        }
        _ => anyhow::bail!("relay did not welcome publisher"),
    }

    let label = stream_identity.label.unwrap_or("default");
    let stream_id = stable_stream_id(&publisher, label)?;
    let epoch_id = Uuid::new_v4();
    write_publisher(
        &mut socket,
        &PublisherMessage::Resume {
            publisher_id: publisher.public()?.id()?,
            streams: vec![PublisherResumeStream {
                stream_id,
                next_sequence: 1,
                epoch_id,
                key_group: 1,
            }],
        },
    )
    .await?;
    let committed = match read_relay(&mut socket).await? {
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
    write_publisher(&mut socket, &PublisherMessage::Descriptor(descriptor)).await?;

    let first = capture
        .capture_frame(args.max_frame_width, args.max_frame_height)
        .await?
        .frame;
    let width = first.width();
    let height = first.height();
    let group_frames = ((args.fps * 4.0).round() as u64).clamp(1, u64::from(u16::MAX)) as u16;
    let encoder = EncoderActor::spawn(EncoderConfig {
        mode: args.encoder,
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
    let mut key_history: Vec<_> = load_key_history(&history_path)?
        .into_iter()
        .filter(|group| group.stream_id == stream_id)
        .collect();
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
    let mut cursor_bitmap_state = super::CursorBitmapState::default();

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
            group = Some(next_group);
        } else if let Some(current_group) = &group {
            for viewer in &newly_approved {
                write_publisher(
                    &mut socket,
                    &PublisherMessage::KeyEnvelope(KeyEnvelope::seal(
                        &publisher,
                        viewer,
                        stream_id,
                        epoch_id,
                        group_id,
                        current_group.key_id(),
                        &current_group.content_key(),
                    )?),
                )
                .await?;
            }
        }
        approved = latest_approved;
        let frame = match next_frame.take() {
            Some(frame) => frame,
            None => {
                tokio::select! {
                    frame = capture.capture_frame(args.max_frame_width, args.max_frame_height) => frame?.frame,
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
            key_history.push(RetainedGroupKey {
                stream_id,
                epoch_id,
                key_group_id: group_id,
                key_id: group.key_id(),
                content_key: group.content_key(),
                created_at_ms: glacialcast_protocol::now_ms(),
                content_bytes: 0,
            });
            prune_key_history(
                &mut key_history,
                glacialcast_protocol::now_ms(),
                history_bytes,
                history_age_ms,
            );
            replace_stream_key_history(&history_path, stream_id, &key_history)?;
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
                write_publisher(&mut socket, &PublisherMessage::KeyEnvelope(envelope)).await?;
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
        let mut content_bytes = u64::try_from(encoded.annex_b.len()).unwrap_or(u64::MAX);
        if let Some(cursor) = capture.cursor(frame_index).await? {
            let cursor_event =
                super::cursor_to_event(cursor, timestamp, width, height, &mut cursor_bitmap_state)?;
            let cursor_sequence = sequence
                .checked_add(1)
                .context("native cursor sequence space exhausted")?;
            let cursor_payload = encode_cursor_batch(
                CursorContext {
                    stream_id,
                    epoch_id,
                    sequence: cursor_sequence,
                    start_timestamp: timestamp,
                    source_width: width,
                    source_height: height,
                },
                &CursorBatch {
                    source_width: width,
                    source_height: height,
                    events: vec![cursor_event],
                },
            )?;
            content_bytes = content_bytes
                .saturating_add(u64::try_from(cursor_payload.len()).unwrap_or(u64::MAX));
            sequence = cursor_sequence;
            let cursor_object = group.seal(
                &publisher,
                NewNativeObject {
                    sequence,
                    timestamp,
                    duration: 1,
                    kind: NativeObjectKind::Cursor,
                    random_access: false,
                    codec: None,
                },
                &cursor_payload,
            )?;
            publish(&mut socket, cursor_object, sequence).await?;
        }
        if let Some(retained) = key_history.last_mut()
            && retained.stream_id == stream_id
            && retained.epoch_id == epoch_id
            && retained.key_group_id == group_id
        {
            retained.content_bytes = retained.content_bytes.saturating_add(content_bytes);
        }
        prune_key_history(
            &mut key_history,
            glacialcast_protocol::now_ms(),
            history_bytes,
            history_age_ms,
        );
        replace_stream_key_history(&history_path, stream_id, &key_history)?;
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
    write_publisher(socket, &PublisherMessage::Object(object)).await?;
    match read_relay(socket).await? {
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
        save_key_history_unlocked(&path, &groups).unwrap();
        assert_eq!(load_key_history(&path).unwrap().len(), 2);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_key_history(&path).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stream_history_updates_preserve_other_monitor_groups() {
        const HISTORY_BYTES: u64 = 10;
        let root = std::env::temp_dir().join(format!("gcpub-key-merge-{}", Uuid::new_v4()));
        let path = root.join("history.bin");
        let first_stream = Uuid::from_u128(1);
        let second_stream = Uuid::from_u128(2);
        let group = |stream_id, key_group_id| RetainedGroupKey {
            stream_id,
            epoch_id: Uuid::from_u128(u128::from(key_group_id)),
            key_group_id,
            key_id: [u8::try_from(key_group_id).unwrap(); 16],
            content_key: [u8::try_from(key_group_id).unwrap(); 32],
            created_at_ms: i64::try_from(key_group_id).unwrap(),
            content_bytes: HISTORY_BYTES,
        };

        replace_stream_key_history(&path, first_stream, &[group(first_stream, 1)]).unwrap();
        replace_stream_key_history(&path, second_stream, &[group(second_stream, 2)]).unwrap();
        replace_stream_key_history(&path, first_stream, &[group(first_stream, 3)]).unwrap();

        let groups = load_key_history(&path).unwrap();
        assert_eq!(groups.len(), 2);
        assert!(groups.iter().any(|group| group.stream_id == second_stream));
        assert!(groups.iter().any(|group| group.key_group_id == 3));
        assert!(!groups.iter().any(|group| group.key_group_id == 1));
        std::fs::remove_dir_all(root).unwrap();
    }
}
