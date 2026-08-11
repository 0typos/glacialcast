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
    private_state::read_private,
    trust::KnownRelays,
    wire::{PublisherMessage, PublisherResumeStream, RelayPublisherMessage, SessionHello},
};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::{net::TcpStream, sync::watch};
use uuid::Uuid;

const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;
const MEDIA_TIMESCALE: u64 = 90_000;

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
        mode: match args.dash_encoder {
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
    let approved = native_admin::load_state(&state_dir.join("publisher-state.bin"))?.approved;
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
        let starts_group = group.is_none() || frame_index.is_multiple_of(u64::from(group_frames));
        if starts_group {
            group_id = group_id.saturating_add(1);
            group = Some(GroupEncryptor::generate(
                &publisher.public()?,
                stream_id,
                epoch_id,
                group_id,
                sequence,
            )?);
        }
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
                    duration: 0,
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
        frame_index = frame_index.saturating_add(1);
        timestamp = timestamp.saturating_add(u64::from(duration));
        tokio::time::sleep(Duration::from_secs_f64(1.0 / args.fps)).await;
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
}
