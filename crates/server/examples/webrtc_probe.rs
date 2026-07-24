use anyhow::{Context, Result, bail};
use bytes::Bytes;
use glacialcast_protocol::{
    h264_access_unit_has_idr, h264_access_unit_has_parameter_sets, h264_access_unit_nal_types,
};
use rtp::{codecs::h264::H264Packet, packetizer::Depacketizer};
use serde::{Deserialize, Serialize};
use std::{env, sync::Arc, time::Duration};
use tokio::sync::mpsc;
use webrtc::{
    api::{APIBuilder, media_engine::MediaEngine},
    peer_connection::{
        configuration::RTCConfiguration, sdp::session_description::RTCSessionDescription,
    },
    rtp_transceiver::rtp_codec::RTPCodecType,
};

#[derive(Debug, Serialize)]
struct WebRtcOffer {
    sdp: String,
}

#[derive(Debug, Deserialize)]
struct WebRtcAnswer {
    sdp: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let control_addr = args
        .next()
        .context("usage: webrtc_probe <control_addr> <stream_id> [timeout_seconds]")?;
    let stream_id = args
        .next()
        .context("usage: webrtc_probe <control_addr> <stream_id> [timeout_seconds]")?;
    let timeout = args
        .next()
        .as_deref()
        .unwrap_or("10")
        .parse::<u64>()
        .context("timeout_seconds must be an integer")?;

    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let api = APIBuilder::new().with_media_engine(media_engine).build();
    let peer = Arc::new(api.new_peer_connection(RTCConfiguration::default()).await?);
    peer.add_transceiver_from_kind(RTPCodecType::Video, None)
        .await?;

    let (packet_tx, mut packet_rx) = mpsc::channel::<RtpProbePacket>(64);
    peer.on_track(Box::new(move |track, _, _| {
        let packet_tx = packet_tx.clone();
        Box::pin(async move {
            if !track
                .codec()
                .capability
                .mime_type
                .eq_ignore_ascii_case("video/h264")
            {
                return;
            }
            while let Ok((packet, _)) = track.read_rtp().await {
                let _ = packet_tx
                    .send(RtpProbePacket {
                        timestamp: packet.header.timestamp,
                        marker: packet.header.marker,
                        payload: packet.payload,
                    })
                    .await;
            }
        })
    }));

    let offer = peer.create_offer(None).await?;
    peer.set_local_description(offer).await?;
    let mut gather_complete = peer.gathering_complete_promise().await;
    let _ = gather_complete.recv().await;
    let local = peer
        .local_description()
        .await
        .context("WebRTC local description was not set")?;

    let client = reqwest::Client::new();
    let answer = client
        .post(format!(
            "http://{control_addr}/api/streams/{stream_id}/webrtc/offer"
        ))
        .json(&WebRtcOffer { sdp: local.sdp })
        .send()
        .await?
        .error_for_status()?
        .json::<WebRtcAnswer>()
        .await?;
    peer.set_remote_description(RTCSessionDescription::answer(answer.sdp)?)
        .await?;

    let deadline = tokio::time::sleep(Duration::from_secs(timeout));
    tokio::pin!(deadline);
    let mut packets = 0usize;
    let mut bytes = 0usize;
    let mut access_units = 0usize;
    let mut depacketizer = H264Packet::default();
    let mut current_timestamp = None;
    let mut current_access_unit = Vec::new();
    loop {
        tokio::select! {
            Some(packet) = packet_rx.recv() => {
                packets += 1;
                bytes += packet.payload.len();
                if h264_rtp_payload_has_annexb_start_code(&packet.payload) {
                    peer.close().await?;
                    bail!("WebRTC received malformed H.264 RTP payload containing Annex-B start codes");
                }

                if current_timestamp.is_some_and(|timestamp| timestamp != packet.timestamp) && !current_access_unit.is_empty() {
                    current_access_unit.clear();
                }
                current_timestamp = Some(packet.timestamp);

                let depacketized = depacketizer
                    .depacketize(&packet.payload)
                    .context("depacketizing H.264 RTP payload")?;
                current_access_unit.extend_from_slice(&depacketized);

                if packet.marker {
                    access_units += 1;
                    if h264_access_unit_has_idr(&current_access_unit) {
                        let nal_types = h264_access_unit_nal_types(&current_access_unit);
                        if !h264_access_unit_has_parameter_sets(&current_access_unit) {
                            peer.close().await?;
                            bail!("WebRTC received an IDR access unit without SPS/PPS headers; nal_types={nal_types:?}");
                        }
                        peer.close().await?;
                        println!(
                            "PASS: WebRTC viewer received decodable H.264 random access point after {packets} RTP packets ({bytes} payload bytes, {access_units} access units, nal_types={nal_types:?})"
                        );
                        return Ok(());
                    }
                    current_access_unit.clear();
                }
            }
            _ = &mut deadline => {
                let _ = peer.close().await;
                bail!("timed out waiting for WebRTC decodable H.264 random access point; received {packets} packets ({bytes} payload bytes, {access_units} complete access units)");
            }
        }
    }
}

struct RtpProbePacket {
    timestamp: u32,
    marker: bool,
    payload: Bytes,
}

fn h264_rtp_payload_has_annexb_start_code(payload: &[u8]) -> bool {
    payload.starts_with(&[0, 0, 1]) || payload.starts_with(&[0, 0, 0, 1])
}
