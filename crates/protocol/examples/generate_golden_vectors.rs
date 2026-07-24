use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use glacialcast_dash::{DASH_FORMAT_VERSION, EpochKeys};
use glacialcast_protocol::{DashObject, DashObjectKind, NewDashObject, PROTOCOL_VERSION};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let viewer_key = std::array::from_fn::<_, 32, _>(|index| index as u8);
    let stream_id = Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef")?;
    let epoch_id = Uuid::parse_str("fedcba98-7654-3210-fedc-ba9876543210")?;
    let keys = EpochKeys::derive(&viewer_key, stream_id, epoch_id)?;
    let object = DashObject::authenticated(
        NewDashObject {
            stream_id,
            epoch_id,
            kind: DashObjectKind::Media,
            sequence: 42,
            segment_number: 7,
            chunk_index: 2,
            timestamp: 1_234_567,
            duration: 90_000,
            random_access: false,
            mime: "video/iso.segment",
            payload: vec![0, 1, 2, 3, 252, 253, 254, 255],
        },
        &keys,
    )?;
    let portable = object.to_portable_bytes()?;
    let vector = json!({
        "schema": "glacialcast-protocol-golden-v1",
        "protocol_version": PROTOCOL_VERSION,
        "dash_format_version": DASH_FORMAT_VERSION,
        "viewer_key_b64": URL_SAFE_NO_PAD.encode(viewer_key),
        "stream_id": stream_id,
        "epoch_id": epoch_id,
        "key_id_b64": keys.key_id_b64(),
        "cenc_key_b64": keys.cenc_key_b64(),
        "cursor_key_b64": URL_SAFE_NO_PAD.encode(keys.cursor_key),
        "authentication_key_b64": URL_SAFE_NO_PAD.encode(keys.authentication_key),
        "portable_object_b64": URL_SAFE_NO_PAD.encode(&portable),
        "portable_object_sha256_b64": URL_SAFE_NO_PAD.encode(Sha256::digest(&portable)),
    });
    println!("{}", serde_json::to_string_pretty(&vector)?);
    Ok(())
}
