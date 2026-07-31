use glacialcast_dash::{
    CursorBatch, CursorBitmap, CursorContext, CursorEvent, EpochKeys, FragmentInput,
    build_encrypted_fragment, decrypt_cursor_batch, encrypt_cursor_batch,
};
use glacialcast_protocol::{DashObject, DashObjectKind, NewDashObject};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};
use uuid::Uuid;

const MIB: f64 = 1024.0 * 1024.0;

fn measure(iterations: usize, mut operation: impl FnMut()) -> Duration {
    for _ in 0..iterations.min(5) {
        operation();
    }
    let started = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    started.elapsed()
}

fn throughput_mib_s(bytes_per_iteration: usize, iterations: usize, elapsed: Duration) -> f64 {
    bytes_per_iteration as f64 * iterations as f64 / MIB / elapsed.as_secs_f64()
}

fn require_throughput(name: &str, actual: f64, minimum: f64) {
    assert!(
        actual >= minimum,
        "{name} throughput {actual:.2} MiB/s is below the {minimum:.2} MiB/s floor"
    );
}

fn cursor_probe(keys: &EpochKeys, stream_id: Uuid, epoch_id: Uuid) -> f64 {
    let bitmap_bytes = 64 * 64 * 4;
    let mut events = Vec::with_capacity(30);
    for index in 0..30 {
        events.push(CursorEvent {
            timestamp: 100 + index,
            x_micropixels: i64::try_from(index).unwrap_or(0) * 1_000_000,
            y_micropixels: i64::try_from(index).unwrap_or(0) * 500_000,
            visible: true,
            bitmap_id: 1,
            bitmap: (index == 0).then(|| CursorBitmap {
                width: 64,
                height: 64,
                hotspot_x: 4,
                hotspot_y: 4,
                rgba: vec![0x7f; bitmap_bytes],
            }),
        });
    }
    let batch = CursorBatch {
        source_width: 1920,
        source_height: 1080,
        events,
    };
    let context = CursorContext {
        stream_id,
        epoch_id,
        sequence: 1,
        start_timestamp: 100,
        source_width: 1920,
        source_height: 1080,
    };
    let iterations = 2_000;
    let elapsed = measure(iterations, || {
        let encrypted = encrypt_cursor_batch(keys, context, black_box(&batch)).unwrap();
        let decoded = decrypt_cursor_batch(keys, context, black_box(&encrypted)).unwrap();
        black_box(decoded);
    });
    throughput_mib_s(bitmap_bytes, iterations, elapsed)
}

fn fragment_probe(keys: &EpochKeys) -> f64 {
    let payload_len = 256 * 1024;
    let mut access_unit = vec![0; payload_len];
    access_unit[..5].copy_from_slice(&[0, 0, 0, 1, 0x65]);
    for (index, byte) in access_unit[5..].iter_mut().enumerate() {
        *byte = u8::try_from(index % 256).unwrap_or(0);
    }
    let iterations = 500;
    let elapsed = measure(iterations, || {
        let fragment = build_encrypted_fragment(
            &keys.cenc_key,
            FragmentInput {
                sequence: 1,
                decode_time: 0,
                duration: 90_000,
                keyframe: true,
                annex_b: black_box(&access_unit),
                iv: [3; 16],
            },
        )
        .unwrap();
        black_box(fragment);
    });
    throughput_mib_s(payload_len, iterations, elapsed)
}

fn portable_probe(keys: &EpochKeys, stream_id: Uuid, epoch_id: Uuid) -> f64 {
    let payload_len = 256 * 1024;
    let payload = vec![0x5a; payload_len];
    let iterations = 500;
    let elapsed = measure(iterations, || {
        let object = DashObject::authenticated(
            NewDashObject {
                stream_id,
                epoch_id,
                kind: DashObjectKind::Media,
                sequence: 1,
                segment_number: 1,
                chunk_index: 0,
                timestamp: 0,
                duration: 90_000,
                random_access: true,
                mime: "video/iso.segment",
                payload: black_box(payload.clone()),
            },
            keys,
        )
        .unwrap();
        let encoded = object.to_portable_bytes().unwrap();
        let decoded = DashObject::from_portable_bytes(black_box(&encoded)).unwrap();
        decoded.verify_authentication(keys).unwrap();
        black_box(decoded);
    });
    throughput_mib_s(payload_len, iterations, elapsed)
}

fn main() {
    let stream_id = Uuid::from_u128(1);
    let epoch_id = Uuid::from_u128(2);
    let keys = EpochKeys::derive(&[7; 32], stream_id, epoch_id).unwrap();

    let cursor = cursor_probe(&keys, stream_id, epoch_id);
    let fragment = fragment_probe(&keys);
    let portable = portable_probe(&keys, stream_id, epoch_id);

    // These intentionally conservative floors catch pathological regressions while
    // remaining stable on slower CI hosts. GlacialCast's target rates are far lower.
    require_throughput("cursor round trip", cursor, 5.0);
    require_throughput("CENC fragment generation", fragment, 10.0);
    require_throughput("portable object round trip", portable, 10.0);

    println!("cursor_round_trip_mib_s={cursor:.2}");
    println!("cenc_fragment_mib_s={fragment:.2}");
    println!("portable_round_trip_mib_s={portable:.2}");
}
