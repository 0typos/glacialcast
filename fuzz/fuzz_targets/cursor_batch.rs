#![no_main]

use glacialcast_protocol::cursor::{CursorContext, decode_cursor_batch};
use libfuzzer_sys::fuzz_target;
use uuid::Uuid;

fuzz_target!(|data: &[u8]| {
    let context = CursorContext {
        stream_id: Uuid::from_u128(1),
        epoch_id: Uuid::from_u128(2),
        sequence: 1,
        start_timestamp: 0,
        source_width: 1920,
        source_height: 1080,
    };
    let _ = decode_cursor_batch(context, data);
});
