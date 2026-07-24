#![no_main]

use glacialcast_protocol::parse_noise_segment;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(segment) = parse_noise_segment(data) {
        assert!(segment.offset <= segment.total_len);
        assert!(segment.offset.saturating_add(segment.chunk.len()) <= segment.total_len);
    }
});
