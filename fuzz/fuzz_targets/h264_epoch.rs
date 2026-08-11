#![no_main]

use glacialcast_protocol::native::H264EpochPayload;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(epoch) = H264EpochPayload::decode(data) {
        let encoded = epoch.encode().expect("re-encoding H.264 epoch");
        let reparsed = H264EpochPayload::decode(&encoded).expect("reparsing H.264 epoch");
        assert_eq!(reparsed, epoch);
    }
});
