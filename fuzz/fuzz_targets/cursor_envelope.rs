#![no_main]

use glacialcast_dash::EncryptedCursorBatch;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = EncryptedCursorBatch::from_bytes(data) {
        let encoded = envelope
            .to_bytes()
            .expect("re-encoding parsed cursor envelope");
        let reparsed =
            EncryptedCursorBatch::from_bytes(&encoded).expect("reparsing cursor envelope");
        assert_eq!(reparsed, envelope);
    }
});
