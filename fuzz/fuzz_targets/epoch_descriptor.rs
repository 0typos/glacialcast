#![no_main]

use glacialcast_stream::EpochDescriptor;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(descriptor) = EpochDescriptor::from_json(data) {
        let encoded = descriptor
            .to_json()
            .expect("re-encoding parsed epoch descriptor");
        let reparsed = EpochDescriptor::from_json(&encoded).expect("reparsing epoch descriptor");
        assert_eq!(reparsed, descriptor);
    }
});
