#![no_main]

use glacialcast_protocol::DashObject;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(object) = DashObject::from_portable_bytes(data) {
        object
            .validate()
            .expect("portable parser returned an invalid object");
        let encoded = object
            .to_portable_bytes()
            .expect("re-encoding parsed object");
        let reparsed = DashObject::from_portable_bytes(&encoded).expect("reparsing encoded object");
        assert_eq!(reparsed, object);
    }
});
