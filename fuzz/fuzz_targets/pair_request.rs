#![no_main]

use glacialcast_protocol::pairing::PairRequest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = PairRequest::decode(data) {
        let encoded = request.encode().expect("re-encoding pairing request");
        let reparsed = PairRequest::decode(&encoded).expect("reparsing pairing request");
        assert_eq!(reparsed, request);
    }
});
