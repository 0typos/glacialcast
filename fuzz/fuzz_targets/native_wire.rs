#![no_main]

use glacialcast_protocol::wire::{
    PublisherMessage, RelayPublisherMessage, RelayViewerMessage, ViewerMessage,
    decode_native_message, encode_native_message,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    macro_rules! round_trip {
        ($message:ty) => {
            if let Ok(message) = decode_native_message::<$message>(data) {
                let encoded = encode_native_message(&message).expect("re-encoding native message");
                let reparsed = decode_native_message::<$message>(&encoded)
                    .expect("reparsing canonical native message");
                assert_eq!(reparsed, message);
            }
        };
    }
    round_trip!(PublisherMessage);
    round_trip!(RelayPublisherMessage);
    round_trip!(ViewerMessage);
    round_trip!(RelayViewerMessage);
});
