#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    glacialcast_protocol::transfer::fuzz_transfer_index(data);
});
