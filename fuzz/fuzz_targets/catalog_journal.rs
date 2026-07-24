#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    glacialcast_server::fuzz_catalog_journal_record(data);
});
