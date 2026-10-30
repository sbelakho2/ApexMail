//! Fuzz target: the SPF TXT-record parser (`mail-auth::spf::SpfRecord`).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_tests::fuzz_api::spf_record(data);
});
