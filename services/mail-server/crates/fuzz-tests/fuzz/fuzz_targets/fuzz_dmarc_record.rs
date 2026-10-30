//! Fuzz target: the DMARC TXT-record parser (`mail-auth::dmarc::DmarcRecord`).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_tests::fuzz_api::dmarc_record(data);
});
