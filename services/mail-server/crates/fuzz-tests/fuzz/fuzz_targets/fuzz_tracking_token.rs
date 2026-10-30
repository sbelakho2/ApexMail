//! Fuzz target: the tracking-token decoder + unsubscribe verifier
//! (`tracking-service::codec::TrackingCodec`).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_tests::fuzz_api::tracking_token(&String::from_utf8_lossy(data));
});
