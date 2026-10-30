//! Fuzz target: webhook HMAC verification (billing-service
//! `stripe_events::verify_signature`, the Stripe-Signature parser).
//!
//! Input: the first line is the signature header, the rest the payload.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let split = data
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(data.len());
    let (header, payload) = data.split_at(split);
    let payload = payload.strip_prefix(b"\n").unwrap_or(payload);
    fuzz_tests::fuzz_api::webhook_signature(header, payload);
});
