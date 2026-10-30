//! Fuzz target: the mta SMTP envelope-address extractor (`extract_addr_safe`,
//! the `MAIL FROM:` / `RCPT TO:` address grammar).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_tests::fuzz_api::smtp_envelope_address(&String::from_utf8_lossy(data));
});
