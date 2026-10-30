//! Fuzz target: the DKIM-Signature header parser (`mail-auth`), the parser
//! the mta authenticator runs on untrusted message headers.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_tests::fuzz_api::dkim_signature(data);
});
