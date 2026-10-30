//! Fuzz target: the template parser/validator (`template-renderer`).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_tests::fuzz_api::template_source(&String::from_utf8_lossy(data));
});
