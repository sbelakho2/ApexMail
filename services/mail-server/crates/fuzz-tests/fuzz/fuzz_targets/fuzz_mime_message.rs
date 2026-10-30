//! Fuzz target: MIME/header parsing through `mail-parser`, the parser the
//! mta submission path runs over every submitted message.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_tests::fuzz_api::mime_message(data);
});
