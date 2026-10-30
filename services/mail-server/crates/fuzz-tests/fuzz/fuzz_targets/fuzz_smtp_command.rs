//! Fuzz target: the mta SMTP command-line tokenizer (`split_verb`, the
//! splitter the submission and inbound servers run on every command line).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_tests::fuzz_api::smtp_command_line(&String::from_utf8_lossy(data));
});
