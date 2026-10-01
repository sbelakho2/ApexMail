//! Fuzz target: the IMAP response parser (imap-proto-patched).
//!
//! Surface: `imap_proto::parse_response` — the parser that consumes
//! attacker-influenced bytes from remote mail servers.

#![no_main]

use imap_proto::parse_response;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Ok and Err are both legitimate outcomes; a panic, hang, or
    // out-of-bounds access here is the bug libFuzzer is hunting.
    if let Ok((rest, _response)) = parse_response(data) {
        // Oracle: a successful parse MUST have consumed at least one byte.
        // An Ok that consumed nothing would loop forever in any caller
        // that advances past the parsed prefix.
        assert!(
            rest.len() < data.len(),
            "parser reported Ok but consumed nothing (input len {})",
            data.len()
        );
    }
});
