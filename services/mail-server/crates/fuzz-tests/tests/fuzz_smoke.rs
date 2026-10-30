//! Deterministic fuzz-lite smoke test (T7).
//!
//! The real fuzzing engine is libFuzzer (`crates/fuzz-tests/fuzz`, run by
//! `tools/run_fuzz_nightly.sh`). CI must still PROVE the harness works
//! without paying for a ten-minute-per-target nightly, so this test drives
//! every parser driver over:
//!
//! 1. the committed seed corpus (`fuzz/corpus/<target>/`), and
//! 2. a fixed, seeded pseudo-random input set (the crate's `FUZZ_SEED`
//!    default — fully reproducible, no wall clock, no OS entropy).
//!
//! A panic here is a crash-class finding: the drivers call the SAME
//! production parsers the libFuzzer targets call (`fuzz_tests::fuzz_api`).
//! The nightly script's `--smoke` mode runs exactly this test; the test
//! stage records it as the `fuzz-smoke` lane.

use fuzz_tests::fuzz_api;
use rand::Rng;
use std::path::{Path, PathBuf};

/// Every fuzz target must have a driver in this list; the nightly script
/// cross-checks the `fuzz/fuzz_targets/` directory against these names.
const TARGETS: &[&str] = &[
    "mail_proto",
    "smtp_command",
    "smtp_envelope",
    "mime_message",
    "dkim_signature",
    "spf_record",
    "dmarc_record",
    "webhook_signature",
    "template_source",
    "csv_report",
    "tracking_token",
];

fn corpus_dir(target: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz")
        .join("corpus")
        .join(target)
}

fn drive(target: &str, data: &[u8]) {
    match target {
        "mail_proto" => fuzz_api::mail_proto_decode(data),
        "smtp_command" => fuzz_api::smtp_command_line(&String::from_utf8_lossy(data)),
        "smtp_envelope" => fuzz_api::smtp_envelope_address(&String::from_utf8_lossy(data)),
        "mime_message" => fuzz_api::mime_message(data),
        "dkim_signature" => fuzz_api::dkim_signature(data),
        "spf_record" => fuzz_api::spf_record(data),
        "dmarc_record" => fuzz_api::dmarc_record(data),
        "webhook_signature" => {
            // The first line is the signature header; the rest is the body.
            let split = data
                .iter()
                .position(|byte| *byte == b'\n')
                .unwrap_or(data.len());
            let (header, payload) = data.split_at(split);
            let payload = payload.strip_prefix(b"\n").unwrap_or(payload);
            fuzz_api::webhook_signature(header, payload);
        }
        "template_source" => fuzz_api::template_source(&String::from_utf8_lossy(data)),
        "csv_report" => fuzz_api::csv_report(&String::from_utf8_lossy(data)),
        "tracking_token" => fuzz_api::tracking_token(&String::from_utf8_lossy(data)),
        other => panic!("target {other:?} has no smoke driver"),
    }
}

/// The generated input shapes the nightly fuzzer spends most time mutating
/// around: arbitrary bytes, ASCII, unicode and corpus-derived mutations.
fn generated_inputs(target: &str) -> Vec<Vec<u8>> {
    let mut rng = fuzz_tests::fuzz_rng();
    let mut inputs = Vec::new();
    for index in 0..48 {
        match index % 4 {
            0 => {
                let len = rng.random_range(0..512);
                inputs.push((0..len).map(|_| rng.random::<u8>()).collect());
            }
            1 => {
                let len = rng.random_range(0..512);
                inputs.push((0..len).map(|_| rng.random_range(0x20u8..0x7f)).collect());
            }
            2 => {
                let len = rng.random_range(0..256);
                let text: String = (0..len)
                    .map(|_| loop {
                        let code = rng.random_range(0x20u32..0x10000);
                        if let Some(ch) = char::from_u32(code) {
                            if !ch.is_control() {
                                return ch;
                            }
                        }
                    })
                    .collect();
                inputs.push(text.into_bytes());
            }
            _ => {
                // Mutate a committed corpus seed (the mutation engine's
                // starting point, deterministically).
                let seeds = corpus_seeds(target);
                if seeds.is_empty() {
                    inputs.push(Vec::new());
                } else {
                    let mut seed = seeds[rng.random_range(0..seeds.len())].clone();
                    if !seed.is_empty() {
                        let mutations = rng.random_range(1..5);
                        for _ in 0..mutations {
                            let index = rng.random_range(0..seed.len());
                            seed[index] = rng.random::<u8>();
                        }
                    }
                    inputs.push(seed);
                }
            }
        }
    }
    inputs
}

fn corpus_seeds(target: &str) -> Vec<Vec<u8>> {
    let dir = corpus_dir(target);
    let mut seeds = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        let mut paths: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.is_file())
            .collect();
        paths.sort();
        for path in paths {
            if let Ok(bytes) = std::fs::read(&path) {
                seeds.push(bytes);
            }
        }
    }
    seeds
}

#[test]
fn every_target_has_a_committed_seed_corpus() {
    for target in TARGETS {
        let seeds = corpus_seeds(target);
        assert!(
            !seeds.is_empty(),
            "target {target:?} has no committed corpus under {}",
            corpus_dir(target).display()
        );
    }
}

#[test]
fn fuzz_lite_smoke_survives_committed_corpora_and_fixed_generated_inputs() {
    for target in TARGETS {
        for seed in corpus_seeds(target) {
            drive(target, &seed);
        }
        for input in generated_inputs(target) {
            drive(target, &input);
        }
    }
}
