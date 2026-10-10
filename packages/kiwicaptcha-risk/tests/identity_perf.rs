//! The measured cost budget of the full identity-vector computation
//! (change.md 2 / 3.1.1): one derivation of all seven dimensions must
//! stay under 20 µs. Prebuilt inputs, `Instant`, no criterion.
//!
//! The asserted bound follows the PerfBenchTest convention: an
//! optimized build (the deployed artifact) asserts the spec budget
//! itself, while the unoptimized dev build the plain `cargo test` lane
//! runs asserts a 10x CI-safe margin and prints the measured figure,
//! because the sha2 block function dominates the timing when compiled
//! without optimization. Both numbers print; the honest budget number
//! is the optimized one.

use std::net::IpAddr;
use std::time::Instant;

use kiwicaptcha_risk::asn::AsnDataset;
use kiwicaptcha_risk::identity::RiskIdentityFactory;
use kiwicaptcha_risk::identity_vector::{IdentityVector, IdentityVectorInput};
use kiwicaptcha_risk::keys::RiskKeys;

/// The budget change.md states for one identity computation.
const BUDGET_US: f64 = 20.0;
/// The dev-build margin (10x), mirroring PerfBenchTest's CI-safe bound.
const DEBUG_BUDGET_US: f64 = 200.0;
const ITERATIONS: usize = 10_000;

fn dataset() -> AsnDataset {
    AsnDataset::open(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/asn/sample-asn.tsv"),
    )
    .expect("sample dataset opens")
}

#[test]
fn full_seven_dimension_derivation_stays_under_the_budget() {
    let dataset = dataset();
    let factory = RiskIdentityFactory::new(RiskKeys::from_master(&[0x42; 32]));
    let cookie = [0x5au8; 16];
    let descriptor = IdentityVectorInput {
        client_ip: "203.0.113.27".parse::<IpAddr>().unwrap(),
        session_cookie: Some(&cookie),
        principal_id: Some(b"principal-42"),
        agent_key_id: Some("agent-key-7"),
        target_normalized: Some("user@example.com"),
        asn_dataset: &dataset,
        now_unix_secs: 1_700_000_000,
    };

    // Warm-up: the first derivation pays page faults and code paths
    // once, so the budget measures the steady-state request cost.
    for _ in 0..200 {
        let _ = IdentityVector::derive(&descriptor, &factory);
    }
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let vector = IdentityVector::derive(&descriptor, &factory);
        std::hint::black_box(&vector);
    }
    let mean_us = start.elapsed().as_secs_f64() * 1_000_000.0 / ITERATIONS as f64;
    let budget = if cfg!(debug_assertions) {
        DEBUG_BUDGET_US
    } else {
        BUDGET_US
    };
    eprintln!(
        "identity perf ({}): {} full seven-dimension derivations, mean {mean_us:.3} µs each (spec budget {BUDGET_US} µs, asserted {budget} µs in this profile)",
        if cfg!(debug_assertions) { "dev profile" } else { "optimized profile" },
        ITERATIONS,
    );
    assert!(
        mean_us < budget,
        "mean {mean_us:.3} µs per derivation exceeds the {budget} µs bound of this profile (spec budget {BUDGET_US} µs)"
    );
}
