//! The `HKDF` derivation-cache counting test — a dedicated test binary on
//! purpose: the counting seam
//! (`kiwicaptcha::keys::from_master_call_count`) is PROCESS-global, and
//! the main lib test binary runs issuance/verification tests in parallel
//! threads that each derive `HKDF` keys, polluting any exact-count window.
//! In this binary the counting test is the only test, so the counts are
//! exact: from_master runs once per key id per verifier, and never again
//! for the verifier's lifetime.
//!
//! The store side runs against the hermetic fake endpoint from
//! `tests/common` (no real Redis needed): a full `verify()` drives the
//! cheap phase twice per verification (the peek plus the post-consume
//! re-check), each hitting the v2 signature check AND the IP-binding
//! re-derivation — four `HKDF` derivations per verification without the
//! cache, zero with it (after the once-per-kid map build).

#![cfg(feature = "redis")]

mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use common::FakeEndpoint;
use kiwicaptcha::challenge::{issue_challenge, BindingMode, ChallengeConfig, PoWAlgorithm};
use kiwicaptcha::keys;
use kiwicaptcha::redis_verify::{ProductionVerifier, RedisChallengeStore};
use kiwicaptcha::token::SolutionToken;
use kiwicaptcha::verify::{solve_for_test, RequestBindingExpectation, VerifyOutcome};

const SECRET: &str = "0123456789abcdef0123456789abcdef";
const SECRET_2: &str = "fedcba9876543210fedcba9876543210";
const IP: &str = "198.51.100.7";

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64
}

fn sha_config(secret: &str, kid: u32) -> ChallengeConfig {
    ChallengeConfig {
        secret_key: secret.into(),
        kid,
        algorithm: PoWAlgorithm::Sha256,
        m_kib: 0,
        t: 1,
        p: 1,
        target_bits: 4,
        argon2_target_bits: 4,
        ttl_secs: 120,
        min_duration_ms: None,
        auto_tune: false,
        auto_tune_min_bits: 8,
        auto_tune_max_bits: 20,
        binding_mode: BindingMode::Bound,
        region: None,
        issuer: None,
        policy_version: 1,
    }
}

fn encode_token(nonce: &str, counter: u64) -> String {
    SolutionToken {
        nonce: nonce.into(),
        counter,
        duration_ms: 5000,
        telemetry: serde_json::json!({}),
    }
    .encode()
}

#[test]
fn from_master_runs_once_per_kid_per_verifier_process() {
    let (url, endpoint) = FakeEndpoint::spawn();
    let prefix = "kiwitest:hkdf-cache:".to_string();
    let store = RedisChallengeStore::new(redis::Client::open(url).unwrap(), prefix.clone());
    let verifier = ProductionVerifier::new(store, SECRET)
        .with_secrets_by_kid([(1u32, SECRET.to_string()), (2u32, SECRET_2.to_string())]);

    // Issuance (outside every measured window): each issue derives once
    // for the challenge signature plus once for the nonce-bound binding
    // tag — the pre-cache behavior of the pure helper functions, which
    // stay available and unchanged for direct callers.
    let issued_1 = issue_challenge(
        &sha_config(SECRET, 1),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let issued_2 = issue_challenge(
        &sha_config(SECRET_2, 2),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let counter_1 = solve_for_test(&issued_1.record).expect("4-bit sha solves");
    let counter_2 = solve_for_test(&issued_2.record).expect("4-bit sha solves");
    endpoint.seed(&prefix, &issued_1.record);
    endpoint.seed(&prefix, &issued_2.record);

    // First verification under kid 1: the verifier builds its full
    // per-kid derived-keys map (one derivation per configured kid — 2),
    // then the whole verification (cheap phase × 2: peek + post-consume
    // re-check; signature + IP binding each) runs on the cache.
    let before = keys::from_master_call_count();
    assert!(matches!(
        verifier.verify(
            &encode_token(&issued_1.record.nonce, counter_1),
            "login",
            IP,
            issued_1.record.issued_at_ns + 1_000_000,
            None,
            RequestBindingExpectation::Unenforced,
        ),
        VerifyOutcome::Valid { .. }
    ));
    assert_eq!(
        keys::from_master_call_count() - before,
        2,
        "the first verification derives exactly once per configured kid (the full map), nothing more — without the cache this one verification alone would derive 4 times"
    );

    // Every later verification — the second kid AND repeats of the first
    // — derives nothing: the per-kid map is cached for the verifier's
    // lifetime (each verification would derive 4 times without the
    // cache).
    let before_more = keys::from_master_call_count();
    for (issued, counter) in [
        (&issued_2, counter_2),
        (&issued_1, counter_1),
        (&issued_2, counter_2),
    ] {
        // The records were consumed by their first verification; re-seed
        // so each repeat is a fresh pending record.
        endpoint.seed(&prefix, &issued.record);
        assert!(matches!(
            verifier.verify(
                &encode_token(&issued.record.nonce, counter),
                "login",
                IP,
                issued.record.issued_at_ns + 1_000_000,
                None,
                RequestBindingExpectation::Unenforced,
            ),
            VerifyOutcome::Valid { .. }
        ));
    }
    assert_eq!(
        keys::from_master_call_count() - before_more,
        0,
        "three further full verifications (two kids, repeats included) must derive NOTHING — 12 derivations without the cache"
    );
}
