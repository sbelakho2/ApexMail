//! Deterministic fuzz/property tests (seeded LCG, no external harness):
//! 10,000 random JSON observations must decode and score in 0..=1000,
//! a stronger malicious signal must never lower the score, added trust
//! must never raise it, and `ChallengeProfile::validate` must never panic
//! on arbitrary inputs.

mod common;

use kiwicaptcha::challenge::PoWAlgorithm;
use kiwicaptcha_risk::profile::ChallengeProfile;
use kiwicaptcha_risk::score::{score, RiskWeights};
use kiwicaptcha_risk::signals::SignalVector;
use serde_json::json;

const ITERATIONS: usize = 10_000;

/// One random observation-shaped JSON object: the 13 signal fields plus
/// observation-ish keys (serde ignores the extras).
fn json_vector(state: &mut u64) -> serde_json::Value {
    json!({
        "event": 1,
        "scope": 1,
        "now_ms": 0,
        "source_fast": common::lcg_next(state),
        "source_slow": common::lcg_next(state),
        "subnet_fast": common::lcg_next(state),
        "issue_debt": common::lcg_next(state),
        "bad_proof": common::lcg_next(state),
        "malformed": common::lcg_next(state),
        "replay": common::lcg_next(state),
        "action_failure": common::lcg_next(state),
        "scope_switch": common::lcg_next(state),
        "global_pressure": common::lcg_next(state),
        "network_risk": common::lcg_next(state),
        "trust_credit": common::lcg_next(state),
        "principal_credit": common::lcg_next(state),
    })
}

#[test]
fn ten_thousand_random_observations_decode_and_score_in_range() {
    let weights = RiskWeights::default();
    let mut state = 42u64;
    for i in 0..ITERATIONS {
        let vector: SignalVector = serde_json::from_value(json_vector(&mut state))
            .unwrap_or_else(|e| panic!("iteration {i}: decode failed: {e}"));
        let value = score(100, &vector, &weights);
        assert!(
            value <= 1000,
            "iteration {i}: score {value} escaped the 0..=1000 contract range"
        );
    }
}

#[test]
fn stronger_malicious_signal_never_lowers_score() {
    let weights = RiskWeights::default();
    let mut state = 42u64;
    for i in 0..ITERATIONS {
        let base = json_vector(&mut state);
        let mut hot = base.clone();
        hot["replay"] = json!(1000);
        let base_v: SignalVector = serde_json::from_value(base).expect("decodes");
        let hot_v: SignalVector = serde_json::from_value(hot).expect("decodes");
        let base_score = score(100, &base_v, &weights);
        let hot_score = score(100, &hot_v, &weights);
        assert!(
            hot_score >= base_score,
            "iteration {i}: replay=1000 lowered the score from {base_score} to {hot_score}"
        );
    }
}

#[test]
fn added_trust_never_raises_score() {
    let weights = RiskWeights::default();
    let mut state = 42u64;
    for i in 0..ITERATIONS {
        let base = json_vector(&mut state);
        let mut trusted = base.clone();
        trusted["trust_credit"] = json!(1000);
        let base_v: SignalVector = serde_json::from_value(base).expect("decodes");
        let trusted_v: SignalVector = serde_json::from_value(trusted).expect("decodes");
        let base_score = score(100, &base_v, &weights);
        let trusted_score = score(100, &trusted_v, &weights);
        assert!(
            trusted_score <= base_score,
            "iteration {i}: trust=1000 raised the score from {base_score} to {trusted_score}"
        );
    }
}

#[test]
fn challenge_profile_validate_never_panics_on_random_params() {
    let mut state = 42u64;
    for _ in 0..ITERATIONS {
        let algorithm = if common::lcg_next(&mut state).is_multiple_of(2) {
            PoWAlgorithm::Sha256
        } else {
            PoWAlgorithm::Argon2id
        };
        let profile = ChallengeProfile {
            algorithm,
            target_bits: (common::lcg_next(&mut state) % 40) as u8,
            m_kib: (common::lcg_next(&mut state) as u32) * 700,
            t: (common::lcg_next(&mut state) % 12) as u32,
            p: (common::lcg_next(&mut state) % 4) as u32,
        };
        // Must either validate or reject — never panic.
        let _ = profile.validate();
    }
}
