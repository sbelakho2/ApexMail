//! Fixed-point risk scoring, byte-identical with the cross-language
//! contract:
//!
//! `weighted(v, w) = (v * w) / 1000` (integer division, saturating product)
//!
//! `score(base, s, w) = base + Σ weighted(positive signals) - weighted(trust)
//! - weighted(principal)`, clamped to [0, 1000] with saturating arithmetic.

use serde::{Deserialize, Serialize};

use crate::policy::RiskReason;
use crate::signals::SignalVector;

/// 13 weight fields, same names/order as [`SignalVector`].
///
/// `Default` is the contract default (identical to `fixtures.json`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RiskWeights {
    pub source_fast: u16,
    pub source_slow: u16,
    pub subnet_fast: u16,
    pub issue_debt: u16,
    pub bad_proof: u16,
    pub malformed: u16,
    pub replay: u16,
    pub action_failure: u16,
    pub scope_switch: u16,
    pub global_pressure: u16,
    pub network_risk: u16,
    pub trust_credit: u16,
    pub principal_credit: u16,
}

impl Default for RiskWeights {
    fn default() -> RiskWeights {
        RiskWeights {
            source_fast: 190,
            source_slow: 110,
            subnet_fast: 80,
            issue_debt: 150,
            bad_proof: 220,
            malformed: 260,
            replay: 320,
            action_failure: 120,
            scope_switch: 60,
            global_pressure: 170,
            network_risk: 100,
            trust_credit: 130,
            principal_credit: 100,
        }
    }
}

/// `(v * w) / 1000` with a saturating product (values are 0..1000 so the
/// product always fits u32).
pub fn weighted(value: u16, weight: u16) -> u32 {
    (value as u32).saturating_mul(weight as u32) / 1000
}

/// Contract scoring: base + the 11 positive signals in SignalVector order,
/// minus trust and principal credit, clamped to 0..=1000.
pub fn score(base: u16, s: &SignalVector, w: &RiskWeights) -> u16 {
    let mut risk = base as i32;
    risk += weighted(s.source_fast, w.source_fast) as i32;
    risk += weighted(s.source_slow, w.source_slow) as i32;
    risk += weighted(s.subnet_fast, w.subnet_fast) as i32;
    risk += weighted(s.issue_debt, w.issue_debt) as i32;
    risk += weighted(s.bad_proof, w.bad_proof) as i32;
    risk += weighted(s.malformed, w.malformed) as i32;
    risk += weighted(s.replay, w.replay) as i32;
    risk += weighted(s.action_failure, w.action_failure) as i32;
    risk += weighted(s.scope_switch, w.scope_switch) as i32;
    risk += weighted(s.global_pressure, w.global_pressure) as i32;
    risk += weighted(s.network_risk, w.network_risk) as i32;
    risk -= weighted(s.trust_credit, w.trust_credit) as i32;
    risk -= weighted(s.principal_credit, w.principal_credit) as i32;
    risk.clamp(0, 1000) as u16
}

/// The 11 positive signals in SignalVector order with their per-signal
/// contributions `(v * w) / 1000` (integer); only strictly positive
/// contributions are recorded. The `RiskReason` codes are in contract
/// order: SourceBurst, SourceSustained, NetworkBurst, ChallengeDebt,
/// InvalidProofs, MalformedTraffic, ReplayTraffic, ActionFailures,
/// ScopeHopping, GlobalAttack, LocalNetworkRisk.
pub fn contributors(s: &SignalVector, w: &RiskWeights) -> Vec<(RiskReason, u32)> {
    let mut out = Vec::with_capacity(11);
    let mut push = |reason: RiskReason, value: u16, weight: u16| {
        let contribution = weighted(value, weight);
        if contribution > 0 {
            out.push((reason, contribution));
        }
    };
    push(RiskReason::SourceBurst, s.source_fast, w.source_fast);
    push(RiskReason::SourceSustained, s.source_slow, w.source_slow);
    push(RiskReason::NetworkBurst, s.subnet_fast, w.subnet_fast);
    push(RiskReason::ChallengeDebt, s.issue_debt, w.issue_debt);
    push(RiskReason::InvalidProofs, s.bad_proof, w.bad_proof);
    push(RiskReason::MalformedTraffic, s.malformed, w.malformed);
    push(RiskReason::ReplayTraffic, s.replay, w.replay);
    push(
        RiskReason::ActionFailures,
        s.action_failure,
        w.action_failure,
    );
    push(RiskReason::ScopeHopping, s.scope_switch, w.scope_switch);
    push(
        RiskReason::GlobalAttack,
        s.global_pressure,
        w.global_pressure,
    );
    push(RiskReason::LocalNetworkRisk, s.network_risk, w.network_risk);
    out
}

/// The top-4 contributor reasons: sorted by contribution descending (ties
/// keep SignalVector order), capped at 4. This NEVER changes the score —
/// it only explains it.
pub fn top_contributor_reasons(s: &SignalVector, w: &RiskWeights) -> Vec<RiskReason> {
    let mut contributions = contributors(s, w);
    contributions.sort_by_key(|(_, contribution)| std::cmp::Reverse(*contribution));
    contributions.truncate(4);
    contributions
        .into_iter()
        .map(|(reason, _)| reason)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    const FIXTURES_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/risk-v1/fixtures.json"
    );
    const TEN_K_HASH: &str = "f711eac8057f8c142a4f4e63c33fabe4cfe6de62b1d0bd4deb9f21883eddb8ac";

    /// Deterministic LCG vector generator for the 10k parity anchor and the
    /// monotonicity property tests:
    ///
    /// `x_{n+1} = (x_n * 6364136223846793005 + 1442695040888963407) mod 2^64`
    /// seed 42; `value = (x >> 11) % 1001`.
    ///
    /// This MUST produce the same stream as the PHP/Python reference
    /// implementations (verified anchor: first value 291).
    struct SeededVector {
        x: u64,
    }

    impl SeededVector {
        fn new() -> SeededVector {
            SeededVector { x: 42 }
        }

        fn next(&mut self) -> u16 {
            self.x = self
                .x
                .wrapping_mul(6364136223846793005u64)
                .wrapping_add(1442695040888963407u64);
            ((self.x >> 11) % 1001) as u16
        }

        fn vector(&mut self) -> SignalVector {
            SignalVector {
                source_fast: self.next(),
                source_slow: self.next(),
                subnet_fast: self.next(),
                issue_debt: self.next(),
                bad_proof: self.next(),
                malformed: self.next(),
                replay: self.next(),
                action_failure: self.next(),
                scope_switch: self.next(),
                global_pressure: self.next(),
                network_risk: self.next(),
                trust_credit: self.next(),
                principal_credit: self.next(),
            }
        }
    }

    fn load_fixtures() -> serde_json::Value {
        let raw = std::fs::read_to_string(FIXTURES_PATH)
            .unwrap_or_else(|e| panic!("cannot read {FIXTURES_PATH}: {e}"));
        serde_json::from_str(&raw).expect("fixtures.json must be valid JSON")
    }

    #[test]
    fn fixtures_parity() {
        let fixtures = load_fixtures();
        let weights = RiskWeights::default();
        let cases = fixtures["fixtures"]
            .as_array()
            .expect("fixtures array")
            .clone();
        assert!(!cases.is_empty(), "fixtures must not be empty");
        for case in &cases {
            let signals: SignalVector = serde_json::from_value(case["signals"].clone())
                .expect("signals must deserialize into SignalVector");
            let expected: u16 = case["expected_score"].as_u64().expect("expected_score") as u16;
            let actual = score(100, &signals, &weights);
            assert_eq!(actual, expected, "fixture score mismatch for {case:?}");
        }
    }

    #[test]
    fn ten_thousand_vector_parity_anchor() {
        let weights = RiskWeights::default();
        let mut prng = SeededVector::new();
        let mut blob = Vec::with_capacity(20_000);
        for _ in 0..10_000 {
            let vector = prng.vector();
            blob.extend_from_slice(&score(100, &vector, &weights).to_be_bytes());
        }
        assert_eq!(blob.len(), 20_000);
        let digest = Sha256::digest(&blob);
        assert_eq!(hex::encode(digest), TEN_K_HASH);
    }

    #[test]
    fn seeded_prng_first_value() {
        let mut prng = SeededVector::new();
        assert_eq!(prng.next(), 291);
    }

    /// (getter, setter) pairs for a signal field.
    type FieldAccessors = (fn(&SignalVector) -> u16, fn(&mut SignalVector, u16));

    /// (getter, setter) pairs for the 11 positive signal fields, in contract
    /// order.
    fn positive_fields() -> Vec<FieldAccessors> {
        vec![
            (|s| s.source_fast, |s, v| s.source_fast = v),
            (|s| s.source_slow, |s, v| s.source_slow = v),
            (|s| s.subnet_fast, |s, v| s.subnet_fast = v),
            (|s| s.issue_debt, |s, v| s.issue_debt = v),
            (|s| s.bad_proof, |s, v| s.bad_proof = v),
            (|s| s.malformed, |s, v| s.malformed = v),
            (|s| s.replay, |s, v| s.replay = v),
            (|s| s.action_failure, |s, v| s.action_failure = v),
            (|s| s.scope_switch, |s, v| s.scope_switch = v),
            (|s| s.global_pressure, |s, v| s.global_pressure = v),
            (|s| s.network_risk, |s, v| s.network_risk = v),
        ]
    }

    #[test]
    fn raising_positive_signal_never_lowers_score() {
        let weights = RiskWeights::default();
        let mut prng = SeededVector::new();
        for _ in 0..500 {
            let base = prng.vector();
            let base_score = score(100, &base, &weights);
            for (get, set) in positive_fields() {
                let mut raised = base;
                let value = get(&raised).saturating_add(1).min(1000);
                set(&mut raised, value);
                let raised_score = score(100, &raised, &weights);
                assert!(
                    raised_score >= base_score,
                    "raising a positive signal lowered the score from {base_score} to {raised_score}"
                );
            }
        }
    }

    #[test]
    fn raising_credit_never_raises_score() {
        let weights = RiskWeights::default();
        let mut prng = SeededVector::new();
        let credit_fields: [FieldAccessors; 2] = [
            (
                |s: &SignalVector| s.trust_credit,
                |s: &mut SignalVector, v| s.trust_credit = v,
            ),
            (
                |s: &SignalVector| s.principal_credit,
                |s: &mut SignalVector, v| s.principal_credit = v,
            ),
        ];
        for _ in 0..500 {
            let base = prng.vector();
            let base_score = score(100, &base, &weights);
            for (get, set) in credit_fields {
                let mut raised = base;
                let value = get(&raised).saturating_add(1).min(1000);
                set(&mut raised, value);
                let raised_score = score(100, &raised, &weights);
                assert!(
                    raised_score <= base_score,
                    "raising credit raised the score from {base_score} to {raised_score}"
                );
            }
        }
    }

    #[test]
    fn scores_stay_in_range() {
        let weights = RiskWeights::default();
        let mut prng = SeededVector::new();
        for _ in 0..10_000 {
            let s = score(100, &prng.vector(), &weights);
            assert!(s <= 1000);
        }
    }

    #[test]
    fn weighted_is_integer_division() {
        assert_eq!(weighted(1, 1), 0);
        assert_eq!(weighted(500, 500), 250);
        assert_eq!(weighted(1000, 1000), 1000);
        let w = RiskWeights::default();
        let v = SignalVector {
            source_fast: 500,
            ..Default::default()
        };
        // 100 + intdiv(500*190, 1000) = 100 + 95 = 195
        assert_eq!(score(100, &v, &w), 195);
        let v = SignalVector {
            source_fast: 1,
            ..Default::default()
        };
        assert_eq!(score(100, &v, &w), 100);
    }

    #[test]
    fn score_clamps() {
        let w = RiskWeights::default();
        let all_max = SignalVector {
            source_fast: 1000,
            source_slow: 1000,
            subnet_fast: 1000,
            issue_debt: 1000,
            bad_proof: 1000,
            malformed: 1000,
            replay: 1000,
            action_failure: 1000,
            scope_switch: 1000,
            global_pressure: 1000,
            network_risk: 1000,
            trust_credit: 1000,
            principal_credit: 1000,
        };
        assert_eq!(score(100, &all_max, &w), 1000);
        let trust_only = SignalVector {
            trust_credit: 1000,
            ..Default::default()
        };
        assert_eq!(score(100, &trust_only, &w), 0);
    }

    #[test]
    fn contributor_reasons_order_and_sort() {
        let w = RiskWeights::default();
        // Only two signals contribute; contributions differ.
        let s = SignalVector {
            source_fast: 500, // 500*190/1000 = 95
            replay: 300,      // 300*320/1000 = 96
            ..Default::default()
        };
        let top = top_contributor_reasons(&s, &w);
        assert_eq!(
            top,
            vec![RiskReason::ReplayTraffic, RiskReason::SourceBurst]
        );

        // Ties keep SignalVector order: scope_switch 1000 -> 60 and
        // network_risk 600 -> 60 contribute equally; scope_switch (earlier
        // in SignalVector order) must sort first.
        let s = SignalVector {
            scope_switch: 1000, // 60
            network_risk: 600,  // 60
            source_fast: 1000,  // 190
            ..Default::default()
        };
        let top = top_contributor_reasons(&s, &w);
        assert_eq!(
            top,
            vec![
                RiskReason::SourceBurst,
                RiskReason::ScopeHopping,
                RiskReason::LocalNetworkRisk,
            ]
        );

        // Zero vector: no contributors.
        assert!(contributors(&SignalVector::zero(), &w).is_empty());
        assert!(top_contributor_reasons(&SignalVector::zero(), &w).is_empty());
    }

    #[test]
    fn contributor_reasons_never_change_the_score() {
        let w = RiskWeights::default();
        let mut prng = SeededVector::new();
        for _ in 0..500 {
            let vector = prng.vector();
            let before = score(100, &vector, &w);
            let _ = top_contributor_reasons(&vector, &w);
            assert_eq!(score(100, &vector, &w), before);
        }
    }
}
