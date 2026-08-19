//! Fixed-point risk scoring, byte-identical with the cross-language
//! contract:
//!
//! `weighted(v, w) = (v * w) / 1000` (integer division, saturating product)
//!
//! `score(base, s, w) = base + Σ weighted(positive signals) - weighted(trust)
//! - weighted(principal)`, clamped to [0, 1000] with saturating arithmetic.
//!
//! The SCORE is pure integer math (u16/u32/i32): NaN/Inf cannot enter, and
//! the output is always a bounded u16 in 0..=1000. The only floats in the
//! risk path live in the calibration boundary, which is guarded separately
//! (calibration.lua + `bounded_bias`).

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

/// The 3 ADDITIVE risk-v2 weight fields, same names/order as
/// [`crate::signals::RiskV2Signals`].
///
/// The risk-v1 contract weights ([`RiskWeights`]) are untouched — these are
/// a separate, additive surface with identical fixed-point semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RiskV2Weights {
    /// Weight of the honeypot/decoy evidence signal (default 200: one hit
    /// raises the aggregate meaningfully without hard-denying alone).
    pub honeypot: u16,
    /// Weight of the session client-context inconsistency signal (default
    /// 120: a changed context tag raises the aggregate, a consistent or
    /// absent tag is neutral).
    pub session_inconsistency: u16,
    /// Weight of the trusted-edge TLS inconsistency signal (default 80: a
    /// changed TLS classification tag raises the aggregate, a consistent or
    /// absent tag is neutral).
    pub tls: u16,
}

impl Default for RiskV2Weights {
    fn default() -> RiskV2Weights {
        RiskV2Weights {
            honeypot: 200,
            session_inconsistency: 120,
            tls: 80,
        }
    }
}

/// Risk-v2 scoring: the risk-v1 score PLUS the weighted risk-v2 evidence
/// factors (honeypot, session client-context inconsistency, trusted-edge
/// TLS inconsistency), clamped to 0..=1000.
///
/// With zero risk-v2 signals this is EXACTLY [`score`] — the v1 contract
/// semantics (the 13 signals and their weights) are unchanged; the v2
/// factors are purely additive.
pub fn score_v2(
    base: u16,
    s: &SignalVector,
    w: &RiskWeights,
    v2: &crate::signals::RiskV2Signals,
    w2: &RiskV2Weights,
) -> u16 {
    let mut risk = score(base, s, w) as u32;
    risk += weighted(v2.honeypot, w2.honeypot);
    risk += weighted(v2.session_inconsistency, w2.session_inconsistency);
    risk += weighted(v2.tls_inconsistency, w2.tls);
    risk.min(1000) as u16
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
    use crate::signals::RiskV2Signals;
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

    /// ASYMMETRIC TRUST: the exact-IP (source) signals must
    /// outweigh the subnet (network) signals in the scorer weights, so one
    /// attacker IP is always punished harder than the /64 aggregate it
    /// shares. Pinned on the contract defaults; a future symmetric-weight
    /// regression fails here.
    #[test]
    fn source_weights_outweigh_subnet_weights() {
        let w = RiskWeights::default();
        assert!(
            w.source_fast > w.subnet_fast,
            "source_fast (exact-IP burst) must outweigh subnet_fast (network burst)"
        );
        assert!(
            w.bad_proof > w.subnet_fast,
            "bad_proof (exact-IP invalid proofs) must outweigh the subnet effect"
        );
        // The CONTRIBUTION-level asymmetry: for the same signal value the
        // exact-IP channel contributes strictly more score than the subnet
        // aggregate channel.
        let source_only = SignalVector {
            source_fast: 500,
            ..Default::default()
        };
        let subnet_only = SignalVector {
            subnet_fast: 500,
            ..Default::default()
        };
        assert!(
            score(0, &source_only, &w) > score(0, &subnet_only, &w),
            "an identical exact-IP signal must contribute more than the same network aggregate signal"
        );
    }

    /// ABSOLUTE USER-VISIBLE CAP: the score is clamped to
    /// 0..1000, so a poisoned source (every signal at saturation) reaches
    /// the cap but can NEVER exceed it — there is no unbounded punishment
    /// mode.
    #[test]
    fn saturated_source_reaches_the_cap_but_never_exceeds_it() {
        let w = RiskWeights::default();
        let saturated = SignalVector {
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
            trust_credit: 0,
            principal_credit: 0,
        };
        let cap = score(100, &saturated, &w);
        assert_eq!(cap, 1000, "a fully saturated source must reach the cap");
        assert!(cap <= 1000, "the score must never exceed the 0..1000 cap");

        // Hundreds of invalid proofs alone: bad_proof saturates at 1000 and
        // the contribution is bounded by the weight (220/1000 of it).
        let bad_only = SignalVector {
            bad_proof: 1000,
            ..Default::default()
        };
        assert_eq!(
            score(100, &bad_only, &w),
            100 + weighted(1000, w.bad_proof) as u16
        );
    }

    // ── Risk-v2 evidence factors (additive surface) ──────────────────────

    /// Honeypot evidence raises the aggregate: 100 + 1000*200/1000 = 300.
    #[test]
    fn honeypot_raises_the_aggregate() {
        let w = RiskWeights::default();
        let w2 = RiskV2Weights::default();
        let clean = SignalVector::zero();
        let before = score(100, &clean, &w);
        let after = score_v2(
            100,
            &clean,
            &w,
            &RiskV2Signals {
                honeypot: 1000,
                ..Default::default()
            },
            &w2,
        );
        assert!(after > before, "honeypot evidence must raise the aggregate");
        assert_eq!(after, 300);
    }

    /// A honeypot hit with an otherwise-clean vector stays BELOW the Deny
    /// band: it raises the aggregate (stronger profiles are selected) but
    /// never hard-denies alone.
    #[test]
    fn honeypot_hit_with_clean_vector_stays_below_deny() {
        let w = RiskWeights::default();
        let w2 = RiskV2Weights::default();
        let after = score_v2(
            100,
            &SignalVector::zero(),
            &w,
            &RiskV2Signals {
                honeypot: 1000,
                ..Default::default()
            },
            &w2,
        );
        assert!(
            after < 980,
            "a lone honeypot hit must stay below the Deny band"
        );
        assert_eq!(after, 300);
    }

    /// Honeypot + elevated signals crosses Deny: the aggregate reaches the
    /// cap (1000) and maps to Deny — the evidence only pushes an already
    /// risky profile over the edge.
    #[test]
    fn honeypot_plus_elevated_signals_crosses_deny() {
        let w = RiskWeights::default();
        let w2 = RiskV2Weights::default();
        // bad_proof 1000 (220) + issue_debt 1000 (150) + global_pressure
        // 1000 (170) + source_fast 900 (171) = 711; base 100 -> 811 WITHOUT
        // the honeypot factor (Argon32, no hard-deny thresholds hit).
        let elevated = SignalVector {
            bad_proof: 1000,
            issue_debt: 1000,
            global_pressure: 1000,
            source_fast: 900,
            ..Default::default()
        };
        let before = score(100, &elevated, &w);
        assert!(
            before < 980,
            "elevated-but-honeypot-free must stay below Deny"
        );
        assert_eq!(before, 811);
        let after = score_v2(
            100,
            &elevated,
            &w,
            &RiskV2Signals {
                honeypot: 1000,
                ..Default::default()
            },
            &w2,
        );
        assert!(after >= 980, "honeypot + elevated signals must cross Deny");
        assert_eq!(after, 1000);
    }

    /// Consistent client context is NEUTRAL: a zero session-inconsistency
    /// signal contributes nothing.
    #[test]
    fn consistent_client_context_is_neutral() {
        let w = RiskWeights::default();
        let w2 = RiskV2Weights::default();
        let vector = SignalVector::zero();
        let plain = score(100, &vector, &w);
        let with_v2 = score_v2(100, &vector, &w, &RiskV2Signals::zero(), &w2);
        assert_eq!(
            with_v2, plain,
            "consistent/absent context must not change the score"
        );
    }

    /// A CHANGED client-context tag raises the aggregate: 100 + 120 = 220.
    #[test]
    fn changed_client_context_raises_the_aggregate() {
        let w = RiskWeights::default();
        let w2 = RiskV2Weights::default();
        let before = score(100, &SignalVector::zero(), &w);
        let after = score_v2(
            100,
            &SignalVector::zero(),
            &w,
            &RiskV2Signals {
                session_inconsistency: 1000,
                ..Default::default()
            },
            &w2,
        );
        assert!(
            after > before,
            "context inconsistency must raise the aggregate"
        );
        assert_eq!(after, 220);
    }

    /// ABSENT client-context tag (first request) is NEUTRAL: no record
    /// exists yet, so no inconsistency signal is produced.
    #[test]
    fn absent_client_context_is_neutral() {
        let w = RiskWeights::default();
        let w2 = RiskV2Weights::default();
        let vector = SignalVector::zero();
        assert_eq!(
            score_v2(100, &vector, &w, &RiskV2Signals::zero(), &w2),
            score(100, &vector, &w)
        );
    }

    /// The DEFAULT risk-v2 weights match the cross-language contract
    /// (byte-identical with the PHP mirror).
    #[test]
    fn default_v2_weights_match_the_cross_language_contract() {
        let w2 = RiskV2Weights::default();
        assert_eq!(w2.honeypot, 200);
        assert_eq!(w2.session_inconsistency, 120);
        assert_eq!(w2.tls, 80);
    }

    /// Consistent trusted-edge TLS classification is NEUTRAL: a zero
    /// tls_inconsistency signal contributes nothing.
    #[test]
    fn consistent_tls_tag_is_neutral() {
        let w = RiskWeights::default();
        let w2 = RiskV2Weights::default();
        let vector = SignalVector::zero();
        let plain = score(100, &vector, &w);
        let with_v2 = score_v2(100, &vector, &w, &RiskV2Signals::zero(), &w2);
        assert_eq!(
            with_v2, plain,
            "consistent/absent TLS classification must not change the score"
        );
    }

    /// A CHANGED trusted-edge TLS tag raises the aggregate: 100 + 80 = 180.
    #[test]
    fn changed_tls_tag_raises_the_aggregate() {
        let w = RiskWeights::default();
        let w2 = RiskV2Weights::default();
        let before = score(100, &SignalVector::zero(), &w);
        let after = score_v2(
            100,
            &SignalVector::zero(),
            &w,
            &RiskV2Signals {
                tls_inconsistency: 1000,
                ..Default::default()
            },
            &w2,
        );
        assert!(after > before, "TLS inconsistency must raise the aggregate");
        assert_eq!(after, 180);
    }

    /// ABSENT trusted-edge TLS tag (first request) is NEUTRAL: no record
    /// exists yet, so no inconsistency signal is produced.
    #[test]
    fn absent_tls_tag_is_neutral() {
        let w = RiskWeights::default();
        let w2 = RiskV2Weights::default();
        let vector = SignalVector::zero();
        assert_eq!(
            score_v2(100, &vector, &w, &RiskV2Signals::zero(), &w2),
            score(100, &vector, &w)
        );
    }

    /// The risk-v2 factors are PURELY additive: with zero v2 signals the
    /// v2 scoring is byte-identical to the v1 score on the 10k parity
    /// stream.
    #[test]
    fn v2_zero_signals_match_v1_score_stream() {
        let w = RiskWeights::default();
        let w2 = RiskV2Weights::default();
        let mut prng = SeededVector::new();
        for _ in 0..1000 {
            let vector = prng.vector();
            assert_eq!(
                score_v2(100, &vector, &w, &RiskV2Signals::zero(), &w2),
                score(100, &vector, &w),
            );
        }
    }
}
