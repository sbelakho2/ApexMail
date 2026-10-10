//! Continuous work pricing: the additive post-marks decision stage of
//! change.md 3.3.1 and 3.3.2.
//!
//! The stage prices one request as
//! `work = price(risk, value_class, trust_in_current_asn, untrusted_scope_pressure)`
//! and quantizes the continuous score onto the challenge ladder, so the
//! ladder stays the output alphabet. The score adds the value-weighted
//! risk term to the gated pressure term, clamped into 0..1000: monotone
//! in risk, sub-linear in trust, and sharp for marked identities
//! because the upstream marks stage already floors their action at the
//! maximum rung and the price may only raise it.
//!
//! Pressure targets unproven identities only (3.3.2). The pressure gain
//! enters through the `(1 - trust_factor)` gate over the session's credit
//! in its current ASN bucket, so a trusted bucket keeps its individual
//! price within one rung under a full-pressure storm while an unproven
//! bucket takes the whole ramp. The floor logic of the plain policy
//! (scope minima, global floors, capacity step-ups) keeps applying to
//! every request underneath; the price never weakens any of it.
//!
//! The constants live in one table ([`PRICE_CONSTS`]) mirrored
//! byte-identically by the PHP `PriceModel`, and the shared corpus
//! (protocol/risk-v1/pricing-vectors.json) records the table plus the
//! expected outputs, so the two cores can never drift apart silently.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::action::RiskAction;
use crate::policy::RiskReason;
use crate::resources::ResourcePressure;
use crate::RiskDecision;
use crate::RiskError;

/// The one consts table of the price model, mirrored byte-identically by
/// the PHP core (`PriceModel::CONSTS`). Every number the curve uses is
/// here and nowhere else, so a revision is one edit plus a version bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriceConsts {
    /// The version stamp of the curve and band table. Bump on any change
    /// to a constant below; decisions priced under different stamps are
    /// distinguishable by the stamp the caller logged.
    pub version: u32,
    /// The score ceiling of the fixed-point domain (work scores and every
    /// per-mille factor live in 0..=1000).
    pub score_saturation: u32,
    /// The raw bucket-trust ceiling (identical to the trust plane's
    /// saturation: 10000 raw units normalize to the full 1000 credit).
    pub trust_saturation: u32,
    /// The half-scale K of the sub-linear trust factor
    /// `trust_factor = trust / (trust + K)`. At K the factor is 1/2; the
    /// curve rises steeply for young trust and saturates toward 4/5 at the
    /// trust ceiling, so each additional unit of earned trust buys less
    /// relief than the one before.
    pub trust_half_scale: u32,
    /// The documented trust threshold: raw bucket credit at or above this
    /// value counts as a trusted identity for the pressure gate. The
    /// residual pressure a trusted bucket may take (71 points at the
    /// threshold, 60 at full credit) is structurally below the narrowest
    /// gap of the band table, so a trusted price moves at most one rung.
    pub trusted_bucket_credit: u32,
    /// The saturation of the pressure ramp: the largest score gain the
    /// gate can add at pressure 1000.
    pub pressure_gain_saturation: u32,
    /// Per-mille value weights in [`ValueClass`] order
    /// (low, standard, high, critical). A high-value target prices above
    /// its raw risk; a low-value one below it.
    pub value_weights: [u32; 4],
    /// The work-score band edges (exclusive upper bounds of the first
    /// eight rungs). The first four edges match `action_for_score`; the
    /// upper bands widen so the narrowest consecutive gap (90) exceeds
    /// the trusted pressure residual (71) and the one-rung invariant is
    /// structural rather than tested luck.
    pub band_edges: [u16; 8],
    /// Below this argon capacity a priced Argon rung re-escalates to the
    /// interactive step-up (the policy's own capacity check, applied to
    /// the priced rung exactly like the marks stage applies it).
    pub argon_capacity_floor: u16,
}

/// The pinned consts table of the current price model.
pub const PRICE_CONSTS: PriceConsts = PriceConsts {
    version: 1,
    score_saturation: 1000,
    trust_saturation: 10_000,
    trust_half_scale: 2_500,
    trusted_bucket_credit: 8_000,
    pressure_gain_saturation: 300,
    value_weights: [800, 1000, 1200, 1400],
    band_edges: [150, 300, 450, 600, 700, 790, 880, 970],
    argon_capacity_floor: 300,
};

/// The value class of the priced request: what the protected action is
/// worth to the deployment. Weights are per-mille multipliers of the risk
/// score, ordered in [`PRICE_CONSTS.value_weights`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueClass {
    #[default]
    Low,
    Standard,
    High,
    Critical,
}

impl ValueClass {
    /// The per-mille value weight of the class.
    pub fn weight(self) -> u32 {
        let index = match self {
            ValueClass::Low => 0,
            ValueClass::Standard => 1,
            ValueClass::High => 2,
            ValueClass::Critical => 3,
        };
        PRICE_CONSTS.value_weights[index]
    }

    /// The wire spelling (matches the serde representation).
    pub fn as_str(self) -> &'static str {
        match self {
            ValueClass::Low => "low",
            ValueClass::Standard => "standard",
            ValueClass::High => "high",
            ValueClass::Critical => "critical",
        }
    }

    /// Parses the wire spelling.
    pub fn parse(s: &str) -> Option<ValueClass> {
        match s {
            "low" => Some(ValueClass::Low),
            "standard" => Some(ValueClass::Standard),
            "high" => Some(ValueClass::High),
            "critical" => Some(ValueClass::Critical),
            _ => None,
        }
    }
}

/// The per-request pricing inputs a deployment resolves: the value class
/// of the protected action and the session's raw bucket-trust credit in
/// its current ASN bucket (0..=10000, the trust plane's raw scale).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriceInputs {
    pub value_class: ValueClass,
    pub bucket_trust: u32,
}

impl PriceInputs {
    /// The fail-closed inputs for an unreadable pricing surface: a
    /// standard-value request with zero bucket credit, so the pressure
    /// gate treats the identity as unproven and the full ramp applies.
    /// The price may still only raise the composed action.
    pub fn fail_closed() -> PriceInputs {
        PriceInputs {
            value_class: ValueClass::Standard,
            bucket_trust: 0,
        }
    }
}

/// The request identity picture the engine hands a price-context source:
/// the scope, the source address and the session and principal pseudonyms
/// the engine derived (the same picture the marks reader receives).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceRequest {
    pub scope: u32,
    pub source_ip: IpAddr,
    /// The session pseudonym (32 hex chars), or `None` without a session.
    pub session: Option<String>,
    /// The principal pseudonym (32 hex chars), or `None` when the request
    /// is unauthenticated.
    pub principal: Option<String>,
}

/// The price-context seam of the engine wiring (the marks-reader
/// precedent): given the identity picture the engine derived, answer the
/// pricing inputs of the request. The bucket trust is the same record the
/// trust plane reads; the value class is the deployment's own mapping of
/// the scope or form to what the action protects.
pub trait PriceContextSource: Send + Sync {
    /// The pricing inputs of one request.
    ///
    /// # Errors
    ///
    /// [`RiskError::Store`] when the underlying surface fails; the engine
    /// then prices the request with [`PriceInputs::fail_closed`] so an
    /// unreadable trust record escalates instead of discounting.
    fn price_inputs(&self, request: &PriceRequest) -> Result<PriceInputs, RiskError>;
}

/// The versioned price model: pure fixed-point math over
/// [`PRICE_CONSTS`], stateless and identical in both cores. All
/// arithmetic is `u32` with truncating division, so no float boundary
/// can diverge between the implementations.
pub struct PriceModel;

impl PriceModel {
    /// The version stamp of the pinned consts table.
    pub fn version() -> u32 {
        PRICE_CONSTS.version
    }

    /// The per-mille value weight of a class.
    pub fn value_weight(class: ValueClass) -> u32 {
        class.weight()
    }

    /// The trust factor in per-mille: `1000 x trust / (trust + K)`,
    /// clamped at the trust saturation first. Sub-linear and concave in
    /// trust: 0 at no credit, 500 at K, 761 at the trusted threshold,
    /// 800 at full credit. The residual `1000 - factor` is the share of
    /// the pressure ramp the identity still takes.
    pub fn trust_factor_mille(trust: u32) -> u32 {
        let trust = trust.min(PRICE_CONSTS.trust_saturation);
        1000 * trust / (trust + PRICE_CONSTS.trust_half_scale)
    }

    /// The pressure ramp gain in score points: a monotone concave ramp
    /// `saturation x (2x - x^2)` with `x = pressure / 1000`, so
    /// `gain(p) = saturation x (2000p - p^2) / 1000000`. The curve rises
    /// fast for small pressure (a storm bites early) and flattens as it
    /// approaches the saturation: 0 at rest, 225 at pressure 500, the
    /// full 300 at pressure 1000.
    pub fn pressure_gain(pressure: u16) -> u32 {
        let p = u32::from(pressure.min(PRICE_CONSTS.score_saturation as u16));
        let unit = 2_000 * p - p * p;
        PRICE_CONSTS.pressure_gain_saturation * unit / 1_000_000
    }

    /// The continuous work score of one request:
    /// `risk_term + pressure_term`, clamped into 0..1000 where the risk
    /// term is the value-weighted score and the pressure term is the
    /// ramp gain times the trust-factor residual gate.
    /// Every input is clamped to its domain first (risk and pressure at
    /// 1000, bucket trust at the trust saturation).
    pub fn work_score(risk: u16, value_class: ValueClass, bucket_trust: u32, pressure: u16) -> u16 {
        let risk = u32::from(risk.min(PRICE_CONSTS.score_saturation as u16));
        let risk_term = risk * Self::value_weight(value_class) / PRICE_CONSTS.score_saturation;
        let gate = PRICE_CONSTS.score_saturation - Self::trust_factor_mille(bucket_trust);
        let gain = Self::pressure_gain(pressure);
        let pressure_term = gain * gate / PRICE_CONSTS.score_saturation;
        (risk_term + pressure_term).min(PRICE_CONSTS.score_saturation) as u16
    }

    /// The quantization band table: maps a work score onto the ladder.
    /// The edges are the exclusive upper bounds of the first eight rungs;
    /// a score at or above the last edge denies. The first four edges are
    /// `action_for_score`'s own, so the boundary between the sha and
    /// argon regimes (600) is the same number in both tables.
    pub fn action_for_work_score(work_score: u16) -> RiskAction {
        let edges = PRICE_CONSTS.band_edges;
        let w = work_score;
        if w < edges[0] {
            RiskAction::Allow
        } else if w < edges[1] {
            RiskAction::Sha16
        } else if w < edges[2] {
            RiskAction::Sha18
        } else if w < edges[3] {
            RiskAction::Sha20
        } else if w < edges[4] {
            RiskAction::Argon16
        } else if w < edges[5] {
            RiskAction::Argon32
        } else if w < edges[6] {
            RiskAction::Argon64
        } else if w < edges[7] {
            RiskAction::StepUp
        } else {
            RiskAction::Deny
        }
    }

    /// The priced rung: the continuous score quantized onto the ladder.
    pub fn price(
        risk: u16,
        value_class: ValueClass,
        bucket_trust: u32,
        pressure: u16,
    ) -> RiskAction {
        Self::action_for_work_score(Self::work_score(risk, value_class, bucket_trust, pressure))
    }

    /// The price-floor stage: composes the plain decision (band, floors,
    /// overrides, hysteresis, marks) with the priced rung. The price may
    /// only raise: when the priced rung does not exceed the composed
    /// action the decision passes through untouched, and when it does the
    /// action rises to the priced rung. A priced Argon rung on a
    /// saturated backend re-escalates to the interactive step-up exactly
    /// like the policy's own capacity check, so the floor never demands
    /// memory-hard work the backend cannot serve.
    ///
    /// Pure; the decision's score, band, policy version, model revision,
    /// global level and decision id pass through untouched. Stage reasons
    /// prepend exactly like the policy's hard overrides, then
    /// deduplicate and cap at 4.
    pub fn apply(
        plain: RiskDecision,
        inputs: &PriceInputs,
        pressure: u16,
        resources: &ResourcePressure,
    ) -> RiskDecision {
        let priced = Self::price(
            plain.score,
            inputs.value_class,
            inputs.bucket_trust,
            pressure,
        );
        if priced.rank() <= plain.action.rank() {
            return plain;
        }
        let mut action = priced;
        let mut stage_reasons = vec![RiskReason::PricedEscalation];
        if action.is_argon() && resources.argon_capacity < PRICE_CONSTS.argon_capacity_floor {
            // StepUp outranks every argon rung, so the capacity
            // re-escalation is still a raise over the composed action.
            action = RiskAction::StepUp;
            stage_reasons.push(RiskReason::CapacityPressure);
        }
        let mut decision = plain;
        decision.action = action;
        merge_stage_reasons(&mut decision, stage_reasons);
        decision
    }
}

/// Prepends the stage reasons to the decision's reasons, deduplicates
/// and caps at 4 (the policy's own assembly order).
fn merge_stage_reasons(decision: &mut RiskDecision, stage_reasons: Vec<RiskReason>) {
    let mut reasons = stage_reasons;
    reasons.extend(decision.reasons_vec());
    let mut seen = std::collections::HashSet::new();
    reasons.retain(|reason| seen.insert(*reason));
    reasons.truncate(4);
    let mut out = [None; 4];
    for (slot, reason) in out.iter_mut().zip(reasons) {
        *slot = Some(reason);
    }
    decision.reasons = out;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marks::{self, MarksView};
    use crate::outcomes::{MarkDimension, MarkRecord};
    use crate::policy::RiskPolicy;
    use crate::signals::SignalVector;
    use serde_json::json;

    const T0: u64 = 1_700_000_000_000;
    const TTL: u64 = marks::DEFAULT_MARK_TTL_MS;

    fn policy() -> RiskPolicy {
        RiskPolicy::from_config(
            3,
            &json!({
                "version": 3,
                "weights": {
                    "source_fast": 190, "source_slow": 110, "subnet_fast": 80,
                    "issue_debt": 150, "bad_proof": 220, "malformed": 260,
                    "replay": 320, "action_failure": 120, "scope_switch": 60,
                    "global_pressure": 170, "network_risk": 100,
                    "trust_credit": 130, "principal_credit": 100
                },
                "scopes": {
                    "1": { "base_risk": 100, "minimum": "allow", "post_solve_check": true, "degraded": "sha20" }
                },
                "global_floors": { "0": "allow", "1": "sha16", "2": "sha18", "3": "sha20", "4": "sha20" }
            }),
        )
        .expect("config parses")
    }

    fn healthy() -> ResourcePressure {
        ResourcePressure::default()
    }

    fn plain(score: u16) -> RiskDecision {
        policy().decide(1, score, &SignalVector::zero(), &healthy(), 0, T0, 0)
    }

    fn inputs(class: ValueClass, trust: u32) -> PriceInputs {
        PriceInputs {
            value_class: class,
            bucket_trust: trust,
        }
    }

    #[test]
    fn consts_table_is_pinned() {
        assert_eq!(PriceModel::version(), 1);
        assert_eq!(PRICE_CONSTS.score_saturation, 1000);
        assert_eq!(PRICE_CONSTS.trust_saturation, 10_000);
        assert_eq!(PRICE_CONSTS.trust_half_scale, 2_500);
        assert_eq!(PRICE_CONSTS.trusted_bucket_credit, 8_000);
        assert_eq!(PRICE_CONSTS.pressure_gain_saturation, 300);
        assert_eq!(PRICE_CONSTS.value_weights, [800, 1000, 1200, 1400]);
        assert_eq!(
            PRICE_CONSTS.band_edges,
            [150, 300, 450, 600, 700, 790, 880, 970]
        );
        assert_eq!(PRICE_CONSTS.argon_capacity_floor, 300);
    }

    /// Hand-computed pins of every curve piece, so a systematic error in
    /// both cores cannot hide behind the shared corpus.
    #[test]
    fn hand_computed_curve_pins() {
        // trust factor: 0 at none, half at K, clamped at saturation.
        assert_eq!(PriceModel::trust_factor_mille(0), 0);
        assert_eq!(PriceModel::trust_factor_mille(2_500), 500);
        assert_eq!(PriceModel::trust_factor_mille(5_000), 666);
        assert_eq!(PriceModel::trust_factor_mille(8_000), 761);
        assert_eq!(PriceModel::trust_factor_mille(10_000), 800);
        assert_eq!(PriceModel::trust_factor_mille(u32::MAX), 800);

        // pressure ramp: rest, quarter, half, three quarters, saturation.
        assert_eq!(PriceModel::pressure_gain(0), 0);
        assert_eq!(PriceModel::pressure_gain(250), 131);
        assert_eq!(PriceModel::pressure_gain(500), 225);
        assert_eq!(PriceModel::pressure_gain(750), 281);
        assert_eq!(PriceModel::pressure_gain(914), 297);
        assert_eq!(PriceModel::pressure_gain(1000), 300);
        assert_eq!(PriceModel::pressure_gain(u16::MAX), 300);

        // value weights.
        assert_eq!(PriceModel::value_weight(ValueClass::Low), 800);
        assert_eq!(PriceModel::value_weight(ValueClass::Standard), 1000);
        assert_eq!(PriceModel::value_weight(ValueClass::High), 1200);
        assert_eq!(PriceModel::value_weight(ValueClass::Critical), 1400);

        // work scores: trust gates the ramp, clamps hold at both ends.
        assert_eq!(PriceModel::work_score(0, ValueClass::Standard, 0, 0), 0);
        assert_eq!(
            PriceModel::work_score(100, ValueClass::Standard, 10_000, 0),
            100
        );
        assert_eq!(
            PriceModel::work_score(100, ValueClass::Standard, 10_000, 1000),
            160
        );
        assert_eq!(
            PriceModel::work_score(100, ValueClass::Standard, 8_000, 1000),
            171
        );
        assert_eq!(
            PriceModel::work_score(100, ValueClass::Standard, 0, 1000),
            400
        );
        assert_eq!(
            PriceModel::work_score(500, ValueClass::High, 4_000, 600),
            697
        );
        assert_eq!(
            PriceModel::work_score(u16::MAX, ValueClass::Critical, 0, 1000),
            1000
        );

        // quantization corners of the band table.
        let cases = [
            (0u16, RiskAction::Allow),
            (149, RiskAction::Allow),
            (150, RiskAction::Sha16),
            (299, RiskAction::Sha16),
            (300, RiskAction::Sha18),
            (449, RiskAction::Sha18),
            (450, RiskAction::Sha20),
            (599, RiskAction::Sha20),
            (600, RiskAction::Argon16),
            (699, RiskAction::Argon16),
            (700, RiskAction::Argon32),
            (789, RiskAction::Argon32),
            (790, RiskAction::Argon64),
            (879, RiskAction::Argon64),
            (880, RiskAction::StepUp),
            (969, RiskAction::StepUp),
            (970, RiskAction::Deny),
            (1000, RiskAction::Deny),
        ];
        for (score, expected) in cases {
            assert_eq!(
                PriceModel::action_for_work_score(score),
                expected,
                "work score {score}"
            );
        }
        // The sha-to-argon edge is the policy's own decision boundary.
        assert_eq!(
            PriceModel::action_for_work_score(RiskAction::DECISION_BOUNDARY_SCORE),
            RiskAction::Argon16
        );
        // Priced rungs at the pinned corners.
        assert_eq!(
            PriceModel::price(100, ValueClass::Standard, 10_000, 1000),
            RiskAction::Sha16
        );
        assert_eq!(
            PriceModel::price(100, ValueClass::Standard, 0, 1000),
            RiskAction::Sha18
        );
        assert_eq!(
            PriceModel::price(500, ValueClass::High, 4_000, 600),
            RiskAction::Argon16
        );
    }

    /// Monotone in risk: raising the risk score never drops the priced
    /// rung, for every class, trust and pressure on a dense grid.
    #[test]
    fn monotone_in_risk() {
        for class in [
            ValueClass::Low,
            ValueClass::Standard,
            ValueClass::High,
            ValueClass::Critical,
        ] {
            for trust in [0u32, 2_500, 8_000, 10_000] {
                for pressure in [0u16, 250, 500, 1000] {
                    let mut last = RiskAction::Allow;
                    for risk in (0..=1000u16).step_by(7) {
                        let rung = PriceModel::price(risk, class, trust, pressure);
                        assert!(
                            rung.rank() >= last.rank(),
                            "risk {risk} class {class:?} trust {trust} pressure {pressure} dropped the rung"
                        );
                        last = rung;
                    }
                }
            }
        }
    }

    /// Sub-linear in trust. The work score never rises with trust;
    /// halving the trust never doubles the residual pressure gate; and
    /// the trust factor's gain over equal steps diminishes (concave)
    /// within one fixed-point unit of floor rounding.
    #[test]
    fn sub_linear_in_trust() {
        // halving: the residual gate at t/2 never exceeds twice the gate
        // at t, so no trust halving doubles the pressure penalty.
        for t in 1..=10_000u32 {
            let g_half = 1000 - PriceModel::trust_factor_mille(t / 2);
            let g_full = 1000 - PriceModel::trust_factor_mille(t);
            assert!(
                g_half <= 2 * g_full,
                "gate at half of {t} is {g_half}, twice the full gate is {g_full}"
            );
        }
        // concavity: over equal trust steps the factor's gain diminishes,
        // one rounding unit of slack for the floor in each term.
        for delta in [1u32, 7, 125, 1000, 2500] {
            for base in (0..=10_000).step_by(137) {
                if base + 2 * delta > 10_000 {
                    continue;
                }
                let t1 = base;
                let t2 = base + delta;
                let t3 = base + 2 * delta;
                let gain1 = PriceModel::trust_factor_mille(t2) - PriceModel::trust_factor_mille(t1);
                let gain2 = PriceModel::trust_factor_mille(t3) - PriceModel::trust_factor_mille(t2);
                assert!(
                    gain1 + 1 >= gain2,
                    "the trust factor is not concave at {t1}->{t2}->{t3}"
                );
            }
        }
        // the work score itself never rises with trust, anywhere
        for class in [
            ValueClass::Low,
            ValueClass::Standard,
            ValueClass::High,
            ValueClass::Critical,
        ] {
            for pressure in [0u16, 375, 1000] {
                for risk in (0..=1000u16).step_by(50) {
                    let mut last = PriceModel::work_score(risk, class, 0, pressure);
                    for trust in (0..=10_000u32).step_by(97) {
                        let score = PriceModel::work_score(risk, class, trust, pressure);
                        assert!(
                            score <= last,
                            "work score rose with trust {trust} (risk {risk}, {class:?}, pressure {pressure})"
                        );
                        last = score;
                    }
                }
            }
        }
    }

    /// The 3.3.2 core property: a trusted bucket (credit at or above the
    /// documented threshold) with full pressure prices within one rung of
    /// its no-pressure price, for every risk and class.
    #[test]
    fn trusted_full_pressure_moves_at_most_one_rung() {
        for trust in [
            PRICE_CONSTS.trusted_bucket_credit,
            9_000,
            PRICE_CONSTS.trust_saturation,
        ] {
            for class in [
                ValueClass::Low,
                ValueClass::Standard,
                ValueClass::High,
                ValueClass::Critical,
            ] {
                for risk in 0..=1000u16 {
                    let calm = PriceModel::price(risk, class, trust, 0);
                    let storm = PriceModel::price(risk, class, trust, 1000);
                    assert!(
                        storm.rank() - calm.rank() <= 1,
                        "trusted {trust} risk {risk} {:?} moved {} rungs under full pressure",
                        class,
                        storm.rank() - calm.rank()
                    );
                }
            }
        }
    }

    /// An unproven bucket takes the whole ramp: the untrusted work score
    /// is exactly the calm score plus the ramp gain wherever the clamp
    /// does not bite, and the residual gate at the trusted threshold
    /// stays under the narrowest band gap (the structural half of the
    /// one-rung invariant).
    #[test]
    fn untrusted_takes_the_full_ramp() {
        for risk in (0..=700u16).step_by(35) {
            let calm = PriceModel::work_score(risk, ValueClass::Standard, 0, 0);
            let storm = PriceModel::work_score(risk, ValueClass::Standard, 0, 1000);
            assert_eq!(storm - calm, 300, "risk {risk}");
        }
        // trusted residual under full pressure vs the narrowest gap
        let trusted_residual = PriceModel::pressure_gain(1000)
            * (1000 - PriceModel::trust_factor_mille(PRICE_CONSTS.trusted_bucket_credit))
            / 1000;
        let gaps = PRICE_CONSTS
            .band_edges
            .windows(2)
            .map(|pair| pair[1] - pair[0]);
        let narrowest = gaps.min().expect("eight edges have seven gaps");
        assert_eq!(trusted_residual, 71);
        assert!(
            trusted_residual < u32::from(narrowest),
            "residual {trusted_residual} must stay under the narrowest gap {narrowest}"
        );
    }

    /// Floor and cap invariants: every output is a ladder rung, and every
    /// input clamps at its domain bound instead of wrapping.
    #[test]
    fn floors_and_caps() {
        for risk in [0u16, 500, 1000, u16::MAX] {
            for trust in [0u32, 8_000, 10_000, u32::MAX] {
                for pressure in [0u16, 500, 1000, u16::MAX] {
                    let rung = PriceModel::price(risk, ValueClass::Standard, trust, pressure);
                    assert!(rung.rank() <= RiskAction::Deny.rank());
                    assert_eq!(
                        rung,
                        PriceModel::price(
                            risk.min(1000),
                            ValueClass::Standard,
                            trust.min(10_000),
                            pressure.min(1000)
                        ),
                        "the clamps must make over-domain inputs equal their clamped values"
                    );
                }
            }
        }
        // over-domain trust behaves exactly like full credit
        assert_eq!(
            PriceModel::work_score(600, ValueClass::Standard, u32::MAX, 1000),
            PriceModel::work_score(600, ValueClass::Standard, 10_000, 1000)
        );
    }

    /// The stage only raises: for a grid of composed decisions and price
    /// inputs, the priced decision's action never drops below the
    /// composed action and the pass-through fields never change.
    #[test]
    fn price_never_lowers_the_composed_action() {
        let healthy = healthy();
        for score in (0..=1000u16).step_by(61) {
            for level in 0..=4u8 {
                let composed =
                    policy().decide(1, score, &SignalVector::zero(), &healthy, level, T0, 0);
                for trust in [0u32, 8_000, 10_000] {
                    for pressure in [0u16, 500, 1000] {
                        for class in [
                            ValueClass::Low,
                            ValueClass::Standard,
                            ValueClass::High,
                            ValueClass::Critical,
                        ] {
                            let out = PriceModel::apply(
                                composed.clone(),
                                &inputs(class, trust),
                                pressure,
                                &healthy,
                            );
                            assert!(
                                out.action.rank() >= composed.action.rank(),
                                "score {score} level {level}: {:?} -> {:?}",
                                composed.action,
                                out.action
                            );
                            assert_eq!(out.score, composed.score);
                            assert_eq!(out.band, composed.band);
                            assert_eq!(out.policy_version, composed.policy_version);
                            assert_eq!(out.model_revision, composed.model_revision);
                            assert_eq!(out.global_level, composed.global_level);
                            assert_eq!(out.decision_id, composed.decision_id);
                        }
                    }
                }
            }
        }
    }

    /// Sharp for marked identities: composing marks (Argon64 floor) and
    /// then the price keeps the action at or above the marks floor, so
    /// the price never softens the decisive stage.
    #[test]
    fn price_never_softens_the_marks_floor() {
        let now = T0 as i64;
        let view = MarksView::from_parts(
            vec![(
                MarkDimension::Session,
                MarkRecord {
                    kind: "accountBanned".to_string(),
                    last_kind: "accountBanned".to_string(),
                    count: 1,
                    first_ms: now,
                    last_ms: now,
                },
            )],
            None,
        );
        for score in (0..=1000u16).step_by(37) {
            let composed = policy().decide(1, score, &SignalVector::zero(), &healthy(), 0, T0, 0);
            let marked = marks::apply(composed, &view, false, T0, TTL, &healthy(), false);
            for trust in [0u32, 8_000, 10_000] {
                for pressure in [0u16, 1000] {
                    let out = PriceModel::apply(
                        marked.clone(),
                        &inputs(ValueClass::Low, trust),
                        pressure,
                        &healthy(),
                    );
                    assert!(
                        out.action.rank() >= RiskAction::Argon64.rank(),
                        "score {score} trust {trust} pressure {pressure}: {:?}",
                        out.action
                    );
                }
            }
        }
    }

    /// The stage prepends its reason exactly like the marks stage, and a
    /// saturated backend re-escalates a priced argon rung to the
    /// interactive step-up instead of demanding unservable work.
    #[test]
    fn apply_stage_reasons_and_capacity() {
        // plain Allow, priced Sha16: raised with the reason.
        let out = PriceModel::apply(
            plain(100),
            &inputs(ValueClass::Standard, 10_000),
            1000,
            &healthy(),
        );
        assert_eq!(out.action, RiskAction::Sha16);
        assert!(out.has_reason(RiskReason::PricedEscalation));
        assert_eq!(out.score, 100);
        assert_eq!(out.band, 1);

        // priced rung below the composed action: byte-identical pass-through.
        let composed = plain(980);
        let out = PriceModel::apply(
            composed.clone(),
            &inputs(ValueClass::Low, 10_000),
            0,
            &healthy(),
        );
        assert_eq!(out.action, composed.action);
        assert_eq!(out.reasons, composed.reasons);

        // priced Argon rung on a saturated backend: StepUp with both reasons.
        let saturated = ResourcePressure {
            argon_capacity: 299,
            ..Default::default()
        };
        let out = PriceModel::apply(
            plain(400),
            &inputs(ValueClass::Standard, 0),
            1000,
            &saturated,
        );
        assert_eq!(out.action, RiskAction::StepUp);
        assert!(out.has_reason(RiskReason::PricedEscalation));
        assert!(out.has_reason(RiskReason::CapacityPressure));

        // priced Deny on a saturated backend stays Deny (capacity only
        // re-escalates argon rungs).
        let out = PriceModel::apply(
            plain(600),
            &inputs(ValueClass::Critical, 0),
            1000,
            &saturated,
        );
        assert_eq!(out.action, RiskAction::Deny);
    }

    #[test]
    fn fail_closed_inputs_price_as_unproven_standard() {
        let inputs = PriceInputs::fail_closed();
        assert_eq!(inputs.value_class, ValueClass::Standard);
        assert_eq!(inputs.bucket_trust, 0);
        assert_eq!(
            PriceModel::work_score(100, inputs.value_class, inputs.bucket_trust, 1000),
            PriceModel::work_score(100, ValueClass::Standard, 0, 1000)
        );
    }

    #[test]
    fn value_class_wire_spellings_round_trip() {
        for class in [
            ValueClass::Low,
            ValueClass::Standard,
            ValueClass::High,
            ValueClass::Critical,
        ] {
            assert_eq!(ValueClass::parse(class.as_str()), Some(class));
            assert_eq!(
                serde_json::to_value(class).unwrap(),
                serde_json::json!(class.as_str())
            );
        }
        assert_eq!(ValueClass::parse("vip"), None);
    }
}
