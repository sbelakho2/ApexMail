//! Plane 2 evidence scoring (change.md 3.2.1): the interaction-anomaly
//! and solve-anomaly signals derived from the telemetry-v1 payload and
//! the client-performance reference table, plus the additive decision
//! stage that composes them (change.md 3.2.3).
//!
//! The module is a pure side channel beside the frozen risk-v1 wire:
//! the observation argv, the contract fixtures and the v1 scorer are
//! untouched. The stage runs after the marks stage and before the
//! pricing stage and may only raise the composed action, exactly like
//! the marks and pricing stages; an unwired or absent-evidence
//! assessment is byte-identical to the plain path.
//!
//! The scoring constants live in one table ([`EVIDENCE_CONSTS`]) mirrored
//! byte-identically by the PHP core (`EvidenceModel::CONSTS`), and the
//! shared corpus (protocol/telemetry-v1/evidence-vectors.json) pins the
//! scoring, the schema acceptance and the composed stage in both cores.

use serde::{Deserialize, Serialize};

use crate::action::RiskAction;
use crate::policy::RiskReason;
use crate::resources::ResourcePressure;
use crate::RiskDecision;

/// The schema version the parser accepts. Anything else is a reject.
pub const PAYLOAD_VERSION: i64 = 1;

/// The wire bound on the telemetry payload string (bytes). The largest
/// valid payload is far below this; an over-bound payload is rejected
/// before parsing (fail-closed, identical to the context-tag bound).
pub const MAX_PAYLOAD_BYTES: usize = 512;

/// The one consts table of the evidence model, mirrored byte-identically
/// by the PHP core (`EvidenceModel::CONSTS`). The shared corpus
/// (protocol/telemetry-v1/evidence-vectors.json) carries the same table.
pub const EVIDENCE_CONSTS: EvidenceConsts = EvidenceConsts {
    version: 1,
    score_saturation: 1000,
    sample_cap: 32,
    entropy_max: 15,
    entropy_min_samples: 32,
    entropy_weight: 400,
    focus_weight: 200,
    paste_weight: 400,
    paste_volume_floor: 8,
    paste_ratio_edge: 900,
    paste_anomaly_value: 800,
    human_band_edge: 150,
    agent_evidence_edge: 400,
    interaction_weight: 500,
    solve_weight: 500,
    solve_ratio_saturation_mille: 1000,
    band_edges: [150, 300, 500, 700],
    max_solve_ms: 3_600_000,
};

/// The pinned consts table of the current evidence model.
pub const EVIDENCE_CONSTS_TABLE: EvidenceConsts = EVIDENCE_CONSTS;

/// One table of scoring constants; every number the evidence model uses
/// is here and nowhere else, so a revision is one edit plus a version
/// bump (and a shared-corpus refresh in both cores).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceConsts {
    /// The version stamp of the model and its constants.
    pub version: u32,
    /// The per-mille saturation every signal lives in (0..=1000).
    pub score_saturation: u32,
    /// The payload sample cap: collection freezes at this event count,
    /// every payload count is bounded by it, and it is the entropy
    /// rule's minimum-sample count (the no-dead-rule invariant).
    pub sample_cap: u32,
    /// The 4-bit entropy ceiling (16 buckets).
    pub entropy_max: u32,
    /// The minimum sample count the entropy term requires. Equal to the
    /// payload cap by invariant: exactly reachable, never a dead rule.
    pub entropy_min_samples: u32,
    /// Per-mille weight of the entropy term within the interaction mix.
    pub entropy_weight: u32,
    /// Per-mille weight of the focus-transition term.
    pub focus_weight: u32,
    /// Per-mille weight of the paste term.
    pub paste_weight: u32,
    /// The combined key-plus-paste count the paste term requires before
    /// it may fire, so one stray paste on thin evidence stays neutral.
    pub paste_volume_floor: u32,
    /// The paste-versus-type ratio (per-mille) at or above which the
    /// paste term may fire.
    pub paste_ratio_edge: u32,
    /// The fixed value of the paste term when it fires.
    pub paste_anomaly_value: u32,
    /// The interaction anomaly at or below which a payload counts as
    /// human-band (the corpus pins the band).
    pub human_band_edge: u16,
    /// The interaction anomaly at or above which a payload counts as
    /// positive machine evidence (never absent, never human).
    pub agent_evidence_edge: u16,
    /// Per-mille weight of the interaction signal in the stage mix.
    pub interaction_weight: u32,
    /// Per-mille weight of the solve signal in the stage mix.
    pub solve_weight: u32,
    /// The solve-time ratio (per-mille) at or above which the solve
    /// anomaly is zero (the solve is at least as slow as the reference).
    pub solve_ratio_saturation_mille: u32,
    /// The stage band edges (exclusive lower bounds) onto the ladder:
    /// at or above each edge the action rises to the matching rung of
    /// [`BAND_RUNGS`]; below the first edge the decision passes through.
    pub band_edges: [u16; 4],
    /// The absolute solve-ms bound (the wire duration ceiling).
    pub max_solve_ms: u64,
}

/// The band rungs in [`EvidenceConsts::band_edges`] order. The evidence
/// stage never rises past the first argon rung: evidence alone never
/// demands the strongest work, never a step-up and never a deny.
pub const BAND_RUNGS: [RiskAction; 4] = [
    RiskAction::Sha16,
    RiskAction::Sha18,
    RiskAction::Sha20,
    RiskAction::Argon16,
];

/// The per-rung fastest-device reference table
/// (protocol/telemetry-v1/client-perf-p1.json, schema
/// kiwicaptcha.client-perf-p1/1). The compiled table is asserted equal
/// to the published file by the fixture test in `tests/evidence_vectors.rs`;
/// a refresh of the published table without the compiled one (or the
/// reverse) fails the suite.
pub const EVIDENCE_P1_MS: &[(&str, u64)] = &[
    ("sha16", 23),
    ("sha18", 27),
    ("sha20", 27),
    ("argon16", 86),
    ("argon32", 86),
    ("argon64", 86),
    ("rsw75k", 244),
    ("rsw150k", 432),
    ("rsw300k", 810),
];

/// The parsed telemetry-v1 payload (all fields validated).
///
/// Constructed only through [`TelemetryPayloadV1::parse`], which accepts
/// exactly the published schema and rejects everything else, so a valid
/// value can never carry an out-of-range count or an unknown field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryPayloadV1 {
    /// Schema version (always [`PAYLOAD_VERSION`]).
    pub v: i64,
    /// Event-class counts, in wire order.
    pub ec: EventClassCounts,
    /// Quantized inter-event entropy (0..=15).
    pub qe: i64,
    /// Focus-transition count.
    pub ft: i64,
    /// Paste-versus-type ratio (per-mille).
    pub pt: i64,
    /// Sample count.
    pub n: i64,
}

/// The event-class counts of one payload (wire keys `fo`, `ke`, `pa`,
/// `po`, `fm`). Unknown keys reject the payload; the counts are bounded
/// by the sample cap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventClassCounts {
    /// Focus events (focusin and focusout).
    pub fo: i64,
    /// Key events (keydown, repeats excluded).
    pub ke: i64,
    /// Paste events.
    pub pa: i64,
    /// Pointer events (pointerdown).
    pub po: i64,
    /// Form-field mutation events (input and change).
    pub fm: i64,
}

impl TelemetryPayloadV1 {
    /// Parses one telemetry payload from its JSON text against the
    /// published schema. Every violation (wrong version, missing field,
    /// out-of-range value, unknown field, wrong JSON shape) is a reject;
    /// the caller treats a reject exactly like an absent payload
    /// (neutral-unknown, never negative).
    pub fn parse(raw: &str) -> Option<TelemetryPayloadV1> {
        if raw.len() > MAX_PAYLOAD_BYTES {
            return None;
        }
        let value: serde_json::Value = serde_json::from_str(raw).ok()?;
        let obj = value.as_object()?;
        // Unknown fields reject: the published schema is the contract.
        let known = ["v", "ec", "qe", "ft", "pt", "n"];
        for key in obj.keys() {
            if !known.contains(&key.as_str()) {
                return None;
            }
        }
        let payload: TelemetryPayloadV1 = serde_json::from_value(value).ok()?;
        let payload = payload.validate()?;
        Some(payload)
    }

    /// Applies every range rule the schema publishes, including the
    /// collector invariant: every counted event increments exactly one
    /// class and the sample count, so the class counts must sum to `n`.
    fn validate(self) -> Option<TelemetryPayloadV1> {
        if self.v != PAYLOAD_VERSION {
            return None;
        }
        let cap = i64::from(EVIDENCE_CONSTS_TABLE.sample_cap);
        if self.qe < 0 || self.qe > i64::from(EVIDENCE_CONSTS_TABLE.entropy_max) {
            return None;
        }
        if self.ft < 0 || self.ft > cap {
            return None;
        }
        if self.pt < 0 || self.pt > i64::from(EVIDENCE_CONSTS_TABLE.score_saturation) {
            return None;
        }
        if self.n < 0 || self.n > cap {
            return None;
        }
        for count in [self.ec.fo, self.ec.ke, self.ec.pa, self.ec.po, self.ec.fm] {
            if count < 0 || count > cap {
                return None;
            }
        }
        if self.ec.fo + self.ec.ke + self.ec.pa + self.ec.po + self.ec.fm != self.n {
            return None;
        }
        Some(self)
    }
}

/// The per-request evidence inputs the engine hands the stage, derived
/// from the additive risk-v2 context (the token payload and the solved
/// rung facts).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvidenceInputs {
    /// The interaction anomaly (0..=1000) when a valid payload is
    /// present; `None` for an absent or rejected payload (the
    /// neutral-unknown state, never negative).
    pub interaction: Option<u16>,
    /// The solve anomaly (0..=1000) when solve facts are present;
    /// `None` otherwise.
    pub solve: Option<u16>,
}

impl EvidenceInputs {
    /// True when the inputs carry no evidence at all.
    pub fn is_empty(&self) -> bool {
        self.interaction.is_none() && self.solve.is_none()
    }
}

/// The interaction anomaly (0..=1000) of one validated payload, or
/// `None` for an absent or rejected payload.
///
/// The mix: the entropy term (400 per-mille, only at the minimum-sample
/// count, which equals the payload cap), the focus-transition term
/// (200) and the paste term (400), scaled by how much of the cap the
/// session actually produced. Integer division everywhere, identical in
/// the PHP mirror.
pub fn interaction_anomaly(payload: Option<&TelemetryPayloadV1>) -> Option<u16> {
    let payload = payload?;
    let c = &EVIDENCE_CONSTS_TABLE;
    let scale = (payload.n.min(i64::from(c.sample_cap)) as u32 * 1000) / c.sample_cap;
    let entropy_term = if payload.n >= i64::from(c.entropy_min_samples) {
        ((c.entropy_max - payload.qe as u32) * 1000) / c.entropy_max
    } else {
        0
    };
    let focus_term = if payload.ec.fm > 0 && payload.ft == 0 {
        1000
    } else {
        0
    };
    let input_volume = (payload.ec.ke + payload.ec.pa) as u32;
    let paste_term = if input_volume >= c.paste_volume_floor
        && payload.ec.pa > 0
        && payload.pt >= i64::from(c.paste_ratio_edge)
    {
        c.paste_anomaly_value
    } else {
        0
    };
    let weighted_mille =
        entropy_term * c.entropy_weight + focus_term * c.focus_weight + paste_term * c.paste_weight;
    let anomaly = weighted_mille * scale / 1_000_000;
    Some(anomaly.min(c.score_saturation) as u16)
}

/// The fastest-device reference (milliseconds) for a rung key, or
/// `None` for a rung the table does not carry (the signal is then
/// neutral: an unknown rung must never fabricate evidence).
pub fn p1_ms(rung: &str) -> Option<u64> {
    EVIDENCE_P1_MS
        .iter()
        .find(|(key, _)| *key == rung)
        .map(|(_, ms)| *ms)
}

/// The solve anomaly (0..=1000) of one solve: the measured solve time
/// against the fastest qualified-device reference for the rung, clamped.
/// A solve at or above the reference scores zero; each per-mille of the
/// reference the solve beats adds one point of anomaly; an instant
/// solve saturates. `None` solve facts score zero (neutral), and an
/// unknown rung scores zero rather than fabricating evidence.
pub fn solve_anomaly(solve_ms: Option<u64>, rung: Option<&str>) -> u16 {
    let (Some(solve_ms), Some(rung)) = (solve_ms, rung) else {
        return 0;
    };
    let Some(reference) = p1_ms(rung) else {
        return 0;
    };
    let c = &EVIDENCE_CONSTS_TABLE;
    let solve_ms = solve_ms.min(c.max_solve_ms);
    let ratio_mille = (solve_ms * 1000 / reference) as u32;
    if ratio_mille >= c.solve_ratio_saturation_mille {
        return 0;
    }
    (c.solve_ratio_saturation_mille - ratio_mille).min(c.score_saturation) as u16
}

/// Derives the stage inputs from the additive context pieces (payload
/// text plus solve facts). An invalid payload is the neutral-unknown
/// state, never an error and never a negative signal.
pub fn evidence_inputs(
    telemetry_payload: Option<&str>,
    solve_ms: Option<u64>,
    solve_rung: Option<&str>,
) -> EvidenceInputs {
    let payload = telemetry_payload.and_then(TelemetryPayloadV1::parse);
    EvidenceInputs {
        interaction: interaction_anomaly(payload.as_ref()),
        solve: {
            let anomaly = solve_anomaly(solve_ms, solve_rung);
            if solve_ms.is_some() && solve_rung.is_some() {
                Some(anomaly)
            } else {
                None
            }
        },
    }
}

/// The evidence stage: composes the plain decision (bands, floors,
/// overrides, hysteresis, marks) with the interaction and solve
/// evidence. Below the first band edge nothing fired and the decision
/// passes through byte-identically. At or above it the evidence has
/// fired: the stage reasons prepend (marks-style), and the action rises
/// to the band rung when that exceeds the composed action, so a deny is
/// never softened and a stronger rung never lowered. The stage never
/// rises past the first argon rung, and an argon band rung on a
/// saturated backend re-escalates to the interactive step-up exactly
/// like the policy's own capacity check.
///
/// Pure; the decision's score, band, policy version, model revision,
/// global level and decision id pass through untouched. Stage reasons
/// prepend exactly like the policy's hard overrides, then deduplicate
/// and cap at 4.
pub fn apply(
    plain: RiskDecision,
    inputs: &EvidenceInputs,
    resources: &ResourcePressure,
) -> RiskDecision {
    let c = &EVIDENCE_CONSTS_TABLE;
    let interaction = u32::from(inputs.interaction.unwrap_or(0));
    let solve = u32::from(inputs.solve.unwrap_or(0));
    let combined = (weighted(interaction, c.interaction_weight) + weighted(solve, c.solve_weight))
        .min(c.score_saturation) as u16;
    let mut edge = None;
    for (index, bound) in c.band_edges.iter().enumerate() {
        if combined >= *bound {
            edge = Some(index);
        }
    }
    let Some(index) = edge else {
        return plain;
    };
    let mut stage_reasons = Vec::new();
    if inputs.interaction.unwrap_or(0) > 0 {
        stage_reasons.push(RiskReason::InteractionAnomaly);
    }
    if inputs.solve.unwrap_or(0) > 0 {
        stage_reasons.push(RiskReason::SolveAnomaly);
    }
    let rung = BAND_RUNGS[index];
    let mut decision = plain;
    if rung.rank() > decision.action.rank() {
        decision.action = rung;
        if rung.is_argon()
            && resources.argon_capacity < crate::pricing::PRICE_CONSTS.argon_capacity_floor
        {
            decision.action = RiskAction::StepUp;
            stage_reasons.push(RiskReason::CapacityPressure);
        }
    }
    merge_stage_reasons(&mut decision, stage_reasons);
    decision
}

/// `(v * w) / 1000` with a saturating product (the shared fixed-point
/// weighted helper, identical to the scorer's).
fn weighted(value: u32, weight: u32) -> u32 {
    value.saturating_mul(weight) / 1000
}

/// Prepends the stage reasons to the decision's reasons, deduplicates
/// and caps at 4 (the policy's own assembly order).
fn merge_stage_reasons(decision: &mut RiskDecision, stage_reasons: Vec<RiskReason>) {
    if stage_reasons.is_empty() {
        return;
    }
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

    /// A valid payload with the class counts summing to `n` (the
    /// collector invariant the schema enforces).
    fn payload(qe: i64, ft: i64, pt: i64, n: i64) -> TelemetryPayloadV1 {
        TelemetryPayloadV1 {
            v: PAYLOAD_VERSION,
            ec: EventClassCounts {
                fo: 2,
                ke: 2,
                pa: 0,
                po: 2,
                fm: n - 6,
            },
            qe,
            ft,
            pt,
            n,
        }
    }

    #[test]
    fn consts_table_is_pinned() {
        assert_eq!(EVIDENCE_CONSTS_TABLE.version, 1);
        assert_eq!(EVIDENCE_CONSTS_TABLE.sample_cap, 32);
        assert_eq!(EVIDENCE_CONSTS_TABLE.entropy_min_samples, 32);
        assert_eq!(EVIDENCE_CONSTS_TABLE.band_edges, [150, 300, 500, 700]);
        assert_eq!(
            BAND_RUNGS,
            [
                RiskAction::Sha16,
                RiskAction::Sha18,
                RiskAction::Sha20,
                RiskAction::Argon16
            ]
        );
        // The no-dead-rule invariant: the entropy rule's minimum-sample
        // count equals the payload cap.
        assert_eq!(
            EVIDENCE_CONSTS_TABLE.entropy_min_samples, EVIDENCE_CONSTS_TABLE.sample_cap,
            "the entropy rule must stay exactly reachable at the payload cap"
        );
    }

    #[test]
    fn parse_accepts_the_published_shape() {
        let raw =
            r#"{"v":1,"ec":{"fo":6,"ke":10,"pa":0,"po":4,"fm":12},"qe":11,"ft":3,"pt":0,"n":32}"#;
        let payload = TelemetryPayloadV1::parse(raw).expect("valid payload");
        assert_eq!(payload.qe, 11);
        assert_eq!(payload.ec.ke, 10);
        assert_eq!(payload.n, 32);
    }

    #[test]
    fn parse_rejects_every_violation() {
        let rejects = [
            r#"{"v":2,"ec":{"fo":1,"ke":1,"pa":0,"po":0,"fm":1},"qe":5,"ft":1,"pt":0,"n":3}"#,
            r#"{"ec":{"fo":1,"ke":1,"pa":0,"po":0,"fm":1},"qe":5,"ft":1,"pt":0,"n":3}"#,
            r#"{"v":1,"ec":{"fo":1,"ke":1,"pa":0,"po":0,"fm":1},"ft":1,"pt":0,"n":3}"#,
            r#"{"v":1,"ec":{"fo":1,"ke":1,"pa":0,"po":0},"qe":5,"ft":1,"pt":0,"n":3}"#,
            r#"{"v":1,"ec":{"fo":1,"ke":1,"pa":0,"po":0,"fm":1},"qe":5,"ft":1,"pt":0,"n":3,"x":1}"#,
            r#"{"v":1,"ec":{"fo":1,"ke":1,"pa":0,"po":0,"fm":1},"qe":16,"ft":1,"pt":0,"n":3}"#,
            r#"{"v":1,"ec":{"fo":1,"ke":1,"pa":0,"po":0,"fm":1},"qe":5,"ft":1,"pt":1001,"n":3}"#,
            r#"{"v":1,"ec":{"fo":1,"ke":1,"pa":0,"po":0,"fm":1},"qe":5,"ft":1,"pt":0,"n":33}"#,
            r#"{"v":1,"ec":{"fo":1,"ke":40,"pa":0,"po":0,"fm":1},"qe":5,"ft":1,"pt":0,"n":32}"#,
            r#"{"v":1,"ec":{"fo":-1,"ke":1,"pa":0,"po":0,"fm":1},"qe":5,"ft":1,"pt":0,"n":3}"#,
            r#"{"v":1,"ec":{"fo":1,"ke":1,"pa":0,"po":0,"fm":1},"qe":5.5,"ft":1,"pt":0,"n":3}"#,
            r#"{"v":1,"ec":3,"qe":5,"ft":1,"pt":0,"n":3}"#,
            "[1,2,3]",
            "telemetry",
            "",
        ];
        for raw in rejects {
            assert!(
                TelemetryPayloadV1::parse(raw).is_none(),
                "expected reject: {raw}"
            );
        }
    }

    #[test]
    fn over_bound_payload_rejects() {
        let raw = format!("{{\"v\":1,\"ec\":{{\"fo\":1,\"ke\":{},\"pa\":0,\"po\":0,\"fm\":1}},\"qe\":5,\"ft\":1,\"pt\":0,\"n\":3}}", "1".repeat(MAX_PAYLOAD_BYTES));
        assert!(TelemetryPayloadV1::parse(&raw).is_none());
    }

    #[test]
    fn absent_and_rejected_payloads_are_neutral() {
        assert_eq!(interaction_anomaly(None), None);
        let inputs = evidence_inputs(Some("not json"), None, None);
        assert_eq!(inputs.interaction, None);
        assert!(inputs.is_empty());
        let inputs = evidence_inputs(None, None, None);
        assert_eq!(inputs.interaction, None);
        assert_eq!(inputs.solve, None);
    }

    #[test]
    fn human_and_agent_pins() {
        // Exact pins of the shared corpus ends: the highest human-band
        // vector and the lowest agent vector.
        let human = payload(10, 5, 0, 32);
        assert_eq!(interaction_anomaly(Some(&human)), Some(133));
        let agent = payload(0, 1, 0, 32);
        assert_eq!(interaction_anomaly(Some(&agent)), Some(400));
        let agent_no_focus = payload(0, 0, 0, 32);
        assert_eq!(interaction_anomaly(Some(&agent_no_focus)), Some(600));
    }

    #[test]
    fn entropy_term_ignores_thin_samples() {
        // Below the minimum-sample count the entropy term is zero even
        // at qe 0 (the rule is reachable exactly at the cap).
        let thin = payload(0, 2, 0, 31);
        assert_eq!(interaction_anomaly(Some(&thin)), Some(0));
        let at_cap = payload(0, 2, 0, 32);
        assert_eq!(interaction_anomaly(Some(&at_cap)), Some(400));
    }

    #[test]
    fn paste_term_requires_volume_and_ratio() {
        // One stray paste on thin input volume stays neutral.
        let stray = TelemetryPayloadV1 {
            v: PAYLOAD_VERSION,
            ec: EventClassCounts {
                fo: 1,
                ke: 2,
                pa: 1,
                po: 0,
                fm: 0,
            },
            qe: 15,
            ft: 1,
            pt: 1000,
            n: 4,
        };
        assert_eq!(interaction_anomaly(Some(&stray)), Some(0));
        // All-paste input at real volume with machine entropy fires.
        let all_paste = TelemetryPayloadV1 {
            v: PAYLOAD_VERSION,
            ec: EventClassCounts {
                fo: 1,
                ke: 0,
                pa: 16,
                po: 1,
                fm: 14,
            },
            qe: 3,
            ft: 1,
            pt: 1000,
            n: 32,
        };
        assert_eq!(interaction_anomaly(Some(&all_paste)), Some(640));
    }

    #[test]
    fn solve_anomaly_vectors() {
        assert_eq!(solve_anomaly(Some(0), Some("sha18")), 1000);
        assert_eq!(solve_anomaly(Some(13), Some("sha18")), 519);
        assert_eq!(solve_anomaly(Some(27), Some("sha18")), 0);
        assert_eq!(solve_anomaly(Some(100), Some("sha18")), 0);
        assert_eq!(solve_anomaly(Some(0), Some("sha20")), 1000);
        assert_eq!(solve_anomaly(Some(40), Some("argon16")), 535);
        assert_eq!(solve_anomaly(Some(86), Some("argon16")), 0);
        assert_eq!(solve_anomaly(Some(400), Some("rsw150k")), 75);
        assert_eq!(solve_anomaly(Some(432), Some("rsw150k")), 0);
        assert_eq!(solve_anomaly(Some(11), Some("sha16")), 522);
        // Unknown rung: neutral, never fabricated evidence.
        assert_eq!(solve_anomaly(Some(0), Some("sha17")), 0);
        // Absent facts: neutral.
        assert_eq!(solve_anomaly(None, Some("sha18")), 0);
        assert_eq!(solve_anomaly(Some(0), None), 0);
        // Over-domain input clamps.
        assert_eq!(solve_anomaly(Some(u64::MAX), Some("sha16")), 0);
    }

    #[test]
    fn p1_table_covers_the_published_ladder() {
        for (key, ms) in EVIDENCE_P1_MS {
            assert!(*ms > 0, "{key} reference must be positive");
        }
        assert_eq!(p1_ms("rsw300k"), Some(810));
        assert_eq!(p1_ms("unknown"), None);
    }

    #[test]
    fn evidence_inputs_derive_both_signals() {
        let raw =
            r#"{"v":1,"ec":{"fo":0,"ke":16,"pa":0,"po":0,"fm":16},"qe":0,"ft":1,"pt":0,"n":32}"#;
        let inputs = evidence_inputs(Some(raw), Some(100), Some("sha18"));
        assert_eq!(inputs.interaction, Some(400));
        assert_eq!(inputs.solve, Some(0));
        // Half-present solve facts are the absent state, never an error.
        let inputs = evidence_inputs(None, Some(100), None);
        assert_eq!(inputs.solve, None);
        assert!(inputs.is_empty());
    }
}
