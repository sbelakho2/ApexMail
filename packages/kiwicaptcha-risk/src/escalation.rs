//! Decoy escalation (change.md 3.2.2): the additive post-marks
//! decision stage that raises a session's price by one rung for the
//! escalation window after a confirmed decoy hit, plus the reader seam
//! the engine wires the stage through. The evidence stage composes
//! right after it, so the two raises stack before the pricing stage.
//!
//! An escalation, never a block: the raise caps at the interactive
//! step-up, so a Deny never deepens and the strongest outcome stays the
//! step-up. The window is carried by the store record's TTL (the
//! canonical decoy_escalation.lua writes a 10-minute record); the stage
//! itself is a pure one-rung raise over whatever the pipeline has
//! already composed.
//!
//! The gate is part of the contract, not a deployment afterthought: the
//! canonical script (protocol/risk-v1/decoy_escalation.lua, embedded
//! here as [`DECOY_ESCALATION_LUA`]) refuses the record op unless the
//! caller passes the autofill-qualification gate as open, and the gate
//! is open only when the qualification matrix
//! (tests/browser/qualification/autofill-matrix.json) passes every
//! required surface. Until then the write path writes nothing, so a
//! password manager can never trip the escalation on a real user.

use std::net::IpAddr;

use crate::action::RiskAction;
use crate::policy::RiskReason;
use crate::RiskDecision;

/// The canonical decoy-escalation script (byte-identical across the
/// three shipped copies: protocol/risk-v1/, this package's resources/
/// and the PHP package's resources/).
pub const DECOY_ESCALATION_LUA: &str = include_str!("../resources/decoy_escalation.lua");

/// The escalation window: 10 minutes in milliseconds (the record TTL
/// the canonical script is invoked with).
pub const ESCALATION_TTL_MS: u64 = 600_000;

/// The reader seam of the engine wiring (the marks-reader precedent):
/// answers whether the session's decoy escalation is live. An
/// unreadable surface degrades to not-live: the stage is a temporary
/// price raise, so a backend miss must never escalate anyone.
pub trait DecoyEscalationReader: Send + Sync {
    /// True when the session carries a live escalation record. `None`
    /// session (no session dimension on the request) answers false.
    fn escalation_live(&self, session: Option<&str>) -> bool;
}

/// The request identity picture the engine hands the reader (the same
/// shape the marks and pricing readers receive).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoyEscalationRequest {
    pub scope: u32,
    pub source_ip: IpAddr,
    /// The session pseudonym (32 hex chars), or `None` without a session.
    pub session: Option<String>,
}

/// The decoy-escalation stage: raises the composed action by exactly
/// one ladder rung, capped at the interactive step-up. Pure; the score,
/// band, policy version, model revision, global level and decision id
/// pass through untouched. The stage reason prepends exactly like the
/// policy's hard overrides, then deduplicates and caps at 4.
pub fn apply(plain: RiskDecision, live: bool) -> RiskDecision {
    if !live {
        return plain;
    }
    let mut decision = plain;
    let next_rank = decision.action.rank() + 1;
    let next = if next_rank >= RiskAction::Deny.rank() {
        RiskAction::StepUp
    } else {
        rung_at_rank(next_rank)
    };
    if next.rank() <= decision.action.rank() {
        return decision;
    }
    decision.action = next;
    let mut reasons = vec![RiskReason::DecoyEscalation];
    reasons.extend(decision.reasons_vec());
    let mut seen = std::collections::HashSet::new();
    reasons.retain(|reason| seen.insert(*reason));
    reasons.truncate(4);
    let mut out = [None; 4];
    for (slot, reason) in out.iter_mut().zip(reasons) {
        *slot = Some(reason);
    }
    decision.reasons = out;
    decision
}

/// The ladder rung at a rank (the inverse of [`RiskAction::rank`] for
/// the raise path; the rank always comes from a real rung).
fn rung_at_rank(rank: u8) -> RiskAction {
    match rank {
        0 => RiskAction::Allow,
        1 => RiskAction::Sha16,
        2 => RiskAction::Sha18,
        3 => RiskAction::Sha20,
        4 => RiskAction::Argon16,
        5 => RiskAction::Argon32,
        6 => RiskAction::Argon64,
        7 => RiskAction::StepUp,
        _ => RiskAction::Deny,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::RiskPolicy;
    use crate::resources::ResourcePressure;
    use crate::signals::SignalVector;
    use serde_json::json;

    const T0: u64 = 1_700_000_000_000;

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

    fn plain(score: u16) -> RiskDecision {
        policy().decide(
            1,
            score,
            &SignalVector::zero(),
            &ResourcePressure::default(),
            0,
            T0,
            0,
        )
    }

    #[test]
    fn embedded_script_is_the_canonical_copy() {
        // The resources copy must stay byte-identical to the protocol
        // asset (the same parity the other Lua scripts keep).
        let canonical = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/risk-v1/decoy_escalation.lua"
        );
        let raw = std::fs::read_to_string(canonical).expect("protocol copy readable");
        assert_eq!(raw, DECOY_ESCALATION_LUA);
    }

    #[test]
    fn not_live_passes_through() {
        let base = plain(500);
        let out = apply(base.clone(), false);
        assert_eq!(out.action, base.action);
        assert_eq!(out.reasons, base.reasons);
    }

    #[test]
    fn live_raises_exactly_one_rung() {
        let out = apply(plain(100), true);
        assert_eq!(out.action, RiskAction::Sha16);
        assert!(out.has_reason(RiskReason::DecoyEscalation));
        let out = apply(plain(500), true);
        assert_eq!(out.action, RiskAction::Argon16);
        let out = apply(plain(900), true);
        assert_eq!(out.action, RiskAction::StepUp);
    }

    #[test]
    fn escalation_never_blocks() {
        // StepUp stays StepUp and Deny never deepens: the raise caps at
        // the interactive step-up.
        let out = apply(plain(950), true);
        assert_eq!(out.action, RiskAction::StepUp);
        let deny = plain(990);
        let out = apply(deny.clone(), true);
        assert_eq!(out.action, RiskAction::Deny);
        assert_eq!(out.reasons, deny.reasons);
    }

    #[test]
    fn stage_fields_pass_through() {
        let base = plain(500);
        let out = apply(base.clone(), true);
        assert_eq!(out.score, base.score);
        assert_eq!(out.band, base.band);
        assert_eq!(out.policy_version, base.policy_version);
        assert_eq!(out.model_revision, base.model_revision);
        assert_eq!(out.global_level, base.global_level);
        assert_eq!(out.decision_id, base.decision_id);
    }

    #[test]
    fn ttl_constant_is_the_ten_minute_window() {
        assert_eq!(ESCALATION_TTL_MS, 600_000);
    }
}
