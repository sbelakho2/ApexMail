//! Risk event kinds, fixed by the cross-language risk-v1 contract.
//!
//! Values 1..14 are authoritative and MUST NOT be renumbered: they are the
//! event identifiers passed into the canonical state script (`risk.lua`) and
//! must be byte-identical across the PHP and Rust implementations.

use serde::{Deserialize, Serialize};

/// The fixed risk event kinds of the risk-v1 contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum RiskEventKind {
    PreIssue = 1,
    ChallengeIssued = 2,
    SolveSuccess = 3,
    InvalidProof = 4,
    MalformedToken = 5,
    ExpiredChallenge = 6,
    ReplayAttempt = 7,
    ProtectedActionSuccess = 8,
    ProtectedActionFailure = 9,
    AuthenticationSuccess = 10,
    AuthenticationFailure = 11,
    ConfirmedLegitimate = 12,
    ConfirmedAbuse = 13,
    RateLimitHit = 14,
}

impl RiskEventKind {
    /// All fourteen kinds, in contract value order.
    pub const ALL: [RiskEventKind; 14] = [
        RiskEventKind::PreIssue,
        RiskEventKind::ChallengeIssued,
        RiskEventKind::SolveSuccess,
        RiskEventKind::InvalidProof,
        RiskEventKind::MalformedToken,
        RiskEventKind::ExpiredChallenge,
        RiskEventKind::ReplayAttempt,
        RiskEventKind::ProtectedActionSuccess,
        RiskEventKind::ProtectedActionFailure,
        RiskEventKind::AuthenticationSuccess,
        RiskEventKind::AuthenticationFailure,
        RiskEventKind::ConfirmedLegitimate,
        RiskEventKind::ConfirmedAbuse,
        RiskEventKind::RateLimitHit,
    ];

    /// The contract integer value (1..14), as passed to the Lua script.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Inverse of [`RiskEventKind::as_u8`]; `None` for values outside 1..14.
    pub fn from_u8(value: u8) -> Option<RiskEventKind> {
        match value {
            1 => Some(RiskEventKind::PreIssue),
            2 => Some(RiskEventKind::ChallengeIssued),
            3 => Some(RiskEventKind::SolveSuccess),
            4 => Some(RiskEventKind::InvalidProof),
            5 => Some(RiskEventKind::MalformedToken),
            6 => Some(RiskEventKind::ExpiredChallenge),
            7 => Some(RiskEventKind::ReplayAttempt),
            8 => Some(RiskEventKind::ProtectedActionSuccess),
            9 => Some(RiskEventKind::ProtectedActionFailure),
            10 => Some(RiskEventKind::AuthenticationSuccess),
            11 => Some(RiskEventKind::AuthenticationFailure),
            12 => Some(RiskEventKind::ConfirmedLegitimate),
            13 => Some(RiskEventKind::ConfirmedAbuse),
            14 => Some(RiskEventKind::RateLimitHit),
            _ => None,
        }
    }
}

/// One immutable observation applied atomically to the risk state.
///
/// `source_id`/`subnet_id` are 128-bit pseudonyms from the identity module;
/// `session_id`/`principal_id` are the same, or `None` when the request
/// carries no session/principal. `event_id` is 16 random bytes and is the
/// dedupe key: an identical event_id never double-increments the state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskObservation {
    pub event: RiskEventKind,
    pub scope: u16,
    pub source_id: [u8; 16],
    pub subnet_id: [u8; 16],
    pub session_id: Option<[u8; 16]>,
    pub principal_id: Option<[u8; 16]>,
    pub event_id: [u8; 16],
    /// Classifier-derived network risk (0..1000), side-channel into the
    /// Lua's reserved `network_risk` slot.
    pub network_risk: u16,
    /// Server clock, epoch milliseconds.
    pub now_ms: u64,
}

impl Default for RiskObservation {
    fn default() -> Self {
        RiskObservation {
            event: RiskEventKind::PreIssue,
            scope: 0,
            source_id: [0u8; 16],
            subnet_id: [0u8; 16],
            session_id: None,
            principal_id: None,
            event_id: [0u8; 16],
            network_risk: 0,
            now_ms: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_values_are_stable() {
        let expected = [
            (1, "pre_issue"),
            (2, "challenge_issued"),
            (3, "solve_success"),
            (4, "invalid_proof"),
            (5, "malformed_token"),
            (6, "expired_challenge"),
            (7, "replay_attempt"),
            (8, "protected_action_success"),
            (9, "protected_action_failure"),
            (10, "authentication_success"),
            (11, "authentication_failure"),
            (12, "confirmed_legitimate"),
            (13, "confirmed_abuse"),
            (14, "rate_limit_hit"),
        ];
        for (i, (value, name)) in expected.iter().enumerate() {
            let kind = RiskEventKind::ALL[i];
            assert_eq!(kind.as_u8(), *value);
            assert_eq!(RiskEventKind::from_u8(*value), Some(kind));
            assert_eq!(serde_json::to_value(kind).unwrap(), serde_json::json!(name));
        }
        assert_eq!(RiskEventKind::from_u8(0), None);
        assert_eq!(RiskEventKind::from_u8(15), None);
    }

    #[test]
    fn observation_defaults_to_pre_issue() {
        let o = RiskObservation::default();
        assert_eq!(o.event, RiskEventKind::PreIssue);
        assert_eq!(o.scope, 0);
        assert_eq!(o.source_id, [0u8; 16]);
        assert_eq!(o.session_id, None);
        assert_eq!(o.network_risk, 0);
    }
}
