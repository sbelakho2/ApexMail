//! Ordered risk actions, fixed by the cross-language risk-v1 contract.
//!
//! The ordering (Allow < Sha16 < Sha18 < Sha20 < Argon16 < Argon32 <
//! Argon64 < StepUp < Deny) is the escalation ladder; `rank()` is strictly
//! monotonic and is the only comparison that may be used to combine actions
//! (score bands, scope minima, global floors).

use serde::{Deserialize, Serialize};

/// The risk action ladder. JSON values are lowercase strings matching the
/// PHP enum values (`step_up` for the StepUp case).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RiskAction {
    #[default]
    Allow,
    Sha16,
    Sha18,
    Sha20,
    Argon16,
    Argon32,
    Argon64,
    StepUp,
    Deny,
}

impl RiskAction {
    /// Strictly monotonic escalation rank: Allow = 0 … Deny = 8.
    pub fn rank(self) -> u8 {
        match self {
            RiskAction::Allow => 0,
            RiskAction::Sha16 => 1,
            RiskAction::Sha18 => 2,
            RiskAction::Sha20 => 3,
            RiskAction::Argon16 => 4,
            RiskAction::Argon32 => 5,
            RiskAction::Argon64 => 6,
            RiskAction::StepUp => 7,
            RiskAction::Deny => 8,
        }
    }

    /// Wire string value (matches the serde representation).
    pub fn as_str(self) -> &'static str {
        match self {
            RiskAction::Allow => "allow",
            RiskAction::Sha16 => "sha16",
            RiskAction::Sha18 => "sha18",
            RiskAction::Sha20 => "sha20",
            RiskAction::Argon16 => "argon16",
            RiskAction::Argon32 => "argon32",
            RiskAction::Argon64 => "argon64",
            RiskAction::StepUp => "step_up",
            RiskAction::Deny => "deny",
        }
    }

    /// True for the three memory-hard actions.
    pub fn is_argon(self) -> bool {
        matches!(
            self,
            RiskAction::Argon16 | RiskAction::Argon32 | RiskAction::Argon64
        )
    }

    /// Default score bands (configurable in policy; hard floors apply on
    /// top).
    pub fn action_for_score(score: u16) -> RiskAction {
        match score {
            0..=149 => RiskAction::Allow,
            150..=299 => RiskAction::Sha16,
            300..=449 => RiskAction::Sha18,
            450..=599 => RiskAction::Sha20,
            600..=749 => RiskAction::Argon16,
            750..=849 => RiskAction::Argon32,
            850..=929 => RiskAction::Argon64,
            930..=979 => RiskAction::StepUp,
            _ => RiskAction::Deny,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_band_boundary() {
        let cases = [
            (0, RiskAction::Allow),
            (149, RiskAction::Allow),
            (150, RiskAction::Sha16),
            (299, RiskAction::Sha16),
            (300, RiskAction::Sha18),
            (449, RiskAction::Sha18),
            (450, RiskAction::Sha20),
            (599, RiskAction::Sha20),
            (600, RiskAction::Argon16),
            (749, RiskAction::Argon16),
            (750, RiskAction::Argon32),
            (849, RiskAction::Argon32),
            (850, RiskAction::Argon64),
            (929, RiskAction::Argon64),
            (930, RiskAction::StepUp),
            (979, RiskAction::StepUp),
            (980, RiskAction::Deny),
            (1000, RiskAction::Deny),
        ];
        for (score, expected) in cases {
            assert_eq!(
                RiskAction::action_for_score(score),
                expected,
                "score {score}"
            );
        }
    }

    #[test]
    fn rank_is_strictly_monotonic_in_enum_order() {
        let ladder = [
            RiskAction::Allow,
            RiskAction::Sha16,
            RiskAction::Sha18,
            RiskAction::Sha20,
            RiskAction::Argon16,
            RiskAction::Argon32,
            RiskAction::Argon64,
            RiskAction::StepUp,
            RiskAction::Deny,
        ];
        for (i, action) in ladder.iter().enumerate() {
            assert_eq!(action.rank(), i as u8);
        }
    }

    #[test]
    fn wire_values_match_php() {
        assert_eq!(RiskAction::Allow.as_str(), "allow");
        assert_eq!(RiskAction::Sha16.as_str(), "sha16");
        assert_eq!(RiskAction::Sha20.as_str(), "sha20");
        assert_eq!(RiskAction::Argon16.as_str(), "argon16");
        assert_eq!(RiskAction::StepUp.as_str(), "step_up");
        assert_eq!(RiskAction::Deny.as_str(), "deny");
        assert_eq!(
            serde_json::to_value(RiskAction::StepUp).unwrap(),
            serde_json::json!("step_up")
        );
    }

    #[test]
    fn argon_detection() {
        assert!(RiskAction::Argon16.is_argon());
        assert!(RiskAction::Argon32.is_argon());
        assert!(RiskAction::Argon64.is_argon());
        assert!(!RiskAction::Sha20.is_argon());
        assert!(!RiskAction::Deny.is_argon());
    }
}
