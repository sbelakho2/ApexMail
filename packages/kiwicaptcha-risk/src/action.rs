//! Ordered risk actions, fixed by the cross-language risk-v1 contract.
//!
//! The ordering (Allow < Sha16 < Sha18 < Sha20 < Argon16 < Argon32 <
//! Argon64 < Rsw < StepUp < Deny) is the escalation ladder; `rank()` is
//! strictly monotonic and is the only comparison that may be used to
//! combine actions (score bands, scope minima, global floors).

use serde::{Deserialize, Serialize};

/// The risk action ladder. JSON values are lowercase strings matching the
/// PHP enum values (`step_up` for the StepUp case, `rsw` for the Rsw
/// time-lock rung).
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
    Rsw,
    StepUp,
    Deny,
}

impl RiskAction {
    /// Strictly monotonic escalation rank: Allow = 0 … Deny = 9.
    pub fn rank(self) -> u8 {
        match self {
            RiskAction::Allow => 0,
            RiskAction::Sha16 => 1,
            RiskAction::Sha18 => 2,
            RiskAction::Sha20 => 3,
            RiskAction::Argon16 => 4,
            RiskAction::Argon32 => 5,
            RiskAction::Argon64 => 6,
            RiskAction::Rsw => 7,
            RiskAction::StepUp => 8,
            RiskAction::Deny => 9,
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
            RiskAction::Rsw => "rsw",
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

    /// True for the rungs the argon-capacity checks re-escalate to the
    /// interactive step-up under a saturated backend: the three
    /// memory-hard actions plus the sequential rsw rung. The capacity
    /// floor must never leave a decision demanding work the backend
    /// cannot serve — an rsw decision under argon saturation therefore
    /// escalates to StepUp exactly like an argon rung, never weakens.
    pub fn is_capacity_gated(self) -> bool {
        self.is_argon() || self == RiskAction::Rsw
    }

    /// The decision boundary between the last SHA band and the first
    /// Argon band: the score where the default ladder leaves sha20
    /// (450..=599) and enters argon16 (600..=749). The calibration error
    /// is measured relative to this boundary (calibration.lua's
    /// boundary_T, which is this same value), so the two cores must never
    /// disagree about it; `boundary_is_the_sha20_argon16_edge` pins the
    /// mapping.
    pub const DECISION_BOUNDARY_SCORE: u16 = 600;

    /// Default score bands (configurable in policy; hard floors apply on
    /// top). The rsw band splits the former step-up band: 930..=954 is
    /// the sequential time-lock rung, 955..=979 stays the interactive
    /// step-up.
    pub fn action_for_score(score: u16) -> RiskAction {
        match score {
            0..=149 => RiskAction::Allow,
            150..=299 => RiskAction::Sha16,
            300..=449 => RiskAction::Sha18,
            450..=599 => RiskAction::Sha20,
            600..=749 => RiskAction::Argon16,
            750..=849 => RiskAction::Argon32,
            850..=929 => RiskAction::Argon64,
            930..=954 => RiskAction::Rsw,
            955..=979 => RiskAction::StepUp,
            _ => RiskAction::Deny,
        }
    }
}

impl std::str::FromStr for RiskAction {
    type Err = ();

    fn from_str(s: &str) -> Result<RiskAction, ()> {
        match s {
            "allow" => Ok(RiskAction::Allow),
            "sha16" => Ok(RiskAction::Sha16),
            "sha18" => Ok(RiskAction::Sha18),
            "sha20" => Ok(RiskAction::Sha20),
            "argon16" => Ok(RiskAction::Argon16),
            "argon32" => Ok(RiskAction::Argon32),
            "argon64" => Ok(RiskAction::Argon64),
            "rsw" => Ok(RiskAction::Rsw),
            "step_up" => Ok(RiskAction::StepUp),
            "deny" => Ok(RiskAction::Deny),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_is_the_sha20_argon16_edge() {
        // calibration.lua's boundary_T and the Rust calibration tests use
        // this exact score; the ladder must agree at the edge.
        assert_eq!(RiskAction::action_for_score(599), RiskAction::Sha20);
        assert_eq!(
            RiskAction::action_for_score(RiskAction::DECISION_BOUNDARY_SCORE),
            RiskAction::Argon16
        );
        assert_eq!(RiskAction::DECISION_BOUNDARY_SCORE, 600);
    }

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
            (930, RiskAction::Rsw),
            (954, RiskAction::Rsw),
            (955, RiskAction::StepUp),
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
            RiskAction::Rsw,
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
        assert_eq!(RiskAction::Argon64.as_str(), "argon64");
        assert_eq!(RiskAction::Rsw.as_str(), "rsw");
        assert_eq!(RiskAction::StepUp.as_str(), "step_up");
        assert_eq!(RiskAction::Deny.as_str(), "deny");
        assert_eq!(
            serde_json::to_value(RiskAction::StepUp).unwrap(),
            serde_json::json!("step_up")
        );
        assert_eq!(
            serde_json::to_value(RiskAction::Rsw).unwrap(),
            serde_json::json!("rsw")
        );
        assert_eq!("rsw".parse::<RiskAction>(), Ok(RiskAction::Rsw));
    }

    #[test]
    fn argon_detection() {
        assert!(RiskAction::Argon16.is_argon());
        assert!(RiskAction::Argon32.is_argon());
        assert!(RiskAction::Argon64.is_argon());
        assert!(!RiskAction::Sha20.is_argon());
        assert!(!RiskAction::Rsw.is_argon());
        assert!(!RiskAction::Deny.is_argon());
    }

    /// The capacity gate covers exactly the rungs a saturated backend
    /// must not be asked to serve: the three argon rungs and the rsw
    /// time-lock rung, never the interactive step-up or deny.
    #[test]
    fn capacity_gate_covers_argon_and_rsw() {
        for action in [
            RiskAction::Argon16,
            RiskAction::Argon32,
            RiskAction::Argon64,
            RiskAction::Rsw,
        ] {
            assert!(action.is_capacity_gated(), "{action:?}");
        }
        for action in [
            RiskAction::Allow,
            RiskAction::Sha16,
            RiskAction::Sha18,
            RiskAction::Sha20,
            RiskAction::StepUp,
            RiskAction::Deny,
        ] {
            assert!(!action.is_capacity_gated(), "{action:?}");
        }
    }
}
