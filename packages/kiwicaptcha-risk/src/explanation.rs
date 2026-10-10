//! The names-only decision explanation (change.md 3.8.3).
//!
//! A decision log carries the top contributing reasons, the identity
//! dimensions involved, the chosen action and, when a pricing stage is
//! composed, the chosen price rung. Every field is a name: reason
//! identifiers, dimension names, action and rung names. Pseudonym
//! values, raw identifiers and HMAC digests have no path into this
//! type, so a serialized explanation cannot leak them by construction.

use serde::ser::{Serialize, SerializeStruct, Serializer};

use crate::action::RiskAction;
use crate::identity_vector::DIMENSIONS;
use crate::policy::RiskReason;
use crate::RiskDecision;

/// The names-only explanation of one decision: the top contributors
/// (the decision's reason vector, at most four), the contract names of
/// the identity dimensions involved, the chosen action and the chosen
/// price rung when a pricing stage is composed.
///
/// The default is the names-only empty explanation (no reasons, no
/// dimensions, no rung): consumers that never compose an explanation
/// keep working unchanged. Dimension names outside the contract
/// vocabulary are dropped at construction, so an unknown name can
/// never smuggle a value onto the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionExplanation {
    action: RiskAction,
    reasons: Vec<RiskReason>,
    dimensions: Vec<&'static str>,
    price_rung: Option<&'static str>,
}

impl Default for DecisionExplanation {
    /// The names-only empty explanation; see [`DecisionExplanation`].
    fn default() -> DecisionExplanation {
        DecisionExplanation {
            action: RiskAction::Allow,
            reasons: Vec::new(),
            dimensions: Vec::new(),
            price_rung: None,
        }
    }
}

impl DecisionExplanation {
    /// The names-only empty explanation (allow, nothing composed).
    pub fn empty() -> DecisionExplanation {
        DecisionExplanation::default()
    }

    /// Builds the explanation of an assessed decision. `dimensions`
    /// carries the contract names of the identity dimensions involved
    /// in the assessment (for example the present dimensions of the
    /// request's [`crate::identity_vector::IdentityVector`]);
    /// `price_rung` carries the rung name when a pricing stage chose
    /// one.
    pub fn for_decision(
        decision: &RiskDecision,
        dimensions: &[&'static str],
        price_rung: Option<&'static str>,
    ) -> DecisionExplanation {
        DecisionExplanation {
            action: decision.action,
            reasons: decision.reasons_vec(),
            dimensions: dimensions
                .iter()
                .copied()
                .filter(|name| DIMENSIONS.contains(name))
                .collect(),
            price_rung,
        }
    }

    /// True when nothing is composed (no reasons, no dimensions, no
    /// rung).
    pub fn is_empty(&self) -> bool {
        self.reasons.is_empty() && self.dimensions.is_empty() && self.price_rung.is_none()
    }

    /// The chosen action (name-only on the wire).
    pub fn action(&self) -> RiskAction {
        self.action
    }

    /// The top contributing reasons, in the decision's priority order.
    pub fn reasons(&self) -> &[RiskReason] {
        &self.reasons
    }

    /// The contract names of the identity dimensions involved.
    pub fn dimensions(&self) -> &[&'static str] {
        &self.dimensions
    }

    /// The chosen price rung name, when a pricing stage is composed.
    pub fn price_rung(&self) -> Option<&'static str> {
        self.price_rung
    }
}

impl Serialize for DecisionExplanation {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let reasons: Vec<&str> = self.reasons.iter().map(|r| r.as_str()).collect();
        let mut state = serializer.serialize_struct("DecisionExplanation", 4)?;
        state.serialize_field("action", self.action.as_str())?;
        state.serialize_field("reasons", &reasons)?;
        state.serialize_field("dimensions", &self.dimensions)?;
        state.serialize_field("price_rung", &self.price_rung)?;
        state.end()
    }
}

/// An assessed decision with its explanation attached: the additive
/// explanation surface of the engine's assess result. The serialized
/// form is the decision's public fields plus one `explanation` object,
/// so existing consumers of the decision JSON keep parsing unchanged.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ExplainedDecision {
    #[serde(flatten)]
    pub decision: RiskDecision,
    pub explanation: DecisionExplanation,
}

impl ExplainedDecision {
    /// Wraps an assessed decision with the explanation built from the
    /// given dimension names and optional price rung.
    pub fn new(
        decision: RiskDecision,
        dimensions: &[&'static str],
        price_rung: Option<&'static str>,
    ) -> ExplainedDecision {
        ExplainedDecision {
            explanation: DecisionExplanation::for_decision(&decision, dimensions, price_rung),
            decision,
        }
    }

    /// The names-only explanation.
    pub fn explanation(&self) -> &DecisionExplanation {
        &self.explanation
    }

    /// The wrapped decision.
    pub fn decision(&self) -> &RiskDecision {
        &self.decision
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_explanation_serializes_names_only() {
        let json = serde_json::to_value(DecisionExplanation::empty()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "action": "allow",
                "reasons": [],
                "dimensions": [],
                "price_rung": null,
            })
        );
    }

    #[test]
    fn unknown_dimension_names_are_dropped() {
        let decision = RiskDecision {
            score: 400,
            action: RiskAction::Sha20,
            reasons: [Some(RiskReason::SourceBurst), None, None, None],
            policy_version: 1,
            model_revision: 1,
            global_level: 0,
            retry_after_ms: None,
            band: 4,
            decision_id: String::new(),
            quarantined: false,
        };
        let explanation = DecisionExplanation::for_decision(
            &decision,
            &["source", "device", "agent"],
            Some("sha20"),
        );
        assert_eq!(explanation.dimensions(), &["source", "agent"]);
        assert_eq!(explanation.reasons(), &[RiskReason::SourceBurst]);
        assert_eq!(explanation.action(), RiskAction::Sha20);
        assert_eq!(explanation.price_rung(), Some("sha20"));
        assert!(!explanation.is_empty());
    }

    #[test]
    fn explained_decision_serializes_the_decision_plus_one_field() {
        let decision = RiskDecision {
            score: 100,
            action: RiskAction::Allow,
            reasons: [None, None, None, None],
            policy_version: 1,
            model_revision: 1,
            global_level: 0,
            retry_after_ms: None,
            band: 1,
            decision_id: String::new(),
            quarantined: false,
        };
        let explained = ExplainedDecision::new(decision, &["source"], None);
        let json = serde_json::to_value(&explained).unwrap();
        // The decision's public fields survive unchanged and the
        // explanation rides as the single additive field. The quarantine
        // flag is the decision's ninth additive field.
        assert_eq!(json["score"], 100);
        assert_eq!(json["action"], "allow");
        assert_eq!(json["quarantined"], false);
        assert_eq!(
            json["explanation"]["dimensions"],
            serde_json::json!(["source"])
        );
        assert_eq!(json.as_object().unwrap().len(), 10);
    }
}
