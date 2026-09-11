//! The central decision gate and the Decision Packet.
//!
//! Every automated external action must go through [`decide`]. It evaluates
//! each hard constraint in a fixed order, records **every** failure reason,
//! persists exactly one `sales_decisions` row (including denials and shadowed
//! decisions), and returns the enforcement verdict.
//!
//! Release gates this module implements:
//!
//! * **100% of external sales messages map to a `sales_decision`.** No other
//!   sales route may construct a send; the dispatcher calls this gate and the
//!   decision id is attached to the queued action.
//! * **Legal-policy denial is impossible to bypass through another sales
//!   route.** Every external decision must carry a legal-policy input and a
//!   missing input fails closed; the resolved policy uuid is stored on the
//!   packet.
//! * **100% of human replies prevent subsequent normal sequence sends.** A
//!   `sales_enrollments.has_human_reply` row denies the next touch even when
//!   the action row was already queued.
//! * **The global kill switch prevents new outbound actions immediately while
//!   preserving data and inbound reply processing.** `decide` records and
//!   denies; nothing is deleted, and read/inbound paths remain untouched.
//!
//! Gate order (all reasons are kept, not just the first):
//!
//! 1. global kill switch
//! 2. autonomy mode `disabled`
//! 3. suppression (`sales_unsubscribes` ∪ platform `suppressions`)
//! 4. contact point verification `invalid`
//! 5. legal policy: `prohibited` denies; `approval_required` forces a human
//! 6. enrollment already has a human reply
//! 7. sender-health gate
//! 8. per-account weekly frequency budget
//! 9. contact point `suppressed_at`
//!
//! The autonomy state is loaded inline from `sales_autonomy_state` (the
//! `crate::autonomy` module is written in parallel); no row fails closed to
//! `disabled`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::legal_policy::{self, ContactPolicyInput};
use crate::sender_health;
use crate::types::{
    AutonomyMode, AutonomyState, ContactDecision, DecisionAction, Enforcement, OpportunityScore,
    SalesError,
};

/// Default weekly per-account touch budget when the account has no explicit
/// policy. Rationale: automation must never independently hammer one company.
/// An account's own budget is `max(DEFAULT_WEEKLY_ACCOUNT_BUDGET,
/// max_active_contacts * WEEKLY_BUDGET_PER_ACTIVE_CONTACT)` so multi-threaded
/// accounts get proportionally more room.
pub const DEFAULT_WEEKLY_ACCOUNT_BUDGET: i64 = 15;

/// Additional weekly touches granted per active contact slot on an account.
pub const WEEKLY_BUDGET_PER_ACTIVE_CONTACT: i64 = 5;

/// Everything one decision needs. Built by callers from the canonical tables.
#[derive(Debug, Clone)]
pub struct DecisionContext {
    pub tenant_id: String,
    pub account_id: Option<Uuid>,
    pub contact_id: Option<Uuid>,
    pub contact_point_id: Option<Uuid>,
    pub enrollment_id: Option<Uuid>,
    pub action: DecisionAction,
    pub score: OpportunityScore,
    pub expected_value_eur: f64,
    pub confidence: f32,
    pub evidence_ids: Vec<Uuid>,
    pub selected_offer: Option<String>,
    pub selected_sequence: Option<String>,
    pub selected_variant: Option<String>,
    pub selected_sender: Option<Uuid>,
    pub model_version: Option<String>,
    /// Owned form of the legal-policy input. Required for external sends;
    /// when absent an external action fails closed.
    pub policy: Option<ContactPolicyInputOwned>,
    pub rationale: String,
    pub execute_after: Option<DateTime<Utc>>,
}

/// Owned counterpart of [`ContactPolicyInput`], so a [`DecisionContext`] can
/// be built, queued and moved without lifetime plumbing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactPolicyInputOwned {
    pub account_id: Option<Uuid>,
    pub contact_id: Option<Uuid>,
    pub contact_point_id: Option<Uuid>,
    pub recipient_country: Option<String>,
    pub country_confidence: f32,
    pub contact_type: String,
    pub channel: String,
    pub source: Option<String>,
    pub purpose: Option<String>,
    pub has_existing_relationship: bool,
    pub consent_status: Option<String>,
    pub soft_opt_in: bool,
    pub legitimate_interest_assessed: bool,
}

impl ContactPolicyInputOwned {
    /// Borrow this owned input for [`legal_policy::evaluate`].
    pub fn as_borrowed<'a>(&'a self, tenant_id: &'a str) -> ContactPolicyInput<'a> {
        ContactPolicyInput {
            tenant_id,
            account_id: self.account_id,
            contact_id: self.contact_id,
            contact_point_id: self.contact_point_id,
            recipient_country: self.recipient_country.clone(),
            country_confidence: self.country_confidence,
            contact_type: &self.contact_type,
            channel: &self.channel,
            source: self.source.as_deref(),
            purpose: self.purpose.as_deref(),
            has_existing_relationship: self.has_existing_relationship,
            consent_status: self.consent_status.as_deref(),
            soft_opt_in: self.soft_opt_in,
            legitimate_interest_assessed: self.legitimate_interest_assessed,
        }
    }
}

/// What the gate decided, plus the id of the persisted Decision Packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionOutcome {
    pub decision_id: Uuid,
    pub enforcement: Enforcement,
    pub block_reasons: Vec<String>,
}

/// Combine gate failures, the autonomy mode and the legal verdict into the
/// enforcement decision. Pure, so every combination is unit-testable.
///
/// Any failure denies. With no failures: `AutonomousGuarded` executes only
/// when the legal gate is `Allowed` (an `ApprovalRequired` legal verdict
/// forces a human even in autonomous mode); `Assisted`/`ApprovalRequired`
/// await approval; `Shadow` records but blocks; `Disabled` denies.
pub fn combine(failures: &[String], mode: AutonomyMode, legal: ContactDecision) -> Enforcement {
    if !failures.is_empty() {
        return Enforcement::Denied;
    }
    match mode {
        AutonomyMode::Disabled => Enforcement::Denied,
        AutonomyMode::Shadow => Enforcement::Shadowed,
        AutonomyMode::Assisted | AutonomyMode::ApprovalRequired => Enforcement::AwaitApproval,
        AutonomyMode::AutonomousGuarded => match legal {
            ContactDecision::Allowed => Enforcement::Execute,
            // A legal approval requirement outranks autonomous mode.
            ContactDecision::ApprovalRequired => Enforcement::AwaitApproval,
            // Prohibited should already be a failure; deny defensively.
            ContactDecision::Prohibited => Enforcement::Denied,
        },
    }
}

async fn load_autonomy_state(db: &PgPool, tenant_id: &str) -> Result<AutonomyState, SalesError> {
    let row: Option<(String, bool)> =
        sqlx::query_as("SELECT mode, kill_switch FROM sales_autonomy_state WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_optional(db)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

    Ok(match row {
        Some((mode, kill_switch)) => AutonomyState {
            tenant_id: tenant_id.to_string(),
            mode: AutonomyMode::parse(&mode),
            kill_switch,
            rules: serde_json::json!({}),
            last_action: None,
            last_action_at: None,
        },
        // No row means autonomy was never granted for this tenant: fail
        // closed to disabled rather than assuming a permissive default.
        None => AutonomyState {
            tenant_id: tenant_id.to_string(),
            ..AutonomyState::default()
        },
    })
}

/// Evaluate every hard constraint, persist the Decision Packet, and return
/// the enforcement verdict. EVERY automated external action must go through
/// this.
///
/// Persists exactly one `sales_decisions` row even when the action is denied
/// or shadowed, so the machine stays explainable and replayable. Execute
/// requests (external sends) under an engaged kill switch additionally return
/// [`SalesError::KillSwitchEngaged`] after the packet is written.
pub async fn decide(db: &PgPool, ctx: DecisionContext) -> Result<DecisionOutcome, SalesError> {
    let tenant_id = ctx.tenant_id.as_str();
    let autonomy = load_autonomy_state(db, tenant_id).await?;
    let external = ctx.action.is_external_send();

    let mut failures: Vec<String> = Vec::new();
    let mut legal_decision = ContactDecision::Allowed;
    let mut policy_id: Option<String> = None;

    // Gate 1 — global kill switch. Immediate stop for NEW outbound actions;
    // data and inbound processing are untouched.
    if autonomy.kill_switch {
        failures.push(
            "global_kill_switch: outbound halted by operator; no new external action may start"
                .to_string(),
        );
    }

    // Gate 2 — autonomy disabled. Fail closed for tenants that never granted
    // autonomy.
    if autonomy.mode == AutonomyMode::Disabled {
        failures.push(
            "autonomy_disabled: tenant autonomy mode is 'disabled'; no automated action"
                .to_string(),
        );
    }

    // Gates 3, 4 and 9 — suppression status and contact-point verification.
    // Only possible when the decision carries a contact point; the address is
    // an attribute of the point, never a field on the decision.
    if let Some(contact_point_id) = ctx.contact_point_id {
        let point: Option<(String, String, String, Option<DateTime<Utc>>)> = sqlx::query_as(
            "SELECT channel, normalized_value, verification, suppressed_at \
             FROM sales_contact_points \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(contact_point_id)
        .bind(tenant_id)
        .fetch_optional(db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        match point {
            None => failures.push(format!(
                "contact_point_not_found: contact point {contact_point_id} does not exist \
                 for this tenant; fail closed"
            )),
            Some((channel, value, verification, suppressed_at)) => {
                if channel != "email" {
                    failures.push(format!(
                        "contact_point_channel_not_email: contact point channel is '{channel}'; \
                         the sales gate only sends email"
                    ));
                } else {
                    // Gate 3 — suppression (both the sales fast path and the
                    // platform-wide authority).
                    if check_suppression(db, tenant_id, &value).await? {
                        failures.push(format!(
                            "suppressed: {value} is on the unsubscribe/suppression list"
                        ));
                    }
                }

                // Gate 4 — an invalid address must never be contacted.
                if verification == "invalid" {
                    failures.push(format!(
                        "contact_point_invalid: verification is 'invalid' for contact point \
                         {contact_point_id}"
                    ));
                }

                // Gate 9 — the point itself was suppressed.
                if suppressed_at.is_some() {
                    failures.push(format!(
                        "contact_point_suppressed: contact point {contact_point_id} has \
                         suppressed_at set"
                    ));
                }
            }
        }
    }

    // Gate 5 — legal policy. External sends without a legal input fail closed.
    if let Some(mut owned) = ctx.policy.clone() {
        if owned.account_id.is_none() {
            owned.account_id = ctx.account_id;
        }
        if owned.contact_id.is_none() {
            owned.contact_id = ctx.contact_id;
        }
        if owned.contact_point_id.is_none() {
            owned.contact_point_id = ctx.contact_point_id;
        }
        let input = owned.as_borrowed(tenant_id);
        let verdict = legal_policy::evaluate(db, &input).await?;
        legal_decision = verdict.decision;
        policy_id = verdict.policy_id.map(|id| id.to_string());
        // Audit trail: every evaluated contact attempt is recorded.
        legal_policy::record(db, tenant_id, &input, &verdict).await?;

        match verdict.decision {
            ContactDecision::Prohibited => {
                failures.push(format!("legal_policy_prohibited: {}", verdict.reason))
            }
            // ApprovalRequired is not a failure: it forces AwaitApproval via
            // `combine` even in autonomous mode.
            ContactDecision::ApprovalRequired | ContactDecision::Allowed => {}
        }
    } else if external {
        failures.push(
            "legal_policy_input_missing: external send without a legal-policy input; \
             fail closed"
                .to_string(),
        );
    }

    // Gate 6 — a human reply must prevent the next touch racing out.
    if let Some(enrollment_id) = ctx.enrollment_id {
        if check_enrollment_replied(db, enrollment_id).await? {
            failures.push(format!(
                "human_reply: enrollment {enrollment_id} has a human reply; \
                 subsequent sequence sends are blocked"
            ));
        }
    }

    // Gate 7 — sender health (only when a sender was resolved; resolution is
    // upstream and a missing sender is handled by the dispatcher).
    if let Some(sender_identity_id) = ctx.selected_sender {
        if let Err(err) = sender_health::gate(db, tenant_id, sender_identity_id).await {
            failures.push(format!("sender_health_denied: {err}"));
        }
    }

    // Gate 8 — per-account weekly frequency budget.
    if let Some(account_id) = ctx.account_id {
        if !check_frequency_budget(db, tenant_id, account_id).await? {
            failures.push(format!(
                "account_frequency_budget_exhausted: account {account_id} reached its \
                 weekly touch budget"
            ));
        }
    }

    let enforcement = combine(&failures, autonomy.mode, legal_decision);
    let blocked = enforcement == Enforcement::Denied;

    // Persist the Decision Packet — ALWAYS, including denials and shadowed
    // decisions. The decision id is what makes the machine explainable.
    let block_reasons = serde_json::json!(failures);
    let confidence = ctx.confidence.clamp(0.0, 1.0) as f64;
    let score_total = ctx.score.total as f64;

    let decision_id: Uuid = sqlx::query_scalar(
        "INSERT INTO sales_decisions ( \
             id, tenant_id, account_id, contact_id, action, expected_value_eur, \
             confidence, score_total, selected_offer, selected_sequence, \
             selected_variant, selected_sender, evidence_ids, policy_id, \
             model_version, autonomy_mode, rationale, blocked, block_reasons, \
             execute_after, created_at \
         ) VALUES ( \
             gen_random_uuid(), $1, $2, $3, $4, \
             LEAST(GREATEST($5::double precision, -1000000000), 1000000000)::numeric(14, 4), \
             LEAST(GREATEST($6::double precision, 0), 1), \
             $7::double precision, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, NOW() \
         ) RETURNING id",
    )
    .bind(tenant_id)
    .bind(ctx.account_id)
    .bind(ctx.contact_id)
    .bind(ctx.action.as_str())
    .bind(ctx.expected_value_eur)
    .bind(confidence)
    .bind(score_total)
    .bind(ctx.selected_offer.as_deref())
    .bind(ctx.selected_sequence.as_deref())
    .bind(ctx.selected_variant.as_deref())
    .bind(ctx.selected_sender.map(|id| id.to_string()))
    .bind(&ctx.evidence_ids)
    .bind(policy_id.as_deref())
    .bind(ctx.model_version.as_deref())
    .bind(autonomy.mode.as_str())
    .bind(&ctx.rationale)
    .bind(blocked)
    .bind(&block_reasons)
    .bind(ctx.execute_after)
    .fetch_one(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    if blocked {
        tracing::warn!(
            tenant_id,
            decision_id = %decision_id,
            action = ctx.action.as_str(),
            reasons = ?failures,
            "sales decision denied by hard gate"
        );
    }

    // Execute requests under a kill switch surface the stop as an error, not
    // just a blocked packet, so the caller cannot mistake it for a normal
    // approval wait.
    if autonomy.kill_switch && external {
        return Err(SalesError::KillSwitchEngaged);
    }

    Ok(DecisionOutcome {
        decision_id,
        enforcement,
        block_reasons: failures,
    })
}

/// Is this address on either suppression authority?
pub async fn check_suppression(
    db: &PgPool,
    tenant_id: &str,
    email: &str,
) -> Result<bool, SalesError> {
    let suppressed: bool = sqlx::query_scalar(
        "SELECT EXISTS ( \
             SELECT 1 FROM sales_unsubscribes \
             WHERE tenant_id = $1 AND lower(email) = lower($2) \
         ) OR EXISTS ( \
             SELECT 1 FROM suppressions \
             WHERE tenant_id = $1 AND lower(email) = lower($2) \
         )",
    )
    .bind(tenant_id)
    .bind(email)
    .fetch_one(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;
    Ok(suppressed)
}

/// Has a human already replied to this enrollment? A missing row answers
/// `false` (there is no recorded human reply).
pub async fn check_enrollment_replied(
    db: &PgPool,
    enrollment_id: Uuid,
) -> Result<bool, SalesError> {
    let replied: Option<bool> =
        sqlx::query_scalar("SELECT has_human_reply FROM sales_enrollments WHERE id = $1")
            .bind(enrollment_id)
            .fetch_optional(db)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;
    Ok(replied.unwrap_or(false))
}

/// Account weekly touch budget: `max(DEFAULT_WEEKLY_ACCOUNT_BUDGET,
/// max_active_contacts * WEEKLY_BUDGET_PER_ACTIVE_CONTACT)`. A missing account
/// row uses the default.
async fn account_weekly_budget(
    db: &PgPool,
    tenant_id: &str,
    account_id: Uuid,
) -> Result<i64, SalesError> {
    let max_active_contacts: Option<i16> = sqlx::query_scalar(
        "SELECT max_active_contacts FROM sales_accounts WHERE id = $1 AND tenant_id = $2",
    )
    .bind(account_id)
    .bind(tenant_id)
    .fetch_optional(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    Ok(max_active_contacts
        .map(|n| DEFAULT_WEEKLY_ACCOUNT_BUDGET.max(i64::from(n) * WEEKLY_BUDGET_PER_ACTIVE_CONTACT))
        .unwrap_or(DEFAULT_WEEKLY_ACCOUNT_BUDGET))
}

/// Does the account still have weekly budget for another touch?
///
/// Counts distinct sends (one `sales_outcomes` row per step execution at
/// most; `open`/`click` are deliberately excluded as weak signals) for the
/// account over the last 7 days and compares against the account budget.
/// Returns `true` when a touch is still allowed.
pub async fn check_frequency_budget(
    db: &PgPool,
    tenant_id: &str,
    account_id: Uuid,
) -> Result<bool, SalesError> {
    let budget = account_weekly_budget(db, tenant_id, account_id).await?;

    let touches: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT COALESCE(step_execution_id::text, id::text))::bigint \
         FROM sales_outcomes \
         WHERE tenant_id = $1 AND account_id = $2 \
           AND occurred_at >= NOW() - INTERVAL '7 days' \
           AND outcome IN ('delivered', 'reply', 'positive_reply', 'meeting_booked', \
                           'meeting_attended', 'trial', 'paid_subscription', \
                           'retained_mrr', 'bounce', 'complaint', 'unsubscribe')",
    )
    .bind(tenant_id)
    .bind(account_id)
    .fetch_one(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    Ok(touches < budget)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failure() -> Vec<String> {
        vec!["suppressed: someone opted out".to_string()]
    }

    #[test]
    fn any_failure_denies_regardless_of_mode_or_legal_verdict() {
        for mode in AutonomyMode::all() {
            assert_eq!(
                combine(&failure(), mode, ContactDecision::Allowed),
                Enforcement::Denied,
                "mode {mode} must not execute with failures"
            );
        }
    }

    #[test]
    fn autonomous_guarded_with_all_gates_passed_executes() {
        assert_eq!(
            combine(
                &[],
                AutonomyMode::AutonomousGuarded,
                ContactDecision::Allowed
            ),
            Enforcement::Execute
        );
    }

    #[test]
    fn legal_approval_required_forces_a_human_even_in_autonomous_mode() {
        assert_eq!(
            combine(
                &[],
                AutonomyMode::AutonomousGuarded,
                ContactDecision::ApprovalRequired
            ),
            Enforcement::AwaitApproval
        );
    }

    #[test]
    fn legal_prohibited_denies_even_without_recorded_failures() {
        assert_eq!(
            combine(
                &[],
                AutonomyMode::AutonomousGuarded,
                ContactDecision::Prohibited
            ),
            Enforcement::Denied
        );
    }

    #[test]
    fn assisted_and_approval_required_modes_await_approval() {
        for mode in [AutonomyMode::Assisted, AutonomyMode::ApprovalRequired] {
            assert_eq!(
                combine(&[], mode, ContactDecision::Allowed),
                Enforcement::AwaitApproval
            );
        }
    }

    #[test]
    fn shadow_mode_shadows_clean_decisions() {
        assert_eq!(
            combine(&[], AutonomyMode::Shadow, ContactDecision::Allowed),
            Enforcement::Shadowed
        );
    }

    #[test]
    fn disabled_mode_denies_clean_decisions() {
        assert_eq!(
            combine(&[], AutonomyMode::Disabled, ContactDecision::Allowed),
            Enforcement::Denied
        );
    }

    #[test]
    fn weekly_budget_default_is_documented() {
        assert_eq!(DEFAULT_WEEKLY_ACCOUNT_BUDGET, 15);
        assert_eq!(WEEKLY_BUDGET_PER_ACTIVE_CONTACT, 5);
    }

    #[test]
    fn owned_policy_input_borrows_correctly() {
        let owned = ContactPolicyInputOwned {
            account_id: None,
            contact_id: None,
            contact_point_id: None,
            recipient_country: Some("EE".into()),
            country_confidence: 0.9,
            contact_type: "b2b_professional".into(),
            channel: "email".into(),
            source: Some("public_registry".into()),
            purpose: Some("sales_outreach".into()),
            has_existing_relationship: false,
            consent_status: Some("granted".into()),
            soft_opt_in: false,
            legitimate_interest_assessed: true,
        };
        let borrowed = owned.as_borrowed("tenant-a");
        assert_eq!(borrowed.tenant_id, "tenant-a");
        assert_eq!(borrowed.recipient_country.as_deref(), Some("EE"));
        assert_eq!(borrowed.contact_type, "b2b_professional");
        assert_eq!(borrowed.channel, "email");
        assert_eq!(borrowed.consent_status, Some("granted"));
        assert_eq!(
            legal_policy::resolve_jurisdiction(
                borrowed.recipient_country.as_deref(),
                borrowed.country_confidence
            ),
            legal_policy::EU_POLICY_KEY
        );
    }
}
