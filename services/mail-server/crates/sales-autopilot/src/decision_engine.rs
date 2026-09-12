//! The central decision gate and the Decision Packet.
//!
//! Every automated external action must go through [`decide`]. It evaluates
//! each hard constraint in a fixed order, records **every** failure reason,
//! persists exactly one `sales_decisions` row (including denials and shadowed
//! decisions) carrying the enforcement verdict, the selected sender reference
//! and the operator-review state, and returns the enforcement verdict.
//!
//! Approval is never a bypass: immediately before an external effect is
//! produced, [`revalidate_execution`] re-runs every hard gate for an existing
//! decision, so an unsubscribe, a human reply, a legal-policy change or a
//! newly quarantined sender still stops a send that was decided (or approved)
//! earlier.
//!
//! Release gates this module implements:
//!
//! * **100% of external sales messages map to a `sales_decision`.** Every
//!   sales route — the live sequence worker included — builds its send through
//!   [`decide`] instead of an inline copy of the gates; the decision id is
//!   attached to the queued action and the packet stores the enforcement
//!   verdict the worker acts on.
//! * **Legal-policy denial is impossible to bypass through another sales
//!   route.** Every external decision re-evaluates the legal policy from the
//!   current canonical store — a verdict supplied by a caller is never
//!   trusted — and a missing input fails closed; the resolved policy uuid is
//!   stored on the packet, and [`revalidate_execution`] repeats the evaluation
//!   before the send.
//! * **An approval cannot resurrect a gate that changed.** An operator
//!   approval is permission to proceed, not an indefinite capability token:
//!   [`revalidate_execution`] re-runs every hard gate immediately before the
//!   external effect, so an approval recorded minutes ago does not defeat an
//!   unsubscribe, a human reply, a legal-policy change or a newly quarantined
//!   sender.
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
//! 5. legal policy, re-evaluated from the current canonical store:
//!    `prohibited` denies; `approval_required` forces a human; no policy input
//!    at all fails closed
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

impl Enforcement {
    /// The wire string persisted in `sales_decisions.enforcement`. These four
    /// values are exactly the ones accepted by the migration-201 CHECK
    /// constraint `chk_sales_decisions_enforcement`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Execute => "execute",
            Self::AwaitApproval => "await_approval",
            Self::Shadowed => "shadowed",
            Self::Denied => "denied",
        }
    }

    /// Parse a persisted enforcement value. An unknown value is `None` so the
    /// caller can fail closed instead of guessing a verdict the worker's match
    /// arms do not handle.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "execute" => Some(Self::Execute),
            "await_approval" => Some(Self::AwaitApproval),
            "shadowed" => Some(Self::Shadowed),
            "denied" => Some(Self::Denied),
            _ => None,
        }
    }
}

/// The `sales_decisions.review_status` value a verdict requires.
///
/// Only a verdict that awaits a human goes into the operator queue; a denied,
/// shadowed or executing verdict requires no review (marking those `pending`
/// would flood the queue with decisions that need no human).
pub fn review_status_for(enforcement: Enforcement) -> Option<&'static str> {
    match enforcement {
        Enforcement::AwaitApproval => Some("pending"),
        Enforcement::Denied | Enforcement::Shadowed | Enforcement::Execute => Some("not_required"),
    }
}

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

    // Gate 5 — legal policy. The context carries recipient FACTS (jurisdiction,
    // contact type, consent state), never a verdict or an authorization: the
    // verdict is re-evaluated from the current canonical store on every call,
    // so a policy that changed since the caller assembled the context is
    // honoured. No inputs at all means the gate cannot be evaluated, which
    // fails closed instead of silently skipping the gate.
    let (legal_decision, policy_id): (ContactDecision, Option<String>) = match ctx.policy.clone() {
        Some(mut owned) => {
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

            (verdict.decision, verdict.policy_id.map(|id| id.to_string()))
        }
        None => {
            failures.push(
                "legal_policy_input_missing: no legal-policy input on the context; the \
                 legal gate cannot be evaluated and fails closed"
                    .to_string(),
            );
            (ContactDecision::ApprovalRequired, None)
        }
    };

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
    // A verdict that awaits a human becomes the operator's queue item; every
    // other verdict is recorded as requiring no review.
    let review_status = review_status_for(enforcement);

    // Persist the Decision Packet — ALWAYS, including denials and shadowed
    // decisions. The decision id is what makes the machine explainable. The
    // enforcement verdict, the sender reference and the review status make the
    // packet the execution contract the worker acts on; the deprecated TEXT
    // `selected_sender` column is deliberately not written any more.
    let block_reasons = serde_json::json!(failures);
    let confidence = ctx.confidence.clamp(0.0, 1.0) as f64;
    let score_total = ctx.score.total as f64;

    let decision_id: Uuid = sqlx::query_scalar(
        "INSERT INTO sales_decisions ( \
             id, tenant_id, account_id, contact_id, action, expected_value_eur, \
             confidence, score_total, selected_offer, selected_sequence, \
             selected_variant, selected_sender_id, evidence_ids, policy_id, \
             model_version, autonomy_mode, rationale, blocked, block_reasons, \
             execute_after, enforcement, review_status, created_at \
         ) VALUES ( \
             gen_random_uuid(), $1, $2, $3, $4, \
             LEAST(GREATEST($5::double precision, -1000000000), 1000000000)::numeric(14, 4), \
             LEAST(GREATEST($6::double precision, 0), 1), \
             $7::double precision, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, NOW() \
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
    .bind(ctx.selected_sender)
    .bind(&ctx.evidence_ids)
    .bind(policy_id.as_deref())
    .bind(ctx.model_version.as_deref())
    .bind(autonomy.mode.as_str())
    .bind(&ctx.rationale)
    .bind(blocked)
    .bind(&block_reasons)
    .bind(ctx.execute_after)
    .bind(enforcement.as_str())
    .bind(review_status)
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

/// The verdict of re-checking every hard gate immediately before an external
/// effect is produced.
#[derive(Debug, Clone)]
pub struct ExecutionRevalidation {
    pub allowed: bool,
    pub reasons: Vec<String>,
    /// The gates that were re-read, for the audit trail.
    pub checked: Vec<&'static str>,
}

/// Gate names reported in [`ExecutionRevalidation::checked`], in the order
/// [`revalidate_execution`] evaluates them.
const GATE_KILL_SWITCH: &str = "global_kill_switch";
const GATE_AUTONOMY_MODE: &str = "autonomy_mode";
const GATE_SUPPRESSION: &str = "suppression";
const GATE_CONTACT_POINT_SUPPRESSED: &str = "contact_point_suppressed";
const GATE_ADDRESS_VERIFICATION: &str = "address_verification";
const GATE_HUMAN_REPLY: &str = "human_reply";
const GATE_SENDER_HEALTH: &str = "sender_health";
const GATE_FREQUENCY_BUDGET: &str = "frequency_budget";
const GATE_LEGAL_POLICY: &str = "legal_policy";

/// The result for an action with no external effect: nothing was re-checked
/// and nothing needs to be. Documented reason: there is no external effect to
/// protect, so the send gates do not apply.
fn internal_action_revalidation() -> ExecutionRevalidation {
    ExecutionRevalidation {
        allowed: true,
        reasons: Vec::new(),
        checked: Vec::new(),
    }
}

/// Does a persisted `sales_decisions.action` value produce an external effect
/// (a message to a human)? Unknown values fail closed: they are treated as
/// external sends and must pass every gate.
fn action_is_external(action: &str) -> bool {
    match action.trim().to_ascii_lowercase().as_str() {
        "do_nothing" | "wait" | "collect_evidence" | "enrich" | "verify_email"
        | "research_company" | "operator_task" | "nurture" | "stop_permanently" => false,
        // contact | follow_up | change_angle | ask_for_referral | book_meeting
        // and anything unrecognised.
        _ => true,
    }
}

/// Map a freshly evaluated legal verdict — plus the decision's recorded review
/// state — to a revalidation failure. Pure, so every combination is
/// unit-tested.
///
/// `Prohibited` always fails. `ApprovalRequired` fails unless a human has
/// approved the decision (`review_status = 'approved'`): the human requirement
/// must be satisfied *under the current policy*, and a policy that moved to
/// approval-required after the decision may not ride on an old autonomous
/// verdict. `Allowed` never fails.
fn legal_revalidation_failure(
    verdict: ContactDecision,
    verdict_reason: &str,
    review_status: Option<&str>,
) -> Option<String> {
    match verdict {
        ContactDecision::Allowed => None,
        ContactDecision::Prohibited => Some(format!("legal_policy_prohibited: {verdict_reason}")),
        ContactDecision::ApprovalRequired if review_status == Some("approved") => None,
        ContactDecision::ApprovalRequired => Some(format!(
            "legal_policy_approval_required: {verdict_reason}; the decision's review_status is \
             '{}' — a human must approve under the current policy before this can execute",
            review_status.unwrap_or("none")
        )),
    }
}

/// The columns [`revalidate_execution`] needs from the Decision Packet.
///
/// `contact_point_id` and `enrollment_id` are deliberately resolved through
/// their canonical carriers: `sales_decisions` has neither column (migration
/// 200 creates the packet without them; migration 201 adds only enforcement,
/// sender, and review columns).
#[derive(sqlx::FromRow)]
struct ExecutionDecisionRow {
    tenant_id: String,
    account_id: Option<Uuid>,
    contact_id: Option<Uuid>,
    action: String,
    selected_sender_id: Option<Uuid>,
    review_status: Option<String>,
}

/// The gate-relevant state of the enrollment a decision belongs to.
#[derive(sqlx::FromRow)]
struct EnrollmentGateRow {
    contact_point_id: Option<Uuid>,
    has_human_reply: bool,
}

/// Resolve the enrollment a decision belongs to, through the canonical
/// carriers in priority order: the queued action for the decision, the step
/// execution that carries the decision id, an enrollment created from the
/// decision, then the contact's newest enrollment as a last resort (so a
/// missing link cannot silently skip the human-reply gate).
async fn resolve_enrollment(
    db: &PgPool,
    tenant_id: &str,
    decision_id: Uuid,
    contact_id: Option<Uuid>,
) -> Result<Option<EnrollmentGateRow>, SalesError> {
    let linked: Option<Uuid> = sqlx::query_scalar(
        "SELECT entity_id FROM sales_actions \
         WHERE tenant_id = $1 AND decision_id = $2 AND entity_type = 'enrollment' \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(tenant_id)
    .bind(decision_id)
    .fetch_optional(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    let linked = match linked {
        Some(id) => Some(id),
        None => sqlx::query_scalar(
            "SELECT enrollment_id FROM sales_step_executions \
                 WHERE decision_id = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(decision_id)
        .fetch_optional(db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?,
    };

    let linked = match linked {
        Some(id) => Some(id),
        None => sqlx::query_scalar(
            "SELECT id FROM sales_enrollments \
                 WHERE tenant_id = $1 AND decision_id = $2 \
                 ORDER BY enrolled_at DESC LIMIT 1",
        )
        .bind(tenant_id)
        .bind(decision_id)
        .fetch_optional(db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?,
    };

    if let Some(enrollment_id) = linked {
        return sqlx::query_as(
            "SELECT contact_point_id, has_human_reply FROM sales_enrollments \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(enrollment_id)
        .bind(tenant_id)
        .fetch_optional(db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()));
    }

    let Some(contact_id) = contact_id else {
        return Ok(None);
    };
    sqlx::query_as(
        "SELECT contact_point_id, has_human_reply FROM sales_enrollments \
         WHERE tenant_id = $1 AND contact_id = $2 \
         ORDER BY enrolled_at DESC LIMIT 1",
    )
    .bind(tenant_id)
    .bind(contact_id)
    .fetch_optional(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))
}

/// The legal-policy evaluation recorded for a contact point (or, when the
/// point is unknown, for the contact) at decision time.
///
/// Only the `inputs` are used: they are recipient FACTS. The verdict itself is
/// deliberately ignored and re-derived by [`revalidate_execution`], so a stale
/// policy decision can never be replayed as an indefinite capability.
async fn latest_policy_audit(
    db: &PgPool,
    tenant_id: &str,
    contact_id: Option<Uuid>,
    contact_point_id: Option<Uuid>,
) -> Result<Option<(Option<Uuid>, serde_json::Value)>, SalesError> {
    if let Some(point_id) = contact_point_id {
        return sqlx::query_as(
            "SELECT contact_point_id, inputs FROM sales_contact_policy_decisions \
             WHERE tenant_id = $1 AND contact_point_id = $2 \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(tenant_id)
        .bind(point_id)
        .fetch_optional(db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()));
    }

    let Some(contact_id) = contact_id else {
        return Ok(None);
    };
    sqlx::query_as(
        "SELECT contact_point_id, inputs FROM sales_contact_policy_decisions \
         WHERE tenant_id = $1 AND contact_id = $2 \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(tenant_id)
    .bind(contact_id)
    .fetch_optional(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))
}

/// The contact's newest email contact point, used only when neither the
/// enrollment link nor the policy audit row identifies one.
async fn newest_email_contact_point(
    db: &PgPool,
    tenant_id: &str,
    contact_id: Option<Uuid>,
) -> Result<Option<Uuid>, SalesError> {
    let Some(contact_id) = contact_id else {
        return Ok(None);
    };
    sqlx::query_scalar(
        "SELECT id FROM sales_contact_points \
         WHERE tenant_id = $1 AND contact_id = $2 AND channel = 'email' \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(tenant_id)
    .bind(contact_id)
    .fetch_optional(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))
}

/// Re-run every hard gate for a decision that already exists.
///
/// An operator approval is permission to proceed, not permission to bypass a
/// gate that changed since the decision was made: an approval from five
/// minutes ago must not defeat an unsubscribe, a human reply, a legal-policy
/// change or a newly quarantined sender.
///
/// Used by the worker immediately before the external enqueue, and by the
/// approval path in `control.rs`.
///
/// Gates are re-read in this order, and **every** failure is recorded (the
/// check does not stop at the first): global kill switch; autonomy mode still
/// permits execution; suppression on the contact point's current email (both
/// `sales_unsubscribes` and platform `suppressions`); the contact point's
/// `suppressed_at`; its current address verification; the enrollment's
/// `has_human_reply`; the selected sender's current health; the account's
/// current frequency budget; the current legal policy (re-evaluated from the
/// canonical store, never replayed from the packet).
///
/// `allowed` is true only when no gate failed. A missing decision is
/// [`SalesError::InvalidInput`]. Internal actions (not
/// [`DecisionAction::is_external_send`]) short-circuit to `allowed: true` with
/// `checked: []` — there is no external effect to protect.
pub async fn revalidate_execution(
    db: &PgPool,
    decision_id: Uuid,
) -> Result<ExecutionRevalidation, SalesError> {
    let decision: Option<ExecutionDecisionRow> = sqlx::query_as(
        "SELECT tenant_id, account_id, contact_id, action, selected_sender_id, \
                review_status \
         FROM sales_decisions \
         WHERE id = $1",
    )
    .bind(decision_id)
    .fetch_optional(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    let Some(decision) = decision else {
        return Err(SalesError::InvalidInput(format!(
            "revalidate_execution: no sales_decisions row with id {decision_id}"
        )));
    };

    // Internal actions have no external effect to protect.
    if !action_is_external(&decision.action) {
        return Ok(internal_action_revalidation());
    }

    let mut reasons: Vec<String> = Vec::new();
    let mut checked: Vec<&'static str> = Vec::new();
    let tenant_id = decision.tenant_id.as_str();

    // Gates 1 and 2 — the autonomy state as it is NOW. The kill switch stops
    // new outbound actions immediately, and a mode that blocks all execution
    // (`disabled`/`shadow`) must not be bypassed by replaying an old decision.
    let autonomy = load_autonomy_state(db, tenant_id).await?;
    checked.push(GATE_KILL_SWITCH);
    if autonomy.kill_switch {
        reasons.push(
            "global_kill_switch: outbound halted by operator; no external action may start"
                .to_string(),
        );
    }
    checked.push(GATE_AUTONOMY_MODE);
    if autonomy.mode.blocks_all_execution() {
        reasons.push(format!(
            "autonomy_mode_blocks_execution: tenant autonomy mode is '{}'; execution is not \
             permitted",
            autonomy.mode.as_str()
        ));
    }

    // Resolve the enrollment and the contact point this decision was made for.
    let enrollment = resolve_enrollment(db, tenant_id, decision_id, decision.contact_id).await?;
    let enrollment_point = enrollment.as_ref().and_then(|e| e.contact_point_id);
    let mut policy_audit = match enrollment_point {
        Some(point_id) => {
            latest_policy_audit(db, tenant_id, decision.contact_id, Some(point_id)).await?
        }
        None => None,
    };
    if policy_audit.is_none() {
        policy_audit = latest_policy_audit(db, tenant_id, decision.contact_id, None).await?;
    }
    let contact_point_id =
        match enrollment_point.or_else(|| policy_audit.as_ref().and_then(|(point, _)| *point)) {
            Some(point_id) => Some(point_id),
            None => newest_email_contact_point(db, tenant_id, decision.contact_id).await?,
        };

    // Gates 3-5 — the contact point's current suppression status, its own
    // suppressed flag, and its current verification.
    match contact_point_id {
        None => reasons.push(format!(
            "contact_point_not_found: decision {decision_id} has no resolvable email contact \
             point; the suppression and verification gates cannot be evaluated — fail closed"
        )),
        Some(point_id) => {
            let point: Option<(String, String, String, Option<DateTime<Utc>>)> = sqlx::query_as(
                "SELECT channel, normalized_value, verification, suppressed_at \
                 FROM sales_contact_points \
                 WHERE id = $1 AND tenant_id = $2",
            )
            .bind(point_id)
            .bind(tenant_id)
            .fetch_optional(db)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

            match point {
                None => reasons.push(format!(
                    "contact_point_not_found: contact point {point_id} does not exist for this \
                     tenant; fail closed"
                )),
                Some((channel, value, verification, suppressed_at)) => {
                    // Gate 3 — both suppression authorities, on the address as
                    // it is NOW, not as it was at decision time.
                    if channel != "email" {
                        reasons.push(format!(
                            "contact_point_channel_not_email: contact point channel is \
                             '{channel}'; the sales gate only sends email"
                        ));
                    } else {
                        checked.push(GATE_SUPPRESSION);
                        if check_suppression(db, tenant_id, &value).await? {
                            reasons.push(format!(
                                "suppressed: {value} is on the unsubscribe/suppression list"
                            ));
                        }
                    }

                    // Gate 4 — the point itself was suppressed after the
                    // decision.
                    checked.push(GATE_CONTACT_POINT_SUPPRESSED);
                    if suppressed_at.is_some() {
                        reasons.push(format!(
                            "contact_point_suppressed: contact point {point_id} has \
                             suppressed_at set"
                        ));
                    }

                    // Gate 5 — an address that is now invalid must never be
                    // contacted.
                    checked.push(GATE_ADDRESS_VERIFICATION);
                    if verification == "invalid" {
                        reasons.push(format!(
                            "contact_point_invalid: verification is 'invalid' for contact point \
                             {point_id}"
                        ));
                    }
                }
            }
        }
    }

    // Gate 6 — a human reply that arrived after the decision stops the send.
    if let Some(enrollment) = enrollment.as_ref() {
        checked.push(GATE_HUMAN_REPLY);
        if enrollment.has_human_reply {
            reasons.push(format!(
                "human_reply: the enrollment for decision {decision_id} has a human reply; \
                 subsequent sequence sends are blocked"
            ));
        }
    }

    // Gate 7 — the selected sender's current health.
    if let Some(sender_identity_id) = decision.selected_sender_id {
        checked.push(GATE_SENDER_HEALTH);
        if let Err(err) = sender_health::gate(db, tenant_id, sender_identity_id).await {
            reasons.push(format!("sender_health_denied: {err}"));
        }
    }

    // Gate 8 — the account's current weekly frequency budget.
    if let Some(account_id) = decision.account_id {
        checked.push(GATE_FREQUENCY_BUDGET);
        if !check_frequency_budget(db, tenant_id, account_id).await? {
            reasons.push(format!(
                "account_frequency_budget_exhausted: account {account_id} reached its weekly \
                 touch budget"
            ));
        }
    }

    // Gate 9 — the legal policy as it stands NOW. The recorded inputs are
    // recipient facts; the verdict is re-derived from the current canonical
    // store, never replayed from the decision's policy_id.
    checked.push(GATE_LEGAL_POLICY);
    match policy_audit {
        None => reasons.push(
            "legal_policy_input_missing: no recorded legal-policy inputs for this decision; the \
             legal gate cannot be re-evaluated and fails closed"
                .to_string(),
        ),
        Some((_, inputs)) => match serde_json::from_value::<ContactPolicyInputOwned>(inputs) {
            Err(err) => reasons.push(format!(
                "legal_policy_input_unreadable: recorded legal-policy inputs cannot be \
                 deserialized ({err}); fail closed"
            )),
            Ok(mut owned) => {
                if owned.account_id.is_none() {
                    owned.account_id = decision.account_id;
                }
                if owned.contact_id.is_none() {
                    owned.contact_id = decision.contact_id;
                }
                if owned.contact_point_id.is_none() {
                    owned.contact_point_id = contact_point_id;
                }
                let input = owned.as_borrowed(tenant_id);
                let verdict = legal_policy::evaluate(db, &input).await?;
                if let Some(reason) = legal_revalidation_failure(
                    verdict.decision,
                    &verdict.reason,
                    decision.review_status.as_deref(),
                ) {
                    reasons.push(reason);
                }
            }
        },
    }

    let allowed = reasons.is_empty();
    Ok(ExecutionRevalidation {
        allowed,
        reasons,
        checked,
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

    #[test]
    fn enforcement_wire_strings_match_the_201_check_constraint() {
        // Exactly the four values `chk_sales_decisions_enforcement` allows.
        assert_eq!(Enforcement::Execute.as_str(), "execute");
        assert_eq!(Enforcement::Denied.as_str(), "denied");
        assert_eq!(Enforcement::Shadowed.as_str(), "shadowed");
        assert_eq!(Enforcement::AwaitApproval.as_str(), "await_approval");
    }

    #[test]
    fn enforcement_parse_inverts_as_str_and_rejects_unknown_values() {
        for enforcement in [
            Enforcement::Execute,
            Enforcement::Denied,
            Enforcement::Shadowed,
            Enforcement::AwaitApproval,
        ] {
            assert_eq!(Enforcement::parse(enforcement.as_str()), Some(enforcement));
        }
        assert_eq!(
            Enforcement::parse(" AWAIT_APPROVAL "),
            Some(Enforcement::AwaitApproval)
        );
        assert_eq!(Enforcement::parse("maybe"), None);
        assert_eq!(Enforcement::parse(""), None);
    }

    #[test]
    fn review_status_is_pending_only_for_await_approval() {
        assert_eq!(
            review_status_for(Enforcement::AwaitApproval),
            Some("pending")
        );
        assert_eq!(review_status_for(Enforcement::Denied), Some("not_required"));
        assert_eq!(
            review_status_for(Enforcement::Shadowed),
            Some("not_required")
        );
        assert_eq!(
            review_status_for(Enforcement::Execute),
            Some("not_required")
        );
    }

    #[test]
    fn only_external_actions_need_execution_revalidation() {
        let internal = [
            DecisionAction::DoNothing,
            DecisionAction::Wait,
            DecisionAction::CollectEvidence,
            DecisionAction::Enrich,
            DecisionAction::VerifyEmail,
            DecisionAction::ResearchCompany,
            DecisionAction::OperatorTask,
            DecisionAction::Nurture,
            DecisionAction::StopPermanently,
        ];
        for action in internal {
            assert!(!action.is_external_send(), "{action} must be internal");
            assert!(!action_is_external(action.as_str()));
        }
        let external = [
            DecisionAction::Contact,
            DecisionAction::FollowUp,
            DecisionAction::ChangeAngle,
            DecisionAction::AskForReferral,
            DecisionAction::BookMeeting,
        ];
        for action in external {
            assert!(action.is_external_send(), "{action} must be external");
            assert!(action_is_external(action.as_str()));
        }
        // Unknown/forward-compatible action names fail closed.
        assert!(action_is_external("future_action"));
        assert!(action_is_external(""));
    }

    #[test]
    fn internal_action_short_circuit_is_clean() {
        let result = internal_action_revalidation();
        assert!(result.allowed);
        assert!(result.reasons.is_empty());
        assert!(result.checked.is_empty());
    }

    #[test]
    fn legal_revalidation_matrix() {
        // Prohibited denies regardless of any recorded review state.
        for review in [
            None,
            Some("pending"),
            Some("approved"),
            Some("rejected"),
            Some("not_required"),
        ] {
            let failure =
                legal_revalidation_failure(ContactDecision::Prohibited, "policy prohibits", review);
            assert!(
                failure.is_some_and(|reason| reason.starts_with("legal_policy_prohibited")),
                "review {review:?} must not rescue a prohibited verdict"
            );
        }

        // ApprovalRequired needs a human approval CURRENT for this policy.
        for review in [
            None,
            Some("pending"),
            Some("rejected"),
            Some("not_required"),
        ] {
            assert!(
                legal_revalidation_failure(
                    ContactDecision::ApprovalRequired,
                    "unknown jurisdiction",
                    review
                )
                .is_some_and(|reason| reason.starts_with("legal_policy_approval_required")),
                "review {review:?} is not an approval"
            );
        }
        assert!(legal_revalidation_failure(
            ContactDecision::ApprovalRequired,
            "unknown jurisdiction",
            Some("approved")
        )
        .is_none());

        // Allowed never fails.
        assert!(
            legal_revalidation_failure(ContactDecision::Allowed, "legitimate interest", None)
                .is_none()
        );
    }

    // -----------------------------------------------------------------------
    // Live-database tests (ignored by default)
    // -----------------------------------------------------------------------

    /// A complete, cleanly executable send fixture on the canonically
    /// provisioned test database.
    struct SendFixture {
        tenant: String,
        account_id: Uuid,
        contact_id: Uuid,
        contact_point_id: Uuid,
        enrollment_id: Uuid,
        step_execution_id: Uuid,
        sender_id: Uuid,
        policy_id: Uuid,
        jurisdiction: String,
        email: String,
    }

    impl SendFixture {
        fn policy_input(&self) -> ContactPolicyInputOwned {
            ContactPolicyInputOwned {
                account_id: Some(self.account_id),
                contact_id: Some(self.contact_id),
                contact_point_id: Some(self.contact_point_id),
                recipient_country: Some(self.jurisdiction.clone()),
                country_confidence: 0.95,
                contact_type: "b2b_professional".into(),
                channel: "email".into(),
                source: Some("public_registry".into()),
                purpose: Some("sales_outreach".into()),
                has_existing_relationship: false,
                consent_status: None,
                soft_opt_in: false,
                legitimate_interest_assessed: true,
            }
        }
    }

    /// Canonically provisioned pool (never a raw `TEST_DATABASE_URL`).
    async fn live_pool(test_name: &str) -> Option<PgPool> {
        crate::test_db::canonical_test_pool(test_name).await
    }

    /// A 2-letter jurisdiction code unique enough that its policy row cannot
    /// collide with another test or a previous run on the shared database.
    fn unique_jurisdiction() -> String {
        let bytes = *Uuid::new_v4().as_bytes();
        format!(
            "{}{}",
            (b'A' + (bytes[0] % 26)) as char,
            (b'A' + (bytes[1] % 26)) as char
        )
    }

    async fn seed_send_fixture(
        pool: &PgPool,
        tenant: &str,
        policy_decision: &str,
        policy_basis: &str,
    ) -> SendFixture {
        let account_id = Uuid::new_v4();
        let contact_id = Uuid::new_v4();
        let contact_point_id = Uuid::new_v4();
        let sequence_id = Uuid::new_v4();
        let version_id = Uuid::new_v4();
        let step_id = Uuid::new_v4();
        let enrollment_id = Uuid::new_v4();
        let step_execution_id = Uuid::new_v4();
        let sender_id = Uuid::new_v4();
        // The policy row's id is generated by the shared race-safe helper, and
        // the code it actually used is what the fixture must key on.
        let jurisdiction = unique_jurisdiction();
        let email = format!("prospect-{contact_id}@example.com");

        sqlx::query(
            "INSERT INTO sales_accounts (id, tenant_id, company, domain, max_active_contacts) \
             VALUES ($1, $2, 'Revalidation Co', $3, 2)",
        )
        .bind(account_id)
        .bind(tenant)
        .bind(format!("{account_id}.example"))
        .execute(pool)
        .await
        .expect("insert sales_accounts");

        sqlx::query(
            "INSERT INTO sales_contacts (id, tenant_id, account_id, full_name, country) \
             VALUES ($1, $2, $3, 'Fixture Prospect', $4)",
        )
        .bind(contact_id)
        .bind(tenant)
        .bind(account_id)
        .bind(&jurisdiction)
        .execute(pool)
        .await
        .expect("insert sales_contacts");

        sqlx::query(
            "INSERT INTO sales_contact_points \
                 (id, tenant_id, contact_id, channel, value, normalized_value, verification) \
             VALUES ($1, $2, $3, 'email', $4, lower($4), 'valid')",
        )
        .bind(contact_point_id)
        .bind(tenant)
        .bind(contact_id)
        .bind(&email)
        .execute(pool)
        .await
        .expect("insert sales_contact_points");

        sqlx::query(
            "INSERT INTO sales_sequences (id, tenant_id, name, status) \
             VALUES ($1, $2, 'Revalidation Sequence', 'active')",
        )
        .bind(sequence_id)
        .bind(tenant)
        .execute(pool)
        .await
        .expect("insert sales_sequences");

        sqlx::query(
            "INSERT INTO sales_sequence_versions \
                 (id, tenant_id, sequence_id, version, status, locale, approved_by, approved_at) \
             VALUES ($1, $2, $3, 1, 'active', 'en', 'fixture', NOW())",
        )
        .bind(version_id)
        .bind(tenant)
        .bind(sequence_id)
        .execute(pool)
        .await
        .expect("insert sales_sequence_versions");

        sqlx::query(
            "INSERT INTO sales_sequence_steps \
                 (id, tenant_id, version_id, step_index, kind, min_delay_secs, max_delay_secs) \
             VALUES ($1, $2, $3, 0, 'email', 0, 0)",
        )
        .bind(step_id)
        .bind(tenant)
        .bind(version_id)
        .execute(pool)
        .await
        .expect("insert sales_sequence_steps");

        sqlx::query(
            "INSERT INTO sales_enrollments \
                 (id, tenant_id, sequence_version_id, account_id, contact_id, contact_point_id, \
                  state, current_step_index) \
             VALUES ($1, $2, $3, $4, $5, $6, 'active', 0)",
        )
        .bind(enrollment_id)
        .bind(tenant)
        .bind(version_id)
        .bind(account_id)
        .bind(contact_id)
        .bind(contact_point_id)
        .execute(pool)
        .await
        .expect("insert sales_enrollments");

        sqlx::query(
            "INSERT INTO sales_step_executions \
                 (id, tenant_id, enrollment_id, sequence_version_id, sequence_step_id, step_index, \
                  attempt_kind, variant, state, idempotency_key, scheduled_for) \
             VALUES ($1, $2, $3, $4, $5, 0, 'primary', 'default', 'scheduled', $6, NOW())",
        )
        .bind(step_execution_id)
        .bind(tenant)
        .bind(enrollment_id)
        .bind(version_id)
        .bind(step_id)
        .bind(format!("reval-{step_execution_id}"))
        .execute(pool)
        .await
        .expect("insert sales_step_executions");

        sqlx::query(
            "INSERT INTO sales_sender_identities \
                 (id, tenant_id, pool, from_email, from_name, domain, status, daily_limit) \
             VALUES ($1, $2, 'sales_outbound', $3, 'Fixture Sender', 'example.com', 'active', 200)",
        )
        .bind(sender_id)
        .bind(tenant)
        .bind(format!("sender-{sender_id}@example.com"))
        .execute(pool)
        .await
        .expect("insert sales_sender_identities");

        sqlx::query(
            "INSERT INTO sales_sender_health \
                 (id, tenant_id, sender_identity_id, health_score, state) \
             VALUES (gen_random_uuid(), $1, $2, 0.99, 'healthy')",
        )
        .bind(tenant)
        .bind(sender_id)
        .execute(pool)
        .await
        .expect("insert sales_sender_health");

        sqlx::query(
            "INSERT INTO sales_autonomy_state (tenant_id, mode) \
             VALUES ($1, 'autonomous_guarded')",
        )
        .bind(tenant)
        .execute(pool)
        .await
        .expect("insert sales_autonomy_state");

        // Race-safe: the 2-letter fixture namespace is small and shared across
        // parallel test processes, so the policy is inserted optimistically and
        // the code actually taken is the one the fixture must then use.
        let jurisdiction =
            crate::test_db::insert_unique_jurisdiction_policy(pool, policy_decision, policy_basis)
                .await;
        let policy_id: uuid::Uuid = sqlx::query_scalar(
            "SELECT id FROM sales_jurisdiction_policies WHERE jurisdiction = $1",
        )
        .bind(&jurisdiction)
        .fetch_one(pool)
        .await
        .expect("the inserted policy must be readable");

        SendFixture {
            tenant: tenant.to_string(),
            account_id,
            contact_id,
            contact_point_id,
            enrollment_id,
            step_execution_id,
            sender_id,
            policy_id,
            jurisdiction,
            email,
        }
    }

    fn send_context(fixture: &SendFixture, policy: ContactPolicyInputOwned) -> DecisionContext {
        DecisionContext {
            tenant_id: fixture.tenant.clone(),
            account_id: Some(fixture.account_id),
            contact_id: Some(fixture.contact_id),
            contact_point_id: Some(fixture.contact_point_id),
            enrollment_id: None,
            action: DecisionAction::FollowUp,
            score: OpportunityScore::default(),
            expected_value_eur: 250.0,
            confidence: 0.9,
            evidence_ids: Vec::new(),
            selected_offer: None,
            selected_sequence: None,
            selected_variant: None,
            selected_sender: None,
            model_version: Some("test".into()),
            policy: Some(policy),
            rationale: "live-DB revalidation fixture".into(),
            execute_after: None,
        }
    }

    /// Attach the decision to the step execution, the canonical carrier the
    /// live worker populates.
    async fn link_decision_to_step_execution(
        pool: &PgPool,
        decision_id: Uuid,
        step_execution_id: Uuid,
    ) {
        sqlx::query("UPDATE sales_step_executions SET decision_id = $1 WHERE id = $2")
            .bind(decision_id)
            .bind(step_execution_id)
            .execute(pool)
            .await
            .expect("link decision to step execution");
    }

    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn revalidation_denies_a_contact_suppressed_after_the_decision() {
        let Some(pool) =
            live_pool("decision_engine::tests::revalidation_denies_suppressed_after_decision")
                .await
        else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("reval-suppress");
        let fixture = seed_send_fixture(&pool, &tenant, "allowed", "legitimate_interest").await;

        let outcome = decide(&pool, send_context(&fixture, fixture.policy_input()))
            .await
            .unwrap();
        assert_eq!(
            outcome.enforcement,
            Enforcement::Execute,
            "fixture must start executable: {:?}",
            outcome.block_reasons
        );

        // The recipient unsubscribes AFTER the decision was made (and would
        // have been approved).
        sqlx::query("INSERT INTO sales_unsubscribes (tenant_id, email) VALUES ($1, $2)")
            .bind(&tenant)
            .bind(&fixture.email)
            .execute(&pool)
            .await
            .unwrap();

        let revalidation = revalidate_execution(&pool, outcome.decision_id)
            .await
            .unwrap();
        assert!(
            !revalidation.allowed,
            "an unsubscribe must defeat the old decision"
        );
        assert!(
            revalidation
                .reasons
                .iter()
                .any(|reason| reason.starts_with("suppressed:")),
            "reasons: {:?}",
            revalidation.reasons
        );
        assert!(revalidation.checked.contains(&GATE_SUPPRESSION));
    }

    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn revalidation_denies_a_human_reply_that_arrived_after_the_decision() {
        let Some(pool) =
            live_pool("decision_engine::tests::revalidation_denies_human_reply_after_decision")
                .await
        else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("reval-reply");
        let fixture = seed_send_fixture(&pool, &tenant, "allowed", "legitimate_interest").await;
        let outcome = decide(&pool, send_context(&fixture, fixture.policy_input()))
            .await
            .unwrap();
        assert_eq!(
            outcome.enforcement,
            Enforcement::Execute,
            "fixture must start executable: {:?}",
            outcome.block_reasons
        );
        link_decision_to_step_execution(&pool, outcome.decision_id, fixture.step_execution_id)
            .await;

        sqlx::query("UPDATE sales_enrollments SET has_human_reply = TRUE WHERE id = $1")
            .bind(fixture.enrollment_id)
            .execute(&pool)
            .await
            .unwrap();

        let revalidation = revalidate_execution(&pool, outcome.decision_id)
            .await
            .unwrap();
        assert!(
            !revalidation.allowed,
            "a human reply must defeat the old decision"
        );
        assert!(
            revalidation
                .reasons
                .iter()
                .any(|reason| reason.starts_with("human_reply:")),
            "reasons: {:?}",
            revalidation.reasons
        );
        assert!(revalidation.checked.contains(&GATE_HUMAN_REPLY));
    }

    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn prohibited_policy_denies_even_under_autonomous_guarded() {
        let Some(pool) =
            live_pool("decision_engine::tests::prohibited_policy_denies_autonomous_guarded").await
        else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("reval-prohibited");
        let fixture = seed_send_fixture(&pool, &tenant, "prohibited", "not_permitted").await;
        let outcome = decide(&pool, send_context(&fixture, fixture.policy_input()))
            .await
            .unwrap();
        assert_eq!(outcome.enforcement, Enforcement::Denied);
        assert!(
            outcome
                .block_reasons
                .iter()
                .any(|reason| reason.starts_with("legal_policy_prohibited")),
            "reasons: {:?}",
            outcome.block_reasons
        );

        // A policy that flips to prohibited after an allowed decision also
        // defeats the old decision at revalidation time.
        let allowed_tenant = crate::test_db::unique_test_tenant("reval-flip");
        let allowed =
            seed_send_fixture(&pool, &allowed_tenant, "allowed", "legitimate_interest").await;
        let first = decide(&pool, send_context(&allowed, allowed.policy_input()))
            .await
            .unwrap();
        assert_eq!(first.enforcement, Enforcement::Execute);

        sqlx::query(
            "UPDATE sales_jurisdiction_policies \
             SET decision = 'prohibited', basis = 'not_permitted' WHERE id = $1",
        )
        .bind(allowed.policy_id)
        .execute(&pool)
        .await
        .unwrap();

        let revalidation = revalidate_execution(&pool, first.decision_id)
            .await
            .unwrap();
        assert!(!revalidation.allowed);
        assert!(
            revalidation
                .reasons
                .iter()
                .any(|reason| reason.starts_with("legal_policy_prohibited")),
            "reasons: {:?}",
            revalidation.reasons
        );
    }

    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn checked_names_every_gate_that_was_re_read() {
        let Some(pool) = live_pool("decision_engine::tests::checked_names_every_gate").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("reval-checked");
        let fixture = seed_send_fixture(&pool, &tenant, "allowed", "legitimate_interest").await;
        let outcome = {
            // The live worker resolves and stores the sender before the packet
            // is written; the fixture must too so the sender gate is evaluated.
            let mut ctx = send_context(&fixture, fixture.policy_input());
            ctx.selected_sender = Some(fixture.sender_id);
            decide(&pool, ctx).await.unwrap()
        };
        assert_eq!(
            outcome.enforcement,
            Enforcement::Execute,
            "fixture must start executable: {:?}",
            outcome.block_reasons
        );
        link_decision_to_step_execution(&pool, outcome.decision_id, fixture.step_execution_id)
            .await;

        let revalidation = revalidate_execution(&pool, outcome.decision_id)
            .await
            .unwrap();
        assert!(
            revalidation.allowed,
            "clean fixture must revalidate: {:?}",
            revalidation.reasons
        );
        assert_eq!(
            revalidation.checked,
            vec![
                GATE_KILL_SWITCH,
                GATE_AUTONOMY_MODE,
                GATE_SUPPRESSION,
                GATE_CONTACT_POINT_SUPPRESSED,
                GATE_ADDRESS_VERIFICATION,
                GATE_HUMAN_REPLY,
                GATE_SENDER_HEALTH,
                GATE_FREQUENCY_BUDGET,
                GATE_LEGAL_POLICY,
            ]
        );
    }

    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn revalidation_of_a_missing_decision_is_an_error() {
        let Some(pool) = live_pool("decision_engine::tests::missing_decision").await else {
            return;
        };
        let missing = Uuid::new_v4();
        let err = revalidate_execution(&pool, missing).await.unwrap_err();
        assert!(
            matches!(err, SalesError::InvalidInput(_)),
            "unexpected error: {err}"
        );
        assert!(err.to_string().contains(&missing.to_string()));
    }
}
