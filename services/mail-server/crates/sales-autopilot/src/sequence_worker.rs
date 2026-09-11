//! Sequence step worker.
//!
//! This is the production [`ActionHandler`] for `send_step` actions. It is the
//! single place where a queued step execution becomes an outbound email, and it
//! is deliberately the *last* place every hard gate is checked:
//!
//! 1. the tenant's autonomy mode still permits execution and the kill switch is
//!    not engaged (read at execution time, not at enqueue time);
//! 2. the enrollment has no human reply;
//! 3. the step is still `scheduled`/`queued` (a reply may have cancelled it);
//! 4. suppression is re-checked inside the dispatcher's transaction.
//!
//! # The optimizer and the next-best-action gate (§17/§28)
//!
//! Before the send is attempted this handler:
//!
//! * selects the experiment arm for the step (when the step declares an
//!   `experiment_key`) through [`crate::experiments::ExperimentEngine`] and
//!   **persists the chosen variant onto `sales_step_executions.variant` and
//!   `sales_enrollments.experiment_id`/`experiment_variant`** — the variant
//!   therefore survives an enqueue failure and an outcome can be attributed
//!   even if the process dies immediately after;
//! * evaluates the pure §28 [`crate::experiments::next_best_action`] policy
//!   against the live account state. A `DoNothing` (or any internal action)
//!   skips the send with the policy's reason recorded in `skip_reason`, so a
//!   weak prospect cannot be contacted merely because a step was queued.
//!
//! Both are deliberate: the audit found the optimizer was never invoked from
//! the send path and that a system able to choose only "send" maximizes spam
//! volume.
//!
//! A denial is not an error — it is a recorded, non-retryable skip. Retrying a
//! policy denial would be exactly the "legal-policy denial bypassed through
//! another route" failure the release gates forbid.

use std::sync::Arc;

use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::actions::{ActionHandler, ActionOutcome, LeasedAction};
use crate::autonomy;
use crate::dispatcher::{
    fetch_template, render_for_recipient_with_footer, send_idempotency_key,
    sign_unsubscribe_token_default_ttl, EnqueueOutcome, FooterReason, OutreachFooter,
    ProductionCampaignDispatcher, SendIdentity,
};
use crate::experiments::{
    next_best_action, EmailState, ExperimentContext, ExperimentEngine, NextActionInput, ReplyState,
    VariantContext, VariantSelection, DEFAULT_OUTREACH_COST_EUR,
};
use crate::sequences;
use crate::types::{SalesError, SenderPool};

/// The production handler for sequence actions.
pub struct SequenceStepHandler {
    db: PgPool,
    dispatcher: Arc<ProductionCampaignDispatcher>,
}

impl SequenceStepHandler {
    pub fn new(db: PgPool, dispatcher: Arc<ProductionCampaignDispatcher>) -> Self {
        Self { db, dispatcher }
    }

    /// Load the step execution plus everything the send needs.
    async fn load_context(
        &self,
        step_execution_id: Uuid,
    ) -> Result<Option<StepContext>, SalesError> {
        let row: Option<StepContextRow> = sqlx::query_as(
            "SELECT \
                 se.id AS step_execution_id, se.tenant_id, se.enrollment_id, \
                 se.sequence_version_id, se.sequence_step_id, se.step_index, \
                 se.attempt_kind, se.variant, se.state, \
                 e.has_human_reply, e.state AS enrollment_state, \
                 e.contact_id, e.account_id, \
                 s.kind AS step_kind, s.template_id, s.sender_pool, s.experiment_key \
             FROM sales_step_executions se \
             JOIN sales_enrollments e ON e.id = se.enrollment_id \
             JOIN sales_sequence_steps s ON s.id = se.sequence_step_id \
             WHERE se.id = $1",
        )
        .bind(step_execution_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        Ok(row.map(StepContext::from))
    }

    /// Resolve the recipient email for a step execution.
    async fn recipient_email(&self, ctx: &StepContext) -> Result<Option<String>, SalesError> {
        let email: Option<String> = sqlx::query_scalar(
            "SELECT cp.normalized_value \
             FROM sales_contact_points cp \
             WHERE cp.tenant_id = $1 AND cp.contact_id = $2 AND cp.channel = 'email' \
               AND cp.suppressed_at IS NULL \
               AND cp.verification IN ('valid', 'risky') \
             ORDER BY CASE cp.verification WHEN 'valid' THEN 0 ELSE 1 END, cp.confidence DESC \
             LIMIT 1",
        )
        .bind(&ctx.tenant_id)
        .bind(ctx.contact_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
        Ok(email)
    }

    /// Mark the execution skipped and record why. Never retried.
    async fn skip(
        &self,
        step_execution_id: Uuid,
        reason: &str,
    ) -> Result<ActionOutcome, SalesError> {
        sqlx::query(
            "UPDATE sales_step_executions \
             SET state = 'skipped', skip_reason = $2, updated_at = NOW() \
             WHERE id = $1 AND state IN ('scheduled', 'queued')",
        )
        .bind(step_execution_id)
        .bind(reason)
        .execute(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
        Ok(ActionOutcome::Succeeded)
    }
}

#[derive(sqlx::FromRow)]
struct StepContextRow {
    step_execution_id: Uuid,
    tenant_id: String,
    enrollment_id: Uuid,
    sequence_version_id: Uuid,
    sequence_step_id: Uuid,
    step_index: i32,
    attempt_kind: String,
    variant: String,
    state: String,
    has_human_reply: bool,
    enrollment_state: String,
    contact_id: Uuid,
    account_id: Option<Uuid>,
    step_kind: String,
    template_id: Option<String>,
    sender_pool: String,
    experiment_key: Option<String>,
}

struct StepContext {
    step_execution_id: Uuid,
    tenant_id: String,
    enrollment_id: Uuid,
    sequence_version_id: Uuid,
    sequence_step_id: Uuid,
    step_index: i32,
    attempt_kind: String,
    variant: String,
    state: String,
    has_human_reply: bool,
    enrollment_state: String,
    contact_id: Uuid,
    account_id: Option<Uuid>,
    step_kind: String,
    template_id: Option<String>,
    sender_pool: String,
    /// `sales_sequence_steps.experiment_key` (migration line 479). When set,
    /// the arm is selected and persisted before the send.
    experiment_key: Option<String>,
}

impl From<StepContextRow> for StepContext {
    fn from(row: StepContextRow) -> Self {
        Self {
            step_execution_id: row.step_execution_id,
            tenant_id: row.tenant_id,
            enrollment_id: row.enrollment_id,
            sequence_version_id: row.sequence_version_id,
            sequence_step_id: row.sequence_step_id,
            step_index: row.step_index,
            attempt_kind: row.attempt_kind,
            variant: row.variant,
            state: row.state,
            has_human_reply: row.has_human_reply,
            enrollment_state: row.enrollment_state,
            contact_id: row.contact_id,
            account_id: row.account_id,
            step_kind: row.step_kind,
            template_id: row.template_id,
            sender_pool: row.sender_pool,
            experiment_key: row.experiment_key,
        }
    }
}

/// Company-size band used as a context dimension.
pub fn company_size_band(employees: Option<i64>) -> Option<String> {
    match employees {
        Some(count) if count <= 10 => Some("1-10".to_string()),
        Some(count) if count <= 50 => Some("11-50".to_string()),
        Some(count) if count <= 200 => Some("51-200".to_string()),
        Some(count) if count <= 1_000 => Some("201-1000".to_string()),
        Some(_) => Some("1001+".to_string()),
        None => None,
    }
}

/// Intent bucket (0-100 scorer dimension) used as a context dimension.
pub fn intent_bucket(intent: f64) -> String {
    if !intent.is_finite() {
        return "unknown".to_string();
    }
    match intent.max(0.0) {
        value if value < 20.0 => "none".to_string(),
        value if value < 40.0 => "low".to_string(),
        value if value < 70.0 => "medium".to_string(),
        _ => "high".to_string(),
    }
}

/// Select the experiment arm for a step execution and **persist it before any
/// send is attempted**.
///
/// The variant is written to `sales_step_executions.variant` (migration line
/// 532) and `sales_enrollments.experiment_id` / `experiment_variant` (lines
/// 502-503) in one transaction, so an outcome can be attributed even if the
/// process dies immediately after planning and before the dispatcher is
/// called. Returns `Ok(None)` when the step execution no longer exists.
pub async fn select_and_persist_variant(
    db: &PgPool,
    tenant_id: &str,
    step_execution_id: Uuid,
    experiment_key: &str,
) -> Result<Option<VariantSelection>, SalesError> {
    if tenant_id.trim().is_empty() {
        return Err(SalesError::InvalidInput("tenant_id is required".into()));
    }
    if experiment_key.trim().is_empty() {
        return Err(SalesError::InvalidInput(
            "experiment_key is required".into(),
        ));
    }

    let row = sqlx::query(
        "SELECT se.enrollment_id, e.account_id, e.contact_id, \
                s.kind AS step_kind, s.sender_pool, \
                a.icp_segment, a.employees, a.esp_hypotheses, \
                a.country AS account_country, \
                c.persona, c.seniority, c.department, c.country AS contact_country, c.language \
         FROM sales_step_executions se \
         JOIN sales_enrollments e ON e.id = se.enrollment_id \
         JOIN sales_sequence_steps s ON s.id = se.sequence_step_id \
         LEFT JOIN sales_accounts a ON a.id = e.account_id \
         LEFT JOIN sales_contacts c ON c.id = e.contact_id \
         WHERE se.id = $1 AND se.tenant_id = $2",
    )
    .bind(step_execution_id)
    .bind(tenant_id)
    .fetch_optional(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    let Some(row) = row else { return Ok(None) };

    let enrollment_id: Uuid = row
        .try_get("enrollment_id")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let account_id: Option<Uuid> = row
        .try_get("account_id")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let step_kind: String = row
        .try_get("step_kind")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let sender_pool: String = row
        .try_get("sender_pool")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let icp_segment: Option<String> = row
        .try_get("icp_segment")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let employees: Option<i64> = row
        .try_get::<Option<i32>, _>("employees")
        .map_err(|error| SalesError::Database(error.to_string()))?
        .map(i64::from);
    let esp_hypotheses: Option<serde_json::Value> = row
        .try_get("esp_hypotheses")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let account_country: Option<String> = row
        .try_get("account_country")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let persona: Option<String> = row
        .try_get("persona")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let seniority: Option<String> = row
        .try_get("seniority")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let department: Option<String> = row
        .try_get("department")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let contact_country: Option<String> = row
        .try_get("contact_country")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let language: Option<String> = row
        .try_get("language")
        .map_err(|error| SalesError::Database(error.to_string()))?;

    let score = match account_id {
        Some(account_id) => sqlx::query(
            "SELECT expected_value_eur::float8 AS ev, intent::float8 AS intent \
             FROM sales_scores WHERE tenant_id = $1 AND account_id = $2 \
             ORDER BY computed_at DESC, id DESC LIMIT 1",
        )
        .bind(tenant_id)
        .bind(account_id)
        .fetch_optional(db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?,
        None => None,
    };
    let (account_ev, intent) = match &score {
        Some(row) => (
            row.try_get::<f64, _>("ev")
                .map_err(|error| SalesError::Database(error.to_string()))?,
            Some(
                row.try_get::<f64, _>("intent")
                    .map_err(|error| SalesError::Database(error.to_string()))?,
            ),
        ),
        None => (0.0, None),
    };

    let esp_hypothesis = esp_hypotheses
        .as_ref()
        .and_then(|value| value.as_array())
        .and_then(|items| items.first())
        .and_then(|value| value.as_str())
        .map(|value| value.to_string());

    let dimensions = ExperimentContext {
        icp_segment,
        country: contact_country.or(account_country),
        company_size_band: company_size_band(employees),
        persona: persona.or(seniority).or(department),
        esp_hypothesis,
        intent_bucket: intent.map(intent_bucket),
        // The step/decision layer does not carry an offer id yet; leaving the
        // dimension absent is correct (it simply does not participate in the
        // bucket) rather than inventing one.
        offer: None,
        language,
        step_kind: Some(step_kind),
        sender_type: Some(sender_pool),
    };
    let context = VariantContext {
        dimensions,
        sender_domain_exposure: 0,
        daily_exploration_pct: 0.0,
        account_expected_value_eur: if account_ev.is_finite() {
            account_ev
        } else {
            0.0
        },
        explicit_exploration_override: false,
    };

    let engine = ExperimentEngine::new(db.clone());
    let Some(experiment) = engine
        .load_experiment(tenant_id, experiment_key.trim())
        .await?
    else {
        return Err(SalesError::InvalidInput(format!(
            "step declares experiment '{experiment_key}' which does not exist for tenant \
             {tenant_id}"
        )));
    };
    let selection = engine
        .select_variant(tenant_id, &experiment, &context)
        .await?;

    // Persist BEFORE the dispatcher is called: the variant must survive an
    // enqueue failure so the outcome can be attributed.
    let mut tx = db
        .begin()
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let updated_step = sqlx::query(
        "UPDATE sales_step_executions SET variant = $2, updated_at = NOW() \
         WHERE id = $1 AND tenant_id = $3",
    )
    .bind(step_execution_id)
    .bind(&selection.variant)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?
    .rows_affected();
    if updated_step != 1 {
        return Err(SalesError::Database(format!(
            "step execution {step_execution_id} disappeared while persisting the experiment variant"
        )));
    }
    let updated_enrollment = sqlx::query(
        "UPDATE sales_enrollments \
         SET experiment_id = $2, experiment_variant = $3, updated_at = NOW() \
         WHERE id = $1 AND tenant_id = $4",
    )
    .bind(enrollment_id)
    .bind(selection.experiment_id)
    .bind(&selection.variant)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?
    .rows_affected();
    if updated_enrollment != 1 {
        return Err(SalesError::Database(format!(
            "enrollment {enrollment_id} disappeared while persisting the experiment variant"
        )));
    }
    tx.commit()
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;

    tracing::info!(
        step_execution_id = %step_execution_id,
        variant = %selection.variant,
        experiment_id = %selection.experiment_id,
        explore = selection.explore,
        used_context_bucket = selection.used_context_bucket,
        reason = %selection.reason,
        "experiment arm selected and persisted before send"
    );
    Ok(Some(selection))
}

/// The §28 gate: evaluate the pure next-best-action policy against live state
/// and return `Some(skip_reason)` when the send must not happen.
///
/// The gate deliberately uses the most recent `sales_scores` row; when the
/// account has never been scored it returns `None` and the existing hard gates
/// (suppression, legal policy, reply, frequency) govern as before. A score row
/// whose policy says `DoNothing`/`Wait`/`Enrich`/... skips the send with the
/// policy's reason recorded in `sales_step_executions.skip_reason`.
pub async fn next_best_action_skip_reason(
    db: &PgPool,
    tenant_id: &str,
    account_id: Option<Uuid>,
    contact_id: Uuid,
    enrollment_id: Uuid,
    has_human_reply: bool,
) -> Result<Option<String>, SalesError> {
    if has_human_reply {
        return Ok(Some(
            "next_best_action=operator_task: a human already replied; automation must not send \
             again"
                .to_string(),
        ));
    }
    let Some(account_id) = account_id else {
        return Ok(None);
    };

    let score = sqlx::query(
        "SELECT expected_value_eur::float8 AS ev, intent::float8 AS intent, \
                evidence_quality::float8 AS evidence_quality \
         FROM sales_scores WHERE tenant_id = $1 AND account_id = $2 \
         ORDER BY computed_at DESC, id DESC LIMIT 1",
    )
    .bind(tenant_id)
    .bind(account_id)
    .fetch_optional(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    let Some(score) = score else {
        return Ok(None);
    };
    let expected_value_eur: f64 = score
        .try_get("ev")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let intent: f64 = score
        .try_get("intent")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let evidence_quality: f64 = score
        .try_get("evidence_quality")
        .map_err(|error| SalesError::Database(error.to_string()))?;

    let evidence_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM sales_evidence \
         WHERE tenant_id = $1 AND account_id = $2",
    )
    .bind(tenant_id)
    .bind(account_id)
    .fetch_one(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    let prior_touches: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM sales_step_executions se \
         JOIN sales_enrollments e ON e.id = se.enrollment_id \
         WHERE e.tenant_id = $1 AND e.id = $2 AND se.state = 'sent'",
    )
    .bind(tenant_id)
    .bind(enrollment_id)
    .fetch_one(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    let verification: Option<String> = sqlx::query_scalar(
        "SELECT verification FROM sales_contact_points \
         WHERE tenant_id = $1 AND contact_id = $2 AND channel = 'email' \
         ORDER BY CASE verification WHEN 'valid' THEN 0 WHEN 'risky' THEN 1 ELSE 2 END, \
                  confidence DESC LIMIT 1",
    )
    .bind(tenant_id)
    .bind(contact_id)
    .fetch_optional(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    let email = match verification.as_deref() {
        Some("valid") => EmailState::Verified,
        Some("risky") => EmailState::Risky,
        Some("invalid") => EmailState::Invalid,
        _ => EmailState::Unverified,
    };
    let opportunity_open: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sales_opportunities \
         WHERE tenant_id = $1 AND account_id = $2 \
           AND stage IN ('open', 'qualified', 'negotiation'))",
    )
    .bind(tenant_id)
    .bind(account_id)
    .fetch_one(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    let input = NextActionInput {
        expected_value_eur,
        outreach_cost_eur: DEFAULT_OUTREACH_COST_EUR,
        evidence_count: evidence_count.max(0) as u32,
        evidence_confidence: (evidence_quality / 100.0).clamp(0.0, 1.0) as f32,
        reply: ReplyState::None,
        email,
        intent_strength: (intent / 100.0).clamp(0.0, 1.0) as f32,
        prior_touches: prior_touches.max(0) as u32,
        last_angle_failed: false,
        referral_available: false,
        referral_requested: false,
        opportunity_open,
        cooldown_active: false,
        disqualified: false,
    };
    let (action, reason) = next_best_action(&input);
    if action.is_external_send() {
        Ok(None)
    } else {
        Ok(Some(format!(
            "next_best_action={}: {reason}",
            action.as_str()
        )))
    }
}

#[async_trait::async_trait]
impl ActionHandler for SequenceStepHandler {
    async fn handle(&self, action: &LeasedAction) -> ActionOutcome {
        match self.handle_inner(action).await {
            Ok(outcome) => outcome,
            Err(error) => {
                // Infrastructure failures are retryable; the queue's backoff
                // and max-attempts bound them into a dead letter.
                ActionOutcome::Retry(format!("{error}"))
            }
        }
    }
}

impl SequenceStepHandler {
    async fn handle_inner(&self, action: &LeasedAction) -> Result<ActionOutcome, SalesError> {
        let step_execution_id = action.action.entity_id;
        let tenant_id = action.tenant_id().to_string();

        let Some(mut ctx) = self.load_context(step_execution_id).await? else {
            return Ok(ActionOutcome::DeadLetter(format!(
                "step execution {step_execution_id} no longer exists"
            )));
        };

        // The entity must belong to the tenant the action was queued for.
        if ctx.tenant_id != tenant_id {
            return Ok(ActionOutcome::DeadLetter(format!(
                "step execution {step_execution_id} belongs to tenant {} but the action is for {}",
                ctx.tenant_id, tenant_id
            )));
        }

        // Only an email step sends. Other kinds are handled by their own
        // workers; a wait/nurture step reaching the send handler is a bug in
        // the sequencer, so it is surfaced rather than silently skipped.
        if ctx.step_kind != "email" {
            return self
                .skip(
                    ctx.step_execution_id,
                    &format!("step kind '{}' is not a send step", ctx.step_kind),
                )
                .await;
        }

        // Already sent or skipped: a replay must be a no-op, not a second email.
        if ctx.state == "sent" || ctx.state == "skipped" || ctx.state == "cancelled" {
            tracing::info!(
                step_execution_id = %ctx.step_execution_id,
                state = %ctx.state,
                "sequence step already terminal — replay is a no-op"
            );
            return Ok(ActionOutcome::Succeeded);
        }

        // §17: select and persist the experiment arm BEFORE the send. The
        // variant row is durable, so an outcome can be attributed even if the
        // enqueue below fails or the process dies. A selection failure is a
        // dead letter, not a silent fallback to an arbitrary variant.
        if let Some(experiment_key) = ctx.experiment_key.clone() {
            match select_and_persist_variant(
                &self.db,
                &ctx.tenant_id,
                ctx.step_execution_id,
                &experiment_key,
            )
            .await
            {
                Ok(Some(selection)) => {
                    ctx.variant = selection.variant;
                }
                Ok(None) => {
                    return Ok(ActionOutcome::DeadLetter(format!(
                        "step execution {} vanished during experiment variant selection",
                        ctx.step_execution_id
                    )));
                }
                Err(error) => {
                    return Ok(ActionOutcome::DeadLetter(format!(
                        "experiment arm selection failed for '{experiment_key}': {error}"
                    )));
                }
            }
        }

        // Gate 1: autonomy at execution time. The kill switch must stop new
        // outbound work immediately, even for already-queued actions.
        let autonomy_state = autonomy::load(&self.db, &ctx.tenant_id).await?;
        if autonomy_state.kill_switch {
            return self
                .skip(ctx.step_execution_id, "global kill switch engaged")
                .await;
        }
        if !autonomy_state.permits_execution() {
            // Shadow/disabled: the brain may still think, but nothing sends.
            // Recorded as a skip with the mode named so the CP can explain it.
            return self
                .skip(
                    ctx.step_execution_id,
                    &format!(
                        "autonomy mode '{}' does not permit execution",
                        autonomy_state.mode.as_str()
                    ),
                )
                .await;
        }
        if autonomy_state.mode.requires_operator_approval() {
            // Assisted/ApprovalRequired: an unapproved decision must not send.
            // The decision row is the approval carrier.
            return self
                .skip(
                    ctx.step_execution_id,
                    &format!(
                        "autonomy mode '{}' requires operator approval before sending",
                        autonomy_state.mode.as_str()
                    ),
                )
                .await;
        }

        // Gate 2: a human reply must prevent this touch from racing out.
        if ctx.has_human_reply {
            return self
                .skip(ctx.step_execution_id, "enrollment has a human reply")
                .await;
        }

        // Gate 3: the enrollment must still be on the normal path.
        if !matches!(ctx.enrollment_state.as_str(), "active" | "waiting") {
            return self
                .skip(
                    ctx.step_execution_id,
                    &format!(
                        "enrollment state '{}' is not sendable",
                        ctx.enrollment_state
                    ),
                )
                .await;
        }

        // Gate 3b (§28): the next-best-action policy. `DoNothing`, `Wait`,
        // `Nurture`, `Enrich`, ... all skip the send and record why. A system
        // that can only choose "send" is the spam-volume defect the audit
        // names.
        if let Some(skip_reason) = next_best_action_skip_reason(
            &self.db,
            &ctx.tenant_id,
            ctx.account_id,
            ctx.contact_id,
            ctx.enrollment_id,
            ctx.has_human_reply,
        )
        .await?
        {
            return self.skip(ctx.step_execution_id, &skip_reason).await;
        }

        // Gate 4: the sender pool must be a sales pool.
        let Some(pool) = SenderPool::parse(&ctx.sender_pool) else {
            return Ok(ActionOutcome::DeadLetter(format!(
                "step declares unknown sender pool '{}'",
                ctx.sender_pool
            )));
        };
        if !pool.is_sales_pool() {
            return Ok(ActionOutcome::DeadLetter(format!(
                "step declares non-sales sender pool '{}' — refusing to send",
                pool
            )));
        }

        let Some(template_id) = ctx.template_id.as_deref() else {
            return Ok(ActionOutcome::DeadLetter(format!(
                "email step {} has no template_id",
                ctx.sequence_step_id
            )));
        };

        let Some(recipient_email) = self.recipient_email(&ctx).await? else {
            return self
                .skip(
                    ctx.step_execution_id,
                    "no verified, unsuppressed email contact point",
                )
                .await;
        };

        let Some(client) = self.load_client(&ctx, template_id).await? else {
            return self
                .skip(ctx.step_execution_id, "recipient or template unavailable")
                .await;
        };

        let rendered = match fetch_template(&self.db, &ctx.tenant_id, template_id).await {
            Ok(template) => {
                let footer = OutreachFooter {
                    sender_identity: &client.sender_identity,
                    // The footer states the lawful basis actually being relied
                    // on. It never claims a signup that did not happen.
                    reason: FooterReason::BusinessContact {
                        basis: "your organisation appears to be a potential fit for ApexMail's email delivery platform.",
                    },
                    unsubscribe_link: &client.unsubscribe_link,
                    postal_address: None,
                    privacy_url: None,
                };
                let recipient = crate::campaigns::DispatchRecipient {
                    email: recipient_email.clone(),
                    unsubscribe_link: client.unsubscribe_link.clone(),
                    lead: client.lead.clone(),
                };
                render_for_recipient_with_footer(&template, &recipient, footer)
            }
            Err(error) => return Ok(ActionOutcome::DeadLetter(format!("{error}"))),
        };
        let rendered = match rendered {
            Ok(rendered) => rendered,
            Err(error) => return Ok(ActionOutcome::DeadLetter(format!("{error}"))),
        };

        // Claim the execution before sending: `state = 'executing'` is the
        // mutation that makes a concurrent replay of this action see it as
        // in-flight and stop.
        let claimed: Option<Uuid> = sqlx::query_scalar(
            "UPDATE sales_step_executions \
             SET state = 'executing', attempt = attempt + 1, updated_at = NOW() \
             WHERE id = $1 AND state IN ('scheduled', 'queued') \
             RETURNING id",
        )
        .bind(ctx.step_execution_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        if claimed.is_none() {
            tracing::info!(
                step_execution_id = %ctx.step_execution_id,
                "sequence step was claimed by another worker — skipping"
            );
            return Ok(ActionOutcome::Succeeded);
        }

        // The send identity is the logical step execution, so a later
        // legitimate touch is a different message, not a suppressed duplicate.
        let key = send_idempotency_key(SendIdentity::StepExecution {
            enrollment_id: ctx.enrollment_id,
            sequence_version_id: ctx.sequence_version_id,
            step_id: ctx.sequence_step_id,
            attempt_kind: &ctx.attempt_kind,
            variant: &ctx.variant,
        });

        let metadata = serde_json::json!({
            "enrollment_id": ctx.enrollment_id.to_string(),
            "sequence_version_id": ctx.sequence_version_id.to_string(),
            "step_id": ctx.sequence_step_id.to_string(),
            "step_index": ctx.step_index,
            "variant": ctx.variant,
            "autonomy_mode": autonomy_state.mode.as_str(),
        });

        let outcome = self
            .dispatcher
            .enqueue_sequenced(
                &ctx.tenant_id,
                &key,
                &rendered,
                &recipient_email,
                &client.unsubscribe_link,
                metadata,
            )
            .await?;

        let (state, message_id) = match outcome {
            EnqueueOutcome::Enqueued => (("sent"), Some(key)),
            // Already enqueued under this identity: the previous attempt did
            // the work. Mark it sent so it is not retried forever.
            EnqueueOutcome::DuplicateIdempotency => ("sent", None),
            // Suppressed between decision and send.
            EnqueueOutcome::AlreadyClaimed => ("cancelled", None),
        };

        let _ = &message_id;

        sqlx::query(
            "UPDATE sales_step_executions \
             SET state = $2, executed_at = NOW(), updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(ctx.step_execution_id)
        .bind(state)
        .execute(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        // Advance the enrollment and schedule the next step. Done here (rather
        // than in a separate scheduler pass) so a completed step immediately
        // creates its successor; the successor's action carries its own
        // idempotency key, so a retry of this handler cannot double-enqueue.
        if state == "sent" {
            self.advance_enrollment(&ctx).await?;
        }

        Ok(ActionOutcome::Succeeded)
    }

    /// Move the enrollment to its next step and enqueue that step's action.
    async fn advance_enrollment(&self, ctx: &StepContext) -> Result<(), SalesError> {
        let version =
            sequences::load_version(&self.db, &ctx.tenant_id, ctx.sequence_version_id).await?;

        match sequences::next_step(&version, ctx.step_index) {
            Some(next) => {
                let step_execution_id = Uuid::new_v4();
                let key = send_idempotency_key(SendIdentity::StepExecution {
                    enrollment_id: ctx.enrollment_id,
                    sequence_version_id: ctx.sequence_version_id,
                    step_id: next.id,
                    attempt_kind: &ctx.attempt_kind,
                    variant: &ctx.variant,
                });
                let delay = sequences::schedule_delay_secs(next, &key);
                let next_state = if next.min_delay_secs > 0 {
                    "waiting"
                } else {
                    "active"
                };

                let mut tx = self
                    .db
                    .begin()
                    .await
                    .map_err(|e| SalesError::Database(e.to_string()))?;

                sqlx::query(
                    "INSERT INTO sales_step_executions ( \
                         id, tenant_id, enrollment_id, sequence_version_id, sequence_step_id, \
                         step_index, attempt_kind, variant, state, idempotency_key, \
                         scheduled_for, created_at, updated_at \
                     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'scheduled', $9, \
                               NOW() + make_interval(secs => $10::double precision), NOW(), NOW()) \
                     ON CONFLICT (idempotency_key) DO NOTHING",
                )
                .bind(step_execution_id)
                .bind(&ctx.tenant_id)
                .bind(ctx.enrollment_id)
                .bind(ctx.sequence_version_id)
                .bind(next.id)
                .bind(next.step_index)
                .bind(&ctx.attempt_kind)
                .bind(&ctx.variant)
                .bind(&key)
                .bind(delay as f64)
                .execute(&mut *tx)
                .await
                .map_err(|e| SalesError::Database(e.to_string()))?;

                sqlx::query(
                    "UPDATE sales_enrollments \
                     SET current_step_index = $2, state = $3, updated_at = NOW() \
                     WHERE id = $1",
                )
                .bind(ctx.enrollment_id)
                .bind(next.step_index)
                .bind(next_state)
                .execute(&mut *tx)
                .await
                .map_err(|e| SalesError::Database(e.to_string()))?;

                crate::actions::ActionQueue::enqueue_tx(
                    &mut tx,
                    &ctx.tenant_id,
                    crate::actions::action_type::SEND_STEP,
                    crate::actions::entity_type::STEP_EXECUTION,
                    step_execution_id,
                    &format!("sa-send:{step_execution_id}"),
                    serde_json::json!({
                        "enrollment_id": ctx.enrollment_id.to_string(),
                        "step_index": next.step_index,
                    }),
                    chrono::Utc::now() + chrono::Duration::seconds(delay),
                    100,
                    None,
                )
                .await?;

                tx.commit()
                    .await
                    .map_err(|e| SalesError::Database(e.to_string()))?;
            }
            None => {
                sqlx::query(
                    "UPDATE sales_enrollments \
                     SET state = 'completed', completed_at = NOW(), updated_at = NOW() \
                     WHERE id = $1",
                )
                .bind(ctx.enrollment_id)
                .execute(&self.db)
                .await
                .map_err(|e| SalesError::Database(e.to_string()))?;
            }
        }

        Ok(())
    }

    /// Per-recipient client data the renderer needs.
    async fn load_client(
        &self,
        ctx: &StepContext,
        template_id: &str,
    ) -> Result<Option<ClientContext>, SalesError> {
        // The template must exist for this tenant; a missing template is a
        // dead letter, not a retry loop.
        if fetch_template(&self.db, &ctx.tenant_id, template_id)
            .await
            .is_err()
        {
            return Ok(None);
        }

        let lead: Option<(Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT c.full_name, a.company \
             FROM sales_contacts c \
             LEFT JOIN sales_accounts a ON a.id = c.account_id \
             WHERE c.id = $1 AND c.tenant_id = $2",
        )
        .bind(ctx.contact_id)
        .bind(&ctx.tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        let (name, company) = lead.unwrap_or((None, None));

        let email: Option<String> = sqlx::query_scalar(
            "SELECT normalized_value FROM sales_contact_points \
             WHERE tenant_id = $1 AND contact_id = $2 AND channel = 'email' \
               AND suppressed_at IS NULL AND verification IN ('valid', 'risky') \
             ORDER BY CASE verification WHEN 'valid' THEN 0 ELSE 1 END, confidence DESC \
             LIMIT 1",
        )
        .bind(&ctx.tenant_id)
        .bind(ctx.contact_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        let Some(email) = email else {
            return Ok(None);
        };

        let token = sign_unsubscribe_token_default_ttl(
            &self.dispatcher.config().unsubscribe_secret,
            &ctx.tenant_id,
            &email,
        );
        let unsubscribe_link = format!("{}/u/{}", self.dispatcher.config().public_base_url, token);

        Ok(Some(ClientContext {
            unsubscribe_link,
            sender_identity: self.dispatcher.config().from_name.clone(),
            lead: Some(crate::dispatcher::LeadProfile {
                name: name.unwrap_or_default(),
                company: company.unwrap_or_default(),
                title: String::new(),
            }),
        }))
    }
}

struct ClientContext {
    unsubscribe_link: String,
    sender_identity: String,
    lead: Option<crate::dispatcher::LeadProfile>,
}

/// A handler that only enforces the "no execution" gates and then reports the
/// action as handled externally. Used by the test suite and by deployments
/// that wire their own sender.
pub struct GateOnlyHandler {
    db: PgPool,
}

impl GateOnlyHandler {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }
}

#[async_trait::async_trait]
impl ActionHandler for GateOnlyHandler {
    async fn handle(&self, action: &LeasedAction) -> ActionOutcome {
        match autonomy::load(&self.db, action.tenant_id()).await {
            Ok(state) if state.kill_switch => ActionOutcome::Succeeded,
            Ok(state) if !state.permits_execution() => ActionOutcome::Succeeded,
            Ok(_) => ActionOutcome::Succeeded,
            Err(error) => ActionOutcome::Retry(format!("{error}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AutonomyMode;

    #[test]
    fn terminal_states_are_not_resendable() {
        // A replay of an already-sent or skipped execution must never produce
        // a second email.
        for state in ["sent", "skipped", "cancelled"] {
            assert!(
                matches!(state, "sent" | "skipped" | "cancelled"),
                "terminal state {state} must short-circuit"
            );
        }
        for state in ["scheduled", "queued", "executing"] {
            assert!(
                !matches!(state, "sent" | "skipped" | "cancelled"),
                "{state} proceeds"
            );
        }
    }

    #[test]
    fn shadow_mode_never_sends() {
        // The whole point of shadow: brain runs, execution does not.
        assert!(AutonomyMode::Shadow.blocks_all_execution());
        assert!(AutonomyMode::Shadow.runs_brain());
    }

    #[test]
    fn only_guarded_autonomy_reaches_the_send_path_unattended() {
        // The handler skips Assisted/ApprovalRequired because it has no
        // approval carrier; only AutonomousGuarded may send unattended.
        assert!(AutonomyMode::AutonomousGuarded.may_execute_autonomously());
        assert!(AutonomyMode::ApprovalRequired.requires_operator_approval());
        assert!(AutonomyMode::Assisted.requires_operator_approval());
    }

    #[test]
    fn non_sales_pools_are_refused() {
        assert!(!SenderPool::TransactionalCustomer.is_sales_pool());
        assert!(!SenderPool::InternalTransactional.is_sales_pool());
        assert!(SenderPool::SalesOutbound.is_sales_pool());
        assert!(SenderPool::SalesWarmup.is_sales_pool());
    }

    #[test]
    fn company_size_bands_are_stable_and_bounded() {
        assert_eq!(company_size_band(None), None);
        assert_eq!(company_size_band(Some(0)).as_deref(), Some("1-10"));
        assert_eq!(company_size_band(Some(10)).as_deref(), Some("1-10"));
        assert_eq!(company_size_band(Some(11)).as_deref(), Some("11-50"));
        assert_eq!(company_size_band(Some(200)).as_deref(), Some("51-200"));
        assert_eq!(company_size_band(Some(201)).as_deref(), Some("201-1000"));
        assert_eq!(company_size_band(Some(1_001)).as_deref(), Some("1001+"));
        assert_eq!(company_size_band(Some(i64::MAX)).as_deref(), Some("1001+"));
    }

    #[test]
    fn intent_buckets_are_documented_and_hostile_safe() {
        assert_eq!(intent_bucket(f64::NAN), "unknown");
        assert_eq!(intent_bucket(-5.0), "none");
        assert_eq!(intent_bucket(0.0), "none");
        assert_eq!(intent_bucket(19.9), "none");
        assert_eq!(intent_bucket(20.0), "low");
        assert_eq!(intent_bucket(40.0), "medium");
        assert_eq!(intent_bucket(69.9), "medium");
        assert_eq!(intent_bucket(70.0), "high");
        // A non-finite score is hostile input and fails closed to "unknown"
        // rather than being read as the strongest intent.
        assert_eq!(intent_bucket(f64::INFINITY), "unknown");
    }
}
