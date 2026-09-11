//! Control-plane surface.
//!
//! This is the authenticated read/steer API the ApexMail control plane proxies
//! to. It exists so the CP never needs — and never gets — its own sales brain:
//! every read here is a view over the canonical tables, and every write is an
//! operator intent (mode, kill switch, review, replay) rather than a decision.
//!
//! All responses are plain JSON with camelCase keys, matching the CP's
//! existing admin API conventions.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use crate::actions::ActionQueue;
use crate::enrollments;
use crate::routes::AppState;
use crate::types::{AutonomyMode, EnrollmentState, SalesError};

/// Build an action queue handle for this request's tenant.
fn queue_for(state: &AppState, worker_id: &str) -> ActionQueue {
    ActionQueue::new(state.db.clone(), worker_id)
}

fn tenant_of(headers: &axum::http::HeaderMap) -> Result<String, SalesError> {
    headers
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .ok_or_else(|| SalesError::InvalidInput("missing x-tenant-id header".into()))
}

#[derive(Debug, Deserialize)]
pub struct PagingQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/// `GET /control/overview` — is the machine generating qualified pipeline
/// profitably and safely right now? This is the primary question the CP page
/// answers, so it leads with autonomy state and exceptions, not lead counts.
pub async fn overview(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant = tenant_of(&headers)?;
    let autonomy = crate::autonomy::load(&state.db, &tenant).await?;
    let queue = queue_for(&state, "control-read");

    let actions = queue.stats(&tenant).await?;

    let enrollments_by_state: Vec<(String, i64)> = sqlx::query_as(
        "SELECT state, COUNT(*)::bigint FROM sales_enrollments \
         WHERE tenant_id = $1 GROUP BY state ORDER BY state",
    )
    .bind(&tenant)
    .fetch_all(&state.db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    let decisions_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM sales_decisions \
         WHERE tenant_id = $1 AND created_at >= NOW() - INTERVAL '24 hours'",
    )
    .bind(&tenant)
    .fetch_one(&state.db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    let blocked_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM sales_decisions \
         WHERE tenant_id = $1 AND blocked AND created_at >= NOW() - INTERVAL '24 hours'",
    )
    .bind(&tenant)
    .fetch_one(&state.db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    // Revenue is the objective. Activities (sends) are context, not the goal.
    let revenue: Vec<(String, f64)> = sqlx::query_as(
        "SELECT outcome, COALESCE(SUM(value_eur), 0)::float8 FROM sales_outcomes \
         WHERE tenant_id = $1 AND occurred_at >= NOW() - INTERVAL '30 days' \
           AND outcome IN ('paid_subscription', 'retained_mrr', 'trial') \
         GROUP BY outcome",
    )
    .bind(&tenant)
    .fetch_all(&state.db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    let meetings_booked: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM sales_meetings \
         WHERE tenant_id = $1 AND created_at >= NOW() - INTERVAL '30 days'",
    )
    .bind(&tenant)
    .fetch_one(&state.db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    Ok(Json(serde_json::json!({
        "autonomy": {
            "mode": autonomy.mode.as_str(),
            "modeDescription": mode_description(autonomy.mode),
            "killSwitch": autonomy.kill_switch,
            "runsBrain": autonomy.mode.runs_brain(),
            "mayExecute": autonomy.permits_execution(),
            "lastAction": autonomy.last_action,
            "lastActionAt": autonomy.last_action_at.map(|t| t.to_rfc3339()),
        },
        "actions": actions,
        "enrollments": enrollments_by_state
            .into_iter()
            .map(|(state, count)| serde_json::json!({ "state": state, "count": count }))
            .collect::<Vec<_>>(),
        "decisions": {
            "last24h": decisions_24h,
            "blockedLast24h": blocked_24h,
        },
        "outcomes30d": {
            "meetingsBooked": meetings_booked,
            "revenueEur": revenue
                .into_iter()
                .map(|(outcome, sum)| serde_json::json!({ "outcome": outcome, "eur": sum }))
                .collect::<Vec<_>>(),
        },
    })))
}

fn mode_description(mode: AutonomyMode) -> &'static str {
    match mode {
        AutonomyMode::Disabled => "The engine does nothing: no thinking, no generation, no sending.",
        AutonomyMode::Shadow => {
            "The engine runs the whole brain and records what it would have done, but sends nothing."
        }
        AutonomyMode::Assisted => "The engine plans and drafts; an operator sends.",
        AutonomyMode::ApprovalRequired => "The engine executes only decisions an operator approved.",
        AutonomyMode::AutonomousGuarded => {
            "The engine executes automatically when every policy and confidence constraint passes."
        }
    }
}

/// `GET /control/decisions` — what did it decide, and why?
pub async fn decisions(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Query(paging): Query<PagingQuery>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant = tenant_of(&headers)?;
    let limit = paging.limit.clamp(1, 200);
    let offset = paging.offset.max(0);

    let rows: Vec<DecisionRow> = sqlx::query_as(
        "SELECT id, account_id, contact_id, action, expected_value_eur::float8, \
                confidence::float8, score_total::float8, selected_offer, selected_sequence, \
                selected_variant, selected_sender, evidence_ids::text[] AS evidence_ids, \
                policy_id, model_version, autonomy_mode, rationale, blocked, block_reasons, \
                execute_after, created_at \
         FROM sales_decisions \
         WHERE tenant_id = $1 \
         ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(&tenant)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    Ok(Json(serde_json::json!({
        "decisions": rows.into_iter().map(DecisionRow::into_json).collect::<Vec<_>>(),
        "limit": limit,
        "offset": offset,
    })))
}

/// `GET /control/exceptions` — decisions a human must act on.
///
/// Two kinds qualify: blocked decisions (a hard gate refused them, so an
/// operator needs to fix the cause) and pending-approval decisions.
pub async fn exceptions(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Query(paging): Query<PagingQuery>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant = tenant_of(&headers)?;
    let limit = paging.limit.clamp(1, 200);
    let offset = paging.offset.max(0);

    let rows: Vec<DecisionRow> = sqlx::query_as(
        "SELECT id, account_id, contact_id, action, expected_value_eur::float8, \
                confidence::float8, score_total::float8, selected_offer, selected_sequence, \
                selected_variant, selected_sender, evidence_ids::text[] AS evidence_ids, \
                policy_id, model_version, autonomy_mode, rationale, blocked, block_reasons, \
                execute_after, created_at \
         FROM sales_decisions \
         WHERE tenant_id = $1 \
           AND (blocked OR autonomy_mode IN ('assisted', 'approval_required')) \
         ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(&tenant)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    // Dead letters are the other class of thing a human must see: work the
    // engine could not complete on its own.
    let dead_letters: Vec<ActionRow> = sqlx::query_as(
        "SELECT id, action_type, entity_type, entity_id, state, attempt, max_attempts, \
                last_error, due_at, lease_expires_at, created_at \
         FROM sales_actions \
         WHERE tenant_id = $1 AND state = 'dead_letter' \
         ORDER BY created_at DESC LIMIT 100",
    )
    .bind(&tenant)
    .fetch_all(&state.db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    Ok(Json(serde_json::json!({
        "exceptions": rows.into_iter().map(DecisionRow::into_json).collect::<Vec<_>>(),
        "deadLetters": dead_letters.into_iter().map(ActionRow::into_json).collect::<Vec<_>>(),
        "limit": limit,
        "offset": offset,
    })))
}

/// `GET /control/actions` — the durable queue's visible state.
pub async fn actions(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Query(paging): Query<PagingQuery>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant = tenant_of(&headers)?;
    let queue = queue_for(&state, "control-read");
    let stats = queue.stats(&tenant).await?;
    let limit = paging.limit.clamp(1, 200);

    let rows: Vec<ActionRow> = sqlx::query_as(
        "SELECT id, action_type, entity_type, entity_id, state, attempt, max_attempts, \
                last_error, due_at, lease_expires_at, created_at \
         FROM sales_actions \
         WHERE tenant_id = $1 AND state <> 'succeeded' \
         ORDER BY due_at ASC LIMIT $2",
    )
    .bind(&tenant)
    .bind(limit)
    .fetch_all(&state.db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    Ok(Json(serde_json::json!({
        "stats": stats,
        "actions": rows.into_iter().map(ActionRow::into_json).collect::<Vec<_>>(),
    })))
}

#[derive(sqlx::FromRow)]
struct DecisionRow {
    id: Uuid,
    account_id: Option<Uuid>,
    contact_id: Option<Uuid>,
    action: String,
    expected_value_eur: f64,
    confidence: f64,
    score_total: f64,
    selected_offer: Option<String>,
    selected_sequence: Option<String>,
    selected_variant: Option<String>,
    selected_sender: Option<String>,
    evidence_ids: Vec<String>,
    policy_id: Option<String>,
    model_version: Option<String>,
    autonomy_mode: String,
    rationale: String,
    blocked: bool,
    block_reasons: serde_json::Value,
    execute_after: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl DecisionRow {
    fn into_json(self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "accountId": self.account_id,
            "contactId": self.contact_id,
            "action": self.action,
            "expectedValueEur": self.expected_value_eur,
            "confidence": self.confidence,
            "scoreTotal": self.score_total,
            "selectedOffer": self.selected_offer,
            "selectedSequence": self.selected_sequence,
            "selectedVariant": self.selected_variant,
            "selectedSender": self.selected_sender,
            "evidenceIds": self.evidence_ids,
            "policyId": self.policy_id,
            "modelVersion": self.model_version,
            "autonomyMode": self.autonomy_mode,
            "rationale": self.rationale,
            "blocked": self.blocked,
            "blockReasons": self.block_reasons,
            "executeAfter": self.execute_after.map(|t| t.to_rfc3339()),
            "createdAt": self.created_at.to_rfc3339(),
        })
    }
}

#[derive(sqlx::FromRow)]
struct ActionRow {
    id: Uuid,
    action_type: String,
    entity_type: String,
    entity_id: Uuid,
    state: String,
    attempt: i32,
    max_attempts: i32,
    last_error: Option<String>,
    due_at: chrono::DateTime<chrono::Utc>,
    lease_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl ActionRow {
    fn into_json(self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "actionType": self.action_type,
            "entityType": self.entity_type,
            "entityId": self.entity_id,
            "state": self.state,
            "attempt": self.attempt,
            "maxAttempts": self.max_attempts,
            "lastError": self.last_error,
            "dueAt": self.due_at.to_rfc3339(),
            "leaseExpiresAt": self.lease_expires_at.map(|t| t.to_rfc3339()),
            "createdAt": self.created_at.to_rfc3339(),
        })
    }
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ModeBody {
    pub mode: String,
}

/// `POST /control/mode` — grant or reduce autonomy.
pub async fn set_mode(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<ModeBody>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant = tenant_of(&headers)?;

    // Reject an unknown mode rather than silently falling back to Disabled:
    // an operator who typed the wrong thing must be told, not obeyed.
    let mode = AutonomyMode::parse(&body.mode);
    if mode == AutonomyMode::Disabled && body.mode.trim().to_ascii_lowercase() != "disabled" {
        return Err(SalesError::InvalidInput(format!(
            "unknown autonomy mode '{}'; valid: disabled, shadow, assisted, approval_required, autonomous_guarded",
            body.mode
        )));
    }

    let state_row = crate::autonomy::set_mode(
        &state.db,
        &tenant,
        mode,
        &format!("set_mode:{}", mode.as_str()),
    )
    .await?;

    Ok(Json(serde_json::json!({
        "success": true,
        "mode": state_row.mode.as_str(),
        "killSwitch": state_row.kill_switch,
    })))
}

/// `POST /control/pause` — stop new outbound work.
///
/// Pausing is expressed as `shadow`: the brain keeps running and recording
/// decisions (so the validation dataset keeps growing) while execution stops.
pub async fn pause(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant = tenant_of(&headers)?;
    let state_row =
        crate::autonomy::set_mode(&state.db, &tenant, AutonomyMode::Shadow, "pause").await?;
    Ok(Json(serde_json::json!({
        "success": true,
        "mode": state_row.mode.as_str(),
        "note": "Outbound execution paused; the decision brain continues recording.",
    })))
}

/// `POST /control/resume` — return to the pre-pause operating mode.
///
/// Resuming never guesses upward: it restores `approval_required`, the
/// lowest-authority mode that can actually send. An operator who wants
/// guarded autonomy must ask for it explicitly.
pub async fn resume(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant = tenant_of(&headers)?;
    let state_row =
        crate::autonomy::set_mode(&state.db, &tenant, AutonomyMode::ApprovalRequired, "resume")
            .await?;
    Ok(Json(serde_json::json!({
        "success": true,
        "mode": state_row.mode.as_str(),
        "note": "Resumed at approval_required; guarded autonomy must be requested explicitly.",
    })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KillSwitchBody {
    pub engaged: bool,
}

/// `POST /control/kill-switch` — immediate stop for new outbound actions.
pub async fn kill_switch(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<KillSwitchBody>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant = tenant_of(&headers)?;
    let action = if body.engaged {
        "kill-switch:engage"
    } else {
        "kill-switch:release"
    };
    let state_row =
        crate::autonomy::set_kill_switch(&state.db, &tenant, body.engaged, action).await?;
    Ok(Json(serde_json::json!({
        "success": true,
        "killSwitch": state_row.kill_switch,
        "mode": state_row.mode.as_str(),
        "note": "Inbound reply processing continues while the kill switch is engaged.",
    })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReviewBody {
    /// `approved` or `rejected`.
    pub outcome: String,
    pub note: Option<String>,
}

/// `POST /control/decisions/:id/review` — operator review of one decision.
///
/// Approving replays the decision's queued work; rejecting cancels it. The
/// review note is appended to the decision's block reasons so the explanation
/// the CP renders stays truthful about who decided what.
pub async fn review_decision(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ReviewBody>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant = tenant_of(&headers)?;
    let decision_id = parse_uuid(&id, "decision id")?;

    let outcome = body.outcome.trim().to_ascii_lowercase();
    if outcome != "approved" && outcome != "rejected" {
        return Err(SalesError::InvalidInput(
            "outcome must be 'approved' or 'rejected'".into(),
        ));
    }

    let exists: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM sales_decisions WHERE id = $1 AND tenant_id = $2")
            .bind(decision_id)
            .bind(&tenant)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

    if exists.is_none() {
        return Err(SalesError::InvalidInput(format!(
            "decision {decision_id} not found for this tenant"
        )));
    }

    let queue = queue_for(&state, "control-review");
    let mut affected = 0u64;

    let linked: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM sales_actions WHERE tenant_id = $1 AND decision_id = $2",
    )
    .bind(&tenant)
    .bind(decision_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    for action_id in linked {
        if outcome == "approved" {
            if queue.replay(&tenant, action_id).await? {
                affected += 1;
            }
        } else {
            affected += queue
                .cancel_for_entity(
                    &tenant,
                    "decision",
                    decision_id,
                    "operator rejected the decision",
                )
                .await?;
            break;
        }
    }

    // Record the review on the decision itself so the rendered explanation
    // reflects the human input.
    let note = body.note.unwrap_or_default();
    sqlx::query(
        "UPDATE sales_decisions \
         SET block_reasons = block_reasons || $3::jsonb \
         WHERE id = $1 AND tenant_id = $2",
    )
    .bind(decision_id)
    .bind(&tenant)
    .bind(serde_json::json!([format!(
        "operator {outcome}{}",
        if note.is_empty() {
            String::new()
        } else {
            format!(": {note}")
        }
    )]))
    .execute(&state.db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    Ok(Json(serde_json::json!({
        "success": true,
        "decisionId": decision_id,
        "outcome": outcome,
        "actionsAffected": affected,
    })))
}

/// `POST /control/actions/:id/replay` — retry one dead-lettered or failed action.
pub async fn replay_action(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant = tenant_of(&headers)?;
    let action_id = parse_uuid(&id, "action id")?;

    let queue = queue_for(&state, "control-replay");
    if !queue.replay(&tenant, action_id).await? {
        return Err(SalesError::InvalidInput(format!(
            "action {action_id} is not replayable for this tenant (not found, or still in flight)"
        )));
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "actionId": action_id,
        "state": "queued",
    })))
}

// ---------------------------------------------------------------------------
// Enrollments (the CP's outreach command and campaign read model)
// ---------------------------------------------------------------------------

/// `POST /enrollments` — the canonical outreach command.
pub async fn start_outreach(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(request): Json<enrollments::StartOutreachRequest>,
) -> Result<Json<enrollments::StartOutreachResponse>, SalesError> {
    let tenant = tenant_of(&headers)?;
    let queue = queue_for(&state, "control-enroll");
    let response = enrollments::start_outreach(&state.db, &queue, &tenant, &request).await?;
    Ok(Json(response))
}

/// `GET /enrollments` — the CP's campaign/enrollment list.
pub async fn list_enrollments(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Query(paging): Query<PagingQuery>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant = tenant_of(&headers)?;
    let limit = paging.limit.clamp(1, 200);
    let offset = paging.offset.max(0);
    let rows = enrollments::list_enrollments(&state.db, &tenant, limit, offset).await?;

    Ok(Json(serde_json::json!({
        "enrollments": rows
            .into_iter()
            .map(|row| serde_json::json!({
                "id": row.id,
                "sequenceName": row.sequence_name,
                "sequenceVersion": row.sequence_version,
                "contactName": row.contact_name,
                "contactEmail": row.contact_email,
                "accountCompany": row.account_company,
                "state": row.state,
                "currentStepIndex": row.current_step_index,
                "enrolledAt": row.enrolled_at.to_rfc3339(),
                "updatedAt": row.updated_at.to_rfc3339(),
            }))
            .collect::<Vec<_>>(),
        "limit": limit,
        "offset": offset,
    })))
}

/// `POST /enrollments/:id/pause|resume|cancel` — stop or restart one
/// enrollment's queued work.
pub async fn set_enrollment_state(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path((id, action)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant = tenant_of(&headers)?;
    let enrollment_id = parse_uuid(&id, "enrollment id")?;

    let target = match action.as_str() {
        "pause" => EnrollmentState::Paused,
        "resume" => EnrollmentState::Active,
        "cancel" => EnrollmentState::Completed,
        other => {
            return Err(SalesError::InvalidInput(format!(
                "unknown enrollment action '{other}'; valid: pause, resume, cancel"
            )))
        }
    };

    let queue = queue_for(&state, "control-enrollment");
    let changed =
        enrollments::set_enrollment_state(&state.db, &queue, &tenant, enrollment_id, target)
            .await?;

    if !changed {
        return Err(SalesError::InvalidInput(format!(
            "enrollment {enrollment_id} not found for this tenant"
        )));
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "enrollmentId": enrollment_id,
        "state": target.as_str(),
    })))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_uuid(value: &str, what: &str) -> Result<Uuid, SalesError> {
    Uuid::parse_str(value.trim())
        .map_err(|_| SalesError::InvalidInput(format!("invalid {what}: not a UUID")))
}

/// Note for tests: the CP sends `x-tenant-id: system`; the plain `TenantId`
/// extractor in `routes.rs` is used by the rest of the service. Keeping this
/// check in one helper means the control surface cannot accidentally become
/// tenant-agnostic.
#[allow(dead_code)]
fn status_for(error: &SalesError) -> StatusCode {
    match error {
        SalesError::InvalidInput(_) => StatusCode::BAD_REQUEST,
        SalesError::PolicyDenied(_) => StatusCode::FORBIDDEN,
        SalesError::KillSwitchEngaged => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_description_is_specific_for_every_mode() {
        for mode in AutonomyMode::all() {
            let text = mode_description(mode);
            assert!(!text.is_empty(), "mode {mode} needs a description");
        }
        // Shadow must be described in a way that makes clear the brain runs.
        assert!(mode_description(AutonomyMode::Shadow).contains("whole brain"));
    }

    #[test]
    fn invalid_uuid_is_rejected_with_the_field_named() {
        let err = parse_uuid("not-a-uuid", "decision id").unwrap_err();
        assert!(err.to_string().contains("decision id"));
    }

    #[test]
    fn paging_defaults_are_bounded() {
        assert_eq!(
            PagingQuery {
                limit: 50,
                offset: 0
            }
            .limit
            .clamp(1, 200),
            50
        );
        // A caller asking for 10_000 gets 200, never an unbounded scan.
        assert_eq!(
            PagingQuery {
                limit: 10_000,
                offset: 0
            }
            .limit
            .clamp(1, 200),
            200
        );
    }

    #[test]
    fn resume_targets_approval_required_not_guarded() {
        // Resume must never silently restore guarded autonomy.
        assert_ne!(
            AutonomyMode::ApprovalRequired,
            AutonomyMode::AutonomousGuarded
        );
        assert!(!AutonomyMode::ApprovalRequired.may_execute_autonomously());
        assert!(AutonomyMode::ApprovalRequired.runs_brain());
    }
}
