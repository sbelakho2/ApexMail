//! Control-plane surface.
//!
//! This is the authenticated read/steer API the ApexMail control plane proxies
//! to. It exists so the CP never needs — and never gets — its own sales brain:
//! every read here is a view over the canonical tables, and every write is an
//! operator intent (mode, kill switch, review, replay) rather than a decision.
//!
//! The review transition is atomic: the decision row lock, the revalidation of
//! every gate, the linked-action transition and the terminal `review_status`
//! all happen in one transaction, so a failure cannot leave the decision
//! recorded as approved while its work is still parked. Operator identity is
//! taken from `x-operator-id` (legacy alias `x-user-id`) and is trusted only
//! behind the service-token authentication this router applies to every
//! `/control/*` route.
//!
//! All responses are plain JSON with camelCase keys, matching the CP's
//! existing admin API conventions.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::actions::ActionQueue;
use crate::control_read;
use crate::enrollments;
use crate::routes::AppState;
use crate::types::{AutonomyMode, EnrollmentState, SalesError};

/// Map a SQL error into the crate error type.
fn db_error(error: sqlx::Error) -> SalesError {
    SalesError::Database(error.to_string())
}

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
    let snapshot = control_read::load_overview(&state.db, &tenant).await?;
    Ok(Json(control_json(snapshot)?))
}

/// Serialize a typed control snapshot into the response JSON. Serialization
/// of these plain structs cannot realistically fail, but a failure must
/// surface as an error rather than an empty payload.
fn control_json<T: serde::Serialize>(snapshot: T) -> Result<serde_json::Value, SalesError> {
    serde_json::to_value(snapshot).map_err(|error| SalesError::Internal(error.into()))
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

    let rows = control_read::load_decisions(&state.db, &tenant, limit, offset).await?;

    Ok(Json(serde_json::json!({
        "decisions": rows,
        "limit": limit,
        "offset": offset,
    })))
}

/// `GET /control/exceptions` — decisions a human must act on.
///
/// Two kinds qualify: decisions a hard gate refused
/// (`enforcement = 'denied'`) and decisions waiting for an operator
/// (`enforcement = 'await_approval'`, or any decision whose review is still
/// `pending`). The predicate is the decision's OWN recorded state — autonomy
/// mode is context, not authority, and an `execute` decision recorded under an
/// old mode must not surface as an exception forever.
pub async fn exceptions(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Query(paging): Query<PagingQuery>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant = tenant_of(&headers)?;
    let limit = paging.limit.clamp(1, 200);
    let offset = paging.offset.max(0);

    let rows = control_read::load_exceptions(&state.db, &tenant, limit, offset).await?;

    // Dead letters are the other class of thing a human must see: work the
    // engine could not complete on its own.
    let dead_letters = control_read::load_dead_letters(&state.db, &tenant, 100).await?;

    Ok(Json(serde_json::json!({
        "exceptions": rows,
        "deadLetters": dead_letters,
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
    let stats = control_read::load_action_stats(&state.db, &tenant).await?;
    let limit = paging.limit.clamp(1, 200);

    let rows = control_read::load_actions(&state.db, &tenant, limit).await?;

    Ok(Json(serde_json::json!({
        "stats": stats,
        "actions": rows,
    })))
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

/// The operator's requested review outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReviewAction {
    Approve,
    Reject,
}

impl ReviewAction {
    fn parse(raw: &str) -> Result<Self, SalesError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "approved" | "approve" => Ok(Self::Approve),
            "rejected" | "reject" => Ok(Self::Reject),
            other => Err(SalesError::InvalidInput(format!(
                "outcome must be 'approved' or 'rejected', got '{other}'"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approved",
            Self::Reject => "rejected",
        }
    }

    /// The authoritative `sales_decisions.review_status` value for this
    /// outcome. Approval and rejection are the only review statuses an
    /// operator can write; `pending` and `not_required` are set elsewhere.
    fn review_status(self) -> &'static str {
        self.as_str()
    }
}

/// Why a decision cannot be reviewed, if it cannot. Pure mirror of the
/// authoritative SQL guard
/// (`enforcement = 'await_approval' AND review_status = 'pending'`), so a
/// refused review names the exact condition instead of silently no-oping.
fn review_guard_violation(
    enforcement: Option<&str>,
    review_status: Option<&str>,
) -> Option<String> {
    match enforcement {
        None => Some(
            "no enforcement verdict is recorded; only a decision recorded as \
             'await_approval' can be reviewed"
                .to_string(),
        ),
        Some(value) if value != "await_approval" => Some(format!(
            "enforcement is '{value}', not 'await_approval'; approval is not required for \
             this decision and it will not be replayed"
        )),
        Some(_) => match review_status {
            Some("pending") => None,
            Some(value) => Some(format!(
                "review_status is already '{value}'; a review is terminal and cannot be overwritten"
            )),
            None => Some(
                "review_status is NULL; only a decision awaiting review can be decided".to_string(),
            ),
        },
    }
}

/// The gates' verdict on whether an approved decision may now execute.
///
/// Mirrors [`crate::decision_engine::ExecutionRevalidation`] (the `checked`
/// gate names are `&'static str` there by design), so the CP can render why
/// the release was or was not allowed.
#[derive(Debug, Clone)]
struct RevalidationReport {
    allowed: bool,
    reasons: Vec<String>,
    checked: Vec<&'static str>,
}

impl RevalidationReport {
    fn denied(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            reasons: vec![reason.into()],
            checked: Vec::new(),
        }
    }

    fn into_json(self) -> serde_json::Value {
        serde_json::json!({
            "allowed": self.allowed,
            "reasons": self.reasons,
            "checked": self.checked,
        })
    }
}

/// Result of applying one operator review.
#[derive(Debug, Clone)]
struct ReviewOutcome {
    decision_id: Uuid,
    /// The authoritative final `review_status` ("approved" or "rejected").
    status: String,
    actions_affected: u64,
    revalidation: RevalidationReport,
}

/// Maximum accepted length of an operator identifier, in bytes.
pub const MAX_OPERATOR_ID_LEN: usize = 128;

/// Reviewer recorded when the authenticated caller supplies no operator
/// identity. `sales_decisions.reviewed_by` is NOT NULL, so a name must always
/// be written; naming the authenticated control plane is honest, whereas
/// inventing an operator id is not.
pub const CONTROL_PLANE_REVIEWER: &str = "control-plane";

/// Does this request carry the sales service credential?
///
/// Mirrors `routes::require_service_token`'s credential extraction exactly
/// (`x-api-key`, or `Authorization: Bearer`) so the operator identity cannot
/// be trusted on a request the middleware would have rejected.
fn request_has_valid_service_token(headers: &axum::http::HeaderMap, service_token: &str) -> bool {
    if service_token.is_empty() {
        return false;
    }
    if headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|provided| apexmail_lib::timing_safe_compare(provided, service_token))
    {
        return true;
    }
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| raw.trim().strip_prefix("Bearer "))
        .is_some_and(|provided| apexmail_lib::timing_safe_compare(provided, service_token))
}

/// The operator identity to record in `sales_decisions.reviewed_by`.
///
/// Contract with the control plane:
///
/// * the canonical header is `x-operator-id` (legacy alias: `x-user-id`, used
///   only when `x-operator-id` is absent);
/// * it is honoured only when the request carries the sales service token
///   (`x-api-key`, or `Authorization: Bearer`) — the same credential
///   `routes::require_service_token` enforces on every `/control/*` route;
/// * the value is trimmed and must then be a non-empty identifier of at most
///   [`MAX_OPERATOR_ID_LEN`] bytes containing only printable ASCII characters
///   (`char::is_ascii_graphic`), so a header can never smuggle control
///   characters into the audit trail;
/// * absent header → [`CONTROL_PLANE_REVIEWER`]; present-but-invalid
///   (non-UTF-8, empty/blank, oversized, non-printable) → [`SalesError::InvalidInput`],
///   never a silent drop.
fn operator_identity(
    headers: &axum::http::HeaderMap,
    service_token: &str,
) -> Result<String, SalesError> {
    let Some(raw) = headers
        .get("x-operator-id")
        .or_else(|| headers.get("x-user-id"))
    else {
        return Ok(CONTROL_PLANE_REVIEWER.to_string());
    };

    if !request_has_valid_service_token(headers, service_token) {
        return Err(SalesError::InvalidInput(
            "x-operator-id is only accepted on a request authenticated with the sales service \
             token (x-api-key or Authorization: Bearer)"
                .to_string(),
        ));
    }

    let value = raw.to_str().map_err(|_| {
        SalesError::InvalidInput("x-operator-id must be valid ASCII header text".to_string())
    })?;
    let value = value.trim();
    if value.is_empty() {
        return Err(SalesError::InvalidInput(
            "x-operator-id must not be empty".to_string(),
        ));
    }
    if value.len() > MAX_OPERATOR_ID_LEN {
        return Err(SalesError::InvalidInput(format!(
            "x-operator-id must be at most {MAX_OPERATOR_ID_LEN} bytes"
        )));
    }
    if !value.chars().all(|c| c.is_ascii_graphic()) {
        return Err(SalesError::InvalidInput(
            "x-operator-id must contain only printable ASCII characters".to_string(),
        ));
    }
    Ok(value.to_string())
}

/// Move the decision's linked actions out of `awaiting_approval` back into the
/// queue, inside the caller's review transaction.
///
/// The lease columns are ASSERTED NULL in the predicate rather than cleared:
/// an `awaiting_approval` row written by `ActionQueue::finish` never carries a
/// lease, so a non-null owner/token here means the row was mutated outside the
/// contract. Clearing it silently would overwrite that writer; refusing is the
/// only safe response. Returns the number of actions released.
async fn release_actions_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant: &str,
    decision_id: Uuid,
) -> Result<u64, SalesError> {
    let still_leased: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM sales_actions \
         WHERE tenant_id = $1 AND decision_id = $2 AND state = 'awaiting_approval' \
           AND (lease_owner IS NOT NULL OR lease_token IS NOT NULL \
                OR lease_expires_at IS NOT NULL)",
    )
    .bind(tenant)
    .bind(decision_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(db_error)?;

    if still_leased > 0 {
        return Err(SalesError::Database(format!(
            "refusing to release decision {decision_id}: {still_leased} action(s) awaiting \
             approval still carry lease ownership; reconcile the queue before approving"
        )));
    }

    let affected = sqlx::query(
        "UPDATE sales_actions \
         SET state = 'queued', due_at = NOW(), attempt = 0, last_error = NULL \
         WHERE tenant_id = $1 AND decision_id = $2 AND state = 'awaiting_approval' \
           AND lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL",
    )
    .bind(tenant)
    .bind(decision_id)
    .execute(&mut **tx)
    .await
    .map_err(db_error)?
    .rows_affected();
    Ok(affected)
}

/// Cancel every non-terminal action linked to the decision, recording the
/// reason, inside the caller's review transaction. This is the "did not
/// release the work" transition: an action that was queued by a review must
/// not run after the review was refused.
async fn cancel_linked_actions_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant: &str,
    decision_id: Uuid,
    reason: &str,
) -> Result<u64, SalesError> {
    let affected = sqlx::query(
        "UPDATE sales_actions \
         SET state = 'cancelled', last_error = $3, \
             lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, \
             completed_at = NOW() \
         WHERE tenant_id = $1 AND decision_id = $2 \
           AND state IN ('queued', 'awaiting_approval', 'leased', 'executing')",
    )
    .bind(tenant)
    .bind(decision_id)
    .bind(reason)
    .execute(&mut **tx)
    .await
    .map_err(db_error)?
    .rows_affected();
    Ok(affected)
}

/// Write the review columns on the locked decision row. Must only run inside a
/// transaction that holds the decision row lock (see `apply_review_tx`).
async fn write_review_status_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant: &str,
    decision_id: Uuid,
    status: &str,
    reviewed_by: &str,
    note: &str,
) -> Result<(), SalesError> {
    sqlx::query(
        "UPDATE sales_decisions \
         SET review_status = $3, reviewed_by = $4, reviewed_at = NOW(), review_note = $5 \
         WHERE id = $1 AND tenant_id = $2",
    )
    .bind(decision_id)
    .bind(tenant)
    .bind(status)
    .bind(reviewed_by)
    .bind(note)
    .execute(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(())
}

/// Apply an operator review to a decision and its linked actions.
///
/// Everything happens in ONE transaction:
/// 1. lock the decision row (`SELECT ... FOR UPDATE`) and verify it is
///    `enforcement = 'await_approval' AND review_status = 'pending'`; any
///    other state is a hard error, never a fallback to replaying actions;
/// 2. on approve, re-run every gate with
///    [`crate::decision_engine::revalidate_execution_tx`] on this same
///    transaction — approval is not a bypass;
/// 3. transition the linked actions (`awaiting_approval` → `queued` when the
///    gates pass, → `cancelled` on reject or on a revalidation refusal);
/// 4. write the terminal `review_status` + `reviewed_by` + `reviewed_at` +
///    `review_note`.
///
/// Any failure rolls back ALL of it, leaving the decision reviewable; there is
/// no window in which `review_status = 'approved'` is durable while the
/// linked action is still `awaiting_approval`.
async fn apply_review(
    db: &PgPool,
    tenant: &str,
    decision_id: Uuid,
    action: ReviewAction,
    note: &str,
    reviewed_by: &str,
) -> Result<ReviewOutcome, SalesError> {
    let mut tx = db.begin().await.map_err(db_error)?;
    let result = apply_review_tx(&mut tx, tenant, decision_id, action, note, reviewed_by).await;
    match result {
        Ok(outcome) => {
            tx.commit().await.map_err(db_error)?;
            Ok(outcome)
        }
        Err(error) => {
            let _ = tx.rollback().await;
            Err(error)
        }
    }
}

/// The body of [`apply_review`], on the caller's transaction.
async fn apply_review_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant: &str,
    decision_id: Uuid,
    action: ReviewAction,
    note: &str,
    reviewed_by: &str,
) -> Result<ReviewOutcome, SalesError> {
    // 1. The decision row lock is the review's serialisation point: a second
    //    reviewer blocks here until the first transaction commits or rolls
    //    back, and the state it then reads is the durable one.
    let current: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT enforcement, review_status FROM sales_decisions \
         WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
    )
    .bind(decision_id)
    .bind(tenant)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)?;

    match current {
        None => {
            return Err(SalesError::InvalidInput(format!(
                "decision {decision_id} not found for this tenant"
            )))
        }
        Some((enforcement, review_status)) => {
            if let Some(violation) =
                review_guard_violation(enforcement.as_deref(), review_status.as_deref())
            {
                return Err(SalesError::InvalidInput(format!(
                    "decision {decision_id} cannot be reviewed: {violation}"
                )));
            }
        }
    }

    match action {
        ReviewAction::Reject => {
            let reason = if note.trim().is_empty() {
                "operator rejected the decision".to_string()
            } else {
                note.trim().to_string()
            };
            // Transition the work, release any touch slot the decision had
            // reserved (the touch will never happen), then write the terminal
            // review state. The transaction makes the three atomic.
            let affected = cancel_linked_actions_tx(tx, tenant, decision_id, &reason).await?;
            crate::decision_engine::release_decision_touch_tx(tx, tenant, decision_id).await?;
            write_review_status_tx(
                tx,
                tenant,
                decision_id,
                action.review_status(),
                reviewed_by,
                &reason,
            )
            .await?;
            Ok(ReviewOutcome {
                decision_id,
                status: ReviewAction::Reject.as_str().to_string(),
                actions_affected: affected,
                revalidation: RevalidationReport::denied("operator rejected the decision"),
            })
        }
        ReviewAction::Approve => {
            // 2. Approval is not a bypass, but the legal gate requires a
            //    CURRENT human approval under an approval-required policy, so
            //    record the operator's decision provisionally before
            //    re-running the gates. It is invisible outside this
            //    transaction until COMMIT, and every failure below rolls it
            //    back: `approved` becomes durable only after the revalidation
            //    passed AND the requeue succeeded.
            write_review_status_tx(
                tx,
                tenant,
                decision_id,
                action.review_status(),
                reviewed_by,
                note,
            )
            .await?;

            let report =
                match crate::decision_engine::revalidate_execution_tx(tx, decision_id).await {
                    Ok(result) => RevalidationReport {
                        allowed: result.allowed,
                        reasons: result.reasons,
                        checked: result.checked,
                    },
                    Err(error) => RevalidationReport::denied(format!(
                        "revalidation_failed: the gates could not be re-checked ({error}); \
                     refusing to release the work"
                    )),
                };

            if report.allowed {
                // 3. Only a successful requeue commits the approval above.
                let affected = release_actions_tx(tx, tenant, decision_id).await?;
                Ok(ReviewOutcome {
                    decision_id,
                    status: ReviewAction::Approve.as_str().to_string(),
                    actions_affected: affected,
                    revalidation: report,
                })
            } else {
                let reasons = if report.reasons.is_empty() {
                    "revalidation returned allowed=false without naming a failed gate".to_string()
                } else {
                    report.reasons.join("; ")
                };
                let refusal = format!("approval refused by revalidation: {reasons}");
                let affected = cancel_linked_actions_tx(tx, tenant, decision_id, &refusal).await?;
                // The touch will never happen: give back any reserved slot.
                crate::decision_engine::release_decision_touch_tx(tx, tenant, decision_id).await?;

                // 4. The durable review record must say the approval was
                //    refused, or a later reader would see an approved decision
                //    with cancelled work and no explanation.
                let final_note = if note.trim().is_empty() {
                    refusal
                } else {
                    format!("{refusal} | operator note: {}", note.trim())
                };
                sqlx::query(
                    "UPDATE sales_decisions \
                     SET review_status = 'rejected', review_note = $3 \
                     WHERE id = $1 AND tenant_id = $2",
                )
                .bind(decision_id)
                .bind(tenant)
                .bind(&final_note)
                .execute(&mut **tx)
                .await
                .map_err(db_error)?;

                Ok(ReviewOutcome {
                    decision_id,
                    status: ReviewAction::Reject.as_str().to_string(),
                    actions_affected: affected,
                    revalidation: report,
                })
            }
        }
    }
}

/// `POST /control/decisions/:id/review` — operator review of one decision.
///
/// The decision's `review_status` is the authority: only a decision recorded
/// as `await_approval` with `review_status = 'pending'` can be decided, and
/// only the atomic transaction in `apply_review` releases (or cancels) its
/// linked actions. Approval re-runs the hard gates first — an approval that
/// the gates now refuse cancels the work and is recorded as a rejection with
/// the reasons.
///
/// The operator identity is taken from the `x-operator-id` header (legacy
/// alias `x-user-id`) and is honoured only because this route sits behind the
/// service-token middleware; see [`operator_identity`] for the exact
/// validation contract. Without the header, `reviewed_by` records
/// [`CONTROL_PLANE_REVIEWER`].
///
/// The response reports `outcome` (the final authoritative status),
/// `reviewedBy`, `actionsAffected`, and `revalidation: {allowed, reasons,
/// checked}` so the CP can show why an approval did or did not release the
/// work.
pub async fn review_decision(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ReviewBody>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant = tenant_of(&headers)?;
    let decision_id = parse_uuid(&id, "decision id")?;
    let action = ReviewAction::parse(&body.outcome)?;
    let note = body.note.unwrap_or_default();
    let reviewed_by = operator_identity(&headers, &state.service_token)?;

    let result = apply_review(&state.db, &tenant, decision_id, action, &note, &reviewed_by).await?;

    Ok(Json(serde_json::json!({
        "success": true,
        "decisionId": result.decision_id,
        "outcome": result.status,
        "reviewStatus": result.status,
        "reviewedBy": reviewed_by,
        "actionsAffected": result.actions_affected,
        "revalidation": result.revalidation.into_json(),
    })))
}

/// `POST /control/actions/:id/replay` — retry one dead-lettered or failed action.
///
/// Deliberately restricted to `failed`/`dead_letter`
/// ([`crate::actions::ActionQueue::replay`]): actions in `awaiting_approval`
/// are waiting for a human decision, and replaying them would be a second path
/// around the approval gate. Approval-gated work is released only by
/// [`review_decision`].
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
            "action {action_id} is not replayable for this tenant (only failed or \
             dead-lettered actions can be replayed; approval-gated work must be released \
             through decision review)"
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

    // -----------------------------------------------------------------------
    // Review transition guards (pure)
    // -----------------------------------------------------------------------

    #[test]
    fn review_action_parses_only_approve_and_reject() {
        assert_eq!(
            ReviewAction::parse("approved").unwrap(),
            ReviewAction::Approve
        );
        assert_eq!(
            ReviewAction::parse("  REJECTED ").unwrap(),
            ReviewAction::Reject
        );
        for bad in ["", "pending", "maybe", "approvee"] {
            assert!(
                ReviewAction::parse(bad).is_err(),
                "'{bad}' must not parse as a review outcome"
            );
        }
        assert_eq!(ReviewAction::Approve.review_status(), "approved");
        assert_eq!(ReviewAction::Reject.review_status(), "rejected");
    }

    /// The SQL guard is `enforcement = 'await_approval' AND
    /// review_status = 'pending'`; this pure mirror must agree exactly so the
    /// error message names the condition that actually failed.
    #[test]
    fn review_guard_names_the_failed_condition() {
        assert_eq!(
            review_guard_violation(Some("await_approval"), Some("pending")),
            None
        );
        assert!(review_guard_violation(Some("execute"), Some("pending"))
            .unwrap_or_default()
            .contains("execute"));
        assert!(review_guard_violation(Some("denied"), Some("pending"))
            .unwrap_or_default()
            .contains("denied"));
        assert!(
            review_guard_violation(Some("await_approval"), Some("approved"))
                .unwrap_or_default()
                .contains("already")
        );
        assert!(review_guard_violation(Some("await_approval"), Some("rejected")).is_some());
        assert!(review_guard_violation(Some("await_approval"), None).is_some());
        assert!(review_guard_violation(None, Some("pending")).is_some());
    }

    /// The service token used by the identity tests.
    const TEST_SERVICE_TOKEN: &str = "service-token-abc";

    fn headers_with_token() -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-api-key", TEST_SERVICE_TOKEN.parse().unwrap());
        headers
    }

    #[test]
    fn operator_identity_is_trusted_only_behind_the_service_token() {
        // No header: the authenticated CP itself is named; the column is NOT
        // NULL and inventing an operator id would be dishonest.
        assert_eq!(
            operator_identity(&axum::http::HeaderMap::new(), TEST_SERVICE_TOKEN).unwrap(),
            CONTROL_PLANE_REVIEWER
        );

        // A valid service token makes the operator id authoritative.
        let mut authenticated = headers_with_token();
        authenticated.insert("x-operator-id", "user-42".parse().unwrap());
        assert_eq!(
            operator_identity(&authenticated, TEST_SERVICE_TOKEN).unwrap(),
            "user-42"
        );

        // Legacy alias `x-user-id` is still accepted; the canonical header wins.
        let mut legacy = headers_with_token();
        legacy.insert("x-user-id", "legacy-7".parse().unwrap());
        assert_eq!(
            operator_identity(&legacy, TEST_SERVICE_TOKEN).unwrap(),
            "legacy-7"
        );
        legacy.insert("x-operator-id", "operator-9".parse().unwrap());
        assert_eq!(
            operator_identity(&legacy, TEST_SERVICE_TOKEN).unwrap(),
            "operator-9"
        );

        // Surrounded by whitespace is trimmed to the identifier.
        let mut padded = headers_with_token();
        padded.insert("x-operator-id", "  user-42  ".parse().unwrap());
        assert_eq!(
            operator_identity(&padded, TEST_SERVICE_TOKEN).unwrap(),
            "user-42"
        );

        // Bearer is the middleware's other accepted credential.
        let mut bearer = axum::http::HeaderMap::new();
        bearer.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {TEST_SERVICE_TOKEN}").parse().unwrap(),
        );
        bearer.insert("x-operator-id", "bearer-user".parse().unwrap());
        assert_eq!(
            operator_identity(&bearer, TEST_SERVICE_TOKEN).unwrap(),
            "bearer-user"
        );

        // The operator id is NOT trusted without the service credential
        // (defence in depth: this route is already behind the middleware).
        let mut unauthenticated = axum::http::HeaderMap::new();
        unauthenticated.insert("x-operator-id", "impostor".parse().unwrap());
        assert!(operator_identity(&unauthenticated, TEST_SERVICE_TOKEN).is_err());

        // ... nor with a wrong token, nor when the configured token is empty.
        let mut wrong = axum::http::HeaderMap::new();
        wrong.insert("x-api-key", "not-the-token".parse().unwrap());
        wrong.insert("x-operator-id", "impostor".parse().unwrap());
        assert!(operator_identity(&wrong, TEST_SERVICE_TOKEN).is_err());
        assert!(operator_identity(&authenticated, "").is_err());
    }

    #[test]
    fn operator_identity_rejects_empty_oversized_and_non_printable_values() {
        // A present-but-blank header is an error, not the fallback.
        let mut blank = headers_with_token();
        blank.insert("x-operator-id", "   ".parse().unwrap());
        let err = operator_identity(&blank, TEST_SERVICE_TOKEN).unwrap_err();
        assert!(err.to_string().contains("empty"), "{err}");

        // Oversized is refused, exactly the bound is accepted.
        let mut oversized = headers_with_token();
        oversized.insert(
            "x-operator-id",
            "a".repeat(MAX_OPERATOR_ID_LEN + 1).parse().unwrap(),
        );
        let err = operator_identity(&oversized, TEST_SERVICE_TOKEN).unwrap_err();
        assert!(err.to_string().contains("at most"), "{err}");

        let mut bounded = headers_with_token();
        bounded.insert(
            "x-operator-id",
            "a".repeat(MAX_OPERATOR_ID_LEN).parse().unwrap(),
        );
        assert_eq!(
            operator_identity(&bounded, TEST_SERVICE_TOKEN)
                .unwrap()
                .len(),
            MAX_OPERATOR_ID_LEN
        );

        // A header value may contain a space, but an identifier may not: only
        // printable non-space ASCII is recorded, so control/format characters
        // can never reach the audit trail.
        let mut spaced = headers_with_token();
        spaced.insert("x-operator-id", "bad id".parse().unwrap());
        assert!(operator_identity(&spaced, TEST_SERVICE_TOKEN).is_err());
    }

    // -----------------------------------------------------------------------
    // Live-DB proofs
    // -----------------------------------------------------------------------

    async fn set_autonomy(pool: &PgPool, tenant: &str, mode: &str, kill_switch: bool) {
        sqlx::query(
            "INSERT INTO sales_autonomy_state (tenant_id, mode, kill_switch) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (tenant_id) DO UPDATE SET mode = EXCLUDED.mode, \
                 kill_switch = EXCLUDED.kill_switch",
        )
        .bind(tenant)
        .bind(mode)
        .bind(kill_switch)
        .execute(pool)
        .await
        .expect("seed autonomy state");
    }

    async fn insert_decision(
        pool: &PgPool,
        tenant: &str,
        action_type: &str,
        enforcement: &str,
        review_status: Option<&str>,
        autonomy_mode: &str,
    ) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_decisions \
                 (id, tenant_id, action, autonomy_mode, rationale, enforcement, review_status) \
             VALUES ($1, $2, $3, $4, 'control-test decision', $5, $6)",
        )
        .bind(id)
        .bind(tenant)
        .bind(action_type)
        .bind(autonomy_mode)
        .bind(enforcement)
        .bind(review_status)
        .execute(pool)
        .await
        .expect("insert decision");
        id
    }

    /// Claim one specific action.
    ///
    /// Scoped to the id rather than taking the global claim: retrying the broad
    /// claim both raced every other test sharing this database and could steal
    /// their work.
    async fn claim_one(queue: &ActionQueue, action_id: Uuid) -> crate::actions::LeasedAction {
        queue
            .claim_filtered(1, crate::actions::DEFAULT_LEASE_SECS, Some(&[action_id]))
            .await
            .expect("claim")
            .into_iter()
            .find(|leased| leased.id() == action_id)
            .unwrap_or_else(|| panic!("action {action_id} was never claimable"))
    }

    /// A decision recorded as awaiting a human, with one linked action parked
    /// in `awaiting_approval` through the real queue machinery.
    async fn seed_awaiting_approval(
        pool: &PgPool,
        tenant: &str,
        label: &str,
        decision_action: &str,
    ) -> (Uuid, Uuid) {
        let decision_id = insert_decision(
            pool,
            tenant,
            decision_action,
            "await_approval",
            Some("pending"),
            "approval_required",
        )
        .await;
        let queue = ActionQueue::new(pool.clone(), format!("seed-{label}-{tenant}"));
        let action = queue
            .enqueue(
                tenant,
                crate::actions::action_type::ENRICH,
                crate::actions::entity_type::ACCOUNT,
                Uuid::new_v4(),
                &format!("review-test:{tenant}:{label}"),
                serde_json::json!({}),
                chrono::Utc::now() - chrono::Duration::seconds(1),
                100,
                Some(decision_id),
            )
            .await
            .expect("enqueue action");
        let leased = claim_one(&queue, action.id).await;
        assert!(
            queue
                .finish(
                    &leased.fence(),
                    crate::actions::ActionOutcome::AwaitApproval
                )
                .await
                .expect("finish awaiting approval"),
            "the claim must still be live"
        );
        (decision_id, action.id)
    }

    async fn cleanup(pool: &PgPool, tenant: &str) {
        sqlx::query("DELETE FROM sales_actions WHERE tenant_id = $1")
            .bind(tenant)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM sales_decisions WHERE tenant_id = $1")
            .bind(tenant)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM sales_autonomy_state WHERE tenant_id = $1")
            .bind(tenant)
            .execute(pool)
            .await
            .ok();
    }

    /// (c) Approving a legitimate pending review releases the parked work.
    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn approve_releases_awaiting_approval_actions_to_queued() {
        let Some(pool) = crate::test_db::canonical_test_pool("review_approve").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("approve");
        set_autonomy(&pool, &tenant, "approval_required", false).await;
        let (decision_id, action_id) =
            seed_awaiting_approval(&pool, &tenant, "approve", "enrich").await;

        let result = apply_review(
            &pool,
            &tenant,
            decision_id,
            ReviewAction::Approve,
            "ship it",
            "tester",
        )
        .await
        .expect("approve must succeed");

        assert_eq!(result.status, "approved");
        assert_eq!(
            result.actions_affected, 1,
            "the linked action must be released"
        );
        assert!(
            result.revalidation.allowed,
            "the gates must permit an approved enrich action: {:?}",
            result.revalidation.reasons
        );

        let (state, attempt, last_error, due_at, owner, token, expires): (
            String,
            i32,
            Option<String>,
            chrono::DateTime<chrono::Utc>,
            Option<String>,
            Option<Uuid>,
            Option<chrono::DateTime<chrono::Utc>>,
        ) = sqlx::query_as(
            "SELECT state, attempt, last_error, due_at, lease_owner, lease_token, lease_expires_at \
             FROM sales_actions WHERE id = $1",
        )
        .bind(action_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(state, "queued");
        assert_eq!(attempt, 0, "a released action gets a fresh attempt budget");
        assert_eq!(last_error, None);
        assert!(due_at <= chrono::Utc::now());
        assert_eq!(owner, None);
        assert_eq!(token, None);
        assert_eq!(expires, None);

        let (review_status, reviewed_by, reviewed_at, review_note): (
            Option<String>,
            Option<String>,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<String>,
        ) = sqlx::query_as(
            "SELECT review_status, reviewed_by, reviewed_at, review_note \
             FROM sales_decisions WHERE id = $1",
        )
        .bind(decision_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(review_status.as_deref(), Some("approved"));
        assert_eq!(reviewed_by.as_deref(), Some("tester"));
        assert!(reviewed_at.is_some());
        assert_eq!(review_note.as_deref(), Some("ship it"));

        cleanup(&pool, &tenant).await;
    }

    /// (a) Atomicity: a failure AFTER revalidation passed — the requeue refuses
    /// because the parked action carries lease ownership — must roll back the
    /// whole review. Before this fix, `review_status` was committed as
    /// `approved` before the release ran, so the action stayed parked and the
    /// retry was rejected as "already approved".
    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn failed_requeue_rolls_back_the_review_and_keeps_it_reviewable() {
        let Some(pool) = crate::test_db::canonical_test_pool("review_rollback").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("rollback");
        set_autonomy(&pool, &tenant, "approval_required", false).await;
        let (decision_id, action_id) =
            seed_awaiting_approval(&pool, &tenant, "rollback", "enrich").await;

        // Inject the failure: an `awaiting_approval` row written by the real
        // queue never carries a lease, so `release_actions_tx` refuses one
        // that does. This lands after revalidation (the internal enrich action
        // revalidates cleanly) and before the terminal status write.
        sqlx::query(
            "UPDATE sales_actions SET lease_owner = 'rogue-writer', \
                 lease_expires_at = NOW() + INTERVAL '5 minutes' WHERE id = $1",
        )
        .bind(action_id)
        .execute(&pool)
        .await
        .expect("inject the post-revalidation failure");

        let failed = apply_review(
            &pool,
            &tenant,
            decision_id,
            ReviewAction::Approve,
            "go",
            "tester",
        )
        .await;
        assert!(failed.is_err(), "the requeue failure must abort the review");

        // The transaction rolled back: no durable approval, work still parked.
        let (review_status, reviewed_by, reviewed_at, review_note): (
            Option<String>,
            Option<String>,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<String>,
        ) = sqlx::query_as(
            "SELECT review_status, reviewed_by, reviewed_at, review_note \
             FROM sales_decisions WHERE id = $1",
        )
        .bind(decision_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            review_status.as_deref(),
            Some("pending"),
            "a failed review must not be durable"
        );
        assert_eq!(reviewed_by, None);
        assert_eq!(reviewed_at, None);
        assert_eq!(review_note, None);

        let (state, owner): (String, Option<String>) =
            sqlx::query_as("SELECT state, lease_owner FROM sales_actions WHERE id = $1")
                .bind(action_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(state, "awaiting_approval");
        assert_eq!(owner.as_deref(), Some("rogue-writer"));

        // The decision remains reviewable: clear the injected lease and retry.
        // (Under the old flow this retry was rejected because the review was
        // already recorded as approved.)
        sqlx::query(
            "UPDATE sales_actions SET lease_owner = NULL, lease_expires_at = NULL WHERE id = $1",
        )
        .bind(action_id)
        .execute(&pool)
        .await
        .unwrap();
        let retried = apply_review(
            &pool,
            &tenant,
            decision_id,
            ReviewAction::Approve,
            "go",
            "tester",
        )
        .await
        .expect("the decision must remain reviewable after the rollback");
        assert_eq!(retried.status, "approved");
        assert_eq!(retried.actions_affected, 1);
        let state: String = sqlx::query_scalar("SELECT state FROM sales_actions WHERE id = $1")
            .bind(action_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(state, "queued");

        cleanup(&pool, &tenant).await;
    }

    /// (c) Rejecting moves the parked work to `cancelled` with the note.
    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn reject_cancels_awaiting_approval_actions() {
        let Some(pool) = crate::test_db::canonical_test_pool("review_reject").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("reject");
        set_autonomy(&pool, &tenant, "approval_required", false).await;
        let (decision_id, action_id) =
            seed_awaiting_approval(&pool, &tenant, "reject", "enrich").await;

        let result = apply_review(
            &pool,
            &tenant,
            decision_id,
            ReviewAction::Reject,
            "not now",
            "tester",
        )
        .await
        .expect("reject must succeed");

        assert_eq!(result.status, "rejected");
        assert!(!result.revalidation.allowed);
        assert_eq!(result.actions_affected, 1);

        let (state, last_error, completed): (
            String,
            Option<String>,
            Option<chrono::DateTime<chrono::Utc>>,
        ) = sqlx::query_as(
            "SELECT state, last_error, completed_at FROM sales_actions WHERE id = $1",
        )
        .bind(action_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(state, "cancelled");
        assert_eq!(last_error.as_deref(), Some("not now"));
        assert!(completed.is_some());

        let (review_status, note): (Option<String>, Option<String>) =
            sqlx::query_as("SELECT review_status, review_note FROM sales_decisions WHERE id = $1")
                .bind(decision_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(review_status.as_deref(), Some("rejected"));
        assert_eq!(note.as_deref(), Some("not now"));

        cleanup(&pool, &tenant).await;
    }

    /// (d) Approval is not a bypass: a decision whose gates now refuse is
    /// cancelled, durably recorded as rejected, and the reasons are reported.
    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn approval_refused_by_gates_cancels_work_and_reports_reasons() {
        let Some(pool) = crate::test_db::canonical_test_pool("review_revalidate").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("gates");
        // Both hard stops fire: no autonomy, kill switch engaged.
        set_autonomy(&pool, &tenant, "disabled", true).await;
        let (decision_id, action_id) =
            seed_awaiting_approval(&pool, &tenant, "gates", "contact").await;

        let result = apply_review(
            &pool,
            &tenant,
            decision_id,
            ReviewAction::Approve,
            "please send",
            "tester",
        )
        .await
        .expect("the call itself succeeds; the gates refuse the work");

        assert!(!result.revalidation.allowed, "the gates must refuse");
        assert!(
            !result.revalidation.reasons.is_empty(),
            "the refusal must name the failed gate(s)"
        );
        assert_eq!(result.actions_affected, 1);

        let state: String = sqlx::query_scalar("SELECT state FROM sales_actions WHERE id = $1")
            .bind(action_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(state, "cancelled", "refused approval must not release work");

        let (review_status, note): (Option<String>, Option<String>) =
            sqlx::query_as("SELECT review_status, review_note FROM sales_decisions WHERE id = $1")
                .bind(decision_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(review_status.as_deref(), Some("rejected"));
        let note = note.unwrap_or_default();
        assert!(
            note.contains("revalidation"),
            "the refusal reasons must be durable on the decision, got: {note}"
        );

        // A second review attempt must not be able to flip the terminal state.
        let again = apply_review(
            &pool,
            &tenant,
            decision_id,
            ReviewAction::Approve,
            "",
            "tester",
        )
        .await;
        assert!(again.is_err(), "a terminal review must not be overwritten");

        cleanup(&pool, &tenant).await;
    }

    /// (e) Exceptions select on the decision's own recorded state, not the
    /// autonomy mode: an `execute` decision recorded under `assisted` must not
    /// be an exception.
    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn exceptions_select_decision_state_not_autonomy_mode() {
        let Some(pool) = crate::test_db::canonical_test_pool("exceptions_predicate").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("exceptions");

        let awaiting = insert_decision(
            &pool,
            &tenant,
            "contact",
            "await_approval",
            Some("pending"),
            "approval_required",
        )
        .await;
        let denied = insert_decision(
            &pool,
            &tenant,
            "contact",
            "denied",
            Some("not_required"),
            "autonomous_guarded",
        )
        .await;
        // The trap: the old predicate matched this row via autonomy_mode.
        let executed = insert_decision(
            &pool,
            &tenant,
            "contact",
            "execute",
            Some("not_required"),
            "assisted",
        )
        .await;

        let rows = control_read::load_exceptions(&pool, &tenant, 50, 0)
            .await
            .expect("exceptions query");
        let ids: Vec<Uuid> = rows.into_iter().map(|row| row.id).collect();

        assert!(
            ids.contains(&awaiting),
            "await_approval must be an exception"
        );
        assert!(ids.contains(&denied), "denied must be an exception");
        assert!(
            !ids.contains(&executed),
            "an execute decision must not be an exception regardless of autonomy mode"
        );

        cleanup(&pool, &tenant).await;
    }
}
