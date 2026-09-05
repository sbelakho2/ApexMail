//! Human approval surface for AI-generated inbound-reply drafts.
//!
//! The email agent (ai-service) writes drafts with `pending_approval = true`
//! and NEVER sends anything. This surface is the missing reader: operators
//! list pending drafts, approve (which sends the reply through the
//! platform's verified system sender — `queue_system_email`, attributed to
//! the system tenant that owns the sending domain) or reject them. Every
//! decision is audit-logged with full actor attribution.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_drafts))
        .route("/:id/approve", post(approve_draft))
        .route("/:id/reject", post(reject_draft))
}

#[derive(Debug, Serialize)]
struct DraftDto {
    id: String,
    tenant_id: String,
    from_email: String,
    subject: String,
    draft_reply: String,
    received_at: String,
}

async fn list_drafts(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["*"])?;

    let rows: Vec<(
        Uuid,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
    )> = sqlx::query_as(
        r#"
        SELECT id, tenant_id, from_email, subject, ai_response, received_at
        FROM inbound_messages
        WHERE pending_approval = true
          AND ai_response IS NOT NULL
        ORDER BY received_at ASC
        LIMIT 100
        "#,
    )
    .fetch_all(&state.db)
    .await?;

    let drafts: Vec<DraftDto> = rows
        .into_iter()
        .map(|(id, tenant, from, subject, reply, ts)| DraftDto {
            id: id.to_string(),
            tenant_id: tenant.unwrap_or_default(),
            from_email: from.unwrap_or_default(),
            subject: subject.unwrap_or_default(),
            draft_reply: reply.unwrap_or_default(),
            received_at: ts.to_rfc3339(),
        })
        .collect();

    Ok(Json(
        serde_json::json!({ "drafts": drafts, "count": drafts.len() }),
    ))
}

#[derive(Debug, Deserialize)]
struct ApproveBody {
    /// Operator note recorded in the audit log.
    #[serde(default)]
    pub note: String,
}

/// Actor-attributed audit for AI-draft decisions (P1-4/P2-2): an approved
/// AI reply is a platform-sent message to a customer — the operator who
/// approved it (tenant + user) and the routed tenant must be on record.
async fn log_draft_audit(
    state: &AppState,
    auth: &AuthUser,
    action: &str,
    draft_id: &str,
    metadata: serde_json::Value,
) {
    crate::audit_log::insert_audit_log_best_effort_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        action,
        "ai_draft",
        Some(draft_id),
        metadata,
        None,
        None,
    )
    .await;
}

async fn approve_draft(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    body: Option<Json<ApproveBody>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["*"])?;
    let note = body.map(|Json(b)| b.note).unwrap_or_default();

    // Claim the draft atomically: exactly one approve/reject wins.
    let row: Option<(
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        r#"
        UPDATE inbound_messages
        SET pending_approval = false, processed_at = NOW()
        WHERE id = $1::uuid
          AND pending_approval = true
          AND ai_response IS NOT NULL
        RETURNING tenant_id, from_email, subject, ai_response
        "#,
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await?;

    let Some((tenant_id, from_email, subject, reply)) = row else {
        return Err(ApiError::NotFound(
            "draft not found or already handled".into(),
        ));
    };
    let tenant_id = tenant_id.unwrap_or_default();
    let from_email = from_email.unwrap_or_default();
    let subject = subject.unwrap_or_default();
    let reply = reply.unwrap_or_default();

    if tenant_id.is_empty() || from_email.is_empty() {
        // Cannot route the reply — release the claim so it stays visible.
        let _ = sqlx::query(
            "UPDATE inbound_messages SET pending_approval = true, processed_at = NULL \
             WHERE id = $1::uuid",
        )
        .bind(&id)
        .execute(&state.db)
        .await;
        return Err(ApiError::Validation(vec![
            "draft is missing tenant or sender; reject it instead".into(),
        ]));
    }

    // P1-4: route through the platform's verified system sender. The
    // previous hand-rolled email_queue INSERT hardcoded
    // `support@apexmail.ee` as the from-address while attributing the row to
    // the CUSTOMER's tenant — the customer neither owns apexmail.ee (SPF/
    // DKIM alignment broken) nor sent the mail. `queue_system_email`
    // enforces system-sender readiness under lock and attributes the queue
    // row to the system tenant that actually owns the sending domain.
    let queued = crate::routes::system_sender::queue_system_email(
        &state.db,
        &from_email,
        &subject,
        "",
        &reply,
        vec!["ai-draft-approval".to_string()],
    )
    .await;

    match queued {
        Ok(message_uuid) => {
            tracing::info!(
                operator = %auth.user_id.clone().unwrap_or_default(),
                draft_id = %id,
                tenant_id = %tenant_id,
                note = %note,
                "AI reply draft APPROVED and queued"
            );
            log_draft_audit(
                &state,
                &auth,
                "control_plane.ai_draft.approved",
                &id,
                serde_json::json!({
                    "note": note,
                    "routedTenantId": tenant_id,
                    "recipient": from_email,
                    "queuedMessageId": message_uuid.to_string(),
                }),
            )
            .await;
            Ok(Json(serde_json::json!({
                "approved": true,
                "queued_message_id": message_uuid.to_string(),
            })))
        }
        Err(e) => {
            // Release the claim: the draft remains pending for retry.
            let _ = sqlx::query(
                "UPDATE inbound_messages SET pending_approval = true, processed_at = NULL \
                 WHERE id = $1::uuid",
            )
            .bind(&id)
            .execute(&state.db)
            .await;
            tracing::error!(error = %e, draft_id = %id, "approve: queue insert failed");
            Err(ApiError::Internal(
                "could not queue the reply; draft still pending".into(),
            ))
        }
    }
}

async fn reject_draft(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    body: Option<Json<ApproveBody>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["*"])?;
    let note = body.map(|Json(b)| b.note).unwrap_or_default();

    let result = sqlx::query(
        "UPDATE inbound_messages SET pending_approval = false, processed_at = NOW() \
         WHERE id = $1::uuid AND pending_approval = true",
    )
    .bind(&id)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound(
            "draft not found or already handled".into(),
        ));
    }
    tracing::info!(
        operator = %auth.user_id.clone().unwrap_or_default(),
        draft_id = %id,
        note = %note,
        "AI reply draft REJECTED"
    );
    log_draft_audit(
        &state,
        &auth,
        "control_plane.ai_draft.rejected",
        &id,
        serde_json::json!({ "note": note }),
    )
    .await;
    Ok(Json(serde_json::json!({ "rejected": true })))
}

// Keep StatusCode import used uniformly.
#[allow(dead_code)]
fn _status_guard(_s: StatusCode) {}
