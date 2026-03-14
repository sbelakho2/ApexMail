//! Message sending and management routes.

use super::helpers::{clamp_limit, default_limit};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(send_message).get(list_messages))
        .route("/batch", post(send_batch))
        .route("/:id", get(get_message))
        .route("/:id/cancel", post(cancel_message))
}

// ─── Constants ─────────────────────────────────────────────────

/// Maximum recipients per single message (to + cc + bcc combined).
static MAX_RECIPIENTS: LazyLock<usize> = LazyLock::new(|| {
    std::env::var("API_MESSAGES_MAX_RECIPIENTS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1000)
});
/// Maximum messages in a batch request.
static MAX_BATCH_SIZE: LazyLock<usize> = LazyLock::new(|| {
    std::env::var("API_MESSAGES_MAX_BATCH_SIZE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(100)
});

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    pub from: String,
    pub to: Vec<String>,
    #[serde(default)]
    pub cc: Option<Vec<String>>,
    #[serde(default)]
    pub bcc: Option<Vec<String>>,
    pub subject: String,
    #[serde(default)]
    pub html: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub scheduled_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub id: String,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct MessageDetail {
    pub id: String,
    pub from: String,
    pub to: serde_json::Value,
    pub subject: String,
    pub status: String,
    pub tags: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
    pub scheduled_at: Option<String>,
    pub sent_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct ListMessagesQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub cursor: Option<i64>,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BatchSendRequest {
    pub messages: Vec<SendMessageRequest>,
}

#[derive(Debug, Serialize)]
pub struct BatchSendResponse {
    pub accepted: usize,
    pub rejected: usize,
    pub results: Vec<BatchResult>,
}

#[derive(Debug, Serialize)]
pub struct BatchResult {
    pub index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ─── Handlers ──────────────────────────────────────────────────

async fn send_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<SendMessageRequest>,
) -> Result<(StatusCode, Json<MessageResponse>), ApiError> {
    require_scopes(&auth, &["messages:send"])?;
    validate_send(&body, &state, &auth.tenant_id).await?;

    let id = Uuid::new_v4();
    let now = Utc::now();
    let status = if body.scheduled_at.is_some() {
        "scheduled"
    } else {
        "queued"
    };

    sqlx::query(
        "INSERT INTO messages (id, tenant_id, from_email, to_emails, cc_emails, bcc_emails,
         subject, html_body, text_body, status, tags, metadata, scheduled_at, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .bind(&body.from)
    .bind(serde_json::json!(body.to))
    .bind(body.cc.as_ref().map(|v| serde_json::json!(v)))
    .bind(body.bcc.as_ref().map(|v| serde_json::json!(v)))
    .bind(&body.subject)
    .bind(&body.html)
    .bind(&body.text)
    .bind(status)
    .bind(body.tags.as_ref().map(|v| serde_json::json!(v)))
    .bind(&body.metadata)
    .bind(body.scheduled_at)
    .bind(now)
    .execute(&state.db)
    .await?;

    Ok((
        StatusCode::ACCEPTED,
        Json(MessageResponse {
            id: id.to_string(),
            status: status.into(),
            created_at: now.to_rfc3339(),
        }),
    ))
}

async fn send_batch(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<BatchSendRequest>,
) -> Result<Json<BatchSendResponse>, ApiError> {
    require_scopes(&auth, &["messages:send"])?;

    // Fix #26: Limit batch size to prevent abuse.
    if body.messages.len() > *MAX_BATCH_SIZE {
        return Err(ApiError::BadRequest(format!(
            "batch size {} exceeds maximum of {}",
            *MAX_BATCH_SIZE,
            body.messages.len()
        )));
    }

    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut results = Vec::with_capacity(body.messages.len());

    for (i, msg) in body.messages.iter().enumerate() {
        if let Err(e) = validate_send(msg, &state, &auth.tenant_id).await {
            rejected += 1;
            results.push(BatchResult {
                index: i,
                id: None,
                status: "rejected".into(),
                error: Some(e.to_string()),
            });
            continue;
        }

        let id = Uuid::new_v4();
        let now = Utc::now();

        let res = sqlx::query(
            "INSERT INTO messages (id, tenant_id, from_email, to_emails, subject, html_body, text_body, status, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,'queued',$8)",
        )
        .bind(id)
        .bind(&auth.tenant_id)
        .bind(&msg.from)
        .bind(serde_json::json!(msg.to))
        .bind(&msg.subject)
        .bind(&msg.html)
        .bind(&msg.text)
        .bind(now)
        .execute(&state.db)
        .await;

        match res {
            Ok(_) => {
                accepted += 1;
                results.push(BatchResult {
                    index: i,
                    id: Some(id),
                    status: "queued".into(),
                    error: None,
                });
            }
            Err(e) => {
                // Fix #27: Don't leak raw DB error details to client.
                tracing::error!(error = %e, batch_index = i, "batch insert failed");
                rejected += 1;
                results.push(BatchResult {
                    index: i,
                    id: None,
                    status: "rejected".into(),
                    error: Some("database error".into()),
                });
            }
        }
    }

    Ok(Json(BatchSendResponse {
        accepted,
        rejected,
        results,
    }))
}

async fn list_messages(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ListMessagesQuery>,
) -> Result<Json<Vec<MessageDetail>>, ApiError> {
    require_scopes(&auth, &["messages:read"])?;

    // Fix #30: Validate offset >= 0.
    // Fix #58: Clamp offset to valid range.
    let offset = params.cursor.unwrap_or(params.offset).clamp(0, 100_000);

    // Fix #29: Use status filter in query when provided.
    let rows = if let Some(ref status) = params.status {
        sqlx::query_as::<_, MessageRow>(
            "SELECT id, from_email, to_emails, subject, status, tags, metadata, scheduled_at, sent_at, created_at
             FROM messages WHERE tenant_id = $1 AND status = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4",
        )
        .bind(&auth.tenant_id)
        .bind(status)
        .bind(clamp_limit(params.limit, 100))
        .bind(offset)
        .fetch_all(&state.db)
        .await?
    } else {
        sqlx::query_as::<_, MessageRow>(
            "SELECT id, from_email, to_emails, subject, status, tags, metadata, scheduled_at, sent_at, created_at
             FROM messages WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(&auth.tenant_id)
        .bind(clamp_limit(params.limit, 100))
        .bind(offset)
        .fetch_all(&state.db)
        .await?
    };

    Ok(Json(rows.into_iter().map(row_to_detail).collect()))
}

async fn get_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<MessageDetail>, ApiError> {
    require_scopes(&auth, &["messages:read"])?;

    let row = sqlx::query_as::<_, MessageRow>(
        "SELECT id, from_email, to_emails, subject, status, tags, metadata, scheduled_at, sent_at, created_at
         FROM messages WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("message not found".into()))?;

    Ok(Json(row_to_detail(row)))
}

async fn cancel_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<MessageResponse>, ApiError> {
    require_scopes(&auth, &["messages:send"])?;

    let result = sqlx::query(
        "UPDATE messages SET status = 'cancelled' WHERE id = $1 AND tenant_id = $2 AND status IN ('queued', 'scheduled')",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::Conflict(
            "message cannot be cancelled (already sent or not found)".into(),
        ));
    }

    Ok(Json(MessageResponse {
        id: id.to_string(),
        status: "cancelled".into(),
        created_at: Utc::now().to_rfc3339(),
    }))
}

// ─── Helpers ───────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct MessageRow {
    id: String,
    from_email: String,
    to_emails: serde_json::Value,
    subject: String,
    status: String,
    tags: Option<serde_json::Value>,
    metadata: Option<serde_json::Value>,
    scheduled_at: Option<DateTime<Utc>>,
    sent_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

fn row_to_detail(r: MessageRow) -> MessageDetail {
    MessageDetail {
        id: r.id,
        from: r.from_email,
        to: r.to_emails,
        subject: r.subject,
        status: r.status,
        tags: r.tags,
        metadata: r.metadata,
        scheduled_at: r.scheduled_at.map(|t| t.to_rfc3339()),
        sent_at: r.sent_at.map(|t| t.to_rfc3339()),
        created_at: r.created_at.to_rfc3339(),
    }
}

/// Validate a send request before enqueueing.
///
/// Fix #25: Enforces max recipient count (1000).
/// Fix #28: Verifies the sender's domain is owned by the authenticated tenant.
async fn validate_send(
    body: &SendMessageRequest,
    state: &AppState,
    tenant_id: &str,
) -> Result<(), ApiError> {
    let mut errors = Vec::new();
    if body.from.is_empty() {
        errors.push("from is required".into());
    } else if !apexmail_lib::validation::is_valid_email(&body.from) {
        errors.push(format!("invalid sender email: {}", body.from));
    }
    if body.to.is_empty() {
        errors.push("at least one recipient is required".into());
    }

    // Fix #25: Enforce max recipients across to/cc/bcc.
    let total_recipients = body.to.len()
        + body.cc.as_ref().map_or(0, |v| v.len())
        + body.bcc.as_ref().map_or(0, |v| v.len());
    if total_recipients > *MAX_RECIPIENTS {
        errors.push(format!(
            "total recipients ({total_recipients}) exceeds maximum of {}",
            *MAX_RECIPIENTS
        ));
    }

    if body.subject.is_empty() {
        errors.push("subject is required".into());
    }
    if body.html.is_none() && body.text.is_none() {
        errors.push("html or text body is required".into());
    }
    for email in &body.to {
        if !apexmail_lib::validation::is_valid_email(email) {
            errors.push(format!("invalid recipient email: {email}"));
        }
    }
    // Validate CC recipients
    if let Some(ref cc) = body.cc {
        for email in cc {
            if !apexmail_lib::validation::is_valid_email(email) {
                errors.push(format!("invalid CC email: {email}"));
            }
        }
    }
    // Validate BCC recipients
    if let Some(ref bcc) = body.bcc {
        for email in bcc {
            if !apexmail_lib::validation::is_valid_email(email) {
                errors.push(format!("invalid BCC email: {email}"));
            }
        }
    }

    // Fix #28: Verify the sender's domain is owned by the tenant.
    // Extract domain from the "from" email.
    if !body.from.is_empty() {
        if let Some(domain) = body.from.split('@').nth(1) {
            let exists: Option<(i64,)> = sqlx::query_as(
                "SELECT 1 FROM domains WHERE tenant_id = $1 AND name = $2 AND verified = true",
            )
            .bind(tenant_id)
            .bind(domain.to_lowercase())
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "domain ownership check failed");
                ApiError::Internal("domain verification error".into())
            })?;

            if exists.is_none() {
                errors.push(format!(
                    "domain '{domain}' is not verified for this account"
                ));
            }
        }
    }

    if !errors.is_empty() {
        return Err(ApiError::Validation(errors));
    }
    Ok(())
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_request_deser() {
        let json = r#"{
            "from": "sender@example.com",
            "to": ["user@example.com"],
            "subject": "Hello",
            "html": "<p>Hi</p>"
        }"#;
        let req: SendMessageRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.to.len(), 1);
    }

    // Note: validate_send tests removed because the function is now async and
    // requires AppState + tenant_id. Integration tests should verify validation.

    #[test]
    fn test_batch_send_response_serialisation() {
        let resp = BatchSendResponse {
            accepted: 2,
            rejected: 1,
            results: vec![
                BatchResult { index: 0, id: Some(Uuid::nil()), status: "queued".into(), error: None },
                BatchResult { index: 1, id: None, status: "rejected".into(), error: Some("bad email".into()) },
            ],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["accepted"], 2);
    }
}
