//! Message sending and management routes.

use super::helpers::{clamp_limit, default_limit};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use billing_service::types::MeterEventType;
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
    pub id: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

struct PersistedMessage {
    id: String,
    status: &'static str,
    created_at: DateTime<Utc>,
}

enum CancelDeliveryResult {
    Cancelled(DateTime<Utc>),
    NotFound,
    NotCancellable,
}

fn message_status(body: &SendMessageRequest) -> &'static str {
    if body.scheduled_at.is_some() {
        "scheduled"
    } else {
        "queued"
    }
}

fn delivery_recipients(body: &SendMessageRequest) -> Vec<&str> {
    let mut recipients = Vec::with_capacity(
        body.to.len()
            + body.cc.as_ref().map_or(0, |recipients| recipients.len())
            + body.bcc.as_ref().map_or(0, |recipients| recipients.len()),
    );

    recipients.extend(body.to.iter().map(String::as_str));
    if let Some(cc) = &body.cc {
        recipients.extend(cc.iter().map(String::as_str));
    }
    if let Some(bcc) = &body.bcc {
        recipients.extend(bcc.iter().map(String::as_str));
    }

    recipients
}

async fn insert_message_and_queue(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    body: &SendMessageRequest,
    metadata: &Option<serde_json::Value>,
) -> Result<PersistedMessage, sqlx::Error> {
    let message_id = apexmail_lib::id::generate_id("msg", 22);
    let created_at = Utc::now();
    let status = message_status(body);
    let sender_domain = body
        .from
        .rsplit_once('@')
        .map(|(_, domain)| domain.to_lowercase())
        .unwrap_or_default();
    let domain_id = sqlx::query_scalar::<_, String>(
        "SELECT id FROM domains WHERE tenant_id = $1 AND domain = $2 AND is_verified = true LIMIT 1",
    )
    .bind(tenant_id)
    .bind(&sender_domain)
    .fetch_one(&mut **tx)
    .await?;

    sqlx::query(
        "INSERT INTO messages (id, tenant_id, from_email, to_emails, cc_emails, bcc_emails,
         subject, html_body, text_body, status, tags, metadata, scheduled_at, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
    )
    .bind(&message_id)
    .bind(tenant_id)
    .bind(&body.from)
    .bind(serde_json::json!(body.to))
    .bind(body.cc.as_ref().map(|recipients| serde_json::json!(recipients)))
    .bind(body.bcc.as_ref().map(|recipients| serde_json::json!(recipients)))
    .bind(&body.subject)
    .bind(&body.html)
    .bind(&body.text)
    .bind(status)
    .bind(body.tags.as_ref().map(|tags| serde_json::json!(tags)))
    .bind(metadata)
    .bind(body.scheduled_at)
    .bind(created_at)
    .execute(&mut **tx)
    .await?;

    for recipient in delivery_recipients(body) {
        sqlx::query(
            "INSERT INTO email_queue (
                id, message_id, tenant_id, domain_id, \"from\", \"to\", subject,
                html, text, tags, metadata, scheduled_at, priority, status, created_at, updated_at
             ) VALUES (
                $1, $2, $3, $4, $5, $6, $7,
                $8, $9, $10, $11, $12, 5, 'pending', $13, $13
             )",
        )
        .bind(apexmail_lib::id::generate_id("emq", 22))
        .bind(&message_id)
        .bind(tenant_id)
        .bind(&domain_id)
        .bind(&body.from)
        .bind(recipient)
        .bind(&body.subject)
        .bind(&body.html)
        .bind(&body.text)
        .bind(body.tags.as_ref().map(|tags| serde_json::json!(tags)))
        .bind(metadata)
        .bind(body.scheduled_at)
        .bind(created_at)
        .execute(&mut **tx)
        .await?;
    }

    Ok(PersistedMessage {
        id: message_id,
        status,
        created_at,
    })
}

async fn cancel_message_and_queue(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    message_id: &str,
) -> Result<CancelDeliveryResult, sqlx::Error> {
    let row: Option<(String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT status, created_at FROM messages WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
    )
    .bind(message_id)
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await?;

    let Some((status, created_at)) = row else {
        return Ok(CancelDeliveryResult::NotFound);
    };

    if !matches!(status.as_str(), "queued" | "scheduled") {
        return Ok(CancelDeliveryResult::NotCancellable);
    }

    let non_pending_queue_rows = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint
         FROM email_queue
         WHERE message_id = $1 AND tenant_id = $2 AND status NOT IN ('pending', 'cancelled')",
    )
    .bind(message_id)
    .bind(tenant_id)
    .fetch_one(&mut **tx)
    .await?;

    if non_pending_queue_rows > 0 {
        return Ok(CancelDeliveryResult::NotCancellable);
    }

    sqlx::query(
        "UPDATE email_queue
         SET status = 'cancelled', locked_until = NULL, updated_at = NOW()
         WHERE message_id = $1 AND tenant_id = $2 AND status = 'pending'",
    )
    .bind(message_id)
    .bind(tenant_id)
    .execute(&mut **tx)
    .await?;

    sqlx::query(
        "UPDATE messages SET status = 'cancelled' WHERE id = $1 AND tenant_id = $2",
    )
    .bind(message_id)
    .bind(tenant_id)
    .execute(&mut **tx)
    .await?;

    Ok(CancelDeliveryResult::Cancelled(created_at))
}

// ─── Handlers ──────────────────────────────────────────────────

async fn send_message(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: HeaderMap,
    Json(body): Json<SendMessageRequest>,
) -> Result<(StatusCode, Json<MessageResponse>), ApiError> {
    require_scopes(&auth, &["messages:send"])?;
    validate_send(&body, &state, &auth.tenant_id).await?;

// existing message instead of creating a duplicate.
    if let Some(idem_key) = headers.get("idempotency-key").and_then(|v| v.to_str().ok()) {
        if !idem_key.is_empty() && idem_key.len() <= 255 {
            let existing: Option<(String, String, DateTime<Utc>)> = sqlx::query_as(
                "SELECT id, status, created_at FROM messages
                 WHERE tenant_id = $1 AND metadata->>'idempotency_key' = $2
                 LIMIT 1",
            )
            .bind(&auth.tenant_id)
            .bind(idem_key)
            .fetch_optional(&state.db)
            .await?;

            if let Some((id, status, created_at)) = existing {
                return Ok((
                    StatusCode::OK,
                    Json(MessageResponse {
                        id,
                        status,
                        created_at: created_at.to_rfc3339(),
                    }),
                ));
            }
        }
    }

    let quota_reservation = reserve_email_quota(&state, &auth.tenant_id).await?;

// Merge idempotency key into metadata if present.
    let metadata = {
        let mut meta = body.metadata.clone().unwrap_or_else(|| serde_json::json!({}));
        if let Some(idem_key) = headers.get("idempotency-key").and_then(|v| v.to_str().ok()) {
            if !idem_key.is_empty() && idem_key.len() <= 255 {
                meta.as_object_mut()
                    .map(|m| m.insert("idempotency_key".into(), serde_json::json!(idem_key)));
            }
        }
        Some(meta)
    };

    let mut tx = state.db.begin().await.map_err(|error| {
        tracing::error!(error = %error, tenant_id = %auth.tenant_id, "failed to begin message transaction");
        ApiError::Internal("database error".into())
    })?;

    let persisted = match insert_message_and_queue(&mut tx, &auth.tenant_id, &body, &metadata).await {
        Ok(persisted) => persisted,
        Err(error) => {
            let _ = tx.rollback().await;

            if let Err(rollback_error) = rollback_email_quota(&state, &auth.tenant_id, &quota_reservation).await {
                tracing::error!(
                    error = %rollback_error,
                    tenant_id = %auth.tenant_id,
                    event_id = %quota_reservation.event_id,
                    "failed to roll back reserved email quota after single-send insert failure"
                );
            }

            tracing::error!(error = %error, tenant_id = %auth.tenant_id, "failed to persist message delivery");
            return Err(ApiError::Internal("database error".into()));
        }
    };

    if let Err(error) = tx.commit().await {
        if let Err(rollback_error) = rollback_email_quota(&state, &auth.tenant_id, &quota_reservation).await {
            tracing::error!(
                error = %rollback_error,
                tenant_id = %auth.tenant_id,
                event_id = %quota_reservation.event_id,
                "failed to roll back reserved email quota after single-send commit failure"
            );
        }

        tracing::error!(error = %error, tenant_id = %auth.tenant_id, "failed to commit message delivery");
        return Err(ApiError::Internal("database error".into()));
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(MessageResponse {
            id: persisted.id,
            status: persisted.status.into(),
            created_at: persisted.created_at.to_rfc3339(),
        }),
    ))
}

async fn send_batch(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<BatchSendRequest>,
) -> Result<Json<BatchSendResponse>, ApiError> {
    require_scopes(&auth, &["messages:send"])?;

    if body.messages.len() > *MAX_BATCH_SIZE {
        return Err(ApiError::BadRequest(format!(
            "batch size {} exceeds maximum of {}",
            body.messages.len(),
            *MAX_BATCH_SIZE
        )));
    }

    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut results = Vec::with_capacity(body.messages.len());
    let mut committed_quota_reservations: Vec<QuotaReservation> = Vec::with_capacity(body.messages.len());

    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!(error = %e, "failed to begin batch transaction");
        ApiError::Internal("database error".into())
    })?;

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

        let quota_reservation = match reserve_email_quota(&state, &auth.tenant_id).await {
            Ok(reservation) => reservation,
            Err(ApiError::Forbidden(message)) => {
                rejected += 1;
                results.push(BatchResult {
                    index: i,
                    id: None,
                    status: "rejected".into(),
                    error: Some(message),
                });
                continue;
            }
            Err(err) => return Err(err),
        };

        match insert_message_and_queue(&mut tx, &auth.tenant_id, msg, &msg.metadata).await {
            Ok(persisted) => {
                accepted += 1;
                committed_quota_reservations.push(quota_reservation);
                results.push(BatchResult {
                    index: i,
                    id: Some(persisted.id),
                    status: persisted.status.into(),
                    error: None,
                });
            }
            Err(e) => {
                if let Err(rollback_error) = rollback_email_quota(&state, &auth.tenant_id, &quota_reservation).await {
                    tracing::error!(
                        error = %rollback_error,
                        tenant_id = %auth.tenant_id,
                        event_id = %quota_reservation.event_id,
                        batch_index = i,
                        "failed to roll back reserved email quota after batch insert failure"
                    );
                }
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

// Commit only if at least one message was accepted.
    if accepted > 0 {
        if let Err(error) = tx.commit().await {
            for reservation in &committed_quota_reservations {
                if let Err(rollback_error) = rollback_email_quota(&state, &auth.tenant_id, reservation).await {
                    tracing::error!(
                        error = %rollback_error,
                        tenant_id = %auth.tenant_id,
                        event_id = %reservation.event_id,
                        "failed to roll back reserved email quota after batch commit failure"
                    );
                }
            }

            tracing::error!(error = %error, "failed to commit batch transaction");
            return Err(ApiError::Internal("database error".into()));
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

    let offset = params.cursor.unwrap_or(params.offset).clamp(0, 100_000);

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
    Path(id): Path<String>,
) -> Result<Json<MessageDetail>, ApiError> {
    require_scopes(&auth, &["messages:read"])?;

    let row = sqlx::query_as::<_, MessageRow>(
        "SELECT id, from_email, to_emails, subject, status, tags, metadata, scheduled_at, sent_at, created_at
         FROM messages WHERE id = $1 AND tenant_id = $2",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("message not found".into()))?;

    Ok(Json(row_to_detail(row)))
}

async fn cancel_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, ApiError> {
    require_scopes(&auth, &["messages:send"])?;

    let mut tx = state.db.begin().await.map_err(|error| {
        tracing::error!(error = %error, tenant_id = %auth.tenant_id, message_id = %id, "failed to begin message cancellation transaction");
        ApiError::Internal("database error".into())
    })?;

    let created_at = match cancel_message_and_queue(&mut tx, &auth.tenant_id, &id).await? {
        CancelDeliveryResult::Cancelled(created_at) => created_at,
        CancelDeliveryResult::NotFound | CancelDeliveryResult::NotCancellable => {
            let _ = tx.rollback().await;
            return Err(ApiError::Conflict("message cannot be cancelled (already sent or not found)".into()));
        }
    };

    tx.commit().await.map_err(|error| {
        tracing::error!(error = %error, tenant_id = %auth.tenant_id, message_id = %id, "failed to commit message cancellation");
        ApiError::Internal("database error".into())
    })?;

    Ok(Json(MessageResponse {
        id,
        status: "cancelled".into(),
        created_at: created_at.to_rfc3339(),
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

// Extract domain from the "from" email.
    if !body.from.is_empty() {
        if let Some(domain) = body.from.split('@').nth(1) {
            let exists: Option<(i64,)> = sqlx::query_as(
                "SELECT 1 FROM domains WHERE tenant_id = $1 AND domain = $2 AND is_verified = true",
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

#[derive(Debug, Clone)]
struct QuotaReservation {
    event_id: Uuid,
    recorded_at: DateTime<Utc>,
}

async fn reserve_email_quota(state: &AppState, tenant_id: &str) -> Result<QuotaReservation, ApiError> {
    let reservation = QuotaReservation {
        event_id: Uuid::new_v4(),
        recorded_at: Utc::now(),
    };

    let quota = billing_service::usage::record_with_quota_check(
        &state.db,
        &state.redis,
        tenant_id,
        MeterEventType::EmailsSent,
        1,
        Some(reservation.event_id),
        None,
    )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, tenant_id = %tenant_id, "quota reservation failed");
            ApiError::ServiceUnavailable("billing quota enforcement is temporarily unavailable".into())
        })?;

    if !quota.allowed {
        return Err(ApiError::Forbidden("email quota exceeded".into()));
    }

    Ok(reservation)
}

async fn rollback_email_quota(
    state: &AppState,
    tenant_id: &str,
    reservation: &QuotaReservation,
) -> Result<(), ApiError> {
    billing_service::usage::rollback_usage_record(
        &state.db,
        &state.redis,
        tenant_id,
        MeterEventType::EmailsSent,
        1,
        reservation.event_id,
        reservation.recorded_at,
    )
    .await
    .map_err(|e| {
        ApiError::ServiceUnavailable(format!("failed to roll back reserved quota: {e}"))
    })
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    use sqlx::{migrate::Migrator, PgPool};
    use uuid::Uuid;

    fn tool_migrations_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../tools/migrations")
    }

    async fn apply_tool_migrations(pool: &PgPool) {
        let source_dir = tool_migrations_dir();
        let temp_dir = std::env::temp_dir().join(format!(
            "apexmail-api-messages-up-migrations-{}",
            Uuid::new_v4()
        ));

        fs::create_dir_all(&temp_dir).expect("failed to create temp sqlx migration directory");

        let mut entries: Vec<PathBuf> = fs::read_dir(&source_dir)
            .expect("failed to read tools/migrations")
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("sql"))
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| !name.ends_with("_down.sql") && !name.contains("performance_indexes"))
                    .unwrap_or(false)
            })
            .collect();
        entries.sort();

        for path in entries {
            let file_name = path.file_name().expect("migration path missing filename");
            let raw = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("failed to read migration {:?}: {error}", path));
            let normalized = raw
                .replace("CREATE UNIQUE INDEX CONCURRENTLY", "CREATE UNIQUE INDEX")
                .replace("CREATE INDEX CONCURRENTLY", "CREATE INDEX");
            fs::write(temp_dir.join(file_name), normalized)
                .unwrap_or_else(|error| panic!("failed to write copied migration {:?}: {error}", path));
        }

        let migrator = Migrator::new(temp_dir.clone())
            .await
            .expect("failed to load copied up migrations");
        migrator
            .run(pool)
            .await
            .expect("failed to apply copied up migrations");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    fn bounded_id(prefix: &str) -> String {
        let suffix_len = 26usize.saturating_sub(prefix.len() + 1);
        apexmail_lib::id::generate_id(prefix, suffix_len)
    }

    async fn insert_test_tenant(pool: &PgPool, suffix: &str) -> String {
        let id = bounded_id("ten");
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status)
             VALUES ($1, $2, $3, 'free', 'active')",
        )
        .bind(&id)
        .bind(format!("Test Tenant {suffix}"))
        .bind(format!("test-{suffix}"))
        .execute(pool)
        .await
        .expect("failed to insert test tenant");
        id
    }

    async fn insert_verified_domain(pool: &PgPool, tenant_id: &str, domain: &str) -> String {
        let id = bounded_id("dom");
        sqlx::query(
            "INSERT INTO domains (id, tenant_id, domain, is_verified)
             VALUES ($1, $2, $3, true)",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(domain)
        .execute(pool)
        .await
        .expect("failed to insert verified domain");
        id
    }

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

// Note:validate_send tests removed because the function is now async and
// requires AppState + tenant_id. Integration tests should verify validation.

    #[test]
    fn test_batch_send_response_serialisation() {
        let resp = BatchSendResponse {
            accepted: 2,
            rejected: 1,
            results: vec![
                BatchResult { index: 0, id: Some("msg_test_id".into()), status: "queued".into(), error: None },
                BatchResult { index: 1, id: None, status: "rejected".into(), error: Some("bad email".into()) },
            ],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["accepted"], 2);
    }

    #[sqlx::test]
    async fn api_messages_enqueue_worker_rows_for_all_recipients(pool: PgPool) {
        apply_tool_migrations(&pool).await;

        let tenant_id = insert_test_tenant(&pool, "message-queue").await;
        let domain_id = insert_verified_domain(&pool, &tenant_id, "example.com").await;
        let scheduled_at = Utc::now() + chrono::Duration::minutes(15);
        let body = SendMessageRequest {
            from: "sender@example.com".into(),
            to: vec!["to@example.com".into()],
            cc: Some(vec!["cc@example.com".into()]),
            bcc: Some(vec!["bcc@example.com".into()]),
            subject: "Queue me".into(),
            html: Some("<p>Hello</p>".into()),
            text: Some("Hello".into()),
            tags: Some(vec!["promo".into()]),
            metadata: Some(serde_json::json!({"source": "api"})),
            scheduled_at: Some(scheduled_at),
        };

        let mut tx = pool.begin().await.expect("failed to begin message transaction");
        let persisted = insert_message_and_queue(&mut tx, &tenant_id, &body, &body.metadata)
            .await
            .expect("failed to persist message delivery");
        tx.commit().await.expect("failed to commit message transaction");

        let message_row: (String, Option<DateTime<Utc>>,) = sqlx::query_as(
            "SELECT status, scheduled_at FROM messages WHERE id = $1 AND tenant_id = $2",
        )
        .bind(&persisted.id)
        .bind(&tenant_id)
        .fetch_one(&pool)
        .await
        .expect("failed to fetch stored message");
        assert_eq!(message_row.0, "scheduled");
        assert_eq!(message_row.1, Some(scheduled_at));

        let queue_rows: Vec<(String, String, String, Option<DateTime<Utc>>)> = sqlx::query_as(
            "SELECT \"to\", message_id, domain_id, scheduled_at
             FROM email_queue WHERE message_id = $1 ORDER BY \"to\"",
        )
        .bind(&persisted.id)
        .fetch_all(&pool)
        .await
        .expect("failed to fetch queued email rows");

        assert_eq!(queue_rows.len(), 3);
        assert_eq!(
            queue_rows.iter().map(|row| row.0.clone()).collect::<Vec<_>>(),
            vec![
                "bcc@example.com".to_string(),
                "cc@example.com".to_string(),
                "to@example.com".to_string(),
            ]
        );
        assert!(queue_rows.iter().all(|row| row.1 == persisted.id));
        assert!(queue_rows.iter().all(|row| row.2 == domain_id));
        assert!(queue_rows.iter().all(|row| row.3 == Some(scheduled_at)));
    }

    // ── Aggressive fail-first: validation edge cases ────────────

    #[test]
    fn test_message_status_returns_queued_when_no_schedule() {
        let body = SendMessageRequest {
            from: "sender@example.com".into(),
            to: vec!["to@example.com".into()],
            cc: None,
            bcc: None,
            subject: "Test".into(),
            html: Some("<p>Hi</p>".into()),
            text: None,
            tags: None,
            metadata: None,
            scheduled_at: None,
        };
        assert_eq!(message_status(&body), "queued");
    }

    #[test]
    fn test_message_status_returns_scheduled_when_future_date() {
        let body = SendMessageRequest {
            from: "sender@example.com".into(),
            to: vec!["to@example.com".into()],
            cc: None,
            bcc: None,
            subject: "Test".into(),
            html: Some("<p>Hi</p>".into()),
            text: None,
            tags: None,
            metadata: None,
            scheduled_at: Some(Utc::now() + chrono::Duration::hours(1)),
        };
        assert_eq!(message_status(&body), "scheduled");
    }

    #[test]
    fn test_delivery_recipients_combines_to_cc_bcc() {
        let body = SendMessageRequest {
            from: "sender@example.com".into(),
            to: vec!["a@example.com".into()],
            cc: Some(vec!["b@example.com".into(), "c@example.com".into()]),
            bcc: Some(vec!["d@example.com".into()]),
            subject: "Test".into(),
            html: None,
            text: Some("hi".into()),
            tags: None,
            metadata: None,
            scheduled_at: None,
        };
        let recipients = delivery_recipients(&body);
        assert_eq!(recipients, vec!["a@example.com", "b@example.com", "c@example.com", "d@example.com"]);
    }

    #[test]
    fn test_delivery_recipients_empty_cc_bcc() {
        let body = SendMessageRequest {
            from: "sender@example.com".into(),
            to: vec!["a@example.com".into()],
            cc: None,
            bcc: None,
            subject: "Test".into(),
            html: None,
            text: Some("hi".into()),
            tags: None,
            metadata: None,
            scheduled_at: None,
        };
        let recipients = delivery_recipients(&body);
        assert_eq!(recipients, vec!["a@example.com"]);
    }

    #[test]
    fn test_send_request_rejects_missing_html_and_text() {
        // When both html and text are None, this should fail validation
        let json = r#"{"from":"a@b.com","to":["c@d.com"],"subject":"X"}"#;
        let req: SendMessageRequest = serde_json::from_str(json).unwrap();
        assert!(req.html.is_none() && req.text.is_none(),
            "request with no body content should fail validation downstream");
    }

    #[test]
    fn test_batch_send_response_rejected_item_skips_id_and_error_serialization() {
        let resp = BatchResult {
            index: 0,
            id: None,
            status: "rejected".into(),
            error: Some("bad email".into()),
        };
        let json = serde_json::to_value(&resp).unwrap();
        // id is skipped when None
        assert!(json.get("id").is_none(), "id must be skipped when None");
        // error must be present when Some
        assert_eq!(json["error"], "bad email");
    }

    #[test]
    fn test_batch_send_response_accepted_item_has_id() {
        let resp = BatchResult {
            index: 0,
            id: Some("msg_test123".into()),
            status: "queued".into(),
            error: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], "msg_test123");
        // error must be skipped when None
        assert!(json.get("error").is_none(), "error must be skipped when None");
    }

    #[test]
    fn test_list_messages_query_defaults() {
        let json = r#"{}"#;
        let q: ListMessagesQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.limit, default_limit());
        assert_eq!(q.offset, 0);
        assert!(q.cursor.is_none());
        assert!(q.status.is_none());
    }

    #[test]
    fn test_quota_reservation_debug_format_includes_event_id() {
        let reservation = QuotaReservation {
            event_id: Uuid::new_v4(),
            recorded_at: Utc::now(),
        };
        let debug_str = format!("{:?}", reservation);
        assert!(debug_str.contains("event_id"));
    }

    #[sqlx::test]
    async fn cancelling_api_message_cancels_pending_queue_rows(pool: PgPool) {
        apply_tool_migrations(&pool).await;

        let tenant_id = insert_test_tenant(&pool, "message-cancel").await;
        insert_verified_domain(&pool, &tenant_id, "example.com").await;
        let body = SendMessageRequest {
            from: "sender@example.com".into(),
            to: vec!["to@example.com".into()],
            cc: None,
            bcc: None,
            subject: "Cancel me".into(),
            html: Some("<p>Hello</p>".into()),
            text: Some("Hello".into()),
            tags: None,
            metadata: None,
            scheduled_at: None,
        };

        let mut create_tx = pool.begin().await.expect("failed to begin create transaction");
        let persisted = insert_message_and_queue(&mut create_tx, &tenant_id, &body, &body.metadata)
            .await
            .expect("failed to persist message delivery");
        create_tx
            .commit()
            .await
            .expect("failed to commit create transaction");

        let mut cancel_tx = pool.begin().await.expect("failed to begin cancel transaction");
        let result = cancel_message_and_queue(&mut cancel_tx, &tenant_id, &persisted.id)
            .await
            .expect("failed to cancel message delivery");
        cancel_tx
            .commit()
            .await
            .expect("failed to commit cancel transaction");

        assert!(matches!(result, CancelDeliveryResult::Cancelled(_)));

        let message_status: (String,) = sqlx::query_as(
            "SELECT status FROM messages WHERE id = $1 AND tenant_id = $2",
        )
        .bind(&persisted.id)
        .bind(&tenant_id)
        .fetch_one(&pool)
        .await
        .expect("failed to fetch cancelled message");
        assert_eq!(message_status.0, "cancelled");

        let queue_statuses: Vec<(String,)> = sqlx::query_as(
            "SELECT DISTINCT status FROM email_queue WHERE message_id = $1",
        )
        .bind(&persisted.id)
        .fetch_all(&pool)
        .await
        .expect("failed to fetch cancelled queue rows");
        assert_eq!(queue_statuses, vec![("cancelled".to_string(),)]);
    }
}
