//! Message sending and management routes.

use super::helpers::{
    clamp_limit, compute_etag, decode_cursor, default_limit, encode_cursor, has_more,
    is_not_modified, pagination_meta,
};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use billing_service::types::MeterEventType;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use uuid::Uuid;

use crate::config::Config;
use crate::error::{success, ApiError, ApiResponse};
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::middleware::rate_limiter::INCR_EXPIRE_LUA;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(send_message).get(list_messages))
        .route("/batch", post(send_batch))
        .route("/:id", get(get_message))
        .route("/:id/cancel", post(cancel_message))
}

// ─── Constants ─────────────────────────────────────────────────

/// Allowlist of valid sort columns for the list_messages endpoint.
/// Prevents arbitrary sort column injection (HC-003).
static ALLOWED_SORT_COLUMNS: [&str; 4] = ["created_at", "updated_at", "status", "subject"];

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
const TENANT_MESSAGE_CIRCUIT_FAILURE_THRESHOLD: i64 = 5;
const TENANT_MESSAGE_CIRCUIT_FAILURE_WINDOW_SECONDS: i64 = 60;
const TENANT_MESSAGE_CIRCUIT_OPEN_SECONDS: i64 = 300;

/// Maximum subject length accepted by the send endpoints (RFC 5321 header
/// line limit).
const MAX_SUBJECT_CHARS: usize = 998;

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct ListMessagesQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    /// Cursor for cursor-based pagination — hex-encoded `created_at` + row id
    /// pair of the last item from the previous page. When provided, overrides
    /// `offset` (only valid with the default `created_at` sort).
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    /// Sort column — validated against [`ALLOWED_SORT_COLUMNS`] allowlist.
    /// Defaults to `created_at`; an explicit unknown column is rejected with 400.
    #[serde(default = "default_sort_column")]
    pub sort_by: String,
}

fn default_sort_column() -> String {
    "created_at".into()
}

// ─── Keyset cursor helpers ─────────────────────────────────────
//
// The list cursor encodes the `(created_at, id)` pair of the last row of the
// previous page. A timestamp alone skips or duplicates rows that share a
// `created_at` value (bulk inserts do this constantly): the tie-break
// `created_at = $ts AND id < $id` makes the ordering total.

/// Separator between the RFC3339 timestamp and the row id inside the
/// hex-encoded cursor payload (RFC3339 and UUID ids never contain it).
const KEYSET_CURSOR_SEP: char = '\n';

/// Encode a `(created_at, id)` keyset cursor as an opaque hex string.
fn encode_keyset_cursor(created_at: &DateTime<Utc>, id: &str) -> String {
    encode_cursor(&format!("{created_at}{KEYSET_CURSOR_SEP}{id}"))
}

/// Decode and validate a `(created_at, id)` keyset cursor. Malformed
/// encodings, unparsable timestamps, or ids that cannot name a row id
/// (empty, over 64 bytes, control characters) are client errors (400) —
/// they used to surface as database 500s.
fn decode_keyset_cursor(encoded: &str) -> Result<(DateTime<Utc>, String), ApiError> {
    let Some(decoded) = decode_cursor(encoded) else {
        return Err(ApiError::BadRequest(
            "invalid cursor: malformed encoding".into(),
        ));
    };
    let Some((timestamp, id)) = decoded.split_once(KEYSET_CURSOR_SEP) else {
        return Err(ApiError::BadRequest(
            "invalid cursor: must encode a created_at timestamp and row id".into(),
        ));
    };
    let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp)
        .map_err(|_| {
            ApiError::BadRequest(
                "invalid cursor: must be an encoded created_at timestamp".into(),
            )
        })?
        .with_timezone(&Utc);
    if id.is_empty() || id.len() > 64 || id.bytes().any(|b| b.is_ascii_control()) {
        return Err(ApiError::BadRequest("invalid cursor: malformed row id".into()));
    }
    Ok((timestamp, id.to_string()))
}

/// Validate the sort column against the allowlist.
/// Returns the validated column name, or a 400 error for unknown columns —
/// silently falling back to `created_at` masked client bugs and let callers
/// probe for injection-relevant error differences (HC-003 hardening).
fn validate_sort_column(column: &str) -> Result<String, ApiError> {
    if ALLOWED_SORT_COLUMNS.contains(&column) {
        Ok(column.to_string())
    } else {
        Err(ApiError::BadRequest(format!(
            "invalid sort_by '{column}': must be one of created_at, updated_at, status, subject"
        )))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
    // String (not &'static str) because the idempotent-duplicate re-fetch
    // path reconstructs this struct from a database row, whose status is
    // owned data ("queued" | "scheduled" | ...).
    status: String,
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

fn canonical_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

/// Extract the lowercased sender domain from a `from` address.
fn sender_domain(from: &str) -> Option<String> {
    from.rsplit_once('@')
        .map(|(_, domain)| domain.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|domain| !domain.is_empty())
}

/// Resolve the ready `domains.id` for a sender domain while holding a row lock
/// through queue insertion. This closes the check-then-enqueue race where a
/// domain could be disabled or deleted after request validation.
///
/// Production domains.id is UUID; unknown, incomplete, or transport-unready
/// sender domains yield `None` and are never handed to the worker unsigned.
async fn resolve_sender_domain_id(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    from: &str,
) -> Result<Option<String>, sqlx::Error> {
    let Some(sender_domain) = sender_domain(from) else {
        return Ok(None);
    };
    sqlx::query_scalar(
        "SELECT id::text FROM domains
                 WHERE tenant_id = $1 AND name = $2 AND status = 'verified'
                     AND dkim_enabled = true
                     AND dkim_selector IS NOT NULL AND dkim_public_key IS NOT NULL AND dkim_private_key IS NOT NULL
                           AND dkim_private_key LIKE 'dkim:v1:%'
                     AND ($3::boolean = false OR ses_verified = true)
                 LIMIT 1 FOR SHARE",
    )
    .bind(tenant_id)
    .bind(&sender_domain)
        .bind(Config::ses_transport_enabled())
        .fetch_optional(&mut **tx)
    .await
}

/// Resolve verified domain IDs for every unique sender domain in a batch with
/// one query per batch (instead of one query per message — the previous code
/// performed an N+1 lookup inside `insert_message_and_queue` for each item).
async fn resolve_batch_domain_ids(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    bodies: &[SendMessageRequest],
) -> Result<std::collections::HashMap<String, Option<String>>, sqlx::Error> {
    let mut unique: std::collections::HashSet<String> = std::collections::HashSet::new();
    for body in bodies {
        if let Some(domain) = sender_domain(&body.from) {
            unique.insert(domain);
        }
    }

    let mut map: std::collections::HashMap<String, Option<String>> =
        std::collections::HashMap::new();
    if unique.is_empty() {
        return Ok(map);
    }

    let domains: Vec<String> = unique.into_iter().collect();
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT name, id::text FROM domains
                 WHERE tenant_id = $1 AND name = ANY($2) AND status = 'verified'
                     AND dkim_enabled = true
                     AND dkim_selector IS NOT NULL AND dkim_public_key IS NOT NULL AND dkim_private_key IS NOT NULL
                       AND dkim_private_key LIKE 'dkim:v1:%'
                     AND ($3::boolean = false OR ses_verified = true)
                 FOR SHARE",
    )
    .bind(tenant_id)
    .bind(&domains)
        .bind(Config::ses_transport_enabled())
        .fetch_all(&mut **tx)
    .await?;

    for domain in domains {
        map.insert(domain, None);
    }
    for (name, id) in rows {
        map.insert(name, Some(id));
    }
    Ok(map)
}

async fn suppressed_recipients(
    db: &sqlx::PgPool,
    tenant_id: &str,
    body: &SendMessageRequest,
) -> Result<Vec<String>, ApiError> {
    let recipients: std::collections::HashSet<String> = delivery_recipients(body)
        .into_iter()
        .map(canonical_email)
        .collect();

    if recipients.is_empty() {
        return Ok(Vec::new());
    }

    let recipient_list: Vec<String> = recipients.into_iter().collect();
    let mut suppressed: Vec<String> = sqlx::query_scalar(
        "SELECT LOWER(email) FROM suppressions WHERE tenant_id = $1 AND LOWER(email) = ANY($2)",
    )
    .bind(tenant_id)
    .bind(&recipient_list)
    .fetch_all(db)
    .await
    .map_err(|error| {
        tracing::error!(error = %error, tenant_id = %tenant_id, "suppression lookup failed");
        ApiError::Internal("suppression lookup error".into())
    })?;

    suppressed.sort();
    suppressed.dedup();
    Ok(suppressed)
}

async fn insert_message_and_queue(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    body: &SendMessageRequest,
    metadata: &Option<serde_json::Value>,
    idempotency_key: Option<&str>,
    domain_id: Option<String>,
) -> Result<Option<PersistedMessage>, sqlx::Error> {
    let message_id = Uuid::new_v4().to_string();
    let created_at = Utc::now();
    let status = message_status(body);

    // Store the idempotency key in the dedicated `idempotency_key` column (not
    // just inside JSONB metadata) so the UNIQUE(tenant_id, idempotency_key)
    // index is actually enforced. `ON CONFLICT ... DO NOTHING` is the
    // race-condition safety net: if a concurrent request already inserted the
    // same (tenant_id, idempotency_key), this insert is a no-op and we return
    // `None` so the caller can re-fetch the existing message. NULL keys never
    // conflict (standard SQL NULL-distinct semantics), so batch sends and any
    // request without an idempotency key insert normally.
    let result = sqlx::query(
        "INSERT INTO messages (id, tenant_id, from_email, to_emails, cc_emails, bcc_emails,
         subject, html_body, text_body, status, tags, metadata, scheduled_at, created_at, idempotency_key)
         VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
         ON CONFLICT (tenant_id, idempotency_key) DO NOTHING",
    )
    .bind(&message_id)
    .bind(tenant_id)
    .bind(&body.from)
    .bind(serde_json::json!(body.to))
    .bind(
        body.cc
            .as_ref()
            .map(|recipients| serde_json::json!(recipients)),
    )
    .bind(
        body.bcc
            .as_ref()
            .map(|recipients| serde_json::json!(recipients)),
    )
    .bind(&body.subject)
    .bind(&body.html)
    .bind(&body.text)
    .bind(status)
    .bind(body.tags.as_ref().map(|tags| serde_json::json!(tags)))
    .bind(metadata)
    .bind(body.scheduled_at)
    .bind(created_at)
    .bind(idempotency_key)
    .execute(&mut **tx)
    .await?;

    // Conflict (concurrent duplicate idempotency key) → nothing inserted.
    if result.rows_affected() == 0 {
        return Ok(None);
    }

    // Batched email_queue inserts (previously one INSERT per delivery
    // recipient — up to MAX_RECIPIENTS sequential round-trips per message).
    // 13 bind parameters per row × 500 rows stays far below Postgres's
    // 65,535-parameter statement limit.
    const EMAIL_QUEUE_CHUNK_SIZE: usize = 500;
    for chunk in delivery_recipients(body).chunks(EMAIL_QUEUE_CHUNK_SIZE) {
        let mut query = String::from(
            "INSERT INTO email_queue (
                id, message_id, tenant_id, domain_id, from_address, to_addresses, subject,
                \"from\", \"to\", html, text, tags, metadata, scheduled_at, priority, status, created_at, updated_at
             ) VALUES ",
        );
        let mut param_idx = 1u32;
        for (i, _) in chunk.iter().enumerate() {
            if i > 0 {
                query.push_str(", ");
            }
            // Parameter layout per row — "from"/"to" reuse the same values
            // as from_address/to_addresses, and created_at doubles as
            // updated_at, exactly like the single-row form.
            let (i_id, i_msg, i_ten, i_dom, i_from, i_rcpt) = (
                param_idx,
                param_idx + 1,
                param_idx + 2,
                param_idx + 3,
                param_idx + 4,
                param_idx + 5,
            );
            let (i_subj, i_html, i_text, i_tags, i_meta, i_sched, i_created) = (
                param_idx + 6,
                param_idx + 7,
                param_idx + 8,
                param_idx + 9,
                param_idx + 10,
                param_idx + 11,
                param_idx + 12,
            );
            query.push_str(&format!(
                "(${i_id}::uuid, ${i_msg}::uuid, ${i_ten}, ${i_dom}::uuid, ${i_from}, ARRAY[${i_rcpt}], ${i_subj}, \
                 ${i_from}, ${i_rcpt}, ${i_html}, ${i_text}, ${i_tags}, ${i_meta}, ${i_sched}, 5, 'pending', \
                 ${i_created}, ${i_created}"
            ));
            param_idx += 13;
        }

        let mut q = sqlx::query(&query);
        for recipient in chunk {
            q = q
                .bind(Uuid::new_v4())
                .bind(&message_id)
                .bind(tenant_id)
                .bind(domain_id.clone())
                .bind(&body.from)
                .bind(recipient)
                .bind(&body.subject)
                .bind(&body.html)
                .bind(&body.text)
                .bind(body.tags.clone())
                .bind(metadata)
                .bind(body.scheduled_at)
                .bind(created_at);
        }
        q.execute(&mut **tx).await?;
    }

    Ok(Some(PersistedMessage {
        id: message_id,
        status: status.to_owned(),
        created_at,
    }))
}

async fn cancel_message_and_queue(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    message_id: &str,
) -> Result<CancelDeliveryResult, sqlx::Error> {
    let row: Option<(String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT status, created_at FROM messages WHERE id = $1::uuid AND tenant_id = $2 FOR UPDATE",
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
         WHERE message_id = $1::uuid AND tenant_id = $2 AND status NOT IN ('pending', 'cancelled')",
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
         WHERE message_id = $1::uuid AND tenant_id = $2 AND status = 'pending'",
    )
    .bind(message_id)
    .bind(tenant_id)
    .execute(&mut **tx)
    .await?;

    sqlx::query("UPDATE messages SET status = 'cancelled' WHERE id = $1::uuid AND tenant_id = $2")
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
) -> Result<(StatusCode, Json<ApiResponse<MessageResponse>>), ApiError> {
    require_scopes(&auth, &["messages:send"])?;
    validate_send(&body, &state.db, &auth.tenant_id).await?;

    // existing message instead of creating a duplicate.
    if let Some(idem_key) = headers.get("idempotency-key").and_then(|v| v.to_str().ok()) {
        if !idem_key.is_empty() && idem_key.len() <= 255 {
            let existing: Option<(String, String, DateTime<Utc>)> = sqlx::query_as(
                "SELECT id::text AS id, status, created_at FROM messages
                 WHERE tenant_id = $1 AND idempotency_key = $2
                 LIMIT 1",
            )
            .bind(&auth.tenant_id)
            .bind(idem_key)
            .fetch_optional(&state.db)
            .await?;

            if let Some((id, status, created_at)) = existing {
                return Ok((
                    StatusCode::OK,
                    Json(ApiResponse::success(MessageResponse {
                        id,
                        status,
                        created_at: created_at.to_rfc3339(),
                    })),
                ));
            }
        }
    }

    ensure_tenant_message_circuit_closed(&state, &auth.tenant_id).await?;

    // Merge idempotency key into metadata if present.
    let metadata = {
        let mut meta = body
            .metadata
            .clone()
            .unwrap_or_else(|| serde_json::json!({}));
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

    // Resolve the sender domain once (shared by validation and the insert).
    let domain_id = resolve_sender_domain_id(&mut tx, &auth.tenant_id, &body.from)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, tenant_id = %auth.tenant_id, "failed to resolve sender domain");
            ApiError::Internal("database error".into())
        })?
        .ok_or_else(|| {
            ApiError::Validation(vec![
                "sender domain is not ready for the configured delivery transport".into(),
            ])
        })?;

    // Admission-time quota gate: meter one unit per delivery recipient
    // (to + cc + bcc), not one per message — each recipient becomes its own
    // email_queue row that is delivered (and billed) separately. The Lua
    // check-and-increment in record_with_quota_check is atomic for the whole
    // quantity, so an insufficient quota rejects the entire request with 403
    // before anything is queued and without partially consuming quota (F1).
    let quota_reservation =
        reserve_email_quota(&state, &auth.tenant_id, quota_quantity_for_request(&body)).await?;

    // Idempotency key for the send — stored in the dedicated column so the
    // UNIQUE(tenant_id, idempotency_key) index is enforced inside the insert
    // (the pre-check above is only a fast path; it cannot close the
    // concurrent-duplicate race window on its own).
    let idempotency_key: Option<&str> = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|key| !key.is_empty() && key.len() <= 255);

    let persisted = match insert_message_and_queue(
        &mut tx,
        &auth.tenant_id,
        &body,
        &metadata,
        idempotency_key,
        Some(domain_id),
    )
    .await
    {
        Ok(Some(persisted)) => persisted,
        Ok(None) => {
            // Idempotent duplicate: a concurrent request won the insert race
            // (the header pre-check missed it). Re-fetch the existing message
            // so the response returns the original id instead of double-sending.
            let refetched: Result<Option<(String, String, DateTime<Utc>)>, sqlx::Error> =
                sqlx::query_as(
                    "SELECT id::text, status, created_at FROM messages
                     WHERE tenant_id = $1 AND idempotency_key = $2
                     LIMIT 1",
                )
                .bind(&auth.tenant_id)
                // A NULL key can never conflict (SQL NULL-distinct semantics),
                // so reaching this arm implies a key was provided.
                .bind(idempotency_key.unwrap_or_default())
                .fetch_optional(&mut *tx)
                .await;

            let (existing, refetch_error) = match refetched {
                Ok(existing) => (existing, None),
                Err(error) => (None, Some(error)),
            };
            let Some((id, status, created_at)) = existing else {
                let _ = tx.rollback().await;

                if let Err(rollback_error) =
                    rollback_email_quota(&state, &auth.tenant_id, &quota_reservation).await
                {
                    tracing::error!(
                        error = %rollback_error,
                        tenant_id = %auth.tenant_id,
                        event_id = %quota_reservation.event_id,
                        "failed to roll back reserved email quota after idempotent re-fetch failure"
                    );
                }

                record_tenant_message_circuit_failure(&state, &auth.tenant_id).await;
                tracing::error!(
                    error = ?refetch_error,
                    tenant_id = %auth.tenant_id,
                    "failed to re-fetch existing message for idempotent duplicate"
                );
                return Err(ApiError::Internal("database error".into()));
            };

            PersistedMessage {
                id,
                status,
                created_at,
            }
        }
        Err(error) => {
            let _ = tx.rollback().await;

            if let Err(rollback_error) =
                rollback_email_quota(&state, &auth.tenant_id, &quota_reservation).await
            {
                tracing::error!(
                    error = %rollback_error,
                    tenant_id = %auth.tenant_id,
                    event_id = %quota_reservation.event_id,
                    "failed to roll back reserved email quota after single-send insert failure"
                );
            }

            record_tenant_message_circuit_failure(&state, &auth.tenant_id).await;
            tracing::error!(error = %error, tenant_id = %auth.tenant_id, "failed to persist message delivery");
            return Err(ApiError::Internal("database error".into()));
        }
    };

    if let Err(error) = tx.commit().await {
        if let Err(rollback_error) =
            rollback_email_quota(&state, &auth.tenant_id, &quota_reservation).await
        {
            tracing::error!(
                error = %rollback_error,
                tenant_id = %auth.tenant_id,
                event_id = %quota_reservation.event_id,
                "failed to roll back reserved email quota after single-send commit failure"
            );
        }

        record_tenant_message_circuit_failure(&state, &auth.tenant_id).await;
        tracing::error!(error = %error, tenant_id = %auth.tenant_id, "failed to commit message delivery");
        return Err(ApiError::Internal("database error".into()));
    }

    record_tenant_message_circuit_success(&state, &auth.tenant_id).await;

    Ok((
        StatusCode::ACCEPTED,
        Json(ApiResponse::success(MessageResponse {
            id: persisted.id,
            status: persisted.status,
            created_at: persisted.created_at.to_rfc3339(),
        })),
    ))
}

async fn send_batch(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<BatchSendRequest>,
) -> Result<Json<ApiResponse<BatchSendResponse>>, ApiError> {
    require_scopes(&auth, &["messages:send"])?;

    if body.messages.len() > *MAX_BATCH_SIZE {
        return Err(ApiError::BadRequest(format!(
            "batch size {} exceeds maximum of {}",
            body.messages.len(),
            *MAX_BATCH_SIZE
        )));
    }

    // Same per-tenant delivery circuit as single sends: refuse the whole
    // batch while the tenant's circuit is open instead of queueing more
    // messages into an already-failing pipeline.
    ensure_tenant_message_circuit_closed(&state, &auth.tenant_id).await?;

    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut results = Vec::with_capacity(body.messages.len());
    let mut committed_quota_reservations: Vec<QuotaReservation> =
        Vec::with_capacity(body.messages.len());

    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!(error = %e, "failed to begin batch transaction");
        ApiError::Internal("database error".into())
    })?;

    // Resolve every unique sender domain once per batch instead of once per
    // message (removes the N+1 domain lookups from validation and inserts).
    let domain_ids = resolve_batch_domain_ids(&mut tx, &auth.tenant_id, &body.messages)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to resolve batch sender domains");
            ApiError::Internal("database error".into())
        })?;

    for (i, msg) in body.messages.iter().enumerate() {
        if let Err(e) =
            validate_send_with_domain_cache(msg, &state.db, &auth.tenant_id, Some(&domain_ids))
                .await
        {
            rejected += 1;
            results.push(BatchResult {
                index: i,
                id: None,
                status: "rejected".into(),
                error: Some(e.to_string()),
            });
            continue;
        }

        // Per-recipient metering, same as single sends: the reservation covers
        // every delivery recipient of this batch item in one atomic quantity
        // (F1). Insufficient quota rejects just this item — the reservation is
        // all-or-nothing, so no partial quota is consumed.
        let quota_reservation = match reserve_email_quota(
            &state,
            &auth.tenant_id,
            quota_quantity_for_request(msg),
        )
        .await
        {
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
            Err(err) => {
                // Quota infrastructure failure aborts the whole batch. The
                // still-open transaction is dropped (message inserts roll
                // back), but reservations for earlier items live OUTSIDE the
                // transaction and must be released explicitly — otherwise they
                // leak and permanently consume the tenant's quota.
                for reservation in &committed_quota_reservations {
                    if let Err(rollback_error) =
                        rollback_email_quota(&state, &auth.tenant_id, reservation).await
                    {
                        tracing::error!(
                            error = %rollback_error,
                            tenant_id = %auth.tenant_id,
                            event_id = %reservation.event_id,
                            "failed to roll back reserved email quota after batch quota-reservation failure"
                        );
                    }
                }
                let _ = tx.rollback().await;
                return Err(err);
            }
        };

        let domain_id = sender_domain(&msg.from)
            .and_then(|domain| domain_ids.get(&domain).cloned())
            .flatten();
        // Batch items carry no idempotency key (and a NULL key can never
        // conflict), so the ON CONFLICT DO NOTHING path cannot fire here —
        // Ok(None) is handled defensively below all the same.
        match insert_message_and_queue(
            &mut tx,
            &auth.tenant_id,
            msg,
            &msg.metadata,
            None,
            domain_id,
        )
        .await
        {
            Ok(Some(persisted)) => {
                accepted += 1;
                committed_quota_reservations.push(quota_reservation);
                results.push(BatchResult {
                    index: i,
                    id: Some(persisted.id),
                    status: persisted.status,
                    error: None,
                });
            }
            Ok(None) => {
                // Nothing was inserted: release the reserved quota (no message
                // will be delivered) and report the item as a duplicate.
                if let Err(rollback_error) =
                    rollback_email_quota(&state, &auth.tenant_id, &quota_reservation).await
                {
                    tracing::error!(
                        error = %rollback_error,
                        tenant_id = %auth.tenant_id,
                        event_id = %quota_reservation.event_id,
                        batch_index = i,
                        "failed to roll back reserved email quota after batch duplicate detection"
                    );
                }
                tracing::warn!(batch_index = i, "batch insert skipped idempotent duplicate");
                rejected += 1;
                results.push(BatchResult {
                    index: i,
                    id: None,
                    status: "rejected".into(),
                    error: Some("duplicate message".into()),
                });
            }
            Err(e) => {
                if let Err(rollback_error) =
                    rollback_email_quota(&state, &auth.tenant_id, &quota_reservation).await
                {
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
                if let Err(rollback_error) =
                    rollback_email_quota(&state, &auth.tenant_id, reservation).await
                {
                    tracing::error!(
                        error = %rollback_error,
                        tenant_id = %auth.tenant_id,
                        event_id = %reservation.event_id,
                        "failed to roll back reserved email quota after batch commit failure"
                    );
                }
            }

            tracing::error!(error = %error, "failed to commit batch transaction");
            record_tenant_message_circuit_failure(&state, &auth.tenant_id).await;
            return Err(ApiError::Internal("database error".into()));
        }

        // Mirror the single-send path: a committed delivery resets the
        // tenant's circuit failure counter.
        record_tenant_message_circuit_success(&state, &auth.tenant_id).await;
    }

    Ok(success(BatchSendResponse {
        accepted,
        rejected,
        results,
    }))
}

async fn list_messages(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: HeaderMap,
    Query(params): Query<ListMessagesQuery>,
) -> Result<Response, ApiError> {
    require_scopes(&auth, &["messages:read"])?;

    // Validate sort column against allowlist to prevent SQL injection (HC-003)
    let sort_column = validate_sort_column(&params.sort_by)?;
    // Cursor pagination is only well-defined for the default `created_at`
    // ordering — the cursor encodes a created_at timestamp, so honouring it
    // under another sort column would page incorrectly (and let callers mix
    // cursors across sorts). Reject the combination instead.
    if params.cursor.is_some() && sort_column != "created_at" {
        return Err(ApiError::BadRequest(
            "cursor pagination is only supported for sort_by=created_at".into(),
        ));
    }
    let limit = clamp_limit(params.limit, 100);

    // Cursor-based pagination: the cursor is a hex-encoded
    // `created_at\nid` pair. Both halves are validated BEFORE binding — a
    // decoded-but-bogus cursor used to reach the `::timestamp` cast and
    // surface as a database 500 instead of a client 400. The `id`
    // tie-break makes the ordering total so rows sharing a `created_at`
    // are neither skipped nor duplicated across pages.
    let cursor_value = match params.cursor.as_deref() {
        Some(encoded) => Some(decode_keyset_cursor(encoded)?),
        None => None,
    };

    let fetch_limit = limit + 1; // fetch one extra to detect has_more

    let rows = if let Some((ref cursor_ts, ref cursor_id)) = cursor_value {
        // Cursor-based: strictly-less tuple comparison (for created_at DESC,
        // id DESC ordering). The VALUE is cast once (`$k::uuid` /
        // `$k::timestamp`), never the indexed column.
        if let Some(ref status) = params.status {
            let query = format!(
                "SELECT id::text AS id, from_email, to_emails, subject, status, tags, metadata, scheduled_at, sent_at, created_at
                 FROM messages WHERE tenant_id = $1 AND status = $2
                   AND (created_at < $3::timestamp OR (created_at = $3::timestamp AND id < $4::uuid))
                 ORDER BY created_at DESC, id DESC LIMIT $5",
            );
            sqlx::query_as::<_, MessageRow>(&query)
                .bind(&auth.tenant_id)
                .bind(status)
                .bind(cursor_ts)
                .bind(cursor_id)
                .bind(fetch_limit)
                .fetch_all(&state.db)
                .await?
        } else {
            let query = format!(
                "SELECT id::text AS id, from_email, to_emails, subject, status, tags, metadata, scheduled_at, sent_at, created_at
                 FROM messages WHERE tenant_id = $1
                   AND (created_at < $2::timestamp OR (created_at = $2::timestamp AND id < $3::uuid))
                 ORDER BY created_at DESC, id DESC LIMIT $4",
            );
            sqlx::query_as::<_, MessageRow>(&query)
                .bind(&auth.tenant_id)
                .bind(cursor_ts)
                .bind(cursor_id)
                .bind(fetch_limit)
                .fetch_all(&state.db)
                .await?
        }
    } else {
        // Fallback to offset-based pagination for backward compatibility
        let offset = params.offset.clamp(0, 100_000);
        if let Some(ref status) = params.status {
            let query = format!(
                "SELECT id::text AS id, from_email, to_emails, subject, status, tags, metadata, scheduled_at, sent_at, created_at
                 FROM messages WHERE tenant_id = $1 AND status = $2 ORDER BY {} DESC, id DESC LIMIT $3 OFFSET $4",
                sort_column
            );
            sqlx::query_as::<_, MessageRow>(&query)
                .bind(&auth.tenant_id)
                .bind(status)
                .bind(fetch_limit)
                .bind(offset)
                .fetch_all(&state.db)
                .await?
        } else {
            let query = format!(
                "SELECT id::text AS id, from_email, to_emails, subject, status, tags, metadata, scheduled_at, sent_at, created_at
                 FROM messages WHERE tenant_id = $1 ORDER BY {} DESC, id DESC LIMIT $2 OFFSET $3",
                sort_column
            );
            sqlx::query_as::<_, MessageRow>(&query)
                .bind(&auth.tenant_id)
                .bind(fetch_limit)
                .bind(offset)
                .fetch_all(&state.db)
                .await?
        }
    };

    // Build the response rows and detect has_more
    let mut details: Vec<MessageDetail> = rows.into_iter().map(row_to_detail).collect();
    let more = has_more(&mut details, limit as usize);

    // Compute the next cursor from the last row. The (created_at, id) pair is
    // only a valid cursor for created_at ordering — other sort columns emit
    // no cursor and clients fall back to offset paging.
    let next_cursor = if sort_column == "created_at" {
        details.last().and_then(|r| {
            chrono::DateTime::parse_from_rfc3339(&r.created_at)
                .ok()
                .map(|ts| encode_keyset_cursor(&ts.with_timezone(&Utc), &r.id))
        })
    } else {
        None
    };
    let meta = pagination_meta(more, next_cursor);

    // Build the response body and compute ETag
    let body = serde_json::json!({
        "data": details,
        "error": null,
        "meta": meta,
    });
    let body_bytes = serde_json::to_vec(&body)?;
    let etag = compute_etag(&body_bytes);

    // Check If-None-Match for 304
    if is_not_modified(&headers, &etag) {
        return Ok(axum::response::Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header("ETag", &etag)
            .body(axum::body::Body::empty())
            .expect("invariant: Response builder with empty body should not fail"));
    }

    Ok(axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("ETag", &etag)
        .header("Cache-Control", "private, max-age=0, must-revalidate")
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(body_bytes))
        .expect("invariant: Response builder with valid body should not fail"))
}

async fn get_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<MessageDetail>>, ApiError> {
    require_scopes(&auth, &["messages:read"])?;

    let row = sqlx::query_as::<_, MessageRow>(
        "SELECT id::text AS id, from_email, to_emails, subject, status, tags, metadata, scheduled_at, sent_at, created_at
         FROM messages WHERE id = $1::uuid AND tenant_id = $2",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("message not found".into()))?;

    Ok(success(row_to_detail(row)))
}

async fn cancel_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<MessageResponse>>, ApiError> {
    require_scopes(&auth, &["messages:send"])?;

    let mut tx = state.db.begin().await.map_err(|error| {
        tracing::error!(error = %error, tenant_id = %auth.tenant_id, message_id = %id, "failed to begin message cancellation transaction");
        ApiError::Internal("database error".into())
    })?;

    let created_at = match cancel_message_and_queue(&mut tx, &auth.tenant_id, &id).await? {
        CancelDeliveryResult::Cancelled(created_at) => created_at,
        CancelDeliveryResult::NotFound | CancelDeliveryResult::NotCancellable => {
            let _ = tx.rollback().await;
            return Err(ApiError::Conflict(
                "message cannot be cancelled (already sent or not found)".into(),
            ));
        }
    };

    tx.commit().await.map_err(|error| {
        tracing::error!(error = %error, tenant_id = %auth.tenant_id, message_id = %id, "failed to commit message cancellation");
        ApiError::Internal("database error".into())
    })?;

    Ok(success(MessageResponse {
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
    db: &sqlx::PgPool,
    tenant_id: &str,
) -> Result<(), ApiError> {
    validate_send_with_domain_cache(body, db, tenant_id, None).await
}

/// Like [`validate_send`], but skips the per-message domain query when the
/// caller already resolved the batch's sender domains (see
/// [`resolve_batch_domain_ids`]).
async fn validate_send_with_domain_cache(
    body: &SendMessageRequest,
    db: &sqlx::PgPool,
    tenant_id: &str,
    domain_cache: Option<&std::collections::HashMap<String, Option<String>>>,
) -> Result<(), ApiError> {
    let mut errors = Vec::new();
    if body.from.is_empty() {
        errors.push("from is required".into());
    } else if !apexmail_lib::validation::is_valid_email(&body.from) {
        errors.push(format!("invalid sender email: {}", body.from));
    }
    // Header injection: CR/LF in the sender address or subject would let a
    // caller smuggle extra headers (e.g. Bcc) into the outgoing message.
    if body.from.contains('\r') || body.from.contains('\n') {
        errors.push("from must not contain line breaks".into());
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
    // CRLF in a subject breaks header folding and enables header injection.
    if body.subject.contains('\r') || body.subject.contains('\n') {
        errors.push("subject must not contain line breaks".into());
    }
    // RFC 5321 caps a header line at 998 characters — an over-long subject
    // would be folded or rejected downstream by the MTA.
    if body.subject.chars().count() > MAX_SUBJECT_CHARS {
        errors.push(format!(
            "subject must be {MAX_SUBJECT_CHARS} characters or fewer"
        ));
    }
    if body.html.is_none() && body.text.is_none() {
        errors.push("html or text body is required".into());
    }
    for email in &body.to {
        if !apexmail_lib::validation::is_valid_email(email) {
            errors.push(format!("invalid recipient email: {email}"));
        }
        // Header injection via recipients: a quoted-string local part could
        // historically smuggle CR/LF past the email regex — reject control
        // characters in every recipient, exactly like the subject check above.
        if email.contains('\r') || email.contains('\n') || email.contains('\0') {
            errors.push("recipient must not contain line breaks".into());
        }
    }
    // Validate CC recipients
    if let Some(ref cc) = body.cc {
        for email in cc {
            if !apexmail_lib::validation::is_valid_email(email) {
                errors.push(format!("invalid CC email: {email}"));
            }
            if email.contains('\r') || email.contains('\n') || email.contains('\0') {
                errors.push("cc recipient must not contain line breaks".into());
            }
        }
    }
    // Validate BCC recipients
    if let Some(ref bcc) = body.bcc {
        for email in bcc {
            if !apexmail_lib::validation::is_valid_email(email) {
                errors.push(format!("invalid BCC email: {email}"));
            }
            if email.contains('\r') || email.contains('\n') || email.contains('\0') {
                errors.push("bcc recipient must not contain line breaks".into());
            }
        }
    }

    // Extract domain from the "from" email.
    if !body.from.is_empty() {
        if let Some(domain) = sender_domain(&body.from) {
            let verified = match domain_cache {
                Some(cache) => cache.get(&domain).is_some_and(|id| id.is_some()),
                None => {
                    let exists: Option<String> = sqlx::query_scalar(
                        "SELECT id::text FROM domains
                                                 WHERE tenant_id = $1 AND name = $2 AND status = 'verified'
                                                     AND dkim_enabled = true
                                                     AND dkim_selector IS NOT NULL AND dkim_public_key IS NOT NULL AND dkim_private_key IS NOT NULL
                                                       AND dkim_private_key LIKE 'dkim:v1:%'
                                                     AND ($3::boolean = false OR ses_verified = true)
                         LIMIT 1",
                    )
                    .bind(tenant_id)
                    .bind(&domain)
                                        .bind(Config::ses_transport_enabled())
                    .fetch_optional(db)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "domain ownership check failed");
                        ApiError::Internal("domain verification error".into())
                    })?;
                    exists.is_some()
                }
            };

            if !verified {
                errors.push(format!(
                    "domain '{domain}' is not ready for the configured delivery transport"
                ));
            }
        }
    }

    if !errors.is_empty() {
        return Err(ApiError::Validation(errors));
    }

    let suppressed = suppressed_recipients(db, tenant_id, body).await?;
    if !suppressed.is_empty() {
        errors.extend(
            suppressed
                .into_iter()
                .map(|email| format!("recipient is suppressed: {email}")),
        );
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
    /// Number of metered units this reservation holds. Every delivery
    /// recipient (to + cc + bcc) becomes its own email_queue row that is
    /// delivered separately, so quota must be metered per recipient, not per
    /// message (F1).
    quantity: i64,
}

/// Metered quantity for a send request: the number of delivery recipients.
/// Each recipient is enqueued as a separate email_queue row, so this is the
/// number of sends the tenant will actually consume.
fn quota_quantity_for_request(body: &SendMessageRequest) -> i64 {
    delivery_recipients(body).len() as i64
}

async fn reserve_email_quota(
    state: &AppState,
    tenant_id: &str,
    quantity: i64,
) -> Result<QuotaReservation, ApiError> {
    let reservation = QuotaReservation {
        event_id: Uuid::new_v4(),
        recorded_at: Utc::now(),
        quantity,
    };

    let quota = billing_service::usage::record_with_quota_check(
        &state.db,
        &state.redis,
        tenant_id,
        MeterEventType::EmailsSent,
        quantity,
        Some(reservation.event_id),
        None,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, tenant_id = %tenant_id, "quota reservation failed");
        ApiError::ServiceUnavailable("billing quota enforcement is temporarily unavailable".into())
    })?;

    if !quota.allowed {
        return Err(ApiError::Forbidden(
                    "email quota exceeded: the plan volume and its overage allowance are exhausted — upgrade the plan or contact sales for a higher ceiling".into(),
                ));
    }

    Ok(reservation)
}

fn tenant_message_circuit_open_key(tenant_id: &str) -> String {
    format!("apexmail:tenant-circuit:messages:{tenant_id}:open")
}

fn tenant_message_circuit_failure_key(tenant_id: &str) -> String {
    format!("apexmail:tenant-circuit:messages:{tenant_id}:failures")
}

async fn ensure_tenant_message_circuit_closed(
    state: &AppState,
    tenant_id: &str,
) -> Result<(), ApiError> {
    let mut conn = match state.redis.get().await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(tenant_id = %tenant_id, error = %error, "tenant circuit Redis unavailable; allowing send");
            return Ok(());
        }
    };

    let open: Option<String> = deadpool_redis::redis::cmd("GET")
        .arg(tenant_message_circuit_open_key(tenant_id))
        .query_async(&mut *conn)
        .await
        .unwrap_or(None);

    if open.is_some() {
        return Err(ApiError::ServiceUnavailable(
            "tenant message delivery circuit is temporarily open".into(),
        ));
    }

    Ok(())
}

async fn record_tenant_message_circuit_failure(state: &AppState, tenant_id: &str) {
    let mut conn = match state.redis.get().await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(tenant_id = %tenant_id, error = %error, "tenant circuit failure not recorded");
            return;
        }
    };

    let failure_key = tenant_message_circuit_failure_key(tenant_id);
    let failures: i64 = match deadpool_redis::redis::Script::new(INCR_EXPIRE_LUA)
        .key(&failure_key)
        .arg(TENANT_MESSAGE_CIRCUIT_FAILURE_WINDOW_SECONDS)
        .invoke_async(&mut *conn)
        .await
    {
        Ok(failures) => failures,
        Err(error) => {
            tracing::warn!(tenant_id = %tenant_id, error = %error, "tenant circuit failure counter update failed");
            return;
        }
    };

    if failures >= TENANT_MESSAGE_CIRCUIT_FAILURE_THRESHOLD {
        let _: Result<(), _> = deadpool_redis::redis::cmd("SETEX")
            .arg(tenant_message_circuit_open_key(tenant_id))
            .arg(TENANT_MESSAGE_CIRCUIT_OPEN_SECONDS)
            .arg("1")
            .query_async(&mut *conn)
            .await;
        tracing::warn!(tenant_id = %tenant_id, failures, "tenant message delivery circuit opened");
    }
}

async fn record_tenant_message_circuit_success(state: &AppState, tenant_id: &str) {
    let mut conn = match state.redis.get().await {
        Ok(conn) => conn,
        Err(_) => return,
    };

    let _: Result<i64, _> = deadpool_redis::redis::cmd("DEL")
        .arg(tenant_message_circuit_failure_key(tenant_id))
        .query_async(&mut *conn)
        .await;
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
        reservation.quantity,
        reservation.event_id,
        reservation.recorded_at,
    )
    .await
    .map_err(|e| ApiError::ServiceUnavailable(format!("failed to roll back reserved quota: {e}")))
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
                    .map(|name| {
                        !name.ends_with("_down.sql") && !name.contains("performance_indexes")
                    })
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
            fs::write(temp_dir.join(file_name), normalized).unwrap_or_else(|error| {
                panic!("failed to write copied migration {:?}: {error}", path)
            });
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
        .bind(format!("test-{suffix}-{id}"))
        .execute(pool)
        .await
        .expect("failed to insert test tenant");
        id
    }

    async fn insert_verified_domain(pool: &PgPool, tenant_id: &str, domain: &str) -> String {
        // Prod domain ids are uuid; the send path casts domain_id::uuid, so
        // the test fixture must use uuid ids too.
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO domains (id, tenant_id, name, status, verified, dkim_enabled, ses_verified,
             dkim_selector, dkim_public_key, dkim_private_key)
             VALUES ($1, $2, $3, 'verified', true, true, true, 'test-selector', 'test-public-key', 'dkim:v1:test')",
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

    #[test]
    fn tenant_message_circuit_keys_are_tenant_scoped() {
        assert_eq!(
            tenant_message_circuit_open_key("tenant_a"),
            "apexmail:tenant-circuit:messages:tenant_a:open"
        );
        assert_eq!(
            tenant_message_circuit_failure_key("tenant_a"),
            "apexmail:tenant-circuit:messages:tenant_a:failures"
        );
        assert_ne!(
            tenant_message_circuit_open_key("tenant_a"),
            tenant_message_circuit_open_key("tenant_b")
        );
    }

    // Note:validate_send tests removed because the function is now async and
    // requires AppState + tenant_id. Integration tests should verify validation.

    #[test]
    fn test_batch_send_response_serialisation() {
        let resp = BatchSendResponse {
            accepted: 2,
            rejected: 1,
            results: vec![
                BatchResult {
                    index: 0,
                    id: Some("msg_test_id".into()),
                    status: "queued".into(),
                    error: None,
                },
                BatchResult {
                    index: 1,
                    id: None,
                    status: "rejected".into(),
                    error: Some("bad email".into()),
                },
            ],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["accepted"], 2);
    }

    #[tokio::test]
    async fn api_messages_enqueue_worker_rows_for_all_recipients() {
        let Some(pool) =
            crate::test_db::optional_pg_pool("api_messages_enqueue_worker_rows_for_all_recipients")
                .await
        else {
            return;
        };
        apply_tool_migrations(&pool).await;

        let tenant_id = insert_test_tenant(&pool, "message-queue").await;
        let domain_id = insert_verified_domain(&pool, &tenant_id, "example.com").await;

        // Postgres TIMESTAMPTZ keeps microsecond precision; an untruncated
        // Utc::now() carries nanoseconds that cannot survive the round-trip
        // and fail the equality assertions below on any sub-µs clock read
        // (this is the exact failure that stalled the deploy-host pipeline).
        let scheduled_at = chrono::DateTime::<chrono::Utc>::from_timestamp_micros(
            (Utc::now() + chrono::Duration::minutes(15)).timestamp_micros(),
        )
        .expect("timestamp_micros is always representable as a DateTime");
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

        let mut tx = pool
            .begin()
            .await
            .expect("failed to begin message transaction");
        let persisted = insert_message_and_queue(
            &mut tx,
            &tenant_id,
            &body,
            &body.metadata,
            None,
            Some(domain_id.clone()),
        )
        .await
        .expect("failed to persist message delivery")
        .expect("fresh insert without idempotency key must persist a message");
        tx.commit()
            .await
            .expect("failed to commit message transaction");

        let message_row: (String, Option<DateTime<Utc>>) = sqlx::query_as(
            "SELECT status, scheduled_at FROM messages WHERE id = $1::uuid AND tenant_id = $2",
        )
        .bind(&persisted.id)
        .bind(&tenant_id)
        .fetch_one(&pool)
        .await
        .expect("failed to fetch stored message");
        assert_eq!(message_row.0, "scheduled");
        assert_eq!(message_row.1, Some(scheduled_at));

        let queue_rows: Vec<(String, String, String, Option<DateTime<Utc>>)> = sqlx::query_as(
            r#"SELECT "to", message_id::text, domain_id, scheduled_at
             FROM email_queue WHERE message_id = $1::uuid ORDER BY "to""#,
        )
        .bind(&persisted.id)
        .fetch_all(&pool)
        .await
        .expect("failed to fetch queued email rows");

        assert_eq!(queue_rows.len(), 3);
        assert_eq!(
            queue_rows
                .iter()
                .map(|row| row.0.clone())
                .collect::<Vec<_>>(),
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

    #[tokio::test]
    async fn api_messages_validate_send_rejects_suppressed_recipients() {
        let Some(pool) = crate::test_db::optional_pg_pool(
            "api_messages_validate_send_rejects_suppressed_recipients",
        )
        .await
        else {
            return;
        };
        apply_tool_migrations(&pool).await;

        let tenant_id = insert_test_tenant(&pool, "message-suppression").await;
        let _domain_id = insert_verified_domain(&pool, &tenant_id, "example.com").await;

        sqlx::query(
            "INSERT INTO suppressions (id, tenant_id, email, reason, source, created_at)
             VALUES ($1, $2, $3, $4, $5, NOW())",
        )
        .bind(apexmail_lib::id::generate_id("sup", 22))
        .bind(&tenant_id)
        .bind("blocked@example.com")
        .bind("unsubscribe")
        .bind("test")
        .execute(&pool)
        .await
        .expect("failed to insert suppression record");

        let body = SendMessageRequest {
            from: "sender@example.com".into(),
            to: vec!["Blocked@Example.com".into(), "allowed@example.com".into()],
            cc: None,
            bcc: None,
            subject: "Respect suppressions".into(),
            html: Some("<p>Hello</p>".into()),
            text: Some("Hello".into()),
            tags: None,
            metadata: None,
            scheduled_at: None,
        };

        let error = validate_send(&body, &pool, &tenant_id)
            .await
            .expect_err("suppressed recipients should be rejected");

        match error {
            ApiError::Validation(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error.contains("blocked@example.com")));
            }
            other => panic!("expected validation error, got {other:?}"),
        }
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
        assert_eq!(
            recipients,
            vec![
                "a@example.com",
                "b@example.com",
                "c@example.com",
                "d@example.com"
            ]
        );
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
        assert!(
            req.html.is_none() && req.text.is_none(),
            "request with no body content should fail validation downstream"
        );
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
        assert!(
            json.get("error").is_none(),
            "error must be skipped when None"
        );
    }

    #[test]
    fn test_list_messages_query_defaults() {
        let json = r#"{}"#;
        let q: ListMessagesQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.limit, default_limit());
        assert_eq!(q.offset, 0);
        assert!(q.cursor.is_none());
        assert!(q.status.is_none());
        assert_eq!(q.sort_by, "created_at");
    }

    // ── Sort-column / cursor hardening (audit J) ─────────────────

    #[test]
    fn test_validate_sort_column_rejects_unknown_column() {
        // Allowed columns pass through verbatim
        for column in ALLOWED_SORT_COLUMNS {
            assert_eq!(
                validate_sort_column(column).expect("allowed column must validate"),
                column
            );
        }
        // Injection probes and unknown names are rejected with 400 material
        // (BadRequest), never silently coerced to the default column.
        for probe in [
            "created_at; DROP TABLE messages--",
            "created_at DESC",
            "1=1",
            "subject\x00",
            "nonexistent",
            "",
        ] {
            match validate_sort_column(probe) {
                Err(ApiError::BadRequest(_)) => {}
                other => panic!("expected BadRequest for sort_by {probe:?}, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn api_messages_validate_send_rejects_crlf_in_recipients() {
        let Some(pool) = crate::test_db::optional_pg_pool(
            "api_messages_validate_send_rejects_crlf_in_recipients",
        )
        .await
        else {
            return;
        };
        apply_tool_migrations(&pool).await;

        let tenant_id = insert_test_tenant(&pool, "message-crlf").await;
        let _domain_id = insert_verified_domain(&pool, &tenant_id, "example.com").await;

        // The quoted local part below is designed so a naive email validator
        // would accept it; CR/LF smuggling a Bcc header must be rejected.
        let body = SendMessageRequest {
            from: "sender@example.com".into(),
            to: vec![r#""x
Bcc: victim@example.com"@example.com"#
                .into()],
            cc: Some(vec!["good@example.com\r\nBcc: evil@example.com".into()]),
            bcc: Some(vec!["nul\0byte@example.com".into()]),
            subject: "CRLF smuggling".into(),
            html: Some("<p>Hello</p>".into()),
            text: None,
            tags: None,
            metadata: None,
            scheduled_at: None,
        };

        let error = validate_send(&body, &pool, &tenant_id)
            .await
            .expect_err("CRLF-bearing recipients must be rejected");

        match error {
            ApiError::Validation(errors) => {
                assert!(
                    errors.iter().any(|e| e.contains("line breaks")),
                    "expected line-break rejection, got {errors:?}"
                );
            }
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn test_quota_reservation_debug_format_includes_event_id() {
        let reservation = QuotaReservation {
            event_id: Uuid::new_v4(),
            recorded_at: Utc::now(),
            quantity: 3,
        };
        let debug_str = format!("{:?}", reservation);
        assert!(debug_str.contains("event_id"));
    }

    // ── Per-recipient quota metering (F1) ───────────────────────

    #[test]
    fn test_quota_quantity_counts_all_delivery_recipients() {
        // to + cc + bcc each produce one email_queue row, so the metered
        // quantity must be the combined recipient count, not 1.
        let body = SendMessageRequest {
            from: "sender@example.com".into(),
            to: vec!["a@example.com".into(), "b@example.com".into()],
            cc: Some(vec!["c@example.com".into()]),
            bcc: Some(vec!["d@example.com".into(), "e@example.com".into()]),
            subject: "Test".into(),
            html: None,
            text: Some("hi".into()),
            tags: None,
            metadata: None,
            scheduled_at: None,
        };
        assert_eq!(quota_quantity_for_request(&body), 5);
    }

    #[test]
    fn test_quota_quantity_minimum_is_one_for_valid_request() {
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
        // A validated request always has at least one `to` recipient, so the
        // metered quantity is never zero (record_with_quota_check rejects
        // quantity <= 0 with InvalidQuantity).
        assert_eq!(quota_quantity_for_request(&body), 1);
    }

    #[test]
    fn test_quota_quantity_matches_enqueued_queue_rows() {
        // The quantity must equal the number of email_queue rows
        // insert_message_and_queue creates for the same request.
        let body = SendMessageRequest {
            from: "sender@example.com".into(),
            to: vec!["to@example.com".into()],
            cc: Some(vec!["cc@example.com".into()]),
            bcc: Some(vec!["bcc@example.com".into()]),
            subject: "Test".into(),
            html: None,
            text: Some("hi".into()),
            tags: None,
            metadata: None,
            scheduled_at: None,
        };
        assert_eq!(
            quota_quantity_for_request(&body) as usize,
            delivery_recipients(&body).len()
        );
    }

    #[tokio::test]
    async fn cancelling_api_message_cancels_pending_queue_rows() {
        let Some(pool) =
            crate::test_db::optional_pg_pool("cancelling_api_message_cancels_pending_queue_rows")
                .await
        else {
            return;
        };
        apply_tool_migrations(&pool).await;

        let tenant_id = insert_test_tenant(&pool, "message-cancel").await;
        let domain_id = insert_verified_domain(&pool, &tenant_id, "example.com").await;
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

        let mut create_tx = pool
            .begin()
            .await
            .expect("failed to begin create transaction");
        let persisted = insert_message_and_queue(
            &mut create_tx,
            &tenant_id,
            &body,
            &body.metadata,
            None,
            Some(domain_id.clone()),
        )
        .await
        .expect("failed to persist message delivery")
        .expect("fresh insert without idempotency key must persist a message");
        create_tx
            .commit()
            .await
            .expect("failed to commit create transaction");

        let mut cancel_tx = pool
            .begin()
            .await
            .expect("failed to begin cancel transaction");
        let result = cancel_message_and_queue(&mut cancel_tx, &tenant_id, &persisted.id)
            .await
            .expect("failed to cancel message delivery");
        cancel_tx
            .commit()
            .await
            .expect("failed to commit cancel transaction");

        assert!(matches!(result, CancelDeliveryResult::Cancelled(_)));

        let message_status: (String,) =
            sqlx::query_as("SELECT status FROM messages WHERE id = $1::uuid AND tenant_id = $2")
                .bind(&persisted.id)
                .bind(&tenant_id)
                .fetch_one(&pool)
                .await
                .expect("failed to fetch cancelled message");
        assert_eq!(message_status.0, "cancelled");

        let queue_statuses: Vec<(String,)> =
            sqlx::query_as("SELECT DISTINCT status FROM email_queue WHERE message_id = $1::uuid")
                .bind(&persisted.id)
                .fetch_all(&pool)
                .await
                .expect("failed to fetch cancelled queue rows");
        assert_eq!(queue_statuses, vec![("cancelled".to_string(),)]);
    }
}
