//! Message sending and management routes.

use super::helpers::{
    clamp_limit, compute_etag, decode_cursor, default_limit, encode_cursor, has_more,
    is_not_modified, pagination_meta,
};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use billing_service::types::MeterEventType;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;
use uuid::Uuid;

use crate::config::Config;
use crate::error::{success, ApiError, ApiResponse, ErrorBody, ErrorDetail};
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::middleware::idempotency::principal_binding;
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

/// Maximum serialized size of caller metadata accepted by the send
/// endpoints (F44 — bounded object-shaped customer metadata).
const MAX_METADATA_BYTES: usize = 16 * 1024;

/// Maximum number of keys in the caller metadata object (F44).
const MAX_METADATA_KEYS: usize = 64;

/// Metadata keys owned by the server's queue machinery. A caller who sets
/// any of them could otherwise forge operational queue state — most
/// dangerously `pending_recipients`, which the worker trusts over the
/// validated envelope recipients (F45).
const RESERVED_METADATA_KEYS: [&str; 4] = [
    "pending_recipients",
    "lease_token",
    "possibly_sent",
    "requeue_reason",
];

/// Header names the caller cannot set through the free-form `headers`
/// field. They are either derived from validated fields (From/To/Cc/Subject/
/// Message-ID), filtered by the worker, or owned by the platform. Mirrors
/// the worker's PROTECTED_HEADERS set plus the dedicated `reply_to` field.
const PROTECTED_CUSTOM_HEADERS: [&str; 26] = [
    "from",
    "to",
    "cc",
    "bcc",
    "subject",
    "date",
    "message-id",
    "dkim-signature",
    "arc-seal",
    "arc-message-signature",
    "arc-authentication-results",
    "return-path",
    "received",
    "received-spf",
    "authentication-results",
    "x-apexmail-message-id",
    "x-apexmail-tenant-id",
    "x-apexmail-campaign-id",
    "x-originating-ip",
    "x-mailer",
    "mime-version",
    "content-type",
    "content-transfer-encoding",
    "reply-to",
    "sender",
    "errors-to",
];

/// Maximum decoded size of a single attachment (F48).
const MAX_ATTACHMENT_BYTES: usize = 10 * 1024 * 1024;

/// Maximum aggregate decoded attachment bytes per message (F48).
const MAX_TOTAL_ATTACHMENT_BYTES: usize = 25 * 1024 * 1024;

/// Maximum number of attachments per message (F48).
const MAX_ATTACHMENTS: usize = 50;

/// email_queue priority bounds (1 = highest urgency, 10 = lowest). The
/// default row priority stays 5 (F48).
const QUEUE_PRIORITY_MIN: i32 = 1;
const QUEUE_PRIORITY_MAX: i32 = 10;
const QUEUE_PRIORITY_DEFAULT: i32 = 5;

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
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
    // ── F48: the persistence/queue/transport stack supports these
    // end-to-end, so they are accepted and honoured.
    /// Optional Reply-To header (stored on the message + queue rows and set
    /// on the outgoing MIME).
    #[serde(default)]
    pub reply_to: Option<String>,
    /// Free-form custom headers (object of header name → string value).
    /// Protected header names are rejected with 422.
    #[serde(default)]
    pub headers: Option<serde_json::Value>,
    /// Attachments: `{filename, content (base64), contentType}`.
    #[serde(default)]
    pub attachments: Option<Vec<SendAttachment>>,
    /// Queue priority (1–10, default 5) — orders worker claims.
    #[serde(default)]
    pub priority: Option<i32>,
    // ── F48: advertised by the SDK but NOT implemented anywhere in the
    // persistence/queue/transport stack. Accepted here ONLY so they can be
    // rejected with an explicit 422 naming the field — never silently
    // discarded.
    #[serde(default)]
    pub template_id: Option<String>,
    #[serde(default)]
    pub template_data: Option<serde_json::Value>,
}

/// One attachment on a send request (F48). `content` is base64-encoded;
/// the camelCase `contentType` matches the queue/worker storage shape.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SendAttachment {
    pub filename: String,
    pub content: String,
    #[serde(rename = "contentType", alias = "content_type")]
    pub content_type: String,
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
            ApiError::BadRequest("invalid cursor: must be an encoded created_at timestamp".into())
        })?
        .with_timezone(&Utc);
    if id.is_empty() || id.len() > 64 || id.bytes().any(|b| b.is_ascii_control()) {
        return Err(ApiError::BadRequest(
            "invalid cursor: malformed row id".into(),
        ));
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

#[derive(Debug, Deserialize, Serialize)]
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
    /// Terminal parent state — e.g. already cancelled.
    NotCancellable,
    /// F24: the irreversible dispatch boundary was crossed — at least one
    /// recipient row has been claimed by a worker (or already delivered),
    /// so cancellation is explicitly TOO LATE rather than silently racing
    /// the worker.
    TooLate,
}

/// F24: cancel a message's remaining deliveries.
///
/// Cancellation protocol (shared lock order with the worker's claim):
///
/// 1. Lock EVERY queue row of the message first (`FOR UPDATE`), in the same
///    order the worker's claim locks them (`email_queue` before `messages`).
///    The worker's `FETCH_JOBS_SQL` claims rows with
///    `FOR UPDATE SKIP LOCKED` and only touches `email_queue`; its
///    post-send bookkeeping updates `email_queue` before `messages`. Taking
///    the queue rows first here keeps both sides on one lock order.
/// 2. Lock the parent `messages` row and re-read its status.
/// 3. Decide under the locks: any queue row that is not `pending` (and not
///    already `cancelled`) means dispatch has started — TooLate.
/// 4. Verify AFFECTED COUNTS on both updates: if the number of rows flipped
///    to `cancelled` differs from the pending count observed under the
///    lock, the decision was raced — TooLate, transaction rolled back by
///    the caller.
///
/// The irreversible dispatch boundary is the worker's CLAIM: once a queue
/// row leaves `pending` (status `processing`), that recipient's copy is
/// beyond cancellation. Rows still `pending` are cancelled atomically with
/// the parent transition.
async fn cancel_message_and_queue(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    message_id: &str,
) -> Result<CancelDeliveryResult, sqlx::Error> {
    // 1. Lock every delivery row of the message (queue rows before the
    //    parent — same order as the worker).
    let queue_rows: Vec<String> = sqlx::query_scalar(
        "SELECT status FROM email_queue
         WHERE message_id = $1::uuid AND tenant_id = $2
         ORDER BY id
         FOR UPDATE",
    )
    .bind(message_id)
    .bind(tenant_id)
    .fetch_all(&mut **tx)
    .await?;

    // 2. Lock the parent row.
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

    if !matches!(status.as_str(), "queued" | "scheduled" | "processing") {
        return Ok(CancelDeliveryResult::NotCancellable);
    }

    // 3. Decide under the locks: the dispatch boundary is the worker claim.
    let pending = queue_rows
        .iter()
        .filter(|s| s.as_str() == "pending")
        .count();
    let dispatched = queue_rows
        .iter()
        .filter(|s| !matches!(s.as_str(), "pending" | "cancelled"))
        .count();
    if dispatched > 0 {
        return Ok(CancelDeliveryResult::TooLate);
    }
    // A parent already in `processing` whose rows were all re-released to
    // `pending` is still claimable — but conservatively treat a processing
    // parent with zero pending rows as too late (nothing left to cancel).
    if pending == 0 {
        return Ok(CancelDeliveryResult::TooLate);
    }

    // 4. Flip the pending rows, VERIFYING the affected count matches the
    // count observed under the lock.
    let cancelled_rows = sqlx::query(
        "UPDATE email_queue
         SET status = 'cancelled', locked_until = NULL, updated_at = NOW()
         WHERE message_id = $1::uuid AND tenant_id = $2 AND status = 'pending'",
    )
    .bind(message_id)
    .bind(tenant_id)
    .execute(&mut **tx)
    .await?;
    if cancelled_rows.rows_affected() as usize != pending {
        tracing::warn!(
            message_id,
            expected = pending,
            affected = cancelled_rows.rows_affected(),
            "cancellation raced a worker claim — treating as too late"
        );
        return Ok(CancelDeliveryResult::TooLate);
    }

    let parent_updated = sqlx::query(
        "UPDATE messages SET status = 'cancelled', updated_at = NOW()
         WHERE id = $1::uuid AND tenant_id = $2
           AND status IN ('queued', 'scheduled', 'processing')",
    )
    .bind(message_id)
    .bind(tenant_id)
    .execute(&mut **tx)
    .await?;
    if parent_updated.rows_affected() != 1 {
        return Ok(CancelDeliveryResult::NotCancellable);
    }

    Ok(CancelDeliveryResult::Cancelled(created_at))
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

// ─── F48: honest unsupported-option contract ───────────────────

/// 422 response for send-option contract violations (F44/F45/F48). Uses the
/// exact JSON error shape `ApiError::Validation` renders (code/message/
/// details envelope) but with the 422 status the finding requires.
fn unprocessable_send_options(details: Vec<String>) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(ErrorBody {
            data: None,
            error: Some(ErrorDetail {
                code: "VALIDATION_ERROR".to_string(),
                message: "request fields are not supported by this endpoint".to_string(),
                details: Some(details),
            }),
            meta: None,
        }),
    )
        .into_response()
}

/// F44/F45: validate the caller's `metadata` and return the sanitized
/// customer object.
///
/// * `None` / JSON `null` → `None` (missing).
/// * Anything but a bounded JSON object → 422 (a scalar/array poisons the
///   worker's `jsonb_set` queue-state merges — SQLSTATE 22023 — and could
///   not carry server-written operational keys anyway).
/// * Server-reserved operational keys (`pending_recipients`, `lease_token`,
///   ...) → 422: those fields are exclusively server-written (F45); a
///   caller-supplied value could override the validated recipient set.
fn sanitize_customer_metadata(
    metadata: &Option<serde_json::Value>,
) -> Result<Option<serde_json::Value>, Vec<String>> {
    let Some(value) = metadata else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let Some(map) = value.as_object() else {
        return Err(vec![format!(
            "metadata must be a JSON object (received {}); scalar or array metadata is rejected",
            type_name_of(value)
        )]);
    };
    if map.is_empty() {
        return Ok(None);
    }
    let mut errors = Vec::new();
    if map.len() > MAX_METADATA_KEYS {
        errors.push(format!(
            "metadata must contain at most {MAX_METADATA_KEYS} keys (received {})",
            map.len()
        ));
    }
    for key in RESERVED_METADATA_KEYS {
        if map.contains_key(key) {
            errors.push(format!(
                "metadata field '{key}' is reserved for queue state and cannot be set by clients"
            ));
        }
    }
    let serialized = serde_json::to_vec(value).unwrap_or_default();
    if serialized.len() > MAX_METADATA_BYTES {
        errors.push(format!(
            "metadata exceeds the maximum serialized size of {MAX_METADATA_BYTES} bytes"
        ));
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    // Return a plain clone: from here on the value is known-object customer
    // data, never merged with server operational state.
    Ok(Some(value.clone()))
}

fn type_name_of(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

/// F48: validate the F48 send options (`reply_to`, `headers`,
/// `attachments`, `priority`) and explicitly reject the advertised-but-
/// unsupported `template_id` / `template_data` fields. Returns per-field
/// error strings for the 422 body.
fn validate_send_options(body: &SendMessageRequest) -> Vec<String> {
    let mut errors = Vec::new();

    if let Some(template_id) = body.template_id.as_deref() {
        if !template_id.trim().is_empty() {
            errors.push(
                "field 'template_id' is not supported by this endpoint: template-based sending is not implemented; render the template and send the result explicitly"
                    .to_string(),
            );
        }
    }
    if let Some(template_data) = body.template_data.as_ref() {
        if !template_data.is_null() {
            errors.push(
                "field 'template_data' is not supported by this endpoint: template-based sending is not implemented; render the template and send the result explicitly"
                    .to_string(),
            );
        }
    }

    if let Some(reply_to) = body.reply_to.as_deref() {
        if !reply_to.is_empty() && !apexmail_lib::validation::is_valid_email(reply_to) {
            errors.push(format!("invalid reply_to email: {reply_to}"));
        }
        if reply_to.contains('\r') || reply_to.contains('\n') {
            errors.push("reply_to must not contain line breaks".into());
        }
    }

    if let Some(headers) = body.headers.as_ref() {
        match headers.as_object() {
            None => {
                errors.push(
                    "field 'headers' must be an object of header name to string value".to_string(),
                );
            }
            Some(map) => {
                for (name, value) in map {
                    let lower = name.to_lowercase();
                    if PROTECTED_CUSTOM_HEADERS.contains(&lower.as_str()) {
                        if lower == "reply-to" {
                            errors.push(format!(
                                "header '{name}' is protected: use the reply_to field instead"
                            ));
                        } else {
                            errors.push(format!(
                                "header '{name}' is protected and cannot be set by clients"
                            ));
                        }
                        continue;
                    }
                    if name.is_empty()
                        || name.len() > 998
                        || name
                            .bytes()
                            .any(|b| b.is_ascii_control() || b == b' ' || b == b':')
                    {
                        errors.push(format!("invalid custom header name: '{name}'"));
                    }
                    let Some(value) = value.as_str() else {
                        errors.push(format!("custom header '{name}' must have a string value"));
                        continue;
                    };
                    if value.contains('\r') || value.contains('\n') || value.contains('\0') {
                        errors.push(format!(
                            "custom header '{name}' must not contain line breaks"
                        ));
                    }
                }
            }
        }
    }

    if let Some(priority) = body.priority {
        if !(QUEUE_PRIORITY_MIN..=QUEUE_PRIORITY_MAX).contains(&priority) {
            errors.push(format!(
                "priority must be between {QUEUE_PRIORITY_MIN} and {QUEUE_PRIORITY_MAX}"
            ));
        }
    }

    if let Some(attachments) = body.attachments.as_ref() {
        if attachments.len() > MAX_ATTACHMENTS {
            errors.push(format!(
                "at most {MAX_ATTACHMENTS} attachments are allowed per message (received {})",
                attachments.len()
            ));
        }
        let mut total = 0usize;
        for (i, attachment) in attachments.iter().enumerate() {
            if attachment.filename.is_empty()
                || attachment.filename.len() > 255
                || attachment.filename.contains('\r')
                || attachment.filename.contains('\n')
                || attachment.filename.contains('\0')
            {
                errors.push(format!(
                    "attachments[{i}].filename must be 1–255 characters without line breaks"
                ));
            }
            if attachment.content_type.is_empty()
                || attachment.content_type.contains('\r')
                || attachment.content_type.contains('\n')
            {
                errors.push(format!(
                    "attachments[{i}].contentType must be a non-empty MIME type without line breaks"
                ));
            }
            use base64::Engine;
            match base64::engine::general_purpose::STANDARD.decode(&attachment.content) {
                Ok(decoded) => {
                    if decoded.len() > MAX_ATTACHMENT_BYTES {
                        errors.push(format!(
                            "attachments[{i}] exceeds the maximum decoded size of {MAX_ATTACHMENT_BYTES} bytes"
                        ));
                    }
                    total = total.saturating_add(decoded.len());
                }
                Err(_) => {
                    errors.push(format!("attachments[{i}].content is not valid base64"));
                }
            }
        }
        if total > MAX_TOTAL_ATTACHMENT_BYTES {
            errors.push(format!(
                "attachments exceed the maximum total decoded size of {MAX_TOTAL_ATTACHMENT_BYTES} bytes"
            ));
        }
    }

    errors
}

/// F48: queue priority for the insert (validated beforehand).
fn queue_priority_of(body: &SendMessageRequest) -> i32 {
    body.priority
        .filter(|p| (QUEUE_PRIORITY_MIN..=QUEUE_PRIORITY_MAX).contains(p))
        .unwrap_or(QUEUE_PRIORITY_DEFAULT)
}

/// F26: the MIME header object stored on every email_queue copy. The
/// original To/Cc header values are stored SEPARATELY from the envelope
/// destination (`"to"`/`to_addresses`), so each per-recipient copy can show
/// the full visible recipient list while delivering to exactly one envelope
/// recipient. Bcc is intentionally absent — it exists only in the delivery
/// data (the per-recipient queue rows), never in a visible header. Custom
/// caller headers ride along under `custom`, and `reply_to` gets its own
/// key (F48).
fn mime_headers_for(body: &SendMessageRequest) -> Result<serde_json::Value, Vec<String>> {
    let mut map = serde_json::Map::new();
    map.insert("to".into(), serde_json::json!(body.to.join(", ")));
    if let Some(cc) = body.cc.as_ref().filter(|cc| !cc.is_empty()) {
        map.insert("cc".into(), serde_json::json!(cc.join(", ")));
    }
    if let Some(reply_to) = body.reply_to.as_ref().filter(|r| !r.is_empty()) {
        map.insert("reply_to".into(), serde_json::json!(reply_to));
    }
    if let Some(headers) = body.headers.as_ref().and_then(|h| h.as_object()) {
        if !headers.is_empty() {
            map.insert("custom".into(), serde_json::Value::Object(headers.clone()));
        }
    }
    Ok(serde_json::Value::Object(map))
}

/// F48: attachments in the queue/worker storage shape (filename / content
/// base64 / contentType).
fn queue_attachments_of(body: &SendMessageRequest) -> Option<serde_json::Value> {
    body.attachments
        .as_ref()
        .filter(|a| !a.is_empty())
        .map(|attachments| serde_json::to_value(attachments).unwrap_or(serde_json::json!([])))
}

// ─── F19/F20: durable idempotency ledger ───────────────────────

/// Route identity stored in the ledger (bound to the key, F19).
const SEND_ROUTE: &str = "/v1/messages";
const BATCH_ROUTE: &str = "/v1/messages/batch";

/// Ledger rows stuck in `in_flight` for this long are considered abandoned
/// (crashed request) and may be taken over by a retry (F21).
const LEDGER_STALE_AFTER_SECONDS: i64 = 600;

/// Canonical SHA-256 (hex) of a canonicalized send payload. Field order
/// follows the struct declaration, so the hash is stable for identical
/// requests and distinguishes every semantic difference (F19).
fn canonical_send_hash<T: Serialize>(payload: &T) -> String {
    let bytes = serde_json::to_vec(payload).unwrap_or_default();
    hex::encode(Sha256::digest(&bytes))
}

/// Result of consulting the durable idempotency ledger.
#[derive(Debug)]
enum LedgerReplay {
    /// The key was used with a different method/route/principal/payload —
    /// reject with 409 (F19).
    Conflict(&'static str),
    /// A completed record exists — replay its stored response (F20).
    Complete {
        response_status: i64,
        response_body: String,
    },
    /// Another live request owns the key right now (F21).
    InFlight,
}

struct LedgerRow {
    request_method: String,
    request_route: String,
    payload_hash: String,
    principal_id: String,
    status: String,
    response_status: Option<i64>,
    response_body: Option<String>,
}

async fn fetch_ledger_row(
    executor: impl sqlx::PgExecutor<'_>,
    tenant_id: &str,
    key: &str,
) -> Result<Option<LedgerRow>, sqlx::Error> {
    let row: Option<(
        String,
        String,
        String,
        String,
        String,
        Option<i64>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT request_method, request_route, payload_hash, principal_id, status,
                    response_status, response_body
             FROM idempotency_records
             WHERE tenant_id = $1 AND idempotency_key = $2",
    )
    .bind(tenant_id)
    .bind(key)
    .fetch_optional(executor)
    .await?;
    Ok(row.map(
        |(
            request_method,
            request_route,
            payload_hash,
            principal_id,
            status,
            response_status,
            response_body,
        )| {
            LedgerRow {
                request_method,
                request_route,
                payload_hash,
                principal_id,
                status,
                response_status,
                response_body,
            }
        },
    ))
}

/// Classify an existing ledger row against the incoming request identity.
fn classify_ledger_row(
    row: &LedgerRow,
    method: &str,
    route: &str,
    payload_hash: &str,
    principal_id: &str,
) -> LedgerReplay {
    if !row.request_method.eq_ignore_ascii_case(method) || row.request_route != route {
        return LedgerReplay::Conflict("idempotency-key was already used on a different endpoint");
    }
    if row.principal_id != principal_id {
        return LedgerReplay::Conflict(
            "idempotency-key was created by a different authenticated principal",
        );
    }
    if row.payload_hash != payload_hash {
        return LedgerReplay::Conflict(
            "idempotency-key was already used with a different request body",
        );
    }
    match row.status.as_str() {
        "complete" => LedgerReplay::Complete {
            response_status: row.response_status.unwrap_or(202),
            response_body: row.response_body.clone().unwrap_or_default(),
        },
        _ => LedgerReplay::InFlight,
    }
}

/// F19/F20 fast path: consult the durable ledger BEFORE executing a send.
/// `Ok(None)` → no record, proceed. `Ok(Some(replay))` → act on it.
async fn ledger_preflight(
    db: &sqlx::PgPool,
    tenant_id: &str,
    key: &str,
    method: &str,
    route: &str,
    payload_hash: &str,
    principal_id: &str,
) -> Result<Option<LedgerReplay>, sqlx::Error> {
    let Some(row) = fetch_ledger_row(db, tenant_id, key).await? else {
        return Ok(None);
    };
    Ok(Some(classify_ledger_row(
        &row,
        method,
        route,
        payload_hash,
        principal_id,
    )))
}

/// F20/F21: open the durable ledger record for a send inside the request's
/// own transaction, so the ledger row, the message row, and every queue row
/// commit together.
///
/// * `Ok(true)` — this request created (and owns) the record.
/// * `Ok(false)` — a completed record already exists; the caller must
///   return the stored response instead of executing.
/// * `Err(LedgerReplay::Conflict(_))` — conflicting reuse.
/// * `Err(LedgerReplay::InFlight)` — a live creator still owns the key.
async fn open_ledger_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    key: &str,
    method: &str,
    route: &str,
    payload_hash: &str,
    principal_id: &str,
    owner_token: &str,
) -> Result<bool, LedgerReplay> {
    let inserted = sqlx::query(
        "INSERT INTO idempotency_records
             (tenant_id, idempotency_key, request_method, request_route, payload_hash,
              principal_id, owner_token, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'in_flight')
         ON CONFLICT (tenant_id, idempotency_key) DO NOTHING",
    )
    .bind(tenant_id)
    .bind(key)
    .bind(method)
    .bind(route)
    .bind(payload_hash)
    .bind(principal_id)
    .bind(owner_token)
    .execute(&mut **tx)
    .await
    .map_err(|_| LedgerReplay::Conflict("idempotency ledger unavailable"))?;

    if inserted.rows_affected() > 0 {
        return Ok(true);
    }

    // A record exists: read and classify it. A concurrent creator that
    // completes the row right after this read makes the classification
    // stale (`InFlight`), which only costs the retry a 409-and-retry — the
    // takeover below is the only WRITE and is a guarded conditional UPDATE.
    let row: Option<LedgerRow> = fetch_ledger_row(&mut **tx, tenant_id, key)
        .await
        .map_err(|_| LedgerReplay::Conflict("idempotency ledger unavailable"))?;
    let Some(row) = row else {
        // Vanished between insert-conflict and lock (concurrent delete):
        // retry once via a plain insert.
        return Ok(true);
    };
    match classify_ledger_row(&row, method, route, payload_hash, principal_id) {
        LedgerReplay::Complete { .. } => Ok(false),
        LedgerReplay::Conflict(reason) => Err(LedgerReplay::Conflict(reason)),
        LedgerReplay::InFlight => {
            // F21: an abandoned in-flight record (crashed creator, older
            // than LEDGER_STALE_AFTER_SECONDS) may be taken over with a new
            // owner token; a live one rejects the concurrent duplicate.
            let taken = sqlx::query(
                "UPDATE idempotency_records
                 SET owner_token = $3, updated_at = NOW()
                 WHERE tenant_id = $1 AND idempotency_key = $2
                   AND status = 'in_flight'
                   AND updated_at < NOW() - ($4::text::interval)",
            )
            .bind(tenant_id)
            .bind(key)
            .bind(owner_token)
            .bind(format!("{LEDGER_STALE_AFTER_SECONDS} seconds"))
            .execute(&mut **tx)
            .await
            .map_err(|_| LedgerReplay::Conflict("idempotency ledger unavailable"))?;
            if taken.rows_affected() > 0 {
                Ok(true)
            } else {
                Err(LedgerReplay::InFlight)
            }
        }
    }
}

/// F21: complete the ledger record with the handler's response, fenced on
/// this request's owner token. Called inside the same transaction as the
/// message/queue writes, so response and effects are atomic (F20).
async fn complete_ledger_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    key: &str,
    owner_token: &str,
    response_status: i64,
    response_body: &str,
) {
    let completed = sqlx::query(
        "UPDATE idempotency_records
         SET status = 'complete', response_status = $4, response_body = $5,
             completed_at = NOW(), updated_at = NOW()
         WHERE tenant_id = $1 AND idempotency_key = $2 AND owner_token = $3",
    )
    .bind(tenant_id)
    .bind(key)
    .bind(owner_token)
    .bind(response_status)
    .bind(response_body)
    .execute(&mut **tx)
    .await;
    match completed {
        Ok(updated) if updated.rows_affected() == 0 => {
            tracing::warn!(
                tenant_id,
                idempotency_key = key,
                "idempotency ledger completion fenced out — ownership lost"
            );
        }
        Ok(_) => {}
        Err(error) => {
            tracing::error!(error = %error, tenant_id, idempotency_key = key,
                "failed to complete idempotency ledger record");
        }
    }
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

    // F26: MIME headers (original To/Cc visibility + reply-to + custom
    // headers) live in the queue row's `headers` JSONB, separate from the
    // envelope destination columns. F48: attachments + priority ride on the
    // same insert.
    let mime_headers = mime_headers_for(body).unwrap_or(serde_json::json!({}));
    let queue_attachments = queue_attachments_of(body);
    let queue_priority = queue_priority_of(body);
    let reply_to = body.reply_to.as_deref().filter(|r| !r.is_empty());

    // Store the idempotency key in the dedicated `idempotency_key` column (not
    // inside JSONB metadata) so the UNIQUE(tenant_id, idempotency_key)
    // index is actually enforced. `ON CONFLICT ... DO NOTHING` is the
    // race-condition safety net: if a concurrent request already inserted the
    // same (tenant_id, idempotency_key), this insert is a no-op and we return
    // `None` so the caller can re-fetch the existing message. NULL keys never
    // conflict (standard SQL NULL-distinct semantics), so batch sends and any
    // request without an idempotency key insert normally.
    //
    // F45: `metadata` is now the sanitized CUSTOMER object only — server
    // operational state (pending_recipients / lease_token / ...) is written
    // exclusively by the worker into its own metadata namespace and is never
    // seeded from caller input.
    let result = sqlx::query(
        "INSERT INTO messages (id, tenant_id, from_email, to_emails, cc_emails, bcc_emails,
         subject, html_body, text_body, status, tags, metadata, scheduled_at, created_at, idempotency_key,
         reply_to, headers, attachments)
         VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
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
    .bind(reply_to)
    // messages.headers keeps the same server-written MIME header map so the
    // audit row records what recipients actually saw (F26).
    .bind(&mime_headers)
    .bind(&queue_attachments)
    .execute(&mut **tx)
    .await?;

    // Conflict (concurrent duplicate idempotency key) → nothing inserted.
    if result.rows_affected() == 0 {
        return Ok(None);
    }

    // Batched email_queue inserts (previously one INSERT per delivery
    // recipient — up to MAX_RECIPIENTS sequential round-trips per message).
    // 17 bind parameters per row × 500 rows stays far below Postgres's
    // 65,535-parameter statement limit.
    const EMAIL_QUEUE_CHUNK_SIZE: usize = 500;
    for chunk in delivery_recipients(body).chunks(EMAIL_QUEUE_CHUNK_SIZE) {
        let mut query = String::from(
            "INSERT INTO email_queue (
                id, message_id, tenant_id, domain_id, from_address, to_addresses, subject,
                \"from\", \"to\", html, text, tags, metadata, scheduled_at, priority, status, created_at, updated_at,
                reply_to, headers, attachments
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
            let (i_prio, i_reply, i_hdr, i_att) = (
                param_idx + 13,
                param_idx + 14,
                param_idx + 15,
                param_idx + 16,
            );
            query.push_str(&format!(
                "(${i_id}::uuid, ${i_msg}::uuid, ${i_ten}, ${i_dom}::uuid, ${i_from}, ARRAY[${i_rcpt}], ${i_subj}, \
                 ${i_from}, ${i_rcpt}, ${i_html}, ${i_text}, ${i_tags}, ${i_meta}, ${i_sched}, ${i_prio}, 'pending', \
                 ${i_created}, ${i_created}, ${i_reply}, ${i_hdr}, ${i_att})"
            ));
            param_idx += 17;
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
                .bind(created_at)
                .bind(queue_priority)
                .bind(reply_to)
                .bind(&mime_headers)
                .bind(&queue_attachments);
        }
        q.execute(&mut **tx).await?;
    }

    Ok(Some(PersistedMessage {
        id: message_id,
        status: status.to_owned(),
        created_at,
    }))
}

// ─── Handlers ──────────────────────────────────────────────────

async fn send_message(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: HeaderMap,
    Json(body): Json<SendMessageRequest>,
) -> Result<Response, ApiError> {
    require_scopes(&auth, &["messages:send"])?;

    // F44/F45/F48: contract validation BEFORE any quota reservation or
    // persistence — metadata shape, reserved operational keys, and the
    // explicitly-unsupported SDK options (template sending) are rejected
    // with 422 here, never silently discarded.
    let option_errors = validate_send_options(&body);
    if !option_errors.is_empty() {
        return Ok(unprocessable_send_options(option_errors));
    }
    let metadata = match sanitize_customer_metadata(&body.metadata) {
        Ok(metadata) => metadata,
        Err(errors) => return Ok(unprocessable_send_options(errors)),
    };

    validate_send(&body, &state.db, &auth.tenant_id).await?;

    // ── F19/F20: durable idempotency ledger ───────────────────────────
    //
    // Redis (the middleware) only accelerates; the ledger is authoritative
    // and is committed in the SAME transaction as the message + queue rows,
    // so the stored response survives response loss and Redis failures.
    let idempotency_key: Option<String> = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|key| !key.is_empty() && key.len() <= 255)
        .map(str::to_string);

    let payload_hash = canonical_send_hash(&body);
    let principal = principal_binding(&auth);

    if let Some(key) = idempotency_key.as_deref() {
        match ledger_preflight(
            &state.db,
            &auth.tenant_id,
            key,
            "POST",
            SEND_ROUTE,
            &payload_hash,
            &principal,
        )
        .await?
        {
            Some(LedgerReplay::Complete {
                response_status,
                response_body,
            }) => {
                // The original response was durably stored even though the
                // caller never consumed it — replay it (F20).
                return replay_ledger_response(response_status, &response_body);
            }
            Some(LedgerReplay::Conflict(reason)) => return Err(ApiError::Conflict(reason.into())),
            Some(LedgerReplay::InFlight) => {
                return Err(ApiError::Conflict(
                    "a request with this Idempotency-Key is already in flight; retry after a short delay".into(),
                ));
            }
            None => {}
        }
    }

    ensure_tenant_message_circuit_closed(&state, &auth.tenant_id).await?;

    let mut tx = state.db.begin().await.map_err(|error| {
        tracing::error!(error = %error, tenant_id = %auth.tenant_id, "failed to begin message transaction");
        ApiError::Internal("database error".into())
    })?;

    // F20/F21: open the ledger record inside this transaction so the
    // message row, every queue row, and the idempotent response commit (or
    // roll back) together.
    let owner_token = Uuid::new_v4().simple().to_string();
    if let Some(key) = idempotency_key.as_deref() {
        match open_ledger_in_tx(
            &mut tx,
            &auth.tenant_id,
            key,
            "POST",
            SEND_ROUTE,
            &payload_hash,
            &principal,
            &owner_token,
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => {
                // A completed record appeared between preflight and the
                // locked insert — replay it instead of double-sending.
                if let Some(row) = fetch_ledger_row(&mut *tx, &auth.tenant_id, key).await? {
                    if let LedgerReplay::Complete {
                        response_status,
                        response_body,
                    } = classify_ledger_row(&row, "POST", SEND_ROUTE, &payload_hash, &principal)
                    {
                        let _ = tx.rollback().await;
                        return replay_ledger_response(response_status, &response_body);
                    }
                }
                let _ = tx.rollback().await;
                return Err(ApiError::Conflict(
                    "a request with this Idempotency-Key is already in flight; retry after a short delay".into(),
                ));
            }
            Err(LedgerReplay::Conflict(reason)) => {
                let _ = tx.rollback().await;
                return Err(ApiError::Conflict(reason.into()));
            }
            Err(LedgerReplay::InFlight) => {
                let _ = tx.rollback().await;
                return Err(ApiError::Conflict(
                    "a request with this Idempotency-Key is already in flight; retry after a short delay".into(),
                ));
            }
            // Unreachable by construction (classify drives Complete to
            // Ok(false)), but the compiler cannot prove it.
            Err(LedgerReplay::Complete { .. }) => {
                let _ = tx.rollback().await;
                return Err(ApiError::Conflict(
                    "a request with this Idempotency-Key is already in flight; retry after a short delay".into(),
                ));
            }
        }
    }

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
    //
    // F22: the usage event id is DERIVED from (tenant, idempotency key), so
    // a concurrent duplicate send records the SAME metering event — the
    // billing layer de-duplicates on it and the quota is reserved exactly
    // once. The reservation carries the inserted/duplicate outcome so only
    // a real insert is ever compensated.
    let usage_event_id = quota_usage_event_id(&auth.tenant_id, idempotency_key.as_deref(), None);
    let quota_reservation = reserve_email_quota(
        &state,
        &auth.tenant_id,
        quota_quantity_for_request(&body),
        usage_event_id,
    )
    .await?;

    // Idempotency key for the send — stored in the dedicated column so the
    // UNIQUE(tenant_id, idempotency_key) index is enforced inside the insert
    // (the ledger pre-check above is only a fast path; it cannot close the
    // concurrent-duplicate race window on its own).
    let persisted = match insert_message_and_queue(
        &mut tx,
        &auth.tenant_id,
        &body,
        &metadata,
        idempotency_key.as_deref(),
        Some(domain_id),
    )
    .await
    {
        Ok(Some(persisted)) => persisted,
        Ok(None) => {
            // Idempotent duplicate: a concurrent request won the insert race
            // (the ledger pre-check missed it). The payload identity was
            // verified against the ledger above (F19), so re-fetch the
            // existing message and return the original id instead of
            // double-sending.
            let refetched: Result<Option<(String, String, DateTime<Utc>)>, sqlx::Error> =
                sqlx::query_as(
                    "SELECT id::text, status, created_at FROM messages
                     WHERE tenant_id = $1 AND idempotency_key = $2
                     LIMIT 1",
                )
                .bind(&auth.tenant_id)
                // A NULL key can never conflict (SQL NULL-distinct semantics),
                // so reaching this arm implies a key was provided.
                .bind(idempotency_key.as_deref().unwrap_or_default())
                .fetch_optional(&mut *tx)
                .await;

            let (existing, refetch_error) = match refetched {
                Ok(existing) => (existing, None),
                Err(error) => (None, Some(error)),
            };
            let Some((id, status, created_at)) = existing else {
                let _ = tx.rollback().await;
                compensate_reservation(&state, &auth.tenant_id, &quota_reservation).await;

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
            compensate_reservation(&state, &auth.tenant_id, &quota_reservation).await;

            record_tenant_message_circuit_failure(&state, &auth.tenant_id).await;
            tracing::error!(error = %error, tenant_id = %auth.tenant_id, "failed to persist message delivery");
            return Err(ApiError::Internal("database error".into()));
        }
    };

    let response = MessageResponse {
        id: persisted.id,
        status: persisted.status,
        created_at: persisted.created_at.to_rfc3339(),
    };

    // F20: durably record the response in the same transaction as the
    // message + queue rows — a caller that loses the HTTP response gets the
    // exact same reply on retry.
    if let Some(key) = idempotency_key.as_deref() {
        if let Ok(body_json) = serde_json::to_string(&response) {
            complete_ledger_in_tx(
                &mut tx,
                &auth.tenant_id,
                key,
                &owner_token,
                StatusCode::ACCEPTED.as_u16() as i64,
                &body_json,
            )
            .await;
        }
    }

    if let Err(error) = tx.commit().await {
        compensate_reservation(&state, &auth.tenant_id, &quota_reservation).await;

        record_tenant_message_circuit_failure(&state, &auth.tenant_id).await;
        tracing::error!(error = %error, tenant_id = %auth.tenant_id, "failed to commit message delivery");
        return Err(ApiError::Internal("database error".into()));
    }

    record_tenant_message_circuit_success(&state, &auth.tenant_id).await;

    Ok((StatusCode::ACCEPTED, Json(ApiResponse::success(response))).into_response())
}

/// F20: replay a durably stored ledger response.
fn replay_ledger_response(status: i64, body: &str) -> Result<Response, ApiError> {
    let status =
        StatusCode::from_u16(u16::try_from(status).unwrap_or(StatusCode::ACCEPTED.as_u16()))
            .unwrap_or(StatusCode::ACCEPTED);
    let body = serde_json::from_str::<serde_json::Value>(body)
        .unwrap_or(serde_json::json!({"data": null, "error": null}));
    Ok((status, Json(body)).into_response())
}

async fn send_batch(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: HeaderMap,
    Json(body): Json<BatchSendRequest>,
) -> Result<Response, ApiError> {
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

    // ── F20: durable batch idempotency ledger ──────────────────────────
    //
    // Batch results used to live ONLY in the HTTP response (and the Redis
    // accelerator): losing the response — or a Redis failure — made the
    // retry re-send the whole batch. The ledger record is committed in the
    // SAME transaction as every accepted message + queue row and stores the
    // full per-item results, so a retry replays them verbatim.
    let batch_key: Option<String> = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|key| !key.is_empty() && key.len() <= 255)
        .map(str::to_string);

    let payload_hash = canonical_send_hash(&body);
    let principal = principal_binding(&auth);

    if let Some(key) = batch_key.as_deref() {
        match ledger_preflight(
            &state.db,
            &auth.tenant_id,
            key,
            "POST",
            BATCH_ROUTE,
            &payload_hash,
            &principal,
        )
        .await?
        {
            Some(LedgerReplay::Complete {
                response_status,
                response_body,
            }) => {
                return replay_ledger_response(response_status, &response_body);
            }
            Some(LedgerReplay::Conflict(reason)) => return Err(ApiError::Conflict(reason.into())),
            Some(LedgerReplay::InFlight) => {
                return Err(ApiError::Conflict(
                    "a request with this Idempotency-Key is already in flight; retry after a short delay".into(),
                ));
            }
            None => {}
        }
    }

    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut results = Vec::with_capacity(body.messages.len());
    let mut committed_quota_reservations: Vec<QuotaReservation> =
        Vec::with_capacity(body.messages.len());

    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!(error = %e, "failed to begin batch transaction");
        ApiError::Internal("database error".into())
    })?;

    // F21: open the ledger record inside this transaction — the batch's
    // queue rows and its stored response commit (or roll back) together.
    let owner_token = Uuid::new_v4().simple().to_string();
    if let Some(key) = batch_key.as_deref() {
        match open_ledger_in_tx(
            &mut tx,
            &auth.tenant_id,
            key,
            "POST",
            BATCH_ROUTE,
            &payload_hash,
            &principal,
            &owner_token,
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => {
                if let Some(row) = fetch_ledger_row(&mut *tx, &auth.tenant_id, key).await? {
                    if let LedgerReplay::Complete {
                        response_status,
                        response_body,
                    } = classify_ledger_row(&row, "POST", BATCH_ROUTE, &payload_hash, &principal)
                    {
                        let _ = tx.rollback().await;
                        return replay_ledger_response(response_status, &response_body);
                    }
                }
                let _ = tx.rollback().await;
                return Err(ApiError::Conflict(
                    "a request with this Idempotency-Key is already in flight; retry after a short delay".into(),
                ));
            }
            Err(LedgerReplay::Conflict(reason)) => {
                let _ = tx.rollback().await;
                return Err(ApiError::Conflict(reason.into()));
            }
            Err(LedgerReplay::InFlight) => {
                let _ = tx.rollback().await;
                return Err(ApiError::Conflict(
                    "a request with this Idempotency-Key is already in flight; retry after a short delay".into(),
                ));
            }
            // Unreachable by construction (classify drives Complete to
            // Ok(false)), but the compiler cannot prove it.
            Err(LedgerReplay::Complete { .. }) => {
                let _ = tx.rollback().await;
                return Err(ApiError::Conflict(
                    "a request with this Idempotency-Key is already in flight; retry after a short delay".into(),
                ));
            }
        }
    }

    // Resolve every unique sender domain once per batch instead of once per
    // message (removes the N+1 domain lookups from validation and inserts).
    let domain_ids = resolve_batch_domain_ids(&mut tx, &auth.tenant_id, &body.messages)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to resolve batch sender domains");
            ApiError::Internal("database error".into())
        })?;

    for (i, msg) in body.messages.iter().enumerate() {
        // F23: forbidden/invalid values are validated BEFORE this item's
        // quota reservation — a rejected item never touches quota.
        macro_rules! reject_item {
            ($error:expr) => {{
                rejected += 1;
                results.push(BatchResult {
                    index: i,
                    id: None,
                    status: "rejected".into(),
                    error: Some($error),
                });
            }};
        }

        // F44/F45/F48: same honest contract as single sends, per item.
        let option_errors = validate_send_options(msg);
        if !option_errors.is_empty() {
            reject_item!(option_errors.join("; "));
            continue;
        }
        let item_metadata = match sanitize_customer_metadata(&msg.metadata) {
            Ok(metadata) => metadata,
            Err(errors) => {
                reject_item!(errors.join("; "));
                continue;
            }
        };

        if let Err(e) =
            validate_send_with_domain_cache(msg, &state.db, &auth.tenant_id, Some(&domain_ids))
                .await
        {
            reject_item!(e.to_string());
            continue;
        }

        // Per-recipient metering, same as single sends: the reservation covers
        // every delivery recipient of this batch item in one atomic quantity
        // (F1). Insufficient quota rejects just this item — the reservation is
        // all-or-nothing, so no partial quota is consumed.
        //
        // F22: the usage event id is derived from (tenant, batch key, item
        // index), so a concurrent duplicate batch can never reserve item
        // quota twice — the billing layer de-duplicates on the event id.
        let usage_event_id = quota_usage_event_id(&auth.tenant_id, batch_key.as_deref(), Some(i));
        let quota_reservation = match reserve_email_quota(
            &state,
            &auth.tenant_id,
            quota_quantity_for_request(msg),
            usage_event_id,
        )
        .await
        {
            Ok(reservation) => reservation,
            Err(ApiError::Forbidden(message)) => {
                reject_item!(message);
                continue;
            }
            Err(err) => {
                // Quota infrastructure failure aborts the whole batch. The
                // still-open transaction is dropped (message inserts roll
                // back), but reservations for earlier items live OUTSIDE the
                // transaction and must be released explicitly — otherwise they
                // leak and permanently consume the tenant's quota.
                for reservation in &committed_quota_reservations {
                    compensate_reservation(&state, &auth.tenant_id, reservation).await;
                }
                let _ = tx.rollback().await;
                return Err(err);
            }
        };

        let domain_id = sender_domain(&msg.from)
            .and_then(|domain| domain_ids.get(&domain).cloned())
            .flatten();

        // F23: per-item SAVEPOINT. Previously one failed item INSERT
        // aborted the whole Postgres transaction — every later item then
        // failed with InFailedSqlTransaction and the commit lied about the
        // items it had "accepted". Each item's mutations now roll back to
        // their own savepoint, the transaction stays usable, and the
        // committed per-item results tell the truth.
        sqlx::query("SAVEPOINT batch_item")
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to open batch item savepoint");
                ApiError::Internal("database error".into())
            })?;

        // Batch items carry no per-message idempotency key (and a NULL key
        // can never conflict); the batch-level ledger above owns replay.
        match insert_message_and_queue(
            &mut tx,
            &auth.tenant_id,
            msg,
            &item_metadata,
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
                // F22: a duplicate billing event owns no quota — only a real
                // insert is compensated.
                compensate_reservation(&state, &auth.tenant_id, &quota_reservation).await;
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
                // F23: roll this item's mutations back to the savepoint so
                // the shared transaction survives; later items still get
                // their chance and the commit cannot lie.
                if let Err(rollback_error) = sqlx::query("ROLLBACK TO SAVEPOINT batch_item")
                    .execute(&mut *tx)
                    .await
                {
                    tracing::error!(error = %rollback_error, "failed to roll back batch item savepoint");
                }
                compensate_reservation(&state, &auth.tenant_id, &quota_reservation).await;
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

    let response = BatchSendResponse {
        accepted,
        rejected,
        results,
    };

    // F20: store the full per-item results in the ledger BEFORE the commit,
    // so they are durable the instant the batch itself is — independent of
    // whether the caller ever consumes the HTTP response.
    if accepted > 0 {
        if let Some(key) = batch_key.as_deref() {
            if let Ok(body_json) = serde_json::to_string(&response) {
                complete_ledger_in_tx(
                    &mut tx,
                    &auth.tenant_id,
                    key,
                    &owner_token,
                    StatusCode::OK.as_u16() as i64,
                    &body_json,
                )
                .await;
            }
        }
        if let Err(error) = tx.commit().await {
            for reservation in &committed_quota_reservations {
                compensate_reservation(&state, &auth.tenant_id, reservation).await;
            }

            tracing::error!(error = %error, "failed to commit batch transaction");
            record_tenant_message_circuit_failure(&state, &auth.tenant_id).await;
            return Err(ApiError::Internal("database error".into()));
        }

        // Mirror the single-send path: a committed delivery resets the
        // tenant's circuit failure counter.
        record_tenant_message_circuit_success(&state, &auth.tenant_id).await;
    } else {
        // Nothing accepted: drop the transaction (and with it the in-flight
        // ledger record) so a retry can execute cleanly.
        let _ = tx.rollback().await;
    }

    Ok(success(response).into_response())
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
            let query = String::from(
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
            let query = String::from(
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
        CancelDeliveryResult::NotFound => {
            let _ = tx.rollback().await;
            return Err(ApiError::NotFound("message not found".into()));
        }
        CancelDeliveryResult::NotCancellable => {
            let _ = tx.rollback().await;
            return Err(ApiError::Conflict(
                "message cannot be cancelled (already cancelled or in a terminal state)".into(),
            ));
        }
        // F24: the irreversible dispatch boundary — a worker already
        // claimed (or delivered) at least one recipient copy. Rejected
        // with an explicit too-late result instead of racing the claim.
        CancelDeliveryResult::TooLate => {
            let _ = tx.rollback().await;
            return Err(ApiError::Conflict(
                "message can no longer be cancelled: dispatch has already started for at least one recipient".into(),
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
    /// F22: true when the billing layer recognized the usage event id as
    /// already recorded — this request reserved NOTHING and must not be
    /// compensated (the winner of the race owns the event).
    duplicate: bool,
}

/// Metered quantity for a send request: the number of delivery recipients.
/// Each recipient is enqueued as a separate email_queue row, so this is the
/// number of sends the tenant will actually consume.
fn quota_quantity_for_request(body: &SendMessageRequest) -> i64 {
    delivery_recipients(body).len() as i64
}

/// F22: stable logical usage ID for a send's quota reservation.
///
/// With an idempotency key the id is derived deterministically from
/// (tenant, key[, batch item index]), so concurrent duplicate sends — or a
/// retry whose Redis accelerator state was lost — record the SAME metering
/// event. `record_with_quota_check` de-duplicates on the event id and
/// reports `duplicate: true`, making a double reservation impossible.
/// Without a key the reservation keeps a random id (no replay identity to
/// bind to). UUID v5 is not compiled into the workspace `uuid` features;
/// the first 16 SHA-256 bytes of the namespace string serve the same
/// purpose (deterministic, collision-free in practice).
fn quota_usage_event_id(
    tenant_id: &str,
    idempotency_key: Option<&str>,
    item: Option<usize>,
) -> Uuid {
    match idempotency_key {
        Some(key) => {
            let namespace = match item {
                Some(index) => format!("apexmail:usage:{tenant_id}:batch:{key}:{index}"),
                None => format!("apexmail:usage:{tenant_id}:send:{key}"),
            };
            let digest = Sha256::digest(namespace.as_bytes());
            Uuid::from_slice(&digest[..16])
                .expect("the first 16 SHA-256 bytes are always a valid UUID")
        }
        None => Uuid::new_v4(),
    }
}

async fn reserve_email_quota(
    state: &AppState,
    tenant_id: &str,
    quantity: i64,
    usage_event_id: Uuid,
) -> Result<QuotaReservation, ApiError> {
    let reservation = QuotaReservation {
        event_id: usage_event_id,
        recorded_at: Utc::now(),
        quantity,
        duplicate: false,
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

    // F22: explicit inserted/duplicate outcome — a duplicate billing event
    // reserved nothing and its compensation is a no-op.
    Ok(QuotaReservation {
        duplicate: quota.duplicate,
        ..reservation
    })
}

/// F22: compensate a reservation — idempotently, and ONLY the loser.
///
/// * a `duplicate` reservation owns no metering state (the concurrent
///   winner's event carries the quota) — compensating it would delete the
///   winner's usage record, so it is skipped;
/// * a real insert is rolled back exactly once by the billing layer's
///   event-id keyed `rollback_usage_record`.
async fn compensate_reservation(state: &AppState, tenant_id: &str, reservation: &QuotaReservation) {
    if reservation.duplicate {
        tracing::debug!(
            tenant_id = tenant_id,
            event_id = %reservation.event_id,
            "skipping quota compensation for duplicate billing event (F22)"
        );
        return;
    }
    if let Err(rollback_error) = rollback_email_quota(state, tenant_id, reservation).await {
        tracing::error!(
            error = %rollback_error,
            tenant_id = tenant_id,
            event_id = %reservation.event_id,
            "failed to roll back reserved email quota"
        );
    }
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
            reply_to: None,
            headers: None,
            attachments: None,
            priority: None,
            template_id: None,
            template_data: None,
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
            reply_to: None,
            headers: None,
            attachments: None,
            priority: None,
            template_id: None,
            template_data: None,
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
            reply_to: None,
            headers: None,
            attachments: None,
            priority: None,
            template_id: None,
            template_data: None,
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
            reply_to: None,
            headers: None,
            attachments: None,
            priority: None,
            template_id: None,
            template_data: None,
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
            reply_to: None,
            headers: None,
            attachments: None,
            priority: None,
            template_id: None,
            template_data: None,
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
            reply_to: None,
            headers: None,
            attachments: None,
            priority: None,
            template_id: None,
            template_data: None,
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
            reply_to: None,
            headers: None,
            attachments: None,
            priority: None,
            template_id: None,
            template_data: None,
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
            duplicate: false,
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
            reply_to: None,
            headers: None,
            attachments: None,
            priority: None,
            template_id: None,
            template_data: None,
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
            reply_to: None,
            headers: None,
            attachments: None,
            priority: None,
            template_id: None,
            template_data: None,
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
            reply_to: None,
            headers: None,
            attachments: None,
            priority: None,
            template_id: None,
            template_data: None,
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
            reply_to: None,
            headers: None,
            attachments: None,
            priority: None,
            template_id: None,
            template_data: None,
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

    // ── F44/F45: metadata shape validation ──────────────────────────

    fn meta_value(v: serde_json::Value) -> Option<serde_json::Value> {
        Some(v)
    }

    #[test]
    fn metadata_object_is_accepted_and_passed_through_unchanged() {
        let metadata = meta_value(serde_json::json!({"source": "api", "n": 1}));
        let sanitized = sanitize_customer_metadata(&metadata).unwrap().unwrap();
        assert_eq!(sanitized, serde_json::json!({"source": "api", "n": 1}));
    }

    #[test]
    fn metadata_null_is_treated_as_missing() {
        assert!(
            sanitize_customer_metadata(&meta_value(serde_json::Value::Null))
                .unwrap()
                .is_none()
        );
        assert!(sanitize_customer_metadata(&None).unwrap().is_none());
    }

    /// The reported production failure: scalar metadata reached the worker's
    /// jsonb_set and failed the whole claim batch with SQLSTATE 22023.
    #[test]
    fn metadata_scalar_is_rejected_with_shape_error() {
        for value in [
            serde_json::json!("just a string"),
            serde_json::json!(42),
            serde_json::json!(true),
        ] {
            let errors = sanitize_customer_metadata(&meta_value(value)).unwrap_err();
            assert!(
                errors.iter().any(|e| e.contains("must be a JSON object")),
                "scalar metadata must be rejected: {errors:?}"
            );
        }
    }

    #[test]
    fn metadata_array_is_rejected_with_shape_error() {
        let errors =
            sanitize_customer_metadata(&meta_value(serde_json::json!([1, 2]))).unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("must be a JSON object")),
            "array metadata must be rejected: {errors:?}"
        );
    }

    /// F45: reserved operational keys are exclusively server-written — a
    /// caller-supplied pending_recipients could override the validated
    /// recipient set.
    #[test]
    fn metadata_reserved_operational_keys_are_rejected() {
        for key in RESERVED_METADATA_KEYS {
            let mut map = serde_json::Map::new();
            map.insert(key.to_string(), serde_json::json!(["attacker@evil.com"]));
            let errors = sanitize_customer_metadata(&meta_value(serde_json::Value::Object(map)))
                .unwrap_err();
            assert!(
                errors
                    .iter()
                    .any(|e| e.contains(key) && e.contains("reserved")),
                "reserved key {key} must be rejected: {errors:?}"
            );
        }
    }

    #[test]
    fn metadata_size_is_bounded() {
        let big: serde_json::Map<String, serde_json::Value> = (0..MAX_METADATA_KEYS)
            .map(|i| (format!("k{i}"), serde_json::json!("v".repeat(1024))))
            .collect();
        let errors =
            sanitize_customer_metadata(&meta_value(serde_json::Value::Object(big))).unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("maximum serialized size")),
            "oversized metadata must be rejected: {errors:?}"
        );
    }

    // ── F48: honest send-option contract ────────────────────────────

    fn options_request() -> SendMessageRequest {
        SendMessageRequest {
            from: "sender@example.com".into(),
            to: vec!["to@example.com".into()],
            cc: None,
            bcc: None,
            subject: "Options".into(),
            html: Some("<p>hi</p>".into()),
            text: None,
            tags: None,
            metadata: None,
            scheduled_at: None,
            reply_to: None,
            headers: None,
            attachments: None,
            priority: None,
            template_id: None,
            template_data: None,
        }
    }

    #[test]
    fn valid_supported_options_produce_no_errors() {
        let mut body = options_request();
        body.reply_to = Some("reply@example.com".into());
        body.headers = Some(serde_json::json!({"X-Custom": "v"}));
        body.attachments = Some(vec![SendAttachment {
            filename: "a.txt".into(),
            content: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"hello"),
            content_type: "text/plain".into(),
        }]);
        body.priority = Some(3);
        assert!(validate_send_options(&body).is_empty());
        assert_eq!(queue_priority_of(&body), 3);
    }

    /// Advertised-but-unsupported options must be REJECTED with an explicit
    /// error naming the field — never silently discarded.
    #[test]
    fn template_id_is_rejected_naming_the_field() {
        let mut body = options_request();
        body.template_id = Some("tmpl_123".into());
        let errors = validate_send_options(&body);
        assert!(
            errors.len() == 1 && errors[0].contains("'template_id'"),
            "template_id must be rejected naming the field: {errors:?}"
        );
    }

    #[test]
    fn template_data_is_rejected_naming_the_field() {
        let mut body = options_request();
        body.template_data = Some(serde_json::json!({"x": 1}));
        let errors = validate_send_options(&body);
        assert!(
            errors.len() == 1 && errors[0].contains("'template_data'"),
            "template_data must be rejected naming the field: {errors:?}"
        );
    }

    #[test]
    fn unsupported_fields_never_pass_validation_silently() {
        // Sanity for the deny_unknown_fields contract: any field outside the
        // struct (e.g. a future SDK option) is a deserialization error, and
        // the two template fields deserialize only to be explicitly
        // rejected — both paths produce a client-visible failure.
        let json = r#"{"from":"a@b.com","to":["c@d.com"],"subject":"X","html":"y",
                      "send_at":"2030-01-01T00:00:00Z"}"#;
        assert!(serde_json::from_str::<SendMessageRequest>(json).is_err());
    }

    #[test]
    fn invalid_reply_to_is_rejected() {
        let mut body = options_request();
        body.reply_to = Some("not-an-email".into());
        assert!(validate_send_options(&body)
            .iter()
            .any(|e| e.contains("reply_to")));
        let mut body = options_request();
        body.reply_to = Some("a@b.com\r\nBcc: x@y.com".into());
        assert!(validate_send_options(&body)
            .iter()
            .any(|e| e.contains("line breaks")));
    }

    #[test]
    fn headers_must_be_an_object_of_strings() {
        let mut body = options_request();
        body.headers = Some(serde_json::json!(["not", "an", "object"]));
        assert!(validate_send_options(&body)
            .iter()
            .any(|e| e.contains("'headers' must be an object")));
        let mut body = options_request();
        body.headers = Some(serde_json::json!({"X-Num": 5}));
        assert!(validate_send_options(&body)
            .iter()
            .any(|e| e.contains("must have a string value")));
    }

    #[test]
    fn protected_header_names_are_rejected() {
        let mut body = options_request();
        body.headers = Some(serde_json::json!({"Bcc": "evil@example.com"}));
        assert!(validate_send_options(&body)
            .iter()
            .any(|e| e.contains("'Bcc' is protected")));
        // Reply-To has a dedicated field.
        let mut body = options_request();
        body.headers = Some(serde_json::json!({"Reply-To": "r@example.com"}));
        assert!(validate_send_options(&body)
            .iter()
            .any(|e| e.contains("use the reply_to field")));
    }

    #[test]
    fn header_injection_via_values_is_rejected() {
        let mut body = options_request();
        body.headers = Some(serde_json::json!({"X-Good": "v\r\nBcc: evil@x.com"}));
        assert!(validate_send_options(&body)
            .iter()
            .any(|e| e.contains("line breaks")));
    }

    #[test]
    fn priority_must_be_in_range() {
        let mut body = options_request();
        body.priority = Some(0);
        assert!(validate_send_options(&body)
            .iter()
            .any(|e| e.contains("priority must be between")));
        let mut body = options_request();
        body.priority = Some(11);
        assert!(validate_send_options(&body)
            .iter()
            .any(|e| e.contains("priority must be between")));
        // Out-of-range values fall back to the default at insert time.
        let mut body = options_request();
        body.priority = Some(99);
        assert_eq!(queue_priority_of(&body), QUEUE_PRIORITY_DEFAULT);
    }

    #[test]
    fn attachments_must_be_valid_base64_with_bounded_size() {
        let mut body = options_request();
        body.attachments = Some(vec![SendAttachment {
            filename: "a.txt".into(),
            content: "not base64!!".into(),
            content_type: "text/plain".into(),
        }]);
        assert!(validate_send_options(&body)
            .iter()
            .any(|e| e.contains("not valid base64")));

        let mut body = options_request();
        body.attachments = Some(vec![SendAttachment {
            filename: "big.bin".into(),
            content: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                vec![0u8; MAX_ATTACHMENT_BYTES + 1],
            ),
            content_type: "application/octet-stream".into(),
        }]);
        assert!(validate_send_options(&body)
            .iter()
            .any(|e| e.contains("maximum decoded size")));

        let mut body = options_request();
        body.attachments = Some(vec![SendAttachment {
            filename: "crlf.txt\r\nBcc: x".into(),
            content: "aGk=".into(),
            content_type: "text/plain".into(),
        }]);
        assert!(validate_send_options(&body)
            .iter()
            .any(|e| e.contains("filename")));
    }

    // ── F22: stable logical usage IDs ───────────────────────────────

    #[test]
    fn quota_usage_event_id_is_stable_per_idempotency_key() {
        let a = quota_usage_event_id("ten_1", Some("key-1"), None);
        let b = quota_usage_event_id("ten_1", Some("key-1"), None);
        assert_eq!(a, b, "a duplicate send derives the SAME usage event");
        // Different key / tenant / item → different event.
        assert_ne!(a, quota_usage_event_id("ten_1", Some("key-2"), None));
        assert_ne!(a, quota_usage_event_id("ten_2", Some("key-1"), None));
        assert_ne!(a, quota_usage_event_id("ten_1", Some("key-1"), Some(0)));
        // Batch items are distinct from each other and stable.
        assert_eq!(
            quota_usage_event_id("ten_1", Some("bk"), Some(3)),
            quota_usage_event_id("ten_1", Some("bk"), Some(3))
        );
        assert_ne!(
            quota_usage_event_id("ten_1", Some("bk"), Some(3)),
            quota_usage_event_id("ten_1", Some("bk"), Some(4))
        );
        // Without a key there is no replay identity — random events.
        assert_ne!(
            quota_usage_event_id("ten_1", None, None),
            quota_usage_event_id("ten_1", None, None)
        );
    }

    // ── F19: ledger classification ──────────────────────────────────

    fn complete_ledger_row() -> LedgerRow {
        LedgerRow {
            request_method: "POST".into(),
            request_route: SEND_ROUTE.into(),
            payload_hash: "a".repeat(64),
            principal_id: "user:usr_1".into(),
            status: "complete".into(),
            response_status: Some(202),
            response_body: Some("{\"data\":{}}".into()),
        }
    }

    #[test]
    fn ledger_replays_only_on_full_identity_match() {
        let row = complete_ledger_row();
        assert!(matches!(
            classify_ledger_row(&row, "POST", SEND_ROUTE, &"a".repeat(64), "user:usr_1"),
            LedgerReplay::Complete { .. }
        ));
    }

    #[test]
    fn ledger_conflicts_on_different_payload() {
        let row = complete_ledger_row();
        match classify_ledger_row(&row, "POST", SEND_ROUTE, &"b".repeat(64), "user:usr_1") {
            LedgerReplay::Conflict(reason) => assert!(reason.contains("different request body")),
            other => panic!("expected conflict, got {other:?}"),
        }
    }

    #[test]
    fn ledger_conflicts_on_different_route_or_principal() {
        let row = complete_ledger_row();
        assert!(matches!(
            classify_ledger_row(&row, "POST", BATCH_ROUTE, &"a".repeat(64), "user:usr_1"),
            LedgerReplay::Conflict(_)
        ));
        assert!(matches!(
            classify_ledger_row(&row, "POST", SEND_ROUTE, &"a".repeat(64), "user:usr_2"),
            LedgerReplay::Conflict(_)
        ));
    }

    #[test]
    fn ledger_in_flight_rejects_concurrent_duplicate() {
        let row = LedgerRow {
            status: "in_flight".into(),
            ..complete_ledger_row()
        };
        assert!(matches!(
            classify_ledger_row(&row, "POST", SEND_ROUTE, &"a".repeat(64), "user:usr_1"),
            LedgerReplay::InFlight
        ));
    }

    #[test]
    fn canonical_send_hash_is_stable_and_distinguishing() {
        let a = options_request();
        let mut b = options_request();
        b.subject = "Different".into();
        assert_eq!(canonical_send_hash(&a), canonical_send_hash(&a));
        assert_ne!(canonical_send_hash(&a), canonical_send_hash(&b));
    }

    // ── F26: MIME header storage ────────────────────────────────────

    #[test]
    fn mime_headers_preserve_visible_to_cc_and_never_bcc() {
        let mut body = options_request();
        body.cc = Some(vec!["cc@example.com".into()]);
        body.bcc = Some(vec!["bcc@example.com".into()]);
        body.reply_to = Some("reply@example.com".into());
        body.headers = Some(serde_json::json!({"X-Custom": "v"}));

        let headers = mime_headers_for(&body).unwrap();
        assert_eq!(headers["to"], serde_json::json!("to@example.com"));
        assert_eq!(headers["cc"], serde_json::json!("cc@example.com"));
        assert_eq!(headers["reply_to"], serde_json::json!("reply@example.com"));
        assert_eq!(headers["custom"], serde_json::json!({"X-Custom": "v"}));
        assert!(
            headers.get("bcc").is_none(),
            "Bcc must never appear in the visible MIME headers (F26)"
        );
    }

    #[test]
    fn queue_attachments_serialize_to_worker_shape() {
        let mut body = options_request();
        assert!(queue_attachments_of(&body).is_none());
        body.attachments = Some(vec![SendAttachment {
            filename: "a.txt".into(),
            content: "aGk=".into(),
            content_type: "text/plain".into(),
        }]);
        let json = queue_attachments_of(&body).unwrap();
        assert_eq!(json[0]["filename"], "a.txt");
        assert_eq!(json[0]["contentType"], "text/plain");
        assert_eq!(json[0]["content"], "aGk=");
    }

    // ── F24 (DB): cancellation protocol ─────────────────────────────

    #[tokio::test]
    async fn cancelling_after_worker_claim_is_explicitly_too_late() {
        let Some(pool) = crate::test_db::optional_pg_pool(
            "cancelling_after_worker_claim_is_explicitly_too_late",
        )
        .await
        else {
            return;
        };
        apply_tool_migrations(&pool).await;

        let tenant_id = insert_test_tenant(&pool, "message-race").await;
        let domain_id = insert_verified_domain(&pool, &tenant_id, "example.com").await;
        let body = options_request();

        let mut create_tx = pool.begin().await.expect("begin create");
        let persisted = insert_message_and_queue(
            &mut create_tx,
            &tenant_id,
            &body,
            &body.metadata,
            None,
            Some(domain_id.clone()),
        )
        .await
        .expect("persist")
        .expect("fresh insert");
        create_tx.commit().await.expect("commit create");

        // Simulate the worker CLAIMING the first recipient copy — the
        // irreversible dispatch boundary (F24).
        sqlx::query("UPDATE email_queue SET status = 'processing' WHERE message_id = $1::uuid AND \"to\" = 'to@example.com'")
            .bind(&persisted.id)
            .execute(&pool)
            .await
            .expect("claim one row");

        let mut cancel_tx = pool.begin().await.expect("begin cancel");
        let result = cancel_message_and_queue(&mut cancel_tx, &tenant_id, &persisted.id)
            .await
            .expect("cancel attempt");
        cancel_tx.rollback().await.expect("rollback cancel");

        assert!(
            matches!(result, CancelDeliveryResult::TooLate),
            "a claimed recipient copy must make cancellation explicitly too late"
        );
        // Nothing was cancelled by the fenced attempt.
        let statuses: Vec<(String,)> = sqlx::query_as(
            "SELECT status FROM email_queue WHERE message_id = $1::uuid ORDER BY \"to\"",
        )
        .bind(&persisted.id)
        .fetch_all(&pool)
        .await
        .expect("statuses");
        assert_eq!(statuses, vec![("processing".to_string(),)]);
    }

    #[tokio::test]
    async fn cancelling_pending_message_flips_all_rows_and_verifies_counts() {
        let Some(pool) = crate::test_db::optional_pg_pool(
            "cancelling_pending_message_flips_all_rows_and_verifies_counts",
        )
        .await
        else {
            return;
        };
        apply_tool_migrations(&pool).await;

        let tenant_id = insert_test_tenant(&pool, "message-clean-cancel").await;
        let domain_id = insert_verified_domain(&pool, &tenant_id, "example.com").await;
        let mut body = options_request();
        body.cc = Some(vec!["cc@example.com".into()]);
        body.bcc = Some(vec!["bcc@example.com".into()]);

        let mut create_tx = pool.begin().await.expect("begin create");
        let persisted = insert_message_and_queue(
            &mut create_tx,
            &tenant_id,
            &body,
            &body.metadata,
            None,
            Some(domain_id),
        )
        .await
        .expect("persist")
        .expect("fresh insert");
        create_tx.commit().await.expect("commit create");

        let mut cancel_tx = pool.begin().await.expect("begin cancel");
        let result = cancel_message_and_queue(&mut cancel_tx, &tenant_id, &persisted.id)
            .await
            .expect("cancel attempt");
        cancel_tx.commit().await.expect("commit cancel");

        assert!(matches!(result, CancelDeliveryResult::Cancelled(_)));

        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT status FROM email_queue WHERE message_id = $1::uuid")
                .bind(&persisted.id)
                .fetch_all(&pool)
                .await
                .expect("rows");
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|(status,)| status == "cancelled"));

        let parent: (String,) =
            sqlx::query_as("SELECT status FROM messages WHERE id = $1::uuid AND tenant_id = $2")
                .bind(&persisted.id)
                .bind(&tenant_id)
                .fetch_one(&pool)
                .await
                .expect("parent");
        assert_eq!(parent.0, "cancelled");
    }

    // ── F23 (DB): per-item savepoints keep the batch transaction alive ──

    #[tokio::test]
    async fn batch_item_savepoint_contains_item_failures() {
        let Some(pool) =
            crate::test_db::optional_pg_pool("batch_item_savepoint_contains_item_failures").await
        else {
            return;
        };
        apply_tool_migrations(&pool).await;

        let tenant_id = insert_test_tenant(&pool, "message-savepoint").await;
        let domain_id = insert_verified_domain(&pool, &tenant_id, "example.com").await;
        let body = options_request();

        let mut tx = pool.begin().await.expect("begin");

        // Item 0: succeeds.
        sqlx::query("SAVEPOINT batch_item")
            .execute(&mut *tx)
            .await
            .expect("sp0");
        let first = insert_message_and_queue(
            &mut tx,
            &tenant_id,
            &body,
            &body.metadata,
            None,
            Some(domain_id.clone()),
        )
        .await
        .expect("insert 0")
        .expect("persisted 0");

        // Item 1: its statement FAILS (invalid uuid bind) — without a
        // savepoint this would abort the whole transaction and every later
        // item would fail with InFailedSqlTransaction (the F23 lie).
        sqlx::query("SAVEPOINT batch_item")
            .execute(&mut *tx)
            .await
            .expect("sp1");
        let failed = sqlx::query("INSERT INTO messages (id, tenant_id, from_email, to_emails, subject, status, created_at) VALUES ($1, $2, 'a@b.com', '[]', 'x', 'queued', NOW())")
            .bind("not-a-uuid")
            .bind(&tenant_id)
            .execute(&mut *tx)
            .await;
        assert!(failed.is_err(), "the poisoned item must fail");
        sqlx::query("ROLLBACK TO SAVEPOINT batch_item")
            .execute(&mut *tx)
            .await
            .expect("rollback to savepoint");

        // Item 2: still succeeds — the transaction survived item 1's failure.
        sqlx::query("SAVEPOINT batch_item")
            .execute(&mut *tx)
            .await
            .expect("sp2");
        let third = insert_message_and_queue(
            &mut tx,
            &tenant_id,
            &body,
            &body.metadata,
            None,
            Some(domain_id),
        )
        .await
        .expect("insert 2")
        .expect("persisted 2");

        tx.commit()
            .await
            .expect("commit must succeed after a savepoint-contained failure");

        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM messages WHERE tenant_id = $1 AND id::text = ANY($2)",
        )
        .bind(&tenant_id)
        .bind(vec![first.id, third.id])
        .fetch_one(&pool)
        .await
        .expect("count");
        assert_eq!(count.0, 2, "both surviving items must be committed");
    }

    // ── F26 (DB): queue copies carry the original MIME headers ───────

    #[tokio::test]
    async fn queue_rows_store_original_mime_to_cc_and_reply_to() {
        let Some(pool) =
            crate::test_db::optional_pg_pool("queue_rows_store_original_mime_to_cc_and_reply_to")
                .await
        else {
            return;
        };
        apply_tool_migrations(&pool).await;

        let tenant_id = insert_test_tenant(&pool, "message-mime").await;
        let domain_id = insert_verified_domain(&pool, &tenant_id, "example.com").await;
        let mut body = options_request();
        body.cc = Some(vec!["cc@example.com".into()]);
        body.bcc = Some(vec!["bcc@example.com".into()]);
        body.reply_to = Some("reply@example.com".into());

        let mut create_tx = pool.begin().await.expect("begin create");
        let persisted = insert_message_and_queue(
            &mut create_tx,
            &tenant_id,
            &body,
            &body.metadata,
            None,
            Some(domain_id),
        )
        .await
        .expect("persist")
        .expect("fresh insert");
        create_tx.commit().await.expect("commit create");

        let rows: Vec<(String, serde_json::Value, Option<String>)> = sqlx::query_as(
            "SELECT \"to\", headers, reply_to FROM email_queue WHERE message_id = $1::uuid ORDER BY \"to\"",
        )
        .bind(&persisted.id)
        .fetch_all(&pool)
        .await
        .expect("queue rows");
        assert_eq!(rows.len(), 3);
        for (_envelope_to, headers, reply_to) in &rows {
            // The visible MIME To keeps the original To list on every
            // copy, Cc is preserved separately, and Bcc appears NOWHERE.
            assert_eq!(headers["to"], serde_json::json!("to@example.com"));
            assert_eq!(headers["cc"], serde_json::json!("cc@example.com"));
            assert!(headers.get("bcc").is_none());
            assert_eq!(reply_to.as_deref(), Some("reply@example.com"));
        }
    }
}
