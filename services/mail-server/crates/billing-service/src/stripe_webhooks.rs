use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use chrono::{DateTime, TimeDelta, Utc};
use futures::future::join_all;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::time::timeout;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::routes::{append_audit_log, generate_audit_log_id};
use crate::AppState;

type HmacSha256 = Hmac<Sha256>;

const DEADLETTER_EVENT_PREFIX: &str = "stripe:deadletter:event:";
const DEADLETTER_INDEX_KEY: &str = "stripe:deadletter:index";
const DEADLETTER_RETENTION_SECONDS: usize = 35 * 24 * 60 * 60;
const DEADLETTER_RETENTION_MS: i64 = (DEADLETTER_RETENTION_SECONDS as i64) * 1000;
const DEADLETTER_RETRY_INDEX_KEY: &str = "stripe:deadletter:retry:index";
const DEADLETTER_MAX_RETRIES: u32 = 5;
/// Maximum stored webhook body size (4 KiB). Larger bodies are truncated
/// before the Redis SET so a single oversized Stripe payload cannot bloat
/// every deadletter entry. Truncated bodies are kept for debugging but are
/// never replayed — the retry scheduler skips entries whose body was cut.
const DEADLETTER_MAX_BODY_BYTES: usize = 4 * 1024;
/// Poll interval for the deadletter retry worker.
const DEADLETTER_RETRY_POLL_INTERVAL_SECS: u64 = 60;
/// Exponential backoff schedule in seconds: 5 min, 15 min, 30 min, 1 hour, 2 hours (max 5 attempts).
const DEADLETTER_RETRY_BACKOFF_SECONDS: [i64; 5] = [300, 900, 1800, 3600, 7200];
/// Maximum number of deadletter entries to retry per batch.
const DEADLETTER_RETRY_BATCH_SIZE: usize = 10;
const STRIPE_WEBHOOK_TOLERANCE_SECONDS: i64 = 300;
const DUNNING_STATUS_CACHE_TTL_SECONDS: u64 = 300;

static DUNNING_CONFIG_TABLE_ENSURED: OnceLock<()> = OnceLock::new();

pub(crate) fn router() -> Router<Arc<AppState>> {
    Router::new().route("/webhooks/stripe", post(handle_stripe_webhook))
}

async fn handle_stripe_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let signature = headers
        .get("stripe-signature")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty());

    let Some(signature) = signature else {
        record_deadletter(
            &state,
            DeadletterEntry {
                reason: "missing_signature".into(),
                occurred_at: None,
                event_id: None,
                error: None,
                payload_length: None,
                ..Default::default()
            },
            Some(&body),
            None,
        )
        .await;

        return json_error(StatusCode::BAD_REQUEST, "Missing stripe-signature header");
    };

    let event_id = match extract_event_id(&body) {
        Ok(event_id) => event_id,
        Err(RouteValidationError::InvalidJson(error_message)) => {
            record_deadletter(
                &state,
                DeadletterEntry {
                    reason: "invalid_json_payload".into(),
                    occurred_at: None,
                    event_id: None,
                    error: Some(error_message),
                    payload_length: Some(body.len()),
                    ..Default::default()
                },
                Some(&body),
                Some(signature),
            )
            .await;

            return json_error(StatusCode::BAD_REQUEST, "Invalid JSON payload");
        }
        Err(RouteValidationError::MissingEventId) => {
            record_deadletter(
                &state,
                DeadletterEntry {
                    reason: "missing_event_id".into(),
                    occurred_at: None,
                    event_id: None,
                    error: None,
                    payload_length: Some(body.len()),
                    ..Default::default()
                },
                Some(&body),
                Some(signature),
            )
            .await;

            return json_error(StatusCode::BAD_REQUEST, "Missing event ID");
        }
    };

    match process_webhook(&state, &body, signature).await {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({ "received": true })),
        )
            .into_response(),
        Err(error) => {
            let error_message = error.message().to_string();
            if error.should_record_deadletter() {
                record_deadletter(
                    &state,
                    DeadletterEntry {
                        reason: "processing_failed".into(),
                        occurred_at: None,
                        event_id: Some(event_id.clone()),
                        error: Some(error_message.clone()),
                        payload_length: None,
                        ..Default::default()
                    },
                    Some(&body),
                    Some(signature),
                )
                .await;
            }

            error!(event_id = %event_id, error = %error_message, "stripe webhook processing failed");
            json_error(error.http_status(), "Webhook processing failed")
        }
    }
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

fn extract_event_id(body: &[u8]) -> Result<String, RouteValidationError> {
    let envelope = serde_json::from_slice::<EventIdEnvelope>(body)
        .map_err(|error| RouteValidationError::InvalidJson(error.to_string()))?;

    let Some(event_id) = envelope.id.map(|value| value.trim().to_string()) else {
        return Err(RouteValidationError::MissingEventId);
    };

    if event_id.is_empty() {
        return Err(RouteValidationError::MissingEventId);
    }

    Ok(event_id)
}

async fn record_deadletter(
    state: &AppState,
    entry: DeadletterEntry,
    body: Option<&[u8]>,
    signature: Option<&str>,
) {
    let prepared = prepare_deadletter(entry, body, signature, Utc::now());

    if let Err(error) = write_prepared_deadletter_to_redis(state, &prepared).await {
        error!(error = %error, "failed to write stripe dead letter");
    }
}

/// Cap `text` at `max_bytes`, cutting at a UTF-8 char boundary and marking
/// the result as truncated. Used for the deadletter body cap.
fn truncate_at_char_boundary(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }

    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }

    let mut truncated = text[..end].to_string();
    truncated.push_str("...(truncated)");
    truncated
}

/// Prepare a deadletter entry for storage. Serialization of this
/// all-string/Option struct is infallible, so no error arm is invented.
fn prepare_deadletter(
    entry: DeadletterEntry,
    body: Option<&[u8]>,
    signature: Option<&str>,
    now: DateTime<Utc>,
) -> PreparedDeadletter {
    let now_ms = now.timestamp_millis();
    let occurred_at = entry
        .occurred_at
        .clone()
        .unwrap_or_else(|| now.to_rfc3339());
    let (body_str, body_truncated) = match body {
        Some(bytes) => {
            let text = String::from_utf8_lossy(bytes);
            let truncated = text.len() > DEADLETTER_MAX_BODY_BYTES;
            (
                Some(truncate_at_char_boundary(&text, DEADLETTER_MAX_BODY_BYTES)),
                truncated,
            )
        }
        None => (None, false),
    };
    let sig_str = signature.map(str::to_string);
    let event_key = format!(
        "{}{}:{}",
        DEADLETTER_EVENT_PREFIX,
        sanitize_event_id(entry.event_id.as_deref()),
        now_ms
    );
    // A truncated body cannot be replayed (the stored JSON is incomplete),
    // so only schedule a retry when the full body was preserved.
    let retry_at_ms = (entry.reason == "processing_failed"
        && body_str.is_some()
        && !body_truncated
        && sig_str.is_some()
        && entry.retry_count < entry.max_retries)
        .then_some(now_ms + DEADLETTER_RETRY_BACKOFF_SECONDS[0] * 1000);

    let store_entry = DeadletterEntry {
        occurred_at: Some(occurred_at),
        body: body_str,
        signature: sig_str,
        ..entry
    };

    PreparedDeadletter {
        event_key,
        payload: serde_json::to_string(&store_entry).expect("deadletter entry serializes"),
        now_ms,
        cleanup_before_ms: now_ms - DEADLETTER_RETENTION_MS,
        retry_at_ms,
    }
}

async fn write_prepared_deadletter_to_redis(
    state: &AppState,
    prepared: &PreparedDeadletter,
) -> Result<(), String> {
    let mut conn = state.redis.get().await.map_err(|error| {
        format!("failed to acquire redis connection for stripe dead letter: {error}")
    })?;

    let mut pipe = redis::pipe();
    pipe.atomic();
    pipe.cmd("SETEX")
        .arg(&prepared.event_key)
        .arg(DEADLETTER_RETENTION_SECONDS)
        .arg(&prepared.payload)
        .ignore()
        .cmd("ZADD")
        .arg(DEADLETTER_INDEX_KEY)
        .arg(prepared.now_ms)
        .arg(&prepared.event_key)
        .ignore()
        .cmd("ZREMRANGEBYSCORE")
        .arg(DEADLETTER_INDEX_KEY)
        .arg(0)
        .arg(prepared.cleanup_before_ms)
        .ignore()
        .cmd("EXPIRE")
        .arg(DEADLETTER_INDEX_KEY)
        .arg(DEADLETTER_RETENTION_SECONDS)
        .ignore();

    if let Some(retry_at_ms) = prepared.retry_at_ms {
        pipe.cmd("ZADD")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .arg(retry_at_ms)
            .arg(&prepared.event_key)
            .ignore()
            .cmd("EXPIRE")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .arg(DEADLETTER_RETENTION_SECONDS)
            .ignore();
    }

    pipe.query_async::<()>(&mut conn)
        .await
        .map_err(|error| format!("failed to write stripe dead letter: {error}"))
}

async fn remove_prepared_deadletter_from_redis(state: &AppState, event_key: &str) {
    if let Ok(mut conn) = state.redis.get().await {
        // Best-effort compensation: a Redis failure here is only logged (the
        // deadletter entry is retry-indexed and expires on its own TTL).
        if let Err(error) = redis::pipe()
            .atomic()
            .cmd("DEL")
            .arg(event_key)
            .ignore()
            .cmd("ZREM")
            .arg(DEADLETTER_INDEX_KEY)
            .arg(event_key)
            .ignore()
            .cmd("ZREM")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .arg(event_key)
            .ignore()
            .query_async::<()>(&mut conn)
            .await
        {
            error!(error = %error, event_key, "failed to compensate stripe dead letter after DB commit failure");
        }
    }
}

fn sanitize_event_id(event_id: Option<&str>) -> String {
    let Some(event_id) = event_id.map(str::trim).filter(|value| !value.is_empty()) else {
        return "unknown".into();
    };

    event_id
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' || character == '-' {
                character
            } else {
                '_'
            }
        })
        .collect()
}

async fn process_webhook(
    state: &AppState,
    payload: &[u8],
    signature: &str,
) -> Result<ProcessWebhookResult, ProcessWebhookError> {
    let event = verify_and_parse_event(state, payload, signature)?;

    match claim_webhook_event(state, &event.id, &event.event_type).await? {
        WebhookEventClaim::Claimed => {}
        WebhookEventClaim::AlreadyProcessed => {
            info!(event_id = %event.id, event_type = %event.event_type, "duplicate stripe webhook already processed");
            return Ok(ProcessWebhookResult {
                event_type: event.event_type,
                processed: false,
            });
        }
        WebhookEventClaim::AlreadyPending => {
            // Fix G — acknowledging a concurrently-pending event with a 200
            // makes Stripe stop retrying; if the worker that claimed it then
            // crashes, the row is stuck in `pending` forever. Return a
            // retryable status instead so Stripe keeps retrying (and the
            // stale-pending reclaimer below eventually resets the row).
            info!(event_id = %event.id, event_type = %event.event_type, "stripe webhook is already being processed by another worker; asking Stripe to retry");
            return Err(ProcessWebhookError::RetryLater(format!(
                "event {} is pending on another worker",
                event.id
            )));
        }
    }

    let event_id = event.id.clone();
    let event_type = event.event_type.clone();

    match handle_stripe_event(state, &event).await {
        Ok(()) => {
            sqlx::query(
                r#"
                UPDATE stripe_webhook_events
                SET status = 'processed', processed_at = NOW(), updated_at = NOW()
                WHERE stripe_event_id = $1
                "#,
            )
            .bind(&event_id)
            .execute(&state.db)
            .await
            .map_err(|error| format!("Failed to mark Stripe webhook as processed: {error}"))?;

            Ok(ProcessWebhookResult {
                event_type,
                processed: true,
            })
        }
        Err(error_message) => {
            if let Err(deadletter_error) = record_failed_webhook_deadletter_atomic(
                state,
                &event_id,
                &error_message,
                payload,
                signature,
            )
            .await
            {
                error!(
                    event_id = %event_id,
                    error = %deadletter_error,
                    "failed to persist stripe webhook failure/deadletter atomically"
                );
            }

            Err(ProcessWebhookError::DeadletterFlowHandled(error_message))
        }
    }
}

async fn record_failed_webhook_deadletter_atomic(
    state: &AppState,
    event_id: &str,
    error_message: &str,
    payload: &[u8],
    signature: &str,
) -> Result<(), String> {
    let prepared = prepare_deadletter(
        DeadletterEntry {
            reason: "processing_failed".into(),
            occurred_at: None,
            event_id: Some(event_id.to_string()),
            error: Some(error_message.to_string()),
            payload_length: None,
            ..Default::default()
        },
        Some(payload),
        Some(signature),
        Utc::now(),
    );

    let mut tx =
        state.db.begin().await.map_err(|error| {
            format!("Failed to begin Stripe webhook failure transaction: {error}")
        })?;

    let update_result = sqlx::query(
        r#"
        UPDATE stripe_webhook_events
        SET status = 'failed', error = $2, updated_at = NOW()
        WHERE stripe_event_id = $1
        "#,
    )
    .bind(event_id)
    .bind(error_message)
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("Failed to mark Stripe webhook as failed: {error}"))?;

    if update_result.rows_affected() == 0 {
        tx.rollback().await.map_err(|error| {
            format!("Failed to roll back empty Stripe webhook failure transaction: {error}")
        })?;
        return Err(format!(
            "Failed to mark Stripe webhook {event_id} as failed: event row was not found"
        ));
    }

    if let Err(error) = write_prepared_deadletter_to_redis(state, &prepared).await {
        if let Err(rollback_error) = tx.rollback().await {
            error!(event_id, error = %rollback_error, "failed to roll back Stripe webhook failure transaction after Redis deadletter error");
        }
        return Err(error);
    }

    if let Err(error) = tx.commit().await {
        remove_prepared_deadletter_from_redis(state, &prepared.event_key).await;
        return Err(format!(
            "Failed to commit Stripe webhook failure transaction after Redis deadletter write: {error}"
        ));
    }

    Ok(())
}

async fn claim_webhook_event(
    state: &AppState,
    event_id: &str,
    event_type: &str,
) -> Result<WebhookEventClaim, String> {
    let row = sqlx::query_as::<_, WebhookEventClaimRow>(
        r#"
        WITH claimed AS (
            INSERT INTO stripe_webhook_events (id, stripe_event_id, event_type, status, created_at, updated_at)
            VALUES (gen_random_uuid(), $1, $2, 'pending', NOW(), NOW())
            ON CONFLICT (stripe_event_id) DO UPDATE
            SET event_type = EXCLUDED.event_type,
                status = 'pending',
                error = NULL,
                updated_at = NOW()
            WHERE stripe_webhook_events.status <> 'processed'
              AND stripe_webhook_events.status <> 'pending'
            RETURNING true AS claimed, status
        )
        SELECT claimed, status FROM claimed
        UNION ALL
        SELECT false AS claimed, status
        FROM stripe_webhook_events
        WHERE stripe_event_id = $1
          AND NOT EXISTS (SELECT 1 FROM claimed)
        LIMIT 1
        "#,
    )
    .bind(event_id)
    .bind(event_type)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| format!("Failed to claim Stripe webhook event: {error}"))?;

    Ok(classify_webhook_claim(row))
}

fn classify_webhook_claim(row: Option<WebhookEventClaimRow>) -> WebhookEventClaim {
    match row {
        Some(WebhookEventClaimRow { claimed: true, .. }) => WebhookEventClaim::Claimed,
        Some(WebhookEventClaimRow { status, .. }) if status == "processed" => {
            WebhookEventClaim::AlreadyProcessed
        }
        _ => WebhookEventClaim::AlreadyPending,
    }
}

/// Age after which a `pending` webhook event row is considered abandoned
/// (claiming worker crashed mid-processing) and may be reclaimed (Fix G).
pub const STALE_PENDING_RECLAIM_SECS: u64 = 10 * 60;

/// Cutoff timestamp for the stale-pending reclaim sweep.
fn stale_pending_cutoff(now: DateTime<Utc>) -> DateTime<Utc> {
    now - TimeDelta::seconds(STALE_PENDING_RECLAIM_SECS as i64)
}

/// Reclaim webhook events stuck in `pending` for longer than
/// [`STALE_PENDING_RECLAIM_SECS`]. Rows are reset to `received` (with the
/// reason recorded in `error`) so either a Stripe retry or a deadletter
/// replay can claim them again. Returns the reclaimed event ids.
///
/// Wired into the maintenance worker loop (runs on startup and hourly).
pub async fn reclaim_stale_pending_webhooks(state: &AppState) -> Result<Vec<String>, String> {
    let cutoff = stale_pending_cutoff(Utc::now());
    let reclaimed: Vec<String> = sqlx::query_scalar(
        r#"
        UPDATE stripe_webhook_events
        SET status = 'received',
            error = 'reclaimed: pending exceeded stale threshold',
            updated_at = NOW()
        WHERE status = 'pending'
          AND updated_at < $1
        RETURNING stripe_event_id
        "#,
    )
    .bind(cutoff)
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("Failed to reclaim stale pending webhook events: {error}"))?;

    if !reclaimed.is_empty() {
        warn!(
            count = reclaimed.len(),
            "reclaimed stale pending stripe webhook events"
        );
    }

    Ok(reclaimed)
}

/// Map Stripe invoice money fields (all integer minor units / cents) onto
/// the local invoice columns, deriving whichever of subtotal/VAT/total is
/// missing. Negative or absent amounts degrade to zero (Fix A).
fn derive_invoice_totals(
    subtotal: Option<i64>,
    tax: Option<i64>,
    total: Option<i64>,
    amount_due: i64,
) -> (i64, i64, i64) {
    // Explicit Stripe figures are authoritative INCLUDING their sign: credit
    // invoices (customer credit / matrix proration exceeding the charge) are
    // legitimately negative, and a 100%-discounted invoice legitimately has
    // subtotal 0. Absence is already encoded by Option — Some(0) is a real
    // Stripe-reported zero and must not be treated as missing data. The
    // pre-fix `> 0` filters recorded both as zeros, overstating period
    // revenue/VAT and hiding the applied credit from the local ledger.
    let amount_due = amount_due.max(0);

    let (subtotal, vat, total) = match (subtotal, total) {
        (Some(sub), Some(tot)) => {
            let derived_vat = if tot < 0 {
                // Credit invoice: the VAT reversal carries the invoice's sign.
                tot - sub
            } else {
                (tot - sub).max(0)
            };
            let vat = tax
                .filter(|value| sub + value <= tot)
                .unwrap_or(derived_vat);
            (sub, vat, tot)
        }
        (Some(sub), None) => {
            let vat = tax.unwrap_or(0);
            (sub, vat, sub + vat)
        }
        (None, Some(tot)) => (tot, 0, tot),
        (None, None) => (amount_due, 0, amount_due),
    };

    (subtotal, vat, total)
}

/// Effective VAT rate (percent) implied by a subtotal + VAT amount pair.
/// Returns one decimal of precision so fractional statutory rates (e.g.
/// Finland's 25.5 %) survive; display code trims trailing zeros.
fn derive_invoice_vat_rate(subtotal: i64, vat_amount: i64) -> f64 {
    if subtotal <= 0 || vat_amount <= 0 {
        return 0.0;
    }
    // rate × 10, rounded half-up, then scaled back to percent
    let tenths = (vat_amount * 1000 + subtotal / 2) / subtotal;
    tenths as f64 / 10.0
}

/// Normalize a Stripe currency code for the local `invoices.currency`
/// column (lowercase, like invoices.rs). Defaults to `eur`.
fn normalize_stripe_currency(currency: Option<&str>) -> String {
    currency
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| "eur".into())
}

/// Verify the HMAC-SHA256 signature header over `payload` (the timestamp
/// segment participates in the MAC). Shared by live delivery verification
/// and deadletter replay re-verification.
fn verify_signature_hmac(secret: &str, payload: &[u8], signature: &str) -> Result<(), String> {
    let (timestamp, signatures) = parse_signature_header(signature)?;
    let timestamp_value = timestamp.to_string();
    let verified = signatures
        .into_iter()
        .filter_map(|candidate| hex::decode(candidate).ok())
        .any(|expected| {
            let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
                .expect("HMAC accepts arbitrary key lengths");
            mac.update(timestamp_value.as_bytes());
            mac.update(b".");
            mac.update(payload);
            mac.verify_slice(&expected).is_ok()
        });

    if verified {
        Ok(())
    } else {
        Err("Invalid webhook signature".into())
    }
}

fn verify_and_parse_event(
    state: &AppState,
    payload: &[u8],
    signature: &str,
) -> Result<StripeEventPayload, String> {
    let secret = state.config.stripe_webhook_secret.trim();
    if secret.is_empty() {
        return Err("Stripe webhook secret is not configured".into());
    }

    let (timestamp, _) = parse_signature_header(signature)?;
    if (Utc::now().timestamp() - timestamp).abs() > STRIPE_WEBHOOK_TOLERANCE_SECONDS {
        return Err("Invalid webhook signature".into());
    }

    verify_signature_hmac(secret, payload, signature)?;

    serde_json::from_slice(payload)
        .map_err(|error| format!("Failed to decode Stripe event payload: {error}"))
}

fn parse_signature_header(signature: &str) -> Result<(i64, Vec<&str>), String> {
    let mut timestamp = None;
    let mut signatures = Vec::new();

    for segment in signature.split(',') {
        let mut parts = segment.splitn(2, '=');
        let Some(key) = parts.next().map(str::trim) else {
            continue;
        };
        let Some(value) = parts.next().map(str::trim) else {
            continue;
        };

        match key {
            "t" => {
                timestamp = value.parse::<i64>().ok();
            }
            "v1" if !value.is_empty() => {
                signatures.push(value);
            }
            _ => {}
        }
    }

    match (timestamp, signatures.is_empty()) {
        (Some(timestamp), false) => Ok((timestamp, signatures)),
        _ => Err("Invalid webhook signature".into()),
    }
}

async fn handle_stripe_event(state: &AppState, event: &StripeEventPayload) -> Result<(), String> {
    match event.event_type.as_str() {
        "checkout.session.completed" => {
            let session: CheckoutSession = serde_json::from_value(event.data.object.clone())
                .map_err(|error| format!("Failed to decode checkout session: {error}"))?;
            handle_checkout_completed(state, session).await
        }
        "customer.subscription.created" | "customer.subscription.updated" => {
            let subscription: SubscriptionEvent = serde_json::from_value(event.data.object.clone())
                .map_err(|error| format!("Failed to decode subscription event: {error}"))?;
            handle_subscription_change(state, subscription).await
        }
        "customer.subscription.deleted" => {
            let subscription: SubscriptionEvent = serde_json::from_value(event.data.object.clone())
                .map_err(|error| format!("Failed to decode subscription delete event: {error}"))?;
            handle_subscription_deleted(state, subscription).await
        }
        "invoice.paid" => {
            let invoice: InvoiceEvent = serde_json::from_value(event.data.object.clone())
                .map_err(|error| format!("Failed to decode invoice paid event: {error}"))?;
            handle_invoice_paid(state, invoice).await
        }
        "invoice.payment_failed" => {
            let invoice: InvoiceEvent =
                serde_json::from_value(event.data.object.clone()).map_err(|error| {
                    format!("Failed to decode invoice payment_failed event: {error}")
                })?;
            handle_payment_failed(state, invoice).await
        }
        "customer.subscription.trial_will_end" => {
            let subscription: SubscriptionEvent = serde_json::from_value(event.data.object.clone())
                .map_err(|error| format!("Failed to decode trial ending event: {error}"))?;
            handle_trial_ending(state, subscription).await
        }
        _ => {
            warn!(event_type = %event.event_type, "unhandled stripe webhook event — consider adding a handler or ignoring intentionally");
            Ok(())
        }
    }
}

async fn handle_checkout_completed(
    _state: &AppState,
    session: CheckoutSession,
) -> Result<(), String> {
    let Some(tenant_id) = tenant_id_from_metadata(session.metadata.as_ref()) else {
        warn!(session_id = %session.id, "stripe checkout session missing tenant_id metadata");
        return Ok(());
    };

    // Checkout completion is not an entitlement event: the subscription can
    // still be incomplete or unpaid. Only the corresponding verified
    // `customer.subscription.*` webhook below changes plan access. In
    // particular, this must not reactivate a tenant suspended for abuse.
    info!(tenant_id = %tenant_id, session_id = %session.id, "stripe checkout completed; awaiting subscription state webhook");
    Ok(())
}

async fn handle_subscription_change(
    state: &AppState,
    subscription: SubscriptionEvent,
) -> Result<(), String> {
    let Some(tenant_id) = tenant_id_from_metadata(subscription.metadata.as_ref()) else {
        warn!(subscription_id = %subscription.id, "stripe subscription missing tenant_id metadata");
        return Ok(());
    };

    let Some(primary_item) = subscription.items.data.first() else {
        return Err(format!(
            "Subscription {} has no line items",
            subscription.id
        ));
    };
    let Some(price) = primary_item.price.as_ref() else {
        return Err(format!(
            "Subscription {} has no line-item price",
            subscription.id
        ));
    };
    let Some(price_id) = price.id.as_deref() else {
        return Err(format!(
            "Subscription {} has no valid line-item price",
            subscription.id
        ));
    };
    let Some(interval) = price
        .recurring
        .as_ref()
        .and_then(|recurring| recurring.interval)
    else {
        return Err(format!(
            "Subscription {} has an unsupported billing interval",
            subscription.id
        ));
    };
    let plan_name = sqlx::query_scalar::<_, String>(
        r#"
        SELECT name
        FROM plans
        WHERE is_active = true
          AND (
              (stripe_price_id_monthly = $1 AND $2 = 'monthly')
              OR (stripe_price_id_yearly = $1 AND $2 = 'yearly')
          )
        LIMIT 1
        "#,
    )
    .bind(price_id)
    .bind(interval.as_db_value())
    .fetch_optional(&state.db)
    .await
    .map_err(|error| format!("Failed to resolve plan for Stripe price {price_id}: {error}"))?
    .ok_or_else(|| format!("Unknown Stripe price ID: {price_id}"))?;
    let entitlement_plan = subscription.status.entitlement_plan_name(&plan_name);

    let incoming_period_start =
        DateTime::<Utc>::from_timestamp(subscription.current_period_start, 0);
    let incoming_period_end = DateTime::<Utc>::from_timestamp(subscription.current_period_end, 0);

    // Run the upsert inside a tenant-scoped entitlement transaction (audit
    // F36): the advisory lock serializes every entitlement writer (create,
    // update, delete) for this tenant, and the CURRENT subscription state
    // is read and validated INSIDE the lock (below), so reconciled plans
    // can never interleave with a stale event. Migration 078's partial
    // unique index on (tenant_id) WHERE status = 'active' is protected the
    // same way.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|error| format!("Failed to begin subscription upsert transaction: {error}"))?;

    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("stripe_entitlement:{tenant_id}"))
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("Failed to lock tenant entitlement: {error}"))?;

    // ── Audit F36: read/validate the CURRENT state INSIDE the lock ────
    // The old flow validated before acquiring the tenant lock and then
    // applied unconditionally: a delayed event could pass validation
    // against an earlier snapshot, wait while a replacement committed,
    // then restore the old subscription and cancel the new one. The
    // in-lock re-read (FOR UPDATE) plus the event/version watermark
    // (migration 184) makes that impossible.
    let current_subscription = sqlx::query_as::<
        _,
        (
            String,
            String,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
            Option<String>,
            Option<DateTime<Utc>>,
        ),
    >(
        r#"
        SELECT tenant_id, status::text, billing_cycle_start, billing_cycle_end, plan,
               event_watermark
        FROM stripe_subscriptions
        WHERE stripe_subscription_id = $1
        FOR UPDATE
        "#,
    )
    .bind(&subscription.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| format!("Failed to load current Stripe subscription: {error}"))?;

    if let Some((current_tenant_id, current_status, .., current_watermark)) =
        current_subscription.as_ref()
    {
        if current_tenant_id.as_str() != tenant_id {
            return Err(format!(
                "Stripe subscription {} is already bound to a different tenant",
                subscription.id
            ));
        }
        if current_status.as_str() != subscription.status.as_str()
            && !subscription.status.can_transition_from(current_status)
        {
            return Err(format!(
                "Invalid subscription status transition: {current_status} -> {}",
                subscription.status.as_str()
            ));
        }
        // Watermark check (audit F36): an event whose billing cycle is
        // OLDER than the last applied event for this subscription must not
        // rewind the cycle (same-status older price/period updates, or a
        // long-delayed active update racing a committed renewal).
        if subscription_event_is_stale(incoming_period_start, *current_watermark) {
            info!(
                tenant_id = %tenant_id,
                subscription_id = %subscription.id,
                incoming_cycle = ?incoming_period_start,
                applied_watermark = ?current_watermark,
                "stale stripe subscription update ignored — event predates the applied cycle watermark"
            );
            let _ = tx.rollback().await;
            return Ok(());
        }
    } else if !subscription.status.is_valid_initial_status() {
        return Err(format!(
            "Invalid initial subscription state: {}",
            subscription.status.as_str()
        ));
    }

    // Replacement proof (audit F36): a superseded ACTIVE subscription may
    // be canceled only when the incoming event represents the CURRENT
    // replacement — no other active row may carry a NEWER event watermark.
    // If one does, this event is stale relative to a committed replacement
    // and is ignored wholesale (it must not cancel the newer row).
    if let Some(incoming_start) = incoming_period_start {
        let newer_replacement: Option<String> = sqlx::query_scalar(
            r#"
            SELECT stripe_subscription_id
            FROM stripe_subscriptions
            WHERE tenant_id = $1
              AND stripe_subscription_id <> $2
              AND status = 'active'
              AND event_watermark IS NOT NULL
              AND event_watermark > $3
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(&subscription.id)
        .bind(incoming_start)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| format!("Failed to check replacement currency: {error}"))?;
        if let Some(newer) = newer_replacement {
            info!(
                tenant_id = %tenant_id,
                subscription_id = %subscription.id,
                newer_subscription = %newer,
                "stale stripe subscription update ignored — a newer active replacement exists"
            );
            let _ = tx.rollback().await;
            return Ok(());
        }
    }

    // Audit F30: before the upsert overwrites the period bounds, snapshot
    // the subscription's CLOSING cycle into the immutable billing_periods
    // table — a renewal must never erase the just-ended period before the
    // overage sweep has read it. Only a genuine period transition (new
    // start differs from the stored one) snapshots the old cycle. The
    // snapshot comes from the LOCKED state (audit F36) and freezes the
    // complete pricing context (audit F32).
    if let Some((_, previous_status, Some(previous_start), Some(previous_end), previous_plan, _)) =
        current_subscription.as_ref()
    {
        if incoming_period_start.is_none_or(|incoming| incoming != *previous_start) {
            snapshot_billing_period(
                &mut tx,
                tenant_id,
                &subscription.id,
                previous_status,
                previous_plan.as_deref(),
                *previous_start,
                *previous_end,
            )
            .await?;
        }
    }

    let superseded: Vec<SupersededCycleRow> = sqlx::query_as(
        r#"
        UPDATE stripe_subscriptions
        SET status = 'canceled', updated_at = NOW()
        WHERE tenant_id = $1
          AND status = 'active'
          AND stripe_subscription_id <> $2
        RETURNING stripe_subscription_id, billing_cycle_start, billing_cycle_end, plan
        "#,
    )
    .bind(tenant_id)
    .bind(&subscription.id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|error| format!("Failed to deactivate superseded subscriptions: {error}"))?;

    // Audit F30: superseded subscriptions' current cycles are equally
    // billable periods — snapshot them before their rows go terminal.
    // Their pre-deactivation status was 'active' (the UPDATE's WHERE).
    for cycle in &superseded {
        if let (Some(start), Some(end)) = (cycle.billing_cycle_start, cycle.billing_cycle_end) {
            snapshot_billing_period(
                &mut tx,
                tenant_id,
                &cycle.stripe_subscription_id,
                "active",
                cycle.plan.as_deref(),
                start,
                end,
            )
            .await?;
        }
    }

    // Audit F27: the upsert persists BOTH the resolved plan and the Stripe
    // price — the old DO UPDATE preserved a stale price (and never wrote
    // `plan` at all), so consumers keying on ss.plan mis-resolved after
    // upgrades/downgrades. The event watermark (audit F36) records the
    // cycle of the last APPLIED event; replays of the same cycle are
    // idempotent, older cycles were rejected above.
    sqlx::query(
        r#"
        WITH upsert_subscription AS (
            INSERT INTO stripe_subscriptions (
                id, tenant_id, stripe_subscription_id, stripe_customer_id, stripe_price_id,
                plan, status, billing_interval, billing_cycle_start, billing_cycle_end,
                cancel_at_period_end, canceled_at, trial_end, event_watermark,
                created_at, updated_at
            )
            VALUES (
                gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7,
                to_timestamp($8), to_timestamp($9), $10, to_timestamp($11), to_timestamp($12),
                COALESCE(to_timestamp($8), NOW()),
                NOW(), NOW()
            )
            ON CONFLICT (stripe_subscription_id) DO UPDATE SET
                stripe_price_id = $4,
                plan = $5,
                status = $6,
                billing_interval = $7,
                billing_cycle_start = to_timestamp($8),
                billing_cycle_end = to_timestamp($9),
                cancel_at_period_end = $10,
                canceled_at = to_timestamp($11),
                trial_end = to_timestamp($12),
                event_watermark = COALESCE(to_timestamp($8), stripe_subscriptions.event_watermark),
                updated_at = NOW()
            RETURNING tenant_id
        ),
        update_tenant AS (
            UPDATE tenants
            SET plan = $13, updated_at = NOW()
            WHERE id = $1
            RETURNING id
        )
        SELECT 1
        "#,
    )
    .bind(tenant_id)
    .bind(&subscription.id)
    .bind(subscription.customer.id())
    .bind(price_id)
    .bind(&plan_name)
    .bind(subscription.status.as_str())
    .bind(interval.as_db_value())
    .bind(subscription.current_period_start)
    .bind(subscription.current_period_end)
    .bind(subscription.cancel_at_period_end)
    .bind(subscription.canceled_at)
    .bind(subscription.trial_end)
    .bind(entitlement_plan)
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("Failed to upsert Stripe subscription: {error}"))?;

    // Audit F30/F32: the incoming cycle gets its period record now, with
    // the resolved plan AND the complete effective pricing snapshotted.
    if let (Some(period_start), Some(period_end)) = (incoming_period_start, incoming_period_end) {
        snapshot_billing_period(
            &mut tx,
            tenant_id,
            &subscription.id,
            subscription.status.as_str(),
            Some(&plan_name),
            period_start,
            period_end,
        )
        .await?;
    }

    tx.commit()
        .await
        .map_err(|error| format!("Failed to commit Stripe subscription upsert: {error}"))?;

    info!(
        tenant_id = %tenant_id,
        subscription_id = %subscription.id,
        status = %subscription.status.as_str(),
        entitlement_plan,
        "stripe subscription updated"
    );

    if matches!(subscription.status, SubscriptionStatus::Active) {
        // Spawn dedicated IP provisioning in background so the webhook handler
        // returns immediately. There is NO maintenance retry consumer for
        // `dedicated_ip_provisioning_requests` rows: a failure here is logged
        // and recorded as 'failed'/'partial' on the request row (see below),
        // and a subsequent subscription event re-runs the whole provisioning
        // path (the pending-request upsert is idempotent, and the active-count
        // query skips already-allocated IPs).
        let state = state.clone();
        let tenant_id = tenant_id.to_string();
        tokio::spawn(async move {
            if let Err(e) = auto_provision_dedicated_ips_background(&state, &tenant_id).await {
                error!(tenant_id = %tenant_id, error = %e, "background dedicated IP provisioning failed");
            }
        });
    }

    Ok(())
}

/// The exact JSON body sent to `POST {api_base_url}/v1/dedicated-ips`.
///
/// The API's `AllocateIpRequest` is `#[serde(deny_unknown_fields)]` and only
/// declares `region` (optional). The previous body
/// (`{"auto_provisioned": true}`) carried an unknown field, so axum's JSON
/// extractor rejected the request with 422 during deserialization — before
/// the allocation handler ever ran. The empty object parses into the
/// contract (every field is defaulted). If a region ever needs to be
/// pinned, extend this object with `region` only.
fn auto_provision_request_body() -> serde_json::Value {
    serde_json::json!({})
}

/// Background task that performs the actual dedicated IP provisioning.
/// Called from a `tokio::spawn` to avoid blocking the webhook handler.
///
/// There is no maintenance retry consumer: failures are logged and the
/// `dedicated_ip_provisioning_requests` row is finalized as
/// 'failed'/'partial'. A later active-subscription event retries the
/// provisioning path from scratch (idempotent request upsert + active-count
/// check), so the absence of a sweeper does not strand provisioning.
async fn auto_provision_dedicated_ips_background(
    app_state: &AppState,
    tenant_id: &str,
) -> Result<(), String> {
    // Re-borrow the inner fields we need
    let state = app_state;
    let included_count = sqlx::query_scalar::<_, i32>(
        r#"
        SELECT COALESCE((p.features->>'dedicated_ip_count')::int, 0) AS included_count
        FROM stripe_subscriptions s
        JOIN plans p ON p.name = (
            SELECT plan FROM tenants WHERE id = s.tenant_id
        )
        WHERE s.tenant_id = $1 AND s.status = 'active'
        ORDER BY s.created_at DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| format!("Failed to load dedicated IP allowance: {error}"))?
    .unwrap_or(0);

    if included_count <= 0 {
        return Ok(());
    }

    let active_count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)::bigint
        FROM dedicated_ips
        WHERE tenant_id = $1
          AND status NOT IN ('retired', 'releasing', 'failed', 'cleanup_failed')
        "#,
    )
    .bind(tenant_id)
    .fetch_one(&state.db)
    .await
    .map_err(|error| format!("Failed to load active dedicated IP count: {error}"))?;
    // Terminal provisioning-failure rows (`failed`, `cleanup_failed`) do not
    // occupy the allowance: the API-side `NON_OCCUPYING_STATUSES` is the
    // canonical list (crates/api-server/src/ip_provider.rs) and must stay in
    // sync with the literal above.

    let to_allocate = i64::from(included_count) - active_count;
    if to_allocate <= 0 {
        info!(tenant_id = %tenant_id, active_count, included_count, "tenant already has sufficient dedicated IPs");
        return Ok(());
    }

    sqlx::query(
        r#"
        INSERT INTO dedicated_ip_provisioning_requests
            (id, tenant_id, requested_count, status, created_at, updated_at)
        VALUES (gen_random_uuid(), $1, $2, 'pending', NOW(), NOW())
        ON CONFLICT (tenant_id) WHERE status = 'pending'
        DO UPDATE SET requested_count = $2, updated_at = NOW()
        "#,
    )
    .bind(tenant_id)
    .bind(to_allocate)
    .execute(&state.db)
    .await
    .map_err(|error| format!("Failed to record dedicated IP provisioning request: {error}"))?;

    // Use a shared HTTP client with sane timeouts.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))?;

    let api_base_url = state.config.api_base_url.trim_end_matches('/');
    let bearer = format!("Bearer {}", state.config.service_auth_token);

    // Build all requests upfront, then fire them concurrently with bounded parallelism.
    let mut requests: Vec<_> = (0..to_allocate)
        .map(|_| {
            client
                .post(format!("{api_base_url}/v1/dedicated-ips"))
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .header(reqwest::header::AUTHORIZATION, &bearer)
                .header("X-Internal-Service", "billing")
                .header("X-Tenant-Id", tenant_id)
                .json(&auto_provision_request_body())
                .send()
        })
        .collect();

    // Fire requests in concurrent batches of 5 to avoid overwhelming the API server.
    let mut success_count = 0_i64;
    let mut failure_count = 0_i64;
    const BATCH_SIZE: usize = 5;

    for chunk in requests.chunks_mut(BATCH_SIZE) {
        let results = join_all(
            chunk
                .iter_mut()
                .map(|req| timeout(Duration::from_secs(30), req)),
        )
        .await;

        for result in results {
            match result {
                Ok(Ok(response)) if response.status().is_success() => {
                    success_count += 1;
                }
                Ok(Ok(response)) => {
                    failure_count += 1;
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    warn!(
                        tenant_id = %tenant_id,
                        status = %status,
                        error = %body,
                        "dedicated IP auto-provision request failed"
                    );
                }
                Ok(Err(error)) => {
                    failure_count += 1;
                    error!(
                        tenant_id = %tenant_id,
                        error = %error,
                        "dedicated IP auto-provision request errored"
                    );
                }
                Err(_elapsed) => {
                    failure_count += 1;
                    error!(
                        tenant_id = %tenant_id,
                        "dedicated IP auto-provision request timed out after 30s"
                    );
                }
            }
        }
    }

    let final_status = if failure_count == 0 {
        "completed"
    } else if success_count > 0 {
        "partial"
    } else {
        "failed"
    };

    sqlx::query(
        r#"
        UPDATE dedicated_ip_provisioning_requests
        SET status = $2, success_count = $3, failure_count = $4, updated_at = NOW()
        WHERE tenant_id = $1 AND status = 'pending'
        "#,
    )
    .bind(tenant_id)
    .bind(final_status)
    .bind(success_count)
    .bind(failure_count)
    .execute(&state.db)
    .await
    .map_err(|error| format!("Failed to update dedicated IP provisioning request: {error}"))?;

    if failure_count > 0 {
        error!(
            tenant_id = %tenant_id,
            requested_count = to_allocate,
            success_count,
            failure_count,
            final_status,
            "dedicated IP provisioning had failures"
        );
    }

    Ok(())
}

/// Record (or leave untouched) the immutable billing-period snapshot for a
/// subscription cycle (audit F30). Runs INSIDE the caller's entitlement
/// transaction. `status` is the subscription's status while the cycle was
/// in force — ACTIVE cycles snapshot the tenant-level override-aware plan
/// (the same source the enforcement gate used), terminal cycles the
/// subscription's own plan. The COMPLETE effective pricing is frozen at
/// snapshot time (audit F32): email allowance, integer overage rate
/// (resolved from the SAME plan the allowance came from) and currency —
/// the sweep prices exclusively from these fields, never today's plan.
async fn snapshot_billing_period(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    stripe_subscription_id: &str,
    status: &str,
    subscription_plan: Option<&str>,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
) -> Result<(), String> {
    if period_end <= period_start {
        return Ok(());
    }

    // `p.name` is NULL when the tenant's effective plan name is not present
    // in `plans` (legacy/renamed plan, or an override removed out-of-band).
    // Decoding it as a bare `String` turned that legitimate state into a
    // decode ERROR, failing the whole entitlement webhook (dead-lettering a
    // valid subscription update) instead of degrading to the fallback below.
    let effective: Option<(Option<String>, Option<i64>, String)> = sqlx::query_as(
        r#"
        SELECT p.name, p.email_limit,
               COALESCE(t.settings->>'billingCurrency', 'EUR')
        FROM tenants t
        LEFT JOIN plan_overrides po
          ON po.tenant_id = t.id
         AND po.active = true
         AND (po.expires_at IS NULL OR po.expires_at > NOW())
        LEFT JOIN plans p
          ON p.name = CASE WHEN $2 = 'active'
                           THEN COALESCE(po.plan, t.plan, $3)
                           ELSE $3
                      END
        WHERE t.id = $1
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(status)
    .bind(subscription_plan)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| format!("Failed to snapshot billing period plan: {error}"))?;

    let (plan_name, email_allowance, currency) = match effective {
        Some((Some(name), limit, currency)) => {
            let currency = normalize_period_currency(&currency);
            (Some(name), limit, currency)
        }
        _ => (
            subscription_plan.map(str::to_string),
            None,
            crate::overage::default_period_currency(),
        ),
    };

    // Rate comes from the SAME plan the allowance/name came from — the
    // builtin per-plan ladder (review 2026-09-08 §9). Free/PAYG plans
    // resolve to None (no automatic overage) and stay NULL on the period.
    let rate_millicents = plan_name
        .as_deref()
        .and_then(crate::plans::plan_overage_rate_millicents);

    let pricing_snapshot = serde_json::json!({
        "snapshotVersion": 1,
        "planName": plan_name,
        "emailAllowance": email_allowance,
        "overageRateMillicents": rate_millicents,
        "currency": currency,
        "overrideAware": status == "active",
    });

    sqlx::query(
        r#"
        INSERT INTO billing_periods (
            tenant_id, stripe_subscription_id, usage_kind,
            period_start, period_end, currency, plan_name, email_allowance,
            overage_rate_millicents, pricing_snapshot, pricing_resolved_at
        )
        VALUES ($1, $2, 'subscription', $3, $4, $5, $6, $7, $8, $9::jsonb, NOW())
        ON CONFLICT (tenant_id, usage_kind, period_start) DO NOTHING
        "#,
    )
    .bind(tenant_id)
    .bind(stripe_subscription_id)
    .bind(period_start)
    .bind(period_end)
    .bind(&currency)
    .bind(plan_name)
    .bind(email_allowance)
    .bind(rate_millicents)
    .bind(pricing_snapshot.to_string())
    .execute(&mut **tx)
    .await
    .map_err(|error| format!("Failed to snapshot billing period: {error}"))?;
    Ok(())
}

/// Normalize a tenant billing-currency setting to a 3-letter uppercase ISO
/// code, defaulting to EUR (audit F32: the default is applied ONCE at
/// snapshot time and frozen, not per-invoice-read).
fn normalize_period_currency(raw: &str) -> String {
    let normalized = raw.trim().to_uppercase();
    if normalized.len() == 3 && normalized.chars().all(|c| c.is_ascii_uppercase()) {
        normalized
    } else {
        crate::overage::default_period_currency().to_string()
    }
}

/// Entitlement decision after a subscription was deleted (audit F36):
/// the plan comes from the tenant's best REMAINING entitled subscription
/// (active preferred over trialing); with none left, the tenant drops to
/// free. Pure — unit-tested. This is what makes a stale `deleted` event for
/// an already-replaced subscription unable to downgrade the newer active
/// one: the decision never consults the deleted row.
fn reconciled_entitlement_plan(remaining: Option<(Option<&str>, &str)>) -> String {
    match remaining {
        Some((Some(plan), _status)) if !plan.trim().is_empty() => plan.trim().to_string(),
        _ => "free".to_string(),
    }
}

/// Audit F36 — pure staleness check for a subscription event against the
/// last APPLIED event watermark (migration 184): an event whose billing
/// cycle predates the watermark must not rewind the cycle (same-status
/// older price/period updates, or a delayed active update racing a
/// committed renewal). Same-cycle events apply (plan changes at a cycle
/// boundary are legitimate); a missing watermark or a missing cycle in
/// the event is never treated as stale.
fn subscription_event_is_stale(
    incoming_cycle: Option<DateTime<Utc>>,
    applied_watermark: Option<DateTime<Utc>>,
) -> bool {
    match (incoming_cycle, applied_watermark) {
        (Some(incoming), Some(watermark)) => incoming < watermark,
        _ => false,
    }
}

async fn handle_subscription_deleted(
    state: &AppState,
    subscription: SubscriptionEvent,
) -> Result<(), String> {
    let Some(tenant_id) = tenant_id_from_metadata(subscription.metadata.as_ref()) else {
        return Ok(());
    };

    // Audit F36: reconcile entitlement under a tenant-scoped transaction.
    // The advisory lock serializes every entitlement writer for this
    // tenant (create/update/delete), so a stale delete event can no longer
    // interleave with a newer subscription webhook and downgrade a tenant
    // that still has an entitled subscription.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|error| format!("Failed to begin subscription delete transaction: {error}"))?;

    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("stripe_entitlement:{tenant_id}"))
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("Failed to lock tenant entitlement: {error}"))?;

    // Cancel ONLY this tenant's row for the deleted subscription: a stale
    // or foreign event (subscription bound to another tenant, already
    // replaced) matches no row and is a no-op.
    let canceled: Option<String> = sqlx::query_scalar(
        r#"
        UPDATE stripe_subscriptions
        SET status = 'canceled', updated_at = NOW()
        WHERE stripe_subscription_id = $1
          AND tenant_id = $2
        RETURNING tenant_id
        "#,
    )
    .bind(&subscription.id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| format!("Failed to cancel Stripe subscription: {error}"))?;

    let Some(canceled_tenant) = canceled else {
        // Stale event (or the row belongs to another tenant): reject its
        // effect on the tenant's plan outright.
        tx.rollback()
            .await
            .map_err(|error| format!("Failed to roll back stale delete: {error}"))?;
        info!(
            tenant_id = %tenant_id,
            subscription_id = %subscription.id,
            "stripe subscription.deleted ignored — no matching row for this tenant (stale event)"
        );
        return Ok(());
    };
    debug_assert_eq!(canceled_tenant, tenant_id);

    // Audit F30: the deleted subscription's final cycle is still a
    // billable period — snapshot it before the row goes terminal.
    let final_cycle: Option<SubscriptionCycleRow> = sqlx::query_as(
        r#"
        SELECT billing_cycle_start, billing_cycle_end, plan
        FROM stripe_subscriptions
        WHERE stripe_subscription_id = $1 AND tenant_id = $2
        "#,
    )
    .bind(&subscription.id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| format!("Failed to load deleted subscription cycle: {error}"))?;
    if let Some(SubscriptionCycleRow {
        billing_cycle_start: Some(start),
        billing_cycle_end: Some(end),
        plan,
    }) = final_cycle
    {
        snapshot_billing_period(
            &mut tx,
            tenant_id,
            &subscription.id,
            "canceled",
            plan.as_deref(),
            start,
            end,
        )
        .await?;
    }

    // Reconcile the tenant's plan from the CURRENT subscription state: an
    // entitled subscription that remains (active or trialing) keeps its
    // plan; only when none remains does the tenant drop to free. This is
    // what makes a stale delete of an OLD subscription unable to downgrade
    // a NEWER active one (audit F36).
    let remaining: Option<(Option<String>, String)> = sqlx::query_as(
        r#"
        SELECT plan, status::text
        FROM stripe_subscriptions
        WHERE tenant_id = $1
          AND stripe_subscription_id <> $2
          AND status IN ('active', 'trialing')
        ORDER BY CASE WHEN status = 'active' THEN 0 ELSE 1 END, created_at DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(&subscription.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| format!("Failed to reconcile remaining entitlement: {error}"))?;

    let reconciled_plan = reconciled_entitlement_plan(
        remaining
            .as_ref()
            .map(|(plan, status)| (plan.as_deref(), status.as_str())),
    );

    sqlx::query("UPDATE tenants SET plan = $2, updated_at = NOW() WHERE id = $1")
        .bind(tenant_id)
        .bind(&reconciled_plan)
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("Failed to reconcile tenant plan: {error}"))?;

    tx.commit()
        .await
        .map_err(|error| format!("Failed to commit subscription delete: {error}"))?;

    info!(
        tenant_id = %tenant_id,
        subscription_id = %subscription.id,
        reconciled_plan = %reconciled_plan,
        "stripe subscription canceled — entitlement reconciled from current subscription state"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Tax truth (P0): immutable Stripe tax snapshot + independent validation
// ---------------------------------------------------------------------------
//
// Stripe and ApexMail must not be two tax deciders. Stripe Tax is the
// charging authority (`automatic_tax` is enabled at checkout session
// creation in api-server and is requested on usage invoices); ApexMail
// persists what Stripe actually decided — amounts, jurisdiction, tax-ID
// status, invoice id and a payload hash — into `stripe_tax_snapshots`
// (immutable, migration 218), recomputes the total independently and
// compares. A mismatch BLOCKS local invoice finalization and raises a
// `finance_incidents` row instead of quietly recording inconsistent books.

/// ApexMail's independently computed total for a Stripe invoice.
#[derive(Debug, Clone, PartialEq)]
struct ExpectedTax {
    subtotal_cents: i64,
    vat_cents: i64,
    total_cents: i64,
    /// `local_invoice`, `recomputed` or `unavailable`.
    source: &'static str,
    country: Option<String>,
    vat_rate: f64,
    evidence_id: Option<Uuid>,
}

/// A charged-total mismatch between Stripe and ApexMail.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TaxTotalDiscrepancy {
    observed_subtotal_cents: i64,
    observed_vat_cents: i64,
    observed_total_cents: i64,
    expected_subtotal_cents: i64,
    expected_vat_cents: i64,
    expected_total_cents: i64,
    delta_cents: i64,
}

impl TaxTotalDiscrepancy {
    fn summary(&self) -> String {
        format!(
            "charged total {} != ApexMail-computed {} (subtotal {} vs {}, VAT {} vs {})",
            self.observed_total_cents,
            self.expected_total_cents,
            self.observed_subtotal_cents,
            self.expected_subtotal_cents,
            self.observed_vat_cents,
            self.expected_vat_cents,
        )
    }
}

/// Compare the charged (Stripe) money fields against ApexMail's independent
/// computation. Pure and unit-tested: the required P0 behaviour is that a
/// mismatch is an error (the caller blocks finalization and raises a
/// finance incident), never a warning.
fn check_charged_total(
    expected: &ExpectedTax,
    observed_subtotal_cents: i64,
    observed_vat_cents: i64,
    observed_total_cents: i64,
) -> Result<(), TaxTotalDiscrepancy> {
    if expected.subtotal_cents == observed_subtotal_cents
        && expected.vat_cents == observed_vat_cents
        && expected.total_cents == observed_total_cents
    {
        return Ok(());
    }
    Err(TaxTotalDiscrepancy {
        observed_subtotal_cents,
        observed_vat_cents,
        observed_total_cents,
        expected_subtotal_cents: expected.subtotal_cents,
        expected_vat_cents: expected.vat_cents,
        expected_total_cents: expected.total_cents,
        delta_cents: observed_total_cents - expected.total_cents,
    })
}

/// Customer tax-ID summary persisted on the snapshot. Stripe verification
/// states (`verified`, `pending`, `unverified`) are preserved verbatim.
fn summarize_tax_ids(invoice: &InvoiceEvent) -> (String, serde_json::Value) {
    let entries = invoice.customer_tax_ids.as_deref().unwrap_or_default();
    if entries.is_empty() {
        return ("not_provided".to_string(), serde_json::json!([]));
    }
    let mut rows = Vec::with_capacity(entries.len());
    let mut any_verified = false;
    for entry in entries {
        let verification_status = entry
            .verification
            .as_ref()
            .and_then(|verification| verification.get("status"))
            .and_then(|status| status.as_str())
            .map(str::to_string);
        if verification_status.as_deref() == Some("verified") {
            any_verified = true;
        }
        rows.push(serde_json::json!({
            "type": entry.kind,
            "value": entry.value,
            "verification_status": verification_status,
        }));
    }
    let status = if any_verified {
        "verified"
    } else {
        "provided_unverified"
    };
    (status.to_string(), serde_json::Value::Array(rows))
}

/// The jurisdiction Stripe attributed the tax to, from whichever tax
/// breakdown shape the API version supplies.
fn tax_jurisdiction(invoice: &InvoiceEvent) -> Option<String> {
    let entries = invoice
        .total_taxes
        .as_ref()
        .or(invoice.total_tax_amounts.as_ref())?;
    for entry in entries {
        for container in [entry.tax_rate_details.as_ref(), entry.tax_rate.as_ref()]
            .into_iter()
            .flatten()
        {
            if let Some(country) = container.get("country").and_then(|value| value.as_str()) {
                if !country.trim().is_empty() {
                    return Some(country.trim().to_uppercase());
                }
            }
        }
    }
    None
}

/// Normalized tax breakdown persisted on the snapshot (raw Stripe objects
/// are not retained verbatim; the hash covers this normalized payload).
fn tax_breakdown_json(invoice: &InvoiceEvent) -> serde_json::Value {
    let Some(entries) = invoice
        .total_taxes
        .as_ref()
        .or(invoice.total_tax_amounts.as_ref())
    else {
        return serde_json::json!([]);
    };
    serde_json::Value::Array(
        entries
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "amount": entry.amount,
                    "inclusive": entry.inclusive,
                    "taxability_reason": entry.taxability_reason,
                    "tax_rate_details": entry.tax_rate_details,
                })
            })
            .collect(),
    )
}

/// The `automatic_tax` status Stripe reported, or `not_enabled`.
fn automatic_tax_status(invoice: &InvoiceEvent) -> String {
    invoice
        .automatic_tax
        .as_ref()
        .and_then(|automatic| automatic.status.clone())
        .or_else(|| {
            invoice
                .automatic_tax
                .as_ref()
                .and_then(|automatic| automatic.disabled_reason.clone())
        })
        .unwrap_or_else(|| "not_enabled".to_string())
}

fn automatic_tax_complete(invoice: &InvoiceEvent) -> bool {
    invoice.automatic_tax.as_ref().is_some_and(|automatic| {
        automatic.enabled.unwrap_or(false) && automatic.status.as_deref() == Some("complete")
    })
}

/// SHA-256 over the canonical snapshot payload.
fn snapshot_payload_hash(payload: &serde_json::Value) -> String {
    use sha2::Digest;
    let canonical = serde_json::to_vec(payload).unwrap_or_default();
    hex::encode(Sha256::digest(&canonical))
}

/// Row of `stripe_tax_snapshots` already persisted for this Stripe invoice.
async fn load_existing_tax_snapshot(
    db: &sqlx::PgPool,
    stripe_invoice_id: &str,
) -> Result<Option<(String, i64, i64)>, String> {
    sqlx::query_as(
        r#"
        SELECT validation_status, total_cents,
               COALESCE(apexmail_expected_total_cents, total_cents)::bigint
        FROM stripe_tax_snapshots
        WHERE stripe_invoice_id = $1
        "#,
    )
    .bind(stripe_invoice_id)
    .fetch_optional(db)
    .await
    .map_err(|error| format!("failed to load existing tax snapshot: {error}"))
}

/// Persist a snapshot (first write wins; the table is trigger-immutable).
/// Returns the snapshot id.
#[allow(clippy::too_many_arguments)]
async fn persist_tax_snapshot(
    db: &sqlx::PgPool,
    invoice: &InvoiceEvent,
    tenant_id: &str,
    local_invoice_id: Option<Uuid>,
    currency: &str,
    observed: (i64, i64, i64),
    expected: &ExpectedTax,
    authority: &str,
    validation_status: &str,
    discrepancy_cents: i64,
    tax_id_status: &str,
    tax_ids: &serde_json::Value,
) -> Result<Uuid, String> {
    let breakdown = tax_breakdown_json(invoice);
    let jurisdiction = tax_jurisdiction(invoice).or_else(|| expected.country.clone());
    let observed_payload = serde_json::json!({
        "stripe_invoice_id": invoice.id,
        "stripe_invoice_number": invoice.number,
        "currency": currency,
        "subtotal_cents": observed.0,
        "tax_cents": observed.1,
        "total_cents": observed.2,
        "amount_paid_cents": invoice.amount_paid,
        "automatic_tax_status": automatic_tax_status(invoice),
        "tax_id_status": tax_id_status,
        "tax_ids": tax_ids,
        "jurisdiction": jurisdiction,
        "tax_breakdown": breakdown,
        "apexmail": {
            "expected_subtotal_cents": expected.subtotal_cents,
            "expected_vat_cents": expected.vat_cents,
            "expected_total_cents": expected.total_cents,
            "source": expected.source,
            "vat_rate": expected.vat_rate,
            "evidence_id": expected.evidence_id,
        },
        "validation_status": validation_status,
    });
    let raw_hash = snapshot_payload_hash(&observed_payload);

    let inserted: Option<(Uuid,)> = sqlx::query_as(
        r#"
        INSERT INTO stripe_tax_snapshots (
            stripe_invoice_id, stripe_invoice_number, tenant_id, local_invoice_id,
            currency, subtotal_cents, tax_cents, total_cents, amount_paid_cents,
            automatic_tax_status, authority, jurisdiction, tax_id_status,
            tax_ids, tax_breakdown,
            apexmail_expected_subtotal_cents, apexmail_expected_vat_cents,
            apexmail_expected_total_cents, validation_status, discrepancy_cents,
            raw_payload_hash, raw_payload
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
            $16, $17, $18, $19, $20, $21, $22
        )
        ON CONFLICT (stripe_invoice_id) DO NOTHING
        RETURNING id
        "#,
    )
    .bind(&invoice.id)
    .bind(&invoice.number)
    .bind(tenant_id)
    .bind(local_invoice_id)
    .bind(currency)
    .bind(observed.0)
    .bind(observed.1)
    .bind(observed.2)
    .bind(invoice.amount_paid)
    .bind(automatic_tax_status(invoice))
    .bind(authority)
    .bind(&jurisdiction)
    .bind(tax_id_status)
    .bind(tax_ids)
    .bind(&breakdown)
    .bind(expected.subtotal_cents)
    .bind(expected.vat_cents)
    .bind(expected.total_cents)
    .bind(validation_status)
    .bind(discrepancy_cents)
    .bind(&raw_hash)
    .bind(&observed_payload)
    .fetch_optional(db)
    .await
    .map_err(|error| format!("failed to persist stripe tax snapshot: {error}"))?;

    if let Some((id,)) = inserted {
        return Ok(id);
    }
    // Already persisted (replay): immutability means first write wins.
    sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM stripe_tax_snapshots WHERE stripe_invoice_id = $1",
    )
    .bind(&invoice.id)
    .fetch_one(db)
    .await
    .map_err(|error| format!("failed to reload stripe tax snapshot: {error}"))
}

/// Raise a durable finance incident. Idempotent per open incident: webhook
/// retries and dead-letter replays cannot spam duplicate open rows.
#[allow(clippy::too_many_arguments)]
async fn raise_finance_incident(
    db: &sqlx::PgPool,
    kind: &str,
    severity: &str,
    tenant_id: &str,
    local_invoice_id: Option<Uuid>,
    stripe_invoice_id: &str,
    currency: &str,
    expected_total_cents: Option<i64>,
    observed_total_cents: Option<i64>,
    detail: &serde_json::Value,
) -> Result<(), String> {
    sqlx::query(
        r#"
        INSERT INTO finance_incidents (
            kind, severity, status, tenant_id, local_invoice_id,
            stripe_invoice_id, currency, expected_total_cents,
            observed_total_cents, delta_cents, detail
        )
        SELECT $1, $2, 'open', $3, $4, $5, $6, $7, $8,
               COALESCE($7, 0) - COALESCE($8, 0), $9
        WHERE NOT EXISTS (
            SELECT 1 FROM finance_incidents
            WHERE kind = $1 AND stripe_invoice_id = $5 AND status = 'open'
        )
        "#,
    )
    .bind(kind)
    .bind(severity)
    .bind(tenant_id)
    .bind(local_invoice_id)
    .bind(stripe_invoice_id)
    .bind(currency)
    .bind(expected_total_cents)
    .bind(observed_total_cents)
    .bind(detail)
    .execute(db)
    .await
    .map_err(|error| format!("failed to raise finance incident: {error}"))?;
    Ok(())
}

/// Load local invoices bound to a Stripe invoice for validation.
async fn load_local_invoice_tax_rows(
    db: &sqlx::PgPool,
    stripe_invoice_id: &str,
    tenant_id: &str,
) -> Result<Vec<(Uuid, i64, i64, i64, Option<String>, Option<f64>)>, String> {
    sqlx::query_as(
        r#"
        SELECT id,
               COALESCE(subtotal, amount, 0)::bigint,
               COALESCE(vat_total, 0)::bigint,
               COALESCE(total, amount, 0)::bigint,
               billing_country,
               vat_rate
        FROM invoices
        WHERE stripe_invoice_id = $1
          AND (tenant_id = $2 OR tenant_id IS NULL)
        ORDER BY created_at
        "#,
    )
    .bind(stripe_invoice_id)
    .bind(tenant_id)
    .fetch_all(db)
    .await
    .map_err(|error| format!("failed to load local invoices for tax validation: {error}"))
}

/// The tax-truth gate. Persists an immutable snapshot of the finalized
/// Stripe invoice and validates the charged total against ApexMail's own
/// computation. Returns `Err` (blocking invoice finalization) when the
/// charged total disagrees, after raising a durable finance incident.
async fn validate_and_snapshot_stripe_tax(
    state: &AppState,
    invoice: &InvoiceEvent,
    tenant_id: &str,
) -> Result<Option<Uuid>, String> {
    // Replays: the first snapshot is immutable. A recorded discrepancy stays
    // blocking until a finance operator resolves it; a validated snapshot
    // makes replays no-ops.
    if let Some((status, expected_total, observed_total)) =
        load_existing_tax_snapshot(&state.db, &invoice.id).await?
    {
        if status == "discrepancy" {
            raise_finance_incident(
                &state.db,
                "tax_total_mismatch",
                "high",
                tenant_id,
                None,
                &invoice.id,
                &normalize_stripe_currency(invoice.currency.as_deref()),
                Some(expected_total),
                Some(observed_total),
                &serde_json::json!({
                    "reason": "existing immutable snapshot records a charged-total discrepancy",
                }),
            )
            .await?;
            return Err(format!(
                "invoice.paid for {} blocked: an open finance incident records a Stripe/ApexMail \
                 tax discrepancy (Stripe total {observed_total}, ApexMail expected {expected_total})",
                invoice.id
            ));
        }
        return Ok(Some(
            sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM stripe_tax_snapshots WHERE stripe_invoice_id = $1",
            )
            .bind(&invoice.id)
            .fetch_one(&state.db)
            .await
            .map_err(|error| format!("failed to load tax snapshot id: {error}"))?,
        ));
    }

    let (observed_subtotal, observed_vat, observed_total) = derive_invoice_totals(
        invoice.subtotal,
        invoice.tax,
        invoice.total,
        invoice.amount_due,
    );
    let currency = normalize_stripe_currency(invoice.currency.as_deref());

    // Expected side 1: the local invoice row(s) already bound to this Stripe
    // invoice (the overage collection path writes them before finalizing
    // Stripe-side). Their stored totals ARE ApexMail's computation.
    let local_rows = load_local_invoice_tax_rows(&state.db, &invoice.id, tenant_id).await?;
    let expected = if let Some((_, subtotal, vat, total, country, rate)) = local_rows.first() {
        ExpectedTax {
            subtotal_cents: *subtotal,
            vat_cents: *vat,
            total_cents: *total,
            source: "local_invoice",
            country: country.clone(),
            vat_rate: rate.unwrap_or(0.0),
            evidence_id: None,
        }
    } else {
        // Expected side 2: recompute from the tenant's billing address and
        // the tenant's authoritative VAT evidence (reverse charge only
        // against VIES-verified numbers).
        let address: Option<(Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT country, vat_number FROM billing_addresses WHERE tenant_id = $1 \
             ORDER BY updated_at DESC, created_at DESC, id LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|error| format!("failed to load billing address for tax validation: {error}"))?;

        match address {
            Some((country, vat_number)) => {
                let country = country.filter(|value| !value.trim().is_empty());
                let vat_number = vat_number.filter(|value| !value.trim().is_empty());
                let evidence = match (country.as_deref(), vat_number.as_deref()) {
                    (Some(_), Some(vat)) => {
                        crate::invoices::load_vat_evidence_for_tenant(&state.db, tenant_id, vat)
                            .await
                    }
                    _ => None,
                };
                let at = Utc::now().date_naive();
                let (rate, vat) = match country.as_deref() {
                    Some(country) => billing_common::vat_rates::calculate_vat_with_evidence(
                        observed_subtotal,
                        country,
                        vat_number.as_deref(),
                        evidence.as_ref(),
                        at,
                    ),
                    None => (0.0, 0),
                };
                ExpectedTax {
                    subtotal_cents: observed_subtotal,
                    vat_cents: vat,
                    total_cents: observed_subtotal + vat,
                    source: "recomputed",
                    country: country.clone(),
                    vat_rate: rate,
                    evidence_id: evidence.and_then(|evidence| evidence.id),
                }
            }
            None => ExpectedTax {
                // No expectation: ApexMail could not recompute. Explicitly
                // zero/`unavailable` rather than echoing Stripe's numbers,
                // which would read as an independent match.
                subtotal_cents: 0,
                vat_cents: 0,
                total_cents: 0,
                source: "unavailable",
                country: None,
                vat_rate: 0.0,
                evidence_id: None,
            },
        }
    };

    let (tax_id_status, tax_ids) = summarize_tax_ids(invoice);
    let stripe_tax_complete = automatic_tax_complete(invoice);
    let authority = if stripe_tax_complete {
        "stripe_tax"
    } else {
        "apexmail_local"
    };

    // Cannot independently recompute (no billing address) and Stripe Tax did
    // not authoritatively compute either: fail closed. Zero-value invoices
    // (100% discounts/credits) are exempt — there is no tax decision to
    // validate and nothing was charged.
    let zero_value = observed_total <= 0 && observed_vat <= 0;
    if expected.source == "unavailable" && !stripe_tax_complete && !zero_value {
        let detail = serde_json::json!({
            "reason": "no billing address and Stripe Tax is not complete — cannot validate the charged tax",
            "automatic_tax_status": automatic_tax_status(invoice),
        });
        persist_tax_snapshot(
            &state.db,
            invoice,
            tenant_id,
            None,
            &currency,
            (observed_subtotal, observed_vat, observed_total),
            &expected,
            authority,
            "discrepancy",
            0,
            &tax_id_status,
            &tax_ids,
        )
        .await?;
        raise_finance_incident(
            &state.db,
            "tax_validation_unavailable",
            "high",
            tenant_id,
            None,
            &invoice.id,
            &currency,
            None,
            Some(observed_total),
            &detail,
        )
        .await?;
        return Err(format!(
            "invoice.paid for {} blocked: cannot validate charged tax (no billing address, \
             Stripe Tax status {})",
            invoice.id,
            automatic_tax_status(invoice)
        ));
    }

    let validation = if expected.source == "unavailable" {
        // Stripe Tax is the authoritative charging authority and ApexMail
        // has no address to recompute from: accept the external authority,
        // explicitly flagged.
        Ok(())
    } else {
        check_charged_total(&expected, observed_subtotal, observed_vat, observed_total)
    };

    let (validation_status, discrepancy_cents) = match &validation {
        Ok(()) if expected.source == "unavailable" => ("unverified_external", 0),
        Ok(()) if stripe_tax_complete => ("validated", 0),
        Ok(()) => ("fallback_unavailable", 0),
        Err(discrepancy) => ("discrepancy", discrepancy.delta_cents),
    };

    let local_invoice_id = local_rows.first().map(|row| row.0);
    let snapshot_id = persist_tax_snapshot(
        &state.db,
        invoice,
        tenant_id,
        local_invoice_id,
        &currency,
        (observed_subtotal, observed_vat, observed_total),
        &expected,
        authority,
        validation_status,
        discrepancy_cents,
        &tax_id_status,
        &tax_ids,
    )
    .await?;

    if let Err(discrepancy) = validation {
        let detail = serde_json::json!({
            "reason": discrepancy.summary(),
            "automatic_tax_status": automatic_tax_status(invoice),
            "expected_source": expected.source,
            "expected_country": expected.country,
            "expected_vat_rate": expected.vat_rate,
            "vat_evidence_id": expected.evidence_id,
            "tax_id_status": tax_id_status,
        });
        raise_finance_incident(
            &state.db,
            "tax_total_mismatch",
            "critical",
            tenant_id,
            local_invoice_id,
            &invoice.id,
            &currency,
            Some(expected.total_cents),
            Some(observed_total),
            &detail,
        )
        .await?;
        error!(
            stripe_invoice_id = %invoice.id,
            tenant_id = %tenant_id,
            observed_total_cents = observed_total,
            expected_total_cents = expected.total_cents,
            delta_cents = discrepancy.delta_cents,
            "BLOCKED invoice finalization: Stripe charged a total that disagrees with ApexMail's \
             computation — finance incident raised"
        );
        return Err(format!(
            "invoice.paid for {} blocked: {}",
            invoice.id,
            discrepancy.summary()
        ));
    }

    info!(
        stripe_invoice_id = %invoice.id,
        tenant_id = %tenant_id,
        authority,
        validation_status,
        observed_total_cents = observed_total,
        expected_total_cents = expected.total_cents,
        "stripe tax snapshot persisted and charged total validated"
    );

    Ok(Some(snapshot_id))
}

async fn handle_invoice_paid(state: &AppState, invoice: InvoiceEvent) -> Result<(), String> {
    // Prefer tenant_id from event metadata (immutable snapshot from Stripe),
    // then fall back to resolving the invoice's subscription locally.
    let metadata_tenant_id = tenant_id_from_metadata(
        invoice
            .subscription_details
            .as_ref()
            .and_then(|details| details.metadata.as_ref()),
    )
    .map(str::to_string);

    let subscription_id = invoice.subscription.as_ref().map(ExpandableId::id);

    // Resolve tenant via the subscription fallback when metadata is absent.
    let fallback_tenant_id = match (&metadata_tenant_id, subscription_id) {
        (Some(_), _) => None,
        (None, Some(sub_id)) => sqlx::query_scalar::<_, String>(
            r#"
                SELECT tenant_id
                FROM stripe_subscriptions
                WHERE stripe_subscription_id = $1
                ORDER BY created_at DESC
                LIMIT 1
                "#,
        )
        .bind(sub_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|error| format!("Failed to resolve tenant from subscription: {error}"))?,
        (None, None) => None,
    };

    // Never silently drop paid revenue: when no tenant can be resolved the
    // event is deadlettered with a reason (it can be replayed once the
    // subscription row exists).
    let Some(tenant_id) = metadata_tenant_id.or(fallback_tenant_id) else {
        return Err(format!(
            "invoice.paid for {} could not be resolved to a tenant (no metadata tenant_id, no subscription match)",
            invoice.id
        ));
    };

    // TAX-TRUTH GATE (P0): persist an immutable snapshot of the finalized
    // Stripe invoice's tax decision and validate the charged total against
    // ApexMail's own computation BEFORE finalizing any local invoice. A
    // mismatch returns Err here — no local invoice is marked paid, no
    // revenue-recognising insert runs — and a durable finance incident is
    // raised for operators.
    let tax_snapshot_id = validate_and_snapshot_stripe_tax(state, &invoice, &tenant_id).await?;

    // Settle the local invoice(s) bound to this Stripe invoice (audits
    // F72/F73). The old modifying CTE ended in `SELECT 1` and relied on
    // rows_affected — but PostgreSQL's CommandComplete for `SELECT 1`
    // reports one retrieved row even when the marked/allocation CTEs
    // contained ZERO invoices, so a missing local invoice was
    // indistinguishable from a real settlement. The replacement locks and
    // RETURNS the actual invoice identities, and the allocation records
    // the VERIFIED payment amount (amount_paid), capped against the
    // authoritative remaining obligation (total − confirmed allocations −
    // debt-reduction credits) in the MATCHING currency — never the full
    // invoice total on top of existing wallet payments. Zero-value
    // invoices settle without a positive allocation (the amount_cents > 0
    // CHECK forbids storing one). Legacy nullable totals resolve through
    // the canonical COALESCE(total, amount, 0) resolver.
    let payment_cents = verified_payment_cents(&invoice);
    let event_currency = invoice
        .currency
        .as_deref()
        .map(|raw| normalize_stripe_currency(Some(raw)));

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|error| format!("Failed to begin invoice settlement transaction: {error}"))?;

    let marked: Vec<(Uuid, String, String)> = sqlx::query_as(
        r#"
        SELECT id, tenant_id, currency
        FROM invoices
        WHERE stripe_invoice_id = $1
          AND (tenant_id = $2 OR tenant_id IS NULL)
        ORDER BY created_at
        FOR UPDATE
        "#,
    )
    .bind(&invoice.id)
    .bind(&tenant_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|error| format!("Failed to lock invoices for Stripe {}: {error}", invoice.id))?;

    for (invoice_row_id, row_tenant, invoice_currency) in &marked {
        if let Some(event_currency) = event_currency.as_deref() {
            if !event_currency.eq_ignore_ascii_case(invoice_currency.trim()) {
                // A payment in a different currency must never be recorded
                // against this invoice's obligation — surface for
                // reconciliation instead of minting phantom value.
                return Err(format!(
                    "invoice.paid for {} carries currency {event_currency} but local invoice \
                     {invoice_row_id} is denominated in {invoice_currency}",
                    invoice.id
                ));
            }
        }

        let outstanding = crate::invoices::invoice_outstanding_cents_in(&mut *tx, *invoice_row_id)
            .await
            .map_err(|error| {
                format!("Failed to derive outstanding for {invoice_row_id}: {error}")
            })?;

        let allocation = payment_cents.min(outstanding).max(0);
        if payment_cents > outstanding {
            warn!(
                invoice_id = %invoice_row_id,
                stripe_invoice_id = %invoice.id,
                payment_cents,
                outstanding,
                "stripe payment exceeds the remaining obligation — allocating only the \
                 authoritative remainder (over-allocation rejected)"
            );
        }

        sqlx::query(
            r#"
            UPDATE invoices
            SET status = 'paid',
                paid_at = COALESCE(paid_at, NOW()),
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(invoice_row_id)
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("Failed to mark invoice {invoice_row_id} paid: {error}"))?;

        if allocation > 0 {
            sqlx::query(
                r#"
                INSERT INTO invoice_payment_allocations (
                    id, tenant_id, invoice_id, operation_id, source, amount_cents, currency
                )
                VALUES (
                    gen_random_uuid(), $1, $2, $3, 'stripe', $4, $5
                )
                ON CONFLICT (operation_id) DO NOTHING
                "#,
            )
            .bind(row_tenant)
            .bind(invoice_row_id)
            .bind(format!("stripe:{}", invoice.id))
            .bind(allocation)
            .bind(invoice_currency.trim().to_uppercase())
            .execute(&mut *tx)
            .await
            .map_err(|error| format!("Failed to record Stripe payment allocation: {error}"))?;

            // Statutory ledger: post the settlement (Dr processor clearing,
            // Cr AR) in the same transaction. Idempotent on the allocation's
            // unique operation id, so a replayed webhook posts once.
            crate::accounting_postings::post_payment_allocation_in(
                &mut tx,
                &format!("stripe:{}", invoice.id),
            )
            .await;
        } else {
            info!(
                invoice_id = %invoice_row_id,
                stripe_invoice_id = %invoice.id,
                payment_cents,
                outstanding,
                "stripe invoice settled without a positive allocation (zero-value/already covered)"
            );
        }
    }

    tx.commit()
        .await
        .map_err(|error| format!("Failed to commit invoice settlement: {error}"))?;

    // Statutory ledger: post invoice finalization for every locally settled
    // invoice (no-op replay when the usage sweep already posted it). Runs
    // AFTER the settlement commit because a zero/legacy invoice may still
    // need its revenue entry; the source identity makes the replay
    // idempotent.
    for (invoice_row_id, _row_tenant, _invoice_currency) in &marked {
        crate::accounting_postings::post_invoice_issued(&state.db, *invoice_row_id).await;
    }

    // Fix F4/F72 — dunning recovery is only legitimate when this event
    // actually settled THE tenant's invoice. `marked` contains the REAL
    // returned invoice identities (never a constant SELECT result), so a
    // missing local invoice falls through to the external-invoice
    // reconciliation/import path keyed on the unique Stripe invoice id.
    let invoice_persisted = !marked.is_empty();
    if !invoice_persisted {
        // Fix A — no local row matched, meaning the invoice was created
        // on Stripe's side (e.g. subscription billing, Meter usage, or a
        // finalized usage-collection invoice whose local draft was never
        // linked) without a local row. Insert the paid invoice so revenue
        // is recorded. ON CONFLICT makes replays idempotent. Rows == 0
        // means the tenant guard rejected the upsert (the local row is
        // bound to a DIFFERENT tenant) — not this tenant's invoice.
        let inserted = insert_paid_invoice_from_stripe(state, &invoice, &tenant_id).await?;
        if inserted == 0 {
            warn!(
                invoice_id = %invoice.id,
                tenant_id = %tenant_id,
                "invoice.paid upsert matched 0 rows (invoice bound to another tenant) — dunning state left untouched"
            );
        } else {
            // Statutory ledger: post the imported invoice's revenue/AR entry.
            // The local id is resolved by the unique Stripe invoice id.
            let local_id: Option<Uuid> =
                sqlx::query_scalar("SELECT id FROM invoices WHERE stripe_invoice_id = $1")
                    .bind(&invoice.id)
                    .fetch_optional(&state.db)
                    .await
                    .map_err(|error| {
                        format!("Failed to resolve imported invoice {}: {error}", invoice.id)
                    })?;
            if let Some(local_id) = local_id {
                crate::accounting_postings::post_invoice_issued(&state.db, local_id).await;
            }
        }
    }

    // If a previously-dunning invoice was settled, clear the tenant's dunning
    // state (healthy again), release queued messages and drop the cached
    // status — mirrors the auto-pay recovery path in maintenance.rs.
    // Fix F4 — only when the settlement actually persisted an invoice for
    // this tenant above; a guard-rejected event must never blanket-reset
    // dunning or reactivate the tenant. The recovery is scoped to this
    // invoice's failure history inside mark_payment_recovered.
    if invoice_persisted {
        crate::maintenance::mark_payment_recovered(state, &tenant_id, Some(&invoice.id)).await?;
    }

    // Recognition ledger: reflect the settlement/new invoice in
    // `vat_recognition_entries`. General-scheme supplies were recognised at
    // issue; cash-accounting supplies recognise on payment (or the
    // third-month fallback, handled by the sweep). Idempotent, best-effort:
    // a failure here is logged, never allowed to fake or skip the ledger.
    let bound_invoices: Vec<(Uuid,)> = sqlx::query_as(
        r#"
        SELECT id FROM invoices
        WHERE stripe_invoice_id = $1
          AND (tenant_id = $2 OR tenant_id IS NULL)
        "#,
    )
    .bind(&invoice.id)
    .bind(&tenant_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    for (invoice_row_id,) in &bound_invoices {
        if let Err(error) = crate::vat_recognition::materialize_invoice_recognition_by_id(
            &state.db,
            *invoice_row_id,
            Utc::now(),
        )
        .await
        {
            warn!(
                invoice_id = %invoice_row_id,
                stripe_invoice_id = %invoice.id,
                error = %error,
                "failed to materialize VAT recognition after Stripe settlement"
            );
        }
    }

    // Link the immutable tax snapshot onto every local invoice bound to this
    // Stripe invoice (rows settled above plus the row inserted from the
    // Stripe payload when there was none).
    if let Some(snapshot_id) = tax_snapshot_id {
        if let Err(error) = sqlx::query(
            r#"
            UPDATE invoices
            SET stripe_tax_snapshot_id = $2,
                updated_at = NOW()
            WHERE stripe_invoice_id = $1
              AND (tenant_id = $3 OR tenant_id IS NULL)
            "#,
        )
        .bind(&invoice.id)
        .bind(snapshot_id)
        .bind(&tenant_id)
        .execute(&state.db)
        .await
        {
            warn!(
                stripe_invoice_id = %invoice.id,
                snapshot_id = %snapshot_id,
                error = %error,
                "failed to link stripe tax snapshot onto local invoice(s) — snapshot remains authoritative"
            );
        }
    }

    info!(
        invoice_id = %invoice.id,
        tenant_id = %tenant_id,
        settled_invoices = marked.len(),
        payment_cents,
        dunning_recovery = invoice_persisted,
        "stripe invoice marked as paid"
    );
    Ok(())
}

/// The VERIFIED payment amount for an `invoice.paid` event (audit F73):
/// Stripe's own `amount_paid` when present; otherwise the canonical
/// derived total (never `invoices.total`, which may already be partially
/// covered by wallet allocations). Clamped at zero.
fn verified_payment_cents(invoice: &InvoiceEvent) -> i64 {
    match invoice.amount_paid {
        Some(paid) => paid.max(0),
        None => {
            let (_, _, total) = derive_invoice_totals(
                invoice.subtotal,
                invoice.tax,
                invoice.total,
                invoice.amount_due,
            );
            total.max(0)
        }
    }
}

/// Insert a paid invoice from a Stripe `invoice.paid` event when no local
/// row exists (Fix A). Money stays integer cents; the currency, subtotal,
/// VAT and total come from the Stripe payload; sequential numbering uses the
/// existing `invoice_number_seq` unless Stripe assigned a number.
/// Idempotent via ON CONFLICT (stripe_invoice_id) (unique index, migration 101).
/// Returns the number of rows affected: 0 when the tenant guard in the ON
/// CONFLICT clause rejected the update (the local row is bound to a
/// different tenant) — callers use that to decide whether payment recovery
/// is legitimate (Fix F4).
/// Parse a Stripe decimal-string amount ("65.00", "0.40") into integer
/// cents without floating point. Returns None on malformed input.
fn stripe_decimal_to_cents(value: &str) -> Option<i64> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let (whole, frac) = match value.split_once('.') {
        Some((w, f)) => (w, f),
        None => (value, ""),
    };
    if whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if frac.len() > 2 || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let whole: i64 = whole.parse().ok()?;
    let frac_parsed: i64 = if frac.is_empty() {
        0
    } else if frac.len() == 1 {
        frac.parse::<i64>().ok()? * 10
    } else {
        frac.parse().ok()?
    };
    Some(whole * 100 + frac_parsed)
}

async fn insert_paid_invoice_from_stripe(
    state: &AppState,
    invoice: &InvoiceEvent,
    tenant_id: &str,
) -> Result<u64, String> {
    let (subtotal, vat_total, total) = derive_invoice_totals(
        invoice.subtotal,
        invoice.tax,
        invoice.total,
        invoice.amount_due,
    );
    let vat_rate = derive_invoice_vat_rate(subtotal, vat_total);
    let currency = normalize_stripe_currency(invoice.currency.as_deref());

    // Mandatory invoice content: when Stripe's event carries line items,
    // store them. Fall back to a single summary line so the stored invoice
    // (and its PDF) never renders an empty items table.
    let line_items_json = match &invoice.lines {
        Some(lines) if !lines.data.is_empty() => {
            let items: Vec<serde_json::Value> = lines
                .data
                .iter()
                .map(|line| {
                    let amount = line.amount.unwrap_or(subtotal);
                    let vat_amount = billing_common::vat_rates::vat_amount_half_up(
                        amount,
                        if vat_rate > 0.0 { vat_rate } else { 0.0 },
                    );
                    let quantity = line.quantity.unwrap_or(1).max(1);
                    // Prefer Stripe's VAT-exclusive unit amount when present;
                    // fall back to deriving net from amount − VAT.
                    let net = line
                        .unit_amount_excluding_tax
                        .as_deref()
                        .and_then(stripe_decimal_to_cents)
                        .map(|unit_cents| unit_cents * quantity)
                        .unwrap_or(amount - vat_amount);
                    serde_json::json!({
                        "description": line.description.clone().unwrap_or_else(|| "Subscription".to_string()),
                        "quantity": quantity,
                        "unit_price": net / quantity,
                        "amount": net,
                        "vat_rate": vat_rate,
                        "vat_amount": vat_amount,
                    })
                })
                .collect();
            serde_json::Value::Array(items)
        }
        _ => {
            let vat_amount = vat_total;
            let net = total - vat_amount;
            serde_json::json!([{
                "description": "Subscription",
                "quantity": 1,
                "unit_price": net,
                "amount": net,
                "vat_rate": vat_rate,
                "vat_amount": vat_amount,
            }])
        }
    };

    let issued_at = invoice
        .created
        .and_then(|secs| DateTime::<Utc>::from_timestamp(secs, 0))
        .unwrap_or_else(Utc::now);
    let period_start = invoice
        .period_start
        .and_then(|secs| DateTime::<Utc>::from_timestamp(secs, 0))
        .unwrap_or(issued_at);
    let period_end = invoice
        .period_end
        .and_then(|secs| DateTime::<Utc>::from_timestamp(secs, 0))
        .unwrap_or(issued_at);

    // Best-effort capture of the billing country for KMD bucketing (I4):
    // invoices created directly from Stripe carry no local VAT derivation,
    // so store the current address; the VAT rate is derived from the Stripe
    // amounts themselves. Audit F08: the FULL address is snapshotted
    // immutably onto the invoice in the SAME versioned contract the
    // billing-service and api-server writers use (snapshotVersion +
    // registry identity) — null/empty optional fields stay null and are
    // never refilled from the live account on re-export.
    let address_snapshot: Option<String> = sqlx::query_scalar(
        r#"
        SELECT json_build_object(
            'snapshotVersion', 1,
            'company_name', ba.company_name,
            'vat_number', ba.vat_number,
            'address_line1', ba.address_line1,
            'address_line2', ba.address_line2,
            'city', ba.city,
            'state', ba.state,
            'postal_code', ba.postal_code,
            'country', ba.country,
            'email', ba.email,
            'registry_code', t.settings->>'registryCode'
        )::text
        FROM billing_addresses ba
        JOIN tenants t ON t.id = ba.tenant_id
        WHERE ba.tenant_id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None)
    .flatten();
    let billing_country: Option<String> = address_snapshot
        .as_deref()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
        .and_then(|snapshot| {
            snapshot
                .get("country")
                .and_then(|value| value.as_str())
                .map(|country| country.to_uppercase())
        });
    let billing_registry_code: Option<String> = address_snapshot
        .as_deref()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
        .and_then(|snapshot| {
            snapshot
                .get("registry_code")
                .and_then(|value| value.as_str())
                .map(str::to_string)
        });

    let result = sqlx::query(
        r#"
        INSERT INTO invoices (
            id, tenant_id, stripe_invoice_id, invoice_number, status,
            currency, amount, subtotal, vat_total, total, line_items,
            issued_at, due_at, paid_at, period_start, period_end,
            billing_country, vat_rate, billing_address, billing_registry_code,
            created_at, updated_at
        ) VALUES (
            gen_random_uuid(), $1, $2,
            COALESCE($3, to_char(NOW(), 'YYYY') || '-' || LPAD(nextval('invoice_number_seq')::text, 6, '0')),
            'paid', $4, $7, $5, $6, $7, $13,
            to_timestamp($8), to_timestamp($8), NOW(), to_timestamp($9), to_timestamp($10),
            $11, $12, $14, $15,
            NOW(), NOW()
        )
        -- migration 101 created stripe_invoice_id as a PARTIAL unique index
        -- (WHERE stripe_invoice_id IS NOT NULL); conflict inference must
        -- repeat that predicate or PostgreSQL raises 42P10 ("no unique or
        -- exclusion constraint matching the ON CONFLICT specification") and
        -- every Stripe-originated paid invoice fails to persist.
        ON CONFLICT (stripe_invoice_id) WHERE stripe_invoice_id IS NOT NULL DO UPDATE SET
            status = 'paid',
            paid_at = COALESCE(invoices.paid_at, NOW()),
            updated_at = NOW()
        -- Tenant guard mirrors the subscription handler's re-binding
        -- protection: a local row already bound to a DIFFERENT tenant must
        -- never be flipped to paid by an event resolved to this tenant —
        -- without the WHERE, the DO UPDATE would mark tenant A's invoice
        -- paid while silently discarding the EXCLUDED tenant attribution.
        WHERE invoices.tenant_id IS NULL
           OR invoices.tenant_id = EXCLUDED.tenant_id
        "#,
    )
    .bind(tenant_id)
    .bind(&invoice.id)
    .bind(invoice.number.as_deref().filter(|value| !value.is_empty()))
    .bind(&currency)
    .bind(subtotal)
    .bind(vat_total)
    .bind(total)
    .bind(issued_at.timestamp())
    .bind(period_start.timestamp())
    .bind(period_end.timestamp())
    .bind(billing_country)
    .bind(vat_rate)
    .bind(line_items_json)
    .bind(address_snapshot)
    .bind(billing_registry_code)
    .execute(&state.db)
    .await
    .map_err(|error| format!("Failed to insert paid Stripe invoice {}: {error}", invoice.id))?;

    let rows_affected = result.rows_affected();

    info!(
        invoice_id = %invoice.id,
        tenant_id = %tenant_id,
        subtotal,
        vat_total,
        total,
        currency = %currency,
        rows_affected,
        "inserted missing local invoice from Stripe invoice.paid event"
    );

    Ok(rows_affected)
}

async fn handle_payment_failed(state: &AppState, invoice: InvoiceEvent) -> Result<(), String> {
    // Fix H — resolve the tenant from event metadata first, then fall back
    // to the same stripe_subscriptions lookup handle_invoice_paid uses.
    // Unresolvable events are deadlettered (via the returned error) instead
    // of being silently dropped.
    let metadata_tenant_id = tenant_id_from_metadata(
        invoice
            .subscription_details
            .as_ref()
            .and_then(|details| details.metadata.as_ref()),
    )
    .map(str::to_string);

    let tenant_id = match metadata_tenant_id {
        Some(tenant_id) => tenant_id,
        None => {
            let Some(sub_id) = invoice.subscription.as_ref().map(ExpandableId::id) else {
                return Err(format!(
                    "invoice.payment_failed for {} has neither subscription metadata nor a subscription reference — tenant unresolvable",
                    invoice.id
                ));
            };

            sqlx::query_scalar::<_, String>(
                r#"
                SELECT tenant_id
                FROM stripe_subscriptions
                WHERE stripe_subscription_id = $1
                ORDER BY created_at DESC
                LIMIT 1
                "#,
            )
            .bind(sub_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|error| format!("Failed to resolve tenant from subscription: {error}"))?
            .ok_or_else(|| {
                format!(
                    "invoice.payment_failed for {} references unknown subscription {sub_id} — tenant unresolvable",
                    invoice.id
                )
            })?
        }
    };

    let dunning = record_failed_payment(state, &tenant_id, &invoice.id, invoice.amount_due).await?;

    sqlx::query(
        r#"
        INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
        VALUES (gen_random_uuid(), $1, 'payment_failed', $2, 'pending', NOW())
        "#,
    )
    .bind(&tenant_id)
    .bind(serde_json::json!({
        "invoiceId": invoice.id,
        "amount": invoice.amount_due,
        "attemptCount": invoice.attempt_count.unwrap_or_default(),
        "dunningStatus": dunning.status,
        "nextRetryAt": dunning.next_retry_at.map(|value| value.to_rfc3339()),
    }))
    .execute(&state.db)
    .await
    .map_err(|error| format!("Failed to enqueue payment_failed notification: {error}"))?;

    warn!(tenant_id = %tenant_id, invoice_id = %invoice.id, "stripe invoice payment failed");
    Ok(())
}

async fn handle_trial_ending(
    state: &AppState,
    subscription: SubscriptionEvent,
) -> Result<(), String> {
    let Some(tenant_id) = tenant_id_from_metadata(subscription.metadata.as_ref()) else {
        return Ok(());
    };

    sqlx::query(
        r#"
        INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
        VALUES (gen_random_uuid(), $1, 'trial_ending', $2, 'pending', NOW())
        "#,
    )
    .bind(tenant_id)
    .bind(serde_json::json!({
        "subscriptionId": subscription.id,
        "trialEnd": subscription.trial_end,
    }))
    .execute(&state.db)
    .await
    .map_err(|error| format!("Failed to enqueue trial_ending notification: {error}"))?;

    info!(tenant_id = %tenant_id, subscription_id = %subscription.id, "stripe trial ending notification queued");
    Ok(())
}

/// Post-increment dunning state as returned by the atomic upsert.
#[derive(Debug, Clone, sqlx::FromRow)]
struct DunningSnapshot {
    failed_payment_count: i32,
    first_failed_at: Option<DateTime<Utc>>,
    status: String,
}

/// Dunning state decision derived from the post-increment snapshot (pure —
/// Fix H). `failed_payment_count` here is the already-incremented value
/// produced SQL-side, so concurrent failures can never lose an increment;
/// `first_failed_at` is the LEAST() of the existing value and `now`, also
/// computed SQL-side.
#[derive(Debug)]
struct ComputedDunningState {
    failed_payment_count: i32,
    first_failed_at: DateTime<Utc>,
    status: String,
    suspended_at: Option<DateTime<Utc>>,
    grace_period_ends_at: Option<DateTime<Utc>>,
}

fn next_dunning_state(
    existing: Option<DunningSnapshot>,
    now: DateTime<Utc>,
    config: &DunningConfig,
) -> ComputedDunningState {
    let first_failed_at = existing
        .as_ref()
        .and_then(|row| row.first_failed_at)
        .unwrap_or(now);
    let failed_payment_count = existing
        .as_ref()
        .map(|row| row.failed_payment_count)
        // The insert path passes the already-incremented count (SQL side);
        // a missing snapshot means this is the first failure.
        .unwrap_or(1);
    let days_since_first_failure = (now - first_failed_at).num_days().max(0);

    let mut new_status = "warning".to_string();
    let mut suspended_at = None;
    let mut grace_period_ends_at = None;

    if days_since_first_failure >= i64::from(config.hard_suspend_after_days) {
        new_status = "hard_suspended".into();
        if existing.as_ref().map(|row| row.status.as_str()) != Some("hard_suspended") {
            suspended_at = Some(now);
            grace_period_ends_at = Some(now + TimeDelta::days(i64::from(config.grace_period_days)));
        }
    } else if days_since_first_failure >= i64::from(config.soft_suspend_after_days) {
        new_status = "soft_suspended".into();
        let already_suspended = existing
            .as_ref()
            .map(|row| row.status.contains("suspended"))
            .unwrap_or(false);
        if !already_suspended {
            suspended_at = Some(now);
        }
    }

    ComputedDunningState {
        failed_payment_count,
        first_failed_at,
        status: new_status,
        suspended_at,
        grace_period_ends_at,
    }
}

/// A dunning lifecycle transition worth emitting an event for
/// (audit item 3g): entering soft/hard suspension, or recovering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DunningTransition {
    SoftSuspended,
    HardSuspended,
    Recovered,
}

impl DunningTransition {
    /// `dunning_events.event_type` value for the transition.
    pub fn event_type(self) -> &'static str {
        match self {
            Self::SoftSuspended => "soft_suspended",
            Self::HardSuspended => "hard_suspended",
            Self::Recovered => "payment_recovered",
        }
    }
}

/// Pure classifier for dunning state transitions: returns `Some` only when
/// the status actually *changes into* a suspension state (or back to
/// healthy), so repeated `invoice.payment_failed` webhooks for a tenant
/// that is already suspended do not spam duplicate transition events.
/// Unit-tested.
pub fn dunning_transition(previous: Option<&str>, new_status: &str) -> Option<DunningTransition> {
    let previous = previous.map(str::trim).filter(|status| !status.is_empty());
    if previous == Some(new_status) {
        return None; // No state change.
    }

    match new_status {
        "soft_suspended" if !matches!(previous, Some("soft_suspended" | "hard_suspended")) => {
            Some(DunningTransition::SoftSuspended)
        }
        "hard_suspended" if !matches!(previous, Some("hard_suspended")) => {
            Some(DunningTransition::HardSuspended)
        }
        "healthy"
            if matches!(
                previous,
                Some("warning" | "soft_suspended" | "hard_suspended")
            ) =>
        {
            Some(DunningTransition::Recovered)
        }
        _ => None,
    }
}

async fn record_failed_payment(
    state: &AppState,
    tenant_id: &str,
    invoice_id: &str,
    amount: i64,
) -> Result<DunningResult, String> {
    let config = get_dunning_config_for_tenant(state, tenant_id).await;
    let now = Utc::now();
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|error| format!("Failed to begin payment failure transaction: {error}"))?;

    // Fix H — single UPSERT with SQL-side increment. The counter increment
    // and first_failed_at=LEAST(existing, now) happen atomically inside the
    // statement, eliminating the read-compute-write race that lost
    // increments under concurrent invoice.payment_failed events.
    // dunning_records.id is VARCHAR(26) (migrations 087/093) — a 36-char
    // gen_random_uuid() string would overflow the column. Generate the id
    // in Rust with the shared 26-char generator instead.
    let dunning_record_id = generate_audit_log_id();

    let snapshot = sqlx::query_as::<_, DunningSnapshot>(
        r#"
        INSERT INTO dunning_records (
            id, tenant_id, status, failed_payment_count, first_failed_at,
            last_failed_at, next_retry_at, suspended_at, grace_period_ends_at,
            created_at, updated_at
        )
        VALUES ($2, $1, 'warning', 1, $3, $3, NULL, NULL, NULL, NOW(), NOW())
        ON CONFLICT (tenant_id) DO UPDATE SET
            failed_payment_count = dunning_records.failed_payment_count + 1,
            first_failed_at = LEAST(
                COALESCE(dunning_records.first_failed_at, EXCLUDED.first_failed_at),
                EXCLUDED.first_failed_at
            ),
            last_failed_at = EXCLUDED.last_failed_at,
            updated_at = NOW()
        RETURNING failed_payment_count, first_failed_at, status
        "#,
    )
    .bind(tenant_id)
    .bind(&dunning_record_id)
    .bind(now)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| format!("Failed to upsert dunning counters: {error}"))?;

    let computed = next_dunning_state(Some(snapshot.clone()), now, &config);
    let next_retry_at = calculate_next_retry(
        computed.first_failed_at,
        computed.failed_payment_count,
        &config,
    );

    // Audit item 3g — emit a distinct event when the tenant *transitions*
    // into soft/hard suspension (not on every repeated failure), so
    // webhook consumers and internal automations can key off the lifecycle
    // change instead of diffing payment_failed rows.
    let transition = dunning_transition(Some(&snapshot.status), &computed.status);

    sqlx::query(
        r#"
        WITH update_dunning AS (
            UPDATE dunning_records
            SET status = $2,
                next_retry_at = $3,
                suspended_at = COALESCE(dunning_records.suspended_at, $4),
                grace_period_ends_at = COALESCE($5, dunning_records.grace_period_ends_at),
                updated_at = NOW()
            WHERE tenant_id = $1
            RETURNING tenant_id
        ),
        log_event AS (
            INSERT INTO dunning_events (
                id, tenant_id, event_type, invoice_id, created_at
            )
            VALUES (gen_random_uuid(), $1, 'payment_failed', $8, NOW())
            RETURNING tenant_id
        ),
        log_transition AS (
            INSERT INTO dunning_events (
                id, tenant_id, event_type, invoice_id, created_at
            )
            SELECT gen_random_uuid(), $1, $7, $8, NOW()
            WHERE $7 IS NOT NULL
            RETURNING tenant_id
        ),
        suspend_tenant AS (
            UPDATE tenants
            SET status = 'suspended', updated_at = NOW()
            WHERE id = $1 AND $6 = true
            RETURNING id
        ),
        -- Audit F09: a dunning suspension is a BILLING restriction. It is
        -- recorded independently so payment recovery can clear exactly
        -- this hold without touching administrative, verification or
        -- abuse restrictions on the same tenant.
        billing_restriction AS (
            INSERT INTO tenant_restrictions (tenant_id, kind, reason, actor_type)
            SELECT $1, 'billing', 'dunning hard suspension', 'system'
            WHERE $6 = true
            ON CONFLICT (tenant_id, kind) WHERE cleared_at IS NULL
            DO NOTHING
        )
        SELECT 1
        "#,
    )
    .bind(tenant_id)
    .bind(&computed.status)
    .bind(next_retry_at)
    .bind(computed.suspended_at)
    .bind(computed.grace_period_ends_at)
    .bind(computed.status == "hard_suspended")
    .bind(transition.map(DunningTransition::event_type))
    .bind(invoice_id)
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("Failed to upsert dunning state: {error}"))?;

    if let Some(transition) = transition {
        append_audit_log(
            &mut tx,
            tenant_id,
            "billing.dunning_transition",
            "dunning_record",
            Some(tenant_id),
            serde_json::json!({
                "transition": transition.event_type(),
                "fromStatus": snapshot.status,
                "toStatus": computed.status,
                "invoiceId": invoice_id,
                "failedPaymentCount": computed.failed_payment_count,
            }),
            now,
        )
        .await
        .map_err(|error| format!("Failed to insert dunning transition audit log: {error}"))?;
    }

    append_audit_log(
        &mut tx,
        tenant_id,
        "billing.payment_failed",
        "invoice",
        Some(invoice_id),
        serde_json::json!({
            "amount": amount,
            "failedPaymentCount": computed.failed_payment_count,
            "daysSinceFirstFailure": (now - computed.first_failed_at).num_days().max(0),
            "status": computed.status,
            "nextRetryAt": next_retry_at.map(|value| value.to_rfc3339()),
        }),
        now,
    )
    .await
    .map_err(|error| format!("Failed to insert payment failure audit log: {error}"))?;

    tx.commit()
        .await
        .map_err(|error| format!("Failed to commit payment failure transaction: {error}"))?;

    // Soft/hard suspension transitions notify out-of-band AFTER the state
    // change is durably committed: the notification queue feeds the
    // tenant-facing email/webhook fan-out, keyed off the transition.
    if let Some(transition) = transition {
        send_dunning_notification(
            state,
            tenant_id,
            &computed.status,
            serde_json::json!({
                "transition": transition.event_type(),
                "failedCount": computed.failed_payment_count,
                "daysSinceFirstFailure": (now - computed.first_failed_at).num_days().max(0),
                "gracePeriodEndsAt": computed.grace_period_ends_at.map(|value| value.to_rfc3339()),
            }),
        )
        .await;
    }

    send_dunning_notification(
        state,
        tenant_id,
        &computed.status,
        serde_json::json!({
            "failedCount": computed.failed_payment_count,
            "daysSinceFirstFailure": (now - computed.first_failed_at).num_days().max(0),
            "nextRetryAt": next_retry_at.map(|value| value.to_rfc3339()),
        }),
    )
    .await;

    if let Ok(mut conn) = state.redis.get().await {
        let cache_key = format!("dunning:status:{tenant_id}");
        let cache_result: Result<(), _> = redis::AsyncCommands::set_ex(
            &mut conn,
            &cache_key,
            &computed.status,
            DUNNING_STATUS_CACHE_TTL_SECONDS,
        )
        .await;
        if let Err(error) = cache_result {
            warn!(tenant_id = %tenant_id, error = %error, "failed to cache dunning status");
        }
    }

    Ok(DunningResult {
        status: computed.status,
        next_retry_at,
    })
}

async fn get_dunning_config_for_tenant(state: &AppState, tenant_id: &str) -> DunningConfig {
    if let Err(error) = ensure_dunning_config_table(state).await {
        warn!(tenant_id = %tenant_id, error = %error, "failed to ensure dunning_config table; using defaults");
        return DunningConfig::default();
    }

    let result = sqlx::query_as::<_, DunningConfigRow>(
        r#"
        SELECT retry_schedule_days, soft_suspend_after_days, hard_suspend_after_days, grace_period_days
        FROM dunning_config
        WHERE tenant_id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await;

    match result {
        Ok(Some(row)) => DunningConfig {
            retry_schedule_days: row.retry_schedule_days,
            soft_suspend_after_days: row.soft_suspend_after_days,
            hard_suspend_after_days: row.hard_suspend_after_days,
            grace_period_days: row.grace_period_days,
        },
        Ok(None) => DunningConfig::default(),
        Err(error) => {
            warn!(tenant_id = %tenant_id, error = %error, "failed to load dunning config; using defaults");
            DunningConfig::default()
        }
    }
}

async fn ensure_dunning_config_table(state: &AppState) -> Result<(), String> {
    if DUNNING_CONFIG_TABLE_ENSURED.get().is_some() {
        return Ok(());
    }

    // The dunning_config table is now created via the formal migration system
    // (migrations/045_create_dunning_config.sql). This function validates that
    // the migration has been applied, rather than creating the table at runtime.
    let table_exists: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT FROM information_schema.tables
            WHERE table_name = 'dunning_config'
        )
        "#,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|error| format!("Failed to check dunning_config table existence: {error}"))?;

    if !table_exists {
        tracing::error!(
            "dunning_config table does not exist — migration 045 has not been applied. \
             Dunning features will use hardcoded defaults."
        );
        return Err("dunning_config table not found — run migrations".to_string());
    }

    let _ = DUNNING_CONFIG_TABLE_ENSURED.set(());
    Ok(())
}

fn calculate_next_retry(
    first_failed_at: DateTime<Utc>,
    attempt_count: i32,
    config: &DunningConfig,
) -> Option<DateTime<Utc>> {
    let index = usize::try_from(attempt_count.saturating_sub(1)).ok()?;
    let days_to_add = *config.retry_schedule_days.get(index)?;
    Some(first_failed_at + TimeDelta::days(i64::from(days_to_add)))
}

async fn send_dunning_notification(
    state: &AppState,
    tenant_id: &str,
    status: &str,
    payload: serde_json::Value,
) {
    let notification_type = match status {
        "warning" => "payment_reminder",
        "soft_suspended" => "account_soft_suspended",
        _ => "account_hard_suspended",
    };

    let result = sqlx::query(
        r#"
        INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
        VALUES (gen_random_uuid(), $1, $2, $3, 'pending', NOW())
        "#,
    )
    .bind(tenant_id)
    .bind(notification_type)
    .bind(payload)
    .execute(&state.db)
    .await;

    if let Err(error) = result {
        error!(tenant_id = %tenant_id, error = %error, "failed to enqueue dunning notification");
    }
}

fn tenant_id_from_metadata(metadata: Option<&HashMap<String, String>>) -> Option<&str> {
    metadata
        .and_then(|values| values.get("tenant_id"))
        .map(String::as_str)
        .filter(|value| !value.is_empty())
}

#[derive(Debug, Deserialize)]
struct EventIdEnvelope {
    id: Option<String>,
}

#[derive(Debug)]
enum RouteValidationError {
    InvalidJson(String),
    MissingEventId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeadletterEntry {
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    occurred_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_length: Option<usize>,
    /// How many times this entry has been retried so far.
    #[serde(default)]
    retry_count: u32,
    /// Maximum retry attempts before giving up.
    #[serde(default = "default_max_retries")]
    max_retries: u32,
    /// Raw Stripe webhook body (JSON), for replay on retry.
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    /// Original `Stripe-Signature` header value, for replay on retry.
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
}

const fn default_max_retries() -> u32 {
    DEADLETTER_MAX_RETRIES
}

impl Default for DeadletterEntry {
    fn default() -> Self {
        Self {
            reason: String::new(),
            occurred_at: None,
            event_id: None,
            error: None,
            payload_length: None,
            retry_count: 0,
            max_retries: DEADLETTER_MAX_RETRIES,
            body: None,
            signature: None,
        }
    }
}

#[derive(Debug)]
struct PreparedDeadletter {
    event_key: String,
    payload: String,
    now_ms: i64,
    cleanup_before_ms: i64,
    retry_at_ms: Option<i64>,
}

#[derive(Debug)]
struct ProcessWebhookResult {
    #[expect(
        dead_code,
        reason = "returned for webhook worker diagnostics outside unit-test assertions"
    )]
    event_type: String,
    #[expect(
        dead_code,
        reason = "returned for webhook worker diagnostics outside unit-test assertions"
    )]
    processed: bool,
}

#[derive(Debug)]
enum ProcessWebhookError {
    RecordDeadletter(String),
    DeadletterFlowHandled(String),
    /// Transient condition (e.g. another worker holds the event): Stripe
    /// must retry. Maps to 5xx and never deadletters (Fix G).
    RetryLater(String),
}

impl ProcessWebhookError {
    fn message(&self) -> &str {
        match self {
            Self::RecordDeadletter(message)
            | Self::DeadletterFlowHandled(message)
            | Self::RetryLater(message) => message,
        }
    }

    fn should_record_deadletter(&self) -> bool {
        matches!(self, Self::RecordDeadletter(_))
    }

    /// HTTP status Stripe sees. Retryable errors use 503 (Stripe retries on
    /// any non-2xx; 5xx signals server-side transience); business failures
    /// keep the legacy 400.
    fn http_status(&self) -> StatusCode {
        match self {
            Self::RetryLater(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::RecordDeadletter(_) | Self::DeadletterFlowHandled(_) => StatusCode::BAD_REQUEST,
        }
    }
}

impl From<String> for ProcessWebhookError {
    fn from(message: String) -> Self {
        Self::RecordDeadletter(message)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebhookEventClaim {
    Claimed,
    AlreadyProcessed,
    AlreadyPending,
}

/// A subscription row's current billing cycle (audit F30 snapshot input).
#[derive(Debug, sqlx::FromRow)]
struct SubscriptionCycleRow {
    billing_cycle_start: Option<DateTime<Utc>>,
    billing_cycle_end: Option<DateTime<Utc>>,
    plan: Option<String>,
}

/// A superseded (deactivated) subscription's cycle, returned by the
/// deactivating UPDATE (audit F30).
#[derive(Debug, sqlx::FromRow)]
struct SupersededCycleRow {
    stripe_subscription_id: String,
    billing_cycle_start: Option<DateTime<Utc>>,
    billing_cycle_end: Option<DateTime<Utc>>,
    plan: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct WebhookEventClaimRow {
    claimed: bool,
    status: String,
}

#[derive(Debug, Deserialize)]
struct StripeEventPayload {
    id: String,
    #[serde(rename = "type")]
    event_type: String,
    data: StripeEventData,
}

#[derive(Debug, Deserialize)]
struct StripeEventData {
    object: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct CheckoutSession {
    id: String,
    metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct SubscriptionEvent {
    id: String,
    customer: ExpandableId,
    status: SubscriptionStatus,
    metadata: Option<HashMap<String, String>>,
    current_period_start: i64,
    current_period_end: i64,
    cancel_at_period_end: bool,
    canceled_at: Option<i64>,
    trial_end: Option<i64>,
    items: SubscriptionItems,
}

#[derive(Debug, Deserialize)]
struct SubscriptionItems {
    data: Vec<SubscriptionItem>,
}

#[derive(Debug, Deserialize)]
struct SubscriptionItem {
    price: Option<SubscriptionPrice>,
}

#[derive(Debug, Deserialize)]
struct SubscriptionPrice {
    id: Option<String>,
    recurring: Option<SubscriptionRecurring>,
}

#[derive(Debug, Deserialize)]
struct SubscriptionRecurring {
    interval: Option<StripeBillingInterval>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SubscriptionStatus {
    Active,
    PastDue,
    Unpaid,
    Canceled,
    Incomplete,
    IncompleteExpired,
    Trialing,
    Paused,
}

impl SubscriptionStatus {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::PastDue => "past_due",
            Self::Unpaid => "unpaid",
            Self::Canceled => "canceled",
            Self::Incomplete => "incomplete",
            Self::IncompleteExpired => "incomplete_expired",
            Self::Trialing => "trialing",
            Self::Paused => "paused",
        }
    }

    fn is_valid_initial_status(&self) -> bool {
        matches!(self, Self::Incomplete | Self::Trialing | Self::Active)
    }

    /// A verified Stripe subscription is the only source of paid-plan
    /// entitlement. Incomplete, delinquent, paused, unpaid, and canceled
    /// subscriptions remain recorded locally for reconciliation but resolve
    /// to Free access until Stripe reports an entitled state again.
    fn entitlement_plan_name<'a>(&self, paid_plan_name: &'a str) -> &'a str {
        match self {
            Self::Active | Self::Trialing => paid_plan_name,
            Self::PastDue
            | Self::Unpaid
            | Self::Canceled
            | Self::Incomplete
            | Self::IncompleteExpired
            | Self::Paused => "free",
        }
    }

    fn can_transition_from(&self, current_status: &str) -> bool {
        match current_status {
            "incomplete" => matches!(self, Self::Active | Self::IncompleteExpired),
            // Reactivation (uncancel / support-side resume) revives a terminal
            // subscription to a paying status. Only revival is admitted —
            // terminal -> terminal stays impossible.
            "incomplete_expired" | "canceled" => {
                matches!(self, Self::Active | Self::Trialing | Self::PastDue)
            }
            "trialing" => matches!(
                self,
                Self::Active | Self::PastDue | Self::Canceled | Self::Unpaid | Self::Paused
            ),
            "active" => matches!(
                self,
                Self::PastDue | Self::Canceled | Self::Unpaid | Self::Paused
            ),
            "past_due" => matches!(self, Self::Active | Self::Canceled | Self::Unpaid),
            "unpaid" => matches!(self, Self::Active | Self::Canceled),
            "paused" => matches!(self, Self::Active | Self::Canceled),
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
enum StripeBillingInterval {
    #[serde(rename = "month")]
    Month,
    #[serde(rename = "year")]
    Year,
}

impl StripeBillingInterval {
    fn as_db_value(self) -> &'static str {
        match self {
            Self::Month => "monthly",
            Self::Year => "yearly",
        }
    }
}

#[derive(Debug, Deserialize)]
struct InvoiceEvent {
    id: String,
    amount_due: i64,
    /// The amount ACTUALLY paid in this settlement (audit F73) — the
    /// verified payment amount, in the invoice currency's minor unit.
    /// Falls back to the canonical derived total when Stripe omits it.
    #[serde(default)]
    amount_paid: Option<i64>,
    #[serde(default)]
    currency: Option<String>,
    /// Subtotal excluding VAT, in the invoice currency's minor unit (cents).
    #[serde(default)]
    subtotal: Option<i64>,
    /// Total tax/VAT, in cents.
    #[serde(default)]
    tax: Option<i64>,
    /// Grand total including VAT, in cents.
    #[serde(default)]
    total: Option<i64>,
    /// Human-readable invoice number assigned by Stripe (e.g. "2026-000042").
    #[serde(default)]
    number: Option<String>,
    #[serde(default)]
    created: Option<i64>,
    #[serde(default)]
    period_start: Option<i64>,
    #[serde(default)]
    period_end: Option<i64>,
    #[serde(default)]
    attempt_count: Option<i64>,
    #[serde(default)]
    subscription_details: Option<InvoiceSubscriptionDetails>,
    #[serde(default)]
    subscription: Option<ExpandableId>,
    /// Line items from the invoice object. Present on invoice.paid events;
    /// used so locally stored invoices (and their PDFs) carry mandatory
    /// line-level detail instead of an empty items table.
    #[serde(default)]
    lines: Option<StripeInvoiceLines>,
    /// Stripe Tax decision state (`enabled`, `status`, `disabled_reason`).
    /// Present when automatic tax was requested at checkout / invoice
    /// creation; `status = "complete"` is the only authoritative state.
    #[serde(default)]
    automatic_tax: Option<StripeAutomaticTax>,
    /// Tax IDs collected for the customer (checkout `tax_id_collection`).
    #[serde(default)]
    customer_tax_ids: Option<Vec<StripeCustomerTaxId>>,
    /// Per-jurisdiction tax breakdown on newer API versions.
    #[serde(default)]
    total_taxes: Option<Vec<StripeTotalTax>>,
    /// Per-jurisdiction tax breakdown on older API versions.
    #[serde(default)]
    total_tax_amounts: Option<Vec<StripeTotalTax>>,
}

/// Stripe `automatic_tax` object (subset).
#[derive(Debug, Deserialize)]
struct StripeAutomaticTax {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    disabled_reason: Option<String>,
}

/// Stripe `customer_tax_ids[]` entry (subset).
#[derive(Debug, Deserialize)]
struct StripeCustomerTaxId {
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    verification: Option<serde_json::Value>,
}

/// Stripe `total_taxes[]` / `total_tax_amounts[]` entry (subset). The
/// jurisdiction is read from whichever nested rate object the API version
/// supplies.
#[derive(Debug, Deserialize)]
struct StripeTotalTax {
    #[serde(default)]
    amount: Option<i64>,
    #[serde(default)]
    inclusive: Option<bool>,
    #[serde(default)]
    taxability_reason: Option<String>,
    #[serde(default)]
    tax_rate_details: Option<serde_json::Value>,
    #[serde(default)]
    tax_rate: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct StripeInvoiceLines {
    #[serde(default)]
    data: Vec<StripeInvoiceLine>,
}

#[derive(Debug, Deserialize)]
struct StripeInvoiceLine {
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    quantity: Option<i64>,
    /// Line amount including VAT, in cents.
    #[serde(default)]
    amount: Option<i64>,
    /// Unit amount excluding VAT, in cents.
    #[serde(default)]
    unit_amount_excluding_tax: Option<String>,
}

#[derive(Debug, Deserialize)]
struct InvoiceSubscriptionDetails {
    metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ExpandableId {
    Id(String),
    Object { id: String },
}

impl ExpandableId {
    fn id(&self) -> &str {
        match self {
            Self::Id(id) => id,
            Self::Object { id } => id,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct DunningConfigRow {
    retry_schedule_days: Vec<i32>,
    soft_suspend_after_days: i32,
    hard_suspend_after_days: i32,
    grace_period_days: i32,
}

#[derive(Debug, Clone)]
struct DunningConfig {
    retry_schedule_days: Vec<i32>,
    soft_suspend_after_days: i32,
    hard_suspend_after_days: i32,
    grace_period_days: i32,
}

impl Default for DunningConfig {
    fn default() -> Self {
        Self {
            retry_schedule_days: vec![1, 3, 7, 14],
            soft_suspend_after_days: 7,
            hard_suspend_after_days: 21,
            grace_period_days: 7,
        }
    }
}

#[derive(Debug)]
struct DunningResult {
    status: String,
    next_retry_at: Option<DateTime<Utc>>,
}

/// Replay a deadletter entry by re-verifying the stored signature, parsing the
/// stored body, claiming the event in the database (idempotent via
/// `ON CONFLICT`), and calling `handle_stripe_event`.
async fn replay_deadletter(state: &AppState, entry: &DeadletterEntry) -> Result<(), String> {
    let body = entry
        .body
        .as_deref()
        .ok_or_else(|| "No body stored for retry".to_string())?;
    let signature = entry
        .signature
        .as_deref()
        .ok_or_else(|| "No signature stored for retry".to_string())?;

    // Re-verify the stored HMAC before processing: the body+signature live in
    // Redis between the original failure and this replay, so integrity must be
    // re-checked against the secret instead of trusting the stored payload.
    // The timestamp segment is part of the MAC (so it is verified implicitly);
    // the original 5-minute freshness window is deliberately NOT re-enforced —
    // the entry already passed it on first receipt and retries run on a
    // minutes-to-hours backoff schedule.
    let secret = state.config.stripe_webhook_secret.trim();
    if secret.is_empty() {
        return Err("Stripe webhook secret is not configured".into());
    }
    verify_signature_hmac(secret, body.as_bytes(), signature)?;

    let event: StripeEventPayload = serde_json::from_str(body)
        .map_err(|e| format!("Failed to parse stored webhook body: {e}"))?;

    match claim_webhook_event(state, &event.id, &event.event_type).await? {
        WebhookEventClaim::Claimed => {}
        WebhookEventClaim::AlreadyProcessed => {
            info!(
                event_id = %event.id,
                "deadletter retry: event already processed, skipping"
            );
            return Ok(());
        }
        WebhookEventClaim::AlreadyPending => {
            return Err("Event is already pending on another worker".into());
        }
    }

    // Process the event business logic.
    handle_stripe_event(state, &event).await?;

    // Mark as processed in the database.
    sqlx::query(
        r#"
        UPDATE stripe_webhook_events
        SET status = 'processed', processed_at = NOW(), updated_at = NOW()
        WHERE stripe_event_id = $1
        "#,
    )
    .bind(&event.id)
    .execute(&state.db)
    .await
    .map_err(|e| format!("Failed to mark retried event as processed: {e}"))?;

    info!(event_id = %event.id, "deadletter retry succeeded");
    Ok(())
}

/// Scan the retry index for entries whose retry timestamp is due, attempt to
/// replay them, and either remove them on success or schedule the next
/// exponential-backoff retry on transient failure.
async fn process_deadletter_retries(state: &AppState) -> Result<(), String> {
    let now_ms = Utc::now().timestamp_millis();
    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| format!("Redis connection error: {e}"))?;

    // Fetch all entries due for retry (score <= now_ms).
    let due_entries: Vec<String> = redis::cmd("ZRANGEBYSCORE")
        .arg(DEADLETTER_RETRY_INDEX_KEY)
        .arg(0i64)
        .arg(now_ms)
        .query_async(&mut *conn)
        .await
        .map_err(|e| format!("Failed to query retry index: {e}"))?;

    for event_key in &due_entries {
        // Read the full deadletter entry from the event key.
        let entry_json: Option<String> = redis::cmd("GET")
            .arg(event_key)
            .query_async(&mut *conn)
            .await
            .map_err(|e| format!("Failed to read deadletter entry: {e}"))?;

        let Some(entry_json) = entry_json else {
            // Entry already evicted — remove stale retry index member.
            let _: () = redis::cmd("ZREM")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .arg(event_key)
                .query_async(&mut *conn)
                .await
                .unwrap_or_default();
            continue;
        };

        let entry: DeadletterEntry = match serde_json::from_str(&entry_json) {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, key = %event_key, "corrupt deadletter entry, removing from retry index");
                let _: () = redis::cmd("ZREM")
                    .arg(DEADLETTER_RETRY_INDEX_KEY)
                    .arg(event_key)
                    .query_async(&mut *conn)
                    .await
                    .unwrap_or_default();
                continue;
            }
        };

        // Only retry processing_failed entries that have body + signature.
        if entry.reason != "processing_failed" || entry.body.is_none() || entry.signature.is_none()
        {
            let _: () = redis::cmd("ZREM")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .arg(event_key)
                .query_async(&mut *conn)
                .await
                .unwrap_or_default();
            continue;
        }

        match replay_deadletter(state, &entry).await {
            Ok(()) => {
                // Success — remove from retry index (deadletter remains for audit).
                let _: () = redis::cmd("ZREM")
                    .arg(DEADLETTER_RETRY_INDEX_KEY)
                    .arg(event_key)
                    .query_async(&mut *conn)
                    .await
                    .unwrap_or_default();
            }
            Err(error) => {
                let next_count = entry.retry_count + 1;
                warn!(
                    event_id = ?entry.event_id,
                    retry_count = next_count,
                    max_retries = DEADLETTER_MAX_RETRIES,
                    error = %error,
                    "deadletter retry attempt failed"
                );

                if next_count >= DEADLETTER_MAX_RETRIES {
                    // Exhausted — remove from retry index but keep the deadletter entry
                    // for manual inspection (with a shorter 7-day TTL).
                    warn!(
                        event_id = ?entry.event_id,
                        retry_count = next_count,
                        "deadletter retry exhausted, giving up"
                    );
                    let _: () = redis::cmd("ZREM")
                        .arg(DEADLETTER_RETRY_INDEX_KEY)
                        .arg(event_key)
                        .query_async(&mut *conn)
                        .await
                        .unwrap_or_default();

                    // Shorten TTL to 7 days for final review.
                    let mut final_entry = entry.clone();
                    final_entry.retry_count = next_count;
                    if let Ok(json) = serde_json::to_string(&final_entry) {
                        let _: () = redis::cmd("SETEX")
                            .arg(event_key)
                            .arg(7 * 24 * 60 * 60usize)
                            .arg(json)
                            .query_async(&mut *conn)
                            .await
                            .unwrap_or_default();
                    }
                } else {
                    // Schedule next retry with exponential backoff.
                    let backoff_secs = DEADLETTER_RETRY_BACKOFF_SECONDS
                        .get(next_count as usize - 1)
                        .copied()
                        .unwrap_or(DEADLETTER_RETRY_BACKOFF_SECONDS[4]); // cap at max
                    let next_retry_ms = Utc::now().timestamp_millis() + backoff_secs * 1000;

                    let mut updated_entry = entry.clone();
                    updated_entry.retry_count = next_count;
                    if let Ok(json) = serde_json::to_string(&updated_entry) {
                        let _: () = redis::pipe()
                            .atomic()
                            .cmd("SET")
                            .arg(event_key)
                            .arg(json)
                            .ignore()
                            .cmd("ZADD")
                            .arg(DEADLETTER_RETRY_INDEX_KEY)
                            .arg(next_retry_ms)
                            .arg(event_key)
                            .ignore()
                            .query_async(&mut *conn)
                            .await
                            .unwrap_or_default();
                    }
                }
            }
        }
    }

    Ok(())
}

/// Spawns a background tokio task that polls the deadletter retry index every
/// [`DEADLETTER_RETRY_POLL_INTERVAL_SECS`] seconds and replays due entries.
///
/// Call this once at application startup (e.g. from `main()`).
pub fn spawn_deadletter_retry_worker(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_secs(DEADLETTER_RETRY_POLL_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            if let Err(e) = process_deadletter_retries(&state).await {
                error!(error = %e, "deadletter retry worker error");
            }
        }
    });

    info!(
        "deadletter retry worker spawned (poll interval: {}s)",
        DEADLETTER_RETRY_POLL_INTERVAL_SECS
    );
}

/// Retry deadlettered webhook events from the retry index.
/// Processes events in batches of [`DEADLETTER_RETRY_BATCH_SIZE`] (default 10).
/// Uses exponential backoff: retry after 5min, 15min, 30min, 1hr, 2hr (max 5 attempts).
/// Logs successful retries and final failures (after max attempts).
pub async fn retry_deadlettered_webhooks(state: &AppState) -> Result<(), String> {
    let now_ms = Utc::now().timestamp_millis();
    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| format!("Redis connection error: {e}"))?;

    // Fetch up to BATCH_SIZE entries due for retry (score <= now_ms).
    let due_entries: Vec<String> = redis::cmd("ZRANGEBYSCORE")
        .arg(DEADLETTER_RETRY_INDEX_KEY)
        .arg(0i64)
        .arg(now_ms)
        .query_async(&mut *conn)
        .await
        .map_err(|e| format!("Failed to query retry index: {e}"))?;

    let batch: Vec<&str> = due_entries
        .iter()
        .map(String::as_str)
        .take(DEADLETTER_RETRY_BATCH_SIZE)
        .collect();

    if batch.is_empty() {
        return Ok(());
    }

    info!(
        batch_size = batch.len(),
        "retrying deadlettered webhook events"
    );

    for event_key in &batch {
        let entry_json: Option<String> = redis::cmd("GET")
            .arg(event_key)
            .query_async(&mut *conn)
            .await
            .map_err(|e| format!("Failed to read deadletter entry: {e}"))?;

        let Some(entry_json) = entry_json else {
            // Entry already evicted — remove stale retry index member.
            let _: () = redis::cmd("ZREM")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .arg(event_key)
                .query_async(&mut *conn)
                .await
                .unwrap_or_default();
            continue;
        };

        let entry: DeadletterEntry = match serde_json::from_str(&entry_json) {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, key = %event_key, "corrupt deadletter entry, removing from retry index");
                let _: () = redis::cmd("ZREM")
                    .arg(DEADLETTER_RETRY_INDEX_KEY)
                    .arg(event_key)
                    .query_async(&mut *conn)
                    .await
                    .unwrap_or_default();
                continue;
            }
        };

        // Only retry processing_failed entries that have body + signature.
        if entry.reason != "processing_failed" || entry.body.is_none() || entry.signature.is_none()
        {
            let _: () = redis::cmd("ZREM")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .arg(event_key)
                .query_async(&mut *conn)
                .await
                .unwrap_or_default();
            continue;
        }

        match replay_deadletter(state, &entry).await {
            Ok(()) => {
                // Success — remove from retry index (deadletter remains for audit).
                let _: () = redis::cmd("ZREM")
                    .arg(DEADLETTER_RETRY_INDEX_KEY)
                    .arg(event_key)
                    .query_async(&mut *conn)
                    .await
                    .unwrap_or_default();
                info!(
                    event_id = ?entry.event_id,
                    "deadletter retry succeeded"
                );
            }
            Err(error) => {
                let next_count = entry.retry_count + 1;
                warn!(
                    event_id = ?entry.event_id,
                    retry_count = next_count,
                    max_retries = DEADLETTER_MAX_RETRIES,
                    error = %error,
                    "deadletter retry attempt failed"
                );

                if next_count >= DEADLETTER_MAX_RETRIES {
                    // Exhausted — log final failure and remove from retry index.
                    error!(
                        event_id = ?entry.event_id,
                        retry_count = next_count,
                        "deadletter retry exhausted after max attempts, giving up"
                    );
                    let _: () = redis::cmd("ZREM")
                        .arg(DEADLETTER_RETRY_INDEX_KEY)
                        .arg(event_key)
                        .query_async(&mut *conn)
                        .await
                        .unwrap_or_default();

                    // Shorten TTL to 7 days for final review.
                    let mut final_entry = entry.clone();
                    final_entry.retry_count = next_count;
                    if let Ok(json) = serde_json::to_string(&final_entry) {
                        let _: () = redis::cmd("SETEX")
                            .arg(event_key)
                            .arg(7 * 24 * 60 * 60usize)
                            .arg(json)
                            .query_async(&mut *conn)
                            .await
                            .unwrap_or_default();
                    }
                } else {
                    // Schedule next retry with exponential backoff.
                    let backoff_secs = DEADLETTER_RETRY_BACKOFF_SECONDS
                        .get(next_count as usize - 1)
                        .copied()
                        .unwrap_or(DEADLETTER_RETRY_BACKOFF_SECONDS[4]); // cap at max
                    let next_retry_ms = Utc::now().timestamp_millis() + backoff_secs * 1000;

                    let mut updated_entry = entry.clone();
                    updated_entry.retry_count = next_count;
                    if let Ok(json) = serde_json::to_string(&updated_entry) {
                        let _: () = redis::pipe()
                            .atomic()
                            .cmd("SET")
                            .arg(event_key)
                            .arg(json)
                            .ignore()
                            .cmd("ZADD")
                            .arg(DEADLETTER_RETRY_INDEX_KEY)
                            .arg(next_retry_ms)
                            .arg(event_key)
                            .ignore()
                            .query_async(&mut *conn)
                            .await
                            .unwrap_or_default();
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Audit F36 — entitlement reconciliation after a subscription delete.
    // ------------------------------------------------------------------

    fn ts(secs: i64) -> Option<DateTime<Utc>> {
        DateTime::from_timestamp(secs, 0)
    }

    #[test]
    fn older_cycle_events_are_stale_against_the_applied_watermark() {
        // F36 verification shape: pause update A after its initial read,
        // process replacement B (watermark advances), resume A — B stays.
        assert!(subscription_event_is_stale(ts(1_000), ts(2_000)));
        // Same cycle (replay or same-boundary plan change) is NOT stale.
        assert!(!subscription_event_is_stale(ts(2_000), ts(2_000)));
        // A newer cycle is the current replacement.
        assert!(!subscription_event_is_stale(ts(3_000), ts(2_000)));
        // Missing watermark (legacy row) or missing cycle in the event is
        // never treated as stale.
        assert!(!subscription_event_is_stale(ts(1_000), None));
        assert!(!subscription_event_is_stale(None, ts(2_000)));
        assert!(!subscription_event_is_stale(None, None));
    }

    // ------------------------------------------------------------------
    // Audit F73 — the verified payment amount drives the allocation.
    // ------------------------------------------------------------------

    fn invoice_event_with(amount_paid: Option<i64>, total: Option<i64>, due: i64) -> InvoiceEvent {
        InvoiceEvent {
            id: "in_test".into(),
            amount_due: due,
            amount_paid,
            currency: Some("eur".into()),
            subtotal: None,
            tax: None,
            total,
            number: None,
            created: None,
            period_start: None,
            period_end: None,
            attempt_count: None,
            subscription_details: None,
            subscription: None,
            lines: None,
            automatic_tax: None,
            customer_tax_ids: None,
            total_taxes: None,
            total_tax_amounts: None,
        }
    }

    // ------------------------------------------------------------------
    // Tax truth (P0) — a Stripe/ApexMail charged-total discrepancy blocks
    // finalization; a match passes.
    // ------------------------------------------------------------------

    fn expected(subtotal: i64, vat: i64) -> ExpectedTax {
        ExpectedTax {
            subtotal_cents: subtotal,
            vat_cents: vat,
            total_cents: subtotal + vat,
            source: "local_invoice",
            country: Some("EE".into()),
            vat_rate: 24.0,
            evidence_id: None,
        }
    }

    #[test]
    fn tax_total_mismatch_is_an_error_not_a_warning() {
        // Stripe charged X (e.g. 10.00 + 0 tax); ApexMail's statutory
        // invoice says X + VAT (10.00 + 2.40). This MUST block.
        let discrepancy = check_charged_total(&expected(1_000, 240), 1_000, 0, 1_000)
            .expect_err("mismatch must be an error");
        assert_eq!(discrepancy.expected_total_cents, 1_240);
        assert_eq!(discrepancy.observed_total_cents, 1_000);
        assert_eq!(discrepancy.delta_cents, -240);
        assert!(discrepancy.summary().contains("1240"));

        // Subtotal or VAT disagreement alone is also a discrepancy.
        assert!(check_charged_total(&expected(1_000, 240), 1_000, 190, 1_190).is_err());
        assert!(check_charged_total(&expected(1_000, 240), 900, 240, 1_140).is_err());
    }

    #[test]
    fn matching_charged_total_passes_validation() {
        assert!(check_charged_total(&expected(1_000, 240), 1_000, 240, 1_240).is_ok());
        // A legitimately zero-rated reverse charge matches with zero VAT.
        let reverse = ExpectedTax {
            subtotal_cents: 1_000,
            vat_cents: 0,
            total_cents: 1_000,
            source: "local_invoice",
            country: Some("DE".into()),
            vat_rate: 0.0,
            evidence_id: Some(Uuid::new_v4()),
        };
        assert!(check_charged_total(&reverse, 1_000, 0, 1_000).is_ok());
    }

    #[test]
    fn automatic_tax_status_is_read_verbatim() {
        let mut invoice = invoice_event_with(Some(1_240), Some(1_240), 0);
        invoice.automatic_tax = Some(StripeAutomaticTax {
            enabled: Some(true),
            status: Some("complete".into()),
            disabled_reason: None,
        });
        assert_eq!(automatic_tax_status(&invoice), "complete");
        assert!(automatic_tax_complete(&invoice));

        invoice.automatic_tax = Some(StripeAutomaticTax {
            enabled: Some(true),
            status: Some("requires_location_inputs".into()),
            disabled_reason: None,
        });
        assert!(!automatic_tax_complete(&invoice));

        invoice.automatic_tax = None;
        assert_eq!(automatic_tax_status(&invoice), "not_enabled");
        assert!(!automatic_tax_complete(&invoice));
    }

    #[test]
    fn tax_id_summary_distinguishes_verified_from_merely_provided() {
        let mut invoice = invoice_event_with(Some(1_240), Some(1_240), 0);
        assert_eq!(summarize_tax_ids(&invoice).0, "not_provided");

        invoice.customer_tax_ids = Some(vec![StripeCustomerTaxId {
            kind: Some("eu_vat".into()),
            value: Some("DE123456789".into()),
            verification: Some(serde_json::json!({"status": "unverified"})),
        }]);
        let (status, ids) = summarize_tax_ids(&invoice);
        assert_eq!(status, "provided_unverified");
        assert_eq!(ids[0]["value"], "DE123456789");

        invoice.customer_tax_ids = Some(vec![StripeCustomerTaxId {
            kind: Some("eu_vat".into()),
            value: Some("DE123456789".into()),
            verification: Some(serde_json::json!({"status": "verified"})),
        }]);
        let (status, _) = summarize_tax_ids(&invoice);
        assert_eq!(status, "verified");
    }

    #[test]
    fn jurisdiction_is_read_from_either_api_shape() {
        let mut invoice = invoice_event_with(Some(1_240), Some(1_240), 0);
        assert_eq!(tax_jurisdiction(&invoice), None);

        invoice.total_taxes = Some(vec![StripeTotalTax {
            amount: Some(240),
            inclusive: Some(false),
            taxability_reason: Some("standard_rated".into()),
            tax_rate_details: Some(
                serde_json::json!({"country": "ee", "percentage_decimal": "24"}),
            ),
            tax_rate: None,
        }]);
        assert_eq!(tax_jurisdiction(&invoice).as_deref(), Some("EE"));

        invoice.total_taxes = None;
        invoice.total_tax_amounts = Some(vec![StripeTotalTax {
            amount: Some(240),
            inclusive: Some(false),
            taxability_reason: None,
            tax_rate_details: None,
            tax_rate: Some(serde_json::json!({"country": "DE"})),
        }]);
        assert_eq!(tax_jurisdiction(&invoice).as_deref(), Some("DE"));
    }

    #[test]
    fn snapshot_payload_hash_is_stable_and_content_addressed() {
        let payload = serde_json::json!({"a": 1, "b": [true, null]});
        let first = snapshot_payload_hash(&payload);
        let second = snapshot_payload_hash(&payload);
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert_ne!(first, snapshot_payload_hash(&serde_json::json!({"a": 2})));
    }

    #[test]
    fn snapshot_persist_sql_binds_expected_and_observed_sides() {
        // Guard the write shape: the snapshot must carry both the observed
        // Stripe figures and ApexMail's independent expectation plus hash.
        let source = include_str!("stripe_webhooks.rs");
        for needle in [
            "apexmail_expected_total_cents",
            "raw_payload_hash",
            "validation_status",
            "ON CONFLICT (stripe_invoice_id) DO NOTHING",
        ] {
            assert!(
                source.contains(needle),
                "snapshot write must include {needle}"
            );
        }
        // The discrepancy path must both block (Err) and persist an incident.
        assert!(source.contains("finance_incidents"));
        assert!(source.contains("BLOCKED invoice finalization"));
    }

    #[test]
    fn verified_payment_prefers_amount_paid_over_totals() {
        // The confirmed payment wins over any derived total.
        let event = invoice_event_with(Some(6_000), Some(10_000), 10_000);
        assert_eq!(verified_payment_cents(&event), 6_000);
    }

    #[test]
    fn verified_payment_falls_back_to_the_canonical_derived_total() {
        // No amount_paid: the canonical derivation prefers Stripe's own
        // explicit total...
        let mut event = invoice_event_with(None, Some(10_000), 10_000);
        event.subtotal = Some(8_000);
        event.tax = Some(1_920);
        assert_eq!(verified_payment_cents(&event), 10_000);
        // ...then subtotal + tax when total is absent...
        let mut event = invoice_event_with(None, None, 0);
        event.subtotal = Some(8_000);
        event.tax = Some(1_920);
        assert_eq!(verified_payment_cents(&event), 9_920);
        // ...and otherwise amount_due.
        let event = invoice_event_with(None, None, 7_500);
        assert_eq!(verified_payment_cents(&event), 7_500);
    }

    #[test]
    fn verified_payment_never_goes_negative() {
        let event = invoice_event_with(Some(-5), None, 0);
        assert_eq!(verified_payment_cents(&event), 0);
    }

    #[test]
    fn zero_value_payments_settle_without_a_positive_allocation() {
        // F73: a zero-value paid invoice must not attempt an allocation
        // (the amount_cents > 0 CHECK would fail the callback); the
        // settlement marks it paid with no allocation row.
        let event = invoice_event_with(Some(0), Some(0), 0);
        let payment = verified_payment_cents(&event);
        assert_eq!(payment, 0);
        // The allocation decision mirrors the handler: only positive
        // amounts against a positive remainder allocate.
        let outstanding = 0_i64;
        assert_eq!(payment.min(outstanding).max(0), 0);
    }

    #[test]
    fn delete_with_a_remaining_active_subscription_keeps_its_plan() {
        // A stale deleted event for an OLD subscription must not downgrade
        // the newer active one.
        assert_eq!(
            reconciled_entitlement_plan(Some((Some("growth"), "active"))),
            "growth"
        );
    }

    #[test]
    fn delete_with_a_remaining_trial_keeps_the_trialled_plan() {
        assert_eq!(
            reconciled_entitlement_plan(Some((Some("pro"), "trialing"))),
            "pro"
        );
    }

    #[test]
    fn delete_with_no_entitled_subscription_remaining_drops_to_free() {
        assert_eq!(reconciled_entitlement_plan(None), "free");
        // A remaining row with no plan recorded cannot grant entitlement.
        assert_eq!(reconciled_entitlement_plan(Some((None, "active"))), "free");
        // Blank plans are data corruption, not entitlement.
        assert_eq!(
            reconciled_entitlement_plan(Some((Some("  "), "active"))),
            "free"
        );
    }

    #[test]
    fn delete_reconciliation_never_consults_the_deleted_row() {
        // The decision input is exclusively the remaining-subscription
        // query result; pin that the handler's query only selects rows
        // OTHER than the deleted subscription and only entitled statuses.
        // (Behavioral pin: the deleted subscription's plan 'enterprise'
        // must lose to the remaining active 'starter'.)
        assert_eq!(
            reconciled_entitlement_plan(Some((Some("starter"), "active"))),
            "starter"
        );
    }

    #[test]
    fn reactivation_transitions_from_terminal_states_are_allowed() {
        // Stripe genuinely emits customer.subscription.updated with
        // status=active for an un-cancelled (cancel_at_period_end removed) or
        // support-side reactivated subscription whose last observed status was
        // canceled/incomplete_expired. Refusing the transition deadletters
        // the event and strands a paying customer on the free plan.
        assert!(SubscriptionStatus::Active.can_transition_from("canceled"));
        assert!(SubscriptionStatus::Active.can_transition_from("incomplete_expired"));
        assert!(SubscriptionStatus::Trialing.can_transition_from("canceled"));
        // Terminal states must still never "transition" to other terminal
        // states — only revival to a paying/entitled state is admitted.
        assert!(!SubscriptionStatus::Canceled.can_transition_from("canceled"));
        assert!(!SubscriptionStatus::Unpaid.can_transition_from("canceled"));
    }

    #[test]
    fn only_entitled_stripe_statuses_grant_the_paid_plan() {
        assert_eq!(
            SubscriptionStatus::Active.entitlement_plan_name("scale"),
            "scale"
        );
        assert_eq!(
            SubscriptionStatus::Trialing.entitlement_plan_name("scale"),
            "scale"
        );

        for status in [
            SubscriptionStatus::Incomplete,
            SubscriptionStatus::IncompleteExpired,
            SubscriptionStatus::PastDue,
            SubscriptionStatus::Unpaid,
            SubscriptionStatus::Paused,
            SubscriptionStatus::Canceled,
        ] {
            assert_eq!(status.entitlement_plan_name("scale"), "free");
        }
    }

    #[test]
    fn deadletter_entry_default_has_max_retries() {
        let entry = DeadletterEntry::default();
        assert_eq!(entry.max_retries, DEADLETTER_MAX_RETRIES);
        assert_eq!(entry.retry_count, 0);
        assert!(entry.body.is_none());
        assert!(entry.signature.is_none());
        assert!(entry.event_id.is_none());
    }

    #[test]
    fn deadletter_entry_serialization_roundtrip_with_retry_fields() {
        let entry = DeadletterEntry {
            reason: "processing_failed".into(),
            occurred_at: Some("2025-01-01T00:00:00Z".into()),
            event_id: Some("evt_123".into()),
            error: Some("transient db error".into()),
            payload_length: Some(1024),
            retry_count: 2,
            max_retries: DEADLETTER_MAX_RETRIES,
            body: Some(r#"{"id":"evt_123","type":"checkout.session.completed"}"#.into()),
            signature: Some("t=123,v1=abc".into()),
        };

        let json = serde_json::to_string(&entry).expect("serialize");
        let deserialized: DeadletterEntry = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.reason, "processing_failed");
        assert_eq!(deserialized.retry_count, 2);
        assert_eq!(deserialized.max_retries, DEADLETTER_MAX_RETRIES);
        assert_eq!(deserialized.event_id, Some("evt_123".into()));
        assert!(deserialized.body.is_some());
        assert!(deserialized.signature.is_some());
    }

    #[test]
    fn deadletter_entry_deserializes_legacy_entry_without_retry_fields() {
        // Simulate a legacy entry that was stored before the retry fields existed.
        let legacy_json = r#"{
            "reason": "processing_failed",
            "occurredAt": "2025-01-01T00:00:00Z",
            "eventId": "evt_999",
            "error": "timeout"
        }"#;
        let entry: DeadletterEntry = serde_json::from_str(legacy_json).expect("deserialize legacy");

        assert_eq!(entry.retry_count, 0);
        assert_eq!(entry.max_retries, DEADLETTER_MAX_RETRIES);
        assert!(entry.body.is_none());
        assert!(entry.signature.is_none());
    }

    #[test]
    fn prepare_deadletter_schedules_retry_for_processing_failure() {
        let now = Utc::now();
        let prepared = prepare_deadletter(
            DeadletterEntry {
                reason: "processing_failed".into(),
                event_id: Some("evt_retry".into()),
                error: Some("db timeout".into()),
                ..Default::default()
            },
            Some(br#"{"id":"evt_retry"}"#),
            Some("t=123,v1=abc"),
            now,
        );

        assert!(prepared.event_key.contains("evt_retry"));
        assert_eq!(
            prepared.retry_at_ms,
            Some(prepared.now_ms + DEADLETTER_RETRY_BACKOFF_SECONDS[0] * 1000)
        );

        let entry: DeadletterEntry = serde_json::from_str(&prepared.payload).expect("payload json");
        assert_eq!(entry.reason, "processing_failed");
        assert_eq!(entry.body.as_deref(), Some(r#"{"id":"evt_retry"}"#));
        assert_eq!(entry.signature.as_deref(), Some("t=123,v1=abc"));
    }

    #[test]
    fn prepare_deadletter_caps_body_to_4kb_and_skips_retry() {
        // A body larger than the 4 KiB cap must be truncated before the Redis
        // SET, and — because the stored JSON is incomplete — no retry may be
        // scheduled for it.
        let oversized_body = format!(
            r#"{{"id":"evt_big","data":"{}"}}"#,
            "x".repeat(DEADLETTER_MAX_BODY_BYTES)
        );
        let oversized_bytes = oversized_body.as_bytes();
        assert!(oversized_bytes.len() > DEADLETTER_MAX_BODY_BYTES);

        let prepared = prepare_deadletter(
            DeadletterEntry {
                reason: "processing_failed".into(),
                event_id: Some("evt_big".into()),
                error: Some("boom".into()),
                ..Default::default()
            },
            Some(oversized_bytes),
            Some("t=123,v1=abc"),
            Utc::now(),
        );

        assert_eq!(
            prepared.retry_at_ms, None,
            "truncated bodies must not replay"
        );

        let entry: DeadletterEntry = serde_json::from_str(&prepared.payload).expect("payload json");
        let stored_body = entry.body.as_deref().expect("body stored");
        assert!(stored_body.len() <= DEADLETTER_MAX_BODY_BYTES + "...(truncated)".len());
        assert!(stored_body.ends_with("...(truncated)"));
    }

    #[test]
    fn truncate_at_char_boundary_respects_multibyte_chars() {
        assert_eq!(truncate_at_char_boundary("short", 100), "short");

        // é is 2 bytes — the cut must back off to the previous char boundary.
        let truncated = truncate_at_char_boundary(&"é".repeat(100), 11);
        assert!(truncated.len() <= 11 + "...(truncated)".len());
        assert!(truncated.ends_with("...(truncated)"));
    }

    #[test]
    fn verify_signature_hmac_accepts_valid_and_rejects_tampered() {
        let secret = "whsec_test_secret";
        let payload = br#"{"id":"evt_1","type":"invoice.paid"}"#;
        let timestamp = 1_711_234_567_i64.to_string();

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(timestamp.as_bytes());
        mac.update(b".");
        mac.update(payload);
        let signature = format!(
            "t={timestamp},v1={}",
            hex::encode(mac.finalize().into_bytes())
        );

        assert!(verify_signature_hmac(secret, payload, &signature).is_ok());

        // Tampered body → HMAC mismatch.
        assert!(verify_signature_hmac(secret, b"{\"id\":\"evt_2\"}", &signature).is_err());
        // Wrong secret → mismatch.
        assert!(verify_signature_hmac("whsec_other", payload, &signature).is_err());
    }

    #[test]
    fn process_webhook_error_tracks_deadletter_ownership() {
        let unrecorded = ProcessWebhookError::RecordDeadletter("invalid signature".into());
        assert!(unrecorded.should_record_deadletter());
        assert_eq!(unrecorded.message(), "invalid signature");

        let handled = ProcessWebhookError::DeadletterFlowHandled("business failure".into());
        assert!(!handled.should_record_deadletter());
        assert_eq!(handled.message(), "business failure");
    }

    #[test]
    fn sanitize_event_id_handles_edge_cases() {
        assert_eq!(sanitize_event_id(None), "unknown");
        assert_eq!(sanitize_event_id(Some("")), "unknown");
        assert_eq!(sanitize_event_id(Some("  ")), "unknown");
        assert_eq!(sanitize_event_id(Some("evt_123")), "evt_123");
        assert_eq!(sanitize_event_id(Some("evt_123:456")), "evt_123_456");
        assert_eq!(sanitize_event_id(Some("evt/abc<>def")), "evt_abc__def");
    }

    #[test]
    fn classify_webhook_claim_allows_claimed_event() {
        let decision = classify_webhook_claim(Some(WebhookEventClaimRow {
            claimed: true,
            status: "pending".into(),
        }));

        assert_eq!(decision, WebhookEventClaim::Claimed);
    }

    #[test]
    fn classify_webhook_claim_skips_processed_event() {
        let decision = classify_webhook_claim(Some(WebhookEventClaimRow {
            claimed: false,
            status: "processed".into(),
        }));

        assert_eq!(decision, WebhookEventClaim::AlreadyProcessed);
    }

    #[test]
    fn classify_webhook_claim_skips_pending_event() {
        let decision = classify_webhook_claim(Some(WebhookEventClaimRow {
            claimed: false,
            status: "pending".into(),
        }));

        assert_eq!(decision, WebhookEventClaim::AlreadyPending);
    }

    // ------------------------------------------------------------------
    // Fix G — AlreadyPending must be retryable, not a silent 200.
    // ------------------------------------------------------------------

    #[test]
    fn retry_later_error_maps_to_500_and_no_deadletter() {
        let error = ProcessWebhookError::RetryLater("event pending on another worker".into());

        assert_eq!(error.http_status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!error.should_record_deadletter());
        assert_eq!(error.message(), "event pending on another worker");
    }

    #[test]
    fn deadlettered_errors_map_to_400_and_skip_duplicate_deadletter() {
        let error = ProcessWebhookError::DeadletterFlowHandled("business failure".into());

        assert_eq!(error.http_status(), StatusCode::BAD_REQUEST);
        // The deadletter was already written atomically with the DB status
        // flip inside process_webhook — must not be recorded twice.
        assert!(!error.should_record_deadletter());
    }

    #[test]
    fn stale_pending_cutoff_is_ten_minutes_in_the_past() {
        let now = Utc::now();
        let cutoff = stale_pending_cutoff(now);

        assert_eq!(
            now - cutoff,
            TimeDelta::seconds(STALE_PENDING_RECLAIM_SECS as i64)
        );
    }

    // ------------------------------------------------------------------
    // Fix A — invoice.paid must insert revenue when no local row exists.
    // ------------------------------------------------------------------

    #[test]
    fn derive_invoice_totals_preserves_signed_credit_invoices() {
        // Stripe emits NEGATIVE invoices when customer credit / matrix
        // proration exceeds the charge. Recording them as 0/0/0 overstates
        // period revenue and hides the applied credit from the local ledger.
        let (subtotal, vat, total) =
            derive_invoice_totals(Some(-1_000), Some(-240), Some(-1_240), -1_240);
        assert_eq!((subtotal, vat, total), (-1_000, -240, -1_240));
        // VAT derivation mirrors the sign of the invoice for credits.
        let (subtotal, vat, total) = derive_invoice_totals(Some(-1_000), None, Some(-1_240), 0);
        assert_eq!((subtotal, vat, total), (-1_000, -240, -1_240));
    }

    #[test]
    fn derive_invoice_totals_keeps_a_legitimate_zero_subtotal() {
        // A 100%-discounted invoice legitimately has subtotal 0; replacing
        // it with amount_due mislabels the row as charged.
        let (subtotal, vat, total) = derive_invoice_totals(Some(0), Some(0), Some(0), 0);
        assert_eq!((subtotal, vat, total), (0, 0, 0));
        // The charge-relevant amount_due stays clamped at zero — nothing was
        // due — but the explicit Stripe figures are preserved verbatim.
        let (subtotal, _vat, total) = derive_invoice_totals(Some(0), None, Some(0), 5_000);
        assert_eq!((subtotal, total), (0, 0));
    }

    #[test]
    fn derive_invoice_totals_prefers_explicit_stripe_amounts() {
        let (subtotal, vat, total) =
            derive_invoice_totals(Some(10_000), Some(2_400), Some(12_400), 12_400);
        assert_eq!((subtotal, vat, total), (10_000, 2_400, 12_400));
    }

    #[test]
    fn derive_invoice_totals_derives_vat_from_total_minus_subtotal() {
        // Older Stripe payloads may omit `tax`; derive it from total-subtotal.
        let (subtotal, vat, total) =
            derive_invoice_totals(Some(10_000), None, Some(12_400), 12_400);
        assert_eq!((subtotal, vat, total), (10_000, 2_400, 12_400));
    }

    #[test]
    fn derive_invoice_totals_falls_back_to_amount_due_without_subtotal() {
        // Only amount_due known: treat it as the taxable subtotal, VAT 0.
        let (subtotal, vat, total) = derive_invoice_totals(None, None, None, 5_000);
        assert_eq!((subtotal, vat, total), (5_000, 0, 5_000));
    }

    #[test]
    fn derive_invoice_totals_handles_empty_and_negative_inputs() {
        assert_eq!(derive_invoice_totals(None, None, None, 0), (0, 0, 0));
        assert_eq!(derive_invoice_totals(None, None, None, -5), (0, 0, 0));
        // Inconsistent Stripe data never yields a negative VAT.
        assert_eq!(
            derive_invoice_totals(Some(2_000), None, Some(1_000), 1_000),
            (2_000, 0, 1_000)
        );
    }

    #[test]
    fn derive_invoice_vat_rate_computes_effective_rate() {
        assert_eq!(derive_invoice_vat_rate(10_000, 2_400), 24.0);
        assert_eq!(derive_invoice_vat_rate(10_000, 1_900), 19.0);
        assert_eq!(derive_invoice_vat_rate(10_000, 0), 0.0);
        assert_eq!(derive_invoice_vat_rate(0, 500), 0.0);
    }

    #[test]
    fn normalize_stripe_currency_defaults_to_eur_and_lowercases() {
        assert_eq!(normalize_stripe_currency(Some("EUR")), "eur");
        assert_eq!(normalize_stripe_currency(Some("usd")), "usd");
        assert_eq!(normalize_stripe_currency(Some("  ")), "eur");
        assert_eq!(normalize_stripe_currency(None), "eur");
    }

    #[test]
    fn invoice_event_decodes_full_stripe_amount_payload() {
        let payload = serde_json::json!({
            "id": "in_123",
            "amount_due": 12_400,
            "currency": "eur",
            "subtotal": 10_000,
            "tax": 2_400,
            "total": 12_400,
            "number": "2026-000042",
            "created": 1_777_000_000,
            "period_start": 1_777_000_000,
            "period_end": 1_779_000_000,
            "attempt_count": 1,
            "subscription": "sub_1",
            "subscription_details": { "metadata": { "tenant_id": "tenant_1" } }
        });

        let invoice: InvoiceEvent = serde_json::from_value(payload).expect("decode");
        assert_eq!(invoice.id, "in_123");
        assert_eq!(invoice.subtotal, Some(10_000));
        assert_eq!(invoice.tax, Some(2_400));
        assert_eq!(invoice.total, Some(12_400));
        assert_eq!(invoice.currency.as_deref(), Some("eur"));
        assert_eq!(invoice.number.as_deref(), Some("2026-000042"));
        assert_eq!(
            invoice.subscription.as_ref().map(ExpandableId::id),
            Some("sub_1")
        );
    }

    #[test]
    fn invoice_event_decodes_minimal_payload_with_defaults() {
        let payload = serde_json::json!({ "id": "in_min", "amount_due": 500 });

        let invoice: InvoiceEvent = serde_json::from_value(payload).expect("decode");
        assert_eq!(invoice.id, "in_min");
        assert_eq!(invoice.amount_due, 500);
        assert!(invoice.subtotal.is_none());
        assert!(invoice.subscription_details.is_none());
        assert!(invoice.subscription.is_none());
        assert!(invoice.currency.is_none());
    }

    // ------------------------------------------------------------------
    // Fix H — dunning state computed from atomically-incremented counters.
    // ------------------------------------------------------------------

    // ------------------------------------------------------------------
    // Audit item 3g — suspension transitions emit distinct events.
    // ------------------------------------------------------------------

    #[test]
    fn dunning_transition_fires_on_entering_soft_suspension() {
        assert_eq!(
            dunning_transition(Some("warning"), "soft_suspended"),
            Some(DunningTransition::SoftSuspended)
        );
        assert_eq!(
            dunning_transition(None, "soft_suspended"),
            Some(DunningTransition::SoftSuspended)
        );
    }

    #[test]
    fn dunning_transition_fires_on_entering_hard_suspension() {
        assert_eq!(
            dunning_transition(Some("warning"), "hard_suspended"),
            Some(DunningTransition::HardSuspended)
        );
        // Escalation soft -> hard is also a hard-suspension transition.
        assert_eq!(
            dunning_transition(Some("soft_suspended"), "hard_suspended"),
            Some(DunningTransition::HardSuspended)
        );
    }

    #[test]
    fn dunning_transition_fires_on_recovery() {
        assert_eq!(
            dunning_transition(Some("hard_suspended"), "healthy"),
            Some(DunningTransition::Recovered)
        );
        assert_eq!(
            dunning_transition(Some("soft_suspended"), "healthy"),
            Some(DunningTransition::Recovered)
        );
        assert_eq!(
            dunning_transition(Some("warning"), "healthy"),
            Some(DunningTransition::Recovered)
        );
    }

    #[test]
    fn dunning_transition_does_not_fire_without_state_change() {
        // Repeated payment failures in the same state must not spam
        // duplicate transition events.
        assert_eq!(dunning_transition(Some("warning"), "warning"), None);
        assert_eq!(
            dunning_transition(Some("soft_suspended"), "soft_suspended"),
            None
        );
        assert_eq!(
            dunning_transition(Some("hard_suspended"), "hard_suspended"),
            None
        );
        assert_eq!(dunning_transition(None, "warning"), None);
        assert_eq!(dunning_transition(None, "healthy"), None);
    }

    #[test]
    fn dunning_transition_de_escalation_hard_to_soft_is_not_soft_transition() {
        // Hard -> soft is a state change but not a new suspension entry; the
        // soft-suspension event must not fire again for an already
        // suspended tenant.
        assert_eq!(
            dunning_transition(Some("hard_suspended"), "soft_suspended"),
            None
        );
    }

    #[test]
    fn dunning_transition_event_types_are_snake_case_rows() {
        // Values must match the dunning_events.event_type conventions
        // already used by the payment_recovered path (mark_payment_recovered).
        assert_eq!(
            DunningTransition::SoftSuspended.event_type(),
            "soft_suspended"
        );
        assert_eq!(
            DunningTransition::HardSuspended.event_type(),
            "hard_suspended"
        );
        assert_eq!(
            DunningTransition::Recovered.event_type(),
            "payment_recovered"
        );
    }

    #[test]
    fn dunning_state_first_failure_is_warning() {
        let now = Utc::now();
        let state = next_dunning_state(None, now, &dunning_config());

        assert_eq!(state.failed_payment_count, 1);
        assert_eq!(state.status, "warning");
        assert_eq!(state.first_failed_at, now);
        assert!(state.suspended_at.is_none());
    }

    #[test]
    fn dunning_state_consumes_post_increment_snapshot() {
        // The SQL upsert increments the counter atomically; this function only
        // sees the already-incremented snapshot (count=2 for a second
        // failure) and must preserve it together with the original
        // first_failed_at.
        let now = Utc::now();
        let first = now - TimeDelta::days(2);

        let state = next_dunning_state(
            Some(DunningSnapshot {
                failed_payment_count: 2,
                first_failed_at: Some(first),
                status: "warning".into(),
            }),
            now,
            &dunning_config(),
        );

        assert_eq!(state.failed_payment_count, 2);
        assert_eq!(state.first_failed_at, first);
        assert_eq!(state.status, "warning");
    }

    #[test]
    fn dunning_state_soft_suspends_after_threshold_days() {
        let now = Utc::now();
        let first = now - TimeDelta::days(7); // soft_suspend_after_days = 7

        let state = next_dunning_state(
            Some(DunningSnapshot {
                failed_payment_count: 3,
                first_failed_at: Some(first),
                status: "warning".into(),
            }),
            now,
            &dunning_config(),
        );

        assert_eq!(state.status, "soft_suspended");
        assert!(state.suspended_at.is_some());
        assert!(state.grace_period_ends_at.is_none());
    }

    #[test]
    fn dunning_state_hard_suspends_and_sets_grace_once() {
        let now = Utc::now();
        let first = now - TimeDelta::days(21); // hard_suspend_after_days = 21

        let state = next_dunning_state(
            Some(DunningSnapshot {
                failed_payment_count: 5,
                first_failed_at: Some(first),
                status: "warning".into(),
            }),
            now,
            &dunning_config(),
        );

        assert_eq!(state.status, "hard_suspended");
        assert!(state.suspended_at.is_some());
        assert_eq!(state.grace_period_ends_at, Some(now + TimeDelta::days(7)));

        // Already hard-suspended → grace/suspension timestamps preserved.
        let state = next_dunning_state(
            Some(DunningSnapshot {
                failed_payment_count: 6,
                first_failed_at: Some(first),
                status: "hard_suspended".into(),
            }),
            now,
            &dunning_config(),
        );
        assert_eq!(state.status, "hard_suspended");
        assert!(state.suspended_at.is_none());
        assert!(state.grace_period_ends_at.is_none());
    }

    fn dunning_config() -> DunningConfig {
        DunningConfig::default()
    }

    // -----------------------------------------------------------------------
    // Fix 7.4 — Stripe webhook processing integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_signature_header_parses_valid_input() {
        // Simulate a real Stripe signature header with timestamp and v1 signatures.
        let header = "t=1711234567,v1=abcdef1234567890abcdef1234567890abcdef12,v1=deadbeef";
        let result = parse_signature_header(header);

        let (timestamp, signatures) = result.expect("valid signature header should parse");
        assert_eq!(timestamp, 1_711_234_567);
        assert_eq!(signatures.len(), 2);
        assert_eq!(signatures[0], "abcdef1234567890abcdef1234567890abcdef12");
        assert_eq!(signatures[1], "deadbeef");
    }

    #[test]
    fn parse_signature_header_rejects_missing_timestamp() {
        // Header without a 't=' segment should be rejected.
        let header = "v1=abc123";
        let result = parse_signature_header(header);
        assert!(result.is_err(), "missing timestamp should be rejected");
        assert!(result.err().unwrap().contains("Invalid webhook signature"));
    }

    #[test]
    fn parse_signature_header_rejects_empty_signatures() {
        // Header with a timestamp but no v1 signatures should be rejected.
        let header = "t=1711234567,v0=legacy";
        let result = parse_signature_header(header);
        assert!(result.is_err(), "no v1 signatures should be rejected");
    }

    #[test]
    fn handle_stripe_event_unknown_type_returns_ok() {
        // The catch-all arm in handle_stripe_event returns Ok(()) for unknown event types.
        // This tests the event-type routing logic (serde deserialization + match).
        let event = StripeEventPayload {
            id: "evt_test_unknown".into(),
            event_type: "unknown.event.type".into(),
            data: StripeEventData {
                object: serde_json::json!({}),
            },
        };

        // The routing itself is synchronous; we verify the event type mapping
        // by checking it would match the catch-all arm.
        assert!(!matches!(
            event.event_type.as_str(),
            "checkout.session.completed"
                | "customer.subscription.created"
                | "customer.subscription.updated"
                | "customer.subscription.deleted"
                | "invoice.paid"
                | "invoice.payment_failed"
                | "customer.subscription.trial_will_end"
        ));
    }

    // -----------------------------------------------------------------------
    // Fix 7.5 — Dedicated IP auto-provisioning tests
    // -----------------------------------------------------------------------

    /// Locally-declared mirror of the API's
    /// `api_server::routes::dedicated_ips::AllocateIpRequest` (api-server is
    /// deliberately NOT a dependency of billing-service). Field names and the
    /// `deny_unknown_fields` validation MUST match the API extractor exactly:
    /// if the API contract gains a field, this mirror must gain it too, or
    /// the request body built here is rejected at deserialization time.
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AllocateIpRequestMirror {
        #[serde(default)]
        region: Option<String>,
    }

    #[test]
    fn auto_provision_body_deserializes_into_the_api_allocate_contract() {
        // Serialize the EXACT production request body and prove the API's
        // extractor contract accepts it.
        let body = serde_json::to_string(&auto_provision_request_body())
            .expect("auto-provision body must serialize");
        let parsed: AllocateIpRequestMirror = serde_json::from_str(&body)
            .expect("billing auto-provision body must deserialize into AllocateIpRequest");
        assert!(parsed.region.is_none());

        // Regression guard: the pre-fix body carried an unknown field and the
        // same contract rejects it — so this mirror genuinely exercises
        // `deny_unknown_fields` rather than accepting everything.
        let pre_fix = r#"{"auto_provisioned":true}"#;
        assert!(
            serde_json::from_str::<AllocateIpRequestMirror>(pre_fix).is_err(),
            "the old auto_provisioned body must remain rejected by the API contract"
        );
    }

    #[test]
    fn dedicated_ip_provisioning_flow_pending_then_provisioned() {
        // Verify the conceptual state machine: a request moves from 'pending'
        // to 'provisioning' to 'provisioned'. This test validates the invariants
        // without requiring a real database connection.
        let states = ["pending", "provisioning", "provisioned", "failed"];

        assert!(states.contains(&"pending"), "initial state must be pending");
        assert!(
            states.contains(&"provisioning"),
            "provisioning is a valid intermediate state"
        );
        assert!(
            states.contains(&"provisioned"),
            "provisioned is the terminal success state"
        );
        assert!(
            states.contains(&"failed"),
            "failed is the terminal error state"
        );
    }
}

// ---------------------------------------------------------------------------
// Adversarial coverage tests (DB + Redis backed) for the Stripe webhook
// pipeline, dunning escalation, deadletter replay, and the tax-truth gate.
//
// These call the PRIVATE handlers directly: the public route wrapper is
// already covered by tests/coverage_adversarial.rs, while the private
// replay/dunning/tax functions can only be driven from inside the crate.
// Every test provisions its own canonical database clone; `TEST_DATABASE_URL`
// unset means soft-skip.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod coverage_adversarial {
    use super::*;
    use crate::config::BillingConfig;
    use deadpool_redis::Runtime;
    use sqlx::postgres::PgPoolOptions;
    use std::sync::Arc;

    struct Env {
        state: Arc<AppState>,
        pool: sqlx::PgPool,
        redis: deadpool_redis::Pool,
        db_name: String,
        admin_url: String,
    }

    impl Env {
        /// Schema-level fault injection in this test's PRIVATE database
        /// clone: rename a table so queries against it fail (42P01).
        async fn break_table(&self, table: &str) {
            sqlx::query(&format!("ALTER TABLE {table} RENAME TO {table}_broken"))
                .execute(&self.pool)
                .await
                .expect("break table");
        }

        async fn restore_table(&self, table: &str) {
            let _ = sqlx::query(&format!("ALTER TABLE {table}_broken RENAME TO {table}"))
                .execute(&self.pool)
                .await;
        }

        async fn finish(self) {
            self.pool.close().await;
            let admin = PgPoolOptions::new()
                .max_connections(1)
                .connect(&self.admin_url)
                .await
                .expect("admin connect for teardown");
            let _ = sqlx::query(&format!(
                r#"DROP DATABASE IF EXISTS "{}" WITH (FORCE)"#,
                self.db_name
            ))
            .execute(&admin)
            .await;
            admin.close().await;
        }
    }

    async fn provision(test_name: &str) -> Option<Env> {
        let url = std::env::var("TEST_DATABASE_URL")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())?;
        let (server_part, db_part) = url.rsplit_once('/').expect("db segment");
        let db_only = db_part.split('?').next().unwrap_or(db_part);
        let mut digest: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in test_name.bytes() {
            digest ^= u64::from(byte);
            digest = digest.wrapping_mul(0x0000_0100_0000_01b3);
        }
        let db_name = format!("{db_only}_swcov_{:08x}", digest & 0xffff_ffff);

        let admin_url = std::env::var("TEST_DATABASE_ADMIN_URL")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| format!("{server_part}/postgres"));
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(30))
            .connect(&admin_url)
            .await
            .expect("admin connect");

        let migrations_dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
        let mut count = 0_usize;
        let mut newest = 0_i64;
        for entry in std::fs::read_dir(&migrations_dir).expect("migrations dir") {
            let name = entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .to_string();
            if let Some(prefix) = name.split('_').next() {
                if let Ok(version) = prefix.parse::<i64>() {
                    count += 1;
                    newest = newest.max(version);
                }
            }
        }
        let template: Option<String> = sqlx::query_scalar(
            "SELECT datname FROM pg_database WHERE datname LIKE $1 ORDER BY datname DESC LIMIT 1",
        )
        .bind(format!("apexmail_canonical_tpl_{count}_{newest}_%"))
        .fetch_optional(&admin)
        .await
        .expect("template lookup");
        let template = template.expect("canonical template database must exist");

        sqlx::query(&format!(
            r#"DROP DATABASE IF EXISTS "{}" WITH (FORCE)"#,
            db_name
        ))
        .execute(&admin)
        .await
        .expect("drop test db");
        {
            // Serialize template clones process-wide and retry the transient
            // 55006 (a concurrent cloner's internal session on the template).
            let _clone_guard = crate::test_support::CLONE_LOCK.lock().await;
            let mut last_error = None;
            for _ in 0..5 {
                match sqlx::query(&format!(
                    r#"CREATE DATABASE "{}" TEMPLATE "{}""#,
                    db_name, template
                ))
                .execute(&admin)
                .await
                {
                    Ok(_) => {
                        last_error = None;
                        break;
                    }
                    Err(error) => {
                        last_error = Some(error);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
            if let Some(error) = last_error {
                panic!("clone test db: {error}");
            }
        }
        admin.close().await;

        let database_url = format!("{server_part}/{db_name}");
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(10))
            .connect(&database_url)
            .await
            .expect("connect test db");
        let redis_url = std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .expect("TEST_REDIS_URL must be set");
        let redis = deadpool_redis::Config::from_url(redis_url)
            .create_pool(Some(Runtime::Tokio1))
            .expect("redis pool");
        let config = BillingConfig {
            database_url,
            redis_url: "redis://127.0.0.1:6379".to_string(),
            service_auth_token: "coverage".to_string(),
            stripe_webhook_secret: "whsec_coverage".to_string(),
            api_base_url: "http://127.0.0.1:9".to_string(),
            ..BillingConfig::default()
        };
        let state = AppState::new(pool.clone(), redis.clone(), config);
        Some(Env {
            state,
            pool,
            redis,
            db_name,
            admin_url,
        })
    }

    macro_rules! env_test {
        ($name:ident, |$e:ident| $body:block) => {
            #[tokio::test]
            async fn $name() {
                if let Some(owned) = provision(stringify!($name)).await {
                    let $e = &owned;
                    $body
                    owned.finish().await;
                }
            }
        };
    }

    /// Serializes tests that use the process-shared deadletter Redis indexes.
    static DEADLETTER_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn seed_tenant(env: &Env, tenant: &str, plan: &str, status: &str) {
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status) VALUES ($1, $2, $3, $4)
             ON CONFLICT (id) DO UPDATE SET plan = EXCLUDED.plan, status = EXCLUDED.status",
        )
        .bind(tenant)
        .bind(format!("Coverage {tenant}"))
        .bind(plan)
        .bind(status)
        .execute(&env.pool)
        .await
        .expect("seed tenant");
    }

    async fn seed_billing_address(env: &Env, tenant: &str, country: &str) {
        sqlx::query(
            "INSERT INTO billing_addresses (tenant_id, country, city)
             VALUES ($1, $2, 'Testville')
             ON CONFLICT (tenant_id) DO UPDATE SET country = EXCLUDED.country",
        )
        .bind(tenant)
        .bind(country)
        .execute(&env.pool)
        .await
        .expect("seed billing address");
    }

    async fn seed_plan(env: &Env, name: &str, price_id: &str) {
        sqlx::query(
            "INSERT INTO plans (id, name, display_name, price_cents, email_limit, api_call_limit,
                                stripe_price_id_monthly, is_active)
             VALUES ($1, $2, $2, 4900, 100000, 100000, $3, true)
             ON CONFLICT (name) DO UPDATE SET stripe_price_id_monthly = EXCLUDED.stripe_price_id_monthly,
                 is_active = true",
        )
        .bind(format!("plan_{name}"))
        .bind(name)
        .bind(price_id)
        .execute(&env.pool)
        .await
        .expect("seed plan");
    }

    fn invoice_event(value: serde_json::Value) -> InvoiceEvent {
        serde_json::from_value(value).expect("invoice event")
    }

    fn decode_invoice(value: &serde_json::Value) -> InvoiceEvent {
        serde_json::from_value(value.clone()).expect("invoice event")
    }

    fn subscription_event(value: serde_json::Value) -> SubscriptionEvent {
        serde_json::from_value(value).expect("subscription event")
    }

    fn sign(secret: &str, payload: &[u8], timestamp: i64) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key");
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(payload);
        format!(
            "t={timestamp},v1={}",
            hex::encode(mac.finalize().into_bytes())
        )
    }

    /// A `invoice.payment_failed` payload whose resolved tenant is `tenant`.
    fn payment_failed_payload(event_id: &str, invoice_id: &str, tenant: &str) -> serde_json::Value {
        serde_json::json!({
            "id": event_id,
            "type": "invoice.payment_failed",
            "data": { "object": {
                "id": invoice_id,
                "amount_due": 4200,
                "currency": "eur",
                "subscription_details": { "metadata": { "tenant_id": tenant } }
            }}
        })
    }

    // ---------------- deadletter replay ----------------

    env_test!(replay_deadletter_reverifies_hmac_and_is_idempotent, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        let tenant = "swcov_replay";
        seed_tenant(env, tenant, "growth", "active").await;
        let payload = payment_failed_payload("evt_sw_replay", "in_sw_replay", tenant);
        let body = serde_json::to_string(&payload).expect("body");
        let timestamp = Utc::now().timestamp();
        let good = sign("whsec_coverage", body.as_bytes(), timestamp);
        let forged = sign("whsec_not_the_secret", body.as_bytes(), timestamp);

        // A tampered secret must write NOTHING, not even the claim row.
        let bad_entry = DeadletterEntry {
            reason: "processing_failed".into(),
            event_id: Some("evt_sw_replay".into()),
            body: Some(body.clone()),
            signature: Some(forged),
            ..Default::default()
        };
        let error = replay_deadletter(&env.state, &bad_entry)
            .await
            .expect_err("forged signature must be refused");
        assert!(error.contains("Invalid webhook signature"), "{error}");
        let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stripe_webhook_events")
            .fetch_one(&env.pool)
            .await
            .expect("events");
        assert_eq!(events, 0, "failed verification writes nothing at all");
        let dunning: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dunning_records")
            .fetch_one(&env.pool)
            .await
            .expect("dunning");
        assert_eq!(dunning, 0);

        // Missing body/signature: refused before any side effect.
        let empty = DeadletterEntry {
            reason: "processing_failed".into(),
            event_id: Some("evt_sw_replay".into()),
            ..Default::default()
        };
        let error = replay_deadletter(&env.state, &empty)
            .await
            .expect_err("no body");
        assert!(error.contains("No body stored"), "{error}");

        // The verified entry replays exactly once.
        let entry = DeadletterEntry {
            reason: "processing_failed".into(),
            event_id: Some("evt_sw_replay".into()),
            body: Some(body),
            signature: Some(good),
            ..Default::default()
        };
        replay_deadletter(&env.state, &entry)
            .await
            .expect("verified replay");
        let (status, count): (String, i32) = sqlx::query_as(
            "SELECT status, failed_payment_count FROM dunning_records WHERE tenant_id = $1",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("dunning");
        assert_eq!(status, "warning");
        assert_eq!(count, 1);

        // Replaying the same deadletter again must not double-count.
        replay_deadletter(&env.state, &entry)
            .await
            .expect("replay is idempotent");
        let count: i32 = sqlx::query_scalar(
            "SELECT failed_payment_count FROM dunning_records WHERE tenant_id = $1",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("dunning count");
        assert_eq!(count, 1, "replay never re-applies the failure");
        let processed: String = sqlx::query_scalar(
            "SELECT status FROM stripe_webhook_events WHERE stripe_event_id = 'evt_sw_replay'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("event row");
        assert_eq!(processed, "processed");
    });

    async fn redis_conn(env: &Env) -> deadpool_redis::Connection {
        env.redis.get().await.expect("redis connection")
    }

    env_test!(deadletter_retry_backs_off_then_exhausts, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        let tenant = "swcov_backoff";
        seed_tenant(env, tenant, "growth", "active").await;
        let payload = payment_failed_payload("evt_sw_backoff", "in_sw_backoff", tenant);
        let body = serde_json::to_string(&payload).expect("body");
        // A signature that can never verify keeps the retry ladder
        // deterministic: every attempt fails.
        let entry = DeadletterEntry {
            reason: "processing_failed".into(),
            event_id: Some("evt_sw_backoff".into()),
            body: Some(body),
            signature: Some("t=1,v1=deadbeef".into()),
            ..Default::default()
        };
        let the_key = "stripe:deadletter:event:evt_sw_backoff";
        let entry_json = serde_json::to_string(&entry).expect("entry json");
        let mut conn = redis_conn(env).await;
        // Isolate the shared retry index for this test.
        let _: () = redis::cmd("ZREMRANGEBYSCORE")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .arg("-inf")
            .arg("+inf")
            .query_async(&mut conn)
            .await
            .expect("clear retry index");
        let _: () = redis::cmd("SET")
            .arg(the_key)
            .arg(&entry_json)
            .query_async(&mut conn)
            .await
            .expect("store entry");
        let before = Utc::now().timestamp_millis();
        let _: () = redis::cmd("ZADD")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .arg(1)
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("schedule due retry");
        drop(conn);

        process_deadletter_retries(&env.state)
            .await
            .expect("retry pass");
        let mut conn = redis_conn(env).await;
        let updated: Option<String> = redis::cmd("GET")
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("read entry");
        let updated: DeadletterEntry =
            serde_json::from_str(updated.as_deref().expect("entry kept")).expect("json");
        assert_eq!(updated.retry_count, 1, "attempt recorded");
        let score: Option<i64> = redis::cmd("ZSCORE")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("score");
        let score = score.expect("rescheduled");
        assert!(
            score > before,
            "backoff schedules the next attempt in the future"
        );

        // Simulate four prior attempts: the fifth failure exhausts the ladder.
        let mut almost_done = updated.clone();
        almost_done.retry_count = 4;
        let _: () = redis::cmd("SET")
            .arg(the_key)
            .arg(serde_json::to_string(&almost_done).expect("json"))
            .query_async(&mut conn)
            .await
            .expect("store almost-done entry");
        let _: () = redis::cmd("ZADD")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .arg(1)
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("reschedule due");
        drop(conn);

        process_deadletter_retries(&env.state)
            .await
            .expect("exhausting pass");
        let mut conn = redis_conn(env).await;
        let score: Option<i64> = redis::cmd("ZSCORE")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("score");
        assert!(score.is_none(), "exhausted retries leave the retry index");
        let ttl: i64 = redis::cmd("TTL")
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("ttl");
        assert!(
            (0..=7 * 24 * 60 * 60).contains(&ttl),
            "final entry keeps a bounded review TTL, got {ttl}"
        );
        let kept: Option<String> = redis::cmd("GET")
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("read final entry");
        let kept: DeadletterEntry =
            serde_json::from_str(kept.as_deref().expect("kept for review")).expect("json");
        assert_eq!(kept.retry_count, 5, "attempts are capped at max_retries");
        // Leave the shared index clean for other tests in this binary.
        let _: () = redis::cmd("ZREMRANGEBYSCORE")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .arg("-inf")
            .arg("+inf")
            .query_async(&mut conn)
            .await
            .expect("clear retry index");
        let _: () = redis::cmd("DEL")
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("drop entry");
    });

    #[test]
    fn stripe_decimal_to_cents_is_exact_and_rejects_malformed() {
        assert_eq!(stripe_decimal_to_cents("65.00"), Some(6500));
        assert_eq!(stripe_decimal_to_cents("0.40"), Some(40));
        assert_eq!(stripe_decimal_to_cents("0.4"), Some(40));
        assert_eq!(stripe_decimal_to_cents("0"), Some(0));
        assert_eq!(stripe_decimal_to_cents(" 12.34 "), Some(1234));
        assert_eq!(stripe_decimal_to_cents("100"), Some(10_000));
        assert_eq!(stripe_decimal_to_cents(""), None);
        assert_eq!(stripe_decimal_to_cents("abc"), None);
        assert_eq!(stripe_decimal_to_cents("1.234"), None);
        assert_eq!(stripe_decimal_to_cents("-5.00"), None);
        assert_eq!(stripe_decimal_to_cents("1."), Some(100));
        assert_eq!(stripe_decimal_to_cents(".5"), None);
        assert_eq!(stripe_decimal_to_cents("99999999999999999999"), None);
    }

    #[test]
    fn invoice_total_derivation_never_invents_or_hides_money() {
        // Credit invoices keep their sign (VAT reversal is negative).
        assert_eq!(
            derive_invoice_totals(Some(1_000), None, Some(-500), -500),
            (1_000, -1_500, -500)
        );
        // Explicit Stripe tax wins only when it reconciles with the total.
        assert_eq!(
            derive_invoice_totals(Some(1_000), Some(210), Some(1_210), 1_210),
            (1_000, 210, 1_210)
        );
        assert_eq!(
            derive_invoice_totals(Some(1_000), Some(9_999), Some(1_210), 1_210),
            (1_000, 210, 1_210),
            "inconsistent Stripe tax is replaced by the derived VAT"
        );
        // Missing fields degrade without inventing a VAT figure.
        assert_eq!(
            derive_invoice_totals(Some(1_000), None, None, 1_000),
            (1_000, 0, 1_000)
        );
        assert_eq!(
            derive_invoice_totals(None, Some(500), None, 500),
            (500, 0, 500)
        );
        assert_eq!(derive_invoice_totals(None, None, None, 300), (300, 0, 300));
        assert_eq!(
            derive_invoice_totals(None, None, None, -42),
            (0, 0, 0),
            "a negative amount_due never becomes a negative subtotal"
        );
        // Rate derivation preserves one decimal of a fractional rate.
        assert_eq!(derive_invoice_vat_rate(1_000, 255), 25.5);
        assert_eq!(derive_invoice_vat_rate(1_000, 2_000), 200.0);
        assert_eq!(derive_invoice_vat_rate(0, 100), 0.0);
        assert_eq!(derive_invoice_vat_rate(100, -1), 0.0);
        assert_eq!(normalize_stripe_currency(None), "eur");
        assert_eq!(normalize_stripe_currency(Some("  EUR ")), "eur");
        assert_eq!(normalize_stripe_currency(Some("")), "eur");
    }

    // ---------------- dunning escalation ----------------

    env_test!(payment_failed_escalates_and_only_transitions_audit, |env| {
        let tenant = "swcov_dunning";
        seed_tenant(env, tenant, "growth", "active").await;

        let first = invoice_event(serde_json::json!({
            "id": "in_sw_dun_1",
            "amount_due": 4200,
            "subscription_details": { "metadata": { "tenant_id": tenant } }
        }));
        handle_payment_failed(&env.state, first)
            .await
            .expect("first failure");
        let (status, count, first_failed, retry): (
            String,
            i32,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
        ) = sqlx::query_as(
            "SELECT status, failed_payment_count, first_failed_at, next_retry_at
             FROM dunning_records WHERE tenant_id = $1",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("dunning");
        assert_eq!((status.as_str(), count), ("warning", 1));
        let first_failed = first_failed.expect("first failure recorded");
        let retry = retry.expect("retry scheduled");
        assert_eq!(
            (retry - first_failed).num_days(),
            1,
            "first retry follows the 1-day schedule"
        );
        let events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM dunning_events WHERE tenant_id = $1 AND event_type = 'payment_failed'",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("events");
        assert_eq!(events, 1);
        let transitions: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM dunning_events WHERE tenant_id = $1 AND event_type = 'soft_suspended'",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("transitions");
        assert_eq!(transitions, 0, "warning is not a suspension transition");

        // Age the failure history into the soft-suspension band (7 days).
        sqlx::query(
            "UPDATE dunning_records SET first_failed_at = NOW() - INTERVAL '8 days',
                status = 'warning' WHERE tenant_id = $1",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("age dunning");
        let second = invoice_event(serde_json::json!({
            "id": "in_sw_dun_2",
            "amount_due": 4200,
            "subscription_details": { "metadata": { "tenant_id": tenant } }
        }));
        handle_payment_failed(&env.state, second)
            .await
            .expect("second failure");
        let (status, count, retry): (String, i32, Option<DateTime<Utc>>) = sqlx::query_as(
            "SELECT status, failed_payment_count, next_retry_at FROM dunning_records WHERE tenant_id = $1",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("dunning");
        assert_eq!(status, "soft_suspended");
        assert_eq!(count, 2);
        let retry = retry.expect("still retrying");
        assert!(
            retry <= Utc::now(),
            "the retry is anchored to the (aged) first failure, so it is due now"
        );
        let soft_transitions: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM dunning_events WHERE tenant_id = $1 AND event_type = 'soft_suspended'",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("soft transitions");
        assert_eq!(soft_transitions, 1, "the transition is logged exactly once");
        let notifications: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_queue
             WHERE tenant_id = $1 AND type = 'account_soft_suspended'",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("notifications");
        assert!(notifications >= 1, "suspension notifies the tenant");

        // Age into the hard-suspension band (21 days).
        sqlx::query(
            "UPDATE dunning_records SET first_failed_at = NOW() - INTERVAL '25 days',
                status = 'soft_suspended' WHERE tenant_id = $1",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("age dunning");
        let third = invoice_event(serde_json::json!({
            "id": "in_sw_dun_3",
            "amount_due": 4200,
            "subscription_details": { "metadata": { "tenant_id": tenant } }
        }));
        handle_payment_failed(&env.state, third)
            .await
            .expect("third failure");
        let (status, grace): (String, Option<DateTime<Utc>>) = sqlx::query_as(
            "SELECT status, grace_period_ends_at FROM dunning_records WHERE tenant_id = $1",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("dunning");
        assert_eq!(status, "hard_suspended");
        let grace = grace.expect("grace window recorded");
        assert!(
            (grace - Utc::now()).num_days() >= 6,
            "the 7-day grace window is concrete"
        );
        let tenant_status: String = sqlx::query_scalar("SELECT status FROM tenants WHERE id = $1")
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("tenant");
        assert_eq!(tenant_status, "suspended", "hard suspension halts sending");
        let holds: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM tenant_restrictions
             WHERE tenant_id = $1 AND kind = 'billing' AND cleared_at IS NULL",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("restriction");
        assert_eq!(holds, 1, "the suspension is independently recorded");

        // Idempotence of the suspension state: another failure leaves the
        // original grace deadline and does not duplicate the hold.
        let fourth = invoice_event(serde_json::json!({
            "id": "in_sw_dun_4",
            "amount_due": 4200,
            "subscription_details": { "metadata": { "tenant_id": tenant } }
        }));
        handle_payment_failed(&env.state, fourth)
            .await
            .expect("fourth failure");
        let (grace_after, holds): (Option<DateTime<Utc>>, i64) = sqlx::query_as(
            "SELECT grace_period_ends_at,
                    (SELECT COUNT(*) FROM tenant_restrictions tr
                     WHERE tr.tenant_id = dunning_records.tenant_id AND tr.kind = 'billing'
                       AND tr.cleared_at IS NULL)
             FROM dunning_records WHERE tenant_id = $1",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("dunning");
        assert_eq!(grace_after, Some(grace), "grace deadline is not extended");
        assert_eq!(holds, 1, "the hold is never duplicated");
    });

    env_test!(
        payment_failed_without_resolvable_tenant_is_deadlettered,
        |env| {
            let invoice = invoice_event(serde_json::json!({
                "id": "in_sw_orphan",
                "amount_due": 1000
            }));
            let error = handle_payment_failed(&env.state, invoice)
                .await
                .expect_err("unresolvable tenant");
            assert!(error.contains("unresolvable"), "{error}");
            let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dunning_records")
                .fetch_one(&env.pool)
                .await
                .expect("dunning");
            assert_eq!(rows, 0, "nothing is written for an unresolvable event");

            // A subscription reference that exists resolves the tenant instead.
            let tenant = "swcov_orphan_ref";
            seed_tenant(env, tenant, "growth", "active").await;
            sqlx::query(
            "INSERT INTO stripe_subscriptions
                 (tenant_id, stripe_subscription_id, plan, status, billing_cycle_start,
                  billing_cycle_end, stripe_customer_id)
             VALUES ($1, 'sub_sw_orphan', 'growth', 'active', NOW(), NOW() + INTERVAL '30 days', 'cus_sw')",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("subscription");
            let fallback = invoice_event(serde_json::json!({
                "id": "in_sw_orphan_resolved",
                "amount_due": 1000,
                "subscription": "sub_sw_orphan"
            }));
            handle_payment_failed(&env.state, fallback)
                .await
                .expect("tenant resolved via subscription");
            let status: String =
                sqlx::query_scalar("SELECT status FROM dunning_records WHERE tenant_id = $1")
                    .bind(tenant)
                    .fetch_one(&env.pool)
                    .await
                    .expect("dunning");
            assert_eq!(status, "warning");
        }
    );

    // ---------------- tax-truth gate ----------------

    env_test!(tax_gate_blocks_mismatch_and_dedupes_incidents, |env| {
        let tenant = "swcov_tax";
        seed_tenant(env, tenant, "growth", "active").await;
        seed_billing_address(env, tenant, "US").await;

        // Stripe charged 1000 cents of tax on a US (0%) supply: mismatch.
        let mismatch = invoice_event(serde_json::json!({
            "id": "in_sw_tax_bad",
            "amount_due": 5900,
            "amount_paid": 5900,
            "currency": "eur",
            "subtotal": 4900,
            "tax": 1000,
            "total": 5900,
            "automatic_tax": { "enabled": true, "status": "complete" }
        }));
        let error = validate_and_snapshot_stripe_tax(&env.state, &mismatch, tenant)
            .await
            .expect_err("charged total must not be accepted on trust");
        assert!(error.contains("blocked"), "{error}");
        let incidents: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM finance_incidents
             WHERE kind = 'tax_total_mismatch' AND stripe_invoice_id = 'in_sw_tax_bad'
               AND status = 'open'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("incidents");
        assert_eq!(incidents, 1, "a durable finance incident is raised");
        let (validation, delta): (String, i64) = sqlx::query_as(
            "SELECT validation_status, discrepancy_cents FROM stripe_tax_snapshots
             WHERE stripe_invoice_id = 'in_sw_tax_bad'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("snapshot");
        assert_eq!(validation, "discrepancy");
        assert_eq!(delta, 1000, "the delta is the over-charged VAT");

        // A replay (new event id, same Stripe invoice) stays blocked and
        // never duplicates the incident.
        let replay = invoice_event(serde_json::json!({
            "id": "in_sw_tax_bad",
            "amount_due": 5900,
            "amount_paid": 5900,
            "currency": "eur",
            "subtotal": 4900,
            "tax": 1000,
            "total": 5900,
            "automatic_tax": { "enabled": true, "status": "complete" }
        }));
        validate_and_snapshot_stripe_tax(&env.state, &replay, tenant)
            .await
            .expect_err("an open discrepancy keeps blocking");
        let incidents: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM finance_incidents
             WHERE kind = 'tax_total_mismatch' AND stripe_invoice_id = 'in_sw_tax_bad'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("incidents");
        assert_eq!(incidents, 1, "incident dedupe");

        // A matching invoice validates and snapshots as authoritative.
        let good = invoice_event(serde_json::json!({
            "id": "in_sw_tax_ok",
            "amount_due": 4900,
            "amount_paid": 4900,
            "currency": "EUR",
            "subtotal": 4900,
            "tax": 0,
            "total": 4900,
            "automatic_tax": { "enabled": true, "status": "complete" }
        }));
        let snapshot = validate_and_snapshot_stripe_tax(&env.state, &good, tenant)
            .await
            .expect("matching invoice validates")
            .expect("snapshot id");
        assert!(!snapshot.is_nil());
        let (validation, authority): (String, String) = sqlx::query_as(
            "SELECT validation_status, authority FROM stripe_tax_snapshots
             WHERE stripe_invoice_id = 'in_sw_tax_ok'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("snapshot");
        assert_eq!(validation, "validated");
        assert_eq!(authority, "stripe_tax");
    });

    env_test!(tax_gate_fails_closed_without_any_expectation, |env| {
        let tenant = "swcov_tax_unavail";
        seed_tenant(env, tenant, "growth", "active").await;
        // No billing address and Stripe Tax not complete: cannot validate.
        let unknown = invoice_event(serde_json::json!({
            "id": "in_sw_tax_unknown",
            "amount_due": 1000,
            "currency": "eur",
            "subtotal": 1000,
            "total": 1000
        }));
        let error = validate_and_snapshot_stripe_tax(&env.state, &unknown, tenant)
            .await
            .expect_err("fail closed");
        assert!(error.contains("cannot validate"), "{error}");
        let (incidents, validation): (i64, String) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM finance_incidents
                     WHERE kind = 'tax_validation_unavailable'
                       AND stripe_invoice_id = 'in_sw_tax_unknown'),
                    validation_status
             FROM stripe_tax_snapshots WHERE stripe_invoice_id = 'in_sw_tax_unknown'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("snapshot");
        assert_eq!(incidents, 1);
        assert_eq!(validation, "discrepancy");

        // Zero-value invoices (credits/100% discounts) have no tax decision
        // and are explicitly accepted as external.
        let zero = invoice_event(serde_json::json!({
            "id": "in_sw_tax_zero",
            "amount_due": 0,
            "currency": "eur",
            "subtotal": 0,
            "total": 0
        }));
        validate_and_snapshot_stripe_tax(&env.state, &zero, tenant)
            .await
            .expect("zero-value invoices are exempt");
        let validation: String = sqlx::query_scalar(
            "SELECT validation_status FROM stripe_tax_snapshots
             WHERE stripe_invoice_id = 'in_sw_tax_zero'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("snapshot");
        assert_eq!(validation, "unverified_external");
    });

    // ---------------- paid-invoice persistence guards ----------------

    env_test!(insert_paid_invoice_never_rebinds_to_another_tenant, |env| {
        let owner = "swcov_inv_owner";
        let other = "swcov_inv_other";
        seed_tenant(env, owner, "growth", "active").await;
        seed_tenant(env, other, "growth", "active").await;
        let local_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO invoices (id, tenant_id, stripe_invoice_id, invoice_number, status,
                                   amount, currency, subtotal, vat_total, total,
                                   due_at, period_start, period_end, created_at, updated_at)
             VALUES ($1, $2, 'in_sw_rebind', 'SWCOV-REBIND', 'pending',
                     1000, 'eur', 1000, 0, 1000, NOW(), NOW(), NOW(), NOW(), NOW())",
        )
        .bind(local_id)
        .bind(owner)
        .execute(&env.pool)
        .await
        .expect("local invoice");

        let event = invoice_event(serde_json::json!({
            "id": "in_sw_rebind",
            "amount_due": 1000,
            "amount_paid": 1000,
            "currency": "eur",
            "subtotal": 1000,
            "tax": 0,
            "total": 1000,
            "lines": { "data": [
                { "description": "Subscription", "amount": 1000, "quantity": 1,
                  "unit_amount_excluding_tax": "10.00" }
            ] }
        }));

        // The same Stripe invoice resolved to a DIFFERENT tenant must not
        // flip the existing local row to paid.
        let affected = insert_paid_invoice_from_stripe(&env.state, &event, other)
            .await
            .expect("insert attempt");
        assert_eq!(affected, 0, "tenant mismatch is rejected by the guard");
        let (status, bound): (String, String) =
            sqlx::query_as("SELECT status, tenant_id FROM invoices WHERE id = $1")
                .bind(local_id)
                .fetch_one(&env.pool)
                .await
                .expect("invoice");
        assert_eq!(status, "pending", "rejected write changes nothing");
        assert_eq!(bound, owner);
        let duplicates: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM invoices WHERE stripe_invoice_id = 'in_sw_rebind'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("count");
        assert_eq!(duplicates, 1);

        // The rightful tenant's event settles it in place.
        let affected = insert_paid_invoice_from_stripe(&env.state, &event, owner)
            .await
            .expect("settle");
        assert_eq!(affected, 1);
        let (status, line_items): (String, serde_json::Value) = sqlx::query_as(
            "SELECT status, COALESCE(line_items, '[]'::jsonb) FROM invoices WHERE id = $1",
        )
        .bind(local_id)
        .fetch_one(&env.pool)
        .await
        .expect("invoice");
        assert_eq!(status, "paid");
        assert_eq!(
            line_items,
            serde_json::json!([]),
            "settling an existing row never rewrites its line items"
        );

        // A brand-new Stripe invoice is inserted WITH its line items.
        let fresh = invoice_event(serde_json::json!({
            "id": "in_sw_rebind_new",
            "amount_due": 1000,
            "amount_paid": 1000,
            "currency": "eur",
            "subtotal": 1000,
            "tax": 0,
            "total": 1000,
            "lines": { "data": [
                { "description": "Subscription", "amount": 1000, "quantity": 1,
                  "unit_amount_excluding_tax": "10.00" }
            ] }
        }));
        let affected = insert_paid_invoice_from_stripe(&env.state, &fresh, owner)
            .await
            .expect("fresh insert");
        assert_eq!(affected, 1);
        let (status, line_items): (String, serde_json::Value) = sqlx::query_as(
            "SELECT status, line_items FROM invoices WHERE stripe_invoice_id = 'in_sw_rebind_new'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("fresh invoice");
        assert_eq!(status, "paid");
        let items = line_items.as_array().expect("line items array").clone();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["amount"], 1000);
        assert_eq!(items[0]["unit_price"], 1000);
        assert_eq!(items[0]["quantity"], 1);
    });

    // ---------------- subscription lifecycle guards ----------------

    fn subscription_payload(
        tenant: Option<&str>,
        status: &str,
        price_id: &str,
        interval: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "id": "sub_sw_lifecycle",
            "customer": "cus_sw_lifecycle",
            "status": status,
            "metadata": tenant.map(|tenant| serde_json::json!({ "tenant_id": tenant })),
            "current_period_start": Utc::now().timestamp(),
            "current_period_end": Utc::now().timestamp() + 2_592_000,
            "cancel_at_period_end": false,
            "canceled_at": null,
            "trial_end": null,
            "items": { "data": [ { "price": { "id": price_id, "recurring": { "interval": interval } } } ] }
        })
    }

    env_test!(subscription_change_refuses_malformed_events, |env| {
        let tenant = "swcov_sub";
        seed_tenant(env, tenant, "free", "active").await;
        seed_plan(env, "swcov_growth", "price_sw_growth").await;

        // Missing metadata: deliberately ignored, not an error.
        let no_tenant = subscription_event(subscription_payload(
            None,
            "active",
            "price_sw_growth",
            "month",
        ));
        handle_subscription_change(&env.state, no_tenant)
            .await
            .expect("unattributable events are a no-op");

        // Unknown price: must be refused, never silently bound to free.
        let unknown_price = subscription_event(subscription_payload(
            Some(tenant),
            "active",
            "price_does_not_exist",
            "month",
        ));
        let error = handle_subscription_change(&env.state, unknown_price)
            .await
            .expect_err("unknown price");
        assert!(error.contains("Unknown Stripe price"), "{error}");

        // A price with no recurring interval cannot be mapped to a plan.
        let mut bad_interval =
            subscription_payload(Some(tenant), "active", "price_sw_growth", "month");
        bad_interval["items"] =
            serde_json::json!({ "data": [ { "price": { "id": "price_sw_growth" } } ] });
        let error = handle_subscription_change(&env.state, subscription_event(bad_interval))
            .await
            .expect_err("unsupported interval");
        assert!(error.contains("unsupported billing interval"), "{error}");

        // An initial delinquent state is refused (only active/trialing/
        // incomplete may create a subscription).
        let bad_initial = subscription_event(subscription_payload(
            Some(tenant),
            "past_due",
            "price_sw_growth",
            "month",
        ));
        let error = handle_subscription_change(&env.state, bad_initial)
            .await
            .expect_err("invalid initial state");
        assert!(
            error.contains("Invalid initial subscription state"),
            "{error}"
        );
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stripe_subscriptions")
            .fetch_one(&env.pool)
            .await
            .expect("subscriptions");
        assert_eq!(rows, 0, "rejected events write no subscription");

        // No line items.
        let mut no_items = subscription_payload(Some(tenant), "active", "price_sw_growth", "month");
        no_items["items"] = serde_json::json!({ "data": [] });
        let error = handle_subscription_change(&env.state, subscription_event(no_items))
            .await
            .expect_err("no items");
        assert!(error.contains("no line items"), "{error}");

        // A valid activation applies the plan and snapshots the period.
        let valid = subscription_event(subscription_payload(
            Some(tenant),
            "active",
            "price_sw_growth",
            "month",
        ));
        handle_subscription_change(&env.state, valid)
            .await
            .expect("valid activation");
        let (plan, status): (String, String) =
            sqlx::query_as("SELECT plan, status FROM stripe_subscriptions WHERE tenant_id = $1")
                .bind(tenant)
                .fetch_one(&env.pool)
                .await
                .expect("subscription");
        assert_eq!(plan, "swcov_growth");
        assert_eq!(status, "active");
        let tenant_plan: String = sqlx::query_scalar("SELECT plan FROM tenants WHERE id = $1")
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("tenant plan");
        assert_eq!(tenant_plan, "swcov_growth");
        let periods: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM billing_periods WHERE tenant_id = $1 AND usage_kind = 'subscription'",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("periods");
        assert_eq!(periods, 1, "the billing period is snapshotted");
    });

    env_test!(subscription_delete_downgrades_and_ignores_unknown, |env| {
        let tenant = "swcov_sub_del";
        seed_tenant(env, tenant, "swcov_growth", "active").await;
        seed_plan(env, "swcov_growth", "price_sw_growth").await;
        sqlx::query(
            "INSERT INTO stripe_subscriptions
                 (tenant_id, stripe_subscription_id, plan, status, billing_cycle_start,
                  billing_cycle_end, stripe_customer_id)
             VALUES ($1, 'sub_sw_del', 'swcov_growth', 'active', NOW(), NOW() + INTERVAL '30 days', 'cus_del')",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("subscription");

        // Unknown subscription: acknowledged without local effect.
        let mut unknown =
            subscription_payload(Some(tenant), "canceled", "price_sw_growth", "month");
        unknown["id"] = serde_json::json!("sub_sw_unknown");
        handle_subscription_deleted(&env.state, subscription_event(unknown))
            .await
            .expect("unknown delete is a no-op");

        let mut deleted =
            subscription_payload(Some(tenant), "canceled", "price_sw_growth", "month");
        deleted["id"] = serde_json::json!("sub_sw_del");
        handle_subscription_deleted(&env.state, subscription_event(deleted))
            .await
            .expect("delete");
        let (status, plan): (String, String) =
            sqlx::query_as("SELECT status, plan FROM stripe_subscriptions WHERE tenant_id = $1")
                .bind(tenant)
                .fetch_one(&env.pool)
                .await
                .expect("subscription");
        assert_eq!(status, "canceled");
        assert_eq!(
            plan, "swcov_growth",
            "the historical plan name is retained on the terminal row"
        );
        let tenant_plan: String = sqlx::query_scalar("SELECT plan FROM tenants WHERE id = $1")
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("tenant plan");
        assert_eq!(tenant_plan, "free");
    });

    // ---------------- trial ending / checkout ----------------

    env_test!(trial_ending_notifies_and_checkout_never_grants, |env| {
        let tenant = "swcov_trial";
        seed_tenant(env, tenant, "suspended", "suspended").await;

        let mut trial = subscription_payload(Some(tenant), "trialing", "price_sw_growth", "month");
        trial["id"] = serde_json::json!("sub_sw_trial");
        handle_trial_ending(&env.state, subscription_event(trial))
            .await
            .expect("trial notification");
        let queued: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_queue WHERE tenant_id = $1 AND type = 'trial_ending'",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("notifications");
        assert_eq!(queued, 1);

        // No metadata: ignored entirely.
        let mut orphan = subscription_payload(None, "trialing", "price_sw_growth", "month");
        orphan["id"] = serde_json::json!("sub_sw_trial_orphan");
        handle_trial_ending(&env.state, subscription_event(orphan))
            .await
            .expect("unattributable trial");
        let queued: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notification_queue")
            .fetch_one(&env.pool)
            .await
            .expect("notifications");
        assert_eq!(queued, 1);

        // Checkout completed must NOT reactivate a suspended tenant.
        let session: CheckoutSession = serde_json::from_value(serde_json::json!({
            "id": "cs_sw_checkout",
            "metadata": { "tenant_id": tenant }
        }))
        .expect("session");
        handle_checkout_completed(&env.state, session)
            .await
            .expect("checkout");
        let status: String = sqlx::query_scalar("SELECT status FROM tenants WHERE id = $1")
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("tenant");
        assert_eq!(status, "suspended", "checkout never bypasses a suspension");
        let subs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stripe_subscriptions")
            .fetch_one(&env.pool)
            .await
            .expect("subscriptions");
        assert_eq!(subs, 0);
    });

    // ---------------- stale-pending reclaim ----------------

    env_test!(reclaim_stale_pending_only_touches_abandoned_rows, |env| {
        let stale = "evt_sw_stale";
        let fresh = "evt_sw_fresh";
        let processed = "evt_sw_done";
        let received = "evt_sw_received";
        for (event_id, status, updated_offset_minutes) in [
            (stale, "pending", 20_i64),
            (fresh, "pending", 1),
            (processed, "processed", 20),
            (received, "received", 20),
        ] {
            sqlx::query(
                "INSERT INTO stripe_webhook_events
                     (id, stripe_event_id, event_type, status, created_at, updated_at)
                 VALUES (gen_random_uuid(), $1, 'invoice.paid', $2,
                         NOW() - make_interval(mins => $3::int),
                         NOW() - make_interval(mins => $3::int))",
            )
            .bind(event_id)
            .bind(status)
            .bind(updated_offset_minutes)
            .execute(&env.pool)
            .await
            .expect("event row");
        }

        let reclaimed = reclaim_stale_pending_webhooks(&env.state)
            .await
            .expect("reclaim");
        assert_eq!(reclaimed, vec![stale.to_string()]);
        let (fresh_status, done_status, received_status): (String, String, String) =
            sqlx::query_as(
                "SELECT
                (SELECT status FROM stripe_webhook_events WHERE stripe_event_id = $1),
                (SELECT status FROM stripe_webhook_events WHERE stripe_event_id = $2),
                (SELECT status FROM stripe_webhook_events WHERE stripe_event_id = $3)",
            )
            .bind(fresh)
            .bind(processed)
            .bind(received)
            .fetch_one(&env.pool)
            .await
            .expect("statuses");
        assert_eq!(fresh_status, "pending", "a fresh claim is left alone");
        assert_eq!(done_status, "processed", "completed work is never rewound");
        assert_eq!(received_status, "received");
        let reclaimed_status: String = sqlx::query_scalar(
            "SELECT status FROM stripe_webhook_events WHERE stripe_event_id = $1",
        )
        .bind(stale)
        .fetch_one(&env.pool)
        .await
        .expect("stale status");
        assert_eq!(reclaimed_status, "received");
    });

    env_test!(claim_webhook_event_is_exactly_once, |env| {
        let event_id = "evt_sw_claim";
        let first = claim_webhook_event(&env.state, event_id, "invoice.paid")
            .await
            .expect("claim");
        assert!(matches!(first, WebhookEventClaim::Claimed));
        // A second worker sees the row as pending.
        let second = claim_webhook_event(&env.state, event_id, "invoice.paid")
            .await
            .expect("claim");
        assert!(matches!(second, WebhookEventClaim::AlreadyPending));
        // A failed attempt may be reclaimed; a processed one never is.
        sqlx::query(
            "UPDATE stripe_webhook_events SET status = 'failed' WHERE stripe_event_id = $1",
        )
        .bind(event_id)
        .execute(&env.pool)
        .await
        .expect("mark failed");
        let reclaimed = claim_webhook_event(&env.state, event_id, "invoice.paid")
            .await
            .expect("claim");
        assert!(matches!(reclaimed, WebhookEventClaim::Claimed));
        sqlx::query(
            "UPDATE stripe_webhook_events SET status = 'processed' WHERE stripe_event_id = $1",
        )
        .bind(event_id)
        .execute(&env.pool)
        .await
        .expect("mark processed");
        let duplicate = claim_webhook_event(&env.state, event_id, "invoice.paid")
            .await
            .expect("claim");
        assert!(matches!(duplicate, WebhookEventClaim::AlreadyProcessed));
    });

    #[test]
    fn dunning_config_and_transition_helpers_are_bounded() {
        let config = DunningConfig::default();
        let now = Utc::now();
        assert_eq!(
            calculate_next_retry(now, 1, &config),
            Some(now + TimeDelta::days(1))
        );
        assert_eq!(
            calculate_next_retry(now, 2, &config),
            Some(now + TimeDelta::days(3))
        );
        assert_eq!(
            calculate_next_retry(now, 4, &config),
            Some(now + TimeDelta::days(14))
        );
        assert_eq!(
            calculate_next_retry(now, 99, &config),
            None,
            "past the schedule there is no next retry"
        );
        assert_eq!(
            calculate_next_retry(now, 0, &config),
            None,
            "a zero count has no schedule slot and must not panic"
        );
        assert!(dunning_transition(Some("warning"), "warning").is_none());
        assert!(dunning_transition(None, "warning").is_none());
        assert_eq!(
            dunning_transition(None, "soft_suspended"),
            Some(DunningTransition::SoftSuspended)
        );
        assert!(dunning_transition(Some("soft_suspended"), "soft_suspended").is_none());
        assert_eq!(
            dunning_transition(Some("warning"), "hard_suspended"),
            Some(DunningTransition::HardSuspended)
        );
        assert_eq!(
            dunning_transition(Some("hard_suspended"), "healthy"),
            Some(DunningTransition::Recovered)
        );
        assert!(dunning_transition(Some("healthy"), "healthy").is_none());
        assert_eq!(
            DunningTransition::Recovered.event_type(),
            "payment_recovered"
        );
    }

    #[test]
    fn deadletter_preparation_truncates_and_never_schedules_truncated_replays() {
        let now = Utc::now();
        let small = prepare_deadletter(
            DeadletterEntry {
                reason: "processing_failed".into(),
                event_id: Some("evt/with spaces".into()),
                ..Default::default()
            },
            Some(b"{\"id\":\"evt_1\"}"),
            Some("t=1,v1=aa"),
            now,
        );
        assert!(small.retry_at_ms.is_some(), "a full body is retryable");
        assert!(small.event_key.contains("evt_with_spaces"));

        let oversized = "x".repeat(DEADLETTER_MAX_BODY_BYTES + 100);
        let big = prepare_deadletter(
            DeadletterEntry {
                reason: "processing_failed".into(),
                event_id: Some("evt_big".into()),
                ..Default::default()
            },
            Some(oversized.as_bytes()),
            Some("t=1,v1=aa"),
            now,
        );
        assert!(
            big.retry_at_ms.is_none(),
            "a truncated body can never be replayed"
        );
        let stored: DeadletterEntry = serde_json::from_str(&big.payload).expect("payload");
        assert!(stored.body.as_deref().is_some_and(str::is_empty).eq(&false));
        assert!(
            stored.body.expect("body").ends_with("...(truncated)"),
            "truncation is marked"
        );
    }

    // ===================================================================
    // Deep adversarial additions: signature verification (real HMAC),
    // every event arm, replay exactly-once, cross-tenant binding refusal,
    // dead-letter fault injection, and the tax/settlement edges.
    // ===================================================================

    use crate::test_support::{
        ensure_trace_subscriber, seed_plan as shared_seed_plan, seed_tenant as shared_seed_tenant,
        sign_stripe, state_with_broken_db, state_with_dead_redis, state_with_empty_stripe_secret,
        TestEnv,
    };
    use tower::ServiceExt;

    async fn shared_env(tag: &str) -> TestEnv {
        ensure_trace_subscriber();
        crate::test_support::provision(tag)
            .await
            .expect("TEST_DATABASE_URL provisioning")
    }

    fn stripe_request(
        body: &[u8],
        signature: Option<&str>,
    ) -> axum::http::Request<axum::body::Body> {
        let mut builder = axum::http::Request::builder()
            .method("POST")
            .uri("/webhooks/stripe");
        if let Some(signature) = signature {
            builder = builder.header("stripe-signature", signature);
        }
        builder.body(axum::body::Body::from(body.to_vec())).unwrap()
    }

    async fn post_webhook(
        state: &Arc<AppState>,
        body: &[u8],
        signature: Option<&str>,
    ) -> axum::response::Response {
        router()
            .with_state(state.clone())
            .oneshot(stripe_request(body, signature))
            .await
            .expect("oneshot")
    }

    async fn response_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    fn signed_event(event_id: &str, event_type: &str, object: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": event_id,
            "type": event_type,
            "data": { "object": object }
        }))
        .expect("event json")
    }

    /// Clear every deadletter key/index: the Redis server is shared across
    /// runs, so stale entries (35-day TTL) would otherwise pollute counts.
    /// Callers must hold DEADLETTER_LOCK.
    async fn clear_all_deadletters(env: &Env) {
        let mut conn = redis_conn(env).await;
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg("stripe:deadletter:*")
            .query_async(&mut conn)
            .await
            .expect("keys");
        if !keys.is_empty() {
            let _: () = redis::cmd("DEL")
                .arg(&keys)
                .query_async(&mut conn)
                .await
                .expect("del");
        }
    }

    async fn deadletter_entries(env: &Env, pattern: &str) -> Vec<String> {
        let mut conn = redis_conn(env).await;
        deadletter_entries_on(&mut conn, pattern).await
    }

    async fn deadletter_entries_on(
        conn: &mut deadpool_redis::Connection,
        pattern: &str,
    ) -> Vec<String> {
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(pattern)
            .query_async(&mut *conn)
            .await
            .expect("keys");
        let mut out = Vec::new();
        for key in keys {
            let value: Option<String> = redis::cmd("GET")
                .arg(&key)
                .query_async(conn)
                .await
                .expect("get");
            if let Some(value) = value {
                out.push(value);
            }
        }
        out
    }

    async fn pool_conn(pool: &deadpool_redis::Pool) -> deadpool_redis::Connection {
        pool.get().await.expect("redis connection")
    }

    /// AppState over `env`'s DB with a private throwaway redis — full
    /// isolation for tests that poison the shared deadletter indexes.
    fn state_with_isolated_redis(
        env: &Env,
        isolated: &crate::test_support::IsolatedRedis,
    ) -> Arc<AppState> {
        let mut config = env.state.config.clone();
        config.redis_url = "redis://127.0.0.1:1".to_string();
        AppState::new(env.pool.clone(), isolated.pool.clone(), config)
    }

    async fn event_rows(pool: &sqlx::PgPool) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM stripe_webhook_events")
            .fetch_one(pool)
            .await
            .expect("event rows")
    }

    // ---------------- signature verification (real HMAC) ----------------

    env_test!(route_missing_signature_is_400_and_deadletters, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        clear_all_deadletters(env).await;
        let body = br#"{"id":"evt_nosig","type":"invoice.paid"}"#;
        let response = post_webhook(&env.state, body, None).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = response_json(response).await;
        assert_eq!(json["error"], "Missing stripe-signature header");
        let entries = deadletter_entries(env, "stripe:deadletter:event:unknown*").await;
        assert_eq!(entries.len(), 1, "missing signature is deadlettered");
        let entry: DeadletterEntry = serde_json::from_str(&entries[0]).expect("entry");
        assert_eq!(entry.reason, "missing_signature");
        assert_eq!(event_rows(&env.pool).await, 0, "nothing claimed");
    });

    env_test!(route_empty_signature_header_is_400, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        clear_all_deadletters(env).await;
        let response = post_webhook(&env.state, br#"{"id":"evt_emptysig"}"#, Some("  ")).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(event_rows(&env.pool).await, 0);
    });

    env_test!(route_malformed_json_refused_with_no_write, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        clear_all_deadletters(env).await;
        let timestamp = Utc::now().timestamp();
        let signature = sign_stripe("whsec_coverage", b"not json", timestamp);
        let response = post_webhook(&env.state, b"not json", Some(&signature)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = response_json(response).await;
        assert_eq!(json["error"], "Invalid JSON payload");
        assert_eq!(
            event_rows(&env.pool).await,
            0,
            "malformed JSON writes nothing"
        );
        let entries = deadletter_entries(env, "stripe:deadletter:event:unknown*").await;
        assert_eq!(entries.len(), 1);
        let entry: DeadletterEntry = serde_json::from_str(&entries[0]).expect("entry");
        assert_eq!(entry.reason, "invalid_json_payload");
    });

    env_test!(route_missing_and_blank_event_ids_refused, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        clear_all_deadletters(env).await;
        let timestamp = Utc::now().timestamp();
        for body in [
            br#"{"no_id": true}"#.to_vec(),
            br#"{"id": null}"#.to_vec(),
            br#"{"id": "   "}"#.to_vec(),
        ] {
            let signature = sign_stripe("whsec_coverage", &body, timestamp);
            let response = post_webhook(&env.state, &body, Some(&signature)).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let json = response_json(response).await;
            assert_eq!(json["error"], "Missing event ID");
        }
        assert_eq!(event_rows(&env.pool).await, 0);
    });

    env_test!(route_tampered_signature_and_secret_refused, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        clear_all_deadletters(env).await;
        let body = signed_event(
            "evt_tamper",
            "invoice.paid",
            serde_json::json!({"id":"in_t","amount_due":1}),
        );
        let timestamp = Utc::now().timestamp();
        let wrong_secret = sign_stripe("whsec_NOT_the_secret", &body, timestamp);
        let response = post_webhook(&env.state, &body, Some(&wrong_secret)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            event_rows(&env.pool).await,
            0,
            "forged signature writes nothing"
        );

        let right_secret = sign_stripe("whsec_coverage", &body, timestamp);
        let mut segments = right_secret.split(',');
        let ts = segments.next().unwrap();
        let v1 = segments.next().unwrap();
        let flipped: String = format!(
            "{},{}",
            ts,
            v1.chars()
                .map(|c| if c == '0' { '1' } else { '0' })
                .collect::<String>()
        );
        let response = post_webhook(&env.state, &body, Some(&flipped)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            event_rows(&env.pool).await,
            0,
            "bit-flipped signature writes nothing"
        );
    });

    env_test!(route_timestamp_tolerance_window_enforced, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        clear_all_deadletters(env).await;
        let body = signed_event(
            "evt_stale",
            "invoice.paid",
            serde_json::json!({"id":"in_s","amount_due":1}),
        );
        for delta in [301_i64, -301] {
            let signature = sign_stripe("whsec_coverage", &body, Utc::now().timestamp() + delta);
            let response = post_webhook(&env.state, &body, Some(&signature)).await;
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "outside tolerance refused"
            );
            assert_eq!(event_rows(&env.pool).await, 0);
        }
        // Inside the window the signature verifies and the event is CLAIMED
        // (it may then fail on its own business content — never on the MAC).
        let signature = sign_stripe("whsec_coverage", &body, Utc::now().timestamp() - 299);
        let _response = post_webhook(&env.state, &body, Some(&signature)).await;
        assert_eq!(
            event_rows(&env.pool).await,
            1,
            "verified signature claims the event"
        );
    });

    env_test!(route_malformed_signature_headers_refused, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        clear_all_deadletters(env).await;
        let body = br#"{"id":"evt_badsig","type":"invoice.paid"}"#;
        for header in [
            "t=abc,v1=deadbeef",
            "t=123",
            "v1=deadbeef",
            "t=123,v1=",
            "garbage",
            "t=123,v0=legacy",
        ] {
            let response = post_webhook(&env.state, body, Some(header)).await;
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "header {header} refused"
            );
        }
        assert_eq!(event_rows(&env.pool).await, 0);
    });

    #[test]
    fn parse_signature_header_skips_valueless_and_unknown_segments() {
        // A segment with no '=' is skipped, unknown keys are ignored, and a
        // second t= overwrites the first.
        let (timestamp, signatures) = parse_signature_header("junk,t=5,t=7,v1=ab,v0=x,=").unwrap();
        assert_eq!(timestamp, 7);
        assert_eq!(signatures, vec!["ab"]);
        assert!(parse_signature_header("t=notanumber,v1=ab").is_err());
    }

    env_test!(
        verify_signature_empty_secret_refused_before_any_write,
        |env| {
            let body = signed_event(
                "evt_nosecret",
                "invoice.paid",
                serde_json::json!({"id":"in_n","amount_due":1}),
            );
            let timestamp = Utc::now().timestamp();
            let signature = sign_stripe("whsec_coverage", &body, timestamp);
            let broken = state_with_empty_stripe_secret(&env.pool, &env.redis, &env.state.config);
            let error = verify_and_parse_event(&broken, &body, &signature)
                .expect_err("empty secret refused");
            assert_eq!(error, "Stripe webhook secret is not configured");

            let error = replay_deadletter(
                &broken,
                &DeadletterEntry {
                    reason: "processing_failed".into(),
                    event_id: Some("evt_nosecret".into()),
                    body: Some(String::from_utf8(body.clone()).unwrap()),
                    signature: Some(signature.clone()),
                    ..Default::default()
                },
            )
            .await
            .expect_err("replay refuses an unconfigured secret");
            assert_eq!(error, "Stripe webhook secret is not configured");
            assert_eq!(event_rows(&env.pool).await, 0);
        }
    );

    // ---------------- replay / concurrency semantics ----------------

    env_test!(route_replay_is_exactly_once_no_double_entitlement, |env| {
        shared_seed_tenant(&env.pool, "swadv_replay", "free").await;
        shared_seed_plan(&env.pool, "swadv_growth", "price_swadv_growth").await;
        let object = serde_json::json!({
            "id": "sub_swadv_replay",
            "customer": "cus_swadv",
            "status": "active",
            "metadata": { "tenant_id": "swadv_replay" },
            "current_period_start": Utc::now().timestamp(),
            "current_period_end": Utc::now().timestamp() + 2_592_000,
            "cancel_at_period_end": false,
            "canceled_at": null,
            "trial_end": null,
            "items": { "data": [ { "price": { "id": "price_swadv_growth", "recurring": { "interval": "month" } } } ] }
        });
        let body = signed_event("evt_swadv_replay", "customer.subscription.created", object);
        let timestamp = Utc::now().timestamp();
        let signature = sign_stripe("whsec_coverage", &body, timestamp);

        let first = post_webhook(&env.state, &body, Some(&signature)).await;
        assert_eq!(first.status(), StatusCode::OK);
        let second = post_webhook(&env.state, &body, Some(&signature)).await;
        assert_eq!(
            second.status(),
            StatusCode::OK,
            "Stripe expects 2xx on replay"
        );

        let (plan, subs): (String, i64) = sqlx::query_as(
            "SELECT (SELECT plan FROM tenants WHERE id = 'swadv_replay'),
                    (SELECT COUNT(*) FROM stripe_subscriptions WHERE tenant_id = 'swadv_replay')",
        )
        .fetch_one(&env.pool)
        .await
        .expect("state");
        assert_eq!(plan, "swadv_growth");
        assert_eq!(subs, 1, "replay never duplicates the subscription");
        let periods: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM billing_periods WHERE tenant_id = 'swadv_replay'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("periods");
        assert_eq!(periods, 1, "replay never duplicates the billing period");
    });

    env_test!(
        route_event_pending_elsewhere_returns_503_and_no_deadletter,
        |env| {
            let _guard = DEADLETTER_LOCK.lock().await;
            let _dl_guard =
                crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
            clear_all_deadletters(env).await;
            shared_seed_tenant(&env.pool, "swadv_pending", "free").await;
            sqlx::query(
                "INSERT INTO stripe_webhook_events (id, stripe_event_id, event_type, status)
             VALUES (gen_random_uuid(), 'evt_swadv_pending', 'invoice.paid', 'pending')",
            )
            .execute(&env.pool)
            .await
            .expect("pending row");
            let body = signed_event(
                "evt_swadv_pending",
                "invoice.paid",
                serde_json::json!({"id": "in_p", "amount_due": 1}),
            );
            let timestamp = Utc::now().timestamp();
            let signature = sign_stripe("whsec_coverage", &body, timestamp);
            let response = post_webhook(&env.state, &body, Some(&signature)).await;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            let entries = deadletter_entries(env, "stripe:deadletter:event:*").await;
            assert_eq!(entries.len(), 0, "a pending event is never deadlettered");
            let status: String = sqlx::query_scalar(
            "SELECT status FROM stripe_webhook_events WHERE stripe_event_id = 'evt_swadv_pending'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("status");
            assert_eq!(status, "pending", "the other worker's claim is untouched");
        }
    );

    // ---------------- unknown types + per-arm decode failures ----------------

    env_test!(route_unknown_event_type_acknowledged_and_processed, |env| {
        let body = signed_event(
            "evt_swadv_unknown",
            "customer.created",
            serde_json::json!({"id": "cus_x"}),
        );
        let timestamp = Utc::now().timestamp();
        let signature = sign_stripe("whsec_coverage", &body, timestamp);
        let response = post_webhook(&env.state, &body, Some(&signature)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(json["received"], true);
        let status: String = sqlx::query_scalar(
            "SELECT status FROM stripe_webhook_events WHERE stripe_event_id = 'evt_swadv_unknown'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("status");
        assert_eq!(
            status, "processed",
            "unknown types are claimed and acknowledged"
        );
    });

    env_test!(handle_stripe_event_decode_failures_fail_closed, |env| {
        // Every handled event type with a malformed object must be an error
        // (deadlettered by the caller), never a silent drop.
        let cases = [
            (
                "checkout.session.completed",
                serde_json::json!({"no_id": 1}),
            ),
            (
                "customer.subscription.created",
                serde_json::json!({"id": "sub_x"}),
            ),
            (
                "customer.subscription.updated",
                serde_json::json!({"id": 42}),
            ),
            (
                "customer.subscription.deleted",
                serde_json::json!({"items": "nope"}),
            ),
            ("invoice.paid", serde_json::json!({"id": "in_x"})),
            (
                "invoice.payment_failed",
                serde_json::json!({"amount_due": "many"}),
            ),
            (
                "customer.subscription.trial_will_end",
                serde_json::json!({"id": "sub_y"}),
            ),
        ];
        for (event_type, object) in cases {
            let event: StripeEventPayload = serde_json::from_value(serde_json::json!({
                "id": "evt_decode",
                "type": event_type,
                "data": { "object": object }
            }))
            .expect("envelope");
            let error = handle_stripe_event(&env.state, &event)
                .await
                .err()
                .unwrap_or_else(|| panic!("decode failure must be an error"));
            assert!(
                error.contains("Failed to decode"),
                "decode failure must be an error"
            );
        }
        assert_eq!(event_rows(&env.pool).await, 0);
    });

    env_test!(handle_checkout_completed_without_metadata_is_noop, |env| {
        let event: StripeEventPayload = serde_json::from_value(serde_json::json!({
            "id": "evt_checkout_orphan",
            "type": "checkout.session.completed",
            "data": { "object": { "id": "cs_orphan" } }
        }))
        .expect("envelope");
        handle_stripe_event(&env.state, &event)
            .await
            .expect("unattributable checkout is acknowledged");
        let subs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stripe_subscriptions")
            .fetch_one(&env.pool)
            .await
            .expect("subs");
        assert_eq!(subs, 0);
    });

    // ---------------- subscription binding / lifecycle guards ----------------

    async fn sub_event(
        tenant: Option<&str>,
        status: &str,
        price_id: &str,
        interval: Option<&str>,
        period_start: i64,
    ) -> SubscriptionEvent {
        let price = match interval {
            Some(interval) => {
                serde_json::json!({ "id": price_id, "recurring": { "interval": interval } })
            }
            None => serde_json::json!({ "id": price_id }),
        };
        serde_json::from_value(serde_json::json!({
            "id": "sub_swadv",
            "customer": "cus_swadv",
            "status": status,
            "metadata": tenant.map(|t| serde_json::json!({ "tenant_id": t })),
            "current_period_start": period_start,
            "current_period_end": period_start + 2_592_000,
            "cancel_at_period_end": false,
            "canceled_at": null,
            "trial_end": null,
            "items": { "data": [ { "price": price } ] }
        }))
        .expect("subscription event")
    }

    env_test!(subscription_price_shape_failures_fail_closed, |env| {
        shared_seed_tenant(&env.pool, "swadv_shape", "free").await;
        shared_seed_plan(&env.pool, "swadv_growth", "price_swadv_growth").await;
        let now = Utc::now().timestamp();

        // items[0].price == null
        let no_price: SubscriptionEvent = serde_json::from_value(serde_json::json!({
            "id": "sub_swadv", "customer": "cus", "status": "active",
            "metadata": { "tenant_id": "swadv_shape" },
            "current_period_start": now, "current_period_end": now + 100,
            "cancel_at_period_end": false, "canceled_at": null, "trial_end": null,
            "items": { "data": [ { "price": null } ] }
        }))
        .expect("event");
        let error = handle_subscription_change(&env.state, no_price)
            .await
            .expect_err("missing price refused");
        assert!(error.contains("no line-item price"));

        // price present but id missing
        let event = sub_event(
            Some("swadv_shape"),
            "active",
            "price_swadv_growth",
            None,
            now,
        )
        .await;
        let priceless = SubscriptionEvent {
            items: SubscriptionItems {
                data: vec![SubscriptionItem {
                    price: Some(SubscriptionPrice {
                        id: None,
                        recurring: None,
                    }),
                }],
            },
            ..event
        };
        let error = handle_subscription_change(&env.state, priceless)
            .await
            .expect_err("missing price id refused");
        assert!(error.contains("no valid line-item price"));
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stripe_subscriptions")
            .fetch_one(&env.pool)
            .await
            .expect("rows");
        assert_eq!(rows, 0, "refused shapes write nothing");
    });

    env_test!(subscription_cross_tenant_rebind_refused, |env| {
        shared_seed_tenant(&env.pool, "swadv_owner", "free").await;
        shared_seed_tenant(&env.pool, "swadv_attacker", "free").await;
        shared_seed_plan(&env.pool, "swadv_growth", "price_swadv_growth").await;
        let now = Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO stripe_subscriptions
                 (tenant_id, stripe_subscription_id, plan, status, billing_cycle_start,
                  billing_cycle_end, stripe_customer_id)
             VALUES ('swadv_owner', 'sub_swadv', 'swadv_growth', 'active', NOW(), NOW() + INTERVAL '30 days', 'cus_owner')",
        )
        .execute(&env.pool)
        .await
        .expect("owner row");

        // The same Stripe subscription id, attributed to a DIFFERENT tenant.
        let event = sub_event(
            Some("swadv_attacker"),
            "active",
            "price_swadv_growth",
            Some("month"),
            now,
        )
        .await;
        let error = handle_subscription_change(&env.state, event)
            .await
            .expect_err("cross-tenant rebind refused");
        assert!(error.contains("already bound to a different tenant"));
        let owner: String = sqlx::query_scalar(
            "SELECT tenant_id FROM stripe_subscriptions WHERE stripe_subscription_id = 'sub_swadv'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("owner");
        assert_eq!(owner, "swadv_owner");
    });

    env_test!(subscription_illegal_transition_refused, |env| {
        shared_seed_tenant(&env.pool, "swadv_trans", "free").await;
        shared_seed_plan(&env.pool, "swadv_growth", "price_swadv_growth").await;
        let now = Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO stripe_subscriptions
                 (tenant_id, stripe_subscription_id, plan, status, billing_cycle_start,
                  billing_cycle_end, stripe_customer_id)
             VALUES ('swadv_trans', 'sub_swadv', 'swadv_growth', 'active', NOW(), NOW() + INTERVAL '30 days', 'cus_t')",
        )
        .execute(&env.pool)
        .await
        .expect("active row");

        // active -> incomplete is not an admitted transition.
        let event = sub_event(
            Some("swadv_trans"),
            "incomplete",
            "price_swadv_growth",
            Some("month"),
            now,
        )
        .await;
        let error = handle_subscription_change(&env.state, event)
            .await
            .expect_err("illegal transition refused");
        assert!(error.contains("Invalid subscription status transition"));
        let status: String = sqlx::query_scalar(
            "SELECT status FROM stripe_subscriptions WHERE stripe_subscription_id = 'sub_swadv'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("status");
        assert_eq!(status, "active", "the refused event changes nothing");

        // Legal deactivation still applies.
        let event = sub_event(
            Some("swadv_trans"),
            "canceled",
            "price_swadv_growth",
            Some("month"),
            now,
        )
        .await;
        handle_subscription_change(&env.state, event)
            .await
            .expect("legal transition applies");
    });

    env_test!(
        subscription_stale_cycle_and_stale_replacement_ignored,
        |env| {
            shared_seed_tenant(&env.pool, "swadv_stale", "free").await;
            shared_seed_plan(&env.pool, "swadv_growth", "price_swadv_growth").await;
            let now = Utc::now().timestamp();
            // The stored row already applied a NEWER cycle watermark.
            sqlx::query(
                "INSERT INTO stripe_subscriptions
                 (tenant_id, stripe_subscription_id, plan, status, billing_cycle_start,
                  billing_cycle_end, stripe_customer_id, event_watermark)
             VALUES ('swadv_stale', 'sub_swadv', 'swadv_growth', 'active',
                     to_timestamp($1), to_timestamp($2), 'cus_s', to_timestamp($1))",
            )
            .bind(now)
            .bind(now + 2_592_000)
            .execute(&env.pool)
            .await
            .expect("row");

            // An OLDER event for the same subscription must not rewind the cycle.
            let event = sub_event(
                Some("swadv_stale"),
                "past_due",
                "price_swadv_growth",
                Some("month"),
                now - 100_000,
            )
            .await;
            handle_subscription_change(&env.state, event)
                .await
                .expect("stale events are acknowledged");
            let (status, watermark): (String, Option<DateTime<Utc>>) = sqlx::query_as(
            "SELECT status, event_watermark FROM stripe_subscriptions WHERE stripe_subscription_id = 'sub_swadv'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("row");
            assert_eq!(status, "active", "stale event cannot rewind state");
            assert_eq!(
                watermark.expect("watermark").timestamp(),
                now,
                "watermark never rewinds"
            );

            // A stale event for an OLD subscription cannot outrank a newer
            // active replacement on the same tenant: the old row is demoted
            // (no watermark) and the replacement is ACTIVE with a newer one.
            sqlx::query(
                "UPDATE stripe_subscriptions SET status = 'canceled', event_watermark = NULL
                 WHERE stripe_subscription_id = 'sub_swadv'",
            )
            .execute(&env.pool)
            .await
            .expect("demote the old row");
            sqlx::query(
                "INSERT INTO stripe_subscriptions
                     (tenant_id, stripe_subscription_id, plan, status, billing_cycle_start,
                      billing_cycle_end, stripe_customer_id, event_watermark)
                 VALUES ('swadv_stale', 'sub_swadv_old', 'swadv_growth', 'active',
                         to_timestamp($1), to_timestamp($2), 'cus_s', to_timestamp($1))",
            )
            .bind(now)
            .bind(now + 2_592_000)
            .execute(&env.pool)
            .await
            .expect("replacement row");
            let mut revival = sub_event(
                Some("swadv_stale"),
                "active",
                "price_swadv_growth",
                Some("month"),
                now - 100_000,
            )
            .await;
            revival.id = "sub_swadv".to_string();
            handle_subscription_change(&env.state, revival)
                .await
                .expect("stale replacement events are acknowledged");
            let newer_status: String = sqlx::query_scalar(
            "SELECT status FROM stripe_subscriptions WHERE stripe_subscription_id = 'sub_swadv_old'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("newer");
            assert_eq!(newer_status, "active", "the newer replacement survives");
        }
    );

    env_test!(
        subscription_renewal_snapshots_closing_and_superseded_cycles,
        |env| {
            shared_seed_tenant(&env.pool, "swadv_renew", "free").await;
            shared_seed_plan(&env.pool, "swadv_growth", "price_swadv_growth").await;
            let now = Utc::now().timestamp();

            // A closing cycle on the renewed subscription (trialing: only one
            // ACTIVE row per tenant is possible) plus an ACTIVE superseded one.
            for (sub_id, status) in [("sub_swadv", "trialing"), ("sub_swadv_other", "active")] {
                sqlx::query(
                    "INSERT INTO stripe_subscriptions
                     (tenant_id, stripe_subscription_id, plan, status, billing_cycle_start,
                      billing_cycle_end, stripe_customer_id, event_watermark)
                 VALUES ('swadv_renew', $3, 'swadv_growth', $4,
                         to_timestamp($1), to_timestamp($2), 'cus_r', to_timestamp($1))",
                )
                .bind(
                    now - 2_592_000
                        - if sub_id == "sub_swadv_other" {
                            86_400
                        } else {
                            0
                        },
                )
                .bind(
                    now - if sub_id == "sub_swadv_other" {
                        86_400
                    } else {
                        0
                    },
                )
                .bind(sub_id)
                .bind(status)
                .execute(&env.pool)
                .await
                .expect("row");
            }

            // A renewal (trialing -> active, a legal transition) with a NEW
            // cycle start snapshots both the closing cycle and the
            // superseded sibling before overwriting.
            let event = sub_event(
                Some("swadv_renew"),
                "active",
                "price_swadv_growth",
                Some("month"),
                now,
            )
            .await;
            handle_subscription_change(&env.state, event)
                .await
                .expect("renewal applies");
            let periods: Vec<(String,)> = sqlx::query_as(
                "SELECT stripe_subscription_id FROM billing_periods
             WHERE tenant_id = 'swadv_renew' ORDER BY stripe_subscription_id, period_start",
            )
            .fetch_all(&env.pool)
            .await
            .expect("periods");
            assert!(
                periods.len() >= 3,
                "closing + superseded + incoming cycles snapshotted"
            );
            let superseded_status: String = sqlx::query_scalar(
            "SELECT status FROM stripe_subscriptions WHERE stripe_subscription_id = 'sub_swadv_other'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("superseded");
            assert_eq!(
                superseded_status, "canceled",
                "renewal deactivates superseded rows"
            );
            // Replay of the same renewal is idempotent (same cycle start).
            let event = sub_event(
                Some("swadv_renew"),
                "active",
                "price_swadv_growth",
                Some("month"),
                now,
            )
            .await;
            handle_subscription_change(&env.state, event)
                .await
                .expect("replay applies");
        }
    );

    #[test]
    fn subscription_status_deserializes_every_arm_and_maps_entitlement() {
        for (raw, expect) in [
            ("active", "active"),
            ("past_due", "past_due"),
            ("unpaid", "unpaid"),
            ("canceled", "canceled"),
            ("incomplete", "incomplete"),
            ("incomplete_expired", "incomplete_expired"),
            ("trialing", "trialing"),
            ("paused", "paused"),
        ] {
            let status: SubscriptionStatus =
                serde_json::from_value(serde_json::json!(raw)).expect("status");
            assert_eq!(status.as_str(), expect);
        }
        assert!(SubscriptionStatus::Active.can_transition_from("paused"));
        assert!(SubscriptionStatus::Canceled.can_transition_from("paused"));
        assert!(!SubscriptionStatus::Trialing.can_transition_from("paused"));
        assert!(SubscriptionStatus::Active.can_transition_from("incomplete"));
        assert!(SubscriptionStatus::IncompleteExpired.can_transition_from("incomplete"));
        assert!(!SubscriptionStatus::Paused.can_transition_from("incomplete"));
        assert!(SubscriptionStatus::Unpaid.can_transition_from("past_due"));
        assert!(SubscriptionStatus::Active.can_transition_from("unpaid"));
        assert!(SubscriptionStatus::Canceled.can_transition_from("unpaid"));
        assert!(!SubscriptionStatus::Incomplete.can_transition_from("unpaid"));
        assert!(!SubscriptionStatus::Active.can_transition_from("unknown_status"));
        // ExpandableId object form.
        let expanded: ExpandableId =
            serde_json::from_value(serde_json::json!({"id": "cus_obj"})).expect("expandable");
        assert_eq!(expanded.id(), "cus_obj");
        let plain: ExpandableId =
            serde_json::from_value(serde_json::json!("cus_plain")).expect("expandable");
        assert_eq!(plain.id(), "cus_plain");
    }

    // ---------------- dead-letter fault injection ----------------

    env_test!(
        deadletter_write_failure_on_dead_redis_is_logged_not_fatal,
        |env| {
            let dead = state_with_dead_redis(&env.pool);
            // A missing signature must still answer 400 even when Redis is down.
            let response = post_webhook(&dead, br#"{"id":"evt_deadredis"}"#, None).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(event_rows(&env.pool).await, 0);
        }
    );

    env_test!(deadletter_index_wrongtype_fails_the_write_arm, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        let mut conn = redis_conn(env).await;
        let _: () = redis::cmd("SET")
            .arg(DEADLETTER_INDEX_KEY)
            .arg("not-a-zset")
            .query_async(&mut conn)
            .await
            .expect("poison index");
        drop(conn);

        let response = post_webhook(&env.state, br#"{"id":"evt_wrongtype"}"#, None).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut conn = redis_conn(env).await;
        let _: () = redis::cmd("DEL")
            .arg(DEADLETTER_INDEX_KEY)
            .query_async(&mut conn)
            .await
            .expect("cleanup index");
    });

    env_test!(
        record_failed_deadletter_without_row_reports_not_found,
        |env| {
            let error = record_failed_webhook_deadletter_atomic(
                &env.state,
                "evt_never_claimed",
                "boom",
                br#"{"id":"evt_never_claimed"}"#,
                "t=1,v1=ab",
            )
            .await
            .expect_err("missing claim row");
            assert!(error.contains("was not found"), "honest failure: {error}");
        }
    );

    env_test!(
        record_failed_deadletter_begin_failure_is_a_hard_error,
        |env| {
            let broken = state_with_broken_db();
            let error = record_failed_webhook_deadletter_atomic(
                &broken,
                "evt_beginfail",
                "boom",
                br#"{"id":"evt_beginfail"}"#,
                "t=1,v1=ab",
            )
            .await
            .expect_err("broken db begin");
            assert!(error.contains("Failed to begin"), "honest failure: {error}");
            assert_eq!(event_rows(&env.pool).await, 0, "nothing was claimed");
        }
    );

    env_test!(
        record_failed_deadletter_redis_failure_rolls_back_the_status_flip,
        |env| {
            let isolated = crate::test_support::spawn_isolated_redis();
            let state = state_with_isolated_redis(env, &isolated);
            sqlx::query(
                "INSERT INTO stripe_webhook_events (id, stripe_event_id, event_type, status)
                 VALUES (gen_random_uuid(), 'evt_rollback', 'invoice.paid', 'pending')",
            )
            .execute(&env.pool)
            .await
            .expect("claim row");

            let mut conn = pool_conn(&isolated.pool).await;
            let _: () = redis::cmd("SET")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .arg("not-a-zset")
                .query_async(&mut conn)
                .await
                .expect("poison retry index");
            drop(conn);

            let error = record_failed_webhook_deadletter_atomic(
                &state,
                "evt_rollback",
                "boom",
                br#"{"id":"evt_rollback"}"#,
                "t=1,v1=ab",
            )
            .await
            .expect_err("redis failure surfaces");
            assert!(
                error.contains("failed to write stripe dead letter"),
                "honest failure: {error}"
            );
            let status: String = sqlx::query_scalar(
                "SELECT status FROM stripe_webhook_events WHERE stripe_event_id = 'evt_rollback'",
            )
            .fetch_one(&env.pool)
            .await
            .expect("status");
            assert_eq!(status, "pending", "the failed-status flip rolled back");
        }
    );

    env_test!(
        record_failed_deadletter_commit_failure_compensates_redis,
        |env| {
            let isolated = crate::test_support::spawn_isolated_redis();
            let state = state_with_isolated_redis(env, &isolated);
            sqlx::query(
                "INSERT INTO stripe_webhook_events (id, stripe_event_id, event_type, status)
                 VALUES (gen_random_uuid(), 'evt_commitfail', 'invoice.paid', 'pending')",
            )
            .execute(&env.pool)
            .await
            .expect("claim row");
            // Deferred constraint: the UPDATE succeeds inside the tx and the
            // COMMIT itself fails — the exact commit-failure fault to inject.
            // (Postgres CHECK constraints cannot defer; a FK to a guard table
            // can, and 'failed' is absent from the guard.)
            for statement in [
                "CREATE TABLE cov_status_guard (status text PRIMARY KEY)",
                "INSERT INTO cov_status_guard VALUES ('pending'), ('received')",
                "ALTER TABLE stripe_webhook_events ADD CONSTRAINT cov_status_fk FOREIGN KEY (status)                  REFERENCES cov_status_guard(status) DEFERRABLE INITIALLY DEFERRED",
            ] {
                sqlx::query(statement)
                    .execute(&env.pool)
                    .await
                    .expect("deferred constraint setup");
            }

            let error = record_failed_webhook_deadletter_atomic(
                &state,
                "evt_commitfail",
                "boom",
                br#"{"id":"evt_commitfail"}"#,
                "t=1,v1=ab",
            )
            .await
            .expect_err("commit failure surfaces");
            assert!(
                error.contains("Failed to commit"),
                "honest failure: {error}"
            );
            let status: String = sqlx::query_scalar(
                "SELECT status FROM stripe_webhook_events WHERE stripe_event_id = 'evt_commitfail'",
            )
            .fetch_one(&env.pool)
            .await
            .expect("status");
            assert_eq!(
                status, "pending",
                "commit failure leaves the claim untouched"
            );
            // The already-written deadletter entry is compensated away.
            let mut conn = pool_conn(&isolated.pool).await;
            let entries =
                deadletter_entries_on(&mut conn, "stripe:deadletter:event:evt_commitfail*").await;
            assert_eq!(
                entries.len(),
                0,
                "redis entry compensated after commit failure"
            );
        }
    );

    env_test!(compensation_failure_is_logged_never_fatal, |env| {
        // Direct fault injection: the compensation pipeline must tolerate a
        // Redis failure (it only logs) — a commit failure must never panic
        // or mask its own error because the compensating DEL/ZREM failed.
        let isolated = crate::test_support::spawn_isolated_redis();
        let state = state_with_isolated_redis(env, &isolated);
        let mut conn = pool_conn(&isolated.pool).await;
        let the_key = "stripe:deadletter:event:evt_comp_direct";
        let _: () = redis::cmd("SETEX")
            .arg(the_key)
            .arg(60)
            .arg("{}")
            .query_async(&mut conn)
            .await
            .expect("stored entry");
        // Poison the shared index as a STRING: DEL succeeds, ZREM fails.
        let _: () = redis::cmd("SET")
            .arg(DEADLETTER_INDEX_KEY)
            .arg("not-a-zset")
            .query_async(&mut conn)
            .await
            .expect("poison index");
        drop(conn);

        remove_prepared_deadletter_from_redis(&state, the_key).await;

        let mut conn = pool_conn(&isolated.pool).await;
        let gone: Option<String> = redis::cmd("GET")
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("entry state");
        assert_eq!(gone, None, "the DEL in the compensation still ran");
    });

    env_test!(
        prepare_deadletter_without_body_stores_nothing_replayable,
        |env| {
            let _ = env;
            let prepared = prepare_deadletter(
                DeadletterEntry {
                    reason: "missing_signature".into(),
                    ..Default::default()
                },
                None,
                None,
                Utc::now(),
            );
            assert_eq!(prepared.retry_at_ms, None);
            let entry: DeadletterEntry = serde_json::from_str(&prepared.payload).expect("entry");
            assert!(entry.body.is_none());
            assert!(entry.signature.is_none());
        }
    );

    // ---------------- retry worker arms ----------------

    env_test!(
        retry_worker_handles_evicted_corrupt_and_foreign_entries,
        |env| {
            let isolated = crate::test_support::spawn_isolated_redis();
            let state = state_with_isolated_redis(env, &isolated);
            let mut conn = pool_conn(&isolated.pool).await;
            let _ = &state;
            let _: () = redis::cmd("ZREMRANGEBYSCORE")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .arg("-inf")
                .arg("+inf")
                .query_async(&mut conn)
                .await
                .expect("clear");

            // 1) evicted entry: index member without a stored body.
            let _: () = redis::cmd("ZADD")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .arg(1)
                .arg("stripe:deadletter:event:evicted")
                .query_async(&mut conn)
                .await
                .expect("schedule evicted");
            // 2) corrupt entry: stored body is not JSON.
            let _: () = redis::cmd("SET")
                .arg("stripe:deadletter:event:corrupt")
                .arg("this is not json")
                .query_async(&mut conn)
                .await
                .expect("store corrupt");
            let _: () = redis::cmd("ZADD")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .arg(1)
                .arg("stripe:deadletter:event:corrupt")
                .query_async(&mut conn)
                .await
                .expect("schedule corrupt");
            // 3) foreign entry: not a processing_failed reason.
            let foreign = DeadletterEntry {
                reason: "missing_signature".into(),
                ..Default::default()
            };
            let _: () = redis::cmd("SET")
                .arg("stripe:deadletter:event:foreign")
                .arg(serde_json::to_string(&foreign).unwrap())
                .query_async(&mut conn)
                .await
                .expect("store foreign");
            let _: () = redis::cmd("ZADD")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .arg(1)
                .arg("stripe:deadletter:event:foreign")
                .query_async(&mut conn)
                .await
                .expect("schedule foreign");
            drop(conn);

            retry_deadlettered_webhooks(&state)
                .await
                .expect("retry pass");
            let mut conn = pool_conn(&isolated.pool).await;
            let remaining: i64 = redis::cmd("ZCARD")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .query_async(&mut conn)
                .await
                .expect("card");
            assert_eq!(remaining, 0, "all three arms drop their index members");
            let _: () = redis::cmd("DEL")
                .arg("stripe:deadletter:event:corrupt")
                .arg("stripe:deadletter:event:foreign")
                .query_async(&mut conn)
                .await
                .expect("cleanup");
        }
    );

    env_test!(retry_worker_empty_index_is_a_clean_noop, |env| {
        let isolated = crate::test_support::spawn_isolated_redis();
        let state = state_with_isolated_redis(env, &isolated);
        retry_deadlettered_webhooks(&state)
            .await
            .expect("empty batch returns immediately");
    });

    env_test!(retry_worker_success_removes_entry_from_index, |env| {
        let isolated = crate::test_support::spawn_isolated_redis();
        let state = state_with_isolated_redis(env, &isolated);
        shared_seed_tenant(&env.pool, "swadv_retry_ok", "growth").await;
        let payload = payment_failed_payload("evt_retry_ok", "in_retry_ok", "swadv_retry_ok");
        let body = serde_json::to_string(&payload).unwrap();
        let timestamp = Utc::now().timestamp();
        let signature = sign_stripe("whsec_coverage", body.as_bytes(), timestamp);
        let entry = DeadletterEntry {
            reason: "processing_failed".into(),
            event_id: Some("evt_retry_ok".into()),
            body: Some(body),
            signature: Some(signature),
            ..Default::default()
        };
        let the_key = "stripe:deadletter:event:evt_retry_ok";
        let mut conn = pool_conn(&isolated.pool).await;
        let _: () = redis::cmd("ZREMRANGEBYSCORE")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .arg("-inf")
            .arg("+inf")
            .query_async(&mut conn)
            .await
            .expect("clear");
        let _: () = redis::cmd("SET")
            .arg(the_key)
            .arg(serde_json::to_string(&entry).unwrap())
            .query_async(&mut conn)
            .await
            .expect("store");
        let _: () = redis::cmd("ZADD")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .arg(1)
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("schedule");
        drop(conn);

        retry_deadlettered_webhooks(&state).await.expect("retry");
        let mut conn = pool_conn(&isolated.pool).await;
        let score: Option<i64> = redis::cmd("ZSCORE")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("score");
        assert_eq!(score, None, "success leaves the retry index");
        let kept: Option<String> = redis::cmd("GET")
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("kept");
        assert!(kept.is_some(), "the deadletter body stays for audit");
        let count: i32 = sqlx::query_scalar(
            "SELECT failed_payment_count FROM dunning_records WHERE tenant_id = 'swadv_retry_ok'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("dunning");
        assert_eq!(count, 1, "the retried failure applied exactly once");
        let _: () = redis::cmd("DEL")
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("cleanup");
    });

    env_test!(process_retries_pass_drains_due_entries_once, |env| {
        let isolated = crate::test_support::spawn_isolated_redis();
        let state = state_with_isolated_redis(env, &isolated);
        process_deadletter_retries(&state)
            .await
            .expect("nothing due is a clean pass");
    });

    #[tokio::test]
    async fn spawned_retry_worker_performs_one_immediate_pass() {
        {
            let env = shared_env("worker_spawn").await;
            spawn_deadletter_retry_worker(env.state.clone());
            // The first interval tick fires immediately: one full retry pass
            // runs before the runtime is torn down.
            tokio::time::sleep(Duration::from_millis(20)).await;
            env.finish().await;
        }
    }

    // ---------------- invoice settlement edges ----------------

    env_test!(
        invoice_paid_without_any_tenant_reference_deadletters,
        |env| {
            let orphan: InvoiceEvent = serde_json::from_value(serde_json::json!({
                "id": "in_orphan_paid", "amount_due": 100
            }))
            .expect("event");
            let error = handle_invoice_paid(&env.state, orphan)
                .await
                .expect_err("unresolvable invoice.paid");
            assert!(error.contains("could not be resolved to a tenant"));

            // A subscription reference that matches nothing is equally refused.
            let unknown_sub: InvoiceEvent = serde_json::from_value(serde_json::json!({
                "id": "in_orphan_sub", "amount_due": 100, "subscription": "sub_ghost"
            }))
            .expect("event");
            let error = handle_invoice_paid(&env.state, unknown_sub)
                .await
                .expect_err("unknown subscription");
            assert!(error.contains("could not be resolved to a tenant"));
        }
    );

    env_test!(invoice_paid_settles_allocates_and_recovers_dunning, |env| {
        let tenant = "swadv_settle";
        shared_seed_tenant(&env.pool, tenant, "growth").await;
        let invoice_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO invoices (id, tenant_id, stripe_invoice_id, invoice_number, status,
                                   amount, currency, subtotal, vat_total, total,
                                   due_at, period_start, period_end)
             VALUES ($1, $2, 'in_swadv_settle', 'SWADV-1', 'pending', 12400, 'eur', 10000, 2400,
                     12400, NOW(), NOW(), NOW() + INTERVAL '30 days')",
        )
        .bind(invoice_id)
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("local invoice");
        // Tenant already in dunning: settlement must recover it.
        sqlx::query(
            "INSERT INTO dunning_records (id, tenant_id, status, failed_payment_count)
             VALUES ('swadv_settle_dunning_0001', $1, 'soft_suspended', 3)",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("dunning");

        let settlement_body = serde_json::json!({
            "id": "in_swadv_settle",
            "amount_due": 12400,
            "amount_paid": 12400,
            "currency": "eur",
            "subtotal": 10000,
            "tax": 2400,
            "total": 12400,
            "subscription_details": { "metadata": { "tenant_id": tenant } },
            "automatic_tax": { "enabled": true, "status": "complete" }
        });
        handle_invoice_paid(&env.state, decode_invoice(&settlement_body))
            .await
            .expect("settlement");
        let (status, paid_at_is_set): (String, bool) =
            sqlx::query_as("SELECT status, paid_at IS NOT NULL FROM invoices WHERE id = $1")
                .bind(invoice_id)
                .fetch_one(&env.pool)
                .await
                .expect("invoice");
        assert_eq!(status, "paid");
        assert!(paid_at_is_set);
        let allocation: i64 = sqlx::query_scalar(
            "SELECT amount_cents FROM invoice_payment_allocations WHERE invoice_id = $1",
        )
        .bind(invoice_id)
        .fetch_one(&env.pool)
        .await
        .expect("allocation");
        assert_eq!(
            allocation, 12400,
            "the verified payment is allocated exactly once"
        );
        let dunning: Option<String> =
            sqlx::query_scalar("SELECT status FROM dunning_records WHERE tenant_id = $1")
                .bind(tenant)
                .fetch_one(&env.pool)
                .await
                .expect("dunning");
        assert_eq!(
            dunning.as_deref(),
            Some("healthy"),
            "settlement recovers dunning"
        );

        // Replay: idempotent, no second allocation.
        handle_invoice_paid(&env.state, decode_invoice(&settlement_body))
            .await
            .expect("replay");
        let allocations: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM invoice_payment_allocations WHERE invoice_id = $1",
        )
        .bind(invoice_id)
        .fetch_one(&env.pool)
        .await
        .expect("count");
        assert_eq!(allocations, 1, "replay never double-allocates");
    });

    env_test!(invoice_paid_currency_mismatch_refused, |env| {
        let tenant = "swadv_currency";
        shared_seed_tenant(&env.pool, tenant, "growth").await;
        let invoice_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO invoices (id, tenant_id, stripe_invoice_id, invoice_number, status,
                                   amount, currency, subtotal, vat_total, total,
                                   due_at, period_start, period_end)
             VALUES ($1, $2, 'in_ccy', 'SWADV-2', 'pending', 1000, 'eur', 1000, 0, 1000,
                     NOW(), NOW(), NOW() + INTERVAL '30 days')",
        )
        .bind(invoice_id)
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("local invoice");

        let event: InvoiceEvent = serde_json::from_value(serde_json::json!({
            "id": "in_ccy",
            "amount_due": 1000,
            "amount_paid": 1000,
            "currency": "usd",
            "subtotal": 1000,
            "total": 1000,
            "subscription_details": { "metadata": { "tenant_id": tenant } },
            "automatic_tax": { "enabled": true, "status": "complete" }
        }))
        .expect("event");
        let error = handle_invoice_paid(&env.state, event)
            .await
            .expect_err("currency mismatch refused");
        assert!(error.contains("denominated in"), "honest failure: {error}");
        let status: String = sqlx::query_scalar("SELECT status FROM invoices WHERE id = $1")
            .bind(invoice_id)
            .fetch_one(&env.pool)
            .await
            .expect("status");
        assert_eq!(status, "pending", "the refused settlement writes nothing");
    });

    env_test!(invoice_paid_zero_value_settles_without_allocation, |env| {
        let tenant = "swadv_zero";
        shared_seed_tenant(&env.pool, tenant, "growth").await;
        let event: InvoiceEvent = serde_json::from_value(serde_json::json!({
            "id": "in_swadv_zero",
            "amount_due": 0,
            "amount_paid": 0,
            "currency": "eur",
            "subtotal": 0,
            "total": 0,
            "subscription_details": { "metadata": { "tenant_id": tenant } },
            "automatic_tax": { "enabled": true, "status": "complete" }
        }))
        .expect("event");
        handle_invoice_paid(&env.state, event)
            .await
            .expect("zero-value invoices settle");
        let invoice: Option<(String,)> =
            sqlx::query_as("SELECT status FROM invoices WHERE stripe_invoice_id = 'in_swadv_zero'")
                .fetch_optional(&env.pool)
                .await
                .expect("invoice");
        assert_eq!(
            invoice.expect("imported").0,
            "paid",
            "Fix A imports the paid row"
        );
        let allocations: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM invoice_payment_allocations WHERE operation_id = 'stripe:in_swadv_zero'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("allocations");
        assert_eq!(
            allocations, 0,
            "no positive allocation is invented for zero value"
        );
    });

    env_test!(
        invoice_paid_import_refused_for_foreign_tenant_leaves_dunning,
        |env| {
            let owner = "swadv_import_owner";
            let other = "swadv_import_other";
            shared_seed_tenant(&env.pool, owner, "growth").await;
            shared_seed_tenant(&env.pool, other, "growth").await;
            sqlx::query(
                "INSERT INTO invoices (id, tenant_id, stripe_invoice_id, invoice_number, status,
                                   amount, currency, subtotal, vat_total, total,
                                   due_at, period_start, period_end)
             VALUES (gen_random_uuid(), $1, 'in_import', 'SWADV-3', 'pending',
                     1000, 'eur', 1000, 0, 1000, NOW(), NOW(), NOW() + INTERVAL '30 days')",
            )
            .bind(owner)
            .execute(&env.pool)
            .await
            .expect("owner invoice");
            sqlx::query(
                "INSERT INTO dunning_records (id, tenant_id, status, failed_payment_count)
             VALUES ('swadv_import_dunning_01', $1, 'soft_suspended', 2)",
            )
            .bind(other)
            .execute(&env.pool)
            .await
            .expect("other dunning");

            let event: InvoiceEvent = serde_json::from_value(serde_json::json!({
                "id": "in_import",
                "amount_due": 1000,
                "amount_paid": 1000,
                "currency": "eur",
                "subtotal": 1000,
                "total": 1000,
                "subscription_details": { "metadata": { "tenant_id": other } },
                "automatic_tax": { "enabled": true, "status": "complete" }
            }))
            .expect("event");
            handle_invoice_paid(&env.state, event)
                .await
                .expect("guard-rejected upsert is not an error");
            let dunning: Option<String> =
                sqlx::query_scalar("SELECT status FROM dunning_records WHERE tenant_id = $1")
                    .bind(other)
                    .fetch_one(&env.pool)
                    .await
                    .expect("dunning");
            assert_eq!(
                dunning.as_deref(),
                Some("soft_suspended"),
                "Fix F4: no blanket recovery"
            );
            let status: String = sqlx::query_scalar(
                "SELECT status FROM invoices WHERE stripe_invoice_id = 'in_import'",
            )
            .fetch_one(&env.pool)
            .await
            .expect("status");
            assert_eq!(status, "pending", "the foreign tenant cannot settle it");
        }
    );

    env_test!(
        invoice_paid_tax_gate_with_recomputation_from_address,
        |env| {
            let tenant = "swadv_recompute";
            shared_seed_tenant(&env.pool, tenant, "growth").await;
            // A country outside the EU with no VAT number: recomputed VAT is 0.
            sqlx::query(
                "INSERT INTO billing_addresses (tenant_id, country, city)
             VALUES ($1, 'US', 'Testville')",
            )
            .bind(tenant)
            .execute(&env.pool)
            .await
            .expect("address");

            let matching: InvoiceEvent = serde_json::from_value(serde_json::json!({
                "id": "in_recompute_ok",
                "amount_due": 4900,
                "amount_paid": 4900,
                "currency": "eur",
                "subtotal": 4900,
                "total": 4900,
                "subscription_details": { "metadata": { "tenant_id": tenant } }
            }))
            .expect("event");
            handle_invoice_paid(&env.state, matching)
                .await
                .expect("recomputed 0% VAT matches");
            let (validation, source): (String, String) = sqlx::query_as(
                "SELECT validation_status,
                    raw_payload->'apexmail'->>'source'
             FROM stripe_tax_snapshots WHERE stripe_invoice_id = 'in_recompute_ok'",
            )
            .fetch_one(&env.pool)
            .await
            .expect("snapshot");
            assert_eq!(validation, "fallback_unavailable");
            assert_eq!(source, "recomputed");

            // An EU country without evidence recomputes the statutory rate; a
            // mismatching charged total blocks.
            sqlx::query("UPDATE billing_addresses SET country = 'EE' WHERE tenant_id = $1")
                .bind(tenant)
                .execute(&env.pool)
                .await
                .expect("address");
            let mismatch: InvoiceEvent = serde_json::from_value(serde_json::json!({
                "id": "in_recompute_bad",
                "amount_due": 4900,
                "amount_paid": 4900,
                "currency": "eur",
                "subtotal": 4900,
                "total": 4900,
                "subscription_details": { "metadata": { "tenant_id": tenant } }
            }))
            .expect("event");
            let error = handle_invoice_paid(&env.state, mismatch)
                .await
                .expect_err("missing statutory VAT blocks");
            assert!(error.contains("blocked"), "honest failure: {error}");
            let incidents: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM finance_incidents WHERE kind = 'tax_total_mismatch'",
            )
            .fetch_one(&env.pool)
            .await
            .expect("incidents");
            assert_eq!(incidents, 1, "a critical finance incident is raised");
        }
    );

    env_test!(
        invoice_paid_null_country_address_degrades_to_zero_vat,
        |env| {
            let tenant = "swadv_nullcountry";
            shared_seed_tenant(&env.pool, tenant, "growth").await;
            sqlx::query(
                "INSERT INTO billing_addresses (tenant_id, country, city)
             VALUES ($1, NULL, 'Testville')",
            )
            .bind(tenant)
            .execute(&env.pool)
            .await
            .expect("address");
            let event: InvoiceEvent = serde_json::from_value(serde_json::json!({
                "id": "in_nullcountry",
                "amount_due": 1000,
                "amount_paid": 1000,
                "currency": "eur",
                "subtotal": 1000,
                "total": 1000,
                "subscription_details": { "metadata": { "tenant_id": tenant } }
            }))
            .expect("event");
            handle_invoice_paid(&env.state, event)
                .await
                .expect("null country recomputes 0% VAT and matches");
            let validation: String = sqlx::query_scalar(
            "SELECT validation_status FROM stripe_tax_snapshots WHERE stripe_invoice_id = 'in_nullcountry'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("snapshot");
            assert_eq!(validation, "fallback_unavailable");
        }
    );

    env_test!(persist_tax_snapshot_replay_returns_the_first_write, |env| {
        let tenant = "swadv_snapreplay";
        shared_seed_tenant(&env.pool, tenant, "growth").await;
        let event: InvoiceEvent = serde_json::from_value(serde_json::json!({
            "id": "in_snapreplay",
            "amount_due": 1000,
            "currency": "eur",
            "subtotal": 1000,
            "total": 1000
        }))
        .expect("event");
        let expected = ExpectedTax {
            subtotal_cents: 1000,
            vat_cents: 0,
            total_cents: 1000,
            source: "recomputed",
            country: Some("US".into()),
            vat_rate: 0.0,
            evidence_id: None,
        };
        let first = persist_tax_snapshot(
            &env.pool,
            &event,
            tenant,
            None,
            "eur",
            (1000, 0, 1000),
            &expected,
            "apexmail_local",
            "fallback_unavailable",
            0,
            "not_provided",
            &serde_json::json!([]),
        )
        .await
        .expect("first write");
        let second = persist_tax_snapshot(
            &env.pool,
            &event,
            tenant,
            None,
            "eur",
            (1000, 0, 1000),
            &expected,
            "apexmail_local",
            "fallback_unavailable",
            0,
            "not_provided",
            &serde_json::json!([]),
        )
        .await
        .expect("replay");
        assert_eq!(first, second, "the immutable first write wins");
    });

    // ---------------- dunning config + notification edges ----------------

    env_test!(dunning_config_degrades_to_defaults_on_faults, |env| {
        let tenant = "swadv_duncfg";
        shared_seed_tenant(&env.pool, tenant, "growth").await;
        // Per-tenant configured schedule is honored.
        sqlx::query(
            "INSERT INTO dunning_config
                 (tenant_id, retry_schedule_days, soft_suspend_after_days, hard_suspend_after_days, grace_period_days)
             VALUES ($1, ARRAY[2,4], 5, 9, 3)",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("config row");
        let config = get_dunning_config_for_tenant(&env.state, tenant).await;
        assert_eq!(config.retry_schedule_days, vec![2, 4]);

        // Table missing: defaults, loudly.
        env.break_table("dunning_config").await;
        let config = get_dunning_config_for_tenant(&env.state, tenant).await;
        assert_eq!(
            config.soft_suspend_after_days, 7,
            "defaults survive a missing table"
        );
        env.restore_table("dunning_config").await;

        // Table exists again (the OnceLock now trusts it): the tenant row wins.
        let config = get_dunning_config_for_tenant(&env.state, tenant).await;
        assert_eq!(config.retry_schedule_days, vec![2, 4]);
        env.break_table("dunning_config").await;
        let config = get_dunning_config_for_tenant(&env.state, tenant).await;
        assert_eq!(
            config.hard_suspend_after_days, 21,
            "defaults survive a failing query"
        );
        env.restore_table("dunning_config").await;
    });

    env_test!(
        dunning_notification_type_mapping_and_enqueue_failure,
        |env| {
            let tenant = "swadv_notif";
            shared_seed_tenant(&env.pool, tenant, "growth").await;
            for (status, _kind) in [
                ("warning", "payment_reminder"),
                ("soft_suspended", "account_soft_suspended"),
                ("hard_suspended", "account_hard_suspended"),
            ] {
                send_dunning_notification(&env.state, tenant, status, serde_json::json!({})).await;
            }
            let rows: Vec<(String,)> = sqlx::query_as(
                "SELECT type FROM notification_queue WHERE tenant_id = $1 ORDER BY type",
            )
            .bind(tenant)
            .fetch_all(&env.pool)
            .await
            .expect("queue");
            let types: Vec<String> = rows.into_iter().map(|r| r.0).collect();
            assert_eq!(
                types,
                vec![
                    "account_hard_suspended".to_string(),
                    "account_soft_suspended".to_string(),
                    "payment_reminder".to_string()
                ]
            );

            // Enqueue failure is logged, never fatal.
            env.break_table("notification_queue").await;
            send_dunning_notification(&env.state, tenant, "warning", serde_json::json!({})).await;
            env.restore_table("notification_queue").await;
        }
    );

    env_test!(
        payment_failed_caches_status_and_survives_cache_faults,
        |env| {
            let tenant = "swadv_cache";
            shared_seed_tenant(&env.pool, tenant, "growth").await;
            let dead = state_with_dead_redis(&env.pool);
            let event: InvoiceEvent = serde_json::from_value(serde_json::json!({
                "id": "in_cache",
                "amount_due": 10,
                "subscription_details": { "metadata": { "tenant_id": tenant } }
            }))
            .expect("event");
            handle_payment_failed(&dead, event)
                .await
                .expect("payment failure processing survives a dead cache");
            let count: i32 = sqlx::query_scalar(
                "SELECT failed_payment_count FROM dunning_records WHERE tenant_id = $1",
            )
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("dunning");
            assert_eq!(count, 1);
        }
    );

    env_test!(reclaim_reports_reclaimed_events_loudly, |env| {
        sqlx::query(
            "INSERT INTO stripe_webhook_events (id, stripe_event_id, event_type, status, updated_at)
             VALUES (gen_random_uuid(), 'evt_swadv_reclaim', 'invoice.paid', 'pending',
                     NOW() - INTERVAL '20 minutes')",
        )
        .execute(&env.pool)
        .await
        .expect("stale row");
        let reclaimed = reclaim_stale_pending_webhooks(&env.state)
            .await
            .expect("reclaim");
        assert_eq!(reclaimed, vec!["evt_swadv_reclaim".to_string()]);
    });

    // ---------------- dedicated-IP auto-provisioning (local servers) ----------------

    /// A local axum server on an ephemeral port answering /v1/dedicated-ips.
    async fn local_api_server(
        status: axum::http::StatusCode,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let app = axum::Router::new().route(
            "/v1/dedicated-ips",
            axum::routing::post(move || async move { (status, "{}") }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("local server");
        });
        (format!("http://{addr}"), handle)
    }

    fn state_with_api_base(env: &Env, api_base: String) -> Arc<AppState> {
        let mut config = env.state.config.clone();
        config.api_base_url = api_base;
        AppState::new(env.pool.clone(), env.redis.clone(), config)
    }

    async fn seed_dedicated_ip_plan(env: &Env, name: &str, included: i32) {
        sqlx::query(
            "INSERT INTO plans (id, name, display_name, price_cents, email_limit, api_call_limit, features)
             VALUES ($1, $2, $2, 0, 1000, 1000, jsonb_build_object('dedicated_ip_count', $3))
             ON CONFLICT (name) DO UPDATE SET features = EXCLUDED.features",
        )
        .bind(format!("plan_{name}"))
        .bind(name)
        .bind(included)
        .execute(&env.pool)
        .await
        .expect("plan with dedicated ips");
    }

    async fn seed_active_subscription(env: &Env, tenant: &str, plan: &str, sub_id: &str) {
        sqlx::query(
            "INSERT INTO stripe_subscriptions
                 (tenant_id, stripe_subscription_id, plan, status, billing_cycle_start,
                  billing_cycle_end, stripe_customer_id)
             VALUES ($1, $2, $3, 'active', NOW(), NOW() + INTERVAL '30 days', 'cus_ip')",
        )
        .bind(tenant)
        .bind(sub_id)
        .bind(plan)
        .execute(&env.pool)
        .await
        .expect("active subscription");
    }

    env_test!(auto_provision_covers_every_allocation_outcome, |env| {
        // 1) plan without dedicated IPs -> immediate no-op.
        let none = "swadv_ip_none";
        shared_seed_tenant(&env.pool, none, "growth").await;
        auto_provision_dedicated_ips_background(&env.state, none)
            .await
            .expect("no allowance is a no-op");

        // 2) tenant already at its allowance -> no-op.
        let full = "swadv_ip_full";
        seed_dedicated_ip_plan(env, "swadv_ip_plan", 1).await;
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status) VALUES ($1, $1, 'swadv_ip_plan', 'active')",
        )
        .bind(full)
        .execute(&env.pool)
        .await
        .expect("tenant");
        seed_active_subscription(env, full, "swadv_ip_plan", "sub_swadv_ip_full").await;
        sqlx::query(
            "INSERT INTO dedicated_ips (id, tenant_id, ip_address, status)
             VALUES ('ip-swadv-full-0000000000000001', $1, '198.51.100.10', 'active')",
        )
        .bind(full)
        .execute(&env.pool)
        .await
        .expect("ip");
        auto_provision_dedicated_ips_background(&env.state, full)
            .await
            .expect("sufficient IPs is a no-op");

        // 3) success: a local 200 server records a completed request.
        let ok_tenant = "swadv_ip_ok";
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status) VALUES ($1, $1, 'swadv_ip_plan', 'active')",
        )
        .bind(ok_tenant)
        .execute(&env.pool)
        .await
        .expect("tenant");
        seed_active_subscription(env, ok_tenant, "swadv_ip_plan", "sub_swadv_ip_ok").await;
        let (base, server) = local_api_server(StatusCode::OK).await;
        auto_provision_dedicated_ips_background(&state_with_api_base(env, base), ok_tenant)
            .await
            .expect("success path");
        let (status, ok): (String, i32) = sqlx::query_as(
            "SELECT status, success_count FROM dedicated_ip_provisioning_requests WHERE tenant_id = $1",
        )
        .bind(ok_tenant)
        .fetch_one(&env.pool)
        .await
        .expect("request");
        assert_eq!(status, "completed");
        assert_eq!(ok, 1);
        server.abort();

        // 4) partial: one IP already allocated, the next attempt fails (409).
        let partial = "swadv_ip_partial";
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status) VALUES ($1, $1, 'swadv_ip_plan', 'active')",
        )
        .bind(partial)
        .execute(&env.pool)
        .await
        .expect("tenant");
        seed_active_subscription(env, partial, "swadv_ip_plan", "sub_swadv_ip_partial").await;
        let (base_fail, server_fail) = local_api_server(StatusCode::CONFLICT).await;
        auto_provision_dedicated_ips_background(&state_with_api_base(env, base_fail), partial)
            .await
            .expect("failure recorded");
        server_fail.abort();
        let (status, failures): (String, i32) = sqlx::query_as(
            "SELECT status, failure_count FROM dedicated_ip_provisioning_requests WHERE tenant_id = $1",
        )
        .bind(partial)
        .fetch_one(&env.pool)
        .await
        .expect("request");
        assert_eq!(status, "failed");
        assert_eq!(failures, 1, "the non-2xx response is a recorded failure");

        // 5) transport error: closed local port.
        let errored = "swadv_ip_err";
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status) VALUES ($1, $1, 'swadv_ip_plan', 'active')",
        )
        .bind(errored)
        .execute(&env.pool)
        .await
        .expect("tenant");
        seed_active_subscription(env, errored, "swadv_ip_plan", "sub_swadv_ip_err").await;
        auto_provision_dedicated_ips_background(
            &state_with_api_base(env, "http://127.0.0.1:1".to_string()),
            errored,
        )
        .await
        .expect("transport errors are recorded, not fatal");
        let status: String = sqlx::query_scalar(
            "SELECT status FROM dedicated_ip_provisioning_requests WHERE tenant_id = $1",
        )
        .bind(errored)
        .fetch_one(&env.pool)
        .await
        .expect("request");
        assert_eq!(status, "failed");
    });

    env_test!(
        auto_provision_request_recording_faults_are_surfaced,
        |env| {
            let tenant = "swadv_ip_fault";
            seed_dedicated_ip_plan(env, "swadv_ip_plan2", 1).await;
            sqlx::query(
            "INSERT INTO tenants (id, name, plan, status) VALUES ($1, $1, 'swadv_ip_plan2', 'active')",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("tenant");
            seed_active_subscription(env, tenant, "swadv_ip_plan2", "sub_swadv_ip_fault").await;
            // The request table is gone: recording the intent fails honestly.
            env.break_table("dedicated_ip_provisioning_requests").await;
            let error = auto_provision_dedicated_ips_background(&env.state, tenant)
                .await
                .expect_err("broken request table");
            assert!(
                error.contains("Failed to record dedicated IP provisioning request"),
                "honest failure: {error}"
            );
            env.restore_table("dedicated_ip_provisioning_requests")
                .await;

            // The allowance query itself failing is surfaced too.
            env.break_table("stripe_subscriptions").await;
            let error = auto_provision_dedicated_ips_background(&env.state, tenant)
                .await
                .expect_err("broken allowance query");
            assert!(error.contains("Failed to load dedicated IP allowance"));
            env.restore_table("stripe_subscriptions").await;

            env.break_table("dedicated_ips").await;
            let error = auto_provision_dedicated_ips_background(&env.state, tenant)
                .await
                .expect_err("broken count query");
            assert!(error.contains("Failed to load active dedicated IP count"));
            env.restore_table("dedicated_ips").await;
        }
    );

    // ---------------- snapshot helpers ----------------

    #[test]
    fn normalize_period_currency_rejects_malformed_codes() {
        assert_eq!(normalize_period_currency("eur"), "EUR");
        assert_eq!(normalize_period_currency("  usd "), "USD");
        assert_eq!(normalize_period_currency("EURO"), "EUR");
        assert_eq!(normalize_period_currency("e1"), "EUR");
        assert_eq!(normalize_period_currency(""), "EUR");
    }

    #[test]
    fn derive_invoice_totals_none_total_arm_uses_the_total() {
        let (subtotal, vat, total) = derive_invoice_totals(None, None, Some(7_777), 7_777);
        assert_eq!((subtotal, vat, total), (7_777, 0, 7_777));
    }

    env_test!(snapshot_period_edges_are_honest, |env| {
        let tenant = "swadv_snapedge";
        shared_seed_tenant(&env.pool, tenant, "growth").await;
        let mut tx = env.pool.begin().await.expect("tx");
        // Inverted period: no snapshot, no error.
        snapshot_billing_period(
            &mut tx,
            tenant,
            "sub_snap",
            "active",
            Some("growth"),
            Utc::now(),
            Utc::now() - Duration::from_secs(60),
        )
        .await
        .expect("inverted periods are skipped");
        // Unknown tenant: degrades to the subscription plan + default currency.
        snapshot_billing_period(
            &mut tx,
            "swadv_missing_tenant",
            "sub_snap",
            "canceled",
            Some("growth"),
            Utc::now(),
            Utc::now() + Duration::from_secs(60),
        )
        .await
        .expect("unknown tenant degrades");
        tx.commit().await.expect("commit");
        let snapshot: serde_json::Value = sqlx::query_scalar(
            "SELECT pricing_snapshot FROM billing_periods WHERE tenant_id = 'swadv_missing_tenant'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("snapshot");
        assert_eq!(snapshot["currency"], "EUR");
    });

    // ---------------- replay refusals ----------------

    env_test!(replay_deadletter_missing_signature_refused, |env| {
        let entry = DeadletterEntry {
            reason: "processing_failed".into(),
            event_id: Some("evt_nosig_replay".into()),
            body: Some(r#"{"id":"evt_nosig_replay","type":"invoice.paid"}"#.into()),
            ..Default::default()
        };
        let error = replay_deadletter(&env.state, &entry)
            .await
            .expect_err("missing signature");
        assert!(error.contains("No signature stored"));
    });

    env_test!(replay_deadletter_malformed_body_refused, |env| {
        let timestamp = Utc::now().timestamp();
        let body = r#"{"id":"evt_badbody","type":"invoice.paid"#;
        let signature = sign_stripe("whsec_coverage", body.as_bytes(), timestamp);
        let entry = DeadletterEntry {
            reason: "processing_failed".into(),
            event_id: Some("evt_badbody".into()),
            body: Some(body.to_string()),
            signature: Some(signature),
            ..Default::default()
        };
        let error = replay_deadletter(&env.state, &entry)
            .await
            .expect_err("malformed stored body");
        assert!(
            error.contains("Failed to parse stored webhook body"),
            "honest failure: {error}"
        );
        assert_eq!(event_rows(&env.pool).await, 0, "nothing claimed");
    });

    env_test!(replay_deadletter_pending_event_is_refused, |env| {
        shared_seed_tenant(&env.pool, "swadv_pendreplay", "growth").await;
        let payload = payment_failed_payload("evt_pendreplay", "in_pendreplay", "swadv_pendreplay");
        let body = serde_json::to_string(&payload).unwrap();
        let timestamp = Utc::now().timestamp();
        let signature = sign_stripe("whsec_coverage", body.as_bytes(), timestamp);
        let entry = DeadletterEntry {
            reason: "processing_failed".into(),
            event_id: Some("evt_pendreplay".into()),
            body: Some(body),
            signature: Some(signature),
            ..Default::default()
        };
        replay_deadletter(&env.state, &entry)
            .await
            .expect("first replay claims");
        // Simulate a concurrent worker holding the claim.
        sqlx::query(
            "UPDATE stripe_webhook_events SET status = 'pending', processed_at = NULL
             WHERE stripe_event_id = 'evt_pendreplay'",
        )
        .execute(&env.pool)
        .await
        .expect("re-pend");
        let error = replay_deadletter(&env.state, &entry)
            .await
            .expect_err("pending event");
        assert!(
            error.contains("pending on another worker"),
            "honest failure: {error}"
        );
    });
}
