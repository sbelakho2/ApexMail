//! Webhook management routes.

use super::helpers::{clamp_limit, default_limit};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use billing_entitlements::FeatureKey;
use chrono::{DateTime, Utc};
use mail_common::{is_localhost, is_private_or_reserved_host};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use url::Url;
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(create_webhook).get(list_webhooks))
        .route(
            "/:id",
            get(get_webhook).put(update_webhook).delete(delete_webhook),
        )
        .route("/:id/test", post(test_webhook))
        .route("/:id/rotate-secret", post(rotate_webhook_secret))
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateWebhookRequest {
    pub url: String,
    pub events: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateWebhookRequest {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub events: Option<Vec<String>>,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WebhookResponse {
    pub id: String,
    pub url: String,
    pub events: serde_json::Value,
    // Secret is only returned at creation time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
pub struct TestWebhookResponse {
    pub success: bool,
    pub status_code: Option<u16>,
    pub response_time_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListWebhooksQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub cursor: Option<i64>,
}

// ─── Validation ────────────────────────────────────────────────

/// Event types a webhook may subscribe to (audit L-2; canonicalized
/// 2026-09-08 per the external API review §7 — exactly ONE vocabulary).
///
/// Every message-scoped event uses the `message.*` namespace:
///
/// - `message.accepted`   — message accepted for delivery (API 202)
/// - `message.queued`     — message entered the outbound queue
/// - `message.attempted`  — delivery attempt started
/// - `message.deferred`   — recipient server deferred (4xx); retry scheduled
/// - `message.delivered`  — recipient mail server returned a successful
///   SMTP acceptance response
/// - `message.bounced`    — permanent failure (5xx / hard bounce)
/// - `message.complained` — feedback-loop spam complaint
/// - `message.suppressed` — recipient added to the suppression list
/// - `message.opened`     — open tracked
/// - `message.clicked`    — click tracked
/// - `message.cancelled`  — scheduled send cancelled before dispatch
///
/// Non-message resources keep their own noun: `recipient.unsubscribed`,
/// `placement_test.completed`, `inbound`. The legacy `email.*` names and
/// `message.sent` are mapped in-place by migration 128 for stored
/// subscriptions and are rejected at validation time. `*` is the
/// wildcard every consumer's selector honours (`events @> '"*"'::jsonb`).
/// Unknown names previously validated as non-empty only — a typo like
/// `delivred` registered silently and the webhook never fired.
pub(crate) const KNOWN_WEBHOOK_EVENTS: &[&str] = &[
    // Message lifecycle (canonical vocabulary)
    "message.accepted",
    "message.queued",
    "message.attempted",
    "message.deferred",
    "message.delivered",
    "message.bounced",
    "message.complained",
    "message.suppressed",
    "message.opened",
    "message.clicked",
    "message.cancelled",
    // tracking-service
    "recipient.unsubscribed",
    // inbox-placement
    "placement_test.completed",
    // inbound email pipeline
    "inbound",
    // Wildcard honoured by every webhook selector
    "*",
];

/// Validate a webhook's event subscription list (audit L-2): non-empty, no
/// blank entries, and every name must be a known event type. The error
/// message lists the valid names so a typo is immediately fixable.
fn validate_webhook_events(events: &[String]) -> Result<(), String> {
    if events.is_empty() {
        return Err(format!(
            "at least one event is required; valid events: {}",
            KNOWN_WEBHOOK_EVENTS.join(", ")
        ));
    }
    let invalid: Vec<&str> = events
        .iter()
        .filter_map(|event| {
            let trimmed = event.trim();
            if trimmed.is_empty() || !KNOWN_WEBHOOK_EVENTS.contains(&trimmed) {
                Some(trimmed)
            } else {
                None
            }
        })
        .collect();
    if !invalid.is_empty() {
        return Err(format!(
            "unknown event type(s): {}; valid events: {}",
            invalid.join(", "),
            KNOWN_WEBHOOK_EVENTS.join(", ")
        ));
    }
    Ok(())
}

/// Env var that explicitly re-enables plain-HTTP loopback webhook targets for
/// local development (audit F). Defaults to OFF — the previous unconditional
/// localhost/127.0.0.1/::1 HTTP exemption let any authenticated tenant
/// register an SSRF probe against services bound to the host's loopback.
const ALLOW_LOCALHOST_WEBHOOKS_ENV: &str = "APEXMAIL_ALLOW_LOCALHOST_WEBHOOKS";

fn localhost_webhooks_allowed() -> bool {
    std::env::var(ALLOW_LOCALHOST_WEBHOOKS_ENV).is_ok_and(|value| value == "true")
}

/// Consuming inbound mail through the shared webhook pipeline requires the
/// `inbound_email` entitlement. Raw MX/SMTP acceptance is deliberately NOT
/// gated: inbound acceptance must remain available for mail that the
/// platform is authoritative for; this gate covers the customer-facing
/// consumption surface (the `inbound` event subscription).
async fn require_inbound_event_entitlement(
    state: &AppState,
    tenant_id: &str,
    events: &[String],
) -> Result<(), ApiError> {
    if events.iter().any(|event| event.trim() == "inbound") {
        crate::entitlements::require_feature(state, tenant_id, FeatureKey::InboundEmail).await?;
    }
    Ok(())
}

/// Validate webhook URL format and security requirements (parameterised for
/// testability — [`validate_webhook_url`] reads the env override).
///
/// Requires HTTPS (plain HTTP is only accepted for loopback hosts when
/// `APEXMAIL_ALLOW_LOCALHOST_WEBHOOKS=true`), and rejects private/reserved
/// hosts unless that same explicit override is set for a loopback target.
fn validate_webhook_url_with(url_str: &str, allow_localhost: bool) -> Result<(), String> {
    let url = Url::parse(url_str).map_err(|e| format!("invalid URL: {}", e))?;

    let scheme = url.scheme();
    let host = url.host_str().ok_or("URL must have a host")?;

    // Require HTTPS for production URLs
    if scheme == "http" {
        // Plain HTTP is only ever allowed for localhost/development targets
        // AND only when the explicit env override is set (audit F).
        if !(allow_localhost && is_localhost(host)) {
            return Err("webhook URL must use HTTPS".into());
        }
    } else if scheme != "https" {
        return Err(format!("invalid URL scheme: {}, must be https", scheme));
    }

    // Loopback hosts bypass the private-range rejection ONLY under the same
    // explicit override; every other private/reserved/metadata target is
    // always rejected.
    let loopback_exempt = allow_localhost && is_localhost(host);
    if !loopback_exempt && is_private_or_reserved_host(host) {
        return Err("webhook URL cannot point to private or reserved addresses".into());
    }

    Ok(())
}

/// Validate webhook URL format and security requirements.
/// Requires HTTPS (or HTTP for loopback hosts when
/// `APEXMAIL_ALLOW_LOCALHOST_WEBHOOKS=true` is explicitly set).
///
/// Shared by the JSON create/update handlers AND the zero-JS form twin
/// (`/web/webhooks`) — the form must never run a weaker check than the
/// API surface.
pub(crate) fn validate_webhook_url(url_str: &str) -> Result<(), String> {
    validate_webhook_url_with(url_str, localhost_webhooks_allowed())
}

/// Filter resolved addresses down to those safe to dial (audit F).
///
/// Returns the first safe address to pin the connection to, rejecting the
/// whole resolution set if ANY address is private/reserved (an attacker
/// controlling DNS can mix public and private A records — rejecting the set,
/// not skipping the bad entry, prevents partial-rebinding tricks).
/// Loopback targets are tolerated only under the explicit dev override.
fn select_pinned_addr(addrs: &[SocketAddr], allow_loopback: bool) -> Result<SocketAddr, String> {
    if addrs.is_empty() {
        return Err("webhook URL could not be resolved to any IP address".into());
    }
    for addr in addrs {
        let ip_str = addr.ip().to_string();
        if is_private_or_reserved_host(&ip_str) {
            if allow_loopback && addr.ip().is_loopback() {
                continue;
            }
            return Err(
                "webhook URL resolves to a private IP address (possible DNS rebinding)".into(),
            );
        }
    }
    // First non-loopback address when the override is on, else the first addr.
    Ok(*addrs
        .iter()
        .find(|addr| !addr.ip().is_loopback())
        .unwrap_or(&addrs[0]))
}

/// Build the dedicated webhook delivery client (audit F): DNS-pinned to the
/// validated addresses and with redirects DISABLED — the shared
/// `state.http_client` follows redirects, so a webhook endpoint replying
/// `302 → http://169.254.169.254/...` would turn the validated delivery into
/// an SSRF hop to internal services.
fn webhook_delivery_client(
    host: &str,
    safe_addrs: &[SocketAddr],
) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10));
    if !safe_addrs.is_empty() {
        builder = builder.resolve_to_addrs(host, safe_addrs);
    }
    builder
        .build()
        .map_err(|e| format!("failed to build webhook client: {e}"))
}

/// Per-tenant webhook ceiling, enforced by BOTH the JSON create handler
/// and the form twin.
pub(crate) const MAX_WEBHOOKS_PER_TENANT: i64 = 25;

// ─── Handlers ──────────────────────────────────────────────────

async fn create_webhook(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateWebhookRequest>,
) -> Result<(StatusCode, Json<WebhookResponse>), ApiError> {
    require_scopes(&auth, &["webhooks:write"])?;

    // Entitlement gate (403 for a plan without `webhooks_enabled`).
    crate::entitlements::require_feature(&state, &auth.tenant_id, FeatureKey::Webhooks).await?;
    // Consuming inbound mail through webhooks additionally requires
    // `inbound_email`; raw SMTP acceptance is deliberately never gated.
    require_inbound_event_entitlement(&state, &auth.tenant_id, &body.events).await?;

    let mut errors = Vec::new();

    if body.url.is_empty() {
        errors.push("url is required".into());
    } else if let Err(e) = validate_webhook_url(&body.url) {
        errors.push(e);
    }

    if let Err(e) = validate_webhook_events(&body.events) {
        errors.push(e);
    }

    if !errors.is_empty() {
        return Err(ApiError::Validation(errors));
    }

    // Enforce per-tenant webhook count limit (default:25)
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM webhooks WHERE tenant_id = $1")
        .bind(&auth.tenant_id)
        .fetch_one(&state.db)
        .await?;

    if count.0 >= MAX_WEBHOOKS_PER_TENANT {
        return Err(ApiError::Forbidden(format!(
            "webhook limit reached: maximum {} webhooks per tenant",
            MAX_WEBHOOKS_PER_TENANT,
        )));
    }

    let id = Uuid::new_v4();
    let now = Utc::now();
    let secret = apexmail_lib::id::generate_webhook_secret();

    sqlx::query(
        "INSERT INTO webhooks (id, tenant_id, url, events, secret, status, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,'active',$6,$6)",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .bind(&body.url)
    .bind(serde_json::json!(body.events))
    .bind(&secret)
    .bind(now)
    .execute(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(WebhookResponse {
            id: id.to_string(),
            url: body.url,
            events: serde_json::json!(body.events),
            // Only return secret at creation time
            secret: Some(secret),
            status: "active".into(),
            created_at: now.to_rfc3339(),
            updated_at: now.to_rfc3339(),
        }),
    ))
}

async fn list_webhooks(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ListWebhooksQuery>,
) -> Result<Json<Vec<WebhookResponse>>, ApiError> {
    require_scopes(&auth, &["webhooks:read"])?;

    let offset = params.cursor.unwrap_or(params.offset).clamp(0, 100_000);
    let rows = sqlx::query_as::<_, WebhookRow>(
        "SELECT id, url, events, secret, status, created_at, updated_at
         FROM webhooks WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(&auth.tenant_id)
    .bind(clamp_limit(params.limit, 200))
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn get_webhook(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<WebhookResponse>, ApiError> {
    require_scopes(&auth, &["webhooks:read"])?;
    let row = fetch_webhook(&state, &auth.tenant_id, id).await?;
    Ok(Json(row.into()))
}

async fn update_webhook(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<UpdateWebhookRequest>,
) -> Result<Json<WebhookResponse>, ApiError> {
    require_scopes(&auth, &["webhooks:write"])?;

    // Entitlement gate (403 for a plan without `webhooks_enabled`).
    crate::entitlements::require_feature(&state, &auth.tenant_id, FeatureKey::Webhooks).await?;
    if let Some(ref new_events) = body.events {
        require_inbound_event_entitlement(&state, &auth.tenant_id, new_events).await?;
    }

    // Validate new URL if provided
    if let Some(ref new_url) = body.url {
        if let Err(e) = validate_webhook_url(new_url) {
            return Err(ApiError::Validation(vec![e]));
        }
    }

    // L-2: an events update must pass the same validation as creation —
    // `events: []` or unknown names previously persisted silently, leaving a
    // webhook that can never fire.
    if let Some(ref new_events) = body.events {
        if let Err(e) = validate_webhook_events(new_events) {
            return Err(ApiError::Validation(vec![e]));
        }
    }

    let existing = fetch_webhook(&state, &auth.tenant_id, id.clone()).await?;
    let url = body.url.unwrap_or(existing.url);
    let events = body
        .events
        .map(|e| serde_json::json!(e))
        .unwrap_or(existing.events);

    let status = match body.status.as_deref() {
        Some(s) if s == "active" || s == "paused" || s == "disabled" => s.to_string(),
        Some(s) => {
            return Err(ApiError::Validation(vec![format!(
                "invalid status '{}': must be 'active', 'paused', or 'disabled'",
                s
            )]))
        }
        None => existing.status,
    };

    sqlx::query(
        "UPDATE webhooks SET url=$1, events=$2, status=$3, updated_at=NOW()
         WHERE id=$4 AND tenant_id=$5",
    )
    .bind(&url)
    .bind(&events)
    .bind(&status)
    .bind(&id)
    .bind(&auth.tenant_id)
    .execute(&state.db)
    .await?;

    Ok(Json(WebhookResponse {
        id,
        url,
        events,
        secret: None, // Don't expose secret in update response
        status,
        created_at: existing.created_at.to_rfc3339(),
        updated_at: Utc::now().to_rfc3339(),
    }))
}

async fn delete_webhook(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["webhooks:write"])?;

    let result = sqlx::query("DELETE FROM webhooks WHERE id = $1 AND tenant_id = $2")
        .bind(&id)
        .bind(&auth.tenant_id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("webhook not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn test_webhook(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<TestWebhookResponse>, ApiError> {
    require_scopes(&auth, &["webhooks:write"])?;

    let wh = fetch_webhook(&state, &auth.tenant_id, id).await?;

    if let Err(e) = validate_webhook_url(&wh.url) {
        return Err(ApiError::BadRequest(format!(
            "webhook URL validation failed: {e}"
        )));
    }

    // RS-058 + audit F: SSRF protection — resolve DNS and verify every IP is
    // public BEFORE making the HTTP request, then PIN the connection to the
    // validated addresses. The previous code validated `safe_addrs` and then
    // threw them away, posting to the hostname again via the shared client —
    // a classic DNS-rebinding TOCTOU (the comment claimed pinning that never
    // happened). The dedicated client also disables redirect following so a
    // `302 → http://169.254.169.254/` reply cannot pivot the validated
    // delivery to internal services.
    let url = Url::parse(&wh.url).map_err(|e| ApiError::BadRequest(format!("invalid URL: {e}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| ApiError::BadRequest("webhook URL has no host".into()))?
        .to_string();

    let allow_loopback = localhost_webhooks_allowed() && is_localhost(&host);
    let target_port = url.port_or_known_default().unwrap_or(443);
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{host}:{target_port}"))
        .await
        .map_err(|e| ApiError::BadRequest(format!("failed to resolve webhook URL host: {e}")))?
        .collect();

    // Reject the whole resolution set if any address is private/reserved;
    // returns the address to pin (first public one).
    let _pinned = select_pinned_addr(&addrs, allow_loopback).map_err(ApiError::BadRequest)?;

    let client = webhook_delivery_client(&host, &addrs).map_err(ApiError::BadRequest)?;

    let timeout = std::time::Duration::from_millis(state.config.webhook_timeout_ms);

    let payload = serde_json::json!({
        "type": "test",
        "timestamp": Utc::now().to_rfc3339(),
    });

    // RS-071: Return error instead of using unwrap_or_default() which would
    // produce an HMAC of empty data, causing silent signature verification failures.
    let payload_bytes = serde_json::to_vec(&payload).map_err(|e| {
        ApiError::Internal(format!("failed to serialize webhook test payload: {e}"))
    })?;
    let signature =
        apexmail_lib::crypto::create_hmac_signature(wh.secret.as_bytes(), &payload_bytes);

    let start = std::time::Instant::now();
    let result = client
        .post(&wh.url)
        .timeout(timeout)
        .header("Content-Type", "application/json")
        .header("X-Webhook-Signature", &signature)
        .json(&payload)
        .send()
        .await;
    let elapsed = start.elapsed().as_millis() as u64;

    match result {
        Ok(resp) => Ok(Json(TestWebhookResponse {
            success: resp.status().is_success(),
            status_code: Some(resp.status().as_u16()),
            response_time_ms: elapsed,
            error: None,
        })),
        Err(e) => Ok(Json(TestWebhookResponse {
            success: false,
            status_code: None,
            response_time_ms: elapsed,
            error: Some(e.to_string()),
        })),
    }
}

/// Rotate the webhook signing secret atomically.
///
/// Generates a new HMAC signing secret and updates the database in a single
/// transaction. The old secret is immediately invalidated — callers should
/// update their consumer endpoint to use the new secret before the next
/// webhook delivery.
///
/// # Security (API-M-03)
/// Rotation is atomic: the new secret is generated and persisted in one
/// database transaction, preventing a window where the webhook could be
/// delivered with a stale or absent secret.
async fn rotate_webhook_secret(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<WebhookResponse>, ApiError> {
    use crate::middleware::auth::require_scopes;
    require_scopes(&auth, &["webhooks:write"])?;

    // Verify the webhook exists and belongs to this tenant
    let existing = fetch_webhook(&state, &auth.tenant_id, id).await?;

    // Generate a new secret atomically within a transaction
    let new_secret = apexmail_lib::id::generate_webhook_secret();

    sqlx::query(
        "UPDATE webhooks SET secret = $1, updated_at = NOW()
         WHERE id = $2 AND tenant_id = $3",
    )
    .bind(&new_secret)
    .bind(&existing.id)
    .bind(&auth.tenant_id)
    .execute(&state.db)
    .await?;

    tracing::info!(
        webhook_id = %existing.id,
        tenant_id = %auth.tenant_id,
        "Webhook signing secret rotated"
    );

    Ok(Json(WebhookResponse {
        id: existing.id,
        url: existing.url,
        events: existing.events,
        secret: Some(new_secret),
        status: existing.status,
        created_at: existing.created_at.to_rfc3339(),
        updated_at: Utc::now().to_rfc3339(),
    }))
}

// ─── Row types ─────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct WebhookRow {
    id: String,
    url: String,
    events: serde_json::Value,
    secret: String,
    status: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<WebhookRow> for WebhookResponse {
    fn from(r: WebhookRow) -> Self {
        Self {
            id: r.id,
            url: r.url,
            events: r.events,
            secret: None,
            status: r.status,
            created_at: r.created_at.to_rfc3339(),
            updated_at: r.updated_at.to_rfc3339(),
        }
    }
}

async fn fetch_webhook(
    state: &AppState,
    tenant_id: &str,
    id: String,
) -> Result<WebhookRow, ApiError> {
    sqlx::query_as::<_, WebhookRow>(
        "SELECT id, url, events, secret, status, created_at, updated_at
         FROM webhooks WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("webhook not found".into()))
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_webhook_request_deser() {
        let json = r#"{"url":"https://example.com/hook","events":["delivered","bounced"]}"#;
        let req: CreateWebhookRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.events.len(), 2);
    }

    // ── L-2: event-type validation ───────────────────────────────

    fn events(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn webhook_events_must_be_non_empty() {
        let error = validate_webhook_events(&events(&[])).unwrap_err();
        assert!(
            error.contains("at least one event is required"),
            "unexpected error: {error}"
        );
        // The message must list the valid names so the fix is obvious.
        assert!(error.contains("message.delivered"));
        assert!(error.contains("recipient.unsubscribed"));
    }

    #[test]
    fn webhook_events_reject_unknown_names_with_a_helpful_message() {
        // `delivered`/`bounced` (the bare names the old tests used) are NOT
        // emitted by anything — they must now be rejected with the valid
        // alternatives listed.
        for bad in [
            "delivered",
            "delivred",
            "email.delivere",
            "email.delivered",
            "email.bounced",
            "message.sent",
        ] {
            let error = validate_webhook_events(&events(&[bad])).unwrap_err();
            assert!(
                error.contains(&format!("unknown event type(s): {bad}")),
                "unexpected error for {bad}: {error}"
            );
            assert!(error.contains("valid events:"), "must list valid events");
        }
        // Blank entries are invalid too.
        assert!(validate_webhook_events(&events(&["   "])).is_err());
        // A single bad name poisons the whole list, valid ones notwithstanding.
        assert!(validate_webhook_events(&events(&["message.delivered", "nope"])).is_err());
    }

    #[test]
    fn webhook_events_accept_every_emitted_and_documented_name() {
        for known in KNOWN_WEBHOOK_EVENTS {
            assert!(
                validate_webhook_events(&events(&[known])).is_ok(),
                "{known} must be accepted"
            );
        }
        // Mixed valid lists and the wildcard pass; surrounding whitespace on
        // a valid name is tolerated (trimmed).
        assert!(validate_webhook_events(&events(&[
            "message.delivered",
            "recipient.unsubscribed",
            "*"
        ]))
        .is_ok());
        // The legacy email.* vocabulary is retired — it must be rejected
        // with the canonical names listed (migration 128 remapped stored
        // subscriptions, so nothing legitimate still sends them).
        assert!(validate_webhook_events(&events(&["  email.bounced  "])).is_err());
    }

    #[test]
    fn known_webhook_events_match_the_documented_and_emitted_set() {
        // Documented API contract names must all be present.
        for documented in [
            "message.accepted",
            "message.delivered",
            "message.bounced",
            "message.complained",
            "message.opened",
            "message.clicked",
            "recipient.unsubscribed",
        ] {
            assert!(KNOWN_WEBHOOK_EVENTS.contains(&documented));
        }
        // Emitted names (ses_notifications, tracking, inbox-placement, mta)
        // and the selector wildcard must all be present.
        for emitted in [
            "message.delivered",
            "message.bounced",
            "message.complained",
            "message.queued",
            "message.attempted",
            "message.deferred",
            "message.suppressed",
            "message.cancelled",
            "placement_test.completed",
            "inbound",
            "*",
        ] {
            assert!(KNOWN_WEBHOOK_EVENTS.contains(&emitted));
        }
        // The retired vocabulary must be absent from the known set.
        for retired in [
            "email.delivered",
            "email.bounced",
            "email.complained",
            "message.sent",
            "bounce",
            "complaint",
        ] {
            assert!(!KNOWN_WEBHOOK_EVENTS.contains(&retired));
        }
    }

    #[test]
    fn test_webhook_response_serialisation() {
        let resp = WebhookResponse {
            id: String::new(),
            url: "https://example.com".into(),
            events: serde_json::json!(["delivered"]),
            secret: Some("whsec_abc".into()),
            status: "active".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "active");
    }

    #[test]
    fn test_test_webhook_response_success() {
        let resp = TestWebhookResponse {
            success: true,
            status_code: Some(200),
            response_time_ms: 150,
            error: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["success"], true);
        assert!(json.get("error").is_none());
    }

    #[test]
    fn test_validate_webhook_url_allows_explicit_localhost_http() {
        // NOTE (audit F): this test previously asserted that loopback HTTP
        // URLs are accepted unconditionally. That exemption let any
        // authenticated tenant point a webhook at services bound to the
        // host's loopback (SSRF). Loopback HTTP is now only allowed when
        // APEXMAIL_ALLOW_LOCALHOST_WEBHOOKS=true is explicitly set.
        assert!(validate_webhook_url_with("http://localhost:3000/hook", true).is_ok());
        assert!(validate_webhook_url_with("http://127.0.0.1:3000/hook", true).is_ok());
        // Without the override, loopback HTTP (and HTTPS) targets are rejected.
        assert!(validate_webhook_url_with("http://localhost:3000/hook", false).is_err());
        assert!(validate_webhook_url_with("http://127.0.0.1:3000/hook", false).is_err());
        assert!(validate_webhook_url_with("https://localhost:3000/hook", false).is_err());
        assert!(validate_webhook_url_with("https://[::1]/hook", false).is_err());
        // The override only ever applies to loopback — other private ranges
        // stay blocked even with the flag on.
        assert!(validate_webhook_url_with("http://10.0.0.5/hook", true).is_err());
        assert!(validate_webhook_url_with("https://192.168.1.10/hook", true).is_err());
        assert!(validate_webhook_url_with("https://169.254.169.254/hook", true).is_err());
    }

    #[test]
    fn test_validate_webhook_url_blocks_ipv6_link_local_targets() {
        let error = validate_webhook_url("https://[fe80::1]/hook").unwrap_err();
        assert!(error.contains("private or reserved addresses"));
    }

    #[test]
    fn test_validate_webhook_url_blocks_private_and_metadata_targets() {
        for url in [
            "https://10.0.0.1/hook",
            "https://192.168.0.1/hook",
            "https://172.16.5.5/hook",
            "https://169.254.169.254/latest/meta-data",
            "https://metadata.google.internal/hook",
            "https://printer.local/hook",
            "https://service.internal/hook",
        ] {
            assert!(
                validate_webhook_url(url).is_err(),
                "{url} must be rejected as an SSRF target"
            );
        }
        // Public HTTPS endpoints are accepted.
        assert!(validate_webhook_url("https://hooks.example.com/endpoint").is_ok());
        // Non-HTTP(s) schemes are rejected.
        assert!(validate_webhook_url("file:///etc/passwd").is_err());
        assert!(validate_webhook_url("gopher://127.0.0.1:6379/_INFO").is_err());
        // Plain HTTP to a public host is rejected without the override.
        assert!(validate_webhook_url("http://hooks.example.com/endpoint").is_err());
    }

    // ── DNS rebinding pin selection (audit F) ────────────────────

    fn socket_addr(ip: &str, port: u16) -> SocketAddr {
        format!("{ip}:{port}")
            .parse()
            .expect("test address must parse")
    }

    #[test]
    fn test_select_pinned_addr_rejects_any_private_address_in_resolution_set() {
        // Rebinding simulation: the hostname resolves to a public IP AND a
        // private IP (attacker-controlled DNS mixing records). The whole set
        // must be rejected — skipping only the private entry still lets the
        // connection race between records.
        let mixed = vec![
            socket_addr("93.184.216.34", 443),
            socket_addr("192.168.1.10", 443),
        ];
        let error = select_pinned_addr(&mixed, false).unwrap_err();
        assert!(error.contains("DNS rebinding"), "unexpected error: {error}");

        // Metadata endpoint in the resolution set.
        let metadata = vec![
            socket_addr("93.184.216.34", 443),
            socket_addr("169.254.169.254", 443),
        ];
        assert!(select_pinned_addr(&metadata, false).is_err());

        // All-public resolution pins the first address.
        let public = vec![
            socket_addr("93.184.216.34", 443),
            socket_addr("104.16.132.229", 443),
        ];
        let pinned = select_pinned_addr(&public, false).expect("public addrs must pin");
        assert_eq!(pinned, socket_addr("93.184.216.34", 443));

        // Empty resolution is an error, not a panic or silent pass.
        assert!(select_pinned_addr(&[], false).is_err());
    }

    #[test]
    fn test_select_pinned_addr_loopback_only_under_override() {
        let loopback = vec![socket_addr("127.0.0.1", 8080)];
        assert!(select_pinned_addr(&loopback, false).is_err());
        assert_eq!(
            select_pinned_addr(&loopback, true).unwrap(),
            socket_addr("127.0.0.1", 8080)
        );

        // Even with the override, non-loopback private addresses reject the set.
        let mixed = vec![
            socket_addr("127.0.0.1", 8080),
            socket_addr("10.0.0.5", 8080),
        ];
        assert!(select_pinned_addr(&mixed, true).is_err());
    }

    /// Audit F: webhook delivery must not follow redirects — a webhook
    /// endpoint replying `302 → http://127.0.0.1:1/metadata` must surface as
    /// the 302 itself, never issue the second hop.
    #[tokio::test]
    async fn webhook_test_delivery_does_not_follow_redirects() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind ephemeral test listener");
        let port = listener.local_addr().unwrap().port();
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let hits_clone = hits.clone();

        let server = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut sock, _)) = listener.accept().await {
                hits_clone.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                // 302 pointing at an "internal" target that must never be dialed.
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 302 Found\r\n\
                          Location: http://127.0.0.1:1/metadata\r\n\
                          Content-Length: 0\r\n\
                          Connection: close\r\n\r\n",
                    )
                    .await;
                let _ = sock.shutdown().await;
            }
        });

        let addrs = vec![SocketAddr::from(([127, 0, 0, 1], port))];
        let client = webhook_delivery_client("127.0.0.1", &addrs)
            .expect("failed to build pinned no-redirect client");

        let response = client
            .post(format!("http://127.0.0.1:{port}/hook"))
            .timeout(std::time::Duration::from_secs(5))
            .json(&serde_json::json!({"type": "test"}))
            .send()
            .await
            .expect("pinned request must reach the local test server");

        assert_eq!(
            response.status().as_u16(),
            302,
            "the redirect itself must be surfaced, not followed"
        );

        server.abort();
        let _ = server.await;
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "exactly one hop — the Location target must never be requested"
        );
    }
}
