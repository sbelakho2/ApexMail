//! Server-Sent Events (SSE) endpoint for real-time delivery event streaming.
//!
//! `GET /v1/stream`
//!
//! Clients connect via EventSource / fetch and receive a continuous stream of
//! tracking events (opened, clicked, unsubscribed, delivered, bounced) as they
//! happen. Events are scoped to the authenticated tenant via a JWT bearer
//! token passed in the `Authorization: Bearer <token>` header.
//!
//! Architecture:
//! 1. Client connects with a short-lived JWT containing `tenant_id` + `sub` (user id).
//! 2. Handler validates token, subscribes to Redis Pub/Sub channel `events:{tenant_id}`.
//! 3. The EventProcessor publishes each flushed event to `events:{tenant_id}` after
//!    successful Postgres write.
//! 4. This handler forwards matching events as SSE `data:` frames.
//! 5. Keepalive comments (`:keepalive`) are sent every 15 seconds to prevent
//!    proxy/LB idle timeouts.
//! 6. On disconnect, the Redis subscription is dropped automatically.
//!
//! Security:
//! - Token is validated with RS256 (asymmetric JWT — SEC-119).
//! - Token must have `stream` scope.
//! - Maximum connection duration:1 hour (server-side timeout).
//! - Rate-limited to 5 concurrent SSE connections per tenant.
//!
//! F12:the per-tenant cap is tracked in Redis, but when Redis is unreachable
//! an IN-PROCESS per-tenant counter takes over (bounded fail-over, not
//! fail-open) so streams survive a Redis outage without the cap
//! disappearing.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
};
use futures::stream::Stream;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tokio_stream::StreamExt;
use tracing::{debug, error, info, warn};

use crate::state::AppState;

/// Query parameters for SSE endpoint.
#[derive(Debug, Deserialize)]
pub struct StreamQuery {
    /// Optional:filter by event types (comma-separated).
    /// Values:opened, clicked, unsubscribed, delivered, bounced
    #[serde(default)]
    pub events: Option<String>,
    /// Optional:filter by specific message_id.
    #[serde(default)]
    pub message_id: Option<String>,
}

/// Minimal JWT claims for SSE authentication.
#[derive(Debug, serde::Deserialize)]
struct StreamClaims {
    /// Tenant ID
    pub tenant_id: String,
    /// User/API key ID
    pub sub: String,
    /// Scopes (must include "stream" or "*")
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Expiration (unix timestamp) — read by jsonwebtoken's `validate_exp`
    /// during verification, not directly by this crate.
    #[expect(
        dead_code,
        reason = "validated by jsonwebtoken, not read directly here"
    )]
    pub exp: u64,
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let authorization = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let mut parts = authorization.splitn(2, ' ');
    let scheme = parts.next()?.trim();
    let token = parts.next().unwrap_or("").trim();

    if scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() {
        Some(token.to_string())
    } else {
        None
    }
}

/// Maximum concurrent SSE connections per tenant (Redis counter, and the
/// in-process fallback when Redis is unreachable — F12).
const MAX_CONNS_PER_TENANT: u64 = 5;

/// F12:in-process per-tenant connection counts, used ONLY when the Redis
/// counter is unreachable. Keeps the cap bounded during a Redis outage
/// (streams still connect — the event bus itself degrades separately)
/// instead of the old fail-open behaviour where one Redis blip removed the
/// cap entirely for every tenant.
static LOCAL_CONN_COUNTS: LazyLock<Mutex<HashMap<String, u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Increment the local fallback counter for a tenant; returns the NEW count
/// (the caller rejects when it exceeds [`MAX_CONNS_PER_TENANT`]).
fn local_conn_inc(tenant_id: &str) -> u64 {
    // A panicked holder cannot leave the cap unenforced — recover the guard.
    let mut counts = LOCAL_CONN_COUNTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let count = counts
        .entry(tenant_id.to_string())
        .and_modify(|c| *c += 1)
        .or_insert(1);
    *count
}

/// Decrement the local fallback counter for a tenant (never below zero).
fn local_conn_dec(tenant_id: &str) {
    let mut counts = LOCAL_CONN_COUNTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(count) = counts.get_mut(tenant_id) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(tenant_id);
        }
    }
}

/// SSE handler:validates token, subscribes to Redis Pub/Sub, streams events.
pub async fn handle_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<StreamQuery>,
) -> Response {
    // ── Validate JWT ──────────────────────────────────────────────────
    let Some(token) = extract_bearer_token(&headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({
                "error": {
                    "code": "UNAUTHORIZED",
                    "message": "missing Authorization: Bearer token"
                }
            })),
        )
            .into_response();
    };

    let claims = match validate_stream_token(&token, &state) {
        Ok(c) => c,
        Err(msg) => {
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({
                    "error": { "code": "UNAUTHORIZED", "message": msg }
                })),
            )
                .into_response();
        }
    };

    let tenant_id = claims.tenant_id.clone();

    // ── Check concurrent connection limit ─────────────────────────────
    // F12:Redis is the primary counter; when Redis is unreachable an
    // in-process per-tenant counter keeps the cap bounded (bounded
    // fail-over instead of the old fail-open, which removed the cap for
    // every tenant during a Redis blip).
    let conn_key = format!("sse:conns:{}", tenant_id);
    let conn_slot = match acquire_conn_slot(&state, &tenant_id, &conn_key).await {
        Ok(slot) => slot,
        Err(()) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                axum::Json(serde_json::json!({
                    "error": {
                        "code": "TOO_MANY_CONNECTIONS",
                        "message": format!("maximum {MAX_CONNS_PER_TENANT} concurrent SSE connections per tenant")
                    }
                })),
            )
                .into_response();
        }
    };

    // ── Parse event type filter ───────────────────────────────────────
    let event_filter: Option<Vec<String>> = params.events.map(|e| {
        e.split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect()
    });

    let message_filter = params.message_id.clone();

    info!(
        tenant_id = %tenant_id,
        user_id = %claims.sub,
        event_filter = ?event_filter,
        message_filter = ?message_filter,
        "SSE stream connected"
    );

    // ── Subscribe to Redis Pub/Sub channel ────────────────────────────
    let channel = format!("events:{}", tenant_id);
    let redis_url = state.config.redis.url.clone();

    let stream = make_event_stream(
        redis_url,
        channel,
        tenant_id.clone(),
        event_filter,
        message_filter,
        conn_slot,
    );

    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keepalive"),
        )
        .into_response()
}

/// Create the SSE event stream backed by a Redis Pub/Sub subscription.
/// This spawns a dedicated Redis connection (separate from the pool) for the
/// Pub/Sub subscription, since subscribed connections cannot issue other
/// commands — pub/sub connections are protocol-bound to subscription mode
/// and therefore cannot be borrowed from/returned to the deadpool pool the
/// crate uses for regular commands.
fn make_event_stream(
    redis_url: String,
    channel: String,
    tenant_id: String,
    event_filter: Option<Vec<String>>,
    message_filter: Option<String>,
    conn_slot: ConnSlot,
) -> impl Stream<Item = Result<Event, Infallible>> {
    async_stream::stream! {
    // ── Connection-count guard ───────────────────────────────────
    // Takes ownership of the slot for the lifetime of the stream; releases
    // on drop (client disconnect, timeout, error or normal end).
            let _guard = ConnCountGuard::new(conn_slot);

    // ── Initial connection event ──────────────────────────────────
            yield Ok(Event::default()
                .event("connected")
                .data(serde_json::json!({
                    "tenant_id": &tenant_id,
                    "channel": &channel,
                    "filters": {
                        "events": &event_filter,
                        "message_id": &message_filter,
                    },
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                }).to_string()));

    // ── Connect to Redis Pub/Sub ──────────────────────────────────
            let client = match redis::Client::open(redis_url.as_str()) {
                Ok(c) => c,
                Err(e) => {
                    error!(error = %e, "Failed to create Redis client for SSE");
                    yield Ok(Event::default()
                        .event("error")
                        .data(r#"{"error":"internal_error","message":"Failed to connect to event bus"}"#));
                    return;
                }
            };

            let mut pubsub_conn = match client.get_async_pubsub().await {
                Ok(c) => c,
                Err(e) => {
                    error!(error = %e, "Failed to get Pub/Sub connection");
                    yield Ok(Event::default()
                        .event("error")
                        .data(r#"{"error":"internal_error","message":"Failed to subscribe to event bus"}"#));
                    return;
                }
            };

            if let Err(e) = pubsub_conn.subscribe(&channel).await {
                error!(error = %e, channel = %channel, "Failed to subscribe to channel");
                yield Ok(Event::default()
                    .event("error")
                    .data(r#"{"error":"internal_error","message":"Failed to subscribe to channel"}"#));
                return;
            }

            debug!(channel = %channel, "Subscribed to Redis Pub/Sub");

    // ── Stream events with 1-hour maximum duration ────────────────
            let max_duration = tokio::time::sleep(Duration::from_secs(3600));
            tokio::pin!(max_duration);

            let mut msg_stream = pubsub_conn.on_message();

            loop {
                tokio::select! {
    // Timeout after 1 hour
                    _ = &mut max_duration => {
                        info!(tenant_id = %tenant_id, "SSE stream max duration reached (1h)");
                        yield Ok(Event::default()
                            .event("timeout")
                            .data(r#"{"message":"Maximum stream duration reached. Please reconnect."}"#));
                        break;
                    }
    // Receive message from Redis Pub/Sub
                    msg = msg_stream.next() => {
                        match msg {
                            Some(msg) => {
                                let payload: String = match msg.get_payload() {
                                    Ok(p) => p,
                                    Err(e) => {
                                        warn!(error = %e, "Failed to decode Pub/Sub message payload");
                                        continue;
                                    }
                                };

    // Parse the event JSON to apply filters
                                if let Ok(event_json) = serde_json::from_str::<serde_json::Value>(&payload) {
    // Apply event type filter
                                    if let Some(ref filter) = event_filter {
                                        if let Some(event_type) = event_json.get("type").and_then(|v| v.as_str()) {
                                            if !filter.iter().any(|f| f == event_type) {
                                                continue;
                                            }
                                        }
                                    }

    // Apply message_id filter
                                    if let Some(ref mid) = message_filter {
                                        if let Some(msg_id) = event_json.get("messageId").and_then(|v| v.as_str()) {
                                            if msg_id != mid.as_str() {
                                                continue;
                                            }
                                        }
                                    }

    // Determine SSE event name from the type field
                                    let event_name = event_json
                                        .get("type")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("event");

                                    yield Ok(Event::default()
                                        .event(event_name)
                                        .data(payload));
                                } else {
    // Raw payload without valid JSON — send as-is
                                    yield Ok(Event::default()
                                        .event("event")
                                        .data(payload));
                                }
                            }
                            None => {
    // Redis connection closed
                                warn!(tenant_id = %tenant_id, "Redis Pub/Sub stream ended");
                                yield Ok(Event::default()
                                    .event("error")
                                    .data(r#"{"error":"stream_ended","message":"Event stream connection lost. Please reconnect."}"#));
                                break;
                            }
                        }
                    }
                }
            }

    // Cleanup:release the connection slot via the guard (drop decrements on
    // every exit path; the explicit release simply runs it inline).
            let _ = _guard.release().await;
            info!(tenant_id = %tenant_id, "SSE stream disconnected");
        }
}

/// Decrement the per-tenant SSE connection counter in Redis.
async fn decrement_conn_count(pool: &deadpool_redis::Pool, key: &str) {
    if let Ok(mut conn) = pool.get().await {
        let _: Result<(), _> = redis::cmd("DECR").arg(key).query_async(&mut *conn).await;
    }
}

/// A claimed per-tenant connection slot (F12). Released exactly once by
/// [`ConnCountGuard`] — against the Redis counter when it was acquired
/// there, or against the in-process fallback otherwise.
enum ConnSlot {
    Redis {
        pool: deadpool_redis::Pool,
        key: String,
    },
    Local {
        tenant_id: String,
    },
}

impl ConnSlot {
    async fn release(self) {
        match self {
            ConnSlot::Redis { pool, key } => decrement_conn_count(&pool, &key).await,
            ConnSlot::Local { tenant_id } => local_conn_dec(&tenant_id),
        }
    }

    /// Synchronous release path for Drop:the local slot is sync; the Redis
    /// slot needs the async decrement spawned on the current runtime.
    fn release_on_drop(self) {
        match self {
            ConnSlot::Redis { pool, key } => {
                // Drop is synchronous — fire the async decrement on the current
                // runtime. Outside a runtime (e.g. dropped during shutdown) there is
                // nothing we can do; the counter key's TTL is the backstop.
                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    handle.spawn(async move {
                        decrement_conn_count(&pool, &key).await;
                    });
                } else {
                    warn!(key = %key, "SSE conn-count guard dropped outside runtime; relying on key TTL");
                }
            }
            ConnSlot::Local { tenant_id } => local_conn_dec(&tenant_id),
        }
    }
}

/// Claim a connection slot for a new SSE stream (F12).
///
/// `Ok(slot)` — proceed; the guard releases it on stream end.
/// `Err(())` — the tenant is at [`MAX_CONNS_PER_TENANT`] (reject with 429).
///
/// Redis INCR/EXPIRE is the primary counter. On ANY Redis error the
/// in-process fallback counter is used instead — streams stay available
/// during a Redis outage while the per-tenant cap stays bounded.
async fn acquire_conn_slot(
    state: &AppState,
    tenant_id: &str,
    conn_key: &str,
) -> Result<ConnSlot, ()> {
    let mut conn = match state.redis.get().await {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "SSE Redis pool error — using in-process connection cap fallback");
            return acquire_local_conn_slot(tenant_id);
        }
    };

    let count: u64 = match redis::cmd("INCR")
        .arg(conn_key)
        .query_async(&mut *conn)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "SSE Redis INCR failed — using in-process connection cap fallback");
            return acquire_local_conn_slot(tenant_id);
        }
    };

    // Refresh the TTL on EVERY increment so the counter self-heals after
    // a crash (a key only set on the first INCR could keep a stale high
    // count alive if the process died between INCR and EXPIRE, or outlive
    // its window when connections keep coming). A failure here only loses
    // the self-heal; the count itself is valid.
    if let Err(e) = redis::cmd("EXPIRE")
        .arg(conn_key)
        .arg(3700u64) // slightly longer than max 1h session
        .query_async::<()>(&mut *conn)
        .await
    {
        warn!(error = %e, "SSE connection counter TTL refresh failed");
    }

    if count > MAX_CONNS_PER_TENANT {
        // Decrement back since we won't actually use the slot
        let _: Result<(), _> = redis::cmd("DECR")
            .arg(conn_key)
            .query_async(&mut *conn)
            .await;
        return Err(());
    }

    Ok(ConnSlot::Redis {
        pool: state.redis.clone(),
        key: conn_key.to_string(),
    })
}

/// Claim a slot from the in-process fallback counter (F12).
fn acquire_local_conn_slot(tenant_id: &str) -> Result<ConnSlot, ()> {
    if local_conn_inc(tenant_id) > MAX_CONNS_PER_TENANT {
        // Release the probe increment before rejecting.
        local_conn_dec(tenant_id);
        return Err(());
    }
    Ok(ConnSlot::Local {
        tenant_id: tenant_id.to_string(),
    })
}

/// RAII guard that releases the per-tenant connection slot exactly once
/// when the SSE stream is dropped.
///
/// The old implementation decremented after the streaming loop, which never
/// ran when the client disconnected mid-stream (axum drops the `Sse` body
/// without polling the generator to completion) — the Redis counter leaked
/// until the key's TTL expired and the tenant hit `TOO_MANY_CONNECTIONS`.
/// Dropping the guard covers *every* exit path: client disconnect, 1-hour
/// timeout, Redis errors and normal end-of-stream.
struct ConnCountGuard {
    slot: Option<ConnSlot>,
    /// Set when the release has already been performed (or explicitly
    /// deferred) so Drop never releases twice.
    released: bool,
}

impl ConnCountGuard {
    fn new(slot: ConnSlot) -> Self {
        Self {
            slot: Some(slot),
            released: false,
        }
    }

    /// Release the slot asynchronously (used on graceful stream end so the
    /// release happens inline rather than via a spawned task).
    async fn release(mut self) {
        self.released = true;
        if let Some(slot) = self.slot.take() {
            slot.release().await;
        }
    }
}

impl Drop for ConnCountGuard {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        if let Some(slot) = self.slot.take() {
            slot.release_on_drop();
        }
    }
}

/// Validate the SSE stream JWT token using RS256 (SEC-119).
/// All JWTs in the system use RS256 (asymmetric) to prevent algorithm confusion
/// attacks. The public key is loaded from JWT_PUBLIC_KEY_PEM at startup.
fn validate_stream_token(token: &str, state: &AppState) -> Result<StreamClaims, String> {
    let decoding_key = DecodingKey::from_rsa_pem(state.config.jwt_public_key_pem.as_bytes())
        .map_err(|e| format!("Invalid JWT public key configuration: {e}"))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;
    validation.set_required_spec_claims(&["exp", "sub", "tenant_id"]);

    let token_data = decode::<StreamClaims>(token, &decoding_key, &validation)
        .map_err(|e| format!("Invalid stream token: {e}"))?;

    let claims = token_data.claims;

    // Check scope
    if !claims.scopes.iter().any(|s| s == "stream" || s == "*") {
        return Err("Token missing 'stream' scope".into());
    }

    if claims.tenant_id.is_empty() {
        return Err("Token missing tenant_id".into());
    }

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_bearer_token_accepts_authorization_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer stream.jwt".parse().unwrap(),
        );

        assert_eq!(
            extract_bearer_token(&headers).as_deref(),
            Some("stream.jwt")
        );
    }

    /// F12:the in-process fallback counter enforces the same per-tenant cap
    /// as Redis when Redis is unreachable.
    #[test]
    fn test_local_conn_counter_enforces_cap() {
        let tenant = format!("tenant_local_cap_test_{}", std::process::id());
        // Drain any residue from a previous (failed) run of this test.
        while LOCAL_CONN_COUNTS
            .lock()
            .expect("local conn-counts lock")
            .contains_key(&tenant)
        {
            local_conn_dec(&tenant);
        }

        // Up to the cap:slots are granted.
        for i in 1..=MAX_CONNS_PER_TENANT {
            assert!(
                acquire_local_conn_slot(&tenant).is_ok(),
                "slot {i} of {MAX_CONNS_PER_TENANT} must be granted"
            );
        }
        // One past the cap:rejected, and the probe increment is rolled back.
        assert!(acquire_local_conn_slot(&tenant).is_err());

        // Releasing a slot makes room again.
        local_conn_dec(&tenant);
        assert!(acquire_local_conn_slot(&tenant).is_ok());

        // Cleanup for repeat runs.
        for _ in 0..MAX_CONNS_PER_TENANT {
            local_conn_dec(&tenant);
        }
        assert!(
            !LOCAL_CONN_COUNTS
                .lock()
                .expect("local conn-counts lock")
                .contains_key(&tenant),
            "counter entry must be removed at zero"
        );
    }

    /// F12:tenants are independent in the fallback counter.
    #[test]
    fn test_local_conn_counter_is_per_tenant() {
        let a = format!("tenant_a_{}", std::process::id());
        let b = format!("tenant_b_{}", std::process::id());
        assert!(acquire_local_conn_slot(&a).is_ok());
        assert!(acquire_local_conn_slot(&b).is_ok());
        local_conn_dec(&a);
        local_conn_dec(&b);
    }

    /// F12:the local slot releases synchronously on guard drop.
    #[test]
    fn test_local_guard_releases_exactly_once() {
        let tenant = format!("tenant_guard_test_{}", std::process::id());
        let slot = acquire_local_conn_slot(&tenant).expect("slot");
        {
            let _guard = ConnCountGuard::new(slot);
            // Guard still holds the slot here.
        }
        // Dropped → the counter is back to zero (entry removed).
        assert!(!LOCAL_CONN_COUNTS
            .lock()
            .expect("local conn-counts lock")
            .contains_key(&tenant));
    }

    #[test]
    fn test_extract_bearer_token_rejects_missing_or_invalid_values() {
        let mut headers = HeaderMap::new();
        assert!(extract_bearer_token(&headers).is_none());

        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Basic abc123".parse().unwrap(),
        );
        assert!(extract_bearer_token(&headers).is_none());

        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer   ".parse().unwrap(),
        );
        assert!(extract_bearer_token(&headers).is_none());
    }
}
