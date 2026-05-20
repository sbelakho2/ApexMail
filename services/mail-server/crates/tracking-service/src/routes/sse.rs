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

use std::convert::Infallible;
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
    /// Expiration (unix timestamp)
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
    let conn_key = format!("sse:conns:{}", &tenant_id);
    let conn_check: Result<bool, String> = async {
        let mut conn = state.redis.get().await.map_err(|e| format!("Redis: {e}"))?;
        let count: u64 = redis::cmd("INCR")
            .arg(&conn_key)
            .query_async(&mut *conn)
            .await
            .map_err(|e| format!("Redis INCR: {e}"))?;
        // Set expiry on first increment to auto-cleanup on crash
        if count == 1 {
            let _: () = redis::cmd("EXPIRE")
                .arg(&conn_key)
                .arg(3700u64) // slightly longer than max 1h session
                .query_async(&mut *conn)
                .await
                .map_err(|e| format!("Redis EXPIRE: {e}"))?;
        }
        if count > 5 {
            // Decrement back since we won't actually use the slot
            let _: () = redis::cmd("DECR")
                .arg(&conn_key)
                .query_async(&mut *conn)
                .await
                .map_err(|e| format!("Redis DECR: {e}"))?;
            return Ok(false);
        }
        Ok(true)
    }
    .await;

    match conn_check {
        Ok(false) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                axum::Json(serde_json::json!({
                    "error": {
                        "code": "TOO_MANY_CONNECTIONS",
                        "message": "maximum 5 concurrent SSE connections per tenant"
                    }
                })),
            )
                .into_response();
        }
        Err(e) => {
            error!(error = %e, "SSE connection limit check failed");
            // Allow on Redis failure (fail open for availability)
        }
        Ok(true) => {}
    }

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
    let channel = format!("events:{}", &tenant_id);
    let redis_url = state.config.redis.url.clone();
    // Decrement connection count cleanup
    let cleanup_redis = state.redis.clone();
    let cleanup_key = conn_key.clone();

    let stream = make_event_stream(
        redis_url,
        channel,
        tenant_id.clone(),
        event_filter,
        message_filter,
        cleanup_redis,
        cleanup_key,
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
/// Pub/Sub subscription, since subscribed connections cannot issue other commands.
fn make_event_stream(
    redis_url: String,
    channel: String,
    tenant_id: String,
    event_filter: Option<Vec<String>>,
    message_filter: Option<String>,
    cleanup_redis: deadpool_redis::Pool,
    cleanup_key: String,
) -> impl Stream<Item = Result<Event, Infallible>> {
    async_stream::stream! {
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
                    decrement_conn_count(&cleanup_redis, &cleanup_key).await;
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
                    decrement_conn_count(&cleanup_redis, &cleanup_key).await;
                    return;
                }
            };

            if let Err(e) = pubsub_conn.subscribe(&channel).await {
                error!(error = %e, channel = %channel, "Failed to subscribe to channel");
                yield Ok(Event::default()
                    .event("error")
                    .data(r#"{"error":"internal_error","message":"Failed to subscribe to channel"}"#));
                decrement_conn_count(&cleanup_redis, &cleanup_key).await;
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

    // Cleanup:decrement connection count
            decrement_conn_count(&cleanup_redis, &cleanup_key).await;
            info!(tenant_id = %tenant_id, "SSE stream disconnected");
        }
}

/// Decrement the per-tenant SSE connection counter in Redis.
async fn decrement_conn_count(pool: &deadpool_redis::Pool, key: &str) {
    if let Ok(mut conn) = pool.get().await {
        let _: Result<(), _> = redis::cmd("DECR").arg(key).query_async(&mut *conn).await;
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
