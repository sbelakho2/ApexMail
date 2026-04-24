//! Fixed-window (and sliding-window approximation) rate limiter backed by Redis.
//!
//! Keys are per-tenant. On Redis failure the behaviour depends on the
//! environment:fail-open in development, fail-closed (503) in production.

use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use deadpool_redis::redis::{self, AsyncCommands};

use crate::config::Environment;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

// ─── Fixed-window rate limiter (middleware function) ────────────

/// Axum middleware that enforces per-tenant fixed-window rate limits.
/// Inject via `axum::middleware::from_fn_with_state`.
pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response
{
// Extract tenant_id from AuthUser (set by require_auth middleware).
    let tenant_id = req
        .extensions()
        .get::<AuthUser>()
        .map(|u| u.tenant_id.clone());

    let tenant_key = match tenant_id {
        Some(id) => id,
        None => "anonymous".to_string(),
    };

    let window_ms = state.config.rate_limit_window_ms;
    let max_requests = state.config.rate_limit_max_requests;
    let redis_key = format!("apexmail:ratelimit:{}:{}", tenant_key, current_window(window_ms));

    match check_rate_limit(&state, &redis_key, max_requests, window_ms).await {
        Ok(info) => {
            let mut resp = next.run(req).await;
            let headers = resp.headers_mut();
            headers.insert("X-RateLimit-Limit", max_requests.into());
            headers.insert("X-RateLimit-Remaining", info.remaining.into());
            headers.insert("X-RateLimit-Reset", info.reset_at.into());
            resp
        }
        Err(RateLimitOutcome::Exceeded { reset_at }) => {
            let mut resp = (
                StatusCode::TOO_MANY_REQUESTS,
                axum::Json(serde_json::json!({
                    "error": {
                        "code": "RATE_LIMIT_EXCEEDED",
                        "message": "too many requests"
                    }
                })),
            )
                .into_response();
            resp.headers_mut()
                .insert("Retry-After", (reset_at / 1000).into());
            resp
        }
        Err(RateLimitOutcome::RedisDown) => {
            if state.config.environment == Environment::Production {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    axum::Json(serde_json::json!({
                        "error": {
                            "code": "SERVICE_UNAVAILABLE",
                            "message": "rate limiter unavailable"
                        }
                    })),
                )
                    .into_response()
            } else {
// Fail open in development
                tracing::warn!("rate limiter Redis unavailable — failing open (dev mode)");
                next.run(req).await
            }
        }
    }
}

// ─── Internals ─────────────────────────────────────────────────

struct RateLimitInfo {
    remaining: u64,
    reset_at: u64,
}

enum RateLimitOutcome {
    Exceeded { reset_at: u64 },
    RedisDown,
}

fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn current_window(window_ms: u64) -> u64 {
    current_time_ms() / window_ms
}

async fn check_rate_limit(
    state: &AppState,
    key: &str,
    max: u64,
    window_ms: u64,
) -> Result<RateLimitInfo, RateLimitOutcome> {
    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "redis pool error in rate limiter");
            RateLimitOutcome::RedisDown
        })?;

// This prevents the race where a crash between INCR and EXPIRE leaves
// a key without TTL (permanent rate limit).
    let ttl_secs = (window_ms / 1000).max(1) as i64;
    let script = redis::Script::new(
        r#"
        local count = redis.call('INCR', KEYS[1])
        if count == 1 then
            redis.call('EXPIRE', KEYS[1], ARGV[1])
        end
        return count
        "#,
    );
    let count: u64 = script
        .key(key)
        .arg(ttl_secs)
        .invoke_async(&mut *conn)
        .await
        .map_err(|_| RateLimitOutcome::RedisDown)?;

    let reset_at = (current_window(window_ms) + 1) * window_ms;

    if count > max {
        return Err(RateLimitOutcome::Exceeded { reset_at });
    }

    Ok(RateLimitInfo {
        remaining: max.saturating_sub(count),
        reset_at,
    })
}

// ─── Public (IP-based) rate limiter for unauthenticated endpoints ────────

/// Stricter rate limiter for public auth endpoints (login, register, SSO).
/// Keys by source IP and route path, falling back to the request path when
/// no forwarded client IP is available. Limits:20 requests per 60-second
/// window per IP/path bucket — enough for legitimate users, tight enough to
/// mitigate credential-stuffing and registration spam without coupling every
/// public auth route to the same local-development bucket.
pub async fn public_rate_limit_middleware(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    let bucket = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|ip| !ip.is_empty())
        .map(|ip| format!("ip:{ip}:{path}"))
        .unwrap_or_else(|| format!("path:{path}"));

    let window_ms: u64 = 60_000; // 1 minute
    let max_requests: u64 = 20;
    let redis_key = format!(
        "apexmail:ratelimit:public:{}:{}",
        bucket,
        current_window(window_ms)
    );

    match check_rate_limit(&state, &redis_key, max_requests, window_ms).await {
        Ok(info) => {
            let mut resp = next.run(req).await;
            let headers = resp.headers_mut();
            headers.insert("X-RateLimit-Limit", max_requests.into());
            headers.insert("X-RateLimit-Remaining", info.remaining.into());
            headers.insert("X-RateLimit-Reset", info.reset_at.into());
            resp
        }
        Err(RateLimitOutcome::Exceeded { reset_at }) => {
            let mut resp = (
                StatusCode::TOO_MANY_REQUESTS,
                axum::Json(serde_json::json!({
                    "error": {
                        "code": "RATE_LIMIT_EXCEEDED",
                        "message": "too many requests — try again later"
                    }
                })),
            )
                .into_response();
            resp.headers_mut()
                .insert("Retry-After", (reset_at / 1000).into());
            resp
        }
        Err(RateLimitOutcome::RedisDown) => {
            if state.config.environment == Environment::Production {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    axum::Json(serde_json::json!({
                        "error": {
                            "code": "SERVICE_UNAVAILABLE",
                            "message": "rate limiter unavailable"
                        }
                    })),
                )
                    .into_response()
            } else {
                tracing::warn!("public rate limiter Redis unavailable — failing open (dev mode)");
                next.run(req).await
            }
        }
    }
}

// ─── Sliding-window approximation ──────────────────────────────

/// A sliding-window rate limiter that interpolates between the current and
/// previous window counts for smoother limiting.
pub async fn sliding_window_count(
    state: &AppState,
    tenant_id: &str,
    window_ms: u64,
    max: u64,
) -> Result<bool, ()> {
    let now_ms = current_time_ms();

    let current = now_ms / window_ms;
    let previous = current.saturating_sub(1);
    let position_in_window = (now_ms % window_ms) as f64 / window_ms as f64;

    let curr_key = format!("apexmail:ratelimit:{}:{}", tenant_id, current);
    let prev_key = format!("apexmail:ratelimit:{}:{}", tenant_id, previous);

    let mut conn = state.redis.get().await.map_err(|e| {
        tracing::warn!(error = %e, "redis pool error in sliding window count");
    })?;

    let curr_count: Option<u64> = conn.get(&curr_key).await.map_err(|e| {
        tracing::warn!(error = %e, key = %curr_key, "redis GET error in sliding window");
    })?;
    let prev_count: Option<u64> = conn.get(&prev_key).await.map_err(|e| {
        tracing::warn!(error = %e, key = %prev_key, "redis GET error in sliding window");
    })?;
    let curr_count = curr_count.unwrap_or(0);
    let prev_count = prev_count.unwrap_or(0);

    let estimated =
        (prev_count as f64 * (1.0 - position_in_window)) + curr_count as f64;

    Ok(estimated <= max as f64)
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_window_deterministic() {
        let w1 = current_window(60_000);
        let w2 = current_window(60_000);
        assert_eq!(w1, w2);
    }

    #[test]
    fn test_current_window_different_sizes() {
        let big = current_window(1_000);
        let small = current_window(60_000);
        assert!(big >= small);
    }

    #[test]
    fn test_rate_limit_info_remaining() {
        let info = RateLimitInfo {
            remaining: 999,
            reset_at: 1_700_000_000_000,
        };
        assert_eq!(info.remaining, 999);
    }

    #[test]
    fn test_sliding_window_math() {
// Pure math check:50% through window, prev=100, curr=50 → estimated 100
        let prev_count = 100_f64;
        let curr_count = 50_f64;
        let position = 0.5_f64;
        let estimated = prev_count * (1.0 - position) + curr_count;
        assert!((estimated - 100.0).abs() < f64::EPSILON);
    }
}
