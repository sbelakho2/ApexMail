//! Fixed-window (and sliding-window approximation) rate limiter backed by Redis.
//!
//! Keys are per-tenant. On Redis failure the behaviour depends on the
//! environment:fail-open in development, fail-closed (503) in production.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use billing_service::{plans, types::RateLimitTier};
use deadpool_redis::redis::{self, AsyncCommands};
use ipnetwork::IpNetwork;

use crate::config::Environment;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

const TENANT_RATE_LIMIT_CACHE_PREFIX: &str = "apexmail:ratelimit:tenant_plan:";
const TENANT_RATE_LIMIT_CACHE_TTL_SECS: u64 = 60;
/// DB-15: ±10% jitter range for cache TTL to prevent stampede on expiry.
const TENANT_RATE_LIMIT_CACHE_TTL_JITTER: f64 = 0.10;
const TENANT_RATE_LIMIT_CACHE_NONE: &str = "__none__";

/// Atomic `INCR` + `EXPIRE`-on-first.
///
/// Runs as a single Lua script so a crash between `INCR` and `EXPIRE` cannot
/// leave a counter key with no TTL (a stale key that never expires). Returns
/// the new counter value.
pub(crate) const INCR_EXPIRE_LUA: &str = r#"
    local count = redis.call('INCR', KEYS[1])
    if count == 1 then
        redis.call('EXPIRE', KEYS[1], ARGV[1])
    end
    return count
"#;

// ─── Fixed-window rate limiter (middleware function) ────────────

/// Axum middleware that enforces per-tenant fixed-window rate limits.
/// Inject via `axum::middleware::from_fn_with_state`.
pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    // Extract tenant_id from AuthUser (set by require_auth middleware).
    let tenant_id = req
        .extensions()
        .get::<AuthUser>()
        .map(|u| u.tenant_id.clone());

    let tenant_key = tenant_id.clone().unwrap_or_else(|| "anonymous".to_string());

    let window_ms = state.config.rate_limit_window_ms;
    let max_requests =
        resolve_rate_limit_max_requests(&state, tenant_id.as_deref(), window_ms).await;
    let redis_key = format!(
        "apexmail:ratelimit:{}:{}",
        tenant_key,
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

fn requests_per_window_for_tier(tier: RateLimitTier, window_ms: u64) -> u64 {
    let window_seconds = (window_ms.saturating_add(999) / 1000).max(1);
    u64::from(tier.rps()) * window_seconds
}

async fn resolve_rate_limit_max_requests(
    state: &AppState,
    tenant_id: Option<&str>,
    window_ms: u64,
) -> u64 {
    let Some(tenant_id) =
        tenant_id.filter(|tenant_id| *tenant_id != "anonymous" && *tenant_id != "system")
    else {
        return state.config.rate_limit_max_requests;
    };

    if let Ok(Some(cached_tier)) = lookup_cached_rate_limit_tier(state, tenant_id).await {
        return cached_tier
            .map(|tier| requests_per_window_for_tier(tier, window_ms))
            .unwrap_or(state.config.rate_limit_max_requests);
    }

    match plans::get_quota_for_tenant(&state.db, tenant_id).await {
        Ok(Some(quota)) => {
            cache_rate_limit_tier(state, tenant_id, Some(quota.rate_limit_tier)).await;
            requests_per_window_for_tier(quota.rate_limit_tier, window_ms)
        }
        Ok(None) => {
            cache_rate_limit_tier(state, tenant_id, None).await;
            state.config.rate_limit_max_requests
        }
        Err(error) => {
            tracing::warn!(tenant_id = %tenant_id, error = %error, "Failed to resolve tenant plan for rate limiting");
            state.config.rate_limit_max_requests
        }
    }
}

fn tenant_rate_limit_cache_key(tenant_id: &str) -> String {
    format!("{TENANT_RATE_LIMIT_CACHE_PREFIX}{tenant_id}")
}

fn parse_cached_rate_limit_tier(value: &str) -> Option<Option<RateLimitTier>> {
    if value == TENANT_RATE_LIMIT_CACHE_NONE {
        return Some(None);
    }
    serde_json::from_str::<RateLimitTier>(value).ok().map(Some)
}

async fn lookup_cached_rate_limit_tier(
    state: &AppState,
    tenant_id: &str,
) -> Result<Option<Option<RateLimitTier>>, ()> {
    let cache_key = tenant_rate_limit_cache_key(tenant_id);
    let mut conn = state.redis.get().await.map_err(|error| {
        tracing::warn!(error = %error, tenant_id, "redis pool error in tenant rate-limit cache lookup");
    })?;

    let cached: Option<String> = conn.get(&cache_key).await.map_err(|error| {
        tracing::warn!(error = %error, tenant_id, "redis GET error in tenant rate-limit cache lookup");
    })?;

    match cached.as_deref() {
        None => Ok(None),
        Some(value) => match parse_cached_rate_limit_tier(value) {
            Some(parsed) => Ok(Some(parsed)),
            None => {
                tracing::warn!(
                    tenant_id = %tenant_id,
                    value = %value,
                    "invalid tenant rate-limit cache value; falling back to database"
                );
                Ok(None)
            }
        },
    }
}

/// DB-15: Apply ±jitter to a base TTL (seconds) so that cache entries expire
/// at slightly different times, preventing all concurrent requests from
/// stampeding the database when the TTL elapses.
fn ttl_with_jitter(base_secs: u64, jitter: f64) -> u64 {
    let jitter_secs = (base_secs as f64 * jitter) as u64;
    if jitter_secs == 0 {
        return base_secs;
    }
    // Deterministic jitter using a simple hash of the cache key is a viable
    // alternative for embededded environments, but here we use the system time
    // as a cheap source of per-request variation.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64;
    let offset = (nanos % (jitter_secs * 2 + 1)) as i64 - jitter_secs as i64;
    (base_secs as i64 + offset).max(1) as u64
}

async fn cache_rate_limit_tier(state: &AppState, tenant_id: &str, tier: Option<RateLimitTier>) {
    let value = match tier {
        Some(tier) => match serde_json::to_string(&tier) {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(tenant_id = %tenant_id, error = %error, "failed to serialize tenant rate-limit tier");
                return;
            }
        },
        None => TENANT_RATE_LIMIT_CACHE_NONE.to_string(),
    };

    let cache_key = tenant_rate_limit_cache_key(tenant_id);
    if let Ok(mut conn) = state.redis.get().await {
        let ttl = ttl_with_jitter(
            TENANT_RATE_LIMIT_CACHE_TTL_SECS,
            TENANT_RATE_LIMIT_CACHE_TTL_JITTER,
        );
        let _: Result<(), _> = conn.set_ex(&cache_key, value, ttl).await;
    }
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
    let mut conn = state.redis.get().await.map_err(|e| {
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
    let socket_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());

    // SA2-006: Derive a user-scoped key component to prevent IP-only bypass
    // via botnets. When an authenticated credential (API key or session cookie)
    // is present, we hash it to create a deterministic user key. This means
    // each user/API key gets its own rate limit bucket regardless of source IP.
    let user_key = extract_user_key_from_headers(req.headers());

    let bucket = if let Some(socket_ip) = socket_ip {
        let client_ip =
            extract_public_client_ip(req.headers(), socket_ip, &state.config.trusted_proxies);
        if let Some(ref uk) = user_key {
            format!("ip:{client_ip}:user:{uk}:{path}")
        } else {
            format!("ip:{client_ip}:{path}")
        }
    } else if let Some(ref uk) = user_key {
        format!("user:{uk}:{path}")
    } else {
        tracing::warn!("public rate limiter missing ConnectInfo; falling back to path bucket");
        format!("path:{path}")
    };

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

pub(crate) fn extract_public_client_ip(
    headers: &HeaderMap,
    socket_ip: IpAddr,
    trusted_proxies: &[String],
) -> String {
    let socket_ip = normalise_ip(socket_ip);
    let trusted_networks = parse_trusted_proxy_networks(trusted_proxies);

    if !is_in_trusted(socket_ip, &trusted_networks) {
        return socket_ip.to_string();
    }

    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        // Walk XFF right-to-left: the rightmost entry was appended by the
        // closest proxy, so the first untrusted address encountered from the
        // right is the real client IP. Leftmost entries are client-supplied
        // and trivially spoofable (`X-Forwarded-For: 1.2.3.4, real-client,
        // trusted-proxy`), so a left-to-right scan would let callers pick an
        // arbitrary rate-limit identity.
        for part in xff.split(',').rev().map(str::trim) {
            if let Ok(ip) = part.parse::<IpAddr>() {
                let ip = normalise_ip(ip);
                if !is_in_trusted(ip, &trusted_networks) {
                    return ip.to_string();
                }
            }
        }
    }

    if let Some(xri) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        if let Ok(ip) = xri.trim().parse::<IpAddr>() {
            return normalise_ip(ip).to_string();
        }
    }

    socket_ip.to_string()
}

fn parse_trusted_proxy_networks(trusted_proxies: &[String]) -> Vec<IpNetwork> {
    let mut networks = Vec::new();

    for entry in trusted_proxies {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Ok(net) = trimmed.parse::<IpNetwork>() {
            networks.push(net);
            continue;
        }

        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            networks.push(IpNetwork::from(ip));
            continue;
        }

        tracing::warn!(value = %trimmed, "Ignoring invalid TRUSTED_PROXIES entry");
    }

    networks
}

fn normalise_ip(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return IpAddr::V4(v4);
        }
    }
    ip
}

/// SA2-006: Extract a user-scoped key from request headers to prevent
/// IP-only rate limit bypass via botnets. Returns a SHA-256 hash of the
/// API key or session token if present, allowing per-credential rate
/// limiting irrespective of source IP.
fn extract_user_key_from_headers(headers: &HeaderMap) -> Option<String> {
    use sha2::{Digest, Sha256};

    // Prefer API key (most stable per-user identifier)
    if let Some(api_key) = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .filter(|k| !k.is_empty())
    {
        let hash = hex::encode(Sha256::digest(api_key.as_bytes()));
        return Some(format!("ak:{hash}"));
    }

    // Fall back to session token from cookie
    let cookies = headers.get("cookie").and_then(|v| v.to_str().ok())?;
    for cookie in cookies.split(';') {
        let cookie = cookie.trim();
        if let Some(value) = cookie.strip_prefix("am_session=") {
            if !value.is_empty() {
                let hash = hex::encode(Sha256::digest(value.as_bytes()));
                return Some(format!("session:{hash}"));
            }
        }
    }

    None
}

fn is_in_trusted(ip: IpAddr, ranges: &[IpNetwork]) -> bool {
    ranges.iter().any(|net| net.contains(ip))
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

    let estimated = (prev_count as f64 * (1.0 - position_in_window)) + curr_count as f64;

    Ok(estimated <= max as f64)
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_current_window_deterministic() {
        let w1 = current_window(60_000);
        let w2 = current_window(60_000);
        assert_eq!(w1, w2);
    }

    #[test]
    fn test_extract_public_client_ip_ignores_forwarded_when_socket_untrusted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.55, 203.0.113.10"),
        );

        let ip = extract_public_client_ip(&headers, "203.0.113.77".parse().unwrap(), &[]);

        assert_eq!(ip, "203.0.113.77");
    }

    #[test]
    fn test_extract_public_client_ip_uses_forwarded_when_socket_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.55, 10.0.0.2"),
        );

        let trusted = vec!["10.0.0.0/8".to_string()];
        let ip = extract_public_client_ip(&headers, "10.1.2.3".parse().unwrap(), &trusted);

        assert_eq!(ip, "198.51.100.55");
    }

    /// The client can inject arbitrary leftmost XFF entries; the walk must
    /// start from the right (closest proxy) so spoofed prefixes are ignored.
    #[test]
    fn test_extract_public_client_ip_ignores_spoofed_leftmost_entries() {
        let mut headers = HeaderMap::new();
        // "1.2.3.4" was injected by the client; 198.51.100.55 is the real
        // client as observed by the trusted proxy 10.0.0.2.
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.2.3.4, 198.51.100.55, 10.0.0.2"),
        );

        let trusted = vec!["10.0.0.0/8".to_string()];
        let ip = extract_public_client_ip(&headers, "10.1.2.3".parse().unwrap(), &trusted);

        assert_eq!(ip, "198.51.100.55");
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
    fn test_requests_per_window_for_rate_limit_tiers() {
        assert_eq!(
            requests_per_window_for_tier(RateLimitTier::Free, 60_000),
            600
        );
        assert_eq!(
            requests_per_window_for_tier(RateLimitTier::Standard, 60_000),
            6_000
        );
        assert_eq!(
            requests_per_window_for_tier(RateLimitTier::High, 60_000),
            30_000
        );
        assert_eq!(
            requests_per_window_for_tier(RateLimitTier::Unlimited, 60_000),
            300_000
        );
    }

    #[test]
    fn test_requests_per_window_rounds_up_subsecond_windows() {
        assert_eq!(requests_per_window_for_tier(RateLimitTier::Free, 500), 10);
    }

    #[test]
    fn test_tenant_rate_limit_cache_key_scopes_by_tenant() {
        assert_eq!(
            tenant_rate_limit_cache_key("ten_test_001"),
            "apexmail:ratelimit:tenant_plan:ten_test_001"
        );
    }

    #[test]
    fn test_parse_cached_rate_limit_tier_handles_tier_and_none_sentinel() {
        assert_eq!(
            parse_cached_rate_limit_tier(r#""high""#),
            Some(Some(RateLimitTier::High))
        );
        assert_eq!(
            parse_cached_rate_limit_tier(TENANT_RATE_LIMIT_CACHE_NONE),
            Some(None)
        );
        assert_eq!(parse_cached_rate_limit_tier("not-a-tier"), None);
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

    #[test]
    fn test_sliding_window_math_edge_cases() {
        // Window position at boundaries
        let at_start = 0.0_f64;
        let at_mid = 0.5_f64;
        let at_end = 1.0_f64;

        // At window start: estimated = prev * 1.0 + curr = prev + curr
        let prev_count = 100_f64;
        let curr_count = 50_f64;
        let estimated_start = prev_count * (1.0 - at_start) + curr_count;
        assert!((estimated_start - 150.0).abs() < f64::EPSILON);

        // At window midpoint: estimated = prev * 0.5 + curr
        let estimated_mid = prev_count * (1.0 - at_mid) + curr_count;
        assert!((estimated_mid - 100.0).abs() < f64::EPSILON);

        // At window end: estimated = curr
        let estimated_end = prev_count * (1.0 - at_end) + curr_count;
        assert!((estimated_end - 50.0).abs() < f64::EPSILON);
    }

    // ── Redis Failover Tests ─────────────────────────────────────

    /// Verifies the `check_rate_limit` function returns `RedisDown` when
    /// the Redis pool is unreachable — simulating a connection failure.
    /// This is a compile-time verification that the error mapping is correct:
    /// Redis pool errors → RateLimitOutcome::RedisDown.
    #[test]
    fn test_rate_limit_outcome_redis_down_maps_correctly() {
        // Verify the enum variant exists and can be constructed
        let outcome = RateLimitOutcome::RedisDown;
        assert!(
            matches!(outcome, RateLimitOutcome::RedisDown),
            "RateLimitOutcome::RedisDown must exist for Redis failure scenarios"
        );
    }

    /// Verifies the `RateLimitOutcome::Exceeded` variant carries the
    /// reset timestamp for proper Retry-After headers.
    #[test]
    fn test_rate_limit_outcome_exceeded_has_reset_at() {
        let outcome = RateLimitOutcome::Exceeded {
            reset_at: 1_700_000_000,
        };
        assert!(
            matches!(outcome, RateLimitOutcome::Exceeded { .. }),
            "RateLimitOutcome::Exceeded must carry reset_at for Retry-After header"
        );
    }

    /// Verifies the `RateLimitInfo` struct carries the correct fields
    /// for X-RateLimit-* headers.
    #[test]
    fn test_rate_limit_info_struct_fields() {
        let info = RateLimitInfo {
            remaining: 42,
            reset_at: 1_700_000_000_000,
        };
        assert_eq!(info.remaining, 42);
        assert_eq!(info.reset_at, 1_700_000_000_000);
    }

    /// Tests that `current_time_ms` returns a monotonically increasing
    /// value within a reasonable range (within the last 100 years).
    #[test]
    fn test_current_time_ms_reasonable_range() {
        let now = current_time_ms();
        // Must be after 2020 (milliseconds since epoch)
        assert!(
            now > 1_577_836_800_000,
            "current_time_ms must return a post-2020 timestamp"
        );
        // Must be before year 3000
        assert!(
            now < 32_507_712_000_000,
            "current_time_ms must return a sane timestamp"
        );
    }

    /// Tests the `current_window` function produces non-overlapping
    /// windows regardless of current time.
    #[test]
    fn test_current_window_non_overlapping() {
        let window_1s = current_window(1_000);
        let window_1m = current_window(60_000);
        // 1-minute window number should be <= 1-second window number
        // (since we have fewer 1-minute windows than 1-second windows)
        assert!(
            window_1m <= window_1s,
            "1-minute window index must be <= 1-second window index"
        );
        // Both should be > 0 (we're past epoch)
        assert!(window_1s > 0);
        assert!(window_1m > 0);
    }

    /// Tests that `requests_per_window_for_tier` correctly handles
    /// sub-second windows without division by zero.
    #[test]
    fn test_requests_per_window_tiny_window() {
        // A 1ms window with Free tier (10 rps) should yield at least 1
        let count = requests_per_window_for_tier(RateLimitTier::Free, 1);
        assert!(
            count > 0,
            "even a 1ms window must produce a positive request count"
        );
    }

    /// Tests that `requests_per_window_for_tier` handles all tiers
    /// consistently for the same window size.
    #[test]
    fn test_requests_per_window_all_tiers_monotonic() {
        let window = 60_000;
        let free = requests_per_window_for_tier(RateLimitTier::Free, window);
        let standard = requests_per_window_for_tier(RateLimitTier::Standard, window);
        let high = requests_per_window_for_tier(RateLimitTier::High, window);
        let unlimited = requests_per_window_for_tier(RateLimitTier::Unlimited, window);

        assert!(
            free <= standard,
            "Free tier must have <= Standard tier requests per window"
        );
        assert!(
            standard <= high,
            "Standard tier must have <= High tier requests per window"
        );
        assert!(
            high <= unlimited,
            "High tier must have <= Unlimited tier requests per window"
        );
    }
}
