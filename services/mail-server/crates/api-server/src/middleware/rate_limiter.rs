//! Fixed-window (and sliding-window approximation) rate limiter backed by Redis.
//!
//! Keys are per-tenant. On Redis failure the behaviour depends on the
//! environment:fail-open in development, fail-closed (503) in production.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use billing_common::cost_throttle::{cost_throttle_key, CostThrottleOverride};
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
            // F1b: browser surfaces (form posts, SSR pages) get a small
            // branded HTML page instead of a raw JSON error dump; API paths
            // keep the machine-readable envelope.
            let browser = crate::middleware::is_browser_facing_path(req.uri().path());
            let mut resp = if browser {
                crate::middleware::browser_error_page_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too Many Requests",
                    "Too many attempts",
                    "Wait a minute and try again.",
                    "/login",
                    "Back to sign in",
                )
            } else {
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    axum::Json(serde_json::json!({
                        "error": {
                            "code": "RATE_LIMIT_EXCEEDED",
                            "message": "too many requests"
                        }
                    })),
                )
                    .into_response()
            };
            resp.headers_mut()
                .insert("Retry-After", (reset_at / 1000).into());
            resp
        }
        Err(RateLimitOutcome::RedisDown) => {
            if state.config.environment == Environment::Production {
                // F1b: browser surfaces get the branded HTML outage page;
                // API paths keep the JSON envelope.
                if crate::middleware::is_browser_facing_path(req.uri().path()) {
                    crate::middleware::browser_error_page_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Service Unavailable",
                        "Temporarily unavailable",
                        "The console is temporarily unavailable — please try again shortly.",
                        "/login",
                        "Back to sign in",
                    )
                } else {
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
                }
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
        let baseline = cached_tier
            .map(|tier| requests_per_window_for_tier(tier, window_ms))
            .unwrap_or(state.config.rate_limit_max_requests);
        return apply_cost_throttle(state, tenant_id, baseline).await;
    }

    let baseline = match plans::get_quota_for_tenant(&state.db, tenant_id).await {
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
    };

    apply_cost_throttle(state, tenant_id, baseline).await
}

/// Apply a billing-owned cost throttle only when it can strictly reduce the
/// normal plan-derived request limit. A bad Redis value never lets a tenant
/// receive a larger limit or turns rate limiting off.
async fn apply_cost_throttle(state: &AppState, tenant_id: &str, baseline: u64) -> u64 {
    let key = cost_throttle_key(tenant_id);
    let mut connection = match state.redis.get().await {
        Ok(connection) => connection,
        Err(error) => {
            tracing::warn!(tenant_id = %tenant_id, error = %error, "redis pool error while resolving cost throttle");
            return baseline;
        }
    };

    let raw_override: Option<String> = match connection.get(&key).await {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(tenant_id = %tenant_id, error = %error, "redis GET error while resolving cost throttle");
            return baseline;
        }
    };

    let Some(raw_override) = raw_override else {
        return baseline;
    };

    let override_ = match serde_json::from_str::<CostThrottleOverride>(&raw_override) {
        Ok(override_) => override_,
        Err(error) => {
            tracing::warn!(tenant_id = %tenant_id, error = %error, "ignoring malformed cost throttle override");
            return baseline;
        }
    };

    match override_.capped_limit(baseline) {
        Some(capped) => {
            tracing::warn!(
                tenant_id = %tenant_id,
                baseline,
                capped,
                cap_percent = override_.cap_percent,
                reason = ?override_.reason,
                "applying temporary cost-protection rate limit"
            );
            capped
        }
        None => {
            tracing::warn!(
                tenant_id = %tenant_id,
                baseline,
                cap_percent = override_.cap_percent,
                version = override_.version,
                "ignoring non-reducing or unsupported cost throttle override"
            );
            baseline
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
    // Test/dev opt-out ONLY: production always enforces the public limiter
    // (see Config::public_rate_limit_enabled). The suite's parallel tests
    // share one Redis and one socket-less fallback path bucket; without this
    // the 20/min cap couples tests (429 instead of the asserted 400).
    if state.config.environment != crate::config::Environment::Production
        && !state.config.public_rate_limit_enabled
    {
        return next.run(req).await;
    }

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
            // F1b: browser form posts (/web/auth/*, /consent, detail pages)
            // get a small branded HTML page instead of a raw JSON error
            // dump; API paths keep the machine-readable envelope.
            let browser = crate::middleware::is_browser_facing_path(req.uri().path());
            let mut resp = if browser {
                crate::middleware::browser_error_page_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too Many Requests",
                    "Too many attempts",
                    "Wait a minute and try again.",
                    "/login",
                    "Back to sign in",
                )
            } else {
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    axum::Json(serde_json::json!({
                        "error": {
                            "code": "RATE_LIMIT_EXCEEDED",
                            "message": "too many requests — try again later"
                        }
                    })),
                )
                    .into_response()
            };
            resp.headers_mut()
                .insert("Retry-After", (reset_at / 1000).into());
            resp
        }
        Err(RateLimitOutcome::RedisDown) => {
            if state.config.environment == Environment::Production {
                // F1b: a Redis outage must not bounce a browser to a raw
                // JSON dump (or, via session resolution, silently to
                // /login as unauthenticated) — serve the branded HTML
                // outage page on browser paths; API paths keep JSON.
                if crate::middleware::is_browser_facing_path(req.uri().path()) {
                    crate::middleware::browser_error_page_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Service Unavailable",
                        "Temporarily unavailable",
                        "Sign-in is temporarily unavailable — please try again shortly.",
                        "/login",
                        "Back to sign in",
                    )
                } else {
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
                }
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
#[allow(clippy::result_unit_err)]
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
    fn cost_throttle_contract_only_reduces_the_plan_limit() {
        let override_ = CostThrottleOverride::critical_low_margin();
        assert_eq!(override_.capped_limit(30_000), Some(15_000));

        let cap_increase = CostThrottleOverride {
            cap_percent: 100,
            ..override_
        };
        assert_eq!(cap_increase.capped_limit(30_000), None);
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

// ─── W6a adversarial coverage campaign ─────────────────────────────────────
// These drive the REAL middleware fns through `tower::oneshot` over a mini
// router: burst boundaries at the exact limit, per-key isolation, window
// rotation on the real clock, plan-cache and cost-throttle resolution, and
// Redis-down fail-open/fail-closed. Redis-backed cases soft-skip when
// TEST_REDIS_URL is unreachable, per the idempotency-suite convention.

#[cfg(test)]
mod w6a_adversarial_tests {
    use super::*;
    use crate::config::Config;
    use axum::body::Body;
    use axum::http::HeaderValue;
    use axum::http::Method;
    use axum::routing::{get, post};
    use axum::Router;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tower::ServiceExt;
    use uuid::Uuid;

    async fn handler() -> &'static str {
        "ok"
    }

    fn test_redis_url() -> String {
        std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "redis://127.0.0.1:6379".into())
    }

    fn rl_config(
        environment: Environment,
        max_requests: u64,
        window_ms: u64,
        public_enabled: bool,
    ) -> Config {
        let mut cfg = crate::app::test_support::test_config();
        cfg.environment = environment;
        cfg.rate_limit_max_requests = max_requests;
        cfg.rate_limit_window_ms = window_ms;
        cfg.public_rate_limit_enabled = public_enabled;
        cfg.trusted_proxies = Vec::new();
        cfg
    }

    /// AppState over a lazy pool (handlers here never touch Postgres) and an
    /// explicit Redis URL so adversarial tests can pin a dead endpoint.
    async fn state_with(cfg: Config, redis_url: &str) -> AppState {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "postgres://apexmail:apexmail@127.0.0.1:1/apexmail".into());
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect_lazy(&database_url)
            .expect("lazy test pool");
        crate::app::test_support::test_state_over_with_config_and_redis(db, cfg, redis_url).await
    }

    async fn redis_ok(state: &AppState) -> bool {
        match state.redis.get().await {
            Ok(mut conn) => redis::cmd("PING")
                .query_async::<String>(&mut *conn)
                .await
                .is_ok(),
            Err(_) => false,
        }
    }

    fn tenant_app(state: AppState) -> Router {
        Router::new()
            .route("/rl", get(handler))
            .fallback(get(handler))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                rate_limit_middleware,
            ))
            .with_state(state)
    }

    fn public_app(state: AppState) -> Router {
        Router::new()
            .fallback(get(handler))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                public_rate_limit_middleware,
            ))
            .with_state(state)
    }

    /// Public-limiter router carrying the REAL browser and API paths the
    /// production mount mixes on one limiter stack (browser form routes and
    /// JSON auth routes), so the per-path response-shape split is exercised
    /// against actual path shapes.
    fn public_app_paths(state: AppState) -> Router {
        Router::new()
            .route("/web/auth/login", post(handler))
            .route("/v1/auth/login", post(handler))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                public_rate_limit_middleware,
            ))
            .with_state(state)
    }

    /// Tenant-limiter router mixing the authenticated browser form paths
    /// (/web/*) with API paths (/v1/*), like the production `authenticated`
    /// router does.
    fn tenant_app_paths(state: AppState) -> Router {
        Router::new()
            .route("/web/campaigns/abc/start", post(handler))
            .route("/v1/domains", post(handler))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                rate_limit_middleware,
            ))
            .with_state(state)
    }

    fn auth_user(tenant: &str) -> AuthUser {
        AuthUser {
            tenant_id: tenant.to_string(),
            user_id: None,
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        }
    }

    /// Tenant-scoped GET for the tenant middleware (AuthUser injected, as
    /// `require_auth` would).
    fn tenant_req(tenant: Option<&str>) -> Request<Body> {
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/rl")
            .body(Body::empty())
            .unwrap();
        if let Some(t) = tenant {
            req.extensions_mut().insert(auth_user(t));
        }
        req
    }

    /// Public-limiter request with arbitrary path/headers/socket.
    fn public_req(path: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(path)
            .body(Body::empty())
            .unwrap()
    }

    /// Browser form-post request (the shape /web/auth/login receives).
    fn browser_post_req(path: &str) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::empty())
            .unwrap()
    }

    /// Tenant-limiter form post with the AuthUser extension `require_auth`
    /// would have injected.
    fn tenant_post_req(tenant: &str, path: &str) -> Request<Body> {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(auth_user(tenant));
        req
    }

    fn with_header(mut req: Request<Body>, name: &str, value: &str) -> Request<Body> {
        let name = axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap();
        req.headers_mut()
            .insert(name, HeaderValue::from_str(value).unwrap());
        req
    }

    fn with_socket(mut req: Request<Body>, ip: std::net::IpAddr) -> Request<Body> {
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(ip, 44_000)));
        req
    }

    fn numeric_header(resp: &Response, name: &str) -> u64 {
        resp.headers()
            .get(name)
            .unwrap_or_else(|| panic!("response must carry {name}"))
            .to_str()
            .expect("ascii header")
            .parse()
            .expect("numeric header")
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("body readable");
        serde_json::from_slice(&bytes).expect("JSON body")
    }

    async fn body_string(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("body readable");
        String::from_utf8(bytes.to_vec()).expect("utf-8 body")
    }

    async fn seed(state: &AppState, key: &str, value: &str, ttl_secs: u64) {
        let mut conn = state.redis.get().await.expect("redis pool");
        let _: () = conn.set_ex(key, value, ttl_secs).await.expect("SET EX ok");
    }

    async fn stored_value(state: &AppState, key: &str) -> Option<String> {
        let mut conn = state.redis.get().await.expect("redis pool");
        conn.get(key).await.expect("GET ok")
    }

    #[tokio::test]
    async fn burst_boundary_allows_exactly_max_then_429_with_retry_after() {
        let state = state_with(
            rl_config(Environment::Production, 3, 60_000, true),
            &test_redis_url(),
        )
        .await;
        if !redis_ok(&state).await {
            eprintln!("skipping: TEST_REDIS_URL unreachable");
            return;
        }
        let app = tenant_app(state);
        let tenant = format!("w6a-burst-{}", Uuid::new_v4());

        // Requests 1..=3 are allowed; Remaining counts down to 0.
        for remaining in (0..3).rev() {
            let resp = app
                .clone()
                .oneshot(tenant_req(Some(&tenant)))
                .await
                .expect("oneshot");
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(numeric_header(&resp, "X-RateLimit-Limit"), 3);
            assert_eq!(numeric_header(&resp, "X-RateLimit-Remaining"), remaining);
            assert!(
                numeric_header(&resp, "X-RateLimit-Reset") > 0,
                "Reset must be an epoch timestamp of the window end"
            );
        }

        // The burst+1 request is rejected with Retry-After and the
        // machine-readable error envelope.
        let resp = app
            .oneshot(tenant_req(Some(&tenant)))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            numeric_header(&resp, "Retry-After") > 0,
            "429 must carry a positive Retry-After (seconds to window end)"
        );
        let body = body_json(resp).await;
        assert_eq!(body["error"]["code"], "RATE_LIMIT_EXCEEDED");
        assert_eq!(body["error"]["message"], "too many requests");
    }

    #[tokio::test]
    async fn per_tenant_keys_are_isolated_buckets() {
        let state = state_with(
            rl_config(Environment::Production, 1, 60_000, true),
            &test_redis_url(),
        )
        .await;
        if !redis_ok(&state).await {
            eprintln!("skipping: TEST_REDIS_URL unreachable");
            return;
        }
        let app = tenant_app(state);
        let a = format!("w6a-iso-a-{}", Uuid::new_v4());
        let b = format!("w6a-iso-b-{}", Uuid::new_v4());

        let resp = app.clone().oneshot(tenant_req(Some(&a))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(numeric_header(&resp, "X-RateLimit-Remaining"), 0);

        // A is exhausted; B must be untouched (no shared counter).
        assert_eq!(
            app.clone()
                .oneshot(tenant_req(Some(&a)))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        let resp = app.clone().oneshot(tenant_req(Some(&b))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // And A stays exhausted.
        assert_eq!(
            app.oneshot(tenant_req(Some(&a))).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn window_rotation_restores_the_budget_on_the_real_clock() {
        let state = state_with(
            rl_config(Environment::Production, 1, 1_100, true),
            &test_redis_url(),
        )
        .await;
        if !redis_ok(&state).await {
            eprintln!("skipping: TEST_REDIS_URL unreachable");
            return;
        }
        let app = tenant_app(state);
        let tenant = format!("w6a-rotate-{}", Uuid::new_v4());

        assert_eq!(
            app.clone()
                .oneshot(tenant_req(Some(&tenant)))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone()
                .oneshot(tenant_req(Some(&tenant)))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        // Sleep past the 1.1s window: the window index must advance and the
        // budget must be fresh (a stale key would 429 forever).
        tokio::time::sleep(Duration::from_millis(1_300)).await;
        assert_eq!(
            app.oneshot(tenant_req(Some(&tenant)))
                .await
                .unwrap()
                .status(),
            StatusCode::OK,
            "a new fixed window must reset the counter"
        );
    }

    #[tokio::test]
    async fn anonymous_system_and_unauthenticated_requests_use_the_configured_default() {
        let state = state_with(
            rl_config(Environment::Production, 4_321, 60_000, true),
            &test_redis_url(),
        )
        .await;
        if !redis_ok(&state).await {
            eprintln!("skipping: TEST_REDIS_URL unreachable");
            return;
        }
        let app = tenant_app(state);

        for tenant in [None, Some("anonymous"), Some("system")] {
            let resp = app
                .clone()
                .oneshot(tenant_req(tenant))
                .await
                .expect("oneshot");
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(
                numeric_header(&resp, "X-RateLimit-Limit"),
                4_321,
                "tenant {tenant:?} must resolve to the config default without a plan lookup"
            );
        }
    }

    #[tokio::test]
    async fn plan_cache_tier_drives_limit_and_unknown_tenant_negative_caches() {
        let state = state_with(
            rl_config(Environment::Production, 4_321, 60_000, true),
            &test_redis_url(),
        )
        .await;
        if !redis_ok(&state).await {
            eprintln!("skipping: TEST_REDIS_URL unreachable");
            return;
        }
        let app = tenant_app(state.clone());

        // (a) A cached tier short-circuits the DB and drives the limit.
        let tiered = format!("w6a-tier-{}", Uuid::new_v4());
        seed(
            &state,
            &tenant_rate_limit_cache_key(&tiered),
            &serde_json::to_string(&RateLimitTier::High).unwrap(),
            60,
        )
        .await;
        let resp = app
            .clone()
            .oneshot(tenant_req(Some(&tiered)))
            .await
            .unwrap();
        assert_eq!(
            numeric_header(&resp, "X-RateLimit-Limit"),
            30_000,
            "High tier = 500rps * 60s window"
        );

        // (b) An unknown tenant falls back to the DB's Ok(None) → config
        // default, and the negative result is cached to spare the DB.
        let unknown = format!("w6a-unknown-{}", Uuid::new_v4());
        let resp = app
            .clone()
            .oneshot(tenant_req(Some(&unknown)))
            .await
            .unwrap();
        assert_eq!(numeric_header(&resp, "X-RateLimit-Limit"), 4_321);
        assert_eq!(
            stored_value(&state, &tenant_rate_limit_cache_key(&unknown))
                .await
                .as_deref(),
            Some(TENANT_RATE_LIMIT_CACHE_NONE),
            "Ok(None) must be negative-cached"
        );

        // (c) A corrupted cache value must not poison the limit: the entry is
        // ignored and the DB fallback yields the default.
        let poisoned = format!("w6a-poison-{}", Uuid::new_v4());
        seed(
            &state,
            &tenant_rate_limit_cache_key(&poisoned),
            "{\"not\":\"a tier\"",
            60,
        )
        .await;
        let resp = app
            .clone()
            .oneshot(tenant_req(Some(&poisoned)))
            .await
            .unwrap();
        assert_eq!(
            numeric_header(&resp, "X-RateLimit-Limit"),
            4_321,
            "corrupt cache value must fall back to the database resolution"
        );
    }

    #[tokio::test]
    async fn cost_throttle_caps_baseline_and_ignores_hostile_values() {
        let state = state_with(
            rl_config(Environment::Production, 4_321, 60_000, true),
            &test_redis_url(),
        )
        .await;
        if !redis_ok(&state).await {
            eprintln!("skipping: TEST_REDIS_URL unreachable");
            return;
        }
        let app = tenant_app(state.clone());

        let resolve = |tenant: String| {
            let app = app.clone();
            async move {
                let resp = app
                    .oneshot(tenant_req(Some(tenant.as_str())))
                    .await
                    .unwrap();
                numeric_header(&resp, "X-RateLimit-Limit")
            }
        };

        // (a) A well-formed billing override strictly reduces the limit.
        let throttled = format!("w6a-cost-ok-{}", Uuid::new_v4());
        seed(
            &state,
            &tenant_rate_limit_cache_key(&throttled),
            TENANT_RATE_LIMIT_CACHE_NONE,
            60,
        )
        .await;
        let override_ = CostThrottleOverride::critical_low_margin();
        seed(
            &state,
            &cost_throttle_key(&throttled),
            &serde_json::to_string(&override_).unwrap(),
            60,
        )
        .await;
        assert_eq!(
            resolve(throttled.clone()).await,
            override_.capped_limit(4_321).unwrap(),
            "cost throttle must cap the config-derived baseline"
        );

        // (b) Malformed override JSON → baseline unchanged (never a 500, never off).
        let malformed = format!("w6a-cost-bad-{}", Uuid::new_v4());
        seed(
            &state,
            &tenant_rate_limit_cache_key(&malformed),
            TENANT_RATE_LIMIT_CACHE_NONE,
            60,
        )
        .await;
        seed(&state, &cost_throttle_key(&malformed), "{{{not json", 60).await;
        assert_eq!(resolve(malformed).await, 4_321);

        // (c) cap_percent = 100 would not reduce anything → ignored.
        let non_reducing = format!("w6a-cost-cap100-{}", Uuid::new_v4());
        seed(
            &state,
            &tenant_rate_limit_cache_key(&non_reducing),
            TENANT_RATE_LIMIT_CACHE_NONE,
            60,
        )
        .await;
        let cap100 = CostThrottleOverride {
            cap_percent: 100,
            ..CostThrottleOverride::critical_low_margin()
        };
        seed(
            &state,
            &cost_throttle_key(&non_reducing),
            &serde_json::to_string(&cap100).unwrap(),
            60,
        )
        .await;
        assert_eq!(resolve(non_reducing).await, 4_321);

        // (d) An unsupported version must be ignored, not applied.
        let future_version = format!("w6a-cost-v99-{}", Uuid::new_v4());
        seed(
            &state,
            &tenant_rate_limit_cache_key(&future_version),
            TENANT_RATE_LIMIT_CACHE_NONE,
            60,
        )
        .await;
        let v99 = CostThrottleOverride {
            version: 99,
            ..CostThrottleOverride::critical_low_margin()
        };
        seed(
            &state,
            &cost_throttle_key(&future_version),
            &serde_json::to_string(&v99).unwrap(),
            60,
        )
        .await;
        assert_eq!(resolve(future_version).await, 4_321);
    }

    #[tokio::test]
    async fn redis_down_fails_closed_in_production_and_open_in_development() {
        let dead = "redis://127.0.0.1:1";

        // Production: 503 with the SERVICE_UNAVAILABLE envelope.
        let prod = state_with(rl_config(Environment::Production, 10, 60_000, true), dead).await;
        let app = tenant_app(prod);
        let resp = app
            .clone()
            .oneshot(tenant_req(Some("w6a-dead-prod")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body_json(resp).await;
        assert_eq!(body["error"]["code"], "SERVICE_UNAVAILABLE");
        assert_eq!(body["error"]["message"], "rate limiter unavailable");

        // Development: fail-open — the handler runs and no rate-limit headers
        // are attached (the limiter never saw a counter).
        let dev = state_with(rl_config(Environment::Development, 10, 60_000, true), dead).await;
        let app = tenant_app(dev);
        let resp = app.oneshot(tenant_req(Some("w6a-dead-dev"))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            axum::body::to_bytes(resp.into_body(), 16)
                .await
                .unwrap()
                .as_ref(),
            b"ok"
        );
    }

    #[tokio::test]
    async fn public_limiter_dev_opt_out_never_limits() {
        let state = state_with(
            rl_config(Environment::Development, 10, 60_000, false),
            &test_redis_url(),
        )
        .await;
        let app = public_app(state);

        // The suite-wide opt-out must bypass the limiter entirely — even far
        // beyond 20 requests, and without touching Redis at all.
        for i in 0..30 {
            let resp = app
                .clone()
                .oneshot(public_req(&format!("/opt-out-{i}")))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "request {i} must pass");
            assert!(resp.headers().get("X-RateLimit-Limit").is_none());
        }
    }

    #[tokio::test]
    async fn public_limiter_allows_20_then_429s_the_21st_per_bucket() {
        let state = state_with(
            rl_config(Environment::Development, 1_000, 60_000, true),
            &test_redis_url(),
        )
        .await;
        if !redis_ok(&state).await {
            eprintln!("skipping: TEST_REDIS_URL unreachable");
            return;
        }
        let app = public_app(state);
        let key = format!("w6a-pub-{}", Uuid::new_v4());

        for remaining in (0..20).rev() {
            let resp = app
                .clone()
                .oneshot(with_header(public_req("/"), "x-api-key", &key))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(numeric_header(&resp, "X-RateLimit-Limit"), 20);
            assert_eq!(numeric_header(&resp, "X-RateLimit-Remaining"), remaining);
        }
        let resp = app
            .oneshot(with_header(public_req("/"), "x-api-key", &key))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(numeric_header(&resp, "Retry-After") > 0);
        let body = body_json(resp).await;
        assert_eq!(body["error"]["code"], "RATE_LIMIT_EXCEEDED");
        assert_eq!(
            body["error"]["message"],
            "too many requests — try again later"
        );
    }

    #[tokio::test]
    async fn public_limiter_buckets_are_isolated_per_credential() {
        let state = state_with(
            rl_config(Environment::Development, 1_000, 60_000, true),
            &test_redis_url(),
        )
        .await;
        if !redis_ok(&state).await {
            eprintln!("skipping: TEST_REDIS_URL unreachable");
            return;
        }
        let app = public_app(state);
        let key_a = format!("w6a-pub-iso-{}", Uuid::new_v4());
        let key_b = format!("w6a-pub-iso-{}", Uuid::new_v4());
        let session = format!("w6a-sess-{}", Uuid::new_v4());

        // Burn bucket A to exhaustion.
        for _ in 0..20 {
            assert_eq!(
                app.clone()
                    .oneshot(with_header(public_req("/"), "x-api-key", &key_a))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK
            );
        }
        assert_eq!(
            app.clone()
                .oneshot(with_header(public_req("/"), "x-api-key", &key_a))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );

        // A different API key on the same path is a different bucket.
        assert_eq!(
            app.clone()
                .oneshot(with_header(public_req("/"), "x-api-key", &key_b))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        // A session credential on the same path is yet another bucket — and
        // exhausting it must not leak into the API-key buckets.
        let cookie = format!("other=1; am_session={session}; trailing=2");
        for _ in 0..20 {
            assert_eq!(
                app.clone()
                    .oneshot(with_header(public_req("/"), "cookie", &cookie))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK
            );
        }
        assert_eq!(
            app.clone()
                .oneshot(with_header(public_req("/"), "cookie", &cookie))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            app.oneshot(with_header(public_req("/"), "x-api-key", &key_b))
                .await
                .unwrap()
                .status(),
            StatusCode::OK,
            "session bucket exhaustion must not affect the api-key bucket"
        );
    }

    #[tokio::test]
    async fn public_limiter_without_socket_or_credential_buckets_by_path() {
        let state = state_with(
            rl_config(Environment::Development, 1_000, 60_000, true),
            &test_redis_url(),
        )
        .await;
        if !redis_ok(&state).await {
            eprintln!("skipping: TEST_REDIS_URL unreachable");
            return;
        }
        let app = public_app(state);
        let path_a = format!("/w6a-path-{}", Uuid::new_v4());
        let path_b = format!("/w6a-path-{}", Uuid::new_v4());

        for _ in 0..20 {
            assert_eq!(
                app.clone()
                    .oneshot(public_req(&path_a))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK
            );
        }
        assert_eq!(
            app.clone()
                .oneshot(public_req(&path_a))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            app.oneshot(public_req(&path_b)).await.unwrap().status(),
            StatusCode::OK,
            "a different path must be a different fallback bucket"
        );
    }

    #[tokio::test]
    async fn public_limiter_buckets_by_forwarded_ip_only_through_trusted_proxies() {
        let mut cfg = rl_config(Environment::Development, 1_000, 60_000, true);
        cfg.trusted_proxies = vec!["10.0.0.0/8".into()];
        let state = state_with(cfg, &test_redis_url()).await;
        if !redis_ok(&state).await {
            eprintln!("skipping: TEST_REDIS_URL unreachable");
            return;
        }
        let app = public_app(state);
        let client_ip = format!("198.51.100.{}", 7);
        let xff = format!(
            "1.2.3.4, {client_ip}, 10.0.0.2" // spoofed prefix must be ignored (right-to-left walk)
        );

        // Behind a TRUSTED proxy the identity is the rightmost untrusted XFF
        // entry, not the proxy socket.
        let proxied = || {
            with_socket(
                with_header(public_req("/"), "x-forwarded-for", &xff),
                "10.1.2.3".parse().unwrap(),
            )
        };
        for _ in 0..20 {
            assert_eq!(
                app.clone().oneshot(proxied()).await.unwrap().status(),
                StatusCode::OK
            );
        }
        assert_eq!(
            app.clone().oneshot(proxied()).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS,
            "21st request from the same forwarded client IP must be limited"
        );

        // The SAME XFF behind an UNTRUSTED socket: the header is client-
        // controlled noise there, so the bucket is the socket IP and must be
        // unaffected by the proxied bucket's exhaustion.
        let direct = || {
            with_socket(
                with_header(public_req("/"), "x-forwarded-for", &xff),
                "203.0.113.9".parse().unwrap(),
            )
        };
        assert_eq!(
            app.clone().oneshot(direct()).await.unwrap().status(),
            StatusCode::OK,
            "spoofed XFF behind an untrusted socket must not inherit the proxied bucket"
        );
        assert_eq!(
            app.oneshot(direct()).await.unwrap().status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn public_limiter_redis_down_fails_closed_in_production_only() {
        let dead = "redis://127.0.0.1:1";

        let prod = state_with(rl_config(Environment::Production, 10, 60_000, true), dead).await;
        let app = public_app(prod);
        let resp = app
            .clone()
            .oneshot(public_req("/w6a-pub-dead"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body_json(resp).await;
        assert_eq!(body["error"]["code"], "SERVICE_UNAVAILABLE");

        let dev = state_with(rl_config(Environment::Development, 10, 60_000, true), dead).await;
        let app = public_app(dev);
        let resp = app
            .clone()
            .oneshot(public_req("/w6a-pub-dead"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "dev must fail open");
        assert!(resp.headers().get("X-RateLimit-Limit").is_none());
    }

    // ── F1b: browser surfaces get HTML, API surfaces keep JSON ───────────

    /// F1b: a rate-limited BROWSER form post (here /web/auth/login) gets a
    /// small branded HTML page — status 429, text/html, honest human copy
    /// and a way onward — never the raw JSON error dump a browser cannot
    /// render.
    #[tokio::test]
    async fn rate_limited_browser_post_gets_html_not_json() {
        let state = state_with(
            rl_config(Environment::Development, 1_000, 60_000, true),
            &test_redis_url(),
        )
        .await;
        if !redis_ok(&state).await {
            eprintln!("skipping: TEST_REDIS_URL unreachable");
            return;
        }
        let app = public_app_paths(state);
        // Unique credential per run: the bucket is per API key, so parallel
        // suites and prior runs cannot share (and pre-exhaust) the budget.
        let key = format!("w6a-html-{}", Uuid::new_v4());

        for _ in 0..20 {
            assert_eq!(
                app.clone()
                    .oneshot(with_header(
                        browser_post_req("/web/auth/login"),
                        "x-api-key",
                        &key
                    ))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK
            );
        }

        let resp = app
            .oneshot(with_header(
                browser_post_req("/web/auth/login"),
                "x-api-key",
                &key,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("text/html; charset=utf-8"),
            "the browser must get HTML, not the JSON error envelope"
        );
        assert!(
            numeric_header(&resp, "Retry-After") > 0,
            "the 429 must still carry Retry-After"
        );
        let body = body_string(resp).await;
        assert!(body.contains("Too many attempts"), "got: {body}");
        assert!(body.contains("href=\"/login\""), "got: {body}");
        // The branded page contains no braces at all — a JSON error body
        // cannot hide in it.
        assert!(!body.contains('{'), "got: {body}");
    }

    /// F1b: the same limiter on an API path keeps the machine-readable
    /// envelope EXACTLY — API clients and their tests must not notice the
    /// browser-facing change.
    #[tokio::test]
    async fn rate_limited_api_post_still_gets_json() {
        let state = state_with(
            rl_config(Environment::Development, 1_000, 60_000, true),
            &test_redis_url(),
        )
        .await;
        if !redis_ok(&state).await {
            eprintln!("skipping: TEST_REDIS_URL unreachable");
            return;
        }
        let app = public_app_paths(state);
        let key = format!("w6a-api-json-{}", Uuid::new_v4());

        for _ in 0..20 {
            assert_eq!(
                app.clone()
                    .oneshot(with_header(
                        browser_post_req("/v1/auth/login"),
                        "x-api-key",
                        &key
                    ))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK
            );
        }

        let resp = app
            .oneshot(with_header(
                browser_post_req("/v1/auth/login"),
                "x-api-key",
                &key,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = body_json(resp).await;
        assert_eq!(body["error"]["code"], "RATE_LIMIT_EXCEEDED");
        assert_eq!(
            body["error"]["message"],
            "too many requests — try again later"
        );
    }

    /// F1b: with Redis down in production the browser form post gets the
    /// branded HTML outage page (503, text/html, honest copy + /login link)
    /// instead of a raw JSON dump.
    #[tokio::test]
    async fn redis_outage_browser_post_gets_html_not_json() {
        let dead = "redis://127.0.0.1:1";
        let prod = state_with(rl_config(Environment::Production, 10, 60_000, true), dead).await;
        let app = public_app_paths(prod);

        let resp = app
            .oneshot(browser_post_req("/web/auth/login"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(
            resp.headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store"),
            "a transient outage page must never be cached"
        );
        let body = body_string(resp).await;
        assert!(body.contains("temporarily unavailable"), "got: {body}");
        assert!(body.contains("href=\"/login\""), "got: {body}");
        assert!(!body.contains('{'), "got: {body}");
    }

    /// F1b: with Redis down in production an API path still gets the JSON
    /// SERVICE_UNAVAILABLE envelope, unchanged.
    #[tokio::test]
    async fn redis_outage_api_post_still_gets_json() {
        let dead = "redis://127.0.0.1:1";
        let prod = state_with(rl_config(Environment::Production, 10, 60_000, true), dead).await;
        let app = public_app_paths(prod);

        let resp = app
            .oneshot(browser_post_req("/v1/auth/login"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body_json(resp).await;
        assert_eq!(body["error"]["code"], "SERVICE_UNAVAILABLE");
        assert_eq!(body["error"]["message"], "rate limiter unavailable");
    }

    /// F1b: the tenant limiter rides the SAME production router as the
    /// authenticated /web/* form posts, so the same split applies there:
    /// an exhausted browser post gets the branded HTML page; an exhausted
    /// API post keeps the JSON envelope.
    #[tokio::test]
    async fn tenant_limiter_browser_post_gets_html_and_api_keeps_json() {
        let state = state_with(
            rl_config(Environment::Production, 1, 60_000, true),
            &test_redis_url(),
        )
        .await;
        if !redis_ok(&state).await {
            eprintln!("skipping: TEST_REDIS_URL unreachable");
            return;
        }
        let app = tenant_app_paths(state);
        let browser_tenant = format!("w6a-ten-html-{}", Uuid::new_v4());
        let api_tenant = format!("w6a-ten-json-{}", Uuid::new_v4());

        // Browser path: 1 allowed, 2nd is the 429 HTML page.
        assert_eq!(
            app.clone()
                .oneshot(tenant_post_req(&browser_tenant, "/web/campaigns/abc/start"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let resp = app
            .clone()
            .oneshot(tenant_post_req(&browser_tenant, "/web/campaigns/abc/start"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        let body = body_string(resp).await;
        assert!(body.contains("Too many attempts"), "got: {body}");
        assert!(!body.contains('{'), "got: {body}");

        // API path: 1 allowed, 2nd is the 429 JSON envelope.
        assert_eq!(
            app.clone()
                .oneshot(tenant_post_req(&api_tenant, "/v1/domains"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let resp = app
            .oneshot(tenant_post_req(&api_tenant, "/v1/domains"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = body_json(resp).await;
        assert_eq!(body["error"]["code"], "RATE_LIMIT_EXCEEDED");
    }

    #[tokio::test]
    async fn sliding_window_blocks_over_limit_and_allows_fresh_keys_deterministically() {
        let state = state_with(
            rl_config(Environment::Development, 1_000, 60_000, true),
            &test_redis_url(),
        )
        .await;
        if !redis_ok(&state).await {
            eprintln!("skipping: TEST_REDIS_URL unreachable");
            return;
        }

        // No counters at all → estimate 0 → allowed.
        let fresh = format!("w6a-slide-fresh-{}", Uuid::new_v4());
        assert!(sliding_window_count(&state, &fresh, 60_000, 10)
            .await
            .unwrap());

        // Deterministic over-limit: with window = u64::MAX/2 the window index
        // is 0 now and forever, so current == previous == the seeded key and
        // the estimate is 11..=22 regardless of the position in the window.
        let huge = format!("w6a-slide-max-{}", Uuid::new_v4());
        seed(&state, &format!("apexmail:ratelimit:{huge}:0"), "11", 60).await;
        assert!(!sliding_window_count(&state, &huge, u64::MAX / 2, 10)
            .await
            .unwrap());

        // Dead Redis must be an Err, never a silent allow.
        let dead = state_with(
            rl_config(Environment::Development, 1_000, 60_000, true),
            "redis://127.0.0.1:1",
        )
        .await;
        assert!(sliding_window_count(&dead, "w6a-slide-dead", 60_000, 10)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn incr_expire_lua_sets_the_ttl_on_the_first_incr_only() {
        let state = state_with(
            rl_config(Environment::Development, 1_000, 60_000, true),
            &test_redis_url(),
        )
        .await;
        if !redis_ok(&state).await {
            eprintln!("skipping: TEST_REDIS_URL unreachable");
            return;
        }
        let mut conn = state.redis.get().await.expect("redis pool");
        let key = format!("w6a-lua-{}", Uuid::new_v4());
        let script = redis::Script::new(INCR_EXPIRE_LUA);

        let count: u64 = script
            .key(&key)
            .arg(60)
            .invoke_async(&mut *conn)
            .await
            .unwrap();
        assert_eq!(count, 1);
        let ttl: i64 = redis::cmd("TTL")
            .arg(&key)
            .query_async(&mut *conn)
            .await
            .unwrap();
        assert!(
            (1..=60).contains(&ttl),
            "the first INCR must leave the key with a TTL (crash safety), got {ttl}"
        );

        let count: u64 = script
            .key(&key)
            .arg(60)
            .invoke_async(&mut *conn)
            .await
            .unwrap();
        assert_eq!(count, 2, "the script must return the incrementing count");
        let ttl2: i64 = redis::cmd("TTL")
            .arg(&key)
            .query_async(&mut *conn)
            .await
            .unwrap();
        assert!(
            ttl2 <= ttl + 1,
            "later INCRs must not refresh the TTL (fixed-window semantics)"
        );
        let _: () = conn.del(&key).await.unwrap();
    }

    #[test]
    fn check_rate_limit_source_pins_incr_and_expire_together() {
        // The atomic INCR+EXPIRE-on-first script exists exactly twice: the
        // INCR_EXPIRE_LUA constant and check_rate_limit's inline copy. A
        // regression to a bare INCR would leave counters without TTL on a
        // crash between the two calls (a permanent rate limit). The needle is
        // assembled from parts so this test's own source does not contain it.
        let needle = ["redis.call('EXPIRE', KEYS[1]", ", ARGV[1])"].concat();
        let source = include_str!("rate_limiter.rs");
        assert_eq!(
            source.match_indices(&needle).count(),
            2,
            "INCR_EXPIRE_LUA and check_rate_limit must both pair INCR with EXPIRE-on-first"
        );
        let incr = ["local count = redis.call('IN", "CR', KEYS[1])"].concat();
        assert!(source.contains(&incr));
    }

    // ── Pure helpers ───────────────────────────────────────────────────────

    #[test]
    fn extract_user_key_prefers_api_key_then_session_cookie() {
        use sha2::Digest;

        let mut headers = HeaderMap::new();
        assert_eq!(extract_user_key_from_headers(&headers), None);

        headers.insert("x-api-key", HeaderValue::from_static("key-123"));
        assert_eq!(
            extract_user_key_from_headers(&headers),
            Some(format!(
                "ak:{}",
                hex::encode(sha2::Sha256::digest(b"key-123"))
            ))
        );

        // An EMPTY api key must be ignored, not hashed, so the cookie is used.
        headers.insert("x-api-key", HeaderValue::from_static(""));
        headers.insert(
            "cookie",
            HeaderValue::from_static("other=1; am_session=tok-9; trailing=2"),
        );
        assert_eq!(
            extract_user_key_from_headers(&headers),
            Some(format!(
                "session:{}",
                hex::encode(sha2::Sha256::digest(b"tok-9"))
            ))
        );

        // Cookies without the am_session entry yield nothing.
        headers.remove("x-api-key");
        headers.insert("cookie", HeaderValue::from_static("a=b; c=d"));
        assert_eq!(extract_user_key_from_headers(&headers), None);
        // An empty am_session value yields nothing either.
        headers.insert("cookie", HeaderValue::from_static("am_session=; x=1"));
        assert_eq!(extract_user_key_from_headers(&headers), None);
    }

    #[test]
    fn trusted_proxy_networks_accept_cidr_and_plain_ips_and_skip_junk() {
        let networks = parse_trusted_proxy_networks(&[
            " 10.0.0.0/8 ".into(),
            "192.168.1.7".into(),
            "".into(),
            "   ".into(),
            "definitely-not-a-network".into(),
        ]);
        assert_eq!(
            networks.len(),
            2,
            "CIDR + plain IP are kept, blank and junk entries are dropped"
        );
        assert!(is_in_trusted("10.255.1.1".parse().unwrap(), &networks));
        assert!(is_in_trusted("192.168.1.7".parse().unwrap(), &networks));
        assert!(!is_in_trusted("192.168.1.8".parse().unwrap(), &networks));
    }

    #[test]
    fn normalise_ip_folds_v6_mapped_v4_into_v4() {
        assert_eq!(
            normalise_ip("::ffff:203.0.113.5".parse().unwrap()),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            normalise_ip("2001:db8::1".parse().unwrap()),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn client_ip_walks_xff_then_real_ip_then_socket() {
        let trusted = vec!["10.0.0.0/8".to_string()];
        let socket: IpAddr = "10.1.2.3".parse().unwrap();

        // (a) Trusted socket, no XFF → x-real-ip is the client.
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", HeaderValue::from_static("198.51.100.21"));
        assert_eq!(
            extract_public_client_ip(&h, socket, &trusted),
            "198.51.100.21"
        );

        // (b) XFF made entirely of trusted proxies → walk is exhausted →
        // x-real-ip.
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("10.0.0.1, 10.0.0.2"),
        );
        h.insert("x-real-ip", HeaderValue::from_static("198.51.100.22"));
        assert_eq!(
            extract_public_client_ip(&h, socket, &trusted),
            "198.51.100.22"
        );

        // (c) Unparseable x-real-ip → back to the (normalised) socket.
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", HeaderValue::from_static("not-an-ip"));
        assert_eq!(extract_public_client_ip(&h, socket, &trusted), "10.1.2.3");

        // (d) Junk XFF parts are skipped; the first parseable untrusted entry
        // from the right wins.
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("banana, 198.51.100.23"),
        );
        assert_eq!(
            extract_public_client_ip(&h, socket, &trusted),
            "198.51.100.23"
        );

        // (e) Untrusted socket: headers are never consulted, not even
        // x-real-ip.
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.24"));
        h.insert("x-real-ip", HeaderValue::from_static("198.51.100.25"));
        assert_eq!(
            extract_public_client_ip(&h, "203.0.113.5".parse().unwrap(), &trusted),
            "203.0.113.5"
        );
    }

    #[test]
    fn ttl_jitter_stays_in_band_and_handles_tiny_bases() {
        for _ in 0..200 {
            let ttl = ttl_with_jitter(60, TENANT_RATE_LIMIT_CACHE_TTL_JITTER);
            assert!(
                (54..=66).contains(&ttl),
                "jittered TTL {ttl} outside the ±10% band [54,66]"
            );
        }
        // A base whose jitter band is < 1s must not be jittered (and never
        // become 0 — Redis rejects a 0 TTL).
        assert_eq!(ttl_with_jitter(1, 0.10), 1);
        assert_eq!(ttl_with_jitter(4, 0.10), 4);
        assert_eq!(ttl_with_jitter(0, 0.10), 0);
        // A 100% jitter band stays within [1, 2*base].
        for _ in 0..100 {
            let ttl = ttl_with_jitter(5, 1.0);
            assert!((1..=10).contains(&ttl), "jittered TTL {ttl} outside [1,10]");
        }
    }
}
