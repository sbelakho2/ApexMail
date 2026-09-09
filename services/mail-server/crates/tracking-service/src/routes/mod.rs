//! Axum router factory — assembles all sub-routers and layers middleware.
//!
//! Middleware stack (outer → inner)://! 1. `tower_http::trace::TraceLayer` — structured request/response logging
//! 2. `tower_http::timeout::TimeoutLayer` — 30 s request timeout
//! 3. Compression (gzip)
//! 4. Per-IP rate limiter (Redis sliding-window, only when enabled in config)
//! 5. Request body limit on POST endpoints (10 KB)

pub mod click;
pub mod health;
pub mod pixel;
pub mod sse;
pub mod unsubscribe;

use std::net::SocketAddr;

use axum::{
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Router,
};
use tower_http::{
    compression::CompressionLayer,
    request_id::{MakeRequestUuid, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing::warn;

use crate::state::AppState;

/// 1×1 transparent GIF (hard-coded bytes — no allocation per request).
pub const TRANSPARENT_GIF: &[u8] = &[
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, // GIF89a
    0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x21, 0xf9, 0x04,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02,
    0x02, 0x44, 0x01, 0x00, 0x3b,
];

/// Build the complete axum `Router` with all routes and middleware.
pub fn build_router(state: AppState) -> Router {
    let cfg = state.config.clone();
    let pixel_path = cfg.tracking.pixel_path.clone();
    let click_path = cfg.tracking.click_path.clone();
    let unsub_path = cfg.tracking.unsubscribe_path.clone();
    let prefs_path = cfg.tracking.preferences_path.clone();

    let app = Router::new()
        // Open pixel endpoints
        .route(
            &format!("{pixel_path}/:tracking_id"),
            get(pixel::handle_pixel),
        )
        .route("/o.gif", get(pixel::handle_pixel_gif))
        // Click redirect
        .route(
            &format!("{click_path}/:tracking_id"),
            get(click::handle_click),
        )
        // One-click unsubscribe (RFC 8058)
        .route(
            &format!("{unsub_path}/:token"),
            post(unsubscribe::handle_unsub_post),
        )
        .route(
            &format!("{unsub_path}/:token"),
            get(unsubscribe::handle_unsub_get),
        )
        // F39:browser-facing manual confirmation form submit (plain HTML
        // form POST — no JS). Deliberately separate from the RFC 8058
        // one-click route so the `List-Unsubscribe=One-Click` body contract
        // stays untouched, and GET /u/:token stays side-effect free.
        .route(
            &format!("{unsub_path}/:token/confirm"),
            post(unsubscribe::handle_unsub_confirm_post),
        )
        // Preferences center
        .route(
            &format!("{prefs_path}/:token"),
            get(unsubscribe::handle_prefs_get),
        )
        .route(
            &format!("{prefs_path}/:token"),
            post(unsubscribe::handle_prefs_post),
        )
        // Real-time event streaming (SSE)
        .route("/v1/stream", get(sse::handle_stream))
        // Health checks
        .route("/health", get(health::handle_health))
        .route("/ready", get(health::handle_ready))
        // Inject shared state
        .with_state(state.clone());

    // Apply middleware layers
    let app = app
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(TimeoutLayer::new(std::time::Duration::from_secs(30)))
        .layer(DefaultBodyLimit::max(64 * 1024)); // 64 KB — tracking payloads are tiny

    // Rate-limit middleware (Redis sliding window) — wraps entire router
    if cfg.rate_limit.enabled {
        app.layer(middleware::from_fn_with_state(state, rate_limit_middleware))
    } else {
        app
    }
}

// ── IP extraction ─────────────────────────────────────────────────────────────

/// Extract the real client IP using the rightmost-untrusted XFF algorithm.
///
/// Algorithm:
/// 1. Get socket IP from `ConnectInfo<SocketAddr>` (normalised).
/// 2. If NO trusted proxies are configured, forwarded headers are pure
///    client-supplied input — return the socket IP unconditionally.
/// 3. If trusted proxies ARE configured and the socket IP is NOT one of
///    them, the peer is the client itself → return the socket IP (any XFF
///    it sent is spoofable).
/// 4. Otherwise (the peer IS a configured trusted proxy) walk
///    `X-Forwarded-For` **right-to-left**, skipping IPs that are trusted
///    proxies; the first untrusted IP is the client. The rightmost entries
///    are appended by our own infrastructure, so they are trustworthy —
///    leftmost entries are client-supplied and spoofable. The walk stops at
///    the first entry that does not parse as an IP: everything to its left
///    was written by the client, not by our proxies.
/// 5. Fall back to a validated `X-Real-IP` (only reachable via a trusted
///    peer).
/// 6. Fall back to the socket IP.
pub fn extract_client_ip(
    headers: &HeaderMap,
    socket_ip: std::net::IpAddr,
    state: &AppState,
) -> String {
    let trusted = &state.config.tracking.trusted_proxies;

    // Normalise IPv4-mapped IPv6 (::ffff:a.b.c.d → a.b.c.d)
    let socket_ip = normalise_ip(socket_ip);

    // With no trusted proxies configured there is nobody who could have
    // legitimately appended a forwarded header — honouring XFF here would
    // let any direct client spoof an arbitrary source IP.
    if trusted.is_empty() {
        return socket_ip.to_string();
    }

    if !is_in_trusted(socket_ip, trusted) {
        return socket_ip.to_string();
    }

    // Connecting address is a trusted proxy — read the forwarded header
    // right-to-left, trusting only entries our infrastructure appended.
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        for part in xff.split(',').map(str::trim).rev() {
            let Ok(ip) = part.parse::<std::net::IpAddr>() else {
                // Malformed entry: our proxies only append valid IPs, so
                // this entry (and everything to its left) is client input.
                break;
            };
            let ip = normalise_ip(ip);
            if !is_in_trusted(ip, trusted) {
                return ip.to_string();
            }
        }
        // Every XFF entry is itself a trusted proxy — fall through.
    }

    // #188:Validate X-Real-IP as a valid IP address before trusting it.
    // Only reachable when the peer is a trusted proxy.
    if let Some(xri) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let trimmed = xri.trim();
        if trimmed.parse::<std::net::IpAddr>().is_ok() {
            return trimmed.to_owned();
        }
        // Invalid IP in header — fall through to socket IP
    }

    socket_ip.to_string()
}

fn normalise_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    if let std::net::IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return std::net::IpAddr::V4(v4);
        }
    }
    ip
}

fn is_in_trusted(ip: std::net::IpAddr, ranges: &[ipnetwork::IpNetwork]) -> bool {
    ranges.iter().any(|net| net.contains(ip))
}

// ── Rate-limiting middleware ───────────────────────────────────────────────────

/// G.1: emergency in-process quota applied while Redis (the primary limiter)
/// is unreachable. Bounded fail-open: instead of unlimited pass-through, each
/// IP gets at most `EMERGENCY_LOCAL_LIMIT` requests per minute counted in
/// process memory. Conservative by design — well below the configured
/// ceiling in normal operation.
const EMERGENCY_LOCAL_LIMIT: u32 = 120;

#[derive(Default)]
struct LocalFallbackWindow {
    minute: u64,
    count: u32,
}

/// Per-IP, per-minute local fallback counter (single-process only).
static LOCAL_FALLBACK: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, LocalFallbackWindow>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

fn local_fallback_limit(configured: u32) -> u32 {
    configured.clamp(1, EMERGENCY_LOCAL_LIMIT)
}

/// Count `ip` against the local fallback window; true when still allowed.
fn local_fallback_allows(ip: &str, configured: u32, now_min: u64) -> bool {
    let limit = local_fallback_limit(configured);
    let mut map = LOCAL_FALLBACK.lock().unwrap_or_else(|e| e.into_inner());
    // Opportunistic cleanup: drop stale windows so the map cannot grow
    // without bound during a long Redis outage.
    map.retain(|_, w| w.minute == now_min);
    let window = map.entry(ip.to_string()).or_default();
    if window.minute != now_min {
        window.minute = now_min;
        window.count = 0;
    }
    if window.count >= limit {
        return false;
    }
    window.count += 1;
    true
}

/// Redis sliding-window rate limiter:max N requests per minute per IP.
/// Uses the `rl:{ip}:{minute}` key scheme (scoped under the `tracking:` keyPrefix).
async fn rate_limit_middleware(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let cfg = &state.config.rate_limit;

    let headers = req.headers();
    let socket_ip = addr.ip();
    let ip = extract_client_ip(headers, socket_ip, &state);

    let now_min = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 60)
        .unwrap_or(0);

    let window_key = format!("rl:{ip}:{now_min}");

    let result: anyhow::Result<u64> = async {
        let mut conn = state.redis.get().await?;
        // #183:Atomic INCR + EXPIRE via Lua script to prevent orphaned keys
        // if a crash occurs between the two commands.
        let script = r#"
            local count = redis.call('INCR', KEYS[1])
            if count == 1 then
                redis.call('EXPIRE', KEYS[1], ARGV[1])
            end
            return count
        "#;
        let count: u64 = redis::cmd("EVAL")
            .arg(script)
            .arg(1i32)
            .arg(&window_key)
            .arg(120u64)
            .query_async(&mut *conn)
            .await?;
        Ok(count)
    }
    .await;

    match result {
        Ok(count) if count > cfg.max_per_minute as u64 => rate_limited_response(&ip, count, req),
        Err(e) => {
            // G.1: bounded fail-open — Redis errors no longer mean unlimited
            // traffic; a conservative local per-IP quota still applies.
            tracing::error!(error = %e, "Rate limit Redis error — applying local emergency quota");
            if local_fallback_allows(&ip, cfg.max_per_minute, now_min) {
                next.run(req).await
            } else {
                warn!(ip = %ip, "Local emergency rate limit exceeded");
                rate_limited_response(
                    &ip,
                    u64::from(local_fallback_limit(cfg.max_per_minute)),
                    req,
                )
            }
        }
        _ => next.run(req).await,
    }
}

fn rate_limited_response(ip: &str, count: u64, req: Request) -> Response {
    warn!(ip = %ip, count = count, "Rate limit exceeded");
    let path = req.uri().path();
    if path.contains("/o/") || path.ends_with(".gif") {
        // Return a transparent GIF for pixel paths (-500-351)
        let len = TRANSPARENT_GIF.len().to_string();
        Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("content-type", "image/gif")
            .header("content-length", len)
            .header("retry-after", "60")
            .body(Body::from(TRANSPARENT_GIF))
            .unwrap_or_default()
    } else {
        Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("content-type", "application/json")
            .header("retry-after", "60")
            .body(Body::from(r#"{"error":"Rate limit exceeded"}"#))
            .unwrap_or_default()
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Shared helpers for route handler tests.
    //!
    //! Building an [`AppState`] needs no live services: the Postgres pool is
    //! lazy and the Redis pool points at a dead port unless a test opts into
    //! the live test server via the workspace `TEST_REDIS_URL` convention
    //! (soft-skip when unset or unreachable). Handlers tolerate Redis /
    //! Postgres errors, so offline unit tests are safe; tests that assert on
    //! WAL side effects must use [`live_redis_state`].

    use crate::bot::BotDetector;
    use crate::codec::TrackingCodec;
    use crate::config::{
        ClickHouseConfig, Config, DatabaseConfig, MetricsConfig, RateLimitConfig, RedisConfig,
        ServerConfig, TrackingConfig,
    };
    use crate::processor::EventProcessor;
    use crate::state::AppState;

    pub(crate) const TEST_SECRET: &str = "test-secret-key-32-bytes-minimum!!";

    /// Unique tenant discriminator: unique per process AND per call so tests
    /// never collide on shared Redis keys (domain cache, dedup, WAL search).
    pub(crate) fn unique_tenant(label: &str) -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        format!("tenant_{label}_{}_{n}", std::process::id())
    }

    pub(crate) fn test_config(trusted_proxies: &[&str]) -> Config {
        Config {
            server: ServerConfig {
                addr: "127.0.0.1:0".parse().expect("test addr"),
            },
            database: DatabaseConfig {
                url: "postgresql://offline:offline@127.0.0.1:1/offline".into(),
                max_connections: 1,
            },
            redis: RedisConfig {
                url: "redis://127.0.0.1:1".into(),
                key_prefix: "tracking:".into(),
                pool_size: 1,
            },
            clickhouse: ClickHouseConfig {
                url: "http://127.0.0.1:1".into(),
                database: "apexmail".into(),
                user: "default".into(),
                password: String::new(),
                insert_timeout_seconds: 1,
            },
            tracking: TrackingConfig {
                base_url: "https://track.test.example".into(),
                pixel_path: "/o".into(),
                click_path: "/c".into(),
                unsubscribe_path: "/u".into(),
                preferences_path: "/p".into(),
                fallback_url: "https://fallback.test.example/".into(),
                confirmation_url: "https://fallback.test.example/unsubscribed".into(),
                redirect_status: 302,
                trusted_proxies: trusted_proxies
                    .iter()
                    .filter_map(|s| s.parse().ok())
                    .collect(),
                max_redirect_url_len: 2048,
            },
            rate_limit: RateLimitConfig {
                enabled: false,
                max_per_minute: 1000,
            },
            metrics: MetricsConfig {
                enabled: false,
                port: 9092,
            },
            secret_key: zeroize::Zeroizing::new(TEST_SECRET.into()),
            jwt_public_key_pem: String::new(),
        }
    }

    fn state_with(trusted_proxies: &[&str], redis: deadpool_redis::Pool, db_url: &str) -> AppState {
        let cfg = test_config(trusted_proxies);
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect_lazy(db_url)
            .expect("lazy pg pool");
        let clickhouse = clickhouse::Client::default();
        let processor = std::sync::Arc::new(EventProcessor::new(
            db.clone(),
            redis.clone(),
            clickhouse,
            std::time::Duration::from_secs(1),
        ));
        AppState::new(
            TrackingCodec::new(TEST_SECRET),
            db,
            redis,
            processor,
            BotDetector::new(),
            cfg,
        )
    }

    fn dead_redis_pool() -> deadpool_redis::Pool {
        deadpool_redis::Config::from_url("redis://127.0.0.1:1")
            .builder()
            .expect("dead redis builder")
            .max_size(1)
            .runtime(deadpool_redis::Runtime::Tokio1)
            .build()
            .expect("dead redis pool")
    }

    /// State wired to a dead Redis port — for tests that never touch Redis.
    pub(crate) fn offline_state(trusted_proxies: &[&str]) -> AppState {
        state_with(
            trusted_proxies,
            dead_redis_pool(),
            "postgresql://offline:offline@127.0.0.1:1/offline",
        )
    }

    /// State wired to the live test Redis (`TEST_REDIS_URL`, workspace
    /// convention). Returns `None` (soft-skip) when unset or unreachable.
    #[allow(clippy::type_complexity)]
    pub(crate) async fn live_redis_state(
        trusted_proxies: &[&str],
    ) -> Option<(AppState, deadpool_redis::Pool)> {
        let url = std::env::var("TEST_REDIS_URL").ok()?;
        let pool = deadpool_redis::Config::from_url(&url)
            .builder()
            .ok()?
            .max_size(4)
            .runtime(deadpool_redis::Runtime::Tokio1)
            .build()
            .ok()?;
        let mut conn = pool.get().await.ok()?;
        redis::cmd("PING")
            .query_async::<String>(&mut *conn)
            .await
            .ok()?;
        let state = state_with(trusted_proxies, pool.clone(), &offline_db_url());
        Some((state, pool))
    }

    /// Placeholder DB url for states whose Postgres is never expected to
    /// answer (handlers must tolerate DB failures).
    pub(crate) fn offline_db_url() -> String {
        "postgresql://offline:offline@127.0.0.1:1/offline".into()
    }

    /// F38/F13:state wired to BOTH the live test Redis (`TEST_REDIS_URL`)
    /// and the live test Postgres (`TEST_DATABASE_URL`, api-server
    /// convention). The database must already carry the canonical schema
    /// (tenants, messages, suppressions, subscription_preferences,
    /// email_categories, webhooks, webhook_queue). Returns `None`
    /// (soft-skip) when either is unset or unreachable.
    #[allow(clippy::type_complexity)]
    pub(crate) async fn live_redis_pg_state(
        trusted_proxies: &[&str],
    ) -> Option<(AppState, deadpool_redis::Pool, sqlx::PgPool)> {
        let redis_url = std::env::var("TEST_REDIS_URL").ok()?;
        let db_url = std::env::var("TEST_DATABASE_URL").ok()?;

        let redis = deadpool_redis::Config::from_url(&redis_url)
            .builder()
            .ok()?
            .max_size(4)
            .runtime(deadpool_redis::Runtime::Tokio1)
            .build()
            .ok()?;
        let mut conn = redis.get().await.ok()?;
        redis::cmd("PING")
            .query_async::<String>(&mut *conn)
            .await
            .ok()?;

        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&db_url)
            .await
            .ok()?;

        let state = state_with(trusted_proxies, redis.clone(), &db_url);
        Some((state, redis, db))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test ip")
    }

    fn xff(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::HeaderName::from_static("x-forwarded-for"),
            value.parse().expect("header value"),
        );
        headers
    }

    /// A direct client (peer not a trusted proxy) must never have its
    /// client-supplied XFF honoured — otherwise the source IP is spoofable.
    #[tokio::test]
    async fn direct_client_with_spoofed_xff_uses_peer_ip() {
        let state = test_support::offline_state(&["10.0.0.0/8"]);
        let headers = xff("1.2.3.4, 198.51.100.9");

        assert_eq!(
            extract_client_ip(&headers, ip("203.0.113.5"), &state),
            "203.0.113.5"
        );
    }

    /// With NO trusted proxies configured there is no infrastructure that
    /// could have appended XFF/X-Real-IP — every forwarded header is
    /// client-supplied and must be ignored in favour of the socket peer.
    #[tokio::test]
    async fn no_trusted_proxies_configured_ignores_forwarded_headers_entirely() {
        let state = test_support::offline_state(&[]);
        let mut headers = xff("1.2.3.4");
        headers.insert(
            axum::http::HeaderName::from_static("x-real-ip"),
            "5.6.7.8".parse().expect("header value"),
        );

        assert_eq!(
            extract_client_ip(&headers, ip("203.0.113.5"), &state),
            "203.0.113.5"
        );
    }

    /// Via a trusted proxy chain, the real client is the rightmost XFF entry
    /// that is NOT a trusted proxy; leftmost (spoofable) entries are ignored.
    #[tokio::test]
    async fn trusted_proxy_xff_walk_yields_real_client_not_spoofed_leftmost() {
        let state = test_support::offline_state(&["10.0.0.0/8"]);
        // Chain: client 203.0.113.9 → proxy 10.0.0.9 → peer proxy 10.0.0.1.
        // The client pre-seeded a spoofed leftmost entry (6.6.6.6).
        let headers = xff("6.6.6.6, 203.0.113.9, 10.0.0.9");

        assert_eq!(
            extract_client_ip(&headers, ip("10.0.0.1"), &state),
            "203.0.113.9"
        );
    }

    /// When every XFF entry is a trusted proxy the walk falls through to a
    /// validated X-Real-IP (only reachable through a trusted peer) and then
    /// to the socket IP.
    #[tokio::test]
    async fn all_trusted_xff_falls_back_to_socket_ip() {
        let state = test_support::offline_state(&["10.0.0.0/8"]);
        let headers = xff("10.0.0.9, 10.0.0.8");

        assert_eq!(
            extract_client_ip(&headers, ip("10.0.0.1"), &state),
            "10.0.0.1"
        );
    }

    /// A malformed XFF entry terminates the right-to-left walk: everything
    /// left of it was written by the client, not by our proxies.
    #[tokio::test]
    async fn malformed_xff_entry_stops_the_walk() {
        let state = test_support::offline_state(&["10.0.0.0/8"]);
        let headers = xff("6.6.6.6, not-an-ip, 10.0.0.9");

        assert_eq!(
            extract_client_ip(&headers, ip("10.0.0.1"), &state),
            "10.0.0.1"
        );
    }

    /// G.1: the local fallback limit is the conservative emergency quota,
    /// clamped by (and never above) the configured Redis limit.
    #[test]
    fn local_fallback_limit_is_conservative() {
        assert_eq!(local_fallback_limit(1000), EMERGENCY_LOCAL_LIMIT);
        assert_eq!(local_fallback_limit(60), 60);
        assert_eq!(local_fallback_limit(0), 1, "never zero (fail-closed-ish)");
    }

    /// G.1: when Redis is down, an IP is still capped — the emergency quota
    /// bounds the fail-open window instead of allowing unlimited traffic.
    #[test]
    fn local_fallback_allows_only_up_to_the_emergency_quota() {
        LOCAL_FALLBACK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        const IP: &str = "198.51.100.7";
        let limit = local_fallback_limit(1000);
        for i in 0..limit {
            assert!(
                local_fallback_allows(IP, 1000, 4242),
                "request {} must be allowed",
                i + 1
            );
        }
        assert!(
            !local_fallback_allows(IP, 1000, 4242),
            "request beyond the emergency quota must be throttled"
        );
        // Other IPs are unaffected (per-IP windows).
        assert!(local_fallback_allows("198.51.100.8", 1000, 4242));
        // A new minute resets the window.
        assert!(local_fallback_allows(IP, 1000, 4243));
    }
}
