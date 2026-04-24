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
    http::{HeaderMap, HeaderValue, StatusCode},
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
    0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00,
    0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x21,
    0xf9, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01,
    0x00, 0x3b,
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
        .route(&format!("{pixel_path}/:tracking_id"), get(pixel::handle_pixel))
        .route("/o.gif", get(pixel::handle_pixel_gif))
// Click redirect
        .route(&format!("{click_path}/:tracking_id"), get(click::handle_click))
// One-click unsubscribe (RFC 8058)
        .route(&format!("{unsub_path}/:token"), post(unsubscribe::handle_unsub_post))
        .route(&format!("{unsub_path}/:token"), get(unsubscribe::handle_unsub_get))
// Preferences center
        .route(&format!("{prefs_path}/:token"), get(unsubscribe::handle_prefs_get))
        .route(&format!("{prefs_path}/:token"), post(unsubscribe::handle_prefs_post))
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
        app.layer(middleware::from_fn_with_state(
            state,
            rate_limit_middleware,
        ))
    } else {
        app
    }
}

// ── IP extraction ─────────────────────────────────────────────────────────────

/// Extract the real client IP, trusting `X-Forwarded-For` only when the
/// direct connecting address is a trusted proxy (CIDR match).
/// Algorithm:/// 1. Get socket IP from `ConnectInfo<SocketAddr>`.
/// 2. If the socket IP is NOT in any trusted-proxy CIDR → return it.
/// 3. If it IS trusted → walk `X-Forwarded-For` IPs left-to-right, return
/// the first IP that is NOT a trusted proxy itself.
/// 4. Fall back to `X-Real-IP`.
/// 5. Fall back to the socket IP.
pub fn extract_client_ip(headers: &HeaderMap, socket_ip: std::net::IpAddr, state: &AppState) -> String {
    let trusted = &state.config.tracking.trusted_proxies;

// Normalise IPv4-mapped IPv6 (::ffff:a.b.c.d → a.b.c.d)
    let socket_ip = normalise_ip(socket_ip);

    if !is_in_trusted(socket_ip, trusted) {
        return socket_ip.to_string();
    }

// Connecting address is a trusted proxy — read forwarded header.
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        for part in xff.split(',').map(str::trim) {
            if let Ok(ip) = part.parse::<std::net::IpAddr>() {
                let ip = normalise_ip(ip);
                if !is_in_trusted(ip, trusted) {
                    return ip.to_string();
                }
            }
        }
    }

// #188:Validate X-Real-IP as a valid IP address before trusting it
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
    }.await;

    match result {
        Ok(count) if count > cfg.max_per_minute as u64 => {
            warn!(ip = %ip, count = count, "Rate limit exceeded");
            let path = req.uri().path();
            let mut resp = if path.contains("/o/") || path.ends_with(".gif") {
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
            };
            resp.headers_mut().insert(
                "retry-after",
                HeaderValue::from_static("60"),
            );
            resp
        }
        Err(e) => {
            tracing::error!(error = %e, "Rate limit Redis error, allowing request");
            next.run(req).await
        }
        _ => next.run(req).await,
    }
}
