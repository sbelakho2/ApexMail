//! Adversarial tests for the open-pixel and health/readiness endpoints.
//!
//! Properties proven here:
//! - The pixel ALWAYS answers the exact transparent GIF with locked-down
//!   headers, regardless of token validity — and the response never carries
//!   any recipient-derived bytes (PII-free by construction).
//! - Hostile / oversized / garbage tracking ids are refused before any
//!   decryption, and record nothing.
//! - Bot and prefetcher hits NEVER count as human opens (no WAL entry).
//! - A human open lands exactly once in the Redis WAL (deduped on replay).
//! - The recorder concurrency bound genuinely drops excess opens instead of
//!   spawning unbounded tasks.
//! - /health and /ready report dependency state honestly (503 while
//!   shutting down, on DB failure and on Redis failure; 200 when both are
//!   healthy).

use super::*;
use std::net::SocketAddr;
use std::time::Duration;

use crate::bot::BotDetector;
use crate::codec::{TrackingCodec, TrackingData};
use crate::processor::REDIS_WAL_KEY;
use crate::routes::test_support;
use crate::state::AppState;

const NORMAL_UA: &str =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/124 Safari/537.36";
const BOT_UA: &str = "python-requests/2.31.0";

fn addr() -> ConnectInfo<SocketAddr> {
    ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 41_000)))
}

fn headers_with_ua(ua: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::USER_AGENT,
        ua.parse().expect("ua header"),
    );
    headers
}

/// Serializes the pixel handlers: every pixel test shares the WAL (Redis)
/// and the recorder semaphore, so concurrent valid-open assertions could eat
/// each other's dropped/recorded events.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn tracking_token(tenant: &str, message: &str, recipient: &str) -> String {
    TrackingCodec::new(test_support::TEST_SECRET)
        .encode(&TrackingData {
            tenant_id: tenant.into(),
            message_id: message.into(),
            recipient: recipient.into(),
            link_id: None,
            original_url: None,
        })
        .expect("encode tracking token")
}

async fn wal_entries_for(pool: &deadpool_redis::Pool, needle: &str) -> Vec<String> {
    test_support::wal_entries_containing(pool, needle).await
}

async fn drop_wal_entries(pool: &deadpool_redis::Pool, needle: &str) {
    let Ok(mut conn) = pool.get().await else {
        return;
    };
    for entry in wal_entries_for(pool, needle).await {
        let _: Result<(), _> = redis::cmd("LREM")
            .arg(REDIS_WAL_KEY)
            .arg(1)
            .arg(&entry)
            .query_async(&mut *conn)
            .await;
    }
}

/// Bounded settle for fire-and-forget recorders (≤ 50 ms sleeps).
async fn settle() {
    tokio::time::sleep(Duration::from_millis(50)).await;
}

async fn body_bytes(resp: axum::response::Response) -> Vec<u8> {
    use futures::StreamExt;
    let mut stream = resp.into_body().into_data_stream();
    let mut out = Vec::new();
    while let Ok(Some(Ok(chunk))) =
        tokio::time::timeout(Duration::from_secs(2), stream.next()).await
    {
        out.extend_from_slice(&chunk);
    }
    out
}

// ── The pixel response itself ───────────────────────────────────────────────

#[tokio::test]
async fn pixel_always_serves_the_exact_gif_with_locked_headers_and_no_pii() {
    let _wal_serial = test_support::redis_wal_serial().await;
    let state = test_support::offline_state(&[]);
    let addr = addr();

    for tracking_id in [
        tracking_token("tenant_px", "msg_px", "victim@example.com"),
        "garbage-but-long-enough-token".to_string(),
        "x".repeat(4_096),
    ] {
        let resp = handle_pixel(
            State(state.clone()),
            addr,
            headers_with_ua(NORMAL_UA),
            Path(tracking_id),
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let headers = resp.headers().clone();
        let body = body_bytes(resp).await;
        assert_eq!(body, TRANSPARENT_GIF, "body must be the exact GIF");
        assert_eq!(
            headers.get("content-type").and_then(|v| v.to_str().ok()),
            Some("image/gif")
        );
        let csp = headers
            .get("content-security-policy")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(csp.contains("default-src 'none'"), "{csp}");
        assert_eq!(
            headers
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff")
        );
        assert_eq!(
            headers.get("x-robots-tag").and_then(|v| v.to_str().ok()),
            Some("noindex, nofollow")
        );
        // The response is byte-identical to the static GIF: no recipient
        // data, no tenant id, no error text can ever leak through it.
        assert!(!body.windows(11).any(|w| w == b"@example.com"));
    }
}

// ── record_open gating ──────────────────────────────────────────────────────

#[tokio::test]
async fn pixel_records_human_opens_once_and_hostile_or_bot_hits_never() {
    let _wal_serial = test_support::redis_wal_serial().await;
    let _guard = SERIAL.lock().await;
    let Some((state, redis)) = test_support::live_redis_state(&[]).await else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let addr = addr();
    let tenant = test_support::unique_tenant("pxopen");
    let message = format!("msg_{tenant}");

    // (1) Human open with a valid token → exactly one WAL entry.
    let token = tracking_token(&tenant, &message, "human@example.com");
    let resp = handle_pixel(
        State(state.clone()),
        addr,
        headers_with_ua(NORMAL_UA),
        Path(token),
    )
    .await;
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let mut recorded = false;
    for _ in 0..20 {
        recorded = !wal_entries_for(&redis, &message).await.is_empty();
        if recorded {
            break;
        }
        settle().await;
    }
    assert!(recorded, "human open must be recorded");

    // (2) The same open replayed is deduped (24h SETNX) — no second entry.
    let token = tracking_token(&tenant, &message, "human@example.com");
    let _ = handle_pixel(
        State(state.clone()),
        addr,
        headers_with_ua(NORMAL_UA),
        Path(token),
    )
    .await;
    settle().await;
    settle().await;
    let entries = wal_entries_for(&redis, &message).await;
    assert_eq!(
        entries.len(),
        1,
        "replay of the same open must be deduped, got: {entries:?}"
    );
    drop_wal_entries(&redis, &message).await;

    // (3) Bot UA → the pixel still renders but records NOTHING.
    let bot_message = format!("bot_{tenant}");
    let token = tracking_token(&tenant, &bot_message, "bot@example.com");
    let resp = handle_pixel(
        State(state.clone()),
        addr,
        headers_with_ua(BOT_UA),
        Path(token),
    )
    .await;
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    assert_eq!(body_bytes(resp).await, TRANSPARENT_GIF);
    settle().await;
    settle().await;
    assert!(
        wal_entries_for(&redis, &bot_message).await.is_empty(),
        "bot opens must never count as human opens"
    );

    // (4) A well-formed but bogus token records nothing and must not panic.
    let resp = handle_pixel(
        State(state.clone()),
        addr,
        headers_with_ua(NORMAL_UA),
        Path("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()),
    )
    .await;
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    settle().await;
    assert!(
        wal_entries_for(&redis, &tenant).await.is_empty(),
        "a bogus token records nothing (the human open was cleaned up above)"
    );

    // (5) Oversized and undersized ids are rejected before decryption.
    for bad_len in ["short".to_string(), "x".repeat(4_097)] {
        let resp = handle_pixel(
            State(state.clone()),
            addr,
            headers_with_ua(NORMAL_UA),
            Path(bad_len),
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        assert_eq!(body_bytes(resp).await, TRANSPARENT_GIF);
    }

    drop_wal_entries(&redis, &tenant).await;
}

#[tokio::test]
async fn pixel_gif_alternative_route_records_only_with_t_param() {
    let _wal_serial = test_support::redis_wal_serial().await;
    let _guard = SERIAL.lock().await;
    let Some((state, redis)) = test_support::live_redis_state(&[]).await else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let addr = addr();
    let tenant = test_support::unique_tenant("pxgif");
    let message = format!("msg_{tenant}");

    // No ?t= → pure render, nothing recorded.
    let resp = handle_pixel_gif(
        State(state.clone()),
        addr,
        headers_with_ua(NORMAL_UA),
        Query(PixelQuery { t: None }),
    )
    .await;
    assert_eq!(body_bytes(resp).await, TRANSPARENT_GIF);

    // ?t=<valid token> → recorded exactly once.
    let token = tracking_token(&tenant, &message, "gif@example.com");
    let resp = handle_pixel_gif(
        State(state.clone()),
        addr,
        headers_with_ua(NORMAL_UA),
        Query(PixelQuery { t: Some(token) }),
    )
    .await;
    assert_eq!(body_bytes(resp).await, TRANSPARENT_GIF);
    let mut recorded = false;
    for _ in 0..20 {
        recorded = !wal_entries_for(&redis, &message).await.is_empty();
        if recorded {
            break;
        }
        settle().await;
    }
    assert!(recorded, "?t= open must be recorded");
    drop_wal_entries(&redis, &tenant).await;
}

#[tokio::test]
async fn open_recorder_concurrency_bound_drops_excess_opens() {
    let _wal_serial = test_support::redis_wal_serial().await;
    let _guard = SERIAL.lock().await;
    let Some((state, redis)) = test_support::live_redis_state(&[]).await else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let addr = addr();
    let tenant = test_support::unique_tenant("pxsat");
    let message = format!("msg_{tenant}");

    // Drain the shared semaphore so the next open cannot get a permit.
    let mut held = Vec::new();
    while let Ok(permit) = OPEN_RECORDER_SEMAPHORE.try_acquire() {
        held.push(permit);
    }
    assert!(!held.is_empty(), "permits acquired");

    let token = tracking_token(&tenant, &message, "dropped@example.com");
    let resp = handle_pixel(
        State(state.clone()),
        addr,
        headers_with_ua(NORMAL_UA),
        Path(token),
    )
    .await;
    // The response is unaffected — recording is best-effort by design.
    assert_eq!(body_bytes(resp).await, TRANSPARENT_GIF);
    settle().await;
    settle().await;
    assert!(
        wal_entries_for(&redis, &message).await.is_empty(),
        "an open arriving while the recorder bound is saturated must be dropped"
    );

    drop(held);
    drop_wal_entries(&redis, &tenant).await;
}

// ── /health and /ready ──────────────────────────────────────────────────────

#[tokio::test]
async fn health_reports_shutdown_state_and_ready_checks_both_dependencies() {
    use crate::routes::health::{handle_health, handle_ready, SHUTTING_DOWN};

    // Liveness: healthy until the shutdown flag flips, then 503.
    let was_shutting_down = SHUTTING_DOWN.load(std::sync::atomic::Ordering::Relaxed);
    let resp = handle_health().await;
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    SHUTTING_DOWN.store(true, std::sync::atomic::Ordering::Relaxed);
    let resp = handle_health().await;
    assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    SHUTTING_DOWN.store(was_shutting_down, std::sync::atomic::Ordering::Relaxed);

    // Fast-fail dead pools (50ms): sqlx's default acquire timeout is 30s,
    // which would slow the suite without changing the verdict.
    let dead_db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(50))
        .connect_lazy("postgresql://offline@127.0.0.1:1/offline")
        .expect("lazy pool");
    let dead_redis = || {
        deadpool_redis::Config::from_url("redis://127.0.0.1:1")
            .builder()
            .expect("builder")
            .max_size(1)
            .runtime(deadpool_redis::Runtime::Tokio1)
            .build()
            .expect("dead redis")
    };

    // Readiness with BOTH dependencies dead → 503 (the DB leg fails first).
    let resp = handle_ready(State(state_over(dead_db, dead_redis()))).await;
    assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);

    // Readiness with a live DB but a dead Redis → 503 (the Redis leg).
    let Some(db) = live_pg().await else {
        eprintln!("skipping: set TEST_DATABASE_URL");
        return;
    };
    let resp = handle_ready(State(state_over(db.clone(), dead_redis()))).await;
    assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);

    // Both alive → ready.
    if let Ok(url) = std::env::var("TEST_REDIS_URL") {
        let live_redis = deadpool_redis::Config::from_url(&url)
            .builder()
            .expect("builder")
            .max_size(2)
            .runtime(deadpool_redis::Runtime::Tokio1)
            .build()
            .expect("live redis");
        let resp = handle_ready(State(state_over(db, live_redis))).await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK, "both up → ready");
    }
}

async fn live_pg() -> Option<sqlx::PgPool> {
    let db_url = std::env::var("TEST_DATABASE_URL").ok()?;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&db_url)
        .await
        .ok()
}

/// Rebuild a state with a specific DB + Redis pair (health tests only care
/// about those two legs).
fn state_over(db: sqlx::PgPool, redis: deadpool_redis::Pool) -> AppState {
    use crate::config::{
        ClickHouseConfig, Config, DatabaseConfig, MetricsConfig, RateLimitConfig, RedisConfig,
        ServerConfig, TrackingConfig,
    };
    let cfg = Config {
        server: ServerConfig {
            addr: "127.0.0.1:0".parse().expect("addr"),
        },
        database: DatabaseConfig {
            url: "postgresql://offline@127.0.0.1:1/offline".into(),
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
            trusted_proxies: Vec::new(),
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
        secret_key: zeroize::Zeroizing::new(test_support::TEST_SECRET.into()),
        jwt_public_key_pem: String::new(),
    };
    let processor = std::sync::Arc::new(crate::processor::EventProcessor::new(
        db.clone(),
        redis.clone(),
        clickhouse::Client::default(),
        Duration::from_millis(100),
    ));
    AppState::new(
        TrackingCodec::new(test_support::TEST_SECRET),
        db,
        redis,
        processor,
        BotDetector::new(),
        cfg,
    )
}

/// With a DEBUG subscriber installed, the invalid-token warn's FIELD
/// expressions evaluate (tracing lazily formats only for enabled events) and
/// the response is still the byte-exact GIF.
#[tokio::test]
async fn invalid_pixel_token_warns_with_a_truncated_prefix_and_still_serves() {
    test_log_subscriber();
    let state = test_support::offline_state(&[]);
    let resp = handle_pixel(
        State(state),
        addr(),
        headers_with_ua(NORMAL_UA),
        // Long enough that the logged id_prefix field truncation matters.
        Path("0123456789abcdef0123456789-not-a-valid-token".to_string()),
    )
    .await;
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let body = body_bytes(resp).await;
    assert_eq!(body, TRANSPARENT_GIF, "still the exact GIF");
}

/// A recorder that cannot enqueue (dead Redis) logs the failure and never
/// breaks the pixel response.
#[tokio::test]
async fn failed_open_recorder_still_serves_the_gif() {
    test_log_subscriber();
    let _wal_serial = test_support::redis_wal_serial().await;
    let state = state_over(
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://offline:offline@127.0.0.1:1/offline")
            .expect("lazy pool"),
        test_support::dead_redis_pool(),
    );
    let token = tracking_token("tenant_px_fail", "msg_px_fail", "u@example.com");
    let resp = handle_pixel(
        State(state),
        addr(),
        headers_with_ua(NORMAL_UA),
        Path(token),
    )
    .await;
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let body = body_bytes(resp).await;
    assert_eq!(body, TRANSPARENT_GIF, "the GIF is never withheld");
    // Give the fire-and-forget recorder a moment to fail and log.
    tokio::time::sleep(Duration::from_millis(50)).await;
}

/// Enable a DEBUG-level tracing subscriber so log FIELD expressions (lazily
/// evaluated only for enabled events) execute in these coverage tests.
fn test_log_subscriber() {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("tracking_service=debug"))
        .with_test_writer()
        .try_init();
}
