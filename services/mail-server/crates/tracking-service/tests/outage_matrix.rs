//! Outage matrix for the tracking service (audit item 10: network partitions).
//!
//! Dependency × failure-mode × expected HONEST outcome, driven end-to-end
//! through the real router (`build_router`) and the real `EventProcessor`:
//!
//! │ dependency │ surface                      │ expected honest outcome                 │
//! │------------|------------------------------|-----------------------------------------│
//! │ PG down    │ GET /u/:token (confirm)      │ 200 HTML confirmation form (no DB path) │
//! │ PG down    │ POST /u/:token (one-click)   │ 500 JSON (MUA surface) + retry queued   │
//! │ PG down    │ POST /u/:token/confirm       │ branded HTML error page + retry queued  │
//! │ PG down    │ GET/POST /p/:token           │ branded HTML error pages, never JSON    │
//! │ PG down    │ /health, /ready              │ liveness 200, readiness 503 "not ready" │
//! │ Redis down │ GET /u/:token, GET /p/:token │ unaffected (Postgres-backed)            │
//! │ Redis down │ POST /u/:token, /…/confirm   │ 200 + suppression PERSISTED in Postgres │
//! │            │                              │ (dedup fails OPEN; analytics lost only) │
//! │ Redis down │ /c/:token                    │ 302 via the Postgres authority, bounded │
//! │ Redis down │ /o/:token, /health, /ready   │ GIF 200; liveness 200; readiness 503    │
//! │ ClickHouse │ flush loop                   │ Postgres receives every event; the loop │
//! │ down       │                              │ never wedges; nothing is re-enqueued    │
//!
//! Plus the restart-under-load cells (matrix 4): stop / close-pools
//! mid-processing → no lost events (WAL retained or re-enqueued) and no
//! double-recorded ones (idempotent `ON CONFLICT (id) DO NOTHING` flush).
//!
//! Every HTTP interaction is wrapped in a bounded `tokio::time::timeout` so a
//! regression to an unbounded hang FAILS FAST (naming the matrix cell)
//! instead of stalling nextest toward the 1800 s slow timeout.
//!
//! Soft-skip contract (workspace convention): without TEST_DATABASE_URL or
//! TEST_REDIS_URL the suite skips; a configured-but-broken server panics via
//! the migrator. The raw WAL / suppression-retry keys live in logical Redis
//! DB 9, and every test that runs or observes a flush loop holds the same
//! cross-process Postgres advisory lock as the lib tests
//! (`tracking-service:redis-wal`) so parallel nextest processes can never
//! drain each other's queues.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tracking_service::bot::BotDetector;
use tracking_service::codec::{TrackingCodec, TrackingData};
use tracking_service::config::{
    ClickHouseConfig, Config, DatabaseConfig, MetricsConfig, RateLimitConfig, RedisConfig,
    ServerConfig, TrackingConfig,
};
use tracking_service::processor::{EventProcessor, OpenData};
use tracking_service::routes::{build_router, TRANSPARENT_GIF};
use tracking_service::state::AppState;

const SECRET: &str = "outage-matrix-tracking-secret-32-bytes";
const NORMAL_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36";
const REDIS_TEST_DB: u32 = 9;
const BOUNDED: Duration = Duration::from_secs(15);
const WAL_KEY: &str = "apexmail:events:pending";
const SUPPRESSION_RETRY_KEY: &str = "apexmail:suppressions:pending";

// ── Harness ──────────────────────────────────────────────────────────────────

fn codec() -> TrackingCodec {
    TrackingCodec::new(SECRET)
}

fn unique(label: &str) -> String {
    let hex = uuid::Uuid::new_v4().simple().to_string();
    format!("{label}{}", &hex[..10])
}

fn dead_pg() -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        // Deterministic + fast: a dead pool must surface its error in
        // milliseconds, not in the 10 s production acquire timeout.
        .acquire_timeout(Duration::from_millis(250))
        .connect_lazy("postgresql://offline:offline@127.0.0.1:1/offline")
        .expect("lazy dead pool")
}

fn dead_redis() -> deadpool_redis::Pool {
    deadpool_redis::Config::from_url("redis://127.0.0.1:1")
        .builder()
        .expect("builder")
        .max_size(1)
        .runtime(deadpool_redis::Runtime::Tokio1)
        .build()
        .expect("dead redis pool")
}

/// The suite's dedicated logical Redis database (raw WAL / suppression-retry
/// keys are not key-prefixed: lib tests use DB 8, adversarial_routes uses 7,
/// this outage matrix uses 9).
async fn live_redis() -> Option<deadpool_redis::Pool> {
    let base = std::env::var("TEST_REDIS_URL").ok()?;
    let url = match url::Url::parse(&base) {
        Ok(mut parsed) => {
            parsed.set_path(&REDIS_TEST_DB.to_string());
            parsed.to_string()
        }
        Err(_) => format!("{}/{}", base.trim_end_matches('/'), REDIS_TEST_DB),
    };
    let pool = deadpool_redis::Config::from_url(&url)
        .builder()
        .ok()?
        .max_size(4)
        .runtime(deadpool_redis::Runtime::Tokio1)
        .build()
        .ok()?;
    // Reachability probe: every cell in this file drives or observes the
    // WAL/queue, so an unreachable configured server is a skip, not noise.
    pool.get().await.ok()?;
    Some(pool)
}

fn live_redis_url(base: &str) -> String {
    match url::Url::parse(base) {
        Ok(mut parsed) => {
            parsed.set_path(&REDIS_TEST_DB.to_string());
            parsed.to_string()
        }
        Err(_) => format!("{}/{}", base.trim_end_matches('/'), REDIS_TEST_DB),
    }
}

fn config(redis_url: &str, ch_url: &str) -> Config {
    Config {
        server: ServerConfig {
            addr: "127.0.0.1:0".parse().expect("addr"),
        },
        database: DatabaseConfig {
            url: "postgresql://offline:offline@127.0.0.1:1/offline".into(),
            max_connections: 2,
        },
        redis: RedisConfig {
            url: redis_url.to_string(),
            key_prefix: "tracking:".into(),
            pool_size: 4,
        },
        clickhouse: ClickHouseConfig {
            url: ch_url.to_string(),
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
            token_max_age_days: None,
        },
        rate_limit: RateLimitConfig {
            enabled: false,
            max_per_minute: 1000,
        },
        metrics: MetricsConfig {
            enabled: false,
            port: 9092,
        },
        secret_key: zeroize::Zeroizing::new(SECRET.into()),
        jwt_public_key_pem: String::new(),
    }
}

fn state_over(db: sqlx::PgPool, redis: deadpool_redis::Pool, cfg: Config) -> AppState {
    let processor = Arc::new(EventProcessor::new(
        db.clone(),
        redis.clone(),
        clickhouse::Client::default(),
        Duration::from_secs(1),
    ));
    AppState::new(codec(), db, redis, processor, BotDetector::new(), cfg)
}

async fn server(state: &AppState) -> axum_test::TestServer {
    axum_test::TestServer::new(
        build_router(state.clone()).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .expect("test server")
}

async fn canonical_pool(name: &str) -> Option<sqlx::PgPool> {
    match migrator::test_support::fresh_canonical_pool(name, name).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

async fn seed_tenant(db: &sqlx::PgPool, tenant: &str) {
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status) VALUES ($1, $1, $1, 'free', 'active')
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(tenant)
    .execute(db)
    .await
    .expect("seed tenant");
}

async fn seed_category(db: &sqlx::PgPool, tenant: &str, name: &str) {
    sqlx::query(
        "INSERT INTO email_categories (tenant_id, name, description, active, display_order)
         VALUES ($1, $2, $3, true, 0)",
    )
    .bind(tenant)
    .bind(name)
    .bind("Outage matrix category")
    .execute(db)
    .await
    .expect("seed email category");
}

async fn seed_redirect_wildcard(db: &sqlx::PgPool, tenant: &str, patterns: &[&str]) {
    let json = serde_json::json!(patterns).to_string();
    sqlx::query(
        "INSERT INTO tenant_settings (tenant_id, allowed_redirect_domains) \
         VALUES ($1, $2::jsonb) \
         ON CONFLICT (tenant_id) DO UPDATE SET allowed_redirect_domains = $2::jsonb",
    )
    .bind(tenant)
    .bind(json)
    .execute(db)
    .await
    .expect("seed redirect wildcard patterns");
}

fn unsub_token(tenant: &str, recipient: &str) -> String {
    codec()
        .generate_unsubscribe_token(tenant, recipient)
        .expect("unsub token")
}

fn prefs_token(tenant: &str, recipient: &str) -> String {
    codec()
        .generate_preferences_token(tenant, recipient)
        .expect("prefs token")
}

fn click_token(tenant: &str, message: &str, recipient: &str, original_url: &str) -> String {
    codec()
        .encode(&TrackingData {
            tenant_id: tenant.into(),
            message_id: message.into(),
            recipient: recipient.into(),
            link_id: Some(format!("lnk_{}", &message[..message.len().min(8)])),
            original_url: Some(original_url.into()),
        })
        .expect("click token")
}

/// Every HTTP interaction in this suite goes through this bound: a regression
/// to an unbounded hang panics HERE (naming the matrix cell) instead of
/// stalling nextest toward the 1800 s slow timeout. Accepts futures AND
/// axum-test request builders (`IntoFuture`).
async fn bounded<T, F: std::future::IntoFuture<Output = T>>(cell: &str, fut: F) -> T {
    match tokio::time::timeout(BOUNDED, fut.into_future()).await {
        Ok(value) => value,
        Err(_) => panic!(
            "outage-matrix cell `{cell}` exceeded the {BOUNDED:?} bound — unbounded hang"
        ),
    }
}

// ── Redis side effects (raw keys, logical DB 9) ─────────────────────────────

async fn redis_list(pool: &deadpool_redis::Pool, key: &str) -> Vec<String> {
    let Ok(mut conn) = pool.get().await else {
        return Vec::new();
    };
    redis::cmd("LRANGE")
        .arg(key)
        .arg(0)
        .arg(-1)
        .query_async::<Vec<String>>(&mut *conn)
        .await
        .unwrap_or_default()
}

async fn suppression_retries(pool: &deadpool_redis::Pool, needle: &str) -> Vec<String> {
    redis_list(pool, SUPPRESSION_RETRY_KEY)
        .await
        .into_iter()
        .filter(|entry| entry.contains(needle))
        .collect()
}

async fn lrem(pool: &deadpool_redis::Pool, key: &str, needle: &str) {
    let Ok(mut conn) = pool.get().await else {
        return;
    };
    for entry in redis_list(pool, key)
        .await
        .into_iter()
        .filter(|e| e.contains(needle))
    {
        let _: Result<i64, _> = redis::cmd("LREM")
            .arg(key)
            .arg(1)
            .arg(&entry)
            .query_async(&mut *conn)
            .await;
    }
}

/// Cross-process serialization for the whole logical Redis DB 9 (the WAL and
/// the suppression-retry queue are single global lists — a flush loop in a
/// parallel test process would drain another test's entries). Same shape as
/// the lib tests' `redis_wal_serial`: a session-level Postgres advisory lock
/// on the admin server, released when the pool drops.
async fn wal_serial() -> Option<sqlx::PgPool> {
    let url = std::env::var("TEST_DATABASE_ADMIN_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("TEST_DATABASE_URL")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .and_then(|value| {
                    value
                        .rsplit_once('/')
                        .map(|(server, _)| format!("{server}/postgres"))
                })
        })?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(30))
        .connect(&url)
        .await
        .ok()?;
    sqlx::query("SELECT pg_advisory_lock(hashtext($1))")
        .bind("tracking-service:redis-wal")
        .execute(&pool)
        .await
        .ok()?;
    Some(pool)
}

async fn events_count(db: &sqlx::PgPool, message: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM events WHERE message_id LIKE $1 || '%'",
    )
    .bind(message)
    .fetch_one(db)
    .await
    .expect("count events")
}

async fn suppression_exists(db: &sqlx::PgPool, tenant: &str, email: &str) -> bool {
    sqlx::query_as::<_, (String,)>(
        "SELECT email FROM suppressions WHERE tenant_id = $1 AND email = $2 LIMIT 1",
    )
    .bind(tenant)
    .bind(email)
    .fetch_optional(db)
    .await
    .expect("suppression lookup")
    .is_some()
}

async fn wal_has(pool: &deadpool_redis::Pool, needle: &str) -> bool {
    !redis_list(pool, WAL_KEY)
        .await
        .into_iter()
        .filter(|e| e.contains(needle))
        .collect::<Vec<_>>()
        .is_empty()
}

/// Bounded poll: awaits `predicate` until true or `attempts` × 100 ms elapse.
async fn poll_until(
    cell: &str,
    attempts: usize,
    mut predicate: impl AsyncFnMut() -> bool,
) {
    for _ in 0..attempts {
        if predicate().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("outage-matrix cell `{cell}`: condition not met within the poll bound");
}

// ═════════════════════════════════════════════════════════════════════════════
// Matrix 1a — Postgres DOWN (Redis live): subscription surfaces + health
// ═════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn pg_down_subscription_surfaces_are_honest_bounded_and_queue_the_suppression() {
    let _serial = wal_serial().await;
    let Some(db) = canonical_pool("outage_pg_down").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run the outage matrix");
        return;
    };
    let Some(redis) = live_redis().await else {
        eprintln!("skipping: set TEST_REDIS_URL to run the outage matrix");
        return;
    };
    let redis_url = live_redis_url(&std::env::var("TEST_REDIS_URL").expect("checked"));

    let tenant = unique("tnpgdown");
    seed_tenant(&db, &tenant).await;
    let recipient = "pgdown@example.com";

    let state = state_over(
        dead_pg(),
        redis.clone(),
        config(&redis_url, "http://127.0.0.1:1"),
    );
    let srv = server(&state).await;
    let token = unsub_token(&tenant, recipient);
    let prefs = prefs_token(&tenant, recipient);

    // GET /u/:token — pure render (no DB on the path): the recipient still
    // gets the branded confirmation form.
    let response = bounded("pg_down GET /u", srv.get(&format!("/u/{token}"))).await;
    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(body.contains("Confirm Unsubscribe"), "{body}");
    assert!(
        body.contains(&format!(r#"<form method="POST" action="/u/{token}/confirm">"#)),
        "the confirm form must still POST to /confirm: {body}"
    );

    // POST /u/:token/confirm — the browser surface: a branded HTML error
    // page, NEVER a raw JSON blob or stack trace.
    let response = bounded(
        "pg_down POST /u/:token/confirm",
        srv.post(&format!("/u/{token}/confirm"))
            .form(&[("confirm", "true")]),
    )
    .await;
    assert_eq!(response.status_code().as_u16(), 200);
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        content_type.starts_with("text/html"),
        "browser confirm failure must render HTML, got {content_type}"
    );
    let body = response.text();
    assert!(
        body.contains("Something went wrong"),
        "honest failure copy expected: {body}"
    );
    // THE COMPLIANCE MACHINERY: the failed suppression write must have been
    // queued for retry (F2 durable-or-failed), provable from the outage.
    let retries = suppression_retries(&redis, &tenant).await;
    assert!(
        retries.iter().any(|e| e.contains(recipient)),
        "a failed suppression write must enqueue a pending retry, got: {retries:?}"
    );

    // POST /u/:token — the RFC 8058 MUA surface keeps its JSON contract: an
    // honest 5xx so the MUA retries, plus the queued retry row.
    let response = bounded(
        "pg_down POST /u",
        srv.post(&format!("/u/{token}"))
            .text("List-Unsubscribe=One-Click"),
    )
    .await;
    assert_eq!(response.status_code().as_u16(), 500);
    let body = response.text();
    assert!(
        body.contains(r#""error""#),
        "the MUA surface stays JSON (never an HTML page or stack trace): {body}"
    );
    let retries = suppression_retries(&redis, &tenant).await;
    assert!(
        retries.iter().any(|e| e.contains(recipient)),
        "the one-click failure must also enqueue the retry"
    );

    // GET /p/:token — the preferences center degrades to the branded error
    // page ("unknown, please retry"), never a fabricated empty form.
    let response = bounded("pg_down GET /p", srv.get(&format!("/p/{prefs}"))).await;
    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(
        body.contains("Unable to load preferences. Please try again."),
        "honest unavailable copy expected: {body}"
    );
    assert!(
        !body.contains(r#""error""#),
        "a browser surface must never receive raw JSON: {body}"
    );

    // POST /p/:token (unsubscribe all) — HTML 500, the status is preserved.
    let response = bounded(
        "pg_down POST /p",
        srv.post(&format!("/p/{prefs}"))
            .form(&[("unsubscribe_all", "true")]),
    )
    .await;
    assert_eq!(response.status_code().as_u16(), 500);
    let body = response.text();
    assert!(
        body.contains("Failed to save your unsubscribe preference. Please try again."),
        "{body}"
    );

    // /health stays 200 (liveness: the PROCESS is alive — documented
    // contract), /ready flips to 503 "not ready" (honest dependency report).
    let response = bounded("pg_down /health", srv.get("/health")).await;
    assert_eq!(response.status_code().as_u16(), 200);
    let response = bounded("pg_down /ready", srv.get("/ready")).await;
    assert_eq!(response.status_code().as_u16(), 503);
    assert!(response.text().contains("not ready"));

    // ── The pending-retry machinery must FIRE from this outage: a live
    // processor (same Redis, live Postgres) drains the queued suppression.
    let drainer = Arc::new(EventProcessor::with_config(
        db.clone(),
        redis.clone(),
        clickhouse::Client::default(),
        Duration::from_secs(1),
        25,
        100,
    ));
    Arc::clone(&drainer).start();
    poll_until("suppression retry drained", 150, || async {
        suppression_exists(&db, &tenant, recipient).await
    })
    .await;
    drainer.stop().await;
    assert!(
        suppression_exists(&db, &tenant, recipient).await,
        "the pending retry must land the suppression row in Postgres"
    );

    // Cleanup: raw keys + the per-test database (cascade removes the row).
    lrem(&redis, SUPPRESSION_RETRY_KEY, &tenant).await;
    lrem(&redis, WAL_KEY, &tenant).await;
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(&tenant)
        .execute(&db)
        .await
        .expect("cleanup tenant");
}

// ═════════════════════════════════════════════════════════════════════════════
// Matrix 1b — Redis DOWN (Postgres live): recipient surfaces
// ═════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn redis_down_recipient_surfaces_stay_bounded_honest_and_durable() {
    let Some(db) = canonical_pool("outage_redis_down").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run the outage matrix");
        return;
    };
    let cfg = config("redis://127.0.0.1:1", "http://127.0.0.1:1");

    let tenant = unique("tnredisdown");
    seed_tenant(&db, &tenant).await;
    seed_category(&db, &tenant, "outage-matrix-news").await;
    seed_redirect_wildcard(&db, &tenant, &["allowed.example.test"]).await;

    let state = state_over(db.clone(), dead_redis(), cfg);
    let srv = server(&state).await;

    // ── THE CLICK PATH (highest-traffic edge). A recipient must NEVER hang:
    // with Redis down the authorization falls through to the Postgres
    // authority and the redirect still happens.
    let message = unique("msgclick");
    let landing = "https://allowed.example.test/landing";
    let token = click_token(&tenant, &message, "clicker@example.com", landing);
    let response = bounded("redis_down GET /c", srv.get(&format!("/c/{token}"))).await;
    assert_eq!(response.status_code().as_u16(), 302);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert_eq!(location, landing, "the recipient must reach the target");

    // An UNAUTHORIZED domain with no cached verdict: the Postgres authority
    // answers "absence" → the safe fallback redirect. Bounded, never a hang.
    let evil = "https://evil.example.test/phish";
    let evil_token = click_token(&tenant, &unique("msgevil"), "clicker@example.com", evil);
    let response = bounded(
        "redis_down GET /c (unauthorized)",
        srv.get(&format!("/c/{evil_token}")),
    )
    .await;
    assert_eq!(response.status_code().as_u16(), 302);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert_eq!(
        location, "https://fallback.test.example/",
        "unauthorized domains redirect to the safe fallback"
    );

    // The one-click POST: the dedup check fails OPEN, the suppression write
    // succeeds in Postgres, only the analytics event is unrecordable.
    let recipient = "redisdown@example.com";
    let token = unsub_token(&tenant, recipient);
    let response = bounded(
        "redis_down POST /u",
        srv.post(&format!("/u/{token}"))
            .text("List-Unsubscribe=One-Click"),
    )
    .await;
    assert_eq!(
        response.status_code().as_u16(),
        200,
        "consent must survive a Redis outage: {}",
        response.text()
    );
    assert!(
        suppression_exists(&db, &tenant, recipient).await,
        "the suppression row must be persisted even with Redis down"
    );

    // The manual confirm path equally succeeds and persists.
    let recipient2 = "redisdown2@example.com";
    let token2 = unsub_token(&tenant, recipient2);
    let response = bounded(
        "redis_down POST /u/:token/confirm",
        srv.post(&format!("/u/{token2}/confirm"))
            .form(&[("confirm", "true")]),
    )
    .await;
    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(body.contains("been unsubscribed"), "{body}");
    assert!(
        suppression_exists(&db, &tenant, recipient2).await,
        "confirm-path suppression must persist with Redis down"
    );

    // The preferences center reads Postgres: unaffected, categories render.
    let recipient3 = "redisdown3@example.com";
    let prefs = prefs_token(&tenant, recipient3);
    let response = bounded("redis_down GET /p", srv.get(&format!("/p/{prefs}"))).await;
    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(
        body.contains("outage-matrix-news"),
        "preferences must load from Postgres: {body}"
    );
    assert!(
        !body.contains("Unable to load"),
        "a Redis outage must NOT degrade the Postgres-backed page: {body}"
    );

    // The pixel still serves the GIF (recording is best-effort).
    let message = unique("msgpixel");
    let pixel_token = codec()
        .encode(&TrackingData {
            tenant_id: tenant.clone(),
            message_id: message.clone(),
            recipient: "pixie@example.com".into(),
            link_id: None,
            original_url: None,
        })
        .expect("pixel token");
    let response = bounded(
        "redis_down GET /o",
        srv.get(&format!("/o/{pixel_token}"))
            .add_header(
                axum::http::HeaderName::from_static("user-agent"),
                NORMAL_UA.parse().expect("ua"),
            ),
    )
    .await;
    assert_eq!(response.status_code().as_u16(), 200);
    assert_eq!(response.as_bytes().as_ref(), TRANSPARENT_GIF);

    // Health honesty: liveness 200, readiness 503 (Redis is half the probe).
    let response = bounded("redis_down /health", srv.get("/health")).await;
    assert_eq!(response.status_code().as_u16(), 200);
    let response = bounded("redis_down /ready", srv.get("/ready")).await;
    assert_eq!(response.status_code().as_u16(), 503);

    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(&tenant)
        .execute(&db)
        .await
        .expect("cleanup tenant");
}

// ═════════════════════════════════════════════════════════════════════════════
// Matrix 1c — ClickHouse DOWN (Postgres + Redis live): the flush loop
// ═════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn clickhouse_down_flush_still_persists_every_event_and_never_wedges() {
    let _serial = wal_serial().await;
    let Some(db) = canonical_pool("outage_clickhouse_down").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run the outage matrix");
        return;
    };
    let Some(redis) = live_redis().await else {
        eprintln!("skipping: set TEST_REDIS_URL to run the outage matrix");
        return;
    };
    let tenant = unique("tnchdown");
    let message = unique("msgch");

    // The processor under test: live Postgres + live Redis, dead ClickHouse
    // (connection refused, 1 s insert timeout). The processor IS the surface
    // under outage here, so it is driven directly (the routes only enqueue).
    let processor = Arc::new(EventProcessor::with_config(
        db.clone(),
        redis.clone(),
        clickhouse::Client::default()
            .with_url("http://127.0.0.1:1")
            .with_database("apexmail"),
        Duration::from_secs(1),
        25,
        100,
    ));
    Arc::clone(&processor).start();

    for index in 0..3 {
        processor
            .record_open(OpenData {
                tenant_id: tenant.clone(),
                message_id: format!("{message}-{index}"),
                recipient: format!("chdown{index}@example.com"),
                user_agent: Some(NORMAL_UA.into()),
                ip_address: Some("203.0.113.9".into()),
            })
            .await
            .expect("open enqueues into the WAL");
    }
    // Postgres must receive every event although every ClickHouse insert
    // fails, and the WAL must drain (a ClickHouse failure NEVER re-enqueues —
    // Postgres is the source of truth).
    poll_until("first batch persists despite ClickHouse down", 150, || async {
        events_count(&db, &message).await >= 3
    })
    .await;
    poll_until("WAL drained for the first batch", 100, || async {
        !wal_has(&redis, &message).await
    })
    .await;

    // The loop must still be alive after three failed ClickHouse inserts:
    // a second batch lands too (no wedge, no deadlock).
    for index in 3..6 {
        processor
            .record_open(OpenData {
                tenant_id: tenant.clone(),
                message_id: format!("{message}-{index}"),
                recipient: format!("chdown{index}@example.com"),
                user_agent: Some(NORMAL_UA.into()),
                ip_address: Some("203.0.113.9".into()),
            })
            .await
            .expect("second batch enqueues");
    }
    poll_until("second batch persists (loop not wedged)", 150, || async {
        events_count(&db, &message).await >= 6
    })
    .await;

    // Restart cleanliness: a fresh processor over the same system records
    // nothing new and the count stays exactly 6 (no doubles).
    processor.stop().await;
    let second = Arc::new(EventProcessor::with_config(
        db.clone(),
        redis.clone(),
        clickhouse::Client::default().with_url("http://127.0.0.1:1"),
        Duration::from_secs(1),
        25,
        100,
    ));
    Arc::clone(&second).start();
    tokio::time::sleep(Duration::from_millis(300)).await;
    second.stop().await;
    assert_eq!(
        events_count(&db, &message).await,
        6,
        "a restart must neither lose nor double events after ClickHouse failures"
    );

    lrem(&redis, WAL_KEY, &message).await;
}

// ═════════════════════════════════════════════════════════════════════════════
// Matrix 4 — restart under load: no lost events, no double-recorded ones
// ═════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn processor_restart_with_postgres_down_loses_nothing_and_never_doubles() {
    let _serial = wal_serial().await;
    let Some(db) = canonical_pool("outage_restart").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run the outage matrix");
        return;
    };
    let Some(redis) = live_redis().await else {
        eprintln!("skipping: set TEST_REDIS_URL to run the outage matrix");
        return;
    };
    let tenant = unique("tnrestart");
    let message = unique("msgrestart");
    const N: usize = 8;

    // Processor A: LIVE Redis (the WAL is the durability boundary) + DEAD
    // Postgres. Every event is enqueued; every flush fails and re-enqueues.
    let a = Arc::new(EventProcessor::with_config(
        dead_pg(),
        redis.clone(),
        clickhouse::Client::default(),
        Duration::from_secs(1),
        20,
        100,
    ));
    for index in 0..N {
        a.record_open(OpenData {
            tenant_id: tenant.clone(),
            message_id: format!("{message}-{index}"),
            recipient: format!("restart{index}@example.com"),
            user_agent: Some(NORMAL_UA.into()),
            ip_address: Some("203.0.113.10".into()),
        })
        .await
        .expect("enqueue under PG outage");
    }
    Arc::clone(&a).start();
    // One flush attempt fails; the exponential backoff then spaces the rest
    // 1 s apart, so the 10-retry poison budget cannot burn in this window.
    tokio::time::sleep(Duration::from_millis(300)).await;
    bounded("stop A", a.stop()).await;
    let entries: Vec<String> = redis_list(&redis, WAL_KEY)
        .await
        .into_iter()
        .filter(|e| e.contains(&message))
        .collect();
    assert_eq!(
        entries.len(),
        N,
        "a Postgres outage must LOSE NOTHING: all events stay/return in the WAL, got {entries:?}"
    );

    // Processor B ("start again"): live Postgres, same WAL. Everything
    // drains exactly once.
    let b = Arc::new(EventProcessor::with_config(
        db.clone(),
        redis.clone(),
        clickhouse::Client::default(),
        Duration::from_secs(1),
        25,
        100,
    ));
    Arc::clone(&b).start();
    poll_until("restart drains the whole WAL into Postgres", 200, || async {
        events_count(&db, &message).await >= N as i64 && !wal_has(&redis, &message).await
    })
    .await;
    b.stop().await;

    // Exactly N rows, N distinct recipients — no double-recorded events.
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT recipient FROM events WHERE message_id LIKE $1 || '%' ORDER BY recipient",
    )
    .bind(&message)
    .fetch_all(&db)
    .await
    .expect("select flushed events");
    assert_eq!(rows.len(), N);
    let mut recipients: Vec<String> = rows.into_iter().map(|(r,)| r).collect();
    recipients.sort();
    recipients.dedup();
    assert_eq!(recipients.len(), N, "every recipient exactly once");

    // A third processor over the drained system changes nothing.
    let c = Arc::new(EventProcessor::with_config(
        db.clone(),
        redis.clone(),
        clickhouse::Client::default(),
        Duration::from_secs(1),
        25,
        100,
    ));
    Arc::clone(&c).start();
    tokio::time::sleep(Duration::from_millis(250)).await;
    c.stop().await;
    assert_eq!(events_count(&db, &message).await, N as i64);

    lrem(&redis, WAL_KEY, &message).await;
}

/// The "close pools mid-processing" cell: a live Postgres pool is closed
/// under a running flush loop; the in-flight batch must be re-enqueued, and a
/// fresh pool ("start again") must drain it without loss or duplication.
#[tokio::test]
async fn closing_the_pool_mid_flight_reenqueues_and_a_restart_drains_cleanly() {
    let _serial = wal_serial().await;
    let Some(db) = canonical_pool("outage_pool_close").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run the outage matrix");
        return;
    };
    let Some(redis) = live_redis().await else {
        eprintln!("skipping: set TEST_REDIS_URL to run the outage matrix");
        return;
    };

    let tenant = unique("tnclose");
    let message = unique("msgclose");

    // Phase 1: a live pool OVER THE SAME fresh test database as `db` (the
    // verification pool must stay open while the processor's pool closes, so
    // a second pool is built from the per-test database's resolved name).
    let (db_name,): (String,) = sqlx::query_as("SELECT current_database()")
        .fetch_one(&db)
        .await
        .expect("current db");
    let server_part = std::env::var("TEST_DATABASE_URL")
        .expect("checked")
        .rsplit_once('/')
        .expect("database url with a db segment")
        .0
        .to_string();
    let pool_a = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&format!("{server_part}/{db_name}"))
        .await
        .expect("pool A");
    let a = Arc::new(EventProcessor::with_config(
        pool_a.clone(),
        redis.clone(),
        clickhouse::Client::default(),
        Duration::from_secs(1),
        20,
        100,
    ));
    for index in 0..5 {
        a.record_open(OpenData {
            tenant_id: tenant.clone(),
            message_id: format!("{message}-a{index}"),
            recipient: format!("closea{index}@example.com"),
            user_agent: Some(NORMAL_UA.into()),
            ip_address: Some("203.0.113.11".into()),
        })
        .await
        .expect("enqueue phase 1");
    }
    Arc::clone(&a).start();
    poll_until("phase-1 batch drained", 150, || async {
        events_count(&db, &message).await >= 5
    })
    .await;

    // Phase 2: five MORE events, then the pool closes mid-processing.
    for index in 0..5 {
        a.record_open(OpenData {
            tenant_id: tenant.clone(),
            message_id: format!("{message}-b{index}"),
            recipient: format!("closeb{index}@example.com"),
            user_agent: Some(NORMAL_UA.into()),
            ip_address: Some("203.0.113.12".into()),
        })
        .await
        .expect("enqueue phase 2");
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    pool_a.close().await; // the flush loop now fails every write
    bounded("stop A after pool close", a.stop()).await;

    // The five phase-2 events must still be in the WAL (re-enqueued, not
    // lost) — unless the close raced AFTER their flush, which the final
    // count assertion covers either way.
    if events_count(&db, &message).await < 10 {
        let pending = redis_list(&redis, WAL_KEY)
            .await
            .into_iter()
            .filter(|e| e.contains(&message))
            .count();
        assert_eq!(
            pending, 5,
            "mid-flight events must be re-enqueued after the pool closed"
        );
    }

    // Start again on a FRESH pool: everything lands, exactly once.
    let b = Arc::new(EventProcessor::with_config(
        db.clone(),
        redis.clone(),
        clickhouse::Client::default(),
        Duration::from_secs(1),
        25,
        100,
    ));
    Arc::clone(&b).start();
    poll_until("restart drains all ten events", 200, || async {
        events_count(&db, &message).await >= 10
    })
    .await;
    b.stop().await;

    let ids: Vec<(String,)> =
        sqlx::query_as("SELECT DISTINCT id FROM events WHERE message_id LIKE $1 || '%'")
            .bind(&message)
            .fetch_all(&db)
            .await
            .expect("select ids");
    assert_eq!(ids.len(), 10, "no double-recorded events");

    lrem(&redis, WAL_KEY, &message).await;
}
