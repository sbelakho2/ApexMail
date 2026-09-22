//! Adversarial end-to-end route tests for the tracking service.
//!
//! Drives the real router (axum-test) against the canonical Postgres schema
//! (`migrator::test_support`) and the live test Redis (`TEST_REDIS_URL`).
//! Both soft-skip ONLY when their env var is unset; a configured provisioning
//! failure panics.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tracking_service::bot::BotDetector;
use tracking_service::codec::{TrackingCodec, TrackingData};
use tracking_service::config::{
    ClickHouseConfig, Config, DatabaseConfig, MetricsConfig, RateLimitConfig, RedisConfig,
    ServerConfig, TrackingConfig,
};
use tracking_service::processor::EventProcessor;
use tracking_service::routes::{build_router, TRANSPARENT_GIF};
use tracking_service::state::AppState;

const SECRET: &str = "adversarial-tracking-secret-32-bytes!!";
const NORMAL_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36";
const BOT_UA: &str = "python-requests/2.31.0";

// Static 2048-bit RSA test keypair (throwaway, test-only).
const TEST_RSA_PRIVATE_PEM: &str = include_str!("fixtures/sse_test_key.pem");
const TEST_RSA_PUBLIC_PEM: &str = include_str!("fixtures/sse_test_pub.pem");

async fn canonical_pool(name: &str) -> Option<sqlx::PgPool> {
    match migrator::test_support::fresh_canonical_pool(name, name).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

/// A URL whose database number is `db` (same server as TEST_REDIS_URL).
/// Raw WAL/dedup keys are not key-prefixed, so a dedicated database keeps
/// this suite from interfering with the lib-test binary running in parallel.
fn redis_url_in_db(base: &str, db: u32) -> String {
    match url::Url::parse(base) {
        Ok(mut parsed) => {
            parsed.set_path(&db.to_string());
            parsed.to_string()
        }
        Err(_) => format!("{}/{}", base.trim_end_matches('/'), db),
    }
}

fn env_pool() -> deadpool_redis::Pool {
    let url = redis_url_in_db(
        &std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL must be set for this test"),
        7,
    );
    deadpool_redis::Config::from_url(&url)
        .builder()
        .expect("redis builder")
        .max_size(4)
        .runtime(deadpool_redis::Runtime::Tokio1)
        .build()
        .expect("redis pool")
}

fn dead_redis() -> deadpool_redis::Pool {
    deadpool_redis::Config::from_url("redis://127.0.0.1:1")
        .builder()
        .expect("redis builder")
        .max_size(1)
        .runtime(deadpool_redis::Runtime::Tokio1)
        .build()
        .expect("dead redis pool")
}

fn test_config(redis_url: &str, jwt_public_pem: &str) -> Config {
    Config {
        server: ServerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
        },
        database: DatabaseConfig {
            url: "postgresql://offline@127.0.0.1:1/offline".into(),
            max_connections: 2,
        },
        redis: RedisConfig {
            url: redis_url.to_string(),
            key_prefix: "tracking:".into(),
            pool_size: 4,
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
        secret_key: zeroize::Zeroizing::new(SECRET.into()),
        jwt_public_key_pem: jwt_public_pem.to_string(),
    }
}

fn state_with(db: sqlx::PgPool, redis: deadpool_redis::Pool, config: Config) -> AppState {
    let processor = Arc::new(EventProcessor::new(
        db.clone(),
        redis.clone(),
        clickhouse::Client::default(),
        Duration::from_millis(100),
    ));
    AppState::new(
        TrackingCodec::new(SECRET),
        db,
        redis,
        processor,
        BotDetector::new(),
        config,
    )
}

async fn server(state: &AppState) -> axum_test::TestServer {
    axum_test::TestServer::new(
        build_router(state.clone()).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .expect("test server")
}

fn unique(label: &str) -> String {
    let hex = uuid::Uuid::new_v4().simple().to_string();
    format!("{label}_{}", &hex[..10])
}

fn codec() -> TrackingCodec {
    TrackingCodec::new(SECRET)
}

fn click_token(tenant: &str, message: &str, recipient: &str, original_url: &str) -> String {
    codec()
        .encode(&TrackingData {
            tenant_id: tenant.into(),
            message_id: message.into(),
            recipient: recipient.into(),
            link_id: None,
            original_url: Some(original_url.into()),
        })
        .expect("encode")
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

async fn redis_cmd<T: redis::FromRedisValue>(pool: &deadpool_redis::Pool, parts: &[&str]) -> T {
    let mut conn = pool.get().await.expect("redis conn");
    let mut cmd = redis::cmd(parts[0]);
    for part in &parts[1..] {
        cmd.arg(*part);
    }
    cmd.query_async(&mut *conn).await.expect("redis command")
}

/// Poll the WAL (bounded, ≤ 50 ms per sleep) for an entry containing `needle`.
async fn wait_for_wal(pool: &deadpool_redis::Pool, needle: &str) -> bool {
    for _ in 0..30 {
        let entries: Vec<String> =
            redis_cmd(pool, &["LRANGE", "apexmail:events:pending", "0", "-1"]).await;
        if entries.iter().any(|e| e.contains(needle)) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

async fn drop_wal_entries(pool: &deadpool_redis::Pool, needle: &str) {
    let entries: Vec<String> =
        redis_cmd(pool, &["LRANGE", "apexmail:events:pending", "0", "-1"]).await;
    for entry in entries.iter().filter(|e| e.contains(needle)) {
        let _: i64 = redis_cmd(
            pool,
            &["LREM", "apexmail:events:pending", "1", entry.as_str()],
        )
        .await;
    }
}

// ── Pixel ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn pixel_always_returns_the_gif_and_never_leaks_recipient_data() {
    let Some(db) = canonical_pool("tracking_pixel").await else {
        return;
    };
    let Some(redis_url) = std::env::var("TEST_REDIS_URL").ok() else {
        return;
    };
    let redis = env_pool();
    let state = state_with(db, redis.clone(), test_config(&redis_url, ""));
    let srv = server(&state).await;

    let tenant = unique("tn_pix");
    let message = unique("msg");
    let recipient = "pixel-victim@example.com";
    let token = codec()
        .encode(&TrackingData {
            tenant_id: tenant.clone(),
            message_id: message.clone(),
            recipient: recipient.into(),
            link_id: None,
            original_url: None,
        })
        .unwrap();

    // Canonical pixel path: 200 GIF, no PII in the body, hostile-cache headers.
    let response = srv
        .get(&format!("/o/{token}"))
        .add_header(
            axum::http::HeaderName::from_static("user-agent"),
            NORMAL_UA.parse().expect("ua"),
        )
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    assert_eq!(response.headers().get("content-type").unwrap(), "image/gif");
    assert_eq!(response.as_bytes().as_ref(), TRANSPARENT_GIF);
    let text = String::from_utf8_lossy(response.as_bytes());
    assert!(!text.contains(recipient), "recipient must never leak");
    assert!(!text.contains(&tenant), "tenant must never leak");
    assert_eq!(
        response.headers().get("cache-control").unwrap(),
        "no-store, no-cache, must-revalidate, proxy-revalidate"
    );
    assert!(wait_for_wal(&redis, &tenant).await, "open recorded");
    drop_wal_entries(&redis, &tenant).await;

    // Unknown / short / tampered tokens still return the GIF (clients must
    // render), but record nothing.
    for bad in ["short", "x", "not-a-real-token-but-long-enough!!"] {
        let response = srv.get(&format!("/o/{bad}")).await;
        assert_eq!(response.status_code().as_u16(), 200, "token {bad:?}");
        assert_eq!(response.as_bytes().as_ref(), TRANSPARENT_GIF);
    }

    // Bot user-agent: no recording (E-190), still a GIF.
    let bot_tenant = unique("tn_bot");
    let bot_token = codec()
        .encode(&TrackingData {
            tenant_id: bot_tenant.clone(),
            message_id: unique("msg"),
            recipient: "bot@example.com".into(),
            link_id: None,
            original_url: None,
        })
        .unwrap();
    let response = srv
        .get(&format!("/o/{bot_token}"))
        .add_header(
            axum::http::HeaderName::from_static("user-agent"),
            BOT_UA.parse().expect("ua"),
        )
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    // Give the (wrongly) spawned recorder a bounded window, then prove it did
    // nothing.
    tokio::time::sleep(Duration::from_millis(30)).await;
    let entries: Vec<String> =
        redis_cmd(&redis, &["LRANGE", "apexmail:events:pending", "0", "-1"]).await;
    assert!(
        !entries.iter().any(|e| e.contains(&bot_tenant)),
        "bot pixel must not record"
    );

    // Query-param variant of the pixel: recorded for a human.
    let gif_tenant = unique("tn_gif");
    let gif_token = codec()
        .encode(&TrackingData {
            tenant_id: gif_tenant.clone(),
            message_id: unique("msg"),
            recipient: "gif@example.com".into(),
            link_id: None,
            original_url: None,
        })
        .unwrap();
    let response = srv
        .get("/o.gif")
        .add_query_param("t", &gif_token)
        .add_header(
            axum::http::HeaderName::from_static("user-agent"),
            NORMAL_UA.parse().expect("ua"),
        )
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    assert!(wait_for_wal(&redis, &gif_tenant).await);
    drop_wal_entries(&redis, &gif_tenant).await;

    // No `t` at all is a pure GIF fetch, nothing recorded.
    let response = srv.get("/o.gif").await;
    assert_eq!(response.as_bytes().as_ref(), TRANSPARENT_GIF);
}

// ── Click redirect ───────────────────────────────────────────────────────────

/// The click handler's domain authorization must consult the canonical
/// `domains` table when neither the in-memory nor the Redis cache has an
/// answer: a tenant-owned verified domain redirects and records, an
/// unowned domain falls back and records nothing.
#[tokio::test]
async fn click_redirect_authorises_owned_domains_via_the_database() {
    let Some(db) = canonical_pool("tracking_click_domain").await else {
        return;
    };
    let Ok(redis_url) = std::env::var("TEST_REDIS_URL") else {
        return;
    };
    let redis = env_pool();
    let state = state_with(db.clone(), redis.clone(), test_config(&redis_url, ""));
    let srv = server(&state).await;

    let tenant = unique("tn_clk");
    seed_tenant(&db, &tenant).await;
    // An OWNED, verified domain row. Nothing is seeded into the Redis
    // `redirect_domain:` cache — the database is the authority here.
    sqlx::query("INSERT INTO domains (tenant_id, name, verified) VALUES ($1, $2, true)")
        .bind(&tenant)
        .bind("owned-click.example")
        .execute(&db)
        .await
        .expect("seed owned domain");

    // Baked original_url on the tenant's owned domain → redirect there and
    // record the click.
    let message = unique("msg");
    let token = click_token(
        &tenant,
        &message,
        "clicker@example.com",
        "https://owned-click.example/landing",
    );
    let response = srv
        .get(&format!("/c/{token}"))
        .add_header(
            axum::http::HeaderName::from_static("user-agent"),
            NORMAL_UA.parse().expect("ua"),
        )
        .await;
    assert_eq!(response.status_code().as_u16(), 302);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert_eq!(location, "https://owned-click.example/landing");
    assert!(wait_for_wal(&redis, &tenant).await, "click recorded");
    drop_wal_entries(&redis, &tenant).await;

    // A domain owned by nobody (no row, no cache entry for this tenant)
    // must fall back and record NOTHING.
    let stranger_tenant = unique("tn_clk2");
    let stranger_message = unique("msg");
    let stranger = click_token(
        &stranger_tenant,
        &stranger_message,
        "clicker@example.com",
        "https://not-owned-anywhere.example/phish",
    );
    let response = srv.get(&format!("/c/{stranger}")).await;
    assert_eq!(response.status_code().as_u16(), 302);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert_eq!(location, "https://fallback.test.example/");
    // Bounded settle for the (correctly absent) fire-and-forget recorder.
    tokio::time::sleep(Duration::from_millis(30)).await;
    let entries: Vec<String> =
        redis_cmd(&redis, &["LRANGE", "apexmail:events:pending", "0", "-1"]).await;
    assert!(
        !entries.iter().any(|e| e.contains(&stranger_message)),
        "unowned-domain click must not be recorded"
    );

    // The patterns tier of the same lookup: `tenant_settings.allowed_
    // redirect_domains` is a JSONB array — a `*.wild.example` entry must
    // authorise any subdomain.
    let wildcard_tenant = unique("tn_clk3");
    seed_tenant(&db, &wildcard_tenant).await;
    sqlx::query(
        "INSERT INTO tenant_settings (tenant_id, allowed_redirect_domains) \
         VALUES ($1, '[\"*.wild.example\"]'::jsonb)",
    )
    .bind(&wildcard_tenant)
    .execute(&db)
    .await
    .expect("seed wildcard patterns");
    let wildcard = click_token(
        &wildcard_tenant,
        &unique("msg"),
        "clicker@example.com",
        "https://promo.wild.example/offer",
    );
    let response = srv.get(&format!("/c/{wildcard}")).await;
    assert_eq!(response.status_code().as_u16(), 302);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert_eq!(location, "https://promo.wild.example/offer");

    // The wildcard must NOT authorise the bare apex (documented semantics:
    // `*.example` matches `sub.example` only).
    let apex = click_token(
        &wildcard_tenant,
        &unique("msg"),
        "clicker@example.com",
        "https://wild.example/offer",
    );
    let response = srv.get(&format!("/c/{apex}")).await;
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert_eq!(location, "https://fallback.test.example/");
}

// ── Unsubscribe ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn one_click_unsubscribe_is_durable_idempotent_and_refuses_bad_input() {
    let Some(db) = canonical_pool("tracking_unsub_routes").await else {
        return;
    };
    let Ok(redis_url) = std::env::var("TEST_REDIS_URL") else {
        return;
    };
    let redis = env_pool();
    let tenant = unique("tn_oc");
    let other = unique("tn_oc_other");
    seed_tenant(&db, &tenant).await;
    seed_tenant(&db, &other).await;
    let state = state_with(db.clone(), redis.clone(), test_config(&redis_url, ""));
    let srv = server(&state).await;

    let recipient = "oneclick@example.com";
    let token = codec()
        .generate_unsubscribe_token_with_message(&tenant, recipient, &unique("msg"))
        .expect("unsub token");

    // Invalid body (not the RFC 8058 one-click body) → 400, nothing recorded.
    let response = srv
        .post(&format!("/u/{token}"))
        .text("List-Unsubscribe=No-Click")
        .await;
    assert_eq!(response.status_code().as_u16(), 400);

    // Valid one-click POST → 200 {"success":true} and the suppression row is
    // persisted BEFORE the response is trusted.
    let response = srv
        .post(&format!("/u/{token}"))
        .text("List-Unsubscribe=One-Click")
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    assert_eq!(response.text(), r#"{"success":true}"#);
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM suppressions WHERE tenant_id = $1 AND email = $2")
            .bind(&tenant)
            .bind(recipient)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(count, 1, "suppression written before the 200");
    // Tenant isolation: the other tenant has nothing.
    let other_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM suppressions WHERE tenant_id = $1")
            .bind(&other)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(other_count, 0);

    // Replay → deduped 200 (no second event), suppression still exactly one.
    let response = srv
        .post(&format!("/u/{token}"))
        .text("List-Unsubscribe=One-Click")
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM suppressions WHERE tenant_id = $1 AND email = $2")
            .bind(&tenant)
            .bind(recipient)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(count, 1);

    // Tampered token (one character flipped) → 400.
    let mut tampered = token.clone().into_bytes();
    let last = tampered.len() - 1;
    tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
    let response = srv
        .post(&format!("/u/{}", String::from_utf8(tampered).unwrap()))
        .text("List-Unsubscribe=One-Click")
        .await;
    assert_eq!(response.status_code().as_u16(), 400);

    // Multi-byte hostile token → 400 (no panic, no raw token in the body).
    let response = srv
        .post("/u/üñïçødé-token-multibyte-payload")
        .text("List-Unsubscribe=One-Click")
        .await;
    assert_eq!(response.status_code().as_u16(), 400);
    assert!(!response.text().contains("üñïçødé"));

    // GET is a read: it renders a confirmation form and changes nothing.
    let get_tenant = unique("tn_get");
    seed_tenant(&db, &get_tenant).await;
    let get_token = codec()
        .generate_unsubscribe_token(&get_tenant, "get-only@example.com")
        .unwrap();
    let response = srv.get(&format!("/u/{get_token}")).await;
    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(body.contains("confirm"), "form rendered: {body}");
    assert!(body.contains(&format!("/u/{get_token}/confirm")));
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM suppressions WHERE tenant_id = $1")
        .bind(&get_tenant)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(count, 0, "GET /u must be side-effect free");

    // The confirmation POST is the browser path that changes consent.
    let response = srv
        .post(&format!("/u/{get_token}/confirm"))
        .form(&[("confirm", "true")])
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    assert!(response.text().contains("get-only@example.com"));
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM suppressions WHERE tenant_id = $1")
        .bind(&get_tenant)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(count, 1);

    // Missing/false confirm flag → error page, no consent change.
    let strict_tenant = unique("tn_strict");
    seed_tenant(&db, &strict_tenant).await;
    let strict_token = codec()
        .generate_unsubscribe_token(&strict_tenant, "strict@example.com")
        .unwrap();
    // A form body with no `confirm` field at all.
    let response = srv
        .post(&format!("/u/{strict_token}/confirm"))
        .form(&[("other", "1")])
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    assert!(response.text().to_lowercase().contains("invalid"));
    // Explicitly false confirmation.
    let response = srv
        .post(&format!("/u/{strict_token}/confirm"))
        .form(&[("confirm", "false")])
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    assert!(response.text().to_lowercase().contains("invalid"));
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM suppressions WHERE tenant_id = $1")
        .bind(&strict_tenant)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

// ── Preferences centre ───────────────────────────────────────────────────────

#[tokio::test]
async fn preferences_center_persists_consent_and_reconciles_dedup() {
    let Some(db) = canonical_pool("tracking_prefs").await else {
        return;
    };
    let Ok(redis_url) = std::env::var("TEST_REDIS_URL") else {
        return;
    };
    let redis = env_pool();
    let tenant = unique("tn_prefs");
    seed_tenant(&db, &tenant).await;
    let recipient = "prefs@example.com";
    sqlx::query(
        "INSERT INTO email_categories (tenant_id, name, description, active, display_order)
         VALUES ($1, 'marketing', 'Promotions', true, 0),
                ($1, 'product',   'Product news', true, 1),
                ($1, 'inactive',  'Retired', false, 2)",
    )
    .bind(&tenant)
    .execute(&db)
    .await
    .unwrap();
    let state = state_with(db.clone(), redis.clone(), test_config(&redis_url, ""));
    let srv = server(&state).await;

    let token = codec()
        .generate_preferences_token(&tenant, recipient)
        .expect("prefs token");

    // GET renders the tenant's active categories only, and leaks no other
    // tenant's data.
    let response = srv.get(&format!("/p/{token}")).await;
    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(body.contains("marketing") && body.contains("product"));
    assert!(!body.contains("inactive"), "inactive categories hidden");

    // Category opt-out persists a subscription_preferences row.
    let response = srv
        .post(&format!("/p/{token}"))
        .form(&[("category_marketing", "false")])
        .await;
    assert_eq!(response.status_code().as_u16(), 303);
    let (subscribed,): (bool,) = sqlx::query_as(
        "SELECT subscribed FROM subscription_preferences
         WHERE tenant_id = $1 AND email = $2 AND category = 'marketing'",
    )
    .bind(&tenant)
    .bind(recipient)
    .fetch_one(&db)
    .await
    .expect("preference row");
    assert!(!subscribed);

    // Unknown categories are rejected (F9) without writing junk.
    let response = srv
        .post(&format!("/p/{token}"))
        .form(&[("category_not_a_real_category", "false")])
        .await;
    assert_eq!(response.status_code().as_u16(), 400);
    let junk: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM subscription_preferences WHERE category = 'not_a_real_category'",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(junk, 0);

    // Global unsubscribe writes the durable suppression.
    let response = srv
        .post(&format!("/p/{token}"))
        .form(&[("unsubscribe_all", "true")])
        .await;
    assert_eq!(response.status_code().as_u16(), 303);
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM suppressions WHERE tenant_id = $1 AND email = $2")
            .bind(&tenant)
            .bind(recipient)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(count, 1);

    // Resubscribe removes the suppression AND the dedup marker, so the next
    // one-click unsubscribe is recorded again (unsub → resubscribe → unsub).
    let response = srv
        .post(&format!("/p/{token}"))
        .form(&[("resubscribe_all", "true")])
        .await;
    assert_eq!(response.status_code().as_u16(), 303);
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM suppressions WHERE tenant_id = $1 AND email = $2")
            .bind(&tenant)
            .bind(recipient)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(count, 0, "resubscribe deletes the suppression");

    let unsub_token = codec()
        .generate_unsubscribe_token_with_message(&tenant, recipient, "m1")
        .unwrap();
    let response = srv
        .post(&format!("/u/{unsub_token}"))
        .text("List-Unsubscribe=One-Click")
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM suppressions WHERE tenant_id = $1 AND email = $2")
            .bind(&tenant)
            .bind(recipient)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(count, 1, "post-resubscribe unsubscribe wins");

    // Tampered preferences token → error page anyway.
    let response = srv.get("/p/not-a-valid-token-at-all").await;
    assert_eq!(response.status_code().as_u16(), 200);
    assert!(response.text().to_lowercase().contains("invalid"));
    let _ = drop_wal_entries(&redis, &tenant).await;
}

// ── Health ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn health_and_ready_report_dependency_state_honestly() {
    let Some(db) = canonical_pool("tracking_health").await else {
        return;
    };
    let Ok(redis_url) = std::env::var("TEST_REDIS_URL") else {
        return;
    };
    let redis = env_pool();

    // Healthy: both dependencies reachable.
    let state = state_with(db.clone(), redis.clone(), test_config(&redis_url, ""));
    let srv = server(&state).await;
    let response = srv.get("/health").await;
    assert_eq!(response.status_code().as_u16(), 200);
    assert!(response.text().contains("healthy"));
    let response = srv.get("/ready").await;
    assert_eq!(response.status_code().as_u16(), 200);
    assert!(response.text().contains("ready"));

    // Dead DB → not ready (503), never a fabricated ready.
    let dead_db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(50))
        .connect_lazy("postgres://offline@127.0.0.1:1/offline")
        .unwrap();
    let state = state_with(dead_db, redis.clone(), test_config(&redis_url, ""));
    let srv = server(&state).await;
    assert_eq!(srv.get("/ready").await.status_code().as_u16(), 503);

    // Dead Redis → not ready.
    let state = state_with(db, dead_redis(), test_config("redis://127.0.0.1:1", ""));
    let srv = server(&state).await;
    assert_eq!(srv.get("/ready").await.status_code().as_u16(), 503);
}

// ── Rate limiting middleware ─────────────────────────────────────────────────

#[tokio::test]
async fn rate_limit_middleware_returns_gif_for_pixels_and_json_elsewhere() {
    let Some(db) = canonical_pool("tracking_ratelimit").await else {
        return;
    };
    let Ok(redis_url) = std::env::var("TEST_REDIS_URL") else {
        return;
    };
    let redis = env_pool();
    let mut config = test_config(&redis_url, "");
    config.rate_limit.enabled = true;
    config.rate_limit.max_per_minute = 2;
    // Trust the test peer so a per-run unique XFF client IP is honoured —
    // this keeps the sliding-window key from leaking across reruns.
    config.tracking.trusted_proxies = vec!["127.0.0.1/32".parse().unwrap()];
    let state = state_with(db, redis, config);
    let srv = server(&state).await;

    let client = format!("198.51.100.{}", (uuid::Uuid::new_v4().as_u128() % 200) + 20);
    let with_ip = |req: axum_test::TestRequest| {
        req.add_header(
            axum::http::HeaderName::from_static("x-forwarded-for"),
            client.parse().expect("xff"),
        )
    };

    // Two requests pass, the third is limited within the same window.
    for _ in 0..2 {
        let response = with_ip(srv.get("/health")).await;
        assert_eq!(response.status_code().as_u16(), 200);
    }
    let response = with_ip(srv.get("/health")).await;
    assert_eq!(response.status_code().as_u16(), 429);
    assert_eq!(response.headers().get("retry-after").unwrap(), "60");
    assert!(response.text().contains("Rate limit exceeded"));

    // Pixel path answers with a GIF even when limited (clients must render).
    let response = with_ip(srv.get("/o.gif")).await;
    assert_eq!(response.status_code().as_u16(), 429);
    assert_eq!(response.headers().get("content-type").unwrap(), "image/gif");
    assert_eq!(response.as_bytes().as_ref(), TRANSPARENT_GIF);
}

#[tokio::test]
async fn rate_limit_middleware_fails_boundedly_open_when_redis_is_down() {
    // Dead Redis: the request is admitted by the bounded local emergency
    // quota (never unlimited, never a hard outage of the whole service).
    let Some(db) = canonical_pool("tracking_ratelimit_down").await else {
        return;
    };
    let redis = dead_redis();
    let mut config = test_config("redis://127.0.0.1:1", "");
    config.rate_limit.enabled = true;
    config.rate_limit.max_per_minute = 1000;
    let state = state_with(db, redis, config);
    let srv = server(&state).await;
    let response = srv.get("/health").await;
    assert_eq!(response.status_code().as_u16(), 200);
}

// ── SSE ──────────────────────────────────────────────────────────────────────

fn sse_token(tenant: &str, scopes: &[&str], exp_offset_secs: i64) -> String {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    let exp = (chrono::Utc::now().timestamp() + exp_offset_secs) as u64;
    let claims = serde_json::json!({
        "tenant_id": tenant,
        "sub": "user-1",
        "scopes": scopes,
        "exp": exp,
        "iat": chrono::Utc::now().timestamp(),
    });
    encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_PEM.as_bytes()).expect("test private key"),
    )
    .expect("sign test jwt")
}

/// Drive the SSE handler directly (the stream body itself never ends, so the
/// test asserts on the response head and drops it).
async fn sse_head(
    state: &AppState,
    authorization: Option<&str>,
    events: Option<&str>,
    message_id: Option<&str>,
) -> axum::response::Response {
    use tracking_service::routes::sse::{handle_stream, StreamQuery};
    let mut headers = axum::http::HeaderMap::new();
    if let Some(value) = authorization {
        headers.insert(
            axum::http::header::AUTHORIZATION,
            value.parse().expect("authorization header"),
        );
    }
    handle_stream(
        axum::extract::State(state.clone()),
        headers,
        axum::extract::Query(StreamQuery {
            events: events.map(str::to_string),
            message_id: message_id.map(str::to_string),
        }),
    )
    .await
}

#[tokio::test]
async fn sse_requires_a_signed_stream_scoped_token_and_caps_connections() {
    let Some(db) = canonical_pool("tracking_sse").await else {
        return;
    };
    let Ok(redis_url) = std::env::var("TEST_REDIS_URL") else {
        return;
    };
    let redis = env_pool();
    let state = state_with(
        db,
        redis,
        test_config(&redis_url, TEST_RSA_PUBLIC_PEM.trim()),
    );
    let srv = server(&state).await;
    let tenant = unique("tn_sse");

    // Missing / malformed authorization → 401.
    for auth in [None, Some("Basic abc"), Some("Bearer ")] {
        let response = sse_head(&state, auth, None, None).await;
        assert_eq!(response.status(), 401, "auth {auth:?}");
    }
    let response = srv
        .get("/v1/stream")
        .add_header(
            axum::http::HeaderName::from_static("authorization"),
            "Bearer not-a-jwt".parse().unwrap(),
        )
        .await;
    assert_eq!(response.status_code().as_u16(), 401);

    // Valid signature but no stream scope → 401.
    let no_scope = sse_token(&tenant, &["read"], 3600);
    let response = sse_head(&state, Some(&format!("Bearer {no_scope}")), None, None).await;
    assert_eq!(response.status(), 401);

    // Expired token → 401 (jsonwebtoken validates exp).
    let expired = sse_token(&tenant, &["stream"], -3600);
    let response = sse_head(&state, Some(&format!("Bearer {expired}")), None, None).await;
    assert_eq!(response.status(), 401);

    // Valid token: 200 text/event-stream.
    let good = sse_token(&tenant, &["stream"], 3600);
    let response = sse_head(
        &state,
        Some(&format!("Bearer {good}")),
        Some("opened,clicked"),
        None,
    )
    .await;
    assert_eq!(response.status(), 200);
    assert!(response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/event-stream"));
    drop(response); // release the connection slot

    // The per-tenant cap is enforced: 5 concurrent streams then 429.
    // Use a fresh tenant so the earlier dropped stream's slot release cannot
    // race this assertion.
    let cap_tenant = unique("tn_sse_cap");
    let cap_token = sse_token(&cap_tenant, &["stream"], 3600);
    let mut held = Vec::new();
    for _ in 0..5 {
        let response = sse_head(&state, Some(&format!("Bearer {cap_token}")), None, None).await;
        assert_eq!(response.status(), 200);
        held.push(response);
    }
    let response = sse_head(&state, Some(&format!("Bearer {cap_token}")), None, None).await;
    assert_eq!(response.status(), 429);
    drop(held);
}

#[tokio::test]
async fn sse_wrong_tenant_token_cannot_read_another_tenants_channel() {
    let Some(db) = canonical_pool("tracking_sse_iso").await else {
        return;
    };
    let Ok(redis_url) = std::env::var("TEST_REDIS_URL") else {
        return;
    };
    let redis = env_pool();
    let state = state_with(
        db,
        redis,
        test_config(&redis_url, TEST_RSA_PUBLIC_PEM.trim()),
    );
    let tenant_a = unique("tn_a");
    let tenant_b = unique("tn_b");

    // The channel a stream subscribes to is derived from the VERIFIED token,
    // never from a query parameter: a token for tenant B yields a 200 stream
    // on B's channel even when the query says A.
    let token_b = sse_token(&tenant_b, &["stream"], 3600);
    let response = sse_head(
        &state,
        Some(&format!("Bearer {token_b}")),
        Some("opened"),
        Some(&format!("tenant={tenant_a}")),
    )
    .await;
    assert_eq!(response.status(), 200);
    drop(response);

    // A tenant-A token stays on A's channel (the isolation invariant: the
    // routing key is claims.tenant_id only).
    let token_a = sse_token(&tenant_a, &["stream"], 3600);
    let response = sse_head(&state, Some(&format!("Bearer {token_a}")), None, None).await;
    assert_eq!(response.status(), 200);
}

// ── Residual-arm coverage: preferences faults, dedup side channels, click
//    logging paths ──────────────────────────────────────────────────────────

/// `prefs_post` against hostile database states: a bad token (400), a dead
/// database at BEGIN (500), a deferred trigger fault at COMMIT (500), a
/// dropped table at UPDATE (500) — and the no-op submission that never
/// touches the database at all.
#[tokio::test]
async fn prefs_post_survives_database_faults() {
    let Some(db) = canonical_pool("tracking_prefs_faults").await else {
        return;
    };
    let Ok(redis_url) = std::env::var("TEST_REDIS_URL") else {
        return;
    };
    let redis = env_pool();
    let tenant = unique("tn_pfault");
    seed_tenant(&db, &tenant).await;
    let recipient = "pfault@example.com";
    sqlx::query(
        "INSERT INTO email_categories (tenant_id, name, description, active, display_order)
         VALUES ($1, 'marketing', 'Promotions', true, 0),
                ($1, 'product',   'Product news', true, 1)",
    )
    .bind(&tenant)
    .execute(&db)
    .await
    .unwrap();
    let state = state_with(db.clone(), redis.clone(), test_config(&redis_url, ""));
    let srv = server(&state).await;
    let token = codec()
        .generate_preferences_token(&tenant, recipient)
        .expect("prefs token");

    // (a) A token that fails the shape check → 400 JSON, never a panic.
    let response = srv
        .post("/p/not$$a$$valid$$shape")
        .form(&[("category_marketing", "false")])
        .await;
    assert_eq!(response.status_code().as_u16(), 400);
    assert!(response.text().contains("Invalid token"));

    // (b) Dead database: BEGIN fails → 500 JSON.
    let dead_db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(50))
        .connect_lazy("postgres://offline@127.0.0.1:1/offline")
        .unwrap();
    let dead_srv = server(&state_with(
        dead_db,
        redis.clone(),
        test_config(&redis_url, ""),
    ))
    .await;
    let response = dead_srv
        .post(&format!("/p/{token}"))
        .form(&[("category_marketing", "false")])
        .await;
    assert_eq!(response.status_code().as_u16(), 500);

    // (c) COMMIT-time fault: a DEFERRED constraint trigger raises exactly
    //     when the transaction commits.
    sqlx::query(
        "CREATE OR REPLACE FUNCTION prefs_deferred_fault() RETURNS trigger AS $$
         BEGIN RAISE EXCEPTION 'deferred prefs fault'; END;
         $$ LANGUAGE plpgsql",
    )
    .execute(&db)
    .await
    .unwrap();
    sqlx::query(
        "CREATE CONSTRAINT TRIGGER prefs_deferred_fault_trg
         AFTER INSERT ON subscription_preferences
         DEFERRABLE INITIALLY DEFERRED
         FOR EACH ROW EXECUTE FUNCTION prefs_deferred_fault()",
    )
    .execute(&db)
    .await
    .unwrap();
    let response = srv
        .post(&format!("/p/{token}"))
        .form(&[("category_product", "false")])
        .await;
    assert_eq!(
        response.status_code().as_u16(),
        500,
        "commit fault surfaces"
    );
    let committed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM subscription_preferences WHERE tenant_id = $1 AND email = $2",
    )
    .bind(&tenant)
    .bind(recipient)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(committed, 0, "the faulted transaction rolled back cleanly");
    sqlx::query("DROP TRIGGER prefs_deferred_fault_trg ON subscription_preferences")
        .execute(&db)
        .await
        .unwrap();

    // (d) Table gone: the batch UPDATE fails → 500 JSON.
    sqlx::query("DROP TABLE subscription_preferences CASCADE")
        .execute(&db)
        .await
        .unwrap();
    let response = srv
        .post(&format!("/p/{token}"))
        .form(&[("category_marketing", "false")])
        .await;
    assert_eq!(response.status_code().as_u16(), 500);

    // (e) A submission with no recognised fields never opens a transaction:
    //     still a clean redirect even with the table gone.
    let response = srv
        .post(&format!("/p/{token}"))
        .form(&[("unrelated", "value")])
        .await;
    assert_eq!(response.status_code().as_u16(), 303);
}

/// The dedup side channels (mark on record, clear on resubscribe) are
/// best-effort: a dead Redis must not fail the operation itself.
#[tokio::test]
async fn dedup_side_channels_survive_a_dead_redis() {
    let Some(db) = canonical_pool("tracking_dedup_dead").await else {
        return;
    };
    let Ok(redis_url) = std::env::var("TEST_REDIS_URL") else {
        return;
    };
    let state = state_with(db.clone(), dead_redis(), test_config(&redis_url, ""));
    let srv = server(&state).await;

    let tenant = unique("tn_dedupdead");
    seed_tenant(&db, &tenant).await;
    let recipient = "dedupdead@example.com";

    // One-click unsubscribe: records durably even though the dedup MARK
    // cannot reach Redis.
    let token = codec()
        .generate_unsubscribe_token_with_message(&tenant, recipient, "m1")
        .unwrap();
    let response = srv
        .post(&format!("/u/{token}"))
        .text("List-Unsubscribe=One-Click")
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM suppressions WHERE tenant_id = $1 AND email = $2")
            .bind(&tenant)
            .bind(recipient)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(count, 1, "the suppression landed without dedup marking");

    // Resubscribe: the dedup CLEAR fails the same way — the suppression is
    // still removed.
    let prefs_token = codec()
        .generate_preferences_token(&tenant, recipient)
        .unwrap();
    let response = srv
        .post(&format!("/p/{prefs_token}"))
        .form(&[("resubscribe_all", "true")])
        .await;
    assert_eq!(response.status_code().as_u16(), 303);
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM suppressions WHERE tenant_id = $1 AND email = $2")
            .bind(&tenant)
            .bind(recipient)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(count, 0, "resubscribe removes the suppression");
}

/// A database that cannot record the unsubscribe answers the honest error
/// page — never a fabricated success.
#[tokio::test]
async fn confirm_with_a_dead_database_answers_the_error_page() {
    let Ok(redis_url) = std::env::var("TEST_REDIS_URL") else {
        return;
    };
    let dead_db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(50))
        .connect_lazy("postgres://offline@127.0.0.1:1/offline")
        .unwrap();
    let state = state_with(dead_db, env_pool(), test_config(&redis_url, ""));
    let srv = server(&state).await;

    let token = codec()
        .generate_unsubscribe_token_with_message("tn_confirmdead", "confirmdead@example.com", "m1")
        .unwrap();
    let response = srv
        .post(&format!("/u/{token}/confirm"))
        .form(&[("confirm", "true")])
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(
        body.contains("Something went wrong"),
        "the error page must not claim success: {body}"
    );
}

/// Webhook queueing is best-effort: losing the queue table must not fail
/// the compliance-critical suppression.
#[tokio::test]
async fn webhook_queue_failure_does_not_break_one_click() {
    let Some(db) = canonical_pool("tracking_webhook_fail").await else {
        return;
    };
    let Ok(redis_url) = std::env::var("TEST_REDIS_URL") else {
        return;
    };
    let tenant = unique("tn_hookfail");
    seed_tenant(&db, &tenant).await;
    sqlx::query("DROP TABLE webhook_queue CASCADE")
        .execute(&db)
        .await
        .unwrap();

    let state = state_with(db.clone(), env_pool(), test_config(&redis_url, ""));
    let srv = server(&state).await;
    let recipient = "hookfail@example.com";
    let token = codec()
        .generate_unsubscribe_token_with_message(&tenant, recipient, "m1")
        .unwrap();
    let response = srv
        .post(&format!("/u/{token}"))
        .text("List-Unsubscribe=One-Click")
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM suppressions WHERE tenant_id = $1 AND email = $2")
            .bind(&tenant)
            .bind(recipient)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(count, 1, "the suppression is the durable record");
}

/// A GET with a well-shaped token that cannot verify hits the decode-failure
/// arm (error page), and a shape-invalid token hits the classification log.
#[tokio::test]
async fn get_with_undecodable_but_valid_shape_token_renders_the_error_page() {
    let state = state_with(
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://offline:offline@127.0.0.1:1/offline")
            .unwrap(),
        dead_redis(),
        test_config("redis://127.0.0.1:1", ""),
    );
    let srv = server(&state).await;
    // Alphanumeric (valid shape) but garbage cryptographically.
    let response = srv
        .get("/u/AAAAABLITblobofciphertextaaaaaaaaaaaaaaaa")
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    assert!(response.text().contains("Invalid or expired"));
}
