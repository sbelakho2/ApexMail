//! Adversarial tests for the unsubscribe/preferences handlers and their
//! helpers (routes/unsubscribe.rs).
//!
//! Proven here, against the canonical Postgres schema and the live test
//! Redis:
//! - Suppression-before-response: the 200/303 answers only ever follow a
//!   persisted suppression row (or its idempotent duplicate).
//! - Dedup keys are claim-after-record: a failed record is never swallowed
//!   by the 24h window; a stale key (left by a resubscribe) reconciles
//!   against the durable row.
//! - The preferences center persists consent (global unsubscribe,
//!   resubscribe, per-category) and validates hostile category payloads
//!   against the tenant's own active categories and the count cap.
//! - Hostile tokens are refused everywhere before any processing.
//! - Attribution falls back to exactly "unknown", never an invented id.
//! - Webhook fan-out writes one queue row per subscribed webhook.

use super::*;
use std::net::SocketAddr;
use std::time::Duration;

use crate::codec::TrackingCodec;
use crate::routes::{build_router, test_support};
use crate::state::AppState;

fn codec() -> TrackingCodec {
    TrackingCodec::new(test_support::TEST_SECRET)
}

fn legacy_token(tenant: &str, recipient: &str) -> String {
    codec()
        .generate_unsubscribe_token(tenant, recipient)
        .expect("legacy token")
}

fn v2_token(tenant: &str, recipient: &str, message_id: &str) -> String {
    codec()
        .generate_unsubscribe_token_with_message(tenant, recipient, message_id)
        .expect("v2 token")
}

fn prefs_token(tenant: &str, recipient: &str) -> String {
    codec()
        .generate_preferences_token(tenant, recipient)
        .expect("prefs token")
}

async fn server(state: &AppState) -> axum_test::TestServer {
    axum_test::TestServer::new(
        build_router(state.clone()).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .expect("test server")
}

fn unique(label: &str) -> String {
    // tenant_id is VARCHAR(26): keep discriminators short.
    let hex = uuid::Uuid::new_v4().simple().to_string();
    format!("{label}_{}", &hex[..10])
}

/// Rebuild a state with an explicit DB + Redis pair (dead-DB scenarios).
fn state_with_db(db: sqlx::PgPool, redis: deadpool_redis::Pool) -> AppState {
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
            url: std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:1".into()),
            key_prefix: "tracking:".into(),
            pool_size: 2,
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
        codec(),
        db,
        redis,
        processor,
        crate::bot::BotDetector::new(),
        cfg,
    )
}

fn over_cap_categories() -> Vec<(String, String)> {
    // Keys are well-formed `category_*` fields (the form parser drops
    // anything else before the cap is consulted): 51 parseable categories
    // exceed the F9 cap of 50.
    (0..51)
        .map(|i| (format!("category_junk_{i}"), "true".to_string()))
        .collect()
}

fn lazy_dead_db() -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(50))
        .connect_lazy("postgresql://offline@127.0.0.1:1/offline")
        .expect("lazy pool")
}

/// Live Redis + dead Postgres (fast-fail pool): for handler tests that
/// assert honest 5xx answers when the database cannot persist.
async fn live_redis_dead_db_state() -> Option<AppState> {
    let url = std::env::var("TEST_REDIS_URL").ok()?;
    let redis = deadpool_redis::Config::from_url(&url)
        .builder()
        .ok()?
        .max_size(2)
        .runtime(deadpool_redis::Runtime::Tokio1)
        .build()
        .ok()?;
    redis.get().await.ok()?; // prove the broker answers
    Some(state_with_db(lazy_dead_db(), redis))
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
        "INSERT INTO email_categories (id, tenant_id, name, description, active, display_order) \
         VALUES (gen_random_uuid(), $1, $2, $2, true, 1) ON CONFLICT DO NOTHING",
    )
    .bind(tenant)
    .bind(name)
    .execute(db)
    .await
    .expect("seed category");
}

async fn suppression_count(db: &sqlx::PgPool, tenant: &str, email: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM suppressions WHERE tenant_id=$1 AND email=$2")
        .bind(tenant)
        .bind(email)
        .fetch_one(db)
        .await
        .expect("suppression count")
}

async fn pref_value(db: &sqlx::PgPool, tenant: &str, email: &str, category: &str) -> Option<bool> {
    sqlx::query_as::<_, (bool,)>(
        "SELECT subscribed FROM subscription_preferences \
         WHERE tenant_id=$1 AND email=$2 AND category=$3",
    )
    .bind(tenant)
    .bind(email)
    .bind(category)
    .fetch_optional(db)
    .await
    .expect("pref lookup")
    .map(|(v,)| v)
}

async fn cleanup(db: &sqlx::PgPool, redis: &deadpool_redis::Pool, tenant: &str) {
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant)
        .execute(db)
        .await
        .ok();
    if let Ok(mut conn) = redis.get().await {
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(format!("unsub:dedup:{tenant}:user@example.com"))
            .query_async(&mut *conn)
            .await;
    }
}

// ── One-click POST: validation and failure honesty ──────────────────────────

#[tokio::test]
async fn one_click_rejects_invalid_tokens_and_wrong_bodies() {
    let state = test_support::offline_state(&[]);
    let srv = server(&state).await;

    // Shape-valid but undecodable token → 400 JSON, never a 500 or panic.
    let resp = srv
        .post(&format!("/u/{}", "Q".repeat(40)))
        .text("List-Unsubscribe=One-Click")
        .await;
    assert_eq!(resp.status_code().as_u16(), 400);
    assert!(resp.text().contains("Invalid or expired token"));

    // Wrong body → 400 (the RFC 8058 contract is exact).
    let token = legacy_token("tenant_x", "user@example.com");
    let resp = srv.post(&format!("/u/{token}")).text("bogus").await;
    assert_eq!(resp.status_code().as_u16(), 400);
    assert!(resp.text().contains("Invalid request body"));
}

#[tokio::test]
async fn one_click_answers_500_when_the_suppression_cannot_be_recorded() {
    // Live Redis (dedup check fails open → record proceeds) + a DEAD
    // Postgres → record_unsubscribe fails → the caller gets 500, NEVER a
    // fabricated success, and the dedup key is NOT claimed (the MUA retry
    // must be able to record once the DB recovers).
    let Some(state) = live_redis_dead_db_state().await else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let srv = server(&state).await;
    let tenant = unique("tn_500");
    let token = legacy_token(&tenant, "user@example.com");

    let resp = srv
        .post(&format!("/u/{token}"))
        .text("List-Unsubscribe=One-Click")
        .await;
    assert_eq!(
        resp.status_code().as_u16(),
        500,
        "a failed suppression must surface as 500"
    );

    // The dedup key was NOT claimed by the failed attempt.
    let mut conn = state.redis.get().await.expect("redis conn");
    let claimed: Option<String> = redis::cmd("GET")
        .arg(format!("unsub:dedup:{tenant}:user@example.com"))
        .query_async(&mut *conn)
        .await
        .expect("dedup get");
    assert_eq!(
        claimed, None,
        "F1: a failed record must not claim the dedup slot"
    );
}

#[tokio::test]
async fn confirm_endpoint_requires_the_form_field_and_a_valid_token() {
    let Some((state, _redis, _db)) = test_support::live_redis_pg_state(&[]).await else {
        eprintln!("skipping: set TEST_REDIS_URL + TEST_DATABASE_URL");
        return;
    };
    let srv = server(&state).await;
    let tenant = unique("tn_conf");

    // Invalid token → error page.
    let resp = srv
        .post(&format!("/u/{}/confirm", "Q".repeat(40)))
        .form(&[("confirm", "true")])
        .await;
    assert!(resp.text().contains("Invalid or expired"));

    // Valid token but missing the confirm field → refused.
    let token = legacy_token(&tenant, "user@example.com");
    let resp = srv
        .post(&format!("/u/{token}/confirm"))
        .form(&[("nope", "1")])
        .await;
    assert!(resp.text().contains("Invalid confirmation request"));
}

// ── Dedup helper failure arms ───────────────────────────────────────────────

#[tokio::test]
async fn dedup_check_fails_open_on_redis_and_database_errors() {
    // Dead Redis: the pool GET fails → record anyway (false).
    let offline = test_support::offline_state(&[]);
    assert!(
        !is_unsub_duplicate(&offline, "tn", "User@Example.com").await,
        "Redis outage must fail OPEN (recording proceeds)"
    );
    // Best-effort mark/clear with a dead Redis must not panic.
    mark_unsub_dedup(&offline, "tn", "user@example.com").await;
    clear_unsub_dedup(&offline, "tn", "user@example.com").await;

    let Some((state, redis)) = test_support::live_redis_state(&[]).await else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let tenant = unique("tn_dup");

    // GET against a LIST-typed key raises WRONGTYPE → fail open.
    {
        let mut conn = redis.get().await.expect("conn");
        redis::cmd("DEL")
            .arg(format!("unsub:dedup:{tenant}:user@example.com"))
            .query_async::<()>(&mut *conn)
            .await
            .ok();
        redis::cmd("RPUSH")
            .arg(format!("unsub:dedup:{tenant}:user@example.com"))
            .arg("x")
            .query_async::<()>(&mut *conn)
            .await
            .expect("seed list key");
    }
    assert!(
        !is_unsub_duplicate(&state, &tenant, "user@example.com").await,
        "a broken dedup key must fail open"
    );

    // Key present ("suppressed") but the DB cannot answer → fail open.
    {
        let mut conn = redis.get().await.expect("conn");
        redis::cmd("DEL")
            .arg(format!("unsub:dedup:{tenant}:user@example.com"))
            .query_async::<()>(&mut *conn)
            .await
            .ok();
        redis::cmd("SET")
            .arg(format!("unsub:dedup:{tenant}:user@example.com"))
            .arg("suppressed")
            .query_async::<()>(&mut *conn)
            .await
            .expect("seed dedup key");
    }
    let dead_db_state = {
        // Same live Redis, dead Postgres.
        state_with_db(lazy_dead_db(), state.redis.clone())
    };
    assert!(
        !is_unsub_duplicate(&dead_db_state, &tenant, "user@example.com").await,
        "a DB that cannot confirm the suppression must fail open"
    );

    // Key present, DB answers "no suppression row" (stale key after a
    // resubscribe) → the key is cleared and the request re-records.
    let Some((live_state, _redis2, _db)) = test_support::live_redis_pg_state(&[]).await else {
        eprintln!("skipping: set TEST_DATABASE_URL");
        return;
    };
    assert!(
        !is_unsub_duplicate(&live_state, &tenant, "user@example.com").await,
        "stale key (no durable row) must not count as a duplicate"
    );
    let mut conn = redis.get().await.expect("conn");
    let cleared: Option<String> = redis::cmd("GET")
        .arg(format!("unsub:dedup:{tenant}:user@example.com"))
        .query_async(&mut *conn)
        .await
        .expect("get after clear");
    assert_eq!(cleared, None, "the stale key was reconciled (cleared)");
}

// ── Preferences center (live DB) ────────────────────────────────────────────

#[tokio::test]
async fn preferences_center_round_trips_consent_and_validates_hostile_payloads() {
    let Some((state, redis, db)) = test_support::live_redis_pg_state(&[]).await else {
        eprintln!("skipping: set TEST_REDIS_URL + TEST_DATABASE_URL");
        return;
    };
    let srv = server(&state).await;
    let tenant = unique("tn_prefs");
    let email = "user@example.com";
    seed_tenant(&db, &tenant).await;
    seed_category(&db, &tenant, "marketing").await;
    seed_category(&db, &tenant, "product").await;

    // GET with an invalid token → error page, never a panic.
    let resp = srv.get(&format!("/p/{}", "Q".repeat(40))).await;
    assert!(resp.text().contains("Invalid or expired preferences link"));

    // GET with a valid token renders the form with the tenant's categories
    // (all default-subscribed, none globally suppressed yet).
    let ptok = prefs_token(&tenant, email);
    let resp = srv.get(&format!("/p/{ptok}")).await;
    let body = resp.text();
    assert!(body.contains("marketing"), "{body}");
    assert!(body.contains("product"), "{body}");

    // (1) Global unsubscribe via the preferences center → 303 redirect,
    //     suppression persisted, dedup key claimed.
    let resp = srv
        .post(&format!("/p/{ptok}"))
        .form(&[("unsubscribe_all", "true")])
        .await;
    assert_eq!(resp.status_code().as_u16(), 303);
    assert_eq!(
        suppression_count(&db, &tenant, email).await,
        1,
        "suppression-before-response"
    );
    let mut conn = redis.get().await.expect("redis conn");
    let marked: Option<String> = redis::cmd("GET")
        .arg(format!("unsub:dedup:{tenant}:{email}"))
        .query_async(&mut *conn)
        .await
        .expect("dedup get");
    assert_eq!(marked.as_deref(), Some("suppressed"));

    // The preferences page now shows the global suppression.
    let resp = srv.get(&format!("/p/{ptok}")).await;
    let body = resp.text();
    assert!(
        body.to_lowercase().contains("unsubscribed"),
        "globally-unsubscribed state must render: {body}"
    );

    // (2) Resubscribe → suppression removed, dedup key cleared.
    let resp = srv
        .post(&format!("/p/{ptok}"))
        .form(&[("resubscribe_all", "true")])
        .await;
    assert_eq!(resp.status_code().as_u16(), 303);
    assert_eq!(suppression_count(&db, &tenant, email).await, 0);
    let mut conn = redis.get().await.expect("redis conn");
    let cleared: Option<String> = redis::cmd("GET")
        .arg(format!("unsub:dedup:{tenant}:{email}"))
        .query_async(&mut *conn)
        .await
        .expect("dedup get");
    assert_eq!(cleared, None, "resubscribe must clear the dedup key");

    // (3) Category updates persist through the batch upsert.
    let resp = srv
        .post(&format!("/p/{ptok}"))
        .form(&[
            ("category_marketing", "false"),
            ("category_product", "true"),
        ])
        .await;
    assert_eq!(resp.status_code().as_u16(), 303);
    assert_eq!(
        pref_value(&db, &tenant, email, "marketing").await,
        Some(false)
    );
    assert_eq!(pref_value(&db, &tenant, email, "product").await, Some(true));

    // (3b) Re-posting flips only the submitted categories (upsert).
    let resp = srv
        .post(&format!("/p/{ptok}"))
        .form(&[("category_marketing", "true")])
        .await;
    assert_eq!(resp.status_code().as_u16(), 303);
    assert_eq!(
        pref_value(&db, &tenant, email, "marketing").await,
        Some(true)
    );
    assert_eq!(pref_value(&db, &tenant, email, "product").await, Some(true));

    // (4) Hostile payloads are refused: unknown categories and over-cap
    //     submissions never write.
    let resp = srv
        .post(&format!("/p/{ptok}"))
        .form(&[("category_totally-made-up", "true")])
        .await;
    assert_eq!(resp.status_code().as_u16(), 400);
    let resp = srv
        .post(&format!("/p/{ptok}"))
        .form(&over_cap_categories())
        .await;
    assert_eq!(resp.status_code().as_u16(), 400);
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM subscription_preferences WHERE tenant_id=$1")
            .bind(&tenant)
            .fetch_one(&db)
            .await
            .expect("pref count");
    assert_eq!(count, 2, "hostile payloads wrote nothing");

    // (5) POST with an invalid token → 400 JSON.
    let resp = srv
        .post(&format!("/p/{}", "Q".repeat(40)))
        .form(&[("unsubscribe_all", "true")])
        .await;
    assert_eq!(resp.status_code().as_u16(), 400);

    cleanup(&db, &redis, &tenant).await;
}

#[tokio::test]
async fn preferences_center_answers_5xx_when_the_database_cannot_persist() {
    // Live Redis only; Postgres is dead → the global-unsubscribe POST must
    // answer 500 instead of a fabricated success.
    let Some(state) = live_redis_dead_db_state().await else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let srv = server(&state).await;
    let tenant = unique("tn_prefs500");
    let ptok = prefs_token(&tenant, "user@example.com");
    let resp = srv
        .post(&format!("/p/{ptok}"))
        .form(&[("unsubscribe_all", "true")])
        .await;
    assert_eq!(
        resp.status_code().as_u16(),
        500,
        "CRITICAL: a failed suppression insert must not answer success"
    );

    // Same for the resubscribe path (the DELETE fails).
    let resp = srv
        .post(&format!("/p/{ptok}"))
        .form(&[("resubscribe_all", "true")])
        .await;
    assert_eq!(resp.status_code().as_u16(), 500);

    // And the category path fails closed when the tenant's category list
    // cannot be loaded.
    let resp = srv
        .post(&format!("/p/{ptok}"))
        .form(&[("category_marketing", "true")])
        .await;
    assert_eq!(resp.status_code().as_u16(), 500);
}

#[tokio::test]
async fn prefs_get_renders_an_error_page_when_the_database_fails() {
    let Some(state) = live_redis_dead_db_state().await else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let srv = server(&state).await;
    let ptok = prefs_token(&unique("tn_pgerr"), "user@example.com");
    let resp = srv.get(&format!("/p/{ptok}")).await;
    assert!(resp.text().contains("Unable to load preferences"));
}

// ── Attribution and webhook fan-out (live DB) ───────────────────────────────

#[tokio::test]
async fn attribution_falls_back_to_unknown_and_webhooks_are_enqueued_per_subscriber() {
    let Some((state, _redis, db)) = test_support::live_redis_pg_state(&[]).await else {
        eprintln!("skipping: set TEST_REDIS_URL + TEST_DATABASE_URL");
        return;
    };
    let srv = server(&state).await;
    let tenant = unique("tn_attr");
    seed_tenant(&db, &tenant).await;

    // (1) A v2 token whose embedded message id is unusable (over the
    //     VARCHAR(64) event bound) falls back to recipient resolution.
    let oversized = "m".repeat(65);
    let data = codec()
        .verify_unsubscribe_token(&v2_token(&tenant, "user@example.com", &oversized), None)
        .expect("v2 token with an oversized id still decodes");
    assert_eq!(data.message_id.as_deref(), Some(oversized.as_str()));
    // ...and resolution through the resolver caps it to the DB lookup,
    // which for an unknown recipient answers exactly "unknown".
    let resolved = resolve_message_id(&state, &data).await;
    assert_eq!(resolved, UNKNOWN_MESSAGE_ID);

    // (2) With a dead database the resolver also answers "unknown" instead
    //     of inventing an id. (Fast-fail dead pool — 50ms, not sqlx's 30s
    //     default acquire timeout.)
    let offline = state_with_db(
        lazy_dead_db(),
        deadpool_redis::Config::from_url("redis://127.0.0.1:1")
            .builder()
            .expect("builder")
            .max_size(1)
            .runtime(deadpool_redis::Runtime::Tokio1)
            .build()
            .expect("dead redis"),
    );
    let resolved = resolve_message_id(
        &offline,
        &crate::codec::UnsubscribeData {
            tenant_id: tenant.clone(),
            recipient: "user@example.com".into(),
            timestamp_ms: 0,
            message_id: None,
        },
    )
    .await;
    assert_eq!(resolved, UNKNOWN_MESSAGE_ID);

    // (3) Webhook fan-out: one subscribed webhook → one queue row.
    let webhook_id = format!("wh{}", &uuid::Uuid::new_v4().simple().to_string()[..23]);
    sqlx::query(
        "INSERT INTO webhooks (id, tenant_id, name, url, secret, events, enabled, status) \
         VALUES ($1, $2, 'w', 'https://hooks.example/x', 's', '[\"recipient.unsubscribed\"]'::jsonb, true, 'active')",
    )
    .bind(&webhook_id)
    .bind(&tenant)
    .execute(&db)
    .await
    .expect("seed webhook");
    let token = legacy_token(&tenant, "user@example.com");
    let resp = srv
        .post(&format!("/u/{token}"))
        .text("List-Unsubscribe=One-Click")
        .await;
    assert_eq!(resp.status_code().as_u16(), 200);
    let mut queued = 0i64;
    for _ in 0..30 {
        queued = sqlx::query_scalar(
            "SELECT COUNT(*) FROM webhook_queue WHERE tenant_id=$1 AND event_type='recipient.unsubscribed'",
        )
        .bind(&tenant)
        .fetch_one(&db)
        .await
        .unwrap_or(0);
        if queued >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert_eq!(queued, 1, "one subscriber → one queue row");
    let payload: (String,) = sqlx::query_as(
        "SELECT payload::text FROM webhook_queue WHERE tenant_id=$1 AND event_type='recipient.unsubscribed'",
    )
    .bind(&tenant)
    .fetch_one(&db)
    .await
    .expect("queue row");
    assert!(payload.0.contains(&tenant), "{}", payload.0);
    assert!(payload.0.contains("one-click"), "{}", payload.0);
}

#[tokio::test]
async fn webhook_fanout_with_no_subscribers_is_a_noop() {
    let Some((_state, _redis, db)) = test_support::live_redis_pg_state(&[]).await else {
        eprintln!("skipping: set TEST_REDIS_URL + TEST_DATABASE_URL");
        return;
    };
    let tenant = unique("tn_nowh");
    // queue_unsub_webhook with zero subscribers returns Ok without writing.
    let state = state_with_db(
        db.clone(),
        test_support::live_redis_state(&[]).await.unwrap().1,
    );
    queue_unsub_webhook(&state, &tenant, "user@example.com", "one-click")
        .await
        .expect("no subscribers → ok");
    let queued: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhook_queue WHERE tenant_id=$1")
        .bind(&tenant)
        .fetch_one(&db)
        .await
        .expect("count");
    assert_eq!(queued, 0);
}

// ── Dedup short-circuit (duplicate confirmation) ────────────────────────────

#[tokio::test]
async fn duplicate_confirm_answers_success_without_re_recording() {
    let Some((state, redis, db)) = test_support::live_redis_pg_state(&[]).await else {
        eprintln!("skipping: set TEST_REDIS_URL + TEST_DATABASE_URL");
        return;
    };
    let srv = server(&state).await;
    let tenant = unique("tn_dupconf");
    let email = "user@example.com";
    seed_tenant(&db, &tenant).await;

    // Durable suppression + claimed dedup key = a genuine prior unsubscribe.
    sqlx::query(
        "INSERT INTO suppressions (id, tenant_id, email, reason, subtype, created_at) \
         VALUES ('sup_duplicateprobe000000', $1, $2, 'unsubscribe', 'one-click', NOW()) \
         ON CONFLICT (tenant_id, email) DO NOTHING",
    )
    .bind(&tenant)
    .bind(email)
    .execute(&db)
    .await
    .expect("seed suppression");
    {
        let mut conn = redis.get().await.expect("conn");
        redis::cmd("SET")
            .arg(format!("unsub:dedup:{tenant}:{email}"))
            .arg("suppressed")
            .query_async::<()>(&mut *conn)
            .await
            .expect("seed dedup key");
    }

    let token = legacy_token(&tenant, email);

    // One-click duplicate → success without a second event.
    let resp = srv
        .post(&format!("/u/{token}"))
        .text("List-Unsubscribe=One-Click")
        .await;
    assert_eq!(resp.status_code().as_u16(), 200);

    // Confirm duplicate → success page without re-recording.
    let resp = srv
        .post(&format!("/u/{token}/confirm"))
        .form(&[("confirm", "true")])
        .await;
    assert!(resp.text().contains("been unsubscribed"));

    // Exactly one suppression row remains (idempotent, not duplicated).
    assert_eq!(suppression_count(&db, &tenant, email).await, 1);

    cleanup(&db, &redis, &tenant).await;
}
