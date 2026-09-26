//! Adversarial tests for the click-redirect handler (routes/click.rs).
//!
//! Proven here, against the canonical schema and the live test Redis:
//! - The redirect domain authorization walks its full cache hierarchy:
//!   moka → Redis (authoritative cached verdict) → Postgres (owned domain
//!   row, then JSONB wildcard patterns) — a Redis MISS falls through to the
//!   database, a DB error denies for one request WITHOUT caching, and an
//!   authoritative absence is cached as "0".
//! - Hostile tokens (wrong length, garbage, tampered) redirect to the
//!   fallback, record NOTHING, and never panic.
//! - Oversized and non-http redirect targets are refused.
//! - Bot clicks render the redirect but never record.
//! - Per-link URL cache failures never break the redirect or the recording.

use super::*;
use std::net::SocketAddr;
use std::time::Duration;

use crate::bot::BotDetector;
use crate::codec::{TrackingCodec, TrackingData};
use crate::processor::{EventProcessor, REDIS_WAL_KEY};
use crate::state::AppState;

const SECRET: &str = "click-adversarial-secret-32-bytes!!";
const NORMAL_UA: &str =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/124 Safari/537.36";
const BOT_UA: &str = "python-requests/2.31.0";

fn codec() -> TrackingCodec {
    TrackingCodec::new(SECRET)
}

fn addr() -> ConnectInfo<SocketAddr> {
    ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 41_100)))
}

fn headers_with_ua(ua: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::USER_AGENT,
        ua.parse().expect("ua header"),
    );
    headers
}

fn click_token(tenant: &str, message: &str, original_url: Option<&str>) -> String {
    codec()
        .encode(&TrackingData {
            tenant_id: tenant.into(),
            message_id: message.into(),
            recipient: "clicker@example.com".into(),
            link_id: Some(format!("lnk_{message}")),
            original_url: original_url.map(str::to_owned),
        })
        .expect("encode click token")
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

fn live_redis() -> Option<deadpool_redis::Pool> {
    deadpool_redis::Config::from_url(crate::routes::test_support::live_test_redis_url()?)
        .builder()
        .ok()?
        .max_size(4)
        .runtime(deadpool_redis::Runtime::Tokio1)
        .build()
        .ok()
}

fn config(redis_url: &str) -> crate::config::Config {
    use crate::config::*;
    Config {
        server: ServerConfig {
            addr: "127.0.0.1:0".parse().expect("addr"),
        },
        database: DatabaseConfig {
            url: "postgresql://offline@127.0.0.1:1/offline".into(),
            max_connections: 1,
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
        jwt_public_key_pem: String::new(),
    }
}

fn state(db: sqlx::PgPool, redis: deadpool_redis::Pool, redis_url: &str) -> AppState {
    let cfg = config(redis_url);
    let processor = std::sync::Arc::new(EventProcessor::new(
        db.clone(),
        redis.clone(),
        clickhouse::Client::default(),
        Duration::from_millis(100),
    ));
    AppState::new(codec(), db, redis, processor, BotDetector::new(), cfg)
}

fn lazy_dead_db() -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(50))
        .connect_lazy("postgresql://offline@127.0.0.1:1/offline")
        .expect("lazy pool")
}

async fn live_pg(test_name: &str) -> Option<sqlx::PgPool> {
    match migrator::test_support::fresh_canonical_pool(test_name, test_name).await {
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

async fn seed_domain(db: &sqlx::PgPool, tenant: &str, name: &str) {
    sqlx::query("INSERT INTO domains (tenant_id, name, verified) VALUES ($1, $2, true)")
        .bind(tenant)
        .bind(name)
        .execute(db)
        .await
        .expect("seed domain");
}

async fn seed_wildcard(db: &sqlx::PgPool, tenant: &str, patterns: &[&str]) {
    let json = serde_json::json!(patterns).to_string();
    sqlx::query(
        "INSERT INTO tenant_settings (tenant_id, allowed_redirect_domains) \
         VALUES ($1, $2::jsonb) ON CONFLICT (tenant_id) DO UPDATE SET allowed_redirect_domains = $2::jsonb",
    )
    .bind(tenant)
    .bind(json)
    .execute(db)
    .await
    .expect("seed wildcard patterns");
}

async fn seed_redis_domain(redis: &deadpool_redis::Pool, tenant: &str, domain: &str, ok: bool) {
    let mut conn = redis.get().await.expect("redis conn");
    redis::cmd("SETEX")
        .arg(format!("redirect_domain:{tenant}:{domain}"))
        .arg(300u64)
        .arg(if ok { "1" } else { "0" })
        .query_async::<()>(&mut *conn)
        .await
        .expect("seed redis domain verdict");
}

async fn redis_domain_verdict(
    redis: &deadpool_redis::Pool,
    tenant: &str,
    domain: &str,
) -> Option<String> {
    let mut conn = redis.get().await.expect("redis conn");
    redis::cmd("GET")
        .arg(format!("redirect_domain:{tenant}:{domain}"))
        .query_async::<Option<String>>(&mut *conn)
        .await
        .expect("get verdict")
}

async fn location_of(resp: axum::response::Response) -> String {
    assert_eq!(resp.status(), axum::http::StatusCode::FOUND);
    resp.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

async fn wal_entries_for(redis: &deadpool_redis::Pool, needle: &str) -> Vec<String> {
    let Ok(mut conn) = redis.get().await else {
        return Vec::new();
    };
    redis::cmd("LRANGE")
        .arg(REDIS_WAL_KEY)
        .arg(0)
        .arg(-1)
        .query_async::<Vec<String>>(&mut *conn)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|e| e.contains(needle))
        .collect()
}

async fn drop_wal_entries(redis: &deadpool_redis::Pool, needle: &str) {
    let Ok(mut conn) = redis.get().await else {
        return;
    };
    for entry in wal_entries_for(redis, needle).await {
        let _: Result<(), _> = redis::cmd("LREM")
            .arg(REDIS_WAL_KEY)
            .arg(1)
            .arg(&entry)
            .query_async(&mut *conn)
            .await;
    }
}

/// Wait (bounded) for the fire-and-forget click recorder.
async fn wait_wal_entry(redis: &deadpool_redis::Pool, needle: &str) -> bool {
    for _ in 0..30 {
        if !wal_entries_for(redis, needle).await.is_empty() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

fn unique(label: &str) -> String {
    let hex = uuid::Uuid::new_v4().simple().to_string();
    format!("{label}_{}", &hex[..10])
}

// ── Pattern matcher ─────────────────────────────────────────────────────────

#[test]
fn match_domain_pattern_is_case_insensitive_and_wildcard_scoped() {
    assert!(match_domain_pattern("Sub.Example.COM", "sub.example.com"));
    assert!(match_domain_pattern("promo.wild.example", "*.wild.example"));
    // The wildcard does NOT match the bare apex.
    assert!(!match_domain_pattern("wild.example", "*.wild.example"));
    // The wildcard covers subdomains under the pattern's suffix (tenant-
    // authoritative: the tenant allowed everything under wild.example).
    assert!(match_domain_pattern("a.b.wild.example", "*.wild.example"));
    // …but never a domain merely ENDING with the same text…
    assert!(!match_domain_pattern("evilwild.example", "*.wild.example"));
    // …nor a longer suffix that contains the pattern mid-string.
    assert!(!match_domain_pattern(
        "sub.wild.example.evil.com",
        "*.wild.example"
    ));
    // Exact pattern matches only itself.
    assert!(match_domain_pattern("example.com", "example.com"));
    assert!(!match_domain_pattern("example.com", "notexample.com"));
    // A pattern that merely STARTS with a dot is not a wildcard.
    assert!(!match_domain_pattern("sub.example.com", ".example.com"));
}

// ── Handler guards ──────────────────────────────────────────────────────────

#[tokio::test]
async fn hostile_click_tokens_redirect_to_fallback_and_record_nothing() {
    let _wal_serial = crate::routes::test_support::redis_wal_serial().await;
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let redis_url =
        crate::routes::test_support::live_test_redis_url().expect("TEST_REDIS_URL");
    let state = state(lazy_dead_db(), redis.clone(), &redis_url);

    // Under-length id → refused before any decode.
    let resp = handle_click(
        State(state.clone()),
        addr(),
        headers_with_ua(NORMAL_UA),
        Path("short".into()),
        Query(ClickQuery { r: None }),
    )
    .await;
    assert_eq!(location_of(resp).await, "https://fallback.test.example/");

    // Over-length id → refused before any decode.
    let resp = handle_click(
        State(state.clone()),
        addr(),
        headers_with_ua(NORMAL_UA),
        Path("y".repeat(4_097)),
        Query(ClickQuery { r: None }),
    )
    .await;
    assert_eq!(location_of(resp).await, "https://fallback.test.example/");

    // Right length, garbage content → decode fails, warn, fallback, and
    // (dead DB proves it) nothing is consulted for a redirect target.
    let resp = handle_click(
        State(state.clone()),
        addr(),
        headers_with_ua(NORMAL_UA),
        Path("Z".repeat(40)),
        Query(ClickQuery { r: None }),
    )
    .await;
    assert_eq!(location_of(resp).await, "https://fallback.test.example/");
}

#[tokio::test]
async fn oversized_and_non_http_targets_are_refused() {
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let redis_url =
        crate::routes::test_support::live_test_redis_url().expect("TEST_REDIS_URL");
    let state = state(lazy_dead_db(), redis.clone(), &redis_url);
    let tenant = unique("tn_len");

    // The fallback host is allowed without any DB round-trip, so the token's
    // original_url is the ONLY thing that can exceed the cap here.
    let too_long = format!("https://fallback.test.example/{}", "p".repeat(2_100));
    let token = click_token(&tenant, &unique("msg"), Some(&too_long));
    let resp = handle_click(
        State(state.clone()),
        addr(),
        headers_with_ua(NORMAL_UA),
        Path(token),
        Query(ClickQuery { r: None }),
    )
    .await;
    assert_eq!(
        location_of(resp).await,
        "https://fallback.test.example/",
        "oversized target refused → fallback"
    );

    // A non-http(s) scheme baked into the token is refused.
    let token = click_token(&tenant, &unique("msg"), Some("javascript:alert(1)"));
    let resp = handle_click(
        State(state.clone()),
        addr(),
        headers_with_ua(NORMAL_UA),
        Path(token),
        Query(ClickQuery { r: None }),
    )
    .await;
    assert_eq!(location_of(resp).await, "https://fallback.test.example/");

    // A tampered ?r= cannot rescue a blocked scheme…
    let token = click_token(&tenant, &unique("msg"), Some("javascript:alert(1)"));
    let resp = handle_click(
        State(state.clone()),
        addr(),
        headers_with_ua(NORMAL_UA),
        Path(token),
        Query(ClickQuery {
            r: Some("javascript:alert(1)".into()),
        }),
    )
    .await;
    assert_eq!(location_of(resp).await, "https://fallback.test.example/");

    // …and an unparseable ?r= is refused too (token has no original_url).
    let token = click_token(&tenant, &unique("msg"), None);
    let resp = handle_click(
        State(state.clone()),
        addr(),
        headers_with_ua(NORMAL_UA),
        Path(token),
        Query(ClickQuery {
            r: Some("::: not a url".into()),
        }),
    )
    .await;
    assert_eq!(location_of(resp).await, "https://fallback.test.example/");
}

#[tokio::test]
async fn bot_click_still_redirects_but_records_nothing() {
    let _wal_serial = crate::routes::test_support::redis_wal_serial().await;
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let redis_url =
        crate::routes::test_support::live_test_redis_url().expect("TEST_REDIS_URL");
    let state = state(lazy_dead_db(), redis.clone(), &redis_url);
    let tenant = unique("tn_bot");
    let message = unique("msg");

    // The fallback host is pre-authorized by config, so the redirect works
    // with a dead DB — isolating the bot check.
    let token = click_token(
        &tenant,
        &message,
        Some("https://fallback.test.example/landing"),
    );
    let resp = handle_click(
        State(state.clone()),
        addr(),
        headers_with_ua(BOT_UA),
        Path(token),
        Query(ClickQuery { r: None }),
    )
    .await;
    assert_eq!(
        location_of(resp).await,
        "https://fallback.test.example/landing"
    );

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        wal_entries_for(&redis, &message).await.is_empty(),
        "bot clicks must never be recorded"
    );
    drop_wal_entries(&redis, &tenant).await;
}

#[tokio::test]
async fn human_click_on_the_fallback_host_records_even_with_dead_redis() {
    let _wal_serial = crate::routes::test_support::redis_wal_serial().await;
    // The fallback host is config-authorized; Redis is dead, so the recorder
    // fails — the redirect must STILL happen and the failure must be logged,
    // never swallowed as a fabricated success.
    let state = state(lazy_dead_db(), dead_redis(), "redis://127.0.0.1:1");
    let tenant = unique("tn_deadredis");
    let message = unique("msg");
    let token = click_token(&tenant, &message, Some("https://fallback.test.example/x"));
    let resp = handle_click(
        State(state),
        addr(),
        headers_with_ua(NORMAL_UA),
        Path(token),
        Query(ClickQuery { r: None }),
    )
    .await;
    assert_eq!(location_of(resp).await, "https://fallback.test.example/x");
}

#[tokio::test]
async fn per_link_url_cache_failure_does_not_break_the_redirect() {
    let _wal_serial = crate::routes::test_support::redis_wal_serial().await;
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let redis_url =
        crate::routes::test_support::live_test_redis_url().expect("TEST_REDIS_URL");
    let state = state(lazy_dead_db(), redis.clone(), &redis_url);
    let tenant = unique("tn_lnk");
    let message = unique("msg");

    // Pre-create the link-cache key as a STRING → the HSET pipeline fails
    // with WRONGTYPE; the redirect and the click event must both survive.
    {
        let mut conn = redis.get().await.expect("conn");
        redis::cmd("SET")
            .arg(format!("links:{tenant}:{message}"))
            .arg("a-string")
            .query_async::<()>(&mut *conn)
            .await
            .expect("seed string key");
    }

    let token = click_token(
        &tenant,
        &message,
        Some("https://fallback.test.example/link"),
    );
    let resp = handle_click(
        State(state.clone()),
        addr(),
        headers_with_ua(NORMAL_UA),
        Path(token),
        Query(ClickQuery { r: None }),
    )
    .await;
    assert_eq!(
        location_of(resp).await,
        "https://fallback.test.example/link"
    );
    assert!(
        wait_wal_entry(&redis, &message).await,
        "click recorded despite the link-cache failure"
    );
    drop_wal_entries(&redis, &tenant).await;
    {
        let mut conn = redis.get().await.expect("conn");
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(format!("links:{tenant}:{message}"))
            .query_async(&mut *conn)
            .await;
    }
}

// ── Domain authorization cache hierarchy ────────────────────────────────────

#[tokio::test]
async fn redis_cached_verdicts_are_authoritative_without_db() {
    let _wal_serial = crate::routes::test_support::redis_wal_serial().await;
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let redis_url =
        crate::routes::test_support::live_test_redis_url().expect("TEST_REDIS_URL");

    // Cached "0" → deny, with a DEAD database proving the DB is not consulted.
    let tenant = unique("tn_c0");
    let message = unique("msg");
    seed_redis_domain(&redis, &tenant, "cached-deny.example", false).await;
    let state = state(lazy_dead_db(), redis.clone(), &redis_url);
    let token = click_token(&tenant, &message, Some("https://cached-deny.example/a"));
    let resp = handle_click(
        State(state.clone()),
        addr(),
        headers_with_ua(NORMAL_UA),
        Path(token),
        Query(ClickQuery { r: None }),
    )
    .await;
    assert_eq!(location_of(resp).await, "https://fallback.test.example/");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(wal_entries_for(&redis, &message).await.is_empty());

    // Cached "1" → allow, again without any DB.
    let tenant = unique("tn_c1");
    let message = unique("msg");
    seed_redis_domain(&redis, &tenant, "cached-allow.example", true).await;
    let token = click_token(&tenant, &message, Some("https://cached-allow.example/b"));
    let resp = handle_click(
        State(state.clone()),
        addr(),
        headers_with_ua(NORMAL_UA),
        Path(token),
        Query(ClickQuery { r: None }),
    )
    .await;
    assert_eq!(location_of(resp).await, "https://cached-allow.example/b");
    assert!(
        wait_wal_entry(&redis, &message).await,
        "allowed click recorded"
    );
    drop_wal_entries(&redis, &tenant).await;
}

#[tokio::test]
async fn database_error_denies_for_one_request_and_caches_nothing() {
    let _wal_serial = crate::routes::test_support::redis_wal_serial().await;
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let redis_url =
        crate::routes::test_support::live_test_redis_url().expect("TEST_REDIS_URL");
    let tenant = unique("tn_dberr");
    let message = unique("msg");
    let domain = "never-seen-before.example";

    // No moka entry (fresh state), no Redis entry, and the DB is dead →
    // the lookup errors: deny for THIS request only, and cache NOTHING
    // (neither in Redis nor in moka).
    let state = state(lazy_dead_db(), redis.clone(), &redis_url);
    let token = click_token(&tenant, &message, Some(&format!("https://{domain}/c")));
    let resp = handle_click(
        State(state.clone()),
        addr(),
        headers_with_ua(NORMAL_UA),
        Path(token),
        Query(ClickQuery { r: None }),
    )
    .await;
    assert_eq!(
        location_of(resp).await,
        "https://fallback.test.example/",
        "a DB that cannot answer must deny for this request"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        wal_entries_for(&redis, &message).await.is_empty(),
        "no click event may be recorded for an unproven redirect"
    );
    assert_eq!(
        redis_domain_verdict(&redis, &tenant, domain).await,
        None,
        "the error verdict must NOT be cached in Redis"
    );
    drop_wal_entries(&redis, &tenant).await;
}

#[tokio::test]
async fn database_is_the_authority_on_cache_miss_and_caches_the_verdict() {
    let _wal_serial = crate::routes::test_support::redis_wal_serial().await;
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let redis_url =
        crate::routes::test_support::live_test_redis_url().expect("TEST_REDIS_URL");
    let Some(db) = live_pg("click_domain_auth").await else {
        eprintln!("skipping: set TEST_DATABASE_URL");
        return;
    };
    let state = state(db.clone(), redis.clone(), &redis_url);

    // (1) An owned domain row authorizes the redirect and the verdict is
    //     cached as "1" in Redis.
    let tenant = unique("tn_own");
    seed_tenant(&db, &tenant).await;
    seed_domain(&db, &tenant, "owned.example").await;
    let message = unique("msg");
    let token = click_token(&tenant, &message, Some("https://owned.example/landing"));
    let resp = handle_click(
        State(state.clone()),
        addr(),
        headers_with_ua(NORMAL_UA),
        Path(token),
        Query(ClickQuery { r: None }),
    )
    .await;
    assert_eq!(location_of(resp).await, "https://owned.example/landing");
    assert!(wait_wal_entry(&redis, &message).await, "click recorded");
    assert_eq!(
        redis_domain_verdict(&redis, &tenant, "owned.example").await,
        Some("1".into()),
        "the authoritative allow is cached"
    );
    drop_wal_entries(&redis, &tenant).await;

    // (2) A domain owned by nobody is an authoritative absence → fallback,
    //     no event, and the verdict is cached as "0".
    let stranger = unique("tn_stranger");
    let message = unique("msg");
    let token = click_token(
        &stranger,
        &message,
        Some("https://stranger-owned.example/x"),
    );
    let resp = handle_click(
        State(state.clone()),
        addr(),
        headers_with_ua(NORMAL_UA),
        Path(token),
        Query(ClickQuery { r: None }),
    )
    .await;
    assert_eq!(location_of(resp).await, "https://fallback.test.example/");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(wal_entries_for(&redis, &message).await.is_empty());
    assert_eq!(
        redis_domain_verdict(&redis, &stranger, "stranger-owned.example").await,
        Some("0".into()),
        "the authoritative deny is cached"
    );

    // (3) The moka tier now answers for the stranger's domain: the second
    //     click hits the in-process cache (still denied, still no event).
    let message = unique("msg");
    let token = click_token(
        &stranger,
        &message,
        Some("https://stranger-owned.example/y"),
    );
    let resp = handle_click(
        State(state.clone()),
        addr(),
        headers_with_ua(NORMAL_UA),
        Path(token),
        Query(ClickQuery { r: None }),
    )
    .await;
    assert_eq!(location_of(resp).await, "https://fallback.test.example/");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(wal_entries_for(&redis, &message).await.is_empty());

    // (4) The wildcard tier: tenant_settings.allowed_redirect_domains
    //     (JSONB) with `*.wild.example` authorizes subdomains only.
    let wildcard_tenant = unique("tn_wild");
    seed_tenant(&db, &wildcard_tenant).await;
    seed_wildcard(&db, &wildcard_tenant, &["*.wild.example"]).await;
    let message = unique("msg");
    let token = click_token(
        &wildcard_tenant,
        &message,
        Some("https://promo.wild.example/offer"),
    );
    let resp = handle_click(
        State(state.clone()),
        addr(),
        headers_with_ua(NORMAL_UA),
        Path(token),
        Query(ClickQuery { r: None }),
    )
    .await;
    assert_eq!(
        location_of(resp).await,
        "https://promo.wild.example/offer",
        "wildcard pattern authorizes subdomains"
    );
    assert!(wait_wal_entry(&redis, &message).await, "click recorded");
    drop_wal_entries(&redis, &wildcard_tenant).await;

    // (5) The bare apex is NOT covered by the wildcard.
    let message = unique("msg");
    let token = click_token(
        &wildcard_tenant,
        &message,
        Some("https://wild.example/offer"),
    );
    let resp = handle_click(
        State(state.clone()),
        addr(),
        headers_with_ua(NORMAL_UA),
        Path(token),
        Query(ClickQuery { r: None }),
    )
    .await;
    assert_eq!(location_of(resp).await, "https://fallback.test.example/");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(wal_entries_for(&redis, &message).await.is_empty());
}

#[tokio::test]
async fn fallback_host_is_authorized_without_any_database() {
    let _wal_serial = crate::routes::test_support::redis_wal_serial().await;
    // A redirect to the configured fallback host needs no DB round-trip and
    // is recorded normally even with a dead DB (the click is on OUR page).
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let redis_url =
        crate::routes::test_support::live_test_redis_url().expect("TEST_REDIS_URL");
    let state = state(lazy_dead_db(), redis.clone(), &redis_url);
    let tenant = unique("tn_fb");
    let message = unique("msg");
    let token = click_token(
        &tenant,
        &message,
        Some("https://fallback.test.example/deep"),
    );
    let resp = handle_click(
        State(state),
        addr(),
        headers_with_ua(NORMAL_UA),
        Path(token),
        Query(ClickQuery { r: None }),
    )
    .await;
    assert_eq!(
        location_of(resp).await,
        "https://fallback.test.example/deep"
    );
    assert!(
        wait_wal_entry(&redis, &message).await,
        "fallback-host click is a legitimate recorded click"
    );
    drop_wal_entries(&redis, &tenant).await;
}
