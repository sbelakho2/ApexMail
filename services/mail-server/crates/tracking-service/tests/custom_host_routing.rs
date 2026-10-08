//! Custom tracking domain host routing (capability wave 2).
//!
//! A verified custom tracking domain (e.g. `email.customer.test`) must serve
//! click/open/unsubscribe links for its owning tenant, and every other host
//! must be refused with the NAMED reason — never a silent bounce, and never
//! a link served for the wrong workspace. Resolution is an explicit
//! verified-row lookup (NO cache), so deleting the tracking domain — or the
//! parent sending domain it hangs off — stops serving on the next request.
//!
//! DB-backed: soft-skips when `TEST_DATABASE_URL` is unset (workspace
//! convention). Redis is deliberately a dead pool: the refusal path must not
//! depend on it, and the success path tolerates its absence by design.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::{HeaderName, StatusCode};
use tracking_service::bot::BotDetector;
use tracking_service::codec::{TrackingCodec, TrackingData};
use tracking_service::config::{
    ClickHouseConfig, Config, DatabaseConfig, MetricsConfig, RateLimitConfig, RedisConfig,
    ServerConfig, TrackingConfig,
};
use tracking_service::processor::EventProcessor;
use tracking_service::routes::build_router;
use tracking_service::state::AppState;

const SECRET: &str = "custom-host-tracking-secret-32-bytes!";

async fn canonical_pool(name: &str) -> Option<sqlx::PgPool> {
    match migrator::test_support::fresh_canonical_pool(name, name).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
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

fn test_config() -> Config {
    Config {
        server: ServerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
        },
        database: DatabaseConfig {
            url: "postgresql://offline@127.0.0.1:1/offline".into(),
            max_connections: 2,
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
            token_max_age_days: None,
            allowed_redirect_domains: Vec::new(),
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

fn state(pool: sqlx::PgPool) -> AppState {
    let config = test_config();
    let redis = dead_redis();
    let clickhouse = clickhouse::Client::default();
    let processor = Arc::new(EventProcessor::new(
        pool.clone(),
        redis.clone(),
        clickhouse,
        std::time::Duration::from_secs(1),
    ));
    AppState::new(
        TrackingCodec::new(SECRET),
        pool,
        redis,
        processor,
        BotDetector::new(),
        config,
    )
}

fn server_for(state: &AppState) -> axum_test::TestServer {
    axum_test::TestServer::new(
        build_router(state.clone()).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .expect("test server")
}

/// Seed a tenant plus a verified owned parent domain.
async fn seed_tenant_with_domain(pool: &sqlx::PgPool, tenant: &str, parent: &str) {
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at) \
         VALUES ($1, 'n', $1, 'pro', 'active', NOW(), NOW())",
    )
    .bind(tenant)
    .execute(pool)
    .await
    .expect("seed tenant");
    sqlx::query(
        "INSERT INTO domains (id, tenant_id, name, status, verified, created_at, updated_at) \
         VALUES (gen_random_uuid(), $1, $2, 'verified', true, NOW(), NOW())",
    )
    .bind(tenant)
    .bind(parent)
    .execute(pool)
    .await
    .expect("seed owned domain");
}

async fn seed_tracking_domain(
    pool: &sqlx::PgPool,
    tenant: &str,
    domain: &str,
    parent: &str,
    status: &str,
) {
    sqlx::query(
        "INSERT INTO tracking_domains \
         (id, tenant_id, domain, parent_domain, status, cname_target, created_at, updated_at) \
         VALUES (gen_random_uuid(), $1, $2, $3, $4, 'track.test.example', NOW(), NOW())",
    )
    .bind(tenant)
    .bind(domain)
    .bind(parent)
    .bind(status)
    .execute(pool)
    .await
    .expect("seed tracking domain");
}

fn unique_tenant(tag: &str) -> String {
    // tenants.id is VARCHAR(26).
    let id = format!("t{tag}{}", uuid::Uuid::new_v4().simple());
    id[..id.len().min(26)].to_string()
}

fn click_token(tenant: &str, landing_url: &str) -> String {
    TrackingCodec::new(SECRET)
        .encode(&TrackingData {
            tenant_id: tenant.into(),
            message_id: format!("msg_{tenant}"),
            recipient: "user@customer.test".into(),
            link_id: Some(format!("lnk_{tenant}")),
            original_url: Some(landing_url.into()),
        })
        .expect("click token")
}

fn unsub_token(tenant: &str) -> String {
    TrackingCodec::new(SECRET)
        .generate_unsubscribe_token(tenant, "user@customer.test")
        .expect("unsubscribe token")
}

async fn get(server: &axum_test::TestServer, path: &str, host: &str) -> axum_test::TestResponse {
    server
        .get(path)
        .add_header(
            HeaderName::from_static("host"),
            host.parse().expect("host header"),
        )
        .await
}

struct Fixture {
    tenant_a: String,
    tenant_b: String,
}

async fn fixture(pool: &sqlx::PgPool) -> Fixture {
    let tenant_a = unique_tenant("a");
    let tenant_b = unique_tenant("b");
    seed_tenant_with_domain(pool, &tenant_a, "customer.test").await;
    seed_tenant_with_domain(pool, &tenant_b, "other.test").await;
    seed_tracking_domain(
        pool,
        &tenant_a,
        "email.customer.test",
        "customer.test",
        "verified",
    )
    .await;
    seed_tracking_domain(
        pool,
        &tenant_b,
        "email.other.test",
        "other.test",
        "verified",
    )
    .await;
    Fixture { tenant_a, tenant_b }
}

/// The verified custom host serves the owning tenant's click.
#[tokio::test]
async fn verified_custom_host_serves_click_for_the_owning_tenant() {
    let Some(pool) = canonical_pool("ch_serve").await else {
        return;
    };
    let fx = fixture(&pool).await;
    let state = state(pool.clone());
    let server = server_for(&state);
    let token = click_token(&fx.tenant_a, "https://customer.test/landing");

    let response = get(&server, &format!("/c/{token}"), "email.customer.test").await;
    assert_eq!(
        response.status_code().as_u16(),
        302,
        "the owning tenant's click must be served on its verified host: {}",
        response.text()
    );
    assert_eq!(response.header("location"), "https://customer.test/landing");
}

/// An unknown host is refused by name — 400, no Location, never a bounce.
#[tokio::test]
async fn unknown_host_is_refused_with_the_named_reason_and_no_redirect() {
    let Some(pool) = canonical_pool("ch_unknown").await else {
        return;
    };
    let fx = fixture(&pool).await;
    let state = state(pool.clone());
    let server = server_for(&state);
    let token = click_token(&fx.tenant_a, "https://customer.test/landing");

    let response = get(&server, &format!("/c/{token}"), "ghost.example.test").await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    assert!(
        response.headers().get("location").is_none(),
        "a refusal must never redirect"
    );
    let body = response.text();
    assert!(body.contains("ghost.example.test"), "{body}");
    assert!(
        body.contains("not a verified custom tracking domain"),
        "the refusal names the reason: {body}"
    );
}

/// A configured-but-unverified row does not serve.
#[tokio::test]
async fn unverified_tracking_domain_is_refused() {
    let Some(pool) = canonical_pool("ch_unverified").await else {
        return;
    };
    let fx = fixture(&pool).await;
    // A second owned parent so the one-tracking-domain-per-parent constraint
    // is not in the way of this fixture.
    sqlx::query(
        "INSERT INTO domains (id, tenant_id, name, status, verified, created_at, updated_at) \
         VALUES (gen_random_uuid(), $1, 'pending.test', 'verified', true, NOW(), NOW())",
    )
    .bind(&fx.tenant_a)
    .execute(&pool)
    .await
    .expect("seed second owned domain");
    seed_tracking_domain(
        &pool,
        &fx.tenant_a,
        "email.pending.test",
        "pending.test",
        "pending",
    )
    .await;
    let state = state(pool.clone());
    let server = server_for(&state);
    let token = click_token(&fx.tenant_a, "https://pending.test/landing");

    let response = get(&server, &format!("/c/{token}"), "email.pending.test").await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    assert!(response
        .text()
        .contains("not a verified custom tracking domain"));
}

/// Another workspace's token on this host is refused (403), never served.
#[tokio::test]
async fn foreign_token_on_a_custom_host_is_refused() {
    let Some(pool) = canonical_pool("ch_foreign_token").await else {
        return;
    };
    let fx = fixture(&pool).await;
    let state = state(pool.clone());
    let server = server_for(&state);
    let foreign = click_token(&fx.tenant_b, "https://other.test/landing");

    let response = get(&server, &format!("/c/{foreign}"), "email.customer.test").await;
    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
    assert!(
        response.headers().get("location").is_none(),
        "the refusal must not bounce anywhere"
    );
    assert!(
        response.text().contains("different workspace"),
        "{}",
        response.text()
    );
}

/// Deleting the tracking-domain row stops serving on the next request (the
/// resolution is an explicit verified-row lookup — no stale allow-cache).
#[tokio::test]
async fn deleting_the_tracking_domain_stops_serving() {
    let Some(pool) = canonical_pool("ch_delete").await else {
        return;
    };
    let fx = fixture(&pool).await;
    let state = state(pool.clone());
    let server = server_for(&state);
    let token = click_token(&fx.tenant_a, "https://customer.test/landing");

    let served = get(&server, &format!("/c/{token}"), "email.customer.test").await;
    assert_eq!(served.status_code().as_u16(), 302, "{}", served.text());

    sqlx::query("DELETE FROM tracking_domains WHERE domain = 'email.customer.test'")
        .execute(&pool)
        .await
        .expect("delete tracking domain");

    let refused = get(&server, &format!("/c/{token}"), "email.customer.test").await;
    assert_eq!(
        refused.status_code(),
        StatusCode::BAD_REQUEST,
        "deletion must stop serving immediately"
    );
}

/// Deleting the PARENT sending domain also stops serving — the item-11
/// owned-domain relation is re-checked on every request.
#[tokio::test]
async fn deleting_the_parent_domain_stops_serving_too() {
    let Some(pool) = canonical_pool("ch_parent_delete").await else {
        return;
    };
    let fx = fixture(&pool).await;
    let state = state(pool.clone());
    let server = server_for(&state);
    let token = click_token(&fx.tenant_a, "https://customer.test/landing");

    assert_eq!(
        get(&server, &format!("/c/{token}"), "email.customer.test")
            .await
            .status_code()
            .as_u16(),
        302
    );
    sqlx::query("DELETE FROM domains WHERE tenant_id = $1 AND name = 'customer.test'")
        .bind(&fx.tenant_a)
        .execute(&pool)
        .await
        .expect("delete owned parent domain");
    assert_eq!(
        get(&server, &format!("/c/{token}"), "email.customer.test")
            .await
            .status_code(),
        StatusCode::BAD_REQUEST
    );
}

/// The pixel serves the owner on a verified host and refuses unknown hosts
/// with the named page (never a silent 200-GIF).
#[tokio::test]
async fn pixel_serves_on_the_custom_host_and_refuses_unknown_hosts() {
    let Some(pool) = canonical_pool("ch_pixel").await else {
        return;
    };
    let fx = fixture(&pool).await;
    let state = state(pool.clone());
    let server = server_for(&state);
    let token = click_token(&fx.tenant_a, "https://customer.test/landing");

    let served = get(&server, &format!("/o/{token}"), "email.customer.test").await;
    assert_eq!(served.status_code(), StatusCode::OK);
    assert_eq!(served.header("content-type"), "image/gif");

    let refused = get(&server, &format!("/o/{token}"), "ghost.example.test").await;
    assert_eq!(refused.status_code(), StatusCode::BAD_REQUEST);
    assert!(
        !refused
            .header("content-type")
            .to_str()
            .unwrap_or_default()
            .contains("image/gif"),
        "an unknown host must not look like a served pixel"
    );
}

/// Unsubscribe GET on a custom host renders for the owner and refuses a
/// foreign workspace's token.
#[tokio::test]
async fn unsubscribe_on_custom_host_serves_the_owner_only() {
    let Some(pool) = canonical_pool("ch_unsub").await else {
        return;
    };
    let fx = fixture(&pool).await;
    let state = state(pool.clone());
    let server = server_for(&state);

    let owner_token = unsub_token(&fx.tenant_a);
    let served = get(&server, &format!("/u/{owner_token}"), "email.customer.test").await;
    assert_eq!(served.status_code(), StatusCode::OK, "{}", served.text());
    assert!(served.text().contains("Unsubscribe"));

    let foreign_token = unsub_token(&fx.tenant_b);
    let refused = get(
        &server,
        &format!("/u/{foreign_token}"),
        "email.customer.test",
    )
    .await;
    assert_eq!(refused.status_code(), StatusCode::FORBIDDEN);

    let unknown = get(&server, &format!("/u/{owner_token}"), "ghost.example.test").await;
    assert_eq!(unknown.status_code(), StatusCode::BAD_REQUEST);
}

/// The platform host is unaffected: it serves without any tracking-domain
/// row (pre-existing contract).
#[tokio::test]
async fn platform_host_serves_without_any_configuration() {
    let Some(pool) = canonical_pool("ch_platform").await else {
        return;
    };
    let fx = fixture(&pool).await;
    let state = state(pool.clone());
    let server = server_for(&state);
    let token = click_token(&fx.tenant_a, "https://customer.test/landing");

    let response = get(&server, &format!("/c/{token}"), "track.test.example").await;
    assert_eq!(response.status_code().as_u16(), 302, "{}", response.text());
    assert_eq!(response.header("location"), "https://customer.test/landing");
}
