//! Concurrency & race-condition tests (audit SM12 F3/F14/F16b rewrite).
//!
//! The previous suite re-typed the production SQL inside the test file and
//! executed it against hand-created tables: if the api-server dropped the
//! `ON CONFLICT` clause, the `FOR UPDATE`, or the idempotency claim, every
//! "race regression" test stayed green because it tested Postgres, not
//! ApexMail.
//!
//! Every RC-TEST here now drives the REAL production handlers through the
//! REAL `build_app` router (auth → rate-limit → idempotency → CP gates →
//! handler) over a canonical-chain database provisioned by the production
//! migrator. The tests FAIL if the production concurrency clauses are
//! removed, because the assertions run against the exact SQL that ships.
//!
//! Run with: cargo test --test concurrency_tests -- --nocapture
//! Requires: PostgreSQL (TEST_DATABASE_URL); RC-01/RC-07 additionally
//! require Redis (TEST_REDIS_URL). Skip handling follows the workspace
//! convention: an unset variable prints an explicit skip line in dev and is
//! a hard panic under `APEXMAIL_RELEASE_TEST_MODE=1`; a SET variable whose
//! infrastructure is broken always panics.

use std::sync::Mutex;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use deadpool_redis::Config as RedisConfig;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use api_server::{
    app::build_app,
    config::{Config, Environment},
    ses_provider::SesIpProvider,
    state::AppStateInner,
};

// ═══════════════════════════════════════════════════════════════════════════
// Harness — canonical DB per test + the real api-server router
// ═══════════════════════════════════════════════════════════════════════════

/// The AWS SDK env: `aws_config::defaults(..).load()` in the AppState reads
/// the process environment, so the dummy test credentials are installed
/// exactly ONCE under this lock (concurrent `set_var` is a data race — the
/// same reason audit SM12 F17 removed per-test env writes).
static AWS_ENV_LOCK: Mutex<()> = Mutex::new(());

fn ensure_aws_test_env() {
    let _guard = AWS_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
        if std::env::var("AWS_ACCESS_KEY_ID").is_err() {
            std::env::set_var("AWS_ACCESS_KEY_ID", "test");
        }
        if std::env::var("AWS_SECRET_ACCESS_KEY").is_err() {
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        }
    });
}

async fn optional_canonical_pool(test_name: &str) -> Option<PgPool> {
    // SM12c harness dedup: the shared per-call isolated template clone
    // (soft-skip on unset TEST_DATABASE_URL, F01 panic on configured
    // breakage) — replaces this suite's former hand-rolled DROP/CREATE
    // block, which never applied the canonical migration chain at all.
    // The suffix MUST be unique per test (workspace convention — see
    // tracking-service's `fresh_canonical_pool(test_name, test_name)`):
    // `optional_pg_pool` derives the database name from the suffix alone,
    // so a constant suffix would funnel every parallel test into ONE
    // database whose per-call re-provisioning severs its siblings.
    migrator::test_support::optional_pg_pool(test_name, &format!("conc_{test_name}")).await
}

fn test_config() -> Config {
    Config {
        ai_service_base_url: String::new(),
        cp_auth: Default::default(),
        pdf_renderer_auth_token: None,
        template_renderer_auth_token: None,
        devex_auth_token: None,
        ai_embeddings_auth_token: None,
        public_rate_limit_enabled: false,
        port: 3000,
        host: "0.0.0.0".into(),
        base_url: "http://localhost:3000".into(),
        environment: Environment::Development,
        db_host: "localhost".into(),
        db_port: 5432,
        db_name: "apexmail".into(),
        db_user: "apexmail".into(),
        db_password: "password".into(),
        db_max_connections: 20,
        api_replica_count: 1,
        db_cluster_connection_budget: None,
        expected_replica_count: 3,
        statement_cache_capacity: 500,
        query_timeout_seconds: 30,
        database_replica_url: None,
        redis_host: "localhost".into(),
        redis_port: 6379,
        redis_password: None,
        redis_db: 0,
        redis_pool_max_size: 40,
        jwt_private_key_pem: "BEGIN TEST".into(),
        jwt_public_key_pem: "BEGIN TEST".into(),
        jwt_previous_public_keys_pem: vec![],
        jwt_expiry: Duration::from_secs(86_400),
        api_key_hash_secret: "test-api-key-secret-12345678901234567890".into(),
        rate_limit_window_ms: 60_000,
        rate_limit_max_requests: 1_000,
        max_inflight_requests: 80,
        // Test-only: wildcard CORS origin is acceptable for local/CI testing.
        cors_origins: vec!["*".into()],
        trusted_proxies: vec![],
        ui_web_hosts: vec!["app.apexmail.ee".into(), "localhost".into()],
        ui_control_plane_hosts: vec!["admin.apexmail.ee".into()],
        ui_marketing_hosts: vec!["apexmail.ee".into()],
        ui_marketing_surface: "marketing-zola".into(),
        ui_default_surface: Some("web".into()),
        webhook_signing_secret: "test-webhook-signing-secret-1234567890".into(),
        webhook_timeout_ms: 5_000,
        webhook_max_retries: 10,
        idempotency_ttl_seconds: 86_400,
        aws_region: "us-east-1".into(),
        ses_ip_pool_prefix: "apexmail".into(),
        ses_default_warmup_days: 14,
        ses_configuration_set: None,
        google_client_id: None,
        google_client_secret: None,
        github_client_id: None,
        github_client_secret: None,
        oauth_redirect_base_url: "http://localhost:3000".into(),
        billing_company_iban: "EE381010220123456789".into(),
        billing_company_phone: "+3721234567".into(),
        session_secret: "test-session-secret-1234567890ab".into(),
        impersonation_secret: "test-impersonation-secret-12345".into(),
        csrf_secret: "test-csrf-secret-1234567890abcd".into(),
        control_plane_api_key: None,
        sales_autopilot_base_url: "http://localhost:3010".into(),
        internal_service_token: None,
        tracking_secret_key: "test-tracking-secret-123456789012".into(),
        metrics_port: 9090,
        grader_enabled: false,
        grader_rate_limit: 10,
        grader_rate_window_seconds: 60,
        grader_cache_ttl_seconds: 300,
        grader_max_body_size: 1_048_576,
        placement_enabled: false,
        placement_polling_interval_secs: 60,
        placement_max_polling_attempts: 60,
        placement_max_seeds_per_test: 50,
        placement_max_tests_per_hour: 10,
        placement_imap_timeout_secs: 30,
        placement_encrypt_passwords: false,
        placement_encryption_secret: "test-placement-encryption-secret-32b".into(),
        http_client_timeout_secs: 10,
        internal_tls_enabled: false,
        internal_tls_ca_cert_path: None,
        internal_tls_client_cert_path: None,
        internal_tls_client_key_path: None,
        kiwi_enabled: false,
        kiwi_secret_key: "dev".into(),
        waf_enabled: false,
        waf_enforce: false,
        kiwi_algorithm: kiwicaptcha::PoWAlgorithm::Sha256,
        kiwi_argon_m_kib: 0,
        kiwi_argon_t: 2,
        kiwi_argon_p: 1,
        kiwi_difficulty_bits: 16,
        kiwi_argon2_difficulty_bits: 8,
        kiwi_challenge_ttl_secs: 120,
        kiwi_min_duration_ms: None,
        kiwi_enforce_telemetry: true,
        kiwi_argon2_max_concurrent: 2,
        kiwi_auto_tune: false,
        kiwi_auto_tune_min_bits: 10,
        kiwi_auto_tune_max_bits: 24,
    }
}

/// The REAL router (full middleware stack) over the canonical pool. The
/// Redis pool honors TEST_REDIS_URL; without it a dead port keeps the
/// DB-only tests hermetic (the dev-mode rate limiter fails open).
async fn build_test_app(pool: PgPool) -> axum::Router {
    ensure_aws_test_env();
    let database_url = migrator::test_support::test_database_url().unwrap_or_default();
    let pools = apexmail_db::pool::create_pool_pair(&database_url, None, 2, 0)
        .await
        .expect("test pool pair");

    let redis_url = std::env::var("TEST_REDIS_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "redis://127.0.0.1:1".into());
    let redis = RedisConfig::from_url(&redis_url)
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .expect("lazy redis pool");

    let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_sdk_sesv2::config::Region::new("us-east-1"))
        .load()
        .await;
    let ses_provider = SesIpProvider::new(
        aws_sdk_sesv2::Client::new(&aws_config),
        pool.clone(),
        "apexmail".into(),
        "us-east-1".into(),
    );

    let state = AppStateInner::new(
        pool.clone(),
        pools,
        redis,
        test_config(),
        reqwest::Client::new(),
        ses_provider,
        None,
    )
    .await
    .expect("test app state");
    build_app(state)
}

/// Seed an ACTIVE tenant (`plan` gates webhook entitlements) plus a scoped
/// raw API key; returns (tenant_id, raw_key).
async fn seed_tenant_with_key(pool: &PgPool, plan: &str, scopes: &[&str]) -> (String, String) {
    let tenant_id = apexmail_lib::id::generate_id("ten", 21);
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
         VALUES ($1, 'concurrency fixture', $1, $2, 'active', NOW(), NOW())",
    )
    .bind(&tenant_id)
    .bind(plan)
    .execute(pool)
    .await
    .expect("seed tenant");
    let raw = seed_api_key_for(pool, &tenant_id, scopes).await;
    (tenant_id, raw)
}

/// Seed one API key row for an (existing) tenant; returns the raw key.
async fn seed_api_key_for(pool: &PgPool, tenant_id: &str, scopes: &[&str]) -> String {
    let raw_key = apexmail_lib::id::generate_api_key(true);
    let key_hash = apexmail_lib::hash_api_key_with_secret(
        &raw_key,
        "test-api-key-secret-12345678901234567890",
    );
    sqlx::query(
        "INSERT INTO api_keys (id, tenant_id, name, key_prefix, key_hash, scopes, created_at, updated_at)
         VALUES ($1, $2, 'concurrency fixture', 'am_test_', $3, $4::jsonb, NOW(), NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(&key_hash)
    .bind(serde_json::json!(scopes).to_string())
    .execute(pool)
    .await
    .expect("seed api key");
    raw_key
}

/// The control-plane machine credential: a `system`-tenant wildcard API key
/// (no user identity) — the carve-out that passes require_auth, the
/// system-tenant gate AND the CP session gate on /v1/admin/* routes.
async fn seed_system_admin_key(pool: &PgPool) -> String {
    seed_api_key_for(pool, "system", &["*"]).await
}

/// A lazily-provisioned Redis pool for tests whose production path
/// hard-requires Redis. Unset TEST_REDIS_URL → explicit skip; set but
/// unreachable → panic (infrastructure breakage, never a silent green).
async fn require_reachable_redis(test_name: &str) -> () {
    migrator::test_support::assert_soft_skip_allowed("TEST_REDIS_URL");
    let url = match std::env::var("TEST_REDIS_URL") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => {
            eprintln!("skipping {test_name}: set TEST_REDIS_URL (the admin-credit / idempotency path hard-requires Redis)");
            return;
        }
    };
    let probe = RedisConfig::from_url(&url)
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .expect("redis pool");
    let reachable = match tokio::time::timeout(Duration::from_secs(2), probe.get()).await {
        Ok(Ok(mut conn)) => {
            deadpool_redis::redis::cmd("PING")
                .query_async::<String>(&mut *conn)
                .await
                .is_ok()
        }
        _ => false,
    };
    assert!(
        reachable,
        "{test_name}: TEST_REDIS_URL is configured but Redis is unreachable — \
         start the test Redis (the admin-credit idempotency claim fails closed without it)"
    );
}

/// Drive one request through the REAL router; returns (status, json body).
async fn dispatch(
    app: &axum::Router,
    method: Method,
    path: &str,
    api_key: &str,
    headers: &[(&str, String)],
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("x-api-key", api_key);
    for (name, value) in headers {
        builder = builder.header(*name, value.clone());
    }
    let request = match body {
        Some(json) => builder
            .header("content-type", "application/json")
            .body(Body::from(json.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let response = app.clone().oneshot(request).await.expect("dispatch");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap_or_default();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

// ═══════════════════════════════════════════════════════════════════════════
// RC-TEST-01 (SM12 F3 + F16b): admin wallet credit idempotency — REAL handler
// ═══════════════════════════════════════════════════════════════════════════

/// Two concurrent admin credits with the SAME Idempotency-Key must apply
/// exactly one credit. This drives `admin_apply_credit` (the Redis SET NX
/// claim + the `ON CONFLICT (reference)` ledger insert) through the real
/// CP-authenticated route — deleting either production clause fails here.
#[tokio::test]
async fn rc01_admin_wallet_credit_idempotency_replay_and_race() {
    let Some(pool) = optional_canonical_pool("rc01_admin_wallet_credit").await else {
        return;
    };
    require_reachable_redis("rc01_admin_wallet_credit").await;
    let app = build_test_app(pool.clone()).await;
    let admin_key = seed_system_admin_key(&pool).await;
    let (tenant_id, _customer_key) = seed_tenant_with_key(&pool, "starter", &["billing:read"]).await;

    let credit = |key: String| {
        let app = app.clone();
        let admin = admin_key.clone();
        let tenant = tenant_id.clone();
        async move {
            dispatch(
                &app,
                Method::POST,
                &format!("/v1/billing/admin/tenants/{tenant}/credits"),
                &admin,
                &[("idempotency-key", key)],
                Some(serde_json::json!({ "amount": 100, "reason": "rc01" })),
            )
            .await
        }
    };

    // ── Sequential replay: the idempotency MIDDLEWARE (which sits in front
    // of the handler) caches the first response and serves the replay from
    // it — either way, the ledger and balance must show EXACTLY ONE credit.
    let key1 = format!("rc01-{}", Uuid::new_v4());
    let (status_first, body_first) = credit(key1.clone()).await;
    assert!(
        status_first.is_success(),
        "first credit must succeed, got {status_first}: {body_first}"
    );
    let (status_replay, body_replay) = credit(key1.clone()).await;
    assert_eq!(
        status_replay, status_first,
        "a replayed request must be answered idempotently (cached or claimed), \
         got {status_replay}: {body_replay}"
    );
    let (key1_rows,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM wallet_transactions WHERE reference = $1",
    )
    .bind(&key1)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        key1_rows, 1,
        "a replayed credit must not mint a second ledger row"
    );

    // ── Concurrent race: two racing claims, same key ──
    let key2 = format!("rc01-{}", Uuid::new_v4());
    let (a, b) = tokio::join!(credit(key2.clone()), credit(key2.clone()));
    let succeeded = [a.0.is_success(), b.0.is_success()];
    assert_eq!(
        succeeded.iter().filter(|ok| **ok).count(),
        1,
        "exactly ONE of the two racing claims may succeed: {a:?} / {b:?}"
    );
    let (loser_status, loser_body) = if a.0.is_success() { b } else { a };
    assert_eq!(
        loser_status,
        StatusCode::CONFLICT,
        "the racing loser must see the idempotency conflict, got: {loser_body}"
    );

    // ── Ledger + balance: each key applied EXACTLY once ──
    for key in [&key1, &key2] {
        let (rows,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM wallet_transactions WHERE reference = $1",
        )
        .bind(key)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(rows, 1, "reference {key} must have exactly one ledger row");
    }
    let (balance,): (i64,) =
        sqlx::query_as("SELECT balance FROM wallets WHERE tenant_id = $1")
            .bind(&tenant_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        balance, 200,
        "wallet balance must be credited exactly once per accepted key"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// RC-TEST-02: webhook URL uniqueness — REAL create_webhook handler
// ═══════════════════════════════════════════════════════════════════════════

/// Two concurrent `POST /v1/webhooks` for the same (tenant, url) must
/// produce exactly ONE webhook. The uniqueness is the canonical
/// `uq_webhooks_tenant_url` index (migration 078): if it (or the handler's
/// INSERT) regresses, BOTH requests return 201 and this test fails.
#[tokio::test]
async fn rc02_concurrent_webhook_creation_same_url_is_unique() {
    let Some(pool) = optional_canonical_pool("rc02_webhook_create_race").await else {
        return;
    };
    let app = build_test_app(pool.clone()).await;
    let (tenant_id, key) =
        seed_tenant_with_key(&pool, "starter", &["webhooks:write", "webhooks:read"]).await;

    let url = format!("https://hooks.example/rc02-{}", Uuid::new_v4());
    let create = |tenant: String, key: String, target: String| {
        let app = app.clone();
        async move {
            dispatch(
                &app,
                Method::POST,
                "/v1/webhooks",
                &key,
                &[],
                Some(serde_json::json!({
                    "url": target,
                    "events": ["message.delivered"],
                })),
            )
            .await
            .1
            .get("id")
            .and_then(|v| v.as_str().map(str::to_string))
            .map(|id| (tenant, id))
        }
    };

    let (a, b) = tokio::join!(
        create(tenant_id.clone(), key.clone(), url.clone()),
        create(tenant_id.clone(), key.clone(), url.clone()),
    );
    let created: Vec<_> = [a, b].into_iter().flatten().collect();
    assert_eq!(
        created.len(),
        1,
        "exactly one of two racing same-URL creates may succeed — got {created:?}; \
         a duplicate webhook means the (tenant_id, url) uniqueness is gone"
    );
    let (rows,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM webhooks WHERE tenant_id = $1 AND url = $2")
            .bind(&tenant_id)
            .bind(&url)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(rows, 1, "duplicate webhook rows for the same (tenant, url)");

    // Different tenants may register the SAME url — the constraint is per
    // tenant, and both creates must succeed.
    let (other_tenant, other_key) =
        seed_tenant_with_key(&pool, "starter", &["webhooks:write"]).await;
    let (c, _d) = tokio::join!(
        create(other_tenant.clone(), other_key.clone(), url.clone()),
        async {}
    );
    let (_t, other_webhook_id) = c.expect("the other tenant's create must succeed");
    let (cross_rows,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM webhooks WHERE url = $1")
            .bind(&url)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        cross_rows, 2,
        "the same URL must be registrable by DIFFERENT tenants"
    );
    let _ = other_webhook_id;
}

// ═══════════════════════════════════════════════════════════════════════════
// RC-TEST-03: subscription status override serialization — REAL handler
// ═══════════════════════════════════════════════════════════════════════════

/// Two concurrent `admin_force_subscription_status` calls (row-lock UPDATE)
/// must both commit without losing an update, must never leak onto ANOTHER
/// tenant's subscription, and each committed override must leave exactly
/// one audit row.
#[tokio::test]
async fn rc03_subscription_status_override_concurrent_is_serialized() {
    let Some(pool) = optional_canonical_pool("rc03_subscription_override").await else {
        return;
    };
    let app = build_test_app(pool.clone()).await;
    let admin_key = seed_system_admin_key(&pool).await;
    let (tenant_id, _) = seed_tenant_with_key(&pool, "starter", &["billing:read"]).await;
    let (other_tenant, _) = seed_tenant_with_key(&pool, "starter", &["billing:read"]).await;

    for tenant in [&tenant_id, &other_tenant] {
        sqlx::query(
            "INSERT INTO stripe_subscriptions (id, tenant_id, stripe_subscription_id, status)
             VALUES ($1, $2, $3, 'active')",
        )
        .bind(Uuid::new_v4())
        .bind(tenant)
        .bind(format!("sub-{}", Uuid::new_v4()))
        .execute(&pool)
        .await
        .expect("seed subscription");
    }

    let force = |status: &'static str| {
        let app = app.clone();
        let admin = admin_key.clone();
        let tenant = tenant_id.clone();
        async move {
            dispatch(
                &app,
                Method::POST,
                &format!("/v1/billing/admin/tenants/{tenant}/subscription-status"),
                &admin,
                &[],
                Some(serde_json::json!({ "status": status, "reason": "rc03" })),
            )
            .await
        }
    };

    let ((sa, ba), (sb, bb)) = tokio::join!(
        force("canceled"),
        force("suspended"),
    );
    assert!(
        sa.is_success() && sb.is_success(),
        "both racing overrides must commit (row-lock serialization), got {sa} {ba:?} / {sb} {bb:?}"
    );

    // No lost update: exactly one audit row per override, statuses covering
    // BOTH writes.
    let audit: Vec<(String,)> = sqlx::query_as(
        "SELECT details->>'newStatus' FROM billing_audit_log \
         WHERE tenant_id = $1 AND action = 'subscription_status_override'",
    )
    .bind(&tenant_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    let mut statuses: Vec<String> = audit.into_iter().map(|(s,)| s).collect();
    statuses.sort();
    assert_eq!(
        statuses,
        vec!["canceled".to_string(), "suspended".to_string()],
        "both overrides must be audited exactly once"
    );

    // The surviving status is one of the two writes — never anything else.
    let (final_status,): (String,) =
        sqlx::query_as("SELECT status FROM stripe_subscriptions WHERE tenant_id = $1")
            .bind(&tenant_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        final_status == "canceled" || final_status == "suspended",
        "final status must be one of the two racing writes, got {final_status}"
    );

    // Tenant scoping: the OTHER tenant's subscription is untouched.
    let (other_status,): (String,) =
        sqlx::query_as("SELECT status FROM stripe_subscriptions WHERE tenant_id = $1")
            .bind(&other_tenant)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        other_status, "active",
        "an override on one tenant must never leak onto another tenant's row"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// RC-TEST-04: webhook deletion is tenant-scoped — REAL delete_webhook
// ═══════════════════════════════════════════════════════════════════════════

/// `DELETE /v1/webhooks/:id` must only delete the OWNING tenant's webhook:
/// a foreign tenant gets 404 (the handler's `WHERE tenant_id = $2`), the
/// owner's delete commits, and the row is gone afterwards.
#[tokio::test]
async fn rc04_webhook_deletion_is_tenant_scoped() {
    let Some(pool) = optional_canonical_pool("rc04_webhook_delete_scope").await else {
        return;
    };
    let app = build_test_app(pool.clone()).await;
    let (owner_tenant, owner_key) =
        seed_tenant_with_key(&pool, "starter", &["webhooks:write"]).await;
    let (attacker_tenant, attacker_key) =
        seed_tenant_with_key(&pool, "starter", &["webhooks:write"]).await;

    let webhook_url = format!("https://hooks.example/rc04-{}", Uuid::new_v4());
    sqlx::query(
        "INSERT INTO webhooks (id, tenant_id, url, events, secret, status, created_at, updated_at)
         VALUES ($1, $2, $3, '[\"message.delivered\"]'::jsonb, 'rc04-secret', 'active', NOW(), NOW())",
    )
    .bind(apexmail_lib::id::generate_id("whk", 18))
    .bind(&owner_tenant)
    .bind(&webhook_url)
    .execute(&pool)
    .await
    .expect("seed webhook");
    let (webhook_id,): (String,) =
        sqlx::query_as("SELECT id FROM webhooks WHERE url = $1")
            .bind(&webhook_url)
            .fetch_one(&pool)
            .await
            .unwrap();

    // A foreign tenant CANNOT delete it — the tenant-scoped WHERE holds.
    let (status_foreign, body_foreign) = dispatch(
        &app,
        Method::DELETE,
        &format!("/v1/webhooks/{webhook_id}"),
        &attacker_key,
        &[],
        None,
    )
    .await;
    assert_ne!(
        status_foreign,
        StatusCode::NO_CONTENT,
        "a foreign tenant must not be able to delete another tenant's webhook: {body_foreign}"
    );
    assert_eq!(status_foreign, StatusCode::NOT_FOUND);

    // The owner CAN delete it, and the row is gone.
    let (status_owner, _) = dispatch(
        &app,
        Method::DELETE,
        &format!("/v1/webhooks/{webhook_id}"),
        &owner_key,
        &[],
        None,
    )
    .await;
    assert_eq!(
        status_owner,
        StatusCode::NO_CONTENT,
        "the owning tenant's delete must succeed"
    );
    let (remaining,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM webhooks WHERE id = $1")
            .bind(&webhook_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0, "the webhook row must be gone after delete");
    let _ = attacker_tenant;
}

// ═══════════════════════════════════════════════════════════════════════════
// RC-TEST-05: domain delete serialization — REAL delete_domain handler
// ═══════════════════════════════════════════════════════════════════════════

/// Two concurrent `DELETE /v1/domains/:id` calls (the handler takes the
/// tenant advisory lock + `FOR UPDATE` before deleting) must produce
/// exactly one 204 and one 404 with the row gone; a foreign tenant's
/// delete is a 404 (tenant-scoped `FOR UPDATE` SELECT).
#[tokio::test]
async fn rc05_concurrent_domain_delete_is_serialized_and_tenant_scoped() {
    let Some(pool) = optional_canonical_pool("rc05_domain_delete_race").await else {
        return;
    };
    let app = build_test_app(pool.clone()).await;
    let (tenant_id, key) = seed_tenant_with_key(&pool, "starter", &["domains:write"]).await;
    let (foreign_tenant, foreign_key) =
        seed_tenant_with_key(&pool, "starter", &["domains:write"]).await;

    let domain_id = Uuid::new_v4();
    sqlx::query("INSERT INTO domains (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(domain_id)
        .bind(&tenant_id)
        .bind(format!("rc05-{}.example.com", Uuid::new_v4().simple()))
        .execute(&pool)
        .await
        .expect("seed domain");

    let delete = |key: String| {
        let app = app.clone();
        async move {
            dispatch(
                &app,
                Method::DELETE,
                &format!("/v1/domains/{domain_id}"),
                &key,
                &[],
                None,
            )
            .await
            .0
        }
    };

    // Foreign-tenant attempt: refused by the tenant-scoped lock+SELECT.
    let foreign_status = delete(foreign_key.clone()).await;
    assert_eq!(
        foreign_status,
        StatusCode::NOT_FOUND,
        "a foreign tenant must not observe (let alone delete) the domain"
    );

    // Two concurrent owner deletes: exactly one wins.
    let (a, b) = tokio::join!(delete(key.clone()), delete(key));
    let statuses = [a, b];
    assert_eq!(
        statuses.iter().filter(|s| **s == StatusCode::NO_CONTENT).count(),
        1,
        "exactly one concurrent delete may report 204, got {statuses:?}"
    );
    assert!(
        statuses.iter().any(|s| *s == StatusCode::NOT_FOUND),
        "the losing delete must report 404 (row already gone), got {statuses:?}"
    );
    let (remaining,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM domains WHERE id = $1")
        .bind(domain_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, 0, "the domain row must be gone");
    let _ = foreign_tenant;
}

// ═══════════════════════════════════════════════════════════════════════════
// RC-TEST-06 + SM12 F14: plan override — last COMMITTER's value wins
// ═══════════════════════════════════════════════════════════════════════════

/// The vacuous `plan == "pro" || plan == "enterprise"` assertion is gone.
/// Commit order is now CAPTURED and correlated with the stored value:
/// - sequentially (deterministic), the LAST committer's override is what
///   `plan_overrides` stores and the audit trail records the writes in
///   commit order — a "first write sticks" regression fails;
/// - concurrently, the stored (plan_id, reason) pair must be a CONSISTENT
///   pair from exactly one request (never a mix) and every override must
///   be audited exactly once (the audit commits in the same transaction).
#[tokio::test]
async fn rc06_plan_override_last_committer_value_wins() {
    let Some(pool) = optional_canonical_pool("rc06_plan_override_order").await else {
        return;
    };
    let app = build_test_app(pool.clone()).await;
    let admin_key = seed_system_admin_key(&pool).await;
    let (tenant_id, _) = seed_tenant_with_key(&pool, "starter", &["billing:read"]).await;

    // The override handler requires active plan rows to exist.
    for (name, sort) in [("pro", 3), ("enterprise", 4)] {
        sqlx::query(
            "INSERT INTO plans (name, display_name, description, price_monthly, price_yearly,
                features, email_limit, api_call_limit, is_active, sort_order)
             VALUES ($1, $1, 'rc06 plan', 100, 1000, '{}'::jsonb, 1000, 1000, true, $2)
             ON CONFLICT (name) DO UPDATE SET is_active = true",
        )
        .bind(name)
        .bind(sort)
        .execute(&pool)
        .await
        .expect("seed plan");
    }

    let override_plan = |plan: &'static str, reason: &'static str| {
        let app = app.clone();
        let admin = admin_key.clone();
        let tenant = tenant_id.clone();
        async move {
            dispatch(
                &app,
                Method::POST,
                &format!("/v1/billing/admin/tenants/{tenant}/plan-override"),
                &admin,
                &[],
                Some(serde_json::json!({ "planId": plan, "reason": reason })),
            )
            .await
        }
    };

    // ── Commit-order phase: sequential writes, LAST one must win ──
    let (s1, b1) = override_plan("pro", "rc06-first").await;
    assert!(s1.is_success(), "first override must succeed: {b1:?}");
    let (s2, b2) = override_plan("enterprise", "rc06-second").await;
    assert!(s2.is_success(), "second override must succeed: {b2:?}");
    let (plan_id, reason, admin_id): (String, String, String) = sqlx::query_as(
        "SELECT plan_id, reason, admin_id FROM plan_overrides WHERE tenant_id = $1",
    )
    .bind(&tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        plan_id, "enterprise",
        "the LAST committed override must be the stored plan"
    );
    assert_eq!(
        (plan_id.as_str(), reason.as_str()),
        ("enterprise", "rc06-second"),
        "the stored override must be the last writer's CONSISTENT pair"
    );
    let _ = admin_id;
    // Sequential commit-order correlation (deterministic — each request
    // completes before the next starts): the SECOND audit entry must carry
    // the second override's plan, i.e. commit order is observable and the
    // stored value is the last committer's.
    let ordered: Vec<(String,)> = sqlx::query_as(
        "SELECT details->>'planId' FROM billing_audit_log \
         WHERE tenant_id = $1 AND action = 'plan_override' ORDER BY created_at",
    )
    .bind(&tenant_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    let ordered: Vec<String> = ordered.into_iter().map(|(p,)| p).collect();
    assert_eq!(
        ordered,
        vec!["pro".to_string(), "enterprise".to_string()],
        "the audit trail must record the overrides in commit order"
    );

    // ── Race phase: two concurrent overrides ──
    let ((sa, ba), (sb, bb)) = tokio::join!(
        override_plan("pro", "rc06-race-pro"),
        override_plan("enterprise", "rc06-race-ent"),
    );
    assert!(
        sa.is_success() && sb.is_success(),
        "both racing overrides must commit, got {sa} {ba:?} / {sb} {bb:?}"
    );

    let (plan_id, reason): (String, String) = sqlx::query_as(
        "SELECT plan_id, reason FROM plan_overrides WHERE tenant_id = $1",
    )
    .bind(&tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let consistent_pairs = [
        ("pro", "rc06-race-pro"),
        ("enterprise", "rc06-race-ent"),
    ];
    assert!(
        consistent_pairs.contains(&(plan_id.as_str(), reason.as_str())),
        "the stored override must be one request's CONSISTENT (plan, reason) pair, \
         got (\"{plan_id}\", \"{reason}\") — a mixed pair means the atomic upsert broke"
    );

    // Audit completeness: each override (2 sequential + 2 racing) audited
    // exactly once, and the stored plan is one of the audited plans (audit
    // + override commit in ONE transaction — a detached audit fails here).
    // NOTE: audit rows are timestamped with their transaction's NOW(), so
    // under the race the audit ORDER can invert vs. commit order; the
    // order-sensitive last-writer check above ran in the SEQUENTIAL phase.
    let audited_plans: Vec<(String,)> = sqlx::query_as(
        "SELECT details->>'planId' FROM billing_audit_log \
         WHERE tenant_id = $1 AND action = 'plan_override'",
    )
    .bind(&tenant_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    let audited_plans: Vec<String> =
        audited_plans.into_iter().map(|(plan,)| plan).collect();
    assert_eq!(
        audited_plans.len(),
        4,
        "each override must audit exactly once, got {audited_plans:?}"
    );
    assert!(
        audited_plans.iter().any(|p| p == &plan_id),
        "the stored plan must appear in the audit trail"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// RC-TEST-07: idempotency middleware atomic claim — REAL middleware+route
// ═══════════════════════════════════════════════════════════════════════════

/// The idempotency middleware's Redis SET-NX claim: a sequential replay
/// with the same key + body receives the CACHED first response while the
/// handler executes EXACTLY ONCE (one webhook row); a concurrent duplicate
/// is refused with 409 + Retry-After.
#[tokio::test]
async fn rc07_idempotency_middleware_claim_is_atomic() {
    let Some(pool) = optional_canonical_pool("rc07_idempotency_middleware").await else {
        return;
    };
    require_reachable_redis("rc07_idempotency_middleware").await;
    let app = build_test_app(pool.clone()).await;
    let (tenant_id, key) =
        seed_tenant_with_key(&pool, "starter", &["webhooks:write", "webhooks:read"]).await;
    let _ = &tenant_id;

    let idem_key = format!("rc07-{}", Uuid::new_v4());
    let webhook_url = format!("https://hooks.example/rc07-{}", Uuid::new_v4());
    let send = |replay: bool| {
        let app = app.clone();
        let key = key.clone();
        let idem = idem_key.clone();
        let url = webhook_url.clone();
        async move {
            let headers = if replay {
                vec![("idempotency-key", idem)]
            } else {
                vec![]
            };
            dispatch(
                &app,
                Method::POST,
                "/v1/webhooks",
                &key,
                &headers,
                Some(serde_json::json!({ "url": url, "events": ["message.delivered"] })),
            )
            .await
        }
    };

    // ── Sequential replay: cached response, handler ran ONCE ──
    let (first_status, first_body) = send(true).await;
    assert!(
        first_status == StatusCode::CREATED,
        "the first keyed create must be 201, got {first_status}: {first_body:?}"
    );
    let (replay_status, replay_body) = send(true).await;
    assert_eq!(
        replay_status, first_status,
        "the replay must serve the cached response"
    );
    assert_eq!(
        replay_body.get("id"), first_body.get("id"),
        "the replay must be the SAME resource, not a second create"
    );
    let (rows,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM webhooks WHERE url = $1")
            .bind(&webhook_url)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        rows, 1,
        "the idempotency middleware must let the handler execute exactly once"
    );

    // ── Concurrent duplicates: one executes, the duplicate is 409'd ──
    let fresh_key = format!("rc07-concurrent-{}", Uuid::new_v4());
    let fresh_url = format!("https://hooks.example/rc07c-{}", Uuid::new_v4());
    let race = |k: String| {
        let app = app.clone();
        let key = key.clone();
        let url = fresh_url.clone();
        async move {
            dispatch(
                &app,
                Method::POST,
                "/v1/webhooks",
                &key,
                &[("idempotency-key", k)],
                Some(serde_json::json!({ "url": url, "events": ["message.delivered"] })),
            )
            .await
        }
    };
    let ((sa, mut sa_body), (sb, mut sb_body)) =
        tokio::join!(race(fresh_key.clone()), race(fresh_key.clone()));
    let executed = sa.is_success();
    assert_eq!(
        [sa.is_success(), sb.is_success()].iter().filter(|ok| **ok).count(),
        1,
        "exactly one racing duplicate may execute: {sa} {sa_body:?} / {sb} {sb_body:?}"
    );
    let (conflict_status, conflict_body) = if executed {
        (sb, std::mem::take(&mut sb_body))
    } else {
        (sa, std::mem::take(&mut sa_body))
    };
    assert_eq!(
        conflict_status,
        StatusCode::CONFLICT,
        "the racing duplicate must be refused while the original is in flight: {conflict_body:?}"
    );
    let (rows,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM webhooks WHERE url = $1")
            .bind(&fresh_url)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(rows, 1, "the concurrent duplicate must not create a second webhook");
}

// ═══════════════════════════════════════════════════════════════════════════
// SM12 F16b: admin invoice creation over HTTP — per-period dedupe
// ═══════════════════════════════════════════════════════════════════════════

/// `POST /v1/admin/tenants/:id/invoices` creates an invoice for a period
/// and REFUSES a second invoice for the same period with a 409 naming the
/// existing invoice (the advisory-locked period guard).
#[tokio::test]
async fn f16b_admin_invoice_creation_is_deduplicated_per_period() {
    // TEMP DIAGNOSTIC.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")))
        .with_test_writer()
        .try_init();
    let Some(pool) = optional_canonical_pool("f16b_invoice_dedupe").await else {
        return;
    };
    let app = build_test_app(pool.clone()).await;
    let admin_key = seed_system_admin_key(&pool).await;
    let (tenant_id, _) = seed_tenant_with_key(&pool, "starter", &["billing:read"]).await;

    // The invoice writer snapshots the tenant's billing address, whose
    // `email` column feeds the e-invoice buyer contact. Migration 132 allows
    // a NULL email at the schema level, but production's snapshot query
    // decodes it as a non-optional String — a NULL here surfaces as a 500
    // (escalated to the api-server owner; see the SM12 verification report).
    // A real invoiceable tenant carries a billing email, so the fixture does
    // too — keeping this test pinning the PERIOD DEDUP, not that decode.
    sqlx::query(
        "INSERT INTO billing_addresses (tenant_id, company_name, address_line1, city, postal_code, country, email)
         VALUES ($1, 'Concurrency Fixture OÜ', 'Tänav 1', 'Tallinn', '10111', 'EE', 'billing@concurrency-fixture.example')",
    )
    .bind(&tenant_id)
    .execute(&pool)
    .await
    .expect("seed billing address");

    let create_invoice = || {
        let app = app.clone();
        let admin = admin_key.clone();
        let tenant = tenant_id.clone();
        async move {
            dispatch(
                &app,
                Method::POST,
                &format!("/v1/billing/admin/tenants/{tenant}/invoices"),
                &admin,
                &[],
                Some(serde_json::json!({
                    "periodStart": "2026-01-01T00:00:00Z",
                    "periodEnd": "2026-02-01T00:00:00Z",
                    "lineItems": [],
                    "notes": "f16b",
                })),
            )
            .await
        }
    };

    let (first_status, first_body) = create_invoice().await;
    assert!(
        first_status.is_success(),
        "the first invoice must be created, got {first_status}: {first_body:?}"
    );
    // Success envelope: ApiResponse { data: LegacyInvoiceDto { id, ... } }.
    let invoice_id = first_body["data"]["id"]
        .as_str()
        .or_else(|| first_body["invoice"]["id"].as_str())
        .or_else(|| first_body["id"].as_str())
        .expect("the created invoice carries an id")
        .to_string();

    let (dup_status, dup_body) = create_invoice().await;
    assert_eq!(
        dup_status,
        StatusCode::CONFLICT,
        "a second invoice for the SAME period must 409, got {dup_status}: {dup_body:?}"
    );
    // The SHIPPED conflict envelope is the generic ApiError naming the
    // period in `error.message` — the same contract api-server's in-crate
    // suite pins (api-server/src/routes/billing.rs, "Duplicate period ->
    // 409"). (The advisory-locked helper's richer `existingInvoiceId` body
    // is remapped into ApiError before it reaches the wire.)
    assert_eq!(
        dup_body["error"]["message"].as_str(),
        Some("Invoice already exists for this period"),
        "the conflict must name the period, got: {dup_body:?}"
    );
    // The behavior the whole test exists for, pinned at the storage layer:
    // exactly ONE non-void invoice exists for the period, and it is the
    // one the first request created.
    let (rows, stored_id): (i64, String) = sqlx::query_as(
        "SELECT COUNT(*), MIN(id::text) FROM invoices \
         WHERE tenant_id = $1 AND period_start = $2::timestamptz AND period_end = $3::timestamptz \
         AND status <> 'void'",
    )
    .bind(&tenant_id)
    .bind("2026-01-01T00:00:00Z")
    .bind("2026-02-01T00:00:00Z")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rows, 1, "a duplicate period must not mint a second invoice");
    assert_eq!(
        stored_id, invoice_id,
        "the surviving invoice must be the first request's"
    );
}
