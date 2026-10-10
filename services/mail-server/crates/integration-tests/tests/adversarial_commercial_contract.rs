//! Adversarial cross-service commercial / compliance contract tests.
//!
//! Pins the perfect commercial contract across billing, compliance,
//! enterprise and pricing authority (docs/pricing-authority.md):
//!
//! * Enterprise impersonation start writes an `audit_logs` row AND requires
//!   the control-plane role (wildcard scope + system tenant) — a customer
//!   tenant admin must never mint an impersonation session.
//! * Destructive admin actions (tenant delete, operator delete) require an
//!   explicit typed confirmation — no silent destroy.
//! * SLA/credits matrix is plan-scoped (Business 30%, Enterprise 25%) and
//!   invents no coverage for other plans.
//! * Enterprise IP quota matches the catalog: 3 included dedicated IPs,
//!   NOT the marketing myth of 10.
//!
//! Harness: real `api_server::app::build_app` over the canonical migration
//! chain (`TEST_DATABASE_URL` unset ⇒ soft-skip; configured breakage panics).
//! Redis is required for impersonation single-use jti (fail-closed).

use std::sync::Mutex;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
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
// Harness
// ═══════════════════════════════════════════════════════════════════════════

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
    migrator::test_support::optional_pg_pool(test_name, &format!("advcom_{test_name}")).await
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
        host: "127.0.0.1".into(),
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

async fn seed_api_key_for(pool: &PgPool, tenant_id: &str, scopes: &[&str]) -> String {
    let raw_key = apexmail_lib::id::generate_api_key(true);
    let key_hash = apexmail_lib::hash_api_key_with_secret(
        &raw_key,
        "test-api-key-secret-12345678901234567890",
    );
    sqlx::query(
        "INSERT INTO api_keys (id, tenant_id, name, key_prefix, key_hash, scopes, created_at, updated_at)
         VALUES ($1, $2, 'adversarial commercial fixture', 'am_test_', $3, $4::jsonb, NOW(), NOW())",
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

async fn seed_customer_tenant(pool: &PgPool, plan: &str, scopes: &[&str]) -> (String, String) {
    let tenant_id = apexmail_lib::id::generate_id("ten", 21);
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
         VALUES ($1, 'commercial contract tenant', $1, $2, 'active', NOW(), NOW())",
    )
    .bind(&tenant_id)
    .bind(plan)
    .execute(pool)
    .await
    .expect("seed customer tenant");
    let key = seed_api_key_for(pool, &tenant_id, scopes).await;
    (tenant_id, key)
}

async fn seed_system_admin_key(pool: &PgPool) -> String {
    // The canonical chain (migration 072) already seeds the system tenant
    // with id `system_internal_tenant01` / slug `system`. Use THAT id — a
    // hand-picked 'system' id never existed, so the operator FK below failed
    // (and an invented duplicate collided on the slug unique index).
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
         VALUES ($1, 'ApexMail Platform', 'system', 'enterprise', 'active', NOW(), NOW())
         ON CONFLICT DO NOTHING",
    )
    .bind(api_server::routes::SYSTEM_TENANT_ID)
    .execute(pool)
    .await
    .expect("seed system tenant");
    seed_api_key_for(pool, api_server::routes::SYSTEM_TENANT_ID, &["*"]).await
}

fn api_key_request(method: &str, uri: &str, key: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("x-api-key", key)
        .header("content-type", "application/json")
        .body(Body::empty())
        .expect("request")
}

async fn call(app: &axum::Router, request: Request<Body>) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("router infallible");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// Mint a correctly-signed impersonation token (the CP UI shape).
fn impersonation_token(payload: &serde_json::Value, secret: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let payload_json = serde_json::to_vec(payload).expect("serialize payload");
    let payload_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &payload_json,
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(payload_b64.as_bytes());
    let sig_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        mac.finalize().into_bytes(),
    );
    format!("{payload_b64}.{sig_b64}")
}

fn valid_impersonation_payload(jti: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "impersonation",
        "tenantId": "ten_victim_commercial",
        "operatorId": "op_commercial",
        "operatorName": "Commercial Operator",
        "exp": chrono::Utc::now().timestamp_millis() + 600_000,
        "jti": jti,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// Enterprise impersonation: audited + role-gated
// ═══════════════════════════════════════════════════════════════════════════

/// Impersonation start from the control-plane role writes the audit row
/// naming the session and the operator. A customer tenant admin — even with
/// the wildcard `*` scope every tenant owner carries — is refused.
#[tokio::test]
async fn enterprise_impersonation_start_is_audited_and_requires_control_plane_role() {
    if std::env::var("TEST_REDIS_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .is_none()
    {
        migrator::test_support::assert_soft_skip_allowed("TEST_REDIS_URL");
        eprintln!("skipping: TEST_REDIS_URL unset (impersonation jti is Redis-backed)");
        return;
    }
    let Some(pool) = optional_canonical_pool("impersonation_role").await else {
        return;
    };
    let app = build_test_app(pool.clone()).await;

    let admin_key = seed_system_admin_key(&pool).await;
    let (_customer_tenant, customer_key) = seed_customer_tenant(&pool, "enterprise", &["*"]).await;

    // ── Role gate: a customer tenant admin with `*` must NOT start an
    //    impersonation session (require_scopes alone is insufficient —
    //    every tenant owner carries the wildcard).
    let jti_denied = format!("jti-{}", Uuid::new_v4().simple());
    let body = serde_json::json!({
        "token": impersonation_token(&valid_impersonation_payload(&jti_denied), "test-impersonation-secret-12345"),
    });
    let (status, json) = call(
        &app,
        Request::builder()
            .method("POST")
            .uri("/v1/auth/impersonate")
            .header("x-api-key", &customer_key)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "customer tenant admin must not mint an impersonation session: {json}"
    );
    let denied_audit: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE action = 'impersonation_session_started' AND resource_id = $1",
    )
    .bind(&jti_denied)
    .fetch_one(&pool)
    .await
    .expect("count denied audits");
    assert_eq!(
        denied_audit, 0,
        "a refused impersonation start must write no audit row"
    );

    // ── Control-plane role: start succeeds, sets the cookie, and writes
    //    the audit row BEFORE the session exists.
    let jti = format!("jti-{}", Uuid::new_v4().simple());
    let body = serde_json::json!({
        "token": impersonation_token(&valid_impersonation_payload(&jti), "test-impersonation-secret-12345"),
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/impersonate")
                .header("x-api-key", &admin_key)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("router infallible");
    let status = response.status();
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "impersonation start redirects to the dashboard"
    );

    let (action, operator, tenant_id): (String, String, Option<String>) = sqlx::query_as(
        "SELECT action, details->>'operator_id', tenant_id FROM audit_logs \
         WHERE action = 'impersonation_session_started' AND resource_id = $1",
    )
    .bind(&jti)
    .fetch_one(&pool)
    .await
    .expect("impersonation audit row");
    assert_eq!(action, "impersonation_session_started");
    assert_eq!(operator, "op_commercial", "audit names the operator");
    assert_eq!(
        tenant_id.as_deref(),
        Some("ten_victim_commercial"),
        "audit is attributed to the impersonated tenant"
    );

    // Replay of the same token (same jti) is refused: single-use.
    let replay = serde_json::json!({
        "token": impersonation_token(&valid_impersonation_payload(&jti), "test-impersonation-secret-12345"),
    });
    let (status, _) = call(
        &app,
        Request::builder()
            .method("POST")
            .uri("/v1/auth/impersonate")
            .header("x-api-key", &admin_key)
            .header("content-type", "application/json")
            .body(Body::from(replay.to_string()))
            .expect("request"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an impersonation token is single-use (jti tombstone)"
    );
    let audit_after_replay: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE action = 'impersonation_session_started' AND resource_id = $1",
    )
    .bind(&jti)
    .fetch_one(&pool)
    .await
    .expect("count audits after replay");
    assert_eq!(
        audit_after_replay, 1,
        "replay must not write a second audit row"
    );

    pool.close().await;
}

// ═══════════════════════════════════════════════════════════════════════════
// Destructive admin actions require typed confirmation
// ═══════════════════════════════════════════════════════════════════════════

/// Tenant delete requires the exact typed confirmation phrase
/// `DELETE <tenant_id>` — wrong phrase, missing phrase, and another
/// tenant's id are all refused before any row is touched.
#[tokio::test]
async fn tenant_delete_requires_the_typed_confirmation_phrase() {
    let Some(pool) = optional_canonical_pool("delete_confirm").await else {
        return;
    };
    let app = build_test_app(pool.clone()).await;
    let admin_key = seed_system_admin_key(&pool).await;

    let victim = apexmail_lib::id::generate_id("ten", 21);
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
         VALUES ($1, 'delete-confirm victim', $1, 'free', 'active', NOW(), NOW())",
    )
    .bind(&victim)
    .execute(&pool)
    .await
    .expect("seed victim tenant");

    // DELETE /v1/admin/tenants carries {id, confirmation} in the body.
    let delete_uri = "/v1/admin/tenants";

    // 1. Wrong phrase → 400 naming the expected phrase.
    let (status, json) = call(
        &app,
        Request::builder()
            .method("DELETE")
            .uri(delete_uri)
            .header("x-api-key", &admin_key)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({ "id": victim, "confirmation": "DELETE wrong" }).to_string(),
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {json}");
    let message = json["error"]["message"].as_str().unwrap_or_default();
    let details = json["error"]["details"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    assert!(
        message.contains("DELETE") || details.contains("DELETE"),
        "refusal must name the expected confirmation phrase: message={message} details={details}"
    );

    // 2. Another tenant's id in the phrase → 400 (typed confirmation is
    //    bound to THIS tenant).
    let (status, _) = call(
        &app,
        Request::builder()
            .method("DELETE")
            .uri(delete_uri)
            .header("x-api-key", &admin_key)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({ "id": victim, "confirmation": "DELETE ten_other" }).to_string(),
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // 3. Missing confirmation field entirely → 4xx, never a silent destroy.
    let (status, _) = call(
        &app,
        Request::builder()
            .method("DELETE")
            .uri(delete_uri)
            .header("x-api-key", &admin_key)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::json!({ "id": victim }).to_string()))
            .expect("request"),
    )
    .await;
    assert!(
        status.is_client_error(),
        "missing confirmation must be a 4xx, got {status}"
    );

    // Nothing was deleted by any of the refusals.
    let still_there: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenants WHERE id = $1")
        .bind(&victim)
        .fetch_one(&pool)
        .await
        .expect("count victim");
    assert_eq!(
        still_there, 1,
        "refused deletes must not destroy the tenant"
    );

    // 4. Exact phrase → the delete proceeds.
    let (status, _) = call(
        &app,
        Request::builder()
            .method("DELETE")
            .uri(delete_uri)
            .header("x-api-key", &admin_key)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({ "id": victim, "confirmation": format!("DELETE {victim}") })
                    .to_string(),
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "confirmed delete must succeed"
    );
    let gone: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenants WHERE id = $1")
        .bind(&victim)
        .fetch_one(&pool)
        .await
        .expect("count after delete");
    assert_eq!(gone, 0, "confirmed delete removes the tenant");
}

/// Operator delete requires `?confirm=true` — the query echo proves intent.
#[tokio::test]
async fn operator_delete_requires_the_confirm_echo() {
    let Some(pool) = optional_canonical_pool("operator_confirm").await else {
        return;
    };
    let app = build_test_app(pool.clone()).await;
    let admin_key = seed_system_admin_key(&pool).await;

    // Operators are `users` rows on the caller's tenant with role
    // admin/owner (see routes/admin/operators.rs). Seed a deletable admin
    // on the system tenant.
    let operator_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status)
         VALUES ($1, $3, $2, 'Commercial Operator', 'x', 'admin', 'active')",
    )
    .bind(operator_id)
    .bind(format!("op-{}@apexmail.test", Uuid::new_v4().simple()))
    .bind(api_server::routes::SYSTEM_TENANT_ID)
    .execute(&pool)
    .await
    .expect("seed operator");

    // Missing confirm → 400.
    let (status, json) = call(
        &app,
        api_key_request(
            "DELETE",
            &format!("/v1/admin/operators/{operator_id}"),
            &admin_key,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "delete without ?confirm=true must be refused: {json}"
    );

    // confirm=false → refused.
    let (status, _) = call(
        &app,
        api_key_request(
            "DELETE",
            &format!("/v1/admin/operators/{operator_id}?confirm=false"),
            &admin_key,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "confirm=false must be refused"
    );

    let still_there: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE id = $1")
        .bind(operator_id)
        .fetch_one(&pool)
        .await
        .expect("count operator");
    assert_eq!(
        still_there, 1,
        "refused deletes must not destroy the operator"
    );

    // confirm=true → 204, row gone.
    let (status, _) = call(
        &app,
        api_key_request(
            "DELETE",
            &format!("/v1/admin/operators/{operator_id}?confirm=true"),
            &admin_key,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "confirmed delete succeeds");
    let gone: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE id = $1")
        .bind(operator_id)
        .fetch_one(&pool)
        .await
        .expect("count after delete");
    assert_eq!(gone, 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// SLA / IP quota — plan-scoped, catalog-true
// ═══════════════════════════════════════════════════════════════════════════

/// SLA credit caps and included IP quotas are catalog facts. This test
/// asserts the cross-service agreement: the billing seeds (which api-server
/// and enterprise read through `plans.features`) match the published matrix
/// — Business 30% / 1 IP, Enterprise Cloud 25% / 3 IPs — and no other plan
/// invents SLA coverage or dedicated-IP capacity.
#[test]
fn sla_and_ip_quotas_are_plan_scoped_and_match_the_catalog() {
    // Authoritative seed ladder (plans.rs, pinned to platform-catalog).
    let expected: &[(&str, bool, i32, i32)] = &[
        // plan, sla_guarantee, sla_credit_pct, dedicated_ip_count
        ("free", false, 0, 0),
        ("starter", false, 0, 0),
        ("pro", false, 0, 0),
        ("growth", false, 0, 1),
        ("scale", true, 30, 1),
        ("enterprise", true, 25, 3),
        ("payg", false, 0, 0),
    ];
    for (name, guarantee, credit_pct, ip_count) in expected {
        let seed = billing_service::plans::builtin_plan_seed(Some(name));
        assert_eq!(
            seed.features.sla_guarantee, *guarantee,
            "{name}.sla_guarantee"
        );
        assert_eq!(
            seed.features.sla_credit_percentage, *credit_pct,
            "{name}.sla_credit_percentage"
        );
        assert_eq!(
            seed.features.dedicated_ip_count, *ip_count,
            "{name}.dedicated_ip_count"
        );
    }

    // Enterprise is 3, never the marketing "10 dedicated IPs".
    let enterprise = billing_service::plans::builtin_plan_seed(Some("enterprise"));
    assert_eq!(enterprise.features.dedicated_ip_count, 3);
    assert_ne!(enterprise.features.dedicated_ip_count, 10);

    // Plans without the SLA guarantee carry no credit percentage — the
    // matrix invents no coverage.
    for seed in billing_service::plans::default_plans() {
        if !seed.features.sla_guarantee {
            assert_eq!(
                seed.features.sla_credit_percentage, 0,
                "{}: no SLA guarantee ⇒ no credit cap",
                seed.name
            );
        }
    }
}
