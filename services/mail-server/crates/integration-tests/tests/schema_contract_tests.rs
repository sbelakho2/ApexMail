//! Fail-first schema contract tests.
//!
//! These tests verify that every SQL column/table referenced in application code
//! actually exists in the database schema. They are designed to FAIL first —
//! detecting migration drift before it reaches production.
//!
//! Run with:cargo test --test schema_contract_tests -- --nocapture
//! Requires:PostgreSQL + Redis running with all migrations applied.

use std::{fs, path::PathBuf};

use api_server::{
    app::build_app,
    config::{Config, Environment},
    routes::admin::tenants::delete_tenant_records,
    ses_provider::SesIpProvider,
    state::AppStateInner,
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use deadpool_redis::Config as RedisConfig;
use sqlx::{migrate::Migrator, PgPool};
use std::time::Duration;
use tower::ServiceExt;
use uuid::Uuid;

fn tool_migrations_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../tools/migrations")
}

async fn apply_tool_migrations(pool: &PgPool) {
    let source_dir = tool_migrations_dir();
    let temp_dir =
        std::env::temp_dir().join(format!("apexmail-sqlx-up-migrations-{}", Uuid::new_v4()));

    fs::create_dir_all(&temp_dir).expect("failed to create temp sqlx migration directory");

    let mut entries: Vec<PathBuf> = fs::read_dir(&source_dir)
        .expect("failed to read tools/migrations")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("sql"))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| !name.ends_with("_down.sql") && !name.contains("performance_indexes"))
                .unwrap_or(false)
        })
        .collect();
    entries.sort();

    for path in entries {
        let file_name = path.file_name().expect("migration path missing filename");
        let raw = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read migration {:?}: {error}", path));
        let normalized = raw
            .replace("CREATE UNIQUE INDEX CONCURRENTLY", "CREATE UNIQUE INDEX")
            .replace("CREATE INDEX CONCURRENTLY", "CREATE INDEX");
        fs::write(temp_dir.join(file_name), normalized)
            .unwrap_or_else(|error| panic!("failed to write copied migration {:?}: {error}", path));
    }

    let migrator = Migrator::new(temp_dir.clone())
        .await
        .expect("failed to load copied up migrations");
    migrator
        .run(pool)
        .await
        .expect("failed to apply copied up migrations");

    let _ = fs::remove_dir_all(&temp_dir);
}

fn bounded_id(prefix: &str) -> String {
    let suffix_len = 26usize.saturating_sub(prefix.len() + 1);
    apexmail_lib::id::generate_id(prefix, suffix_len)
}

fn test_config() -> Config {
    Config {
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
        redis_host: "localhost".into(),
        redis_port: 6379,
        redis_password: None,
        redis_db: 0,
        redis_pool_max_size: 40,
        jwt_private_key_pem: "BEGIN TEST".into(),
        jwt_public_key_pem: "BEGIN TEST".into(),
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
        webhook_max_retries: 3,
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
    }
}

async fn registration_test_app(pool: PgPool) -> Router {
    std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
    std::env::set_var("AWS_ACCESS_KEY_ID", "test");
    std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");

    let redis = RedisConfig::from_url("redis://127.0.0.1:6379")
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .expect("failed to create lazy redis pool");

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

    build_app(
        AppStateInner::new(
            pool,
            redis,
            test_config(),
            reqwest::Client::new(),
            ses_provider,
            None,
        )
        .await
        .expect("failed to create test app state"),
    )
}

/// Helper:create a test tenant and return its ID.
async fn insert_test_tenant(pool: &PgPool, suffix: &str) -> String {
    let id = bounded_id("ten");
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status) VALUES ($1, $2, $3, 'free', 'active')
         ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name",
    )
    .bind(&id)
    .bind(format!("Test Tenant {suffix}"))
    .bind(format!("test-{suffix}"))
    .execute(pool)
    .await
    .expect("failed to insert test tenant");
    id
}

/// Helper:create a test user and return its ID.
async fn insert_test_user(pool: &PgPool, tenant_id: &str, email: &str) -> String {
    let id = bounded_id("usr");
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, password_hash, role, status)
         VALUES ($1, $2, $3, '$argon2id$v=19$m=19456,t=2,p=1$fakehash', 'owner', 'active')
         ON CONFLICT (tenant_id, email) DO UPDATE SET status = EXCLUDED.status",
    )
    .bind(&id)
    .bind(tenant_id)
    .bind(email)
    .execute(pool)
    .await
    .expect("failed to insert test user");
    id
}

async fn count_rows_for_tenant(pool: &PgPool, table_name: &str, tenant_id: &str) -> i64 {
    let query = format!(
        "SELECT COUNT(*)::bigint FROM \"{}\" WHERE tenant_id::text = $1",
        table_name.replace('"', "\"\"")
    );

    sqlx::query_scalar::<_, i64>(&query)
        .bind(tenant_id)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|error| panic!("failed to count tenant rows in {table_name}: {error}"))
}

async fn tenant_scoped_tables(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT columns.table_name
                 FROM information_schema.columns AS columns
                 JOIN information_schema.tables AS tables
                     ON tables.table_schema = columns.table_schema
                    AND tables.table_name = columns.table_name
                 WHERE columns.table_schema = 'public'
                     AND columns.column_name = 'tenant_id'
                     AND columns.table_name <> 'tenants'
                     AND tables.table_type = 'BASE TABLE'
                 ORDER BY columns.table_name",
    )
    .fetch_all(pool)
    .await
    .expect("failed to enumerate tenant-scoped tables")
}

// ═══════════════════════════════════════════════════════════════════════════
// messages table column contract
// ═══════════════════════════════════════════════════════════════════════════

#[sqlx::test]
async fn messages_table_has_to_emails_column(pool: PgPool) {
    apply_tool_migrations(&pool).await;

    // The messages.rs send_message handler INSERTs into (to_emails, cc_emails, bcc_emails).
    // If these columns don't exist, this will fail at runtime.
    let tenant_id = insert_test_tenant(&pool, "to_emails").await;

    let result = sqlx::query(
        "INSERT INTO messages (id, tenant_id, from_email, to_emails, cc_emails, bcc_emails,
         subject, html_body, text_body, status, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'queued', NOW())",
    )
    .bind(bounded_id("msg"))
    .bind(&tenant_id)
    .bind("sender@example.com")
    .bind(serde_json::json!(["recipient@example.com"]))
    .bind(serde_json::json!([]))
    .bind(serde_json::json!([]))
    .bind("Test Subject")
    .bind("<p>Hello</p>")
    .bind("Hello")
    .execute(&pool)
    .await;

    assert!(
        result.is_ok(),
        "INSERT with to_emails/cc_emails/bcc_emails failed: {:?}. \
        The messages table is missing columns that messages.rs depends on.",
        result.err()
    );
}

#[sqlx::test]
async fn messages_table_has_html_body_and_text_body_columns(pool: PgPool) {
    apply_tool_migrations(&pool).await;

    // messages.rs uses html_body/text_body but initial schema has html_body/text_body
    // and the send handler also writes html/text. Verify both exist.
    let tenant_id = insert_test_tenant(&pool, "htmltext").await;

    let result = sqlx::query(
        "INSERT INTO messages (id, tenant_id, from_email, to_emails, subject, html_body, text_body, status, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'queued', NOW())",
    )
    .bind(bounded_id("msg"))
    .bind(&tenant_id)
    .bind("sender@example.com")
    .bind(serde_json::json!(["recipient@example.com"]))
    .bind("Subject")
    .bind("<p>HTML</p>")
    .bind("Plain text")
    .execute(&pool)
    .await;

    assert!(
        result.is_ok(),
        "INSERT with html_body/text_body failed: {:?}",
        result.err()
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// sessions table existence
// ═══════════════════════════════════════════════════════════════════════════

#[sqlx::test]
async fn sessions_table_exists_for_password_reset(pool: PgPool) {
    apply_tool_migrations(&pool).await;

    let tenant_id = insert_test_tenant(&pool, "sessions").await;
    let user_id = insert_test_user(&pool, &tenant_id, "sessions@test.com").await;

    // auth.rs:693 does DELETE FROM sessions WHERE user_id = $1
    let result = sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(&user_id)
        .execute(&pool)
        .await;

    assert!(
        result.is_ok(),
        "DELETE FROM sessions failed: {:?}. \
        The sessions table does not exist — password reset/change will crash.",
        result.err()
    );
}

#[sqlx::test]
async fn sessions_table_accepts_insert(pool: PgPool) {
    apply_tool_migrations(&pool).await;

    let tenant_id = insert_test_tenant(&pool, "sessinsert").await;
    let user_id = insert_test_user(&pool, &tenant_id, "sessinsert@test.com").await;

    let result = sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at)
         VALUES ($1, $2, $3, NOW(), NOW() + INTERVAL '7 days')",
    )
    .bind(bounded_id("sess"))
    .bind(&user_id)
    .bind("abc123hash")
    .execute(&pool)
    .await;

    assert!(
        result.is_ok(),
        "INSERT INTO sessions failed: {:?}. \
        Sessions table may be missing required columns.",
        result.err()
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// metering_events table existence
// ═══════════════════════════════════════════════════════════════════════════

#[sqlx::test]
async fn metering_events_table_exists(pool: PgPool) {
    apply_tool_migrations(&pool).await;

    let tenant_id = insert_test_tenant(&pool, "metering").await;
    let event_id = Uuid::new_v4();

    // usage.rs:50-65 INSERTs into metering_events
    let result = sqlx::query(
        "INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp, metadata)
         VALUES ($1, $2, $3::text::meter_event_type, $4, $5, $6)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(event_id)
    .bind(&tenant_id)
    .bind("emails_sent")
    .bind(1_i64)
    .bind(chrono::Utc::now())
    .bind(serde_json::json!({}))
    .execute(&pool)
    .await;

    assert!(
        result.is_ok(),
        "INSERT INTO metering_events failed: {:?}. \
        The metering_events table does not exist — billing is completely broken.",
        result.err()
    );
}

#[sqlx::test]
async fn metering_events_aggregation_works(pool: PgPool) {
    apply_tool_migrations(&pool).await;

    // usage.rs:88-103 aggregates from metering_events
    let result = sqlx::query(
        "SELECT event_type, SUM(quantity)::bigint as total
         FROM metering_events
         WHERE tenant_id = 'nonexistent'
         GROUP BY event_type",
    )
    .fetch_all(&pool)
    .await;

    assert!(
        result.is_ok(),
        "SELECT FROM metering_events failed: {:?}. \
        The table or its columns are missing.",
        result.err()
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// plans table has email_limit and api_call_limit
// ═══════════════════════════════════════════════════════════════════════════

#[sqlx::test]
async fn plans_table_has_email_limit_column(pool: PgPool) {
    apply_tool_migrations(&pool).await;

    // usage.rs:120-132 queries p.email_limit and p.api_call_limit
    let result = sqlx::query(
        "SELECT COALESCE(p.email_limit, 0) as email_limit,
                COALESCE(p.api_call_limit, 0) as api_call_limit
         FROM tenants t
         JOIN plans p ON t.plan = p.name
         WHERE t.id = 'nonexistent'",
    )
    .fetch_optional(&pool)
    .await;

    assert!(
        result.is_ok(),
        "SELECT email_limit/api_call_limit FROM plans failed: {:?}. \
        The plans table is missing email_limit and/or api_call_limit columns.",
        result.err()
    );
}

#[sqlx::test]
async fn plans_table_accepts_limits(pool: PgPool) {
    apply_tool_migrations(&pool).await;

    let plan_name = apexmail_lib::id::generate_id("plan", 16);

    let result = sqlx::query(
        "INSERT INTO plans (
            name, display_name, description, price_monthly, price_yearly,
            features, email_limit, api_call_limit, is_active, sort_order
         ) VALUES (
            $1, 'Test Plan', 'schema contract test plan', 0, 0,
            '{}', 1000, 5000, true, 0
         )
         ON CONFLICT (name) DO UPDATE
         SET email_limit = EXCLUDED.email_limit,
             api_call_limit = EXCLUDED.api_call_limit",
    )
    .bind(&plan_name)
    .execute(&pool)
    .await;

    assert!(
        result.is_ok(),
        "INSERT into plans with email_limit/api_call_limit failed: {:?}. \
        These columns are missing from the plans table.",
        result.err()
    );

    // Cleanup
    let _ = sqlx::query("DELETE FROM plans WHERE name = $1")
        .bind(&plan_name)
        .execute(&pool)
        .await;
}

// ═══════════════════════════════════════════════════════════════════════════
// domains table column names
// ═══════════════════════════════════════════════════════════════════════════

#[sqlx::test]
async fn domains_table_uses_correct_column_names(pool: PgPool) {
    apply_tool_migrations(&pool).await;

    let tenant_id = insert_test_tenant(&pool, "domcols").await;

    // messages.rs:485-495 queries:WHERE tenant_id = $1 AND name = $2 AND verified = true
    // After migration 003, the column is 'domain' not 'name', and 'is_verified' not 'verified'
    let result = sqlx::query(
        "SELECT 1 FROM domains WHERE tenant_id = $1 AND domain = $2 AND is_verified = true",
    )
    .bind(&tenant_id)
    .bind("example.com")
    .fetch_optional(&pool)
    .await;

    assert!(
        result.is_ok(),
        "SELECT from domains with 'domain' and 'is_verified' columns failed: {:?}. \
        The column names may not match what the code expects.",
        result.err()
    );
}

#[sqlx::test]
async fn domains_table_allows_insert_with_domain_column(pool: PgPool) {
    apply_tool_migrations(&pool).await;

    let tenant_id = insert_test_tenant(&pool, "dominsert").await;
    let domain_id = bounded_id("dom");

    let result = sqlx::query(
        "INSERT INTO domains (id, tenant_id, domain, is_verified)
         VALUES ($1, $2, $3, true)
         ON CONFLICT DO NOTHING",
    )
    .bind(&domain_id)
    .bind(&tenant_id)
    .bind("verified.example.com")
    .execute(&pool)
    .await;

    assert!(
        result.is_ok(),
        "INSERT INTO domains with 'domain' column failed: {:?}. \
        Column may still be named 'name' or migration not applied.",
        result.err()
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// api_keys table column names
// ═══════════════════════════════════════════════════════════════════════════

#[sqlx::test]
async fn api_keys_table_uses_prefix_not_key_prefix(pool: PgPool) {
    apply_tool_migrations(&pool).await;

    // After migration 003, the column is 'prefix' not 'key_prefix'
    let result = sqlx::query(
        "SELECT id, name, prefix, scopes FROM api_keys WHERE tenant_id = 'nonexistent'",
    )
    .fetch_all(&pool)
    .await;

    assert!(
        result.is_ok(),
        "SELECT prefix FROM api_keys failed: {:?}. \
        The column may still be 'key_prefix' — migration 003 rename not applied.",
        result.err()
    );
}

#[sqlx::test]
async fn api_keys_insert_with_prefix_column(pool: PgPool) {
    apply_tool_migrations(&pool).await;

    let tenant_id = insert_test_tenant(&pool, "apikeys").await;
    let user_id = insert_test_user(&pool, &tenant_id, "apikeys@test.com").await;
    let key_id = bounded_id("key");

    let result = sqlx::query(
        "INSERT INTO api_keys (id, tenant_id, user_id, name, prefix, key_hash, scopes)
         VALUES ($1, $2, $3, 'Test Key', 'ak_test', 'hash123', '[\"*\"]')",
    )
    .bind(&key_id)
    .bind(&tenant_id)
    .bind(&user_id)
    .execute(&pool)
    .await;

    assert!(
        result.is_ok(),
        "INSERT INTO api_keys with 'prefix' column failed: {:?}. \
        Code uses 'key_prefix' but schema has 'prefix'.",
        result.err()
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// invoices table existence
// ═══════════════════════════════════════════════════════════════════════════

#[sqlx::test]
async fn invoices_table_exists(pool: PgPool) {
    apply_tool_migrations(&pool).await;

    let result = sqlx::query(
        "SELECT id, tenant_id, amount_cents, status, created_at FROM invoices WHERE tenant_id = 'nonexistent'",
    )
    .fetch_all(&pool)
    .await;

    assert!(
        result.is_ok(),
        "SELECT FROM invoices failed: {:?}. \
        The invoices table does not exist — billing invoice endpoints are broken.",
        result.err()
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// subscriptions tenant_id type compatibility
// ═══════════════════════════════════════════════════════════════════════════

#[sqlx::test]
async fn subscriptions_tenant_id_is_varchar_compatible(pool: PgPool) {
    apply_tool_migrations(&pool).await;

    // subscriptions.tenant_id is UUID but tenants.id is VARCHAR(26)
    // This test verifies the JOIN works
    let result = sqlx::query(
        "SELECT s.id FROM subscriptions s JOIN tenants t ON s.tenant_id::text = t.id WHERE t.id = 'nonexistent'",
    )
    .fetch_all(&pool)
    .await;

    assert!(
        result.is_ok(),
        "JOIN between subscriptions and tenants failed: {:?}. \
        Type mismatch between subscriptions.tenant_id (UUID) and tenants.id (VARCHAR).",
        result.err()
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// users table has enough columns for UserRow struct
// ═══════════════════════════════════════════════════════════════════════════

#[sqlx::test]
async fn users_table_has_all_user_row_columns(pool: PgPool) {
    apply_tool_migrations(&pool).await;

    let tenant_id = insert_test_tenant(&pool, "usercols").await;
    let user_id = insert_test_user(&pool, &tenant_id, "usercols@test.com").await;

    // auth.rs change_password selects:id, tenant_id, email, name, password_hash, role, status
    // But UserRow also needs:mfa_enabled, mfa_secret
    let result = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            String,
            String,
            bool,
            Option<String>,
        ),
    >(
        "SELECT id, tenant_id, email, name, password_hash, role, status, mfa_enabled, mfa_secret
         FROM users WHERE id = $1",
    )
    .bind(&user_id)
    .fetch_optional(&pool)
    .await;

    assert!(
        result.is_ok(),
        "SELECT all UserRow columns from users failed: {:?}. \
        The users table may be missing columns expected by the UserRow struct.",
        result.err()
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Registration atomicity — concurrent same-email registrations
// ═══════════════════════════════════════════════════════════════════════════

#[sqlx::test]
async fn concurrent_registration_same_email_no_orphaned_tenant(pool: PgPool) {
    apply_tool_migrations(&pool).await;

    let app = registration_test_app(pool.clone()).await;
    let unique = &Uuid::new_v4().simple().to_string()[..8];
    let email = format!("concurrent-{unique}@test.com");
    let company_name = format!("Concurrent {unique}");
    let request_body = serde_json::json!({
        "company_name": company_name,
        "email": email,
        "name": "Owner Example",
        "password": "StrongPass123!",
        "plan": "free"
    })
    .to_string();

    let request_a = Request::post("/v1/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(request_body.clone()))
        .unwrap();
    let request_b = Request::post("/v1/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(request_body))
        .unwrap();

    let (response_a, response_b) = tokio::join!(
        app.clone().oneshot(request_a),
        app.clone().oneshot(request_b),
    );

    let response_a = response_a.expect("first registration request failed");
    let response_b = response_b.expect("second registration request failed");
    assert_eq!(response_a.status(), StatusCode::ACCEPTED);
    assert_eq!(response_b.status(), StatusCode::ACCEPTED);

    let user_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM users WHERE LOWER(email) = LOWER($1)")
            .bind(&email)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        user_count.0, 1,
        "registration race created duplicate users for {email}"
    );

    let tenant_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tenants WHERE name = $1")
        .bind(&company_name)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        tenant_count.0, 1,
        "registration race left duplicate or orphaned tenants for {company_name}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// tenant deletion coverage
// ═══════════════════════════════════════════════════════════════════════════

#[sqlx::test]
async fn tenant_deletion_removes_seeded_rows_across_tenant_scoped_tables(pool: PgPool) {
    apply_tool_migrations(&pool).await;

    let tenant_id = insert_test_tenant(&pool, "delete-coverage").await;
    let feature_flag_key = format!("delete-coverage-{}", Uuid::new_v4().simple());

    sqlx::query(
        "INSERT INTO events (id, tenant_id, event_type)
         VALUES ($1, $2, 'delivered')",
    )
    .bind(bounded_id("evt"))
    .bind(&tenant_id)
    .execute(&pool)
    .await
    .expect("failed to seed events row");

    sqlx::query(
        "INSERT INTO support_tickets (id, subject, description, tenant_id, tenant_name, tenant_email)
         VALUES ($1, 'Tenant purge', 'GDPR delete coverage', $2, 'Delete Coverage', 'delete@test.com')",
    )
    .bind(bounded_id("tkt"))
    .bind(&tenant_id)
    .execute(&pool)
    .await
    .expect("failed to seed support_tickets row");

    sqlx::query(
        "INSERT INTO feature_flags (key, name, description)
         VALUES ($1, 'Delete Coverage Flag', 'schema contract coverage')",
    )
    .bind(&feature_flag_key)
    .execute(&pool)
    .await
    .expect("failed to seed feature_flags row");

    sqlx::query(
        "INSERT INTO feature_flag_overrides (tenant_id, tenant_name, flag_key, value)
         VALUES ($1, 'Delete Coverage', $2, true)",
    )
    .bind(&tenant_id)
    .bind(&feature_flag_key)
    .execute(&pool)
    .await
    .expect("failed to seed feature_flag_overrides row");

    sqlx::query(
        "INSERT INTO idempotency_keys (
            id, tenant_id, idempotency_key, request_hash, response_status, response_body, expires_at
         ) VALUES ($1, $2, 'delete-coverage-key', 'delete-coverage-hash', 200, '{}'::jsonb, NOW() + INTERVAL '1 day')",
    )
    .bind(bounded_id("idem"))
    .bind(&tenant_id)
    .execute(&pool)
    .await
    .expect("failed to seed idempotency_keys row");

    sqlx::query(
        "INSERT INTO autopilot_inbox_messages (tenant_id, from_address, subject, text_body)
         VALUES ($1, 'sender@example.com', 'Delete Coverage', 'orphan coverage')",
    )
    .bind(&tenant_id)
    .execute(&pool)
    .await
    .expect("failed to seed autopilot_inbox_messages row");

    let deleted = delete_tenant_records(&pool, &tenant_id)
        .await
        .expect("failed to delete tenant through purge helper");
    assert!(
        deleted,
        "tenant purge helper reported no deleted tenant row"
    );

    let mut leftover_tables = Vec::new();
    for table_name in tenant_scoped_tables(&pool).await {
        let remaining = count_rows_for_tenant(&pool, &table_name, &tenant_id).await;
        if remaining > 0 {
            leftover_tables.push(format!("{table_name} ({remaining})"));
        }
    }

    assert!(
        leftover_tables.is_empty(),
        "tenant deletion left rows behind in: {}",
        leftover_tables.join(", ")
    );
}
