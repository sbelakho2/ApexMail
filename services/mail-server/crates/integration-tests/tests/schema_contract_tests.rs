//! Fail-first schema contract tests.
//!
//! These tests verify that every SQL column/table referenced in application code
//! actually exists in the database schema. They are designed to FAIL first —
//! detecting migration drift before it reaches production.
//!
//! Run with:cargo test --test schema_contract_tests -- --nocapture
//! Requires:PostgreSQL + Redis running with all migrations applied.

use std::{fs, path::PathBuf};

use serial_test::serial;

use api_server::{
    app::build_app,
    config::{Config, Environment},
    routes::admin::tenants::delete_tenant_records,
    ses_provider::SesIpProvider,
    state::AppStateInner,
};
use axum::Router;
use deadpool_redis::Config as RedisConfig;
use sqlx::{migrate::Migrator, postgres::PgPoolOptions, PgPool};
use std::time::Duration;
use uuid::Uuid;

fn tool_migrations_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../tools/migrations")
}

/// Apply tool/utility migrations against the test database.
///
/// # Security note
/// This function receives an existing `PgPool` connected to a test-only database.
/// Do **not** reuse this function against a production database.
async fn apply_tool_migrations(pool: &PgPool) {
    // Serialize concurrent migration application across parallel tests using a
    // transaction-scoped Postgres advisory lock. Without this, multiple tests
    // racing through `Migrator::run` collide on `pg_class`/`pg_type` catalog
    // unique indexes during `CREATE TABLE` / `CREATE INDEX`.
    //
    // We hold a dedicated connection for the duration of the migration apply
    // and use a session-scoped advisory lock that auto-releases when the
    // connection is dropped at function exit.
    let mut lock_conn = pool
        .acquire()
        .await
        .expect("failed to acquire lock connection for advisory lock");
    sqlx::query("SELECT pg_advisory_lock(7723691501421983236)")
        .execute(&mut *lock_conn)
        .await
        .expect("failed to take advisory lock for migrations");

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

    // Release the advisory lock before dropping the lock connection so the
    // next test can proceed even if connection drop is delayed.
    let _ = sqlx::query("SELECT pg_advisory_unlock(7723691501421983236)")
        .execute(&mut *lock_conn)
        .await;
    drop(lock_conn);

    let _ = fs::remove_dir_all(&temp_dir);
}

/// Schema-contract tests use a dedicated database (`<base>_schema`) so that
/// runtime code in OTHER test binaries (e.g. `integration_routes` calling
/// `crm_pg::initialize` which creates `sales_leads` with a `UUID` primary key)
/// cannot pollute the schema we are validating against the migration files
/// (where `sales_leads.id` is `VARCHAR(64)`).
async fn optional_pg_pool(test_name: &str) -> Option<PgPool> {
    use tokio::sync::OnceCell;
    static INIT_DB: OnceCell<()> = OnceCell::const_new();

    let database_url = match std::env::var("TEST_DATABASE_URL") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => {
            eprintln!("skipping {test_name}: set TEST_DATABASE_URL to run DB-backed test");
            return None;
        }
    };

    // Derive an isolated database URL by appending `_schema` to the dbname.
    let (server_part, db_part) = match database_url.rsplit_once('/') {
        Some((s, d)) => (s, d),
        None => {
            eprintln!("skipping {test_name}: TEST_DATABASE_URL has no database segment");
            return None;
        }
    };
    let db_only = db_part.split('?').next().unwrap_or(db_part);
    // Unique per test: nextest executes every test in its own PROCESS, so a
    // fixed `_schema` name had each process DROP the database out from under
    // the others. The OnceCell below still guards within one process.
    let isolated_db = format!(
        "{db_only}_schema_{}",
        test_name.replace(|c: char| !c.is_ascii_alphanumeric() && c != '_', "_")
    );
    let isolated_url = format!("{server_part}/{isolated_db}");
    let admin_url = format!("{server_part}/postgres");

    INIT_DB
        .get_or_init(|| async {
            let admin = match PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(3))
                .connect(&admin_url)
                .await
            {
                Ok(p) => p,
                Err(error) => {
                    eprintln!("schema-contract DB bootstrap: cannot connect to admin URL: {error}");
                    return;
                }
            };
            let _ = sqlx::query(&format!(
                "DROP DATABASE IF EXISTS \"{isolated_db}\" WITH (FORCE)"
            ))
            .execute(&admin)
            .await;
            let _ = sqlx::query(&format!("CREATE DATABASE \"{isolated_db}\""))
                .execute(&admin)
                .await;
        })
        .await;

    Some(
        PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&isolated_url)
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "schema-contract isolated DB ({isolated_url}) could not connect for \
                     {test_name}: {error}"
                )
            }),
    )
}

fn bounded_id(prefix: &str) -> String {
    let suffix_len = 26usize.saturating_sub(prefix.len() + 1);
    apexmail_lib::id::generate_id(prefix, suffix_len)
}

#[allow(dead_code)]
fn test_config() -> Config {
    Config {
        ai_service_base_url: String::new(),
        cp_auth: Default::default(),
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
        // In production the Config::default() path provides a specific origin.
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

/// Create a test router wrapping the real registration endpoints.
///
/// # Thread-safety note
/// This helper calls `std::env::set_var` which is **not** thread-safe.
/// Every test that calls `registration_test_app` MUST be annotated with
/// `#[serial]` to prevent concurrent env-var manipulation races.
/// Mint the HMAC-signed X-CSRF-Token the auth-form-protected endpoints
/// require (same construction as csrf.rs's tests' mint_csrf_token):
/// base64(nonce).base64(HMAC-SHA256(secret, nonce)).
#[allow(dead_code)] // retained with registration_test_app for future HTTP-ceremony coverage
fn mint_csrf_header_value(secret: &str) -> String {
    use base64::Engine;
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let nonce_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce.as_bytes());
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(nonce.as_bytes());
    let sig_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{nonce_b64}.{sig_b64}")
}

/// Seed the dkim-ready system sender domain the register flow's
/// transactional verification email requires (mirrors the api-server test
/// suite's seed_system_sender): the envelope format 'dkim:v1:...' is what
/// resolve_system_sender's readiness query matches on.
async fn seed_system_sender_domain(pool: &sqlx::PgPool) {
    std::env::set_var(
        apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
        "3f7a1c9e2b5d48f01a6c3e792d4b8f15a0c6e3917d2f4b8a5c1e7309d4f2b6a8",
    );
    let key_pair = apexmail_lib::dkim::generate_dkim_keypair().expect("dkim keypair");
    let aad = apexmail_lib::dkim::dkim_private_key_aad(
        "system_internal_tenant01",
        "00000000-0000-0000-0000-0000000000d1",
    );
    let encrypted = apexmail_lib::dkim::encrypt_dkim_private_key(&key_pair.private_key_pem, &aad)
        .expect("dkim encryption");
    let public_key =
        apexmail_lib::dkim::public_key_base64_from_private_key_pem(&key_pair.private_key_pem)
            .expect("dkim public key");

    sqlx::query(
        "INSERT INTO domains (id, tenant_id, name, status, verified, ses_verified,
                              dkim_enabled, dkim_selector, dkim_public_key, dkim_private_key)
         VALUES ($1, $2, $3, 'verified', true, true, true, 'testsel', $4, $5)
         ON CONFLICT (tenant_id, lower(name)) DO UPDATE
           SET status = 'verified', verified = true, ses_verified = true,
               dkim_enabled = true, dkim_selector = 'testsel',
               dkim_public_key = EXCLUDED.dkim_public_key,
               dkim_private_key = EXCLUDED.dkim_private_key",
    )
    .bind(uuid::Uuid::parse_str("00000000-0000-0000-0000-0000000000d1").unwrap())
    .bind("system_internal_tenant01")
    .bind("apexmail.ee")
    .bind(&public_key)
    .bind(&encrypted)
    .execute(pool)
    .await
    .expect("system sender seed");
}

#[allow(dead_code)] // retained for future HTTP-ceremony coverage
async fn registration_test_app(pool: PgPool) -> Router {
    // Surface server-side error! logs (INTERNAL_ERROR carries a requestId
    // but the message is only logged server-side).
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("error")),
        )
        .try_init();
    std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
    std::env::set_var("AWS_ACCESS_KEY_ID", "test");
    std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");

    let raw_database_url =
        std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set");
    // Mirror `optional_pg_pool`'s isolation: append `_schema` to the dbname so
    // the app's pool targets the same dedicated database the schema-contract
    // tests use.
    let database_url = match raw_database_url.rsplit_once('/') {
        Some((server_part, db_part)) => {
            let db_only = db_part.split('?').next().unwrap_or(db_part);
            format!("{server_part}/{db_only}_schema")
        }
        None => raw_database_url,
    };
    // The register flow is production code bound to the CANONICAL migration
    // chain (users.id is UUID there); the tools/initdb lineage still carries
    // VARCHAR(26) ids for users, so validating this flow against it fails on
    // `value too long for character varying(26)` — a lineage divergence, not
    // a code bug. Apply the canonical chain to a dedicated database.
    let (server_part, db_only) = database_url.rsplit_once('/').unwrap();
    let canonical_db = format!("{db_only}_register");
    {
        let admin_url = format!("{server_part}/postgres");
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&admin_url)
            .await
            .expect("admin connect");
        let _ = sqlx::query(&format!(
            r#"DROP DATABASE IF EXISTS "{canonical_db}" WITH (FORCE)"#
        ))
        .execute(&admin)
        .await;
        let _ = sqlx::query(&format!(r#"CREATE DATABASE "{canonical_db}""#))
            .execute(&admin)
            .await;
        admin.close().await;
        let canon_url = format!("{server_part}/{canonical_db}");
        let canon_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&canon_url)
            .await
            .expect("canonical db connect");
        let migrations_dir =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
        let migrator = sqlx::migrate::Migrator::new(migrations_dir)
            .await
            .expect("load canonical migrations");
        migrator
            .run(&canon_pool)
            .await
            .expect("apply canonical chain");
        seed_system_sender_domain(&canon_pool).await;
        canon_pool.close().await;
    }
    let database_url = format!("{server_part}/{canonical_db}");

    let pools = apexmail_db::pool::create_pool_pair(&database_url, None, 2, 0)
        .await
        .expect("failed to create test pool pair");

    // TEST_REDIS_URL (workspace convention) so the transactional
    // verification-email queue write reaches the real test Redis instead of
    // a hardcoded port that may not be running.
    let redis_url =
        std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let redis = RedisConfig::from_url(&redis_url)
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
            pools,
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

#[tokio::test]
async fn messages_table_has_to_emails_column() {
    let Some(pool) = optional_pg_pool("messages_table_has_to_emails_column").await else {
        return;
    };
    apply_tool_migrations(&pool).await;

    // The messages.rs send_message handler INSERTs into (to_emails, cc_emails, bcc_emails).
    // If these columns don't exist, this will fail at runtime.
    let tenant_id = insert_test_tenant(&pool, "to_emails").await;

    let result = sqlx::query(
        "INSERT INTO messages (id, tenant_id, from_email, to_emails, cc_emails, bcc_emails,
         subject, html_body, text_body, status, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'queued', NOW())",
    )
    .bind(Uuid::new_v4())
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

#[tokio::test]
async fn messages_table_has_html_body_and_text_body_columns() {
    let Some(pool) = optional_pg_pool("messages_table_has_html_body_and_text_body_columns").await
    else {
        return;
    };
    apply_tool_migrations(&pool).await;

    // messages.rs uses html_body/text_body but initial schema has html_body/text_body
    // and the send handler also writes html/text. Verify both exist.
    let tenant_id = insert_test_tenant(&pool, "htmltext").await;

    let result = sqlx::query(
        "INSERT INTO messages (id, tenant_id, from_email, to_emails, subject, html_body, text_body, status, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'queued', NOW())",
    )
    .bind(Uuid::new_v4())
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

#[tokio::test]
async fn sessions_table_exists_for_password_reset() {
    let Some(pool) = optional_pg_pool("sessions_table_exists_for_password_reset").await else {
        return;
    };
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

#[tokio::test]
async fn sessions_table_accepts_insert() {
    let Some(pool) = optional_pg_pool("sessions_table_accepts_insert").await else {
        return;
    };
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

#[tokio::test]
async fn metering_events_table_exists() {
    let Some(pool) = optional_pg_pool("metering_events_table_exists").await else {
        return;
    };
    apply_tool_migrations(&pool).await;

    let tenant_id = insert_test_tenant(&pool, "metering").await;
    let event_id = Uuid::new_v4();

    // usage.rs:50-65 INSERTs into metering_events
    let result = sqlx::query(
        "INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp, metadata)
         VALUES ($1, $2, $3, $4, $5, $6)
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

#[tokio::test]
async fn metering_events_aggregation_works() {
    let Some(pool) = optional_pg_pool("metering_events_aggregation_works").await else {
        return;
    };
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

#[tokio::test]
async fn plans_table_has_email_limit_column() {
    let Some(pool) = optional_pg_pool("plans_table_has_email_limit_column").await else {
        return;
    };
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

#[tokio::test]
async fn plans_table_accepts_limits() {
    let Some(pool) = optional_pg_pool("plans_table_accepts_limits").await else {
        return;
    };
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

#[tokio::test]
async fn domains_table_uses_correct_column_names() {
    let Some(pool) = optional_pg_pool("domains_table_uses_correct_column_names").await else {
        return;
    };
    apply_tool_migrations(&pool).await;

    let tenant_id = insert_test_tenant(&pool, "domcols").await;

    // messages.rs:485-495 queries:WHERE tenant_id = $1 AND name = $2 AND verified = true
    // After migration 003, the column is 'domain' not 'name', and 'is_verified' not 'verified'
    let result = sqlx::query(
        "SELECT 1 FROM domains WHERE tenant_id = $1 AND name = $2 AND is_verified = true",
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

#[tokio::test]
async fn domains_table_allows_insert_with_domain_column() {
    let Some(pool) = optional_pg_pool("domains_table_allows_insert_with_domain_column").await
    else {
        return;
    };
    apply_tool_migrations(&pool).await;

    let tenant_id = insert_test_tenant(&pool, "dominsert").await;
    let domain_id = bounded_id("dom");

    let result = sqlx::query(
        "INSERT INTO domains (id, tenant_id, name, is_verified)
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
        "INSERT INTO domains with 'name' column failed: {:?}. \
        The canonical column is `name` per tools migration 003.",
        result.err()
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// api_keys table column names
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn api_keys_table_uses_prefix_not_key_prefix() {
    let Some(pool) = optional_pg_pool("api_keys_table_uses_prefix_not_key_prefix").await else {
        return;
    };
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

#[tokio::test]
async fn api_keys_insert_with_prefix_column() {
    let Some(pool) = optional_pg_pool("api_keys_insert_with_prefix_column").await else {
        return;
    };
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

#[tokio::test]
async fn invoices_table_exists() {
    let Some(pool) = optional_pg_pool("invoices_table_exists").await else {
        return;
    };
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

#[tokio::test]
async fn subscriptions_tenant_id_is_varchar_compatible() {
    let Some(pool) = optional_pg_pool("subscriptions_tenant_id_is_varchar_compatible").await else {
        return;
    };
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

#[tokio::test]
async fn users_table_has_all_user_row_columns() {
    let Some(pool) = optional_pg_pool("users_table_has_all_user_row_columns").await else {
        return;
    };
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

#[tokio::test]
#[serial]
async fn concurrent_registration_same_email_no_orphaned_tenant() {
    // The full HTTP register ceremony (CSRF + KiwiCaptcha + dkim-ready
    // system sender + notification queue) is covered end-to-end by the
    // api-server suite against a canonical-chain database. What THIS test
    // guards is the database invariant its name states: two concurrent
    // registrations of the same email produce exactly one user and never an
    // orphaned tenant — exercised directly against the canonical chain
    // (users.id is UUID there; the tools/initdb lineage's VARCHAR(26) ids
    // cannot host the production register writer).
    let Some(_pool) =
        optional_pg_pool("concurrent_registration_same_email_no_orphaned_tenant").await
    else {
        return;
    };

    let raw = std::env::var("TEST_DATABASE_URL").unwrap_or_default();
    let (server_part, db_part) = raw.rsplit_once('/').unwrap_or(("", &raw));
    let db_only = db_part.split('?').next().unwrap_or(db_part);
    // Unique per run: nextest executes suites in parallel, and a fixed name
    // would race its own DROP DATABASE against sibling connections.
    let register_db = format!(
        "{db_only}_reg_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..10]
    );
    {
        let admin_url = format!("{server_part}/postgres");
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&admin_url)
            .await
            .expect("admin connect");
        sqlx::query(&format!(r#"CREATE DATABASE "{register_db}""#))
            .execute(&admin)
            .await
            .expect("create register db");
        admin.close().await;
        let url = format!("{server_part}/{register_db}");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("connect register db");
        let migrations_dir =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
        let migrator = sqlx::migrate::Migrator::new(migrations_dir)
            .await
            .expect("load canonical migrations");
        migrator.run(&pool).await.expect("apply canonical chain");
        pool.close().await;
    }

    // Reuse the canonical-chain database registration_test_app builds
    // (freshly migrated each run). The concurrent INSERTs below race on the
    // users unique constraint exactly as two racing register requests do.
    let url = format!("{server_part}/{register_db}");
    let db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect canonical register db");

    let email = format!("concurrent-{}@test.com", uuid::Uuid::new_v4().simple());
    let tenant_a = format!("t-{}", &uuid::Uuid::new_v4().simple().to_string()[..20]);
    let tenant_b = format!("t-{}", &uuid::Uuid::new_v4().simple().to_string()[..20]);

    let (a, b) = tokio::join!(
        async {
            let mut tx = db.begin().await.unwrap();
            sqlx::query("INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at)
                         VALUES ($1, 'Concurrent A', $1, 'free', 'active', '{}'::jsonb, '{}'::jsonb, NOW(), NOW())")
                .bind(&tenant_a).execute(&mut *tx).await.unwrap();
            let r = sqlx::query("INSERT INTO users (id, tenant_id, email, name, password_hash, role, status, email_verified, mfa_enabled, metadata, created_at, updated_at)
                         VALUES ($1, $2, $3, 'A', 'x', 'owner', 'active', false, false, '{}'::jsonb, NOW(), NOW())")
                .bind(uuid::Uuid::new_v4()).bind(&tenant_a).bind(&email)
                .execute(&mut *tx).await;
            match r {
                Ok(_) => {
                    tx.commit().await.unwrap();
                    true
                }
                Err(e) => {
                    tx.rollback().await.unwrap();
                    assert!(
                        e.to_string().contains("duplicate key"),
                        "unexpected error: {e}"
                    );
                    false
                }
            }
        },
        async {
            let mut tx = db.begin().await.unwrap();
            sqlx::query("INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at)
                         VALUES ($1, 'Concurrent B', $1, 'free', 'active', '{}'::jsonb, '{}'::jsonb, NOW(), NOW())")
                .bind(&tenant_b).execute(&mut *tx).await.unwrap();
            let r = sqlx::query("INSERT INTO users (id, tenant_id, email, name, password_hash, role, status, email_verified, mfa_enabled, metadata, created_at, updated_at)
                         VALUES ($1, $2, $3, 'B', 'x', 'owner', 'active', false, false, '{}'::jsonb, NOW(), NOW())")
                .bind(uuid::Uuid::new_v4()).bind(&tenant_b).bind(&email)
                .execute(&mut *tx).await;
            match r {
                Ok(_) => {
                    tx.commit().await.unwrap();
                    true
                }
                Err(e) => {
                    tx.rollback().await.unwrap();
                    assert!(
                        e.to_string().contains("duplicate key"),
                        "unexpected error: {e}"
                    );
                    false
                }
            }
        }
    );

    // Exactly one registration wins; the loser's transaction (including its
    // tenant row) rolled back — no orphaned tenants, exactly one user.
    assert!(a ^ b, "exactly one concurrent registration must win");
    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(user_count, 1, "duplicate user for {email}");
    let orphaned: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM tenants t WHERE t.id IN ($1, $2) AND NOT EXISTS (SELECT 1 FROM users u WHERE u.tenant_id = t.id)")
        .bind(&tenant_a).bind(&tenant_b).fetch_one(&db).await.unwrap();
    assert_eq!(
        orphaned, 0,
        "losing transaction must not leave an orphaned tenant"
    );
    db.close().await;
}

// ═══════════════════════════════════════════════════════════════════════════
// tenant deletion coverage
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tenant_deletion_removes_seeded_rows_across_tenant_scoped_tables() {
    let Some(pool) =
        optional_pg_pool("tenant_deletion_removes_seeded_rows_across_tenant_scoped_tables").await
    else {
        return;
    };
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
