//! Shared integration-test helpers.
//!
//! Convention (follows `tests/can_spam.rs` and api-server's messages.rs
//! tests): tests run against a real Postgres when `SALES_TEST_DATABASE_URL`
//! (default `postgres://127.0.0.1:5432/apexmail_test`) is reachable and
//! SOFT-SKIP otherwise, so `cargo test -p sales-autopilot` stays green in
//! environments without infrastructure.
//!
//! The PLATFORM schema (tenants, domains, messages, email_queue,
//! suppressions, templates, metering_events, …) is applied from
//! `tools/migrations` exactly the way api-server's test suite does; the
//! sales-autopilot own tables are created by `routes::initialize_schema`.

#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;

use sqlx::{migrate::Migrator, PgPool};
use uuid::Uuid;

/// Name of the dedicated test database this suite provisions. The shared
/// `apexmail_test` DB carries a foreign sqlx migration history (date-versioned
/// migrations no longer present in tools/migrations), which makes
/// `Migrator::run` abort validation — so the suite gets its own PRISTINE
/// database, dropped and recreated once per test process.
const SALES_TEST_DB: &str = "apexmail_sales_test";

/// Process-wide initialization marker: provisioning + migrations run exactly
/// once per test PROCESS. The POOL itself is NOT shared — every
/// `#[tokio::test]` runs on its own runtime, and a sqlx pool is bound to
/// the runtime that created it (sharing it deadlocks cross-runtime with
/// PoolTimedOut). Fresh pool per test, shared initialized database.
static INIT: tokio::sync::OnceCell<bool> = tokio::sync::OnceCell::const_new();

/// Connect to the test database (None ⇒ soft-skip). The platform schema
/// (tools/migrations) and the sales schema (initialize_schema) are prepared
/// once per process; each test gets a fresh pool on the same database.
pub async fn test_pool(test_name: &str) -> Option<PgPool> {
    let ready = INIT
        .get_or_init(|| async {
            let Some(base_url) = shared_test_url() else {
                eprintln!("SKIP [{test_name}]: SALES_TEST_DATABASE_URL unset/unparseable");
                return false;
            };
            if !provision_fresh_db(&base_url).await {
                eprintln!(
                    "SKIP [{test_name}]: cannot provision {SALES_TEST_DB} on the test server"
                );
                return false;
            }
            let Some(db) = connect(&sales_db_url(&base_url)).await else {
                eprintln!("SKIP [{test_name}]: {SALES_TEST_DB} unreachable");
                return false;
            };
            if let Err(e) = apply_platform_migrations(&db).await {
                eprintln!("SKIP [{test_name}]: platform migrations failed: {e}");
                return false;
            }
            if let Err(e) = sales_autopilot::routes::initialize_schema(&db).await {
                eprintln!("SKIP [{test_name}]: sales schema init failed: {e}");
                return false;
            }
            true
        })
        .await;

    if !ready {
        eprintln!("SKIP [{test_name}]: platform test database unavailable");
        return None;
    }
    // Fresh pool for THIS test's runtime.
    let base = shared_test_url()?;
    connect(&sales_db_url(&base)).await
}

fn shared_test_url() -> Option<url::Url> {
    let raw = std::env::var("SALES_TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://127.0.0.1:5432/apexmail_test".to_string());
    url::Url::parse(&raw).ok()
}

fn sales_db_url(base: &url::Url) -> String {
    let mut url = base.clone();
    url.set_path(&format!("/{SALES_TEST_DB}"));
    url.to_string()
}

async fn connect(url: &str) -> Option<PgPool> {
    match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(10)
            .connect(url),
    )
    .await
    {
        Ok(Ok(pool)) => Some(pool),
        _ => None,
    }
}

/// Drop + recreate [`SALES_TEST_DB`] on the same server as the shared test
/// URL (maintenance connection goes to the `postgres` database). Requires
/// CREATEDB — true for the dev/test superuser.
async fn provision_fresh_db(base: &url::Url) -> bool {
    let mut admin_url = base.clone();
    admin_url.set_path("/postgres");
    let Some(admin) = connect_timeout(admin_url.as_str(), 5).await else {
        return false;
    };

    // DROP/CREATE cannot run inside a transaction block — execute them as
    // separate statements (simple protocol, autocommit).
    let _ = sqlx::query(&format!(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{SALES_TEST_DB}'"
    ))
    .execute(&admin)
    .await;
    if let Err(drop_err) =
        sqlx::query(&format!("DROP DATABASE IF EXISTS {SALES_TEST_DB}"))
            .execute(&admin)
            .await
    {
        eprintln!("DROP failed: {drop_err}");
        return false;
    }
    if let Err(create_err) =
        sqlx::query(&format!("CREATE DATABASE {SALES_TEST_DB}"))
            .execute(&admin)
            .await
    {
        eprintln!("CREATE failed: {create_err}");
        return false;
    }
    true
}

async fn connect_timeout(url: &str, secs: u64) -> Option<PgPool> {
    match tokio::time::timeout(
        std::time::Duration::from_secs(secs),
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(url),
    )
    .await
    {
        Ok(Ok(pool)) => Some(pool),
        _ => None,
    }
}

/// Apply `tools/migrations` up-migrations. Mirrors api-server's
/// `apply_tool_migrations` (crates/api-server/src/routes/messages.rs tests):
/// copy the SQL into a temp dir with `CONCURRENTLY` stripped (not allowed
/// inside the migrator's transaction) and `_down`/performance-index files
/// excluded.
async fn apply_platform_migrations(pool: &PgPool) -> anyhow::Result<()> {
    let source_dir = platform_migrations_dir();
    let temp_dir =
        std::env::temp_dir().join(format!("apexmail-sales-up-migrations-{}", Uuid::new_v4()));

    fs::create_dir_all(&temp_dir)?;

    let mut entries: Vec<PathBuf> = fs::read_dir(&source_dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("sql"))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| {
                    !name.ends_with("_down.sql") && !name.contains("performance_indexes")
                })
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
        fs::write(temp_dir.join(file_name), normalized)?;
    }

    let migrator = Migrator::new(temp_dir.clone()).await?;
    migrator.run(pool).await?;
    let _ = fs::remove_dir_all(temp_dir);
    Ok(())
}

fn platform_migrations_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../tools/migrations")
}

/// Insert a platform tenant (bounded nanoid id, FK target for platform
/// tables) and return its id.
pub async fn insert_test_tenant(pool: &PgPool, suffix: &str) -> String {
    let id = apexmail_lib::id::generate_id("ten", 22);
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status)
         VALUES ($1, $2, $3, 'free', 'active')",
    )
    .bind(&id)
    .bind(format!("Sales Test {suffix}"))
    .bind(format!("sales-{suffix}-{id}"))
    .execute(pool)
    .await
    .expect("failed to insert test tenant");
    id
}

/// Insert a verified + DKIM-ready domain (same fixture shape as api-server's
/// messages.rs tests) so the dispatcher's sender-domain gate passes.
pub async fn insert_verified_domain(pool: &PgPool, tenant_id: &str, domain: &str) -> String {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO domains (id, tenant_id, name, status, verified, dkim_enabled, ses_verified,
         dkim_selector, dkim_public_key, dkim_private_key)
         VALUES ($1, $2, $3, 'verified', true, true, true, 'test-selector', 'test-public-key', 'dkim:v1:test')",
    )
    .bind(&id)
    .bind(tenant_id)
    .bind(domain)
    .execute(pool)
    .await
    .expect("failed to insert verified domain");
    id
}

/// Insert an active campaign template.
pub async fn insert_template(
    pool: &PgPool,
    tenant_id: &str,
    subject: &str,
    html_body: &str,
    text_body: Option<&str>,
) -> String {
    let id = format!("tpl_{}", &Uuid::new_v4().simple().to_string()[..16]);
    sqlx::query(
        "INSERT INTO templates (id, tenant_id, name, slug, subject, html_body, text_body)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&id)
    .bind(tenant_id)
    .bind(format!("Template {id}"))
    .bind(&id)
    .bind(subject)
    .bind(html_body)
    .bind(text_body)
    .execute(pool)
    .await
    .expect("failed to insert template");
    id
}

/// A valid dispatcher configuration for tests (sender on the test tenant's
/// verified domain).
pub fn test_dispatch_config() -> sales_autopilot::config::DispatchConfig {
    sales_autopilot::config::DispatchConfig {
        from_email: "sales@example.com".into(),
        from_name: "ApexMail Sales".into(),
        unsubscribe_secret: "integration-test-unsubscribe-secret-321".into(),
        public_base_url: "http://127.0.0.1:3010".into(),
        unsubscribe_redirect_url: None,
        dispatch_interval_secs: 30,
        dispatch_batch_size: 100,
        dispatch_concurrency: 4,
    }
}
