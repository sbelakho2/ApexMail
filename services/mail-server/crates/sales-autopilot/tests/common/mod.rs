//! Shared integration-test helpers.
//!
//! Convention (follows `tests/can_spam.rs` and api-server's messages.rs
//! tests): tests run against a real Postgres when `SALES_TEST_DATABASE_URL`
//! is set explicitly and reachable, and SOFT-SKIP otherwise, so
//! `cargo test -p sales-autopilot` stays green in environments without
//! infrastructure.
//!
//! The PLATFORM schema (tenants, domains, messages, email_queue,
//! suppressions, templates, metering_events, …) is the CANONICAL production
//! chain (`services/mail-server/migrations`) applied through the REAL
//! production migrator (`migrator::test_support` — audit F01), exactly what
//! every deploy installs; the sales-autopilot own tables are created by
//! `routes::initialize_schema`.

#![allow(dead_code)]

use sqlx::PgPool;
use uuid::Uuid;

/// Name of the dedicated test database this suite provisions. A dedicated
/// database keeps the canonical `_sqlx_migrations` lineage isolated from
/// every other suite's runtime tables; it is dropped, recreated, and
/// canonically migrated once per test process.
const SALES_TEST_DB: &str = "apexmail_sales_test";

/// Process-wide initialization marker: provisioning + migrations run exactly
/// once per test PROCESS. The POOL itself is NOT shared — every
/// `#[tokio::test]` runs on its own runtime, and a sqlx pool is bound to
/// the runtime that created it (sharing it deadlocks cross-runtime with
/// PoolTimedOut). Fresh pool per test, shared initialized database.
static INIT: tokio::sync::OnceCell<bool> = tokio::sync::OnceCell::const_new();

/// Connect to the test database (None ⇒ soft-skip). The platform schema
/// (canonical chain via the production migrator) and the sales schema
/// (initialize_schema) are prepared once per process; each test gets a
/// fresh pool on the same database. A CONFIGURED provisioning failure
/// aborts the suite (audit F01) instead of reading as a skip.
pub async fn test_pool(test_name: &str) -> Option<PgPool> {
    let ready = INIT
        .get_or_init(|| async {
            let Some(base_url) = shared_test_url() else {
                eprintln!("SKIP [{test_name}]: SALES_TEST_DATABASE_URL unset/unparseable");
                return false;
            };
            let db =
                match migrator::test_support::fresh_canonical_db(base_url.as_str(), SALES_TEST_DB)
                    .await
                {
                    Ok(db) => db,
                    // F01: the URL is configured, so an unreachable server or a
                    // failed clone/migration is an infrastructure FAILURE — it
                    // must fail the suite, not silently skip every test.
                    Err(error) => panic!("{}", error.panic_message()),
                };
            let Some(db) = db else {
                eprintln!("SKIP [{test_name}]: unconfigured");
                return false;
            };
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
    // F6: no localhost default. A brew/compose postgres listening on the
    // ambient 5432 made these tests run against an unrelated dev database;
    // the env var must name the intended server explicitly (CI points it at
    // an ephemeral container), otherwise the suite soft-skips.
    let raw = std::env::var("SALES_TEST_DATABASE_URL").ok()?;
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
///
/// Canonical `domains` carries a GLOBAL unique index on name (a domain is
/// claimable by one tenant), and the whole suite shares one database — use
/// [`unique_test_domain`] so parallel fixtures never collide on it.
pub async fn insert_verified_domain(pool: &PgPool, tenant_id: &str, domain: &str) -> String {
    // Canonical domains.id is UUID: bind a real UUID, not its text form.
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO domains (id, tenant_id, name, status, verified, dkim_enabled, ses_verified,
         dkim_selector, dkim_public_key, dkim_private_key)
         VALUES ($1, $2, $3, 'verified', true, true, true, 'test-selector', 'test-public-key', 'dkim:v1:test')",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(domain)
    .execute(pool)
    .await
    .expect("failed to insert verified domain");
    id.to_string()
}

/// A per-fixture unique sender domain (canonical `domains.name` is globally
/// unique and this suite shares one database across parallel tests).
pub fn unique_test_domain() -> String {
    format!(
        "mail-{}.example.com",
        &Uuid::new_v4().simple().to_string()[..12]
    )
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

/// A valid dispatcher configuration whose sender sits on the given (verified)
/// test domain.
pub fn test_dispatch_config_for(domain: &str) -> sales_autopilot::config::DispatchConfig {
    sales_autopilot::config::DispatchConfig {
        from_email: format!("sales@{domain}"),
        from_name: "ApexMail Sales".into(),
        unsubscribe_secret: "integration-test-unsubscribe-secret-321".into(),
        public_base_url: "http://127.0.0.1:3010".into(),
        unsubscribe_redirect_url: None,
        dispatch_interval_secs: 30,
        dispatch_batch_size: 100,
        dispatch_concurrency: 4,
    }
}

/// Legacy convenience wrapper for suites that seed the literal
/// `example.com` domain exactly once per database.
pub fn test_dispatch_config() -> sales_autopilot::config::DispatchConfig {
    test_dispatch_config_for("example.com")
}
