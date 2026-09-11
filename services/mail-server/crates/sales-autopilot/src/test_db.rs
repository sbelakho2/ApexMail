//! Canonical test-database provisioning for in-crate (`#[cfg(test)]`)
//! database tests.
//!
//! Mirrors `tests/common/mod.rs`: the platform schema is the CANONICAL
//! production chain applied through the REAL production migrator
//! (`migrator::test_support::shared_canonical_db`, audit F01), the sales
//! schema is then verified by [`crate::routes::initialize_schema`], and every
//! test gets a FRESH pool on that shared database — a sqlx pool is bound to
//! the runtime that created it, and sharing one across `#[tokio::test]`
//! runtimes deadlocks with `PoolTimedOut`.
//!
//! A CONFIGURED provisioning failure PANICS instead of reading as a skip
//! (audit F01: a configured failure that reads as "skipped" is a green test
//! that proved nothing). Only a completely unconfigured environment
//! soft-skips (`None`).

use sqlx::PgPool;

/// Dedicated test database, the same name the integration suites provision
/// (a dedicated database keeps the canonical `_sqlx_migrations` lineage
/// isolated from every other suite's runtime tables).
const SALES_TEST_DB: &str = "apexmail_sales_test";

/// Process-wide initialization marker: provisioning runs exactly once per
/// test PROCESS. The POOL is not shared — see the module docs.
static INIT: tokio::sync::OnceCell<bool> = tokio::sync::OnceCell::const_new();

/// A fresh pool on the canonical provisioned test database.
///
/// Returns `None` only when no base URL is configured (soft-skip); callers
/// should then return without asserting. A configured environment that cannot
/// be provisioned or whose schema does not verify PANICS.
pub(crate) async fn canonical_test_pool(test_name: &str) -> Option<PgPool> {
    let ready = INIT
        .get_or_init(|| async {
            let Some(base_url) = shared_test_url() else {
                eprintln!("SKIP [{test_name}]: SALES_TEST_DATABASE_URL unset/unparseable");
                return false;
            };
            let db =
                match migrator::test_support::shared_canonical_db(base_url.as_str(), SALES_TEST_DB)
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
            if let Err(error) = crate::routes::initialize_schema(&db).await {
                panic!(
                    "canonical test database {SALES_TEST_DB} is missing the sales schema: \
                     {error} (SALES_TEST_DATABASE_URL is configured, so this is an \
                     infrastructure failure — fix the database, do not skip the test)"
                );
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

/// A unique per-run tenant id. The canonical database is SHARED and reused
/// across runs (create-if-absent, reuse-if-canonical), so fixed tenant names
/// would let state from a previous run violate count/emptiness assertions
/// (max-active campaigns, reply rates, per-tenant unique lead emails).
///
/// Capped at 26 chars: platform tables such as `events.tenant_id` are
/// `VARCHAR(26)` (the canonical nanoid tenant-id bound), so a raw UUID would
/// overflow the column.
pub(crate) fn unique_test_tenant(label: &str) -> String {
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let prefix: String = label.chars().take(13).collect();
    format!("{prefix}-{}", &suffix[..12])
}

fn shared_test_url() -> Option<url::Url> {
    // Same contract as tests/common/mod.rs (F6: no localhost default; a
    // brew/compose postgres on the ambient 5432 must not turn "unconfigured"
    // into an accidental run against an unrelated dev database).
    let raw = std::env::var("SALES_TEST_DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("TEST_DATABASE_URL")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })?;
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
