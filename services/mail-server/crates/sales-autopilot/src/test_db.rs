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

/// Insert an approved jurisdiction policy under a fresh 2-letter jurisdiction
/// code, returning the code used.
///
/// `legal_policy::resolve_jurisdiction` only passes through a 2-letter ASCII
/// key (anything else normalizes to the `UNKNOWN` fail-closed default), so the
/// fixture namespace is 676 codes. A check-then-insert cannot be made safe
/// under parallel test processes — it intermittently produced duplicate-key
/// (23505) failures on `sales_jurisdiction_policies`. The insert is therefore
/// optimistic: a unique violation means another test claimed that code, so
/// generate another.
pub(crate) async fn insert_unique_jurisdiction_policy(
    pool: &PgPool,
    policy_decision: &str,
    policy_basis: &str,
) -> String {
    insert_unique_jurisdiction_policy_returning_id(pool, policy_decision, policy_basis)
        .await
        .0
}

/// A jurisdiction deliberately kept free of any policy row.
///
/// The "no policy at all" case cannot be established by probing for a free code
/// in a namespace other tests are concurrently inserting into — a probe
/// followed by another process's insert is exactly the race that made the
/// fail-closed fixture flaky. This code is excluded from the code generator
/// below, so nothing else ever writes a policy for it.
pub(crate) const NO_POLICY_JURISDICTION: &str = "QQ";

/// The reserved no-policy jurisdiction, with any stray row removed.
///
/// Deleting is safe and idempotent: every caller wants this jurisdiction to have
/// no policy, so concurrent callers converge on the same state.
pub(crate) async fn ensure_no_policy_jurisdiction(pool: &PgPool) -> String {
    sqlx::query("DELETE FROM sales_jurisdiction_policies WHERE jurisdiction = $1")
        .bind(NO_POLICY_JURISDICTION)
        .execute(pool)
        .await
        .expect("clear the reserved no-policy jurisdiction");
    NO_POLICY_JURISDICTION.to_string()
}

/// Insert an approved policy and return `(jurisdiction, policy_id)`.
pub(crate) async fn insert_unique_jurisdiction_policy_returning_id(
    pool: &PgPool,
    policy_decision: &str,
    policy_basis: &str,
) -> (String, uuid::Uuid) {
    for _ in 0..256 {
        let bytes = *uuid::Uuid::new_v4().as_bytes();
        let code = format!(
            "{}{}",
            (b'A' + (bytes[0] % 26)) as char,
            (b'A' + (bytes[1] % 26)) as char
        );
        // Skip codes that resolve elsewhere (an EU/EEA member normalizes to the
        // shared `EU` policy key, which would collide with the seeded default).
        if crate::legal_policy::resolve_jurisdiction(Some(&code), 1.0) != code {
            continue;
        }
        // Never hand out the reserved no-policy jurisdiction: a policy row
        // there would falsify every fail-closed fixture.
        if code == NO_POLICY_JURISDICTION {
            continue;
        }
        let policy_id: Option<uuid::Uuid> = sqlx::query_scalar(
            "INSERT INTO sales_jurisdiction_policies \
                 (id, jurisdiction, channel, contact_type, decision, basis, version, approved_by, \
                  approved_at, valid_from) \
             VALUES (gen_random_uuid(), $1, 'email', 'b2b_professional', $2, $3, 1, 'fixture', \
                     NOW(), NOW()) \
             ON CONFLICT (jurisdiction, channel, contact_type, version) DO NOTHING \
             RETURNING id",
        )
        .bind(&code)
        .bind(policy_decision)
        .bind(policy_basis)
        .fetch_optional(pool)
        .await
        .expect("insert sales_jurisdiction_policies");

        // NULL means the code was taken between generation and insert; try
        // another rather than reusing another test's policy (which would make
        // that test's verdict the one in force here).
        if let Some(policy_id) = policy_id {
            return (code, policy_id);
        }
    }
    panic!("could not find an unused two-letter jurisdiction code");
}
