#![deny(unsafe_code)]
#![allow(
    clippy::type_complexity,
    clippy::too_many_arguments,
    clippy::result_large_err
)]
pub mod app;
pub mod audit_log;
pub mod config;
pub mod error;
pub mod ip_provider;
pub mod middleware;
pub mod presentation;
pub mod resilience;
pub mod routes;
pub mod ses_provider;
pub mod state;

#[cfg(test)]
pub(crate) mod test_db {
    use sqlx::{postgres::PgPoolOptions, PgPool};
    use std::time::Duration;
    use tokio::sync::OnceCell;

    /// Serialises tests that mutate the `DKIM_PRIVATE_KEY_ENCRYPTION_KEY`
    /// process env var (env access is process-global; `cargo test` runs
    /// tests in parallel threads). Shared so route-level tests (admin
    /// domains rebind/transfer) and the signup fixtures cannot flip the
    /// key under each other mid-flight.
    pub(crate) static DKIM_ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// api-server unit tests run against the CANONICAL production schema:
    /// the bootstrap applies the full `services/mail-server/migrations` chain
    /// through the REAL production migrator (`migrator::MIGRATIONS`, the same
    /// embedded set every deploy applies before `up`) — never a test-only
    /// schema or the archived `tools/migrations` tree (audit F01).
    ///
    /// The schema lives in a dedicated database derived by appending `_api`
    /// to the dbname segment of `TEST_DATABASE_URL`: other test binaries
    /// (e.g. `integration-tests::integration_routes`) create runtime
    /// `CREATE TABLE IF NOT EXISTS` tables (e.g. `sales_leads`) on their own
    /// databases that would pollute this one's catalog and its
    /// `_sqlx_migrations` lineage ledger.
    ///
    /// Concurrency contract (57P01 flake fix): `cargo nextest` runs EVERY test
    /// in its own process, so a "drop + recreate once per test-binary run"
    /// bootstrap would `DROP DATABASE ... WITH (FORCE)` the shared `<db>_api`
    /// database while other concurrently-running test processes hold open
    /// connections to it — those connections are terminated with
    /// `57P01 terminating connection due to administrator command`, which
    /// used to fail a rotating handful of admin tests under parallel load.
    /// The bootstrap instead:
    ///   1. takes a session-level `pg_advisory_lock` on the admin database,
    ///      keyed by the isolated db name, so only ONE process bootstrap at a
    ///      time (the lock releases when the admin connection closes) — this
    ///      also serializes the canonical migration apply itself;
    ///   2. REUSES an existing healthy `<db>_api` database instead of
    ///      dropping it (tests seed unique rows and scope assertions to them,
    ///      exactly as they already do under `cargo test`'s parallel threads),
    ///      bringing it up to date with any newly added canonical migrations
    ///      (idempotent `Migrator::run`);
    ///   3. only drops + recreates when the database is missing, carries no
    ///      api-server marker table (a name collision with a foreign
    ///      database), or its `_sqlx_migrations` ledger disagrees with the
    ///      embedded canonical chain — a dirty row (a previously
    ///      crashed/failed apply) or a foreign lineage (e.g. the legacy
    ///      `tools/migrations` bootstrap this database carried before audit
    ///      F01, or a chain from a newer build) would poison every subsequent
    ///      `Migrator::run` with `Dirty(version)`/`VersionMismatch`/checksum
    ///      errors.
    pub(crate) async fn optional_pg_pool(test_name: &str) -> Option<PgPool> {
        static INIT_DB: OnceCell<()> = OnceCell::const_new();

        let database_url = match std::env::var("TEST_DATABASE_URL") {
            Ok(value) if !value.trim().is_empty() => value,
            _ => {
                eprintln!("skipping {test_name}: set TEST_DATABASE_URL to run DB-backed test");
                return None;
            }
        };

        let (server_part, db_part) = match database_url.rsplit_once('/') {
            Some((s, d)) => (s, d),
            None => {
                eprintln!("skipping {test_name}: TEST_DATABASE_URL has no database segment");
                return None;
            }
        };
        let db_only = db_part.split('?').next().unwrap_or(db_part);
        let isolated_db = format!("{db_only}_api");
        let isolated_url = format!("{server_part}/{isolated_db}");
        let admin_url = format!("{server_part}/postgres");

        INIT_DB
            .get_or_init(|| async {
                let admin = match PgPoolOptions::new()
                    .max_connections(1)
                    .acquire_timeout(Duration::from_secs(30))
                    .connect(&admin_url)
                    .await
                {
                    Ok(p) => p,
                    Err(error) => {
                        eprintln!(
                            "api-server test DB bootstrap: cannot connect to admin URL: {error}"
                        );
                        return;
                    }
                };

                // Cross-process mutex: a session advisory lock on the admin
                // database, held until `admin` (and its connection) drops.
                // The key is derived from the isolated db name so different
                // TEST_DATABASE_URL targets never contend with each other.
                if let Err(error) = sqlx::query("SELECT pg_advisory_lock(hashtext($1))")
                    .bind(&isolated_db)
                    .execute(&admin)
                    .await
                {
                    eprintln!("api-server test DB bootstrap: advisory lock failed: {error}");
                    return;
                }

                let exists: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)",
                )
                .bind(&isolated_db)
                .fetch_one(&admin)
                .await
                .unwrap_or(false);

                // Health verdict for an EXISTING database. Only POSITIVE
                // proof of an unusable database (foreign/unmarked schema, a
                // committed dirty migration row, or a `_sqlx_migrations`
                // ledger from a different lineage) justifies a drop; a
                // failed probe (e.g. transient connection exhaustion under
                // a parallel nextest run) must NOT — dropping on it is what
                // massacred concurrent test processes with 57P01.
                //
                // The marker check consults pg_catalog only until it passes;
                // `canonical_lineage` then verifies the applied (version,
                // checksum, success) rows against the embedded canonical
                // chain — the audit-F01 self-heal: a `<db>_api` last
                // provisioned from the archived `tools/migrations` tree is
                // POSITIVELY unusable for canonical tests and is recreated.
                // sqlx applies each migration inside a transaction, so a
                // CONCURRENT apply by another process is invisible here
                // (and impossible anyway: the advisory lock above
                // serializes all bootstraps).
                let mut healthy = false;
                if exists {
                    for attempt in 0..3 {
                        match PgPoolOptions::new()
                            .max_connections(1)
                            .acquire_timeout(Duration::from_secs(5))
                            .connect(&isolated_url)
                            .await
                        {
                            Ok(pool) => {
                                let check_test_db_marker = || async {
                                    let marked: bool = sqlx::query_scalar(
                                        "SELECT EXISTS(SELECT 1 FROM pg_tables \
                                         WHERE schemaname = 'public' \
                                           AND tablename = '_apexmail_api_test_db')",
                                    )
                                    .fetch_one(&pool)
                                    .await
                                    .ok()?;
                                    if !marked {
                                        // Never created by this bootstrap — a
                                        // foreign database on our name.
                                        return Some(false);
                                    }
                                    // Some(true): empty ledger (fresh) or a
                                    // canonical prefix; Some(false): dirty
                                    // rows or a foreign lineage; None:
                                    // transient probe failure (do not drop).
                                    migrator::test_support::canonical_lineage(&pool).await
                                };
                                let verdict: Option<bool> = check_test_db_marker().await;
                                pool.close().await;
                                if let Some(is_healthy) = verdict {
                                    healthy = is_healthy;
                                    break;
                                }
                            }
                            Err(_) => {
                                if attempt == 2 {
                                    // Unreachable right now — do NOT drop; the
                                    // caller's own connect below retries and
                                    // fails loudly if the database is truly
                                    // gone.
                                    healthy = true;
                                } else {
                                    tokio::time::sleep(Duration::from_millis(500)).await;
                                }
                            }
                        }
                    }
                }

                if !healthy {
                    eprintln!(
                        "api-server test DB bootstrap: creating fresh {isolated_db} \
                         (exists={exists}; missing, foreign, or poison-marked)"
                    );
                    let _ = sqlx::query(&format!(
                        "DROP DATABASE IF EXISTS \"{isolated_db}\" WITH (FORCE)"
                    ))
                    .execute(&admin)
                    .await;
                    let _ = sqlx::query(&format!("CREATE DATABASE \"{isolated_db}\""))
                        .execute(&admin)
                        .await;
                }

                // Marker + canonical migrations, still under the advisory
                // lock: the marker identifies the database as api-server
                // test infrastructure (guards against reusing a
                // name-colliding foreign database forever), and the
                // production migrator brings the database to the full
                // canonical chain (no-op when already up to date — the
                // reuse path just picks up newly added migrations).
                if let Ok(pool) = PgPoolOptions::new()
                    .max_connections(1)
                    .acquire_timeout(Duration::from_secs(30))
                    .connect(&isolated_url)
                    .await
                {
                    let _ = sqlx::query(
                        "CREATE TABLE IF NOT EXISTS _apexmail_api_test_db \
                         (marker TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())",
                    )
                    .execute(&pool)
                    .await;
                    let _ = sqlx::query(
                        "INSERT INTO _apexmail_api_test_db (marker) VALUES ('api-server')",
                    )
                    .execute(&pool)
                    .await;
                    if let Err(error) =
                        migrator::test_support::apply_canonical_migrations(&pool).await
                    {
                        eprintln!(
                            "api-server test DB bootstrap: canonical migration apply failed \
                             on {isolated_db}: {error:#}"
                        );
                    }
                    pool.close().await;
                }
                // Dropping the admin pool releases the advisory lock.
                admin.close().await;
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
                        "api-server isolated test DB ({isolated_url}) could not connect for \
                         {test_name}: {error}"
                    )
                }),
        )
    }

    /// A per-test isolated database carrying the REAL canonical production
    /// schema: the full `services/mail-server/migrations` chain applied by
    /// the production migrator (`migrator::test_support::fresh_canonical_pool`
    /// — audit F01), not a distilled fixture DDL. The canonical lineage has:
    ///
    ///   * `users.id` UUID (migration 052) — user ids are UUIDs;
    ///   * `tenants.id` / every `*_tenant_id`/`tenant_id` column
    ///     VARCHAR(26) (migration 064 standardization) — tenant ids are
    ///     26-char ULID-style text;
    ///   * campaigns/lists/domains/contacts/messages/email_queue/
    ///     system_alerts ids UUID; templates/gdpr_requests/ip_pools ids
    ///     VARCHAR(26).
    ///
    /// Handler tests that prove id-binding correctness (signup, the
    /// `WHERE id = $n` family) run against THIS shape so a green test
    /// means the bind works against the database a deploy produces.
    ///
    /// The suffix must be unique per test so parallel tests never share the
    /// database (it is dropped + recreated + re-migrated on every call).
    /// Soft-skips without `TEST_DATABASE_URL` (workspace convention); a
    /// CONFIGURED provisioning failure PANICS — the F01 contract: an
    /// infrastructure failure must fail the test, never read as a skip.
    pub(crate) async fn canonical_pool(db_suffix: &str) -> Option<PgPool> {
        match migrator::test_support::fresh_canonical_pool(
            db_suffix,
            &format!("api_canon_{db_suffix}"),
        )
        .await
        {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        }
    }
}
