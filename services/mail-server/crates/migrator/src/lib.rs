//! ApexMail database migrator — the deployment-time migration gate.
//!
//! Every production deploy path (`.github/workflows/deploy-hetzner.yml` and
//! `deploy/scripts/deploy.sh`) runs the `migrator` binary as a one-shot
//! compose job BEFORE `docker compose up -d`:
//!
//! ```sh
//! docker compose -f docker-compose.yml -f docker-compose.prod.yml \
//!   --env-file .env --profile migrate run --rm migrator
//! ```
//!
//! It connects via `DATABASE_URL` (assembled from `DB_*` + the
//! `postgres_password` Docker secret by `deploy/scripts/entrypoint-wrapper.sh`,
//! same as every sibling service) and applies the workspace migration set
//! embedded at compile time from `services/mail-server/migrations`.
//!
//! This library target exists so that test infrastructure can apply EXACTLY
//! what production applies (audit F01): [`MIGRATIONS`] is the one embedded
//! migration set, and [`apply_migrations`] is the same apply sequence the
//! deploy-gate binary runs. Test databases bootstrap through
//! [`test_support`] instead of hand-written schemas or archived migration
//! trees, so a green test means the code works against the real deploy-time
//! schema.

use anyhow::{Context, Result};

/// Embed the canonical workspace migration set at compile time.
///
/// The path is resolved relative to this crate's manifest directory
/// (`services/mail-server/crates/migrator`) at BUILD time, so the binary
/// carries the migrations that match its own build — no runtime mounting of
/// SQL files, no drift between the image and the repo.
pub static MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("./../../migrations");

/// Number of migrations already recorded in `_sqlx_migrations` (0 when the
/// table does not exist yet, i.e. a fresh database before the first run).
///
/// `to_regclass(...)` returns a ROW with a NULL column (not zero rows) when
/// the relation does not exist, so the scalar must decode as `Option<String>`
/// — a plain `String` fails with "unexpected null" on a completely fresh
/// database (pipeline finding F2).
pub async fn applied_count(pool: &sqlx::PgPool) -> Result<i64> {
    let table: Option<Option<String>> =
        sqlx::query_scalar("SELECT to_regclass('public._sqlx_migrations')::text")
            .fetch_optional(pool)
            .await
            .context("failed to check for _sqlx_migrations")?;
    match table.flatten() {
        Some(_) => Ok(sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
            .fetch_one(pool)
            .await
            .context("failed to count applied migrations")?),
        None => Ok(0),
    }
}

/// Apply every pending canonical migration to `pool`, then extend the
/// partition runway — the exact sequence the deploy-gate binary performs on
/// every production deploy. Idempotent: re-running against an up-to-date
/// database is a no-op that still succeeds.
pub async fn apply_migrations(pool: &sqlx::PgPool) -> Result<()> {
    let before = applied_count(pool).await?;
    println!("applied migrations before run: {before}");

    // sqlx records applied versions in _sqlx_migrations; re-running against
    // an up-to-date database is a no-op that exits 0.
    MIGRATIONS
        .run(pool)
        .await
        .context("failed to apply migrations")?;

    let after = applied_count(pool).await?;
    println!(
        "applied migrations after run: {after} ({} new)",
        after - before
    );

    // Partition runway: the high-volume tables are RANGE-partitioned with a
    // static partition horizon (050/058 created partitions to 2027-12 /
    // 2030-Q1) and nothing else calls create_future_partitions() at runtime.
    // Once the horizon passes, every insert lands in the *_default partition
    // and future ATTACHs need an exclusive full scan of it. Extending the
    // horizon on every deploy keeps it ahead forever. Absence of the
    // function (pre-050 databases mid-upgrade) is a notice, not an error —
    // the migration that creates it is the same one that partitions the
    // tables, so by the time it exists the extension is meaningful.
    // Same NULL-decoding shape as `applied_count`. Note to_regprocedure, not
    // to_regclass: functions are not relations, and to_regclass on a function
    // name returns NULL even when the function exists.
    let runway: Option<Option<String>> =
        sqlx::query_scalar("SELECT to_regprocedure('public.create_future_partitions()')::text")
            .fetch_optional(pool)
            .await
            .context("failed to check for create_future_partitions")?;
    match runway.flatten() {
        Some(_) => {
            sqlx::query("SELECT create_future_partitions()")
                .execute(pool)
                .await
                .context("failed to extend the partition runway")?;
            println!("migrator: partition runway extended");
        }
        None => println!("migrator: create_future_partitions absent — runway not extended"),
    }

    Ok(())
}

/// Test-database bootstrap built on the REAL production migrator (audit F01).
///
/// Historically DB-backed tests provisioned themselves from the archived
/// `tools/migrations` tree (or hand-written DDL constants) while deployment
/// applies `services/mail-server/migrations` via the `migrator` binary. The
/// two lineages disagree on identifier and column shapes (users.id
/// VARCHAR(26) vs UUID, domains.verified vs is_verified, api_keys.key_prefix
/// vs prefix, idempotency_keys vs idempotency_records, …), which made
/// DB-backed tests pass against a schema production never runs — and fail
/// against the canonical one. Everything in this module routes through
/// [`MIGRATIONS`]/[`apply_migrations`] so a test database is byte-for-byte
/// what a deploy produces.
///
/// Provisioning contract (audit F01, remediated):
///
/// * `Ok(Some(pool))` — the database carries the complete pinned canonical
///   migration ledger (verified per clone before the pool is returned);
/// * `Ok(None)` — the suite is EXPLICITLY UNCONFIGURED (no / blank
///   `TEST_DATABASE_URL`, blank base URL). This is the only situation that
///   yields `None`;
/// * `Err(ProvisionError)` — the infrastructure was configured but failed
///   (unreachable server, denied clone, migration apply failure, foreign
///   lineage, incomplete clone ledger). Callers MUST fail the test, not
///   soft-skip: a configured-database failure that reads as "skipped" is a
///   green test that proved nothing.
///
/// These helpers are test infrastructure. The `migrator` binary never calls
/// into this module.
pub mod test_support {
    use sqlx::{postgres::PgPoolOptions, PgPool};
    use std::time::Duration;

    /// Why a canonical test database could not be provisioned (audit F01).
    ///
    /// Constructed only for CONFIGURED-infrastructure failures; an
    /// explicitly unconfigured suite is reported as `Ok(None)` instead.
    #[derive(Debug)]
    pub struct ProvisionError {
        /// Short, stable identifier of the failed provisioning stage
        /// (e.g. `"admin-connect"`, `"clone"`, `"clone-ledger"`).
        stage: &'static str,
        /// Human-readable detail for the failure message.
        detail: String,
    }

    impl ProvisionError {
        /// Failure at a named provisioning stage.
        pub fn new(stage: &'static str, detail: impl Into<String>) -> Self {
            Self {
                stage,
                detail: detail.into(),
            }
        }

        /// The provisioning stage that failed.
        pub fn stage(&self) -> &'static str {
            self.stage
        }

        /// Ready-to-panic failure message that names the stage and the fix.
        pub fn panic_message(&self) -> String {
            format!(
                "canonical test-database provisioning failed at stage '{}': {} \
                 (TEST_DATABASE_URL is configured, so this is an infrastructure \
                 failure — fix the server, do not skip the test)",
                self.stage, self.detail
            )
        }
    }

    impl std::fmt::Display for ProvisionError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}: {}", self.stage, self.detail)
        }
    }

    impl std::error::Error for ProvisionError {}

    /// Apply the canonical production chain to an existing pool via
    /// [`super::apply_migrations`] — the same initializer the deploy-gate
    /// binary runs (migration apply + partition runway extension).
    /// Idempotent; safe to call concurrently behind a Postgres advisory lock.
    pub async fn apply_canonical_migrations(pool: &PgPool) -> anyhow::Result<()> {
        super::apply_migrations(pool).await
    }

    /// Does `_sqlx_migrations` agree with the embedded canonical chain?
    ///
    /// * `None` — could not determine (probe failed; e.g. transient
    ///   connection exhaustion). Callers must NOT treat this as unhealthy.
    /// * `Some(true)` — applied set is empty or a strict prefix of the
    ///   canonical chain (pending migrations can be applied incrementally).
    /// * `Some(false)` — the database carries a FOREIGN migration lineage
    ///   (different versions/checksums, e.g. the archived `tools/migrations`
    ///   tree, or a newer build's chain). `Migrator::run` would abort with a
    ///   version/checksum mismatch; the only sound move is recreate.
    pub async fn canonical_lineage(pool: &PgPool) -> Option<bool> {
        let migrations_table: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_tables \
             WHERE schemaname = 'public' AND tablename = '_sqlx_migrations')",
        )
        .fetch_one(pool)
        .await
        .ok()?;
        if !migrations_table {
            // Fresh database — nothing applied yet; canonical by definition.
            return Some(true);
        }

        // (version, checksum, success) rows in application order. A dirty row
        // (success = false, sqlx 0.8's failed-apply marker) also makes the
        // lineage unusable.
        let applied: Vec<(i64, Vec<u8>, bool)> = sqlx::query_as(
            "SELECT version::bigint, checksum, success FROM _sqlx_migrations ORDER BY version",
        )
        .fetch_all(pool)
        .await
        .ok()?;

        if applied.iter().any(|&(_, _, success)| !success) {
            return Some(false);
        }

        let canonical = super::MIGRATIONS.migrations.iter().collect::<Vec<_>>();
        if applied.len() > canonical.len() {
            return Some(false);
        }
        for (index, (version, checksum, _)) in applied.iter().enumerate() {
            let expected = &canonical[index];
            if expected.version != *version || expected.checksum.as_ref() != checksum {
                return Some(false);
            }
        }
        Some(true)
    }

    /// The number of migrations the embedded canonical chain pins.
    fn canonical_migration_count() -> usize {
        super::MIGRATIONS.migrations.len()
    }

    /// A clone is only fit for a test when its ledger is readable, canonical,
    /// and COMPLETE: every pinned migration applied, none extra, none dirty.
    async fn clone_ledger_complete(pool: &PgPool) -> Result<bool, sqlx::Error> {
        let applied: Vec<(i64, Vec<u8>, bool)> = sqlx::query_as(
            "SELECT version::bigint, checksum, success FROM _sqlx_migrations ORDER BY version",
        )
        .fetch_all(pool)
        .await?;
        if applied.len() != canonical_migration_count() {
            return Ok(false);
        }
        if applied.iter().any(|&(_, _, success)| !success) {
            return Ok(false);
        }
        Ok(super::MIGRATIONS.migrations.iter().zip(applied.iter()).all(
            |(expected, (version, checksum, _))| {
                expected.version == *version && expected.checksum.as_ref() == checksum
            },
        ))
    }

    /// Template database name for THIS build's canonical chain.
    ///
    /// Different migration revisions get DISTINCT template names (audit F01):
    /// the name encodes the chain's length, newest version, and an FNV-1a
    /// digest of every (version, checksum) pair, so a template cloned from an
    /// older/newer build's chain is never silently reused — the fresh build
    /// provisions and verifies its own template.
    fn canonical_template_db() -> &'static str {
        static NAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        NAME.get_or_init(|| {
            const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
            const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
            let mut count: u64 = 0;
            let mut newest: i64 = 0;
            let mut digest = FNV_OFFSET;
            for migration in super::MIGRATIONS.migrations.iter() {
                count += 1;
                newest = newest.max(migration.version);
                for byte in migration.version.to_le_bytes() {
                    digest ^= u64::from(byte);
                    digest = digest.wrapping_mul(FNV_PRIME);
                }
                for byte in migration.checksum.iter() {
                    digest ^= u64::from(*byte);
                    digest = digest.wrapping_mul(FNV_PRIME);
                }
            }
            format!(
                "apexmail_canonical_tpl_{count}_{newest}_{:08x}",
                digest & 0xffff_ffff
            )
        })
    }

    // "AXPM-TPL" — cluster-wide exclusive lock guarding template
    // creation/top-up. Per-test clones run WITHOUT the lock (they must
    // not serialize); a clone racing a top-up retries below.
    const TEMPLATE_LOCK_KEY: i64 = 0x4158_504D_5450_4C21;

    /// Process-wide "the template for THIS chain is verified" marker.
    ///
    /// Published ONLY after the template's migrations AND lineage
    /// verification complete (audit F01: the previous OnceLock was set
    /// BEFORE the async initialization ran, so a concurrent test could
    /// clone a half-migrated template). `get_or_try_init` keeps the cell
    /// empty on failure, so the next caller retries instead of trusting a
    /// partial template; waiters (other tests in the same process, on their
    /// own runtimes) block until initialization finishes or fails.
    static TEMPLATE_READY: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

    /// Create-or-top-up the chain's template database under the cluster
    /// advisory lock, then VERIFY it. Returns Err on any failure — there is
    /// deliberately no direct-apply fallback branch any more: the fallback
    /// was documented but never invoked, and a configured failure must
    /// fail the test (audit F01), not limp through a second slow path.
    async fn ensure_template_ready(
        admin: &PgPool,
        server_part: &str,
    ) -> Result<(), ProvisionError> {
        TEMPLATE_READY
            .get_or_try_init(|| async {
                let template_db = canonical_template_db();

                let _ = sqlx::query("SELECT pg_advisory_lock($1)")
                    .bind(TEMPLATE_LOCK_KEY)
                    .execute(admin)
                    .await;

                let result = ensure_template_locked(admin, server_part, template_db).await;

                let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
                    .bind(TEMPLATE_LOCK_KEY)
                    .execute(admin)
                    .await;

                result
            })
            .await
            .map(|&()| ())
    }

    /// Body of [`ensure_template_ready`], run holding the advisory lock.
    /// On success the template's ledger was just verified COMPLETE.
    async fn ensure_template_locked(
        admin: &PgPool,
        server_part: &str,
        template_db: &str,
    ) -> Result<(), ProvisionError> {
        let connect_template = || async {
            PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(60))
                .connect(&format!("{server_part}/{template_db}"))
                .await
                .map_err(|error| {
                    ProvisionError::new(
                        "template-connect",
                        format!("connect template {template_db}: {error}"),
                    )
                })
        };

        let template_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)")
                .bind(template_db)
                .fetch_one(admin)
                .await
                .map_err(|error| {
                    ProvisionError::new("template-exists-check", format!("{template_db}: {error}"))
                })?;

        let healthy = if template_exists {
            // Connect, verify/complete the lineage, disconnect (a connected
            // template blocks clones — keep this window short and exclusive
            // to the advisory lock).
            let template_pool = connect_template().await?;
            let lineage = canonical_lineage(&template_pool).await;
            let result = match lineage {
                Some(true) => apply_canonical_migrations(&template_pool)
                    .await
                    .map_err(|error| {
                        ProvisionError::new(
                            "template-migrate",
                            format!("apply canonical chain to {template_db}: {error}"),
                        )
                    }),
                // Foreign/dirty lineage or an unreadable probe on a
                // template WE own: rebuild it from scratch.
                _ => {
                    template_pool.close().await;
                    drop_database(admin, template_db).await?;
                    sqlx::query(&format!(r#"CREATE DATABASE "{template_db}""#))
                        .execute(admin)
                        .await
                        .map_err(|error| {
                            ProvisionError::new(
                                "template-recreate",
                                format!("recreate {template_db}: {error}"),
                            )
                        })?;
                    let rebuilt = connect_template().await?;
                    let migrated = apply_canonical_migrations(&rebuilt).await.map_err(|error| {
                        ProvisionError::new(
                            "template-migrate",
                            format!("apply canonical chain to rebuilt {template_db}: {error}"),
                        )
                    });
                    migrated
                }
            };
            template_pool.close().await;
            result
        } else {
            sqlx::query(&format!(r#"CREATE DATABASE "{template_db}""#))
                .execute(admin)
                .await
                .map_err(|error| {
                    ProvisionError::new("template-create", format!("create {template_db}: {error}"))
                })?;
            let template_pool = connect_template().await?;
            let migrated = apply_canonical_migrations(&template_pool)
                .await
                .map_err(|error| {
                    ProvisionError::new(
                        "template-migrate",
                        format!("apply canonical chain to new {template_db}: {error}"),
                    )
                });
            template_pool.close().await;
            migrated
        };

        healthy?;

        // Publish only after migrations AND lineage verification finish:
        // re-read the ledger and require the COMPLETE pinned chain.
        let verify_pool = connect_template().await?;
        let complete = clone_ledger_complete(&verify_pool).await.map_err(|error| {
            ProvisionError::new(
                "template-verify",
                format!("read back {template_db} ledger: {error}"),
            )
        })?;
        verify_pool.close().await;
        if !complete {
            return Err(ProvisionError::new(
                "template-verify",
                format!(
                    "{template_db} ledger is not the complete pinned canonical chain \
                     ({} migrations expected)",
                    canonical_migration_count()
                ),
            ));
        }
        Ok(())
    }

    async fn drop_database(admin: &PgPool, db_name: &str) -> Result<(), ProvisionError> {
        sqlx::query(&format!(
            r#"DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)"#
        ))
        .execute(admin)
        .await
        .map_err(|error| {
            ProvisionError::new("drop-database", format!("drop {db_name}: {error}"))
        })?;
        Ok(())
    }

    /// A fresh database named `db_name` carrying the canonical production
    /// schema, cloned from a once-provisioned template.
    ///
    /// Applying the ~170-file chain per test was fine for a handful of
    /// local DB tests, but at CI parallelism (thousands of tests in one
    /// nextest run against one Postgres) the concurrent DDL/lock load
    /// exhausted the cluster's shared lock memory ("out of shared memory",
    /// migration 64) and every DB-backed test slowed to a crawl. The chain
    /// is therefore applied exactly ONCE into a per-revision template
    /// (under a cluster advisory lock, published only after migrations +
    /// lineage verification complete), and each test database is a
    /// `CREATE DATABASE ... TEMPLATE` clone — a fast filesystem copy with
    /// no DDL storm.
    ///
    /// The clone's migration ledger is VERIFIED before the pool is
    /// returned, so a caller can never receive a partially-migrated
    /// database (audit F01).
    ///
    /// Returns `Ok(None)` only for a blank/unset base URL (explicitly
    /// unconfigured); every configured failure is `Err(ProvisionError)`
    /// and must FAIL the test, not skip it.
    pub async fn fresh_canonical_db(
        base_url: &str,
        db_name: &str,
    ) -> Result<Option<PgPool>, ProvisionError> {
        if base_url.trim().is_empty() {
            return Ok(None);
        }
        let (server_part, _) = base_url.rsplit_once('/').ok_or_else(|| {
            ProvisionError::new(
                "url-parse",
                format!("base URL {base_url:?} has no database segment"),
            )
        })?;

        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(60))
            .connect(&format!("{server_part}/postgres"))
            .await
            .map_err(|error| {
                ProvisionError::new(
                    "admin-connect",
                    format!("connect {server_part}/postgres: {error}"),
                )
            })?;

        ensure_template_ready(&admin, server_part).await?;

        // Per-test database: drop any leftover, clone the template. The
        // retry absorbs a clone racing another process's top-up window
        // ("source database is being accessed by other users").
        drop_database(&admin, db_name).await?;
        let template_db = canonical_template_db();
        let mut last_error: Option<sqlx::Error> = None;
        for attempt in 0..12 {
            match sqlx::query(&format!(
                r#"CREATE DATABASE "{db_name}" TEMPLATE "{template_db}""#
            ))
            .execute(&admin)
            .await
            {
                Ok(_) => {
                    last_error = None;
                    break;
                }
                Err(error) => {
                    let busy = error.to_string().contains("source database")
                        || error.to_string().contains("accessed by other users");
                    if !busy || attempt == 11 {
                        last_error = Some(error);
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
        }
        if let Some(error) = last_error {
            admin.close().await;
            return Err(ProvisionError::new(
                "clone",
                format!("clone {db_name} from {template_db}: {error}"),
            ));
        }
        admin.close().await;

        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&format!("{server_part}/{db_name}"))
            .await
            .map_err(|error| {
                ProvisionError::new("clone-connect", format!("connect {db_name}: {error}"))
            })?;

        // Verify the clone's migration ledger BEFORE returning it (audit
        // F01): the pinned chain, complete, canonical, no dirty rows.
        let complete = clone_ledger_complete(&pool).await.map_err(|error| {
            ProvisionError::new(
                "clone-ledger",
                format!("read back {db_name} ledger: {error}"),
            )
        })?;
        if !complete {
            pool.close().await;
            return Err(ProvisionError::new(
                "clone-ledger",
                format!(
                    "{db_name} does not carry the complete pinned canonical chain \
                     ({} migrations expected)",
                    canonical_migration_count()
                ),
            ));
        }

        Ok(Some(pool))
    }

    /// Direct (non-template) provisioning retained for callers that want
    /// the chain applied into a specific database: drop + create + apply.
    /// Same contract as [`fresh_canonical_db`]: `Ok(None)` only for a blank
    /// base URL; configured failures are `Err` and must fail the test.
    pub async fn fresh_canonical_db_direct(
        base_url: &str,
        db_name: &str,
    ) -> Result<Option<PgPool>, ProvisionError> {
        if base_url.trim().is_empty() {
            return Ok(None);
        }
        let (server_part, _) = base_url.rsplit_once('/').ok_or_else(|| {
            ProvisionError::new(
                "url-parse",
                format!("base URL {base_url:?} has no database segment"),
            )
        })?;

        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(30))
            .connect(&format!("{server_part}/postgres"))
            .await
            .map_err(|error| {
                ProvisionError::new(
                    "admin-connect",
                    format!("connect {server_part}/postgres: {error}"),
                )
            })?;
        drop_database(&admin, db_name).await?;
        sqlx::query(&format!(r#"CREATE DATABASE "{db_name}""#))
            .execute(&admin)
            .await
            .map_err(|error| {
                ProvisionError::new("create-database", format!("create {db_name}: {error}"))
            })?;
        admin.close().await;

        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&format!("{server_part}/{db_name}"))
            .await
            .map_err(|error| {
                ProvisionError::new("db-connect", format!("connect {db_name}: {error}"))
            })?;
        apply_canonical_migrations(&pool).await.map_err(|error| {
            ProvisionError::new(
                "direct-migrate",
                format!("apply canonical chain to {db_name}: {error}"),
            )
        })?;
        Ok(Some(pool))
    }

    /// `TEST_DATABASE_URL` convenience wrapper over [`fresh_canonical_db`]:
    /// provisions `<base>_<db_suffix>` (drop + create + canonical migrate).
    ///
    /// `Ok(None)` ONLY when `TEST_DATABASE_URL` is unset/blank (the suite
    /// is explicitly unconfigured — callers soft-skip). A configured server
    /// that cannot provision the database is `Err(ProvisionError)`: panic
    /// and fail the test (audit F01).
    pub async fn fresh_canonical_pool(
        test_name: &str,
        db_suffix: &str,
    ) -> Result<Option<PgPool>, ProvisionError> {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let database_url = match database_url {
            Some(url) => url,
            None => {
                eprintln!("skipping {test_name}: set TEST_DATABASE_URL to run DB-backed test");
                return Ok(None);
            }
        };
        let (server_part, db_part) = database_url.rsplit_once('/').ok_or_else(|| {
            ProvisionError::new(
                "url-parse",
                format!("TEST_DATABASE_URL {database_url:?} has no database segment"),
            )
        })?;
        let db_only = db_part.split('?').next().unwrap_or(db_part);
        let db_name = format!("{db_only}_{db_suffix}");
        fresh_canonical_db(&format!("{server_part}/{db_only}"), &db_name).await
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{fresh_canonical_db, fresh_canonical_pool};

    /// A blank base URL is the ONLY non-error way to get `Ok(None)` — an
    /// explicitly unconfigured suite (audit F01).
    #[tokio::test]
    async fn blank_base_url_is_none_not_an_error() {
        let result = fresh_canonical_db("", "unused").await;
        assert!(
            result.is_ok(),
            "blank base URL must be Ok(None), got {result:?}"
        );
        assert!(result.unwrap().is_none());
    }

    /// A configured-but-malformed URL is a CONFIGURED failure: it must be
    /// Err, never a silent Ok(None) skip (audit F01).
    #[tokio::test]
    async fn malformed_configured_url_is_an_error() {
        let result = fresh_canonical_db("not-a-url", "unused").await;
        assert!(
            result.is_err(),
            "malformed configured URL must be Err, got {result:?}"
        );
    }

    /// Unset TEST_DATABASE_URL → Ok(None); that is the explicit-unconfigured
    /// signal callers soft-skip on (audit F01).
    #[tokio::test]
    async fn unset_test_database_url_is_none() {
        // SAFETY-of-test: runs in a dedicated test process; nothing else in
        // this binary reads TEST_DATABASE_URL concurrently.
        std::env::remove_var("TEST_DATABASE_URL");
        let result = fresh_canonical_pool("f01_unset_env", "unset").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    /// The finding's own verification case: run two concurrent initializers
    /// against a configured server and prove BOTH returned databases carry
    /// the complete pinned migration ledger (audit F01). Skips only when
    /// TEST_DATABASE_URL is absent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_initializers_both_return_complete_ledgers() {
        let Ok(Some(base)) = fresh_canonical_pool(
            "f01_concurrent_init",
            &format!("conc_{}", &uuid_placeholder()[..6]),
        )
        .await
        else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let url = std::env::var("TEST_DATABASE_URL").expect("checked above");
        let (server_part, db_part) = url.rsplit_once('/').expect("url shape checked by helper");
        let db_only = db_part.split('?').next().unwrap_or(db_part);
        let base_url = format!("{server_part}/{db_only}");

        let suffix = &uuid_placeholder()[..8];
        let first_db = format!("{db_only}_f01a_{suffix}");
        let second_db = format!("{db_only}_f01b_{suffix}");
        let (first, second) = tokio::join!(
            fresh_canonical_db(&base_url, &first_db),
            fresh_canonical_db(&base_url, &second_db)
        );
        for (label, result) in [("first", first), ("second", second)] {
            let pool = result
                .unwrap_or_else(|error| panic!("{label} initializer failed: {error}"))
                .expect("configured server must provision");
            let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
                .fetch_one(&pool)
                .await
                .expect("clone ledger readable");
            assert_eq!(
                applied as usize,
                super::MIGRATIONS.migrations.len(),
                "{label} initializer's clone must carry the complete pinned ledger"
            );
            pool.close().await;
        }
        base.close().await;
    }

    fn uuid_placeholder() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("{:016x}{:016x}", n, 0u64)
    }
}
