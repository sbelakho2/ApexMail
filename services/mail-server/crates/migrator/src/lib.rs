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
/// These helpers are test infrastructure. The `migrator` binary never calls
/// into this module.
pub mod test_support {
    use sqlx::{postgres::PgPoolOptions, PgPool};
    use std::time::Duration;

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

    /// A fresh database named `db_name` carrying the canonical production
    /// schema, cloned from a once-provisioned template.
    ///
    /// Applying the ~170-file chain per test was fine for a handful of
    /// local DB tests, but at CI parallelism (thousands of tests in one
    /// nextest run against one Postgres) the concurrent DDL/lock load
    /// exhausted the cluster's shared lock memory ("out of shared memory",
    /// migration 64) and every DB-backed test slowed to a crawl. The chain
    /// is therefore applied exactly ONCE into `apexmail_canonical_tpl`
    /// (under a cluster advisory lock, verified per process), and each
    /// test database is a `CREATE DATABASE ... TEMPLATE` clone — a fast
    /// filesystem copy with no DDL storm.
    ///
    /// `None` means the server is unreachable or the database could not be
    /// created/migrated; callers soft-skip (workspace convention).
    pub async fn fresh_canonical_db(base_url: &str, db_name: &str) -> Option<PgPool> {
        const TEMPLATE_DB: &str = "apexmail_canonical_tpl";
        // "AXPM-TPL" — cluster-wide exclusive lock guarding template
        // creation/top-up. Per-test clones run WITHOUT the lock (they must
        // not serialize); a clone racing a top-up retries below.
        const TEMPLATE_LOCK_KEY: i64 = 0x4158_504D_5450_4C21;
        static TEMPLATE_VERIFIED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

        let (server_part, _) = base_url.rsplit_once('/')?;
        let admin_url = format!("{server_part}/postgres");

        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(60))
            .connect(&admin_url)
            .await
            .ok()?;

        if TEMPLATE_VERIFIED.set(()).is_ok() {
            // First DB test in this process: create or top up the template.
            let _ = sqlx::query("SELECT pg_advisory_lock($1)")
                .bind(TEMPLATE_LOCK_KEY)
                .execute(&admin)
                .await;
            let outcome = async {
                let template_exists: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)",
                )
                .bind(TEMPLATE_DB)
                .fetch_one(&admin)
                .await
                .unwrap_or(false);

                if !template_exists {
                    sqlx::query(&format!(r#"CREATE DATABASE "{TEMPLATE_DB}""#))
                        .execute(&admin)
                        .await
                        .ok()?;
                }

                // Connect, verify/complete the lineage, disconnect (a
                // connected template blocks clones — keep this window
                // short and exclusive to the advisory lock).
                let template_pool = PgPoolOptions::new()
                    .max_connections(1)
                    .acquire_timeout(Duration::from_secs(60))
                    .connect(&format!("{server_part}/{TEMPLATE_DB}"))
                    .await
                    .ok()?;
                let healthy = canonical_lineage(&template_pool).await;
                let result = match healthy {
                    Some(true) => {
                        apply_canonical_migrations(&template_pool).await.ok()?;
                        Some(())
                    }
                    // Foreign/dirty lineage or an unreadable probe on a
                    // template WE own: rebuild it from scratch.
                    _ => {
                        template_pool.close().await;
                        sqlx::query(&format!(
                            r#"DROP DATABASE IF EXISTS "{TEMPLATE_DB}" WITH (FORCE)"#
                        ))
                        .execute(&admin)
                        .await
                        .ok()?;
                        sqlx::query(&format!(r#"CREATE DATABASE "{TEMPLATE_DB}""#))
                            .execute(&admin)
                            .await
                            .ok()?;
                        let rebuilt = PgPoolOptions::new()
                            .max_connections(1)
                            .acquire_timeout(Duration::from_secs(60))
                            .connect(&format!("{server_part}/{TEMPLATE_DB}"))
                            .await
                            .ok()?;
                        apply_canonical_migrations(&rebuilt).await.ok()?;
                        rebuilt.close().await;
                        Some(())
                    }
                };
                if healthy == Some(true) {
                    template_pool.close().await;
                }
                result
            }
            .await;
            let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
                .bind(TEMPLATE_LOCK_KEY)
                .execute(&admin)
                .await;
            if outcome.is_none() {
                eprintln!(
                    "canonical test template bootstrap failed; falling back to a direct apply"
                );
            }
        }

        // Per-test database: drop any leftover, clone the template. The
        // retry absorbs a clone racing another process's top-up window
        // ("source database is being accessed by other users").
        let _ = sqlx::query(&format!(
            r#"DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)"#
        ))
        .execute(&admin)
        .await;
        let mut cloned = false;
        for attempt in 0..12 {
            match sqlx::query(&format!(
                r#"CREATE DATABASE "{db_name}" TEMPLATE "{TEMPLATE_DB}""#
            ))
            .execute(&admin)
            .await
            {
                Ok(_) => {
                    cloned = true;
                    break;
                }
                Err(error) => {
                    let busy = error.to_string().contains("source database")
                        || error.to_string().contains("accessed by other users");
                    if !busy || attempt == 11 {
                        eprintln!("canonical test DB clone failed for {db_name}: {error}");
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
        }
        admin.close().await;
        if !cloned {
            return None;
        }

        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&format!("{server_part}/{db_name}"))
            .await
            .ok()?;
        Some(pool)
    }

    /// Direct (non-template) provisioning retained for callers that want
    /// the chain applied into a specific database: drop + create + apply.
    pub async fn fresh_canonical_db_direct(base_url: &str, db_name: &str) -> Option<PgPool> {
        let (server_part, _) = base_url.rsplit_once('/')?;
        let admin_url = format!("{server_part}/postgres");

        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(30))
            .connect(&admin_url)
            .await
            .ok()?;
        let _ = sqlx::query(&format!(
            r#"DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)"#
        ))
        .execute(&admin)
        .await;
        let created = sqlx::query(&format!(r#"CREATE DATABASE "{db_name}""#))
            .execute(&admin)
            .await;
        admin.close().await;
        created.ok()?;

        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&format!("{server_part}/{db_name}"))
            .await
            .ok()?;
        apply_canonical_migrations(&pool)
            .await
            .map_err(|error| {
                eprintln!("canonical test DB bootstrap: migration apply failed: {error}");
            })
            .ok()?;
        Some(pool)
    }

    /// `TEST_DATABASE_URL` convenience wrapper over [`fresh_canonical_db`]:
    /// provisions `<base>_<db_suffix>` (drop + create + canonical migrate).
    /// Soft-skips (returns `None`) when `TEST_DATABASE_URL` is unset or the
    /// server is unreachable.
    pub async fn fresh_canonical_pool(test_name: &str, db_suffix: &str) -> Option<PgPool> {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| {
                eprintln!("skipping {test_name}: set TEST_DATABASE_URL to run DB-backed test");
                None
            })?;
        let (server_part, db_part) = database_url.rsplit_once('/')?;
        let db_only = db_part.split('?').next().unwrap_or(db_part);
        let db_name = format!("{db_only}_{db_suffix}");
        fresh_canonical_db(&format!("{server_part}/{db_only}"), &db_name).await
    }
}
