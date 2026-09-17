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
    #[derive(Debug, Clone)]
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

    /// Verify a freshly provisioned database's migration ledger BEFORE the
    /// pool is returned (audit F01): the pinned chain, complete, canonical,
    /// no dirty rows. `stage` names the provisioning step for the failure
    /// message; the pool is closed when the ledger is not usable.
    async fn verify_clone_ledger(
        pool: &PgPool,
        stage: &'static str,
        db_name: &str,
        detail: &str,
    ) -> Result<(), ProvisionError> {
        let complete = clone_ledger_complete(pool)
            .await
            .map_err(|error| ledger_read_error(stage, db_name, error))?;
        if !complete {
            pool.close().await;
            return Err(ProvisionError::new(
                stage,
                format!("{db_name} does not carry the complete pinned canonical chain{detail}"),
            ));
        }
        Ok(())
    }

    fn ledger_read_error(stage: &'static str, db_name: &str, error: sqlx::Error) -> ProvisionError {
        ProvisionError::new(stage, format!("read back {db_name} ledger: {error}"))
    }

    fn direct_migrate_error(db_name: &str, error: anyhow::Error) -> ProvisionError {
        ProvisionError::new(
            "direct-migrate",
            format!("apply canonical chain to {db_name}: {error}"),
        )
    }

    fn create_database_error(
        stage: &'static str,
        prefix: &str,
        db_name: &str,
        error: sqlx::Error,
    ) -> ProvisionError {
        ProvisionError::new(stage, format!("{prefix}{db_name}: {error}"))
    }

    /// Connect to a just-created clone with a bounded retry that RE-CREATES
    /// the clone when it has vanished: another process provisioning the same
    /// name (nextest runs every test in its own process) can drop it between
    /// the CREATE and this connect, which surfaced as the confusing
    /// `clone-connect: database "…" does not exist`. The advisory lock held
    /// by the caller serializes same-name provisioning, so the retry
    /// converges.
    async fn connect_clone_with_recreate(
        admin: &PgPool,
        server_part: &str,
        db_name: &str,
        template_db: &str,
    ) -> Result<PgPool, ProvisionError> {
        let mut pool = None;
        let mut last_connect_error: Option<sqlx::Error> = None;
        for attempt in 0..5 {
            match PgPoolOptions::new()
                .max_connections(4)
                .acquire_timeout(Duration::from_secs(5))
                .connect(&format!("{server_part}/{db_name}"))
                .await
            {
                Ok(connected) => {
                    pool = Some(connected);
                    break;
                }
                Err(error) => {
                    let missing = error.to_string().contains("does not exist");
                    last_connect_error = Some(error);
                    if !missing || attempt == 4 {
                        break;
                    }
                    let _ = sqlx::query(&format!(
                        r#"CREATE DATABASE "{db_name}" TEMPLATE "{template_db}""#
                    ))
                    .execute(admin)
                    .await;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
        pool.ok_or_else(|| {
            let error = last_connect_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "unknown connect failure".to_string());
            ProvisionError::new("clone-connect", format!("connect {db_name}: {error}"))
        })
    }

    /// Connect to a freshly created (non-clone) database, mapping a failure
    /// to the named provisioning stage.
    async fn connect_provisioned_db(
        server_part: &str,
        db_name: &str,
        stage: &'static str,
    ) -> Result<PgPool, ProvisionError> {
        PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&format!("{server_part}/{db_name}"))
            .await
            .map_err(|error| ProvisionError::new(stage, format!("connect {db_name}: {error}")))
    }

    /// `CREATE DATABASE` with the failure mapped to the caller's stage and
    /// message prefix (kept as one helper so every provisioning path reports
    /// create failures the same way).
    async fn create_database(
        admin: &PgPool,
        db_name: &str,
        stage: &'static str,
        prefix: &str,
    ) -> Result<(), ProvisionError> {
        sqlx::query(&format!(r#"CREATE DATABASE "{db_name}""#))
            .execute(admin)
            .await
            .map_err(|error| create_database_error(stage, prefix, db_name, error))?;
        Ok(())
    }

    /// Apply the canonical chain to an already-connected fresh database,
    /// mapping a failure to the direct-migrate stage.
    async fn migrate_provisioned_database(
        pool: &PgPool,
        db_name: &str,
    ) -> Result<(), ProvisionError> {
        apply_canonical_migrations(pool)
            .await
            .map_err(|error| direct_migrate_error(db_name, error))
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
        NAME.get_or_init(compute_canonical_template_db)
    }

    /// The template-identity computation: chain length, newest version and an
    /// FNV-1a digest of every (version, checksum) pair.
    fn compute_canonical_template_db() -> String {
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
        // Bounded retry: under a full workspace parallel run (every DB-backed
        // test funnels through this one template) the template-connect probe
        // can time out purely from connection queueing. The cluster advisory
        // lock serializes real work, so a retry is safe; a persistent
        // failure still fails the stage.
        let mut last: Option<ProvisionError> = None;
        for attempt in 0..3u32 {
            match TEMPLATE_READY
                .get_or_try_init(|| prepare_template_under_lock(admin, server_part))
                .await
            {
                Ok(()) => return Ok(()),
                Err(error) => {
                    last = Some(error.clone());
                    if attempt < 2 {
                        tokio::time::sleep(Duration::from_secs(2 * (attempt as u64 + 1))).await;
                    }
                }
            }
        }
        Err(last.unwrap_or_else(|| {
            ProvisionError::new("template-ready", "template preparation failed")
        }))
    }

    /// Body of [`ensure_template_ready`]: take the cluster advisory lock,
    /// run the template build/top-up, release the lock.
    async fn prepare_template_under_lock(
        admin: &PgPool,
        server_part: &str,
    ) -> Result<(), ProvisionError> {
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
    }

    /// Connect to a template database (single connection, generous timeout:
    /// a connected template blocks clones, so the window is kept short and
    /// exclusive to the advisory lock).
    async fn connect_template_db(
        server_part: &str,
        template_db: &str,
    ) -> Result<PgPool, ProvisionError> {
        // The window is deliberately generous: the probe connection queues
        // behind every other process's clone traffic under a full workspace
        // parallel run.
        PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(180))
            .connect(&format!("{server_part}/{template_db}"))
            .await
            .map_err(|error| template_connect_error(template_db, error))
    }

    fn template_connect_error(template_db: &str, error: sqlx::Error) -> ProvisionError {
        ProvisionError::new(
            "template-connect",
            format!("connect template {template_db}: {error}"),
        )
    }

    /// Body of [`ensure_template_ready`], run holding the advisory lock.
    /// On success the template's ledger was just verified COMPLETE.
    async fn ensure_template_locked(
        admin: &PgPool,
        server_part: &str,
        template_db: &str,
    ) -> Result<(), ProvisionError> {
        let connect_template = || async { connect_template_db(server_part, template_db).await };

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
                    create_database(admin, template_db, "template-recreate", "recreate ").await?;
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
            create_database(admin, template_db, "template-create", "create ").await?;
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
        let verified = verify_clone_ledger(
            &verify_pool,
            "template-verify",
            template_db,
            &format!(" ({} migrations expected)", canonical_migration_count()),
        )
        .await;
        verify_pool.close().await;
        verified
    }

    /// Drop a database using the privileges a non-superuser test role has.
    ///
    /// `DROP DATABASE ... WITH (FORCE)` terminates EVERY backend on the target,
    /// including backends owned by other roles, which requires superuser or
    /// `pg_signal_backend`. A non-superuser test role therefore fails with
    /// "must be a member of the role whose process is being terminated"
    /// whenever a session has not finished closing — which made provisioning
    /// fail intermittently (observed as a rotating handful of DB-backed tests
    /// failing under repeat runs).
    ///
    /// Terminating the sessions THIS role owns is always permitted, so release
    /// those and retry before giving up. FORCE stays as the last attempt: it
    /// succeeds for a privileged role, and for an unprivileged one its error is
    /// the most specific available.
    async fn drop_database(admin: &PgPool, db_name: &str) -> Result<(), ProvisionError> {
        let mut last: Option<sqlx::Error> = None;
        for attempt in 0..5u32 {
            match sqlx::query(&format!(r#"DROP DATABASE IF EXISTS "{db_name}""#))
                .execute(admin)
                .await
            {
                Ok(_) => return Ok(()),
                Err(error) => {
                    // Release our own lingering sessions (a pool still shutting
                    // down, or a verification pool that outlived its use). A
                    // database must have no connections to be dropped.
                    let _ = sqlx::query(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                         WHERE datname = $1 AND usename = current_user \
                           AND pid <> pg_backend_pid()",
                    )
                    .bind(db_name)
                    .execute(admin)
                    .await;
                    last = Some(error);
                    tokio::time::sleep(std::time::Duration::from_millis(
                        50 * u64::from(attempt + 1),
                    ))
                    .await;
                }
            }
        }

        if let Err(error) = sqlx::query(&format!(
            r#"DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)"#
        ))
        .execute(admin)
        .await
        {
            return Err(force_drop_error(db_name, &error, last));
        }
        Ok(())
    }

    fn admin_connect_error(server_part: &str, error: sqlx::Error) -> ProvisionError {
        ProvisionError::new(
            "admin-connect",
            format!("connect {server_part}/postgres: {error}"),
        )
    }

    fn url_without_database_segment(base_url: &str) -> ProvisionError {
        ProvisionError::new(
            "url-parse",
            format!("base URL {base_url:?} has no database segment"),
        )
    }

    fn test_database_url_without_segment(database_url: &str) -> ProvisionError {
        ProvisionError::new(
            "url-parse",
            format!("TEST_DATABASE_URL {database_url:?} has no database segment"),
        )
    }

    fn shared_clone_error(db_name: &str, error: sqlx::Error) -> ProvisionError {
        ProvisionError::new("shared-clone", format!("clone {db_name}: {error}"))
    }

    fn shared_connect_error(db_name: &str, error: sqlx::Error) -> ProvisionError {
        ProvisionError::new(
            "shared-connect",
            format!("connect shared {db_name}: {error}"),
        )
    }

    /// The FORCE-drop failure message: names the target, the last plain-drop
    /// error, and the operator fix.
    fn force_drop_error(
        db_name: &str,
        error: &sqlx::Error,
        last: Option<sqlx::Error>,
    ) -> ProvisionError {
        ProvisionError::new(
            "drop-database",
            format!(
                "drop {db_name}: {error}. The plain drop could not release it either (last \
                 error: {}). A session owned by a role other than `{}` is still connected — \
                 terminate it, or grant the test role membership in pg_signal_backend.",
                last.map(|e| e.to_string()).unwrap_or_else(|| "none".into()),
                "the test role",
            ),
        )
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
        let (server_part, _) = base_url
            .rsplit_once('/')
            .ok_or_else(|| url_without_database_segment(base_url))?;

        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(60))
            .connect(&format!("{server_part}/postgres"))
            .await
            .map_err(|error| admin_connect_error(server_part, error))?;

        ensure_template_ready(&admin, server_part).await?;

        // Serialize same-name provisioning across processes: two nextest
        // workers issuing DROP+CREATE for one name otherwise race into
        // pg_database_datname_index duplicates (and a FORCE drop can sever a
        // sibling's active connections).
        let _ = sqlx::query("SELECT pg_advisory_lock(hashtext($1))")
            .bind(db_name)
            .execute(&admin)
            .await;

        // Per-test database: drop any leftover, clone the template. The
        // retry absorbs a clone racing another process's top-up window
        // ("source database is being accessed by other users").
        drop_database(&admin, db_name).await?;
        let template_db = canonical_template_db();
        let mut last_error: Option<sqlx::Error> = None;
        // Backoff ladder: 250ms for the first 24 attempts, then 1s — under
        // a full workspace parallel run the template can be held by another
        // process's top-up or clone for well over a flat 12-second window.
        for attempt in 0..60u32 {
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
                    let text = error.to_string();
                    let busy = text.contains("source database")
                        || text.contains("accessed by other users");
                    // A killed drop can leave the catalog row behind for an
                    // instant: the duplicate-key CREATE failure is the same
                    // transient class — drop again and retry.
                    let stale_catalog_row = text.contains("pg_database_datname_index");
                    if stale_catalog_row {
                        drop_database(&admin, db_name).await?;
                    }
                    if (!busy && !stale_catalog_row) || attempt == 59 {
                        last_error = Some(error);
                        break;
                    }
                    let delay = if attempt < 24 { 250 } else { 1_000 };
                    tokio::time::sleep(Duration::from_millis(delay)).await;
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
        // Connect with a bounded retry that RE-CREATES the clone when it has
        // vanished: another process provisioning the same name can drop it
        // between the CREATE above and this connect.
        let pool =
            match connect_clone_with_recreate(&admin, server_part, db_name, template_db).await {
                Ok(pool) => pool,
                Err(error) => {
                    admin.close().await;
                    return Err(error);
                }
            };
        admin.close().await;

        // Verify the clone's migration ledger BEFORE returning it (audit
        // F01): the pinned chain, complete, canonical, no dirty rows.
        verify_clone_ledger(
            &pool,
            "clone-ledger",
            db_name,
            &format!(" ({} migrations expected)", canonical_migration_count()),
        )
        .await?;

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
        let (server_part, _) = base_url
            .rsplit_once('/')
            .ok_or_else(|| url_without_database_segment(base_url))?;

        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(30))
            .connect(&format!("{server_part}/postgres"))
            .await
            .map_err(|error| admin_connect_error(server_part, error))?;
        drop_database(&admin, db_name).await?;
        create_database(&admin, db_name, "create-database", "create ").await?;
        admin.close().await;

        let pool = connect_provisioned_db(server_part, db_name, "db-connect").await?;
        migrate_provisioned_database(&pool, db_name).await?;
        Ok(Some(pool))
    }

    /// `TEST_DATABASE_URL` convenience wrapper over [`fresh_canonical_db`]:
    /// provisions `<base>_<db_suffix>` (drop + create + canonical migrate).
    ///
    /// `Ok(None)` ONLY when `TEST_DATABASE_URL` is unset/blank (the suite
    /// is explicitly unconfigured — callers soft-skip). A configured server
    /// that cannot provision the database is `Err(ProvisionError)`: panic
    /// and fail the test (audit F01).
    /// Compose a per-test database name that CANNOT exceed Postgres's
    /// 63-byte identifier limit: longer names are silently truncated by the
    /// catalog, which both breaks the later connect (the full name is not
    /// found) and COLLIDES distinct suffixes that share a truncated prefix
    /// (the intermittent `pg_database_datname_index` duplicate-key flake).
    /// A long suffix is folded into a deterministic 16-hex digest.
    fn bounded_test_db_name(db_only: &str, db_suffix: &str) -> String {
        let full = format!("{db_only}_{db_suffix}");
        if full.len() <= 63 {
            return full;
        }
        let digest = {
            // FNV-1a, same family the template fingerprint uses.
            let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
            for byte in db_suffix.bytes() {
                hash ^= u64::from(byte);
                hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            }
            hash
        };
        format!("{db_only}_t{digest:016x}")
    }

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
        let (server_part, db_part) = database_url
            .rsplit_once('/')
            .ok_or_else(|| test_database_url_without_segment(&database_url))?;
        let db_only = db_part.split('?').next().unwrap_or(db_part);
        let db_name = bounded_test_db_name(db_only, db_suffix);
        fresh_canonical_db(&format!("{server_part}/{db_only}"), &db_name).await
    }

    /// A **shared** canonical database: create-if-absent, reuse-if-present.
    ///
    /// Suites whose tests intentionally share ONE database (sales-autopilot's
    /// `apexmail_sales_test`, provisioned once per suite under a
    /// `#[cfg(test)]` process-local OnceCell) run many nextest PROCESSES in
    /// parallel — each process would otherwise DROP+CREATE the same name,
    /// racing into `pg_database_datname_index` duplicates and FORCE-dropping a
    /// database a sibling is actively using. This variant takes a Postgres
    /// advisory lock keyed on the database name and reuses an existing
    /// database that already carries the complete pinned canonical lineage;
    /// anything else (absent, foreign lineage, partial clone) is replaced
    /// under the same lock.
    pub async fn shared_canonical_db(
        base_url: &str,
        db_name: &str,
    ) -> Result<Option<PgPool>, ProvisionError> {
        if base_url.trim().is_empty() {
            return Ok(None);
        }
        let (server_part, _) = base_url
            .rsplit_once('/')
            .ok_or_else(|| url_without_database_segment(base_url))?;
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(60))
            .connect(&format!("{server_part}/postgres"))
            .await
            .map_err(|error| admin_connect_error(server_part, error))?;

        // Serialize provisioning of THIS name across processes. hashtext is
        // stable for the same name; the lock is session-scoped on the admin
        // pool's single connection and released when it closes.
        let _ = sqlx::query("SELECT pg_advisory_lock(hashtext($1))")
            .bind(db_name)
            .execute(&admin)
            .await;

        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)")
                .bind(db_name)
                .fetch_one(&admin)
                .await
                .unwrap_or(false);

        if exists {
            // Reuse only a database whose ledger is the complete pinned
            // chain; a partial/foreign leftover is replaced.
            let healthy = match PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(10))
                .connect(&format!("{server_part}/{db_name}"))
                .await
            {
                Ok(pool) => {
                    let complete = clone_ledger_complete(&pool).await.unwrap_or(false);
                    pool.close().await;
                    complete
                }
                Err(_) => false,
            };
            if healthy {
                admin.close().await; // releases the advisory lock
                let pool = PgPoolOptions::new()
                    .max_connections(4)
                    .acquire_timeout(Duration::from_secs(5))
                    .connect(&format!("{server_part}/{db_name}"))
                    .await
                    .map_err(|error| shared_connect_error(db_name, error))?;
                return Ok(Some(pool));
            }
        }

        ensure_template_ready(&admin, server_part).await?;
        drop_database(&admin, db_name).await?;
        let template_db = canonical_template_db();
        // The template is concurrently topped up by other processes (and a
        // killed drop can leave a stale catalog row): retry the same
        // transient classes the fresh path retries.
        let mut clone_error = None;
        // Same backoff ladder as the fresh path (see there for why).
        for attempt in 0..60u32 {
            match sqlx::query(&format!(
                r#"CREATE DATABASE "{db_name}" TEMPLATE "{template_db}""#
            ))
            .execute(&admin)
            .await
            {
                Ok(_) => {
                    clone_error = None;
                    break;
                }
                Err(error) => {
                    let text = error.to_string();
                    let busy = text.contains("source database")
                        || text.contains("accessed by other users");
                    let stale_catalog_row = text.contains("pg_database_datname_index");
                    if stale_catalog_row {
                        drop_database(&admin, db_name).await?;
                    }
                    if (!busy && !stale_catalog_row) || attempt == 59 {
                        clone_error = Some(error);
                        break;
                    }
                    let delay = if attempt < 24 { 250 } else { 1_000 };
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
            }
        }
        if let Some(error) = clone_error {
            return Err(shared_clone_error(db_name, error));
        }
        admin.close().await;

        let pool = connect_provisioned_db(server_part, db_name, "shared-connect").await?;
        verify_clone_ledger(&pool, "shared-ledger", db_name, "").await?;
        Ok(Some(pool))
    }

    /// Adversarial provisioning tests for the private paths of this module:
    /// template build/rebuild, lineage classification, ledger verification,
    /// clone busy-retry and vanished-clone recreate, drop retries, and the
    /// migration-229 marker/quarantine behaviour. Every database created here
    /// is a PRIVATE throwaway derived from the canonical chain; the shared
    /// base database is never mutated.
    #[cfg(test)]
    pub(crate) mod provision_tests {
        /// Cross-process serialization for tests that HOLD sessions on the
        /// canonical template (or depend on cloning it promptly): under a
        /// full workspace parallel run every DB-backed test clones from the
        /// ONE template, and a deliberate holder here stacks the queue past
        /// any fixed retry window. A session-level advisory lock on the
        /// admin database; released when the pool drops.
        pub(crate) async fn template_clone_guard() -> sqlx::PgPool {
            let url = std::env::var("TEST_DATABASE_ADMIN_URL")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .or_else(|| {
                    std::env::var("TEST_DATABASE_URL")
                        .ok()
                        .filter(|value| !value.trim().is_empty())
                        .and_then(|value| {
                            value
                                .rsplit_once('/')
                                .map(|(server, _)| format!("{server}/postgres"))
                        })
                })
                .expect("admin url");
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(std::time::Duration::from_secs(120))
                .connect(&url)
                .await
                .expect("admin connect for template guard");
            sqlx::query("SELECT pg_advisory_lock(hashtext($1))")
                .bind("migrator:provision-tests:template")
                .execute(&pool)
                .await
                .expect("template advisory lock");
            pool
        }

        use super::{
            apply_canonical_migrations, canonical_lineage, canonical_template_db,
            connect_clone_with_recreate, connect_provisioned_db, create_database, drop_database,
            ensure_template_locked, fresh_canonical_db, fresh_canonical_db_direct,
            migrate_provisioned_database, shared_canonical_db, verify_clone_ledger, ProvisionError,
        };
        use sqlx::postgres::PgPoolOptions;
        use sqlx::PgPool;
        use std::time::Duration;

        /// Serializes every test that touches process-global state (env vars)
        /// or holds sessions on the shared template.
        static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

        fn counter() -> u64 {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            COUNTER.fetch_add(1, Ordering::Relaxed)
        }

        /// The database ROLE the provisioning code connects as (parsed from
        /// the base URL userinfo — not the database name).
        fn test_role(server_part: &str) -> String {
            let (_scheme, rest) = server_part.split_once("://").expect("scheme");
            let userinfo = rest.split('@').next().unwrap_or(rest);
            userinfo.split(':').next().unwrap_or(userinfo).to_string()
        }

        fn probe_name(label: &str) -> String {
            let counter = counter();
            // The process id keeps names unique across runs: a probe left
            // behind by a failed run must not collide with the next one.
            format!(
                "migrator_probe_{label}_{}_{counter:04}",
                std::process::id() % 100000
            )
        }

        /// `(server_part, db_only)` from TEST_DATABASE_URL; `None` when the
        /// suite is unconfigured (caller soft-skips).
        fn base_parts() -> Option<(String, String)> {
            let url = std::env::var("TEST_DATABASE_URL").ok()?;
            let (server, db) = url.rsplit_once('/')?;
            let db_only = db.split('?').next().unwrap_or(db).to_string();
            Some((server.to_string(), db_only))
        }

        /// A pool connected as the test database role (the same role the
        /// provisioning code uses).
        async fn test_role_pool(server_part: &str, db_name: &str) -> PgPool {
            PgPoolOptions::new()
                .max_connections(4)
                .acquire_timeout(Duration::from_secs(10))
                .connect(&format!("{server_part}/{db_name}"))
                .await
                .expect("connect probe database")
        }

        /// A superuser/admin pool for setup steps a DML role cannot do
        /// (`pg_` name rejection probes rely on CREATE attempts, not admin
        /// tricks). `None` when TEST_DATABASE_ADMIN_URL is unset.
        async fn admin_pool() -> Option<PgPool> {
            let url = std::env::var("TEST_DATABASE_ADMIN_URL").ok()?;
            let (server, _) = url.rsplit_once('/')?;
            Some(
                PgPoolOptions::new()
                    .max_connections(2)
                    .acquire_timeout(Duration::from_secs(10))
                    .connect(&format!("{server}/postgres"))
                    .await
                    .expect("connect admin"),
            )
        }

        async fn drop_quietly(server_part: &str, db_name: &str) {
            let Ok(admin) = PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(10))
                .connect(&format!("{server_part}/postgres"))
                .await
            else {
                return;
            };
            let _ = drop_database(&admin, db_name).await;
            admin.close().await;
        }

        /// Build a runtime Migrator over a temp directory holding the
        /// canonical migration files with `version <= upto` — the real chain,
        /// truncated, without touching the frozen source tree.
        async fn subset_migrator(upto: i64) -> sqlx::migrate::Migrator {
            let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
            let dir = std::env::temp_dir().join(format!(
                "apexmail_migrator_subset_{upto}_{}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).expect("create subset dir");
            for entry in std::fs::read_dir(&source).expect("read migrations dir") {
                let entry = entry.expect("dir entry");
                let name = entry.file_name().to_string_lossy().into_owned();
                if !name.ends_with(".sql") {
                    continue;
                }
                let version: i64 = name
                    .split('_')
                    .next()
                    .and_then(|prefix| prefix.parse().ok())
                    .unwrap_or(i64::MAX);
                if version <= upto {
                    std::fs::copy(entry.path(), dir.join(&name)).expect("copy migration");
                }
            }
            sqlx::migrate::Migrator::new(dir)
                .await
                .expect("build subset migrator")
        }

        // ── ProvisionError surface ─────────────────────────────────────────

        #[test]
        fn provision_error_names_stage_detail_and_fix() {
            let error = ProvisionError::new("clone", "database exploded");
            assert_eq!(error.stage(), "clone");
            assert_eq!(error.to_string(), "clone: database exploded");
            let panic = error.panic_message();
            assert!(panic.contains("stage 'clone'"), "{panic}");
            assert!(panic.contains("database exploded"), "{panic}");
            assert!(panic.contains("do not skip the test"), "{panic}");
        }

        // ── applied_count / apply_migrations ───────────────────────────────

        /// `applied_count` counts the ledger on a migrated database (the
        /// to_regclass Some arm) and reports 0 on a database with no ledger.
        #[tokio::test]
        async fn applied_count_reports_ledger_and_zero_for_fresh() {
            let _template_guard = template_clone_guard().await;
            let _guard = SERIAL.lock().await;
            let Some((server, db_only)) = base_parts() else {
                eprintln!("skipping: TEST_DATABASE_URL not set");
                return;
            };
            let probe = probe_name("count");
            let pool = fresh_canonical_db(&format!("{server}/{db_only}"), &probe)
                .await
                .expect("provision")
                .expect("configured");
            let counted = crate::applied_count(&pool)
                .await
                .expect("applied_count ledger");
            assert_eq!(counted as usize, crate::MIGRATIONS.migrations.len());
            pool.close().await;

            // A database with no ledger at all reports 0 (the fresh-database
            // NULL-decode contract, pipeline finding F2).
            let admin = PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(10))
                .connect(&format!("{server}/postgres"))
                .await
                .expect("connect admin");
            let empty = probe_name("count_empty");
            drop_quietly(&server, &empty).await;
            sqlx::query(&format!(r#"CREATE DATABASE "{empty}""#))
                .execute(&admin)
                .await
                .expect("create empty probe");
            admin.close().await;
            let empty_pool = test_role_pool(&server, &empty).await;
            assert_eq!(
                crate::applied_count(&empty_pool)
                    .await
                    .expect("count empty"),
                0
            );
            empty_pool.close().await;
            drop_quietly(&server, &empty).await;
            drop_quietly(&server, &probe).await;
        }

        /// `apply_migrations` is idempotent on a complete database (0 new) and
        /// extends the partition runway.
        #[tokio::test]
        async fn apply_migrations_is_idempotent_and_extends_runway() {
            let _template_guard = template_clone_guard().await;
            let _guard = SERIAL.lock().await;
            let Some((server, db_only)) = base_parts() else {
                eprintln!("skipping: TEST_DATABASE_URL not set");
                return;
            };
            let probe = probe_name("apply");
            let pool = fresh_canonical_db(&format!("{server}/{db_only}"), &probe)
                .await
                .expect("provision")
                .expect("configured");
            apply_canonical_migrations(&pool)
                .await
                .expect("re-apply on complete database");
            let runway: Option<String> = sqlx::query_scalar(
                "SELECT to_regprocedure('public.create_future_partitions()')::text",
            )
            .fetch_one(&pool)
            .await
            .expect("runway probe");
            assert!(runway.is_some(), "runway function must exist after apply");
            pool.close().await;
            drop_quietly(&server, &probe).await;
        }

        /// On a pre-050 database `create_future_partitions` does not exist
        /// yet: applying the chain must still succeed and report the absent
        /// runway as a notice, not an error.
        #[tokio::test]
        async fn apply_migrations_on_pre_partition_database_notes_absent_runway() {
            let _template_guard = template_clone_guard().await;
            let Some((server, _db_only)) = base_parts() else {
                eprintln!("skipping: TEST_DATABASE_URL not set");
                return;
            };
            let probe = probe_name("pre050");
            let admin = PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(10))
                .connect(&format!("{server}/postgres"))
                .await
                .expect("connect admin");
            drop_quietly(&server, &probe).await;
            sqlx::query(&format!(r#"CREATE DATABASE "{probe}""#))
                .execute(&admin)
                .await
                .expect("create probe");
            admin.close().await;
            let pool = test_role_pool(&server, &probe).await;
            subset_migrator(49)
                .await
                .run(&pool)
                .await
                .expect("apply prefix 1..49");
            let before = crate::applied_count(&pool).await.expect("count");
            assert!(before >= 40, "prefix applied (got {before})");
            apply_canonical_migrations(&pool)
                .await
                .expect("apply the rest despite absent runway function");
            let after = crate::applied_count(&pool).await.expect("count");
            assert_eq!(after as usize, crate::MIGRATIONS.migrations.len());
            pool.close().await;
            drop_quietly(&server, &probe).await;
        }

        // ── canonical_lineage ──────────────────────────────────────────────

        /// Lineage classification: fresh database canonical by definition;
        /// strict prefix canonical; dirty row, extra row, foreign checksum
        /// all refuse; unreadable ledger is indistinguishable (None).
        #[tokio::test]
        async fn canonical_lineage_classifies_ledgers() {
            let _template_guard = template_clone_guard().await;
            let _guard = SERIAL.lock().await;
            let Some((server, db_only)) = base_parts() else {
                eprintln!("skipping: TEST_DATABASE_URL not set");
                return;
            };
            let base = format!("{server}/{db_only}");

            // Fresh database (no _sqlx_migrations): canonical by definition.
            let admin = PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(10))
                .connect(&format!("{server}/postgres"))
                .await
                .expect("connect admin");
            let fresh = probe_name("lineage_fresh");
            drop_quietly(&server, &fresh).await;
            sqlx::query(&format!(r#"CREATE DATABASE "{fresh}""#))
                .execute(&admin)
                .await
                .expect("create fresh probe");
            let fresh_pool = test_role_pool(&server, &fresh).await;
            assert_eq!(canonical_lineage(&fresh_pool).await, Some(true));
            fresh_pool.close().await;
            drop_quietly(&server, &fresh).await;

            // A complete canonical clone is canonical; every corruption of
            // the ledger must be classified as foreign.
            let probe = probe_name("lineage");
            let pool = fresh_canonical_db(&base, &probe)
                .await
                .expect("provision")
                .expect("configured");
            assert_eq!(canonical_lineage(&pool).await, Some(true));

            // Dirty row (success = false): unusable.
            sqlx::query(
                "UPDATE _sqlx_migrations SET success = false \
                         WHERE version = (SELECT min(version) FROM _sqlx_migrations)",
            )
            .execute(&pool)
            .await
            .expect("mark dirty");
            assert_eq!(canonical_lineage(&pool).await, Some(false));
            sqlx::query("UPDATE _sqlx_migrations SET success = true WHERE success = false")
                .execute(&pool)
                .await
                .expect("unmark dirty");

            // More rows than the canonical chain pins: foreign lineage.
            sqlx::query("INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) \
                         VALUES (9999, 'future build', NOW(), true, '\\x01'::bytea, 0)")
                .execute(&pool)
                .await
                .expect("insert extra row");
            assert_eq!(canonical_lineage(&pool).await, Some(false));
            sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 9999")
                .execute(&pool)
                .await
                .expect("remove extra row");
            assert_eq!(canonical_lineage(&pool).await, Some(true));

            // Foreign checksum at the first row: foreign lineage (no restore
            // needed — the probe is dropped right after).
            sqlx::query(
                "UPDATE _sqlx_migrations SET checksum = '\\x00'::bytea \
                         WHERE version = (SELECT min(version) FROM _sqlx_migrations)",
            )
            .execute(&pool)
            .await
            .expect("corrupt checksum");
            assert_eq!(canonical_lineage(&pool).await, Some(false));

            // A ledger that cannot be read at all (the relation exists but
            // does not have the expected columns) is reported as undetermined.
            sqlx::query("DROP TABLE _sqlx_migrations")
                .execute(&pool)
                .await
                .expect("drop ledger");
            sqlx::query("CREATE TABLE _sqlx_migrations (unrelated INT)")
                .execute(&pool)
                .await
                .expect("decoy relation");
            assert_eq!(canonical_lineage(&pool).await, None);
            pool.close().await;
            drop_quietly(&server, &probe).await;
            admin.close().await;
        }

        // ── ledger completeness gate ───────────────────────────────────────

        /// `verify_clone_ledger` fails (closing the pool) for an incomplete
        /// ledger, and maps read failures to the named stage.
        #[tokio::test]
        async fn verify_clone_ledger_rejects_incomplete_and_unreadable() {
            let _template_guard = template_clone_guard().await;
            let _guard = SERIAL.lock().await;
            let Some((server, db_only)) = base_parts() else {
                eprintln!("skipping: TEST_DATABASE_URL not set");
                return;
            };
            let base = format!("{server}/{db_only}");
            let prefix_probe = probe_name("ledger_prefix");
            let admin = PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(10))
                .connect(&format!("{server}/postgres"))
                .await
                .expect("connect admin");
            drop_quietly(&server, &prefix_probe).await;
            sqlx::query(&format!(r#"CREATE DATABASE "{prefix_probe}""#))
                .execute(&admin)
                .await
                .expect("create probe");
            let prefix_pool = test_role_pool(&server, &prefix_probe).await;
            subset_migrator(5)
                .await
                .run(&prefix_pool)
                .await
                .expect("apply prefix");
            let error = verify_clone_ledger(
                &prefix_pool,
                "clone-ledger",
                &prefix_probe,
                " (201 migrations expected)",
            )
            .await
            .expect_err("prefix ledger is incomplete");
            assert_eq!(error.stage(), "clone-ledger");
            assert!(
                error.to_string().contains("does not carry the complete"),
                "{error}"
            );
            prefix_pool.close().await;
            drop_quietly(&server, &prefix_probe).await;

            // Unreadable ledger: a closed pool cannot answer the probe.
            let probe = probe_name("ledger_ok");
            let pool = fresh_canonical_db(&base, &probe)
                .await
                .expect("provision")
                .expect("configured");
            verify_clone_ledger(&pool, "clone-ledger", &probe, "")
                .await
                .expect("complete ledger verifies");
            pool.close().await;
            let error = verify_clone_ledger(&pool, "clone-ledger", &probe, "")
                .await
                .expect_err("closed pool cannot be read");
            assert_eq!(error.stage(), "clone-ledger");
            drop_quietly(&server, &probe).await;
            admin.close().await;
        }

        // ── template build / rebuild ───────────────────────────────────────

        /// `ensure_template_locked` provisions a brand-new template (create +
        /// migrate + verify), rebuilds a template whose lineage is foreign,
        /// and classifies connect/create failures at named stages.
        #[tokio::test]
        async fn ensure_template_locked_builds_rebuilds_and_classifies_failures() {
            let _template_guard = template_clone_guard().await;
            let Some((server, db_only)) = base_parts() else {
                eprintln!("skipping: TEST_DATABASE_URL not set");
                return;
            };
            let _ = db_only;
            // Functional blocks run with the SAME role production uses (the
            // database owner must equal the role applying the chain); the
            // pg_database mutations need a superuser.
            let admin = PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(60))
                .connect(&format!("{server}/postgres"))
                .await
                .expect("connect admin");
            let super_admin = match admin_pool().await {
                Some(pool) => pool,
                None => {
                    eprintln!("skipping: TEST_DATABASE_ADMIN_URL not set");
                    admin.close().await;
                    return;
                }
            };

            // 1. Brand-new template: create + migrate + verify. Probes are
            // owned by the test role so the chain applies with the same
            // privileges production uses.
            let probe = probe_name("tpl");
            ensure_template_locked(&admin, &server, &probe)
                .await
                .expect("build template from scratch");
            let pool = test_role_pool(&server, &probe).await;
            let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
                .fetch_one(&pool)
                .await
                .expect("count");
            assert_eq!(rows as usize, crate::MIGRATIONS.migrations.len());
            pool.close().await;

            // 2. Foreign lineage on an existing template: rebuilt from
            // scratch, ending at the complete canonical chain.
            sqlx::query(&format!(r#"DROP DATABASE "{probe}""#))
                .execute(&admin)
                .await
                .expect("drop template");
            sqlx::query(&format!(r#"CREATE DATABASE "{probe}""#))
                .execute(&admin)
                .await
                .expect("create decoy");
            let decoy = test_role_pool(&server, &probe).await;
            sqlx::query("CREATE TABLE _sqlx_migrations \
                         (version BIGINT PRIMARY KEY, description TEXT NOT NULL, \
                          installed_on TIMESTAMPTZ NOT NULL DEFAULT NOW(), success BOOLEAN NOT NULL, \
                          checksum BYTEA NOT NULL, execution_time BIGINT NOT NULL DEFAULT 0)")
                .execute(&decoy)
                .await
                .expect("decoy ledger");
            sqlx::query(
                "INSERT INTO _sqlx_migrations (version, description, success, checksum) \
                         VALUES (1, 'foreign tree', true, '\\xdead'::bytea)",
            )
            .execute(&decoy)
            .await
            .expect("foreign row");
            decoy.close().await;
            ensure_template_locked(&admin, &server, &probe)
                .await
                .expect("rebuild foreign template");
            let pool = test_role_pool(&server, &probe).await;
            let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
                .fetch_one(&pool)
                .await
                .expect("count");
            assert_eq!(rows as usize, crate::MIGRATIONS.migrations.len());
            pool.close().await;
            drop_quietly(&server, &probe).await;

            // 3. Existing-but-unconnectable template: connect failure is
            // reported at the template-connect stage.
            let unconnectable = probe_name("tpl_noconn");
            sqlx::query(&format!(r#"DROP DATABASE IF EXISTS "{unconnectable}""#))
                .execute(&super_admin)
                .await
                .expect("drop leftover probe");
            sqlx::query(&format!(r#"CREATE DATABASE "{unconnectable}""#))
                .execute(&super_admin)
                .await
                .expect("create probe");
            sqlx::query(&format!(
                "UPDATE pg_database SET datallowconn = false WHERE datname = '{unconnectable}'"
            ))
            .execute(&super_admin)
            .await
            .expect("deny connections");
            let error = ensure_template_locked(&admin, &server, &unconnectable)
                .await
                .expect_err("connect must fail");
            assert_eq!(error.stage(), "template-connect");
            sqlx::query(&format!(
                "UPDATE pg_database SET datallowconn = true WHERE datname = '{unconnectable}'"
            ))
            .execute(&super_admin)
            .await
            .expect("allow connections again");
            drop_quietly(&server, &unconnectable).await;

            // 4. Unacceptable database name: an embedded double quote passes
            // the parameterized exists-check but cannot appear inside the
            // quoted identifier of CREATE DATABASE, which fails at the
            // template-create stage.
            let reserved = format!("bad\"quote{}", counter());
            let error = ensure_template_locked(&admin, &server, &reserved)
                .await
                .expect_err("CREATE DATABASE must reject the embedded quote");
            assert_eq!(error.stage(), "template-create");

            // 5. Dead admin connection: the exists-check fails at its own
            // named stage.
            let dead = PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(10))
                .connect(&format!("{server}/postgres"))
                .await
                .expect("connect admin");
            dead.close().await;
            let error = ensure_template_locked(&dead, &server, &probe_name("tpl_dead"))
                .await
                .expect_err("dead admin");
            assert_eq!(error.stage(), "template-exists-check");

            // 6. A canonical strict-prefix template that cannot be completed:
            // the lineage is fine, but a database pinned read-only cannot
            // accept the remaining migrations.
            let migrating_fail = probe_name("tpl_migrate_fail");
            drop_quietly(&server, &migrating_fail).await;
            sqlx::query(&format!(r#"CREATE DATABASE "{migrating_fail}""#))
                .execute(&admin)
                .await
                .expect("create probe");
            let fail_pool = test_role_pool(&server, &migrating_fail).await;
            subset_migrator(3)
                .await
                .run(&fail_pool)
                .await
                .expect("apply canonical prefix");
            fail_pool.close().await;
            sqlx::query(&format!(
                "ALTER DATABASE \"{migrating_fail}\" SET default_transaction_read_only = true"
            ))
            .execute(&admin)
            .await
            .expect("pin probe read-only");
            let error = ensure_template_locked(&admin, &server, &migrating_fail)
                .await
                .expect_err("read-only template cannot be topped up");
            assert_eq!(error.stage(), "template-migrate", "{}", error);
            sqlx::query(&format!(
                "ALTER DATABASE \"{migrating_fail}\" RESET default_transaction_read_only"
            ))
            .execute(&admin)
            .await
            .expect("reset read-only");
            drop_quietly(&server, &migrating_fail).await;
            admin.close().await;
            super_admin.close().await;
        }

        /// A template that carries a canonical strict prefix is topped up in
        /// place (no rebuild): the lineage stays, only missing migrations are
        /// applied.
        #[tokio::test]
        async fn ensure_template_locked_tops_up_strict_prefix_in_place() {
            let _template_guard = template_clone_guard().await;
            let Some((server, _db_only)) = base_parts() else {
                eprintln!("skipping: TEST_DATABASE_URL not set");
                return;
            };
            let probe = probe_name("tpl_topup");
            let admin = PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(30))
                .connect(&format!("{server}/postgres"))
                .await
                .expect("connect admin");
            drop_quietly(&server, &probe).await;
            sqlx::query(&format!(r#"CREATE DATABASE "{probe}""#))
                .execute(&admin)
                .await
                .expect("create probe");
            let pool = test_role_pool(&server, &probe).await;
            subset_migrator(5)
                .await
                .run(&pool)
                .await
                .expect("apply prefix");
            let prefix_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
                .fetch_one(&pool)
                .await
                .expect("count prefix");
            pool.close().await;
            ensure_template_locked(&admin, &server, &probe)
                .await
                .expect("top up in place");
            let pool = test_role_pool(&server, &probe).await;
            let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
                .fetch_one(&pool)
                .await
                .expect("count");
            assert_eq!(rows as usize, crate::MIGRATIONS.migrations.len());
            assert!(prefix_rows < rows, "the top-up added migrations");
            // The template identity is unrelated to the canonical template
            // name, so leave nothing behind.
            pool.close().await;
            drop_quietly(&server, &probe).await;
            admin.close().await;
        }

        /// A `(server, db)` pair re-pointed at a different role: the base
        /// URL's userinfo is replaced, keeping host/port/query intact. Used
        /// to prove privilege-dependent failure paths with dedicated probe
        /// roles instead of touching shared role settings.
        fn url_as_role(server_part: &str, db: &str, role: &str) -> String {
            let (scheme, rest) = server_part.split_once("://").expect("scheme");
            let authority = rest.rsplit_once('@').map_or(rest, |(_, after)| after);
            format!("{scheme}://{role}@{authority}/{db}")
        }

        // ── drop_database retries ──────────────────────────────────────────

        /// A plain drop blocked by THIS role's own sessions terminates them
        /// and retries to success.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn drop_database_terminates_own_sessions_and_retries() {
            let _template_guard = template_clone_guard().await;
            let Some((server, _db_only)) = base_parts() else {
                eprintln!("skipping: TEST_DATABASE_URL not set");
                return;
            };
            let probe = probe_name("drop_own");
            let admin = PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(10))
                .connect(&format!("{server}/postgres"))
                .await
                .expect("connect admin");
            drop_quietly(&server, &probe).await;
            sqlx::query(&format!(r#"CREATE DATABASE "{probe}""#))
                .execute(&admin)
                .await
                .expect("create probe");
            admin.close().await;
            // Hold a live session on the probe database with the SAME role.
            let blocker = test_role_pool(&server, &probe).await;
            sqlx::query("SELECT 1")
                .fetch_one(&blocker)
                .await
                .expect("open session");
            let dropper = PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(10))
                .connect(&format!("{server}/postgres"))
                .await
                .expect("connect dropper");
            drop_database(&dropper, &probe)
                .await
                .expect("own sessions are terminated and the drop retried");
            dropper.close().await;
            blocker.close().await;
        }

        /// When plain drops keep failing because ANOTHER role holds the
        /// database, a superuser admin still succeeds through FORCE.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn drop_database_falls_back_to_force_for_superusers() {
            let _template_guard = template_clone_guard().await;
            let Some((server, db_only)) = base_parts() else {
                eprintln!("skipping: TEST_DATABASE_URL not set");
                return;
            };
            let _ = db_only;
            let Some(admin) = admin_pool().await else {
                eprintln!("skipping: TEST_DATABASE_ADMIN_URL not set");
                return;
            };
            let superuser: bool =
                sqlx::query_scalar("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
                    .fetch_one(&admin)
                    .await
                    .expect("check superuser");
            if !superuser {
                eprintln!("skipping: TEST_DATABASE_ADMIN_URL role is not a superuser");
                admin.close().await;
                return;
            }
            let probe = probe_name("drop_force");
            let role = format!("migrator_blocker_{:04}", counter());
            sqlx::query(&format!(r#"CREATE ROLE "{role}" LOGIN"#))
                .execute(&admin)
                .await
                .expect("create blocker role");
            drop_quietly(&server, &probe).await;
            sqlx::query(&format!(r#"CREATE DATABASE "{probe}" OWNER "{role}""#))
                .execute(&admin)
                .await
                .expect("create probe");
            // Hold a session owned by the blocker ROLE: the plain drop's
            // terminate (restricted to current_user's sessions) cannot clear
            // it, so the five retries exhaust and FORCE runs.
            let blocker = PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(10))
                .connect(&url_as_role(&server, &probe, &role))
                .await
                .expect("connect blocker role");
            sqlx::query("SELECT 1")
                .fetch_one(&blocker)
                .await
                .expect("open session");
            drop_database(&admin, &probe)
                .await
                .expect("FORCE drop succeeds for a privileged role");
            blocker.close().await;
            sqlx::query(&format!(r#"DROP ROLE IF EXISTS "{role}""#))
                .execute(&admin)
                .await
                .expect("drop blocker role");
            admin.close().await;
        }

        /// An unprivileged role cannot FORCE-drop a database another role is
        /// using: the error names the drop-database stage and the fix.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn drop_database_reports_force_failure_for_unprivileged_role() {
            let _template_guard = template_clone_guard().await;
            let Some((server, db_only)) = base_parts() else {
                eprintln!("skipping: TEST_DATABASE_URL not set");
                return;
            };
            let _ = db_only;
            let Some(admin) = admin_pool().await else {
                eprintln!("skipping: TEST_DATABASE_ADMIN_URL not set");
                return;
            };
            let role = format!("migrator_probe_role_{:04}", counter());
            let probe = probe_name("drop_noforce");
            sqlx::query(&format!(r#"CREATE ROLE "{role}" LOGIN"#))
                .execute(&admin)
                .await
                .expect("create role");
            drop_quietly(&server, &probe).await;
            sqlx::query(&format!(r#"CREATE DATABASE "{probe}" OWNER "{role}""#))
                .execute(&admin)
                .await
                .expect("create probe");
            // Blocker session owned by the ADMIN role (not the dropping
            // role), so neither terminate nor FORCE can clear it.
            let blocker = PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(10))
                .connect(&format!("{server}/{probe}"))
                .await
                .expect("connect blocker as admin role");
            sqlx::query("SELECT 1")
                .fetch_one(&blocker)
                .await
                .expect("open session");
            let dropper = PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(10))
                .connect(&url_as_role(&server, "postgres", &role))
                .await
                .expect("connect dropper role");
            let error = drop_database(&dropper, &probe)
                .await
                .expect_err("unprivileged FORCE must fail");
            assert_eq!(error.stage(), "drop-database");
            assert!(
                error.to_string().contains("pg_signal_backend"),
                "the error must name the fix: {error}"
            );
            dropper.close().await;
            blocker.close().await;
            sqlx::query(&format!(r#"DROP DATABASE IF EXISTS "{probe}""#))
                .execute(&admin)
                .await
                .expect("drop probe");
            sqlx::query(&format!(r#"DROP ROLE IF EXISTS "{role}""#))
                .execute(&admin)
                .await
                .expect("drop role");
            admin.close().await;
        }

        // ── clone paths ────────────────────────────────────────────────────

        /// The clone retry absorbs a template being topped up concurrently
        /// ("source database is being accessed by other users") and converges
        /// once the window closes.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn clone_retries_while_template_is_busy() {
            let _template_guard = template_clone_guard().await;
            let _guard = SERIAL.lock().await;
            let Some((server, db_only)) = base_parts() else {
                eprintln!("skipping: TEST_DATABASE_URL not set");
                return;
            };
            let base = format!("{server}/{db_only}");
            let probe = probe_name("clone_busy");
            // Make sure the template exists and is ready first.
            let seed = fresh_canonical_db(&base, &probe_name("clone_busy_seed"))
                .await
                .expect("seed provisioning")
                .expect("configured");
            seed.close().await;
            // Hold a session on the template so CREATE DATABASE ... TEMPLATE
            // fails with the busy error, and release it shortly after.
            let template = canonical_template_db().to_string();
            let holder = test_role_pool(&server, &template).await;
            let release = holder.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(400)).await;
                release.close().await;
            });
            let result = fresh_canonical_db(&base, &probe).await;
            match result {
                Ok(Some(pool)) => {
                    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
                        .fetch_one(&pool)
                        .await
                        .expect("count");
                    assert_eq!(rows as usize, crate::MIGRATIONS.migrations.len());
                    pool.close().await;
                }
                Ok(None) => panic!("configured server must provision"),
                Err(error) => panic!("clone retry must absorb the busy window: {error}"),
            }
            holder.close().await;
            drop_quietly(&server, &probe).await;
            drop_quietly(&server, &probe_name("clone_busy_seed")).await;
        }

        /// A non-busy clone failure that persists across the whole retry
        /// window (the template stays busy) fails closed at the clone stage.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn clone_failure_after_the_full_retry_window_is_reported() {
            let _template_guard = template_clone_guard().await;
            let Some((server, db_only)) = base_parts() else {
                eprintln!("skipping: TEST_DATABASE_URL not set");
                return;
            };
            let _guard = SERIAL.lock().await;
            let template = canonical_template_db().to_string();
            let probe = probe_name("clone_stuck");
            // Ensure the template exists, then hold it for the whole window.
            let seed = fresh_canonical_db(
                &format!("{server}/{db_only}"),
                &probe_name("clone_stuck_seed"),
            )
            .await
            .expect("seed provisioning")
            .expect("configured");
            seed.close().await;
            let holder = test_role_pool(&server, &template).await;
            let pinned = holder.acquire().await.expect("pin template session");
            let error = fresh_canonical_db(&format!("{server}/{db_only}"), &probe)
                .await
                .expect_err("a permanently busy template cannot be cloned");
            drop(pinned);
            assert_eq!(error.stage(), "clone");
            assert!(
                error.to_string().contains("accessed by other users"),
                "{error}"
            );
            holder.close().await;
            drop_quietly(&server, &probe).await;
            drop_quietly(&server, &probe_name("clone_stuck_seed")).await;
        }

        /// fresh_canonical_db maps admin-connect failures at their stage.
        #[tokio::test]
        async fn fresh_canonical_db_reports_admin_connect_failure() {
            let _template_guard = template_clone_guard().await;
            let error = fresh_canonical_db("postgresql://127.0.0.1:1/nowhere", "unused")
                .await
                .expect_err("port 1 must refuse connections");
            assert_eq!(error.stage(), "admin-connect");
        }

        /// The vanished-clone recreate loop: connect to a name that does not
        /// exist re-creates it from the template and converges; a name that
        /// cannot be recreated fails closed at clone-connect.
        #[tokio::test]
        async fn connect_clone_with_recreate_converges_and_fails_closed() {
            let _template_guard = template_clone_guard().await;
            let Some((server, _db_only)) = base_parts() else {
                eprintln!("skipping: TEST_DATABASE_URL not set");
                return;
            };
            let template = canonical_template_db().to_string();
            let admin = PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(10))
                .connect(&format!("{server}/postgres"))
                .await
                .expect("connect admin");

            // The clone "vanished" (never created): the loop recreates it.
            let probe = probe_name("recreate");
            drop_quietly(&server, &probe).await;
            let pool = connect_clone_with_recreate(&admin, &server, &probe, &template)
                .await
                .expect("recreate + connect");
            let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
                .fetch_one(&pool)
                .await
                .expect("count");
            assert_eq!(rows as usize, crate::MIGRATIONS.migrations.len());
            pool.close().await;
            drop_quietly(&server, &probe).await;

            // A template that does not exist: recreate keeps failing and the
            // loop fails closed at clone-connect after the bounded retries.
            let error = connect_clone_with_recreate(
                &admin,
                &server,
                &probe_name("recreate_broken"),
                "apexmail_no_such_template_zz",
            )
            .await
            .expect_err("recreate from a missing template cannot succeed");
            assert_eq!(error.stage(), "clone-connect");
            assert!(error.to_string().contains("does not exist"), "{error}");
            admin.close().await;
        }

        /// connect_provisioned_db maps failures to the caller's stage name.
        #[tokio::test]
        async fn connect_provisioned_db_maps_failures_to_stage() {
            let _template_guard = template_clone_guard().await;
            let error =
                connect_provisioned_db("postgresql://127.0.0.1:1", "nowhere", "shared-connect")
                    .await
                    .expect_err("port 1 must refuse connections");
            assert_eq!(error.stage(), "shared-connect");
        }

        // ── fresh_canonical_db_direct ──────────────────────────────────────

        /// Direct provisioning: blank is unconfigured, malformed URL is a
        /// configured failure, an unreachable server fails at admin-connect,
        /// a colliding name fails at create-database, and the happy path
        /// applies the complete chain.
        #[tokio::test]
        async fn direct_provisioning_paths() {
            let _template_guard = template_clone_guard().await;
            assert!(fresh_canonical_db_direct("", "unused")
                .await
                .unwrap()
                .is_none());
            let error = fresh_canonical_db_direct("not-a-url", "unused")
                .await
                .expect_err("malformed URL");
            assert_eq!(error.stage(), "url-parse");
            let error = fresh_canonical_db_direct("postgresql://127.0.0.1:1/base", "unused")
                .await
                .expect_err("unreachable server");
            assert_eq!(error.stage(), "admin-connect");

            let Some((server, db_only)) = base_parts() else {
                eprintln!("skipping: TEST_DATABASE_URL not set");
                return;
            };
            let admin = PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(30))
                .connect(&format!("{server}/postgres"))
                .await
                .expect("connect admin");
            // A name that already exists collides at CREATE DATABASE: the
            // create-database stage surfaces.
            let colliding = probe_name("direct_collide");
            drop_quietly(&server, &colliding).await;
            sqlx::query(&format!(r#"CREATE DATABASE "{colliding}""#))
                .execute(&admin)
                .await
                .expect("create colliding db");
            let error = create_database(&admin, &colliding, "create-database", "create ")
                .await
                .expect_err("an existing name cannot be created");
            assert_eq!(error.stage(), "create-database");
            assert!(error.to_string().contains("already exists"), "{error}");
            sqlx::query(&format!(r#"DROP DATABASE IF EXISTS "{colliding}""#))
                .execute(&admin)
                .await
                .expect("drop colliding db");
            admin.close().await;

            let probe = probe_name("direct");
            let pool = fresh_canonical_db_direct(&format!("{server}/{db_only}"), &probe)
                .await
                .expect("provision")
                .expect("configured");
            let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
                .fetch_one(&pool)
                .await
                .expect("count");
            assert_eq!(rows as usize, crate::MIGRATIONS.migrations.len());
            pool.close().await;
            drop_quietly(&server, &probe).await;
        }

        /// A database pinned read-only cannot have the chain applied: the
        /// failure is reported at the direct-migrate stage.
        #[tokio::test]
        async fn direct_provisioning_reports_migration_failure() {
            let _template_guard = template_clone_guard().await;
            let Some((server, _db_only)) = base_parts() else {
                eprintln!("skipping: TEST_DATABASE_URL not set");
                return;
            };
            let Some(admin) = admin_pool().await else {
                eprintln!("skipping: TEST_DATABASE_ADMIN_URL not set");
                return;
            };
            let probe = probe_name("direct_ro");
            drop_quietly(&server, &probe).await;
            let owner = test_role(&server);
            sqlx::query(&format!(r#"CREATE DATABASE "{probe}" OWNER "{owner}""#))
                .execute(&admin)
                .await
                .expect("create probe");
            sqlx::query(&format!(
                "ALTER DATABASE \"{probe}\" SET default_transaction_read_only = true"
            ))
            .execute(&admin)
            .await
            .expect("pin probe read-only");
            // A fresh connection to the probe inherits the read-only setting:
            // reads work, the chain cannot be applied.
            let pool = test_role_pool(&server, &probe).await;
            sqlx::query("SELECT 1")
                .fetch_one(&pool)
                .await
                .expect("read");
            let error = migrate_provisioned_database(&pool, &probe)
                .await
                .expect_err("read-only database cannot be migrated");
            assert_eq!(error.stage(), "direct-migrate");
            pool.close().await;
            sqlx::query(&format!(
                "ALTER DATABASE \"{probe}\" RESET default_transaction_read_only"
            ))
            .execute(&admin)
            .await
            .expect("reset read-only");
            drop_quietly(&server, &probe).await;
            admin.close().await;
        }

        // ── shared_canonical_db ────────────────────────────────────────────

        /// Shared provisioning: create-if-absent, reuse-if-healthy,
        /// replace-if-foreign, and the mapped failure stages.
        #[tokio::test]
        async fn shared_canonical_db_lifecycle_and_failure_stages() {
            let _template_guard = template_clone_guard().await;
            let _guard = SERIAL.lock().await;
            assert!(shared_canonical_db("", "unused").await.unwrap().is_none());
            let error = shared_canonical_db("not-a-url", "unused")
                .await
                .expect_err("malformed URL");
            assert_eq!(error.stage(), "url-parse");
            let error = shared_canonical_db("postgresql://127.0.0.1:1/base", "unused")
                .await
                .expect_err("unreachable server");
            assert_eq!(error.stage(), "admin-connect");

            let Some((server, db_only)) = base_parts() else {
                eprintln!("skipping: TEST_DATABASE_URL not set");
                return;
            };
            let base = format!("{server}/{db_only}");
            let probe = probe_name("shared");

            // Create-if-absent.
            let pool = shared_canonical_db(&base, &probe)
                .await
                .expect("provision")
                .expect("configured");
            let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
                .fetch_one(&pool)
                .await
                .expect("count");
            assert_eq!(rows as usize, crate::MIGRATIONS.migrations.len());
            pool.close().await;

            // Reuse-if-healthy: the second call returns the SAME database
            // (identity proven by a marker row that survives).
            let pool = shared_canonical_db(&base, &probe)
                .await
                .expect("re-provision")
                .expect("configured");
            sqlx::query("SELECT 1").execute(&pool).await.expect("alive");
            pool.close().await;

            // Replace-if-foreign: a partial ledger under the shared name is
            // dropped and re-cloned from the template. The pg_database
            // mutation below needs a superuser.
            let Some(admin) = admin_pool().await else {
                eprintln!("skipping rest: TEST_DATABASE_ADMIN_URL not set");
                drop_quietly(&server, &probe).await;
                return;
            };
            let owner = test_role(&server);
            sqlx::query(&format!(r#"DROP DATABASE "{probe}""#))
                .execute(&admin)
                .await
                .expect("drop shared probe");
            sqlx::query(&format!(r#"CREATE DATABASE "{probe}" OWNER "{owner}""#))
                .execute(&admin)
                .await
                .expect("create decoy");
            let decoy = test_role_pool(&server, &probe).await;
            subset_migrator(3)
                .await
                .run(&decoy)
                .await
                .expect("apply tiny prefix");
            decoy.close().await;
            let pool = shared_canonical_db(&base, &probe)
                .await
                .expect("replace foreign shared database")
                .expect("configured");
            let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
                .fetch_one(&pool)
                .await
                .expect("count");
            assert_eq!(rows as usize, crate::MIGRATIONS.migrations.len());
            pool.close().await;

            // A shared database that exists but cannot be connected to is
            // treated as unhealthy and replaced under the same lock.
            sqlx::query(&format!(r#"DROP DATABASE "{probe}""#))
                .execute(&admin)
                .await
                .expect("drop probe");
            sqlx::query(&format!(r#"CREATE DATABASE "{probe}" OWNER "{owner}""#))
                .execute(&admin)
                .await
                .expect("create unconnectable decoy");
            sqlx::query(&format!(
                "UPDATE pg_database SET datallowconn = false WHERE datname = '{probe}'"
            ))
            .execute(&admin)
            .await
            .expect("deny connections");
            let pool = shared_canonical_db(&base, &probe)
                .await
                .expect("replace unconnectable shared database")
                .expect("configured");
            sqlx::query("SELECT 1")
                .fetch_one(&pool)
                .await
                .expect("alive");
            pool.close().await;
            admin.close().await;
            drop_quietly(&server, &probe).await;
        }

        /// A clone blocked for the whole retry window fails closed at the
        /// shared-clone stage.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn shared_clone_failure_is_reported() {
            let _template_guard = template_clone_guard().await;
            let Some((server, db_only)) = base_parts() else {
                eprintln!("skipping: TEST_DATABASE_URL not set");
                return;
            };
            let _guard = SERIAL.lock().await;
            let template = canonical_template_db().to_string();
            let probe = probe_name("shared_busy");
            // Ensure the template exists, then hold it for the whole window.
            let seed = fresh_canonical_db(&format!("{server}/{db_only}"), &probe_name("sh_seed"))
                .await
                .expect("seed")
                .expect("configured");
            seed.close().await;
            let holder = test_role_pool(&server, &template).await;
            // Pin the session: an idle pool connection can be closed by the
            // server during the long retry window, which would let the
            // clone succeed and invert the test's verdict.
            let pinned = holder.acquire().await.expect("pin template session");
            let error = shared_canonical_db(&format!("{server}/{db_only}"), &probe)
                .await
                .expect_err("busy template cannot be cloned");
            drop(pinned);
            assert_eq!(error.stage(), "shared-clone");
            holder.close().await;
            drop_quietly(&server, &probe).await;
            drop_quietly(&server, &probe_name("sh_seed")).await;
        }

        // ── migration 229: marker / quarantine / FK behaviour ──────────────

        /// Migration 229 quarantines non-UUID `user_id` values into
        /// `schema_quarantine` (preserving table, PK and raw value), converts
        /// the columns to UUID, leaves orphaned-but-valid UUIDs in place with
        /// NOT VALID foreign keys (validation skipped with a WARNING), and is
        /// idempotent on re-run.
        ///
        /// A full UUID never fit the VARCHAR(26) columns, so the orphan arm
        /// is reachable only on a deployment whose columns were widened
        /// mid-upgrade — the probe reproduces exactly that shape.
        #[tokio::test]
        async fn migration_229_quarantines_legacy_user_ids_and_skips_orphans() {
            let _template_guard = template_clone_guard().await;
            let Some((server, _db_only)) = base_parts() else {
                eprintln!("skipping: TEST_DATABASE_URL not set");
                return;
            };
            let probe = probe_name("m229");
            let admin = PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(30))
                .connect(&format!("{server}/postgres"))
                .await
                .expect("connect admin");
            drop_quietly(&server, &probe).await;
            sqlx::query(&format!(r#"CREATE DATABASE "{probe}""#))
                .execute(&admin)
                .await
                .expect("create probe");
            admin.close().await;
            let pool = test_role_pool(&server, &probe).await;
            // The chain up to (but excluding) 229: the three columns are
            // still VARCHAR(26).
            subset_migrator(228)
                .await
                .run(&pool)
                .await
                .expect("apply chain up to 228");
            // Widen the columns the way a mid-upgrade deployment would have,
            // so a valid UUID (36 chars) can be present alongside legacy ids.
            for table in ["sessions", "client_errors", "user_tenant_membership"] {
                sqlx::query(&format!(
                    "ALTER TABLE {table} ALTER COLUMN user_id TYPE TEXT"
                ))
                .execute(&pool)
                .await
                .expect("widen user_id");
            }

            let legacy = "legacy-user-id-0123456789"; // 22 chars, not a UUID
            let orphan_uuid = "deadbeef-dead-beef-dead-beefdeadbeef"; // valid UUID, no users row
            sqlx::query(
                "INSERT INTO sessions (id, user_id, tenant_id, expires_at) \
                 VALUES ('sess-legacy', $1, 'tenant-1', NOW() + INTERVAL '1 day'), \
                        ('sess-orphan', $2, 'tenant-1', NOW() + INTERVAL '1 day')",
            )
            .bind(legacy)
            .bind(orphan_uuid)
            .execute(&pool)
            .await
            .expect("insert sessions");
            sqlx::query(
                "INSERT INTO client_errors (tenant_id, user_id, error_message) \
                 VALUES ('tenant-1', $1, 'legacy report'), \
                        ('tenant-1', NULL, 'anonymous report')",
            )
            .bind(legacy)
            .execute(&pool)
            .await
            .expect("insert client_errors");
            sqlx::query(
                "INSERT INTO user_tenant_membership (user_id, tenant_id, role) \
                 VALUES ($1, 'tenant-1', 'member'), ($2, 'tenant-1', 'member')",
            )
            .bind(legacy)
            .bind(orphan_uuid)
            .execute(&pool)
            .await
            .expect("insert membership");

            // Apply the remaining canonical migrations (229).
            apply_canonical_migrations(&pool)
                .await
                .expect("apply through 229");

            // Legacy values were quarantined, preserving source and raw value.
            let quarantined: Vec<(String, String, Option<String>, String)> = sqlx::query_as(
                "SELECT source_table, user_id_raw, source_pk, migration \
                 FROM schema_quarantine ORDER BY source_table",
            )
            .fetch_all(&pool)
            .await
            .expect("read quarantine");
            assert_eq!(quarantined.len(), 3, "{quarantined:?}");
            for (table, raw, _pk, migration) in &quarantined {
                assert_eq!(migration, "229");
                assert_eq!(raw, legacy, "raw value preserved for {table}");
            }
            let tables: Vec<String> = quarantined
                .iter()
                .map(|(table, _, _, _)| table.clone())
                .collect();
            assert!(tables.contains(&"sessions".to_string()));
            assert!(tables.contains(&"client_errors".to_string()));
            assert!(tables.contains(&"user_tenant_membership".to_string()));
            assert!(quarantined.iter().any(
                |(table, _, pk, _)| table == "sessions" && pk.as_deref() == Some("sess-legacy")
            ));

            // Legacy rows left the live tables; the valid-UUID orphan stayed.
            let sessions: i64 =
                sqlx::query_scalar("SELECT count(*) FROM sessions WHERE id = 'sess-legacy'")
                    .fetch_one(&pool)
                    .await
                    .expect("count");
            assert_eq!(sessions, 0, "legacy session deleted after quarantine");
            let orphan_session: Option<String> =
                sqlx::query_scalar("SELECT user_id::text FROM sessions WHERE id = 'sess-orphan'")
                    .fetch_optional(&pool)
                    .await
                    .expect("orphan session");
            assert_eq!(
                orphan_session.map(|id| id.to_string()),
                Some(orphan_uuid.to_string()),
                "valid-UUID session survived (kept as an FK orphan)"
            );
            let nulled: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM client_errors \
                 WHERE error_message = 'legacy report' AND user_id IS NULL",
            )
            .fetch_one(&pool)
            .await
            .expect("count");
            assert_eq!(nulled, 1, "legacy client_errors user_id was NULLed");
            let legacy_membership: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM user_tenant_membership WHERE user_id::text = $1",
            )
            .bind(legacy)
            .fetch_one(&pool)
            .await
            .expect("count");
            assert_eq!(legacy_membership, 0, "legacy membership deleted");

            // Columns are UUID now.
            for table in ["sessions", "client_errors", "user_tenant_membership"] {
                let data_type: String = sqlx::query_scalar(
                    "SELECT data_type FROM information_schema.columns \
                     WHERE table_schema = 'public' AND table_name = $1 AND column_name = 'user_id'",
                )
                .bind(table)
                .fetch_one(&pool)
                .await
                .expect("column type");
                assert_eq!(data_type, "uuid", "{table}.user_id must be UUID");
            }

            // Orphaned sessions keep their FK NOT VALID (validation skipped
            // with a WARNING); client_errors has no orphan UUIDs, so its FK
            // validated.
            let not_valid: Vec<String> = sqlx::query_scalar(
                "SELECT conname FROM pg_constraint \
                 WHERE conrelid IN ('sessions'::regclass, 'user_tenant_membership'::regclass) \
                   AND conname LIKE 'fk_%' AND NOT convalidated",
            )
            .fetch_all(&pool)
            .await
            .expect("constraint state");
            assert!(
                not_valid.contains(&"fk_sessions_user".to_string()),
                "orphan sessions FK stays NOT VALID ({not_valid:?})"
            );
            assert!(
                not_valid.contains(&"fk_user_tenant_membership_user".to_string()),
                "orphan membership FK stays NOT VALID ({not_valid:?})"
            );
            let validated: bool = sqlx::query_scalar(
                "SELECT convalidated FROM pg_constraint WHERE conname = 'fk_client_errors_user'",
            )
            .fetch_one(&pool)
            .await
            .expect("client_errors FK");
            assert!(validated, "client_errors FK must have validated");

            // Idempotence: re-applying changes nothing.
            apply_canonical_migrations(&pool)
                .await
                .expect("re-apply is a no-op");
            let quarantined_after: i64 =
                sqlx::query_scalar("SELECT count(*) FROM schema_quarantine")
                    .fetch_one(&pool)
                    .await
                    .expect("count");
            assert_eq!(quarantined_after, 3, "no additional quarantine on re-run");
            pool.close().await;
            drop_quietly(&server, &probe).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{fresh_canonical_db, fresh_canonical_pool};

    /// Serializes the tests that read or mutate TEST_DATABASE_URL: the env
    /// is process-global, and an unsynchronised `remove_var` in one test
    /// racing a `var` in another made the concurrent-initializer test below
    /// silently take its skip branch (observed as uncovered lines 962-980).
    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
        let _guard = ENV_LOCK.lock().await;
        // SAFETY-of-test: ENV_LOCK serializes every TEST_DATABASE_URL reader
        // in this binary; the value is restored before the guard is dropped.
        let saved = std::env::var("TEST_DATABASE_URL").ok();
        std::env::remove_var("TEST_DATABASE_URL");
        let result = fresh_canonical_pool("f01_unset_env", "unset").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        if let Some(value) = saved {
            std::env::set_var("TEST_DATABASE_URL", value);
        }
    }

    /// A set-but-malformed TEST_DATABASE_URL is a configured failure, not a
    /// silent skip (audit F01): the url-parse stage must surface.
    #[tokio::test]
    async fn malformed_test_database_url_is_an_error() {
        let _guard = ENV_LOCK.lock().await;
        let saved = std::env::var("TEST_DATABASE_URL").ok();
        std::env::set_var("TEST_DATABASE_URL", "not-a-url");
        let result = fresh_canonical_pool("f01_malformed_env", "malformed").await;
        let error = result.expect_err("malformed TEST_DATABASE_URL must be Err");
        assert_eq!(error.stage(), "url-parse");
        match saved {
            Some(value) => std::env::set_var("TEST_DATABASE_URL", value),
            None => std::env::remove_var("TEST_DATABASE_URL"),
        }
    }

    /// The finding's own verification case: run two concurrent initializers
    /// against a configured server and prove BOTH returned databases carry
    /// the complete pinned migration ledger (audit F01). Skips only when
    /// TEST_DATABASE_URL is absent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_initializers_both_return_complete_ledgers() {
        // Hold the env lock across the provisioning call: fresh_canonical_pool
        // reads TEST_DATABASE_URL, and the unset test above must not blank it
        // mid-flight (this race silently took the skip branch before).
        let _guard = ENV_LOCK.lock().await;
        let _template_guard = super::test_support::provision_tests::template_clone_guard().await;
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

// Migration chain re-embedded: 229 (user_id columns carry users.id).

// Migration chain re-embedded: 230 (relay send_unit request fingerprint).
