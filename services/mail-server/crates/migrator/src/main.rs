//! ApexMail database migrator — the deployment-time migration gate.
//!
//! Every production deploy path (`.github/workflows/deploy-hetzner.yml` and
//! `deploy/scripts/deploy.sh`) runs this binary as a one-shot compose job
//! BEFORE `docker compose up -d`:
//!
//! ```sh
//! docker compose -f docker-compose.yml -f docker-compose.prod.yml \
//!   --env-file .env --profile migrate run --rm migrator
//! ```
//!
//! It connects via `DATABASE_URL` (assembled from `DB_*` + the
//! `postgres_password` Docker secret by `deploy/scripts/entrypoint-wrapper.sh`,
//! same as every sibling service) and applies the workspace migration set
//! embedded at compile time from `services/mail-server/migrations` via the
//! library's [`migrator::apply_migrations`] — the same apply path the
//! `test_support` module exposes to test infrastructure (audit F01).
//!
//! The interactive fallback (`sqlx migrate run --source
//! services/mail-server/migrations`) remains documented in
//! `docs/deployment/migrations.md` and `deploy/DEPLOYMENT.md` for
//! operators with direct database access.
//!
//! Usage:
//!   migrator            apply all pending migrations (idempotent)
//!   migrator --dry-run  list the embedded migrations and exit (no DB needed
//!                       for listing; DATABASE_URL is only required to apply)
//!   migrator --gc-test-databases
//!                       drop the per-test `apexmail_*` database clones that
//!                       accumulate on long-lived hosts (see
//!                       `docs/deployment/migrations.md`); protect extra
//!                       names with MIGRATOR_GC_KEEP=name1,name2
//!
//! Exit codes: 0 = applied/up-to-date, non-zero = migration failure (the
//! deploy gate aborts and `up` never runs).

use anyhow::{Context, Result};
use std::process::ExitCode;

fn print_migrations() {
    println!(
        "embedded migrations: {}",
        migrator::MIGRATIONS.migrations.len()
    );
    for migration in migrator::MIGRATIONS.migrations.iter() {
        println!(
            "  {:>4} {} ({}sql)",
            migration.version,
            migration.description,
            if migration.sql.is_empty() { "no " } else { "" }
        );
    }
}

async fn apply_migrations(database_url: &str) -> Result<()> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .connect(database_url)
        .await
        .context("failed to connect to DATABASE_URL")?;

    migrator::apply_migrations(&pool).await?;

    pool.close().await;
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let dry_run = std::env::args().any(|arg| arg == "--dry-run" || arg == "-n"); // nosemgrep: rust.lang.security.args.args — reads argv for flag detection / passes constant tool-side paths — no shell, no user-input interpolation
    let gc_databases = std::env::args().any(|arg| arg == "--gc-test-databases"); // nosemgrep: rust.lang.security.args.args

    if dry_run {
        print_migrations();
        return ExitCode::SUCCESS;
    }

    let database_url = match std::env::var("DATABASE_URL") {
        Ok(url) if !url.is_empty() => url,
        _ => {
            eprintln!("error: DATABASE_URL is not set — the entrypoint wrapper assembles it from DB_* + the postgres_password secret");
            return ExitCode::FAILURE;
        }
    };

    if gc_databases {
        return match gc_test_databases(&database_url).await {
            Ok((dropped, failed)) => {
                println!(
                    "migrator: gc complete ({dropped} test database(s) dropped, {failed} left)"
                );
                if failed == 0 {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                }
            }
            Err(err) => {
                eprintln!("migrator: gc failed: {err:#}");
                ExitCode::FAILURE
            }
        };
    }

    match apply_migrations(&database_url).await {
        Ok(()) => {
            println!("migrator: database is up to date");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("migrator: {err:#}");
            ExitCode::FAILURE
        }
    }
}

/// Drop the per-test database clones the test harness accumulates.
///
/// Every DB-backed suite provisions `apexmail_*` clones from the canonical
/// template and, by design, leaves them behind (a one-shot CI runner throws
/// the whole Postgres away). On a long-lived dev/CI host the clones grow
/// without bound — the 2026-10-07 fold found 1,096 of them (55 GB) and the
/// resulting disk pressure was crashing Postgres mid-suite. This mode drops
/// `apexmail_%` databases other than the protected base name; databases with
/// live connections are terminated only after a `pg_terminate_backend`, and
/// every failure is reported rather than hidden.
///
/// Keep extra databases: `MIGRATOR_GC_KEEP=name1,name2` (the base `apexmail`
/// and the system databases are always protected).
async fn gc_test_databases(database_url: &str) -> anyhow::Result<(usize, usize)> {
    let (server_part, _) = database_url
        .rsplit_once('/')
        .context("DATABASE_URL has no database segment")?;
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .connect(&format!("{server_part}/postgres"))
        .await
        .context("connect to the maintenance database")?;

    let mut keep: Vec<String> = vec!["apexmail".into()];
    if let Ok(extra) = std::env::var("MIGRATOR_GC_KEEP") {
        keep.extend(
            extra
                .split(',')
                .map(|name| name.trim().to_string())
                .filter(|name| !name.is_empty()),
        );
    }

    let candidates: Vec<String> = sqlx::query_scalar(
        "SELECT datname FROM pg_database \
         WHERE datname LIKE 'apexmail\\_%' AND datname <> ALL($1)",
    )
    .bind(&keep)
    .fetch_all(&admin)
    .await
    .context("list test databases")?;

    let mut dropped = 0usize;
    let mut failed = 0usize;
    for name in &candidates {
        // Skip databases still in use by a running suite.
        let in_use: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname = $1)")
                .bind(name)
                .fetch_one(&admin)
                .await
                .unwrap_or(false);
        if in_use {
            println!("gc: skipping {name} (live connections)");
            failed += 1;
            continue;
        }
        match sqlx::query(&format!("DROP DATABASE IF EXISTS \"{name}\""))
            .execute(&admin)
            .await
        {
            Ok(_) => {
                dropped += 1;
            }
            Err(error) => {
                eprintln!("gc: could not drop {name}: {error}");
                failed += 1;
            }
        }
    }
    admin.close().await;
    Ok((dropped, failed))
}

#[cfg(test)]
mod tests {
    use migrator::MIGRATIONS;

    /// The `sqlx::migrate!` macro compiled and embedded the workspace
    /// migration directory. No live database is required for this test.
    #[test]
    fn migrations_are_embedded_and_ordered() {
        assert!(
            !MIGRATIONS.migrations.is_empty(),
            "sqlx::migrate! embedded an empty migration set"
        );
        let mut versions: Vec<i64> = MIGRATIONS.migrations.iter().map(|m| m.version).collect();
        let mut sorted = versions.clone();
        sorted.sort_unstable();
        assert_eq!(versions, sorted, "migration versions must be ascending");
        versions.dedup();
        assert_eq!(
            versions.len(),
            MIGRATIONS.migrations.len(),
            "migration versions must be unique"
        );
    }

    /// The deploy gate relies on the migrator covering the full chain from
    /// its head. sqlx applies every embedded file in version order, so an
    /// interior gap skips nothing — the 2026-09 remediation wave reserved
    /// per-stream number ranges and several slots are intentionally unused
    /// (129, 141–152, 154–158). What a mis-pointed macro or a misnamed file
    /// CAN produce, and what this catches: a chain whose head is missing
    /// (min ≠ 1 — a partial directory). A missing TAIL is not self-
    /// detectable (the embedded set cannot know the true latest); the
    /// ascending + uniqueness contract lives in the test above.
    #[test]
    fn migration_chain_head_is_intact() {
        let versions: Vec<i64> = MIGRATIONS.migrations.iter().map(|m| m.version).collect();
        let min = versions
            .iter()
            .copied()
            .min()
            .expect("non-empty migration set");
        assert_eq!(
            min, 1,
            "migration chain must start at version 1 (partial directory?)"
        );
    }

    /// DB-gated test: applies the full chain to `TEST_DATABASE_URL` when that
    /// variable is set (CI provides a scratch Postgres). Skipped otherwise so
    /// `cargo test -p migrator` never needs a live database.
    #[tokio::test]
    async fn applies_full_chain_to_test_database() {
        migrator::test_support::assert_soft_skip_allowed("TEST_DATABASE_URL");
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            eprintln!("skipping: TEST_DATABASE_URL not set");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .expect("connect TEST_DATABASE_URL");
        MIGRATIONS.run(&pool).await.expect("apply migrations");
        let applied = migrator::applied_count(&pool).await.expect("count applied");
        assert_eq!(applied as usize, MIGRATIONS.migrations.len());
        // Idempotency: a second run is a no-op that still succeeds.
        MIGRATIONS.run(&pool).await.expect("re-run migrations");
        pool.close().await;
    }

    /// DB-gated regression test for the fresh-database NULL decode (F2):
    /// `applied_count` runs BEFORE any migration has created
    /// `_sqlx_migrations`, so `to_regclass` returns a row with a NULL column.
    /// It must report 0 instead of failing to decode. Requires an EMPTY
    /// `TEST_FRESH_DATABASE_URL` (the pipeline points it at an ephemeral
    /// container); skipped when unset.
    #[tokio::test]
    async fn applied_count_on_a_completely_fresh_database_returns_zero() {
        migrator::test_support::assert_soft_skip_allowed("TEST_FRESH_DATABASE_URL");
        let Ok(url) = std::env::var("TEST_FRESH_DATABASE_URL") else {
            eprintln!("skipping: TEST_FRESH_DATABASE_URL not set");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .expect("connect TEST_FRESH_DATABASE_URL");
        // The database must be untouched: no ledger table yet.
        let exists: Option<Option<String>> =
            sqlx::query_scalar("SELECT to_regclass('public._sqlx_migrations')::text")
                .fetch_optional(&pool)
                .await
                .expect("probe _sqlx_migrations");
        assert!(
            exists.flatten().is_none(),
            "TEST_FRESH_DATABASE_URL must point at an empty database"
        );
        let count = migrator::applied_count(&pool)
            .await
            .expect("applied_count on fresh DB");
        assert_eq!(count, 0, "fresh database must report 0 applied migrations");
        pool.close().await;
    }
}
