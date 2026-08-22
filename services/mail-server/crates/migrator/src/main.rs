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
//! embedded at compile time from `services/mail-server/migrations`.
//!
//! The interactive fallback (`sqlx migrate run --source
//! services/mail-server/migrations`) remains documented in
//! `services/mail-server/migrations/README.md` and `deploy/DEPLOYMENT.md` for
//! operators with direct database access.
//!
//! Usage:
//!   migrator            apply all pending migrations (idempotent)
//!   migrator --dry-run  list the embedded migrations and exit (no DB needed
//!                       for listing; DATABASE_URL is only required to apply)
//!
//! Exit codes: 0 = applied/up-to-date, non-zero = migration failure (the
//! deploy gate aborts and `up` never runs).

use anyhow::{Context, Result};
use std::process::ExitCode;

/// Embed the canonical workspace migration set at compile time.
///
/// The path is resolved relative to this crate's manifest directory
/// (`services/mail-server/crates/migrator`) at BUILD time, so the binary
/// carries the migrations that match its own build — no runtime mounting of
/// SQL files, no drift between the image and the repo.
static MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("./../../migrations");

fn print_migrations() {
    println!("embedded migrations: {}", MIGRATIONS.migrations.len());
    for migration in MIGRATIONS.migrations.iter() {
        println!(
            "  {:>4} {} ({}sql)",
            migration.version,
            migration.description,
            if migration.sql.is_empty() { "no " } else { "" }
        );
    }
}

/// Number of migrations already recorded in `_sqlx_migrations` (0 when the
/// table does not exist yet, i.e. a fresh database before the first run).
///
/// `to_regclass(...)` returns a ROW with a NULL column (not zero rows) when
/// the relation does not exist, so the scalar must decode as `Option<String>`
/// — a plain `String` fails with "unexpected null" on a completely fresh
/// database (pipeline finding F2).
async fn applied_count(pool: &sqlx::PgPool) -> Result<i64> {
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

async fn apply_migrations(database_url: &str) -> Result<()> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .connect(database_url)
        .await
        .context("failed to connect to DATABASE_URL")?;

    let before = applied_count(&pool).await?;
    println!("applied migrations before run: {before}");

    // sqlx records applied versions in _sqlx_migrations; re-running against
    // an up-to-date database is a no-op that exits 0.
    MIGRATIONS
        .run(&pool)
        .await
        .context("failed to apply migrations")?;

    let after = applied_count(&pool).await?;
    println!("applied migrations after run: {after} ({} new)", after - before);
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

    let dry_run = std::env::args().any(|arg| arg == "--dry-run" || arg == "-n");

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

#[cfg(test)]
mod tests {
    use super::*;

    /// The `sqlx::migrate!` macro compiled and embedded the workspace
    /// migration directory. No live database is required for this test.
    #[test]
    fn migrations_are_embedded_and_ordered() {
        assert!(
            !MIGRATIONS.migrations.is_empty(),
            "sqlx::migrate! embedded an empty migration set"
        );
        let mut versions: Vec<i64> = MIGRATIONS
            .migrations
            .iter()
            .map(|m| m.version)
            .collect();
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

    /// The deploy gate relies on the migrator covering the full chain — in
    /// particular the 101-108 batch that previously ran in NO deploy path.
    /// Update the floor when the chain grows; this only guards against the
    /// macro silently pointing at the wrong (empty/partial) directory.
    #[test]
    fn migration_chain_is_complete() {
        let latest = MIGRATIONS
            .migrations
            .iter()
            .map(|m| m.version)
            .max()
            .expect("non-empty migration set");
        assert!(latest >= 108, "expected migrations up to >= 108, latest is {latest}");
    }

    /// DB-gated test: applies the full chain to `TEST_DATABASE_URL` when that
    /// variable is set (CI provides a scratch Postgres). Skipped otherwise so
    /// `cargo test -p migrator` never needs a live database.
    #[tokio::test]
    async fn applies_full_chain_to_test_database() {
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
        let applied = applied_count(&pool).await.expect("count applied");
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
        let count = applied_count(&pool).await.expect("applied_count on fresh DB");
        assert_eq!(count, 0, "fresh database must report 0 applied migrations");
        pool.close().await;
    }
}
