//! Deploy-gate binary tests: exercise the REAL `migrator` binary as a
//! subprocess — the exact code path `docker compose --profile migrate run`
//! executes — against private throwaway databases derived from the canonical
//! chain (never the shared base).
//!
//! The binary is reached through `CARGO_BIN_EXE_migrator`, so under
//! `cargo llvm-cov` its profile merges with the test profiles (the child
//! inherits `LLVM_PROFILE_FILE`), and under plain `cargo test` the same
//! assertions still run.

use std::process::Command;
use std::time::{Duration, Instant};

fn migrator_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_migrator"))
}

/// Pass the coverage profile destination through when running under
/// `cargo llvm-cov`, so the child binary's counters are merged; otherwise
/// point it at a scratch file so the repo is not polluted with .profraw.
fn profile_env(command: &mut Command) {
    let destination = std::env::var("LLVM_PROFILE_FILE").unwrap_or_else(|_| {
        std::env::temp_dir()
            .join(format!("migrator_bin_{}.profraw", std::process::id()))
            .to_string_lossy()
            .into_owned()
    });
    command.env("LLVM_PROFILE_FILE", destination);
}

fn run(command: &mut Command) -> (bool, String, String) {
    let output = command.output().expect("spawn migrator binary");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn base_url() -> Option<String> {
    let url = std::env::var("TEST_DATABASE_URL").ok()?;
    let (server, db) = url.rsplit_once('/')?;
    let db_only = db.split('?').next().unwrap_or(db);
    Some(format!("{server}/{db_only}"))
}

/// `--dry-run` lists the embedded chain and needs NO database.
#[test]
fn dry_run_lists_the_embedded_chain_without_a_database() {
    let mut command = migrator_bin();
    command.arg("--dry-run").env_remove("DATABASE_URL");
    profile_env(&mut command);
    let started = Instant::now();
    let (ok, stdout, stderr) = run(&mut command);
    assert!(
        ok,
        "dry-run must exit 0\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("embedded migrations:"),
        "listing header missing: {stdout}"
    );
    assert!(
        stdout.contains("sql)"),
        "per-migration lines missing: {stdout}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "dry-run must not wait on a database"
    );
}

/// `-n` is the short form of `--dry-run`.
#[test]
fn short_dry_run_flag_matches() {
    let mut command = migrator_bin();
    command.arg("-n").env_remove("DATABASE_URL");
    profile_env(&mut command);
    let (ok, stdout, stderr) = run(&mut command);
    assert!(ok, "-n must exit 0\nstderr: {stderr}");
    assert!(stdout.contains("embedded migrations:"), "{stdout}");
}

/// Without DATABASE_URL the binary refuses to run: the deploy gate must
/// abort, not guess a database.
#[test]
fn missing_database_url_is_a_hard_failure() {
    let mut command = migrator_bin();
    command.env_remove("DATABASE_URL");
    profile_env(&mut command);
    let (ok, _stdout, stderr) = run(&mut command);
    assert!(!ok, "missing DATABASE_URL must exit non-zero");
    assert!(
        stderr.contains("DATABASE_URL is not set"),
        "the operator error must name the variable: {stderr}"
    );
}

/// The apply path against a real throwaway database: first run applies the
/// whole chain (runway extended), the second run is an idempotent no-op.
#[tokio::test]
async fn apply_is_idempotent_on_a_throwaway_database() {
    let Some(base) = base_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };
    let suffix = format!(
        "bin_{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            % 0x100000000
    );
    let (server, db_only) = base.rsplit_once('/').unwrap();
    let db_name = format!("{db_only}_migrator_{suffix}");
    let pool = migrator::test_support::fresh_canonical_db(&base, &db_name)
        .await
        .expect("provision throwaway database")
        .expect("configured server");
    pool.close().await;

    let url = format!("{server}/{db_name}");
    let mut command = migrator_bin();
    command.env("DATABASE_URL", &url);
    profile_env(&mut command);
    let (ok, stdout, stderr) = run(&mut command);
    assert!(ok, "apply must succeed\nstdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("applied migrations after run"), "{stdout}");
    assert!(stdout.contains("partition runway extended"), "{stdout}");

    // Second run: up to date, no new migrations, still exit 0.
    let mut command = migrator_bin();
    command.env("DATABASE_URL", &url);
    profile_env(&mut command);
    let (ok, stdout, stderr) = run(&mut command);
    assert!(ok, "re-run must be a no-op success\nstderr: {stderr}");
    assert!(stdout.contains("(0 new)"), "no new migrations: {stdout}");
    assert!(stdout.contains("database is up to date"), "{stdout}");

    // Cleanup the throwaway database.
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&format!("{server}/postgres"))
        .await
        .expect("connect admin");
    let _ = sqlx::query(&format!(
        r#"DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)"#
    ))
    .execute(&admin)
    .await;
    admin.close().await;
}

/// An unreachable DATABASE_URL fails closed with the connect context.
#[test]
fn unreachable_database_fails_closed() {
    let mut command = migrator_bin();
    command.env("DATABASE_URL", "postgresql://127.0.0.1:9/nowhere");
    profile_env(&mut command);
    let (ok, _stdout, stderr) = run(&mut command);
    assert!(!ok, "unreachable database must exit non-zero");
    assert!(
        stderr.contains("failed to connect to DATABASE_URL"),
        "the error must carry the connect context: {stderr}"
    );
}
