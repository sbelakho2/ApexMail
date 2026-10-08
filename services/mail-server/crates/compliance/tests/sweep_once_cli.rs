//! E-SWEEP-TRIGGER (compliance sibling): the `--sweep-once` one-shot
//! entrypoint drives the REAL compliance-server binary against a private
//! canonical DB clone and asserts the printed report — the ops trigger end to
//! end (live dogfood 2026-10-08: the periodic ticks were the only DSR
//! trigger). The sweep semantics themselves are covered by the bin's tick
//! tests; here the ENTRYPOINT is the subject, the same pattern as the
//! billing-service `--sweep-overage-only` test.
//!
//! The queue-side counts (`recovered=`/`processed=`) are deliberately not
//! asserted exactly: the test Redis is shared across concurrent test
//! processes, so sibling tests can legitimately leave entries the sweep is
//! allowed to see. The DB-side counts are private to this clone and are
//! asserted as such (and the seeded row's flip proves the report is the
//! truth, not a printed constant).

use sqlx::PgPool;

fn test_database_url() -> Option<String> {
    migrator::test_support::assert_soft_skip_allowed("TEST_DATABASE_URL");
    std::env::var("TEST_DATABASE_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
}

fn report_value(stdout: &str, key: &str) -> u64 {
    let line = stdout
        .lines()
        .find(|line| line.starts_with("dsr sweep:"))
        .unwrap_or_else(|| panic!("no `dsr sweep:` report line on stdout:\n{stdout}"));
    let needle = format!("{key}=");
    let value = line
        .split_whitespace()
        .find_map(|part| part.strip_prefix(&needle))
        .unwrap_or_else(|| panic!("report line lacks `{key}=`:\n{line}"));
    value
        .parse::<u64>()
        .unwrap_or_else(|error| panic!("`{key}={value}` is not a count: {error}"))
}

#[tokio::test]
async fn sweep_once_cli_runs_the_canonical_dsr_sweep_on_demand() {
    let Some(url) = test_database_url() else {
        return;
    };
    let redis_url = std::env::var("TEST_REDIS_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .expect("TEST_REDIS_URL must be set for the sweep CLI test");
    let (server, db) = url.rsplit_once('/').expect("url has a database segment");
    let db_only = db.split('?').next().unwrap_or(db);
    let db_name = format!("{db_only}_sweep_once_cli");
    let pool: PgPool =
        match migrator::test_support::fresh_canonical_db(&format!("{server}/{db_only}"), &db_name)
            .await
        {
            Ok(Some(pool)) => pool,
            Ok(None) => return,
            Err(e) => panic!("{}", e.panic_message()),
        };

    // The per-test clone is REUSED across runs (fresh_canonical_db keeps an
    // existing clone), so clear this test's fixed-id fixtures first or a
    // re-run dies on the primary key.
    sqlx::query("DELETE FROM data_subject_requests WHERE id = 'REQ-cli-exp'")
        .execute(&pool)
        .await
        .expect("clear prior request fixture");
    sqlx::query("DELETE FROM double_opt_in_tokens WHERE tenant_id = 't-sweep-cli'")
        .execute(&pool)
        .await
        .expect("clear prior DOI fixture");

    // An unverified request past its verification window: the sweep expires it.
    sqlx::query(
        "INSERT INTO data_subject_requests
           (id, tenant_id, request_type, email, verification_token_hash, verified, status,
            requested_at, received_at, statutory_due_at, expires_at)
         VALUES ('REQ-cli-exp', 't-sweep-cli', 'erasure', 'cli@example.test', 'hash', false,
                 'pending_verification', NOW() - INTERVAL '40 days', NOW() - INTERVAL '40 days',
                 NOW() + INTERVAL '10 days', NOW() - INTERVAL '1 hour')",
    )
    .execute(&pool)
    .await
    .expect("seed expired-window request");
    sqlx::query(
        "INSERT INTO double_opt_in_tokens
           (tenant_id, subscriber_id, consent_type, email, token_hash, expires_at, created_at)
         VALUES ('t-sweep-cli', 'cli-gone', 'marketing', 'cli@example.test', 'h',
                 NOW() - INTERVAL '1 hour', NOW())",
    )
    .execute(&pool)
    .await
    .expect("seed stale DOI token");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_compliance-server"))
        .arg("--sweep-once")
        .env("DATABASE_URL", format!("{server}/{db_name}"))
        .env("REDIS_URL", &redis_url)
        .env("NODE_ENV", "development")
        .env("COMPLIANCE_AUTH_TOKEN", "sweep-once-cli-token")
        .env("SECRETS_KDF_SALT", "sweep-once-kdf-salt-0123456789")
        .env("SECRETS_ENCRYPTION_KEY", "sweep-once-master-key-0123456789")
        .env("RUST_LOG", "error")
        .output()
        .expect("spawn compliance-server --sweep-once");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "the one-shot sweep must exit 0\nstdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("dsr sweep:"),
        "the on-demand report line must be printed:\n{stdout}"
    );
    assert!(
        report_value(&stdout, "expired_requests") >= 1,
        "the seeded overdue window must be expired on demand:\n{stdout}"
    );
    assert!(
        report_value(&stdout, "expired_tokens") >= 1,
        "the seeded stale DOI token must be deleted on demand:\n{stdout}"
    );
    assert_eq!(
        report_value(&stdout, "failed_steps"),
        0,
        "no sweep step may fail:\n{stdout}"
    );

    // The report is the truth: the seeded row really flipped.
    let status: String =
        sqlx::query_scalar("SELECT status FROM data_subject_requests WHERE id = 'REQ-cli-exp'")
            .fetch_one(&pool)
            .await
            .expect("expired row");
    assert_eq!(status, "expired");
    let remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM double_opt_in_tokens WHERE tenant_id = $1",
    )
    .bind("t-sweep-cli")
    .fetch_one(&pool)
    .await
    .expect("remaining tokens");
    assert_eq!(remaining, 0, "the stale token must be gone from the clone");

    let _ = pool.close().await;
}
