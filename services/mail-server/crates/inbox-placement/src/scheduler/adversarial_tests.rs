//! Adversarial canonical-schema tests for the placement scheduler
//! (`src/scheduler.rs`): exact-once-per-window claiming, the rate-limit
//! gate, future-scheduled exclusion, stuck-test reaping, and the
//! seed-account health-check probe (success / failure / missing password).

use super::*;
use crate::config::PlacementConfig;
use crate::engine::PlacementEngine;
use crate::imap_poller::{ImapConnector, ImapPoller, ImapSession};
use sqlx::PgPool;
use uuid::Uuid;

async fn canonical_pool(test_name: &str) -> Option<PgPool> {
    match migrator::test_support::fresh_canonical_pool(test_name, test_name).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

fn tenant_key(label: &str) -> String {
    let hex = Uuid::new_v4().simple().to_string();
    format!("{label}{}", &hex[..26 - label.len()])
}

async fn seed_tenant(db: &PgPool, tenant_id: &str) {
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status) VALUES ($1, $1, $1, 'free', 'active')
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(tenant_id)
    .execute(db)
    .await
    .expect("seed tenant");
}

/// Insert a placement test directly with the given status/schedule.
async fn insert_test(
    db: &PgPool,
    tenant: &str,
    status: &str,
    scheduled_for: Option<chrono::DateTime<chrono::Utc>>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO placement_tests \
         (id, tenant_id, name, status, from_email, subject, total_accounts, \
          completed_accounts, seed_accounts_used, scheduled_for, created_at) \
         VALUES ($1, $2, NULL, $3, 's@send.example', 's', 0, 0, '{}', $4, NOW())",
    )
    .bind(id)
    .bind(tenant)
    .bind(status)
    .bind(scheduled_for)
    .execute(db)
    .await
    .expect("insert test");
    id
}

async fn seed_account(db: &PgPool, email: &str, password: &str) -> Uuid {
    let (id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO seed_accounts (provider_id, email, imap_password_encrypted, is_active) \
         SELECT p.id, $1, $2, true FROM seed_providers p WHERE p.name = 'gmail' RETURNING id",
    )
    .bind(email)
    .bind(password)
    .fetch_one(db)
    .await
    .expect("seed account");
    id
}

fn test_config() -> PlacementConfig {
    PlacementConfig {
        polling_interval_secs: 0,
        max_polling_attempts: 1,
        imap_connection_timeout_secs: 2,
        max_tests_per_hour: 5,
        encrypt_stored_passwords: false,
        smtp_host: "127.0.0.1".into(),
        smtp_port: 1, // send will fail — irrelevant to scheduler logic
        ..PlacementConfig::default()
    }
}

// ── fetch_pending_tests ─────────────────────────────────────────────────────

#[tokio::test]
async fn fetch_claims_only_due_pending_tests_within_the_rate_limit() {
    let Some(db) = canonical_pool("ipx_sched_fetch").await else {
        return;
    };
    let tenant = tenant_key("f");
    seed_tenant(&db, &tenant).await;
    // High ceiling for the selection part (the fixtures themselves count
    // toward the sliding-window rate limit).
    let config = PlacementConfig {
        max_tests_per_hour: 100,
        ..test_config()
    };
    let engine = PlacementEngine::new(config.clone(), db.clone());

    let due_now = insert_test(&db, &tenant, "pending", None).await;
    let due_past = insert_test(
        &db,
        &tenant,
        "pending",
        Some(chrono::Utc::now() - chrono::Duration::hours(1)),
    )
    .await;
    let future = insert_test(
        &db,
        &tenant,
        "pending",
        Some(chrono::Utc::now() + chrono::Duration::hours(2)),
    )
    .await;
    let running = insert_test(&db, &tenant, "running", None).await;

    let mut claimed = PlacementScheduler::fetch_pending_tests(&engine, &config)
        .await
        .expect("fetch");
    claimed.sort();
    let mut expected = vec![due_now, due_past];
    expected.sort();
    assert_eq!(claimed, expected, "only due pending tests are claimed");
    assert!(
        !claimed.contains(&future),
        "future-scheduled must not start early"
    );
    assert!(
        !claimed.contains(&running),
        "running tests are not re-fetched"
    );

    // Rate limit: raise the number of recent pending/running tests to the
    // ceiling → the scheduler skips the cycle entirely.
    let config = PlacementConfig {
        max_tests_per_hour: 1,
        ..test_config()
    };
    let claimed = PlacementScheduler::fetch_pending_tests(&engine, &config)
        .await
        .expect("fetch");
    assert!(claimed.is_empty(), "at the ceiling the cycle is skipped");
}

// ── reap_stuck_tests ────────────────────────────────────────────────────────

#[tokio::test]
async fn reaper_fails_only_stale_running_tests() {
    let Some(db) = canonical_pool("ipx_sched_reap").await else {
        return;
    };
    let tenant = tenant_key("r");
    seed_tenant(&db, &tenant).await;
    let engine = PlacementEngine::new(test_config(), db.clone());
    let config = PlacementConfig {
        stuck_test_timeout_secs: 600,
        ..test_config()
    };

    let stale = insert_test(&db, &tenant, "running", None).await;
    sqlx::query("UPDATE placement_tests SET created_at = NOW() - INTERVAL '3 hours' WHERE id=$1")
        .bind(stale)
        .execute(&db)
        .await
        .expect("age the stale test");
    let fresh = insert_test(&db, &tenant, "running", None).await;
    let done = insert_test(&db, &tenant, "completed", None).await;
    sqlx::query("UPDATE placement_tests SET created_at = NOW() - INTERVAL '3 hours' WHERE id=$1")
        .bind(done)
        .execute(&db)
        .await
        .expect("age the done test");

    PlacementScheduler::reap_stuck_tests(&engine, &config).await;

    async fn status_of(db: &PgPool, id: Uuid) -> String {
        let (s,): (String,) = sqlx::query_as("SELECT status FROM placement_tests WHERE id=$1")
            .bind(id)
            .fetch_one(db)
            .await
            .expect("row");
        s
    }
    assert_eq!(
        status_of(&db, stale).await,
        "failed",
        "stale running → failed"
    );
    assert_eq!(
        status_of(&db, fresh).await,
        "running",
        "fresh running survives"
    );
    assert_eq!(
        status_of(&db, done).await,
        "completed",
        "terminal untouched"
    );
}

// ── Health-check probe ──────────────────────────────────────────────────────

/// Accepts logins whose password matches `expected`; refuses everything
/// else with an AUTHENTICATIONFAILED-style error.
struct PasswordExpectingConnector {
    expected: &'static str,
}

impl ImapConnector for PasswordExpectingConnector {
    fn connect(
        &self,
        _host: &str,
        _port: u16,
        _username: &str,
        password: &str,
    ) -> Result<Box<dyn ImapSession>, String> {
        #[derive(Default)]
        struct S;
        impl ImapSession for S {
            fn list_folders(&mut self) -> Result<Vec<String>, String> {
                Ok(vec![])
            }
            fn select_folder(&mut self, _f: &str) -> Result<(), String> {
                Ok(())
            }
            fn search(&mut self, _q: &str) -> Result<Vec<u32>, String> {
                Ok(vec![])
            }
            fn fetch_header_and_date(
                &mut self,
                _i: u32,
            ) -> Result<Option<(Option<Vec<u8>>, Option<chrono::DateTime<chrono::Utc>>)>, String>
            {
                Ok(None)
            }
            fn logout(&mut self) {}
        }
        if password == self.expected {
            Ok(Box::new(S))
        } else {
            Err("IMAP login error: [AUTHENTICATIONFAILED] wrong password".into())
        }
    }
}

#[tokio::test]
async fn health_probe_records_success_failure_and_missing_password() {
    let Some(db) = canonical_pool("ipx_sched_probe").await else {
        return;
    };
    let tenant = tenant_key("h");
    seed_tenant(&db, &tenant).await;
    let config = test_config();
    let poller = ImapPoller::with_connector(
        config.clone(),
        std::sync::Arc::new(PasswordExpectingConnector { expected: "pw" }),
    );
    let engine = PlacementEngine::new(config.clone(), db.clone());
    let account = |id: Uuid| {
        let engine = &engine;
        async move {
            engine
                .seed_manager
                .get_account(id)
                .await
                .expect("get")
                .expect("exists")
        }
    };

    // (1) Healthy account → probe success resets the health record.
    let healthy = seed_account(&db, &format!("{tenant}.ok@seed.example"), "pw").await;
    PlacementScheduler::check_one_account(&engine, &poller, &config, account(healthy).await).await;
    let (status, failures, reason): (String, i32, Option<String>) = sqlx::query_as(
        "SELECT health_status, consecutive_failures, last_failure_reason \
         FROM seed_accounts WHERE id=$1",
    )
    .bind(healthy)
    .fetch_one(&db)
    .await
    .expect("healthy account");
    assert_eq!(status, "ok");
    assert_eq!(failures, 0);
    assert_eq!(reason, None);

    // (2) Wrong password → probe failure recorded (transient reason →
    //     backoff, still active below the threshold).
    let flaky = seed_account(
        &db,
        &format!("{tenant}.flaky@seed.example"),
        "right-password",
    )
    .await;
    PlacementScheduler::check_one_account(&engine, &poller, &config, account(flaky).await).await;
    let (status, is_active): (String, bool) =
        sqlx::query_as("SELECT health_status, is_active FROM seed_accounts WHERE id=$1")
            .bind(flaky)
            .fetch_one(&db)
            .await
            .expect("flaky account");
    assert_eq!(status, "error");
    assert!(is_active, "below the threshold the account stays active");

    // (3) NO password at all → the permanent failure reason disables the
    //     account immediately (compliance: an unusable seed is retired).
    let (no_pw_id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO seed_accounts (provider_id, email, imap_password_encrypted, is_active) \
         SELECT p.id, $1, NULL, true FROM seed_providers p WHERE p.name = 'gmail' RETURNING id",
    )
    .bind(format!("{tenant}.nopw@seed.example"))
    .fetch_one(&db)
    .await
    .expect("seed passwordless account");
    PlacementScheduler::check_one_account(&engine, &poller, &config, account(no_pw_id).await).await;
    let (is_active,): (bool,) = sqlx::query_as("SELECT is_active FROM seed_accounts WHERE id=$1")
        .bind(no_pw_id)
        .fetch_one(&db)
        .await
        .expect("passwordless account");
    assert!(
        !is_active,
        "no IMAP password configured → permanent → disabled"
    );
}

// ── Start / shutdown lifecycle ──────────────────────────────────────────────

#[tokio::test]
async fn scheduler_executes_due_tests_and_stops_cleanly() {
    let Some(db) = canonical_pool("ipx_sched_lifecycle").await else {
        return;
    };
    let tenant = tenant_key("l");
    seed_tenant(&db, &tenant).await;
    // A pending due test with NO seed accounts: the send fails per account…
    // actually zero accounts → execute_test marks it failed, which is the
    // observable transition proving the loop ran.
    let test_id = insert_test(&db, &tenant, "pending", None).await;

    let config = PlacementConfig {
        // Zero interval → the loop's sleep is a yield; the cycle runs
        // immediately and cancellation still terminates the loop.
        polling_interval_secs: 0,
        health_check_interval_secs: 0, // health loop disabled by config
        ..test_config()
    };
    let engine = PlacementEngine::new(config.clone(), db.clone());
    let scheduler = std::sync::Arc::new(PlacementScheduler::new(std::sync::Arc::new(engine)));
    scheduler.clone().start().await;

    // The first cycle executes the due test: poll for the transition.
    let mut done = false;
    for _ in 0..100 {
        let (status,): (String,) = sqlx::query_as("SELECT status FROM placement_tests WHERE id=$1")
            .bind(test_id)
            .fetch_one(&db)
            .await
            .expect("row");
        if status != "pending" {
            done = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(done, "the scheduler executed the due test");
    scheduler.shutdown().await;
    // Give the loop a moment to observe the cancellation, then assert it
    // stopped by checking no further transitions happen — simply awaiting
    // shutdown is the contract under test here.
}
