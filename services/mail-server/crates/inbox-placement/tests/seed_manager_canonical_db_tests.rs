//! Adversarial DB-backed tests for the seed-account health machinery
//! (`SeedManager`): permanent-vs-transient failure classification, the
//! exponential backoff ladder, auto-disable at the threshold, and the
//! due-for-health-check ordering — all against the REAL migration chain.

use inbox_placement::seed_manager::SeedManager;
use sqlx::PgPool;
use uuid::Uuid;

/// One PRIVATE canonical database per test: nextest runs each test as its
/// own process, and a shared name would be dropped mid-test by a sibling's
/// provisioning (observed as PoolTimedOut under parallel load).
fn db(test: &'static str) -> impl std::future::Future<Output = Option<PgPool>> {
    async move {
        match migrator::test_support::fresh_canonical_pool(
            test,
            Box::leak(format!("ip_seed_{test}").into_boxed_str()),
        )
        .await
        {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        }
    }
}

async fn seed_provider(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO seed_providers (name, display_name, inbox_types)
         VALUES ($1, $1, ARRAY['gmail'])
         ON CONFLICT (name) DO UPDATE SET display_name = EXCLUDED.display_name
         RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("provider")
}

async fn seed_account(pool: &PgPool, provider: Uuid, email: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO seed_accounts (provider_id, email, imap_host, imap_username)
         VALUES ($1, $2, 'imap.test', 'user') RETURNING id",
    )
    .bind(provider)
    .bind(email)
    .fetch_one(pool)
    .await
    .expect("account")
}

/// A PERMANENT failure (mixed-case "no IMAP password configured" — the one
/// keyword that previously never matched because only one side was
/// lower-cased) disables the account on the FIRST failure, before the
/// threshold.
#[tokio::test]
async fn permanent_failure_discharges_the_account_immediately() {
    let Some(pool) = db("perm").await else {
        eprintln!("skipping: set TEST_DATABASE_URL");
        return;
    };
    let provider = seed_provider(&pool, "perm-gmail").await;
    let account = seed_account(&pool, provider, "perm@seed.test").await;
    let manager = SeedManager::new(pool.clone());

    let disabled = manager
        .record_health_failure(account, "No IMAP Password Configured", 5)
        .await
        .expect("record");
    assert!(
        disabled,
        "a permanent failure must auto-disable on the first hit"
    );

    let (is_active, health, reason): (bool, String, Option<String>) = sqlx::query_as(
        "SELECT is_active, health_status, last_failure_reason FROM seed_accounts WHERE id = $1",
    )
    .bind(account)
    .fetch_one(&pool)
    .await
    .expect("row");
    assert!(!is_active, "the account is retired");
    assert_eq!(health, "error");
    assert_eq!(reason.as_deref(), Some("No IMAP Password Configured"));

    // A disabled account no longer appears in the due list.
    let due = manager
        .list_accounts_due_for_health_check(0, 50)
        .await
        .expect("due");
    assert!(due.iter().all(|a| a.id != account));
    pool.close().await;
}

/// TRANSIENT failures back off exponentially (300s → 600s → 1200s) WITHOUT
/// disabling, until the threshold finally disables.
#[tokio::test]
async fn transient_failures_back_off_then_disable_at_threshold() {
    let Some(pool) = db("transient").await else {
        eprintln!("skipping: set TEST_DATABASE_URL");
        return;
    };
    let provider = seed_provider(&pool, "transient-gmail").await;
    let account = seed_account(&pool, provider, "flaky@seed.test").await;
    let manager = SeedManager::new(pool.clone());

    let last_checked = |pool: &PgPool, id: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Option<chrono::DateTime<chrono::Utc>>>(
                "SELECT last_checked_at FROM seed_accounts WHERE id = $1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("row")
        }
    };

    // Failure 1: backoff 300s → last_checked_at is ~5 minutes in the FUTURE.
    assert!(!manager
        .record_health_failure(account, "connection timed out", 3)
        .await
        .unwrap());
    let checked = last_checked(&pool, account).await.expect("checked 1");
    assert!(
        checked > chrono::Utc::now(),
        "failure 1 must push last_checked_at into the backoff future"
    );

    // Failure 2: backoff 600s.
    assert!(!manager
        .record_health_failure(account, "connection reset by peer", 3)
        .await
        .unwrap());
    let checked2 = last_checked(&pool, account).await.expect("checked 2");
    assert!(
        checked2 > checked,
        "failure 2 backs off longer than failure 1"
    );

    // Failure 3 = threshold: DISABLED.
    let disabled = manager
        .record_health_failure(account, "connection timed out", 3)
        .await
        .expect("record");
    assert!(disabled, "reaching the threshold disables the account");
    let (is_active,): (bool,) = sqlx::query_as("SELECT is_active FROM seed_accounts WHERE id = $1")
        .bind(account)
        .fetch_one(&pool)
        .await
        .expect("row");
    assert!(!is_active);
    pool.close().await;
}

/// Success clears the failure streak: two transient failures then a success
/// reset the counter, so the NEXT transient failure backs off from 300s
/// again (not 1200s) and does not disable at the old threshold countdown.
#[tokio::test]
async fn success_resets_the_failure_streak() {
    let Some(pool) = db("reset").await else {
        eprintln!("skipping: set TEST_DATABASE_URL");
        return;
    };
    let provider = seed_provider(&pool, "reset-gmail").await;
    let account = seed_account(&pool, provider, "reset@seed.test").await;
    let manager = SeedManager::new(pool.clone());

    assert!(!manager
        .record_health_failure(account, "timeout", 5)
        .await
        .unwrap());
    manager
        .record_health_success(account)
        .await
        .expect("success");

    let (health, failures, reason): (String, i32, Option<String>) = sqlx::query_as(
        "SELECT health_status, consecutive_failures, last_failure_reason \
         FROM seed_accounts WHERE id = $1",
    )
    .bind(account)
    .fetch_one(&pool)
    .await
    .expect("row");
    assert_eq!(health, "ok");
    assert_eq!(failures, 0, "the streak is cleared");
    assert!(reason.is_none());

    // Backoff after the reset starts at the BASE (300s), proving the counter
    // really is zero: last_checked_at lands ~5 minutes out, not ~20.
    assert!(!manager
        .record_health_failure(account, "timeout", 5)
        .await
        .unwrap());
    let checked: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT last_checked_at FROM seed_accounts WHERE id = $1")
            .bind(account)
            .fetch_one(&pool)
            .await
            .expect("row");
    let backoff_secs = (checked - chrono::Utc::now()).num_seconds();
    assert!(
        (250..=350).contains(&backoff_secs),
        "backoff must restart at the base (~300s), got {backoff_secs}s"
    );
    pool.close().await;
}

/// Unknown accounts are a no-op (never an error), and the due list is
/// oldest-checked-first and bounded by the limit.
#[tokio::test]
async fn unknown_account_is_a_noop_and_due_list_is_ordered_and_bounded() {
    let Some(pool) = db("noop").await else {
        eprintln!("skipping: set TEST_DATABASE_URL");
        return;
    };
    let provider = seed_provider(&pool, "due-gmail").await;
    let manager = SeedManager::new(pool.clone());

    let ghost = Uuid::new_v4();
    assert!(
        !manager
            .record_health_failure(ghost, "timeout", 3)
            .await
            .unwrap(),
        "a missing account cannot be disabled"
    );
    manager
        .record_health_success(ghost)
        .await
        .expect("missing account success is a no-op");

    // Three accounts due (NULL last_checked_at), one NOT due (checked now).
    let mut ids = Vec::new();
    for i in 0..3 {
        let id = seed_account(&pool, provider, &format!("due{i}@seed.test")).await;
        ids.push(id);
    }
    let fresh = seed_account(&pool, provider, "fresh@seed.test").await;
    manager
        .update_account_health(fresh, "ok", chrono::Utc::now())
        .await
        .expect("mark fresh");

    let due = manager
        .list_accounts_due_for_health_check(60, 2)
        .await
        .expect("due");
    assert_eq!(due.len(), 2, "the limit bounds the batch");
    let due_ids: std::collections::HashSet<Uuid> = due.iter().map(|a| a.id).collect();
    assert!(due_ids.contains(&ids[0]) && due_ids.contains(&ids[1]));
    assert!(
        !due_ids.contains(&fresh),
        "a just-checked account is not due"
    );
    pool.close().await;
}

/// Backoff ladder arithmetic: base doubling, the 24h cap, and overflow
/// safety on absurd streaks; and the permanent-failure keyword list matches
/// case-insensitively on BOTH sides.
#[test]
fn backoff_ladder_is_exponential_capped_and_overflow_safe() {
    assert_eq!(inbox_placement::seed_manager::backoff_seconds(1), 300);
    assert_eq!(inbox_placement::seed_manager::backoff_seconds(2), 600);
    assert_eq!(inbox_placement::seed_manager::backoff_seconds(3), 1_200);
    assert_eq!(
        inbox_placement::seed_manager::backoff_seconds(9),
        76_800,
        "300s * 2^8 = 76800s (21.3h) — the cap lands at streak 10"
    );
    assert_eq!(
        inbox_placement::seed_manager::backoff_seconds(10),
        86_400,
        "capped at 24h from streak 10"
    );
    assert_eq!(
        inbox_placement::seed_manager::backoff_seconds(500),
        86_400,
        "no overflow panic on absurd streaks"
    );
    for reason in [
        "authentication failed",
        "AUTH FAILED",
        "Invalid Credentials",
        "Login Rejected",
        "no IMAP password configured",
        "No IMAP Password Configured",
    ] {
        assert!(
            inbox_placement::seed_manager::is_permanent_failure(reason),
            "{reason} must classify permanent"
        );
    }
    for reason in ["connection timed out", "reset by peer", "DNS lookup failed"] {
        assert!(
            !inbox_placement::seed_manager::is_permanent_failure(reason),
            "{reason} must classify transient"
        );
    }
}
