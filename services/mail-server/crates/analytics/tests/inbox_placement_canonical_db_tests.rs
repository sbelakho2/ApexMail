//! F84 canonical-schema tests: placement analytics consumes the REAL
//! seed-placement result model (placement_tests / seed_accounts /
//! seed_providers / placement_results), keeps delivery/complaint metrics
//! distinct, and represents unknown placement explicitly. Delivery-only
//! events must never be reported as inbox placement.
//!
//! Gated on `TEST_DATABASE_URL` (workspace convention).

use analytics::inbox_placement::InboxPlacementService;
use sqlx::PgPool;
use uuid::Uuid;

async fn canonical_pool(db_suffix: &str) -> Option<PgPool> {
    match migrator::test_support::fresh_canonical_pool("analytics_f84", db_suffix).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

async fn seed_placement_result(
    pool: &PgPool,
    tenant: &str,
    provider_name: &str,
    inbox_type: Option<&str>,
) {
    let (provider_id,): (Uuid,) = sqlx::query_as("SELECT id FROM seed_providers WHERE name = $1")
        .bind(provider_name)
        .fetch_one(pool)
        .await
        .expect("seed_providers is pre-seeded canonically");

    let (account_id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO seed_accounts (provider_id, email) VALUES ($1, $2) RETURNING id",
    )
    .bind(provider_id)
    .bind(format!(
        "{inbox_id}@seed.example",
        inbox_id = Uuid::new_v4().simple()
    ))
    .fetch_one(pool)
    .await
    .unwrap();

    let (test_id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO placement_tests (tenant_id, name, from_email, subject) \
         VALUES ($1, 'f84', 'sender@apex.example', 'seed') RETURNING id",
    )
    .bind(tenant)
    .fetch_one(pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO placement_results (test_id, seed_account_id, inbox_type, checked_at) \
         VALUES ($1, $2, $3, NOW())",
    )
    .bind(test_id)
    .bind(account_id)
    .bind(inbox_type)
    .execute(pool)
    .await
    .unwrap();
}

async fn seed_event(pool: &PgPool, tenant: &str, event_type: &str, recipient: &str) {
    sqlx::query(
        "INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp) \
         VALUES ($1, $2, $3, $4, $5, NOW())",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(tenant)
    .bind(Uuid::new_v4().to_string())
    .bind(event_type)
    .bind(recipient)
    .execute(pool)
    .await
    .unwrap();
}

/// Delivery-only events: placement stays unknown (None), deliveries are
/// reported as their own metric, and the query runs against the canonical
/// schema (no events.recipient_domain).
#[tokio::test]
async fn delivery_only_events_leave_placement_unknown() {
    let Some(pool) = canonical_pool("delivery_only").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    // Canonical events carry 26-char tenant ids (the ULID domain), and no
    // placement tests exist for such a tenant (placement_tests.tenant_id is
    // UUID-typed), so placement stays unknown while deliveries count.
    let simple = Uuid::new_v4().simple().to_string();
    let tenant = format!("t{}", &simple[..25]);
    for _ in 0..7 {
        seed_event(&pool, &tenant, "delivered", "user@gmail.com").await;
    }
    seed_event(&pool, &tenant, "complained", "user@gmail.com").await;
    seed_event(&pool, &tenant, "bounced", "user@yahoo.com").await;

    let summary = InboxPlacementService::new(pool.clone())
        .get_placement_summary(&tenant, 30)
        .await
        .expect("summary against canonical schema");

    assert_eq!(summary.overall_inbox_rate, None, "no measurement → unknown");
    assert_eq!(summary.measured.inbox, 0);
    assert_eq!(summary.measured.spam, 0);
    assert_eq!(summary.measured.unknown, 0);
    assert_eq!(summary.delivery.delivered, 7);
    assert_eq!(summary.delivery.complained, 1);
    assert_eq!(summary.delivery.bounced, 1);
    assert!(
        summary
            .recommendations
            .iter()
            .any(|r| r.to_lowercase().contains("unknown")),
        "the unknown state must be stated explicitly"
    );

    pool.close().await;
}

/// Measured seed results drive the rate; unknown observations are counted
/// but excluded from it.
#[tokio::test]
async fn measured_seed_results_drive_the_rate() {
    let Some(pool) = canonical_pool("measured").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let simple = Uuid::new_v4().simple().to_string();
    let tenant = format!("t{}", &simple[..25]);
    // gmail: 8 inbox, 2 spam, 1 promotions, 1 unobserved (NULL).
    for _ in 0..8 {
        seed_placement_result(&pool, &tenant, "gmail", Some("inbox")).await;
    }
    for _ in 0..2 {
        seed_placement_result(&pool, &tenant, "gmail", Some("spam")).await;
    }
    seed_placement_result(&pool, &tenant, "gmail", Some("promotions")).await;
    seed_placement_result(&pool, &tenant, "gmail", None).await;
    // outlook: 1 spam only.
    seed_placement_result(&pool, &tenant, "outlook", Some("spam")).await;

    let summary = InboxPlacementService::new(pool.clone())
        .get_placement_summary(&tenant, 30)
        .await
        .expect("summary");

    // Overall rate over ALL measured inbox vs spam placements: 8 / (8 + 3)
    //, the outlook spam row is a measurement too.
    assert!((summary.overall_inbox_rate.unwrap() - 8.0 / 11.0).abs() < 1e-9);
    assert_eq!(summary.measured.inbox, 8);
    assert_eq!(summary.measured.spam, 3);
    assert_eq!(summary.measured.other_folders, 1);
    assert_eq!(summary.measured.unknown, 1);
    assert_eq!(summary.measured.measured_total, 12);
    assert_eq!(
        summary.delivery.delivered, 0,
        "deliveries stay distinct from measured placement (none recorded here)"
    );

    let gmail = summary
        .by_provider
        .iter()
        .find(|p| p.provider == "gmail")
        .expect("gmail grouped from the seed_providers relation");
    assert_eq!(gmail.inbox_rate, Some(0.8));

    let outlook = summary
        .by_provider
        .iter()
        .find(|p| p.provider == "outlook")
        .expect("outlook grouped");
    assert_eq!(outlook.inbox_rate, Some(0.0));

    // Trends come from the measured model too.
    let trends = InboxPlacementService::new(pool.clone())
        .get_trends(&tenant, 30)
        .await
        .expect("trends");
    assert_eq!(trends.len(), 1);
    assert_eq!(trends[0].inbox_count, 8);
    assert_eq!(trends[0].spam_count, 3);
    assert!((trends[0].inbox_rate.unwrap() - 8.0 / 11.0).abs() < 1e-9);

    pool.close().await;
}

/// Another tenant's measurements never leak (tenant predicate is the
/// canonical placement_tests.tenant_id).
#[tokio::test]
async fn measurements_are_tenant_scoped() {
    let Some(pool) = canonical_pool("scoped").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let s1 = Uuid::new_v4().simple().to_string();
    let owner = format!("t{}", &s1[..25]);
    let s2 = Uuid::new_v4().simple().to_string();
    let other = format!("t{}", &s2[..25]);
    seed_placement_result(&pool, &owner, "gmail", Some("inbox")).await;
    seed_placement_result(&pool, &other, "gmail", Some("spam")).await;

    let summary = InboxPlacementService::new(pool.clone())
        .get_placement_summary(&owner, 30)
        .await
        .unwrap();
    assert_eq!(summary.overall_inbox_rate, Some(1.0));
    assert_eq!(summary.measured.spam, 0);

    pool.close().await;
}

/// Report 2026-10-28 p.11 contract: repeated observations of the SAME
/// planned unit (re-polls of one seed mailbox) must not inflate counts —
/// the unit's LATEST observation is its one classification.
#[tokio::test]
async fn repeated_observations_deduplicate_to_one_unit() {
    let Some(pool) = canonical_pool("dedupe_units").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let simple = Uuid::new_v4().simple().to_string();
    let tenant = format!("t{}", &simple[..25]);
    let (provider_id,): (Uuid,) = sqlx::query_as(
        "SELECT id FROM seed_providers WHERE name = 'gmail'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let (account_id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO seed_accounts (provider_id, email) VALUES ($1, $2) RETURNING id",
    )
    .bind(provider_id)
    .bind(format!("{}@seed.example", Uuid::new_v4().simple()))
    .fetch_one(&pool)
    .await
    .unwrap();
    let (test_id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO placement_tests (tenant_id, name, from_email, subject, seed_accounts_used) \
         VALUES ($1, 'dedupe', 'sender@apex.example', 'seed', $2) RETURNING id",
    )
    .bind(&tenant)
    .bind(vec![account_id])
    .fetch_one(&pool)
    .await
    .unwrap();
    // Three polls of the SAME unit: earlier polls said inbox, the LATEST
    // says spam (the message moved). One unit, one classification: spam.
    for (folder, seconds_ago) in [("inbox", 300), ("inbox", 200), ("spam", 0)] {
        sqlx::query(
            "INSERT INTO placement_results \
                (test_id, seed_account_id, inbox_type, checked_at) \
             VALUES ($1, $2, $3, NOW() - make_interval(secs => $4))",
        )
        .bind(test_id)
        .bind(account_id)
        .bind(folder)
        .bind(seconds_ago)
        .execute(&pool)
        .await
        .unwrap();
    }

    let summary = InboxPlacementService::new(pool.clone())
        .get_placement_summary(&tenant, 30)
        .await
        .expect("summary");

    assert_eq!(summary.measured.measured_total, 1, "one unit, not three polls");
    assert_eq!(summary.measured.inbox, 0, "the LATEST observation wins");
    assert_eq!(summary.measured.spam, 1);
    assert_eq!(summary.cohort.planned_units, 1);
    assert_eq!(summary.cohort.observed_units, 1);
    assert_eq!(summary.cohort.missing_units, 0);

    pool.close().await;
}

/// Report 2026-10-28 p.11 contract: a planned seed-recipient unit that was
/// never observed stays EXPLICITLY in the cohort (missing_units), and the
/// summary's inbox-fraction claim is the identifying bound
/// I/N <= fraction <= (I+U)/N — never a silently narrowed rate.
#[tokio::test]
async fn missing_planned_units_stay_explicit_and_bound_the_rate() {
    let Some(pool) = canonical_pool("cohort_bounds").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let simple = Uuid::new_v4().simple().to_string();
    let tenant = format!("t{}", &simple[..25]);
    let (provider_id,): (Uuid,) = sqlx::query_as(
        "SELECT id FROM seed_providers WHERE name = 'gmail'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    let mut planned: Vec<Uuid> = Vec::new();
    for _ in 0..4 {
        let (account_id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO seed_accounts (provider_id, email) VALUES ($1, $2) RETURNING id",
        )
        .bind(provider_id)
        .bind(format!("{}@seed.example", Uuid::new_v4().simple()))
        .fetch_one(&pool)
        .await
        .unwrap();
        planned.push(account_id);
    }
    let (test_id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO placement_tests (tenant_id, name, from_email, subject, seed_accounts_used) \
         VALUES ($1, 'cohort', 'sender@apex.example', 'seed', $2) RETURNING id",
    )
    .bind(&tenant)
    .bind(&planned)
    .fetch_one(&pool)
    .await
    .unwrap();
    // Two units observed inbox, one observed spam, ONE PLANNED UNIT NEVER
    // OBSERVED: N=4, I=2, U=1 -> bound [0.5, 0.75].
    for (unit, folder) in [(planned[0], "inbox"), (planned[1], "inbox"), (planned[2], "spam")] {
        sqlx::query(
            "INSERT INTO placement_results \
                (test_id, seed_account_id, inbox_type, checked_at) \
             VALUES ($1, $2, $3, NOW())",
        )
        .bind(test_id)
        .bind(unit)
        .bind(folder)
        .execute(&pool)
        .await
        .unwrap();
    }

    let summary = InboxPlacementService::new(pool.clone())
        .get_placement_summary(&tenant, 30)
        .await
        .expect("summary");

    assert_eq!(summary.cohort.planned_units, 4);
    assert_eq!(summary.cohort.observed_units, 3);
    assert_eq!(summary.cohort.missing_units, 1, "the unobserved unit must not vanish");
    let (lower, upper) = summary
        .inbox_fraction_bounds
        .expect("a planned cohort carries the bound");
    assert!(
        (lower - 0.5).abs() < 1e-9 && (upper - 0.75).abs() < 1e-9,
        "bound must be [0.5, 0.75], got [{lower}, {upper}]"
    );

    pool.close().await;
}

/// Audit 6: a placement test created BEFORE the window re-observed today
/// must NOT enter measured counts — its test is not in the frozen cohort,
/// so the numerator and denominator can never describe different worlds.
#[tokio::test]
async fn old_test_reobserved_today_never_enters_the_window() {
    let Some(pool) = canonical_pool("cohort_old_test").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let simple = Uuid::new_v4().simple().to_string();
    let tenant = format!("t{}", &simple[..25]);
    let (provider_id,): (Uuid,) = sqlx::query_as(
        "SELECT id FROM seed_providers WHERE name = 'gmail'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let (account_id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO seed_accounts (provider_id, email) VALUES ($1, $2) RETURNING id",
    )
    .bind(provider_id)
    .bind(format!("{}@seed.example", Uuid::new_v4().simple()))
    .fetch_one(&pool)
    .await
    .unwrap();
    // The test was created 40 days ago (outside the 30-day window)...
    let (test_id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO placement_tests (tenant_id, name, from_email, subject, seed_accounts_used, created_at) \
         VALUES ($1, 'old', 'sender@apex.example', 'seed', $2, NOW() - interval '40 days') RETURNING id",
    )
    .bind(&tenant)
    .bind(vec![account_id])
    .fetch_one(&pool)
    .await
    .unwrap();
    // ...but its result row is FRESH (checked today).
    sqlx::query(
        "INSERT INTO placement_results (test_id, seed_account_id, inbox_type, checked_at) \
         VALUES ($1, $2, 'inbox', NOW())",
    )
    .bind(test_id)
    .bind(account_id)
    .execute(&pool)
    .await
    .unwrap();

    let summary = InboxPlacementService::new(pool.clone())
        .get_placement_summary(&tenant, 30)
        .await
        .expect("summary");

    assert_eq!(summary.cohort.planned_units, 0, "the old test is not in the cohort");
    assert_eq!(summary.cohort.observed_units, 0, "its fresh observation does not count");
    assert_eq!(summary.measured.inbox, 0, "the numerator stays empty");
    assert_eq!(summary.inbox_fraction_bounds, None);

    pool.close().await;
}

/// Audit 6: a corrupted observation store (more observed units than the
/// cohort planned) must REFUSE the bound, not clamp it.
#[tokio::test]
async fn inconsistent_cohort_refuses_the_bound_instead_of_clamping() {
    let Some(pool) = canonical_pool("cohort_inconsistent").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let simple = Uuid::new_v4().simple().to_string();
    let tenant = format!("t{}", &simple[..25]);
    let (provider_id,): (Uuid,) = sqlx::query_as(
        "SELECT id FROM seed_providers WHERE name = 'gmail'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let (account_id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO seed_accounts (provider_id, email) VALUES ($1, $2) RETURNING id",
    )
    .bind(provider_id)
    .bind(format!("{}@seed.example", Uuid::new_v4().simple()))
    .fetch_one(&pool)
    .await
    .unwrap();
    let (second_account_id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO seed_accounts (provider_id, email) VALUES ($1, $2) RETURNING id",
    )
    .bind(provider_id)
    .bind(format!("{}@seed.example", Uuid::new_v4().simple()))
    .fetch_one(&pool)
    .await
    .unwrap();
    // The test PLANNED two units, both observed...
    let (test_id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO placement_tests (tenant_id, name, from_email, subject, seed_accounts_used) \
         VALUES ($1, 'shrunk', 'sender@apex.example', 'seed', $2) RETURNING id",
    )
    .bind(&tenant)
    .bind(vec![account_id, second_account_id])
    .fetch_one(&pool)
    .await
    .unwrap();
    for account in [account_id, second_account_id] {
        sqlx::query(
            "INSERT INTO placement_results (test_id, seed_account_id, inbox_type, checked_at) \
             VALUES ($1, $2, 'inbox', NOW())",
        )
        .bind(test_id)
        .bind(account)
        .execute(&pool)
        .await
        .unwrap();
    }
    // ...then the plan was post-hoc SHRUNK below the observed set (the
    // corruption class: seed_accounts_used edited after observations).
    sqlx::query("UPDATE placement_tests SET seed_accounts_used = $2 WHERE id = $1")
        .bind(test_id)
        .bind(vec![account_id])
        .execute(&pool)
        .await
        .unwrap();

    let summary = InboxPlacementService::new(pool.clone())
        .get_placement_summary(&tenant, 30)
        .await
        .expect("summary");

    assert_eq!(summary.cohort.planned_units, 1);
    assert!(
        summary.cohort.observed_units > summary.cohort.planned_units,
        "the corruption is visible in the cohort itself"
    );
    assert!(!summary.cohort.consistent, "the inconsistency is surfaced");
    assert_eq!(
        summary.inbox_fraction_bounds, None,
        "no bound may be published from mismatched populations"
    );

    pool.close().await;
}
