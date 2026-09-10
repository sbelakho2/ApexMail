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
    migrator::test_support::fresh_canonical_pool("analytics_f84", db_suffix).await
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
    // Canonical events carry 26-char tenant ids (the ULID domain) — and no
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
    // — the outlook spam row is a measurement too.
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
