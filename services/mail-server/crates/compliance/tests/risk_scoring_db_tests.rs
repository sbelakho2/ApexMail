//! DB-backed tests for the risk-scoring canonical event metrics adapter (F57).
//!
//! Gated on `TEST_DATABASE_URL` (same convention as
//! `gdpr_compliance_db_tests.rs`): each test provisions its OWN throwaway
//! database carrying the REAL production migration chain
//! (`migrator::test_support::fresh_canonical_pool`, audits F01/F76/F77), so
//! the adapter runs against the canonical `events` shape (migration 075).
//! When the variable is unset every test skips; a configured provisioning
//! failure panics.
//!
//! Coverage:
//! - seeded canonical events (complained/unsubscribed/opened/clicked/
//!   delivered) map to the expected counts through the real SQL
//! - the 90-day window excludes older events
//! - tenant scoping: another tenant's events are invisible
//! - required-source failure stays visible: with no `events` table the
//!   adapter errors (it is never silently zero)

use compliance::risk_scoring::{
    canonical_event_counts, CanonicalEventCounts, EVENT_METRIC_WINDOW_DAYS,
};
use sqlx::PgPool;

// ── Bootstrap ───────────────────────────────────────────────────────────────

/// Each test gets its OWN canonical database clone. `TEST_DATABASE_URL`
/// unset ⇒ soft skip (`None`); a configured provisioning failure panics.
async fn test_pool(test_name: &str) -> Option<PgPool> {
    match migrator::test_support::fresh_canonical_pool(
        &format!("compliance_{test_name}"),
        &format!("compliance_{test_name}"),
    )
    .await
    {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

async fn seed_event(pool: &PgPool, id: &str, tenant: &str, event_type: &str, age_days: i64) {
    sqlx::query(
        "INSERT INTO events (id, tenant_id, event_type, recipient, timestamp)
         VALUES ($1, $2, $3, 'seed@example.com', NOW() - make_interval(days => $4::int))",
    )
    .bind(id)
    .bind(tenant)
    .bind(event_type)
    .bind(age_days)
    .execute(pool)
    .await
    .expect("seed event");
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn canonical_event_counts_maps_seeded_events() {
    let Some(pool) = test_pool("risk_events_mapping").await else {
        return;
    };
    let tenant = "tenant_events_map";

    // Seeded canonical events inside the window.
    for i in 0..3 {
        seed_event(&pool, &format!("cmp-{i}"), tenant, "complained", 1).await;
    }
    for i in 0..6 {
        seed_event(&pool, &format!("unsub-{i}"), tenant, "unsubscribed", 2).await;
    }
    for i in 0..40 {
        seed_event(&pool, &format!("open-{i}"), tenant, "opened", 3).await;
    }
    for i in 0..8 {
        seed_event(&pool, &format!("click-{i}"), tenant, "clicked", 4).await;
    }
    for i in 0..200 {
        seed_event(&pool, &format!("dlv-{i}"), tenant, "delivered", 5).await;
    }

    let counts = canonical_event_counts(&pool, tenant)
        .await
        .expect("canonical_event_counts");
    assert_eq!(
        counts,
        CanonicalEventCounts {
            complained: 3,
            unsubscribed: 6,
            opened: 40,
            clicked: 8,
            delivered: 200,
        }
    );
}

#[tokio::test]
async fn canonical_event_counts_window_excludes_stale_events() {
    let Some(pool) = test_pool("risk_events_window").await else {
        return;
    };
    let tenant = "tenant_events_window";

    seed_event(&pool, "fresh", tenant, "complained", 10).await;
    // Outside the 90-day window — must not count.
    seed_event(
        &pool,
        "stale",
        tenant,
        "complained",
        EVENT_METRIC_WINDOW_DAYS + 1,
    )
    .await;
    seed_event(
        &pool,
        "stale-dlv",
        tenant,
        "delivered",
        EVENT_METRIC_WINDOW_DAYS + 5,
    )
    .await;

    let counts = canonical_event_counts(&pool, tenant)
        .await
        .expect("canonical_event_counts");
    assert_eq!(counts.complained, 1);
    assert_eq!(counts.delivered, 0);
}

#[tokio::test]
async fn canonical_event_counts_is_tenant_scoped() {
    let Some(pool) = test_pool("risk_events_scope").await else {
        return;
    };
    let tenant = "tenant_events_scope";
    let other = "tenant_events_other";

    seed_event(&pool, "mine", tenant, "complained", 1).await;
    seed_event(&pool, "theirs-1", other, "complained", 1).await;
    seed_event(&pool, "theirs-2", other, "unsubscribed", 1).await;

    let counts = canonical_event_counts(&pool, tenant)
        .await
        .expect("canonical_event_counts");
    assert_eq!(counts.complained, 1);
    assert_eq!(counts.unsubscribed, 0);
}

#[tokio::test]
async fn canonical_event_counts_requires_the_events_source() {
    // No `events` table: the complaint/unsubscribe source is REQUIRED —
    // the failure must stay visible instead of reporting zeros. The canonical
    // table is renamed away (a DROP would have to chase inbound references).
    let Some(pool) = test_pool("risk_events_missing").await else {
        return;
    };
    sqlx::query("ALTER TABLE events RENAME TO events_hidden")
        .execute(&pool)
        .await
        .expect("hide canonical events store");
    let err = canonical_event_counts(&pool, "tenant_events_missing")
        .await
        .expect_err("adapter must fail when the canonical events source is missing");
    assert!(
        err.to_string().contains("events"),
        "expected a missing-`events`-relation error, got: {err}"
    );
}
