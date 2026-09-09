//! DB-backed tests for the risk-scoring canonical event metrics adapter (F57).
//!
//! Gated on `TEST_DATABASE_URL` (same convention as
//! `gdpr_compliance_db_tests.rs`): a dedicated database is derived from the
//! URL, dropped/recreated per test, and the minimal canonical `events`
//! shape (migration 075) is created. When the variable is unset every test
//! skips.
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
use std::time::Duration;

// ── Bootstrap ───────────────────────────────────────────────────────────────

/// Minimal canonical `events` shape (columns the adapter reads; mirrors
/// migration 075).
const EVENTS_SCHEMA: &str = r#"
CREATE TABLE events (
    id              VARCHAR(64) PRIMARY KEY,
    tenant_id       VARCHAR(26) NOT NULL,
    message_id      VARCHAR(64),
    event_type      VARCHAR(50) NOT NULL,
    recipient       VARCHAR(255),
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_events_tenant ON events(tenant_id);
"#;

/// Empty schema — used to prove required-source failures propagate.
const EMPTY_SCHEMA: &str = "SELECT 1;";

async fn isolated_pool(db_suffix: &str, schema: &str) -> Option<PgPool> {
    let database_url = match std::env::var("TEST_DATABASE_URL") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed compliance tests");
            return None;
        }
    };
    let (server_part, db_part) = database_url.rsplit_once('/')?;
    let db_only = db_part.split('?').next().unwrap_or(db_part);
    let isolated = format!("{db_only}_{db_suffix}");
    let isolated_url = format!("{server_part}/{isolated}");
    let admin_url = format!("{server_part}/postgres");

    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&admin_url)
        .await
        .ok()?;

    let _ = sqlx::query(&format!(
        r#"DROP DATABASE IF EXISTS "{isolated}" WITH (FORCE)"#
    ))
    .execute(&admin)
    .await;
    if sqlx::query(&format!(r#"CREATE DATABASE "{isolated}""#))
        .execute(&admin)
        .await
        .is_err()
    {
        eprintln!("skipping: could not create isolated test database {isolated}");
        return None;
    }

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&isolated_url)
        .await
        .ok()?;

    sqlx::raw_sql(schema)
        .execute(&pool)
        .await
        .expect("failed to create test schema");

    Some(pool)
}

async fn test_pool(test_name: &str, schema: &str) -> Option<PgPool> {
    isolated_pool(&format!("compliance_{test_name}"), schema).await
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
    let Some(pool) = test_pool("risk_events_mapping", EVENTS_SCHEMA).await else {
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
    let Some(pool) = test_pool("risk_events_window", EVENTS_SCHEMA).await else {
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
    let Some(pool) = test_pool("risk_events_scope", EVENTS_SCHEMA).await else {
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
    // the failure must stay visible instead of reporting zeros.
    let Some(pool) = test_pool("risk_events_missing", EMPTY_SCHEMA).await else {
        return;
    };
    let err = canonical_event_counts(&pool, "tenant_events_missing")
        .await
        .expect_err("adapter must fail when the canonical events source is missing");
    assert!(
        err.to_string().contains("events"),
        "expected a missing-`events`-relation error, got: {err}"
    );
}
