//! Dogfood 2026-10-06 wave B: the audience-level churn overview
//! (`GET /v1/ai/churn-prediction`) is computed from REAL data by the churn
//! engine's signal rules — not the two hardcoded factor strings the route
//! returned before. Canonical-schema tests (the production migrator's
//! `contacts` / `events` shapes).
//!
//! Gated on `TEST_DATABASE_URL` (workspace convention).

use analytics::churn_prediction::ChurnPredictionEngine;
use sqlx::PgPool;
use uuid::Uuid;

async fn canonical_pool(db_suffix: &str) -> Option<PgPool> {
    match migrator::test_support::fresh_canonical_pool("analytics_churn_b", db_suffix).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

/// The engine's `tenant_overview` never touches Redis; a lazy dead-port pool
/// keeps the constructor honest without starting a server.
fn engine(pool: &PgPool) -> ChurnPredictionEngine {
    let redis = deadpool_redis::Config::from_url("redis://127.0.0.1:1")
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .expect("lazy redis pool");
    ChurnPredictionEngine::new(pool.clone(), redis)
}

async fn seed_tenant(pool: &PgPool, tenant: &str) {
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
         VALUES ($1, 'Churn Co', $2, 'growth', 'active', NOW(), NOW())",
    )
    .bind(tenant)
    .bind(format!("slug-{tenant}"))
    .execute(pool)
    .await
    .expect("seed tenant");
}

async fn seed_contact(pool: &PgPool, tenant: &str, email: &str, status: &str) {
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, email, status, tags)
         VALUES ($1, $2, $3, $4, '[]'::jsonb)",
    )
    .bind(Uuid::new_v4())
    .bind(tenant)
    .bind(email)
    .bind(status)
    .execute(pool)
    .await
    .expect("seed contact");
}

/// Insert an engagement event; `hours_ago` positions it in time so the
/// 90-day / 30-day windows can be exercised deterministically.
async fn seed_event(pool: &PgPool, tenant: &str, email: &str, event_type: &str, hours_ago: i64) {
    sqlx::query(
        "INSERT INTO events (id, tenant_id, event_type, recipient, timestamp)
         VALUES ($1, $2, $3, $4, NOW() - make_interval(hours => $5::int))",
    )
    .bind(format!("churn-b-{}", Uuid::new_v4().simple()))
    .bind(tenant)
    .bind(event_type)
    .bind(email)
    .bind(hours_ago)
    .execute(pool)
    .await
    .expect("seed event");
}

/// The route's real factors: complaints and inactivity from actual rows,
/// ordered by the engine's weights, with real contact counts.
#[tokio::test]
async fn overview_reports_real_weighted_factors() {
    let Some(pool) = canonical_pool("overview_factors").await else {
        return;
    };
    let tenant = "chbtenant0000000000000001";
    seed_tenant(&pool, tenant).await;

    seed_contact(&pool, tenant, "idle@example.com", "active").await;
    seed_contact(&pool, tenant, "engaged@example.com", "active").await;
    seed_contact(&pool, tenant, "complainer@example.com", "active").await;
    seed_contact(&pool, tenant, "gone@example.com", "unsubscribed").await;

    // The engaged contact opened today; the complainer only complained.
    seed_event(&pool, tenant, "engaged@example.com", "opened", 1).await;
    seed_event(&pool, tenant, "complainer@example.com", "complained", 2).await;
    // The unsubscribed contact's complaint must NOT count.
    seed_event(&pool, tenant, "gone@example.com", "complained", 2).await;

    let overview = engine(&pool)
        .tenant_overview(tenant)
        .await
        .expect("overview");

    assert_eq!(overview.active_contacts, 3, "only active contacts count");
    assert_eq!(
        overview.at_risk_contacts, 2,
        "idle + complainer have no opens/clicks in 90 days"
    );
    assert!((overview.churn_probability - 2.0 / 3.0).abs() < 1e-9);

    let factors: Vec<(String, i64, f64)> = overview
        .risk_factors
        .iter()
        .map(|factor| (factor.factor.clone(), factor.contacts, factor.weight))
        .collect();
    assert_eq!(factors.len(), 2, "reality has two factors, got {factors:?}");
    assert!(
        factors[0].0.contains("complained") && factors[0].1 == 1 && factors[0].2 == 35.0,
        "complaint (weight 35) must rank first with its real count, got {factors:?}"
    );
    assert!(
        factors[1].0.contains("no opens or clicks in 90 days")
            && factors[1].1 == 2
            && factors[1].2 == 30.0,
        "inactivity must carry the real at-risk count, got {factors:?}"
    );

    assert!(
        overview
            .recommendations
            .iter()
            .any(|r| r.contains("complaint sources")),
        "recommendations must follow the present signals, got {:?}",
        overview.recommendations
    );
    assert!(
        overview
            .recommendations
            .iter()
            .any(|r| r.contains("re-engagement")),
        "the inactivity signal must recommend re-engagement, got {:?}",
        overview.recommendations
    );

    pool.close().await;
}

/// A declining contact is reported by the decay rule (fewer opens in the last
/// 30 days than the previous 30) without being counted as inactive.
#[tokio::test]
async fn overview_detects_decay_without_marking_the_contact_inactive() {
    let Some(pool) = canonical_pool("overview_decay").await else {
        return;
    };
    let tenant = "chbtenant0000000000000002";
    seed_tenant(&pool, tenant).await;
    seed_contact(&pool, tenant, "declining@example.com", "active").await;

    // Two opens 40 days ago (previous window), none in the last 30 days.
    seed_event(&pool, tenant, "declining@example.com", "opened", 40 * 24).await;
    seed_event(&pool, tenant, "declining@example.com", "clicked", 41 * 24).await;

    let overview = engine(&pool)
        .tenant_overview(tenant)
        .await
        .expect("overview");

    assert_eq!(overview.active_contacts, 1);
    assert_eq!(
        overview.at_risk_contacts, 0,
        "the contact engaged within 90 days, so it is not inactive"
    );
    let factors: Vec<(String, i64)> = overview
        .risk_factors
        .iter()
        .map(|factor| (factor.factor.clone(), factor.contacts))
        .collect();
    assert_eq!(factors.len(), 1, "only decay applies, got {factors:?}");
    assert!(
        factors[0].0.contains("engagement declining") && factors[0].1 == 1,
        "the decay factor must carry the real count, got {factors:?}"
    );

    pool.close().await;
}

/// Tenant isolation: another tenant's events for the SAME recipient address
/// must never contribute to this tenant's factors.
#[tokio::test]
async fn overview_is_tenant_scoped() {
    let Some(pool) = canonical_pool("overview_isolation").await else {
        return;
    };
    let tenant_a = "chbtenant0000000000000003";
    let tenant_b = "chbtenant0000000000000004";
    seed_tenant(&pool, tenant_a).await;
    seed_tenant(&pool, tenant_b).await;

    seed_contact(&pool, tenant_a, "shared@example.com", "active").await;
    seed_contact(&pool, tenant_b, "shared@example.com", "active").await;
    // Tenant B's contact is highly engaged and complained; tenant A's is idle.
    seed_event(&pool, tenant_b, "shared@example.com", "opened", 1).await;
    seed_event(&pool, tenant_b, "shared@example.com", "complained", 1).await;

    let overview = engine(&pool)
        .tenant_overview(tenant_a)
        .await
        .expect("overview");

    assert_eq!(overview.active_contacts, 1);
    assert_eq!(
        overview.at_risk_contacts, 1,
        "tenant B's opens must not mark tenant A's contact engaged"
    );
    let factors: Vec<(String, i64)> = overview
        .risk_factors
        .iter()
        .map(|factor| (factor.factor.clone(), factor.contacts))
        .collect();
    assert_eq!(
        factors.len(),
        1,
        "tenant B's complaint must not appear in tenant A's factors, got {factors:?}"
    );
    assert!(factors[0].0.contains("no opens or clicks"));

    pool.close().await;
}

/// An empty tenant answers honestly (zero probability, one explicit
/// no-action recommendation) instead of fabricating risk.
#[tokio::test]
async fn overview_of_an_empty_tenant_is_honest() {
    let Some(pool) = canonical_pool("overview_empty").await else {
        return;
    };
    let tenant = "chbtenant0000000000000005";
    seed_tenant(&pool, tenant).await;

    let overview = engine(&pool)
        .tenant_overview(tenant)
        .await
        .expect("overview");

    assert_eq!(overview.active_contacts, 0);
    assert_eq!(overview.at_risk_contacts, 0);
    assert_eq!(overview.churn_probability, 0.0);
    assert!(overview.risk_factors.is_empty());
    assert_eq!(overview.recommendations.len(), 1);
    assert!(overview.recommendations[0].contains("No churn signals"));

    pool.close().await;
}
