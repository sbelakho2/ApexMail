//! F63 canonical persistence tests for the HA component's health-check
//! results (ha_health_checks, migration 194): record → read → restart →
//! reread, plus the readiness probe and retention cleanup — against the
//! canonical migration chain, not migration-content substring assertions.
//!
//! Gated on `TEST_DATABASE_URL` (workspace convention).

use ha::config::Config;
use ha::health_check::HealthCheckService;
use sqlx::PgPool;
use std::sync::Arc;

async fn canonical_pool(db_suffix: &str) -> Option<PgPool> {
    match migrator::test_support::fresh_canonical_pool("ha_f63", db_suffix).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

fn service(pool: &PgPool, node: &str) -> HealthCheckService {
    let mut config = Config::from_env();
    config.multi_region.node_id = node.to_string();
    config.multi_region.region = "eu-test".to_string();
    HealthCheckService::new(pool.clone(), Arc::new(config))
}

/// F63: readiness — the relation exists on the canonical chain.
#[tokio::test]
async fn persistence_ready_on_canonical_schema() {
    let Some(pool) = canonical_pool("ready").await else {
        return;
    };
    assert!(
        service(&pool, "node-1").persistence_ready().await,
        "canonical migration 194 must create ha_health_checks"
    );
    pool.close().await;
}

/// Record → read → restart → reread: a health result persists, survives a
/// fresh service instance, and the cluster read stays scoped to the recent
/// window with the persisted column contract intact.
#[tokio::test]
async fn health_results_persist_across_restart() {
    let Some(pool) = canonical_pool("restart").await else {
        return;
    };

    let first = service(&pool, "node-a");
    let report = first.check_all().await;
    // The persistence component itself reports healthy on the canonical
    // schema even when sibling checks (e.g. Redis) are degraded.
    let persistence = report
        .components
        .iter()
        .find(|c| c.name == "persistence")
        .expect("check_all must include the persistence readiness component");
    assert_eq!(persistence.status, ha::types::HealthStatus::Healthy);

    // The result row exists with the exact INSERT contract.
    let row: Option<(String, String, serde_json::Value)> = sqlx::query_as(
        "SELECT node_id, status, components FROM ha_health_checks WHERE node_id = 'node-a'",
    )
    .fetch_optional(&pool)
    .await
    .unwrap();
    let (node_id, status, components) = row.expect("health result persisted");
    assert_eq!(node_id, "node-a");
    assert!(!status.is_empty());
    assert!(
        components.as_array().is_some_and(|a| !a.is_empty()),
        "components JSONB carries the per-component report"
    );

    // Restart: a fresh service reads the same cluster status back.
    let restarted = service(&pool, "node-b");
    let cluster = restarted
        .get_cluster_status()
        .await
        .expect("cluster status read");
    assert!(
        cluster.iter().any(|v| v["node_id"] == "node-a"),
        "the persisted result of the previous instance must be readable"
    );

    pool.close().await;
}

/// Retention: cleanup_history removes only results older than the window.
#[tokio::test]
async fn history_retention_cleanup_removes_only_old_rows() {
    let Some(pool) = canonical_pool("retention").await else {
        return;
    };
    sqlx::query(
        "INSERT INTO ha_health_checks (node_id, region, status, components, checked_at) \
         VALUES ('old', 'r', 'healthy', '[]', NOW() - INTERVAL '40 days'), \
                ('new', 'r', 'healthy', '[]', NOW())",
    )
    .execute(&pool)
    .await
    .unwrap();

    let deleted = service(&pool, "node-x")
        .cleanup_history(30)
        .await
        .expect("retention cleanup");
    assert_eq!(deleted, 1);

    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ha_health_checks")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, 1);

    pool.close().await;
}
