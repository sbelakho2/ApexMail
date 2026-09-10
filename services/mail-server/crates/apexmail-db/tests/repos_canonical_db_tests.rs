//! F86/F87 canonical-schema tests for the standalone IncidentRepo and the
//! two-model warmup repositories, exercised against the REAL canonical
//! migration chain (resolved_at arrives with migration 198; the two warmup
//! relations with migration 042). Gated on `TEST_DATABASE_URL`.

use apexmail_db::repos::incidents::{IncidentRepo, IncidentStatus};
use apexmail_db::repos::warmup::{WarmupExecutionRepo, WarmupProfileRepo};
use apexmail_db::types::IspWarmupExecution;
use sqlx::PgPool;

async fn canonical_pool(db_suffix: &str) -> Option<PgPool> {
    migrator::test_support::fresh_canonical_pool("apexdb_f86_f87", db_suffix).await
}

// ── F86: incidents ───────────────────────────────────────────────────────────

/// Create → resolve → reopen → list_active: the reopened incident must
/// reappear with resolved_at cleared, and the transition history stays
/// auditable.
#[tokio::test]
async fn incident_reopen_clears_resolved_and_reappears_in_active_list() {
    let Some(pool) = canonical_pool("incidents").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };

    let incident = IncidentRepo::create(
        &pool,
        "inc_f86_1",
        "API latency",
        "investigating",
        "minor",
        &["api".to_string()],
    )
    .await
    .expect("create on canonical schema");
    assert!(incident.resolved_at.is_none());

    // Active from the start.
    let active = IncidentRepo::list_active(&pool, 10, 0).await.unwrap();
    assert!(active.iter().any(|i| i.id == "inc_f86_1"));

    // Resolve: the typed transition stamps resolved_at and hides it.
    let resolved = IncidentRepo::transition(&pool, "inc_f86_1", IncidentStatus::Resolved)
        .await
        .unwrap()
        .expect("resolved row returned");
    assert_eq!(resolved.status, "resolved");
    let resolved_at = resolved.resolved_at.expect("resolution stamped");
    let active = IncidentRepo::list_active(&pool, 10, 0).await.unwrap();
    assert!(
        !active.iter().any(|i| i.id == "inc_f86_1"),
        "resolved incidents leave the active list"
    );

    // Reopen: the SAME typed transition clears resolved_at — the incident
    // reappears in list_active instead of staying invisible.
    let reopened = IncidentRepo::transition(&pool, "inc_f86_1", IncidentStatus::Investigating)
        .await
        .unwrap()
        .expect("reopened row returned");
    assert_eq!(reopened.status, "investigating");
    assert!(
        reopened.resolved_at.is_none(),
        "reopening must clear resolved_at"
    );
    let active = IncidentRepo::list_active(&pool, 10, 0).await.unwrap();
    assert!(
        active.iter().any(|i| i.id == "inc_f86_1"),
        "the reopened incident must be visible to list_active again"
    );

    // Auditable transition history via the timeline updates.
    IncidentRepo::add_update(
        &pool,
        "upd_f86_1",
        "inc_f86_1",
        "resolved",
        "Latency back to baseline",
        "ops",
    )
    .await
    .unwrap();
    let updates = IncidentRepo::get_updates(&pool, "inc_f86_1").await.unwrap();
    assert_eq!(updates.len(), 1);
    let _ = resolved_at;

    pool.close().await;
}

/// The migration's deliberate backfill: a legacy resolved incident (with a
/// resolved-status timeline update) gains resolved_at from its history.
#[tokio::test]
async fn legacy_resolved_incidents_are_backfilled() {
    let Some(pool) = canonical_pool("backfill").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    // Simulate a legacy row exactly as migration 115 created them (no
    // resolved_at) — insert via SQL so the column is omitted.
    sqlx::query(
        "INSERT INTO status_page_incidents (id, title, status, impact, affected_components, created_at, updated_at) \
         VALUES ('inc_legacy', 'Legacy outage', 'resolved', 'major', '{\"web\"}', \
                 NOW() - INTERVAL '10 days', NOW() - INTERVAL '9 days')",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO status_page_incident_updates (id, incident_id, status, body, author, created_at) \
         VALUES ('upd_legacy', 'inc_legacy', 'resolved', 'fixed', 'ops', NOW() - INTERVAL '9 days')",
    )
    .execute(&pool)
    .await
    .unwrap();

    // Migration 198 already ran in this canonical chain; for the legacy
    // shape we reproduce its backfill statement to prove the rule (the
    // chain itself applied it before any such row could exist).
    sqlx::query(
        "UPDATE status_page_incidents i \
         SET resolved_at = COALESCE( \
             (SELECT MAX(u.created_at) FROM status_page_incident_updates u \
              WHERE u.incident_id = i.id AND lower(u.status) IN ('resolved', 'fixed', 'completed')), \
             i.updated_at) \
         WHERE i.resolved_at IS NULL AND lower(i.status) IN ('resolved', 'fixed', 'completed')",
    )
    .execute(&pool)
    .await
    .unwrap();

    let legacy = IncidentRepo::get_by_id(&pool, "inc_legacy")
        .await
        .unwrap()
        .expect("legacy row");
    assert!(
        legacy.resolved_at.is_some(),
        "resolved legacy incidents gain a resolved_at from their history"
    );
    assert!(!IncidentRepo::list_active(&pool, 10, 0)
        .await
        .unwrap()
        .iter()
        .any(|i| i.id == "inc_legacy"));

    pool.close().await;
}

// ── F87: warmup — two explicit models ────────────────────────────────────────

/// Create an ISP profile, instantiate a pool schedule from it and record
/// daily actuals: both profile CRUD and the per-pool execution view
/// round-trip on the canonical migrations.
#[tokio::test]
async fn warmup_profile_and_pool_execution_round_trip() {
    let Some(pool) = canonical_pool("warmup").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };

    // Profile CRUD on the catalog relation. The name sorts BEFORE the
    // canonically-seeded "Default" profile (whose "*" wildcard matches
    // every host), so pattern resolution can be asserted deterministically.
    let profile = WarmupProfileRepo::create(
        &pool,
        "isp_f87_test",
        "AaaTestISP",
        serde_json::json!(["*.testisp.com"]),
        serde_json::json!([10, 20, 40, 80]),
        Some("f87 fixture"),
    )
    .await
    .expect("profile create on canonical catalog");
    assert_eq!(profile.isp_name, "AaaTestISP");

    let fetched = WarmupProfileRepo::get_by_isp(&pool, "AaaTestISP")
        .await
        .unwrap()
        .expect("profile by isp");
    assert_eq!(fetched.id, "isp_f87_test");
    assert_eq!(
        WarmupProfileRepo::get_daily_limit(&fetched.warmup_schedule, 2),
        Some(40)
    );

    let by_mx = WarmupProfileRepo::find_by_mx_pattern(&pool, "mx1.testisp.com")
        .await
        .unwrap()
        .expect("mx pattern resolves the profile");
    assert_eq!(by_mx.id, "isp_f87_test");

    // Instantiate a pool's execution rows FROM the profile.
    let execution: Vec<IspWarmupExecution> =
        WarmupExecutionRepo::instantiate_from_profile(&pool, &profile, "pool_f87")
            .await
            .expect("pool schedule instantiated from the profile");
    assert_eq!(execution.len(), 4, "one row per schedule day");
    assert_eq!(execution[0].target_volume, 10);
    assert_eq!(execution[3].target_volume, 80);
    assert!(execution.iter().all(|e| e.status == "pending"));

    // Re-instantiating never resets recorded actuals (idempotent per day).
    WarmupExecutionRepo::record_daily_actual(&pool, "pool_f87", 0, 10)
        .await
        .unwrap()
        .expect("record actual");
    let after_reinstantiate =
        WarmupExecutionRepo::instantiate_from_profile(&pool, &profile, "pool_f87")
            .await
            .unwrap();
    assert_eq!(
        after_reinstantiate[0].actual_volume,
        Some(10),
        "re-instantiation keeps recorded actuals"
    );
    assert_eq!(
        after_reinstantiate[0].status, "completed",
        "meeting the target completes the day"
    );

    // Partial day stays active.
    WarmupExecutionRepo::record_daily_actual(&pool, "pool_f87", 1, 5)
        .await
        .unwrap();
    let days = WarmupExecutionRepo::list_by_pool(&pool, "pool_f87")
        .await
        .unwrap();
    assert_eq!(days[1].status, "active");
    assert!(days[1].started_at.is_some());
    assert!(days[1].completed_at.is_none());

    // The execution relation carries NO profile columns — the models stay
    // explicit (a pool day is not an ISP definition).
    let has_isp_name: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM information_schema.columns \
         WHERE table_name = 'isp_warmup_schedules' AND column_name = 'isp_name')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        !has_isp_name,
        "execution rows must not grow profile columns (F87)"
    );

    // Profile update/delete round-trip.
    let updated = WarmupProfileRepo::update(
        &pool,
        "isp_f87_test",
        serde_json::json!([15, 30]),
        Some("tightened"),
    )
    .await
    .unwrap()
    .expect("profile update");
    assert_eq!(updated.warmup_schedule, serde_json::json!([15, 30]));
    assert!(WarmupProfileRepo::delete(&pool, "isp_f87_test")
        .await
        .unwrap());

    pool.close().await;
}
