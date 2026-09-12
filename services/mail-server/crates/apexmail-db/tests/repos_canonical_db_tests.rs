//! F86/F87 canonical-schema tests for the standalone IncidentRepo and the
//! ADVISORY warmup catalog repository, exercised against the REAL canonical
//! migration chain (resolved_at arrives with migration 198; the advisory
//! `isp_warmup_templates` catalog with migration 042). Gated on
//! `TEST_DATABASE_URL`.
//!
//! The former per-pool execution model was removed (audit item 26): no live
//! path resolves the recipient's provider at admission time, so the ISP
//! schedule cannot be enforced. `isp_warmup_templates` survives as inert
//! reference data and only its CRUD is tested here.

use apexmail_db::repos::incidents::{IncidentRepo, IncidentStatus};
use apexmail_db::repos::warmup::WarmupCatalogRepo;
use sqlx::PgPool;

async fn canonical_pool(db_suffix: &str) -> Option<PgPool> {
    match migrator::test_support::fresh_canonical_pool("apexdb_f86_f87", db_suffix).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
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

// ── F87/audit-26: warmup — ADVISORY catalog only ─────────────────────────────

/// The advisory ISP warmup catalog round-trips CRUD on the canonical
/// migrations. This test intentionally exercises STORAGE ONLY: the former
/// execution model (per-pool/day target/actual rows instantiated from a
/// profile) no longer exists in Rust, because no live path resolves a
/// recipient provider at admission time and therefore cannot enforce an ISP
/// target (see `apexmail_db::repos::warmup`). Storing hostile schedule
/// values here (0/negative) is inert data, not a control.
#[tokio::test]
async fn warmup_catalog_crud_round_trip() {
    let Some(pool) = canonical_pool("warmup").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };

    // Catalog CRUD. The name sorts BEFORE the canonically-seeded "Default"
    // template; nothing in this test derives a limit from it.
    let template = WarmupCatalogRepo::create(
        &pool,
        "isp_f87_test",
        "AaaTestISP",
        serde_json::json!(["*.testisp.com"]),
        // Hostile/advisory schedule values: stored, never interpreted.
        serde_json::json!([0, -1, 40, 80]),
        Some("f87 advisory fixture"),
    )
    .await
    .expect("template create on canonical catalog");
    assert_eq!(template.isp_name, "AaaTestISP");

    let fetched = WarmupCatalogRepo::get_by_isp(&pool, "AaaTestISP")
        .await
        .unwrap()
        .expect("template by isp");
    assert_eq!(fetched.id, "isp_f87_test");
    let by_id = WarmupCatalogRepo::get_by_id(&pool, "isp_f87_test")
        .await
        .unwrap()
        .expect("template by id");
    assert_eq!(by_id.isp_name, "AaaTestISP");

    let all = WarmupCatalogRepo::list(&pool).await.unwrap();
    assert!(
        all.iter().any(|t| t.id == "isp_f87_test"),
        "the advisory template is listed"
    );

    // Update/delete round-trip.
    let updated = WarmupCatalogRepo::update(
        &pool,
        "isp_f87_test",
        serde_json::json!([15, 30]),
        Some("tightened"),
    )
    .await
    .unwrap()
    .expect("template update");
    assert_eq!(updated.warmup_schedule, serde_json::json!([15, 30]));
    assert!(WarmupCatalogRepo::delete(&pool, "isp_f87_test")
        .await
        .unwrap());
    assert!(WarmupCatalogRepo::get_by_id(&pool, "isp_f87_test")
        .await
        .unwrap()
        .is_none());

    pool.close().await;
}
