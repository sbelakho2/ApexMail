//! Adversarial DB-backed tests for the retention sweep
//! ([`compliance::retention_sweep`]).
//!
//! The sweeper must stay honest under a hostile deployment: legal holds that
//! must stop unattributable deletions, missing columns/tables, revoked
//! privileges, concurrent row locks that outlast the batch lock timeout, and
//! per-tenant retention overrides that abuse the plan bounds. Every test
//! pins an outcome the report must state truthfully.
//!
//! (The DDL fault injections live in an integration test file on purpose:
//! the `no_runtime_schema_ddl_in_compliance_source` release guard forbids
//! DDL strings anywhere under `crates/compliance/src`.)

use compliance::audit_logger::AuditLogger;
use compliance::config::AuditConfig;
use compliance::retention_sweep::{LegalHoldCheck, RetentionSweeper, SweepStatus};
use sqlx::PgPool;

// ── Bootstrap ───────────────────────────────────────────────────────────────

async fn sweep_db(suffix: &str) -> Option<PgPool> {
    match migrator::test_support::fresh_canonical_pool(
        &format!("sweep_hostile_{suffix}"),
        &format!("sweep_hostile_{suffix}"),
    )
    .await
    {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

/// The owner + unprivileged hostile-role pairing for the PRIVILEGE-failure
/// scenarios (audit 2026-10-02 #12a): the sweeper runs AS the hostile role
/// so a revoked privilege fails with 42501 for real — against a superuser
/// connection `REVOKE ... FROM CURRENT_USER` is a silent no-op.
async fn sweep_hostile_pair(suffix: &str) -> Option<migrator::test_support::HostileDb> {
    match migrator::test_support::fresh_hostile_canonical_pool(
        &format!("sweep_hostile_{suffix}"),
        &format!("sweep_hostile_{suffix}"),
    )
    .await
    {
        Ok(pair) => pair,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

/// An initialized audit logger whose retention never trims anything.
async fn quiet_audit(pool: &PgPool) -> AuditLogger {
    let logger = AuditLogger::new(
        pool.clone(),
        AuditConfig {
            retention_days: 365,
            hash_chain_enabled: true,
            signing_key: "sweep-hostile-audit-key-0123456789abcdef".into(),
        },
    );
    logger.initialize().await.expect("audit init");
    logger
}

async fn seed_tenant(pool: &PgPool, tenant: &str, legal_hold: bool, retention_days: Option<i32>) {
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, legal_hold, retention_days)
         VALUES ($1, 'n', $1, 'free', $2, $3)",
    )
    .bind(tenant)
    .bind(legal_hold)
    .bind(retention_days)
    .execute(pool)
    .await
    .expect("seed tenant");
}

async fn seed_event(pool: &PgPool, tenant: Option<&str>, age_days: i32) {
    sqlx::query(
        "INSERT INTO events (id, tenant_id, event_type, recipient, timestamp)
         VALUES ($1, $2, 'delivered', 'sweep@example.test', NOW() - ($3 || ' days')::interval)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(tenant)
    .bind(age_days.to_string())
    .execute(pool)
    .await
    .expect("seed event");
}

async fn seed_message(pool: &PgPool, tenant: Option<&str>, age_days: i32) {
    sqlx::query(
        "INSERT INTO messages (tenant_id, from_email, to_emails, subject, created_at)
         VALUES ($2, 'sender@example.test', '[\"sweep@example.test\"]'::jsonb, 'sweep',
                 NOW() - ($1 || ' days')::interval)",
    )
    .bind(age_days.to_string())
    .bind(tenant)
    .execute(pool)
    .await
    .expect("seed message");
}

async fn tenant_events_count(pool: &PgPool, tenant: Option<&str>) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE tenant_id IS NOT DISTINCT FROM $1")
        .bind(tenant)
        .fetch_one(pool)
        .await
        .expect("events count")
}

async fn tenant_messages_count(pool: &PgPool, tenant: Option<&str>) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE tenant_id IS NOT DISTINCT FROM $1")
        .bind(tenant)
        .fetch_one(pool)
        .await
        .expect("messages count")
}

fn unique_tenant() -> String {
    format!("t-{}", &uuid::Uuid::new_v4().simple().to_string()[..23])
}

fn category<'a>(
    report: &'a compliance::retention_sweep::RetentionSweepReport,
    store: &str,
) -> &'a compliance::retention_sweep::CategorySweepResult {
    report
        .categories
        .iter()
        .find(|category| category.store == store)
        .unwrap_or_else(|| panic!("{store} must be in the report"))
}

// ── F5: legal holds protect unattributable rows ─────────────────────────────

/// F5: while ANY legal hold is active, rows that cannot be attributed to a
/// tenant (NULL tenant_id) must be KEPT — they might belong to the held
/// tenant. The module doc promises "fall back to keep"; the sweep must honor
/// that for the event stores too, not only for gdpr_exports.
#[tokio::test]
async fn legal_hold_keeps_unattributable_rows_in_event_stores() {
    let Some(pool) = sweep_db("hold_null").await else {
        return;
    };
    let held = unique_tenant();
    let normal = unique_tenant();
    seed_tenant(&pool, &held, true, None).await;
    seed_tenant(&pool, &normal, false, None).await;

    // Expired rows: one for each tenant plus an UNATTRIBUTABLE one.
    seed_message(&pool, Some(&held), 30).await;
    seed_message(&pool, Some(&normal), 30).await;
    seed_message(&pool, None, 30).await;
    // Fresh rows survive everywhere.
    seed_message(&pool, Some(&held), 0).await;
    seed_message(&pool, Some(&normal), 0).await;
    seed_message(&pool, None, 0).await;

    let audit = quiet_audit(&pool).await;
    let report = RetentionSweeper::new(pool.clone(), 7, 30, 365)
        .run_sweep(&audit)
        .await
        .expect("sweep runs");

    let messages = category(&report, "messages");
    assert_eq!(messages.status, SweepStatus::Deleted);
    assert_eq!(
        messages.skipped_legal_hold, 1,
        "the held tenant's expired row"
    );
    assert_eq!(messages.deleted, 1, "only the normal tenant's expired row");

    assert_eq!(
        tenant_messages_count(&pool, Some(&held)).await,
        2,
        "the held tenant keeps its fresh row AND the expired one"
    );
    assert_eq!(
        tenant_messages_count(&pool, Some(&normal)).await,
        1,
        "only fresh row kept"
    );
    assert_eq!(
        tenant_messages_count(&pool, None).await,
        2,
        "an unattributable row MUST be kept while a hold is active"
    );
    let expired_null: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM messages WHERE tenant_id IS NULL AND created_at < NOW() - INTERVAL '20 days'",
    )
    .fetch_one(&pool)
    .await
    .expect("expired null rows");
    assert_eq!(
        expired_null, 1,
        "the EXPIRED unattributable row is the one kept"
    );
    // The events store is unaffected but swept at its own cutoff.
    assert_eq!(category(&report, "events").status, SweepStatus::Deleted);
}

// ── Schema drift: skipped stores, missing tenants table ─────────────────────

/// A timestamp column absent from this deployment is a SKIPPED store —
/// reported with the error, never counted as deleted, and never fatal for
/// the other targets.
#[tokio::test]
async fn missing_timestamp_column_reports_skipped_store() {
    let Some(pool) = sweep_db("missing_column").await else {
        return;
    };
    let tenant = unique_tenant();
    seed_tenant(&pool, &tenant, false, None).await;
    seed_event(&pool, Some(&tenant), 40).await;
    seed_message(&pool, Some(&tenant), 40).await;

    sqlx::query("ALTER TABLE messages RENAME COLUMN created_at TO created_at_swept")
        .execute(&pool)
        .await
        .expect("rename column");

    let audit = quiet_audit(&pool).await;
    let report = RetentionSweeper::new(pool.clone(), 7, 30, 365)
        .run_sweep(&audit)
        .await
        .expect("sweep runs");

    let messages = category(&report, "messages");
    assert_eq!(
        messages.status,
        SweepStatus::SkippedMissingStore,
        "{messages:?}"
    );
    assert_eq!(messages.deleted, 0);
    assert!(
        messages
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("created_at"),
        "{messages:?}"
    );
    // Events (untouched schema) still swept honestly.
    let events = category(&report, "events");
    assert_eq!(events.status, SweepStatus::Deleted);
    assert_eq!(events.deleted, 1);
    assert_eq!(
        tenant_messages_count(&pool, Some(&tenant)).await,
        1,
        "row kept"
    );
    // The run itself still persisted a report.
    let persisted: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM retention_report")
        .fetch_one(&pool)
        .await
        .expect("report rows");
    assert_eq!(persisted, 1);
}

/// No tenants table at all: the sweep degrades to flat defaults and says so
/// via LegalHoldCheck::TenantsTableMissing — and every batched delete still
/// runs (the LIMIT placeholder must match the bound parameters).
#[tokio::test]
async fn missing_tenants_table_degrades_to_flat_defaults() {
    let Some(pool) = sweep_db("no_tenants").await else {
        return;
    };
    seed_message(&pool, None, 30).await;
    sqlx::query("DROP TABLE tenants CASCADE")
        .execute(&pool)
        .await
        .expect("drop tenants");

    let audit = quiet_audit(&pool).await;
    let report = RetentionSweeper::new(pool.clone(), 7, 30, 365)
        .run_sweep(&audit)
        .await
        .expect("sweep runs");

    assert_eq!(report.plan_tier, "default");
    for category in &report.categories {
        assert_eq!(
            category.legal_hold_check,
            LegalHoldCheck::TenantsTableMissing
        );
        assert_eq!(category.zero_retention_tenants, 0);
        assert_eq!(category.custom_retention_tenants, 0);
    }
    // Without a tenants table there are no holds to consult: the default
    // cutoff sweeps even unattributed rows.
    let messages = category(&report, "messages");
    assert_eq!(
        messages.status,
        SweepStatus::Deleted,
        "flat-default sweep must delete: {messages:?}"
    );
    assert_eq!(messages.deleted, 1, "{messages:?}");
    assert_eq!(tenant_messages_count(&pool, None).await, 0);
}

/// Pre-migration-121 tenants (no legal_hold / retention_days columns): the
/// base read degrades to (id, plan) and the sweep proceeds.
#[tokio::test]
async fn tenants_without_new_columns_still_sweep_with_defaults() {
    let Some(pool) = sweep_db("old_tenants").await else {
        return;
    };
    let tenant = unique_tenant();
    sqlx::query("INSERT INTO tenants (id, name, slug, plan) VALUES ($1, 'n', $1, 'free')")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("tenant");
    seed_event(&pool, Some(&tenant), 40).await;

    sqlx::query("ALTER TABLE tenants DROP COLUMN legal_hold")
        .execute(&pool)
        .await
        .expect("drop legal_hold");
    sqlx::query("ALTER TABLE tenants DROP COLUMN retention_days")
        .execute(&pool)
        .await
        .expect("drop retention_days");

    let audit = quiet_audit(&pool).await;
    let report = RetentionSweeper::new(pool.clone(), 7, 30, 365)
        .run_sweep(&audit)
        .await
        .expect("sweep runs");

    assert_eq!(report.plan_tier, "default", "no overrides could be read");
    let events = category(&report, "events");
    assert_eq!(events.status, SweepStatus::Deleted);
    assert_eq!(
        events.deleted, 1,
        "the expired row is swept at the plan-tier default"
    );
    assert_eq!(tenant_events_count(&pool, Some(&tenant)).await, 0);
}

// ── Zero-retention overlay degradation ───────────────────────────────────────

/// The zero-retention overlay degrades when its table is absent or
/// unreadable — the purge must never stall on the enterprise table.
#[tokio::test]
async fn zero_retention_overlay_degrades_when_absent_or_unreadable() {
    // Absent table.
    let Some(pool) = sweep_db("no_overlay").await else {
        return;
    };
    let tenant = unique_tenant();
    seed_tenant(&pool, &tenant, false, None).await;
    seed_event(&pool, Some(&tenant), 40).await;
    sqlx::query("DROP TABLE ent_compliance_configs")
        .execute(&pool)
        .await
        .expect("drop overlay");
    let audit = quiet_audit(&pool).await;
    let report = RetentionSweeper::new(pool.clone(), 7, 30, 365)
        .run_sweep(&audit)
        .await
        .expect("sweep runs");
    let events = category(&report, "events");
    assert_eq!(events.status, SweepStatus::Deleted);
    assert_eq!(events.zero_retention_tenants, 0);
    assert_eq!(tenant_events_count(&pool, Some(&tenant)).await, 0);

    // Unreadable table (privilege failure). Audit #12a: the sweeper runs AS
    // the unprivileged hostile role and the OWNER revokes the overlay read
    // from THAT role — a superuser's `REVOKE ... FROM CURRENT_USER` would be
    // a silent no-op and the "degradation" would prove nothing.
    let Some(pair) = sweep_hostile_pair("locked_overlay").await else {
        return;
    };
    let (owner, pool) = (pair.owner, pair.hostile);
    let tenant = unique_tenant();
    seed_tenant(&owner, &tenant, false, None).await;
    seed_event(&owner, Some(&tenant), 40).await;
    sqlx::query(&format!(
        r#"REVOKE SELECT ON ent_compliance_configs FROM "{}""#,
        pair.role
    ))
    .execute(&owner)
    .await
    .expect("revoke overlay");
    let audit = quiet_audit(&pool).await;
    let report = RetentionSweeper::new(pool.clone(), 7, 30, 365)
        .run_sweep(&audit)
        .await
        .expect("sweep runs");
    let events = category(&report, "events");
    assert_eq!(events.status, SweepStatus::Deleted);
    assert_eq!(events.zero_retention_tenants, 0);
    assert_eq!(tenant_events_count(&owner, Some(&tenant)).await, 0);
}

// ── Privilege failures and degraded optional stores ─────────────────────────

/// A non-schema privilege failure on a store is a FAILED target — the report
/// says so with the error, and other stores still sweep.
///
/// Audit 2026-10-02 #12a: the sweeper runs AS the unprivileged hostile role
/// and the OWNER revokes the events read from THAT role, so the failure is a
/// genuine 42501 (a superuser's `REVOKE ... FROM CURRENT_USER` is a no-op).
#[tokio::test]
async fn privilege_failure_fails_the_target_without_stalling_the_run() {
    let Some(pair) = sweep_hostile_pair("revoked_events").await else {
        return;
    };
    let (owner, pool) = (pair.owner, pair.hostile);
    let tenant = unique_tenant();
    seed_tenant(&owner, &tenant, false, None).await;
    seed_event(&owner, Some(&tenant), 40).await;

    sqlx::query(&format!(r#"REVOKE SELECT ON events FROM "{}""#, pair.role))
        .execute(&owner)
        .await
        .expect("revoke");

    let audit = quiet_audit(&pool).await;
    let report = RetentionSweeper::new(pool.clone(), 7, 30, 365)
        .run_sweep(&audit)
        .await
        .expect("sweep runs");

    let events = category(&report, "events");
    assert_eq!(events.status, SweepStatus::Failed, "{events:?}");
    assert!(events.error.is_some());
    assert_eq!(
        events.deleted, 0,
        "nothing may be deleted once the store failed"
    );
    // Messages swept at its own cutoff regardless.
    assert_eq!(category(&report, "messages").status, SweepStatus::Deleted);
}

/// Missing exports/archive stores degrade the REPORT (zeros / -1) and never
/// abort the run.
#[tokio::test]
async fn degraded_optional_stores_are_reported_not_fatal() {
    let Some(pool) = sweep_db("degraded").await else {
        return;
    };
    let tenant = unique_tenant();
    seed_tenant(&pool, &tenant, false, None).await;
    seed_event(&pool, Some(&tenant), 40).await;

    sqlx::query("DROP TABLE gdpr_exports")
        .execute(&pool)
        .await
        .expect("drop exports");
    sqlx::query("DROP TABLE audit_logs_archive")
        .execute(&pool)
        .await
        .expect("drop archive target");
    sqlx::query("DROP TABLE legal_retention_archive")
        .execute(&pool)
        .await
        .expect("drop legal archive");

    let audit = quiet_audit(&pool).await;
    let report = RetentionSweeper::new(pool.clone(), 7, 30, 365)
        .run_sweep(&audit)
        .await
        .expect("sweep runs");

    assert_eq!(report.gdpr_exports_deleted, 0);
    assert_eq!(
        report.audit_logs_archived, -1,
        "the archive failure is reported as -1"
    );
    assert_eq!(report.archive_expired, 0);
    assert_eq!(report.archive_deleted, 0);
    // The canonical event stores still swept and the report persisted.
    let events = category(&report, "events");
    assert_eq!(events.status, SweepStatus::Deleted);
    assert_eq!(events.deleted, 1);
    let persisted: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM retention_report")
        .fetch_one(&pool)
        .await
        .expect("report rows");
    assert_eq!(persisted, 1);
}

// ── Concurrency: row locks outlasting the batch lock timeout ────────────────

/// A concurrent row lock outlasting the per-batch lock timeout fails the
/// target; rows deleted by earlier batches are still reported, and the rest
/// of the sweep continues.
#[tokio::test]
async fn row_lock_timeout_fails_the_target_and_preserves_counts() {
    let Some(pool) = sweep_db("locked_rows").await else {
        return;
    };
    let tenant = unique_tenant();
    seed_tenant(&pool, &tenant, false, None).await;
    seed_event(&pool, Some(&tenant), 40).await;
    seed_event(&pool, Some(&tenant), 5).await;

    // Hold row locks on every expired events row from a separate transaction.
    let mut holder = pool.begin().await.expect("holder transaction");
    sqlx::query("SELECT id FROM events WHERE timestamp < NOW() FOR UPDATE")
        .fetch_all(&mut *holder)
        .await
        .expect("lock rows");

    let audit = quiet_audit(&pool).await;
    let report = RetentionSweeper::new(pool.clone(), 7, 30, 365)
        .run_sweep(&audit)
        .await
        .expect("sweep runs");
    holder.rollback().await.expect("release locks");

    let events = category(&report, "events");
    assert_eq!(events.status, SweepStatus::Failed, "{events:?}");
    assert!(
        events
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("lock timeout"),
        "the lock timeout is the failure: {events:?}"
    );
    assert_eq!(events.considered, 1, "the expired row was considered");
    assert_eq!(
        events.deleted, 0,
        "the locked row survived the failed batch"
    );
    assert_eq!(
        tenant_events_count(&pool, Some(&tenant)).await,
        2,
        "nothing deleted"
    );
    // Messages unaffected.
    assert_eq!(category(&report, "messages").status, SweepStatus::Deleted);
}

// ── Per-tenant overrides ─────────────────────────────────────────────────────

/// Per-tenant overrides build SEPARATE windows in one sweep: an in-bounds
/// short override purges sooner, an in-bounds long override KEEPS rows the
/// default would purge, and the plan tier reports per-tenant.
#[tokio::test]
async fn distinct_overrides_drive_distinct_cutoffs_in_one_sweep() {
    let Some(pool) = sweep_db("override_groups").await else {
        return;
    };
    let short = unique_tenant(); // free, 5d (cap 7)
    let long = unique_tenant(); // pro, 90d
    let flat = unique_tenant(); // free, no override
    sqlx::query("INSERT INTO tenants (id, name, slug, plan, legal_hold, retention_days) VALUES ($1,'n',$1,'free',false,5)")
        .bind(&short)
        .execute(&pool)
        .await
        .expect("short tenant");
    sqlx::query("INSERT INTO tenants (id, name, slug, plan, legal_hold, retention_days) VALUES ($1,'n',$1,'pro',false,90)")
        .bind(&long)
        .execute(&pool)
        .await
        .expect("long tenant");
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, legal_hold) VALUES ($1,'n',$1,'free',false)",
    )
    .bind(&flat)
    .execute(&pool)
    .await
    .expect("flat tenant");

    // A 6-day-old row: inside the long window, past the short one, inside
    // the default window.
    seed_event(&pool, Some(&short), 6).await;
    seed_event(&pool, Some(&long), 6).await;
    seed_event(&pool, Some(&flat), 6).await;
    // A 35-day-old row: past the default (30d), inside the 90d window.
    seed_event(&pool, Some(&long), 35).await;
    seed_event(&pool, Some(&flat), 35).await;

    let audit = quiet_audit(&pool).await;
    let report = RetentionSweeper::new(pool.clone(), 7, 30, 365)
        .run_sweep(&audit)
        .await
        .expect("sweep runs");

    let events = category(&report, "events");
    assert_eq!(events.status, SweepStatus::Deleted);
    assert_eq!(
        events.custom_retention_tenants, 2,
        "both in-bounds overrides honored"
    );
    // Deleted: short's 6d row (5d override) and flat's 35d row (30d default).
    // flat's 6d row is inside the default window; long keeps BOTH rows
    // inside its 90d window.
    assert_eq!(events.deleted, 2, "{events:?}");
    assert_eq!(report.plan_tier, "per-tenant");

    assert_eq!(tenant_events_count(&pool, Some(&short)).await, 0);
    assert_eq!(
        tenant_events_count(&pool, Some(&long)).await,
        2,
        "both rows survive the 90d override window"
    );
    assert_eq!(
        tenant_events_count(&pool, Some(&flat)).await,
        1,
        "the 6-day-old row is inside the 30d default window"
    );
}

/// A negative tenants.retention_days can never shorten or extend a window:
/// it falls back to the plan-tier default.
#[tokio::test]
async fn negative_retention_override_falls_back_to_plan_default() {
    let Some(pool) = sweep_db("negative_override").await else {
        return;
    };
    let tenant = unique_tenant();
    seed_tenant(&pool, &tenant, false, Some(-5)).await;
    // Past the default (30d): swept.
    seed_event(&pool, Some(&tenant), 40).await;
    // Inside the default: kept.
    seed_event(&pool, Some(&tenant), 5).await;

    let audit = quiet_audit(&pool).await;
    let report = RetentionSweeper::new(pool.clone(), 7, 30, 365)
        .run_sweep(&audit)
        .await
        .expect("sweep runs");

    let events = category(&report, "events");
    assert_eq!(events.status, SweepStatus::Deleted);
    assert_eq!(
        events.custom_retention_tenants, 0,
        "a negative override is not an override"
    );
    assert_eq!(events.deleted, 1, "rows are judged at the 30d default");
    assert_eq!(tenant_events_count(&pool, Some(&tenant)).await, 1);
}

// ── gdpr_exports / DSR outbox purges under hold ─────────────────────────────

/// The gdpr_exports / DSR outbox purges exclude held tenants while deleting
/// everyone else's expired rows.
#[tokio::test]
async fn export_and_outbox_purges_respect_legal_holds() {
    let Some(pool) = sweep_db("hold_exports").await else {
        return;
    };
    let held = unique_tenant();
    let normal = unique_tenant();
    seed_tenant(&pool, &held, true, None).await;
    seed_tenant(&pool, &normal, false, None).await;

    for (tenant, age) in [(&held, "40 days"), (&normal, "40 days"), (&held, "0 days")] {
        sqlx::query(
            "INSERT INTO gdpr_exports (id, request_id, tenant_id, email, data, export_url, expires_at, created_at)
             VALUES ($1, 'r', $2, 'e@example.test', '{}'::jsonb, 'u', NOW() + INTERVAL '1 day',
                     NOW() - $3::interval)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(tenant)
        .bind(age)
        .execute(&pool)
        .await
        .expect("export");
        sqlx::query(
            "INSERT INTO dsr_verification_outbox
               (id, request_id, tenant_id, email, verification_token, verify_url, status, attempts, created_at)
             VALUES ($1, 'r', $2, 'e@example.test', 'tok', 'u', 'pending', 0, NOW() - $3::interval)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(tenant)
        .bind(age)
        .execute(&pool)
        .await
        .expect("outbox");
    }

    let audit = quiet_audit(&pool).await;
    let report = RetentionSweeper::new(pool.clone(), 7, 30, 365)
        .run_sweep(&audit)
        .await
        .expect("sweep runs");

    assert_eq!(
        report.gdpr_exports_deleted, 1,
        "only the unheld tenant's export"
    );
    assert_eq!(
        report.dsr_outbox_purged, 1,
        "only the unheld tenant's outbox row"
    );
    let held_exports: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM gdpr_exports WHERE tenant_id = $1")
            .bind(&held)
            .fetch_one(&pool)
            .await
            .expect("held exports");
    assert_eq!(held_exports, 2, "expired AND fresh held exports survive");
    let held_outbox: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM dsr_verification_outbox WHERE tenant_id = $1")
            .bind(&held)
            .fetch_one(&pool)
            .await
            .expect("held outbox");
    assert_eq!(
        held_outbox, 2,
        "the raw token must not be purged under hold"
    );
}
