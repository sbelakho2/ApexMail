//! Canonical-fixture tests for the compliance audit reader and content
//! scanner (audits F76 / F77).
//!
//! Unlike `gdpr_compliance_db_tests.rs` (which creates minimal hand-written
//! table shapes), these tests provision throwaway databases carrying the
//! REAL production migration chain through `migrator::test_support` — so a
//! green test proves the statements work against the 18-column
//! `audit_logs` / 16-column `audit_logs_archive` split and the
//! `content_policies.enabled` column that a deploy actually installs.
//!
//! Coverage:
//! - F76: search / count / stats / export / chain-integrity queries against
//!   empty, live-only, archived-only and mixed data — the exact UNION
//!   column-count failure mode (42601 even when both tables are empty).
//! - F77: the canonical `content_policies.enabled` predicate — an ENABLED
//!   policy affects scan output, a DISABLED one does not, and a policy-store
//!   outage surfaces as an explicit scan error (never a silent empty policy
//!   set stamping the scan clean).
//!
//! Skips unless TEST_DATABASE_URL is set (workspace convention); a
//! CONFIGURED provisioning failure panics (the F01 Result contract).

use compliance::audit_logger::AuditLogger;
use compliance::config::{AuditConfig, ContentScanningConfig};
use compliance::content_scanner::ContentScanner;
use compliance::types::{
    AuditAction, AuditLogQuery, AuditOutcome, AuditResource, EmailContent, LogContext,
};
use sqlx::PgPool;
use std::collections::HashMap;

// ── Canonical fixture ──────────────────────────────────────────────────────

/// A fresh database carrying the complete canonical production schema.
/// `Ok(None)` only when TEST_DATABASE_URL is unset (soft-skip); a
/// configured failure panics (audit F01).
async fn canonical_pool(test_name: &str) -> Option<PgPool> {
    let suffix = format!("compliance_{}", test_name);
    match migrator::test_support::fresh_canonical_pool(test_name, &suffix).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

fn audit_logger(pool: &PgPool) -> AuditLogger {
    AuditLogger::new(
        pool.clone(),
        AuditConfig {
            retention_days: 365,
            hash_chain_enabled: true,
            signing_key: "canonical-test-signing-key-32-chars-min!!".into(),
        },
    )
}

fn context_for(tenant: &str) -> LogContext {
    LogContext {
        tenant_id: Some(tenant.into()),
        user_id: Some(format!("user-{tenant}")),
        session_id: Some("session-1".into()),
        ip_address: Some("10.0.0.1".into()),
        user_agent: Some("canonical-test/1.0".into()),
    }
}

/// Log `n` entries for `tenant` and return their ids.
async fn log_entries(logger: &AuditLogger, tenant: &str, n: usize) -> Vec<String> {
    let ctx = context_for(tenant);
    let mut ids = Vec::with_capacity(n);
    for i in 0..n {
        let entry = logger
            .log(
                AuditAction::Create,
                AuditResource::Subscriber,
                Some(&format!("resource-{i}")),
                serde_json::json!({"i": i}),
                AuditOutcome::Success,
                None,
                &ctx,
            )
            .await
            .expect("audit entry logs against canonical schema");
        ids.push(entry.id);
    }
    ids
}

fn query_for(tenant: &str) -> AuditLogQuery {
    AuditLogQuery {
        tenant_id: Some(tenant.into()),
        user_id: None,
        action: None,
        resource: None,
        resource_id: None,
        start_date: None,
        end_date: None,
        outcome: None,
        limit: Some(100),
        offset: Some(0),
    }
}

// ── F76: search / count / stats / export / integrity across live + archive ──

/// The exact F76 failure mode: every live ∪ archive consumer must succeed
/// against a FRESH canonical database — with both tables empty the old
/// `SELECT *` unions already failed to PREPARE (42601: each UNION query
/// must have the same number of columns).
#[tokio::test]
async fn f76_union_consumers_succeed_on_empty_canonical_tables() {
    let Some(pool) = canonical_pool("f76_empty").await else {
        eprintln!("skipping f76_union_consumers_succeed_on_empty_canonical_tables: TEST_DATABASE_URL not set");
        return;
    };
    let logger = audit_logger(&pool);
    logger.initialize().await.expect("initialize");

    let (entries, total) = logger.query(&query_for("ten-none")).await.expect("query");
    assert_eq!(total, 0);
    assert!(entries.is_empty());

    let stats = logger.get_stats(Some("ten-none")).await.expect("stats");
    assert_eq!(stats["total_entries"], serde_json::json!(0));

    let verification = logger
        .verify_chain(Some("ten-none"), None, None)
        .await
        .expect("verify_chain on empty canonical tables");
    assert!(verification.valid);

    let export = logger
        .export(&query_for("ten-none"), "json")
        .await
        .expect("json export on empty canonical tables");
    assert!(export.data.contains("[]"));

    let csv = logger
        .export(&query_for("ten-none"), "csv")
        .await
        .expect("csv export on empty canonical tables");
    assert!(csv.data.starts_with("id,tenant_id,user_id,"));

    pool.close().await;
}

/// Live-only data: entries logged to the live table are visible to every
/// consumer, and the chain verifies.
#[tokio::test]
async fn f76_live_only_entries_visible_and_chain_valid() {
    let Some(pool) = canonical_pool("f76_live").await else {
        eprintln!(
            "skipping f76_live_only_entries_visible_and_chain_valid: TEST_DATABASE_URL not set"
        );
        return;
    };
    let tenant = "ten_f76_live";
    let logger = audit_logger(&pool);
    logger.initialize().await.expect("initialize");
    log_entries(&logger, tenant, 3).await;

    let (entries, total) = logger.query(&query_for(tenant)).await.expect("query");
    assert_eq!(total, 3);
    assert_eq!(entries.len(), 3);
    // Type-aligned fields survive the projection round-trip.
    assert!(entries
        .iter()
        .all(|entry| entry.tenant_id.as_deref() == Some(tenant)));
    assert!(entries.iter().all(|entry| entry.signature.len() == 64));

    let stats = logger.get_stats(Some(tenant)).await.expect("stats");
    assert_eq!(stats["total_entries"], serde_json::json!(3));
    assert_eq!(stats["by_action"]["create"], serde_json::json!(3));
    assert_eq!(stats["by_resource"]["subscriber"], serde_json::json!(3));
    assert_eq!(stats["by_outcome"]["success"], serde_json::json!(3));

    let verification = logger
        .verify_chain(Some(tenant), None, None)
        .await
        .expect("verify_chain");
    assert!(verification.valid, "{verification:?}");
    assert_eq!(verification.entries_checked, 3);

    pool.close().await;
}

/// Archived-only + mixed data: after `archive()` moves entries to the
/// 16-column archive table they remain visible EXACTLY ONCE, and the chain
/// still verifies across the live/archive boundary with integrity fields
/// unchanged (F76 + the archival copy's explicit column list).
#[tokio::test]
async fn f76_archived_and_mixed_entries_stay_visible_and_integrity_holds() {
    let Some(pool) = canonical_pool("f76_mixed").await else {
        eprintln!("skipping f76_archived_and_mixed_entries_stay_visible_and_integrity_holds: TEST_DATABASE_URL not set");
        return;
    };
    let tenant = "ten_f76_mixed";
    let logger = audit_logger(&pool);
    logger.initialize().await.expect("initialize");

    // Old entries (to be archived) + new entries (stay live).
    let archived_ids = log_entries(&logger, tenant, 2).await;
    let live_ids = log_entries(&logger, tenant, 2).await;
    let hashes_before: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, hash, previous_hash FROM audit_logs WHERE tenant_id = $1 ORDER BY timestamp",
    )
    .bind(tenant)
    .fetch_all(&pool)
    .await
    .expect("live rows before archival");

    let archived = logger
        .archive(chrono::Utc::now() + chrono::Duration::hours(1))
        .await
        .expect("archive against canonical schema");
    assert_eq!(archived, 4, "every entry predates the cutoff");

    let live_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_logs WHERE tenant_id = $1")
            .bind(tenant)
            .fetch_one(&pool)
            .await
            .expect("live count");
    let archive_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_logs_archive WHERE tenant_id = $1")
            .bind(tenant)
            .fetch_one(&pool)
            .await
            .expect("archive count");
    assert_eq!((live_count, archive_count), (0, 4), "archived-only state");

    // Every id is visible EXACTLY once across the union…
    let (entries, total) = logger.query(&query_for(tenant)).await.expect("query");
    assert_eq!(total, 4);
    assert_eq!(entries.len(), 4);
    let mut seen_ids: Vec<&str> = entries.iter().map(|entry| entry.id.as_str()).collect();
    seen_ids.sort_unstable();
    let mut expected: Vec<&str> = archived_ids
        .iter()
        .chain(live_ids.iter())
        .map(String::as_str)
        .collect();
    expected.sort_unstable();
    assert_eq!(seen_ids, expected, "no duplicates, nothing lost");

    // …integrity fields are UNCHANGED by the archival copy (the explicit
    // 16-column list copies the chain columns verbatim).
    let hashes_after: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, hash, previous_hash FROM audit_logs_archive WHERE tenant_id = $1 ORDER BY timestamp",
    )
    .bind(tenant)
    .fetch_all(&pool)
    .await
    .expect("archive rows after archival");
    assert_eq!(hashes_before, hashes_after);

    // Chain verification spans the archive and still succeeds.
    let verification = logger
        .verify_chain(Some(tenant), None, None)
        .await
        .expect("verify_chain across archive");
    assert!(verification.valid, "{verification:?}");
    assert_eq!(verification.entries_checked, 4);

    // Mixed state: log MORE live entries after the archival; counts and
    // stats span both tables.
    log_entries(&logger, tenant, 1).await;
    let stats = logger.get_stats(Some(tenant)).await.expect("stats");
    assert_eq!(stats["total_entries"], serde_json::json!(5));

    let csv = logger
        .export(&query_for(tenant), "csv")
        .await
        .expect("csv export spans live + archive");
    assert!(csv.data.lines().count() >= 6); // header + 5 rows

    pool.close().await;
}

// ── F77: canonical content_policies predicate ──────────────────────────────

fn scanning_config() -> ContentScanningConfig {
    ContentScanningConfig {
        enabled: true,
        ocr_enabled: false,
        spam_threshold: 5.0,
        max_attachment_size: 10 * 1024 * 1024,
        max_ocr_images: 0,
        banned_domains: vec![],
    }
}

fn scan_content(tenant: &str, body: &str) -> EmailContent {
    EmailContent {
        tenant_id: tenant.into(),
        message_id: format!("msg-{tenant}"),
        from_address: "sender@example.com".into(),
        from_display_name: None,
        subject: "canonical policy test".into(),
        text_body: Some(body.into()),
        html_body: None,
        headers: HashMap::from([("message-id".to_string(), "<m@x>".to_string())]),
        attachments: vec![],
    }
}

async fn seed_policy(pool: &PgPool, tenant: &str, name: &str, enabled: bool) {
    sqlx::query(
        "INSERT INTO content_policies (id, tenant_id, name, rules, enabled)
         VALUES ($1, $2, $3, $4::jsonb, $5)",
    )
    .bind(format!("pol_{tenant}_{name}"))
    .bind(tenant)
    .bind(name)
    .bind(serde_json::json!({"blocked_patterns": ["free money offer"]}))
    .bind(enabled)
    .execute(pool)
    .await
    .expect("seed content policy on canonical schema");
}

/// An ENABLED canonical policy affects scan output; a DISABLED one does
/// not (F77: the query targets `enabled`, the column that exists).
#[tokio::test]
async fn f77_enabled_policy_flags_content_and_disabled_does_not() {
    let Some(pool) = canonical_pool("f77_policy").await else {
        eprintln!("skipping f77_enabled_policy_flags_content_and_disabled_does_not: TEST_DATABASE_URL not set");
        return;
    };
    let tenant_enabled = "ten_f77_on";
    let tenant_disabled = "ten_f77_off";
    seed_policy(&pool, tenant_enabled, "strict", true).await;
    seed_policy(&pool, tenant_disabled, "strict", false).await;

    let scanner = ContentScanner::new(pool.clone(), scanning_config());

    // Enabled policy: the blocked pattern produces a policy violation and
    // a suspicious/blocked verdict — the scan entry REALLY evaluated it.
    let flagged = scanner
        .scan_email(&scan_content(
            tenant_enabled,
            "get your free money offer now",
        ))
        .await
        .expect("scan against canonical content_policies");
    assert!(
        !flagged.policy.compliant,
        "enabled policy must affect scan output"
    );
    assert!(flagged
        .policy
        .violations
        .iter()
        .any(|violation| violation.policy == "strict"));

    // Disabled policy: same content, no policy violation from it.
    let clean = scanner
        .scan_email(&scan_content(
            tenant_disabled,
            "get your free money offer now",
        ))
        .await
        .expect("scan with disabled policy");
    assert!(
        clean
            .policy
            .violations
            .iter()
            .all(|violation| violation.policy != "strict"),
        "disabled policy must not affect scan output"
    );

    // Persisted results are retrievable (the scan entry's writer works
    // against the canonical scan_results table).
    let stored = scanner
        .get_result(&flagged.id)
        .await
        .expect("stored scan result readable")
        .expect("scan result was persisted");
    assert_eq!(stored.id, flagged.id);

    pool.close().await;
}

/// A policy-store OUTAGE is an explicit scan failure — never a swallowed
/// empty policy set that would stamp content clean (F77 required change;
/// the L-04 error propagation from policy loading).
#[tokio::test]
async fn f77_policy_store_outage_is_an_explicit_scan_error() {
    let Some(pool) = canonical_pool("f77_outage").await else {
        eprintln!(
            "skipping f77_policy_store_outage_is_an_explicit_scan_error: TEST_DATABASE_URL not set"
        );
        return;
    };
    sqlx::query("DROP TABLE content_policies")
        .execute(&pool)
        .await
        .expect("simulate the policy-store outage");

    let scanner = ContentScanner::new(pool.clone(), scanning_config());
    let result = scanner
        .scan_email(&scan_content("ten_f77_outage", "hello"))
        .await;
    let error = result.expect_err("policy-store outage must fail the scan explicitly");
    assert!(
        error.contains("Failed to fetch tenant policies"),
        "the outage must surface as the policy-load error, got: {error}"
    );

    pool.close().await;
}
