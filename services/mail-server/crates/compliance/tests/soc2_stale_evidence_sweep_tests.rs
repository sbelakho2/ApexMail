//! DB-backed tests for the SOC 2 stale-attestation sweep (external audit 6
//! remediation #16: "no recurring system automatically sweeps all
//! next_attestation_at controls").
//!
//! Same harness as `soc2_evidence_integrity_tests.rs`: gated on
//! `TEST_DATABASE_URL` via `migrator::test_support::fresh_canonical_pool`
//! (each test provisions its OWN throwaway clone of the canonical migration
//! chain); with the variable unset every test soft-skips; a configured
//! provisioning failure panics.
//!
//! Coverage:
//! * the PURE query — a freshly seeded catalog is entirely unattested and
//!   every in-scope control is flagged with its full missing set; a fully
//!   evidenced control is not; deferred / not-applicable controls are not;
//!   a past `next_attestation_at` and a stale evidence row each drive
//!   `days_overdue`;
//! * the SWEEP — findings are persisted as `stale_attestation_sweep` run
//!   rows, the summary counts match, detection is idempotent, and DB errors
//!   (a broken store, a malformed `evidence_required`) PROPAGATE.

use chrono::{Duration, Utc};
use compliance::soc2::{Soc2Service, StaleControlFinding};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

async fn test_pool(test_name: &str) -> Option<PgPool> {
    match migrator::test_support::fresh_canonical_pool(
        &format!("soc2_{test_name}"),
        &format!("soc2_{test_name}"),
    )
    .await
    {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

fn payload_hash(payload: &serde_json::Value) -> String {
    let canonical = serde_json::to_string(payload).expect("serialize payload");
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

/// Insert a row directly (test setup), bypassing `record_evidence` so the
/// test can control `collected_at`.
async fn insert_evidence_raw(
    pool: &PgPool,
    id: &str,
    control_id: &str,
    evidence_type: &str,
    payload: serde_json::Value,
    collected_at: chrono::DateTime<Utc>,
) {
    sqlx::query(
        "INSERT INTO soc2_control_evidence
           (id, control_id, evidence_type, source, payload, sha256_hash,
            storage_url, period_start, period_end, collected_at, collected_by)
         VALUES ($1,$2,$3,'test',$4,$5,NULL,$6,$7,$8,'test')",
    )
    .bind(id)
    .bind(control_id)
    .bind(evidence_type)
    .bind(&payload)
    .bind(payload_hash(&payload))
    .bind(collected_at - Duration::hours(1))
    .bind(collected_at)
    .bind(collected_at)
    .execute(pool)
    .await
    .expect("insert raw evidence");
}

fn finding_for<'a>(
    findings: &'a [StaleControlFinding],
    control_id: &str,
) -> Option<&'a StaleControlFinding> {
    findings.iter().find(|f| f.control_id == control_id)
}

#[tokio::test]
async fn seeded_catalog_flags_every_unattested_in_scope_control() {
    let Some(pool) = test_pool("stale_seed").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run the stale-evidence sweep tests");
        return;
    };
    let soc2 = Soc2Service::new(pool.clone());
    soc2.seed_default_controls().await.expect("seed controls");

    let findings = soc2
        .stale_evidence_controls(Utc::now())
        .await
        .expect("stale query");
    // Every in-scope control starts UNATTESTED (migration 274 cleared the
    // one-item attestations), so the whole catalog must be flagged with its
    // full required set in `missing` — no required type has any row.
    assert!(
        findings.len() >= 20,
        "a fresh seed must flag the whole catalog, got {}",
        findings.len()
    );
    for finding in &findings {
        assert!(
            !finding.missing.is_empty(),
            "{} must list its missing evidence types: {finding:?}",
            finding.control_id
        );
        assert!(
            finding.stale.is_empty() && finding.invalid.is_empty(),
            "no evidence rows exist, so nothing can be stale or invalid: {finding:?}"
        );
        assert_eq!(
            finding.days_overdue, 0,
            "a never-evidenced control has no due date to be overdue against"
        );
        assert!(finding.next_attestation_at.is_none());
    }
    // Spot-check one known control: CC2.1 requires both types.
    let cc21 = finding_for(&findings, "CC2.1").expect("CC2.1 flagged");
    assert!(cc21.missing.contains(&"audit_log_sample".to_string()));
    assert!(cc21
        .missing
        .contains(&"audit_chain_verification".to_string()));
}

#[tokio::test]
async fn fully_evidenced_control_is_not_flagged() {
    let Some(pool) = test_pool("stale_fresh").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run the stale-evidence sweep tests");
        return;
    };
    let soc2 = Soc2Service::new(pool.clone());
    soc2.seed_default_controls().await.expect("seed controls");

    let now = Utc::now();
    for evidence_type in ["audit_log_sample", "audit_chain_verification"] {
        soc2.record_evidence(
            "CC2.1",
            evidence_type,
            "test",
            json!({"evidence_type": evidence_type}),
            now - Duration::hours(1),
            now,
            "test",
        )
        .await
        .expect("evidence");
    }
    let state = soc2
        .recompute_attestation("CC2.1")
        .await
        .expect("recompute");
    assert!(state.attested, "full fresh set attests: {state:?}");

    let findings = soc2
        .stale_evidence_controls(Utc::now())
        .await
        .expect("stale query");
    assert!(
        finding_for(&findings, "CC2.1").is_none(),
        "an attested control inside its cadence is not stale: {findings:?}"
    );
}

#[tokio::test]
async fn past_next_attestation_is_flagged_with_days_overdue() {
    let Some(pool) = test_pool("stale_overdue").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run the stale-evidence sweep tests");
        return;
    };
    let soc2 = Soc2Service::new(pool.clone());
    soc2.seed_default_controls().await.expect("seed controls");

    // The audit's exact scenario: an attestation whose deadline passed while
    // nothing recomputed it (drifted timestamps, evidence long gone).
    sqlx::query(
        "UPDATE soc2_controls
         SET last_attested_at = NOW() - INTERVAL '100 days',
             next_attestation_at = NOW() - INTERVAL '10 days'
         WHERE control_id = 'CC6.2'",
    )
    .execute(&pool)
    .await
    .expect("backdate attestation");

    let findings = soc2
        .stale_evidence_controls(Utc::now())
        .await
        .expect("stale query");
    let finding = finding_for(&findings, "CC6.2").expect("overdue control flagged");
    // 10 days by construction; ±1 absorbs the SQL-NOW()/Utc::now() clock
    // race across the truncating num_days().
    assert!(
        (9..=11).contains(&finding.days_overdue),
        "expected ~10 days overdue: {finding:?}"
    );
    assert!(
        finding.missing.contains(&"quarterly_access_review".to_string()),
        "the evidence row is gone, so the type is missing: {finding:?}"
    );
}

#[tokio::test]
async fn stale_evidence_row_drives_days_overdue_without_attestation_date() {
    let Some(pool) = test_pool("stale_row").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run the stale-evidence sweep tests");
        return;
    };
    let soc2 = Soc2Service::new(pool.clone()).with_attestation_period(30);
    soc2.seed_default_controls().await.expect("seed controls");

    // CC6.2 requires one manual evidence type; collected 60 days ago under a
    // 30-day cadence → 30 days past the row's own freshness deadline.
    insert_evidence_raw(
        &pool,
        "ev-cc62-old",
        "CC6.2",
        "quarterly_access_review",
        json!({"reviewed": true}),
        Utc::now() - Duration::days(60),
    )
    .await;

    let findings = soc2
        .stale_evidence_controls(Utc::now())
        .await
        .expect("stale query");
    let finding = finding_for(&findings, "CC6.2").expect("stale control flagged");
    assert_eq!(finding.stale, vec!["quarterly_access_review"], "{finding:?}");
    assert!(finding.missing.is_empty());
    assert!(
        (25..=35).contains(&finding.days_overdue),
        "60-day-old row under a 30-day cadence is ~30 days overdue: {finding:?}"
    );
}

#[tokio::test]
async fn deferred_and_not_applicable_controls_are_outside_the_sweep() {
    let Some(pool) = test_pool("stale_status").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run the stale-evidence sweep tests");
        return;
    };
    let soc2 = Soc2Service::new(pool.clone());
    soc2.seed_default_controls().await.expect("seed controls");

    soc2
        .set_status("CC1.1", compliance::soc2::ControlStatus::Deferred)
        .await
        .expect("defer");
    soc2
        .set_status(
            "CC1.2",
            compliance::soc2::ControlStatus::NotApplicable,
        )
        .await
        .expect("mark na");

    let findings = soc2
        .stale_evidence_controls(Utc::now())
        .await
        .expect("stale query");
    assert!(
        finding_for(&findings, "CC1.1").is_none(),
        "deferred controls have no attestation cadence"
    );
    assert!(
        finding_for(&findings, "CC1.2").is_none(),
        "not-applicable controls have no attestation cadence"
    );
}

#[tokio::test]
async fn sweep_persists_run_rows_and_reports_an_honest_summary() {
    let Some(pool) = test_pool("stale_sweep").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run the stale-evidence sweep tests");
        return;
    };
    let soc2 = Soc2Service::new(pool.clone());
    soc2.seed_default_controls().await.expect("seed controls");

    let summary = soc2
        .sweep_stale_attestations()
        .await
        .expect("sweep runs clean on a seeded catalog");
    assert!(summary.stale_controls >= 20, "{summary:?}");
    assert_eq!(summary.controls_scanned, summary.stale_controls);
    assert_eq!(
        summary.run_rows_written as usize, summary.stale_controls,
        "one run row per stale control: {summary:?}"
    );

    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT control_id, evidence_type, status
         FROM soc2_evidence_collection_runs
         WHERE evidence_type = 'stale_attestation_sweep'",
    )
    .fetch_all(&pool)
    .await
    .expect("run rows");
    assert_eq!(rows.len(), summary.stale_controls);
    for (control_id, evidence_type, status) in &rows {
        assert_eq!(evidence_type, "stale_attestation_sweep");
        assert_eq!(status, "failed", "{control_id} is overdue, not healthy");
    }
    let cc21 = rows
        .iter()
        .find(|(control_id, _, _)| control_id == "CC2.1")
        .expect("CC2.1 run row");
    assert_eq!(cc21.2, "failed");

    // Idempotent detection: the second sweep flags the same set (the run
    // trail accumulates exactly like collector run rows do).
    let again = soc2
        .sweep_stale_attestations()
        .await
        .expect("second sweep");
    assert_eq!(again.stale_controls, summary.stale_controls);
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM soc2_evidence_collection_runs
         WHERE evidence_type = 'stale_attestation_sweep'",
    )
    .fetch_one(&pool)
    .await
    .expect("total run rows");
    assert_eq!(total as usize, summary.stale_controls * 2);

    // Healing: once a control's full set is fresh it leaves the sweep.
    let now = Utc::now();
    for evidence_type in ["audit_log_sample", "audit_chain_verification"] {
        soc2.record_evidence(
            "CC2.1",
            evidence_type,
            "test",
            json!({"evidence_type": evidence_type}),
            now - Duration::hours(1),
            now,
            "test",
        )
        .await
        .expect("evidence");
    }
    let healed = soc2.sweep_stale_attestations().await.expect("third sweep");
    assert!(
        finding_for(&healed.findings, "CC2.1").is_none(),
        "a freshly evidenced control leaves the sweep: see summary"
    );
    assert_eq!(healed.stale_controls, summary.stale_controls - 1);
}

#[tokio::test]
async fn sweep_fails_loud_on_db_errors() {
    let Some(pool) = test_pool("stale_fail").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run the stale-evidence sweep tests");
        return;
    };
    let soc2 = Soc2Service::new(pool.clone());
    soc2.seed_default_controls().await.expect("seed controls");

    // A broken control store must surface as an Err, never an empty pass.
    sqlx::query("ALTER TABLE soc2_controls RENAME TO soc2_controls_fault_probe")
        .execute(&pool)
        .await
        .expect("inject control-store failure");
    let error = soc2
        .sweep_stale_attestations()
        .await
        .expect_err("the sweep must fail loud when the store is unreadable");
    assert!(
        error.contains("soc2_controls"),
        "the DB error is propagated verbatim: {error}"
    );
    sqlx::query("ALTER TABLE soc2_controls_fault_probe RENAME TO soc2_controls")
        .execute(&pool)
        .await
        .expect("restore");

    // A malformed evidence_required (not an array) is a seed defect: the
    // sweep must refuse to render the control as evidenced-by-nothing.
    sqlx::query("UPDATE soc2_controls SET evidence_required = '\"oops\"' WHERE control_id = 'CC2.1'")
        .execute(&pool)
        .await
        .expect("corrupt evidence_required");
    let error = soc2
        .stale_evidence_controls(Utc::now())
        .await
        .expect_err("a malformed seed must not look fully evidenced");
    assert!(
        error.contains("CC2.1") && error.contains("not a JSON array"),
        "the malformed control is named: {error}"
    );
}
