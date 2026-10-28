//! DB-backed evidence-integrity tests for the SOC 2 subsystem.
//!
//! Gated on `TEST_DATABASE_URL` (workspace convention, see
//! `migrator::test_support::fresh_canonical_pool`): each test provisions its
//! OWN throwaway database cloned from the canonical migration chain. With the
//! variable unset every test soft-skips; a configured provisioning failure
//! panics.
//!
//! Coverage:
//! * TASK 1 — a collector whose evidence row was not persisted is never
//!   counted as succeeded, and the run row says `failed`.
//! * TASK 2 — attestation needs the FULL required evidence set; one item is
//!   not enough; stale evidence clears it.
//! * TASK 3 — evidence is append-only (history intact, correction supersedes,
//!   DB trigger rejects UPDATE) and readers use the latest row.
//! * TASK 4 — the questionnaire evidence lookup selects latest rows.

use chrono::{Duration, Utc};
use compliance::soc2::Soc2Service;
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
/// test can control `collected_at` and deliberately corrupt the hash.
async fn insert_evidence_raw(
    pool: &PgPool,
    id: &str,
    control_id: &str,
    evidence_type: &str,
    payload: serde_json::Value,
    hash: &str,
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
    .bind(hash)
    .bind(collected_at - Duration::hours(1))
    .bind(collected_at)
    .bind(collected_at)
    .execute(pool)
    .await
    .expect("insert raw evidence");
}

#[tokio::test]
async fn soc2_evidence_collector_persistence_failure_never_reports_success() {
    let Some(pool) = test_pool("collector_fault").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run the collector fault test");
        return;
    };
    let soc2 = Soc2Service::new(pool.clone());
    soc2.seed_default_controls().await.expect("seed controls");

    // Fault injection at the storage boundary (the crate's existing pattern,
    // cf. the GDPR non-deletable view): rename the evidence store so every
    // persistence attempt fails while collection and run logging stay healthy.
    sqlx::query("ALTER TABLE soc2_control_evidence RENAME TO soc2_control_evidence_fault_probe")
        .execute(&pool)
        .await
        .expect("inject evidence-store failure");

    let summary = soc2
        .run_automated_collectors(Utc::now() - Duration::days(1), Utc::now())
        .await;

    assert!(summary.controls_attempted > 0);
    assert_eq!(
        summary.controls_succeeded, 0,
        "an unpersisted collection must never count as success"
    );
    assert_eq!(summary.controls_failed, summary.controls_attempted);
    assert_eq!(summary.items_collected, 0);
    assert_eq!(summary.status, "failed");
    assert!(
        summary
            .failures
            .iter()
            .any(|failure| failure.contains("soc2_control_evidence")),
        "the persistence error is recorded: {:?}",
        summary.failures
    );

    let statuses: Vec<String> =
        sqlx::query_scalar("SELECT status FROM soc2_evidence_collection_runs")
            .fetch_all(&pool)
            .await
            .expect("run rows");
    assert!(!statuses.is_empty());
    assert!(
        statuses.iter().all(|status| status == "failed"),
        "no run row may say success without persisted evidence: {statuses:?}"
    );
}

#[tokio::test]
async fn attestation_requires_every_required_evidence_type() {
    let Some(pool) = test_pool("attest_full_set").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run the attestation test");
        return;
    };
    let soc2 = Soc2Service::new(pool.clone());
    soc2.seed_default_controls().await.expect("seed controls");

    let period_start = Utc::now() - Duration::hours(1);
    let period_end = Utc::now();

    // CC2.1 requires BOTH audit_log_sample and audit_chain_verification.
    soc2.record_evidence(
        "CC2.1",
        "audit_log_sample",
        "test",
        json!({"entries": 4}),
        period_start,
        period_end,
        "test",
    )
    .await
    .expect("first evidence item");

    let control = soc2
        .get_control("CC2.1")
        .await
        .expect("get control")
        .expect("CC2.1 seeded");
    assert!(
        control.last_attested_at.is_none(),
        "one of two required evidence items must not attest the control"
    );
    assert!(control.next_attestation_at.is_none());

    let state = soc2
        .recompute_attestation("CC2.1")
        .await
        .expect("recompute attestation");
    assert!(!state.attested);
    assert_eq!(state.missing, vec!["audit_chain_verification"]);

    soc2.record_evidence(
        "CC2.1",
        "audit_chain_verification",
        "test",
        json!({"chain_ok": true}),
        period_start,
        period_end,
        "test",
    )
    .await
    .expect("second evidence item");

    let state = soc2
        .recompute_attestation("CC2.1")
        .await
        .expect("recompute attestation");
    assert!(
        state.attested,
        "full required evidence set attests: {state:?}"
    );
    assert!(state.missing.is_empty());
    assert!(state.stale.is_empty());
    assert!(state.invalid.is_empty());

    let control = soc2
        .get_control("CC2.1")
        .await
        .expect("get control")
        .expect("CC2.1 seeded");
    assert!(control.last_attested_at.is_some());
    assert!(control.next_attestation_at.is_some());
}

#[tokio::test]
async fn stale_evidence_clears_attestation() {
    let Some(pool) = test_pool("attest_stale").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run the stale-evidence test");
        return;
    };
    let soc2 = Soc2Service::new(pool.clone()).with_attestation_period(30);
    soc2.seed_default_controls().await.expect("seed controls");

    // CC6.2 requires quarterly_access_review (manual evidence).
    let payload = json!({"reviewed": true});
    insert_evidence_raw(
        &pool,
        "ev-cc62-fresh",
        "CC6.2",
        "quarterly_access_review",
        payload.clone(),
        &payload_hash(&payload),
        Utc::now(),
    )
    .await;
    let state = soc2
        .recompute_attestation("CC6.2")
        .await
        .expect("recompute");
    assert!(state.attested);

    // Replace the fresh drill with a stale one (test setup may delete; the
    // production trigger blocks UPDATE, not explicit test cleanup).
    sqlx::query("DELETE FROM soc2_control_evidence WHERE control_id = 'CC6.2'")
        .execute(&pool)
        .await
        .expect("clear evidence for stale scenario");
    insert_evidence_raw(
        &pool,
        "ev-cc62-stale",
        "CC6.2",
        "quarterly_access_review",
        payload.clone(),
        &payload_hash(&payload),
        Utc::now() - Duration::days(60),
    )
    .await;

    let state = soc2
        .recompute_attestation("CC6.2")
        .await
        .expect("recompute");
    assert!(!state.attested, "stale evidence cannot attest");
    assert_eq!(state.stale, vec!["quarterly_access_review"]);

    let control = soc2
        .get_control("CC6.2")
        .await
        .expect("get control")
        .expect("CC6.2 seeded");
    assert!(
        control.last_attested_at.is_none(),
        "expiry must clear the attestation timestamp"
    );
    assert!(control.next_attestation_at.is_none());
}

#[tokio::test]
async fn evidence_is_append_only_and_corrections_supersede() {
    let Some(pool) = test_pool("append_only").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run the append-only test");
        return;
    };
    let soc2 = Soc2Service::new(pool.clone());
    soc2.seed_default_controls().await.expect("seed controls");

    let period_start = Utc::now() - Duration::hours(2);
    let period_end = Utc::now() - Duration::hours(1);
    let first = soc2
        .record_evidence(
            "CC2.1",
            "audit_log_sample",
            "test",
            json!({"generation": 1}),
            period_start,
            period_end,
            "test",
        )
        .await
        .expect("first collection");
    let second = soc2
        .record_evidence(
            "CC2.1",
            "audit_log_sample",
            "test",
            json!({"generation": 2}),
            period_start,
            period_end,
            "test",
        )
        .await
        .expect("second collection");
    assert_ne!(first.id, second.id, "every collection appends a new row");

    let history: Vec<(String, serde_json::Value, String)> = sqlx::query_as(
        "SELECT id, payload, sha256_hash FROM soc2_control_evidence
         WHERE control_id = 'CC2.1' AND evidence_type = 'audit_log_sample'
         ORDER BY collected_at, id",
    )
    .fetch_all(&pool)
    .await
    .expect("history rows");
    assert_eq!(history.len(), 2);
    assert!(history.iter().any(|(id, payload, hash)| id == &first.id
        && payload["generation"] == 1
        && hash == &first.sha256_hash));
    assert!(history.iter().any(|(id, payload, hash)| id == &second.id
        && payload["generation"] == 2
        && hash == &second.sha256_hash));

    // A correction is a third row; the first two remain byte-identical.
    let correction = soc2
        .record_evidence(
            "CC2.1",
            "audit_log_sample",
            "test",
            json!({"generation": 3}),
            period_start,
            period_end,
            "test",
        )
        .await
        .expect("correction");
    let history: Vec<(String, serde_json::Value, String)> = sqlx::query_as(
        "SELECT id, payload, sha256_hash FROM soc2_control_evidence
         WHERE control_id = 'CC2.1' AND evidence_type = 'audit_log_sample'
         ORDER BY collected_at, id",
    )
    .fetch_all(&pool)
    .await
    .expect("history rows after correction");
    assert_eq!(history.len(), 3);
    assert!(history.iter().any(|(id, payload, hash)| id == &first.id
        && payload["generation"] == 1
        && hash == &first.sha256_hash));

    // Readers see only the latest row for (control, type, period).
    let latest = soc2
        .list_evidence_for_control("CC2.1", 100)
        .await
        .expect("latest evidence");
    let current = latest
        .iter()
        .find(|row| row.evidence_type == "audit_log_sample")
        .expect("latest audit_log_sample");
    assert_eq!(current.id, correction.id);
}

#[tokio::test]
async fn evidence_append_only_trigger_rejects_updates_and_latest_row_drives_attestation() {
    let Some(pool) = test_pool("tamper").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run the tamper test");
        return;
    };
    let soc2 = Soc2Service::new(pool.clone());
    soc2.seed_default_controls().await.expect("seed controls");

    let payload = json!({"generation": "original"});
    let evidence = soc2
        .record_evidence(
            "CC2.1",
            "audit_log_sample",
            "test",
            payload.clone(),
            Utc::now() - Duration::hours(1),
            Utc::now(),
            "test",
        )
        .await
        .expect("record evidence");

    // A direct UPDATE of the stored payload is refused by migration 274's
    // trigger, and the row stays intact.
    let update_error = sqlx::query("UPDATE soc2_control_evidence SET payload = $1 WHERE id = $2")
        .bind(json!({"generation": "tampered"}))
        .bind(&evidence.id)
        .execute(&pool)
        .await
        .expect_err("append-only trigger must reject UPDATE");
    assert!(
        update_error.to_string().contains("append-only"),
        "unexpected error: {update_error}"
    );
    let stored: serde_json::Value =
        sqlx::query_scalar("SELECT payload FROM soc2_control_evidence WHERE id = $1")
            .bind(&evidence.id)
            .fetch_one(&pool)
            .await
            .expect("stored payload");
    assert_eq!(stored, payload, "history was not mutated");

    // Latest-row semantics: an older VALID row cannot rescue a newer INVALID
    // one, but a still-newer valid correction supersedes the invalid row.
    let valid_old = json!({"generation": "valid-old"});
    insert_evidence_raw(
        &pool,
        "ev-cc62-valid-old",
        "CC6.2",
        "quarterly_access_review",
        valid_old.clone(),
        &payload_hash(&valid_old),
        Utc::now() - Duration::hours(2),
    )
    .await;
    let invalid_new = json!({"generation": "invalid-new"});
    insert_evidence_raw(
        &pool,
        "ev-cc62-invalid-new",
        "CC6.2",
        "quarterly_access_review",
        invalid_new,
        "deadbeef",
        Utc::now() - Duration::hours(1),
    )
    .await;
    let state = soc2
        .recompute_attestation("CC6.2")
        .await
        .expect("recompute");
    assert!(!state.attested, "the latest row is invalid");
    assert_eq!(state.invalid, vec!["quarterly_access_review"]);

    let correction = json!({"generation": "valid-correction"});
    insert_evidence_raw(
        &pool,
        "ev-cc62-valid-correction",
        "CC6.2",
        "quarterly_access_review",
        correction.clone(),
        &payload_hash(&correction),
        Utc::now(),
    )
    .await;
    let state = soc2
        .recompute_attestation("CC6.2")
        .await
        .expect("recompute");
    assert!(state.attested, "the newest correction wins: {state:?}");
}

#[tokio::test]
async fn questionnaire_lookup_uses_latest_evidence_rows() {
    let Some(pool) = test_pool("questionnaire_latest").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run the questionnaire lookup test");
        return;
    };
    let soc2 = Soc2Service::new(pool.clone());
    soc2.seed_default_controls().await.expect("seed controls");

    let period_start = Utc::now() - Duration::hours(2);
    let period_end = Utc::now() - Duration::hours(1);
    let first = soc2
        .record_evidence(
            "CC2.1",
            "audit_log_sample",
            "test",
            json!({"generation": 1}),
            period_start,
            period_end,
            "test",
        )
        .await
        .expect("first row");
    let latest = soc2
        .record_evidence(
            "CC2.1",
            "audit_log_sample",
            "test",
            json!({"generation": 2}),
            period_start,
            period_end,
            "test",
        )
        .await
        .expect("second row");
    assert_ne!(first.id, latest.id);

    let rows = soc2
        .list_latest_evidence_for_controls(&["CC2.1".to_string()])
        .await
        .expect("latest rows");
    let audit_sample: Vec<_> = rows
        .iter()
        .filter(|row| row.evidence_type == "audit_log_sample")
        .collect();
    assert_eq!(audit_sample.len(), 1, "one latest row per type/period");
    assert_eq!(audit_sample[0].id, latest.id);
    assert_eq!(audit_sample[0].payload["generation"], 2);
}
