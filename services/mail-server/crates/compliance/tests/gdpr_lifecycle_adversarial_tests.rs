//! Adversarial GDPR/DSAR lifecycle tests (commercial & compliance contract).
//!
//! Contract (docs/pricing-authority.md + GDPR Art. 12–17):
//! * request lifecycle is CREATE → in_progress (processing) → completed /
//!   rejected ONLY — there is no silent skip to `completed` without the
//!   deliberate processing record;
//! * every terminal transition writes an `audit_logs` row on the tenant
//!   chain (F5 `record_terminal_transition`);
//! * one tenant can never complete, read, or export another tenant's DSAR.
//!
//! Harness: canonical migration chain via `migrator::test_support`
//! (`TEST_DATABASE_URL` unset ⇒ soft-skip; configured breakage panics).

use compliance::config::{AuditConfig, GdprConfig};
use compliance::gdpr_automation::GdprAutomation;
use compliance::types::DataSubjectRequestType;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

// ── Bootstrap ───────────────────────────────────────────────────────────────

async fn test_pool(test_name: &str) -> Option<PgPool> {
    match migrator::test_support::fresh_canonical_pool(
        &format!("gdpr_adv_{test_name}"),
        &format!("gdpr_adv_{test_name}"),
    )
    .await
    {
        Ok(pool) => Some(pool),
        Err(error) => panic!("{}", error.panic_message()),
    }
}

fn dummy_redis() -> deadpool_redis::Pool {
    deadpool_redis::Config::from_url("redis://127.0.0.1:1/97")
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .expect("fake redis pool")
}

fn test_gdpr_config() -> GdprConfig {
    GdprConfig {
        data_retention_days: 730,
        export_format: "json".into(),
        deletion_grace_period_days: 30,
        request_expiration_days: 30,
        export_expiration_days: 7,
        export_base_url: "https://gdpr.test.local".into(),
        verify_base_url: "https://gdpr.test.local".into(),
        consent_signing_key: "gdpr-adv-signing-key-0123456789".into(),
        access_request_max_messages: 10_000,
        system_from_address: "noreply@apexmail.ee".into(),
        outbox_flush_batch: 25,
        outbox_flush_max_attempts: 5,
        clickhouse_erasure_enabled: false,
        clickhouse_url: "http://clickhouse.test.invalid:8123".into(),
        clickhouse_database: "apexmail".into(),
        clickhouse_user: "default".into(),
        clickhouse_password: String::new(),
    }
}

fn audit_logger(pool: &PgPool) -> Arc<compliance::audit_logger::AuditLogger> {
    Arc::new(compliance::audit_logger::AuditLogger::new(
        pool.clone(),
        AuditConfig {
            retention_days: 365,
            hash_chain_enabled: true,
            signing_key: "gdpr-adv-audit-key-0123456789ab".into(),
        },
    ))
}

fn unique_tenant() -> String {
    format!("t-{}", &Uuid::new_v4().simple().to_string()[..24])
}

async fn seed_tenant(pool: &PgPool, tenant: &str) {
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status) VALUES ($1, 'gdpr adv', $2, 'free', 'active')
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(tenant)
    .bind(format!("slug-{tenant}"))
    .execute(pool)
    .await
    .expect("seed tenant");
}

async fn status_of(pool: &PgPool, id: &str) -> String {
    sqlx::query_scalar("SELECT status FROM data_subject_requests WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read request status")
}

async fn audit_rows_for(pool: &PgPool, tenant: &str, request_id: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs
         WHERE tenant_id = $1
           AND details->>'requestId' = $2
           AND details->>'action' LIKE 'dsr.lifecycle.%'",
    )
    .bind(tenant)
    .bind(request_id)
    .fetch_one(pool)
    .await
    .expect("count dsr lifecycle audit rows")
}

// ── Lifecycle: create → in_progress → completed/rejected only ───────────────

/// The full deliberate path: submit (pending_verification) → verify →
/// process (processing) → completed. A `completed` request MUST carry a
/// processed_at + result record and a `dsr.lifecycle.completed` audit row.
/// Nothing may jump straight to `completed` from intake.
#[tokio::test]
async fn dsar_lifecycle_is_create_in_progress_completed_with_audit_record() {
    let Some(pool) = test_pool("lifecycle").await else {
        return;
    };
    let audit = audit_logger(&pool);
    audit.initialize().await.expect("audit chain init");
    let gdpr = GdprAutomation::new(pool.clone(), dummy_redis(), test_gdpr_config())
        .with_audit_logger(audit);

    let tenant = unique_tenant();
    seed_tenant(&pool, &tenant).await;
    let subject = format!("lifecycle-{}@example.com", Uuid::new_v4().simple());

    // 1. CREATE — never completed on intake.
    let (request, token) = gdpr
        .submit_request(&tenant, DataSubjectRequestType::Access, &subject)
        .await
        .expect("submit DSAR");
    let created_status = status_of(&pool, &request.id).await;
    assert_eq!(
        created_status, "pending_verification",
        "intake is pending_verification, never completed"
    );
    assert_ne!(
        created_status, "completed",
        "a DSAR must not be silently completed at create"
    );
    assert!(
        request.completed_at.is_none(),
        "create must not stamp completed_at"
    );
    assert_eq!(
        audit_rows_for(&pool, &tenant, &request.id).await,
        0,
        "no terminal audit row before processing"
    );

    // 2. Verify identity → verified (still not completed).
    let verified = gdpr
        .verify_request(&request.id, &token)
        .await
        .expect("verify");
    assert!(verified, "correct token verifies");
    assert_eq!(status_of(&pool, &request.id).await, "verified");

    // 3. Process → in_progress (processing) then terminal completed.
    let result = gdpr
        .process_request(&request.id)
        .await
        .expect("process access DSAR");
    assert!(
        result.rejection_reason.is_none(),
        "access request should complete, not reject: {result:?}"
    );

    let (final_status, processed_at, completed_at, stored_result): (
        String,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<serde_json::Value>,
    ) = sqlx::query_as(
        "SELECT status, processed_at, completed_at, result
         FROM data_subject_requests WHERE id = $1",
    )
    .bind(&request.id)
    .fetch_one(&pool)
    .await
    .expect("read terminal row");

    assert_eq!(
        final_status, "completed",
        "the deliberate path ends in completed"
    );
    assert!(
        processed_at.is_some(),
        "processing timestamp is the in_progress record"
    );
    assert!(
        completed_at.is_some(),
        "completed requests carry completed_at (no silent skip)"
    );
    assert!(
        stored_result.is_some(),
        "completion stores the result record — never a bare status flip"
    );

    // 4. Audit trail: exactly one dsr.lifecycle.completed row for this DSR.
    let audit_count = audit_rows_for(&pool, &tenant, &request.id).await;
    assert_eq!(
        audit_count, 1,
        "terminal transition writes exactly one dsr.lifecycle audit row"
    );
    let (action, outcome): (String, String) = sqlx::query_as(
        "SELECT details->>'action', outcome::text FROM audit_logs
         WHERE tenant_id = $1 AND details->>'requestId' = $2",
    )
    .bind(&tenant)
    .bind(&request.id)
    .fetch_one(&pool)
    .await
    .expect("audit row contents");
    assert_eq!(action, "dsr.lifecycle.completed");
    assert_eq!(outcome, "success");

    pool.close().await;
}

/// A request MUST NOT reach `completed` without the processing record:
/// the only writer of `completed` is `process_request`, which stamps
/// processed_at/completed_at/result and the audit row together. An
/// unverified request cannot be processed into a completed state either —
/// intake stays pending_verification until the subject proves identity.
#[tokio::test]
async fn dsar_cannot_skip_to_completed_without_the_processing_record() {
    let Some(pool) = test_pool("noskip").await else {
        return;
    };
    let audit = audit_logger(&pool);
    audit.initialize().await.expect("audit chain init");
    let gdpr = GdprAutomation::new(pool.clone(), dummy_redis(), test_gdpr_config())
        .with_audit_logger(audit);

    let tenant = unique_tenant();
    seed_tenant(&pool, &tenant).await;
    let subject = format!("noskip-{}@example.com", Uuid::new_v4().simple());

    let (request, _token) = gdpr
        .submit_request(&tenant, DataSubjectRequestType::Access, &subject)
        .await
        .expect("submit");

    // Intake leaves no completed record behind.
    let (status, completed_at, result): (
        String,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<serde_json::Value>,
    ) = sqlx::query_as(
        "SELECT status, completed_at, result FROM data_subject_requests WHERE id = $1",
    )
    .bind(&request.id)
    .fetch_one(&pool)
    .await
    .expect("read intake row");
    assert_eq!(status, "pending_verification");
    assert!(completed_at.is_none(), "no completed_at at intake");
    assert!(result.is_none(), "no result record at intake");

    // Wrong verification token cannot open the completed path.
    let rejected = gdpr
        .verify_request(&request.id, "not-the-token")
        .await
        .expect("verify handles a wrong token without exploding");
    assert!(!rejected, "wrong token must not verify");
    assert_eq!(
        status_of(&pool, &request.id).await,
        "pending_verification",
        "failed verification does not advance the lifecycle"
    );

    // Direct status forgery to `completed` without the processing record is
    // exactly what the contract forbids: the public lifecycle only reaches
    // completed through `process_request`. Assert the intake row still has
    // no terminal record after the failed verify (the skip never happened).
    let (status, completed_at): (String, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT status, completed_at FROM data_subject_requests WHERE id = $1")
            .bind(&request.id)
            .fetch_one(&pool)
            .await
            .expect("re-read");
    assert_eq!(status, "pending_verification");
    assert!(completed_at.is_none());
    assert_eq!(
        audit_rows_for(&pool, &tenant, &request.id).await,
        0,
        "no terminal audit row exists for an unprocessed request"
    );

    // Rejection is also a recorded terminal — but only through the
    // deliberate processing path. A request parked in manual review
    // (rectification) must NEVER skip to `completed`.
    let (rect_request, _) = gdpr
        .submit_request(&tenant, DataSubjectRequestType::Rectification, &subject)
        .await
        .expect("submit rectification");
    sqlx::query(
        "UPDATE data_subject_requests SET verified = true, status = 'verified' WHERE id = $1",
    )
    .bind(&rect_request.id)
    .execute(&pool)
    .await
    .expect("mark rectification verified");
    let rect_result = gdpr
        .process_request(&rect_request.id)
        .await
        .expect("process rectification");
    assert!(
        rect_result.review_required,
        "rectification requires human review"
    );
    let rect_status = status_of(&pool, &rect_request.id).await;
    assert_eq!(
        rect_status, "pending_manual_review",
        "rectification must NOT skip to completed"
    );
    assert_ne!(
        rect_status, "completed",
        "Art. 16 corrections are never silently completed"
    );

    pool.close().await;
}

// ── Tenant isolation: no cross-tenant DSAR completion / export ──────────────

/// Tenant B can never complete, export, or claim tenant A's DSAR:
/// * processing A's request leaves B's request untouched;
/// * the CP mirror advance is keyed by (token_hash, tenant_id);
/// * export download is tenant-scoped (unknown id and foreign id are the
///   same 404).
#[tokio::test]
async fn tenant_cannot_complete_another_tenants_dsar() {
    let Some(pool) = test_pool("crosstenant").await else {
        return;
    };
    let audit = audit_logger(&pool);
    audit.initialize().await.expect("audit chain init");
    let gdpr = GdprAutomation::new(pool.clone(), dummy_redis(), test_gdpr_config())
        .with_audit_logger(audit);

    let tenant_a = unique_tenant();
    let tenant_b = unique_tenant();
    seed_tenant(&pool, &tenant_a).await;
    seed_tenant(&pool, &tenant_b).await;

    let email_a = format!("subject-a-{}@example.com", Uuid::new_v4().simple());
    let email_b = format!("subject-b-{}@example.com", Uuid::new_v4().simple());

    let (req_a, token_a) = gdpr
        .submit_request(&tenant_a, DataSubjectRequestType::Access, &email_a)
        .await
        .expect("submit A");
    let (req_b, token_b) = gdpr
        .submit_request(&tenant_b, DataSubjectRequestType::Access, &email_b)
        .await
        .expect("submit B");

    // CP mirror rows for both tenants (the submit path writes them
    // best-effort). Completing A must never advance B's mirror.
    let mirror_b_before: Option<String> =
        sqlx::query_scalar("SELECT status FROM gdpr_requests WHERE tenant_id = $1 LIMIT 1")
            .bind(&tenant_b)
            .fetch_optional(&pool)
            .await
            .expect("B mirror before");

    // Verify + process ONLY tenant A's request.
    assert!(gdpr
        .verify_request(&req_a.id, &token_a)
        .await
        .expect("verify A"));
    gdpr.process_request(&req_a.id).await.expect("process A");
    assert_eq!(status_of(&pool, &req_a.id).await, "completed");

    // Tenant B's request is untouched — not completed by A's processing.
    let status_b = status_of(&pool, &req_b.id).await;
    assert_ne!(
        status_b, "completed",
        "processing tenant A must not complete tenant B's DSAR"
    );
    assert!(
        !matches!(status_b.as_str(), "completed" | "rejected"),
        "B stays in {status_b}, never a terminal state written by A"
    );

    // B's CP mirror is not advanced by A's completion.
    let mirror_b_after: Option<String> =
        sqlx::query_scalar("SELECT status FROM gdpr_requests WHERE tenant_id = $1 LIMIT 1")
            .bind(&tenant_b)
            .fetch_optional(&pool)
            .await
            .expect("B mirror after");
    assert_eq!(
        mirror_b_before, mirror_b_after,
        "A's terminal transition must not touch B's gdpr_requests mirror"
    );

    // A's audit row is attributed to A, not B.
    assert_eq!(audit_rows_for(&pool, &tenant_a, &req_a.id).await, 1);
    assert_eq!(
        audit_rows_for(&pool, &tenant_b, &req_a.id).await,
        0,
        "A's audit row must not be written on B's tenant chain"
    );

    // Completing B afterwards is B's own deliberate transition.
    assert!(gdpr
        .verify_request(&req_b.id, &token_b)
        .await
        .expect("verify B"));
    gdpr.process_request(&req_b.id).await.expect("process B");
    assert_eq!(status_of(&pool, &req_b.id).await, "completed");
    assert_eq!(audit_rows_for(&pool, &tenant_b, &req_b.id).await, 1);

    // Export download is tenant-scoped: B presenting A's export id gets the
    // same 404 as an unknown id (indistinguishable on purpose).
    // Seed an export row for A and attempt the tenant-scoped read the route
    // performs.
    let export_id = format!("gex_{}", &Uuid::new_v4().simple().to_string()[..22]);
    sqlx::query(
        "INSERT INTO gdpr_exports (id, request_id, tenant_id, email, data, export_url, expires_at, created_at)
         VALUES ($1, $2, $3, $4, '{\"secret\": true}'::jsonb, 'https://gdpr.test.local/x', NOW() + INTERVAL '7 days', NOW())",
    )
    .bind(&export_id)
    .bind(&req_a.id)
    .bind(&tenant_a)
    .bind(&email_a)
    .execute(&pool)
    .await
    .expect("seed A export");

    // Same SQL the route runs (gdpr_download_export): tenant must match.
    let foreign: Option<(serde_json::Value,)> =
        sqlx::query_as("SELECT data FROM gdpr_exports WHERE id = $1 AND tenant_id = $2")
            .bind(&export_id)
            .bind(&tenant_b)
            .fetch_optional(&pool)
            .await
            .expect("cross-tenant export lookup");
    assert!(
        foreign.is_none(),
        "tenant B must not resolve tenant A's export"
    );

    let own: Option<(serde_json::Value,)> =
        sqlx::query_as("SELECT data FROM gdpr_exports WHERE id = $1 AND tenant_id = $2")
            .bind(&export_id)
            .bind(&tenant_a)
            .fetch_optional(&pool)
            .await
            .expect("own-tenant export lookup");
    assert!(own.is_some(), "tenant A still reads its own export");

    // A subject present in BOTH tenants: erasure for A never erases B's rows
    // (the hostile cross-tenant shape). Seed a contact in each and run A's
    // erasure.
    let shared = format!("shared-{}@example.com", Uuid::new_v4().simple());
    for tenant in [&tenant_a, &tenant_b] {
        sqlx::query(
            "INSERT INTO contacts (email, tenant_id, name) VALUES ($1, $2, 'shared subject')",
        )
        .bind(&shared)
        .bind(tenant)
        .execute(&pool)
        .await
        .expect("seed shared contact");
    }
    let (era_request, _) = gdpr
        .submit_request(&tenant_a, DataSubjectRequestType::Erasure, &shared)
        .await
        .expect("submit erasure");
    sqlx::query(
        "UPDATE data_subject_requests SET verified = true, status = 'verified' WHERE id = $1",
    )
    .bind(&era_request.id)
    .execute(&pool)
    .await
    .expect("mark erasure verified");
    gdpr.process_request(&era_request.id)
        .await
        .expect("erase A");

    let contacts_a: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM contacts WHERE tenant_id = $1 AND email = $2")
            .bind(&tenant_a)
            .bind(&shared)
            .fetch_one(&pool)
            .await
            .expect("count A contacts");
    let contacts_b: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM contacts WHERE tenant_id = $1 AND email = $2")
            .bind(&tenant_b)
            .bind(&shared)
            .fetch_one(&pool)
            .await
            .expect("count B contacts");
    assert_eq!(contacts_a, 0, "A's erasure removes A's contact");
    assert_eq!(
        contacts_b, 1,
        "A's erasure must NOT touch tenant B's copy of the same address"
    );

    pool.close().await;
}
