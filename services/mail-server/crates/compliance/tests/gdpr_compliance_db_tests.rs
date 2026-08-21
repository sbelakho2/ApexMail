//! DB-backed integration tests for the compliance crate.
//!
//! Gated on `TEST_DATABASE_URL` (workspace convention — see
//! `api-server/src/lib.rs`). A dedicated database (`<db>_compliance`) is
//! derived from the URL, dropped and recreated once per binary run, and the
//! minimal table shapes the crate's queries touch are created. When the
//! variable is unset every test skips.
//!
//! Coverage (audit items A, B, E, F, G, H, I-1):
//! - erasure is scoped to the data subject (other users' data survives,
//!   invoices are anonymized not deleted, suppression is retained)
//! - erasure failures never produce a completed request or an all-erased
//!   certificate; missing tables produce an honest `partial`
//! - consent re-consent updates the same row (RETURNING id)
//! - rectification parks in pending_manual_review
//! - the audit hash chain survives concurrent appends and archival
//! - the access export carries a per-store manifest and is downloadable

use compliance::config::{AuditConfig, GdprConfig};
use compliance::gdpr_automation::{ErasureStore, GdprAutomation, StoreErasureStatus};
use compliance::types::{AuditAction, AuditOutcome, AuditResource, LogContext};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

// ── Bootstrap ───────────────────────────────────────────────────────────────

const MAIN_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS data_subject_requests (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    request_type TEXT NOT NULL,
    email TEXT NOT NULL,
    verification_token_hash TEXT NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'pending_verification',
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    result JSONB
);
CREATE TABLE IF NOT EXISTS gdpr_exports (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    email TEXT NOT NULL,
    data JSONB NOT NULL,
    export_url TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS consent_records (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    subscriber_id TEXT NOT NULL,
    email TEXT NOT NULL,
    consent_type TEXT NOT NULL,
    granted BOOLEAN NOT NULL,
    granted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    source TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    proof_document TEXT,
    expires_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (tenant_id, subscriber_id, consent_type)
);
CREATE TABLE IF NOT EXISTS double_opt_in_tokens (
    tenant_id TEXT NOT NULL,
    subscriber_id TEXT NOT NULL,
    consent_type TEXT NOT NULL,
    email TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, subscriber_id, consent_type)
);
CREATE TABLE IF NOT EXISTS suppression_list (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    email TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, email)
);
CREATE TABLE IF NOT EXISTS subscribers (
    email TEXT NOT NULL,
    tenant_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS message_events (
    recipient_email TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS engagement_events (
    email TEXT NOT NULL,
    tenant_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tracking_events (
    email TEXT NOT NULL,
    tenant_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS subscriber_analytics (
    email TEXT NOT NULL,
    tenant_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS contacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT,
    email VARCHAR(255) UNIQUE NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS webhooks (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    url VARCHAR(2048) NOT NULL
);
CREATE TABLE IF NOT EXISTS invoices (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    amount_cents BIGINT NOT NULL,
    customer_email TEXT
);
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT,
    user_id TEXT,
    session_id TEXT,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    resource_id TEXT,
    details JSONB NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    outcome TEXT NOT NULL,
    error_message TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hash TEXT NOT NULL,
    previous_hash TEXT,
    signature TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_logs_archive (LIKE audit_logs INCLUDING ALL);
"#;

/// Schema where `subscribers` is a VIEW — DELETE fails with a non-missing-table
/// error, injecting a genuine store failure (audit finding B).
const FAILING_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS data_subject_requests (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    request_type TEXT NOT NULL,
    email TEXT NOT NULL,
    verification_token_hash TEXT NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'pending_verification',
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    result JSONB
);
CREATE TABLE IF NOT EXISTS subscribers_backing (
    email TEXT NOT NULL,
    tenant_id TEXT NOT NULL
);
CREATE VIEW subscribers AS SELECT DISTINCT email, tenant_id FROM subscribers_backing;
"#;

async fn isolated_pool(db_suffix: &str, schema: &str) -> Option<PgPool> {
    let database_url = match std::env::var("TEST_DATABASE_URL") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            eprintln!(
                "skipping: set TEST_DATABASE_URL to run DB-backed compliance tests"
            );
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

    let _ = sqlx::query(&format!(r#"DROP DATABASE IF EXISTS "{isolated}" WITH (FORCE)"#))
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

/// Each test gets its OWN database (unique suffix): pools must never be
/// shared across `#[tokio::test]` runtimes, and parallel tests must not
/// drop each other's databases.
async fn test_pool(test_name: &str, schema: &str) -> Option<PgPool> {
    isolated_pool(&format!("compliance_{test_name}"), schema).await
}

/// Fake Redis pool — connection attempts fail at use time; the GDPR retry
/// path tolerates this (the request state is recorded before re-enqueue).
fn dummy_redis() -> deadpool_redis::Pool {
    let cfg = deadpool_redis::Config::from_url("redis://127.0.0.1:1/99");
    cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))
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
        consent_signing_key: "integration-test-signing-key-0123456789".into(),
        access_request_max_messages: 10_000,
    }
}

fn automation(pool: PgPool) -> GdprAutomation {
    GdprAutomation::new(pool, dummy_redis(), test_gdpr_config())
}

/// A 26-char id for VARCHAR(26) columns (invoices, webhooks).
fn short_id() -> String {
    format!("i{}", &Uuid::new_v4().simple().to_string()[..25])
}

fn unique_tenant() -> String {
    format!("t-{}", Uuid::new_v4().simple())
}

async fn seed_request(
    pool: &PgPool,
    id: &str,
    tenant: &str,
    email: &str,
    request_type: &str,
) {
    sqlx::query(
        "INSERT INTO data_subject_requests
         (id, tenant_id, request_type, email, verification_token_hash, verified, status, requested_at, expires_at)
         VALUES ($1,$2,$3,$4,'hash',true,'verified',NOW(),NOW() + INTERVAL '30 days')",
    )
    .bind(id)
    .bind(tenant)
    .bind(request_type)
    .bind(email)
    .execute(pool)
    .await
    .unwrap();
}

async fn request_status(pool: &PgPool, id: &str) -> (String, Option<serde_json::Value>) {
    sqlx::query_as("SELECT status, result FROM data_subject_requests WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn count(pool: &PgPool, sql: &str, email: &str, tenant: &str) -> i64 {
    let (c,): (i64,) = sqlx::query_as(sql)
        .bind(email)
        .bind(tenant)
        .fetch_one(pool)
        .await
        .unwrap();
    c
}

// ── A + B: erasure scoping and honest outcomes ──────────────────────────────

/// A: erasing subject X in tenant T leaves every other user's data intact,
/// anonymizes (not deletes) invoices, retains suppression, and only deletes
/// subject-scoped rows.
#[tokio::test]
async fn erasure_is_scoped_to_the_data_subject() {
    // Erasure also clears subject-scoped Redis caches (and hard-fails when
    // Redis is unreachable), so this test needs a real Redis.
    let Some(redis) = redis_pool().await else {
        eprintln!("skipping: set TEST_REDIS_URL to run the erasure scoping test");
        return;
    };
    let Some(pool) = test_pool("scoping", MAIN_SCHEMA).await else {
        return;
    };
    let tenant = unique_tenant();
    let subject = format!("subject-{}@x.com", Uuid::new_v4().simple());
    let other = format!("other-{}@x.com", Uuid::new_v4().simple());
    let req_id = Uuid::new_v4().to_string();
    seed_request(&pool, &req_id, &tenant, &subject, "erasure").await;

    // Seed subject + unrelated data everywhere the erasure touches.
    for email in [&subject, &other] {
        sqlx::query("INSERT INTO subscribers (email, tenant_id) VALUES ($1,$2)")
            .bind(email).bind(&tenant).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO message_events (recipient_email, tenant_id) VALUES ($1,$2)")
            .bind(email).bind(&tenant).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO engagement_events (email, tenant_id) VALUES ($1,$2)")
            .bind(email).bind(&tenant).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO tracking_events (email, tenant_id) VALUES ($1,$2)")
            .bind(email).bind(&tenant).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO subscriber_analytics (email, tenant_id) VALUES ($1,$2)")
            .bind(email).bind(&tenant).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO contacts (email, tenant_id, name) VALUES ($1,$2,'n')")
            .bind(email).bind(&tenant).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO consent_records (id, tenant_id, subscriber_id, email, consent_type, granted, source) VALUES ($1,$2,$3,$4,'marketing',true,'api')")
            .bind(Uuid::new_v4().to_string()).bind(&tenant).bind(email).bind(email)
            .execute(&pool).await.unwrap();
        // A user account + session per email.
        let user_id: (String,) = sqlx::query_as("INSERT INTO users (tenant_id, email) VALUES ($1,$2) RETURNING id::text")
            .bind(&tenant).bind(email).fetch_one(&pool).await.unwrap();
        sqlx::query("INSERT INTO sessions (id, user_id, tenant_id, expires_at) VALUES ($1,$2,$3, NOW() + INTERVAL '1 day')")
            .bind(Uuid::new_v4().to_string()).bind(&user_id.0).bind(&tenant)
            .execute(&pool).await.unwrap();
    }
    sqlx::query("INSERT INTO suppression_list (id, tenant_id, email, reason) VALUES ($1,$2,$3,'complaint')")
        .bind(Uuid::new_v4().to_string()).bind(&tenant).bind(&subject)
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO api_keys (tenant_id, name) VALUES ($1,'tenant key')")
        .bind(&tenant).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO webhooks (id, tenant_id, url) VALUES ($1,$2,'https://wh.example')")
        .bind(Uuid::new_v4().to_string()).bind(&tenant).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO invoices (id, tenant_id, amount_cents, customer_email) VALUES ($1,$2,100,$3)")
        .bind(short_id()).bind(&tenant).bind(&subject)
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO invoices (id, tenant_id, amount_cents, customer_email) VALUES ($1,$2,200,$3)")
        .bind(short_id()).bind(&tenant).bind(&other)
        .execute(&pool).await.unwrap();

    let gdpr = GdprAutomation::new(pool.clone(), redis, test_gdpr_config());
    let result = gdpr.process_request(&req_id).await.expect("erasure should succeed");

    // Subject rows are gone …
    for (table, col) in [
        ("subscribers", "email"),
        ("message_events", "recipient_email"),
        ("engagement_events", "email"),
        ("tracking_events", "email"),
        ("subscriber_analytics", "email"),
        ("contacts", "email"),
        ("consent_records", "email"),
    ] {
        let c = count(&pool, &format!("SELECT COUNT(*) FROM {table} WHERE {col} = $1 AND tenant_id = $2"), &subject, &tenant).await;
        assert_eq!(c, 0, "{table}: subject rows must be deleted");
        let c = count(&pool, &format!("SELECT COUNT(*) FROM {table} WHERE {col} = $1 AND tenant_id = $2"), &other, &tenant).await;
        assert_eq!(c, 1, "{table}: other users' rows must survive");
    }

    // … including the subject's session (via users.email lookup), while the
    // other user's session survives.
    let subject_session: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sessions s JOIN users u ON u.id::text = s.user_id WHERE u.email = $1",
    )
    .bind(&subject)
    .fetch_one(&pool)
    .await
    .unwrap();
    let other_session: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sessions s JOIN users u ON u.id::text = s.user_id WHERE u.email = $1",
    )
    .bind(&other)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(subject_session, 0, "subject session must be deleted");
    assert_eq!(other_session, 1, "other user's session must survive");

    // Suppression retained (A-5): deleting it would enable re-mailing a
    // complained address.
    let suppressed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM suppression_list WHERE tenant_id = $1 AND email = $2",
    )
    .bind(&tenant)
    .bind(&subject)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(suppressed, 1, "suppression row must be retained");

    // Invoices retained + subject's PII anonymized (A-3).
    let invoice_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM invoices WHERE tenant_id = $1")
            .bind(&tenant)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(invoice_count, 2, "invoices must never be deleted on erasure");
    let anon: String = sqlx::query_scalar(
        "SELECT customer_email FROM invoices WHERE tenant_id = $1 AND customer_email LIKE 'erased+%'",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("subject invoice email must be redacted");
    assert!(!anon.contains(&subject));
    let other_invoice: String = sqlx::query_scalar(
        "SELECT customer_email FROM invoices WHERE tenant_id = $1 AND customer_email = $2",
    )
    .bind(&tenant)
    .bind(&other)
    .fetch_one(&pool)
    .await
    .unwrap_or_default();
    assert_eq!(other_invoice, other, "other customer's invoice must be untouched");

    // Tenant-owned resources survive (A-4).
    let keys: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_keys WHERE tenant_id = $1")
        .bind(&tenant).fetch_one(&pool).await.unwrap();
    assert_eq!(keys, 1, "api_keys must survive a subject erasure");
    let hooks: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhooks WHERE tenant_id = $1")
        .bind(&tenant).fetch_one(&pool).await.unwrap();
    assert_eq!(hooks, 1, "webhooks must survive a subject erasure");

    // Status: contact_list_members does not exist in this schema → honest
    // `partial`, with the skipped store listed in the certificate.
    let (status, result_json) = request_status(&pool, &req_id).await;
    assert_eq!(status, "partial", "missing stores must yield partial, not completed");
    assert_eq!(result.partial, Some(true));
    // The persisted result also records the partial flag.
    assert_eq!(result_json.unwrap()["partial"], true);
    let cert = result.deletion_confirmation.expect("certificate present");
    assert_eq!(cert["stores"].as_array().unwrap().iter().any(|s| {
        s["store"] == "contact_list_members" && s["status"] == "skipped_missing_table"
    }), true);
    assert!(
        !cert["confirmation"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("all personal data has been permanently erased"),
        "partial erasure must not claim full erasure"
    );
}

/// B: injecting a nonexistent table reports SkippedMissingTable (never
/// counted as deleted).
#[tokio::test]
async fn erasure_missing_table_is_reported_as_skipped() {
    let Some(pool) = test_pool("missing_table", MAIN_SCHEMA).await else {
        return;
    };
    let tenant = unique_tenant();
    let subject = format!("ghost-{}@x.com", Uuid::new_v4().simple());
    let req_id = Uuid::new_v4().to_string();
    seed_request(&pool, &req_id, &tenant, &subject, "erasure").await;

    let request = compliance::types::DataSubjectRequest {
        id: req_id,
        tenant_id: tenant.clone(),
        request_type: compliance::types::DataSubjectRequestType::Erasure,
        email: subject,
        verification_token_hash: "h".into(),
        verified: true,
        verified_at: None,
        status: compliance::types::RequestStatus::Verified,
        requested_at: chrono::Utc::now(),
        processed_at: None,
        completed_at: None,
        expires_at: chrono::Utc::now(),
        result: None,
    };

    let gdpr = automation(pool.clone());
    let result = gdpr
        .erase_store(
            &request,
            ErasureStore::TableBySubjectEmail {
                name: "no_such_table_anywhere",
                table: "no_such_table_anywhere",
                email_column: "email",
            },
        )
        .await;
    assert_eq!(result.status, StoreErasureStatus::SkippedMissingTable);
    assert_eq!(result.rows_affected, 0);
}

/// B: a genuine store failure never completes the request and never issues a
/// certificate — it retries, then fails with the error recorded.
#[tokio::test]
async fn erasure_store_failure_fails_the_request_after_retries() {
    let Some(pool) = test_pool("failing", FAILING_SCHEMA).await else {
        return;
    };
    let tenant = unique_tenant();
    let subject = format!("fail-{}@x.com", Uuid::new_v4().simple());
    let req_id = Uuid::new_v4().to_string();
    seed_request(&pool, &req_id, &tenant, &subject, "erasure").await;
    sqlx::query("INSERT INTO subscribers_backing (email, tenant_id) VALUES ($1,$2)")
        .bind(&subject).bind(&tenant).execute(&pool).await.unwrap();

    let gdpr = automation(pool.clone());
    // Three processing passes: attempt 1 → retrying, 2 → retrying, 3 → failed.
    let _ = gdpr.process_request(&req_id).await;
    let (status1, _) = request_status(&pool, &req_id).await;
    assert_eq!(status1, "retrying", "first failure must retry, not reject");

    let _ = gdpr.process_request(&req_id).await;
    let (status2, _) = request_status(&pool, &req_id).await;
    assert_eq!(status2, "retrying");

    let _ = gdpr.process_request(&req_id).await;
    let (status3, result_json) = request_status(&pool, &req_id).await;
    assert_eq!(status3, "failed", "third failure must be terminal");
    let result = result_json.expect("failure reason recorded");
    assert_eq!(result["retry_attempt"], 3);
    assert!(result["error"].as_str().unwrap().contains("erasure failed"));
    assert!(
        result.get("deletion_confirmation").is_none(),
        "no all-erased certificate may be issued for a failed erasure"
    );
}

// ── F: rectification is never auto-completed ────────────────────────────────

#[tokio::test]
async fn rectification_parks_in_pending_manual_review() {
    let Some(pool) = test_pool("rectification", MAIN_SCHEMA).await else {
        return;
    };
    let tenant = unique_tenant();
    let subject = format!("rect-{}@x.com", Uuid::new_v4().simple());
    let req_id = Uuid::new_v4().to_string();
    seed_request(&pool, &req_id, &tenant, &subject, "rectification").await;

    let gdpr = automation(pool.clone());
    let result = gdpr.process_request(&req_id).await.expect("rectification runs");

    let (status, _) = request_status(&pool, &req_id).await;
    assert_eq!(
        status, "pending_manual_review",
        "rectification must not claim completed"
    );
    assert_eq!(result.modified_records, Some(0));
    assert!(result.review_required);

    let completed_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT completed_at FROM data_subject_requests WHERE id = $1")
            .bind(&req_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        completed_at.is_none(),
        "pending review requests have no completion timestamp"
    );
}

// ── H: consent re-consent updates the same row ─────────────────────────────

#[tokio::test]
async fn consent_reconsent_updates_the_same_row() {
    let Some(pool) = test_pool("consent", MAIN_SCHEMA).await else {
        return;
    };
    let tenant = unique_tenant();
    let email = format!("consent-{}@x.com", Uuid::new_v4().simple());
    let gdpr = automation(pool.clone());

    let first = gdpr
        .record_consent(&tenant, "sub-1", &email, compliance::types::ConsentType::Marketing, true, compliance::types::ConsentSource::Api, None)
        .await
        .expect("first consent");
    assert!(first.granted);
    assert!(first.proof_document.is_some());

    // Withdraw, then grant again — must update the SAME row.
    gdpr
        .record_consent(&tenant, "sub-1", &email, compliance::types::ConsentType::Marketing, false, compliance::types::ConsentSource::PreferenceCenter, None)
        .await
        .expect("withdraw");
    let third = gdpr
        .record_consent(&tenant, "sub-1", &email, compliance::types::ConsentType::Marketing, true, compliance::types::ConsentSource::Form, None)
        .await
        .expect("re-grant");

    let (rows, ids): (i64, Vec<String>) = sqlx::query_as(
        "SELECT COUNT(*), array_agg(id::text) FROM consent_records WHERE tenant_id = $1 AND subscriber_id = 'sub-1' AND consent_type = 'marketing'",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rows, 1, "re-consent must update, not duplicate");
    assert_eq!(ids[0], third.id, "RETURNING id must be the existing row id");

    let row: (bool, Option<String>, Option<chrono::DateTime<chrono::Utc>>, Option<String>) = sqlx::query_as(
        "SELECT granted, proof_document, granted_at, revoked_at FROM consent_records WHERE id = $1",
    )
    .bind(&third.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(row.0, "final state granted");
    assert!(row.1.is_some(), "proof document must be stored on the same row");
    assert!(row.2.is_some(), "granted_at recorded");
    assert!(row.3.is_none(), "revoked_at cleared after re-grant");
}

// ── G: access export manifest + download ────────────────────────────────────

#[tokio::test]
async fn access_export_covers_all_stores_and_downloads() {
    let Some(pool) = test_pool("access_export", MAIN_SCHEMA).await else {
        return;
    };
    let tenant = unique_tenant();
    let subject = format!("access-{}@x.com", Uuid::new_v4().simple());
    let req_id = Uuid::new_v4().to_string();
    seed_request(&pool, &req_id, &tenant, &subject, "access").await;

    sqlx::query("INSERT INTO subscribers (email, tenant_id) VALUES ($1,$2)")
        .bind(&subject).bind(&tenant).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO message_events (recipient_email, tenant_id) VALUES ($1,$2)")
        .bind(&subject).bind(&tenant).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO consent_records (id, tenant_id, subscriber_id, email, consent_type, granted, source) VALUES ($1,$2,$3,$4,'marketing',true,'api')")
        .bind(Uuid::new_v4().to_string()).bind(&tenant).bind(&subject).bind(&subject)
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO suppression_list (id, tenant_id, email, reason) VALUES ($1,$2,$3,'complaint')")
        .bind(Uuid::new_v4().to_string()).bind(&tenant).bind(&subject)
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO invoices (id, tenant_id, amount_cents, customer_email) VALUES ($1,$2,42,$3)")
        .bind(short_id()).bind(&tenant).bind(&subject)
        .execute(&pool).await.unwrap();

    let gdpr = automation(pool.clone());
    let result = match gdpr.process_request(&req_id).await {
        Ok(r) => r,
        Err(e) => {
            let (status, res): (String, Option<serde_json::Value>) =
                sqlx::query_as("SELECT status, result FROM data_subject_requests WHERE id = $1")
                    .bind(&req_id)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            panic!("access export failed: {e}; db status={status}; db result={res:?}");
        }
    };

    // The export contains every store from the data map …
    let export_row: (serde_json::Value, String) =
        sqlx::query_as("SELECT data, export_url FROM gdpr_exports WHERE request_id = $1")
            .bind(&req_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let data = export_row.0;
    for key in [
        "profile",
        "message_history",
        "consents",
        "suppression_list",
        "invoices",
        "manifest",
    ] {
        assert!(
            data.get(key).is_some(),
            "export must include the {key} store"
        );
    }
    // … with an explicit manifest listing per-store outcomes + truncation.
    let manifest = &data["manifest"];
    assert_eq!(manifest["truncated"], false);
    assert_eq!(manifest["stores"]["subscribers"]["records"], 1);
    assert_eq!(manifest["stores"]["suppression_list"]["records"], 1);
    // Stores present but empty are still listed with their record count —
    // nothing is silently omitted from the data map.
    assert_eq!(manifest["stores"]["tracking_events"]["included"], true);
    assert_eq!(manifest["stores"]["tracking_events"]["records"], 0);
    assert_eq!(manifest["stores"]["engagement_events"]["records"], 0);

    // Invoice PII is anonymized in the export.
    let invoices = serde_json::to_string(&data["invoices"]).unwrap();
    assert!(!invoices.contains(&subject), "invoice export must be anonymized");
    assert!(invoices.contains("erased+"));

    // export_url points at this service's download route.
    assert!(
        export_row.1.contains("/gdpr/exports/"),
        "export_url must point at the crate's download route: {}",
        export_row.1
    );

    // The stored export is downloadable via the route handler.
    let export_id: String =
        sqlx::query_scalar("SELECT id FROM gdpr_exports WHERE request_id = $1")
            .bind(&req_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    let state = download_test_state(pool.clone()).await;
    let response = compliance::routes::gdpr_download_export(
        axum::extract::State(state),
        auth_headers(),
        axum::extract::Path(export_id.clone()),
    )
    .await
    .expect("download should succeed");
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let disposition = response
        .headers()
        .get(axum::http::header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(disposition.contains("attachment"), "Content-Disposition attachment");

    // Unknown id → 404.
    let missing = compliance::routes::gdpr_download_export(
        axum::extract::State(download_test_state(pool.clone()).await),
        auth_headers(),
        axum::extract::Path("no-such-export-id".to_string()),
    )
    .await
    .unwrap_err();
    assert_eq!(missing.0, axum::http::StatusCode::NOT_FOUND);

    // Expired export → 410 Gone.
    sqlx::query("UPDATE gdpr_exports SET expires_at = NOW() - INTERVAL '1 day' WHERE request_id = $1")
        .bind(&req_id)
        .execute(&pool)
        .await
        .unwrap();
    let gone = compliance::routes::gdpr_download_export(
        axum::extract::State(download_test_state(pool.clone()).await),
        auth_headers(),
        axum::extract::Path(export_id),
    )
    .await
    .unwrap_err();
    assert_eq!(gone.0, axum::http::StatusCode::GONE);

    // Keep `result` alive: the returned result references the export.
    assert!(result.export_url.is_some());
}

/// Minimal AppState for exercising the download handler.
async fn download_test_state(pool: PgPool) -> std::sync::Arc<compliance::routes::AppState> {
    if std::env::var("SECRETS_KDF_SALT").is_err() {
        std::env::set_var("SECRETS_KDF_SALT", "integration-test-salt-0123456789");
    }
    std::sync::Arc::new(compliance::routes::AppState {
        risk_engine: compliance::risk_scoring::RiskScoringEngine::new(pool.clone(), test_compliance_config()),
        content_scanner: compliance::content_scanner::ContentScanner::new(
            pool.clone(),
            compliance::config::ContentScanningConfig {
                enabled: false,
                ocr_enabled: false,
                spam_threshold: 0.0,
                max_attachment_size: 0,
                max_ocr_images: 0,
                banned_domains: vec![],
            },
        ),
        audit_logger: compliance::audit_logger::AuditLogger::new(
            pool.clone(),
            AuditConfig {
                retention_days: 365,
                hash_chain_enabled: true,
                signing_key: "integration-audit-key-0123456789abcdef".into(),
            },
        ),
        secret_manager: compliance::secret_manager::SecretManager::new(
            pool.clone(),
            compliance::config::SecretsConfig {
                encryption_key: String::new(),
                rotation_days: 90,
                max_versions_to_keep: 10,
            },
        )
        .expect("SecretManager with test salt"),
        gdpr: automation(pool.clone()),
        soc2: compliance::soc2::Soc2Service::new(pool.clone()),
        hipaa: compliance::hipaa::HipaaService::new(pool.clone(), b"test".to_vec()),
        trust: compliance::trust_portal::TrustPortalService::new(pool.clone()),
        config: test_compliance_config(),
        db: pool.clone(),
        redis: dummy_redis(),
        http_client: reqwest::Client::new(),
        dsar_rate_limiter: compliance::dsar_rate_limit::DsarRateLimiter::new(
            compliance::config::DsarRateLimitConfig::default(),
            None,
        ),
    })
}

fn test_compliance_config() -> compliance::config::ComplianceConfig {
    compliance::config::ComplianceConfig {
        port: 0,
        database_url: String::new(),
        redis_url: String::new(),
        auth_token: "test-service-token".into(),
        cors_origin: String::new(),
        risk: compliance::config::RiskScoringConfig {
            spam_threshold: 0.0,
            phishing_threshold: 0.0,
            abuse_threshold: 0.0,
            max_daily_emails: 0,
            new_tenant_daily_limit: 0,
            warmup_days: 0,
            weights: compliance::config::RiskWeights {
                spam_complaints: 0.0,
                bounce_rate: 0.0,
                phishing_detection: 0.0,
                content_violation: 0.0,
                sending_pattern: 0.0,
                account_age: 0.0,
                verification_status: 0.0,
                payment_history: 0.0,
                list_quality: 0.0,
                engagement_rate: 0.0,
            },
            thresholds: compliance::config::RiskThresholds {
                spam_complaint_rate: 0.0,
                bounce_rate: 0.0,
            },
            base_limits: compliance::config::BaseLimits {
                max_daily_emails: 0,
                max_hourly_emails: 0,
                max_recipients: 0,
                max_attachment_size_mb: 0,
            },
        },
        content: compliance::config::ContentScanningConfig {
            enabled: false,
            ocr_enabled: false,
            spam_threshold: 0.0,
            max_attachment_size: 0,
            max_ocr_images: 0,
            banned_domains: vec![],
        },
        audit: AuditConfig {
            retention_days: 365,
            hash_chain_enabled: true,
            signing_key: "integration-audit-key-0123456789abcdef".into(),
        },
        gdpr: test_gdpr_config(),
        secrets: compliance::config::SecretsConfig {
            encryption_key: String::new(),
            rotation_days: 90,
            max_versions_to_keep: 10,
        },
        dsar_rate_limit: compliance::config::DsarRateLimitConfig::default(),
    }
}

fn auth_headers() -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        "Bearer test-service-token".parse().unwrap(),
    );
    headers
}

// ── E: audit chain under concurrency and archival ───────────────────────────

/// E-1: 50 concurrent log() calls produce a single verifiable chain (the old
/// read-hash/insert race forked the chain under concurrency).
#[tokio::test]
async fn audit_chain_survives_concurrent_appends() {
    let Some(pool) = test_pool("concurrency", MAIN_SCHEMA).await else {
        return;
    };
    let audit = compliance::audit_logger::AuditLogger::new(
        pool.clone(),
        AuditConfig {
            retention_days: 365,
            hash_chain_enabled: true,
            signing_key: "concurrency-audit-key-0123456789".into(),
        },
    );
    audit.initialize().await.expect("init");

    let tenant = unique_tenant();
    // ONE shared logger (as in production): the per-chain mutex inside it is
    // what must prevent the fork.
    let audit = std::sync::Arc::new(audit);
    let mut handles = Vec::new();
    for i in 0..50 {
        let audit = audit.clone();
        let tenant = tenant.clone();
        handles.push(tokio::spawn(async move {
            let ctx = LogContext {
                tenant_id: Some(tenant),
                user_id: Some(format!("user-{i}")),
                session_id: None,
                ip_address: None,
                user_agent: None,
            };
            audit
                .log(
                    AuditAction::Create,
                    AuditResource::Subscriber,
                    Some(&format!("sub-{i}")),
                    serde_json::json!({"i": i}),
                    AuditOutcome::Success,
                    None,
                    &ctx,
                )
                .await
        }));
    }
    for h in handles {
        h.await.expect("join").expect("log entry persisted");
    }

    let result = audit.verify_chain(Some(&tenant), None, None).await.unwrap();
    assert!(
        result.valid,
        "chain must verify after concurrent appends: {:?}",
        result.error
    );
    assert_eq!(result.entries_checked, 50);
}

/// E-2: archival preserves conflicting originals and verify/export span both
/// tables.
#[tokio::test]
async fn audit_archive_preserves_conflicts_and_verify_spans_tables() {
    let Some(pool) = test_pool("archive", MAIN_SCHEMA).await else {
        return;
    };
    let audit = compliance::audit_logger::AuditLogger::new(
        pool.clone(),
        AuditConfig {
            retention_days: 365,
            hash_chain_enabled: true,
            signing_key: "archive-audit-key-0123456789".into(),
        },
    );
    audit.initialize().await.expect("init");
    let tenant = unique_tenant();
    let ctx = LogContext {
        tenant_id: Some(tenant.clone()),
        user_id: None,
        session_id: None,
        ip_address: None,
        user_agent: None,
    };

    // Old entries (to be archived) …
    let mut old_ids = Vec::new();
    for i in 0..5 {
        let entry = audit
            .log(
                AuditAction::Read,
                AuditResource::Subscriber,
                Some(&format!("old-{i}")),
                serde_json::json!({"old": i}),
                AuditOutcome::Success,
                None,
                &ctx,
            )
            .await
            .unwrap();
        old_ids.push(entry.id);
    }
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let old_cutoff = chrono::Utc::now() - chrono::Duration::seconds(1);

    // … poison the archive with a conflicting row sharing one old id …
    sqlx::query(
        "INSERT INTO audit_logs_archive
         SELECT id, tenant_id, user_id, session_id, action, resource, resource_id, details,
                ip_address, user_agent, outcome, error_message, timestamp, hash, previous_hash, signature
         FROM audit_logs WHERE id = $1",
    )
    .bind(&old_ids[0])
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("UPDATE audit_logs_archive SET hash = 'conflicting-hash' WHERE id = $1")
        .bind(&old_ids[0])
        .execute(&pool)
        .await
        .unwrap();

    // … then archive. The conflicting original must stay in the LIVE table.
    audit.archive(old_cutoff).await.expect("archive");
    let conflicting_live: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE id = $1")
            .bind(&old_ids[0])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        conflicting_live, 1,
        "conflicting row must be preserved in the live table, not vanish"
    );
    // The other old entries moved to the archive.
    let archived_others: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs_archive WHERE id = ANY($1)",
    )
    .bind(&old_ids[1..])
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(archived_others, 4);

    // The tampered archive copy is EVIDENT: verification for this tenant
    // fails on the poisoned row (tamper detection, not data loss).
    let tampered = audit.verify_chain(Some(&tenant), None, None).await.unwrap();
    assert!(
        !tampered.valid,
        "a tampered archive copy must break verification"
    );

    // A clean tenant demonstrates verify/export spanning archive + live.
    let clean_tenant = unique_tenant();
    let clean_ctx = LogContext {
        tenant_id: Some(clean_tenant.clone()),
        user_id: None,
        session_id: None,
        ip_address: None,
        user_agent: None,
    };
    for i in 0..3 {
        audit
            .log(
                AuditAction::Read,
                AuditResource::Subscriber,
                Some(&format!("c-old-{i}")),
                serde_json::json!({"old": i}),
                AuditOutcome::Success,
                None,
                &clean_ctx,
            )
            .await
            .unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    audit
        .archive(chrono::Utc::now() - chrono::Duration::seconds(1))
        .await
        .expect("second archive");
    for i in 0..3 {
        audit
            .log(
                AuditAction::Update,
                AuditResource::Subscriber,
                Some(&format!("c-new-{i}")),
                serde_json::json!({"new": i}),
                AuditOutcome::Success,
                None,
                &clean_ctx,
            )
            .await
            .unwrap();
    }
    let result = audit
        .verify_chain(Some(&clean_tenant), None, None)
        .await
        .unwrap();
    assert!(
        result.valid,
        "chain across archive+live must verify: {:?}",
        result.error
    );
    assert_eq!(result.entries_checked, 6, "3 archived + 3 live entries");

    // Export/query also spans both tables.
    let query = compliance::types::AuditLogQuery {
        tenant_id: Some(clean_tenant.clone()),
        limit: Some(100),
        ..Default::default()
    };
    let (entries, total) = audit.query(&query).await.unwrap();
    assert_eq!(total as usize, entries.len());
    assert_eq!(total, 6, "archived rows must remain queryable/exportable");
}

// ── I-1: stats are tenant-scoped ────────────────────────────────────────────

#[tokio::test]
async fn request_stats_are_tenant_scoped_and_aggregate() {
    let Some(pool) = test_pool("stats", MAIN_SCHEMA).await else {
        return;
    };
    let tenant_a = unique_tenant();
    let tenant_b = unique_tenant();
    for (tenant, n) in [(&tenant_a, 2usize), (&tenant_b, 3usize)] {
        for i in 0..n {
            seed_request(
                &pool,
                &Uuid::new_v4().to_string(),
                tenant,
                &format!("s{i}-{}@x.com", Uuid::new_v4().simple()),
                "access",
            )
            .await;
        }
    }

    let gdpr = automation(pool.clone());
    let stats_a = gdpr.get_request_stats(Some(&tenant_a)).await.unwrap();
    assert_eq!(stats_a["total"], 2, "tenant A sees only its own requests");
    let stats_b = gdpr.get_request_stats(Some(&tenant_b)).await.unwrap();
    assert_eq!(stats_b["total"], 3);
    let all = gdpr.get_request_stats(None).await.unwrap();
    assert_eq!(all["total"], 5, "None aggregates across tenants");
}

// ── F-3: queue reliability (requires a real Redis) ─────────────────────────

async fn redis_pool() -> Option<deadpool_redis::Pool> {
    let url = std::env::var("TEST_REDIS_URL").ok()?;
    deadpool_redis::Config::from_url(url)
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .ok()
}

/// F: an item stranded in the processing list (simulated crash) is requeued
/// by the recovery sweep; processed items are acked and not re-processed.
#[tokio::test]
async fn queue_recovery_sweep_requeues_stuck_entries() {
    let Some(redis) = redis_pool().await else {
        eprintln!("skipping: set TEST_REDIS_URL to run Redis-backed queue tests");
        return;
    };
    let Some(pool) = test_pool("queue", MAIN_SCHEMA).await else {
        return;
    };
    let tenant = unique_tenant();
    let subject = format!("q-{}@x.com", Uuid::new_v4().simple());
    let req_id = Uuid::new_v4().to_string();
    seed_request(&pool, &req_id, &tenant, &subject, "access").await;

    let gdpr = GdprAutomation::new(pool.clone(), redis.clone(), test_gdpr_config());

    // Flush stale state from previous runs.
    let mut conn = redis.get().await.unwrap();
    let _: () = redis::cmd("DEL")
        .arg("gdpr:request_queue")
        .arg("gdpr:request_processing")
        .query_async(&mut *conn)
        .await
        .unwrap();

    // Simulate a crashed worker: a stale entry sits in the processing list
    // with an old timestamp.
    let stale = serde_json::json!({
        "id": req_id,
        "at": (chrono::Utc::now() - chrono::Duration::seconds(600)).to_rfc3339(),
    })
    .to_string();
    let fresh = serde_json::json!({
        "id": "some-other-request",
        "at": chrono::Utc::now().to_rfc3339(),
    })
    .to_string();
    let _: () = redis::cmd("RPUSH")
        .arg("gdpr:request_processing")
        .arg(&stale)
        .query_async(&mut *conn)
        .await
        .unwrap();
    let _: () = redis::cmd("RPUSH")
        .arg("gdpr:request_processing")
        .arg(&fresh)
        .query_async(&mut *conn)
        .await
        .unwrap();

    let requeued = gdpr.recover_stuck_processing(300).await.unwrap();
    assert_eq!(requeued, 1, "only the stale entry is requeued");

    let queue: Vec<String> = redis::cmd("LRANGE")
        .arg("gdpr:request_queue")
        .arg(0)
        .arg(-1)
        .query_async(&mut *conn)
        .await
        .unwrap();
    assert_eq!(queue, vec![stale.clone()], "stale entry returns to the main queue");
    let processing: Vec<String> = redis::cmd("LRANGE")
        .arg("gdpr:request_processing")
        .arg(0)
        .arg(-1)
        .query_async(&mut *conn)
        .await
        .unwrap();
    assert_eq!(processing, vec![fresh], "fresh in-flight entry is untouched");

    // Processing the batch completes the request AND acks the entry.
    let results = gdpr.process_queue_batch(10).await.unwrap();
    assert_eq!(results.len(), 1);
    let (status, _) = request_status(&pool, &req_id).await;
    assert_eq!(status, "completed");
    let processing_after: Vec<String> = redis::cmd("LRANGE")
        .arg("gdpr:request_processing")
        .arg(0)
        .arg(-1)
        .query_async(&mut *conn)
        .await
        .unwrap();
    assert!(
        !processing_after.contains(&stale),
        "processed entry must leave the processing list"
    );
}
