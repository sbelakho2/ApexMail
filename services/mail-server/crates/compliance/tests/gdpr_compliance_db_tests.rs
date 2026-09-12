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
-- The CP mirror production submits also write (gdpr_automation.rs
-- submit_request): without it the DB-backed submit tests fail with
-- "relation gdpr_requests does not exist" — these tests never ran before
-- TEST_DATABASE_URL was wired into the sweep.
CREATE TABLE IF NOT EXISTS gdpr_requests (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    email TEXT NOT NULL,
    request_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    token_hash TEXT,
    fulfilled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

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
    result JSONB,
    -- Migration 213 statutory clock.
    received_at TIMESTAMPTZ,
    identity_verified_at TIMESTAMPTZ,
    statutory_due_at TIMESTAMPTZ,
    extension_due_at TIMESTAMPTZ,
    extension_reason TEXT,
    extension_notified_at TIMESTAMPTZ,
    CONSTRAINT dsr_extension_requires_justification CHECK (
        extension_due_at IS NULL
        OR (extension_reason IS NOT NULL AND length(btrim(extension_reason)) > 0
            AND extension_notified_at IS NOT NULL)
    )
);
-- Migration 213: the DSR verification outbox (previously runtime-created).
CREATE TABLE IF NOT EXISTS dsr_verification_outbox (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    email TEXT NOT NULL,
    verification_token TEXT NOT NULL,
    verify_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at TIMESTAMPTZ
);
-- Migration 214: retention classes; erasure resolves the statutory class.
CREATE TABLE IF NOT EXISTS retention_classes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    statutory BOOLEAN NOT NULL DEFAULT FALSE,
    minimum_days INTEGER NOT NULL CHECK (minimum_days >= 0),
    maximum_days INTEGER,
    retention_days INTEGER NOT NULL CHECK (retention_days >= 0),
    legal_basis_reference TEXT,
    jurisdiction VARCHAR(10),
    customer_selectable BOOLEAN NOT NULL DEFAULT FALSE,
    registry_category_id TEXT,
    review_status VARCHAR(30) NOT NULL DEFAULT 'legal_input_required',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- Migration 213: legally-restricted archive.
CREATE TABLE IF NOT EXISTS legal_retention_archive (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    subject_email_hash TEXT NOT NULL,
    source_table TEXT NOT NULL,
    source_record_id TEXT NOT NULL,
    retention_class_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    state VARCHAR(30) NOT NULL DEFAULT 'legally_restricted',
    archived_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    statutory_expiry_at TIMESTAMPTZ NOT NULL,
    statutory_expired_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,
    disclosure JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (source_table, source_record_id)
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
-- F1: the CANONICAL event store (migration 075) — the phantom
-- subscribers/message_events/tracking_events/engagement_events/
-- subscriber_analytics fixtures are gone; the tests now prove the real map.
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    message_id TEXT,
    event_type TEXT NOT NULL,
    recipient TEXT,
    metadata JSONB,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- Canonical message store (migration 073 shape; id UUID like 052/073).
CREATE TABLE IF NOT EXISTS messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL,
    from_email TEXT NOT NULL,
    to_emails JSONB NOT NULL,
    cc_emails JSONB,
    bcc_emails JSONB,
    subject TEXT NOT NULL,
    html_body TEXT,
    text_body TEXT,
    status TEXT NOT NULL DEFAULT 'queued',
    tags JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
    email VARCHAR(255) UNIQUE NOT NULL,
    name TEXT,
    password_hash TEXT,
    mfa_secret TEXT,
    status TEXT NOT NULL DEFAULT 'active'
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
    amount BIGINT NOT NULL DEFAULT 0,
    billing_address TEXT,
    -- Canonical (052/056/076) accounting column the legal archive needs to
    -- compute the seven-year statutory expiry: issued_at.
    issued_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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

/// Schema where the CANONICAL event store is a VIEW — DELETE fails with a
/// non-missing-table error, injecting a genuine store failure (audit
/// finding B) against the real erasure map.
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
    result JSONB,
    received_at TIMESTAMPTZ,
    identity_verified_at TIMESTAMPTZ,
    statutory_due_at TIMESTAMPTZ,
    extension_due_at TIMESTAMPTZ,
    extension_reason TEXT,
    extension_notified_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS retention_classes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    statutory BOOLEAN NOT NULL DEFAULT FALSE,
    minimum_days INTEGER NOT NULL CHECK (minimum_days >= 0),
    maximum_days INTEGER,
    retention_days INTEGER NOT NULL CHECK (retention_days >= 0),
    legal_basis_reference TEXT,
    jurisdiction VARCHAR(10),
    customer_selectable BOOLEAN NOT NULL DEFAULT FALSE,
    registry_category_id TEXT,
    review_status VARCHAR(30) NOT NULL DEFAULT 'legal_input_required',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS events_backing (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    recipient TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- DISTINCT makes the view non-auto-updatable: DELETE FROM events fails with
-- a non-missing-table error (SQLSTATE 42501) — a genuine store failure.
CREATE VIEW events AS SELECT DISTINCT * FROM events_backing;
"#;

async fn isolated_pool(db_suffix: &str, schema: &str) -> Option<PgPool> {
    let database_url = match std::env::var("TEST_DATABASE_URL") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed compliance tests");
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

    let _ = sqlx::query(&format!(
        r#"DROP DATABASE IF EXISTS "{isolated}" WITH (FORCE)"#
    ))
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
        system_from_address: "noreply@apexmail.ee".into(),
        outbox_flush_batch: 25,
        outbox_flush_max_attempts: 5,
        // ClickHouse erasure step disabled in tests — the certificate then
        // honestly reports skipped_not_configured.
        clickhouse_erasure_enabled: false,
        clickhouse_url: "http://clickhouse.test.invalid:8123".into(),
        clickhouse_database: "apexmail".into(),
        clickhouse_user: "default".into(),
        clickhouse_password: String::new(),
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

async fn seed_request(pool: &PgPool, id: &str, tenant: &str, email: &str, request_type: &str) {
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

    // Seed subject + unrelated data in every CANONICAL store the erasure
    // touches (F1: the map now exercises events/messages/users, not the
    // phantom fixtures).
    for email in [&subject, &other] {
        sqlx::query("INSERT INTO events (id, tenant_id, event_type, recipient) VALUES ($1,$2,'delivered',$3)")
            .bind(Uuid::new_v4().to_string())
            .bind(&tenant)
            .bind(email)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO messages (tenant_id, from_email, to_emails, subject, html_body)
             VALUES ($1, 'noreply@x.com', $2::jsonb, 'Hello there', '<p>Hello there</p>')",
        )
        .bind(&tenant)
        .bind(serde_json::json!([email]))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO contacts (email, tenant_id, name) VALUES ($1,$2,'n')")
            .bind(email)
            .bind(&tenant)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO consent_records (id, tenant_id, subscriber_id, email, consent_type, granted, source) VALUES ($1,$2,$3,$4,'marketing',true,'api')")
            .bind(Uuid::new_v4().to_string()).bind(&tenant).bind(email).bind(email)
            .execute(&pool).await.unwrap();
        // A user account + session per email.
        let user_id: (String,) = sqlx::query_as(
            "INSERT INTO users (tenant_id, email, name, password_hash) VALUES ($1,$2,'Real Name','secret-hash') RETURNING id::text",
        )
        .bind(&tenant)
        .bind(email)
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO sessions (id, user_id, tenant_id, expires_at) VALUES ($1,$2,$3, NOW() + INTERVAL '1 day')")
            .bind(Uuid::new_v4().to_string()).bind(&user_id.0).bind(&tenant)
            .execute(&pool).await.unwrap();
    }
    sqlx::query(
        "INSERT INTO suppression_list (id, tenant_id, email, reason) VALUES ($1,$2,$3,'complaint')",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&tenant)
    .bind(&subject)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO api_keys (tenant_id, name) VALUES ($1,'tenant key')")
        .bind(&tenant)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO webhooks (id, tenant_id, url) VALUES ($1,$2,'https://wh.example')")
        .bind(Uuid::new_v4().to_string())
        .bind(&tenant)
        .execute(&pool)
        .await
        .unwrap();
    // F82: the subject's PII on an invoice lives in the immutable
    // billing-address snapshot (there is no customer_email column).
    sqlx::query(
        "INSERT INTO invoices (id, tenant_id, amount, billing_address)          VALUES ($1,$2,100,$3)",
    )
    .bind(short_id())
    .bind(&tenant)
    .bind(serde_json::json!({ "email": subject, "country": "EE" }).to_string())
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO invoices (id, tenant_id, amount, billing_address)          VALUES ($1,$2,200,$3)",
    )
    .bind(short_id())
    .bind(&tenant)
    .bind(serde_json::json!({ "email": other, "country": "DE" }).to_string())
    .execute(&pool)
    .await
    .unwrap();

    let gdpr = GdprAutomation::new(pool.clone(), redis, test_gdpr_config());
    let result = gdpr
        .process_request(&req_id)
        .await
        .expect("erasure should succeed");

    // Subject rows are gone …
    for (table, col) in [
        ("events", "recipient"),
        ("contacts", "email"),
        ("consent_records", "email"),
    ] {
        let c = count(
            &pool,
            &format!("SELECT COUNT(*) FROM {table} WHERE {col} = $1 AND tenant_id = $2"),
            &subject,
            &tenant,
        )
        .await;
        assert_eq!(c, 0, "{table}: subject rows must be deleted");
        let c = count(
            &pool,
            &format!("SELECT COUNT(*) FROM {table} WHERE {col} = $1 AND tenant_id = $2"),
            &other,
            &tenant,
        )
        .await;
        assert_eq!(c, 1, "{table}: other users' rows must survive");
    }

    // … and the subject's message copy is ANONYMIZED (F1): the row survives
    // as a statutory sending record with the recipient array, subject line
    // and body redacted, while the other recipient's message is untouched.
    let subject_msg: (i64, String, Option<String>) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(MIN(subject), ''), MIN(html_body) FILTER (WHERE html_body IS NOT NULL)
         FROM messages WHERE tenant_id = $1 AND to_emails::text LIKE '%erased+%'",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        subject_msg.0, 1,
        "subject's message row is anonymized, not deleted"
    );
    assert!(subject_msg.1.contains("erased+"), "subject line redacted");
    assert!(subject_msg.2.is_none(), "html body nulled");
    let other_msg_kept: (String, Option<String>) = sqlx::query_as(
        "SELECT subject, html_body FROM messages WHERE tenant_id = $1 AND to_emails::text = $2",
    )
    .bind(&tenant)
    .bind(format!("[\"{other}\"]"))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        other_msg_kept.0, "Hello there",
        "other recipient's subject intact"
    );
    assert_eq!(
        other_msg_kept.1.as_deref(),
        Some("<p>Hello there</p>"),
        "other recipient's body intact"
    );

    // … and the subject's account is a TOMBSTONE (F1/F9): row kept, PII gone.
    let tombstone: (String, Option<String>, String) = sqlx::query_as(
        "SELECT email, name, status FROM users WHERE tenant_id = $1 AND email LIKE 'erased+%'",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("subject's user row must survive as a tombstone");
    assert!(!tombstone.0.contains(&subject), "tombstone email redacted");
    assert!(tombstone.1.is_none(), "tombstone name cleared");
    assert_eq!(tombstone.2, "erased");
    let other_user: (String,) =
        sqlx::query_as("SELECT email FROM users WHERE tenant_id = $1 AND email = $2")
            .bind(&tenant)
            .bind(&other)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(other_user.0, other, "other user's account untouched");

    // … including the subject's session (via users.email lookup), while the
    // other user's session survives. (Sessions are deleted BEFORE the users
    // row is tombstoned — the lookup still resolves.)
    let subject_session: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sessions s JOIN users u ON u.id::text = s.user_id WHERE u.email = $1 OR u.email LIKE 'erased+%'",
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
    assert_eq!(
        invoice_count, 2,
        "invoices must never be deleted on erasure"
    );
    let anon: String = sqlx::query_scalar(
        "SELECT billing_address FROM invoices WHERE tenant_id = $1 \
         AND billing_address LIKE '%erased+%'",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("subject invoice snapshot email must be redacted");
    assert!(!anon.contains(&subject));
    let other_invoice: String = sqlx::query_scalar(
        "SELECT billing_address FROM invoices WHERE tenant_id = $1 AND billing_address LIKE '%' || $2 || '%'",
    )
    .bind(&tenant)
    .bind(&other)
    .fetch_one(&pool)
    .await
    .unwrap_or_default();
    assert!(
        other_invoice.contains(&other),
        "other customer's invoice must be untouched"
    );

    // Tenant-owned resources survive (A-4).
    let keys: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_keys WHERE tenant_id = $1")
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(keys, 1, "api_keys must survive a subject erasure");
    let hooks: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhooks WHERE tenant_id = $1")
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(hooks, 1, "webhooks must survive a subject erasure");

    // Status: contact_list_members does not exist in this schema and the
    // ClickHouse step is not configured → honest `partial`, with each gap
    // listed per store in the certificate.
    let (status, result_json) = request_status(&pool, &req_id).await;
    assert_eq!(
        status, "partial",
        "missing stores must yield partial, not completed"
    );
    assert_eq!(result.partial, Some(true));
    // The persisted result also records the partial flag.
    assert_eq!(result_json.unwrap()["partial"], true);
    let cert = result.deletion_confirmation.expect("certificate present");
    assert!(cert["stores"].as_array().unwrap().iter().any(|s| {
        s["store"] == "contact_list_members" && s["status"] == "skipped_missing_table"
    }));
    // F1: the ClickHouse store is listed honestly as not configured.
    assert!(cert["stores"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| { s["store"] == "clickhouse_events" && s["status"] == "skipped_not_configured" }));
    // F1: the real canonical stores are attested with their real outcomes.
    assert!(cert["stores"].as_array().unwrap().iter().any(|s| {
        s["store"] == "events" && s["status"] == "deleted" && s["rows_affected"] == 1
    }));
    assert!(cert["stores"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| { s["store"] == "messages" && s["status"] == "anonymized" }));
    assert!(cert["stores"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| { s["store"] == "users" && s["status"] == "anonymized" }));
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
        received_at: Some(chrono::Utc::now()),
        identity_verified_at: None,
        statutory_due_at: Some(chrono::Utc::now() + chrono::Duration::days(30)),
        extension_due_at: None,
        extension_reason: None,
        extension_notified_at: None,
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
    let gdpr = automation(pool.clone());
    // A row for the subject in the (non-deletable) events view's backing.
    sqlx::query(
        "INSERT INTO events_backing (id, tenant_id, event_type, recipient) VALUES ($1,$2,'delivered',$3)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&tenant)
    .bind(&subject)
    .execute(&pool)
    .await
    .unwrap();

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
    let result = gdpr
        .process_request(&req_id)
        .await
        .expect("rectification runs");

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
        .record_consent(
            &tenant,
            "sub-1",
            &email,
            compliance::types::ConsentType::Marketing,
            true,
            compliance::types::ConsentSource::Api,
            None,
        )
        .await
        .expect("first consent");
    assert!(first.granted);
    assert!(first.proof_document.is_some());

    // Withdraw, then grant again — must update the SAME row.
    gdpr.record_consent(
        &tenant,
        "sub-1",
        &email,
        compliance::types::ConsentType::Marketing,
        false,
        compliance::types::ConsentSource::PreferenceCenter,
        None,
    )
    .await
    .expect("withdraw");
    let third = gdpr
        .record_consent(
            &tenant,
            "sub-1",
            &email,
            compliance::types::ConsentType::Marketing,
            true,
            compliance::types::ConsentSource::Form,
            None,
        )
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

    let row: (
        bool,
        Option<String>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT granted, proof_document, granted_at, revoked_at FROM consent_records WHERE id = $1",
    )
    .bind(&third.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(row.0, "final state granted");
    assert!(
        row.1.is_some(),
        "proof document must be stored on the same row"
    );
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

    // F1/F9: seed every CANONICAL store the export must read.
    sqlx::query("INSERT INTO contacts (email, tenant_id, name) VALUES ($1,$2,'Subject Name')")
        .bind(&subject)
        .bind(&tenant)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO events (id, tenant_id, event_type, recipient) VALUES ($1,$2,'delivered',$3)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&tenant)
    .bind(&subject)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO messages (tenant_id, from_email, to_emails, subject, html_body)
         VALUES ($1, 'noreply@x.com', $2::jsonb, 'Your receipt', '<p>receipt</p>')",
    )
    .bind(&tenant)
    .bind(serde_json::json!([subject]))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO users (tenant_id, email, name, password_hash) VALUES ($1,$2,'Subject Name','secret-hash')")
        .bind(&tenant)
        .bind(&subject)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO consent_records (id, tenant_id, subscriber_id, email, consent_type, granted, source) VALUES ($1,$2,$3,$4,'marketing',true,'api')")
        .bind(Uuid::new_v4().to_string()).bind(&tenant).bind(&subject).bind(&subject)
        .execute(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO suppression_list (id, tenant_id, email, reason) VALUES ($1,$2,$3,'complaint')",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&tenant)
    .bind(&subject)
    .execute(&pool)
    .await
    .unwrap();
    // Snapshot email stored MIXED-CASE: the export must still match it
    // case-insensitively through the billing-address snapshot (F82/F9) and
    // the anonymized view must redact the mixed-case copy too.
    sqlx::query(
        "INSERT INTO invoices (id, tenant_id, amount, billing_address) VALUES ($1,$2,42,$3)",
    )
    .bind(short_id())
    .bind(&tenant)
    .bind(serde_json::json!({ "email": subject.to_uppercase(), "country": "EE" }).to_string())
    .execute(&pool)
    .await
    .unwrap();

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
        "contacts",
        "events",
        "messages",
        "users",
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
    assert_eq!(manifest["stores"]["contacts"]["records"], 1);
    assert_eq!(manifest["stores"]["events"]["records"], 1);
    assert_eq!(manifest["stores"]["messages"]["records"], 1);
    assert_eq!(manifest["stores"]["suppression_list"]["records"], 1);
    // Stores present but empty are still listed with their record count —
    // nothing is silently omitted from the data map.
    assert_eq!(manifest["stores"]["sessions"]["included"], true);
    assert_eq!(manifest["stores"]["sessions"]["records"], 0);
    // Tenant-owned resources are transparently labelled, never queried.
    assert_eq!(manifest["stores"]["api_keys"]["included"], false);
    assert_eq!(
        manifest["stores"]["webhooks"]["reason"],
        "tenant-owned resource: no personal data of the subject"
    );

    // The users row is exported anonymized-readable: no credentials.
    let users_json = serde_json::to_string(&data["users"]).unwrap();
    assert!(users_json.contains("Subject Name"));
    assert!(
        !users_json.contains("secret-hash"),
        "password hash stripped"
    );
    assert!(!users_json.contains("mfa_secret"), "mfa secret stripped");

    // Invoice PII is anonymized in the export — INCLUDING the mixed-case
    // copy (F9: case-insensitive matching on both the query and the
    // redaction).
    let invoices = serde_json::to_string(&data["invoices"]).unwrap();
    assert!(
        !invoices.contains(&subject),
        "invoice export must be anonymized"
    );
    assert!(
        !invoices.to_lowercase().contains(&subject),
        "even case-folded, the invoice export must not carry the address"
    );
    assert_eq!(
        data["invoices"].as_array().map(Vec::len),
        Some(1),
        "the mixed-case snapshot email must MATCH the export resolution (case-insensitive)"
    );
    assert!(invoices.contains("erased+"));

    // export_url points at this service's download route.
    assert!(
        export_row.1.contains("/gdpr/exports/"),
        "export_url must point at the crate's download route: {}",
        export_row.1
    );

    // The stored export is downloadable via the route handler.
    let export_id: String = sqlx::query_scalar("SELECT id FROM gdpr_exports WHERE request_id = $1")
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
    assert!(
        disposition.contains("attachment"),
        "Content-Disposition attachment"
    );

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
    sqlx::query(
        "UPDATE gdpr_exports SET expires_at = NOW() - INTERVAL '1 day' WHERE request_id = $1",
    )
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
        risk_engine: compliance::risk_scoring::RiskScoringEngine::new(
            pool.clone(),
            test_compliance_config(),
        ),
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
        audit_logger: std::sync::Arc::new(compliance::audit_logger::AuditLogger::new(
            pool.clone(),
            AuditConfig {
                retention_days: 365,
                hash_chain_enabled: true,
                signing_key: "integration-audit-key-0123456789abcdef".into(),
            },
        )),
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
        breach: compliance::breach_notification::BreachNotifier::new(
            pool.clone(),
            std::sync::Arc::new(compliance::audit_logger::AuditLogger::new(
                pool.clone(),
                AuditConfig {
                    retention_days: 365,
                    hash_chain_enabled: true,
                    signing_key: "integration-audit-key-0123456789abcdef".into(),
                },
            )),
            vec![],
            b"integration-breach-key".to_vec(),
        ),
        retention_sweeper: compliance::retention_sweep::RetentionSweeper::new(
            pool.clone(),
            7,
            30,
            365,
        ),
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
        breach_notification_emails: vec![],
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

/// E-3 (regression, deterministic): two INDEPENDENT AuditLogger instances —
/// what two service processes / pods appending to the same database are —
/// must never fork one tenant's chain, even appending concurrently. The old
/// code read the chain head from each logger's private in-memory cache, so
/// logger B built its entries on a head logger A had already superseded (a
/// fork); the advisory transaction lock plus the authoritative DB head read
/// in `log()` make the read-head → append critical section cross-process
/// atomic.
#[tokio::test]
async fn audit_chain_survives_concurrent_appends_from_independent_loggers() {
    let Some(pool) = test_pool("multi_logger", MAIN_SCHEMA).await else {
        return;
    };
    let make_logger = || {
        compliance::audit_logger::AuditLogger::new(
            pool.clone(),
            AuditConfig {
                retention_days: 365,
                hash_chain_enabled: true,
                signing_key: "multi-logger-audit-key-0123456789".into(),
            },
        )
    };
    let logger_a = std::sync::Arc::new(make_logger());
    let logger_b = std::sync::Arc::new(make_logger());
    logger_a.initialize().await.expect("init a");
    logger_b.initialize().await.expect("init b");

    let tenant = unique_tenant();
    let ctx = LogContext {
        tenant_id: Some(tenant.clone()),
        user_id: None,
        session_id: None,
        ip_address: None,
        user_agent: None,
    };

    // Seed one entry so both loggers initialize their view of a NON-empty
    // chain head (the fork-prone state: both caches hold this head).
    logger_a
        .log(
            AuditAction::Create,
            AuditResource::Subscriber,
            Some("seed"),
            serde_json::json!({"seed": true}),
            AuditOutcome::Success,
            None,
            &ctx,
        )
        .await
        .expect("seed entry");

    // Barrier-synchronized concurrent appends from both loggers.
    const PER_LOGGER: usize = 25;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let mut handles = Vec::new();
    for (tag, logger) in [("a", logger_a.clone()), ("b", logger_b.clone())] {
        let barrier = barrier.clone();
        let tenant = tenant.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            for i in 0..PER_LOGGER {
                let ctx = LogContext {
                    tenant_id: Some(tenant.clone()),
                    user_id: Some(format!("{tag}-{i}")),
                    session_id: None,
                    ip_address: None,
                    user_agent: None,
                };
                logger
                    .log(
                        AuditAction::Update,
                        AuditResource::Subscriber,
                        Some(&format!("{tag}-{i}")),
                        serde_json::json!({"logger": tag, "i": i}),
                        AuditOutcome::Success,
                        None,
                        &ctx,
                    )
                    .await
                    .expect("log entry persisted");
            }
        }));
    }
    for h in handles {
        h.await.expect("join");
    }

    // Exactly ONE linear chain: seed + 2×PER_LOGGER entries, no fork, no
    // gap — verified through a fresh logger that re-reads everything.
    let verifier = make_logger();
    let result = verifier
        .verify_chain(Some(&tenant), None, None)
        .await
        .unwrap();
    assert!(
        result.valid,
        "two independent loggers must produce one linear chain: {:?}",
        result.error
    );
    assert_eq!(
        result.entries_checked,
        1 + 2 * PER_LOGGER,
        "every append must be on the single chain (no forked/lost entries)"
    );
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
    let conflicting_live: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE id = $1")
        .bind(&old_ids[0])
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        conflicting_live, 1,
        "conflicting row must be preserved in the live table, not vanish"
    );
    // The other old entries moved to the archive.
    let archived_others: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs_archive WHERE id = ANY($1)")
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
    assert_eq!(
        queue,
        vec![stale.clone()],
        "stale entry returns to the main queue"
    );
    let processing: Vec<String> = redis::cmd("LRANGE")
        .arg("gdpr:request_processing")
        .arg(0)
        .arg(-1)
        .query_async(&mut *conn)
        .await
        .unwrap();
    assert_eq!(
        processing,
        vec![fresh],
        "fresh in-flight entry is untouched"
    );

    // Processing the batch completes the request AND acks the entry. The
    // status is honestly `partial`: the canonical deployment lacks
    // contact_list_members (listed as skipped in the manifest/certificate).
    let results = gdpr.process_queue_batch(10).await.unwrap();
    assert_eq!(results.len(), 1);
    let (status, _) = request_status(&pool, &req_id).await;
    assert_eq!(status, "partial");
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

// ── H-6: retention sweep enforcement ───────────────────────────────────────

/// Extra schema for sweep tests: canonical `tenants` table (with legal_hold)
/// and timestamp columns on the tracking/engagement stores.
const SWEEP_EXTRA_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS tenants (
    id VARCHAR(26) PRIMARY KEY,
    name VARCHAR(255) NOT NULL DEFAULT '',
    slug VARCHAR(100) NOT NULL DEFAULT '',
    plan VARCHAR(50) NOT NULL DEFAULT 'free',
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    settings JSONB NOT NULL DEFAULT '{}',
    metadata JSONB NOT NULL DEFAULT '{}',
    legal_hold BOOLEAN NOT NULL DEFAULT false,
    retention_days INT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_tenants_legal_hold ON tenants (id) WHERE legal_hold;
-- F4: the enterprise zero-retention contract flag (migration 092).
-- Migration 213: the per-run retention report (previously runtime-created).
CREATE TABLE IF NOT EXISTS retention_report (
    id TEXT PRIMARY KEY,
    ran_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    plan_tier TEXT NOT NULL DEFAULT 'default',
    report JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS legal_retention_archive (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    subject_email_hash TEXT NOT NULL,
    source_table TEXT NOT NULL,
    source_record_id TEXT NOT NULL,
    retention_class_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    state VARCHAR(30) NOT NULL DEFAULT 'legally_restricted',
    archived_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    statutory_expiry_at TIMESTAMPTZ NOT NULL,
    statutory_expired_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,
    disclosure JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (source_table, source_record_id)
);
CREATE TABLE IF NOT EXISTS ent_compliance_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL UNIQUE,
    enabled_frameworks TEXT[] NOT NULL DEFAULT '{}',
    status VARCHAR(30) NOT NULL DEFAULT 'inactive',
    zero_retention_mode BOOLEAN NOT NULL DEFAULT FALSE,
    encryption_at_rest BOOLEAN NOT NULL DEFAULT FALSE,
    encryption_in_transit BOOLEAN NOT NULL DEFAULT FALSE,
    audit_log_retention_days INTEGER NOT NULL DEFAULT 2555,
    data_retention_days INTEGER,
    require_mfa BOOLEAN NOT NULL DEFAULT FALSE,
    baa_signed BOOLEAN NOT NULL DEFAULT FALSE,
    dpa_signed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

/// A tenant id that fits tenants.id VARCHAR(26).
fn short_tenant() -> String {
    format!("t{}", &Uuid::new_v4().simple().to_string()[..20])
}

async fn sweep_pool(test_name: &str) -> Option<PgPool> {
    let pool = test_pool(test_name, MAIN_SCHEMA).await?;
    sqlx::raw_sql(SWEEP_EXTRA_SCHEMA)
        .execute(&pool)
        .await
        .expect("sweep extra schema");
    Some(pool)
}

/// H-6: the sweep deletes expired rows from the CANONICAL stores (events per
/// the 30d RET-007/009/010 minimum, messages per the 7d RET-001/002 minimum),
/// skips tenants on legal hold, purges expired gdpr_exports and stale outbox
/// rows, archives old audit logs, and writes an observable retention_report
/// row.
#[tokio::test]
async fn retention_sweep_enforces_durations_and_respects_legal_holds() {
    let Some(pool) = sweep_pool("sweep").await else {
        return;
    };
    let tenant_a = short_tenant(); // normal
    let tenant_b = short_tenant(); // legal hold
    for (id, held) in [(&tenant_a, false), (&tenant_b, true)] {
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, legal_hold)
             VALUES ($1, 'n', $1, 'free', $2)",
        )
        .bind(id)
        .bind(held)
        .execute(&pool)
        .await
        .unwrap();
    }

    // Expired and fresh rows per tenant in every canonical sweep store.
    // events: 30d default cutoff; messages: 7d default cutoff — 40d rows are
    // expired for both, 5d rows fresh for both.
    for tenant in [&tenant_a, &tenant_b] {
        let email = format!("u-{}@x.com", &tenant[..6]);
        for age_days in [40i64, 5] {
            sqlx::query(
                "INSERT INTO events (id, tenant_id, event_type, recipient, timestamp)
                 VALUES ($1, $2, 'delivered', $3, NOW() - ($4 || ' days')::interval)",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(tenant)
            .bind(&email)
            .bind(age_days.to_string())
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO messages (tenant_id, from_email, to_emails, subject, created_at)
                 VALUES ($1, 'noreply@x.com', $2::jsonb, 's', NOW() - ($3 || ' days')::interval)",
            )
            .bind(tenant)
            .bind(serde_json::json!([email]))
            .bind(age_days.to_string())
            .execute(&pool)
            .await
            .unwrap();
        }
    }

    // gdpr_exports: one expired (8d > 7d window), one fresh.
    for age_days in [8i64, 1] {
        sqlx::query(
            "INSERT INTO gdpr_exports
               (id, request_id, tenant_id, email, data, export_url, expires_at, created_at)
             VALUES ($1,'r',$2,'e@x.com','{}'::jsonb,'u', NOW() + INTERVAL '1 day',
                     NOW() - ($3 || ' days')::interval)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&tenant_a)
        .bind(age_days.to_string())
        .execute(&pool)
        .await
        .unwrap();
    }

    // Audit entries to be archived (audit_retention_days = 0 → all live rows).
    let audit = compliance::audit_logger::AuditLogger::new(
        pool.clone(),
        AuditConfig {
            retention_days: 0,
            hash_chain_enabled: true,
            signing_key: "sweep-audit-key-0123456789abcdef".into(),
        },
    );
    audit.initialize().await.expect("audit init");
    let ctx = LogContext {
        tenant_id: Some(tenant_a.clone()),
        user_id: None,
        session_id: None,
        ip_address: None,
        user_agent: None,
    };
    for i in 0..2 {
        audit
            .log(
                AuditAction::Read,
                AuditResource::Subscriber,
                Some(&format!("sweep-{i}")),
                serde_json::json!({"i": i}),
                AuditOutcome::Success,
                None,
                &ctx,
            )
            .await
            .unwrap();
    }

    let sweeper = compliance::retention_sweep::RetentionSweeper::new(pool.clone(), 7, 30, 0);
    let report = sweeper.run_sweep(&audit).await.expect("sweep runs");

    // Expired rows for tenant_a deleted; tenant_b (legal hold) retained;
    // fresh rows for both retained — in BOTH canonical stores.
    let expected = [("events", 30u32), ("messages", 7u32)];
    for (store, default_days) in expected {
        let remaining_a: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM {store} WHERE tenant_id = $1"
        ))
        .bind(&tenant_a)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            remaining_a, 1,
            "{store}: only the fresh row survives for the unheld tenant"
        );

        let remaining_b: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM {store} WHERE tenant_id = $1"
        ))
        .bind(&tenant_b)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            remaining_b, 2,
            "{store}: legal-hold tenant rows must survive"
        );

        let cat = report
            .categories
            .iter()
            .find(|c| c.store == store)
            .unwrap_or_else(|| panic!("{store} must be swept"));
        assert_eq!(cat.considered, 2, "{store}: both tenants' expired rows");
        assert_eq!(cat.deleted, 1, "{store}: unheld tenant's row deleted");
        assert_eq!(cat.skipped_legal_hold, 1, "{store}: held tenant skipped");
        assert_eq!(
            cat.retention_days, default_days,
            "{store}: registry default drives the cutoff"
        );
        assert_eq!(
            cat.legal_hold_check,
            compliance::retention_sweep::LegalHoldCheck::TenantsTable
        );
    }
    assert_eq!(report.categories.len(), 2, "events + messages only");

    // Exports: only the fresh one remains.
    let exports: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM gdpr_exports")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        exports, 1,
        "expired gdpr_exports must be purged (7d window)"
    );
    assert_eq!(report.gdpr_exports_deleted, 1);

    // Audit rows moved to the archive by the sweep (via archive()). The held
    // tenant has no rows here, so nothing is excluded by the hold filter.
    let live: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(live, 0, "audit rows past AUDIT_RETENTION_DAYS are archived");
    let archived: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs_archive")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(archived, 2);
    assert_eq!(report.audit_logs_archived, 2);

    // Out-of-scope stores are listed with their registry durations.
    let oos: Vec<&str> = report.out_of_scope.iter().map(|s| s.store).collect();
    assert_eq!(
        oos,
        vec!["clickhouse_analytics", "backups", "mailstore_blobs"]
    );

    // The run is observable: one retention_report row carrying the JSON.
    let (ran_rows, tier): (i64, String) =
        sqlx::query_as("SELECT COUNT(*), MAX(plan_tier) FROM retention_report")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(ran_rows, 1, "one retention_report row per run");
    assert_eq!(
        tier, "default",
        "no overrides configured — flat default tier"
    );
    let persisted: serde_json::Value = sqlx::query_scalar("SELECT report FROM retention_report")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(persisted["categories"].as_array().unwrap().len(), 2);
    assert_eq!(persisted["out_of_scope"].as_array().unwrap().len(), 3);
}

/// F4: per-tenant retention overrides and zero-retention mode drive the
/// cutoffs; an override the plan rejects falls back to the default.
#[tokio::test]
async fn retention_sweep_honors_per_tenant_retention_and_zero_retention() {
    let Some(pool) = sweep_pool("sweep_tiers").await else {
        return;
    };
    // free plan, override 40d — REJECTED for events (free caps RET-007 at
    // 7d), so events fall back to the 30d default; 40d-old rows survive.
    let tenant_override = short_tenant();
    // zero-retention tenant: everything is purged immediately, even a row
    // written a moment ago.
    let tenant_zero = short_tenant();
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, legal_hold, retention_days)
         VALUES ($1,'n',$1,'free',false,$2)",
    )
    .bind(&tenant_override)
    .bind(40i32)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, legal_hold)
         VALUES ($1,'n',$1,'free',false)",
    )
    .bind(&tenant_zero)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO ent_compliance_configs (tenant_id, zero_retention_mode)
         VALUES ($1, true)",
    )
    .bind(&tenant_zero)
    .execute(&pool)
    .await
    .unwrap();

    for tenant in [&tenant_override, &tenant_zero] {
        sqlx::query(
            "INSERT INTO events (id, tenant_id, event_type, recipient, timestamp)
             VALUES ($1, $2, 'delivered', 'z@x.com', NOW() - INTERVAL '35 days')",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(tenant)
        .execute(&pool)
        .await
        .unwrap();
    }

    let audit = compliance::audit_logger::AuditLogger::new(
        pool.clone(),
        AuditConfig {
            retention_days: 365,
            hash_chain_enabled: true,
            signing_key: "sweep-tier-key-0123456789abcdef".into(),
        },
    );
    audit.initialize().await.expect("audit init");
    let sweeper = compliance::retention_sweep::RetentionSweeper::new(pool.clone(), 7, 30, 365);
    let report = sweeper.run_sweep(&audit).await.expect("sweep runs");

    let events = report
        .categories
        .iter()
        .find(|c| c.store == "events")
        .unwrap();
    // The 40d override exceeds the free plan's RET-007 cap (7d) — the sweep
    // must NOT honor it; rows older than the 30d default are deleted anyway,
    // so both tenants' 35d rows go.
    assert_eq!(
        events.custom_retention_tenants, 0,
        "plan-violating override ignored"
    );
    assert_eq!(
        events.deleted, 2,
        "both 35d rows past the 30d default cutoff"
    );
    assert_eq!(events.zero_retention_tenants, 1);

    let override_left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE tenant_id = $1")
        .bind(&tenant_override)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(override_left, 0);
    let zero_left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE tenant_id = $1")
        .bind(&tenant_zero)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(zero_left, 0, "zero-retention tenant fully purged");

    // An override WITHIN plan bounds shrinks the window: free plan allows
    // 1..7d for RET-007, so 5d purges a 6d-old row the default would keep.
    let tenant_short = short_tenant();
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, legal_hold, retention_days)
         VALUES ($1,'n',$1,'free',false,5)",
    )
    .bind(&tenant_short)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO events (id, tenant_id, event_type, recipient, timestamp)
         VALUES ($1, $2, 'delivered', 'z@x.com', NOW() - INTERVAL '6 days')",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&tenant_short)
    .execute(&pool)
    .await
    .unwrap();
    let report2 = sweeper.run_sweep(&audit).await.expect("second sweep");
    let events2 = report2
        .categories
        .iter()
        .find(|c| c.store == "events")
        .unwrap();
    assert_eq!(
        events2.custom_retention_tenants, 1,
        "the in-bounds 5d override is honored"
    );
    assert_eq!(events2.deleted, 1, "the 6d-old row is past the 5d override");
    assert_eq!(
        report2.plan_tier, "per-tenant",
        "overrides participated — the report says so"
    );
}

/// F5: audit trim under legal hold — a held tenant's rows stay LIVE (not
/// archived away), and NULL-tenant rows are kept while any hold is active.
#[tokio::test]
async fn audit_archive_respects_legal_holds() {
    let Some(pool) = sweep_pool("audit_hold").await else {
        return;
    };
    let held = short_tenant();
    let normal = short_tenant();
    for (id, is_held) in [(&held, true), (&normal, false)] {
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, legal_hold)
             VALUES ($1,'n',$1,'free',$2)",
        )
        .bind(id)
        .bind(is_held)
        .execute(&pool)
        .await
        .unwrap();
    }

    let audit = compliance::audit_logger::AuditLogger::new(
        pool.clone(),
        AuditConfig {
            retention_days: 0,
            hash_chain_enabled: true,
            signing_key: "audit-hold-key-0123456789abcdef".into(),
        },
    );
    audit.initialize().await.expect("audit init");
    for tenant in [&held, &normal] {
        let ctx = LogContext {
            tenant_id: Some(tenant.clone()),
            user_id: None,
            session_id: None,
            ip_address: None,
            user_agent: None,
        };
        audit
            .log(
                AuditAction::Read,
                AuditResource::Subscriber,
                Some("hold"),
                serde_json::json!({}),
                AuditOutcome::Success,
                None,
                &ctx,
            )
            .await
            .unwrap();
    }

    audit
        .archive(chrono::Utc::now() + chrono::Duration::days(1))
        .await
        .expect("archive");

    let held_live: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1")
        .bind(&held)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(held_live, 1, "held tenant's audit rows must stay live");
    let normal_live: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1")
            .bind(&normal)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(normal_live, 0, "unheld tenant's rows archive normally");
    let archived: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs_archive WHERE tenant_id = $1")
            .bind(&normal)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(archived, 1);
}

/// Missing canonical stores are reported as skipped — never silently counted.
#[tokio::test]
async fn retention_sweep_reports_missing_stores() {
    // MAIN_SCHEMA has events; a deployment without the messages store.
    let Some(pool) = test_pool("sweep_missing", MAIN_SCHEMA).await else {
        return;
    };
    sqlx::query("DROP TABLE messages")
        .execute(&pool)
        .await
        .unwrap();

    let audit = compliance::audit_logger::AuditLogger::new(
        pool.clone(),
        AuditConfig {
            retention_days: 365,
            hash_chain_enabled: true,
            signing_key: "sweep-missing-key-0123456789abcdef".into(),
        },
    );
    audit.initialize().await.expect("audit init");

    let sweeper = compliance::retention_sweep::RetentionSweeper::new(pool.clone(), 7, 30, 365);
    let report = sweeper.run_sweep(&audit).await.expect("sweep runs");

    let messages = report
        .categories
        .iter()
        .find(|c| c.store == "messages")
        .unwrap();
    assert_eq!(
        messages.status,
        compliance::retention_sweep::SweepStatus::SkippedMissingStore
    );
    assert_eq!(messages.deleted, 0);
    // No tenants table in this deployment — reported honestly.
    assert_eq!(
        messages.legal_hold_check,
        compliance::retention_sweep::LegalHoldCheck::TenantsTableMissing
    );
    // The sweep degrades gracefully: gdpr_exports table absent too, but the
    // run itself completes and writes its report.
    let report_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM retention_report")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(report_rows, 1);
}

// ── D: DSR verification outbox ─────────────────────────────────────────────

/// Submit writes the raw token to dsr_verification_outbox (same transaction),
/// the worker queue drains pending entries, and mark_outbox_sent completes
/// the handoff.
#[tokio::test]
async fn dsr_submit_writes_verification_outbox() {
    let Some(pool) = test_pool("outbox", MAIN_SCHEMA).await else {
        return;
    };
    let gdpr = automation(pool.clone());

    let tenant = unique_tenant();
    let subject = format!("outbox-{}@x.com", Uuid::new_v4().simple());
    let (request, token) = gdpr
        .submit_request(
            &tenant,
            compliance::types::DataSubjectRequestType::Access,
            &subject,
        )
        .await
        .expect("submit succeeds");

    // Exactly one pending outbox row for the request, carrying the raw token
    // (the requests table stores only its SHA-256 hash) and the verify URL.
    let pending = gdpr.pending_verification_outbox(10).await.unwrap();
    assert_eq!(pending.len(), 1);
    let entry = &pending[0];
    assert_eq!(entry.request_id, request.id);
    assert_eq!(entry.email, subject);
    assert_eq!(entry.status, "pending");
    assert!(entry.sent_at.is_none());
    assert_eq!(
        entry.verification_token, token,
        "raw token must be queued for delivery"
    );

    // The queued token is the one that verifies the request (its SHA-256
    // matches the stored verification_token_hash — checked in SQL to avoid
    // the Redis enqueue path inside verify_request).
    let hash_matches: bool = sqlx::query_scalar(
        "SELECT verification_token_hash = encode(sha256($2::bytea), 'hex') \
         FROM data_subject_requests WHERE id = $1",
    )
    .bind(&request.id)
    .bind(token.as_bytes())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        hash_matches,
        "outbox token must hash to the request's stored token hash"
    );

    // Mark-sent completes the handoff; the queue drains.
    gdpr.mark_outbox_sent(&entry.id).await.unwrap();
    let after = gdpr.pending_verification_outbox(10).await.unwrap();
    assert!(after.is_empty(), "sent entries leave the pending queue");
    let status: String =
        sqlx::query_scalar("SELECT status FROM dsr_verification_outbox WHERE id = $1")
            .bind(&entry.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status, "sent");
}

// ── D: DSR outbox flush — pending rows become real system email ────────────

/// Minimal mail-pipeline shapes the flush job touches (mirrors the prod
/// columns written by api-server's system_sender / the sales dispatcher):
/// the system `domains` row, the `messages` audit row, and `email_queue`
/// (both column families), plus the `gdpr_requests` CP mirror submit writes.
const OUTBOX_FLUSH_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS gdpr_requests (
    id VARCHAR(26) PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    email TEXT NOT NULL,
    request_type TEXT NOT NULL,
    status TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS domains (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    dkim_enabled BOOLEAN NOT NULL DEFAULT false,
    dkim_selector TEXT,
    dkim_public_key TEXT,
    dkim_private_key TEXT,
    ses_verified BOOLEAN NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS messages (
    id UUID PRIMARY KEY,
    tenant_id TEXT,
    from_email TEXT NOT NULL,
    to_emails JSONB NOT NULL,
    subject TEXT,
    html_body TEXT,
    text_body TEXT,
    status TEXT NOT NULL,
    tags JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS email_queue (
    id UUID PRIMARY KEY,
    message_id UUID,
    tenant_id TEXT,
    domain_id UUID,
    from_address TEXT NOT NULL,
    to_addresses TEXT[] NOT NULL,
    subject TEXT NOT NULL,
    "from" TEXT,
    "to" TEXT,
    html TEXT,
    text TEXT,
    tags TEXT[],
    metadata JSONB,
    scheduled_at TIMESTAMPTZ,
    priority INT NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

async fn flush_pool(test_name: &str) -> Option<PgPool> {
    test_pool(test_name, &format!("{MAIN_SCHEMA}{OUTBOX_FLUSH_SCHEMA}")).await
}

/// The email_queue columns the round-trip test asserts on (clippy: factored
/// out of the inline tuple).
type QueuedEmailRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<uuid::Uuid>,
    String,
    i32,
    serde_json::Value,
);

async fn seed_system_domain(pool: &PgPool) -> uuid::Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO domains \
             (id, tenant_id, name, status, dkim_enabled, dkim_selector, \
              dkim_public_key, dkim_private_key, ses_verified) \
         VALUES ($1, 'system_internal_tenant01', 'apexmail.ee', 'verified', true, \
                 'apexmail', 'pubkey', 'dkim:v1:encrypted', true)",
    )
    .bind(id)
    .execute(pool)
    .await
    .unwrap();
    id
}

/// The flush job queues the verification email through the platform's
/// system-email path (messages + email_queue, system sender + domain),
/// marks the outbox row sent transactionally, and is idempotent + bounded.
#[tokio::test]
async fn dsr_outbox_flush_queues_system_email_and_marks_sent() {
    let Some(pool) = flush_pool("outbox_flush").await else {
        return;
    };
    let gdpr = automation(pool.clone());
    let domain_id = seed_system_domain(&pool).await;

    let tenant = unique_tenant();
    let subject = format!("flush-{}@x.com", Uuid::new_v4().simple());
    let (request, token) = gdpr
        .submit_request(
            &tenant,
            compliance::types::DataSubjectRequestType::Access,
            &subject,
        )
        .await
        .expect("submit succeeds");

    let flusher =
        compliance::dsr_outbox_flush::DsrOutboxFlusher::new(pool.clone(), test_gdpr_config());
    let summary = flusher.flush_once().await.expect("flush runs");
    assert_eq!(summary.queued, 1);
    assert_eq!(summary.failed, 0);
    assert!(!summary.skipped_sender_not_ready);

    // The queue row carries BOTH column families under the system sender —
    // exactly the shape the delivery worker claims (worker reads
    // "from"/"to"/html/text; get_domain authorizes on domain_id+tenant_id).
    let queued: QueuedEmailRow = sqlx::query_as(
        "SELECT from_address, to_addresses[1], subject, \"from\", \"to\", html, text, \
                domain_id, status, priority, metadata \
         FROM email_queue",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(queued.0, "noreply@apexmail.ee");
    assert_eq!(queued.1, subject);
    assert_eq!(
        queued.3, "noreply@apexmail.ee",
        "\"from\" mirrors from_address"
    );
    assert_eq!(queued.4, subject, "\"to\" mirrors to_addresses[1]");
    assert_eq!(
        queued.7.map(|d| d.to_string()),
        Some(domain_id.to_string()),
        "queue row is authorized against the system domain"
    );
    assert_eq!(queued.8, "pending");
    assert_eq!(queued.9, 5, "system-email priority");
    assert_eq!(queued.10["request_id"], request.id.as_str());
    assert_eq!(queued.10["source"], "compliance-dsr-outbox");
    assert_eq!(queued.10["dsr_tenant"], tenant.as_str());
    // The email delivers BOTH halves of verification: link + raw token.
    assert!(
        queued.5.contains("gdpr.test.local/gdpr/verify/"),
        "html has the verify URL"
    );
    assert!(queued.5.contains(&token), "html has the raw token");
    assert!(queued.6.contains(&token), "plain text has the raw token");

    // The messages audit row exists and is queued under the system tenant.
    let (msg_status, msg_tenant, msg_from): (String, String, String) =
        sqlx::query_as("SELECT status, tenant_id, from_email FROM messages")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(msg_status, "queued");
    assert_eq!(msg_tenant, "system_internal_tenant01");
    assert_eq!(msg_from, "noreply@apexmail.ee");

    // The outbox row is sent (same transaction), and a second tick neither
    // re-queues nor double-inserts.
    let (status, sent_at): (String, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT status, sent_at FROM dsr_verification_outbox")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status, "sent");
    assert!(sent_at.is_some());

    let again = flusher.flush_once().await.expect("second flush");
    assert_eq!(again.queued, 0, "sent entries are never re-queued");
    let queue_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM email_queue")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(queue_rows, 1, "idempotent: exactly one queue row");
}

/// Without a ready system sender the tick skips (no attempts burned); with
/// the sender ready but delivery persistently failing, attempts increment
/// per tick and the row is parked as `failed` at the cap; the batch bound
/// caps how many rows one tick touches.
#[tokio::test]
async fn dsr_outbox_flush_retries_then_caps_attempts() {
    let Some(pool) = flush_pool("outbox_flush_retry").await else {
        return;
    };
    let gdpr = automation(pool.clone());

    let tenant = unique_tenant();
    let emails: Vec<String> = (0..3)
        .map(|i| format!("cap-{i}-{}@x.com", Uuid::new_v4().simple()))
        .collect();
    for email in &emails {
        gdpr.submit_request(
            &tenant,
            compliance::types::DataSubjectRequestType::Access,
            email,
        )
        .await
        .expect("submit succeeds");
    }

    let mut cfg = test_gdpr_config();
    cfg.outbox_flush_batch = 2; // bound: one tick touches at most 2 rows
    cfg.outbox_flush_max_attempts = 3;
    let flusher = compliance::dsr_outbox_flush::DsrOutboxFlusher::new(pool.clone(), cfg);

    // No system domain row → infrastructure skip, attempts untouched.
    let skipped = flusher.flush_once().await.expect("flush runs");
    assert!(skipped.skipped_sender_not_ready);
    assert_eq!(skipped.queued, 0);
    let (pending, attempts): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(attempts), 0) FROM dsr_verification_outbox WHERE status = 'pending'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (pending, attempts),
        (3, 0),
        "sender-not-ready burns no attempts"
    );

    // Sender ready, but the mail pipeline is broken (messages table gone) →
    // per-row failure path: bounded batch, attempts increment, cap → failed.
    seed_system_domain(&pool).await;
    sqlx::query("DROP TABLE messages")
        .execute(&pool)
        .await
        .unwrap();

    let first = flusher.flush_once().await.expect("flush runs");
    assert_eq!(first.failed, 2, "batch bound caps the tick at 2 rows");
    assert_eq!(first.queued, 0);
    let statuses: Vec<(String, i32)> =
        sqlx::query_as("SELECT status, attempts FROM dsr_verification_outbox ORDER BY created_at")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(statuses.iter().filter(|(s, _)| s == "pending").count(), 3);
    // ORDER BY created_at: the two OLDEST rows are the batch the bound let
    // this tick touch; the newest row must remain untouched (attempts 0).
    assert_eq!(statuses[0], ("pending".to_string(), 1));
    assert_eq!(statuses[1], ("pending".to_string(), 1));
    assert_eq!(statuses[2], ("pending".to_string(), 0));

    flusher.flush_once().await.expect("flush runs"); // rows 1-2: attempts 2
    flusher.flush_once().await.expect("flush runs"); // rows 1-2: attempts 3 → cap → failed
                                                     // Rows 1-2 parked as failed leave the retry set, so subsequent ticks
                                                     // admit row 3 (batch bound 2): three more flushes walk it to the cap.
    for _ in 0..3 {
        flusher.flush_once().await.expect("flush runs");
    }
    let after: Vec<(String, i32)> =
        sqlx::query_as("SELECT status, attempts FROM dsr_verification_outbox ORDER BY created_at")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert!(
        after.iter().all(|(s, a)| s == "failed" && *a == 3),
        "rows park as failed at the attempts cap: {after:?}"
    );
    // Failed rows leave the retry set entirely.
    assert!(gdpr
        .pending_verification_outbox(10)
        .await
        .unwrap()
        .is_empty());
    let queue_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM email_queue")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(queue_rows, 0, "nothing was ever queued");
}

// ── B: breach notification state machine ───────────────────────────────────

/// The breach workflow moved to the canonical-schema release tests
/// (`tests/gdpr_governance_release_tests.rs`): the state machine
/// (detected → triage → notifiable → authority_queued → authority_submitted →
/// authority_acknowledged), the mandatory receipt gate and the Art. 34
/// subject-notification outbox are exercised there against the REAL migration
/// chain, not a hand-written subset.

// ── F82: invoice identity via the immutable billing snapshot ───────────────

/// The finding's exact scenario: issue an invoice containing the subject's
/// snapshot email, change the live billing address, request the export —
/// the invoice must still be included (resolved through the immutable
/// snapshot + the tenant identity relation, not a mutable column).
#[tokio::test]
async fn invoice_export_survives_live_address_change() {
    let Some(pool) = test_pool("f82_snapshot", MAIN_SCHEMA).await else {
        return;
    };
    let tenant = unique_tenant();
    let subject = format!("f82-{}@x.com", Uuid::new_v4().simple());
    let req_id = Uuid::new_v4().to_string();
    seed_request(&pool, &req_id, &tenant, &subject, "access").await;

    sqlx::query("INSERT INTO users (tenant_id, email, name, password_hash) VALUES ($1,$2,'S','h')")
        .bind(&tenant)
        .bind(&subject)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO invoices (id, tenant_id, amount, billing_address) VALUES ($1,$2,42,$3)",
    )
    .bind(short_id())
    .bind(&tenant)
    .bind(
        serde_json::json!({ "email": subject, "country": "EE", "company_name": "Subject OÜ" })
            .to_string(),
    )
    .execute(&pool)
    .await
    .unwrap();

    let gdpr = automation(pool.clone());
    gdpr.process_request(&req_id)
        .await
        .expect("access export succeeds against the snapshot model");

    let (data,): (serde_json::Value,) =
        sqlx::query_as("SELECT data FROM gdpr_exports WHERE request_id = $1")
            .bind(&req_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let invoices = serde_json::to_string(&data["invoices"]).unwrap();
    assert_eq!(
        data["invoices"].as_array().map(Vec::len),
        Some(1),
        "the snapshot-owned invoice must be included in the export"
    );
    assert!(!invoices.contains(&subject), "export is anonymized");
    assert!(invoices.contains("erased+"), "snapshot email redacted");
    assert!(
        invoices.contains("Subject OÜ"),
        "the retained financial record itself survives"
    );

    pool.close().await;
}

/// An invoice whose snapshot carries a DIFFERENT email (e.g. a company
/// bookkeeping address) and no subject-user relation stays out of the
/// subject's export — the mapping is explicit, not whole-tenant.
#[tokio::test]
async fn invoice_export_excludes_non_subject_snapshots() {
    let Some(pool) = test_pool("f82_exclusion", MAIN_SCHEMA).await else {
        return;
    };
    let tenant = unique_tenant();
    let subject = format!("f82b-{}@x.com", Uuid::new_v4().simple());
    let req_id = Uuid::new_v4().to_string();
    seed_request(&pool, &req_id, &tenant, &subject, "access").await;

    // NO users row for the subject in this tenant, and the invoice snapshot
    // points at a different address: not the subject's invoice.
    sqlx::query(
        "INSERT INTO invoices (id, tenant_id, amount, billing_address) VALUES ($1,$2,42,$3)",
    )
    .bind(short_id())
    .bind(&tenant)
    .bind(serde_json::json!({ "email": "billing@corp.example", "country": "DE" }).to_string())
    .execute(&pool)
    .await
    .unwrap();

    let gdpr = automation(pool.clone());
    gdpr.process_request(&req_id).await.expect("export");
    let (data,): (serde_json::Value,) =
        sqlx::query_as("SELECT data FROM gdpr_exports WHERE request_id = $1")
            .bind(&req_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        data["invoices"].as_array().map(Vec::len),
        Some(0),
        "an unrelated snapshot is not the subject's invoice"
    );

    pool.close().await;
}

/// Erasure inventory uses the SAME explicit mapping: only the snapshot
/// carrying the subject's email is redacted; the row and the other
/// invoice's snapshot survive untouched.
#[tokio::test]
async fn invoice_erasure_redacts_only_the_subject_snapshot() {
    let Some(pool) = test_pool("f82_erasure", MAIN_SCHEMA).await else {
        return;
    };
    let tenant = unique_tenant();
    let subject = format!("f82e-{}@x.com", Uuid::new_v4().simple());
    let other = format!("other-{}@x.com", Uuid::new_v4().simple());

    for email in [&subject, &other] {
        sqlx::query(
            "INSERT INTO invoices (id, tenant_id, amount, billing_address) VALUES ($1,$2,50,$3)",
        )
        .bind(short_id())
        .bind(&tenant)
        .bind(serde_json::json!({ "email": email, "country": "EE" }).to_string())
        .execute(&pool)
        .await
        .unwrap();
    }

    let gdpr = automation(pool.clone());
    let request = compliance::types::DataSubjectRequest {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant.clone(),
        email: subject.clone(),
        request_type: compliance::types::DataSubjectRequestType::Erasure,
        verification_token_hash: "h".into(),
        verified: true,
        verified_at: None,
        status: compliance::types::RequestStatus::Verified,
        requested_at: chrono::Utc::now(),
        processed_at: None,
        completed_at: None,
        expires_at: chrono::Utc::now(),
        result: None,
        received_at: Some(chrono::Utc::now()),
        identity_verified_at: None,
        statutory_due_at: Some(chrono::Utc::now() + chrono::Duration::days(30)),
        extension_due_at: None,
        extension_reason: None,
        extension_notified_at: None,
    };
    let result = gdpr
        .erase_store(
            &request,
            ErasureStore::AnonymizeInvoiceSnapshot { name: "invoices" },
        )
        .await;
    assert_eq!(
        result.status,
        StoreErasureStatus::Anonymized,
        "error was: {:?}",
        result.error
    );
    assert_eq!(result.rows_affected, 1, "only the subject's snapshot");

    let redacted: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM invoices WHERE tenant_id = $1 AND billing_address LIKE '%erased+%'",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(redacted, 1);
    let untouched: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM invoices WHERE tenant_id = $1 AND billing_address LIKE '%' || $2 || '%'",
    )
    .bind(&tenant)
    .bind(&other)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(untouched, 1, "the other invoice is untouched");
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invoices WHERE tenant_id = $1")
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(total, 2, "financial records are retained, never deleted");

    pool.close().await;
}
