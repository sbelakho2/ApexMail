//! Adversarial DB-backed GDPR tests that inject schema faults (missing
//! tables, hostile table shapes) and probe the ClickHouse purge path.
//!
//! (The DDL fault injections live in an integration test file on purpose:
//! the `no_runtime_schema_ddl_in_compliance_source` release guard forbids
//! DDL strings anywhere under `crates/compliance/src`.)

use compliance::config::GdprConfig;
use compliance::gdpr_automation::{ErasureStore, GdprAutomation, StoreErasureStatus};
use compliance::types::{DataSubjectRequest, DataSubjectRequestType, RequestStatus};
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

// ── Bootstrap ───────────────────────────────────────────────────────────────

async fn hostile_db(suffix: &str) -> Option<PgPool> {
    match migrator::test_support::fresh_canonical_pool(
        &format!("gdpr_hostile_{suffix}"),
        &format!("gdpr_hostile_{suffix}"),
    )
    .await
    {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

fn config() -> GdprConfig {
    GdprConfig {
        data_retention_days: 730,
        export_format: "json".into(),
        deletion_grace_period_days: 30,
        request_expiration_days: 30,
        export_expiration_days: 7,
        export_base_url: "https://gdpr.test.local".into(),
        verify_base_url: "https://gdpr.test.local".into(),
        consent_signing_key: "hostile-store-test-key-0123456789".into(),
        access_request_max_messages: 10_000,
        system_from_address: "noreply@apexmail.ee".into(),
        outbox_flush_batch: 25,
        outbox_flush_max_attempts: 5,
        clickhouse_erasure_enabled: false,
        clickhouse_url: String::new(),
        clickhouse_database: "apexmail".into(),
        clickhouse_user: "default".into(),
        clickhouse_password: String::new(),
    }
}

fn automation_with(pool: PgPool, cfg: GdprConfig) -> GdprAutomation {
    GdprAutomation::new(pool, dummy_redis(), cfg)
}

fn dummy_redis() -> deadpool_redis::Pool {
    let cfg = deadpool_redis::Config::from_url("redis://127.0.0.1:1/99");
    cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .expect("fake redis pool")
}

fn unique_tenant() -> String {
    format!("t-{}", &Uuid::new_v4().simple().to_string()[..23])
}

fn erasure_request(tenant: &str, email: &str) -> DataSubjectRequest {
    DataSubjectRequest {
        id: format!("REQ-{}", &Uuid::new_v4().simple().to_string()[..12]),
        tenant_id: tenant.into(),
        request_type: DataSubjectRequestType::Erasure,
        email: email.into(),
        verification_token_hash: String::new(),
        verified: true,
        verified_at: None,
        status: RequestStatus::Verified,
        requested_at: Utc::now(),
        processed_at: None,
        completed_at: None,
        expires_at: Utc::now(),
        result: None,
        received_at: Some(Utc::now()),
        identity_verified_at: None,
        statutory_due_at: None,
        extension_due_at: None,
        extension_reason: None,
        extension_notified_at: None,
    }
}

// ── Erasure store status matrix (schema-fault injection) ────────────────────

#[tokio::test]
async fn erasure_store_outcomes_are_reported_honestly() {
    let Some(pool) = hostile_db("store_matrix").await else {
        return;
    };
    let gdpr = automation_with(pool.clone(), config());
    let tenant = unique_tenant();
    let email = format!("matrix-{}@example.test", Uuid::new_v4().simple());

    sqlx::query("INSERT INTO tenants (id, name, slug, plan) VALUES ($1, 'n', $1, 'free')")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("tenant");
    let request = erasure_request(&tenant, &email);

    // Absent optional store: skipped, never counted as deleted.
    let missing = gdpr
        .erase_store(
            &request,
            ErasureStore::TableBySubjectEmail {
                name: "contact_list_members",
                table: "contact_list_members",
                email_column: "subscriber_email",
            },
        )
        .await;
    assert!(matches!(
        missing.status,
        StoreErasureStatus::SkippedMissingTable
    ), "{missing:?}");

    // A retained store answers with its reason and touches nothing.
    let retained = gdpr
        .erase_store(
            &request,
            ErasureStore::Retained {
                name: "audit_logs",
                reason: "retained: accountability trail (Art. 30)",
            },
        )
        .await;
    assert!(matches!(
        retained.status,
        StoreErasureStatus::Retained("retained: accountability trail (Art. 30)")
    ), "{retained:?}");
    assert_eq!(retained.rows_affected, 0);

    // Anonymize-by-column against a real table: the subject's copy is
    // rewritten, an absent candidate column is tolerated.
    sqlx::query("CREATE TABLE dsr_redact_demo (tenant_id text, email text, alt_email text)")
        .execute(&pool)
        .await
        .expect("demo table");
    sqlx::query("INSERT INTO dsr_redact_demo VALUES ($1, $2, $2)")
        .bind(&tenant)
        .bind(&email)
        .execute(&pool)
        .await
        .expect("demo row");
    let anonymized = gdpr
        .erase_store(
            &request,
            ErasureStore::AnonymizeSubjectEmail {
                name: "dsr_redact_demo",
                table: "dsr_redact_demo",
                columns: &["email", "alt_email", "ghost_column"],
            },
        )
        .await;
    assert!(matches!(anonymized.status, StoreErasureStatus::Anonymized), "{anonymized:?}");
    assert_eq!(anonymized.rows_affected, 2, "both email-bearing columns rewritten");
    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM dsr_redact_demo WHERE email = $1 OR alt_email = $1")
            .bind(&email)
            .fetch_one(&pool)
            .await
            .expect("demo count");
    assert_eq!(remaining, 0);

    // A table where NO candidate column exists: skipped.
    sqlx::query("CREATE TABLE dsr_redact_absent (tenant_id text, note text)")
        .execute(&pool)
        .await
        .expect("absent table");
    let skipped = gdpr
        .erase_store(
            &request,
            ErasureStore::AnonymizeSubjectEmail {
                name: "dsr_redact_absent",
                table: "dsr_redact_absent",
                columns: &["email"],
            },
        )
        .await;
    assert!(matches!(
        skipped.status,
        StoreErasureStatus::SkippedMissingTable
    ), "{skipped:?}");

    // A genuine update failure (CHECK constraint rejects the marker) is a
    // FAILED store, not a skip.
    sqlx::query(
        "CREATE TABLE dsr_redact_locked (tenant_id text, email text CHECK (email NOT LIKE 'erased+%'))",
    )
    .execute(&pool)
    .await
    .expect("locked table");
    sqlx::query("INSERT INTO dsr_redact_locked VALUES ($1, $2)")
        .bind(&tenant)
        .bind(&email)
        .execute(&pool)
        .await
        .expect("locked row");
    let failed = gdpr
        .erase_store(
            &request,
            ErasureStore::AnonymizeSubjectEmail {
                name: "dsr_redact_locked",
                table: "dsr_redact_locked",
                columns: &["email"],
            },
        )
        .await;
    assert!(matches!(failed.status, StoreErasureStatus::Failed), "{failed:?}");
    assert!(failed.error.is_some());

    // The AI chat history of the subject's account is deleted.
    sqlx::query("INSERT INTO users (tenant_id, email, password_hash) VALUES ($1, $2, 'x')")
        .bind(&tenant)
        .bind(&email)
        .execute(&pool)
        .await
        .expect("user");
    let user_id: String = sqlx::query_scalar("SELECT id::text FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&pool)
        .await
        .expect("user id");
    sqlx::query(
        "INSERT INTO ai_chat_messages (tenant_id, user_id, role, content) VALUES ($1, $2, 'user', 'hi')",
    )
    .bind(&tenant)
    .bind(&user_id)
    .execute(&pool)
    .await
    .expect("chat");
    let chat = gdpr.erase_store(&request, ErasureStore::AiChatByUserEmail).await;
    assert!(matches!(chat.status, StoreErasureStatus::Deleted), "{chat:?}");
    assert_eq!(chat.rows_affected, 1);
}

// ── ClickHouse best-effort purge ─────────────────────────────────────────────

#[tokio::test]
async fn clickhouse_purge_reports_mutation_submitted_when_reachable() {
    let Some(base_url) = std::env::var("CLICKHOUSE_TEST_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        return; // no analytics node in this deployment
    };
    let Some(pool) = hostile_db("clickhouse").await else {
        return;
    };
    let client = reqwest::Client::new();
    // Provision an isolated database+table so the mutation has a real
    // target; if the node is unreachable, soft-skip.
    let database = format!("apexmail_dsar_erase_{}", Uuid::new_v4().simple());
    for statement in [
        format!("CREATE DATABASE IF NOT EXISTS {database}"),
        format!(
            "CREATE TABLE IF NOT EXISTS {database}.events \
             (recipient String) ENGINE = MergeTree ORDER BY tuple()"
        ),
        format!("INSERT INTO {database}.events VALUES ('victim@example.test')"),
    ] {
        if client
            .post(format!("{base_url}/"))
            .query(&[("query", statement.as_str())])
            .send()
            .await
            .and_then(|response| response.error_for_status())
            .is_err()
        {
            eprintln!("ClickHouse node unreachable — soft skip");
            return;
        }
    }

    let mut cfg = config();
    cfg.clickhouse_erasure_enabled = true;
    cfg.clickhouse_url = base_url.clone();
    cfg.clickhouse_database = database;
    let gdpr = automation_with(pool.clone(), cfg);

    let request = erasure_request("t-ch", "Victim@Example.test");
    let outcome = gdpr.erase_store(&request, ErasureStore::ClickHouseEvents).await;
    assert!(
        matches!(outcome.status, StoreErasureStatus::MutationSubmitted),
        "a live node must accept the mutation submission: {outcome:?}"
    );

    // A disabled configuration is reported as skipped-not-configured —
    // never silently omitted from the certificate.
    let disabled = automation_with(pool, config());
    let outcome = disabled
        .erase_store(&request, ErasureStore::ClickHouseEvents)
        .await;
    assert!(matches!(
        outcome.status,
        StoreErasureStatus::SkippedNotConfigured
    ), "{outcome:?}");
}

// ── CP mirror outage must not fail the subject's submission ─────────────────

#[tokio::test]
async fn mirror_write_failure_does_not_fail_the_submission() {
    let Some(pool) = hostile_db("mirror").await else {
        return;
    };
    let gdpr = automation_with(pool.clone(), config());
    sqlx::query("DROP TABLE IF EXISTS gdpr_requests")
        .execute(&pool)
        .await
        .expect("drop mirror");
    let tenant = unique_tenant();
    let (request, token) = gdpr
        .submit_request(&tenant, DataSubjectRequestType::Access, "mirror@example.test")
        .await
        .expect("the DSR itself must survive a CP-mirror outage");
    assert!(!token.is_empty());
    // The canonical intake is durable: request row + outbox row.
    let outbox: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM dsr_verification_outbox WHERE request_id = $1")
            .bind(&request.id)
            .fetch_one(&pool)
            .await
            .expect("outbox count");
    assert_eq!(outbox, 1);
    let due: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT statutory_due_at FROM data_subject_requests WHERE id = $1")
            .bind(&request.id)
            .fetch_one(&pool)
            .await
            .expect("due");
    assert!(due.is_some(), "the statutory clock is persisted at intake");
}
