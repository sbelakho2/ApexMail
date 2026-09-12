//! Release tests for the GDPR governance findings.
//!
//! Unlike `gdpr_compliance_db_tests.rs` (which deliberately exercises
//! degraded, hand-written schema subsets), these tests run against the REAL
//! canonical migration chain through `migrator::test_support`, because the
//! findings are about exactly that: what the numbered migrations create and
//! what the service may do with a DML-only role.
//!
//! Covered:
//!
//! 1. **No runtime DDL** — source scan of `crates/compliance/src` (no
//!    `CREATE TABLE`/`CREATE INDEX`/`ALTER TABLE`/…), plus the live proof:
//!    `compliance_boots_and_processes_with_dml_only_role` provisions a
//!    role with no CREATE/ALTER/DROP privileges anywhere and boots the full
//!    service through the same `compliance::bootstrap::build_state` the
//!    binary uses, then processes a DSR, a breach (through the receipt gate)
//!    and a retention sweep.
//! 2. **Breach state machine** — a breach cannot reach
//!    `authority_acknowledged` without a receipt, and no authority
//!    submission happens without the generated package + a human task.
//! 3. **DSAR statutory clock** — due date is one calendar month; an
//!    extension requires a reason AND a notification timestamp (DB CHECK).
//! 4. **Retention/erasure interplay** — an erasure does NOT delete a
//!    seven-year invoice record, redacts it, archives it as
//!    `legally_restricted` and discloses what/why/until when in the DSAR
//!    result.
//! 5. **Monotonic archive** — `legally_restricted → statutory_expired →
//!    deleted` only, enforced in code AND by the DB trigger.
//! 6. **Governance registry** — seeded ROPA records cover the platform's
//!    stores; lawful bases / DPIA outcomes / transfer mechanisms are left for
//!    legal input instead of being invented.

use compliance::config::{AuditConfig, ComplianceConfig, GdprConfig};
use compliance::gdpr_automation::GdprAutomation;
use sqlx::PgPool;
use uuid::Uuid;

// ── Provisioning ────────────────────────────────────────────────────────────

fn test_database_url() -> Option<String> {
    std::env::var("TEST_DATABASE_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
}

/// A canonical database (real migration chain) cloned from the migrator's
/// template. `None` only when TEST_DATABASE_URL is unset; a configured
/// failure panics (audit F01 convention).
async fn canonical_pool(test_name: &str) -> Option<PgPool> {
    let url = test_database_url()?;
    let (server, db) = url.rsplit_once('/')?;
    let db_only = db.split('?').next().unwrap_or(db);
    match migrator::test_support::fresh_canonical_db(
        &format!("{server}/{db_only}"),
        &format!("{db_only}_gdpr_{test_name}"),
    )
    .await
    {
        Ok(Some(pool)) => Some(pool),
        Ok(None) => None,
        Err(e) => panic!("{}", e.panic_message()),
    }
}

/// A redis URL for the few tests that exercise the erasure path end to end
/// (which clears subject-scoped cache keys). `None` when unset.
fn test_redis_url() -> Option<String> {
    std::env::var("TEST_REDIS_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
}

fn redis_pool(url: &str) -> deadpool_redis::Pool {
    deadpool_redis::Config::from_url(url)
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .expect("redis pool")
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
        consent_signing_key: "release-test-signing-key-0123456789".into(),
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

fn audit_logger(pool: &PgPool) -> std::sync::Arc<compliance::audit_logger::AuditLogger> {
    std::sync::Arc::new(compliance::audit_logger::AuditLogger::new(
        pool.clone(),
        AuditConfig {
            retention_days: 365,
            hash_chain_enabled: true,
            signing_key: "release-audit-key-0123456789abcdef".into(),
        },
    ))
}

fn notifier(
    pool: &PgPool,
    audit: std::sync::Arc<compliance::audit_logger::AuditLogger>,
) -> compliance::breach_notification::BreachNotifier {
    compliance::breach_notification::BreachNotifier::new(
        pool.clone(),
        audit,
        vec!["dpo@apexmail.ee".into()],
        b"release-breach-signing-key".to_vec(),
    )
}

// ── 1a. Source scan: no runtime schema DDL ─────────────────────────────────

/// Walk every `.rs` file under `crates/compliance/src` and forbid runtime
/// schema DDL. The ONLY tolerated `ALTER TABLE` is the ClickHouse analytics
/// erasure mutation (`ALTER TABLE <db>.events DELETE WHERE recipient = …`),
/// which deletes DATA in a different store and creates nothing; it must
/// carry the `events DELETE WHERE` fragment so the exception cannot hide
/// schema DDL.
#[test]
fn no_runtime_schema_ddl_in_compliance_source() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs_files(&root, &mut files);
    assert!(!files.is_empty(), "no source files found under {root:?}");

    let forbidden = [
        "CREATE TABLE",
        "CREATE INDEX",
        "CREATE UNIQUE INDEX",
        "DROP TABLE",
        "DROP INDEX",
        "CREATE SCHEMA",
        "DROP SCHEMA",
        "ADD COLUMN",
        "DROP COLUMN",
        "TRUNCATE",
        "raw_sql",
        "apply_migration",
        "apply_outbox_migration",
    ];

    let mut violations = Vec::new();
    let mut clickhouse_mutations = 0usize;
    for file in &files {
        let text = std::fs::read_to_string(file).expect("read source file");
        for (index, line) in text.lines().enumerate() {
            // Comments may DISCUSS the DDL that was removed (e.g. "the index
            // this method used to create"); only code counts.
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*") {
                continue;
            }
            for marker in forbidden {
                if line.contains(marker) {
                    violations.push(format!(
                        "{}:{}: forbidden runtime DDL marker {:?}: {}",
                        file.display(),
                        index + 1,
                        marker,
                        line.trim()
                    ));
                }
            }
            if line.contains("ALTER TABLE") {
                let is_clickhouse_data_mutation =
                    line.contains("events DELETE WHERE") && file.ends_with("gdpr_automation.rs");
                if is_clickhouse_data_mutation {
                    clickhouse_mutations += 1;
                } else {
                    violations.push(format!(
                        "{}:{}: ALTER TABLE outside the documented ClickHouse data-mutation \
                         exception: {}",
                        file.display(),
                        index + 1,
                        line.trim()
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "runtime DDL found in compliance source (all schema must be migration-owned):\n{}",
        violations.join("\n")
    );
    assert!(
        clickhouse_mutations >= 1,
        "the ClickHouse erasure mutation should still exist; the scan's exception must not be \
         dead (if it moved, update this guard)"
    );
}

fn collect_rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

// ── 1b. The real proof: DML-only role boots and processes ──────────────────

struct DmlRole {
    name: String,
    url: String,
}

/// Create a LOGIN role with no CREATE/ALTER/DROP capability anywhere and
/// grant it DML on the canonical database's schema.
async fn provision_dml_role(db_name: &str) -> DmlRole {
    let test_url = test_database_url().expect("TEST_DATABASE_URL checked by caller");
    let admin_url = std::env::var("TEST_DATABASE_ADMIN_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| test_url.clone());
    let (admin_server, _) = admin_url
        .rsplit_once('/')
        .expect("admin URL must contain a database segment");

    let name = format!("gdpr_dml_{}", &Uuid::new_v4().simple().to_string()[..8]);
    let password = Uuid::new_v4().simple().to_string();

    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&format!("{admin_server}/postgres"))
        .await
        .unwrap_or_else(|e| {
            panic!(
                "could not connect to the admin database ({admin_server}/postgres): {e}. Set \
                 TEST_DATABASE_ADMIN_URL to a role with CREATEROLE (the TEST_DATABASE_URL role \
                 must not be relied on for this)."
            )
        });

    let create = format!(
        "CREATE ROLE \"{name}\" LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE"
    );
    if let Err(e) = sqlx::query(&create).execute(&admin).await {
        if e.to_string().contains("already exists") {
            sqlx::query(&format!(
                "ALTER ROLE \"{name}\" WITH LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE"
            ))
            .execute(&admin)
            .await
            .expect("reset leftover DML role");
        } else {
            admin.close().await;
            panic!(
                "CREATE ROLE failed ({e}). The TEST_DATABASE_URL role typically lacks CREATEROLE; \
                 set TEST_DATABASE_ADMIN_URL to a superuser/CREATEROLE connection."
            );
        }
    }

    // The role must not be able to create objects in the database or the
    // public schema, and must not own anything.
    let db_admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&format!("{admin_server}/{db_name}"))
        .await
        .expect("connect test database as admin");
    for statement in [
        "REVOKE CREATE ON SCHEMA public FROM PUBLIC".to_string(),
        format!("REVOKE CREATE ON DATABASE \"{db_name}\" FROM PUBLIC"),
        format!("GRANT CONNECT ON DATABASE \"{db_name}\" TO \"{name}\""),
        format!("GRANT USAGE ON SCHEMA public TO \"{name}\""),
        format!(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{name}\""
        ),
        format!("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO \"{name}\""),
    ] {
        sqlx::query(&statement)
            .execute(&db_admin)
            .await
            .unwrap_or_else(|e| panic!("{statement}: {e}"));
    }

    // Prove the role really is DML-only before we rely on it.
    let (schema_create, db_create, dml): (bool, bool, bool) = sqlx::query_as(
        "SELECT has_schema_privilege($1, 'public', 'CREATE'),
                has_database_privilege($1, $2, 'CREATE'),
                has_table_privilege($1, 'data_subject_requests', 'INSERT')",
    )
    .bind(&name)
    .bind(db_name)
    .fetch_one(&db_admin)
    .await
    .expect("privilege probes");
    assert!(
        !schema_create,
        "DML role must not have CREATE on schema public"
    );
    assert!(!db_create, "DML role must not have CREATE on the database");
    assert!(dml, "DML role must be able to INSERT");
    db_admin.close().await;

    let (_, rest) = test_url.rsplit_once('@').expect("url credentials");
    let (host_part, _) = rest.rsplit_once('/').expect("url db segment");
    DmlRole {
        url: format!("postgresql://{name}:{password}@{host_part}/{db_name}"),
        name,
    }
}

/// The finding's central demand, live: the complete compliance service boots
/// against a role without CREATE/ALTER/DROP privileges and processes real
/// work — a DSR access export, a breach through the full state machine, and a
/// retention sweep.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compliance_boots_and_processes_with_dml_only_role() {
    let Some(url) = test_database_url() else {
        eprintln!("skipping: set TEST_DATABASE_URL to run the DML-only boot test");
        return;
    };
    let (server, db) = url.rsplit_once('/').expect("url shape");
    let db_only = db.split('?').next().unwrap_or(db);
    let db_name = format!("{db_only}_gdpr_dml_boot");
    let base_pool =
        match migrator::test_support::fresh_canonical_db(&format!("{server}/{db_only}"), &db_name)
            .await
        {
            Ok(Some(pool)) => pool,
            Ok(None) => return,
            Err(e) => panic!("{}", e.panic_message()),
        };

    let role = provision_dml_role(&db_name).await;

    // Build the COMPLETE service exactly as the binary does. The secret
    // manager requires its KDF salt + master key (env contract).
    std::env::set_var("SECRETS_KDF_SALT", "dml-boot-kdf-salt-0123456789");
    std::env::set_var("SECRETS_ENCRYPTION_KEY", "dml-boot-master-key-0123456789");
    let mut config = ComplianceConfig::from_env();
    config.database_url = role.url.clone();
    config.redis_url = test_redis_url().unwrap_or_else(|| "redis://127.0.0.1:1/0".into());
    config.auth_token = "dml-boot-token".into();
    config.audit = AuditConfig {
        retention_days: 365,
        hash_chain_enabled: true,
        signing_key: "dml-boot-audit-key-0123456789".into(),
    };
    config.gdpr = test_gdpr_config();
    config.breach_notification_emails = vec!["dpo@apexmail.ee".into()];

    let (state, seeds) = match compliance::bootstrap::build_state(&config).await {
        Ok(booted) => booted,
        Err(e) => panic!("service failed to boot under a DML-only role: {e}"),
    };
    // Idempotent DML seeds ran (they may be no-ops on a re-run).
    assert!(
        seeds.soc2_controls > 0,
        "SOC2 catalog must seed with DML only"
    );
    assert!(
        seeds.governance_activities > 0,
        "governance registry must seed with DML only"
    );
    assert!(
        seeds.retention_classes > 0,
        "retention classes must seed with DML only"
    );

    // The router builds against the same state (no DDL in route setup).
    let _router = compliance::routes::create_router(state.clone());

    // Real work #1 — a DSR access request end to end.
    let tenant = format!("t{}", &Uuid::new_v4().simple().to_string()[..20]);
    let subject = format!("dml-{}@example.com", Uuid::new_v4().simple());
    let (request, _token) = state
        .gdpr
        .submit_request(
            &tenant,
            compliance::types::DataSubjectRequestType::Access,
            &subject,
        )
        .await
        .expect("DSR intake with DML-only role");
    assert!(
        request.statutory_due_at.is_some(),
        "the statutory clock must be persisted at intake"
    );
    state
        .gdpr
        .process_request(&request.id)
        .await
        .expect("DSR processing with DML-only role");
    let export_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM gdpr_exports WHERE request_id = $1")
            .bind(&request.id)
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert_eq!(export_rows, 1, "the access export row was written");

    // Real work #2 — a breach through the whole state machine.
    let report = state
        .breach
        .report_breach(
            compliance::breach_notification::BreachReportInput {
                tenant_id: tenant.clone(),
                affected_records: 10,
                data_types: vec!["email".into()],
                description: "DML-only boot breach".into(),
                severity: "high".into(),
                dpo_contact: Some("dpo@apexmail.ee".into()),
                likely_consequences: Some("phishing".into()),
                measures_taken: Some("keys rotated".into()),
            },
            "dml-boot",
        )
        .await
        .expect("breach intake");
    state
        .breach
        .triage(&report.id, true, true, "high risk to subjects", "dml-boot")
        .await
        .expect("breach triage");
    let submission = state
        .breach
        .queue_authority_notification(&report.id, "dml-boot")
        .await
        .expect("submission package + human task");
    state
        .breach
        .record_authority_submission(
            &report.id,
            &submission.id,
            None,
            "AKI-DML-1",
            compliance::breach_notification::SubmissionChannel::HumanTask,
            "dpo@apexmail.ee",
            "dml-boot",
        )
        .await
        .expect("record submission");
    let acknowledged = state
        .breach
        .record_authority_receipt(&report.id, "RECEIPT-DML-1", None, "dml-boot")
        .await
        .expect("record receipt");
    assert_eq!(acknowledged.status, "authority_acknowledged");

    // Real work #3 — the retention sweep writes its report.
    let sweep = state
        .retention_sweeper
        .run_sweep(&state.audit_logger)
        .await
        .expect("retention sweep with DML-only role");
    let report_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM retention_report")
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert!(report_rows >= 1, "sweep persisted its report: {sweep:?}");

    // Cleanup: release the pools, drop the role (best effort).
    state.db.close().await;
    base_pool.close().await;
    cleanup_dml_role(&db_name, &role).await;
}

async fn cleanup_dml_role(db_name: &str, role: &DmlRole) {
    let Some(test_url) = test_database_url() else {
        return;
    };
    let admin_url = std::env::var("TEST_DATABASE_ADMIN_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or(test_url);
    let (admin_server, _) = admin_url.rsplit_once('/').expect("admin url");
    let Ok(db_admin) = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&format!("{admin_server}/{db_name}"))
        .await
    else {
        return;
    };
    let _ = sqlx::query(&format!("DROP OWNED BY \"{}\"", role.name))
        .execute(&db_admin)
        .await;
    db_admin.close().await;
    let Ok(admin) = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&format!("{admin_server}/postgres"))
        .await
    else {
        return;
    };
    let _ = sqlx::query(&format!("DROP ROLE IF EXISTS \"{}\"", role.name))
        .execute(&admin)
        .await;
    admin.close().await;
}

// ── 2. Breach state machine + mandatory receipt ────────────────────────────

/// A breach cannot reach `authority_acknowledged` without a receipt — not
/// through the API (empty receipt refused), and not through direct SQL (the
/// migration-213 CHECK constraint refuses). The authority submission also
/// cannot happen without the generated package + completed human task.
#[tokio::test]
async fn breach_cannot_be_acknowledged_without_receipt() {
    let Some(pool) = canonical_pool("breach_receipt").await else {
        return;
    };
    let audit = audit_logger(&pool);
    audit.initialize().await.expect("audit init");
    let notifier = notifier(&pool, audit);

    let tenant = format!("t{}", &Uuid::new_v4().simple().to_string()[..20]);
    let report = notifier
        .report_breach(
            compliance::breach_notification::BreachReportInput {
                tenant_id: tenant,
                affected_records: 500,
                data_types: vec!["email".into(), "name".into()],
                description: "Release-test breach".into(),
                severity: "HIGH".into(),
                dpo_contact: Some("dpo@apexmail.ee".into()),
                likely_consequences: Some("identity theft".into()),
                measures_taken: Some("access revoked".into()),
            },
            "release-test",
        )
        .await
        .expect("breach reported");
    assert_eq!(report.status, "detected");
    assert_eq!(report.severity, "high");
    assert_eq!(
        (report.gdpr_deadline.unwrap() - report.discovered_at).num_hours(),
        72,
        "the 72h GDPR clock starts at discovery"
    );

    // The graph cannot be skipped: queueing before triage is refused.
    let err = notifier
        .queue_authority_notification(&report.id, "release-test")
        .await
        .expect_err("queueing before triage must fail");
    assert!(err.contains("notifiable"), "unexpected error: {err}");

    let triaged = notifier
        .triage(
            &report.id,
            true,
            true,
            "high risk to data subjects",
            "release-test",
        )
        .await
        .expect("triage");
    assert_eq!(triaged.status, "notifiable");
    assert!(triaged.subject_notification_required);

    // The package + mandatory authenticated human task.
    let submission = notifier
        .queue_authority_notification(&report.id, "release-test")
        .await
        .expect("package queued");
    assert_eq!(submission.status, "queued");
    assert_eq!(submission.channel, "human_task");
    assert_eq!(submission.package["format"], "gdpr-art-33-3-submission/v1");
    assert!(!submission.package_sha256.is_empty(), "package hash stored");
    assert!(
        submission.attachment_sha256.is_some(),
        "the rendered attachment is hashed"
    );
    assert!(
        submission
            .attachment
            .as_deref()
            .unwrap_or_default()
            .contains("gdpr-art-33-3-submission/v1"),
        "the exact submission package is attached"
    );
    let tasks = notifier.open_authority_tasks(10).await.unwrap();
    let task = tasks
        .iter()
        .find(|t| t.breach_id == report.id)
        .expect("mandatory human task opened");
    assert_eq!(task.status, "open");
    assert_eq!(task.required_role, "dpo");
    assert!(task.task.contains("MANDATORY"));

    // Recording a submission without an authenticated person is refused.
    let err = notifier
        .record_authority_submission(
            &report.id,
            &submission.id,
            None,
            "AKI-1",
            compliance::breach_notification::SubmissionChannel::HumanTask,
            "",
            "release-test",
        )
        .await
        .expect_err("submission without an actor must fail");
    assert!(err.contains("authenticated person"), "unexpected: {err}");

    let submitted = notifier
        .record_authority_submission(
            &report.id,
            &submission.id,
            None,
            "AKI-2026-0001",
            compliance::breach_notification::SubmissionChannel::HumanTask,
            "dpo@apexmail.ee",
            "release-test",
        )
        .await
        .expect("submission recorded");
    assert_eq!(submitted.status, "authority_submitted");
    assert!(submitted.authority_submitted_at.is_some());
    assert_eq!(
        submitted.authority_reference.as_deref(),
        Some("AKI-2026-0001")
    );

    // The exact submitted notification + hash are stored.
    let stored: (Option<String>, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT submitted_notification, submitted_sha256, submitted_by \
           FROM breach_authority_submissions WHERE id = $1",
    )
    .bind(&submission.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(stored.0.is_some(), "exact submitted text stored");
    assert!(stored.1.is_some(), "submitted hash stored");
    assert_eq!(stored.2.as_deref(), Some("dpo@apexmail.ee"));
    // The human task was completed by the authenticated actor.
    let (task_status, actor): (String, Option<String>) = sqlx::query_as(
        "SELECT status, authenticated_actor FROM breach_authority_tasks WHERE id = $1",
    )
    .bind(&task.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(task_status, "completed");
    assert!(actor.is_some());

    // Empty receipt refused → still submitted.
    let err = notifier
        .record_authority_receipt(&report.id, "   ", None, "release-test")
        .await
        .expect_err("an empty receipt must be refused");
    assert!(err.contains("receipt"), "unexpected: {err}");
    let still: String = sqlx::query_scalar("SELECT status FROM breach_reports WHERE id = $1")
        .bind(&report.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(still, "authority_submitted");

    // Direct SQL cannot bypass the receipt gate either (DB CHECK).
    let direct =
        sqlx::query("UPDATE breach_reports SET status = 'authority_acknowledged' WHERE id = $1")
            .bind(&report.id)
            .execute(&pool)
            .await;
    assert!(
        direct.is_err(),
        "the DB must refuse authority_acknowledged without a receipt"
    );

    // Only the receipt moves it to acknowledged.
    let acknowledged = notifier
        .record_authority_receipt(&report.id, "RECEIPT-AKI-2026-0001", None, "release-test")
        .await
        .expect("receipt records the acknowledgement");
    assert_eq!(acknowledged.status, "authority_acknowledged");
    assert!(acknowledged.authority_receipt_received_at.is_some());
    // The task is not left open.
    let open_after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM breach_authority_tasks WHERE breach_id = $1 AND status = 'open'",
    )
    .bind(&report.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(open_after, 0);

    // Art. 34: high-risk subject notification is a durable outbox with
    // delivery evidence; resolution waits for it.
    let queued = notifier
        .queue_subject_notifications(
            &report.id,
            &["a@example.com".into(), "b@example.com".into()],
            "release-test",
        )
        .await
        .expect("queue subject notifications");
    assert_eq!(queued, 2);
    let resolve_blocked = notifier
        .resolve(&report.id, "release-test")
        .await
        .expect_err("resolve must wait for pending subject notifications");
    assert!(
        resolve_blocked.contains("pending"),
        "unexpected: {resolve_blocked}"
    );

    let pending = notifier.pending_subject_notifications(10).await.unwrap();
    assert_eq!(pending.len(), 2);
    for row in &pending {
        assert!(!row.body_sha256.is_empty(), "notification text is hashed");
    }
    // Delivery evidence is mandatory to mark sent.
    let no_evidence = notifier
        .record_subject_notification_delivery(&pending[0].id, None, None)
        .await
        .expect_err("delivery without evidence must fail");
    assert!(
        no_evidence.contains("evidence"),
        "unexpected: {no_evidence}"
    );
    for row in &pending {
        notifier
            .record_subject_notification_delivery(
                &row.id,
                Some("ses-message-1"),
                Some(serde_json::json!({"smtp_code": 250})),
            )
            .await
            .expect("record delivery");
    }
    let resolved = notifier
        .resolve(&report.id, "release-test")
        .await
        .expect("resolve after all deliveries");
    assert!(resolved.resolved_at.is_some());
    assert!(resolved.subjects_notified_at.is_some());

    pool.close().await;
}

// ── 3. DSAR statutory clock ─────────────────────────────────────────────────

/// The statutory due date is ONE CALENDAR MONTH from receipt; an extension
/// requires a reason AND a notification timestamp, enforced in code and by
/// the DB CHECK constraint.
#[tokio::test]
async fn dsar_due_date_is_one_month_and_extension_requires_reason_and_notification() {
    // Pure clock arithmetic first: calendar month, not 30 days.
    use chrono::TimeZone;
    let jan31 = chrono::Utc.with_ymd_and_hms(2026, 1, 31, 12, 0, 0).unwrap();
    let due = compliance::gdpr_automation::statutory_due_at(jan31);
    assert_eq!(
        due,
        chrono::Utc.with_ymd_and_hms(2026, 2, 28, 12, 0, 0).unwrap(),
        "one calendar month: 31 Jan → 28 Feb"
    );
    assert_eq!(
        compliance::gdpr_automation::extended_due_at(due),
        chrono::Utc.with_ymd_and_hms(2026, 4, 28, 12, 0, 0).unwrap(),
        "extension adds two further calendar months"
    );
    assert!(
        compliance::gdpr_automation::validate_extension("", jan31, jan31).is_err(),
        "an empty reason is not a justification"
    );
    assert!(compliance::gdpr_automation::validate_extension("too short", jan31, jan31).is_err(),);

    let Some(pool) = canonical_pool("dsar_clock").await else {
        return;
    };
    let gdpr = GdprAutomation::new(
        pool.clone(),
        redis_pool("redis://127.0.0.1:1/0"),
        test_gdpr_config(),
    );
    let tenant = format!("t{}", &Uuid::new_v4().simple().to_string()[..20]);
    let subject = format!("clock-{}@example.com", Uuid::new_v4().simple());
    let (request, _) = gdpr
        .submit_request(
            &tenant,
            compliance::types::DataSubjectRequestType::Access,
            &subject,
        )
        .await
        .expect("submit");
    let (received, statutory_due): (
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
    ) = sqlx::query_as(
        "SELECT received_at, statutory_due_at FROM data_subject_requests WHERE id = $1",
    )
    .bind(&request.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(received.is_some(), "received_at is persisted");
    assert_eq!(
        statutory_due.unwrap(),
        compliance::gdpr_automation::statutory_due_at(received.unwrap()),
        "the persisted due date is receipt + one month"
    );

    // Empty reason refused.
    let err = gdpr
        .extend_request(&request.id, "  ", chrono::Utc::now())
        .await
        .expect_err("extension without a reason must fail");
    assert!(err.contains("reason"), "unexpected: {err}");

    // Direct SQL cannot write an extension without the justification +
    // notification timestamp (migration 213 CHECK).
    let direct = sqlx::query(
        "UPDATE data_subject_requests SET extension_due_at = NOW() + INTERVAL '2 months' WHERE id = $1",
    )
    .bind(&request.id)
    .execute(&pool)
    .await;
    assert!(
        direct.is_err(),
        "the DB must refuse an extension without a reason and a notification timestamp"
    );

    // The justified + notified extension is recorded with all three fields.
    let notified_at = chrono::Utc::now();
    let extended = gdpr
        .extend_request(
            &request.id,
            "The request requires assessment of data across multiple processors",
            notified_at,
        )
        .await
        .expect("justified extension");
    assert!(extended.extension_due_at.is_some());
    assert!(extended.extension_notified_at.is_some());
    assert_eq!(
        extended.extension_due_at.unwrap(),
        compliance::gdpr_automation::extended_due_at(extended.statutory_due_at.unwrap())
    );

    pool.close().await;
}

// ── 4. Retention + erasure interplay ───────────────────────────────────────

/// An erasure does NOT delete a seven-year invoice record: the PII is
/// redacted, the record is moved to the legally-restricted archive with the
/// statutory class and expiry, and the DSAR result DISCLOSES what was
/// retained, why and until when.
#[tokio::test]
async fn erasure_retains_seven_year_invoice_and_discloses_retention() {
    let Some(pool) = canonical_pool("erasure_retention").await else {
        return;
    };
    let Some(redis_url) = test_redis_url() else {
        eprintln!("skipping erasure retention test: set TEST_REDIS_URL");
        return;
    };

    // Seed the governance/retention catalogs as boot would.
    compliance::governance::seed_registry(&pool)
        .await
        .expect("seed registry");

    let tenant = format!("t{}", &Uuid::new_v4().simple().to_string()[..20]);
    let subject = format!("sevenyear-{}@example.com", Uuid::new_v4().simple());
    let other = format!("other-{}@example.com", Uuid::new_v4().simple());
    let issued = chrono::Utc::now() - chrono::Duration::days(100);

    // invoices.tenant_id carries an FK to tenants (canonical chain).
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, 'Erasure retention test')")
        .bind(&tenant)
        .execute(&pool)
        .await
        .unwrap();

    for email in [&subject, &other] {
        sqlx::query(
            "INSERT INTO invoices (tenant_id, amount, currency, status, issued_at,
                                   billing_address, created_at, updated_at)
             VALUES ($1,1000,'EUR','paid',$2,$3,NOW(),NOW())",
        )
        .bind(&tenant)
        .bind(issued)
        .bind(
            serde_json::json!({"email": email, "country": "EE", "company_name": "X OÜ"})
                .to_string(),
        )
        .execute(&pool)
        .await
        .unwrap();
    }

    // A verified erasure request for the subject.
    let request_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO data_subject_requests
           (id, tenant_id, request_type, email, verification_token_hash, verified, verified_at,
            status, requested_at, expires_at, received_at, identity_verified_at, statutory_due_at)
         VALUES ($1,$2,'erasure',$3,'h',true,NOW(),'verified',NOW(),NOW() + INTERVAL '30 days',
                 NOW(), NOW(), NOW() + INTERVAL '1 month')",
    )
    .bind(&request_id)
    .bind(&tenant)
    .bind(&subject)
    .execute(&pool)
    .await
    .unwrap();

    let gdpr = GdprAutomation::new(pool.clone(), redis_pool(&redis_url), test_gdpr_config());
    gdpr.process_request(&request_id)
        .await
        .expect("erasure processes end to end");

    // The financial records survived; only the subject's snapshot was
    // redacted.
    let invoices: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invoices WHERE tenant_id = $1")
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(invoices, 2, "invoices are never deleted by an erasure");
    let redacted: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM invoices WHERE tenant_id = $1 AND billing_address LIKE '%erased+%'",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(redacted, 1, "only the subject's invoice was redacted");

    // The archive row: legally_restricted, statutory class, seven-year expiry.
    let (state, class_id, expiry, subject_hash, reason): (
        String,
        String,
        chrono::DateTime<chrono::Utc>,
        String,
        String,
    ) = sqlx::query_as(
        "SELECT state, retention_class_id, statutory_expiry_at, subject_email_hash, reason \
           FROM legal_retention_archive WHERE tenant_id = $1",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("the retained invoice is archived");
    assert_eq!(state, "legally_restricted");
    assert_eq!(class_id, "RC-STAT-ACCT-7Y");
    assert!(
        (expiry - issued).num_days() >= 2555,
        "statutory expiry is at least seven years after issue, got {} days",
        (expiry - issued).num_days()
    );
    assert!(
        !subject_hash.contains(&subject) && subject_hash.len() == 64,
        "the archive stores only a subject hash, never the plaintext email"
    );
    assert!(reason.contains("Legal obligation") || reason.contains("legal obligation"));

    // The DSAR result discloses what/why/until when.
    let (status, result): (String, serde_json::Value) =
        sqlx::query_as("SELECT status, result FROM data_subject_requests WHERE id = $1")
            .bind(&request_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        matches!(status.as_str(), "completed" | "partial"),
        "unexpected status {status}"
    );
    let disclosure = result
        .get("retained_disclosure")
        .expect("the DSAR result must disclose retained records");
    let retained = disclosure["retained"]
        .as_array()
        .expect("retained list present");
    assert_eq!(retained.len(), 1, "one retained invoice disclosed");
    assert_eq!(retained[0]["source_table"], "invoices");
    assert_eq!(retained[0]["retention_class_id"], "RC-STAT-ACCT-7Y");
    assert!(
        retained[0]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("accounting")
            || retained[0]["reason"]
                .as_str()
                .unwrap_or_default()
                .contains("Statutory"),
        "why is disclosed"
    );
    assert!(
        retained[0]["retain_until"].is_string(),
        "until when is disclosed"
    );
    assert!(
        disclosure["policy"]
            .as_str()
            .unwrap_or_default()
            .contains("seven years"),
        "the disclosure policy names the statutory basis"
    );
    // The deletion confirmation also carries the disclosure for the subject.
    let confirmation = result["deletion_confirmation"].clone();
    assert!(
        confirmation.get("retained_disclosure").is_some(),
        "the deletion certificate carries the retention disclosure"
    );

    pool.close().await;
}

// ── 5. Monotonic archive lifecycle ─────────────────────────────────────────

/// `legally_restricted → statutory_expired → deleted`, one step at a time:
/// code refuses skips/backwards moves and the DB trigger refuses them for
/// direct SQL too.
#[tokio::test]
async fn archive_transitions_are_monotonic() {
    use compliance::legal_archive::{
        advance_state, archive_record, get, ArchiveRecordInput, STATE_DELETED,
        STATE_LEGALLY_RESTRICTED, STATE_STATUTORY_EXPIRED,
    };

    let Some(pool) = canonical_pool("archive_monotonic").await else {
        return;
    };
    let tenant = format!("t{}", &Uuid::new_v4().simple().to_string()[..20]);
    let input = ArchiveRecordInput {
        tenant_id: tenant.clone(),
        subject_email_hash: compliance::legal_archive::subject_email_hash("s@example.com"),
        source_table: "invoices".into(),
        source_record_id: format!("inv{}", &Uuid::new_v4().simple().to_string()[..22]),
        retention_class_id: "RC-STAT-ACCT-7Y".into(),
        reason: "Statutory accounting retention — archive lifecycle test".into(),
        statutory_expiry_at: chrono::Utc::now() + chrono::Duration::days(2555),
        disclosure: serde_json::json!({"why": "test"}),
    };
    let row = archive_record(&pool, &input).await.expect("archive row");
    assert_eq!(row.state, STATE_LEGALLY_RESTRICTED);

    // Skip is refused by code.
    let skip = advance_state(&pool, &row.id, STATE_DELETED)
        .await
        .expect_err("skipping expiry must fail");
    assert!(skip.contains("illegal"), "unexpected: {skip}");

    // Forward one step.
    let expired = advance_state(&pool, &row.id, STATE_STATUTORY_EXPIRED)
        .await
        .expect("expire");
    assert_eq!(expired.state, STATE_STATUTORY_EXPIRED);
    assert!(expired.statutory_expired_at.is_some());

    // Backwards is refused by code.
    let back = advance_state(&pool, &row.id, STATE_LEGALLY_RESTRICTED)
        .await
        .expect_err("backwards move must fail");
    assert!(back.contains("illegal"), "unexpected: {back}");

    // Backwards is refused by the DB trigger even in direct SQL.
    let direct_back = sqlx::query(
        "UPDATE legal_retention_archive SET state = 'legally_restricted' WHERE id = $1",
    )
    .bind(&row.id)
    .execute(&pool)
    .await;
    assert!(
        direct_back.is_err(),
        "the trigger must refuse backwards moves"
    );

    // Forward to deleted; then the row is immutable.
    let deleted = advance_state(&pool, &row.id, STATE_DELETED)
        .await
        .expect("delete");
    assert_eq!(deleted.state, STATE_DELETED);
    assert!(deleted.deleted_at.is_some());
    assert_eq!(
        get(&pool, &row.id).await.unwrap().unwrap().state,
        STATE_DELETED
    );
    assert!(
        advance_state(&pool, &row.id, STATE_STATUTORY_EXPIRED)
            .await
            .is_err(),
        "a deleted archive row cannot move again"
    );

    pool.close().await;
}

// ── 6. Governance registry ─────────────────────────────────────────────────

/// The registry seeds a ROPA record for every store the platform owns, and
/// does NOT invent lawful bases, DPIA outcomes or transfer mechanisms — those
/// stay explicitly `requires_legal_input` / `legal_input_required` for Legal.
#[tokio::test]
async fn governance_registry_seeds_stores_and_leaves_lawful_bases_to_legal() {
    let Some(pool) = canonical_pool("governance").await else {
        return;
    };
    let summary = compliance::governance::seed_registry(&pool)
        .await
        .expect("seed registry");
    assert!(summary.activities_inserted >= 10);
    assert!(summary.awaiting_legal_input >= summary.activities_inserted);

    let inventory = compliance::governance::declared_store_inventory(&pool)
        .await
        .expect("inventory");
    for store in [
        "contacts",
        "events",
        "messages",
        "users",
        "invoices",
        "consent_records",
        "suppression_list",
        "audit_logs",
        "data_subject_requests",
        "dsr_verification_outbox",
        "gdpr_exports",
        "breach_reports",
        "breach_subject_notification_outbox",
        "legal_retention_archive",
        "retention_report",
        "clickhouse_events",
        "mailstore_blobs",
    ] {
        assert!(
            inventory.iter().any(|s| s == store),
            "{store} has no ROPA record"
        );
    }

    // No invented lawful bases.
    let asserted: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM lawful_basis_records WHERE basis IS NOT NULL OR basis_status = 'asserted'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        asserted, 0,
        "seeded lawful-basis records must not assert a basis"
    );
    let awaiting: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM lawful_basis_records WHERE basis_status = 'requires_legal_input'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(awaiting >= summary.activities_inserted as i64);

    // No invented transfer mechanisms / DPIA outcomes.
    let mechanisms: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM international_transfer_assessments WHERE transfer_mechanism <> 'undetermined'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(mechanisms, 0, "transfer mechanisms await Legal");
    let dpias: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM dpia_assessments WHERE status = 'completed'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(dpias, 0, "DPIA outcomes await the DPO");

    // The statutory retention class exists with the seven-year floor.
    let (statutory, minimum): (bool, i32) = sqlx::query_as(
        "SELECT statutory, minimum_days FROM retention_classes WHERE id = 'RC-STAT-ACCT-7Y'",
    )
    .fetch_one(&pool)
    .await
    .expect("statutory accounting class");
    assert!(statutory);
    assert!(minimum >= 2555);

    // A new store cannot be registered without its full identification, and
    // approval is impossible while the basis is unresolved.
    let incomplete = compliance::governance::NewProcessingActivity {
        id: None,
        name: "New store".into(),
        description: "d".into(),
        controller_or_processor: "controller".into(),
        purpose: String::new(), // missing
        data_subjects: vec!["subjects".into()],
        data_categories: vec!["email".into()],
        recipients: vec!["tenant".into()],
        data_stores: vec!["new_store".into()],
        retention_class_id: "RC-OP-EVENT-30D".into(),
        transfer_situation: compliance::governance::TransferSituation::Undetermined,
        source_location: "release-test".into(),
    };
    assert!(
        compliance::governance::register_activity(&pool, &incomplete)
            .await
            .is_err()
    );

    pool.close().await;
}
