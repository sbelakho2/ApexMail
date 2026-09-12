//! DB-backed tests for the statutory filing completion (migration 221).
//!
//! These provision throwaway databases carrying the REAL production
//! migration chain through `migrator::test_support`, so the annual-report
//! derivation, the approval/submission state machine, the obligation
//! scheduler and the VD/OSS submission evidence rows are exercised against
//! the canonical schema (including migration 220's ledger triggers).
//!
//! Skips unless TEST_DATABASE_URL is set (workspace convention); a
//! CONFIGURED provisioning failure panics (audit F01).

use async_trait::async_trait;
use chrono::{NaiveDate, Utc};
use compliance::annual_report::{
    approve_annual_report, generate_annual_report, get_annual_report,
    record_annual_report_submission, AnnualReportStatus,
};
use compliance::filing_transport::{
    ingest_acknowledgement, record_manual_submission, FilingTransport, FilingTransportConfig,
    ReturnKind, SubmissionOutcome, TransportMode, TransportReceipt,
};
use compliance::obligations::{
    derive_obligations, load_filing_facts, sync_obligations, ObligationHorizon,
};
use compliance::vat_oss::submit_oss_return;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

// ── Canonical fixture ──────────────────────────────────────────────────────

async fn canonical_pool(test_name: &str) -> Option<PgPool> {
    let suffix = format!("filing_{}", test_name);
    match migrator::test_support::fresh_canonical_pool(test_name, &suffix).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

fn d(year: i32, month: u32, day: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(year, month, day).expect("test date")
}

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// A legal entity plus the three accounts the ledger tests post against
/// (bank / revenue / retained earnings).
async fn seed_entity_with_accounts(pool: &PgPool, registry_code: &str) -> (Uuid, Uuid, Uuid, Uuid) {
    let entity_id: Uuid = sqlx::query_scalar(
        "INSERT INTO legal_entities (legal_name, registry_code, country_code) \
         VALUES ($1, $2, 'EE') RETURNING id",
    )
    .bind(format!("Test OÜ {registry_code}"))
    .bind(registry_code)
    .fetch_one(pool)
    .await
    .expect("insert legal entity");

    let bank: Uuid = sqlx::query_scalar(
        "INSERT INTO chart_of_accounts (legal_entity_id, code, name, account_type, normal_balance, account_role) \
         VALUES ($1, '1020', 'Bank', 'asset', 'debit', 'bank') RETURNING id",
    )
    .bind(entity_id)
    .fetch_one(pool)
    .await
    .expect("insert bank account");

    let revenue: Uuid = sqlx::query_scalar(
        "INSERT INTO chart_of_accounts (legal_entity_id, code, name, account_type, normal_balance, account_role) \
         VALUES ($1, '4000', 'Revenue', 'revenue', 'credit', 'revenue') RETURNING id",
    )
    .bind(entity_id)
    .fetch_one(pool)
    .await
    .expect("insert revenue account");

    let equity: Uuid = sqlx::query_scalar(
        "INSERT INTO chart_of_accounts (legal_entity_id, code, name, account_type, normal_balance, account_role) \
         VALUES ($1, '3000', 'Retained earnings', 'equity', 'credit', 'retained_earnings') RETURNING id",
    )
    .bind(entity_id)
    .fetch_one(pool)
    .await
    .expect("insert equity account");

    (entity_id, bank, revenue, equity)
}

async fn create_period(
    pool: &PgPool,
    entity_id: Uuid,
    period_type: &str,
    label: &str,
    start: NaiveDate,
    end: NaiveDate,
    close: bool,
) -> Uuid {
    let period_id: Uuid = sqlx::query_scalar(
        "INSERT INTO fiscal_periods (legal_entity_id, period_type, label, start_date, end_date) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(entity_id)
    .bind(period_type)
    .bind(label)
    .bind(start)
    .bind(end)
    .fetch_one(pool)
    .await
    .expect("insert fiscal period");
    if close {
        sqlx::query("UPDATE fiscal_periods SET status = 'closed' WHERE id = $1")
            .bind(period_id)
            .execute(pool)
            .await
            .expect("close fiscal period");
    }
    period_id
}

/// Post a balanced journal entry into an OPEN period exactly as the
/// accounting core requires: draft entry, lines, then the posting update (the
/// deferred balance trigger validates on commit).
async fn post_entry(
    pool: &PgPool,
    entity_id: Uuid,
    period_id: Uuid,
    entry_date: NaiveDate,
    memo: &str,
    lines: &[(Uuid, i64, i64)],
) -> Uuid {
    let idempotency_key = format!("test-{}-{}", memo, Uuid::new_v4());
    let entry_id: Uuid = sqlx::query_scalar(
        "INSERT INTO journal_entries \
            (legal_entity_id, fiscal_period_id, entry_date, entry_type, memo, source_hash, idempotency_key) \
         VALUES ($1, $2, $3, 'standard', $4, $5, $6) RETURNING id",
    )
    .bind(entity_id)
    .bind(period_id)
    .bind(entry_date)
    .bind(memo)
    .bind(sha256_hex(memo))
    .bind(&idempotency_key)
    .fetch_one(pool)
    .await
    .expect("insert draft journal entry");

    for (line_no, (account_id, debit, credit)) in lines.iter().enumerate() {
        sqlx::query(
            "INSERT INTO journal_lines (entry_id, line_no, account_id, debit_cents, credit_cents) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(entry_id)
        .bind(line_no as i32 + 1)
        .bind(account_id)
        .bind(debit)
        .bind(credit)
        .execute(pool)
        .await
        .expect("insert journal line");
    }

    sqlx::query(
        "UPDATE journal_entries SET posted_at = NOW(), posted_by = 'test-post' WHERE id = $1",
    )
    .bind(entry_id)
    .execute(pool)
    .await
    .expect("post journal entry");
    entry_id
}

// ── Annual report derivation ───────────────────────────────────────────────

#[tokio::test]
async fn annual_report_derives_from_posted_lines_and_changes_with_postings() {
    let Some(pool) = canonical_pool("annual_report_derivation").await else {
        return;
    };
    let (entity_id, bank, revenue, _equity) = seed_entity_with_accounts(&pool, "16588741").await;

    let fy2025 = create_period(
        &pool,
        entity_id,
        "year",
        "FY 2025",
        d(2025, 1, 1),
        d(2025, 12, 31),
        false,
    )
    .await;
    let fy2026 = create_period(
        &pool,
        entity_id,
        "year",
        "FY 2026",
        d(2026, 1, 1),
        d(2026, 12, 31),
        false,
    )
    .await;

    // FY2025: one 1 000.00 EUR sale. FY2026: 2 500.00 EUR in two postings.
    post_entry(
        &pool,
        entity_id,
        fy2025,
        d(2025, 3, 10),
        "sale-2025",
        &[(bank, 100_000, 0), (revenue, 0, 100_000)],
    )
    .await;
    post_entry(
        &pool,
        entity_id,
        fy2026,
        d(2026, 2, 10),
        "sale-2026-a",
        &[(bank, 150_000, 0), (revenue, 0, 150_000)],
    )
    .await;
    post_entry(
        &pool,
        entity_id,
        fy2026,
        d(2026, 5, 10),
        "sale-2026-b",
        &[(bank, 100_000, 0), (revenue, 0, 100_000)],
    )
    .await;

    sqlx::query("UPDATE fiscal_periods SET status = 'closed' WHERE id = ANY($1)")
        .bind(vec![fy2025, fy2026])
        .execute(&pool)
        .await
        .expect("close both periods");

    let report_2025 = generate_annual_report(&pool, entity_id, fy2025, "system:close-run")
        .await
        .expect("generate FY2025 report");
    let report_2026 = generate_annual_report(&pool, entity_id, fy2026, "system:close-run")
        .await
        .expect("generate FY2026 report");

    // Values come from posted journal lines, not operational tables.
    assert_eq!(report_2025.status, AnnualReportStatus::Draft.as_str());
    assert!(
        report_2025.balance_sheet.get("revenue_cents").is_none(),
        "revenue belongs to the income statement, not the balance sheet"
    );
    assert_eq!(
        report_2025.income_statement["revenue_cents"],
        json!(100_000)
    );
    assert_eq!(
        report_2026.income_statement["revenue_cents"],
        json!(250_000)
    );
    assert_eq!(
        report_2025.income_statement["net_profit_cents"],
        json!(100_000)
    );
    assert_eq!(report_2026.balance_sheet["assets_cents"], json!(250_000));
    assert!(report_2025.balance_check_ok);
    assert!(report_2026.balance_check_ok);

    // A changed posting set is a changed derivation (different hash, value).
    assert_ne!(report_2025.ledger_hash, report_2026.ledger_hash);
    assert_eq!(report_2025.ledger_entry_count, 1);
    assert_eq!(report_2026.ledger_entry_count, 2);

    // The per-account snapshot persists.
    let line_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM annual_report_lines WHERE report_id = $1")
            .bind(report_2026.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(line_count, 2, "bank + revenue account lines");

    // Regenerating a draft is idempotent for the same posting set.
    let regenerated = generate_annual_report(&pool, entity_id, fy2026, "system:close-run")
        .await
        .expect("regenerate draft");
    assert_eq!(regenerated.ledger_hash, report_2026.ledger_hash);
    assert_eq!(regenerated.id, report_2026.id);

    // The structured document names the ledger provenance and the format.
    assert_eq!(
        regenerated.structured_document["format"],
        json!("apexmail.annual-report/1")
    );
    assert_eq!(
        regenerated.structured_document["ledger_provenance"]["derivation_views"][0],
        json!("v_accounting_trial_balance")
    );
    assert!(!regenerated.xbrl_instance.is_empty());
}

#[tokio::test]
async fn annual_report_cannot_be_approved_without_approver_or_submitted_without_receipt() {
    let Some(pool) = canonical_pool("annual_report_state_machine").await else {
        return;
    };
    let (entity_id, bank, revenue, _equity) = seed_entity_with_accounts(&pool, "16588742").await;
    let period = create_period(
        &pool,
        entity_id,
        "year",
        "FY 2025",
        d(2025, 1, 1),
        d(2025, 12, 31),
        false,
    )
    .await;
    post_entry(
        &pool,
        entity_id,
        period,
        d(2025, 6, 1),
        "sale",
        &[(bank, 500_000, 0), (revenue, 0, 500_000)],
    )
    .await;
    sqlx::query("UPDATE fiscal_periods SET status = 'closed' WHERE id = $1")
        .bind(period)
        .execute(&pool)
        .await
        .unwrap();

    let report = generate_annual_report(&pool, entity_id, period, "system:close-run")
        .await
        .expect("generate draft");
    assert_eq!(report.status, "draft");
    assert!(report.approved_by.is_none());
    assert!(report.submitted_at.is_none());

    // Generation must not be approval: an empty approver is refused.
    let error = approve_annual_report(&pool, report.id, "   ", None)
        .await
        .expect_err("blank approver must be refused");
    assert!(error.contains("authenticated approver"));
    let still = get_annual_report(&pool, report.id).await.unwrap().unwrap();
    assert_eq!(still.status, "draft");

    // Approval with an authenticated identity succeeds and is timestamped.
    approve_annual_report(
        &pool,
        report.id,
        "board:signer-1",
        Some("approved by board"),
    )
    .await
    .expect("approve");
    let approved = get_annual_report(&pool, report.id).await.unwrap().unwrap();
    assert_eq!(approved.status, "management_approved");
    assert_eq!(approved.approved_by.as_deref(), Some("board:signer-1"));
    assert!(approved.approved_at.is_some());

    // An approved report cannot be regenerated (it is a legal act), and its
    // derivation snapshot is immutable even against raw SQL.
    let error = generate_annual_report(&pool, entity_id, period, "system:close-run")
        .await
        .expect_err("approved report must be frozen");
    assert!(error.contains("human legal act"));
    let raw = sqlx::query("DELETE FROM annual_report_lines WHERE report_id = $1")
        .bind(report.id)
        .execute(&pool)
        .await;
    assert!(
        raw.is_err(),
        "the snapshot of an approved report must be immutable"
    );

    // Submission without a receipt reference is refused.
    let error = record_annual_report_submission(&pool, report.id, "cfo:1", "  ", None)
        .await
        .expect_err("receipt-less submission must be refused");
    assert!(error.contains("authority receipt"));
    let still = get_annual_report(&pool, report.id).await.unwrap().unwrap();
    assert_eq!(still.status, "management_approved");

    // Submission with the authority receipt is recorded.
    record_annual_report_submission(
        &pool,
        report.id,
        "cfo:1",
        "ARIREG-2026-000123",
        Some(json!({"registered": true})),
    )
    .await
    .expect("submit");
    let submitted = get_annual_report(&pool, report.id).await.unwrap().unwrap();
    assert_eq!(submitted.status, "submitted");
    assert_eq!(
        submitted.authority_receipt_reference.as_deref(),
        Some("ARIREG-2026-000123")
    );
    assert_eq!(submitted.submitted_by.as_deref(), Some("cfo:1"));
    assert!(submitted.submitted_at.is_some());

    // The database CHECK constraints are a backstop against raw SQL that
    // tries to skip the human legal acts.
    let (other_entity, _bank, _revenue, _equity) =
        seed_entity_with_accounts(&pool, "16588743").await;
    let other_period = create_period(
        &pool,
        other_entity,
        "year",
        "FY 2025",
        d(2025, 1, 1),
        d(2025, 12, 31),
        true,
    )
    .await;
    let other_report =
        generate_annual_report(&pool, other_entity, other_period, "system:close-run")
            .await
            .expect("generate second draft");
    let raw = sqlx::query("UPDATE annual_reports SET status = 'management_approved' WHERE id = $1")
        .bind(other_report.id)
        .execute(&pool)
        .await;
    assert!(
        raw.is_err(),
        "DB must refuse an approval row without an approver"
    );
}

#[tokio::test]
async fn annual_report_refuses_open_periods_and_survives_hostile_periods() {
    let Some(pool) = canonical_pool("annual_report_hostile").await else {
        return;
    };
    let (entity_id, _bank, _revenue, _equity) = seed_entity_with_accounts(&pool, "16588744").await;

    // Open period: refused.
    let open = create_period(
        &pool,
        entity_id,
        "year",
        "FY 2025",
        d(2025, 1, 1),
        d(2025, 12, 31),
        false,
    )
    .await;
    let error = generate_annual_report(&pool, entity_id, open, "system")
        .await
        .expect_err("open period must be refused");
    assert!(error.contains("CLOSED"));

    // Closed but empty period: a zeroed draft, no panic.
    let empty = create_period(
        &pool,
        entity_id,
        "year",
        "FY 2026",
        d(2026, 1, 1),
        d(2026, 12, 31),
        true,
    )
    .await;
    let report = generate_annual_report(&pool, entity_id, empty, "system")
        .await
        .expect("empty closed period generates a zeroed draft");
    assert_eq!(report.ledger_entry_count, 0);
    assert_eq!(report.income_statement["revenue_cents"], json!(0));
    assert!(report.balance_check_ok);

    // Zero-length custom period: allowed structurally, zeroed derivation.
    let zero_length = create_period(
        &pool,
        entity_id,
        "custom",
        "zero-length",
        d(2026, 6, 30),
        d(2026, 6, 30),
        true,
    )
    .await;
    let report = generate_annual_report(&pool, entity_id, zero_length, "system")
        .await
        .expect("zero-length period must not panic");
    assert_eq!(report.balance_sheet["assets_cents"], json!(0));

    // Reversed period cannot even exist in the canonical schema.
    let reversed = sqlx::query(
        "INSERT INTO fiscal_periods (legal_entity_id, period_type, label, start_date, end_date) \
         VALUES ($1, 'custom', 'reversed', $2, $3)",
    )
    .bind(entity_id)
    .bind(d(2026, 12, 31))
    .bind(d(2026, 1, 1))
    .execute(&pool)
    .await;
    assert!(
        reversed.is_err(),
        "reversed period must be rejected by CHECK"
    );

    // A monthly period is the wrong granularity for an annual report.
    let monthly = create_period(
        &pool,
        entity_id,
        "month",
        "2026-01",
        d(2026, 1, 1),
        d(2026, 1, 31),
        true,
    )
    .await;
    let error = generate_annual_report(&pool, entity_id, monthly, "system")
        .await
        .expect_err("monthly period must be refused");
    assert!(error.contains("type 'year'"));
}

// ── Obligation scheduler ───────────────────────────────────────────────────

#[tokio::test]
async fn obligation_sync_persists_holiday_adjusted_deadlines_idempotently() {
    let Some(pool) = canonical_pool("obligation_sync").await else {
        return;
    };
    let (entity_id, _bank, _revenue, _equity) = seed_entity_with_accounts(&pool, "16588745").await;

    sqlx::query(
        "INSERT INTO legal_entity_filing_facts \
            (legal_entity_id, vat_registered_from, employer_since, oss_registered_from, fiscal_year_end_month) \
         VALUES ($1, $2, $2, $2, 12)",
    )
    .bind(entity_id)
    .bind(d(2020, 1, 1))
    .execute(&pool)
    .await
    .expect("insert filing facts");

    let facts = load_filing_facts(&pool, entity_id)
        .await
        .expect("load facts");
    assert_eq!(facts.vat_registered_from, Some(d(2020, 1, 1)));
    assert_eq!(facts.fiscal_year_end_month, 12);

    // June 2026 horizon contains the May KMD deadline, which is legally
    // 20 June (Saturday) and therefore effectively Monday 22 June.
    let horizon = ObligationHorizon::month(2026, 6).unwrap();
    let first = sync_obligations(&pool, &facts, horizon)
        .await
        .expect("sync");
    assert!(first > 0);

    let kmd_due: NaiveDate = sqlx::query_scalar(
        "SELECT due_date FROM statutory_obligations \
         WHERE legal_entity_id = $1 AND obligation_type = 'kmd' AND period_start = $2",
    )
    .bind(entity_id)
    .bind(d(2026, 5, 1))
    .fetch_one(&pool)
    .await
    .expect("May KMD obligation");
    assert_eq!(kmd_due, d(2026, 6, 22));

    let legal: NaiveDate = sqlx::query_scalar(
        "SELECT legal_due_date FROM statutory_obligations \
         WHERE legal_entity_id = $1 AND obligation_type = 'kmd' AND period_start = $2",
    )
    .bind(entity_id)
    .bind(d(2026, 5, 1))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(legal, d(2026, 6, 20));

    let calendar_version: String = sqlx::query_scalar(
        "SELECT calendar_version FROM statutory_obligations \
         WHERE legal_entity_id = $1 AND obligation_type = 'kmd' AND period_start = $2",
    )
    .bind(entity_id)
    .bind(d(2026, 5, 1))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(calendar_version, "EE-2025.1");

    // Re-syncing the same horizon is idempotent (same row count, same due date).
    let second = sync_obligations(&pool, &facts, horizon)
        .await
        .expect("re-sync");
    assert!(second > 0);
    let row_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM statutory_obligations WHERE legal_entity_id = $1")
            .bind(entity_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let distinct_expected = derive_obligations(&facts, horizon).len() as i64;
    assert_eq!(row_count, distinct_expected);

    let kmd_due_again: NaiveDate = sqlx::query_scalar(
        "SELECT due_date FROM statutory_obligations \
         WHERE legal_entity_id = $1 AND obligation_type = 'kmd' AND period_start = $2",
    )
    .bind(entity_id)
    .bind(d(2026, 5, 1))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(kmd_due_again, d(2026, 6, 22));
}

// ── VD/OSS submission transport ────────────────────────────────────────────

struct FakeTransport {
    result: Result<TransportReceipt, String>,
}

#[async_trait]
impl FilingTransport for FakeTransport {
    async fn submit(
        &self,
        _package: &compliance::filing_transport::SubmissionPackage,
    ) -> Result<TransportReceipt, String> {
        self.result.clone()
    }
}

fn machine_config() -> FilingTransportConfig {
    FilingTransportConfig {
        mode: TransportMode::Http,
        endpoint: Some("https://filing.test/submit".into()),
        bearer_token: Some("test-credential".into()),
        timeout_secs: 5,
    }
}

async fn seed_oss_registration(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO oss_registrations (scheme, registration_country, registration_number, valid_from) \
         VALUES ('union', 'EE', 'EE-OSS-TEST', $1) RETURNING id",
    )
    .bind(d(2025, 1, 1))
    .fetch_one(pool)
    .await
    .expect("insert OSS registration")
}

async fn seed_oss_return(pool: &PgPool, registration_id: Uuid, period: &str) -> Uuid {
    let return_id: Uuid = sqlx::query_scalar(
        "INSERT INTO oss_returns \
            (registration_id, period, scheme, status, total_taxable_cents, total_vat_cents, supply_count, payload_hash) \
         VALUES ($1, $2, 'union', 'validated', 10000, 2400, 1, 'payload-hash-1') RETURNING id",
    )
    .bind(registration_id)
    .bind(period)
    .fetch_one(pool)
    .await
    .expect("insert OSS return");

    sqlx::query(
        "INSERT INTO oss_supply_entries \
            (registration_id, period, supply_id, tenant_id, customer_country, consumption_country, \
             taxable_amount_cents, vat_rate, vat_amount_cents, currency) \
         VALUES ($1, $2, $3, 'tenant-1', 'DE', 'DE', 10000, 24.0, 2400, 'EUR')",
    )
    .bind(registration_id)
    .bind(period)
    .bind(format!("supply-{period}"))
    .execute(pool)
    .await
    .expect("insert OSS supply entry");

    return_id
}

#[tokio::test]
async fn oss_submission_without_receipt_is_never_acknowledged() {
    let Some(pool) = canonical_pool("oss_receipt_driven").await else {
        return;
    };
    let registration_id = seed_oss_registration(&pool).await;
    let return_id = seed_oss_return(&pool, registration_id, "2026-01").await;

    // Unconfigured transport: package persisted, mandatory human task open,
    // return NOT submitted.
    let outcome = submit_oss_return(&pool, return_id, &FilingTransportConfig::disabled(), None)
        .await
        .expect("unconfigured submission produces a human task");
    let task_id = match outcome {
        SubmissionOutcome::HumanTaskRequired {
            task_id,
            package_id,
        } => {
            let transport: String = sqlx::query_scalar(
                "SELECT transport FROM filing_submission_packages WHERE id = $1",
            )
            .bind(package_id)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(transport, "human_task");
            task_id
        }
        other => panic!("expected HumanTaskRequired, got {other:?}"),
    };

    let status: String = sqlx::query_scalar("SELECT status FROM oss_returns WHERE id = $1")
        .bind(return_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "validated", "a human task is not a submission");

    // No submission receipt exists yet: acknowledgement must be refused.
    let error = ingest_acknowledgement(
        &pool,
        ReturnKind::Oss,
        return_id,
        "PORTAL-ACK-1",
        json!({"accepted": true}),
        "operator:1",
    )
    .await
    .expect_err("cannot acknowledge an unsubmitted return");
    assert!(error.contains("submitted"));

    // Fetch the open task and try to close it with a fabricated reference.
    let open_task: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM filing_human_tasks WHERE return_id = $1 AND status = 'open'",
    )
    .bind(return_id)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert_eq!(open_task, Some(task_id));

    let error = record_manual_submission(
        &pool,
        ReturnKind::Oss,
        return_id,
        task_id,
        "operator:1",
        "   ",
        None,
    )
    .await
    .expect_err("blank portal reference must be refused");
    assert!(error.contains("portal reference"));

    // A real human submission requires the actor and the portal reference.
    record_manual_submission(
        &pool,
        ReturnKind::Oss,
        return_id,
        task_id,
        "operator:1",
        "EMTA-OSS-2026-01-0001",
        Some(json!({"channel": "emta_portal"})),
    )
    .await
    .expect("manual submission recorded");

    let status: String = sqlx::query_scalar("SELECT status FROM oss_returns WHERE id = $1")
        .bind(return_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "submitted");

    let task: (String, Option<String>) =
        sqlx::query_as("SELECT status, authenticated_actor FROM filing_human_tasks WHERE id = $1")
            .bind(task_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(task.0, "completed");
    assert_eq!(task.1.as_deref(), Some("operator:1"));

    // Blank receipt reference still cannot acknowledge.
    let error = ingest_acknowledgement(
        &pool,
        ReturnKind::Oss,
        return_id,
        " ",
        json!({}),
        "operator:1",
    )
    .await
    .expect_err("blank acknowledgement reference must be refused");
    assert!(error.contains("receipt"));

    // Receipt-driven acknowledgement.
    ingest_acknowledgement(
        &pool,
        ReturnKind::Oss,
        return_id,
        "EMTA-ACK-2026-01-0001",
        json!({"accepted": true, "package_sha256": package_sha256(&pool, return_id).await}),
        "operator:1",
    )
    .await
    .expect("acknowledge with receipt");

    let (status, reference): (String, Option<String>) =
        sqlx::query_as("SELECT status, acknowledgement_reference FROM oss_returns WHERE id = $1")
            .bind(return_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status, "acknowledged");
    assert_eq!(reference.as_deref(), Some("EMTA-ACK-2026-01-0001"));

    let receipts: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM filing_receipts WHERE return_id = $1 AND receipt_type = 'acknowledgement'",
    )
    .bind(return_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(receipts, 1);
}

async fn package_sha256(pool: &PgPool, return_id: Uuid) -> String {
    sqlx::query_scalar(
        "SELECT payload_sha256 FROM filing_submission_packages \
         WHERE return_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(return_id)
    .fetch_one(pool)
    .await
    .expect("package hash")
}

#[tokio::test]
async fn machine_transport_requires_a_real_receipt() {
    let Some(pool) = canonical_pool("oss_machine_receipt").await else {
        return;
    };
    let registration_id = seed_oss_registration(&pool).await;

    // 1) Transport returns a 2xx-like success with NO receipt reference:
    //    must fail, return stays validated, package marked failed.
    let no_receipt_id = seed_oss_return(&pool, registration_id, "2026-02").await;
    let transport = FakeTransport {
        result: Ok(TransportReceipt {
            receipt_reference: "   ".into(),
            accepted_at: Utc::now(),
            receipt_payload: json!({"status": "ok"}),
        }),
    };
    let error = submit_oss_return(&pool, no_receipt_id, &machine_config(), Some(&transport))
        .await
        .expect_err("empty receipt reference must not count as success");
    assert!(error.contains("empty receipt"));
    let status: String = sqlx::query_scalar("SELECT status FROM oss_returns WHERE id = $1")
        .bind(no_receipt_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "validated");

    // 2) Transport fails: return stays validated, package records the error.
    let failed_id = seed_oss_return(&pool, registration_id, "2026-03").await;
    let transport = FakeTransport {
        result: Err("connection refused".into()),
    };
    let error = submit_oss_return(&pool, failed_id, &machine_config(), Some(&transport))
        .await
        .expect_err("transport failure must propagate");
    assert!(error.contains("NOT submitted"));
    let status: String = sqlx::query_scalar("SELECT status FROM oss_returns WHERE id = $1")
        .bind(failed_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "validated");

    // 3) A real receipt moves the return to submitted (not acknowledged).
    let good_id = seed_oss_return(&pool, registration_id, "2026-04").await;
    let transport = FakeTransport {
        result: Ok(TransportReceipt {
            receipt_reference: "EMTA-SUB-2026-04-42".into(),
            accepted_at: Utc::now(),
            receipt_payload: json!({"status": "received", "reference": "EMTA-SUB-2026-04-42"}),
        }),
    };
    let outcome = submit_oss_return(&pool, good_id, &machine_config(), Some(&transport))
        .await
        .expect("machine submission with receipt");
    match outcome {
        SubmissionOutcome::Submitted {
            receipt_reference, ..
        } => assert_eq!(receipt_reference, "EMTA-SUB-2026-04-42"),
        other => panic!("expected Submitted, got {other:?}"),
    }

    let (status, ack_at): (String, Option<chrono::DateTime<Utc>>) =
        sqlx::query_as("SELECT status, acknowledged_at FROM oss_returns WHERE id = $1")
            .bind(good_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status, "submitted");
    assert!(ack_at.is_none(), "submission is NOT acknowledgement");

    // A receipt naming a different package hash cannot acknowledge.
    let error = ingest_acknowledgement(
        &pool,
        ReturnKind::Oss,
        good_id,
        "EMTA-ACK-WRONG",
        json!({"package_sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}),
        "operator:1",
    )
    .await
    .expect_err("mismatched package hash must be refused");
    assert!(error.contains("package"));

    // The matching receipt acknowledges.
    ingest_acknowledgement(
        &pool,
        ReturnKind::Oss,
        good_id,
        "EMTA-ACK-2026-04-42",
        json!({"accepted": true, "package_sha256": package_sha256(&pool, good_id).await}),
        "operator:1",
    )
    .await
    .expect("acknowledge");
    let status: String = sqlx::query_scalar("SELECT status FROM oss_returns WHERE id = $1")
        .bind(good_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "acknowledged");

    // 4) Submission from a non-validated status is refused: generate a fresh
    //    return, submit it once, then a second attempt cannot re-submit.
    let resubmit_id = seed_oss_return(&pool, registration_id, "2026-05").await;
    let transport = FakeTransport {
        result: Ok(TransportReceipt {
            receipt_reference: "EMTA-SUB-2026-05-1".into(),
            accepted_at: Utc::now(),
            receipt_payload: json!({"status": "received"}),
        }),
    };
    submit_oss_return(&pool, resubmit_id, &machine_config(), Some(&transport))
        .await
        .expect("first submission");
    let error = submit_oss_return(&pool, resubmit_id, &machine_config(), Some(&transport))
        .await
        .expect_err("second submission must be refused");
    assert!(error.contains("validated"));
}
