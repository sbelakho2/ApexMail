//! DB-backed tests for the unposted-source sweeps (payroll, expenses, bank).
//!
//! Every test provisions the real canonical migration chain through
//! `migrator::test_support` (the workspace convention). One shared database
//! per binary; tests isolate by working on their own source rows and, where
//! the adapter resolves the default entity, through one cached default seed.
//!
//! Set `TEST_DATABASE_URL` to run them; without it each test skips, and a
//! configured-but-broken provisioning is a hard failure.
//!
//! Covered behaviour:
//!  1. payroll: a record with no writer is posted exactly once by the sweep;
//!     a replay posts nothing; two concurrent sweeps still post once;
//!  2. payroll: an incomplete record (unknown pension participation) is left
//!     unposted and posts automatically once the input is completed;
//!  3. expenses: a missing `operating_costs` store is reported, not an error;
//!     once the store exists, positive rows post idempotently and
//!     non-positive rows are reported unpostable;
//!  4. bank: unreconciled non-zero lines post idempotently and are stamped;
//!     zero-amount lines are reported unpostable.

use accounting_core::chart::{self, LegalEntityInput};
use accounting_core::periods;
use accounting_core::sweeps::{
    self, PayrollAmountsPolicy, PayrollRecordFacts, SweepConfig, SweepReport,
};
use accounting_core::types::*;
use chrono::NaiveDate;
use sqlx::PgPool;
use std::sync::OnceLock;
use uuid::Uuid;

const SHARED_DB: &str = "apexmail_accounting_sweeps_test";

fn run_tag() -> &'static str {
    static TAG: OnceLock<String> = OnceLock::new();
    TAG.get_or_init(|| Uuid::new_v4().simple().to_string()[..8].to_string())
}

async fn provision(test_name: &str) -> Option<PgPool> {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("skipping {test_name}: TEST_DATABASE_URL is not configured");
        return None;
    };
    if url.trim().is_empty() {
        eprintln!("skipping {test_name}: TEST_DATABASE_URL is not configured");
        return None;
    }
    let (server, db_part) = url
        .rsplit_once('/')
        .expect("TEST_DATABASE_URL has a db segment");
    let db_only = db_part.split('?').next().unwrap_or(db_part);
    let base_url = format!("{server}/{db_only}");
    match migrator::test_support::shared_canonical_db(&base_url, SHARED_DB).await {
        Ok(Some(pool)) => Some(pool),
        Ok(None) => None,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

fn date(year: i32, month: u32, day: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(year, month, day).expect("valid date")
}

/// The default legal entity is shared by every payroll/expense test (the
/// adapters resolve it). Serialize its creation and cache it.
static DEFAULT_SEED: tokio::sync::Mutex<Option<Uuid>> = tokio::sync::Mutex::const_new(None);

async fn default_entity(pool: &PgPool) -> Uuid {
    let mut guard = DEFAULT_SEED.lock().await;
    if let Some(entity) = *guard {
        return entity;
    }
    let mut conn = pool.acquire().await.expect("pool acquire");
    let entity = match sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM legal_entities WHERE is_default LIMIT 1",
    )
    .fetch_optional(&mut *conn)
    .await
    .expect("default entity probe")
    {
        Some(entity) => entity,
        None => chart::create_legal_entity(
            &mut conn,
            &LegalEntityInput {
                legal_name: "Sweep Test OÜ".to_string(),
                trading_name: None,
                registry_code: "SWEEP-DEFAULT".to_string(),
                vat_number: None,
                address_line1: None,
                city: None,
                postal_code: None,
                country_code: "EE".to_string(),
                default_currency: "EUR".to_string(),
                fiscal_year_start_month: 1,
                is_default: true,
            },
        )
        .await
        .expect("create default entity"),
    };
    chart::ensure_standard_chart(&mut conn, entity)
        .await
        .expect("chart");
    periods::ensure_period(
        &mut conn,
        entity,
        "year",
        "sweeps-year",
        date(2026, 1, 1),
        date(2026, 12, 31),
    )
    .await
    .expect("period");
    *guard = Some(entity);
    entity
}

/// A non-default entity + chart + period, for tests whose adapter resolves
/// the entity from the source row (bank).
async fn own_seed(pool: &PgPool, tag: &str) -> Uuid {
    let mut conn = pool.acquire().await.expect("pool acquire");
    let entity = chart::create_legal_entity(
        &mut conn,
        &LegalEntityInput {
            legal_name: format!("Sweep {tag} OÜ"),
            trading_name: None,
            registry_code: format!("SWEEP-{tag}"),
            vat_number: None,
            address_line1: None,
            city: None,
            postal_code: None,
            country_code: "EE".to_string(),
            default_currency: "EUR".to_string(),
            fiscal_year_start_month: 1,
            is_default: false,
        },
    )
    .await
    .expect("create legal entity");
    chart::ensure_standard_chart(&mut conn, entity)
        .await
        .expect("chart");
    periods::ensure_period(
        &mut conn,
        entity,
        "year",
        tag,
        date(2026, 1, 1),
        date(2026, 12, 31),
    )
    .await
    .expect("period");
    entity
}

/// Deterministic test policy: the exact identity the adapter validates
/// (`gross = net + income tax + employee unemployment + pension`), no rate
/// decisions. `None` for unknown pension participation, like the real policy.
fn test_policy(record: &PayrollRecordFacts) -> accounting_core::Result<Option<PayrollAmounts>> {
    if record.funded_pension_rate.is_none() && !record.pension_exemption {
        return Ok(None);
    }
    let gross = record.gross_salary_cents;
    let income_tax_cents = gross / 10;
    let unemployment_employee_cents = gross / 100;
    let pension_cents = gross / 50;
    let net_cents = gross - income_tax_cents - unemployment_employee_cents - pension_cents;
    Ok(Some(PayrollAmounts {
        income_tax_cents,
        social_tax_cents: gross / 3,
        unemployment_employee_cents,
        unemployment_employer_cents: gross / 125,
        pension_cents,
        net_cents,
    }))
}

async fn insert_payroll_record(
    pool: &PgPool,
    gross_cents: i64,
    pension_rate: Option<f64>,
    period_end: chrono::DateTime<chrono::Utc>,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO payroll_records (employee_name, personal_code, gross_salary_cents, \
            funded_pension_rate, pay_period) \
         VALUES ('Sweep Employee', 'SWEEP-1', $1, $2, $3) RETURNING id",
    )
    .bind(gross_cents)
    .bind(pension_rate)
    .bind(period_end)
    .fetch_one(pool)
    .await
    .expect("payroll record")
}

fn pay_period() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-06-30T12:00:00Z")
        .expect("timestamp")
        .with_timezone(&chrono::Utc)
}

async fn journal_entries_for(pool: &PgPool, idempotency_key: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*)::bigint FROM journal_entries WHERE idempotency_key = $1")
        .bind(idempotency_key)
        .fetch_one(pool)
        .await
        .expect("entry count")
}

// ---------------------------------------------------------------------------
// 1 + 2. Payroll
// ---------------------------------------------------------------------------

#[tokio::test]
async fn payroll_sweep_posts_once_and_waits_for_incomplete_records() {
    let Some(pool) = provision("sweep_payroll").await else {
        return;
    };
    let _entity = default_entity(&pool).await;
    let config = SweepConfig::default();

    // Incomplete record: unknown pension participation is NOT zero-rated.
    let incomplete = insert_payroll_record(&pool, 100_000, None, pay_period()).await;
    let report = sweeps::sweep_unposted_payroll(&pool, &config, &test_policy)
        .await
        .expect("sweep");
    assert_eq!(report.skipped_incomplete, 1, "{report:?}");
    assert_eq!(
        journal_entries_for(&pool, &format!("payroll:{incomplete}")).await,
        0
    );

    // Completing the input makes the sweep post it — no other wiring.
    sqlx::query("UPDATE payroll_records SET funded_pension_rate = 0.02 WHERE id = $1")
        .bind(incomplete)
        .execute(&pool)
        .await
        .expect("complete the record");
    let report = sweeps::sweep_unposted_payroll(&pool, &config, &test_policy)
        .await
        .expect("sweep after completion");
    assert_eq!(report.posted, 1, "{report:?}");
    assert_eq!(
        journal_entries_for(&pool, &format!("payroll:{incomplete}")).await,
        1
    );

    // The posting is complete: entry type, subledger row, balanced lines.
    let entry_id: Uuid =
        sqlx::query_scalar("SELECT id FROM journal_entries WHERE idempotency_key = $1")
            .bind(format!("payroll:{incomplete}"))
            .fetch_one(&pool)
            .await
            .expect("entry");
    let entry_type: String =
        sqlx::query_scalar("SELECT entry_type::text FROM journal_entries WHERE id = $1")
            .bind(entry_id)
            .fetch_one(&pool)
            .await
            .expect("entry type");
    assert_eq!(entry_type, "payroll");
    let posting_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM payroll_postings WHERE payroll_record_id = $1",
    )
    .bind(incomplete)
    .fetch_one(&pool)
    .await
    .expect("payroll postings");
    assert_eq!(posting_rows, 1);
    let (debit, credit): (i64, i64) = sqlx::query_as(
        "SELECT COALESCE(SUM(debit_cents),0)::bigint, COALESCE(SUM(credit_cents),0)::bigint \
         FROM journal_lines WHERE entry_id = $1",
    )
    .bind(entry_id)
    .fetch_one(&pool)
    .await
    .expect("lines");
    assert_eq!(debit, credit);

    // Replay: nothing left to claim.
    let replay = sweeps::sweep_unposted_payroll(&pool, &config, &test_policy)
        .await
        .expect("replay");
    assert_eq!(replay.claimed, 0, "{replay:?}");
    assert_eq!(
        journal_entries_for(&pool, &format!("payroll:{incomplete}")).await,
        1
    );

    // Zero-gross record: reported unpostable, never deleted, no entry.
    let zero = insert_payroll_record(&pool, 0, Some(0.02), pay_period()).await;
    let report = sweeps::sweep_unposted_payroll(&pool, &config, &test_policy)
        .await
        .expect("zero sweep");
    assert_eq!(report.unpostable, 1, "{report:?}");
    assert_eq!(
        journal_entries_for(&pool, &format!("payroll:{zero}")).await,
        0
    );
    let still_there: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM payroll_records WHERE id = $1")
            .bind(zero)
            .fetch_one(&pool)
            .await
            .expect("row survives");
    assert_eq!(still_there, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_payroll_sweeps_post_exactly_once() {
    let Some(pool) = provision("sweep_payroll_concurrent").await else {
        return;
    };
    let _entity = default_entity(&pool).await;
    let config = SweepConfig::default();
    let record = insert_payroll_record(&pool, 120_000, Some(0.04), pay_period()).await;

    let (left, right) = tokio::join!(
        sweeps::sweep_unposted_payroll(&pool, &config, &test_policy),
        sweeps::sweep_unposted_payroll(&pool, &config, &test_policy),
    );
    let left = left.expect("left sweep");
    let right = right.expect("right sweep");
    assert_eq!(
        left.posted + right.posted,
        1,
        "exactly one sweeper may post the record: left={left:?} right={right:?}"
    );
    assert_eq!(
        journal_entries_for(&pool, &format!("payroll:{record}")).await,
        1
    );
}

// ---------------------------------------------------------------------------
// 3. Expenses
// ---------------------------------------------------------------------------

#[tokio::test]
async fn expense_sweep_reports_missing_store_then_posts_idempotently() {
    let Some(pool) = provision("sweep_expenses").await else {
        return;
    };
    let _entity = default_entity(&pool).await;
    let config = SweepConfig::default();

    // The canonical chain deliberately does not create `operating_costs`; a
    // deployment without the optional store must be reported, not an error.
    // (The shared database may carry the table from an earlier run.)
    let existed: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.operating_costs')::text")
            .fetch_one(&pool)
            .await
            .expect("regclass");
    if existed.is_none() {
        let report = sweeps::sweep_unposted_expenses(&pool, &config)
            .await
            .expect("missing store");
        assert!(report.source_table_missing, "{report:?}");
    }

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS operating_costs ( \
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(), \
            category TEXT, \
            amount_cents BIGINT NOT NULL, \
            incurred_at TIMESTAMPTZ NOT NULL)",
    )
    .execute(&pool)
    .await
    .expect("optional expense table");

    let tag = run_tag();
    let cost_id: Uuid = sqlx::query_scalar(
        "INSERT INTO operating_costs (category, amount_cents, incurred_at) \
         VALUES ($1, 4500, TIMESTAMPTZ '2026-06-10 00:00:00+00') RETURNING id",
    )
    .bind(format!("sweep-{tag}"))
    .fetch_one(&pool)
    .await
    .expect("cost");
    let zero_id: Uuid = sqlx::query_scalar(
        "INSERT INTO operating_costs (category, amount_cents, incurred_at) \
         VALUES ('zero', 0, TIMESTAMPTZ '2026-06-11 00:00:00+00') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("zero cost");

    let report = sweeps::sweep_unposted_expenses(&pool, &config)
        .await
        .expect("expense sweep");
    assert_eq!(report.posted, 1, "{report:?}");
    assert!(report.unpostable >= 1, "{report:?}");

    let entry_id: Uuid =
        sqlx::query_scalar("SELECT id FROM journal_entries WHERE idempotency_key = $1")
            .bind(format!("expense:operating_costs:{cost_id}"))
            .fetch_one(&pool)
            .await
            .expect("expense entry");
    let roles: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT a.account_role, COALESCE(SUM(l.debit_cents),0)::bigint, \
                COALESCE(SUM(l.credit_cents),0)::bigint \
         FROM journal_lines l JOIN chart_of_accounts a ON a.id = l.account_id \
         WHERE l.entry_id = $1 GROUP BY a.account_role",
    )
    .bind(entry_id)
    .fetch_all(&pool)
    .await
    .expect("expense roles");
    assert!(roles.contains(&(ROLE_EXPENSE_DEFAULT.to_string(), 4500, 0)));
    assert!(roles.contains(&(ROLE_AP.to_string(), 0, 4500)));

    // Replay is a no-op, and the zero row is retained (unpostable, not lost).
    let replay = sweeps::sweep_unposted_expenses(&pool, &config)
        .await
        .expect("expense replay");
    assert_eq!(replay.claimed, 0, "{replay:?}");
    let zero_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM operating_costs WHERE id = $1")
            .bind(zero_id)
            .fetch_one(&pool)
            .await
            .expect("zero row survives");
    assert_eq!(zero_rows, 1);
}

// ---------------------------------------------------------------------------
// 4. Bank statement lines
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bank_sweep_posts_unreconciled_lines_once() {
    let Some(pool) = provision("sweep_bank").await else {
        return;
    };
    let tag = format!("bank-{}", run_tag());
    let entity = own_seed(&pool, &tag).await;
    let config = SweepConfig::default();

    let mut conn = pool.acquire().await.expect("conn");
    let bank_ledger = chart::resolve_account_role(&mut conn, entity, ROLE_BANK)
        .await
        .expect("bank account");
    drop(conn);

    let bank_account_id: Uuid = sqlx::query_scalar(
        "INSERT INTO bank_accounts (legal_entity_id, name, iban, currency, account_id) \
         VALUES ($1, 'Sweep Main', $2, 'EUR', $3) RETURNING id",
    )
    .bind(entity)
    .bind(format!("EE00{tag}0000000000"))
    .bind(bank_ledger)
    .fetch_one(&pool)
    .await
    .expect("bank account");

    let receipt: Uuid = sqlx::query_scalar(
        "INSERT INTO bank_statement_lines (bank_account_id, external_id, statement_date, amount_cents, currency) \
         VALUES ($1, $2, DATE '2026-06-20', 5000, 'EUR') RETURNING id",
    )
    .bind(bank_account_id)
    .bind(format!("sweep-{tag}-1"))
    .fetch_one(&pool)
    .await
    .expect("receipt");
    let payment: Uuid = sqlx::query_scalar(
        "INSERT INTO bank_statement_lines (bank_account_id, external_id, statement_date, amount_cents, currency) \
         VALUES ($1, $2, DATE '2026-06-21', -2000, 'EUR') RETURNING id",
    )
    .bind(bank_account_id)
    .bind(format!("sweep-{tag}-2"))
    .fetch_one(&pool)
    .await
    .expect("payment");
    let zero: Uuid = sqlx::query_scalar(
        "INSERT INTO bank_statement_lines (bank_account_id, external_id, statement_date, amount_cents, currency) \
         VALUES ($1, $2, DATE '2026-06-22', 0, 'EUR') RETURNING id",
    )
    .bind(bank_account_id)
    .bind(format!("sweep-{tag}-3"))
    .fetch_one(&pool)
    .await
    .expect("zero line");

    let report = sweeps::sweep_unposted_bank_statement_lines(&pool, &config)
        .await
        .expect("bank sweep");
    assert_eq!(report.posted, 2, "{report:?}");
    assert_eq!(report.unpostable, 1, "{report:?}");

    let stamped: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM bank_statement_lines \
         WHERE journal_entry_id IS NOT NULL AND id IN ($1, $2)",
    )
    .bind(receipt)
    .bind(payment)
    .fetch_one(&pool)
    .await
    .expect("stamped");
    assert_eq!(stamped, 2);
    let zero_stamp: Option<Uuid> =
        sqlx::query_scalar("SELECT journal_entry_id FROM bank_statement_lines WHERE id = $1")
            .bind(zero)
            .fetch_one(&pool)
            .await
            .expect("zero line survives unposted");
    assert!(zero_stamp.is_none());

    let replay = sweeps::sweep_unposted_bank_statement_lines(&pool, &config)
        .await
        .expect("bank replay");
    assert_eq!(replay.claimed, 0, "{replay:?}");
    assert_eq!(
        journal_entries_for(&pool, &format!("bank_statement_line:{receipt}")).await,
        1
    );
    assert_eq!(
        journal_entries_for(&pool, &format!("bank_statement_line:{payment}")).await,
        1
    );
}

/// `SweepReport` accounting: `record` is the only place statuses map to
/// counters, so a new `PostStatus` cannot silently disappear.
#[test]
fn sweep_report_counts_every_status() {
    let mut report = SweepReport::default();
    for status in [
        PostStatus::Posted,
        PostStatus::AlreadyPosted,
        PostStatus::Skipped,
    ] {
        report.record(status);
    }
    assert_eq!(report.posted, 1);
    assert_eq!(report.already_posted, 1);
    assert_eq!(report.skipped_incomplete, 1);
    assert!(report.is_idle());
    assert!(!SweepReport {
        claimed: 1,
        ..SweepReport::default()
    }
    .is_idle());
}

/// A policy reference is a `&dyn PayrollAmountsPolicy`: the public entry
/// points accept both a closure and a named implementation.
#[test]
fn policy_trait_accepts_closures_and_named_types() {
    struct Named;
    impl PayrollAmountsPolicy for Named {
        fn amounts_for(
            &self,
            _: &PayrollRecordFacts,
        ) -> accounting_core::Result<Option<PayrollAmounts>> {
            Ok(None)
        }
    }
    let facts = PayrollRecordFacts {
        id: Uuid::nil(),
        employee_name: None,
        gross_salary_cents: 1,
        funded_pension_rate: Some(0.02),
        pension_exemption: false,
        unemployment_insurance_exemption: false,
        pay_period: pay_period(),
    };
    let closures: &dyn PayrollAmountsPolicy = &test_policy;
    assert!(closures.amounts_for(&facts).expect("policy").is_some());
    let named: &dyn PayrollAmountsPolicy = &Named;
    assert!(named.amounts_for(&facts).expect("policy").is_none());
}
