//! Derivation read contract for filing/report code.
//!
//! **KMD, TSD and the annual report must consume these functions (or the
//! equivalent views) instead of reading `invoices` / `credit_notes` /
//! `payroll_records` directly.** The operational tables are evidence; the
//! posted ledger is the authoritative register.
//!
//! Filters on every function below: `posted_at IS NOT NULL` (drafts are not
//! authoritative) and the requested `(legal_entity_id, fiscal_period_id)`.
//! Reversal entries are included by design — they net against their
//! original exactly as accounting requires.

use chrono::{DateTime, NaiveDate, Utc};
use sqlx::postgres::Postgres;
use uuid::Uuid;

use crate::error::Result;

/// Trial balance: per account debit/credit totals and the signed balance.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TrialBalanceRow {
    pub legal_entity_id: Uuid,
    pub fiscal_period_id: Uuid,
    pub account_id: Uuid,
    pub account_code: String,
    pub account_name: String,
    pub account_type: String,
    pub normal_balance: String,
    pub account_role: Option<String>,
    pub debit_cents: i64,
    pub credit_cents: i64,
    pub balance_debit_positive: i64,
}

/// One VAT-recognizable journal line (KMD row input).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct VatLedgerRow {
    pub legal_entity_id: Uuid,
    pub fiscal_period_id: Uuid,
    pub journal_entry_id: Uuid,
    pub entry_date: NaiveDate,
    pub entry_type: String,
    pub source_document_id: Option<Uuid>,
    pub source_type: Option<String>,
    pub source_table: Option<String>,
    pub source_id: Option<String>,
    pub vat_role: Option<String>,
    pub vat_code: Option<String>,
    pub vat_rate_bp: Option<i32>,
    pub net_cents: Option<i64>,
    pub vat_cents: Option<i64>,
    /// `net_cents` signed by accounting direction (positive = increases the
    /// output liability / input asset, negative = decreases it). Reversals
    /// and credit notes therefore net against their originals.
    pub signed_net_cents: Option<i64>,
    /// `vat_cents` signed by accounting direction.
    pub signed_vat_cents: Option<i64>,
    pub currency: String,
    pub retention_class: String,
}

/// Aggregated VAT totals for a period (KMD boxes: output/input base + tax).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VatTotals {
    pub output_base_cents: i64,
    pub output_vat_cents: i64,
    pub input_base_cents: i64,
    pub input_vat_cents: i64,
}

impl VatTotals {
    /// Net VAT payable (positive) / refundable (negative) for the period.
    pub fn payable_cents(&self) -> i64 {
        self.output_vat_cents.saturating_sub(self.input_vat_cents)
    }
}

/// One payroll posting (TSD input).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PayrollTaxRow {
    pub id: Uuid,
    pub legal_entity_id: Uuid,
    pub fiscal_period_id: Uuid,
    pub payroll_record_id: Uuid,
    pub employee_name: Option<String>,
    pub gross_cents: i64,
    pub income_tax_cents: i64,
    pub social_tax_cents: i64,
    pub unemployment_employee_cents: i64,
    pub unemployment_employer_cents: i64,
    pub pension_cents: i64,
    pub net_cents: i64,
    pub currency: String,
    pub journal_entry_id: Option<Uuid>,
    pub entry_date: Option<NaiveDate>,
    pub posted_at: Option<DateTime<Utc>>,
}

/// Posted-entry summary for audit trails.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PostedEntryRow {
    pub journal_entry_id: Uuid,
    pub legal_entity_id: Uuid,
    pub fiscal_period_id: Uuid,
    pub entry_no: i64,
    pub entry_date: NaiveDate,
    pub entry_type: String,
    pub memo: String,
    pub source_document_id: Option<Uuid>,
    pub source_hash: String,
    pub idempotency_key: String,
    pub reversal_of_entry_id: Option<Uuid>,
    pub posted_at: Option<DateTime<Utc>>,
    pub posted_by: Option<String>,
    pub retention_class: String,
    pub period_label: String,
    pub period_start: NaiveDate,
    pub period_end: NaiveDate,
    pub legal_entity_registry_code: String,
}

/// Debit/credit movement grouped by account type (annual-report input).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PeriodMovementRow {
    pub legal_entity_id: Uuid,
    pub fiscal_period_id: Uuid,
    pub account_type: String,
    pub debit_cents: i64,
    pub credit_cents: i64,
}

/// Trial balance for `(entity, period)`.
pub async fn trial_balance<'e, E>(
    executor: E,
    legal_entity_id: Uuid,
    fiscal_period_id: Uuid,
) -> Result<Vec<TrialBalanceRow>>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let rows = sqlx::query_as::<_, TrialBalanceRow>(
        "SELECT legal_entity_id, fiscal_period_id, account_id, account_code, account_name, \
                account_type, normal_balance, account_role, debit_cents, credit_cents, \
                balance_debit_positive \
         FROM v_accounting_trial_balance \
         WHERE legal_entity_id = $1 AND fiscal_period_id = $2 \
         ORDER BY account_code",
    )
    .bind(legal_entity_id)
    .bind(fiscal_period_id)
    .fetch_all(executor)
    .await?;
    Ok(rows)
}

/// Every VAT-recognizable posted line in `(entity, period)` — the KMD read
/// contract ("VAT-recognizable entries for period P").
pub async fn vat_entries_for_period<'e, E>(
    executor: E,
    legal_entity_id: Uuid,
    fiscal_period_id: Uuid,
) -> Result<Vec<VatLedgerRow>>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let rows = sqlx::query_as::<_, VatLedgerRow>(
        "SELECT legal_entity_id, fiscal_period_id, journal_entry_id, entry_date, entry_type, \
                source_document_id, source_type, source_table, source_id, vat_role, vat_code, \
                vat_rate_bp, net_cents, vat_cents, signed_net_cents, signed_vat_cents, currency, \
                retention_class \
         FROM v_accounting_vat_entries \
         WHERE legal_entity_id = $1 AND fiscal_period_id = $2 \
         ORDER BY entry_date, journal_entry_id",
    )
    .bind(legal_entity_id)
    .bind(fiscal_period_id)
    .fetch_all(executor)
    .await?;
    Ok(rows)
}

/// Aggregated output/input VAT totals for `(entity, period)`.
pub async fn vat_totals_for_period<'e, E>(
    executor: E,
    legal_entity_id: Uuid,
    fiscal_period_id: Uuid,
) -> Result<VatTotals>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let row: (i64, i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COALESCE(SUM(CASE WHEN vat_role = 'vat_output' THEN signed_net_cents END), 0)::bigint,
            COALESCE(SUM(CASE WHEN vat_role = 'vat_output' THEN signed_vat_cents END), 0)::bigint,
            COALESCE(SUM(CASE WHEN vat_role = 'vat_input'  THEN signed_net_cents END), 0)::bigint,
            COALESCE(SUM(CASE WHEN vat_role = 'vat_input'  THEN signed_vat_cents END), 0)::bigint
        FROM v_accounting_vat_entries
        WHERE legal_entity_id = $1 AND fiscal_period_id = $2
        "#,
    )
    .bind(legal_entity_id)
    .bind(fiscal_period_id)
    .fetch_one(executor)
    .await?;

    Ok(VatTotals {
        output_base_cents: row.0,
        output_vat_cents: row.1,
        input_base_cents: row.2,
        input_vat_cents: row.3,
    })
}

/// Payroll tax postings for `(entity, period)` — the TSD read contract.
pub async fn payroll_taxes_for_period<'e, E>(
    executor: E,
    legal_entity_id: Uuid,
    fiscal_period_id: Uuid,
) -> Result<Vec<PayrollTaxRow>>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let rows = sqlx::query_as::<_, PayrollTaxRow>(
        "SELECT id, legal_entity_id, fiscal_period_id, payroll_record_id, employee_name, \
                gross_cents, income_tax_cents, social_tax_cents, unemployment_employee_cents, \
                unemployment_employer_cents, pension_cents, net_cents, currency, \
                journal_entry_id, entry_date, posted_at \
         FROM v_accounting_payroll_taxes \
         WHERE legal_entity_id = $1 AND fiscal_period_id = $2 AND posted_at IS NOT NULL \
         ORDER BY employee_name NULLS LAST, id",
    )
    .bind(legal_entity_id)
    .bind(fiscal_period_id)
    .fetch_all(executor)
    .await?;
    Ok(rows)
}

/// Debit/credit movement per account type for `(entity, period)`.
pub async fn period_movement<'e, E>(
    executor: E,
    legal_entity_id: Uuid,
    fiscal_period_id: Uuid,
) -> Result<Vec<PeriodMovementRow>>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let rows = sqlx::query_as::<_, PeriodMovementRow>(
        "SELECT legal_entity_id, fiscal_period_id, account_type, debit_cents, credit_cents \
         FROM v_accounting_period_movement \
         WHERE legal_entity_id = $1 AND fiscal_period_id = $2 \
         ORDER BY account_type",
    )
    .bind(legal_entity_id)
    .bind(fiscal_period_id)
    .fetch_all(executor)
    .await?;
    Ok(rows)
}

/// Revenue, expense and net result for a period (annual-report input).
pub async fn period_result<'e, E>(
    executor: E,
    legal_entity_id: Uuid,
    fiscal_period_id: Uuid,
) -> Result<(i64, i64, i64)>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let rows = period_movement(executor, legal_entity_id, fiscal_period_id).await?;
    let mut revenue = 0i64;
    let mut expenses = 0i64;
    for row in rows {
        match row.account_type.as_str() {
            "revenue" => {
                revenue = revenue.saturating_add(row.credit_cents.saturating_sub(row.debit_cents))
            }
            "expense" => {
                expenses = expenses.saturating_add(row.debit_cents.saturating_sub(row.credit_cents))
            }
            _ => {}
        }
    }
    Ok((revenue, expenses, revenue.saturating_sub(expenses)))
}

/// Posted entries in `(entity, period)` (audit trail / register export).
pub async fn posted_entries<'e, E>(
    executor: E,
    legal_entity_id: Uuid,
    fiscal_period_id: Uuid,
) -> Result<Vec<PostedEntryRow>>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let rows = sqlx::query_as::<_, PostedEntryRow>(
        "SELECT journal_entry_id, legal_entity_id, fiscal_period_id, entry_no, entry_date, \
                entry_type, memo, source_document_id, source_hash, idempotency_key, \
                reversal_of_entry_id, posted_at, posted_by, retention_class, period_label, \
                period_start, period_end, legal_entity_registry_code \
         FROM v_accounting_posted_entries \
         WHERE legal_entity_id = $1 AND fiscal_period_id = $2 \
         ORDER BY entry_no",
    )
    .bind(legal_entity_id)
    .bind(fiscal_period_id)
    .fetch_all(executor)
    .await?;
    Ok(rows)
}

/// Every posted entry generated from one source document (traceability:
/// "which journal did this Stripe event produce?").
pub async fn entries_for_source<'e, E>(
    executor: E,
    source_type: &str,
    source_table: &str,
    source_id: &str,
) -> Result<Vec<PostedEntryRow>>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let rows = sqlx::query_as::<_, PostedEntryRow>(
        "SELECT journal_entry_id, legal_entity_id, fiscal_period_id, entry_no, entry_date, \
                entry_type, memo, source_document_id, source_hash, idempotency_key, \
                reversal_of_entry_id, posted_at, posted_by, retention_class, period_label, \
                period_start, period_end, legal_entity_registry_code \
         FROM v_accounting_posted_entries \
         WHERE source_document_id = ( \
             SELECT id FROM accounting_source_documents \
             WHERE source_type = $1 AND source_table = $2 AND source_id = $3 \
         ) \
         ORDER BY entry_no",
    )
    .bind(source_type)
    .bind(source_table)
    .bind(source_id)
    .fetch_all(executor)
    .await?;
    Ok(rows)
}
