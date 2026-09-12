//! Source sweeps: post unposted operational rows that have NO production
//! writer to hook.
//!
//! A previous pass built the accounting adapters and reported honestly that
//! three of them had no production writer:
//!
//! * **payroll** — `payroll_records` (migration 199) is created by no code in
//!   the repository. There is no payroll-run service, admin endpoint or CLI
//!   that inserts a row. The missing piece is the payroll-run FEATURE itself,
//!   not the ledger wiring.
//! * **expenses** — `operating_costs` is deployment-optional and deliberately
//!   not created by migration 220. Nothing in the repository writes it (only
//!   `compliance/src/estonia_ou.rs` reads it, through a table-existence
//!   guard). The missing piece is the expense-entry feature (and the
//!   deployment's provisioning of the store).
//! * **bank** — `bank_statement_lines` is created by migration 220 but there
//!   is no bank feed / statement importer anywhere in the repository. The
//!   missing piece is the feed/import feature.
//!
//! This module is the smallest honest closure of those gaps: a sweep per
//! source that posts every row that is not yet posted. It needs no product
//! decision, cannot miss a writer (a future service, an admin endpoint, or
//! plain `psql` all insert the same row), and is safe to run repeatedly.
//!
//! # Claim protocol — same `SKIP LOCKED` discipline as the projectors, in its
//! strongest form
//!
//! The sales projectors (`sales-autopilot::outcome_projector`) claim with
//! `FOR UPDATE SKIP LOCKED` and then carry a durable lease, because the work
//! between claim and apply (other transactions / external side effects)
//! outlives one transaction. A posting sweep does not have that property: the
//! claim, the journal write and the commit are ONE transaction:
//!
//! ```text
//! BEGIN;
//!   SELECT ... FROM <source>
//!    WHERE <not yet posted> AND id <> ALL(<already attempted this tick>)
//!    ORDER BY <stable business order>
//!    FOR UPDATE OF <source> SKIP LOCKED
//!    LIMIT 1;
//!   -- only when a row was returned:
//!   <adapter>::post_*_in(conn, ...);        -- unique source doc + idempotency key
//! COMMIT;
//! ```
//!
//! Two sweepers can never process the same row: the second's `SELECT` skips
//! the locked row. A crash rolls the claim back with the posting, so there is
//! no stranded claim and no lease-expiry recovery sweep is needed — strictly
//! stronger than a lease, not weaker. No lease columns are added to the
//! source tables (they belong to other domains, and `operating_costs` may not
//! even exist in a deployment).
//!
//! # Idempotency
//!
//! Each adapter derives its posting from `(source_type, source_table,
//! source_id)` (`accounting_source_documents` UNIQUE) and a stable
//! idempotency key, so replaying a sweep posts nothing new. The sweep also
//! skips a row it already attempted in the same tick, so one poison row cannot
//! consume the whole batch.
//!
//! # What "unpostable" means
//!
//! Rows that cannot ever post as-is are reported, never silently retried
//! forever inside a batch and never deleted:
//!
//! * zero-amount bank lines and non-positive expenses: no balanced journal
//!   exists; a human must correct or write them off (bank reconciliation is a
//!   separate workflow, migration 220's `bank_reconciliations`);
//! * payroll records whose gross is zero, or whose per-employee facts are
//!   incomplete (`funded_pension_rate IS NULL` without an exemption) — the
//!   caller-supplied [`PayrollAmountsPolicy`] returns `None` for the latter,
//!   mirroring `estonia_ou`'s "incomplete, not silently assumed" rule. Such a
//!   record is retried on the next tick and posts automatically once the row
//!   is completed.

use serde::Serialize;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::adapters;
use crate::error::Result;
use crate::types::{PayrollAmounts, PostStatus};

/// Rows one sweep tick claims at most. Bounds the work per tick; the next
/// tick continues where this one stopped (oldest first).
pub const DEFAULT_SWEEP_BATCH: i64 = 100;

/// Sweep tuning. `Default` is the production shape.
#[derive(Debug, Clone, Copy)]
pub struct SweepConfig {
    pub batch_size: i64,
}

impl Default for SweepConfig {
    fn default() -> Self {
        Self {
            batch_size: DEFAULT_SWEEP_BATCH,
        }
    }
}

/// What one sweep tick did.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct SweepReport {
    /// Rows claimed and processed in this tick.
    pub claimed: u64,
    /// Journal entries created (including their subledger rows).
    pub posted: u64,
    /// Claims idempotently resolved to an existing entry (lost race/replay).
    pub already_posted: u64,
    /// Rows intentionally left for a later tick because the policy could not
    /// compute them yet (e.g. incomplete pension input). Not an error.
    pub skipped_incomplete: u64,
    /// Rows no journal can represent until a human fixes them (zero amounts).
    pub unpostable: u64,
    /// Rows whose posting failed; the claim rolled back and the next tick
    /// retries them.
    pub failed: u64,
    /// The deployment-optional source table does not exist (expenses only).
    pub source_table_missing: bool,
}

impl SweepReport {
    /// Fold one posting outcome into the report counters (public so callers
    /// that wrap an adapter can keep the same accounting).
    pub fn record(&mut self, status: PostStatus) {
        match status {
            PostStatus::Posted => self.posted += 1,
            PostStatus::AlreadyPosted => self.already_posted += 1,
            PostStatus::Skipped => self.skipped_incomplete += 1,
        }
    }

    /// True when this tick saw no postable work at all.
    pub fn is_idle(&self) -> bool {
        self.claimed == 0 && self.unpostable == 0 && !self.source_table_missing
    }
}

/// What one sweep pass across all sources did.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct AllSweepsReport {
    pub payroll: SweepReport,
    pub expenses: SweepReport,
    pub bank_statement_lines: SweepReport,
}

impl AllSweepsReport {
    pub fn total_posted(&self) -> u64 {
        self.payroll.posted + self.expenses.posted + self.bank_statement_lines.posted
    }
}

/// The payroll facts the statutory policy needs, read from
/// `payroll_records` while the row is claimed.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PayrollRecordFacts {
    pub id: Uuid,
    pub employee_name: Option<String>,
    pub gross_salary_cents: i64,
    /// The employee's II-pillar choice for the period. `None` = participation
    /// unknown; the policy must report the record incomplete instead of
    /// assuming a rate (migration 199's contract).
    pub funded_pension_rate: Option<f64>,
    pub pension_exemption: bool,
    pub unemployment_insurance_exemption: bool,
    pub pay_period: chrono::DateTime<chrono::Utc>,
}

/// Computes the statutory payroll amounts for one record.
///
/// Implemented where the tax policy lives (`compliance`), NOT here: this
/// crate owns the ledger, not the rates. Returning `Ok(None)` means the
/// record cannot be computed yet and must be left unposted (retried next
/// tick), never defaulted to a guessed rate.
pub trait PayrollAmountsPolicy: Send + Sync {
    fn amounts_for(&self, record: &PayrollRecordFacts) -> Result<Option<PayrollAmounts>>;
}

impl<F> PayrollAmountsPolicy for F
where
    F: Fn(&PayrollRecordFacts) -> Result<Option<PayrollAmounts>> + Send + Sync,
{
    fn amounts_for(&self, record: &PayrollRecordFacts) -> Result<Option<PayrollAmounts>> {
        self(record)
    }
}

// ---------------------------------------------------------------------------
// Payroll
// ---------------------------------------------------------------------------

/// Claim one unposted payroll record, oldest payment period first.
///
/// "Unposted" is `accounting_source_documents` absence for
/// `('payroll','payroll_records',id)`: the adapter registers that document in
/// the same transaction as the entry, so it is the exact posting marker.
const CLAIM_PAYROLL_SQL: &str = r#"
    SELECT pr.id, pr.employee_name, pr.gross_salary_cents,
           pr.funded_pension_rate, pr.pension_exemption,
           pr.unemployment_insurance_exemption, pr.pay_period
    FROM payroll_records pr
    WHERE NOT EXISTS (
            SELECT 1 FROM accounting_source_documents d
            WHERE d.source_type = 'payroll'
              AND d.source_table = 'payroll_records'
              AND d.source_id = pr.id::text
          )
      AND NOT (pr.id = ANY($1::uuid[]))
    ORDER BY pr.pay_period ASC, pr.id ASC
    FOR UPDATE OF pr SKIP LOCKED
    LIMIT 1
"#;

async fn claim_payroll(
    conn: &mut PgConnection,
    attempted: &[Uuid],
) -> Result<Option<PayrollRecordFacts>> {
    let row: Option<PayrollRecordFacts> = sqlx::query_as(CLAIM_PAYROLL_SQL)
        .bind(attempted)
        .fetch_optional(conn)
        .await?;
    Ok(row)
}

/// Post every unposted `payroll_records` row (up to `batch_size` per tick).
///
/// There is no payroll-run writer in the repository: this sweep is what makes
/// the payroll adapter fire the moment one exists. The caller supplies the
/// statutory policy (see [`PayrollAmountsPolicy`]).
pub async fn sweep_unposted_payroll(
    pool: &PgPool,
    config: &SweepConfig,
    policy: &dyn PayrollAmountsPolicy,
) -> Result<SweepReport> {
    let mut report = SweepReport::default();
    // Rows attempted (and failed/incomplete) in this tick are excluded from
    // later claims so one bad row cannot spin the batch.
    let mut attempted: Vec<Uuid> = Vec::new();

    for _ in 0..config.batch_size.max(1) {
        let mut tx = pool.begin().await?;
        let Some(facts) = claim_payroll(&mut tx, &attempted).await? else {
            tx.commit().await?;
            break;
        };
        attempted.push(facts.id);
        report.claimed += 1;

        if facts.gross_salary_cents <= 0 {
            // No balanced journal exists for an all-zero payroll; a human must
            // fix the record (or it is a genuine zero-pay month that needs an
            // explicit decision). Reported, never deleted.
            report.unpostable += 1;
            tx.rollback().await?;
            continue;
        }

        let legal_entity_id = match crate::chart::default_legal_entity(&mut tx).await {
            Ok(id) => id,
            Err(error) => {
                report.failed += 1;
                tracing::warn!(
                    payroll_record_id = %facts.id,
                    error = %error,
                    "payroll sweep could not resolve the default legal entity; row left unposted"
                );
                tx.rollback().await?;
                continue;
            }
        };

        let amounts = match policy.amounts_for(&facts) {
            Ok(Some(amounts)) => amounts,
            Ok(None) => {
                report.skipped_incomplete += 1;
                tracing::debug!(
                    payroll_record_id = %facts.id,
                    "payroll sweep left an incomplete payroll record unposted; it will post once completed"
                );
                tx.rollback().await?;
                continue;
            }
            Err(error) => {
                report.failed += 1;
                tracing::warn!(
                    payroll_record_id = %facts.id,
                    error = %error,
                    "payroll sweep policy failed; row left unposted"
                );
                tx.rollback().await?;
                continue;
            }
        };

        match adapters::post_payroll_record_in(&mut tx, legal_entity_id, facts.id, amounts).await {
            Ok(outcome) => {
                report.record(outcome.status);
                tx.commit().await?;
            }
            Err(error) => {
                report.failed += 1;
                tracing::warn!(
                    payroll_record_id = %facts.id,
                    error = %error,
                    "payroll sweep posting failed; claim rolled back for the next tick"
                );
                tx.rollback().await?;
            }
        }
    }

    Ok(report)
}

// ---------------------------------------------------------------------------
// Expenses
// ---------------------------------------------------------------------------

/// Claim one unposted `operating_costs` row, oldest incurred first.
const CLAIM_EXPENSE_SQL: &str = r#"
    SELECT oc.id
    FROM operating_costs oc
    WHERE oc.amount_cents > 0
      AND NOT EXISTS (
            SELECT 1 FROM accounting_source_documents d
            WHERE d.source_type = 'expense'
              AND d.source_table = 'operating_costs'
              AND d.source_id = oc.id::text
          )
      AND NOT (oc.id = ANY($1::uuid[]))
    ORDER BY oc.incurred_at ASC, oc.id ASC
    FOR UPDATE OF oc SKIP LOCKED
    LIMIT 1
"#;

/// Post every unposted positive `operating_costs` row (up to `batch_size`).
///
/// `operating_costs` is deployment-optional: when the store is absent the
/// report says `source_table_missing` and the sweep succeeds (nothing to do),
/// so a deployment without an expense feature is not an error. The moment a
/// writer exists — a future expense entry feature, a migration, or `psql` —
/// the row is picked up and posted with no further wiring.
pub async fn sweep_unposted_expenses(pool: &PgPool, config: &SweepConfig) -> Result<SweepReport> {
    let mut report = SweepReport::default();

    let exists: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.operating_costs')::text")
            .fetch_one(pool)
            .await?;
    if exists.is_none() {
        report.source_table_missing = true;
        return Ok(report);
    }

    // Non-positive rows can never produce a balanced journal; count them so
    // the deployment sees the gap instead of an endlessly failing sweep.
    report.unpostable = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM operating_costs oc \
         WHERE oc.amount_cents <= 0 \
           AND NOT EXISTS ( \
                SELECT 1 FROM accounting_source_documents d \
                WHERE d.source_type = 'expense' \
                  AND d.source_table = 'operating_costs' \
                  AND d.source_id = oc.id::text)",
    )
    .fetch_one(pool)
    .await? as u64;

    let mut attempted: Vec<Uuid> = Vec::new();
    for _ in 0..config.batch_size.max(1) {
        let mut tx = pool.begin().await?;
        let id: Option<Uuid> = sqlx::query_scalar(CLAIM_EXPENSE_SQL)
            .bind(&attempted)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(id) = id else {
            tx.commit().await?;
            break;
        };
        attempted.push(id);
        report.claimed += 1;

        let legal_entity_id = match crate::chart::default_legal_entity(&mut tx).await {
            Ok(entity) => entity,
            Err(error) => {
                report.failed += 1;
                tracing::warn!(
                    operating_cost_id = %id,
                    error = %error,
                    "expense sweep could not resolve the default legal entity; row left unposted"
                );
                tx.rollback().await?;
                continue;
            }
        };

        match adapters::post_operating_cost_in(&mut tx, legal_entity_id, id).await {
            Ok(outcome) => {
                report.record(outcome.status);
                tx.commit().await?;
            }
            Err(error) => {
                report.failed += 1;
                tracing::warn!(
                    operating_cost_id = %id,
                    error = %error,
                    "expense sweep posting failed; claim rolled back for the next tick"
                );
                tx.rollback().await?;
            }
        }
    }

    Ok(report)
}

// ---------------------------------------------------------------------------
// Bank statement lines
// ---------------------------------------------------------------------------

/// Claim one unposted non-zero bank statement line, oldest first.
///
/// The line's own `journal_entry_id` (migration 220) is the posting marker;
/// non-zero is required because no balanced journal exists for a zero line.
const CLAIM_BANK_SQL: &str = r#"
    SELECT l.id
    FROM bank_statement_lines l
    WHERE l.journal_entry_id IS NULL
      AND l.amount_cents <> 0
      AND NOT (l.id = ANY($1::uuid[]))
    ORDER BY l.statement_date ASC, l.id ASC
    FOR UPDATE OF l SKIP LOCKED
    LIMIT 1
"#;

/// Post every unreconciled, non-zero `bank_statement_lines` row (up to
/// `batch_size` per tick).
///
/// There is no bank feed writer in the repository: this sweep is what makes
/// the bank adapter fire the moment a statement importer (or `psql`) inserts
/// lines. Matching a receipt against a specific invoice remains the separate
/// reconciliation workflow (`bank_reconciliations`); this posts the line's
/// generic ledger effect exactly once.
pub async fn sweep_unposted_bank_statement_lines(
    pool: &PgPool,
    config: &SweepConfig,
) -> Result<SweepReport> {
    let mut report = SweepReport::default();

    report.unpostable = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM bank_statement_lines \
         WHERE journal_entry_id IS NULL AND amount_cents = 0",
    )
    .fetch_one(pool)
    .await? as u64;

    let mut attempted: Vec<Uuid> = Vec::new();
    for _ in 0..config.batch_size.max(1) {
        let mut tx = pool.begin().await?;
        let id: Option<Uuid> = sqlx::query_scalar(CLAIM_BANK_SQL)
            .bind(&attempted)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(id) = id else {
            tx.commit().await?;
            break;
        };
        attempted.push(id);
        report.claimed += 1;

        match adapters::post_bank_statement_line_in(&mut tx, id).await {
            Ok(outcome) => {
                report.record(outcome.status);
                tx.commit().await?;
            }
            Err(error) => {
                report.failed += 1;
                tracing::warn!(
                    bank_statement_line_id = %id,
                    error = %error,
                    "bank sweep posting failed; claim rolled back for the next tick"
                );
                tx.rollback().await?;
            }
        }
    }

    Ok(report)
}

// ---------------------------------------------------------------------------
// Combined entry point
// ---------------------------------------------------------------------------

/// Run all three source sweeps once. A dedicated accounting scheduler does
/// not exist yet: the compliance server's cron is the interim host for the
/// payroll/expense pair (`compliance::ledger_sweep`), while the bank sweep
/// awaits the bank-feed service that will own a statement ledger loop.
pub async fn sweep_all_unposted(
    pool: &PgPool,
    config: &SweepConfig,
    policy: &dyn PayrollAmountsPolicy,
) -> Result<AllSweepsReport> {
    Ok(AllSweepsReport {
        payroll: sweep_unposted_payroll(pool, config, policy).await?,
        expenses: sweep_unposted_expenses(pool, config).await?,
        bank_statement_lines: sweep_unposted_bank_statement_lines(pool, config).await?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The claim statements must lock the claimed row and let a concurrent
    /// sweeper skip it — the SKIP LOCKED discipline is the concurrency
    /// contract, so it is asserted as text (the DB-backed tests exercise the
    /// behaviour).
    #[test]
    fn claim_statements_use_skip_locked_and_a_row_lock() {
        for (name, sql) in [
            ("payroll", CLAIM_PAYROLL_SQL),
            ("expenses", CLAIM_EXPENSE_SQL),
            ("bank", CLAIM_BANK_SQL),
        ] {
            assert!(
                sql.contains("FOR UPDATE OF") && sql.contains("SKIP LOCKED"),
                "{name} claim must take a row lock with SKIP LOCKED"
            );
            assert!(
                sql.contains("NOT (") && sql.contains("ANY($1::uuid[])"),
                "{name} claim must exclude rows already attempted this tick"
            );
            assert!(
                sql.contains("LIMIT 1"),
                "{name} claim processes one row per transaction so the claim and the post commit together"
            );
        }
    }

    /// Payroll amounts are computed by the caller's policy, never defaulted:
    /// a `None` is the explicit "incomplete" answer.
    #[test]
    fn payroll_policy_is_caller_supplied() {
        let policy = |facts: &PayrollRecordFacts| -> Result<Option<PayrollAmounts>> {
            if facts.funded_pension_rate.is_none() && !facts.pension_exemption {
                return Ok(None);
            }
            Ok(Some(PayrollAmounts {
                income_tax_cents: 0,
                social_tax_cents: 0,
                unemployment_employee_cents: 0,
                unemployment_employer_cents: 0,
                pension_cents: 0,
                net_cents: facts.gross_salary_cents,
            }))
        };
        let mut facts = PayrollRecordFacts {
            id: Uuid::nil(),
            employee_name: None,
            gross_salary_cents: 100,
            funded_pension_rate: None,
            pension_exemption: false,
            unemployment_insurance_exemption: false,
            pay_period: chrono::Utc::now(),
        };
        assert!(policy.amounts_for(&facts).expect("policy").is_none());
        facts.pension_exemption = true;
        assert!(policy.amounts_for(&facts).expect("policy").is_some());
    }
}
