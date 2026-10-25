//! Source sweeps: post unposted operational rows that have NO production
//! writer to hook.
//!
//! A previous pass built the accounting adapters and reported honestly that
//! three of them had no production writer:
//!
//! * **payroll**, `payroll_records` (migration 199) is created by no code in
//!   the repository. There is no payroll-run service, admin endpoint or CLI
//!   that inserts a row. The missing piece is the payroll-run FEATURE itself,
//!   not the ledger wiring.
//! * **expenses**, `operating_costs` is deployment-optional and deliberately
//!   not created by migration 220. Nothing in the repository writes it (only
//!   `compliance/src/estonia_ou.rs` reads it, through a table-existence
//!   guard). The missing piece is the expense-entry feature (and the
//!   deployment's provisioning of the store).
//! * **bank**, CLOSED by [`crate::bank_ingest`] (migration 225): statements
//!   are ingested as CSV with a database-enforced identity, and the
//!   compliance cron hosts [`sweep_unposted_bank_statement_lines`] on the
//!   same tick as the payroll/expense sweeps.
//!
//! This module is the smallest honest closure of those gaps: a sweep per
//! source that posts every row that is not yet posted. It needs no product
//! decision, cannot miss a writer (a future service, an admin endpoint, or
//! plain `psql` all insert the same row), and is safe to run repeatedly.
//!
//! # Billing sources (audit SM7 F1)
//!
//! The invoice / payment-allocation / credit-note adapters DO have production
//! writers, the billing flow's live hooks (`billing-service/src/
//! accounting_postings.rs`). But those hooks are best-effort by policy: a
//! posting that failed (unprovisioned ledger, closed period) is logged and
//! the billing write commits without it. Before this pass there was NO replay
//! for them, so a skipped posting stayed skipped forever. The three billing
//! sweeps below mirror the payroll sweep exactly and replay every source row
//! that has no source document yet, a skipped posting catches up within one
//! tick of [`sweep_all_unposted`] (the combined entry point, the host the
//! compliance cron already uses for the payroll/expense/bank sweeps).
//!
//! # Claim protocol, one bounded SKIP LOCKED batch per tick
//!
//! A sweep tick claims up to [`SweepConfig::batch_size`] unposted rows with
//! ONE `FOR UPDATE ... SKIP LOCKED ... LIMIT $1` statement and posts them
//! inside the SAME transaction. Each row is wrapped in a savepoint: a row
//! whose posting fails rolls back only that row's work, and the remaining
//! rows still commit. That is the same failure isolation the previous
//! one-row-per-transaction loop provided, but the claim and the commit are
//! paid once per tick instead of once per row.
//!
//! ```text
//! BEGIN;
//!   SELECT ... FROM <source>
//!    WHERE <not yet posted>
//!    ORDER BY <stable business order>
//!    FOR UPDATE OF <source> SKIP LOCKED
//!    LIMIT <batch_size>;
//!   -- per row:
//!   SAVEPOINT sweep_row;
//!   <adapter>::post_*_in(conn, ...);        -- unique source doc + idempotency key
//!   RELEASE SAVEPOINT sweep_row;            -- or ROLLBACK TO on failure
//! COMMIT;
//! ```
//!
//! Two sweepers can never process the same row: the second's claim skips the
//! rows the first locked. A crash rolls the whole batch back with no
//! stranded claim; every posting is idempotent (unique source document +
//! idempotency key), so the next tick re-posts the batch exactly once. No
//! lease columns are added to the source tables (they belong to other
//! domains, and `operating_costs` may not even exist in a deployment).
//!
//! # Idempotency
//!
//! Each adapter derives its posting from `(source_type, source_table,
//! source_id)` (`accounting_source_documents` UNIQUE) and a stable
//! idempotency key, so replaying a sweep posts nothing new. A batch claims
//! every row at most once (`FOR UPDATE ... LIMIT`), so a poison row cannot
//! be re-claimed inside the same tick and cannot consume the whole batch —
//! its savepoint is rolled back and the next row proceeds.
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
//!   incomplete (`funded_pension_rate IS NULL` without an exemption), the
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
    /// Billing-source replays (audit SM7 F1): postings the live billing hooks
    /// skipped (unprovisioned ledger, transient failure) catch up here.
    pub invoices: SweepReport,
    pub payment_allocations: SweepReport,
    pub credit_notes: SweepReport,
}

impl AllSweepsReport {
    pub fn total_posted(&self) -> u64 {
        self.payroll.posted
            + self.expenses.posted
            + self.bank_statement_lines.posted
            + self.invoices.posted
            + self.payment_allocations.posted
            + self.credit_notes.posted
    }

    /// True when this tick saw no postable work at all, in any source.
    pub fn is_idle(&self) -> bool {
        self.payroll.is_idle()
            && self.expenses.is_idle()
            && self.bank_statement_lines.is_idle()
            && self.invoices.is_idle()
            && self.payment_allocations.is_idle()
            && self.credit_notes.is_idle()
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

/// Claim up to `$1` unposted payroll records, oldest payment period first.
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
    ORDER BY pr.pay_period ASC, pr.id ASC
    FOR UPDATE OF pr SKIP LOCKED
    LIMIT $1
"#;

// ---------------------------------------------------------------------------
// Savepoint plumbing, one failed row must not take the batch down with it.
// ---------------------------------------------------------------------------

/// Savepoint name wrapping one claimed row inside the batch transaction.
async fn savepoint_row(conn: &mut PgConnection) -> Result<()> {
    sqlx::query("SAVEPOINT sweep_row")
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Keep the row's posting in the batch transaction.
async fn release_row(conn: &mut PgConnection) -> Result<()> {
    sqlx::query("RELEASE SAVEPOINT sweep_row")
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Discard only the failed row's posting, leaving earlier rows intact.
async fn rollback_row(conn: &mut PgConnection) -> Result<()> {
    sqlx::query("ROLLBACK TO SAVEPOINT sweep_row")
        .execute(&mut *conn)
        .await?;
    Ok(())
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

    let mut tx = pool.begin().await?;
    let records: Vec<PayrollRecordFacts> = sqlx::query_as(CLAIM_PAYROLL_SQL)
        .bind(config.batch_size.max(1))
        .fetch_all(&mut *tx)
        .await?;

    for facts in &records {
        report.claimed += 1;

        if facts.gross_salary_cents <= 0 {
            // No balanced journal exists for an all-zero payroll; a human must
            // fix the record (or it is a genuine zero-pay month that needs an
            // explicit decision). Reported, never deleted. Nothing was
            // written for this row, so no savepoint is needed.
            report.unpostable += 1;
            continue;
        }

        savepoint_row(&mut tx).await?;

        let legal_entity_id = match crate::provisioning::ensure_default_entity_in(&mut tx).await {
            Ok(id) => id,
            Err(error) => {
                report.failed += 1;
                tracing::warn!(
                    payroll_record_id = %facts.id,
                    error = %error,
                    "payroll sweep could not resolve the default legal entity; row left unposted"
                );
                rollback_row(&mut tx).await?;
                continue;
            }
        };

        let amounts = match policy.amounts_for(facts) {
            Ok(Some(amounts)) => amounts,
            Ok(None) => {
                report.skipped_incomplete += 1;
                tracing::debug!(
                    payroll_record_id = %facts.id,
                    "payroll sweep left an incomplete payroll record unposted; it will post once completed"
                );
                rollback_row(&mut tx).await?;
                continue;
            }
            Err(error) => {
                report.failed += 1;
                tracing::warn!(
                    payroll_record_id = %facts.id,
                    error = %error,
                    "payroll sweep policy failed; row left unposted"
                );
                rollback_row(&mut tx).await?;
                continue;
            }
        };

        match adapters::post_payroll_record_in(&mut tx, legal_entity_id, facts.id, amounts).await {
            Ok(outcome) => {
                report.record(outcome.status);
                release_row(&mut tx).await?;
            }
            Err(error) => {
                report.failed += 1;
                tracing::warn!(
                    payroll_record_id = %facts.id,
                    error = %error,
                    "payroll sweep posting failed; the row stays unposted for the next tick"
                );
                rollback_row(&mut tx).await?;
            }
        }
    }

    tx.commit().await?;
    Ok(report)
}

// ---------------------------------------------------------------------------
// Expenses
// ---------------------------------------------------------------------------

/// Claim up to `$1` unposted `operating_costs` rows, oldest incurred first.
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
    ORDER BY oc.incurred_at ASC, oc.id ASC
    FOR UPDATE OF oc SKIP LOCKED
    LIMIT $1
"#;

/// Post every unposted positive `operating_costs` row (up to `batch_size`).
///
/// `operating_costs` is deployment-optional: when the store is absent the
/// report says `source_table_missing` and the sweep succeeds (nothing to do),
/// so a deployment without an expense feature is not an error. The moment a
/// writer exists, a future expense entry feature, a migration, or `psql` —
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

    let mut tx = pool.begin().await?;
    let ids: Vec<Uuid> = sqlx::query_scalar(CLAIM_EXPENSE_SQL)
        .bind(config.batch_size.max(1))
        .fetch_all(&mut *tx)
        .await?;

    for id in ids {
        savepoint_row(&mut tx).await?;
        report.claimed += 1;

        let legal_entity_id = match crate::provisioning::ensure_default_entity_in(&mut tx).await {
            Ok(entity) => entity,
            Err(error) => {
                report.failed += 1;
                tracing::warn!(
                    operating_cost_id = %id,
                    error = %error,
                    "expense sweep could not resolve the default legal entity; row left unposted"
                );
                rollback_row(&mut tx).await?;
                continue;
            }
        };

        match adapters::post_operating_cost_in(&mut tx, legal_entity_id, id).await {
            Ok(outcome) => {
                report.record(outcome.status);
                release_row(&mut tx).await?;
            }
            Err(error) => {
                report.failed += 1;
                tracing::warn!(
                    operating_cost_id = %id,
                    error = %error,
                    "expense sweep posting failed; the row stays unposted for the next tick"
                );
                rollback_row(&mut tx).await?;
            }
        }
    }

    tx.commit().await?;
    Ok(report)
}

// ---------------------------------------------------------------------------
// Bank statement lines
// ---------------------------------------------------------------------------

/// Claim up to `$1` unposted non-zero bank statement lines, oldest first.
///
/// The line's own `journal_entry_id` (migration 220) is the posting marker;
/// non-zero is required because no balanced journal exists for a zero line.
const CLAIM_BANK_SQL: &str = r#"
    SELECT l.id
    FROM bank_statement_lines l
    WHERE l.journal_entry_id IS NULL
      AND l.amount_cents <> 0
    ORDER BY l.statement_date ASC, l.id ASC
    FOR UPDATE OF l SKIP LOCKED
    LIMIT $1
"#;

/// Post every unreconciled, non-zero `bank_statement_lines` row (up to
/// `batch_size` per tick).
///
/// The writer is [`crate::bank_ingest::ingest_bank_statement`] (statements
/// ingested as CSV, migration 225); the compliance cron hosts this sweep
/// next to the payroll/expense sweeps, so an ingested line reaches the
/// posted ledger within one tick. Matching a receipt against a specific
/// invoice remains the separate reconciliation workflow
/// (`bank_reconciliations`); this posts the line's generic ledger effect
/// exactly once.
pub async fn sweep_unposted_bank_statement_lines(
    pool: &PgPool,
    config: &SweepConfig,
) -> Result<SweepReport> {
    let unpostable_already = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM bank_statement_lines \
         WHERE journal_entry_id IS NULL AND amount_cents = 0",
    )
    .fetch_one(pool)
    .await? as u64;

    let mut report = SweepReport {
        unpostable: unpostable_already,
        ..SweepReport::default()
    };

    let mut tx = pool.begin().await?;
    let ids: Vec<Uuid> = sqlx::query_scalar(CLAIM_BANK_SQL)
        .bind(config.batch_size.max(1))
        .fetch_all(&mut *tx)
        .await?;

    for id in ids {
        savepoint_row(&mut tx).await?;
        report.claimed += 1;

        match adapters::post_bank_statement_line_in(&mut tx, id).await {
            Ok(outcome) => {
                report.record(outcome.status);
                release_row(&mut tx).await?;
            }
            Err(error) => {
                report.failed += 1;
                tracing::warn!(
                    bank_statement_line_id = %id,
                    error = %error,
                    "bank sweep posting failed; the row stays unposted for the next tick"
                );
                rollback_row(&mut tx).await?;
            }
        }
    }

    tx.commit().await?;
    Ok(report)
}

// ---------------------------------------------------------------------------
// Invoices (audit SM7 F1, billing-source replay)
// ---------------------------------------------------------------------------

/// Claim up to `$1` unposted finalized invoices, oldest issued first.
///
/// "Unposted" is `accounting_source_documents` absence for
/// `('invoice', 'invoices', id)`, the adapter registers that document in the
/// same transaction as the entry. Drafts and non-positive invoices are
/// excluded: no journal exists for them (the adapter skips or refuses them),
/// so claiming them would spin the batch.
const CLAIM_INVOICE_SQL: &str = r#"
    SELECT i.id
    FROM invoices i
    WHERE i.status::text <> 'draft'
      AND COALESCE(i.total, i.subtotal + i.vat_total, i.amount, 0) > 0
      AND NOT EXISTS (
            SELECT 1 FROM accounting_source_documents d
            WHERE d.source_type = 'invoice'
              AND d.source_table = 'invoices'
              AND d.source_id = i.id::text
          )
    ORDER BY i.issued_at ASC, i.id ASC
    FOR UPDATE OF i SKIP LOCKED
    LIMIT $1
"#;

/// Replay every finalized, unposted invoice (up to `batch_size` per tick).
///
/// The live writer is the billing flow's best-effort hook; this sweep is what
/// turns the hook's documented "replay the source event once the ledger is
/// configured" policy into an actual replay (audit SM7 F1).
pub async fn sweep_unposted_invoices(pool: &PgPool, config: &SweepConfig) -> Result<SweepReport> {
    let mut report = SweepReport::default();

    let mut tx = pool.begin().await?;
    let ids: Vec<Uuid> = sqlx::query_scalar(CLAIM_INVOICE_SQL)
        .bind(config.batch_size.max(1))
        .fetch_all(&mut *tx)
        .await?;

    for id in ids {
        savepoint_row(&mut tx).await?;
        report.claimed += 1;

        match adapters::post_invoice_issued_in(&mut tx, id).await {
            Ok(outcome) => {
                report.record(outcome.status);
                release_row(&mut tx).await?;
            }
            Err(error) => {
                report.failed += 1;
                tracing::warn!(
                    invoice_id = %id,
                    error = %error,
                    "invoice sweep posting failed; the row stays unposted for the next tick"
                );
                rollback_row(&mut tx).await?;
            }
        }
    }

    tx.commit().await?;
    Ok(report)
}

// ---------------------------------------------------------------------------
// Payment allocations (audit SM7 F1, billing-source replay)
// ---------------------------------------------------------------------------

/// Claim up to `$1` unposted settlement allocations, oldest first. Credit-note
/// allocations are posted by the credit-note adapter (with the invoice's VAT
/// split) and zero amounts have no balanced journal, both excluded.
const CLAIM_PAYMENT_ALLOCATION_SQL: &str = r#"
    SELECT a.id, a.operation_id
    FROM invoice_payment_allocations a
    WHERE a.amount_cents > 0
      AND a.source <> 'credit_note'
      AND NOT EXISTS (
            SELECT 1 FROM accounting_source_documents d
            WHERE d.source_type IN ('mollie_settlement', 'wallet_settlement', 'manual_settlement')
              AND d.source_table = 'invoice_payment_allocations'
              AND d.source_id = a.operation_id
          )
    ORDER BY a.created_at ASC, a.id ASC
    FOR UPDATE OF a SKIP LOCKED
    LIMIT $1
"#;

/// Replay every unposted settlement allocation (up to `batch_size` per tick).
pub async fn sweep_unposted_payment_allocations(
    pool: &PgPool,
    config: &SweepConfig,
) -> Result<SweepReport> {
    let mut report = SweepReport::default();

    let mut tx = pool.begin().await?;
    let rows: Vec<(Uuid, String)> = sqlx::query_as(CLAIM_PAYMENT_ALLOCATION_SQL)
        .bind(config.batch_size.max(1))
        .fetch_all(&mut *tx)
        .await?;

    for (id, operation_id) in rows {
        savepoint_row(&mut tx).await?;
        report.claimed += 1;

        match adapters::post_payment_allocation_in(&mut tx, &operation_id).await {
            Ok(outcome) => {
                report.record(outcome.status);
                release_row(&mut tx).await?;
            }
            Err(error) => {
                report.failed += 1;
                tracing::warn!(
                    allocation_id = %id,
                    operation_id = %operation_id,
                    error = %error,
                    "payment-allocation sweep posting failed; the row stays unposted for the next tick"
                );
                rollback_row(&mut tx).await?;
            }
        }
    }

    tx.commit().await?;
    Ok(report)
}

// ---------------------------------------------------------------------------
// Credit notes (audit SM7 F1, billing-source replay)
// ---------------------------------------------------------------------------

/// Claim up to `$1` credit notes with an unresolved part, oldest first.
///
/// A credit note posts up to TWO entries (debt reduction + refund), each with
/// its own source document. "Fully posted" means every non-zero part carries
/// its document; the claim excludes fully-posted notes so a resolved note is
/// never re-claimed.
const CLAIM_CREDIT_NOTE_SQL: &str = r#"
    SELECT c.id
    FROM credit_notes c
    WHERE NOT (
            (
                COALESCE(c.debt_reduction_cents, c.amount) <= 0
                OR EXISTS (
                    SELECT 1 FROM accounting_source_documents d
                    WHERE d.source_type = 'credit_note'
                      AND d.source_table = 'credit_notes'
                      AND d.source_id = c.id::text
                )
            )
            AND (
                COALESCE(c.refunded_cents, 0) <= 0
                OR EXISTS (
                    SELECT 1 FROM accounting_source_documents d
                    WHERE d.source_type = 'credit_note_refund'
                      AND d.source_table = 'credit_notes'
                      AND d.source_id = c.id::text
                )
            )
          )
    ORDER BY c.created_at ASC, c.id ASC
    FOR UPDATE OF c SKIP LOCKED
    LIMIT $1
"#;

/// Replay every credit note with an unposted part (up to `batch_size` per
/// tick). Idempotent per part, so a partially-posted note catches up exactly.
pub async fn sweep_unposted_credit_notes(
    pool: &PgPool,
    config: &SweepConfig,
) -> Result<SweepReport> {
    let mut report = SweepReport::default();

    let mut tx = pool.begin().await?;
    let ids: Vec<Uuid> = sqlx::query_scalar(CLAIM_CREDIT_NOTE_SQL)
        .bind(config.batch_size.max(1))
        .fetch_all(&mut *tx)
        .await?;

    for id in ids {
        savepoint_row(&mut tx).await?;
        report.claimed += 1;

        match adapters::post_credit_note_in(&mut tx, id).await {
            Ok(outcomes) => {
                for outcome in outcomes {
                    report.record(outcome.status);
                }
                release_row(&mut tx).await?;
            }
            Err(error) => {
                report.failed += 1;
                tracing::warn!(
                    credit_note_id = %id,
                    error = %error,
                    "credit-note sweep posting failed; the row stays unposted for the next tick"
                );
                rollback_row(&mut tx).await?;
            }
        }
    }

    tx.commit().await?;
    Ok(report)
}

// ---------------------------------------------------------------------------
// Combined entry point
// ---------------------------------------------------------------------------

/// Run all source sweeps once: the payroll/expense/bank sweeps plus the
/// billing-source replays (invoices, payment allocations, credit notes —
/// audit SM7 F1). A dedicated accounting scheduler does not exist: the
/// compliance server's cron hosts the sweeps
/// (`compliance::ledger_sweep::sweep_ledger_sources`), including the bank
/// statement sweep fed by [`crate::bank_ingest`].
pub async fn sweep_all_unposted(
    pool: &PgPool,
    config: &SweepConfig,
    policy: &dyn PayrollAmountsPolicy,
) -> Result<AllSweepsReport> {
    Ok(AllSweepsReport {
        payroll: sweep_unposted_payroll(pool, config, policy).await?,
        expenses: sweep_unposted_expenses(pool, config).await?,
        bank_statement_lines: sweep_unposted_bank_statement_lines(pool, config).await?,
        invoices: sweep_unposted_invoices(pool, config).await?,
        payment_allocations: sweep_unposted_payment_allocations(pool, config).await?,
        credit_notes: sweep_unposted_credit_notes(pool, config).await?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The claim statements must lock the claimed rows and let a concurrent
    /// sweeper skip them, the SKIP LOCKED discipline is the concurrency
    /// contract, so it is asserted as text (the DB-backed tests exercise the
    /// behaviour). Each claim is ONE bounded batch: `LIMIT $1` (the tick's
    /// batch size) replaces the previous per-row `LIMIT 1` loop, and a
    /// stable `ORDER BY` keeps the batch deterministic across ticks.
    #[test]
    fn claim_statements_use_skip_locked_and_a_bounded_batch() {
        for (name, sql) in [
            ("payroll", CLAIM_PAYROLL_SQL),
            ("expenses", CLAIM_EXPENSE_SQL),
            ("bank", CLAIM_BANK_SQL),
            ("invoices", CLAIM_INVOICE_SQL),
            ("payment_allocations", CLAIM_PAYMENT_ALLOCATION_SQL),
            ("credit_notes", CLAIM_CREDIT_NOTE_SQL),
        ] {
            assert!(
                sql.contains("FOR UPDATE OF") && sql.contains("SKIP LOCKED"),
                "{name} claim must take a row lock with SKIP LOCKED"
            );
            assert!(
                sql.contains("LIMIT $1"),
                "{name} claim must be ONE bounded batch (LIMIT $1), not a per-row LIMIT 1 loop"
            );
            assert!(
                sql.contains("ORDER BY"),
                "{name} claim must order by its stable business key"
            );
        }
    }

    /// Audit SM7 F1, the billing sweeps select EXACTLY the rows the adapters
    /// would post: unposted per the source-document marker, and never rows the
    /// adapter refuses/skips (draft or zero invoices, credit-note-source
    /// allocations, fully-posted credit notes), so one claim always makes
    /// progress and no row spins the batch.
    #[test]
    fn billing_claims_select_unpostable_and_already_posted_rows_out() {
        // Invoices: drafts and non-positive totals are never claimable.
        assert!(
            CLAIM_INVOICE_SQL.contains("status::text <> 'draft'"),
            "draft invoices must not be claimed, the adapter refuses them"
        );
        assert!(
            CLAIM_INVOICE_SQL
                .contains("COALESCE(i.total, i.subtotal + i.vat_total, i.amount, 0) > 0"),
            "non-positive invoices must not be claimed, the adapter skips them"
        );
        assert!(
            CLAIM_INVOICE_SQL.contains("d.source_type = 'invoice'")
                && CLAIM_INVOICE_SQL.contains("d.source_table = 'invoices'"),
            "the posting marker is the (invoice, invoices, id) source document"
        );

        // Payment allocations: credit-note allocations are the credit-note
        // adapter's job; zero amounts have no balanced journal.
        assert!(
            CLAIM_PAYMENT_ALLOCATION_SQL.contains("a.source <> 'credit_note'")
                && CLAIM_PAYMENT_ALLOCATION_SQL.contains("a.amount_cents > 0"),
            "credit-note-source and zero allocations must not be claimed"
        );
        assert!(
            CLAIM_PAYMENT_ALLOCATION_SQL
                .contains("'mollie_settlement', 'wallet_settlement', 'manual_settlement'"),
            "the marker check must cover every settlement source_type the adapter registers"
        );

        // Credit notes: fully-posted notes (every non-zero part carrying its
        // document) are excluded so a resolved note is never re-claimed.
        assert!(
            CLAIM_CREDIT_NOTE_SQL.contains("'credit_note'")
                && CLAIM_CREDIT_NOTE_SQL.contains("'credit_note_refund'"),
            "both posting parts' documents mark the note resolved"
        );
        assert!(
            CLAIM_CREDIT_NOTE_SQL.contains("COALESCE(c.debt_reduction_cents, c.amount) <= 0")
                && CLAIM_CREDIT_NOTE_SQL.contains("COALESCE(c.refunded_cents, 0) <= 0"),
            "zero parts never block resolution, a refund-only or debt-only note resolves"
        );
    }

    /// The combined report sums every source, including the SM7 F1 billing
    /// replays.
    #[test]
    fn all_sweeps_report_totals_every_source() {
        let mut report = AllSweepsReport::default();
        report.payroll.posted = 1;
        report.payroll.claimed = 1;
        report.expenses.posted = 2;
        report.expenses.claimed = 2;
        report.bank_statement_lines.posted = 3;
        report.bank_statement_lines.claimed = 3;
        report.invoices.posted = 4;
        report.invoices.claimed = 4;
        report.payment_allocations.posted = 5;
        report.payment_allocations.claimed = 5;
        report.credit_notes.posted = 6;
        report.credit_notes.claimed = 6;
        assert_eq!(report.total_posted(), 21);
        assert!(!report.is_idle());
        // Nothing claimed anywhere: idle.
        assert!(AllSweepsReport::default().is_idle());
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

#[cfg(test)]
mod batch_db_tests {
    //! DB-backed proof of the batched claim protocol:
    //!
    //! * a successful tick posts every claimed row in ONE transaction (the
    //!   pre-fix loop committed one row per transaction, the statement-level
    //!   probe below records one `txid_current()` per row there, one for the
    //!   whole batch here);
    //! * a poison row still rolls back alone (savepoint isolation) and the
    //!   rest of the batch commits;
    //! * a tick claims at most `batch_size` rows and the next tick continues
    //!   where it stopped.
    //!
    //! Gated on `TEST_DATABASE_URL` (workspace convention); a configured
    //! provisioning failure panics.

    use super::*;
    use chrono::{DateTime, Utc};
    use sqlx::PgPool;

    async fn provision(name: &str) -> Option<PgPool> {
        match migrator::test_support::fresh_canonical_pool(name, &format!("acct_sweeps_{name}"))
            .await
        {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        }
    }

    fn pay_period() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-06-30T12:00:00Z")
            .expect("timestamp")
            .with_timezone(&Utc)
    }

    async fn insert_payroll(pool: &PgPool, name: &str, code: &str, gross: i64) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO payroll_records (employee_name, personal_code, gross_salary_cents, \
                funded_pension_rate, pay_period) \
             VALUES ($1, $2, $3, 0.02, $4) RETURNING id",
        )
        .bind(name)
        .bind(code)
        .bind(gross)
        .bind(pay_period())
        .fetch_one(pool)
        .await
        .expect("payroll record")
    }

    /// Exactly-balanced amounts for a gross salary (the adapter validates the
    /// identity, so the policy is deterministic).
    fn valid_amounts(gross: i64) -> PayrollAmounts {
        let income_tax_cents = gross / 10;
        let unemployment_employee_cents = gross / 100;
        let pension_cents = gross / 50;
        let net_cents = gross - income_tax_cents - unemployment_employee_cents - pension_cents;
        PayrollAmounts {
            income_tax_cents,
            social_tax_cents: gross / 3,
            unemployment_employee_cents,
            unemployment_employer_cents: gross / 125,
            pension_cents,
            net_cents,
        }
    }

    async fn install_tx_probe(pool: &PgPool) {
        sqlx::raw_sql(
            r#"
            CREATE TABLE sweep_tx_probe (
                entry_id UUID NOT NULL,
                tx       BIGINT NOT NULL
            );
            CREATE OR REPLACE FUNCTION sweep_tx_probe_fn() RETURNS trigger
            LANGUAGE plpgsql AS $$
            BEGIN
                INSERT INTO sweep_tx_probe (entry_id, tx) VALUES (NEW.id, txid_current());
                RETURN NEW;
            END
            $$;
            CREATE TRIGGER sweep_tx_probe_after_insert
                AFTER INSERT ON journal_entries
                FOR EACH ROW EXECUTE FUNCTION sweep_tx_probe_fn();
            "#,
        )
        .execute(pool)
        .await
        .expect("tx probe trigger");
    }

    /// One tick == one transaction for every successfully posted row.
    #[tokio::test]
    async fn payroll_sweep_posts_the_claimed_batch_in_one_transaction() {
        let Some(pool) = provision("batch_tx").await else {
            return;
        };
        install_tx_probe(&pool).await;
        for index in 0..3 {
            insert_payroll(
                &pool,
                &format!("Batch Employee {index}"),
                &format!("BATCH-{index}"),
                100_000 + index * 10_000,
            )
            .await;
        }

        let config = SweepConfig { batch_size: 10 };
        let report = sweep_unposted_payroll(&pool, &config, &|facts: &PayrollRecordFacts| {
            Ok(Some(valid_amounts(facts.gross_salary_cents)))
        })
        .await
        .expect("payroll sweep");

        assert_eq!(report.claimed, 3, "{report:?}");
        assert_eq!(report.posted, 3, "{report:?}");
        assert_eq!(report.failed, 0, "{report:?}");

        let distinct_transactions: i64 =
            sqlx::query_scalar("SELECT COUNT(DISTINCT tx)::bigint FROM sweep_tx_probe")
                .fetch_one(&pool)
                .await
                .expect("probe tx count");
        assert_eq!(
            distinct_transactions, 1,
            "all three postings must commit in the SAME transaction \
             (the pre-fix implementation committed one row per transaction)"
        );
        let entries: i64 = sqlx::query_scalar("SELECT COUNT(*)::bigint FROM sweep_tx_probe")
            .fetch_one(&pool)
            .await
            .expect("probe entry count");
        assert_eq!(entries, 3);

        pool.close().await;
    }

    /// A poison row rolls back alone; the rest of its batch still commits.
    #[tokio::test]
    async fn one_failing_row_does_not_roll_back_the_batch() {
        let Some(pool) = provision("batch_poison").await else {
            return;
        };
        insert_payroll(&pool, "Poison A", "POISON-A", 100_000).await;
        insert_payroll(&pool, "Poison B", "POISON-B", 100_000).await;
        insert_payroll(&pool, "Poison C", "POISON-C", 100_000).await;

        let config = SweepConfig { batch_size: 10 };
        let report = sweep_unposted_payroll(&pool, &config, &|facts: &PayrollRecordFacts| {
            if facts.employee_name.as_deref() == Some("Poison B") {
                Err(crate::error::AccountingError::Invalid(
                    "policy exploded".to_string(),
                ))
            } else {
                Ok(Some(valid_amounts(facts.gross_salary_cents)))
            }
        })
        .await
        .expect("payroll sweep");

        assert_eq!(report.claimed, 3, "{report:?}");
        assert_eq!(report.posted, 2, "{report:?}");
        assert_eq!(report.failed, 1, "{report:?}");

        let entries: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM journal_entries WHERE idempotency_key LIKE 'payroll:%'",
        )
        .fetch_one(&pool)
        .await
        .expect("posted entries");
        assert_eq!(entries, 2, "the two healthy rows committed");

        // The poison row is still unposted and is retried next tick.
        let retried =
            sweep_unposted_payroll(&pool, &config, &|_facts: &PayrollRecordFacts| Ok(None))
                .await
                .expect("retry sweep");
        assert_eq!(retried.claimed, 1, "{retried:?}");
        assert_eq!(retried.skipped_incomplete, 1, "{retried:?}");

        pool.close().await;
    }

    /// A tick is bounded by `batch_size`; the next tick continues with the
    /// next-oldest rows.
    #[tokio::test]
    async fn a_tick_claims_at_most_batch_size_rows() {
        let Some(pool) = provision("batch_bound").await else {
            return;
        };
        for index in 0..5 {
            insert_payroll(
                &pool,
                &format!("Bounded {index}"),
                &format!("BOUNDED-{index}"),
                100_000,
            )
            .await;
        }

        let mut total = 0u64;
        let config = SweepConfig { batch_size: 2 };
        for expected_claimed in [2, 2, 1] {
            let report = sweep_unposted_payroll(&pool, &config, &|facts: &PayrollRecordFacts| {
                Ok(Some(valid_amounts(facts.gross_salary_cents)))
            })
            .await
            .expect("payroll sweep");
            assert_eq!(report.claimed, expected_claimed, "{report:?}");
            assert_eq!(report.posted, expected_claimed, "{report:?}");
            total += report.posted;
        }
        assert_eq!(total, 5, "every row posts exactly once across the ticks");

        pool.close().await;
    }
}
