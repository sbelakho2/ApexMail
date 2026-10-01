//! Accounting hooks for the billing flow (migration 220, `accounting-core`).
//!
//! These functions are called from the exact places where billing already
//! records an economic event, so the statutory ledger is produced as a side
//! effect of the existing flow (no billing rewrite):
//!
//! * invoice finalization → `overage.rs::finalize_collection` and the
//!   Stripe-paid import path in `stripe_webhooks.rs`;
//! * settlement → the `invoice_payment_allocations` writers in
//!   `stripe_webhooks.rs` (Stripe) and `overage.rs` (wallet);
//! * credit notes and refunds → `credit_notes.rs::create_credit_note`.
//!
//! Failure policy: accounting posting is **best effort from the billing
//! flow's perspective**. A billing write must not be rolled back because the
//! ledger is temporarily unconfigured (e.g. no default legal entity/chart
//! yet); the failure is logged at ERROR level with the source identity so
//! the operator can replay it. Replays are idempotent by construction, so
//! re-running the source operation (or a repair job) posts exactly once.
//!
//! # One policy for both failure modes (audit SM7 F4)
//!
//! The in-transaction hooks run inside a SAVEPOINT. A typed adapter failure
//! (`NoOpenPeriod`, `NoDefaultLegalEntity`) never touches the surrounding
//! transaction — but a SQL-level failure (FK violation, CHECK violation)
//! POISONS a Postgres transaction: without the savepoint, the billing
//! `tx.commit()` would fail with an unrelated `Db` error and roll back the
//! wallet mint / credit note. Rolling back to the savepoint heals the
//! transaction, so SQL failures land on exactly the same logged-skip path as
//! typed errors — one deliberate policy, not two contradictory ones. Every
//! skip increments `accounting_postings_skipped_total` (alertable alongside
//! the ERROR log; the billing sweeps in `accounting-core::sweeps` are the
//! replay that catches skipped postings up).

use accounting_core::adapters;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

/// The savepoint name shared by every in-transaction posting hook (audit
/// SM7 F4). Deliberately distinct from the billing-side savepoints
/// (e.g. `invoice_creation` in the PAYG sweep) so nesting stays legible.
const POSTING_SAVEPOINT: &str = "accounting_posting";

/// The three savepoint statements a hook needs, all anchored on the ONE
/// name (pinned by [`savepoint_statements_share_one_name`]).
enum SavepointAction {
    Open,
    Release,
    Rollback,
}

fn posting_savepoint_sql(action: SavepointAction) -> String {
    match action {
        SavepointAction::Open => format!("SAVEPOINT {POSTING_SAVEPOINT}"),
        SavepointAction::Release => format!("RELEASE SAVEPOINT {POSTING_SAVEPOINT}"),
        SavepointAction::Rollback => format!("ROLLBACK TO SAVEPOINT {POSTING_SAVEPOINT}"),
    }
}

/// Open the posting savepoint on the billing transaction.
async fn open_posting_savepoint(tx: &mut PgConnection, hook: &str, source_id: &str) {
    if let Err(error) = sqlx::query(&posting_savepoint_sql(SavepointAction::Open))
        .execute(&mut *tx)
        .await
    {
        tracing::error!(
            hook,
            source_id,
            error = %error,
            "accounting posting: could not open the savepoint — the posting runs unfenced and \
             a SQL failure would abort the billing transaction"
        );
    }
}

/// Release the posting savepoint after a successful adapter call.
async fn release_posting_savepoint(tx: &mut PgConnection, hook: &str, source_id: &str) {
    if let Err(error) = sqlx::query(&posting_savepoint_sql(SavepointAction::Release))
        .execute(&mut *tx)
        .await
    {
        tracing::error!(
            hook,
            source_id,
            error = %error,
            "accounting posting succeeded but the savepoint release failed — the surrounding \
             billing transaction may abort"
        );
    }
}

/// Roll back to the posting savepoint after a failed adapter call: undoes
/// partial adapter writes AND clears the poisoned-transaction state, so the
/// failure can land on the ONE logged-skip policy (audit SM7 F4).
async fn rollback_posting_savepoint(tx: &mut PgConnection, hook: &str, source_id: &str) {
    if let Err(rollback) = sqlx::query(&posting_savepoint_sql(SavepointAction::Rollback))
        .execute(&mut *tx)
        .await
    {
        tracing::error!(
            hook,
            source_id,
            rollback = %rollback,
            "accounting posting failed AND the savepoint rollback failed — the billing \
             transaction will abort; the billing write is NOT silently lost"
        );
    }
}

fn log_post_failure(what: &str, source_id: &str, error: &accounting_core::AccountingError) {
    metrics::counter!("accounting_postings_skipped_total").increment(1);
    tracing::error!(
        hook = what,
        source_id,
        error = %error,
        "accounting posting failed — billing state is committed; replay the source event once \
         the ledger is configured (posting is idempotent; the accounting sweeps replay it \
         automatically)"
    );
}

fn log_post_success(what: &str, source_id: &str, outcome: &accounting_core::PostOutcome) {
    tracing::debug!(
        hook = what,
        source_id,
        status = ?outcome.status,
        entry_id = ?outcome.entry_id,
        "accounting posting completed"
    );
}

/// Invoice finalization on a caller-owned transaction (usage sweep).
pub async fn post_invoice_issued_in(tx: &mut PgConnection, invoice_id: Uuid) {
    let hook = "invoice_issued";
    let source_id = invoice_id.to_string();
    open_posting_savepoint(tx, hook, &source_id).await;
    let posting = adapters::post_invoice_issued_in(&mut *tx, invoice_id).await;
    match posting {
        Ok(outcome) => {
            release_posting_savepoint(tx, hook, &source_id).await;
            log_post_success(hook, &source_id, &outcome);
        }
        Err(error) => {
            // The ONE skip policy for both failure classes (typed and SQL).
            rollback_posting_savepoint(tx, hook, &source_id).await;
            log_post_failure(hook, &source_id, &error);
        }
    }
}

/// Invoice finalization on the pool (Stripe-imported invoice path).
pub async fn post_invoice_issued(db: &PgPool, invoice_id: Uuid) {
    match adapters::post_invoice_issued(db, invoice_id).await {
        Ok(outcome) => log_post_success("invoice_issued", &invoice_id.to_string(), &outcome),
        Err(error) => log_post_failure("invoice_issued", &invoice_id.to_string(), &error),
    }
}

/// Settlement posting on a caller-owned transaction.
pub async fn post_payment_allocation_in(tx: &mut PgConnection, operation_id: &str) {
    let hook = "payment_allocation";
    open_posting_savepoint(tx, hook, operation_id).await;
    let posting = adapters::post_payment_allocation_in(&mut *tx, operation_id).await;
    match posting {
        Ok(outcome) => {
            release_posting_savepoint(tx, hook, operation_id).await;
            log_post_success(hook, operation_id, &outcome);
        }
        Err(error) => {
            rollback_posting_savepoint(tx, hook, operation_id).await;
            log_post_failure(hook, operation_id, &error);
        }
    }
}

/// Settlement posting on the pool (wallet application commits its own tx).
pub async fn post_payment_allocation(db: &PgPool, operation_id: &str) {
    match adapters::post_payment_allocation(db, operation_id).await {
        Ok(outcome) => log_post_success("payment_allocation", operation_id, &outcome),
        Err(error) => log_post_failure("payment_allocation", operation_id, &error),
    }
}

/// Credit-note (debt reduction + refund) posting on a caller-owned tx.
pub async fn post_credit_note_in(tx: &mut PgConnection, credit_note_id: Uuid) {
    let hook = "credit_note";
    let source_id = credit_note_id.to_string();
    open_posting_savepoint(tx, hook, &source_id).await;
    let posting = adapters::post_credit_note_in(&mut *tx, credit_note_id).await;
    match posting {
        Ok(outcomes) => {
            release_posting_savepoint(tx, hook, &source_id).await;
            for outcome in &outcomes {
                log_post_success(hook, &source_id, outcome);
            }
        }
        Err(error) => {
            rollback_posting_savepoint(tx, hook, &source_id).await;
            log_post_failure(hook, &source_id, &error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Audit SM7 F4: all three savepoint statements are anchored on the ONE
    /// name, so the open/rollback pairing can never drift apart across the
    /// hooks.
    #[test]
    fn savepoint_statements_share_one_name() {
        assert_eq!(
            posting_savepoint_sql(SavepointAction::Open),
            "SAVEPOINT accounting_posting"
        );
        assert_eq!(
            posting_savepoint_sql(SavepointAction::Release),
            "RELEASE SAVEPOINT accounting_posting"
        );
        assert_eq!(
            posting_savepoint_sql(SavepointAction::Rollback),
            "ROLLBACK TO SAVEPOINT accounting_posting"
        );
    }

    /// The skip policy is uniform across BOTH failure classes (audit SM7 F4):
    /// the logged-skip path must render a typed error (no ledger configured)
    /// and a SQL-level error (poisoned transaction) identically — neither may
    /// panic, neither may surface to the billing caller, both count as one
    /// skip.
    #[test]
    fn logged_skip_policy_handles_both_failure_classes() {
        crate::test_support::ensure_trace_subscriber();
        let typed = accounting_core::AccountingError::NoOpenPeriod {
            legal_entity_id: Uuid::nil(),
            date: chrono::NaiveDate::from_ymd_opt(2026, 9, 30).expect("date"),
        };
        let sql = accounting_core::AccountingError::Db(sqlx::Error::ColumnNotFound(
            "accounting_source_documents".into(),
        ));
        for error in [typed, sql] {
            let rendered = error.to_string();
            assert!(!rendered.is_empty(), "every skip carries a reason");
            // The counter+log policy (best effort from the billing flow's
            // perspective) is a void call: exercising it pins that BOTH
            // classes flow through it without panicking or special-casing.
            log_post_failure("test_hook", "sm7-f4", &error);
        }
    }
}
