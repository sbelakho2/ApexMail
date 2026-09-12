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

use accounting_core::adapters;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

fn log_post_failure(what: &str, source_id: &str, error: &accounting_core::AccountingError) {
    tracing::error!(
        hook = what,
        source_id,
        error = %error,
        "accounting posting failed — billing state is committed; replay the source event once \
         the ledger is configured (posting is idempotent)"
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
    match adapters::post_invoice_issued_in(tx, invoice_id).await {
        Ok(outcome) => log_post_success("invoice_issued", &invoice_id.to_string(), &outcome),
        Err(error) => log_post_failure("invoice_issued", &invoice_id.to_string(), &error),
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
    match adapters::post_payment_allocation_in(tx, operation_id).await {
        Ok(outcome) => log_post_success("payment_allocation", operation_id, &outcome),
        Err(error) => log_post_failure("payment_allocation", operation_id, &error),
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
    match adapters::post_credit_note_in(tx, credit_note_id).await {
        Ok(outcomes) => {
            for outcome in &outcomes {
                log_post_success("credit_note", &credit_note_id.to_string(), outcome);
            }
        }
        Err(error) => log_post_failure("credit_note", &credit_note_id.to_string(), &error),
    }
}
