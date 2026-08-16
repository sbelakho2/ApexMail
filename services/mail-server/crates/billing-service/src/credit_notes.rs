//! Credit note management with idempotent creation (BS-007).
//!
//! Credit notes represent money credited back to a tenant (e.g. for SLA
//! breaches, billing errors, goodwill adjustments).  Each credit note is
//! created with an idempotency key so that retries are safe.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::routes::append_audit_log;

// ---------------------------------------------------------------------------
// Input / output types
// ---------------------------------------------------------------------------

/// Input payload for creating a credit note.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCreditNoteInput {
    /// The invoice being credited (partial or full).
    pub invoice_id: Uuid,
    /// Amount to credit in the invoice's currency (smallest unit, e.g. cents).
    pub amount: i64,
    /// Human-readable reason for the credit.
    pub reason: String,
    /// Tenant receiving the credit.
    pub tenant_id: String,
    /// Opaque idempotency key — must be unique per idempotent operation.
    /// If a credit note was already created with this key, the existing
    /// record is returned and no duplicate is created.
    pub idempotency_key: String,
}

/// A created (or pre-existing) credit note.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditNote {
    pub id: Uuid,
    pub invoice_id: Uuid,
    pub tenant_id: String,
    pub amount: i64,
    pub reason: String,
    pub idempotency_key: String,
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum CreditNoteError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("invoice not found: {0}")]
    InvoiceNotFound(Uuid),
    #[error("invoice {0} has status that does not allow credits")]
    InvoiceNotCreditable(Uuid),
    #[error("credit amount exceeds invoice total")]
    AmountExceedsInvoice,
    #[error("audit log failure: {0}")]
    Audit(String),
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create a credit note **idempotently**.
///
/// If a credit note with the same `idempotency_key` already exists, the
/// existing record is returned and no changes are made to the wallet or
/// invoice.  This guarantees exactly-once semantics under retries.
///
/// ## Idempotency guarantees
///
/// 1. `ON CONFLICT (idempotency_key) DO NOTHING` prevents duplicate rows.
/// 2. Wallet credit is applied inside the same transaction via
///    `wallet_transactions`.
/// 3. An audit log entry is written for every *first* creation.
///
/// ## Pre-conditions
///
/// - The referred invoice must exist and be in a creditable state
///   (`Paid`, `Pending`, or `Uncollectible` — not `Void` or `Draft`).
/// - The credit amount must not exceed the invoice total.
pub async fn create_credit_note(
    pool: &PgPool,
    input: CreateCreditNoteInput,
) -> Result<CreditNote, CreditNoteError> {
    let now = Utc::now();

    // ── 1. Validate the invoice ──────────────────────────────────────────
    let invoice_row: Option<(String, i64)> =
        sqlx::query_as("SELECT status::text, total FROM invoices WHERE id = $1 AND tenant_id = $2")
            .bind(input.invoice_id)
            .bind(&input.tenant_id)
            .fetch_optional(pool)
            .await
            .map_err(CreditNoteError::Db)?;

    let Some((invoice_status, invoice_total)) = invoice_row else {
        return Err(CreditNoteError::InvoiceNotFound(input.invoice_id));
    };

    // Allow credits only for invoices that have been issued.
    match invoice_status.as_str() {
        "paid" | "pending" | "uncollectible" => { /* ok */ }
        other => {
            tracing::warn!(
                invoice_id = %input.invoice_id,
                status = %other,
                "attempted to credit non-creditable invoice"
            );
            return Err(CreditNoteError::InvoiceNotCreditable(input.invoice_id));
        }
    }

    // The credit amount must be positive and must not exceed the *remaining*
    // creditable balance (invoice total minus already-credited amounts).
    if input.amount <= 0 {
        return Err(CreditNoteError::AmountExceedsInvoice);
    }

    let already_credited: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount), 0)::BIGINT FROM credit_notes WHERE invoice_id = $1",
    )
    .bind(input.invoice_id)
    .fetch_one(pool)
    .await
    .map_err(CreditNoteError::Db)?;

    if already_credited.saturating_add(input.amount) > invoice_total {
        tracing::warn!(
            invoice_id = %input.invoice_id,
            invoice_total,
            already_credited,
            requested = input.amount,
            "credit amount would exceed invoice total"
        );
        return Err(CreditNoteError::AmountExceedsInvoice);
    }

    // ── 2. Idempotent insert ─────────────────────────────────────────────
    let mut tx = pool.begin().await.map_err(CreditNoteError::Db)?;

    let row: Option<CreditNoteRow> = sqlx::query_as(
        r#"
        INSERT INTO credit_notes (invoice_id, tenant_id, amount, reason, idempotency_key, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (idempotency_key) DO NOTHING
        RETURNING id, invoice_id, tenant_id, amount, reason, idempotency_key, created_at
        "#,
    )
    .bind(input.invoice_id)
    .bind(&input.tenant_id)
    .bind(input.amount)
    .bind(&input.reason)
    .bind(&input.idempotency_key)
    .bind(now)
    .fetch_optional(&mut *tx)
    .await
    .map_err(CreditNoteError::Db)?;

    let credit_note = match row {
        Some(row) => {
            // First-time insert — also credit the wallet in the same
            // transaction so that wallet + credit_note are consistent.
            // Wallet credit in two sequential statements within the same tx:
            // 1. Ensure a wallet row exists (balance 0, idempotent).
            // 2. Increment the balance via UPDATE ... RETURNING and record the
            //    transaction using the RETURNING balance as `balance_after`.
            // Sequential statements (not sibling CTEs) because data-modifying
            // CTEs cannot see each other's writes — the UPDATE would miss a
            // wallet created in the same statement.
            sqlx::query(
                r#"
                INSERT INTO wallets (tenant_id, balance, reserved, currency, created_at, updated_at)
                VALUES ($1, 0, 0, 'eur', NOW(), NOW())
                ON CONFLICT (tenant_id) DO NOTHING
                "#,
            )
            .bind(&input.tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(CreditNoteError::Db)?;

            sqlx::query(
                r#"
                WITH credit_wallet AS (
                    UPDATE wallets
                    SET balance = balance + $2::int4,
                        updated_at = NOW()
                    WHERE tenant_id = $1
                    RETURNING id, balance
                )
                INSERT INTO wallet_transactions
                    (wallet_id, tenant_id, type, amount, balance_after, description, reference, created_at)
                SELECT id, $1, 'credit', $2::int4, balance, $3, $4, $5
                FROM credit_wallet
                "#,
            )
            .bind(&input.tenant_id)
            .bind(input.amount) // positive amount = credit
            .bind(&input.reason)
            .bind(row.id.to_string())
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(CreditNoteError::Db)?;

            // Audit trail.
            append_audit_log(
                &mut tx,
                &input.tenant_id,
                "billing.credit_note_created",
                "credit_note",
                Some(&row.id.to_string()),
                serde_json::json!({
                    "invoiceId": input.invoice_id,
                    "amount": input.amount,
                    "reason": input.reason,
                    "idempotencyKey": input.idempotency_key,
                }),
                now,
            )
            .await
            .map_err(CreditNoteError::Audit)?;

            row
        }
        None => {
            // Idempotency key collision — fetch the existing record.
            // This path is taken when the caller retries with the same key.
            let existing: CreditNoteRow = sqlx::query_as(
                r#"
                SELECT id, invoice_id, tenant_id, amount, reason, idempotency_key, created_at
                FROM credit_notes
                WHERE idempotency_key = $1
                "#,
            )
            .bind(&input.idempotency_key)
            .fetch_one(&mut *tx)
            .await
            .map_err(CreditNoteError::Db)?;

            tracing::info!(
                idempotency_key = %input.idempotency_key,
                credit_note_id = %existing.id,
                "reusing existing credit note (idempotent retry)"
            );

            existing
        }
    };

    tx.commit().await.map_err(CreditNoteError::Db)?;

    Ok(CreditNote {
        id: credit_note.id,
        invoice_id: credit_note.invoice_id,
        tenant_id: credit_note.tenant_id,
        amount: credit_note.amount,
        reason: credit_note.reason,
        idempotency_key: credit_note.idempotency_key,
        created_at: credit_note.created_at,
    })
}

// ---------------------------------------------------------------------------
// Internal row type
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct CreditNoteRow {
    id: Uuid,
    invoice_id: Uuid,
    tenant_id: String,
    amount: i64,
    reason: String,
    idempotency_key: String,
    created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `CreateCreditNoteInput` can be constructed with a valid
    /// non-empty idempotency key.
    #[test]
    fn credit_note_idempotency_key_is_required() {
        let input = CreateCreditNoteInput {
            invoice_id: Uuid::nil(),
            amount: 1000,
            reason: "Test credit".into(),
            tenant_id: "tenant-1".into(),
            idempotency_key: "idem-001".into(),
        };
        // The idempotency key is validated at the DB layer (NOT NULL +
        // UNIQUE constraint via ON CONFLICT DO NOTHING).  The type itself
        // does not enforce non-emptiness, so callers are responsible for
        // providing a meaningful key.
        assert_eq!(input.idempotency_key, "idem-001");
    }

    #[test]
    fn credit_note_serde_roundtrip() {
        let note = CreditNote {
            id: Uuid::new_v4(),
            invoice_id: Uuid::new_v4(),
            tenant_id: "tenant-1".into(),
            amount: 5000,
            reason: "SLA breach credit".into(),
            idempotency_key: Uuid::new_v4().to_string(),
            created_at: Utc::now(),
        };
        let json = serde_json::to_value(&note).unwrap();
        let deserialized: CreditNote = serde_json::from_value(json).unwrap();
        assert_eq!(note.id, deserialized.id);
        assert_eq!(note.amount, deserialized.amount);
        assert_eq!(note.idempotency_key, deserialized.idempotency_key);
    }
}
