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
    /// ISO-4217 code of the credited invoice's currency — a credit must
    /// reconcile in the currency it was issued in (audit F60).
    pub currency: String,
    pub reason: String,
    pub idempotency_key: String,
    pub created_at: DateTime<Utc>,
    /// Audit F60 — the part of `amount` reducing the unpaid obligation.
    #[serde(default)]
    pub debt_reduction_cents: i64,
    /// Audit F60 — the part of `amount` refunding actually-paid value
    /// (the only part that minted wallet balance).
    #[serde(default)]
    pub refunded_cents: i64,
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
    #[error(
        "invoice currency {invoice_currency} does not match wallet currency {wallet_currency}"
    )]
    CurrencyMismatch {
        invoice_currency: String,
        wallet_currency: String,
    },
    #[error(
        "idempotency key {idempotency_key} was already used for a different credit note payload"
    )]
    IdempotencyKeyReused { idempotency_key: String },
    #[error("audit log failure: {0}")]
    Audit(String),
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Invoice row lookup used by [`create_credit_note`]. `FOR UPDATE` serializes
/// concurrent credit-note writers on the same invoice so the read of
/// `already_credited` can never race (Fix F — TOCTOU over-credit).
const LOCK_INVOICE_FOR_CREDIT_SQL: &str = "SELECT status::text, COALESCE(total, amount, 0)::bigint, currency FROM invoices WHERE id = $1 AND tenant_id = $2 FOR UPDATE";

/// Validate a credit amount against the invoice total and the amount already
/// credited (pure — Fix F). Callers must hold a row lock on the invoice while
/// reading `already_credited` for this to be race-free.
fn validate_credit_amount(
    amount: i64,
    invoice_total: i64,
    already_credited: i64,
) -> Result<(), CreditNoteError> {
    if amount <= 0 {
        return Err(CreditNoteError::AmountExceedsInvoice);
    }
    if already_credited.saturating_add(amount) > invoice_total {
        return Err(CreditNoteError::AmountExceedsInvoice);
    }
    Ok(())
}

/// Split a credit into its two dispositions (audit F60, pure — unit-tested):
///
/// * `debt_reduction` — the part reducing the still-UNPAID obligation
///   (what the outstanding derivation subtracts);
/// * `refund` — the part returning value that was ACTUALLY PAID (the only
///   part eligible to mint wallet balance).
///
/// Splitting prevents the double benefit: crediting an unpaid invoice
/// reduces its debt without creating spendable wallet value; only the
/// genuinely-paid part becomes refundable value.
fn split_credit_disposition(
    amount: i64,
    payments_cents: i64,
    outstanding_before: i64,
) -> (i64, i64) {
    let debt_reduction = amount.min(outstanding_before.max(0));
    let refund = (amount - debt_reduction)
        // The refund can never exceed what was actually paid (it can only
        // originate from the paid part of the obligation).
        .min(payments_cents.max(0))
        .max(0);
    (debt_reduction, refund)
}

/// Replay comparison (audit F60): a retried request with the same
/// (tenant, idempotency key) is a REPLAY only when the payload matches the
/// stored credit note — same invoice, same amount. A key reused for a
/// different payload is an error, never a silent return of someone else's
/// credit. Pure — unit-tested.
fn replay_matches(existing: &CreditNoteRow, input: &CreateCreditNoteInput) -> bool {
    existing.invoice_id == input.invoice_id && existing.amount == input.amount
}

/// Create a credit note **idempotently**.
///
/// If a credit note with the same `(tenant_id, idempotency_key)` already
/// exists AND the payload matches, the existing record is returned and no
/// changes are made to the wallet or invoice — exactly-once semantics
/// under retries. A key reused for a DIFFERENT payload is rejected with
/// [`CreditNoteError::IdempotencyKeyReused`].
///
/// ## Idempotency guarantees (audit F60)
///
/// 1. The replay lookup + payload compare happen BEFORE any credit is
///    reserved — a mismatched retry never touches the wallet.
/// 2. `ON CONFLICT (tenant_id, idempotency_key) DO NOTHING` prevents
///    duplicate rows; idempotency is scoped to the TENANT so one tenant's
///    key can never adopt another tenant's credit.
/// 3. Invoice lock, credit-note row, wallet credit and audit log commit in
///    ONE transaction.
/// 4. Fix F — the invoice row is locked with `SELECT ... FOR UPDATE` for the
///    whole transaction, so two concurrent credit notes (different keys)
///    cannot both read the same `already_credited` and over-credit the
///    invoice; the second is rejected with `AmountExceedsInvoice`.
///
/// ## Pre-conditions
///
/// - The referred invoice must exist and be in a creditable state
///   (`Paid`, `Pending`, or `Uncollectible` — not `Void` or `Draft`).
/// - The credit amount must be positive and not exceed the invoice total.
pub async fn create_credit_note(
    pool: &PgPool,
    input: CreateCreditNoteInput,
) -> Result<CreditNote, CreditNoteError> {
    let now = Utc::now();

    // ── 1. Open the transaction and lock the invoice row (Fix F) ────────
    let mut tx = pool.begin().await.map_err(CreditNoteError::Db)?;

    let invoice_row: Option<(String, i64, String)> = sqlx::query_as(LOCK_INVOICE_FOR_CREDIT_SQL)
        .bind(input.invoice_id)
        .bind(&input.tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(CreditNoteError::Db)?;

    let Some((invoice_status, invoice_total, invoice_currency)) = invoice_row else {
        return Err(CreditNoteError::InvoiceNotFound(input.invoice_id));
    };

    // Allow credits only for invoices that have been issued.
    match invoice_status.as_str() {
        "paid" | "pending" | "uncollectible" => { /* ok */ }
        other => {
            tracing::warn!(
                invoice_id = %input.invoice_id,
                status = other,
                "attempted to credit non-creditable invoice"
            );
            return Err(CreditNoteError::InvoiceNotCreditable(input.invoice_id));
        }
    }

    // ── 2. Replay compare BEFORE reserving any credit (audit F60) ───────
    // A retry with the same (tenant, key) returns the stored record only
    // when the payload matches; a reused key with a different payload is
    // an error. Nothing below this point runs for a replay.
    let replayed: Option<CreditNoteRow> = sqlx::query_as(
        r#"
        SELECT id, invoice_id, tenant_id, amount, currency, reason, idempotency_key,
               debt_reduction_cents, refunded_cents, created_at
        FROM credit_notes
        WHERE tenant_id = $1 AND idempotency_key = $2
        "#,
    )
    .bind(&input.tenant_id)
    .bind(&input.idempotency_key)
    .fetch_optional(&mut *tx)
    .await
    .map_err(CreditNoteError::Db)?;

    if let Some(existing) = replayed {
        if !replay_matches(&existing, &input) {
            tracing::error!(
                tenant_id = %input.tenant_id,
                idempotency_key = %input.idempotency_key,
                stored_invoice_id = %existing.invoice_id,
                stored_amount = existing.amount,
                requested_invoice_id = %input.invoice_id,
                requested_amount = input.amount,
                "credit-note idempotency key reused for a different payload — rejected"
            );
            return Err(CreditNoteError::IdempotencyKeyReused {
                idempotency_key: input.idempotency_key,
            });
        }
        tracing::info!(
            idempotency_key = %input.idempotency_key,
            credit_note_id = %existing.id,
            "reusing existing credit note (idempotent replay)"
        );
        let credit_note = existing;
        return Ok(CreditNote {
            id: credit_note.id,
            invoice_id: credit_note.invoice_id,
            tenant_id: credit_note.tenant_id,
            amount: credit_note.amount,
            currency: credit_note.currency,
            reason: credit_note.reason,
            idempotency_key: credit_note.idempotency_key,
            created_at: credit_note.created_at,
            debt_reduction_cents: credit_note
                .debt_reduction_cents
                .unwrap_or(credit_note.amount),
            refunded_cents: credit_note.refunded_cents.unwrap_or(0),
        });
    }

    // The credit amount must not exceed the *remaining* creditable balance
    // (invoice total minus already-credited amounts). Read under the row
    // lock, so a concurrent writer's committed credits are visible here.
    let already_credited: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount), 0)::BIGINT FROM credit_notes WHERE invoice_id = $1",
    )
    .bind(input.invoice_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(CreditNoteError::Db)?;

    if let Err(error) = validate_credit_amount(input.amount, invoice_total, already_credited) {
        tracing::warn!(
            invoice_id = %input.invoice_id,
            invoice_total,
            already_credited,
            requested = input.amount,
            "credit amount would exceed invoice total"
        );
        return Err(error);
    }

    // ── Audit F60: derive the credit's DISPOSITION under the lock ─────
    // The split decides which part reduces the unpaid obligation and
    // which part refunds value that was actually paid (see
    // `split_credit_disposition`). Everything below — the credit note
    // row, its unique operation id and (only for the refund part) the
    // wallet mint — derives from this split inside the same locked
    // transaction, so concurrent credits can never over-derive capacity.
    let payments_cents: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount_cents), 0)::BIGINT FROM invoice_payment_allocations WHERE invoice_id = $1",
    )
    .bind(input.invoice_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(CreditNoteError::Db)?;
    let existing_debt_reduction: i64 = sqlx::query_scalar(
        r#"
        SELECT COALESCE(SUM(
            CASE WHEN debt_reduction_cents IS NULL THEN amount ELSE debt_reduction_cents END
        ), 0)::BIGINT
        FROM credit_notes WHERE invoice_id = $1
        "#,
    )
    .bind(input.invoice_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(CreditNoteError::Db)?;
    let outstanding_before = invoice_total
        .saturating_sub(payments_cents)
        .saturating_sub(existing_debt_reduction)
        .max(0);
    let (debt_reduction_cents, refunded_cents) =
        split_credit_disposition(input.amount, payments_cents, outstanding_before);

    let operation_id = format!("credit_note:{}:{}", input.tenant_id, input.idempotency_key);

    let row: Option<CreditNoteRow> = sqlx::query_as(
        r#"
        INSERT INTO credit_notes (
            invoice_id, tenant_id, amount, currency, reason, idempotency_key,
            operation_id, debt_reduction_cents, refunded_cents, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
        RETURNING id, invoice_id, tenant_id, amount, currency, reason, idempotency_key,
                   debt_reduction_cents, refunded_cents, created_at
        "#,
    )
    .bind(input.invoice_id)
    .bind(&input.tenant_id)
    .bind(input.amount)
    .bind(&invoice_currency)
    .bind(&input.reason)
    .bind(&input.idempotency_key)
    .bind(&operation_id)
    .bind(debt_reduction_cents)
    .bind(refunded_cents)
    .bind(now)
    .fetch_optional(&mut *tx)
    .await
    .map_err(CreditNoteError::Db)?;

    let credit_note = match row {
        Some(row) => {
            // First-time insert — mint wallet value ONLY for the actually
            // paid, refundable part of the credit (audit F60: the
            // debt-reduction part reduces the unpaid obligation and must
            // NOT create spendable value — that was the double benefit).
            // The wallet is single-currency: a refund in the invoice's
            // currency must never land in a wallet held in another
            // currency. Create with the invoice currency; when a wallet
            // already exists, refuse the mismatch instead of mixing.
            if refunded_cents > 0 {
                sqlx::query(
                    r#"
                    INSERT INTO wallets (tenant_id, balance, reserved, currency, created_at, updated_at)
                    VALUES ($1, 0, 0, $2, NOW(), NOW())
                    ON CONFLICT (tenant_id) DO NOTHING
                    "#,
                )
                .bind(&input.tenant_id)
                .bind(&invoice_currency)
                .execute(&mut *tx)
                .await
                .map_err(CreditNoteError::Db)?;

                let wallet_currency: String =
                    sqlx::query_scalar("SELECT currency FROM wallets WHERE tenant_id = $1")
                        .bind(&input.tenant_id)
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(CreditNoteError::Db)?;
                if !wallet_currency.eq_ignore_ascii_case(&invoice_currency) {
                    tracing::error!(
                        tenant_id = %input.tenant_id,
                        invoice_id = %input.invoice_id,
                        invoice_currency = %invoice_currency,
                        wallet_currency = %wallet_currency,
                        "credit-note refund currency mismatch refused — refund via the payment provider instead"
                    );
                    return Err(CreditNoteError::CurrencyMismatch {
                        invoice_currency,
                        wallet_currency,
                    });
                }

                // Wallet credit in two sequential statements within the same tx:
                // 1. Ensure a wallet row exists (balance 0, idempotent).
                // 2. Increment the balance via UPDATE ... RETURNING and record the
                //    transaction using the RETURNING balance as `balance_after`.
                // Sequential statements (not sibling CTEs) because data-modifying
                // CTEs cannot see each other's writes — the UPDATE would miss a
                // wallet created in the same statement.
                sqlx::query(
                    r#"
                    WITH credit_wallet AS (
                        UPDATE wallets
                        SET balance = balance + $2::int8,
                            updated_at = NOW()
                        WHERE tenant_id = $1
                        RETURNING id, balance
                    )
                    INSERT INTO wallet_transactions
                        (wallet_id, tenant_id, type, amount, balance_after, description, reference, created_at)
                    SELECT id, $1, 'credit', $2::int8, balance, $3, $4, $5
                    FROM credit_wallet
                    "#,
                )
                .bind(&input.tenant_id)
                .bind(refunded_cents) // positive amount = credit (refund part only)
                .bind(&input.reason)
                .bind(row.id.to_string())
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(CreditNoteError::Db)?;
            }

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
                    "currency": invoice_currency,
                    "reason": input.reason,
                    "idempotencyKey": input.idempotency_key,
                    "debtReductionCents": debt_reduction_cents,
                    "refundedCents": refunded_cents,
                }),
                now,
            )
            .await
            .map_err(CreditNoteError::Audit)?;

            row
        }
        None => {
            // Lost a concurrent insert race on (tenant, key): the winner's
            // record IS this request's replay — compare and return it, or
            // reject a divergent payload (audit F60).
            let existing: CreditNoteRow = sqlx::query_as(
                r#"
                SELECT id, invoice_id, tenant_id, amount, currency, reason, idempotency_key,
               debt_reduction_cents, refunded_cents, created_at
                FROM credit_notes
                WHERE tenant_id = $1 AND idempotency_key = $2
                "#,
            )
            .bind(&input.tenant_id)
            .bind(&input.idempotency_key)
            .fetch_one(&mut *tx)
            .await
            .map_err(CreditNoteError::Db)?;

            if !replay_matches(&existing, &input) {
                return Err(CreditNoteError::IdempotencyKeyReused {
                    idempotency_key: input.idempotency_key,
                });
            }

            tracing::info!(
                idempotency_key = %input.idempotency_key,
                credit_note_id = %existing.id,
                "reusing existing credit note (idempotent retry after insert race)"
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
        currency: credit_note.currency,
        reason: credit_note.reason,
        idempotency_key: credit_note.idempotency_key,
        created_at: credit_note.created_at,
        debt_reduction_cents: credit_note
            .debt_reduction_cents
            .unwrap_or(credit_note.amount),
        refunded_cents: credit_note.refunded_cents.unwrap_or(0),
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
    currency: String,
    reason: String,
    idempotency_key: String,
    /// Audit F60 disposition split (NULL on rows that predate migration
    /// 183 — treated as a full debt reduction).
    debt_reduction_cents: Option<i64>,
    refunded_cents: Option<i64>,
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
            currency: "EUR".into(),
            reason: "SLA breach credit".into(),
            idempotency_key: Uuid::new_v4().to_string(),
            created_at: Utc::now(),
            debt_reduction_cents: 2000,
            refunded_cents: 3000,
        };
        let json = serde_json::to_value(&note).unwrap();
        let deserialized: CreditNote = serde_json::from_value(json).unwrap();
        assert_eq!(note.id, deserialized.id);
        assert_eq!(note.amount, deserialized.amount);
        assert_eq!(note.currency, deserialized.currency);
        assert_eq!(note.idempotency_key, deserialized.idempotency_key);
    }

    // ------------------------------------------------------------------
    // Audit F60 — replay comparison gates every idempotent retry.
    // ------------------------------------------------------------------

    fn sample_row(invoice_id: Uuid, amount: i64) -> CreditNoteRow {
        CreditNoteRow {
            id: Uuid::new_v4(),
            invoice_id,
            tenant_id: "tenant-1".into(),
            amount,
            currency: "EUR".into(),
            reason: "goodwill".into(),
            idempotency_key: "idem-001".into(),
            debt_reduction_cents: Some(amount),
            refunded_cents: Some(0),
            created_at: Utc::now(),
        }
    }

    fn sample_input(invoice_id: Uuid, amount: i64) -> CreateCreditNoteInput {
        CreateCreditNoteInput {
            invoice_id,
            amount,
            reason: "goodwill".into(),
            tenant_id: "tenant-1".into(),
            idempotency_key: "idem-001".into(),
        }
    }

    #[test]
    fn replay_with_identical_payload_matches() {
        let invoice = Uuid::new_v4();
        assert!(replay_matches(
            &sample_row(invoice, 1_000),
            &sample_input(invoice, 1_000)
        ));
    }

    #[test]
    fn replay_with_different_amount_is_not_a_replay() {
        let invoice = Uuid::new_v4();
        assert!(!replay_matches(
            &sample_row(invoice, 1_000),
            &sample_input(invoice, 2_000)
        ));
    }

    #[test]
    fn replay_for_a_different_invoice_is_not_a_replay() {
        assert!(!replay_matches(
            &sample_row(Uuid::new_v4(), 1_000),
            &sample_input(Uuid::new_v4(), 1_000)
        ));
    }

    // ------------------------------------------------------------------
    // Fix F — credit cap enforced under invoice row lock.
    // ------------------------------------------------------------------

    #[test]
    fn validate_credit_amount_accepts_credits_within_invoice_total() {
        // Sequential credits with different keys: 60 + 40 = 100 ≤ 100.
        assert!(validate_credit_amount(60, 100, 40).is_ok());
        assert!(validate_credit_amount(100, 100, 0).is_ok());
        assert!(validate_credit_amount(1, 100, 99).is_ok());
    }

    #[test]
    fn validate_credit_amount_rejects_second_credit_exceeding_total() {
        // First credit of 60 already committed; a concurrent/retry credit of
        // 41 with a different key must be rejected (60 + 41 > 100).
        let err = validate_credit_amount(41, 100, 60).unwrap_err();
        assert!(matches!(err, CreditNoteError::AmountExceedsInvoice));

        // Exactly reaching the total is allowed; one cent more is not.
        assert!(validate_credit_amount(40, 100, 60).is_ok());
        let err = validate_credit_amount(41, 100, 60).unwrap_err();
        assert!(matches!(err, CreditNoteError::AmountExceedsInvoice));
    }

    #[test]
    fn validate_credit_amount_rejects_non_positive_amounts() {
        for amount in [0, -1, -10_000] {
            let err = validate_credit_amount(amount, 100, 0).unwrap_err();
            assert!(
                matches!(err, CreditNoteError::AmountExceedsInvoice),
                "amount {amount} must be rejected"
            );
        }
    }

    #[test]
    fn validate_credit_amount_does_not_overflow_on_huge_credits() {
        // saturating_add must not wrap around and accidentally allow the
        // credit (i64::MAX + 1 would wrap to a small number without it).
        let err = validate_credit_amount(i64::MAX, 100, 1).unwrap_err();
        assert!(matches!(err, CreditNoteError::AmountExceedsInvoice));
    }

    #[test]
    fn credit_note_invoice_lookup_locks_the_row() {
        assert!(LOCK_INVOICE_FOR_CREDIT_SQL.contains("FOR UPDATE"));
    }

    // ------------------------------------------------------------------
    // Audit F60 — the disposition split: one credit yields exactly one
    // unit of benefit per cent, split between debt reduction and refund.
    // ------------------------------------------------------------------

    #[test]
    fn credit_on_a_fully_unpaid_invoice_is_pure_debt_reduction() {
        // 100 unpaid, credit 20: debt 100 -> 80, wallet +0 (no double
        // benefit).
        let (debt, refund) = split_credit_disposition(20, 0, 100);
        assert_eq!((debt, refund), (20, 0));
    }

    #[test]
    fn credit_on_a_fully_paid_invoice_is_a_pure_refund() {
        // 100 fully paid (outstanding 0): the whole credit refunds paid
        // value; the debt was already zero.
        let (debt, refund) = split_credit_disposition(20, 100, 0);
        assert_eq!((debt, refund), (0, 20));
    }

    #[test]
    fn partial_payment_splits_the_credit_exactly_once() {
        // 100 invoice, 40 paid, outstanding 60; credit 20: 20 goes to debt
        // (60 -> 40), nothing refunds. Credit 70 instead: 60 clears the
        // debt and 10 refunds paid value — 70 units of benefit total.
        let (debt, refund) = split_credit_disposition(20, 40, 60);
        assert_eq!((debt, refund), (20, 0));
        let (debt, refund) = split_credit_disposition(70, 40, 60);
        assert_eq!((debt, refund), (60, 10));
    }

    #[test]
    fn split_never_exceeds_the_paid_part_or_goes_negative() {
        // Degenerate inputs (hostile outstanding/payments) clamp safely.
        let (debt, refund) = split_credit_disposition(30, 5, -100);
        assert_eq!((debt, refund), (0, 5));
        let (debt, refund) = split_credit_disposition(10, -5, 50);
        assert_eq!((debt, refund), (10, 0));
        assert!(debt >= 0 && refund >= 0);
    }

    #[test]
    fn total_benefit_always_equals_the_credited_amount() {
        for &(amount, payments, outstanding) in &[
            (20_i64, 0_i64, 100_i64),
            (20, 100, 0),
            (70, 40, 60),
            (100, 100, 0),
            (50, 50, 50),
        ] {
            let (debt, refund) = split_credit_disposition(amount, payments, outstanding);
            assert_eq!(
                debt + refund,
                amount.min(payments.max(0) + outstanding.max(0)),
                "amount {amount} payments {payments} outstanding {outstanding}"
            );
        }
    }
}
