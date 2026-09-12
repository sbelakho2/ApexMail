//! Source adapters: operational event → idempotent journal entry.
//!
//! Each adapter reads the row where the event is ALREADY recorded (never a
//! parallel copy) and posts through [`crate::posting::post_journal_entry_in`],
//! so replaying the originating step is idempotent (unique source document +
//! unique idempotency key).
//!
//! | Adapter | Event source (file:line at time of writing) |
//! |---|---|
//! | [`post_invoice_issued`] | invoice finalization — `billing-service/src/overage.rs:1966` (`finalize_collection`, draft→paid/pending) and `billing-service/src/stripe_webhooks.rs:1608` (`handle_invoice_paid`) |
//! | [`post_payment_allocation`] | Stripe settlement / wallet settlement — allocation rows written at `billing-service/src/stripe_webhooks.rs:1741` and `billing-service/src/overage.rs:1918` (`invoice_payment_allocations`) |
//! | [`post_credit_note`] | credit notes / refunds — `billing-service/src/credit_notes.rs:172` (`create_credit_note`, `credit_notes` rows) |
//! | [`post_operating_cost`] | expenses — deployment-optional `operating_costs`, read by `compliance/src/estonia_ou.rs:973` (there is no canonical expense table; the adapter reports `SourceTableMissing` when absent) |
//! | [`post_payroll_record`] | payroll — `payroll_records` (migration `199_payroll_tax_inputs.sql:26`, read by `compliance/src/estonia_ou.rs:1026`) |
//! | [`post_bank_statement_line`] | bank receipts/payments — `bank_statement_lines` (created by migration 220; no pre-existing bank feed/table exists in the repo) |
//!
//! `invoices` also carries rows inserted directly as paid by
//! `stripe_webhooks.rs:1875` (`insert_paid_invoice_from_stripe`); that path
//! calls [`post_invoice_issued`] via the billing-service hook too.

use chrono::NaiveDate;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::error::{AccountingError, Result};
use crate::posting::post_journal_entry_in;
use crate::types::*;

fn upper(currency: &str) -> String {
    currency.trim().to_uppercase()
}

/// Split a gross credit-note amount into (net, VAT) proportionally to the
/// invoice's own VAT split. Rounding is half-up; the VAT part is clamped to
/// the credited amount.
fn split_vat_proportional(amount_cents: i64, invoice_total: i64, invoice_vat: i64) -> (i64, i64) {
    if amount_cents <= 0 {
        return (0, 0);
    }
    if invoice_total <= 0 || invoice_vat <= 0 {
        return (amount_cents, 0);
    }
    let vat = ((i128::from(amount_cents) * i128::from(invoice_vat) + i128::from(invoice_total) / 2)
        / i128::from(invoice_total)) as i64;
    let vat = vat.clamp(0, amount_cents);
    (amount_cents - vat, vat)
}

// ===========================================================================
// Invoices
// ===========================================================================

#[derive(Debug, sqlx::FromRow)]
struct InvoiceRow {
    id: Uuid,
    tenant_id: Option<String>,
    subtotal: i64,
    vat_total: i64,
    total: i64,
    currency: String,
    issued_at: chrono::DateTime<chrono::Utc>,
    due_at: Option<chrono::DateTime<chrono::Utc>>,
    invoice_number: Option<String>,
    status: String,
    vat_rate: Option<f64>,
}

/// Net revenue after VAT; kept non-negative so a malformed invoice cannot
/// produce an invalid line.
fn invoice_net_cents(total: i64, vat_total: i64) -> (i64, i64) {
    let vat = vat_total.clamp(0, total.max(0));
    let net = total.max(0).saturating_sub(vat);
    (net, vat)
}

/// Post the invoice-finalization entry: Dr AR, Cr revenue, Cr output VAT.
pub async fn post_invoice_issued(pool: &PgPool, invoice_id: Uuid) -> Result<PostOutcome> {
    let mut tx = pool.begin().await?;
    let outcome = post_invoice_issued_in(&mut tx, invoice_id).await?;
    tx.commit().await?;
    Ok(outcome)
}

/// Post the invoice-finalization entry on a caller-owned connection.
///
/// Idempotency key `invoice:<id>:issued`; source document
/// `('invoice', 'invoices', <id>)` with a hash over the invoice's financial
/// fields. A replay posts nothing and returns the original entry.
pub async fn post_invoice_issued_in(
    conn: &mut PgConnection,
    invoice_id: Uuid,
) -> Result<PostOutcome> {
    let invoice: Option<InvoiceRow> = sqlx::query_as(
        r#"
        SELECT id,
               tenant_id::text AS tenant_id,
               COALESCE(subtotal, amount, 0)::bigint AS subtotal,
               COALESCE(vat_total, 0)::bigint AS vat_total,
               COALESCE(total, subtotal + vat_total, amount, 0)::bigint AS total,
               COALESCE(currency, 'EUR') AS currency,
               issued_at,
               due_at,
               invoice_number,
               status::text AS status,
               vat_rate::double precision AS vat_rate
        FROM invoices
        WHERE id = $1
        "#,
    )
    .bind(invoice_id)
    .fetch_optional(&mut *conn)
    .await?;

    let Some(invoice) = invoice else {
        return Err(AccountingError::SourceRowMissing {
            table: "invoices",
            id: invoice_id.to_string(),
        });
    };

    if invoice.status.eq_ignore_ascii_case("draft") {
        return Err(AccountingError::Invalid(format!(
            "invoice {invoice_id} is still a draft; finalization is the posting trigger"
        )));
    }

    if invoice.total <= 0 {
        return Ok(PostOutcome::skipped());
    }

    let legal_entity_id = crate::chart::default_legal_entity(conn).await?;
    let currency = upper(&invoice.currency);
    let (net_cents, vat_cents) = invoice_net_cents(invoice.total, invoice.vat_total);
    let vat_rate_bp = invoice
        .vat_rate
        .filter(|rate| rate.is_finite() && *rate >= 0.0)
        .map(|rate| (rate * 100.0).round() as i32);

    let customer_id = ensure_customer(conn, legal_entity_id, invoice.tenant_id.as_deref()).await?;

    let document_date = invoice.issued_at.date_naive();
    let fiscal_period_id =
        crate::periods::find_open_period_for_date(conn, legal_entity_id, document_date).await?;

    let ar = crate::chart::resolve_account_role(conn, legal_entity_id, ROLE_AR).await?;
    let revenue = crate::chart::resolve_account_role(conn, legal_entity_id, ROLE_REVENUE).await?;

    let mut lines =
        vec![JournalLine::debit(ar, invoice.total, &currency)
            .with_description("Accounts receivable")];

    if net_cents > 0 {
        lines.push(
            JournalLine::credit(revenue, net_cents, &currency).with_description("Service revenue"),
        );
    }
    if vat_cents > 0 {
        let vat_account = crate::chart::resolve_tax_account(
            conn,
            legal_entity_id,
            "vat_output",
            ROLE_VAT_OUTPUT,
            document_date,
        )
        .await?;
        lines.push(
            JournalLine::credit(vat_account, vat_cents, &currency)
                .with_vat(
                    net_cents,
                    vat_cents,
                    vat_rate_bp,
                    Some("OUTPUT".to_string()),
                )
                .with_description("Output VAT"),
        );
    }

    // NOTE: `status` is deliberately NOT part of the evidence hash — an
    // invoice may be finalized as `pending` and later read as `paid`; the
    // financial identity (amounts, currency, issue date) is what must stay
    // stable for the idempotent replay.
    let payload = serde_json::json!({
        "invoice_id": invoice.id,
        "invoice_number": invoice.invoice_number,
        "tenant_id": invoice.tenant_id,
        "subtotal_cents": invoice.subtotal,
        "vat_total_cents": invoice.vat_total,
        "total_cents": invoice.total,
        "currency": currency,
        "issued_at": invoice.issued_at.to_rfc3339(),
    });

    let source = SourceIdentity::new(
        "invoice",
        "invoices",
        &invoice.id.to_string(),
        document_date,
        &currency,
        invoice.total,
        payload,
    );

    let request = PostJournalRequest {
        legal_entity_id,
        fiscal_period_id,
        entry_date: document_date,
        entry_type: EntryType::Standard,
        memo: format!(
            "Invoice {} issued",
            invoice
                .invoice_number
                .clone()
                .unwrap_or_else(|| invoice.id.to_string())
        ),
        posted_by: "adapter:invoice".to_string(),
        idempotency_key: format!("invoice:{}:issued", invoice.id),
        source: Some(source),
        reversal_of_entry_id: None,
        lines,
    };

    let outcome = post_journal_entry_in(conn, &request).await?;

    // Subledger linkage + opening AR balance.
    sqlx::query(
        r#"
        INSERT INTO accounts_receivable (
            legal_entity_id, customer_id, invoice_id, source_document_id,
            amount_cents, currency, due_date, status
        )
        VALUES (
            $1, $2, $3,
            (SELECT id FROM accounting_source_documents
              WHERE source_type = 'invoice' AND source_table = 'invoices' AND source_id = $4),
            $5, $6, $7,
            CASE WHEN $5 = 0 THEN 'settled' ELSE 'open' END
        )
        ON CONFLICT (invoice_id) DO NOTHING
        "#,
    )
    .bind(legal_entity_id)
    .bind(customer_id)
    .bind(invoice.id)
    .bind(invoice.id.to_string())
    .bind(invoice.total)
    .bind(&currency)
    .bind(invoice.due_at.map(|due| due.date_naive()))
    .execute(&mut *conn)
    .await?;

    Ok(outcome)
}

/// Register/resolve the platform tenant as an accounting customer. PII (the
/// contact email) is left to the GDPR anonymisation path; the row itself is
/// a retained counterparty record.
async fn ensure_customer(
    conn: &mut PgConnection,
    legal_entity_id: Uuid,
    tenant_id: Option<&str>,
) -> Result<Option<Uuid>> {
    let Some(tenant_id) = tenant_id else {
        return Ok(None);
    };

    sqlx::query(
        r#"
        INSERT INTO customers (legal_entity_id, tenant_id, name, registry_code, vat_number, country_code)
        SELECT $1, t.id, COALESCE(NULLIF(t.name, ''), t.id),
               NULLIF(t.settings->>'registryCode', ''),
               NULLIF(ba.vat_number, ''),
               NULLIF(UPPER(COALESCE(ba.country, '')), '')
        FROM tenants t
        LEFT JOIN LATERAL (
            SELECT vat_number, country FROM billing_addresses
            WHERE tenant_id = t.id LIMIT 1
        ) ba ON TRUE
        WHERE t.id = $2
        ON CONFLICT (legal_entity_id, tenant_id) DO NOTHING
        "#,
    )
    .bind(legal_entity_id)
    .bind(tenant_id)
    .execute(&mut *conn)
    .await?;

    let customer_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM customers WHERE legal_entity_id = $1 AND tenant_id = $2",
    )
    .bind(legal_entity_id)
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await?;

    Ok(customer_id)
}

// ===========================================================================
// Stripe settlement / wallet settlement (invoice_payment_allocations)
// ===========================================================================

#[derive(Debug, sqlx::FromRow)]
struct PaymentAllocationRow {
    operation_id: String,
    tenant_id: String,
    invoice_id: Uuid,
    amount_cents: i64,
    currency: String,
    source: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

/// Post a settlement: Dr processor clearing / wallet liability / bank,
/// Cr AR. Idempotency key `settlement:<operation_id>` — the allocation's own
/// unique operation id, so a replayed Stripe webhook posts once.
pub async fn post_payment_allocation(pool: &PgPool, operation_id: &str) -> Result<PostOutcome> {
    let mut tx = pool.begin().await?;
    let outcome = post_payment_allocation_in(&mut tx, operation_id).await?;
    tx.commit().await?;
    Ok(outcome)
}

pub async fn post_payment_allocation_in(
    conn: &mut PgConnection,
    operation_id: &str,
) -> Result<PostOutcome> {
    let allocation: Option<PaymentAllocationRow> = sqlx::query_as(
        r#"
        SELECT operation_id, tenant_id, invoice_id, amount_cents, currency, source, created_at
        FROM invoice_payment_allocations
        WHERE operation_id = $1
        "#,
    )
    .bind(operation_id)
    .fetch_optional(&mut *conn)
    .await?;

    let Some(allocation) = allocation else {
        return Err(AccountingError::SourceRowMissing {
            table: "invoice_payment_allocations",
            id: operation_id.to_string(),
        });
    };

    // Credit-note allocations are posted by the credit-note adapter (with
    // the invoice's VAT split); posting them here too would double count.
    if allocation.source == "credit_note" {
        return Ok(PostOutcome::skipped());
    }
    if allocation.amount_cents <= 0 {
        return Ok(PostOutcome::skipped());
    }

    let legal_entity_id = crate::chart::default_legal_entity(conn).await?;
    let currency = upper(&allocation.currency);
    let document_date = allocation.created_at.date_naive();
    let fiscal_period_id =
        crate::periods::find_open_period_for_date(conn, legal_entity_id, document_date).await?;

    let clearing = match allocation.source.as_str() {
        "stripe" => {
            let processor_account: Option<Uuid> = sqlx::query_scalar(
                "SELECT clearing_account_id FROM processor_clearing_accounts \
                 WHERE legal_entity_id = $1 AND processor = 'stripe' AND currency = $2 \
                   AND is_active LIMIT 1",
            )
            .bind(legal_entity_id)
            .bind(&currency)
            .fetch_optional(&mut *conn)
            .await?;
            match processor_account {
                Some(account) => account,
                None => {
                    crate::chart::resolve_account_role(conn, legal_entity_id, ROLE_STRIPE_CLEARING)
                        .await?
                }
            }
        }
        "wallet" => {
            crate::chart::resolve_account_role(conn, legal_entity_id, ROLE_WALLET_LIABILITY).await?
        }
        _ => crate::chart::resolve_account_role(conn, legal_entity_id, ROLE_BANK).await?,
    };
    let ar = crate::chart::resolve_account_role(conn, legal_entity_id, ROLE_AR).await?;

    let source_type = match allocation.source.as_str() {
        "stripe" => "stripe_settlement",
        "wallet" => "wallet_settlement",
        _ => "manual_settlement",
    };

    let payload = serde_json::json!({
        "operation_id": allocation.operation_id,
        "invoice_id": allocation.invoice_id,
        "tenant_id": allocation.tenant_id,
        "source": allocation.source,
        "amount_cents": allocation.amount_cents,
        "currency": currency,
        "created_at": allocation.created_at.to_rfc3339(),
    });

    let source = SourceIdentity::new(
        source_type,
        "invoice_payment_allocations",
        &allocation.operation_id,
        document_date,
        &currency,
        allocation.amount_cents,
        payload,
    );

    let request = PostJournalRequest {
        legal_entity_id,
        fiscal_period_id,
        entry_date: document_date,
        entry_type: EntryType::Standard,
        memo: format!(
            "{} settlement for invoice {}",
            allocation.source, allocation.invoice_id
        ),
        posted_by: "adapter:payment-allocation".to_string(),
        idempotency_key: format!("settlement:{}", allocation.operation_id),
        source: Some(source),
        reversal_of_entry_id: None,
        lines: vec![
            JournalLine::debit(clearing, allocation.amount_cents, &currency)
                .with_description("Clearing asset"),
            JournalLine::credit(ar, allocation.amount_cents, &currency)
                .with_description("Accounts receivable settled"),
        ],
    };

    let outcome = post_journal_entry_in(conn, &request).await?;

    // Track the settled part of the receivable (subledger only; the journal
    // above is the ledger).
    sqlx::query(
        r#"
        UPDATE accounts_receivable
        SET settled_cents = LEAST(amount_cents, settled_cents + $2),
            status = CASE
                WHEN LEAST(amount_cents, settled_cents + $2) >= amount_cents THEN 'settled'
                WHEN settled_cents + $2 > 0 THEN 'partially_settled'
                ELSE status
            END,
            updated_at = NOW()
        WHERE invoice_id = $1
        "#,
    )
    .bind(allocation.invoice_id)
    .bind(allocation.amount_cents)
    .execute(&mut *conn)
    .await?;

    Ok(outcome)
}

// ===========================================================================
// Credit notes / refunds
// ===========================================================================

#[derive(Debug, sqlx::FromRow)]
struct CreditNoteRow {
    id: Uuid,
    invoice_id: Uuid,
    tenant_id: String,
    amount: i64,
    currency: String,
    reason: String,
    debt_reduction_cents: Option<i64>,
    refunded_cents: Option<i64>,
    created_at: chrono::DateTime<chrono::Utc>,
}

/// Post the credit note's entries: the debt-reduction part reverses revenue
/// and output VAT against AR; the refunded part reverses revenue/VAT against
/// the customer wallet liability (the wallet credit that
/// `credit_notes.rs:353` mints). Returns one outcome per part (skipped parts
/// included as `Skipped`).
pub async fn post_credit_note(pool: &PgPool, credit_note_id: Uuid) -> Result<Vec<PostOutcome>> {
    let mut tx = pool.begin().await?;
    let outcomes = post_credit_note_in(&mut tx, credit_note_id).await?;
    tx.commit().await?;
    Ok(outcomes)
}

pub async fn post_credit_note_in(
    conn: &mut PgConnection,
    credit_note_id: Uuid,
) -> Result<Vec<PostOutcome>> {
    let note: Option<CreditNoteRow> = sqlx::query_as(
        r#"
        SELECT id, invoice_id, tenant_id, amount, currency, reason,
               debt_reduction_cents, refunded_cents, created_at
        FROM credit_notes
        WHERE id = $1
        "#,
    )
    .bind(credit_note_id)
    .fetch_optional(&mut *conn)
    .await?;

    let Some(note) = note else {
        return Err(AccountingError::SourceRowMissing {
            table: "credit_notes",
            id: credit_note_id.to_string(),
        });
    };

    // Legacy rows (pre-183) have NULL split: whole amount was a debt
    // reduction (the outstanding derivation treats it that way).
    let debt_reduction = note.debt_reduction_cents.unwrap_or(note.amount).max(0);
    let refunded = note.refunded_cents.unwrap_or(0).max(0);

    let invoice_split: Option<(i64, i64)> = sqlx::query_as(
        "SELECT COALESCE(total, amount, 0)::bigint, COALESCE(vat_total, 0)::bigint \
         FROM invoices WHERE id = $1",
    )
    .bind(note.invoice_id)
    .fetch_optional(&mut *conn)
    .await?;

    let (invoice_total, invoice_vat) = invoice_split.unwrap_or((0, 0));

    let legal_entity_id = crate::chart::default_legal_entity(conn).await?;
    let currency = upper(&note.currency);
    let document_date = note.created_at.date_naive();
    let fiscal_period_id =
        crate::periods::find_open_period_for_date(conn, legal_entity_id, document_date).await?;

    let ar = crate::chart::resolve_account_role(conn, legal_entity_id, ROLE_AR).await?;
    let revenue = crate::chart::resolve_account_role(conn, legal_entity_id, ROLE_REVENUE).await?;
    let refunds = crate::chart::resolve_account_role(conn, legal_entity_id, ROLE_REFUNDS).await?;
    let vat_account = crate::chart::resolve_tax_account(
        conn,
        legal_entity_id,
        "vat_output",
        ROLE_VAT_OUTPUT,
        document_date,
    )
    .await?;

    let mut outcomes = Vec::with_capacity(2);

    // Part 1: debt reduction — Dr revenue, Dr output VAT, Cr AR.
    if debt_reduction > 0 {
        let (net, vat) = split_vat_proportional(debt_reduction, invoice_total, invoice_vat);
        let mut lines = Vec::with_capacity(3);
        if net > 0 {
            lines.push(
                JournalLine::debit(revenue, net, &currency)
                    .with_description("Credit note — revenue reversal"),
            );
        }
        if vat > 0 {
            lines.push(
                JournalLine::debit(vat_account, vat, &currency)
                    .with_vat(net, vat, None, Some("OUTPUT".to_string()))
                    .with_description("Credit note — output VAT reversal"),
            );
        }
        lines.push(
            JournalLine::credit(ar, debt_reduction, &currency)
                .with_description("Credit note — debt reduction"),
        );

        let payload = serde_json::json!({
            "credit_note_id": note.id,
            "invoice_id": note.invoice_id,
            "tenant_id": note.tenant_id,
            "amount_cents": note.amount,
            "debt_reduction_cents": debt_reduction,
            "reason": note.reason,
            "created_at": note.created_at.to_rfc3339(),
        });
        let request = PostJournalRequest {
            legal_entity_id,
            fiscal_period_id,
            entry_date: document_date,
            entry_type: EntryType::Standard,
            memo: format!("Credit note {} — debt reduction", note.id),
            posted_by: "adapter:credit-note".to_string(),
            idempotency_key: format!("credit_note:{}:debt", note.id),
            source: Some(SourceIdentity::new(
                "credit_note",
                "credit_notes",
                &note.id.to_string(),
                document_date,
                &currency,
                debt_reduction,
                payload,
            )),
            reversal_of_entry_id: None,
            lines,
        };
        outcomes.push(post_journal_entry_in(conn, &request).await?);
    } else {
        outcomes.push(PostOutcome::skipped());
    }

    // Part 2: refund — Dr refunds (contra revenue), Dr output VAT,
    // Cr wallet liability.
    if refunded > 0 {
        let (net, vat) = split_vat_proportional(refunded, invoice_total, invoice_vat);
        let wallet =
            crate::chart::resolve_account_role(conn, legal_entity_id, ROLE_WALLET_LIABILITY)
                .await?;
        let mut lines = Vec::with_capacity(3);
        if net > 0 {
            lines.push(
                JournalLine::debit(refunds, net, &currency)
                    .with_description("Refund — revenue reversal"),
            );
        }
        if vat > 0 {
            lines.push(
                JournalLine::debit(vat_account, vat, &currency)
                    .with_vat(net, vat, None, Some("OUTPUT".to_string()))
                    .with_description("Refund — output VAT reversal"),
            );
        }
        lines.push(
            JournalLine::credit(wallet, refunded, &currency)
                .with_description("Refund — customer wallet liability"),
        );

        let payload = serde_json::json!({
            "credit_note_id": note.id,
            "invoice_id": note.invoice_id,
            "tenant_id": note.tenant_id,
            "refunded_cents": refunded,
            "reason": note.reason,
            "created_at": note.created_at.to_rfc3339(),
        });
        let request = PostJournalRequest {
            legal_entity_id,
            fiscal_period_id,
            entry_date: document_date,
            entry_type: EntryType::Standard,
            memo: format!("Credit note {} — refund to wallet", note.id),
            posted_by: "adapter:credit-note".to_string(),
            idempotency_key: format!("credit_note:{}:refund", note.id),
            source: Some(SourceIdentity::new(
                "credit_note_refund",
                "credit_notes",
                &note.id.to_string(),
                document_date,
                &currency,
                refunded,
                payload,
            )),
            reversal_of_entry_id: None,
            lines,
        };
        outcomes.push(post_journal_entry_in(conn, &request).await?);
    } else {
        outcomes.push(PostOutcome::skipped());
    }

    // Subledger: the debt-reduction part settles the receivable balance.
    if debt_reduction > 0 {
        sqlx::query(
            r#"
            UPDATE accounts_receivable
            SET settled_cents = LEAST(amount_cents, settled_cents + $2),
                status = CASE
                    WHEN LEAST(amount_cents, settled_cents + $2) >= amount_cents THEN 'settled'
                    WHEN settled_cents + $2 > 0 THEN 'partially_settled'
                    ELSE status
                END,
                updated_at = NOW()
            WHERE invoice_id = $1
            "#,
        )
        .bind(note.invoice_id)
        .bind(debt_reduction)
        .execute(&mut *conn)
        .await?;
    }

    Ok(outcomes)
}

// ===========================================================================
// Expenses
// ===========================================================================

/// Post an expense from the deployment-optional `operating_costs` table
/// (source read at `compliance/src/estonia_ou.rs:973`): Dr operating
/// expenses, Cr accounts payable. Returns `SourceTableMissing` when the
/// deployment has no expense store, so the caller can surface the gap
/// instead of silently omitting costs from the ledger.
pub async fn post_operating_cost(
    pool: &PgPool,
    legal_entity_id: Uuid,
    cost_id: Uuid,
) -> Result<PostOutcome> {
    let mut tx = pool.begin().await?;

    let exists: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.operating_costs')::text")
            .fetch_one(&mut *tx)
            .await?;
    if exists.is_none() {
        return Err(AccountingError::SourceTableMissing(
            "operating_costs".to_string(),
        ));
    }

    let row: Option<(Option<String>, i64, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT category, amount_cents, incurred_at FROM operating_costs WHERE id = $1",
    )
    .bind(cost_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some((category, amount_cents, incurred_at)) = row else {
        return Err(AccountingError::SourceRowMissing {
            table: "operating_costs",
            id: cost_id.to_string(),
        });
    };

    if amount_cents <= 0 {
        return Ok(PostOutcome::skipped());
    }

    let document_date = incurred_at.date_naive();
    let fiscal_period_id =
        crate::periods::find_open_period_for_date(&mut tx, legal_entity_id, document_date).await?;

    let expense =
        crate::chart::resolve_account_role(&mut tx, legal_entity_id, ROLE_EXPENSE_DEFAULT).await?;
    let ap = crate::chart::resolve_account_role(&mut tx, legal_entity_id, ROLE_AP).await?;

    let payload = serde_json::json!({
        "operating_cost_id": cost_id,
        "category": category,
        "amount_cents": amount_cents,
        "incurred_at": incurred_at.to_rfc3339(),
    });

    let request = PostJournalRequest {
        legal_entity_id,
        fiscal_period_id,
        entry_date: document_date,
        entry_type: EntryType::Standard,
        memo: format!(
            "Operating cost {} ({})",
            cost_id,
            category.unwrap_or_else(|| "infrastructure".to_string())
        ),
        posted_by: "adapter:expense".to_string(),
        idempotency_key: format!("expense:operating_costs:{cost_id}"),
        source: Some(SourceIdentity::new(
            "expense",
            "operating_costs",
            &cost_id.to_string(),
            document_date,
            "EUR",
            amount_cents,
            payload,
        )),
        reversal_of_entry_id: None,
        lines: vec![
            JournalLine::debit(expense, amount_cents, "EUR").with_description("Operating expense"),
            JournalLine::credit(ap, amount_cents, "EUR").with_description("Accounts payable"),
        ],
    };

    let outcome = post_journal_entry_in(&mut tx, &request).await?;
    tx.commit().await?;
    Ok(outcome)
}

// ===========================================================================
// Payroll
// ===========================================================================

/// Post a payroll record's journal entry and persist its `payroll_postings`
/// row (the TSD derivation input).
///
/// Debit payroll expense (gross + employer social + employer unemployment);
/// credit net wages and every withheld/employer tax payable. The caller
/// supplies the amounts computed by the date-effective tax policy; the
/// adapter validates `gross = net + income tax + employee unemployment +
/// pension` so an inconsistent payroll can never enter the ledger.
pub async fn post_payroll_record(
    pool: &PgPool,
    legal_entity_id: Uuid,
    payroll_record_id: Uuid,
    amounts: PayrollAmounts,
) -> Result<PostOutcome> {
    let mut tx = pool.begin().await?;

    let record: Option<(Option<String>, i64, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT employee_name, gross_salary_cents, pay_period \
         FROM payroll_records WHERE id = $1",
    )
    .bind(payroll_record_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some((employee_name, gross_cents, pay_period)) = record else {
        return Err(AccountingError::SourceRowMissing {
            table: "payroll_records",
            id: payroll_record_id.to_string(),
        });
    };

    let expected_gross = amounts
        .net_cents
        .saturating_add(amounts.income_tax_cents)
        .saturating_add(amounts.unemployment_employee_cents)
        .saturating_add(amounts.pension_cents);
    if expected_gross != gross_cents {
        return Err(AccountingError::Invalid(format!(
            "payroll record {payroll_record_id}: gross {gross_cents} != net + withheld taxes \
             ({expected_gross}); compute the payroll amounts first"
        )));
    }

    let document_date = pay_period.date_naive();
    let fiscal_period_id =
        crate::periods::find_open_period_for_date(&mut tx, legal_entity_id, document_date).await?;

    let expense =
        crate::chart::resolve_account_role(&mut tx, legal_entity_id, ROLE_PAYROLL_EXPENSE).await?;
    let net_wages =
        crate::chart::resolve_account_role(&mut tx, legal_entity_id, ROLE_NET_WAGES_PAYABLE)
            .await?;
    let income_tax = crate::chart::resolve_tax_account(
        &mut tx,
        legal_entity_id,
        "income_tax",
        ROLE_INCOME_TAX_PAYABLE,
        document_date,
    )
    .await?;
    let social_tax = crate::chart::resolve_tax_account(
        &mut tx,
        legal_entity_id,
        "social_tax",
        ROLE_SOCIAL_TAX_PAYABLE,
        document_date,
    )
    .await?;
    let unemployment =
        crate::chart::resolve_account_role(&mut tx, legal_entity_id, ROLE_UNEMPLOYMENT_PAYABLE)
            .await?;
    let pension =
        crate::chart::resolve_account_role(&mut tx, legal_entity_id, ROLE_PENSION_PAYABLE).await?;

    let employer_cost = gross_cents
        .saturating_add(amounts.social_tax_cents)
        .saturating_add(amounts.unemployment_employer_cents);

    let mut lines = Vec::with_capacity(6);
    lines.push(
        JournalLine::debit(expense, employer_cost, "EUR").with_description("Payroll expense"),
    );
    if amounts.net_cents > 0 {
        lines.push(
            JournalLine::credit(net_wages, amounts.net_cents, "EUR").with_description("Net wages"),
        );
    }
    if amounts.income_tax_cents > 0 {
        lines.push(JournalLine::credit(
            income_tax,
            amounts.income_tax_cents,
            "EUR",
        ));
    }
    if amounts.social_tax_cents > 0 {
        lines.push(JournalLine::credit(
            social_tax,
            amounts.social_tax_cents,
            "EUR",
        ));
    }
    let unemployment_total = amounts
        .unemployment_employee_cents
        .saturating_add(amounts.unemployment_employer_cents);
    if unemployment_total > 0 {
        lines.push(JournalLine::credit(unemployment, unemployment_total, "EUR"));
    }
    if amounts.pension_cents > 0 {
        lines.push(JournalLine::credit(pension, amounts.pension_cents, "EUR"));
    }

    let payload = serde_json::json!({
        "payroll_record_id": payroll_record_id,
        "employee_name": employee_name,
        "gross_cents": gross_cents,
        "income_tax_cents": amounts.income_tax_cents,
        "social_tax_cents": amounts.social_tax_cents,
        "unemployment_employee_cents": amounts.unemployment_employee_cents,
        "unemployment_employer_cents": amounts.unemployment_employer_cents,
        "pension_cents": amounts.pension_cents,
        "net_cents": amounts.net_cents,
        "pay_period": pay_period.to_rfc3339(),
    });

    let request = PostJournalRequest {
        legal_entity_id,
        fiscal_period_id,
        entry_date: document_date,
        entry_type: EntryType::Payroll,
        memo: format!(
            "Payroll {} ({})",
            payroll_record_id,
            employee_name
                .clone()
                .unwrap_or_else(|| "employee".to_string())
        ),
        posted_by: "adapter:payroll".to_string(),
        idempotency_key: format!("payroll:{payroll_record_id}"),
        source: Some(SourceIdentity::new(
            "payroll",
            "payroll_records",
            &payroll_record_id.to_string(),
            document_date,
            "EUR",
            gross_cents,
            payload,
        )),
        reversal_of_entry_id: None,
        lines,
    };

    let outcome = post_journal_entry_in(&mut tx, &request).await?;

    sqlx::query(
        r#"
        INSERT INTO payroll_postings (
            legal_entity_id, fiscal_period_id, payroll_record_id, employee_name,
            gross_cents, income_tax_cents, social_tax_cents,
            unemployment_employee_cents, unemployment_employer_cents,
            pension_cents, net_cents, journal_entry_id, source_document_id, currency
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
            (SELECT id FROM accounting_source_documents
              WHERE source_type = 'payroll' AND source_table = 'payroll_records' AND source_id = $13),
            'EUR'
        )
        ON CONFLICT (payroll_record_id) DO UPDATE SET
            journal_entry_id = EXCLUDED.journal_entry_id,
            source_document_id = EXCLUDED.source_document_id
        "#,
    )
    .bind(legal_entity_id)
    .bind(fiscal_period_id)
    .bind(payroll_record_id)
    .bind(&employee_name)
    .bind(gross_cents)
    .bind(amounts.income_tax_cents)
    .bind(amounts.social_tax_cents)
    .bind(amounts.unemployment_employee_cents)
    .bind(amounts.unemployment_employer_cents)
    .bind(amounts.pension_cents)
    .bind(amounts.net_cents)
    .bind(outcome.entry_id)
    .bind(payroll_record_id.to_string())
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(outcome)
}

// ===========================================================================
// Bank statement lines
// ===========================================================================

/// Post a bank statement line: positive amounts (receipts) Dr bank, Cr AR;
/// negative amounts (payments) Dr operating expenses, Cr bank. The line's
/// `journal_entry_id` is stamped, and `bank_reconciliations` can later match
/// a receipt against the specific invoice entry.
pub async fn post_bank_statement_line(pool: &PgPool, line_id: Uuid) -> Result<PostOutcome> {
    let mut tx = pool.begin().await?;

    let row: Option<(
        Uuid,
        Uuid,
        Uuid,
        i64,
        String,
        NaiveDate,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        r#"
            SELECT l.id, ba.legal_entity_id, ba.account_id, l.amount_cents, l.currency,
                   l.statement_date, l.reference, l.counterparty_name
            FROM bank_statement_lines l
            JOIN bank_accounts ba ON ba.id = l.bank_account_id
            WHERE l.id = $1
            "#,
    )
    .bind(line_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some((
        _id,
        legal_entity_id,
        bank_ledger,
        amount_cents,
        currency,
        statement_date,
        reference,
        counterparty,
    )) = row
    else {
        return Err(AccountingError::SourceRowMissing {
            table: "bank_statement_lines",
            id: line_id.to_string(),
        });
    };

    if amount_cents == 0 {
        return Err(AccountingError::Invalid(format!(
            "bank statement line {line_id} has a zero amount"
        )));
    }

    let currency = upper(&currency);
    let fiscal_period_id =
        crate::periods::find_open_period_for_date(&mut tx, legal_entity_id, statement_date).await?;

    let ar = crate::chart::resolve_account_role(&mut tx, legal_entity_id, ROLE_AR).await?;
    let expense =
        crate::chart::resolve_account_role(&mut tx, legal_entity_id, ROLE_EXPENSE_DEFAULT).await?;

    let magnitude = amount_cents.unsigned_abs() as i64;
    let lines = if amount_cents > 0 {
        vec![
            JournalLine::debit(bank_ledger, magnitude, &currency).with_description("Bank receipt"),
            JournalLine::credit(ar, magnitude, &currency).with_description("Receivable collected"),
        ]
    } else {
        vec![
            JournalLine::debit(expense, magnitude, &currency).with_description("Bank payment"),
            JournalLine::credit(bank_ledger, magnitude, &currency).with_description("Bank payment"),
        ]
    };

    let payload = serde_json::json!({
        "bank_statement_line_id": line_id,
        "amount_cents": amount_cents,
        "currency": currency,
        "statement_date": statement_date.to_string(),
        "reference": reference,
        "counterparty": counterparty,
    });

    let request = PostJournalRequest {
        legal_entity_id,
        fiscal_period_id,
        entry_date: statement_date,
        entry_type: EntryType::Standard,
        memo: format!(
            "Bank statement line {} ({})",
            line_id,
            counterparty.unwrap_or_else(|| "unknown counterparty".to_string())
        ),
        posted_by: "adapter:bank".to_string(),
        idempotency_key: format!("bank_statement_line:{line_id}"),
        source: Some(SourceIdentity::new(
            "bank_statement_line",
            "bank_statement_lines",
            &line_id.to_string(),
            statement_date,
            &currency,
            amount_cents,
            payload,
        )),
        reversal_of_entry_id: None,
        lines,
    };

    let outcome = post_journal_entry_in(&mut tx, &request).await?;

    sqlx::query(
        "UPDATE bank_statement_lines SET journal_entry_id = $2 \
         WHERE id = $1 AND journal_entry_id IS NULL",
    )
    .bind(line_id)
    .bind(outcome.entry_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vat_split_is_proportional_and_never_exceeds_amount() {
        assert_eq!(split_vat_proportional(120, 120, 20), (100, 20));
        assert_eq!(split_vat_proportional(100, 120, 20), (83, 17));
        assert_eq!(split_vat_proportional(0, 120, 20), (0, 0));
        assert_eq!(split_vat_proportional(50, 0, 0), (50, 0));
        // VAT share never exceeds the credited amount.
        let (net, vat) = split_vat_proportional(1, 1, 100);
        assert_eq!((net, vat), (0, 1));
    }

    #[test]
    fn invoice_net_is_clamped() {
        assert_eq!(invoice_net_cents(120, 20), (100, 20));
        assert_eq!(invoice_net_cents(120, 0), (120, 0));
        // Malformed VAT > total: VAT clamped, net zero, never negative.
        assert_eq!(invoice_net_cents(10, 50), (0, 10));
        assert_eq!(invoice_net_cents(0, 0), (0, 0));
    }
}
