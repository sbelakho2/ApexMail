//! Invoice management – create, list, get by ID.

use chrono::{DateTime, Datelike, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::{Invoice, InvoiceLineItem, InvoiceStatus};

/// `vat_validation_evidence` row the evidence lookup decodes (named row: the
/// 8-tuple tripped clippy's type-complexity gate).
#[derive(Debug, sqlx::FromRow)]
struct VatEvidenceRow {
    id: Uuid,
    vat_number: String,
    country: String,
    source: String,
    valid: bool,
    valid_from: Option<chrono::NaiveDate>,
    valid_until: Option<chrono::NaiveDate>,
    outage_state: Option<String>,
}

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// PDF Renderer client config
// ---------------------------------------------------------------------------

/// Base URL for the pdf-renderer service. Read per call rather than cached in
/// a `LazyLock` so a long-lived process follows a re-pointed renderer and
/// tests can drive a local mock deterministically.
fn pdf_renderer_url() -> String {
    std::env::var("PDF_RENDERER_URL").unwrap_or_else(|_| "http://pdf-renderer:3004".into())
}

// ---------------------------------------------------------------------------
// S3/R2 object storage config
// ---------------------------------------------------------------------------

/// Default AWS S3 host used when `S3_ENDPOINT` is not configured.
const S3_DEFAULT_HOST: &str = "s3.eu-central-1.amazonaws.com";

/// S3-compatible endpoint (e.g. `https://s3.eu-central-1.amazonaws.com`, an
/// R2 endpoint, or a local mock at `http://127.0.0.1:9000`).
///
/// `None` (unset or blank) means NO endpoint is configured and the historical
/// AWS virtual-hosted behaviour is used. When set, its scheme, host (with
/// port) and path prefix are honoured — see [`s3_object_target`].
fn s3_endpoint() -> Option<String> {
    std::env::var("S3_ENDPOINT")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// S3 bucket for invoice PDFs.
fn s3_bucket() -> String {
    std::env::var("S3_BUCKET").unwrap_or_else(|_| "apexmail-invoices".into())
}

/// AWS region for Sig V4 signing.
fn s3_region() -> String {
    std::env::var("S3_REGION").unwrap_or_else(|_| "eu-central-1".into())
}

/// Optional public URL prefix for the bucket (e.g. `https://storage.apexmail.ee`).
/// When set, returned URLs use this base instead of the raw S3 endpoint.
fn s3_public_url() -> Option<String> {
    std::env::var("S3_PUBLIC_URL").ok()
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for invoice line items JSON.
const INVOICE_LINE_ITEMS_SCHEMA_VERSION: u32 = 1;

/// Schema version for the immutable billing-address snapshot JSON
/// (audit F08). A versioned snapshot DTO lets readers distinguish a
/// deliberately-empty optional field from a malformed/legacy payload.
pub const BILLING_ADDRESS_SNAPSHOT_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Re-exports from billing-common
// ---------------------------------------------------------------------------

/// Calculate the VAT rate and amount for a given subtotal, customer country
/// and optional VAT number.
///
/// Delegates to [`billing_common::vat_rates::calculate_vat`]. Reverse charge
/// is NOT authorised by this wrapper (it carries no evidence) — use
/// [`calculate_vat_for_invoice`] / `calculate_vat_with_evidence` when
/// authoritative VIES evidence is available.
pub use billing_common::vat_rates::calculate_vat;

use billing_common::vat_rates::{self, VatValidationEvidence};

/// Load the newest authoritative VAT evidence for a tenant's VAT number.
///
/// Returns `None` when there is no evidence row (or the evidence cannot be
/// authoritative) — callers then charge the normal destination rate, because
/// structural validity is not evidence. A database error (e.g. the table is
/// absent mid-upgrade) also degrades to `None` (fail closed to normal VAT)
/// with a warning, never to a silent zero-rate.
pub async fn load_vat_evidence_for_tenant(
    pool: &PgPool,
    tenant_id: &str,
    vat_number: &str,
) -> Option<VatValidationEvidence> {
    load_vat_evidence_in(pool, tenant_id, vat_number).await
}

/// Executor-generic variant of [`load_vat_evidence_for_tenant`] for callers
/// inside a transaction.
pub async fn load_vat_evidence_in<'e, E>(
    executor: E,
    tenant_id: &str,
    vat_number: &str,
) -> Option<VatValidationEvidence>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let row: Result<Option<VatEvidenceRow>, sqlx::Error> = sqlx::query_as(
        r#"
        SELECT id, vat_number, country, source, valid, valid_from, valid_until, outage_state
        FROM vat_validation_evidence
        WHERE (tenant_id = $1 OR customer_id = $1)
          AND UPPER(REPLACE(vat_number, ' ', '')) = UPPER(REPLACE($2, ' ', ''))
        ORDER BY requested_at DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(vat_number)
    .fetch_optional(executor)
    .await;

    match row {
        Ok(Some(VatEvidenceRow {
            id,
            vat_number,
            country,
            source,
            valid,
            valid_from,
            valid_until,
            outage_state,
        })) => VatValidationEvidence::from_authority_row(
            Some(id),
            vat_number,
            country,
            &source,
            valid,
            valid_from,
            valid_until,
            outage_state,
        ),
        Ok(None) => None,
        Err(error) => {
            tracing::warn!(
                tenant_id = %tenant_id,
                error = %error,
                "VAT evidence lookup failed — charging normal VAT (fail closed)"
            );
            None
        }
    }
}

/// The invoice writer's VAT computation: reverse charge only against
/// authoritative, in-force VIES evidence for the invoice's tax-point date.
/// Returns the rate and amount together with the evidence id to snapshot.
pub fn calculate_vat_for_invoice(
    subtotal: i64,
    country: &str,
    vat_number: Option<&str>,
    evidence: Option<&VatValidationEvidence>,
    at: chrono::NaiveDate,
) -> (f64, i64, Option<Uuid>) {
    let (rate, amount) =
        vat_rates::calculate_vat_with_evidence(subtotal, country, vat_number, evidence, at);
    let authorised = vat_number
        .is_some_and(|vat| vat_rates::reverse_charge_authorised(country, vat, evidence, at));
    let evidence_id = if authorised {
        evidence.and_then(|evidence| evidence.id)
    } else {
        None
    };
    (rate, amount, evidence_id)
}

/// Generate the next invoice number in `YYYY-NNNNNN` format.
pub async fn generate_invoice_number(pool: &PgPool) -> Result<String, InvoiceError> {
    let year = Utc::now().year();

    let row: (i64,) = sqlx::query_as("SELECT nextval('invoice_number_seq')::bigint")
        .fetch_one(pool)
        .await
        .map_err(InvoiceError::Db)?;

    Ok(format!("{year}-{:06}", row.0))
}

/// Same as [`generate_invoice_number`], on a caller-owned transaction so
/// the sequence bump participates in the caller's atomicity unit.
async fn generate_invoice_number_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<String, InvoiceError> {
    let year = Utc::now().year();

    let row: (i64,) = sqlx::query_as("SELECT nextval('invoice_number_seq')::bigint")
        .fetch_one(&mut **tx)
        .await
        .map_err(InvoiceError::Db)?;

    Ok(format!("{year}-{:06}", row.0))
}

pub struct CreateInvoiceInput {
    pub tenant_id: String,
    pub stripe_invoice_id: Option<String>,
    pub line_items: Vec<NewLineItem>,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub due_at: Option<DateTime<Utc>>,
    pub currency: Option<String>,
    /// Idempotency marker for the usage sweeps (migration 126): the
    /// billing-cycle start (overage) or calendar-month start (PAYG) this
    /// invoice settles. `invoices.overage_period` is written in the SAME
    /// INSERT as the invoice row, so the check-then-insert idempotency in
    /// the overage sweep can never observe a marker-less invoice. `None`
    /// for non-sweep writers (Stripe webhook invoice persistence, the
    /// admin invoice writer).
    pub overage_period: Option<DateTime<Utc>>,
}

pub struct NewLineItem {
    pub description: String,
    pub quantity: i64,
    /// Unit price in cents.
    pub unit_price: i64,
}

/// Escape HTML-special characters in a user-supplied string to prevent
/// XSS injection into the PDF invoice template (BS-005).
///
/// The pdf-renderer service uses the Typst typesetting system which
/// interprets HTML/XML-like syntax.  Without escaping, a malicious
/// `description` field containing `<`, `>`, `&`, `"`, or `'` could
/// inject arbitrary content into the generated PDF.
fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => {
                out.push('&');
                out.push('a');
                out.push('m');
                out.push('p');
                out.push(';');
            }
            '<' => {
                out.push('&');
                out.push('l');
                out.push('t');
                out.push(';');
            }
            '>' => {
                out.push('&');
                out.push('g');
                out.push('t');
                out.push(';');
            }
            '"' => {
                out.push('&');
                out.push('q');
                out.push('u');
                out.push('o');
                out.push('t');
                out.push(';');
            }
            '\'' => {
                out.push('&');
                out.push('#');
                out.push('3');
                out.push('9');
                out.push(';');
            }
            c => out.push(c),
        }
    }
    out
}

/// Round-half-up VAT for a single base amount (integer cents, fractional
/// percent rates supported via billing_common).
pub fn round_vat(amount: i64, rate: f64) -> i64 {
    billing_common::vat_rates::vat_amount_half_up(amount, rate)
}

/// Allocate VAT across invoice lines following the EU convention: round each
/// line independently, then adjust the final non-zero line so the per-line
/// sum always reconciles exactly with the VAT computed on the (rounded)
/// invoice total. Without this, sums of per-line rounding drift by ±1 cent
/// from the headline `vat_total`, breaking KMD returns and PDF totals.
///
/// This is the platform's single VAT-allocation algorithm; every invoice
/// writer (billing-service and the api-server admin route) must use it so
/// per-line VAT never diverges between paths.
///
/// Returns the VAT amount (cents) per line, aligned with `amounts`.
pub fn allocate_vat_across_lines(amounts: &[i64], rate: f64) -> Vec<i64> {
    let mut allocated: Vec<i64> = amounts.iter().map(|&a| round_vat(a, rate)).collect();
    let total: i64 = amounts.iter().sum();
    let target = round_vat(total, rate);
    let drift = target - allocated.iter().sum::<i64>();

    if drift != 0 {
        // Adjust the final line that already carries VAT (falling back to the
        // last line when every per-line rounding rounded down to zero).
        let slot = allocated
            .iter()
            .rposition(|value| *value != 0)
            .unwrap_or(allocated.len().saturating_sub(1));
        if let Some(value) = allocated.get_mut(slot) {
            *value += drift;
        }
    }

    allocated
}

/// Full billing-address row snapshotted onto the invoice at issue time.
/// An issued invoice is a legal document: it must show the address that was
/// in force WHEN it was issued, not the tenant's current (mutable) address
/// (audit F08).
#[derive(sqlx::FromRow)]
struct BillingAddrSnapshotRow {
    company_name: Option<String>,
    vat_number: Option<String>,
    address_line1: Option<String>,
    address_line2: Option<String>,
    city: Option<String>,
    state: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
    email: Option<String>,
    /// Buyer business-registry code (export-relevant identity, audit F08),
    /// frozen at issue time from the tenant's settings.
    registry_code: Option<String>,
}

/// Create an invoice on the pool (own transaction).
pub async fn create_invoice(
    pool: &PgPool,
    input: CreateInvoiceInput,
) -> Result<Invoice, InvoiceError> {
    let mut tx = pool.begin().await.map_err(InvoiceError::Db)?;
    let invoice = create_invoice_in_tx(&mut tx, input).await?;
    tx.commit().await.map_err(InvoiceError::Db)?;
    Ok(invoice)
}

/// Create an invoice INSIDE a caller-owned transaction.
///
/// The usage sweeps must claim the billing period and insert its invoice
/// atomically (audit F29 — the old claim-then-insert-on-another-connection
/// sequence let two sweeps double-invoice a period). Everything this
/// function does (address read, invoice numbering, INSERT) executes on the
/// caller's transaction, so a unique violation on `overage_period`
/// (migration 136) aborts the whole claim together with the insert.
pub async fn create_invoice_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    input: CreateInvoiceInput,
) -> Result<Invoice, InvoiceError> {
    // Fetch the FULL billing address: country + VAT number drive VAT
    // calculation, and the whole row is snapshotted immutably onto the
    // invoice (audit F08). The buyer registry code (export-relevant
    // identity) is frozen from the tenant's settings in the same read.
    let addr: BillingAddrSnapshotRow = sqlx::query_as(
        r#"
        SELECT ba.company_name, ba.vat_number, ba.address_line1, ba.address_line2,
               ba.city, ba.state, ba.postal_code, ba.country, ba.email,
               t.settings->>'registryCode' AS registry_code
        FROM billing_addresses ba
        JOIN tenants t ON t.id = ba.tenant_id
        WHERE ba.tenant_id = $1
        "#,
    )
    .bind(&input.tenant_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(InvoiceError::Db)?
    .ok_or(InvoiceError::NoBillingAddress)?;

    let country = addr
        .country
        .clone()
        .filter(|value| !value.trim().is_empty())
        .ok_or(InvoiceError::NoBillingAddress)?;

    let invoice_number = generate_invoice_number_tx(tx).await?;

    // All lines on one invoice share the billing address, hence the same VAT
    // rate; compute it once from the full subtotal so per-line allocations
    // reconcile with the headline total (Fix I3).
    let mut line_amounts: Vec<i64> = Vec::with_capacity(input.line_items.len());
    for item in &input.line_items {
        let amount = item.quantity.checked_mul(item.unit_price).ok_or_else(|| {
            InvoiceError::PdfGeneration(format!(
                "line amount overflow: {} x {}",
                item.quantity, item.unit_price
            ))
        })?;
        line_amounts.push(amount);
    }
    let subtotal: i64 = line_amounts.iter().sum();
    // Reverse charge (0 %) requires authoritative VIES evidence for this VAT
    // number; a merely structural number charges the destination rate. The
    // evidence row id is snapshotted onto the invoice.
    let vat_evidence = match addr
        .vat_number
        .as_deref()
        .map(str::trim)
        .filter(|vat| !vat.is_empty())
    {
        Some(vat) => load_vat_evidence_in(&mut **tx, &input.tenant_id, vat).await,
        None => None,
    };
    let (vat_rate, _, vat_evidence_id) = calculate_vat_for_invoice(
        subtotal,
        &country,
        addr.vat_number.as_deref(),
        vat_evidence.as_ref(),
        Utc::now().date_naive(),
    );
    let vat_allocations = allocate_vat_across_lines(&line_amounts, vat_rate);

    let mut line_items = Vec::with_capacity(input.line_items.len());
    let mut vat_total: i64 = 0;

    for (item, vat_amount) in input.line_items.iter().zip(vat_allocations) {
        let amount = item.quantity * item.unit_price;
        vat_total += vat_amount;
        line_items.push(InvoiceLineItem {
            description: item.description.clone(),
            quantity: item.quantity,
            unit_price: item.unit_price,
            amount,
            vat_rate,
            vat_amount,
        });
    }

    let total = subtotal + vat_total;
    let now = Utc::now();
    let due_at = input
        .due_at
        .unwrap_or_else(|| now + chrono::Duration::days(30));
    let currency = input.currency.unwrap_or_else(|| "eur".into());
    let id = Uuid::new_v4();
    let items_json = encode_invoice_line_items(&line_items)?;
    // Immutable billing-address snapshot (audit F08). Stored as TEXT
    // (the column's type since migration 076) — versioned JSON (the
    // api-server admin writer snapshots the same contract). Null/empty
    // optional fields stay null: readers must NOT fill them from the live
    // account (F08: snapshot-vs-live is chosen once per invoice).
    let address_snapshot = serde_json::json!({
        "snapshotVersion": BILLING_ADDRESS_SNAPSHOT_VERSION,
        "company_name": addr.company_name,
        "vat_number": addr.vat_number,
        "address_line1": addr.address_line1,
        "address_line2": addr.address_line2,
        "city": addr.city,
        "state": addr.state,
        "postal_code": addr.postal_code,
        "country": addr.country,
        "email": addr.email,
        "registry_code": addr.registry_code,
    })
    .to_string();

    sqlx::query(
        r#"
        INSERT INTO invoices (
            id, tenant_id, stripe_invoice_id, invoice_number, status,
            currency, amount, subtotal, vat_total, total, line_items,
            issued_at, due_at, period_start, period_end,
            billing_country, vat_rate, overage_period, billing_address,
            billing_registry_code, vat_evidence_id,
            created_at, updated_at
        ) VALUES (
            $1, $2, $3, $4, 'draft',
            $5, $8, $6, $7, $8, $9,
            $10, $11, $12, $13,
            $14, $15, $16, $17,
            $18, $19,
            $10, $10
        )
        "#,
    )
    .bind(id)
    .bind(&input.tenant_id)
    .bind(&input.stripe_invoice_id)
    .bind(&invoice_number)
    .bind(&currency)
    .bind(subtotal)
    .bind(vat_total)
    .bind(total)
    .bind(&items_json)
    .bind(now)
    .bind(due_at)
    .bind(input.period_start)
    .bind(input.period_end)
    .bind(country.to_uppercase())
    .bind(vat_rate)
    .bind(input.overage_period)
    .bind(address_snapshot)
    .bind(addr.registry_code)
    .bind(vat_evidence_id)
    .execute(&mut **tx)
    .await
    .map_err(InvoiceError::Db)?;

    // Recognition ledger (migration 218): the general scheme recognises the
    // supply in the invoice's issue period; cash-accounting tenants
    // recognise on payment (or the third-month fallback) and deliberately
    // get no entry yet. KMD aggregates this ledger.
    crate::vat_recognition::materialize_invoice_recognition(
        tx,
        &crate::vat_recognition::InvoiceRecognitionInput {
            invoice_id: id,
            tenant_id: input.tenant_id.clone(),
            currency: currency.clone(),
            subtotal_cents: subtotal,
            vat_rate,
            vat_cents: vat_total,
            issued_at: now,
            paid_at: None,
            billing_country: Some(country.to_uppercase()),
        },
        now,
    )
    .await
    .map_err(InvoiceError::Recognition)?;

    Ok(Invoice {
        id,
        tenant_id: input.tenant_id,
        stripe_invoice_id: input.stripe_invoice_id,
        invoice_number,
        status: InvoiceStatus::Draft,
        currency,
        subtotal,
        vat_total,
        total,
        line_items,
        issued_at: now,
        due_at,
        paid_at: None,
        period_start: input.period_start,
        period_end: input.period_end,
        created_at: now,
        updated_at: now,
    })
}

/// Pure outstanding-balance derivation (audit F35):
/// `total − confirmed payments − valid credits`, saturating at zero —
/// refunds/over-credits can never push the balance below zero, and the
/// subtraction is checked so hostile inputs cannot wrap.
pub fn compute_outstanding(
    total_cents: i64,
    confirmed_payments_cents: i64,
    credits_cents: i64,
) -> i64 {
    total_cents
        .saturating_sub(confirmed_payments_cents.max(0))
        .saturating_sub(credits_cents.max(0))
        .max(0)
}

/// Durable outstanding balance for an invoice: total minus confirmed
/// payment allocations (migration 140) minus the DEBT-REDUCTION part of
/// credit notes (migration 183 — only that part reduces the unpaid
/// obligation; the refunded part returned value that was actually paid).
/// This is the single derivation UI, wallet application, Stripe
/// collection, dunning and credit limits must use (audits F35/F60).
pub async fn invoice_outstanding_cents(
    pool: &PgPool,
    invoice_id: Uuid,
) -> Result<i64, sqlx::Error> {
    let outstanding: i64 = sqlx::query_scalar(OUTSTANDING_ONE_SQL)
        .bind(invoice_id)
        .fetch_one(pool)
        .await?;
    Ok(outstanding.max(0))
}

/// Executor-generic variant of [`invoice_outstanding_cents`] for callers
/// inside a transaction (wallet application under the collection lock).
pub async fn invoice_outstanding_cents_in<'e, E>(
    executor: E,
    invoice_id: Uuid,
) -> Result<i64, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let outstanding: i64 = sqlx::query_scalar(OUTSTANDING_ONE_SQL)
        .bind(invoice_id)
        .fetch_one(executor)
        .await?;
    Ok(outstanding.max(0))
}

/// The one-invoice outstanding derivation shared by every caller
/// (audits F60/F73): the canonical amount resolver handles legacy
/// nullable `total` (pre-076 rows fall back to the NOT NULL `amount`),
/// subtracts confirmed payment allocations, then the debt-reduction part
/// of credit notes (legacy NULL split rows count their full amount, the
/// pre-183 behaviour), and clamps at zero.
///
/// `status = 'paid'` short-circuits to zero, exactly like
/// [`TENANT_OUTSTANDING_SQL`]: `paid` is the authority for FULL settlement,
/// so a paid invoice whose allocation rows are missing or partial has no
/// outstanding remainder. Without the short-circuit a settled invoice could
/// still report a balance on this surface while the tenant total said zero —
/// two answers to one question.
const OUTSTANDING_ONE_SQL: &str = r#"
    SELECT CASE
               WHEN i.status::text = 'paid' THEN 0
               ELSE GREATEST(
                   COALESCE(i.total, i.amount, 0)::bigint
                   - COALESCE(p.payments, 0)
                   - COALESCE(c.credit_debt, 0),
                   0)
           END
    FROM invoices i
    LEFT JOIN (
        SELECT invoice_id, SUM(amount_cents)::bigint AS payments
        FROM invoice_payment_allocations
        WHERE invoice_id = $1
        GROUP BY invoice_id
    ) p ON p.invoice_id = i.id
    LEFT JOIN (
        SELECT invoice_id,
               SUM(CASE WHEN debt_reduction_cents IS NULL
                        THEN amount ELSE debt_reduction_cents END)::bigint AS credit_debt
        FROM credit_notes
        WHERE invoice_id = $1
        GROUP BY invoice_id
    ) c ON c.invoice_id = i.id
    WHERE i.id = $1
"#;

/// Per-currency outstanding buckets for a tenant's WHOLE eligible invoice
/// set (audit F04): every invoice contributes its UNPAID REMAINDER —
/// `paid` is the authority for FULL settlement (a paid invoice with no
/// allocation rows still contributes zero), otherwise the obligation minus
/// the allocation ledger minus debt-reduction credits, clamped per invoice.
/// Allocations remain the authority for PARTIAL settlement, and the
/// aggregation is independent of any list pagination. Both
/// surfaces apply the same `paid -> 0` rule.
const TENANT_OUTSTANDING_SQL: &str = r#"
    SELECT i.currency,
           COALESCE(SUM(
               CASE
                   WHEN i.status::text = 'paid' THEN 0
                   ELSE GREATEST(
                       COALESCE(i.total, i.amount, 0)::bigint
                       - COALESCE(p.payments, 0)
                       - COALESCE(c.credit_debt, 0),
                       0
                   )
               END
           ), 0)::bigint
    FROM invoices i
    LEFT JOIN (
        SELECT invoice_id, SUM(amount_cents)::bigint AS payments
        FROM invoice_payment_allocations
        GROUP BY invoice_id
    ) p ON p.invoice_id = i.id
    LEFT JOIN (
        SELECT invoice_id,
               SUM(CASE WHEN debt_reduction_cents IS NULL
                        THEN amount ELSE debt_reduction_cents END)::bigint AS credit_debt
        FROM credit_notes
        GROUP BY invoice_id
    ) c ON c.invoice_id = i.id
    WHERE i.tenant_id = $1
      AND i.status::text NOT IN ('draft', 'void', 'uncollectible')
    GROUP BY i.currency
    ORDER BY i.currency
"#;

pub async fn tenant_outstanding_by_currency(
    pool: &PgPool,
    tenant_id: &str,
) -> Result<Vec<(String, i64)>, sqlx::Error> {
    sqlx::query_as(TENANT_OUTSTANDING_SQL)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
}

/// Generate a PDF for an invoice by calling the pdf-renderer service, upload
/// to object storage, and update the `pdf_url` column.
/// This is called automatically after `create_invoice` and can also be
/// called on-demand to re-generate a PDF for an existing invoice.
pub async fn generate_invoice_pdf(
    pool: &PgPool,
    http_client: &reqwest::Client,
    invoice: &Invoice,
) -> Result<String, InvoiceError> {
    // Sanitize user-supplied fields to prevent XSS injection into the PDF
    // template (BS-005).  The pdf-renderer service uses Typst which can
    // interpret HTML/XML-like syntax, so we escape the description and
    // invoice_number fields.
    let sanitized_line_items: Vec<serde_json::Value> = invoice
        .line_items
        .iter()
        .map(|item| {
            serde_json::json!({
                "description": escape_html(&item.description),
                "quantity": item.quantity,
                "unit_price": item.unit_price,
                "amount": item.amount,
                "vat_rate": item.vat_rate,
                "vat_amount": item.vat_amount,
            })
        })
        .collect();

    // Buyer identification is mandatory on a VAT invoice; pull the tenant's
    // billing address so the PDF carries it (previously rendered
    // "Customer details not available" on every stored invoice).
    let bill_to: Option<serde_json::Value> = sqlx::query_as::<
        _,
        (
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        ),
    >(
        "SELECT company_name, vat_number, address_line1, city, postal_code, country \
         FROM billing_addresses WHERE tenant_id = $1",
    )
    .bind(&invoice.tenant_id)
    .fetch_optional(pool)
    .await
    .map_err(InvoiceError::Db)?
    .map(|(company, vat, address, city, postal, country)| {
        let mut v = serde_json::Map::new();
        if let Some(company) = company.filter(|s| !s.is_empty()) {
            v.insert("company".into(), escape_html(&company).into());
        }
        if let Some(vat) = vat.filter(|s| !s.is_empty()) {
            v.insert("vat_number".into(), escape_html(&vat).into());
        }
        if let Some(address) = address.filter(|s| !s.is_empty()) {
            v.insert("address".into(), escape_html(&address).into());
        }
        if let Some(city) = city.filter(|s| !s.is_empty()) {
            v.insert("city".into(), escape_html(&city).into());
        }
        if let Some(postal) = postal.filter(|s| !s.is_empty()) {
            // fold postal code into the city line so the template stays simple
            let city_line = match v.get("city") {
                Some(c) => format!("{} {}", c.as_str().unwrap_or_default(), postal),
                None => postal,
            };
            v.insert("city".into(), escape_html(&city_line).into());
        }
        if let Some(country) = country.filter(|s| !s.is_empty()) {
            v.insert(
                "country".into(),
                escape_html(&country).to_uppercase().into(),
            );
        }
        serde_json::Value::Object(v)
    });

    // Seller identity and bank details come from configuration. The bank is
    // Wise; account identifiers are only rendered when actually configured,
    // never hardcoded placeholder values.
    let bank_iban = std::env::var("BILLING_COMPANY_IBAN").unwrap_or_default();
    let bank_bic = std::env::var("BILLING_COMPANY_BIC").unwrap_or_default();
    let bank_name = std::env::var("BILLING_COMPANY_BANK").unwrap_or_else(|_| "Wise".to_string());
    let bank = if bank_iban.is_empty() && bank_bic.is_empty() {
        serde_json::json!({ "name": bank_name })
    } else {
        serde_json::json!({ "name": bank_name, "iban": bank_iban, "bic": bank_bic })
    };

    let seller = serde_json::json!({
        "name": "Bel Consulting OÜ",
        "address": "Sakala 7-2, 10141 Tallinn, Estonia",
        "vat_number": "EE102951727",
        "registry_code": "16588745",
    });

    // Build the JSON payload expected by the invoice.typ template
    let pdf_data = serde_json::json!({
        "invoice_number": escape_html(&invoice.invoice_number),
        "status": format!("{:?}", invoice.status).to_lowercase(),
        "currency": invoice.currency.to_uppercase(),
        "issued_at": invoice.issued_at.format("%Y-%m-%d").to_string(),
        "due_at": invoice.due_at.format("%Y-%m-%d").to_string(),
        "paid_at": invoice.paid_at.map(|d| d.format("%Y-%m-%d").to_string()),
        "period_start": invoice.period_start.format("%Y-%m-%d").to_string(),
        "period_end": invoice.period_end.format("%Y-%m-%d").to_string(),
        "subtotal": invoice.subtotal,
        "vat_total": invoice.vat_total,
        "total": invoice.total,
        "line_items": sanitized_line_items,
        "seller": seller,
        "bank": bank,
        "bill_to": bill_to,
    });

    let render_request = serde_json::json!({
        "template": "invoice",
        "data": pdf_data,
    });

    // Call pdf-renderer service
    let mut request = http_client
        .post(format!("{}/v1/pdf/render", pdf_renderer_url()))
        .json(&render_request)
        .timeout(std::time::Duration::from_secs(30));
    // pdf-renderer requires the shared internal service token; only attach
    // the header when one is configured (empty token would 401 anyway).
    let service_token = std::env::var("INTERNAL_SERVICE_TOKEN").unwrap_or_default();
    if !service_token.is_empty() {
        request = request.header("x-api-key", service_token);
    }
    let resp = request
        .send()
        .await
        .map_err(|e| InvoiceError::PdfGeneration(format!("HTTP request failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(InvoiceError::PdfGeneration(format!(
            "pdf-renderer returned {status}: {body}"
        )));
    }

    let pdf_bytes = resp
        .bytes()
        .await
        .map_err(|e| InvoiceError::PdfGeneration(format!("Failed to read PDF bytes: {e}")))?;

    // Construct S3/R2 object key
    let pdf_key = format!(
        "invoices/{}/{}.pdf",
        invoice.tenant_id, invoice.invoice_number
    );

    // Upload to S3/R2 object storage
    let pdf_url = s3_put_object(http_client, &pdf_key, &pdf_bytes, "application/pdf").await?;

    // Update the invoice record with the PDF URL
    sqlx::query("UPDATE invoices SET pdf_url = $1, updated_at = NOW() WHERE id = $2")
        .bind(&pdf_url)
        .bind(invoice.id)
        .execute(pool)
        .await
        .map_err(InvoiceError::Db)?;

    tracing::info!(
        invoice_id = %invoice.id,
        invoice_number = %invoice.invoice_number,
        pdf_size = pdf_bytes.len(),
        pdf_url = %pdf_url,
        "Invoice PDF generated and stored"
    );

    Ok(pdf_url)
}

/// List invoices for a tenant with pagination.
pub async fn list_invoices(
    pool: &PgPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<Invoice>, InvoiceError> {
    let rows: Vec<InvoiceRow> = sqlx::query_as(
        r#"
        SELECT
            id, tenant_id, stripe_invoice_id, invoice_number,
            status, currency, subtotal, vat_total, total,
            line_items,
            issued_at, due_at, paid_at,
            period_start, period_end,
            created_at, updated_at
        FROM invoices
        WHERE tenant_id = $1
        ORDER BY issued_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(InvoiceError::Db)?;

    Ok(rows.into_iter().map(|r| r.into_invoice()).collect())
}

/// Fetch a single invoice by ID.
pub async fn get_invoice_by_id(
    pool: &PgPool,
    invoice_id: Uuid,
) -> Result<Option<Invoice>, InvoiceError> {
    let row: Option<InvoiceRow> = sqlx::query_as(
        r#"
        SELECT
            id, tenant_id, stripe_invoice_id, invoice_number,
            status, currency, subtotal, vat_total, total,
            line_items,
            issued_at, due_at, paid_at,
            period_start, period_end,
            created_at, updated_at
        FROM invoices
        WHERE id = $1
        "#,
    )
    .bind(invoice_id)
    .fetch_optional(pool)
    .await
    .map_err(InvoiceError::Db)?;

    Ok(row.map(|r| r.into_invoice()))
}

// ---------------------------------------------------------------------------
// Internal row mapping
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct InvoiceRow {
    id: Uuid,
    tenant_id: String,
    stripe_invoice_id: Option<String>,
    invoice_number: String,
    status: String,
    currency: String,
    subtotal: i64,
    vat_total: i64,
    total: i64,
    line_items: Option<serde_json::Value>,
    issued_at: DateTime<Utc>,
    due_at: DateTime<Utc>,
    paid_at: Option<DateTime<Utc>>,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredInvoiceLineItems {
    schema_version: u32,
    items: Vec<InvoiceLineItem>,
}

fn encode_invoice_line_items(
    line_items: &[InvoiceLineItem],
) -> Result<serde_json::Value, InvoiceError> {
    serde_json::to_value(StoredInvoiceLineItems {
        schema_version: INVOICE_LINE_ITEMS_SCHEMA_VERSION,
        items: line_items.to_vec(),
    })
    .map_err(InvoiceError::from)
}

fn decode_invoice_line_items(value: serde_json::Value) -> Vec<InvoiceLineItem> {
    if let Ok(versioned) = serde_json::from_value::<StoredInvoiceLineItems>(value.clone()) {
        return versioned.items;
    }

    serde_json::from_value(value).unwrap_or_default()
}

impl InvoiceRow {
    fn into_invoice(self) -> Invoice {
        let status = match self.status.as_str() {
            "paid" => InvoiceStatus::Paid,
            "pending" => InvoiceStatus::Pending,
            "void" => InvoiceStatus::Void,
            "uncollectible" => InvoiceStatus::Uncollectible,
            _ => InvoiceStatus::Draft,
        };

        let line_items = self
            .line_items
            .map(decode_invoice_line_items)
            .unwrap_or_default();

        Invoice {
            id: self.id,
            tenant_id: self.tenant_id,
            stripe_invoice_id: self.stripe_invoice_id,
            invoice_number: self.invoice_number,
            status,
            currency: self.currency,
            subtotal: self.subtotal,
            vat_total: self.vat_total,
            total: self.total,
            line_items,
            issued_at: self.issued_at,
            due_at: self.due_at,
            paid_at: self.paid_at,
            period_start: self.period_start,
            period_end: self.period_end,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum InvoiceError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("billing address not found for tenant")]
    NoBillingAddress,
    #[error("PDF generation error: {0}")]
    PdfGeneration(String),
    #[error("VAT recognition error: {0}")]
    Recognition(String),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn require_config_value(name: &str, value: Option<String>) -> Result<String, InvoiceError> {
    let Some(value) = value else {
        return Err(InvoiceError::PdfGeneration(format!(
            "{name} must be set for invoice PDF upload"
        )));
    };

    if value.trim().is_empty() {
        return Err(InvoiceError::PdfGeneration(format!(
            "{name} must be set for invoice PDF upload"
        )));
    }

    Ok(value)
}

fn s3_credentials() -> Result<(String, String), InvoiceError> {
    let access_key =
        require_config_value("S3_ACCESS_KEY_ID", std::env::var("S3_ACCESS_KEY_ID").ok())?;
    let secret_key = require_config_value(
        "S3_SECRET_ACCESS_KEY",
        std::env::var("S3_SECRET_ACCESS_KEY").ok(),
    )?;
    Ok((access_key, secret_key))
}

fn new_hmac_sha256(key: &[u8]) -> Result<HmacSha256, InvoiceError> {
    HmacSha256::new_from_slice(key).map_err(|e| {
        InvoiceError::PdfGeneration(format!("failed to initialize S3 signing key: {e}"))
    })
}

// ---------------------------------------------------------------------------
// S3-compatible upload (AWS Signature V4)
// ---------------------------------------------------------------------------

/// The HTTP target for one S3 object PUT: the URL to call, the `Host` header
/// value (which must match the URL authority for Sig V4) and the canonical
/// URI that gets signed.
#[derive(Debug, PartialEq, Eq)]
struct S3ObjectTarget {
    url: String,
    host: String,
    canonical_uri: String,
}

/// Resolve the request target for `bucket`/`key`.
///
/// * No configured endpoint (the historical default): AWS virtual-hosted
///   style, `https://{bucket}.{S3_DEFAULT_HOST}/{key}`.
/// * A configured endpoint: its scheme, host (including port) and path
///   prefix are honoured verbatim and `bucket`/`key` are appended path-style —
///   `{scheme}://{host}{prefix}/{bucket}/{key}`. The old code hard-coded
///   `https://` and dropped any path prefix, so a local HTTP S3-compatible
///   mock was unreachable (and untestable) even though it was configured.
fn s3_object_target(
    endpoint: Option<&str>,
    bucket: &str,
    key: &str,
) -> Result<S3ObjectTarget, InvoiceError> {
    let Some(endpoint) = endpoint.map(str::trim).filter(|value| !value.is_empty()) else {
        let host = format!("{bucket}.{S3_DEFAULT_HOST}");
        return Ok(S3ObjectTarget {
            url: format!("https://{host}/{key}"),
            host,
            canonical_uri: format!("/{key}"),
        });
    };

    let (scheme, remainder) = endpoint.split_once("://").ok_or_else(|| {
        InvoiceError::PdfGeneration(format!(
            "S3_ENDPOINT {endpoint:?} must include an explicit scheme (http:// or https://)"
        ))
    })?;
    if scheme != "http" && scheme != "https" {
        return Err(InvoiceError::PdfGeneration(format!(
            "S3_ENDPOINT {endpoint:?} uses unsupported scheme {scheme:?} (expected http or https)"
        )));
    }
    let remainder = remainder.trim_end_matches('/');
    let (authority, prefix) = match remainder.split_once('/') {
        Some((authority, prefix)) => (authority, format!("/{}", prefix.trim_matches('/'))),
        None => (remainder, String::new()),
    };
    if authority.is_empty() {
        return Err(InvoiceError::PdfGeneration(format!(
            "S3_ENDPOINT {endpoint:?} has an empty host"
        )));
    }

    let canonical_uri = format!("{prefix}/{bucket}/{key}");
    Ok(S3ObjectTarget {
        url: format!("{scheme}://{authority}{canonical_uri}"),
        host: authority.to_string(),
        canonical_uri,
    })
}

/// Upload bytes to S3-compatible object storage using AWS Signature V4.
async fn s3_put_object(
    http_client: &reqwest::Client,
    key: &str,
    body: &[u8],
    content_type: &str,
) -> Result<String, InvoiceError> {
    let bucket = s3_bucket();
    let region = s3_region();
    let (access_key, secret_key) = s3_credentials()?;
    let endpoint = s3_endpoint();
    let target = s3_object_target(endpoint.as_deref(), &bucket, key)?;
    let host = &target.host;
    let canonical_uri = &target.canonical_uri;

    let now = Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

    // SHA-256 of request body
    let payload_hash = hex_encode(&Sha256::digest(body));

    // Canonical headers (must be sorted)
    let canonical_headers = format!(
        "content-type:{content_type}\nhost:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
    );
    let signed_headers = "content-type;host;x-amz-content-sha256;x-amz-date";

    // Canonical request
    let canonical_request =
        format!("PUT\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");

    // String to sign
    let credential_scope = format!("{date_stamp}/{region}/s3/aws4_request");
    let canonical_hash = hex_encode(&Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{canonical_hash}");

    // Derive signing key:HMAC chain date → region → service → aws4_request
    let k_date = new_hmac_sha256(format!("AWS4{secret_key}").as_bytes())?
        .chain_update(date_stamp.as_bytes())
        .finalize()
        .into_bytes();
    let k_region = new_hmac_sha256(&k_date)?
        .chain_update(region.as_bytes())
        .finalize()
        .into_bytes();
    let k_service = new_hmac_sha256(&k_region)?
        .chain_update(b"s3")
        .finalize()
        .into_bytes();
    let k_signing = new_hmac_sha256(&k_service)?
        .chain_update(b"aws4_request")
        .finalize()
        .into_bytes();

    // Final signature
    let signature = hex_encode(
        &new_hmac_sha256(&k_signing)?
            .chain_update(string_to_sign.as_bytes())
            .finalize()
            .into_bytes(),
    );

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, \
         SignedHeaders={signed_headers}, Signature={signature}"
    );

    let url = target.url;

    let resp = http_client
        .put(&url)
        .header("Host", host)
        .header("Content-Type", content_type)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", &payload_hash)
        .header("Authorization", &authorization)
        .body(body.to_vec())
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .await
        .map_err(|e| InvoiceError::PdfGeneration(format!("S3 upload failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let err_body = resp.text().await.unwrap_or_default();
        return Err(InvoiceError::PdfGeneration(format!(
            "S3 upload returned {status}: {err_body}"
        )));
    }

    // Return public URL
    let public_url = match s3_public_url() {
        Some(base) => format!("{}/{key}", base.trim_end_matches('/')),
        None => url,
    };

    Ok(public_url)
}

/// Hex-encode a byte slice to a lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    use billing_common::vat_rates;

    #[test]
    fn missing_required_config_returns_typed_error() {
        let err = require_config_value("S3_ACCESS_KEY_ID", None).unwrap_err();
        assert_eq!(
            err.to_string(),
            "PDF generation error: S3_ACCESS_KEY_ID must be set for invoice PDF upload"
        );
    }

    #[test]
    fn blank_required_config_returns_typed_error() {
        let err = require_config_value("S3_SECRET_ACCESS_KEY", Some("   ".into())).unwrap_err();
        assert_eq!(
            err.to_string(),
            "PDF generation error: S3_SECRET_ACCESS_KEY must be set for invoice PDF upload"
        );
    }

    #[test]
    fn required_config_accepts_present_values() {
        let value = require_config_value("S3_ACCESS_KEY_ID", Some("access-key".into())).unwrap();
        assert_eq!(value, "access-key");
    }

    #[test]
    fn vat_estonia_always_charged() {
        let (rate, amt) = calculate_vat(10_000, "EE", None);
        assert_eq!(rate, 24.0);
        assert_eq!(amt, 2_400); // 24 % of 10 000
    }

    // ------------------------------------------------------------------
    // Fix I3 — per-line VAT rounding must reconcile with the rounded total.
    // ------------------------------------------------------------------

    #[test]
    fn allocate_vat_lines_sums_to_total_rounded_vat() {
        // Three lines of 3 cents each at 24 %: per-line rounding gives
        // 1+1+1 = 3, but round(9 * 24%) = 2. The last line absorbs the -1.
        let allocated = allocate_vat_across_lines(&[3, 3, 3], 24.0);

        assert_eq!(allocated, vec![1, 1, 0]);
        assert_eq!(allocated.iter().sum::<i64>(), ((3 + 3 + 3) * 24 + 50) / 100);
    }

    #[test]
    fn allocate_vat_lines_absorbs_plus_one_cent_drift() {
        // Lines of 1 cent at 24 %: each line rounds to 0, but the total
        // rounds to 1 — the final line is adjusted up by +1.
        let allocated = allocate_vat_across_lines(&[1, 1, 1], 24.0);

        assert_eq!(allocated, vec![0, 0, 1]);
        assert_eq!(allocated.iter().sum::<i64>(), ((1 + 1 + 1) * 24 + 50) / 100);
    }

    #[test]
    fn allocate_vat_lines_exact_rounding_needs_no_adjustment() {
        let allocated = allocate_vat_across_lines(&[10_000, 5_000], 24.0);

        // Exact per-line rounding already reconciles — no drift to absorb.
        assert_eq!(
            allocated,
            vec![(10_000 * 24 + 50) / 100, (5_000 * 24 + 50) / 100]
        );
    }

    #[test]
    fn allocate_vat_lines_zero_rate_and_empty_inputs() {
        assert!(allocate_vat_across_lines(&[], 24.0).is_empty());
        assert_eq!(allocate_vat_across_lines(&[100, 200], 0.0), vec![0, 0]);
    }

    #[test]
    fn allocate_vat_lines_adjusts_last_nonzero_line_only() {
        // A trailing zero-amount line must not receive the reconciliation
        // adjustment; the last *non-zero* line absorbs it instead.
        let allocated = allocate_vat_across_lines(&[3, 3, 3, 0], 24.0);

        assert_eq!(allocated, vec![1, 1, 0, 0]);
        assert_eq!(allocated.iter().sum::<i64>(), 2);
    }

    #[test]
    fn vat_eu_b2b_reverse_charge_requires_evidence() {
        // No VIES evidence: a well-formed DE VAT number charges the
        // destination rate (structurally valid is not evidence).
        let (rate, amt) = calculate_vat(10_000, "DE", Some("DE123456789"));
        assert_eq!(rate, 19.0);
        assert_eq!(amt, 1_900);

        // With valid, in-force evidence the same invoice reverse-charges,
        // and the writer returns the evidence id to snapshot.
        let evidence = VatValidationEvidence {
            id: Some(Uuid::new_v4()),
            vat_number: "DE123456789".into(),
            country: "DE".into(),
            source: vat_rates::VatValidationSource::Vies,
            outcome: vat_rates::VatValidationOutcome::Valid,
            valid_from: chrono::NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(),
            valid_until: None,
            outage_state: None,
        };
        let (rate, amount, evidence_id) = calculate_vat_for_invoice(
            10_000,
            "DE",
            Some("DE123456789"),
            Some(&evidence),
            chrono::NaiveDate::from_ymd_opt(2026, 6, 1).unwrap(),
        );
        assert_eq!(rate, 0.0);
        assert_eq!(amount, 0);
        assert_eq!(evidence_id, evidence.id);
    }

    #[test]
    fn vat_eu_b2c_charged() {
        let (rate, amt) = calculate_vat(10_000, "FR", None);
        // France standard VAT rate is 20% (destination-based)
        assert_eq!(rate, 20.0);
        assert_eq!(amt, 2_000);
    }

    #[test]
    fn vat_non_eu_zero() {
        let (rate, amt) = calculate_vat(50_000, "US", None);
        assert_eq!(rate, 0.0);
        assert_eq!(amt, 0);
    }

    #[test]
    fn invoice_row_status_mapping() {
        let row = InvoiceRow {
            id: Uuid::new_v4(),
            tenant_id: "tenant_01HZY2Q4YQ0L8QW8Q7Q28WKSFJ".into(),
            stripe_invoice_id: None,
            invoice_number: "2026-000001".into(),
            status: "paid".into(),
            currency: "eur".into(),
            subtotal: 1000,
            vat_total: 240,
            total: 1240,
            line_items: Some(serde_json::json!([])),
            issued_at: Utc::now(),
            due_at: Utc::now(),
            paid_at: Some(Utc::now()),
            period_start: Utc::now(),
            period_end: Utc::now(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let inv = row.into_invoice();
        assert_eq!(inv.status, InvoiceStatus::Paid);
    }

    #[test]
    fn invoice_row_decodes_legacy_line_items_array() {
        let line_items = vec![InvoiceLineItem {
            description: "Monthly plan".into(),
            quantity: 1,
            unit_price: 1000,
            amount: 1000,
            vat_rate: 24.0,
            vat_amount: 240,
        }];

        let decoded = decode_invoice_line_items(serde_json::to_value(&line_items).unwrap());

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].description, "Monthly plan");
        assert_eq!(decoded[0].amount, 1000);
    }

    #[test]
    fn invoice_row_decodes_versioned_line_items_wrapper() {
        let encoded = encode_invoice_line_items(&[InvoiceLineItem {
            description: "Extra seats".into(),
            quantity: 2,
            unit_price: 500,
            amount: 1000,
            vat_rate: 0.0,
            vat_amount: 0,
        }])
        .expect("versioned invoice line items should serialize");

        let decoded = decode_invoice_line_items(encoded);

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].description, "Extra seats");
        assert_eq!(decoded[0].quantity, 2);
    }

    #[test]
    fn encode_invoice_line_items_includes_schema_version() {
        let encoded =
            encode_invoice_line_items(&[]).expect("empty invoice line items should serialize");

        assert_eq!(
            encoded["schemaVersion"],
            serde_json::json!(INVOICE_LINE_ITEMS_SCHEMA_VERSION)
        );
        assert_eq!(encoded["items"], serde_json::json!([]));
    }

    #[test]
    fn hex_encode_works() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0xab]), "00ffab");
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    // ------------------------------------------------------------------
    // Bug 3 — the object target follows the CONFIGURED endpoint.
    // ------------------------------------------------------------------

    #[test]
    fn s3_target_defaults_to_aws_virtual_hosted_style() {
        // No endpoint configured: the historical behaviour is preserved —
        // virtual-hosted AWS over https.
        let target = s3_object_target(None, "apexmail-invoices", "invoices/t/2026-000001.pdf")
            .expect("default target");

        assert_eq!(
            target.url,
            "https://apexmail-invoices.s3.eu-central-1.amazonaws.com/invoices/t/2026-000001.pdf"
        );
        assert_eq!(
            target.host,
            "apexmail-invoices.s3.eu-central-1.amazonaws.com"
        );
        assert_eq!(target.canonical_uri, "/invoices/t/2026-000001.pdf");
    }

    #[test]
    fn s3_target_honours_configured_endpoint_scheme_host_and_prefix() {
        // A local http mock: the scheme and the port must survive verbatim,
        // and bucket/key are appended path-style.
        let target = s3_object_target(Some("http://127.0.0.1:9000"), "bucket", "k/a.pdf")
            .expect("local endpoint");
        assert_eq!(target.url, "http://127.0.0.1:9000/bucket/k/a.pdf");
        assert_eq!(target.host, "127.0.0.1:9000");
        assert_eq!(target.canonical_uri, "/bucket/k/a.pdf");

        // A path prefix on the endpoint is preserved (trailing slash and
        // all), never dropped on the floor.
        let target = s3_object_target(
            Some("https://storage.example.com/prefix/"),
            "bucket",
            "k/a.pdf",
        )
        .expect("prefixed endpoint");
        assert_eq!(
            target.url,
            "https://storage.example.com/prefix/bucket/k/a.pdf"
        );
        assert_eq!(target.host, "storage.example.com");
        assert_eq!(target.canonical_uri, "/prefix/bucket/k/a.pdf");
    }

    #[test]
    fn s3_target_refuses_endpoints_without_a_usable_scheme() {
        for endpoint in ["127.0.0.1:9000", "ftp://storage.example.com", "http://"] {
            let error = s3_object_target(Some(endpoint), "bucket", "k/a.pdf")
                .expect_err("unusable endpoint must be refused");
            assert!(
                error.to_string().contains("S3_ENDPOINT"),
                "{endpoint}: {error}"
            );
        }
    }

    // ------------------------------------------------------------------
    // Audits F60/F04/F73 — ONE outstanding derivation, allocation-ledger
    // aware, subtracting only the DEBT-REDUCTION part of credit notes and
    // resolving legacy nullable totals canonically.
    // ------------------------------------------------------------------

    #[test]
    fn outstanding_sql_subtracts_allocations_and_debt_reduction_credits_only() {
        // Legacy nullable totals resolve canonically...
        assert!(OUTSTANDING_ONE_SQL.contains("COALESCE(i.total, i.amount, 0)"));
        // ...confirmed payment allocations are subtracted...
        assert!(OUTSTANDING_ONE_SQL.contains("p.payments"));
        // ...and credit notes contribute ONLY their debt-reduction part
        // (legacy NULL split rows count their full amount).
        assert!(OUTSTANDING_ONE_SQL.contains("CASE WHEN debt_reduction_cents IS NULL"));
        assert!(OUTSTANDING_ONE_SQL.contains("THEN amount ELSE debt_reduction_cents END"));
        // Saturating at zero happens in Rust (`.max(0)`), never a negative
        // balance.
    }

    #[test]
    fn tenant_outstanding_aggregates_the_whole_set_by_currency_bucket() {
        // The shared per-tenant aggregation must consult the allocation
        // ledger and the credit-note debt-reduction split, group by
        // currency, and clamp each invoice's balance at zero (audit F04:
        // whole eligible set, distinct buckets, never a negative sum).
        assert!(TENANT_OUTSTANDING_SQL.contains("GROUP BY i.currency"));
        assert!(TENANT_OUTSTANDING_SQL.contains("invoice_payment_allocations"));
        assert!(TENANT_OUTSTANDING_SQL.contains("debt_reduction_cents"));
        assert!(TENANT_OUTSTANDING_SQL.contains("GREATEST("));
        // Draft/void/uncollectible invoices are not collectible debt.
        assert!(TENANT_OUTSTANDING_SQL.contains("NOT IN ('draft', 'void', 'uncollectible')"));
        // An invoice is outstanding by its UNPAID remainder. Allocations are
        // the authority for PARTIAL settlement (total − allocated), but a
        // `paid` invoice is fully settled by its status: a paid invoice that
        // carries NO allocation rows (e.g. settled out-of-band) contributes
        // zero, not its full total. The earlier assertion that the SQL must
        // NOT mention 'paid' pinned the defect this test now guards.
        assert!(TENANT_OUTSTANDING_SQL.contains("i.status::text = 'paid'"));
        assert!(TENANT_OUTSTANDING_SQL.contains("THEN 0"));
    }

    /// Verify that all 27 EU member states have a defined VAT rate in
    /// EU_VAT_RATES and are listed in EU_COUNTRIES.
    #[test]
    fn test_all_eu_countries_have_vat_rates() {
        let expected: [(&str, f64); 27] = [
            ("AT", 20.0),
            ("BE", 21.0),
            ("BG", 20.0),
            ("HR", 25.0),
            ("CY", 19.0),
            ("CZ", 21.0),
            ("DK", 25.0),
            ("EE", 24.0),
            ("FI", 25.5),
            ("FR", 20.0),
            ("DE", 19.0),
            ("GR", 24.0),
            ("HU", 27.0),
            ("IE", 23.0),
            ("IT", 22.0),
            ("LV", 21.0),
            ("LT", 21.0),
            ("LU", 17.0),
            ("MT", 18.0),
            ("NL", 21.0),
            ("PL", 23.0),
            ("PT", 23.0),
            ("RO", 19.0),
            ("SK", 23.0),
            ("SI", 22.0),
            ("ES", 21.0),
            ("SE", 25.0),
        ];

        // Initially EU_VAT_RATES is empty by default (env var not set),
        // so force-load defaults by dropping and re-initialising.
        // We check the static directly in the default-loaded state.
        for (code, _expected_rate) in &expected {
            assert!(
                vat_rates::EU_COUNTRIES.contains(&code.to_string()),
                "Country {code} missing from EU_COUNTRIES"
            );
        }

        // Verify EU_VAT_RATES has all 27 countries with correct rates
        // by testing calculate_vat which reads from EU_VAT_RATES.
        for (code, expected_rate) in &expected {
            let (rate, _) = calculate_vat(10000, code, None);
            assert_eq!(
                rate, *expected_rate,
                "Country {code} should have VAT rate {expected_rate}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Adversarial coverage tests (DB backed) for invoice writing: VAT evidence,
// numbering, outstanding aggregation, address requirements, and the PDF
// pipeline's escaping + failure reporting.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod coverage_adversarial {
    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use std::sync::Arc;
    use std::time::Duration;

    struct Env {
        pool: PgPool,
        db_name: String,
        admin_url: String,
    }

    impl Env {
        async fn finish(self) {
            self.pool.close().await;
            if let Ok(admin) = PgPoolOptions::new()
                .max_connections(1)
                .connect(&self.admin_url)
                .await
            {
                let _ = sqlx::query(&format!(
                    r#"DROP DATABASE IF EXISTS "{}" WITH (FORCE)"#,
                    self.db_name
                ))
                .execute(&admin)
                .await;
                admin.close().await;
            }
        }
    }

    async fn provision(test_name: &str) -> Option<Env> {
        let url = std::env::var("TEST_DATABASE_URL")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())?;
        let (server_part, db_part) = url.rsplit_once('/').expect("db segment");
        let db_only = db_part.split('?').next().unwrap_or(db_part);
        let mut digest: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in test_name.bytes() {
            digest ^= u64::from(byte);
            digest = digest.wrapping_mul(0x0000_0100_0000_01b3);
        }
        let db_name = format!("{db_only}_ivcov_{:08x}", digest & 0xffff_ffff);

        let admin_url = std::env::var("TEST_DATABASE_ADMIN_URL")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| format!("{server_part}/postgres"));
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(30))
            .connect(&admin_url)
            .await
            .expect("admin connect");

        let migrations_dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
        let mut count = 0_usize;
        let mut newest = 0_i64;
        for entry in std::fs::read_dir(&migrations_dir).expect("migrations dir") {
            let name = entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .to_string();
            if let Some(prefix) = name.split('_').next() {
                if let Ok(version) = prefix.parse::<i64>() {
                    count += 1;
                    newest = newest.max(version);
                }
            }
        }
        let template: Option<String> = sqlx::query_scalar(
            "SELECT datname FROM pg_database WHERE datname LIKE $1 ORDER BY datname DESC LIMIT 1",
        )
        .bind(format!("apexmail_canonical_tpl_{count}_{newest}_%"))
        .fetch_optional(&admin)
        .await
        .expect("template lookup");
        let template = template.expect("canonical template database must exist");

        sqlx::query(&format!(
            r#"DROP DATABASE IF EXISTS "{}" WITH (FORCE)"#,
            db_name
        ))
        .execute(&admin)
        .await
        .expect("drop test db");
        sqlx::query(&format!(
            r#"CREATE DATABASE "{}" TEMPLATE "{}""#,
            db_name, template
        ))
        .execute(&admin)
        .await
        .expect("clone test db");
        admin.close().await;

        let database_url = format!("{server_part}/{db_name}");
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(10))
            .connect(&database_url)
            .await
            .expect("connect test db");
        Some(Env {
            pool,
            db_name,
            admin_url,
        })
    }

    macro_rules! env_test {
        ($name:ident, |$e:ident| $body:block) => {
            #[tokio::test]
            async fn $name() {
                let Some(owned) = provision(stringify!($name)).await else {
                    return;
                };
                let $e = &owned;
                $body
                owned.finish().await;
            }
        };
    }

    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[derive(Clone, Debug)]
    struct RecordedCall {
        method: String,
        path: String,
        headers: std::collections::HashMap<String, String>,
        body: String,
    }

    #[derive(Clone, Default)]
    struct Mock {
        responses: Arc<std::sync::Mutex<std::collections::HashMap<String, (u16, String)>>>,
        calls: Arc<std::sync::Mutex<Vec<RecordedCall>>>,
    }

    impl Mock {
        fn route(&self, path: &str, status: u16, body: impl Into<String>) {
            self.responses
                .lock()
                .expect("lock")
                .insert(path.to_string(), (status, body.into()));
        }

        fn last_call(&self, path: &str) -> Option<RecordedCall> {
            self.calls
                .lock()
                .expect("lock")
                .iter()
                .rev()
                .find(|call| call.path == path)
                .cloned()
        }

        fn last_body(&self, path: &str) -> Option<String> {
            self.last_call(path).map(|call| call.body)
        }
    }

    async fn mock_handler(
        axum::extract::State(mock): axum::extract::State<Mock>,
        request: axum::http::Request<axum::body::Body>,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        let method = request.method().to_string();
        let path = request.uri().path().to_string();
        let headers = request
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        let body = axum::body::to_bytes(request.into_body(), usize::MAX)
            .await
            .unwrap_or_default();
        let (status, response_body) = mock
            .responses
            .lock()
            .expect("lock")
            .get(&path)
            .cloned()
            .unwrap_or_else(|| (404, "{}".to_string()));
        mock.calls.lock().expect("lock").push(RecordedCall {
            method,
            path,
            headers,
            body: String::from_utf8_lossy(&body).to_string(),
        });
        (
            axum::http::StatusCode::from_u16(status).expect("status"),
            [(axum::http::header::CONTENT_TYPE, "application/pdf")],
            response_body,
        )
            .into_response()
    }

    async fn spawn_mock(mock: Mock) -> String {
        let app = axum::Router::new().fallback(mock_handler).with_state(mock);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}")
    }

    async fn seed_tenant(env: &Env, tenant: &str) {
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status) VALUES ($1, $2, 'growth', 'active')
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant)
        .bind(format!("Coverage {tenant}"))
        .execute(&env.pool)
        .await
        .expect("seed tenant");
    }

    async fn seed_address(env: &Env, tenant: &str, country: &str, vat: Option<&str>) {
        sqlx::query(
            "INSERT INTO billing_addresses (tenant_id, country, vat_number) VALUES ($1, $2, $3)
             ON CONFLICT (tenant_id) DO UPDATE SET country = EXCLUDED.country,
                 vat_number = EXCLUDED.vat_number",
        )
        .bind(tenant)
        .bind(country)
        .bind(vat)
        .execute(&env.pool)
        .await
        .expect("seed address");
    }

    async fn insert_evidence(
        env: &Env,
        tenant: &str,
        vat: &str,
        valid: bool,
        outage: Option<&str>,
    ) {
        sqlx::query(
            "INSERT INTO vat_validation_evidence
                 (tenant_id, vat_number, country, source, requested_at, valid,
                  response_hash, valid_from, valid_until, outage_state)
             VALUES ($1, $2, 'DE', 'VIES', NOW(), $3, 'hash-cov', CURRENT_DATE, NULL, $4)",
        )
        .bind(tenant)
        .bind(vat)
        .bind(valid)
        .bind(outage)
        .execute(&env.pool)
        .await
        .expect("seed evidence");
    }

    fn line(description: &str, quantity: i64, unit_price: i64) -> NewLineItem {
        NewLineItem {
            description: description.to_string(),
            quantity,
            unit_price,
        }
    }

    fn input(tenant: &str) -> CreateInvoiceInput {
        let now = Utc::now();
        CreateInvoiceInput {
            tenant_id: tenant.to_string(),
            stripe_invoice_id: None,
            line_items: vec![line("Coverage line", 1, 10_000)],
            period_start: now,
            period_end: now,
            due_at: None,
            currency: Some("eur".into()),
            overage_period: None,
        }
    }

    env_test!(vat_evidence_lookup_normalizes_and_fails_closed, |env| {
        let tenant = "ivcov_evidence";
        seed_tenant(env, tenant).await;
        insert_evidence(env, tenant, "DE123 456 789", true, None).await;

        // Spacing/case-insensitive match on the authoritative row.
        let evidence = load_vat_evidence_for_tenant(&env.pool, tenant, "de123456789")
            .await
            .expect("evidence");
        assert_eq!(evidence.country, "DE");
        assert_eq!(
            evidence.outcome,
            billing_common::vat_rates::VatValidationOutcome::Valid
        );

        // Unknown number/tenant: no evidence, so normal VAT is charged.
        assert!(
            load_vat_evidence_for_tenant(&env.pool, tenant, "DE999999999")
                .await
                .is_none()
        );
        assert!(
            load_vat_evidence_for_tenant(&env.pool, "ivcov_absent", "DE123456789")
                .await
                .is_none()
        );

        // An outage is recorded as evidence but never as validity.
        let outage_tenant = "ivcov_evidence_outage";
        seed_tenant(env, outage_tenant).await;
        insert_evidence(env, outage_tenant, "DE555555555", false, Some("VIES down")).await;
        let evidence = load_vat_evidence_for_tenant(&env.pool, outage_tenant, "DE555555555")
            .await
            .expect("outage evidence");
        assert_eq!(
            evidence.outcome,
            billing_common::vat_rates::VatValidationOutcome::Outage
        );
    });

    env_test!(invoice_numbers_are_monotonic_and_zero_padded, |env| {
        let first = generate_invoice_number(&env.pool).await.expect("first");
        let second = generate_invoice_number(&env.pool).await.expect("second");
        let year = Utc::now().format("%Y").to_string();
        assert!(first.starts_with(&format!("{year}-")), "{first}");
        assert_eq!(first.len(), year.len() + 7);
        let first_seq: i64 = first.split('-').nth(1).expect("seq").parse().expect("num");
        let second_seq: i64 = second.split('-').nth(1).expect("seq").parse().expect("num");
        assert_eq!(second_seq, first_seq + 1, "numbers never repeat");
    });

    env_test!(
        tenant_outstanding_groups_by_currency_and_ignores_settled,
        |env| {
            let tenant = "ivcov_outstanding";
            seed_tenant(env, tenant).await;
            // Pending EUR and USD invoices plus a draft and a paid one. The
            // paid row deliberately has NO allocation rows: `paid` is the
            // authority for FULL settlement, so it must net to zero through
            // its status alone (the previous campaign's defect was this row
            // inflating the bucket by its full total).
            for (status, currency, total) in [
                ("pending", "EUR", 5000_i64),
                ("pending", "EUR", 2500),
                ("overdue", "USD", 700),
                ("draft", "EUR", 9999),
                ("paid", "EUR", 1111),
                ("void", "USD", 4444),
            ] {
                sqlx::query(
                    "INSERT INTO invoices (id, tenant_id, amount, currency, status, invoice_number,
                                       subtotal, vat_total, total, issued_at, due_at,
                                       period_start, period_end, created_at, updated_at)
                 VALUES (gen_random_uuid(), $1, $2, $3, $4,
                         'IVCOV-' || gen_random_uuid()::text, $2, 0, $2, NOW(), NOW(),
                         NOW(), NOW(), NOW(), NOW())",
                )
                .bind(tenant)
                .bind(total)
                .bind(currency)
                .bind(status)
                .execute(&env.pool)
                .await
                .expect("invoice");
            }

            // The allocation ledger is authoritative for PARTIAL settlement
            // while status='paid' is the authority for full settlement: a
            // pending invoice with a recorded 500-unit payment contributes
            // total − 500.
            sqlx::query(
                "INSERT INTO invoice_payment_allocations
                     (id, tenant_id, invoice_id, operation_id, source, amount_cents, currency)
                 SELECT gen_random_uuid(), $1, id, 'ivcov:' || id::text || ':wallet', 'wallet',
                        500, 'EUR'
                 FROM invoices WHERE tenant_id = $1 AND status = 'pending' AND total = 2500",
            )
            .bind(tenant)
            .execute(&env.pool)
            .await
            .expect("allocation");

            let outstanding = tenant_outstanding_by_currency(&env.pool, tenant)
                .await
                .expect("outstanding");
            assert_eq!(
                outstanding,
                vec![("EUR".to_string(), 7000), ("USD".to_string(), 700)],
                "draft/void invoices are excluded; the settled invoice nets to zero by STATUS, \
                 and the partially paid invoice nets to zero by its allocation"
            );
            let none = tenant_outstanding_by_currency(&env.pool, "ivcov_absent")
                .await
                .expect("absent");
            assert!(none.is_empty());
        }
    );

    // The three remainder cases, each proven with its own row (audit F04
    // regression): a paid invoice with NO allocations is fully settled and
    // contributes zero; an unpaid invoice with no allocations contributes
    // its full total; an invoice with allocations contributes
    // total − allocated (and the debt-reduction part of credit notes still
    // reduces it).
    env_test!(
        tenant_outstanding_uses_each_invoices_unpaid_remainder,
        |env| {
            async fn insert_invoice(
                env: &Env,
                tenant: &str,
                status: &str,
                currency: &str,
                total: i64,
            ) -> Uuid {
                sqlx::query_scalar(
                    "INSERT INTO invoices (id, tenant_id, amount, currency, status, invoice_number,
                                           subtotal, vat_total, total, issued_at, due_at,
                                           period_start, period_end, created_at, updated_at)
                     VALUES (gen_random_uuid(), $1, $2, $3, $4,
                             'IVCOV-' || gen_random_uuid()::text, $2, 0, $2, NOW(), NOW(),
                             NOW(), NOW(), NOW(), NOW())
                     RETURNING id",
                )
                .bind(tenant)
                .bind(total)
                .bind(currency)
                .bind(status)
                .fetch_one(&env.pool)
                .await
                .expect("invoice")
            }

            async fn allocate(env: &Env, tenant: &str, invoice: Uuid, amount_cents: i64) {
                sqlx::query(
                    "INSERT INTO invoice_payment_allocations
                         (id, tenant_id, invoice_id, operation_id, source, amount_cents, currency)
                     VALUES (gen_random_uuid(), $1, $2, $3, 'wallet', $4, 'EUR')",
                )
                .bind(tenant)
                .bind(invoice)
                .bind(format!("ivcov-rem:{invoice}:{amount_cents}"))
                .bind(amount_cents)
                .execute(&env.pool)
                .await
                .expect("allocation");
            }

            let tenant = "ivcov_remainder";
            seed_tenant(env, tenant).await;

            // Case 1 — PAID with no allocation rows: zero.
            let _paid_plain = insert_invoice(env, tenant, "paid", "EUR", 1111).await;
            // Case 2 — UNPAID (pending/overdue) with no allocation rows: the
            // full total.
            let _pending_plain = insert_invoice(env, tenant, "pending", "EUR", 5000).await;
            let _overdue_usd = insert_invoice(env, tenant, "overdue", "USD", 700).await;
            // Case 3 — WITH allocations: total − allocated.
            let pending_partial = insert_invoice(env, tenant, "pending", "EUR", 4000).await;
            allocate(env, tenant, pending_partial, 1500).await;
            // A PAID invoice with a PARTIAL allocation is still fully settled
            // by its status, not by its unallocated nominal remainder.
            let paid_partial = insert_invoice(env, tenant, "paid", "EUR", 900).await;
            allocate(env, tenant, paid_partial, 400).await;
            // Debt-reduction credit notes reduce an unpaid remainder.
            let credited = insert_invoice(env, tenant, "overdue", "EUR", 2000).await;
            sqlx::query(
                "INSERT INTO credit_notes
                     (invoice_id, tenant_id, amount, currency, reason, idempotency_key,
                      operation_id, debt_reduction_cents, refunded_cents)
                 VALUES ($1, $2, 500, 'EUR', 'remainder coverage', 'ivcov-remainder-credit',
                         'ivcov-remainder-credit-op', 500, 0)",
            )
            .bind(credited)
            .bind(tenant)
            .execute(&env.pool)
            .await
            .expect("credit note");
            // Not collectible: excluded from the aggregation entirely.
            insert_invoice(env, tenant, "draft", "EUR", 9999).await;
            insert_invoice(env, tenant, "void", "EUR", 4444).await;
            insert_invoice(env, tenant, "uncollectible", "EUR", 8888).await;

            let outstanding = tenant_outstanding_by_currency(&env.pool, tenant)
                .await
                .expect("outstanding");
            assert_eq!(
                outstanding,
                vec![
                    // 0 (paid, no allocations) + 5000 (unpaid, none)
                    // + 2500 (partially paid) + 0 (paid, partial)
                    // + 1500 (credit-note debt reduction).
                    ("EUR".to_string(), 9000),
                    ("USD".to_string(), 700),
                ],
                "each invoice contributes exactly its unpaid remainder"
            );

            // The allocation ledger still matters for PARTIAL settlement: a
            // second 1500 payment zeroes the partially-paid invoice.
            allocate(env, tenant, pending_partial, 2500).await;
            let outstanding = tenant_outstanding_by_currency(&env.pool, tenant)
                .await
                .expect("outstanding");
            assert_eq!(
                outstanding,
                vec![("EUR".to_string(), 6500), ("USD".to_string(), 700)],
                "allocations remain the authority for partial settlement"
            );
        }
    );

    env_test!(
        create_invoice_requires_address_and_respects_vies_evidence,
        |env| {
            // No billing address at all: refused, nothing written.
            let bare = "ivcov_bare";
            seed_tenant(env, bare).await;
            let error = create_invoice(&env.pool, input(bare))
                .await
                .expect_err("address required");
            assert!(matches!(error, InvoiceError::NoBillingAddress), "{error:?}");
            let rows: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM invoices WHERE tenant_id = $1")
                    .bind(bare)
                    .fetch_one(&env.pool)
                    .await
                    .expect("rows");
            assert_eq!(rows, 0, "a rejected write changes nothing");

            // DE customer WITHOUT evidence: destination VAT, no reverse charge.
            let de_no_evidence = "ivcov_de_plain";
            seed_tenant(env, de_no_evidence).await;
            seed_address(env, de_no_evidence, "DE", Some("DE123456789")).await;
            let invoice = create_invoice(&env.pool, input(de_no_evidence))
                .await
                .expect("invoice");
            assert_eq!(invoice.subtotal, 10_000);
            assert_eq!(invoice.vat_total, 1_900, "German 19% destination VAT");
            assert_eq!(invoice.total, 11_900);
            let (country, rate): (Option<String>, Option<f64>) =
                sqlx::query_as("SELECT billing_country, vat_rate FROM invoices WHERE id = $1")
                    .bind(invoice.id)
                    .fetch_one(&env.pool)
                    .await
                    .expect("snapshot");
            assert_eq!(
                country.as_deref(),
                Some("DE"),
                "the billing country is snapshotted"
            );
            assert_eq!(rate, Some(19.0), "the charged rate is frozen on the row");

            // The same customer WITH in-force VIES evidence: reverse charge.
            let de_vies = "ivcov_de_vies";
            seed_tenant(env, de_vies).await;
            seed_address(env, de_vies, "DE", Some("DE123456789")).await;
            insert_evidence(env, de_vies, "DE123456789", true, None).await;
            let invoice = create_invoice(&env.pool, input(de_vies))
                .await
                .expect("reverse-charge invoice");
            assert_eq!(invoice.vat_total, 0, "VIES evidence authorises 0% VAT");
            assert_eq!(invoice.total, 10_000);
            let evidence_id: Option<Uuid> =
                sqlx::query_scalar("SELECT vat_evidence_id FROM invoices WHERE id = $1")
                    .bind(invoice.id)
                    .fetch_one(&env.pool)
                    .await
                    .expect("evidence id");
            assert!(evidence_id.is_some(), "the authorising evidence is frozen");

            // An EXPIRED evidence row cannot authorise the reverse charge.
            let expired = "ivcov_de_expired";
            seed_tenant(env, expired).await;
            seed_address(env, expired, "DE", Some("DE123456789")).await;
            insert_evidence(env, expired, "DE123456789", true, None).await;
            sqlx::query(
                "UPDATE vat_validation_evidence SET valid_from = CURRENT_DATE - 400,
                    valid_until = CURRENT_DATE - 10 WHERE tenant_id = $1",
            )
            .bind(expired)
            .execute(&env.pool)
            .await
            .expect("expire evidence");
            let invoice = create_invoice(&env.pool, input(expired))
                .await
                .expect("expired evidence invoice");
            assert_eq!(
                invoice.vat_total, 1_900,
                "an out-of-force validation charges normal VAT"
            );
        }
    );

    env_test!(
        invoice_pdf_escapes_input_and_reports_renderer_failures,
        |env| {
            let mock = Mock::default();
            mock.route("/v1/pdf/render", 500, "renderer exploded");
            let base = spawn_mock(mock.clone()).await;
            let guard = ENV_LOCK.lock().await;
            let previous = (
                std::env::var("PDF_RENDERER_URL").ok(),
                std::env::var("S3_ACCESS_KEY_ID").ok(),
                std::env::var("INTERNAL_SERVICE_TOKEN").ok(),
            );
            std::env::set_var("PDF_RENDERER_URL", &base);
            std::env::remove_var("S3_ACCESS_KEY_ID");
            std::env::set_var("INTERNAL_SERVICE_TOKEN", "cov-internal-token");

            let tenant = "ivcov_pdf";
            seed_tenant(env, tenant).await;
            seed_address(env, tenant, "EE", None).await;
            sqlx::query("UPDATE tenants SET settings = '{\"registryCode\":\"16588745\"}'::jsonb WHERE id = $1")
            .bind(tenant)
            .execute(&env.pool)
            .await
            .expect("registry code");
            let mut request = input(tenant);
            request.line_items = vec![line("<script>&\"'evil", 2, 1_500)];
            let invoice = create_invoice(&env.pool, request).await.expect("invoice");

            let client = reqwest::Client::new();
            let error = generate_invoice_pdf(&env.pool, &client, &invoice)
                .await
                .expect_err("renderer 500");
            assert!(error.to_string().contains("500"), "{error}");

            // The renderer request carries the escaped description and the
            // frozen billing identity — never raw user markup.
            let body = mock.last_body("/v1/pdf/render").expect("render call");
            assert!(
                body.contains("&lt;script&gt;&amp;&quot;&#39;evil"),
                "escaped description: {body}"
            );
            assert!(!body.contains("<script>"), "raw markup must never be sent");
            assert!(body.contains("16588745"), "registry code is rendered");

            // A successful render still cannot silently drop the PDF: with no
            // S3 credentials configured the upload refuses loudly.
            mock.route("/v1/pdf/render", 200, "%PDF-1.4 coverage");
            let error = generate_invoice_pdf(&env.pool, &client, &invoice)
                .await
                .expect_err("no storage credentials");
            let message = error.to_string();
            assert!(
                message.contains("S3_ACCESS_KEY_ID"),
                "upload config is reported: {message}"
            );
            let stored: Option<String> =
                sqlx::query_scalar("SELECT pdf_url FROM invoices WHERE id = $1")
                    .bind(invoice.id)
                    .fetch_one(&env.pool)
                    .await
                    .expect("invoice");
            assert!(stored.is_none(), "no URL is recorded without an upload");

            match previous {
                (Some(url), Some(key), Some(token)) => {
                    std::env::set_var("PDF_RENDERER_URL", url);
                    std::env::set_var("S3_ACCESS_KEY_ID", key);
                    std::env::set_var("INTERNAL_SERVICE_TOKEN", token);
                }
                _ => {
                    std::env::remove_var("PDF_RENDERER_URL");
                    std::env::remove_var("S3_ACCESS_KEY_ID");
                    std::env::remove_var("INTERNAL_SERVICE_TOKEN");
                }
            }
            drop(guard);
        }
    );

    // Bug 3 regression: the upload must follow the CONFIGURED endpoint —
    // scheme (a local http mock is reachable), host/port and path prefix —
    // sign the request it actually sends, persist the resulting URL, and
    // refuse loudly without persisting anything when the endpoint is
    // unreachable.
    env_test!(
        invoice_pdf_upload_honours_the_configured_s3_endpoint,
        |env| {
            let renderer = Mock::default();
            renderer.route("/v1/pdf/render", 200, "%PDF-1.4 s3-endpoint");
            let renderer_base = spawn_mock(renderer.clone()).await;

            // The local S3-compatible mock, reached over PLAIN HTTP with a
            // path prefix — both of which the old `https://{host}/…` builder
            // discarded.
            let storage = Mock::default();
            let storage_base = spawn_mock(storage.clone()).await;
            let endpoint = format!("{storage_base}/v1");

            let guard = ENV_LOCK.lock().await;
            let previous = [
                "PDF_RENDERER_URL",
                "S3_ENDPOINT",
                "S3_BUCKET",
                "S3_ACCESS_KEY_ID",
                "S3_SECRET_ACCESS_KEY",
                "S3_PUBLIC_URL",
            ]
            .map(|name| (name, std::env::var(name).ok()));
            std::env::set_var("PDF_RENDERER_URL", &renderer_base);
            std::env::set_var("S3_ENDPOINT", &endpoint);
            std::env::set_var("S3_BUCKET", "s3-endpoint-bucket");
            std::env::set_var("S3_ACCESS_KEY_ID", "coverage-access");
            std::env::set_var("S3_SECRET_ACCESS_KEY", "coverage-secret");
            std::env::remove_var("S3_PUBLIC_URL");

            let tenant = "ivcov_s3_endpoint";
            seed_tenant(env, tenant).await;
            seed_address(env, tenant, "EE", None).await;
            let invoice = create_invoice(&env.pool, input(tenant))
                .await
                .expect("invoice");
            let key = format!("invoices/{}/{}.pdf", tenant, invoice.invoice_number);
            let object_path = format!("/s3-endpoint-bucket/{key}");
            let signed_path = format!("/v1{object_path}");
            storage.route(&signed_path, 200, "");

            let client = reqwest::Client::new();
            let url = generate_invoice_pdf(&env.pool, &client, &invoice)
                .await
                .expect("upload against the local http mock");
            assert_eq!(
                url,
                format!("{endpoint}{object_path}"),
                "the http scheme, port and endpoint prefix must survive"
            );
            assert!(url.starts_with("http://"), "{url}");

            let call = storage.last_call(&signed_path).expect("PUT recorded");
            assert_eq!(call.method, "PUT");
            let authority = storage_base
                .trim_start_matches("http://")
                .split('/')
                .next()
                .expect("authority");
            assert_eq!(
                call.headers.get("host").map(String::as_str),
                Some(authority),
                "Host must match the signed authority"
            );
            assert_eq!(
                call.headers.get("content-type").map(String::as_str),
                Some("application/pdf")
            );
            let payload_hash = call
                .headers
                .get("x-amz-content-sha256")
                .expect("payload hash signed");
            assert_eq!(
                payload_hash,
                &hex_encode(&Sha256::digest(call.body.as_bytes())),
                "the signed payload hash matches the uploaded bytes"
            );
            assert!(call.headers.contains_key("x-amz-date"));
            let authorization = call.headers.get("authorization").expect("signed");
            assert!(
                authorization.starts_with("AWS4-HMAC-SHA256 Credential=coverage-access/"),
                "{authorization}"
            );

            let stored: Option<String> =
                sqlx::query_scalar("SELECT pdf_url FROM invoices WHERE id = $1")
                    .bind(invoice.id)
                    .fetch_one(&env.pool)
                    .await
                    .expect("invoice");
            assert_eq!(stored.as_deref(), Some(url.as_str()));

            // An UNREACHABLE configured endpoint: loud typed error, and the
            // invoice keeps no pdf_url (no phantom "stored" artifact).
            let unreachable = "ivcov_s3_unreachable";
            seed_tenant(env, unreachable).await;
            seed_address(env, unreachable, "EE", None).await;
            let invoice = create_invoice(&env.pool, input(unreachable))
                .await
                .expect("invoice");
            std::env::set_var("S3_ENDPOINT", "http://127.0.0.1:1");
            let error = generate_invoice_pdf(&env.pool, &client, &invoice)
                .await
                .expect_err("unreachable endpoint must fail the upload");
            assert!(
                error.to_string().contains("S3 upload failed"),
                "the error must name the failed upload: {error}"
            );
            let stored: Option<String> =
                sqlx::query_scalar("SELECT pdf_url FROM invoices WHERE id = $1")
                    .bind(invoice.id)
                    .fetch_one(&env.pool)
                    .await
                    .expect("invoice");
            assert!(
                stored.is_none(),
                "a failed upload persists no pdf_url: {stored:?}"
            );

            for (name, value) in previous {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
            drop(guard);
        }
    );

    #[test]
    fn vat_rounding_and_line_allocation_reconcile() {
        assert_eq!(round_vat(0, 22.0), 0);
        assert_eq!(round_vat(1000, 22.0), 220);
        assert_eq!(round_vat(1, 25.5), 0);
        assert_eq!(round_vat(2, 25.5), 1);
        // Per-line allocations sum exactly to the headline VAT.
        let allocations = allocate_vat_across_lines(&[333, 333, 334], 22.0);
        assert_eq!(allocations.iter().sum::<i64>(), round_vat(1000, 22.0));
        let allocations = allocate_vat_across_lines(&[0, 0], 22.0);
        assert_eq!(allocations, vec![0, 0]);
        assert_eq!(allocate_vat_across_lines(&[], 22.0), Vec::<i64>::new());
    }
}
