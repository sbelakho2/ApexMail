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
/// port) and path prefix are honoured, see [`s3_object_target`].
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
/// is NOT authorised by this wrapper (it carries no evidence), use
/// [`calculate_vat_for_invoice`] / `calculate_vat_with_evidence` when
/// authoritative VIES evidence is available.
pub use billing_common::vat_rates::calculate_vat;

use billing_common::vat_rates::{self, VatValidationEvidence};

/// Load the newest authoritative VAT evidence for a tenant's VAT number.
///
/// Returns `None` when there is no evidence row (or the evidence cannot be
/// authoritative), callers then charge the normal destination rate, because
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
                "VAT evidence lookup failed, charging normal VAT (fail closed)"
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
pub(crate) async fn generate_invoice_number_tx(
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
    pub mollie_payment_id: Option<String>,
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
    /// for non-sweep writers (Mollie webhook invoice persistence, the
    /// admin invoice writer).
    pub overage_period: Option<DateTime<Utc>>,
    /// Idempotency marker for the CONTRACT product-line sweep (migration
    /// 255): the calendar-month start the invoice settles. A separate
    /// column from `overage_period` on purpose, a PAYG tenant can also
    /// hold a Platform/Mailboxes contract, and sharing one marker would
    /// make the second charge collide with (and be swallowed by) the first
    /// invoice's identity. `invoices.product_lines_period` is written in
    /// the SAME INSERT as the invoice row and carries its own partial
    /// unique index. `None` for non-product-line writers.
    pub product_lines_period: Option<DateTime<Utc>>,
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
/// atomically (audit F29, the old claim-then-insert-on-another-connection
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

    // ── US sales tax (plan WP C2, SaaS-grade) ────────────────────────────
    // A US customer's invoice in a state the OPERATOR has registered carries
    // a sales-tax line computed from the committed rate file (the combined
    // rate when the row carries one), stamped with state + rate + source +
    // retrieved date, OR, when the customer holds a valid exemption
    // certificate for the state, no tax line and an exemption record on the
    // snapshot. The file is loaded lazily, only once the customer is US and
    // the state is registered, so a problem in it can never refuse an
    // invoice that would carry no tax. A registered state with a missing or
    // stale rate row REFUSES the invoice (a named error): charging a guess,
    // or silently skipping the tax of a registered state, are both false.
    // A `not_taxable` state charges nothing, ever. EU customers are
    // untouched (the country gate is step one inside the resolver). Every
    // invoice kind (subscription overage, PAYG usage, product lines and
    // add-on lines) shares THIS writer, so the tax lands on the whole
    // subtotal wherever the invoice is created.
    let now = Utc::now();
    let us_tax = crate::us_tax::tax_decision_for_invoice(
        &mut **tx,
        None,
        &input.tenant_id,
        &country,
        addr.state.as_deref(),
        subtotal,
        now.date_naive(),
    )
    .await
    .map_err(|error| InvoiceError::UsSalesTax(error.to_string()))?;

    let mut line_items = Vec::with_capacity(input.line_items.len() + 1);
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

    let (us_sales_tax_cents, us_sales_tax_snapshot) = match &us_tax {
        crate::us_tax::UsTaxDecision::Taxed(tax) => {
            // The tax is its own line (description carries the whole stamp).
            // It is NOT a VAT line: `vat_amount`/`vat_rate` stay 0 so the
            // Estonian KMD ledger never sees US state tax as Estonian VAT.
            line_items.push(InvoiceLineItem {
                description: tax.description(),
                quantity: 1,
                unit_price: tax.amount_cents,
                amount: tax.amount_cents,
                vat_rate: 0.0,
                vat_amount: 0,
            });
            (tax.amount_cents, Some(tax.snapshot_json()))
        }
        // An exempt sale adds NO tax line but DOES record the certificate:
        // a zero-tax US invoice whose exemption substantiation existed must
        // stay distinguishable from one with no US tax context at all.
        crate::us_tax::UsTaxDecision::Exempt(exemption) => (0, Some(exemption.snapshot_json())),
        crate::us_tax::UsTaxDecision::None => (0, None),
    };

    let total = subtotal + vat_total + us_sales_tax_cents;
    let due_at = input
        .due_at
        .unwrap_or_else(|| now + chrono::Duration::days(30));
    let currency = input.currency.unwrap_or_else(|| "eur".into());
    let id = Uuid::new_v4();
    let items_json = encode_invoice_line_items(&line_items)?;
    // Immutable billing-address snapshot (audit F08). Stored as TEXT
    // (the column's type since migration 076), versioned JSON (the
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
            id, tenant_id, mollie_payment_id, invoice_number, status,
            currency, amount, subtotal, vat_total, total, line_items,
            issued_at, due_at, period_start, period_end,
            billing_country, vat_rate, overage_period, billing_address,
            billing_registry_code, vat_evidence_id,
            product_lines_period,
            us_sales_tax_cents, us_sales_tax_snapshot,
            created_at, updated_at
        ) VALUES (
            $1, $2, $3, $4, 'draft',
            $5, $8, $6, $7, $8, $9,
            $10, $11, $12, $13,
            $14, $15, $16, $17,
            $18, $19,
            $20,
            $21, $22::jsonb,
            $10, $10
        )
        "#,
    )
    .bind(id)
    .bind(&input.tenant_id)
    .bind(&input.mollie_payment_id)
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
    .bind(input.product_lines_period)
    .bind(us_sales_tax_cents)
    .bind(
        us_sales_tax_snapshot
            .as_ref()
            .map(serde_json::Value::to_string),
    )
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
        mollie_payment_id: input.mollie_payment_id,
        invoice_number,
        status: InvoiceStatus::Draft,
        currency,
        subtotal,
        vat_total,
        us_sales_tax_cents,
        us_sales_tax_snapshot,
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

/// Create a PAID invoice for a plan charge whose Mollie payment was the
/// GROSS amount actually collected.
///
/// Catalog prices are the customer-facing charge, so VAT (and, for a US
/// registered state, sales tax) is EXTRACTED from the gross rather than added
/// on top: the invoice total must equal the money Mollie took, or the tax
/// gate (which compares the charge to the invoice total) would refuse the
/// very payment that funded it. The rate comes from the same
/// `calculate_vat_with_evidence` the invoice writer uses; reverse charge
/// requires VIES evidence exactly as there. The address is snapshotted
/// immutably and the recognition ledger is materialised with the paid date.
#[allow(clippy::too_many_arguments)]
pub async fn create_paid_plan_invoice_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    plan_display_name: &str,
    interval: &str,
    gross_cents: i64,
    currency: &str,
    mollie_payment_id: &str,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
) -> Result<Invoice, InvoiceError> {
    if gross_cents <= 0 {
        return Err(InvoiceError::PdfGeneration(
            "a plan charge must be positive".into(),
        ));
    }
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
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(InvoiceError::Db)?
    .ok_or(InvoiceError::NoBillingAddress)?;
    let country = addr
        .country
        .clone()
        .filter(|value| !value.trim().is_empty())
        .ok_or(InvoiceError::NoBillingAddress)?;
    let now = Utc::now();
    let today = now.date_naive();
    let vat_evidence = match addr
        .vat_number
        .as_deref()
        .map(str::trim)
        .filter(|vat| !vat.is_empty())
    {
        Some(vat) => load_vat_evidence_in(&mut **tx, tenant_id, vat).await,
        None => None,
    };
    let (vat_rate, _, vat_evidence_id) = calculate_vat_for_invoice(
        gross_cents,
        &country,
        addr.vat_number.as_deref(),
        vat_evidence.as_ref(),
        today,
    );

    // The provider charges a GROSS, tax-inclusive amount. Extract the net so
    // that net + VAT + US sales tax is EXACTLY the collected sum: solve
    // net·(1 + rate) = gross in integer half-up arithmetic, then let VAT be the
    // remainder of the charge. A fixed-point iteration of the rounded VAT does
    // not converge for every cent (24 % of 1613 and 1614 round to 387 and 388,
    // oscillating around a non-existent fixed point).
    let rate_tenths = (vat_rate * 10.0).round() as i64;
    if rate_tenths <= -1000 {
        return Err(InvoiceError::PdfGeneration(format!(
            "plan invoice cannot extract a net from a {vat_rate}% rate"
        )));
    }
    let net_for = |tax_cents: i64| -> i64 {
        let taxable = (gross_cents - tax_cents).max(0);
        let denominator = i128::from(1000 + rate_tenths);
        let numerator = i128::from(taxable) * 1000;
        // Round half-up on magnitude (the amount is non-negative here).
        ((numerator + denominator / 2) / denominator) as i64
    };
    let mut net = net_for(0);
    let mut us_tax_cents = 0i64;
    let mut us_tax_snapshot: Option<String> = None;
    for _ in 0..2 {
        let decision = crate::us_tax::tax_decision_for_invoice(
            &mut **tx,
            None,
            tenant_id,
            &country,
            addr.state.as_deref(),
            net,
            today,
        )
        .await
        .map_err(|error| InvoiceError::UsSalesTax(error.to_string()))?;
        us_tax_cents = match &decision {
            crate::us_tax::UsTaxDecision::Taxed(tax) => tax.amount_cents,
            _ => 0,
        };
        us_tax_snapshot = match &decision {
            crate::us_tax::UsTaxDecision::Taxed(tax) => Some(tax.snapshot_json().to_string()),
            crate::us_tax::UsTaxDecision::Exempt(exemption) => {
                Some(exemption.snapshot_json().to_string())
            }
            crate::us_tax::UsTaxDecision::None => None,
        };
        net = net_for(us_tax_cents);
    }
    let vat = gross_cents - net - us_tax_cents;
    if net < 0 || vat < 0 || net + vat + us_tax_cents != gross_cents {
        return Err(InvoiceError::PdfGeneration(format!(
            "plan invoice cannot reconcile a gross charge of {gross_cents} cents              (net {net} + VAT {vat} + sales tax {us_tax_cents})"
        )));
    }
    // The extracted VAT must still be the statutory rate applied to the net,
    // within the single cent the gross rounding can absorb.
    let statutory_vat = billing_common::vat_rates::vat_amount_half_up(net, vat_rate);
    if (statutory_vat - vat).abs() > 1 {
        return Err(InvoiceError::PdfGeneration(format!(
            "plan invoice VAT {vat} deviates from {statutory_vat} at rate {vat_rate}% on net {net}"
        )));
    }

    let line_items = vec![InvoiceLineItem {
        description: format!("{plan_display_name}, {interval}"),
        quantity: 1,
        unit_price: net,
        amount: net,
        vat_rate,
        vat_amount: vat,
    }];
    // US sales tax is its own non-VAT line (mirrors the invoice writer).
    let mut all_lines = line_items;
    if us_tax_cents > 0 {
        if let Some(snapshot) = us_tax_snapshot
            .as_deref()
            .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
        {
            all_lines.push(InvoiceLineItem {
                description: snapshot
                    .get("description")
                    .and_then(|value| value.as_str())
                    .unwrap_or("US sales tax")
                    .to_string(),
                quantity: 1,
                unit_price: us_tax_cents,
                amount: us_tax_cents,
                vat_rate: 0.0,
                vat_amount: 0,
            });
        }
    }
    let items_json = encode_invoice_line_items(&all_lines)?;
    let invoice_number = generate_invoice_number_tx(tx).await?;
    let id = Uuid::new_v4();
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
            id, tenant_id, mollie_payment_id, invoice_number, status,
            currency, amount, subtotal, vat_total, total, line_items,
            issued_at, due_at, paid_at, period_start, period_end,
            billing_country, vat_rate, billing_address, billing_registry_code,
            vat_evidence_id, us_sales_tax_cents, us_sales_tax_snapshot,
            created_at, updated_at
        ) VALUES (
            $1, $2, $3, $4, 'paid',
            $5, $6, $7, $8, $6, $9,
            $10, $10, $10, $11, $12,
            $13, $14, $15, $16,
            $17, $18, $19::jsonb,
            $10, $10
        )
        "#,
    )
    .bind(id)
    .bind(tenant_id)
    .bind(mollie_payment_id)
    .bind(&invoice_number)
    .bind(currency.trim().to_ascii_uppercase())
    .bind(gross_cents)
    .bind(net)
    .bind(vat)
    .bind(&items_json)
    .bind(now)
    .bind(period_start)
    .bind(period_end)
    .bind(country.to_uppercase())
    .bind(vat_rate)
    .bind(address_snapshot)
    .bind(addr.registry_code)
    .bind(vat_evidence_id)
    .bind(us_tax_cents)
    .bind(us_tax_snapshot.as_deref())
    .execute(&mut **tx)
    .await
    .map_err(InvoiceError::Db)?;

    crate::vat_recognition::materialize_invoice_recognition(
        tx,
        &crate::vat_recognition::InvoiceRecognitionInput {
            invoice_id: id,
            tenant_id: tenant_id.to_string(),
            currency: currency.trim().to_ascii_uppercase(),
            subtotal_cents: net,
            vat_rate,
            vat_cents: vat,
            issued_at: now,
            paid_at: Some(now),
            billing_country: Some(country.to_uppercase()),
        },
        now,
    )
    .await
    .map_err(InvoiceError::Recognition)?;

    Ok(Invoice {
        id,
        tenant_id: tenant_id.to_string(),
        mollie_payment_id: Some(mollie_payment_id.to_string()),
        invoice_number,
        status: InvoiceStatus::Paid,
        currency: currency.trim().to_ascii_uppercase(),
        subtotal: net,
        vat_total: vat,
        us_sales_tax_cents: us_tax_cents,
        us_sales_tax_snapshot: us_tax_snapshot.and_then(|text| serde_json::from_str(&text).ok()),
        total: gross_cents,
        line_items: all_lines,
        issued_at: now,
        due_at: now,
        paid_at: Some(now),
        period_start,
        period_end,
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
/// credit notes (migration 183, only that part reduces the unpaid
/// obligation; the refunded part returned value that was actually paid).
/// This is the single derivation UI, wallet application, Mollie
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
        // US state sales tax (plan WP C2) rides in its own totals row so the
        // customer-facing invoice adds up: subtotal + vat + US tax = total.
        // An EXEMPT sale renders the same row labelled "exempt" with the
        // certificate id instead of a silent zero.
        "us_sales_tax": invoice.us_sales_tax_snapshot.as_ref().map(|snapshot| {
            serde_json::json!({
                "state": snapshot.get("state").and_then(|v| v.as_str()).unwrap_or_default(),
                "amount_cents": invoice.us_sales_tax_cents,
                "exempt": snapshot
                    .get("exempt")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false),
                "certificate_id": snapshot
                    .get("certificateId")
                    .and_then(|value| value.as_str()),
            })
        }),
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
            id, tenant_id, mollie_payment_id, invoice_number,
            status, currency, subtotal, vat_total, us_sales_tax_cents,
            us_sales_tax_snapshot, total,
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

    let mut invoices = Vec::with_capacity(rows.len());
    for row in rows {
        // Fix #10 sweep: one corrupt row fails the listing rather than
        // silently rendering that invoice with empty line items.
        invoices.push(row.into_invoice()?);
    }
    Ok(invoices)
}

/// Fetch a single invoice by ID.
pub async fn get_invoice_by_id(
    pool: &PgPool,
    invoice_id: Uuid,
) -> Result<Option<Invoice>, InvoiceError> {
    let row: Option<InvoiceRow> = sqlx::query_as(
        r#"
        SELECT
            id, tenant_id, mollie_payment_id, invoice_number,
            status, currency, subtotal, vat_total, us_sales_tax_cents,
            us_sales_tax_snapshot, total,
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

    row.map(|r| r.into_invoice()).transpose()
}

// ---------------------------------------------------------------------------
// Invoice void (DF-5 finding B), the missing half of the invoice state
// machine. Status filters already reference 'void' (outstanding derivation,
// dunning) but NO surface could express the transition; this is the one
// writer. Operators reach it through the api-server admin billing routes
// (`POST /v1/billing/admin/tenants/:tenantId/invoices/:invoiceId/void`).
// ---------------------------------------------------------------------------

/// Input for [`void_invoice`].
#[derive(Debug, Clone)]
pub struct VoidInvoiceInput {
    /// Tenant owning the invoice, the lookup is tenant-scoped, so another
    /// tenant's invoice id is indistinguishable from an unknown one.
    pub tenant_id: String,
    pub invoice_id: Uuid,
    /// Human-readable reason, recorded on the audit event.
    pub reason: String,
    /// Operator-provided idempotency key. Repeated voids of an already-void
    /// invoice return the SAME invoice (the requested end-state) and write
    /// nothing further, so retries are never duplicate rows.
    pub idempotency_key: String,
}

/// Failure modes of [`void_invoice`]. Every variant the caller can influence
/// is a 4xx-shaped product answer; the state variant NAMES the current
/// status so the operator sees why the machine refused.
#[derive(Debug, thiserror::Error)]
pub enum InvoiceVoidError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("invoice not found: {0}")]
    InvoiceNotFound(Uuid),
    /// Only draft/pending invoices void locally. A PAID invoice voids as a
    /// provider refund of its bound payment; without a bound payment
    /// (`mollie_payment_id`) there is nothing provider-side to return, so
    /// the refusal carries the refusing state verbatim, a wallet-settled
    /// paid invoice is refunded with a credit note instead.
    #[error(
        "invoice {invoice_id} is in status '{status}': only draft or open (pending) invoices can \
         be voided, and a paid invoice only when it is bound to a Mollie payment \
         (mollie_payment_id)"
    )]
    NotVoidable { invoice_id: Uuid, status: String },
    /// The invoice carries a Mollie payment (`mollie_payment_id`) whose
    /// refund is required, but this deployment cannot reach Mollie (no
    /// `MOLLIE_API_KEY`/`MOLLIE_PROFILE_ID`): refused HONESTLY, the
    /// local row is left untouched rather than drifting from the provider
    /// state.
    #[error(
        "invoice {invoice_id} is bound to Mollie payment {mollie_payment_id} but Mollie is not \
         configured (MOLLIE_API_KEY/MOLLIE_PROFILE_ID): the refund cannot be issued from this \
         deployment, so the local invoice was left in status '{status}'"
    )]
    MollieUnavailable {
        invoice_id: Uuid,
        mollie_payment_id: String,
        status: String,
    },
    /// Mollie was configured but refused/completed-with-error on the refund.
    #[error("Mollie refused the invoice refund: {message}")]
    MollieFailed { message: String },
    #[error("audit log failure: {0}")]
    Audit(String),
    /// The void committed but the re-read of the voided invoice failed
    /// (e.g. corrupt line_items JSONB), the state DID change, the response
    /// payload could not be built.
    #[error(transparent)]
    Readback(#[from] InvoiceError),
}

/// Issue the provider refund for a paid invoice through the Mollie API.
///
/// Mollie refunds are `POST /payments/{payment_id}/refunds` with a decimal
/// amount, the secret key as a Bearer token and a deterministic
/// `Idempotency-Key` (one refund per invoice, so a retried void replays the
/// same request). The refund settles asynchronously: a 2xx means Mollie
/// accepted it, and the webhook records the final state.
async fn mollie_refund_payment(
    invoice_id: Uuid,
    invoice_status: &str,
    payment_id: &str,
    amount_cents: i64,
    currency: &str,
    reference: &str,
    idempotency_key: &str,
) -> Result<Option<String>, InvoiceVoidError> {
    use crate::mollie_client::{MollieClient, Money};

    let client = MollieClient::from_env().map_err(|_| InvoiceVoidError::MollieUnavailable {
        invoice_id,
        mollie_payment_id: payment_id.to_string(),
        status: invoice_status.to_string(),
    })?;
    let refund = client
        .create_refund(
            payment_id,
            Money::new(currency, amount_cents),
            &format!("Refund {reference}"),
            idempotency_key,
        )
        .await
        .map_err(|error| InvoiceVoidError::MollieFailed {
            message: format!("Mollie refund request failed: {error}"),
        })?;
    // The refund id is the provider-side handle the webhook will name.
    Ok(Some(refund.id).filter(|id| !id.is_empty()))
}

/// The locally-voidable pre-states: `draft` and `pending` (the platform's
/// open/unpaid states, a pending invoice is issued but unsettled). Mollie
/// has no provider-side invoice object, so an unpaid invoice's provider-side
/// "void" is a no-op and these transition locally with NO provider call.
/// `uncollectible` refuses (a deliberate write-off state, not an open
/// obligation); `void` is the idempotent success replay.
fn is_voidable_status(status: &str) -> bool {
    matches!(status, "draft" | "pending")
}

/// Void an invoice **idempotently** (DF-5 finding B).
///
/// * `draft`/`pending` → `void` with `closed_at` pinned, audited on the
///   canonical 7-segment chain (`billing.invoice_voided`). Mollie has no
///   provider-side invoice to void (no invoice/customer/subscription
///   objects exist provider-side), so this is a LOCAL transition, no
///   provider call, no Mollie configuration required.
/// * An already-`void` invoice returns the SAME invoice unchanged, the
///   requested end-state, and writes nothing further (retries and duplicate
///   submissions are never duplicate rows or duplicate audit events).
/// * `paid` with a bound payment (`mollie_payment_id`) voids as a
///   REFUND: `POST /payments/{paymentPspReference}/refunds` for the local
///   invoice's full amount/currency is issued FIRST (deterministic
///   `Idempotency-Key`, so a retried void replays the same refund), then the
///   local rows flip to `void`. A Mollie refusal or an unconfigured Mollie
///   deployment leaves the local row untouched, never a fake local-only
///   success. The refund outcome is async at Mollie; the webhook settles it.
/// * `paid` with NO bound payment (e.g. wallet settlement) and
///   `uncollectible` refuse with [`InvoiceVoidError::NotVoidable`] naming
///   the current status; a wallet-paid invoice is refunded via a credit
///   note (`credit_notes::create_credit_note`) instead.
pub async fn void_invoice(
    pool: &PgPool,
    input: VoidInvoiceInput,
) -> Result<Invoice, InvoiceVoidError> {
    // ── 1. Lock + validate the current state ────────────────────────────
    let (status, mollie_payment_id, total_cents, currency): (String, Option<String>, i64, String) = {
        let mut tx = pool.begin().await.map_err(InvoiceVoidError::Db)?;
        let row: Option<(String, Option<String>, i64, String)> = sqlx::query_as(
            "SELECT status::text, mollie_payment_id,
                    COALESCE(total, amount, 0)::bigint, currency
             FROM invoices
             WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
        )
        .bind(input.invoice_id)
        .bind(&input.tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(InvoiceVoidError::Db)?;
        let Some((status, mollie_payment_id, total_cents, currency)) = row else {
            return Err(InvoiceVoidError::InvoiceNotFound(input.invoice_id));
        };
        if status == "void" {
            // Idempotent replay: the requested end-state is already the
            // stored state, return it, write nothing.
            tx.commit().await.map_err(InvoiceVoidError::Db)?;
            return get_invoice_by_id(pool, input.invoice_id)
                .await?
                .ok_or(InvoiceVoidError::InvoiceNotFound(input.invoice_id));
        }
        // Unpaid (draft/pending) invoices void LOCALLY, Mollie has no
        // provider-side invoice object to void. A PAID invoice voids as a
        // provider refund, but only when a payment is BOUND
        // (`mollie_payment_id`): without one (e.g. wallet settlement)
        // there is nothing provider-side to return and the void refuses,
        // exactly like every other non-voidable state.
        let paid_refund = status == "paid" && mollie_payment_id.is_some();
        if !is_voidable_status(&status) && !paid_refund {
            return Err(InvoiceVoidError::NotVoidable {
                invoice_id: input.invoice_id,
                status,
            });
        }
        // The DB lock is released before any Mollie HTTP call: no database
        // transaction is held across provider I/O. The post-Mollie append
        // re-locks and re-validates below.
        tx.rollback().await.map_err(InvoiceVoidError::Db)?;
        (status, mollie_payment_id, total_cents, currency)
    };

    // ── 2. Mollie refund FIRST (only a paid invoice has provider money) ──
    let mut refund_psp_reference: Option<String> = None;
    if status == "paid" {
        let payment_psp_reference = mollie_payment_id
            .clone()
            .expect("paid refund path requires a bound payment");
        // A missing key is an honest refusal: without provider credentials
        // the refund cannot be issued, so the local row does not move.
        let key = format!("invoice-refund:{}", input.invoice_id.simple());
        let reference = format!("invoice:{}", input.invoice_id);
        refund_psp_reference = mollie_refund_payment(
            input.invoice_id,
            &status,
            &payment_psp_reference,
            total_cents,
            &currency,
            &reference,
            &key,
        )
        .await?;

        // The refund webhook names only the refund id, and Mollie's API needs
        // the payment id to fetch it: persist the mapping now, before the
        // provider can call us back.
        if let Some(refund_id) = refund_psp_reference.as_deref() {
            sqlx::query(
                "INSERT INTO mollie_refunds (id, payment_id, tenant_id, amount_cents, currency, status)
                 VALUES ($1, $2, $3, $4, $5, 'created')
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(refund_id)
            .bind(&payment_psp_reference)
            .bind(&input.tenant_id)
            .bind(total_cents)
            .bind(currency.to_ascii_uppercase())
            .execute(pool)
            .await
            .map_err(InvoiceVoidError::Db)?;
        }
    }

    // ── 3. Flip the local state + audit in ONE transaction ──────────────
    let mut tx = pool.begin().await.map_err(InvoiceVoidError::Db)?;
    let now = Utc::now();
    let result = sqlx::query(
        "UPDATE invoices
         SET status = 'void', closed_at = $3, updated_at = $3
         WHERE id = $1 AND tenant_id = $2 AND status::text = $4",
    )
    .bind(input.invoice_id)
    .bind(&input.tenant_id)
    .bind(now)
    .bind(&status)
    .execute(&mut *tx)
    .await
    .map_err(InvoiceVoidError::Db)?;

    if result.rows_affected() == 0 {
        // A concurrent writer moved the invoice between our validation and
        // the update. Re-read UNDER the lock and answer from reality.
        let current: Option<(String,)> = sqlx::query_as(
            "SELECT status::text FROM invoices WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
        )
        .bind(input.invoice_id)
        .bind(&input.tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(InvoiceVoidError::Db)?;
        let status = current
            .map(|(status,)| status)
            .ok_or(InvoiceVoidError::InvoiceNotFound(input.invoice_id))?;
        if status == "void" {
            // The concurrent void won; this request's end-state is met.
            tx.commit().await.map_err(InvoiceVoidError::Db)?;
            return get_invoice_by_id(pool, input.invoice_id)
                .await?
                .ok_or(InvoiceVoidError::InvoiceNotFound(input.invoice_id));
        }
        return Err(InvoiceVoidError::NotVoidable {
            invoice_id: input.invoice_id,
            status,
        });
    }

    crate::routes::append_audit_log(
        &mut tx,
        &input.tenant_id,
        "billing.invoice_voided",
        "invoice",
        Some(&input.invoice_id.to_string()),
        serde_json::json!({
            "invoiceId": input.invoice_id,
            "reason": input.reason,
            "idempotencyKey": input.idempotency_key,
            // A paid void returned provider money via an async refund; an
            // unpaid void needed no provider call at all.
            "mollieRefunded": status == "paid",
            "mollieRefundPaymentId": refund_psp_reference,
            "molliePaymentPspReference": mollie_payment_id,
        }),
        now,
    )
    .await
    .map_err(InvoiceVoidError::Audit)?;

    tx.commit().await.map_err(InvoiceVoidError::Db)?;

    get_invoice_by_id(pool, input.invoice_id)
        .await?
        .ok_or(InvoiceVoidError::InvoiceNotFound(input.invoice_id))
}

// ---------------------------------------------------------------------------
// Internal row mapping
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct InvoiceRow {
    id: Uuid,
    tenant_id: String,
    mollie_payment_id: Option<String>,
    invoice_number: String,
    status: String,
    currency: String,
    subtotal: i64,
    vat_total: i64,
    us_sales_tax_cents: i64,
    us_sales_tax_snapshot: Option<serde_json::Value>,
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

/// Encode line items in the CANONICAL persisted shape (versioned,
/// snake_case). Public so every writer, including the api-server admin
/// invoice path, stores rows this module can decode back; the legacy
/// bare-array camelCase shape some admin-written rows carry still decodes
/// through [`InvoiceLineItem`]'s aliases, but no writer may emit it again.
pub fn encode_invoice_line_items(
    line_items: &[InvoiceLineItem],
) -> Result<serde_json::Value, InvoiceError> {
    serde_json::to_value(StoredInvoiceLineItems {
        schema_version: INVOICE_LINE_ITEMS_SCHEMA_VERSION,
        items: line_items.to_vec(),
    })
    .map_err(InvoiceError::from)
}

/// Decode persisted invoice line items (Fix #10 sweep).
///
/// `NULL` line_items is the documented legacy shape (invoice stored before
/// the column was populated) and yields an empty list. Present-but-invalid
/// JSON is corruption of the invoice's monetary breakdown, rendering an
/// invoice with its totals but silently EMPTY items would drift the
/// customer-facing money state, so it fails with
/// [`InvoiceError::CorruptLineItems`] naming the invoice.
///
/// Both historical persisted shapes are accepted: the canonical versioned
/// `{schemaVersion, items}` object, and the legacy bare camelCase array the
/// api-server admin writer produced before 2026-10-08 (decoded through
/// [`InvoiceLineItem`]'s field aliases).
pub fn decode_invoice_line_items(
    invoice_id: Uuid,
    value: serde_json::Value,
) -> Result<Vec<InvoiceLineItem>, InvoiceError> {
    if let Ok(versioned) = serde_json::from_value::<StoredInvoiceLineItems>(value.clone()) {
        return Ok(versioned.items);
    }

    serde_json::from_value(value).map_err(|source| {
        tracing::error!(
            invoice_id = %invoice_id,
            error = %source,
            "corrupt invoices.line_items JSONB, invoice decode fails closed (Fix #10 sweep)"
        );
        InvoiceError::CorruptLineItems { invoice_id, source }
    })
}

impl InvoiceRow {
    fn into_invoice(self) -> Result<Invoice, InvoiceError> {
        let status = match self.status.as_str() {
            "paid" => InvoiceStatus::Paid,
            "pending" => InvoiceStatus::Pending,
            "void" => InvoiceStatus::Void,
            "uncollectible" => InvoiceStatus::Uncollectible,
            _ => InvoiceStatus::Draft,
        };

        let line_items = match self.line_items {
            // NULL = legacy row: documented empty default, not corruption.
            None => Vec::new(),
            Some(value) => decode_invoice_line_items(self.id, value)?,
        };

        Ok(Invoice {
            id: self.id,
            tenant_id: self.tenant_id,
            mollie_payment_id: self.mollie_payment_id,
            invoice_number: self.invoice_number,
            status,
            currency: self.currency,
            subtotal: self.subtotal,
            vat_total: self.vat_total,
            us_sales_tax_cents: self.us_sales_tax_cents,
            us_sales_tax_snapshot: self.us_sales_tax_snapshot,
            total: self.total,
            line_items,
            issued_at: self.issued_at,
            due_at: self.due_at,
            paid_at: self.paid_at,
            period_start: self.period_start,
            period_end: self.period_end,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
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
    /// US sales tax refused the invoice (plan WP C2): a registered state
    /// with a missing/stale rate row, or an unreadable data file. The
    /// amount is never guessed, the caller's retry surfaces it.
    #[error("US sales tax refusal: {0}")]
    UsSalesTax(String),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    /// Fix #10 sweep: the persisted `line_items` JSONB does not decode, so
    /// the invoice's monetary breakdown is corrupt, the lookup fails closed
    /// instead of rendering the invoice with silently empty items.
    #[error(
        "corrupt persisted line items for invoice {invoice_id}: monetary breakdown fails closed \
         (repair the invoices.line_items JSONB)"
    )]
    CorruptLineItems {
        invoice_id: Uuid,
        #[source]
        source: serde_json::Error,
    },
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

    // ------------------------------------------------------------------
    // Fix #10 sweep, corrupt persisted line_items fail the invoice decode
    // closed instead of rendering silently empty items.
    // ------------------------------------------------------------------

    #[test]
    fn corrupt_line_items_fail_with_typed_error_naming_the_invoice() {
        let invoice_id = Uuid::new_v4();
        let error =
            decode_invoice_line_items(invoice_id, serde_json::json!({"items": "not-an-array"}))
                .expect_err("corrupt line items must fail the decode");
        match &error {
            InvoiceError::CorruptLineItems {
                invoice_id: failed_id,
                ..
            } => assert_eq!(*failed_id, invoice_id),
            other => panic!("expected CorruptLineItems, got {other:?}"),
        }
        assert!(
            error.to_string().contains(&invoice_id.to_string()),
            "error display must name the invoice: {error}"
        );
    }

    #[test]
    fn sql_null_line_items_remain_documented_legacy_default() {
        // SQL NULL (`Option::None`) is the documented legacy shape: the row
        // decodes with an empty item list, not an error. Exercised via
        // `into_invoice` below.
        let invoice_id = Uuid::new_v4();
        let row = InvoiceRow {
            id: invoice_id,
            tenant_id: "tenant_01HZY2Q4YQ0L8QW8Q7Q28WKSFJ".into(),
            mollie_payment_id: None,
            invoice_number: "2026-000002".into(),
            status: "pending".into(),
            currency: "eur".into(),
            subtotal: 1000,
            vat_total: 240,
            us_sales_tax_cents: 0,
            us_sales_tax_snapshot: None,
            total: 1240,
            line_items: None,
            issued_at: Utc::now(),
            due_at: Utc::now(),
            paid_at: None,
            period_start: Utc::now(),
            period_end: Utc::now(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let invoice = row.into_invoice().expect("SQL NULL items are legacy");
        assert!(
            invoice.line_items.is_empty(),
            "SQL NULL line items decode to the documented empty default"
        );

        // A literal JSON `null` inside the column is "present but invalid"
        // and fails closed like any other corrupt payload.
        let error = decode_invoice_line_items(invoice_id, serde_json::Value::Null)
            .expect_err("literal JSON null is not a valid line-items payload");
        assert!(matches!(error, InvoiceError::CorruptLineItems { .. }));
    }

    /// The api-server admin invoice writer persisted its camelCase response
    /// DTO (`{unitPrice, vatRate, vatAmount}` in a bare array) into
    /// `invoices.line_items`. Every later decode of those rows failed with
    /// "missing field `unit_price`", so void/credit-note readback 500'd while
    /// the state change committed (live dogfood 2026-10-08). The legacy shape
    /// must keep decoding; the canonical encoder is what writers emit now.
    #[test]
    fn legacy_camel_case_line_items_decode() {
        let invoice_id = Uuid::new_v4();
        let legacy = serde_json::json!([
            {
                "amount": 5000,
                "vatRate": 24.0,
                "quantity": 1,
                "unitPrice": 5000,
                "vatAmount": 1200,
                "description": "CP dogfood line"
            }
        ]);
        let items = decode_invoice_line_items(invoice_id, legacy)
            .expect("the admin writer's legacy camelCase array must decode");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].unit_price, 5000);
        assert_eq!(items[0].vat_rate, 24.0);
        assert_eq!(items[0].vat_amount, 1200);
        assert_eq!(items[0].amount, 5000);

        // Round trip through the canonical writer: encode -> decode.
        let encoded = encode_invoice_line_items(&items).expect("encode canonical shape");
        let decoded =
            decode_invoice_line_items(invoice_id, encoded).expect("decode canonical shape");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].unit_price, 5000);
        assert_eq!(decoded[0].vat_amount, 1200);
    }

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
    // Fix I3, per-line VAT rounding must reconcile with the rounded total.
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
        // rounds to 1, the final line is adjusted up by +1.
        let allocated = allocate_vat_across_lines(&[1, 1, 1], 24.0);

        assert_eq!(allocated, vec![0, 0, 1]);
        assert_eq!(allocated.iter().sum::<i64>(), ((1 + 1 + 1) * 24 + 50) / 100);
    }

    #[test]
    fn allocate_vat_lines_exact_rounding_needs_no_adjustment() {
        let allocated = allocate_vat_across_lines(&[10_000, 5_000], 24.0);

        // Exact per-line rounding already reconciles, no drift to absorb.
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
            mollie_payment_id: None,
            invoice_number: "2026-000001".into(),
            status: "paid".into(),
            currency: "eur".into(),
            subtotal: 1000,
            vat_total: 240,
            us_sales_tax_cents: 0,
            us_sales_tax_snapshot: None,
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
        // Fix #10 sweep: into_invoice now validates the persisted monetary
        // breakdown, so valid fixtures assert through the Result.
        let inv = row.into_invoice().expect("valid row decodes (Fix #10)");
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

        // Fix #10 sweep: decode now returns Result, the legacy unversioned
        // array shape still decodes when valid.
        let decoded =
            decode_invoice_line_items(Uuid::new_v4(), serde_json::to_value(&line_items).unwrap())
                .expect("legacy line items decode (Fix #10)");

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

        // Fix #10 sweep: decode now returns Result, the versioned wrapper
        // shape still decodes when valid.
        let decoded = decode_invoice_line_items(Uuid::new_v4(), encoded)
            .expect("versioned line items decode (Fix #10)");

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
    // Bug 3, the object target follows the CONFIGURED endpoint.
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
    // Audits F60/F04/F73, ONE outstanding derivation, allocation-ledger
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
        crate::test_support::assert_soft_skip_allowed("TEST_DATABASE_URL");
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

        fn call_count(&self, path: &str) -> usize {
            self.calls
                .lock()
                .expect("lock")
                .iter()
                .filter(|call| call.path == path)
                .count()
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
            [(axum::http::header::CONTENT_TYPE, "application/json")],
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
            mollie_payment_id: None,
            line_items: vec![line("Coverage line", 1, 10_000)],
            period_start: now,
            period_end: now,
            due_at: None,
            currency: Some("eur".into()),
            overage_period: None,
            product_lines_period: None,
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

            // Case 1, PAID with no allocation rows: zero.
            let _paid_plain = insert_invoice(env, tenant, "paid", "EUR", 1111).await;
            // Case 2, UNPAID (pending/overdue) with no allocation rows: the
            // full total.
            let _pending_plain = insert_invoice(env, tenant, "pending", "EUR", 5000).await;
            let _overdue_usd = insert_invoice(env, tenant, "overdue", "USD", 700).await;
            // Case 3, WITH allocations: total − allocated.
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
            // frozen billing identity, never raw user markup.
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
            // path prefix, both of which the old `https://{host}/…` builder
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

    // -------------------------------------------------------------------
    // DF-5 finding B, the invoice VOID transition (previously referenced
    // by status filters but expressible NOWHERE). The transition matrix,
    // idempotency, Mollie honesty and audit re-derivability.
    // -------------------------------------------------------------------

    fn void_input(tenant: &str, invoice: Uuid, key: &str) -> VoidInvoiceInput {
        VoidInvoiceInput {
            tenant_id: tenant.to_string(),
            invoice_id: invoice,
            reason: "coverage void".to_string(),
            idempotency_key: key.to_string(),
        }
    }

    async fn seed_invoice_status(
        env: &Env,
        tenant: &str,
        status: &str,
        total: i64,
        mollie_payment_id: Option<&str>,
    ) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO invoices (id, tenant_id, amount, currency, status, invoice_number,
                                   subtotal, vat_total, total, mollie_payment_id,
                                   issued_at, due_at, period_start, period_end,
                                   created_at, updated_at)
             VALUES ($1, $2, $3, 'EUR', $4, $5, $3, 0, $3, $6,
                     NOW(), NOW(), NOW(), NOW(), NOW(), NOW())",
        )
        .bind(id)
        .bind(tenant)
        .bind(total)
        .bind(status)
        .bind(format!("IVCOV-{}", id.simple()))
        .bind(mollie_payment_id)
        .execute(&env.pool)
        .await
        .expect("seed invoice");
        id
    }

    // The full transition matrix: draft/open void, paid/uncollectible
    // refuse WITH the state named, unknown and cross-tenant ids are 404-
    // shaped, and a replay of an already-void invoice returns the SAME
    // invoice and writes nothing further.
    env_test!(void_transition_matrix, |env| {
        let tenant = "ivcov_void";
        seed_tenant(env, tenant).await;

        // draft → void: the open-charge path.
        let draft = seed_invoice_status(env, tenant, "draft", 5_000, None).await;
        let voided = void_invoice(&env.pool, void_input(tenant, draft, "k-draft"))
            .await
            .expect("draft voids");
        assert!(matches!(voided.status, crate::types::InvoiceStatus::Void));
        let closed_at: Option<chrono::DateTime<Utc>> =
            sqlx::query_scalar("SELECT closed_at FROM invoices WHERE id = $1")
                .bind(draft)
                .fetch_one(&env.pool)
                .await
                .expect("closed_at");
        assert!(closed_at.is_some(), "voiding pins closed_at");

        // pending (the platform's open state) → void.
        let pending = seed_invoice_status(env, tenant, "pending", 7_000, None).await;
        let voided = void_invoice(&env.pool, void_input(tenant, pending, "k-open"))
            .await
            .expect("pending voids");
        assert!(matches!(voided.status, crate::types::InvoiceStatus::Void));

        // paid WITHOUT a bound Mollie payment → REFUSED, the state named:
        // there is nothing provider-side to refund, so a wallet-settled
        // paid invoice is refunded with a credit note instead.
        let paid = seed_invoice_status(env, tenant, "paid", 9_000, None).await;
        let error = void_invoice(&env.pool, void_input(tenant, paid, "k-paid"))
            .await
            .expect_err("paid refuses");
        match &error {
            InvoiceVoidError::NotVoidable { status, .. } => {
                assert_eq!(status, "paid", "the refusing state must be named");
            }
            other => panic!("expected NotVoidable, got {other:?}"),
        }
        let status: String = sqlx::query_scalar("SELECT status::text FROM invoices WHERE id = $1")
            .bind(paid)
            .fetch_one(&env.pool)
            .await
            .expect("status");
        assert_eq!(status, "paid", "a refused void changes nothing");

        // uncollectible → REFUSED (a deliberate write-off, not an open
        // obligation; it can still be CREDITED via credit notes).
        let uncollectible = seed_invoice_status(env, tenant, "uncollectible", 3_000, None).await;
        let error = void_invoice(&env.pool, void_input(tenant, uncollectible, "k-unc"))
            .await
            .expect_err("uncollectible refuses");
        assert!(
            matches!(&error, InvoiceVoidError::NotVoidable { status, .. } if status == "uncollectible"),
            "{error:?}"
        );

        // Unknown id and cross-tenant id are indistinguishable 404s.
        let stranger = "ivcov_void_other";
        seed_tenant(env, stranger).await;
        let theirs = seed_invoice_status(env, stranger, "draft", 1_000, None).await;
        let error = void_invoice(&env.pool, void_input(tenant, theirs, "k-cross"))
            .await
            .expect_err("cross-tenant invoice");
        assert!(
            matches!(error, InvoiceVoidError::InvoiceNotFound(_)),
            "{error:?}"
        );
        let error = void_invoice(&env.pool, void_input(tenant, Uuid::new_v4(), "k-missing"))
            .await
            .expect_err("unknown invoice");
        assert!(
            matches!(error, InvoiceVoidError::InvoiceNotFound(_)),
            "{error:?}"
        );

        // Idempotent replay: voiding the already-void draft returns the SAME
        // invoice and writes NO second audit row.

        async fn void_audit_rows(pool: &PgPool, invoice: Uuid) -> i64 {
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM audit_logs
                 WHERE action = 'billing.invoice_voided'
                   AND resource_id = $1",
            )
            .bind(invoice.to_string())
            .fetch_one(pool)
            .await
            .expect("audit count")
        }
        assert_eq!(void_audit_rows(&env.pool, draft).await, 1);
        let replay = void_invoice(&env.pool, void_input(tenant, draft, "k-draft-replay"))
            .await
            .expect("replay void");
        assert_eq!(replay.id, draft);
        assert!(matches!(replay.status, crate::types::InvoiceStatus::Void));
        assert_eq!(
            void_audit_rows(&env.pool, draft).await,
            1,
            "a replay writes no duplicate audit event"
        );
    });

    // The audit event a void writes is a CANONICAL chain row: its hash
    // re-derives byte-exactly from the stored columns through the shared
    // formula, and its signature re-derives from the chain link.
    env_test!(void_writes_a_canonical_rederivable_audit_row, |env| {
        let guard = ENV_LOCK.lock().await;
        let previous_key = std::env::var("AUDIT_SIGNING_KEY").ok();
        std::env::set_var("AUDIT_SIGNING_KEY", "ivcov-audit-key-0123456789abcdef");

        let tenant = "ivcov_voidaudit";
        seed_tenant(env, tenant).await;
        let draft = seed_invoice_status(env, tenant, "draft", 5_500, None).await;
        void_invoice(&env.pool, void_input(tenant, draft, "k-audit"))
            .await
            .expect("voids");

        /// `(action, resource, resource_id, tenant_id, details, timestamp,
        /// hash, previous_hash, signature)` as the audit-logs query returns it.
        type AuditRow = (
            String,
            String,
            Option<String>,
            String,
            serde_json::Value,
            chrono::DateTime<Utc>,
            String,
            Option<String>,
            String,
        );
        let (
            action,
            resource,
            resource_id,
            row_tenant,
            details,
            timestamp,
            hash,
            previous_hash,
            signature,
        ): AuditRow = sqlx::query_as(
            "SELECT action, resource, resource_id, tenant_id, details,
                    timestamp, hash, previous_hash, signature
             FROM audit_logs
             WHERE action = 'billing.invoice_voided' AND resource_id = $1",
        )
        .bind(draft.to_string())
        .fetch_one(&env.pool)
        .await
        .expect("audit row");

        assert_eq!(resource, "invoice");
        assert_eq!(resource_id.as_deref(), Some(draft.to_string().as_str()));
        // An unpaid local void issues NO provider refund (Mollie has no
        // provider-side invoice object): the audit row records the honest
        // mollieRefunded=false and no provider refund id.
        assert_eq!(
            details["mollieRefunded"],
            serde_json::Value::Bool(false),
            "a local-only void records an honest mollieRefunded=false"
        );
        assert!(
            details["mollieRefundPaymentId"].is_null(),
            "no refund id without provider money to return: {details}"
        );
        assert!(
            details["molliePaymentPspReference"].is_null(),
            "a draft carries no bound Mollie payment: {details}"
        );

        // Byte-exact re-derivation: the canonical 7-segment formula over the
        // row's own columns (machine writer, empty user segment).
        let recomputed = apexmail_lib::audit::audit_hash(
            Some(&row_tenant),
            None,
            &action,
            &resource,
            resource_id.as_deref(),
            &details,
            timestamp,
        );
        assert_eq!(
            recomputed, hash,
            "the void audit row re-derives byte-exactly"
        );

        let expected_signature = apexmail_lib::audit::audit_log_signature(
            previous_hash.as_deref(),
            &hash,
            "ivcov-audit-key-0123456789abcdef",
        )
        .expect("signs");
        assert_eq!(expected_signature, signature);

        // The row is LINKED into the platform chain: previous_hash is the
        // head the append captured (NULL for the very first append on a
        // fresh template, a real hash otherwise).
        let head_seq: i64 =
            sqlx::query_scalar("SELECT head_seq FROM audit_chain_head WHERE chain_id = 'global'")
                .fetch_one(&env.pool)
                .await
                .expect("chain head");
        if previous_hash.is_none() {
            assert_eq!(head_seq, 1, "the first append starts the chain at seq 1");
        } else {
            assert!(head_seq >= 2, "the append advanced the shared chain head");
        }

        match previous_key {
            Some(value) => std::env::set_var("AUDIT_SIGNING_KEY", value),
            None => std::env::remove_var("AUDIT_SIGNING_KEY"),
        }
        drop(guard);
    });

    // Mollie honesty, both directions of the checkout contract:
    // * an UNPAID (draft/pending) invoice voids LOCALLY, Mollie has no
    //   provider-side invoice object, so no provider call and no Mollie
    //   configuration is involved, even when a payment id is recorded;
    // * a PAID invoice voids as an async REFUND of its bound payment
    //   (`POST /v2/payments/{paymentId}/refunds`): refused honestly when
    //   Mollie is unconfigured, refused when Mollie declines, and both sides
    //   move when the refund request is accepted.
    env_test!(void_with_a_mollie_payment_is_honest_both_sides, |env| {
        let guard = ENV_LOCK.lock().await;
        let previous = (
            std::env::var("MOLLIE_API_KEY").ok(),
            std::env::var("MOLLIE_API_BASE_URL").ok(),
            std::env::var("MOLLIE_PROFILE_ID").ok(),
        );

        let mock = Mock::default();
        // The PAID refund path's payment: a separate binding from the
        // unpaid arm's (the schema keeps payment ids unique).
        mock.route(
            "/v2/payments/tr_void_paid/refunds",
            200,
            r#"{"id":"re_void_refund","status":"pending","amount":{"currency":"EUR","value":"62.00"}}"#,
        );
        let base = spawn_mock(mock.clone()).await;

        let tenant = "ivcov_voidmollie";
        seed_tenant(env, tenant).await;

        // 1. UNPAID with a bound payment id and Mollie UNCONFIGURED: the
        // void still succeeds LOCALLY (no provider object exists to void),
        // and no provider call is made.
        std::env::remove_var("MOLLIE_API_KEY");
        std::env::remove_var("MOLLIE_API_BASE_URL");
        std::env::remove_var("MOLLIE_PROFILE_ID");
        let unpaid = seed_invoice_status(env, tenant, "pending", 6_000, Some("tr_void_cov")).await;
        let voided = void_invoice(&env.pool, void_input(tenant, unpaid, "k-local-unconf"))
            .await
            .expect("an unpaid void needs no provider call");
        assert!(matches!(voided.status, crate::types::InvoiceStatus::Void));
        assert_eq!(
            mock.call_count("/v2/payments/tr_void_cov/refunds"),
            0,
            "an unpaid void must not touch the provider"
        );
        let details: serde_json::Value = sqlx::query_scalar(
            "SELECT details FROM audit_logs
             WHERE action = 'billing.invoice_voided' AND resource_id = $1",
        )
        .bind(unpaid.to_string())
        .fetch_one(&env.pool)
        .await
        .expect("local void audit");
        assert_eq!(details["mollieRefunded"], serde_json::Value::Bool(false));
        assert_eq!(
            details["molliePaymentPspReference"],
            serde_json::json!("tr_void_cov"),
            "the bound payment is recorded even when nothing was refunded"
        );
        assert!(details["mollieRefundPaymentId"].is_null());

        // 2. PAID with a bound payment and Mollie UNCONFIGURED: the refund
        // cannot be issued, so the refusal is honest and the row stands.
        let unconfigured =
            seed_invoice_status(env, tenant, "paid", 6_100, Some("tr_void_unconf")).await;
        let error = void_invoice(
            &env.pool,
            void_input(tenant, unconfigured, "k-mollie-unconf"),
        )
        .await
        .expect_err("unconfigured Mollie refuses the refund");
        match &error {
            InvoiceVoidError::MollieUnavailable {
                mollie_payment_id,
                status,
                ..
            } => {
                assert_eq!(mollie_payment_id, "tr_void_unconf");
                assert_eq!(status, "paid");
            }
            other => panic!("expected MollieUnavailable, got {other:?}"),
        }
        let status: String = sqlx::query_scalar("SELECT status::text FROM invoices WHERE id = $1")
            .bind(unconfigured)
            .fetch_one(&env.pool)
            .await
            .expect("status");
        assert_eq!(status, "paid", "the local row never moves without Mollie");
        let audit_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs
             WHERE action = 'billing.invoice_voided' AND resource_id = $1",
        )
        .bind(unconfigured.to_string())
        .fetch_one(&env.pool)
        .await
        .expect("audit count");
        assert_eq!(audit_rows, 0, "a refused void writes no audit event");

        // 3. PAID + Mollie CONFIGURED (local mock accepting the refund):
        // both sides move. The provider call is Mollie's refund contract —
        // Bearer auth, deterministic Idempotency-Key, decimal amount and a
        // human description. The refund id is persisted in `mollie_refunds`.
        std::env::set_var("MOLLIE_API_KEY", "mollie-test-key-fixture");
        std::env::set_var("MOLLIE_API_BASE_URL", format!("{base}/v2"));
        std::env::set_var("MOLLIE_PROFILE_ID", "pfl_test");

        let paid = seed_invoice_status(env, tenant, "paid", 6_200, Some("tr_void_paid")).await;
        let voided = void_invoice(&env.pool, void_input(tenant, paid, "k-mollie-ok"))
            .await
            .expect("voids both sides");
        assert!(matches!(voided.status, crate::types::InvoiceStatus::Void));

        let call = mock
            .last_call("/v2/payments/tr_void_paid/refunds")
            .expect("Mollie refund called");
        assert_eq!(call.method, "POST");
        assert_eq!(
            call.headers.get("authorization").map(String::as_str),
            Some("Bearer mollie-test-key-fixture"),
            "auth is the secret key as a Bearer token"
        );
        assert_eq!(
            call.headers.get("idempotency-key").map(String::as_str),
            Some(format!("invoice-refund:{}", paid.simple()).as_str()),
            "the refund idempotency key derives from the local operation identity"
        );
        let body: serde_json::Value = serde_json::from_str(&call.body).expect("refund body JSON");
        assert_eq!(
            body["amount"],
            serde_json::json!({"currency": "EUR", "value": "62.00"}),
            "Mollie amounts travel as decimal strings, never minor units"
        );
        assert!(
            body["description"]
                .as_str()
                .unwrap_or_default()
                .contains(&format!("invoice:{paid}")),
            "the refund description names our invoice: {}",
            body["description"]
        );

        let details: serde_json::Value = sqlx::query_scalar(
            "SELECT details FROM audit_logs
             WHERE action = 'billing.invoice_voided' AND resource_id = $1",
        )
        .bind(paid.to_string())
        .fetch_one(&env.pool)
        .await
        .expect("paid void audit");
        assert_eq!(details["mollieRefunded"], serde_json::Value::Bool(true));
        assert_eq!(
            details["mollieRefundPaymentId"],
            serde_json::json!("re_void_refund"),
            "the accepted refund's id is recorded"
        );
        let mapping: (String, i64, String) = sqlx::query_as(
            "SELECT payment_id, amount_cents, currency FROM mollie_refunds WHERE id = $1",
        )
        .bind("re_void_refund")
        .fetch_one(&env.pool)
        .await
        .expect("refund mapping persisted");
        assert_eq!(mapping.0, "tr_void_paid");
        assert_eq!(mapping.1, 6_200);
        assert_eq!(mapping.2, "EUR");

        // 4. Mollie REFUSES the refund (e.g. provider-side state): honest
        // error, local row untouched.
        let refused =
            seed_invoice_status(env, tenant, "paid", 6_300, Some("tr_void_refused")).await;
        mock.route(
            "/v2/payments/tr_void_refused/refunds",
            400,
            r#"{"detail":"The refund could not be processed","status":400}"#,
        );
        let error = void_invoice(&env.pool, void_input(tenant, refused, "k-mollie-refused"))
            .await
            .expect_err("Mollie refusal propagates");
        assert!(
            matches!(&error, InvoiceVoidError::MollieFailed { message }
                if message.contains("The refund could not be processed")),
            "{error:?}"
        );
        let status: String = sqlx::query_scalar("SELECT status::text FROM invoices WHERE id = $1")
            .bind(refused)
            .fetch_one(&env.pool)
            .await
            .expect("status");
        assert_eq!(status, "paid", "a Mollie refusal leaves the row paid");
        let audit_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs
             WHERE action = 'billing.invoice_voided' AND resource_id = $1",
        )
        .bind(refused.to_string())
        .fetch_one(&env.pool)
        .await
        .expect("audit count");
        assert_eq!(audit_rows, 0, "a refused refund writes no void audit event");

        match &previous {
            (Some(key), Some(base_url), Some(merchant)) => {
                std::env::set_var("MOLLIE_API_KEY", key);
                std::env::set_var("MOLLIE_API_BASE_URL", base_url);
                std::env::set_var("MOLLIE_PROFILE_ID", merchant);
            }
            _ => {
                std::env::remove_var("MOLLIE_API_KEY");
                std::env::remove_var("MOLLIE_API_BASE_URL");
                std::env::remove_var("MOLLIE_PROFILE_ID");
            }
        }
        drop(guard);
    });
}
