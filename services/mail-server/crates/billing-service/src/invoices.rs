//! Invoice management – create, list, get by ID.

use std::sync::LazyLock;

use chrono::{DateTime, Datelike, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::{Invoice, InvoiceLineItem, InvoiceStatus};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// PDF Renderer client config
// ---------------------------------------------------------------------------

/// Base URL for the pdf-renderer service.
static PDF_RENDERER_URL: LazyLock<String> = LazyLock::new(|| {
    std::env::var("PDF_RENDERER_URL").unwrap_or_else(|_| "http://pdf-renderer:3004".into())
});

// ---------------------------------------------------------------------------
// S3/R2 object storage config
// ---------------------------------------------------------------------------

/// S3-compatible endpoint (e.g. `https://s3.eu-central-1.amazonaws.com` or R2 endpoint).
static S3_ENDPOINT: LazyLock<String> = LazyLock::new(|| {
    std::env::var("S3_ENDPOINT").unwrap_or_else(|_| "https://s3.eu-central-1.amazonaws.com".into())
});

/// S3 bucket for invoice PDFs.
static S3_BUCKET: LazyLock<String> =
    LazyLock::new(|| std::env::var("S3_BUCKET").unwrap_or_else(|_| "apexmail-invoices".into()));

/// AWS region for Sig V4 signing.
static S3_REGION: LazyLock<String> =
    LazyLock::new(|| std::env::var("S3_REGION").unwrap_or_else(|_| "eu-central-1".into()));

/// Optional public URL prefix for the bucket (e.g. `https://storage.apexmail.ee`).
/// When set, returned URLs use this base instead of the raw S3 endpoint.
static S3_PUBLIC_URL: LazyLock<Option<String>> =
    LazyLock::new(|| std::env::var("S3_PUBLIC_URL").ok());

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for invoice line items JSON.
const INVOICE_LINE_ITEMS_SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Re-exports from billing-common
// ---------------------------------------------------------------------------

/// Calculate the VAT rate and amount for a given subtotal, customer country
/// and optional VAT number.
///
/// Delegates to [`billing_common::vat_rates::calculate_vat`].
pub use billing_common::vat_rates::calculate_vat;

/// Generate the next invoice number in `YYYY-NNNNNN` format.
pub async fn generate_invoice_number(pool: &PgPool) -> Result<String, InvoiceError> {
    let year = Utc::now().year();

    let row: (i64,) = sqlx::query_as("SELECT nextval('invoice_number_seq')::bigint")
        .fetch_one(pool)
        .await
        .map_err(InvoiceError::Db)?;

    Ok(format!("{year}-{:06}", row.0))
}

/// Input for creating an invoice.
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

pub struct CreateInvoiceInput {
    pub tenant_id: String,
    pub stripe_invoice_id: Option<String>,
    pub line_items: Vec<NewLineItem>,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub due_at: Option<DateTime<Utc>>,
    pub currency: Option<String>,
}

pub struct NewLineItem {
    pub description: String,
    pub quantity: i64,
    /// Unit price in cents.
    pub unit_price: i64,
}

/// Round-half-up VAT for a single base amount (integer cents).
pub(crate) fn round_vat(amount: i64, rate: i32) -> i64 {
    ((amount * rate as i64) + 50) / 100
}

/// Allocate VAT across invoice lines following the EU convention: round each
/// line independently, then adjust the final non-zero line so the per-line
/// sum always reconciles exactly with the VAT computed on the (rounded)
/// invoice total. Without this, sums of per-line rounding drift by ±1 cent
/// from the headline `vat_total`, breaking KMD returns and PDF totals.
///
/// Returns the VAT amount (cents) per line, aligned with `amounts`.
pub(crate) fn allocate_vat_across_lines(amounts: &[i64], rate: i32) -> Vec<i64> {
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

/// Create an invoice.
pub async fn create_invoice(
    pool: &PgPool,
    input: CreateInvoiceInput,
) -> Result<Invoice, InvoiceError> {
    // Fetch billing address country + VAT number for VAT calculation.
    let addr: BillingAddrRow =
        sqlx::query_as("SELECT country, vat_number FROM billing_addresses WHERE tenant_id = $1")
            .bind(&input.tenant_id)
            .fetch_optional(pool)
            .await
            .map_err(InvoiceError::Db)?
            .ok_or(InvoiceError::NoBillingAddress)?;

    let invoice_number = generate_invoice_number(pool).await?;

    // All lines on one invoice share the billing address, hence the same VAT
    // rate; compute it once from the full subtotal so per-line allocations
    // reconcile with the headline total (Fix I3).
    let line_amounts: Vec<i64> = input
        .line_items
        .iter()
        .map(|item| item.quantity * item.unit_price)
        .collect();
    let subtotal: i64 = line_amounts.iter().sum();
    let (vat_rate, _) = calculate_vat(subtotal, &addr.country, addr.vat_number.as_deref());
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

    sqlx::query(
        r#"
        INSERT INTO invoices (
            id, tenant_id, stripe_invoice_id, invoice_number, status,
            currency, amount, subtotal, vat_total, total, line_items,
            issued_at, due_at, period_start, period_end,
            billing_country, vat_rate,
            created_at, updated_at
        ) VALUES (
            $1, $2, $3, $4, 'draft',
            $5, $8, $6, $7, $8, $9,
            $10, $11, $12, $13,
            $14, $15,
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
    .bind(addr.country.to_uppercase())
    .bind(vat_rate)
    .execute(pool)
    .await
    .map_err(InvoiceError::Db)?;

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
    });

    let render_request = serde_json::json!({
        "template": "invoice",
        "data": pdf_data,
    });

    // Call pdf-renderer service
    let mut request = http_client
        .post(format!("{}/v1/pdf/render", *PDF_RENDERER_URL))
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
struct BillingAddrRow {
    country: String,
    vat_number: Option<String>,
}

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

/// Upload bytes to S3-compatible object storage using AWS Signature V4.
async fn s3_put_object(
    http_client: &reqwest::Client,
    key: &str,
    body: &[u8],
    content_type: &str,
) -> Result<String, InvoiceError> {
    let endpoint = &*S3_ENDPOINT;
    let bucket = &*S3_BUCKET;
    let region = &*S3_REGION;
    let (access_key, secret_key) = s3_credentials()?;

    let now = Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

    // SHA-256 of request body
    let payload_hash = hex_encode(&Sha256::digest(body));

    // Host:virtual-hosted style for broad S3 compatibility
    let raw_host = endpoint
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host = format!("{bucket}.{raw_host}");
    let canonical_uri = format!("/{key}");

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

    let url = format!("https://{host}{canonical_uri}");

    let resp = http_client
        .put(&url)
        .header("Host", &host)
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
    let public_url = match &*S3_PUBLIC_URL {
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
        assert_eq!(rate, 24);
        assert_eq!(amt, 2_400); // 24 % of 10 000
    }

    // ------------------------------------------------------------------
    // Fix I3 — per-line VAT rounding must reconcile with the rounded total.
    // ------------------------------------------------------------------

    #[test]
    fn allocate_vat_lines_sums_to_total_rounded_vat() {
        // Three lines of 3 cents each at 24 %: per-line rounding gives
        // 1+1+1 = 3, but round(9 * 24%) = 2. The last line absorbs the -1.
        let allocated = allocate_vat_across_lines(&[3, 3, 3], 24);

        assert_eq!(allocated, vec![1, 1, 0]);
        assert_eq!(
            allocated.iter().sum::<i64>(),
            ((3 + 3 + 3) * 24 + 50) / 100
        );
    }

    #[test]
    fn allocate_vat_lines_absorbs_plus_one_cent_drift() {
        // Lines of 1 cent at 24 %: each line rounds to 0, but the total
        // rounds to 1 — the final line is adjusted up by +1.
        let allocated = allocate_vat_across_lines(&[1, 1, 1], 24);

        assert_eq!(allocated, vec![0, 0, 1]);
        assert_eq!(allocated.iter().sum::<i64>(), ((1 + 1 + 1) * 24 + 50) / 100);
    }

    #[test]
    fn allocate_vat_lines_exact_rounding_needs_no_adjustment() {
        let allocated = allocate_vat_across_lines(&[10_000, 5_000], 24);

        // Exact per-line rounding already reconciles — no drift to absorb.
        assert_eq!(
            allocated,
            vec![
                (10_000 * 24 + 50) / 100,
                (5_000 * 24 + 50) / 100
            ]
        );
    }

    #[test]
    fn allocate_vat_lines_zero_rate_and_empty_inputs() {
        assert!(allocate_vat_across_lines(&[], 24).is_empty());
        assert_eq!(allocate_vat_across_lines(&[100, 200], 0), vec![0, 0]);
    }

    #[test]
    fn allocate_vat_lines_adjusts_last_nonzero_line_only() {
        // A trailing zero-amount line must not receive the reconciliation
        // adjustment; the last *non-zero* line absorbs it instead.
        let allocated = allocate_vat_across_lines(&[3, 3, 3, 0], 24);

        assert_eq!(allocated, vec![1, 1, 0, 0]);
        assert_eq!(allocated.iter().sum::<i64>(), 2);
    }

    #[test]
    fn vat_eu_b2b_reverse_charge() {
        let (rate, amt) = calculate_vat(10_000, "DE", Some("DE123456789"));
        assert_eq!(rate, 0);
        assert_eq!(amt, 0);
    }

    #[test]
    fn vat_eu_b2c_charged() {
        let (rate, amt) = calculate_vat(10_000, "FR", None);
        // France standard VAT rate is 20% (destination-based)
        assert_eq!(rate, 20);
        assert_eq!(amt, 2_000);
    }

    #[test]
    fn vat_non_eu_zero() {
        let (rate, amt) = calculate_vat(50_000, "US", None);
        assert_eq!(rate, 0);
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
            vat_rate: 24,
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
            vat_rate: 0,
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

    /// Verify that all 27 EU member states have a defined VAT rate in
    /// EU_VAT_RATES and are listed in EU_COUNTRIES.
    #[test]
    fn test_all_eu_countries_have_vat_rates() {
        let expected: [(&str, i32); 27] = [
            ("AT", 20),
            ("BE", 21),
            ("BG", 20),
            ("HR", 25),
            ("CY", 19),
            ("CZ", 21),
            ("DK", 25),
            ("EE", 24),
            ("FI", 26),
            ("FR", 20),
            ("DE", 19),
            ("GR", 24),
            ("HU", 27),
            ("IE", 23),
            ("IT", 22),
            ("LV", 21),
            ("LT", 21),
            ("LU", 17),
            ("MT", 18),
            ("NL", 21),
            ("PL", 23),
            ("PT", 23),
            ("RO", 19),
            ("SK", 23),
            ("SI", 22),
            ("ES", 21),
            ("SE", 25),
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
