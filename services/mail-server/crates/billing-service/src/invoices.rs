//! Invoice management – create, list, get by ID.
//!
//! VAT logic follows Estonian rules (22 % local, reverse-charge for EU B2B,
//! 0 % for non-EU).

use chrono::{DateTime, Datelike, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::{Invoice, InvoiceLineItem, InvoiceStatus};
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

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
static S3_BUCKET: LazyLock<String> = LazyLock::new(|| {
    std::env::var("S3_BUCKET").unwrap_or_else(|_| "apexmail-invoices".into())
});

/// AWS region for Sig V4 signing.
static S3_REGION: LazyLock<String> = LazyLock::new(|| {
    std::env::var("S3_REGION").unwrap_or_else(|_| "eu-central-1".into())
});

/// S3 access key ID — panics at first access if not set.
static S3_ACCESS_KEY_ID: LazyLock<String> = LazyLock::new(|| {
    std::env::var("S3_ACCESS_KEY_ID")
        .expect("S3_ACCESS_KEY_ID must be set for invoice PDF storage")
});

/// S3 secret access key — panics at first access if not set.
static S3_SECRET_ACCESS_KEY: LazyLock<String> = LazyLock::new(|| {
    std::env::var("S3_SECRET_ACCESS_KEY")
        .expect("S3_SECRET_ACCESS_KEY must be set for invoice PDF storage")
});

/// Optional public URL prefix for the bucket (e.g. `https://storage.apexmail.ee`).
/// When set, returned URLs use this base instead of the raw S3 endpoint.
static S3_PUBLIC_URL: LazyLock<Option<String>> = LazyLock::new(|| {
    std::env::var("S3_PUBLIC_URL").ok()
});

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ESTONIA_VAT_RATE: i32 = 22;

static EU_COUNTRIES: LazyLock<HashSet<String>> = LazyLock::new(|| {
    let default = vec![
        "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR",
        "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK",
        "SI", "ES", "SE",
    ];
    let raw = std::env::var("EU_COUNTRIES").unwrap_or_else(|_| default.join(","));
    raw.split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_uppercase())
        .collect()
});

static EU_VAT_RATES: LazyLock<HashMap<String, i32>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    if let Ok(raw) = std::env::var("EU_VAT_RATES") {
        for pair in raw.split(',') {
            let mut parts = pair.split('=');
            if let (Some(country), Some(rate)) = (parts.next(), parts.next()) {
                if let Ok(rate) = rate.trim().parse::<i32>() {
                    map.insert(country.trim().to_uppercase(), rate);
                }
            }
        }
    }
    map
});

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Calculate the VAT rate and amount for a given subtotal, customer country and
/// optional VAT number.
pub fn calculate_vat(subtotal: i64, country: &str, vat_number: Option<&str>) -> (i32, i64) {
    let country = country.to_uppercase();
    if country == "EE" {
        let amt = ((subtotal * ESTONIA_VAT_RATE as i64) + 50) / 100;
        return (ESTONIA_VAT_RATE, amt);
    }

    if EU_COUNTRIES.contains(&country) {
        if vat_number.is_some() {
            // EU B2B reverse charge
            return (0, 0);
        }
        // EU B2C – charge destination VAT rate when known
        let rate = EU_VAT_RATES.get(&country).copied().unwrap_or(ESTONIA_VAT_RATE);
        let amt = ((subtotal * rate as i64) + 50) / 100;
        return (rate, amt);
    }

    // Non-EU
    (0, 0)
}

/// Generate the next invoice number in `YYYY-NNNNNN` format.
pub async fn generate_invoice_number(pool: &PgPool) -> Result<String, InvoiceError> {
    let year = Utc::now().year();

    let row: (i64,) =
        sqlx::query_as("SELECT nextval('invoice_number_seq')::bigint")
            .fetch_one(pool)
            .await
            .map_err(InvoiceError::Db)?;

    Ok(format!("{year}-{:06}", row.0))
}

/// Input for creating an invoice.
pub struct CreateInvoiceInput {
    pub tenant_id: Uuid,
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

/// Create an invoice.
pub async fn create_invoice(
    pool: &PgPool,
    input: CreateInvoiceInput,
) -> Result<Invoice, InvoiceError> {
    // Fetch billing address country + VAT number for VAT calculation.
    let addr: BillingAddrRow = sqlx::query_as(
        "SELECT country, vat_number FROM billing_addresses WHERE tenant_id = $1",
    )
    .bind(input.tenant_id)
    .fetch_optional(pool)
    .await
    .map_err(InvoiceError::Db)?
    .ok_or(InvoiceError::NoBillingAddress)?;

    let invoice_number = generate_invoice_number(pool).await?;

    let mut line_items = Vec::with_capacity(input.line_items.len());
    let mut subtotal: i64 = 0;
    let mut vat_total: i64 = 0;

    for item in &input.line_items {
        let amount = item.quantity * item.unit_price;
        let (vat_rate, vat_amount) =
            calculate_vat(amount, &addr.country, addr.vat_number.as_deref());
        subtotal += amount;
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
    let due_at = input.due_at.unwrap_or_else(|| {
        now + chrono::Duration::days(30)
    });
    let currency = input.currency.unwrap_or_else(|| "eur".into());
    let id = Uuid::new_v4();
    let items_json = serde_json::to_value(&line_items)?;

    sqlx::query(
        r#"
        INSERT INTO invoices (
            id, tenant_id, stripe_invoice_id, invoice_number, status,
            currency, subtotal, vat_total, total, line_items,
            issued_at, due_at, period_start, period_end,
            created_at, updated_at
        ) VALUES (
            $1, $2, $3, $4, 'draft',
            $5, $6, $7, $8, $9,
            $10, $11, $12, $13,
            $10, $10
        )
        "#,
    )
    .bind(id)
    .bind(input.tenant_id)
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
///
/// This is called automatically after `create_invoice()` and can also be
/// called on-demand to re-generate a PDF for an existing invoice.
pub async fn generate_invoice_pdf(
    pool: &PgPool,
    http_client: &reqwest::Client,
    invoice: &Invoice,
) -> Result<String, InvoiceError> {
    // Build the JSON payload expected by the invoice.typ template
    let pdf_data = serde_json::json!({
        "invoice_number": invoice.invoice_number,
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
        "line_items": invoice.line_items,
    });

    let render_request = serde_json::json!({
        "template": "invoice",
        "data": pdf_data,
    });

    // Call pdf-renderer service
    let resp = http_client
        .post(format!("{}/v1/pdf/render", *PDF_RENDERER_URL))
        .json(&render_request)
        .timeout(std::time::Duration::from_secs(30))
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
    tenant_id: Uuid,
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
    tenant_id: Uuid,
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

impl InvoiceRow {
    fn into_invoice(self) -> Invoice {
        let status = match self.status.as_str() {
            "paid" => InvoiceStatus::Paid,
            "pending" => InvoiceStatus::Pending,
            "void" => InvoiceStatus::Void,
            "uncollectible" => InvoiceStatus::Uncollectible,
            _ => InvoiceStatus::Draft,
        };

        let line_items: Vec<InvoiceLineItem> = self
            .line_items
            .and_then(|v| serde_json::from_value(v).ok())
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
    type HmacSha256 = Hmac<Sha256>;

    let endpoint = &*S3_ENDPOINT;
    let bucket = &*S3_BUCKET;
    let region = &*S3_REGION;
    let access_key = &*S3_ACCESS_KEY_ID;
    let secret_key = &*S3_SECRET_ACCESS_KEY;

    if access_key.is_empty() || secret_key.is_empty() {
        return Err(InvoiceError::PdfGeneration(
            "S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY must be set for invoice PDF upload".into(),
        ));
    }

    let now = Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

    // SHA-256 of request body
    let payload_hash = hex_encode(&Sha256::digest(body));

    // Host: virtual-hosted style for broad S3 compatibility
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
    let canonical_request = format!(
        "PUT\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );

    // String to sign
    let credential_scope = format!("{date_stamp}/{region}/s3/aws4_request");
    let canonical_hash = hex_encode(&Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{canonical_hash}"
    );

    // Derive signing key: HMAC chain date → region → service → aws4_request
    let k_date = HmacSha256::new_from_slice(format!("AWS4{secret_key}").as_bytes())
        .expect("HMAC key length")
        .chain_update(date_stamp.as_bytes())
        .finalize()
        .into_bytes();
    let k_region = HmacSha256::new_from_slice(&k_date)
        .expect("HMAC key length")
        .chain_update(region.as_bytes())
        .finalize()
        .into_bytes();
    let k_service = HmacSha256::new_from_slice(&k_region)
        .expect("HMAC key length")
        .chain_update(b"s3")
        .finalize()
        .into_bytes();
    let k_signing = HmacSha256::new_from_slice(&k_service)
        .expect("HMAC key length")
        .chain_update(b"aws4_request")
        .finalize()
        .into_bytes();

    // Final signature
    let signature = hex_encode(
        &HmacSha256::new_from_slice(&k_signing)
            .expect("HMAC key length")
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

    #[test]
    fn vat_estonia_always_charged() {
        let (rate, amt) = calculate_vat(10_000, "EE", None);
        assert_eq!(rate, 22);
        assert_eq!(amt, 2_200); // 22 % of 10 000
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
        assert_eq!(rate, 22);
        assert_eq!(amt, 2_200);
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
            tenant_id: Uuid::new_v4(),
            stripe_invoice_id: None,
            invoice_number: "2026-000001".into(),
            status: "paid".into(),
            currency: "eur".into(),
            subtotal: 1000,
            vat_total: 220,
            total: 1220,
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
    fn hex_encode_works() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0xab]), "00ffab");
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }
}
