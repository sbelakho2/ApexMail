//! Invoice management – create, list, get by ID.
//!
//! VAT logic follows Estonian rules (22 % local, reverse-charge for EU B2B,
//! 0 % for non-EU).

use chrono::{DateTime, Datelike, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::{Invoice, InvoiceLineItem, InvoiceStatus};
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

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
    let items_json = serde_json::to_value(&line_items).unwrap_or_default();

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
}
