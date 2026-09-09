//! Estonian accounting CSV export — produces a CSV file formatted for
//! Estonian bookkeeping (raamatupidamine) and the KMD VAT return reconciliation.
//!
//! The output follows the Eesti standard arve (invoice) layout with fields
//! compatible with popular accounting software (MerchantPro, e-arve, etc.).
//!
//! # Columns
//!
//! | Column | Eesti | Description |
//! |--------|-------|-------------|
//! | Invoice Number | Arve number | Unique invoice identifier |
//! | Issue Date | Kuupäev | Date invoice was issued |
//! | Due Date | Maksetähtaeg | Payment due date |
//! | Customer Name | Ostja nimi | Tenant / company name |
//! | Registry Code | Registrikood | Business registry code (from tenant metadata) |
//! | Address | Aadress | Full billing address |
//! | VAT Number | KMKR number | Customer's VAT registration number |
//! | Description | Teenuse kirjeldus | Invoice line item description |
//! | Quantity | Kogus | Number of units |
//! | Unit Price | Ühiku hind | Price per unit (cents) |
//! | Net Amount | Netosumma | Amount excluding VAT (cents) |
//! | VAT Rate | Käibemaksumäär | VAT percentage |
//! | VAT Amount | Käibemaks | Total VAT (cents) |
//! | Total Amount | Kogusumma | Grand total including VAT (cents) |
//! | Currency | Valuuta | ISO 4217 currency code |
//! | Status | Staatus | Invoice status (paid/unpaid/cancelled) |

use billing_common::csv::quote_csv_field;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::info;

/// A single row in the accounting export CSV.
#[derive(Debug, sqlx::FromRow)]
struct AccountingExportRow {
    invoice_number: String,
    issued_at: DateTime<Utc>,
    due_at: Option<DateTime<Utc>>,
    tenant_name: Option<String>,
    company_name: Option<String>,
    registry_code: Option<String>,
    address_line1: Option<String>,
    address_line2: Option<String>,
    city: Option<String>,
    state: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
    vat_number: Option<String>,
    subtotal: i64,
    vat_total: i64,
    total: i64,
    currency: String,
    status: String,
}

/// Raw fetched row: the join fields above PLUS the invoice's immutable
/// billing-address snapshot (audit F08). Issued invoices are legal
/// documents — the export must show the address captured AT ISSUE TIME;
/// the live `billing_addresses` join remains the fallback for legacy rows
/// that predate snapshotting.
#[derive(Debug, sqlx::FromRow)]
struct FetchedAccountingRow {
    invoice_number: String,
    issued_at: DateTime<Utc>,
    due_at: Option<DateTime<Utc>>,
    tenant_name: Option<String>,
    company_name: Option<String>,
    address_line1: Option<String>,
    address_line2: Option<String>,
    city: Option<String>,
    state: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
    vat_number: Option<String>,
    billing_address_snapshot: Option<String>,
    subtotal: i64,
    vat_total: i64,
    total: i64,
    currency: String,
    status: String,
}

impl FetchedAccountingRow {
    /// Snapshot-first resolution of one address field: the value frozen on
    /// the invoice wins (snake_case key from the billing-service writer or
    /// camelCase from the api-server admin writer); the live address join
    /// fills legacy gaps.
    fn resolve(
        snapshot: &serde_json::Value,
        snake_key: &str,
        camel_key: &str,
        live: Option<&String>,
    ) -> Option<String> {
        snapshot
            .get(snake_key)
            .or_else(|| snapshot.get(camel_key))
            .and_then(|value| value.as_str())
            .map(str::to_string)
            .filter(|value| !value.is_empty())
            .or_else(|| live.cloned().filter(|value| !value.is_empty()))
    }

    fn into_export_row(self) -> AccountingExportRow {
        let snapshot: serde_json::Value = self
            .billing_address_snapshot
            .as_deref()
            .and_then(|raw| serde_json::from_str(raw).ok())
            .unwrap_or(serde_json::Value::Null);

        AccountingExportRow {
            invoice_number: self.invoice_number,
            issued_at: self.issued_at,
            due_at: self.due_at,
            tenant_name: self.tenant_name,
            company_name: Self::resolve(
                &snapshot,
                "company_name",
                "companyName",
                self.company_name.as_ref(),
            ),
            registry_code: None,
            address_line1: Self::resolve(
                &snapshot,
                "address_line1",
                "addressLine1",
                self.address_line1.as_ref(),
            ),
            address_line2: Self::resolve(
                &snapshot,
                "address_line2",
                "addressLine2",
                self.address_line2.as_ref(),
            ),
            city: Self::resolve(&snapshot, "city", "city", self.city.as_ref()),
            state: Self::resolve(&snapshot, "state", "state", self.state.as_ref()),
            postal_code: Self::resolve(
                &snapshot,
                "postal_code",
                "postalCode",
                self.postal_code.as_ref(),
            ),
            country: Self::resolve(&snapshot, "country", "country", self.country.as_ref()),
            vat_number: Self::resolve(
                &snapshot,
                "vat_number",
                "vatNumber",
                self.vat_number.as_ref(),
            ),
            subtotal: self.subtotal,
            vat_total: self.vat_total,
            total: self.total,
            currency: self.currency,
            status: self.status,
        }
    }
}

/// Export accounting data as a CSV string for the given date range.
///
/// Returns a UTF-8 CSV string with BOM for Excel compatibility.
pub async fn export_accounting_csv(
    pool: &PgPool,
    start_date: DateTime<Utc>,
    end_date: DateTime<Utc>,
) -> Result<String, String> {
    let rows = fetch_accounting_rows(pool, start_date, end_date).await?;
    Ok(build_csv(rows))
}

/// Fetch invoice data joined with tenant info and billing addresses.
///
/// Audit F08: the invoice's immutable `billing_address` snapshot (captured
/// at issue time) is the PRIMARY address source; the live-address LATERAL
/// join is only the fallback for legacy invoices issued before
/// snapshotting. `billing_addresses.state` exists since migration 132.
async fn fetch_accounting_rows(
    pool: &PgPool,
    start_date: DateTime<Utc>,
    end_date: DateTime<Utc>,
) -> Result<Vec<AccountingExportRow>, String> {
    let rows: Vec<FetchedAccountingRow> = sqlx::query_as(
        r#"
        SELECT
            i.invoice_number,
            i.issued_at,
            i.due_at,
            t.name AS tenant_name,
            ba.company_name,
            ba.address_line1,
            ba.address_line2,
            ba.city,
            ba.state,
            ba.postal_code,
            ba.country,
            ba.vat_number,
            i.billing_address AS billing_address_snapshot,
            i.subtotal,
            i.vat_total,
            i.total,
            i.currency,
            i.status
        FROM invoices i
        JOIN tenants t ON t.id = i.tenant_id
        -- LATERAL picks exactly ONE address row per tenant (newest first),
        -- mirroring the KMD rate-breakdown join: a plain LEFT JOIN fans
        -- out when a tenant ever had two billing addresses, duplicating
        -- every invoice row in the export (double-counted bookkeeping).
        -- Migration 116 added UNIQUE(tenant_id) for the future; this also
        -- holds for historical multi-row databases.
        LEFT JOIN LATERAL (
            SELECT company_name, address_line1, address_line2, city, state,
                   postal_code, country, vat_number
            FROM billing_addresses ba
            WHERE ba.tenant_id = i.tenant_id
            ORDER BY ba.updated_at DESC, ba.created_at DESC, ba.id
            LIMIT 1
        ) ba ON true
        WHERE i.issued_at >= $1 AND i.issued_at < $2
        ORDER BY i.issued_at ASC
        "#,
    )
    .bind(start_date)
    .bind(end_date)
    .fetch_all(pool)
    .await
    .map_err(|e| format!("Failed to query accounting data: {e}"))?;

    let rows: Vec<AccountingExportRow> = rows
        .into_iter()
        .map(FetchedAccountingRow::into_export_row)
        .collect();
    info!(rows = rows.len(), "Accounting export query returned rows");

    Ok(rows)
}

/// Build a CSV string from accounting rows.
///
/// Format: UTF-8 with BOM (U+FEFF) for Excel compatibility.
/// All fields are quoted and escaped per RFC 4180.
fn build_csv(rows: Vec<AccountingExportRow>) -> String {
    // BOM for Excel UTF-8 detection
    let mut csv = String::from("\u{feff}");

    // Header row (Estonian accounting column names)
    csv.push_str("\"Arve number\",\"Kuupäev\",\"Maksetähtaeg\",");
    csv.push_str("\"Ostja nimi\",\"Registrikood\",\"Aadress\",\"KMKR number\",");
    csv.push_str("\"Teenuse kirjeldus\",\"Kogus\",\"Ühiku hind\",");
    csv.push_str("\"Netosumma\",\"Käibemaksumäär\",\"Käibemaks\",\"Kogusumma\",");
    csv.push_str("\"Valuuta\",\"Staatus\"\n");

    for row in &rows {
        let customer_name = row
            .company_name
            .as_deref()
            .or(row.tenant_name.as_deref())
            .unwrap_or("");

        let address = build_address_string(row);

        let description = build_description(row);
        let quantity = "1";
        // Each invoice is a single line item, so unit price = subtotal
        let unit_price_cents = row.subtotal.to_string();
        let vat_rate_pct = if row.subtotal > 0 {
            // Integer half-up rounding: (vat * 100 + subtotal/2) / subtotal.
            // Avoids the precision loss of `as f64` for large cent values and
            // matches the integer rates stored in the `vat_rates` table.
            let numer = row.vat_total.saturating_mul(100);
            let half = row.subtotal / 2;
            numer.saturating_add(half) / row.subtotal
        } else {
            0
        };

        append_csv_field(&mut csv, &row.invoice_number);
        append_csv_field(&mut csv, &row.issued_at.format("%Y-%m-%d").to_string());
        append_csv_field(
            &mut csv,
            &row.due_at
                .map(|d| d.format("%Y-%m-%d").to_string())
                .unwrap_or_default(),
        );
        append_csv_field(&mut csv, customer_name);
        append_csv_field(&mut csv, row.registry_code.as_deref().unwrap_or(""));
        append_csv_field(&mut csv, &address);
        append_csv_field(&mut csv, row.vat_number.as_deref().unwrap_or(""));
        append_csv_field(&mut csv, &description);
        append_csv_field(&mut csv, quantity);
        append_csv_field(&mut csv, &unit_price_cents);
        append_csv_field(&mut csv, &row.subtotal.to_string());
        append_csv_field(&mut csv, &format!("{vat_rate_pct}%"));
        append_csv_field(&mut csv, &row.vat_total.to_string());
        append_csv_field(&mut csv, &row.total.to_string());
        append_csv_field(&mut csv, &row.currency);
        append_csv_field(&mut csv, &row.status);
        csv.push('\n');
    }

    csv
}

/// Build a human-readable address string from address components.
fn build_address_string(row: &AccountingExportRow) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if let Some(ref line1) = row.address_line1 {
        parts.push(line1);
    }
    if let Some(ref line2) = row.address_line2 {
        parts.push(line2);
    }
    if let Some(ref city) = row.city {
        parts.push(city);
    }
    if let Some(ref state) = row.state {
        parts.push(state);
    }
    if let Some(ref postal) = row.postal_code {
        parts.push(postal);
    }
    if let Some(ref country) = row.country {
        parts.push(country);
    }
    parts.join(", ")
}

/// Build a description string from available invoice metadata.
fn build_description(row: &AccountingExportRow) -> String {
    format!(
        "Email service - {} ({})",
        row.invoice_number,
        row.issued_at.format("%B %Y")
    )
}

/// Append a single CSV field, properly quoted and escaped.
fn append_csv_field(csv: &mut String, field: &str) {
    csv.push_str(&quote_csv_field(field));
    csv.push(',');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_csv_field_escapes_quotes() {
        let mut csv = String::new();
        append_csv_field(&mut csv, r#"he"llo"#);
        assert_eq!(csv, r#""he""llo","#);
    }

    #[test]
    fn test_append_csv_field_normal() {
        let mut csv = String::new();
        append_csv_field(&mut csv, "hello");
        assert_eq!(csv, r#""hello","#);
    }

    #[test]
    fn test_append_csv_field_empty() {
        let mut csv = String::new();
        append_csv_field(&mut csv, "");
        assert_eq!(csv, r#""","#);
    }

    #[test]
    fn test_append_csv_field_prefixes_formula_like_values() {
        let mut csv = String::new();
        append_csv_field(&mut csv, "=SUM(A1:A2)");
        assert_eq!(csv, "\"'=SUM(A1:A2)\",");
    }

    #[test]
    fn test_build_address_string_all_fields() {
        let row = AccountingExportRow {
            invoice_number: "INV-001".into(),
            issued_at: Utc::now(),
            due_at: None,
            tenant_name: Some("Test".into()),
            company_name: None,
            registry_code: None,
            address_line1: Some("Main St 1".into()),
            address_line2: None,
            city: Some("Tallinn".into()),
            state: None,
            postal_code: Some("10111".into()),
            country: Some("Estonia".into()),
            vat_number: None,
            subtotal: 10000,
            vat_total: 2200,
            total: 12200,
            currency: "EUR".into(),
            status: "paid".into(),
        };
        let addr = build_address_string(&row);
        assert!(addr.contains("Main St 1"));
        assert!(addr.contains("Tallinn"));
        assert!(addr.contains("10111"));
        assert!(addr.contains("Estonia"));
    }

    #[test]
    fn test_build_address_string_minimal() {
        let row = AccountingExportRow {
            invoice_number: "INV-002".into(),
            issued_at: Utc::now(),
            due_at: None,
            tenant_name: Some("Test".into()),
            company_name: None,
            registry_code: None,
            address_line1: None,
            address_line2: None,
            city: None,
            state: None,
            postal_code: None,
            country: None,
            vat_number: None,
            subtotal: 5000,
            vat_total: 1000,
            total: 6000,
            currency: "EUR".into(),
            status: "unpaid".into(),
        };
        let addr = build_address_string(&row);
        assert_eq!(addr, "");
    }

    // ------------------------------------------------------------------
    // Audit F08 — the immutable invoice snapshot wins over the live
    // billing address; legacy rows fall back to the join.
    // ------------------------------------------------------------------

    fn fetched_row(snapshot: Option<&str>, live_city: Option<&str>) -> FetchedAccountingRow {
        FetchedAccountingRow {
            invoice_number: "INV-SNAP".into(),
            issued_at: Utc::now(),
            due_at: None,
            tenant_name: Some("Test".into()),
            company_name: Some("Live Company OÜ".into()),
            address_line1: Some("Live Street 1".into()),
            address_line2: None,
            city: live_city.map(str::to_string),
            state: None,
            postal_code: None,
            country: Some("EE".into()),
            vat_number: None,
            billing_address_snapshot: snapshot.map(str::to_string),
            subtotal: 1000,
            vat_total: 240,
            total: 1240,
            currency: "EUR".into(),
            status: "paid".into(),
        }
    }

    #[test]
    fn snapshot_address_wins_over_the_live_address() {
        let snapshot = r#"{"company_name":"Snapshot OÜ","city":"Tartu","state":"Tartumaa"}"#;
        let row = fetched_row(Some(snapshot), Some("Tallinn")).into_export_row();
        assert_eq!(row.company_name.as_deref(), Some("Snapshot OÜ"));
        assert_eq!(row.city.as_deref(), Some("Tartu"));
        assert_eq!(row.state.as_deref(), Some("Tartumaa"));
        // Fields absent from the snapshot fall back to the live join.
        assert_eq!(row.address_line1.as_deref(), Some("Live Street 1"));
    }

    #[test]
    fn legacy_rows_without_snapshot_use_the_live_address() {
        let row = fetched_row(None, Some("Tallinn")).into_export_row();
        assert_eq!(row.company_name.as_deref(), Some("Live Company OÜ"));
        assert_eq!(row.city.as_deref(), Some("Tallinn"));
    }

    #[test]
    fn malformed_snapshot_degrades_to_the_live_address() {
        let row = fetched_row(Some("{not json"), Some("Tallinn")).into_export_row();
        assert_eq!(row.city.as_deref(), Some("Tallinn"));
    }

    #[test]
    fn test_build_csv_has_bom_and_header() {
        let rows = vec![];
        let csv = build_csv(rows);
        assert!(csv.starts_with('\u{feff}'));
        assert!(csv.contains("Arve number"));
        assert!(csv.contains("Ostja nimi"));
        assert!(csv.contains("Kogusumma"));
    }

    #[test]
    fn test_build_csv_with_data() {
        let row = AccountingExportRow {
            invoice_number: "INV-001".into(),
            issued_at: DateTime::parse_from_rfc3339("2024-01-15T10:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            due_at: Some(
                DateTime::parse_from_rfc3339("2024-02-14T10:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
            tenant_name: Some("OÜ Test".into()),
            company_name: Some("Test Company OÜ".into()),
            registry_code: Some("12345678".into()),
            address_line1: Some("Main St 1".into()),
            address_line2: None,
            city: Some("Tallinn".into()),
            state: None,
            postal_code: Some("10111".into()),
            country: Some("EE".into()),
            vat_number: Some("EE123456789".into()),
            subtotal: 10000,
            vat_total: 2200,
            total: 12200,
            currency: "EUR".into(),
            status: "paid".into(),
        };
        let csv = build_csv(vec![row]);
        assert!(csv.contains("INV-001"));
        assert!(csv.contains("2024-01-15"));
        assert!(csv.contains("2024-02-14"));
        assert!(csv.contains("Test Company OÜ"));
        assert!(csv.contains("12345678"));
        assert!(csv.contains("EE123456789"));
        assert!(csv.contains("22%")); // 2200/10000 = 22%
        assert!(csv.contains("10000")); // subtotal
        assert!(csv.contains("12200")); // total
        assert!(csv.contains("EUR"));
        assert!(csv.contains("paid"));
    }

    #[test]
    fn test_vat_rate_computation() {
        let row = AccountingExportRow {
            invoice_number: "INV-003".into(),
            issued_at: Utc::now(),
            due_at: None,
            tenant_name: None,
            company_name: None,
            registry_code: None,
            address_line1: None,
            address_line2: None,
            city: None,
            state: None,
            postal_code: None,
            country: None,
            vat_number: None,
            subtotal: 20000,
            vat_total: 4800,
            total: 24800,
            currency: "EUR".into(),
            status: "paid".into(),
        };
        let csv = build_csv(vec![row]);
        assert!(csv.contains("24%")); // 4800/20000 = 24%
    }

    #[test]
    fn test_zero_subtotal_handling() {
        let row = AccountingExportRow {
            invoice_number: "INV-004".into(),
            issued_at: Utc::now(),
            due_at: None,
            tenant_name: None,
            company_name: None,
            registry_code: None,
            address_line1: None,
            address_line2: None,
            city: None,
            state: None,
            postal_code: None,
            country: None,
            vat_number: None,
            subtotal: 0,
            vat_total: 0,
            total: 0,
            currency: "EUR".into(),
            status: "cancelled".into(),
        };
        let csv = build_csv(vec![row]);
        assert!(csv.contains("0%")); // vat rate for zero subtotal
        assert!(csv.contains("cancelled"));
    }
}
