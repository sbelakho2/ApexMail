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
/// documents — the export must show the address captured AT ISSUE TIME.
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
    /// Buyer registry code frozen at issue time (audit F08, migration 185);
    /// NULL on legacy invoices that predate the freeze.
    billing_registry_code: Option<String>,
    subtotal: i64,
    vat_total: i64,
    total: i64,
    currency: String,
    status: String,
}

/// Versioned snapshot DTO (audit F08): the billing-address snapshot a
/// reader must parse SUCCESSFULLY for an issued document. Field names
/// accept both writer dialects (billing-service snake_case, api-server
/// admin camelCase); `snapshotVersion` identifies the contract (an
/// unrecognized future version is surfaced, not silently reinterpreted).
#[derive(Debug, serde::Deserialize)]
struct BillingAddressSnapshotV1 {
    #[serde(default, alias = "snapshotVersion")]
    snapshot_version: Option<u32>,
    #[serde(default, alias = "companyName")]
    company_name: Option<String>,
    #[serde(default, alias = "vatNumber")]
    vat_number: Option<String>,
    #[serde(default, alias = "addressLine1")]
    address_line1: Option<String>,
    #[serde(default, alias = "addressLine2")]
    address_line2: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default, alias = "postalCode")]
    postal_code: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default, alias = "registryCode")]
    registry_code: Option<String>,
}

/// The snapshot contract version this reader understands (audit F08).
const SUPPORTED_SNAPSHOT_VERSION: u32 = 1;

/// How ONE invoice's address source was chosen (audit F08: the choice is
/// made ONCE per invoice, never per field).
#[derive(Debug, PartialEq, Eq)]
enum SnapshotSource {
    /// The invoice carries a valid issued snapshot — every field comes
    /// from it; null/empty fields REMAIN null/empty.
    Snapshot,
    /// Legacy invoice issued before snapshotting — the explicitly
    /// labelled live-address fallback applies.
    LegacyLiveFallback,
    /// The snapshot is present but malformed — surfaced for repair (the
    /// export row is emitted with a repair marker, live data is NOT
    /// silently substituted).
    RepairRequired,
}

fn trim_nonempty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.trim().is_empty())
}

impl FetchedAccountingRow {
    /// Choose snapshot-vs-live ONCE for the whole invoice (audit F08) and
    /// build the export row from exactly one source.
    fn into_export_row(self) -> AccountingExportRow {
        // Decide the source first: a parseable snapshot wins for every
        // field; a missing snapshot is the legacy fallback; an
        // unparseable one surfaces for repair.
        let mut source = SnapshotSource::LegacyLiveFallback;
        let mut snapshot = BillingAddressSnapshotV1 {
            snapshot_version: None,
            company_name: None,
            vat_number: None,
            address_line1: None,
            address_line2: None,
            city: None,
            state: None,
            postal_code: None,
            country: None,
            registry_code: None,
        };
        if self.billing_address_snapshot.is_some() {
            match self
                .billing_address_snapshot
                .as_deref()
                .and_then(|raw| serde_json::from_str::<BillingAddressSnapshotV1>(raw).ok())
            {
                Some(parsed) => {
                    if let Some(version) = parsed.snapshot_version {
                        if version > SUPPORTED_SNAPSHOT_VERSION {
                            tracing::warn!(
                                invoice_number = %self.invoice_number,
                                version,
                                "accounting export: unknown billing-address snapshot version — interpreting as v1"
                            );
                        }
                    }
                    source = SnapshotSource::Snapshot;
                    snapshot = parsed;
                }
                None => {
                    source = SnapshotSource::RepairRequired;
                    tracing::error!(
                        invoice_number = %self.invoice_number,
                        "accounting export: malformed billing-address snapshot — row emitted with a repair marker"
                    );
                }
            }
        }

        let mut export = match source {
            SnapshotSource::Snapshot => {
                // Valid snapshot: fields come ONLY from it; null/empty
                // stays null/empty — the live account can never refill a
                // historical document.
                AccountingExportRow {
                    invoice_number: self.invoice_number,
                    issued_at: self.issued_at,
                    due_at: self.due_at,
                    tenant_name: self.tenant_name,
                    company_name: trim_nonempty(snapshot.company_name),
                    registry_code: trim_nonempty(snapshot.registry_code),
                    address_line1: trim_nonempty(snapshot.address_line1),
                    address_line2: trim_nonempty(snapshot.address_line2),
                    city: trim_nonempty(snapshot.city),
                    state: trim_nonempty(snapshot.state),
                    postal_code: trim_nonempty(snapshot.postal_code),
                    country: trim_nonempty(snapshot.country),
                    vat_number: trim_nonempty(snapshot.vat_number),
                    subtotal: self.subtotal,
                    vat_total: self.vat_total,
                    total: self.total,
                    currency: self.currency,
                    status: self.status,
                }
            }
            SnapshotSource::LegacyLiveFallback | SnapshotSource::RepairRequired => {
                // Explicitly labelled LEGACY fallback (pre-snapshot
                // invoices) — or a corrupt snapshot, where the live values
                // are NOT silently substituted: the row ships empty with a
                // repair marker in the customer-name column so operators
                // see exactly which documents need repair.
                let legacy = source == SnapshotSource::LegacyLiveFallback;
                AccountingExportRow {
                    invoice_number: self.invoice_number.clone(),
                    issued_at: self.issued_at,
                    due_at: self.due_at,
                    tenant_name: self.tenant_name,
                    company_name: if legacy {
                        trim_nonempty(self.company_name)
                    } else {
                        None
                    },
                    registry_code: if legacy {
                        trim_nonempty(self.billing_registry_code)
                    } else {
                        None
                    },
                    address_line1: if legacy { self.address_line1 } else { None },
                    address_line2: if legacy { self.address_line2 } else { None },
                    city: if legacy { self.city } else { None },
                    state: if legacy { self.state } else { None },
                    postal_code: if legacy { self.postal_code } else { None },
                    country: if legacy { self.country } else { None },
                    vat_number: if legacy { self.vat_number } else { None },
                    subtotal: self.subtotal,
                    vat_total: self.vat_total,
                    total: self.total,
                    currency: self.currency,
                    status: self.status,
                }
            }
        };

        if source == SnapshotSource::RepairRequired {
            // Surface the corrupt snapshot for repair (audit F08): the
            // buyer column carries an explicit marker instead of live data.
            export.company_name = Some(format!(
                "[SNAPSHOT REPAIR REQUIRED: {}]",
                export.invoice_number
            ));
        }
        export
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
/// at issue time, versioned contract incl. the registry identity frozen
/// via `billing_registry_code`) is the address source for issued
/// documents — chosen ONCE per invoice in `into_export_row`. The
/// live-address LATERAL join feeds only the explicitly labelled legacy
/// fallback for invoices issued before snapshotting.
/// `billing_addresses.state` exists since migration 132.
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
            i.billing_registry_code,
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
    // Audit F08 — snapshot versus live is chosen ONCE per invoice. A
    // valid snapshot supplies every field (nulls stay null); only legacy
    // rows without any snapshot use the live join; malformed snapshots
    // surface for repair instead of silently degrading to live values.
    // ------------------------------------------------------------------

    fn fetched_row(
        snapshot: Option<&str>,
        live_city: Option<&str>,
        registry: Option<&str>,
    ) -> FetchedAccountingRow {
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
            billing_registry_code: registry.map(str::to_string),
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
        let row = fetched_row(Some(snapshot), Some("Tallinn"), None).into_export_row();
        assert_eq!(row.company_name.as_deref(), Some("Snapshot OÜ"));
        assert_eq!(row.city.as_deref(), Some("Tartu"));
        assert_eq!(row.state.as_deref(), Some("Tartumaa"));
        // F08: a field ABSENT from a valid snapshot stays null — the live
        // join no longer refills it.
        assert_eq!(row.address_line1, None);
    }

    #[test]
    fn snapshot_null_optional_fields_stay_null_after_account_edits() {
        // F08 verification: an issued invoice whose optional fields are
        // empty keeps them empty even though the live account now has
        // values (byte-for-byte historical stability).
        let snapshot = r#"{"company_name":"Snapshot OÜ","country":"EE"}"#;
        let row = fetched_row(Some(snapshot), Some("Tallinn"), None).into_export_row();
        assert_eq!(row.company_name.as_deref(), Some("Snapshot OÜ"));
        assert_eq!(row.address_line1, None);
        assert_eq!(row.address_line2, None);
        assert_eq!(row.city, None);
        assert_eq!(row.state, None);
        assert_eq!(row.postal_code, None);
        assert_eq!(row.vat_number, None);
    }

    #[test]
    fn snapshot_parses_the_camelcase_admin_writer_dialect() {
        // Same snapshot contract as the api-server admin writer.
        let snapshot =
            r#"{"snapshotVersion":1,"companyName":"Admin OÜ","addressLine1":"Admin St 9"}"#;
        let row = fetched_row(Some(snapshot), Some("Tallinn"), None).into_export_row();
        assert_eq!(row.company_name.as_deref(), Some("Admin OÜ"));
        assert_eq!(row.address_line1.as_deref(), Some("Admin St 9"));
        assert_eq!(row.city, None);
    }

    #[test]
    fn snapshot_registry_identity_is_frozen_at_issue_time() {
        let snapshot = r#"{"company_name":"Snapshot OÜ","registry_code":"16377012"}"#;
        let row = fetched_row(Some(snapshot), None, Some("LATER-CHANGED")).into_export_row();
        assert_eq!(row.registry_code.as_deref(), Some("16377012"));
    }

    #[test]
    fn legacy_rows_without_snapshot_use_the_live_address() {
        let row = fetched_row(None, Some("Tallinn"), Some("10001234")).into_export_row();
        assert_eq!(row.company_name.as_deref(), Some("Live Company OÜ"));
        assert_eq!(row.city.as_deref(), Some("Tallinn"));
        assert_eq!(row.registry_code.as_deref(), Some("10001234"));
    }

    #[test]
    fn malformed_snapshot_is_surfaced_for_repair_not_refilled() {
        let row = fetched_row(Some("{not json"), Some("Tallinn"), None).into_export_row();
        // No live substitution: the address fields stay empty and the
        // buyer column carries an explicit repair marker.
        assert_eq!(row.city, None);
        assert_eq!(row.address_line1, None);
        let company = row.company_name.expect("repair marker present");
        assert!(company.contains("SNAPSHOT REPAIR REQUIRED"));
        assert!(company.contains("INV-SNAP"));
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
