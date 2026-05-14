//! KMD (Käibedeklaratsioon) VAT return generation and management.
//!
//! This module handles generating KMD VAT returns for Estonian tax filing,
//! managing VAT rate lookups for EU member states, and providing the core
//! data structures used by the e-MTA filing client.

use billing_common::vat_rates;
use chrono::{DateTime, Datelike, LocalResult, NaiveDate, TimeZone, Utc};
use chrono_tz::Europe::Tallinn;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// KMD returns are Estonian VAT returns, so reporting periods are calendar
/// months in Europe/Tallinn and converted to UTC for invoice timestamp queries.
pub const KMD_PERIOD_TIMEZONE: &str = "Europe/Tallinn";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single VAT rate bucket within a KMD return breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VatRateBucket {
    pub rate: i32,
    pub taxable_amount_cents: i64,
    pub vat_amount_cents: i64,
    pub reason: Option<String>,
    pub invoice_count: i64,
}

/// Aggregated VAT breakdown across all invoices in a period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VatBreakdown {
    pub rates: Vec<VatRateBucket>,
    pub total_taxable_cents: i64,
    pub total_vat_cents: i64,
    pub invoice_count: i64,
    pub tenant_count: i32,
}

/// Result of a KMD return generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VatKmdResult {
    pub tax_year: i32,
    pub tax_month: i32,
    pub invoice_count: i64,
    pub tenant_count: i32,
    pub total_taxable_cents: i64,
    pub total_vat_cents: i64,
    pub rates: Vec<VatRateBucket>,
    pub kmd_id: Uuid,
}

/// Database row for the `vat_kmd_returns` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct VatKmdReturn {
    pub id: Uuid,
    pub tax_year: i32,
    pub tax_month: i32,
    pub status: String,
    pub breakdown: Value,
    pub invoice_count: i32,
    pub total_taxable_cents: i64,
    pub total_vat_cents: i64,
    pub generated_at: DateTime<Utc>,
    pub filed_at: Option<DateTime<Utc>>,
    pub filing_reference: Option<String>,
    pub filing_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// API response type for a KMD return row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmdReturnResponse {
    pub id: String,
    pub tax_year: i32,
    pub tax_month: i32,
    pub status: String,
    pub breakdown: Value,
    pub invoice_count: i32,
    pub total_taxable_cents: i64,
    pub total_vat_cents: i64,
    pub generated_at: DateTime<Utc>,
    pub filed_at: Option<DateTime<Utc>>,
    pub filing_reference: Option<String>,
    pub filing_error: Option<String>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Map a raw row from `vat_kmd_returns` into the API response type.
#[allow(clippy::too_many_arguments)]
pub fn map_kmd_row(
    id: String,
    tax_year: i32,
    tax_month: i32,
    status: String,
    breakdown: Value,
    invoice_count: i32,
    total_taxable_cents: i64,
    total_vat_cents: i64,
    generated_at: DateTime<Utc>,
    filed_at: Option<DateTime<Utc>>,
    filing_reference: Option<String>,
    filing_error: Option<String>,
    _created_at: DateTime<Utc>,
    _updated_at: DateTime<Utc>,
) -> KmdReturnResponse {
    KmdReturnResponse {
        id,
        tax_year,
        tax_month,
        status,
        breakdown,
        invoice_count,
        total_taxable_cents,
        total_vat_cents,
        generated_at,
        filed_at,
        filing_reference,
        filing_error,
    }
}

/// Compute the VAT return due date: 20th of the following month.
pub fn vat_return_due_date(year: i32, month: u32) -> DateTime<Utc> {
    let due_month = if month == 12 { 1 } else { month + 1 };
    let due_year = if month == 12 { year + 1 } else { year };

    chrono::NaiveDate::from_ymd_opt(due_year, due_month, 20)
        .unwrap_or_else(|| {
            chrono::NaiveDate::from_ymd_opt(year, month, 20)
                .expect("invariant: fallback year/month date is always valid")
        })
        .and_hms_opt(23, 59, 59)
        .expect("invariant: any NaiveDate supports 23:59:59")
        .and_utc()
}

/// Check whether a `vat_kmd_returns` table exists in the database.
pub async fn kmd_table_exists(db: &PgPool) -> bool {
    sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
            SELECT FROM information_schema.tables
            WHERE table_name = 'vat_kmd_returns'
        )
        "#,
    )
    .fetch_one(db)
    .await
    .unwrap_or(false)
}

/// Retrieve the most recently generated KMD return.
pub async fn get_latest_kmd_return(db: &PgPool) -> Result<Option<VatKmdResult>, String> {
    let row: Option<VatKmdReturn> = sqlx::query_as::<_, VatKmdReturn>(
        r#"
        SELECT id, tax_year, tax_month, status, breakdown,
               invoice_count, total_taxable_cents, total_vat_cents,
               generated_at, filed_at, filing_reference, filing_error,
               created_at, updated_at
        FROM vat_kmd_returns
        ORDER BY tax_year DESC, tax_month DESC
        LIMIT 1
        "#,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| format!("Failed to query latest KMD return: {e}"))?;

    match row {
        Some(r) => {
            let breakdown: VatBreakdown = serde_json::from_value(r.breakdown.clone())
                .map_err(|e| format!("Failed to parse KMD breakdown: {e}"))?;
            Ok(Some(VatKmdResult {
                tax_year: r.tax_year,
                tax_month: r.tax_month,
                invoice_count: r.invoice_count as i64,
                tenant_count: breakdown.tenant_count,
                total_taxable_cents: r.total_taxable_cents,
                total_vat_cents: r.total_vat_cents,
                rates: breakdown.rates,
                kmd_id: r.id,
            }))
        }
        None => Ok(None),
    }
}

/// Generate a KMD VAT return for the given year/month by aggregating invoice
/// data from the database.
pub async fn generate_kmd_return(
    db: &PgPool,
    tax_year: i32,
    tax_month: u32,
) -> Result<VatKmdResult, String> {
    let (period_start, period_end) = kmd_period_bounds_utc(tax_year, tax_month)?;

    // Query invoice totals for the period
    let totals: (i64, i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*)::bigint,
            COUNT(DISTINCT tenant_id)::bigint,
            COALESCE(SUM(subtotal), 0)::bigint,
            COALESCE(SUM(vat_total), 0)::bigint
        FROM invoices
        WHERE issued_at >= $1
          AND issued_at < $2
          AND status IN ('paid', 'pending')
        "#,
    )
    .bind(period_start)
    .bind(period_end)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("Failed to query invoice totals: {e}"))?
    .unwrap_or((0, 0, 0, 0));

    let (invoice_count, tenant_count, total_taxable_cents, total_vat_cents) = totals;

    // Query rate breakdown by country and VAT number
    let rate_rows: Vec<(i64, i64, String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT
            COALESCE(SUM(i.subtotal), 0)::bigint,
            COALESCE(SUM(i.vat_total), 0)::bigint,
            COALESCE(ba.country, 'EE') AS country,
            ba.vat_number
        FROM invoices i
        LEFT JOIN billing_addresses ba ON ba.tenant_id = i.tenant_id
        WHERE i.issued_at >= $1
          AND i.issued_at < $2
          AND i.status IN ('paid', 'pending')
        GROUP BY ba.country, ba.vat_number
        "#,
    )
    .bind(period_start)
    .bind(period_end)
    .fetch_all(db)
    .await
    .map_err(|e| format!("Failed to query rate breakdown: {e}"))?;

    let mut rates: Vec<VatRateBucket> = Vec::new();
    for (taxable, vat, country, vat_number) in &rate_rows {
        let country_up = country.to_uppercase();
        let is_eu = vat_rates::is_eu_country(&country_up);
        let has_vat = vat_number.is_some();

        let reason = if country_up == "EE" {
            None
        } else if is_eu && has_vat {
            Some("reverse_charge")
        } else if is_eu {
            Some("eu_b2c")
        } else {
            Some("non_eu")
        };

        let vat_rate = if country_up == "EE" {
            vat_rates::ESTONIA_VAT_RATE
        } else if is_eu && !has_vat {
            vat_rates::get_eu_vat_rate(&country_up).unwrap_or(0)
        } else {
            0
        };

        // Merge with existing bucket for the same rate+reason
        if let Some(bucket) = rates
            .iter_mut()
            .find(|b: &&mut VatRateBucket| b.rate == vat_rate && b.reason.as_deref() == reason)
        {
            bucket.taxable_amount_cents += taxable;
            bucket.vat_amount_cents += vat;
            bucket.invoice_count += 1;
        } else {
            rates.push(VatRateBucket {
                rate: vat_rate,
                taxable_amount_cents: *taxable,
                vat_amount_cents: *vat,
                reason: reason.map(|s| s.to_string()),
                invoice_count: 1,
            });
        }
    }

    // Insert the KMD return into the database
    let now = Utc::now();
    let breakdown = VatBreakdown {
        rates: rates.clone(),
        total_taxable_cents,
        total_vat_cents,
        invoice_count,
        tenant_count: tenant_count as i32,
    };

    let kmd_id = Uuid::new_v4();
    let breakdown_json = serde_json::to_value(&breakdown)
        .map_err(|e| format!("Failed to serialize breakdown: {e}"))?;

    sqlx::query(
        r#"
        INSERT INTO vat_kmd_returns
            (id, tax_year, tax_month, status, breakdown,
             invoice_count, total_taxable_cents, total_vat_cents,
             generated_at, created_at, updated_at)
        VALUES ($1, $2, $3, 'draft', $4, $5, $6, $7, $8, $9, $10)
        "#,
    )
    .bind(kmd_id)
    .bind(tax_year)
    .bind(tax_month as i32)
    .bind(&breakdown_json)
    .bind(invoice_count as i32)
    .bind(total_taxable_cents)
    .bind(total_vat_cents)
    .bind(now)
    .bind(now)
    .bind(now)
    .execute(db)
    .await
    .map_err(|e| format!("Failed to insert KMD return: {e}"))?;

    Ok(VatKmdResult {
        tax_year,
        tax_month: tax_month as i32,
        invoice_count,
        tenant_count: tenant_count as i32,
        total_taxable_cents,
        total_vat_cents,
        rates,
        kmd_id,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn kmd_period_bounds_utc(
    tax_year: i32,
    tax_month: u32,
) -> Result<(DateTime<Utc>, DateTime<Utc>), String> {
    let start_date = NaiveDate::from_ymd_opt(tax_year, tax_month, 1)
        .ok_or_else(|| format!("Invalid year/month: {tax_year}/{tax_month}"))?;
    let end_date = if tax_month == 12 {
        NaiveDate::from_ymd_opt(tax_year + 1, 1, 1)
            .expect("invariant: tax_year+1/1/1 is always valid")
    } else {
        NaiveDate::from_ymd_opt(tax_year, tax_month + 1, 1)
            .expect("invariant: tax_year/tax_month+1/1 is always valid")
    };

    Ok((
        tallinn_midnight_to_utc(start_date)?,
        tallinn_midnight_to_utc(end_date)?,
    ))
}

fn tallinn_midnight_to_utc(date: NaiveDate) -> Result<DateTime<Utc>, String> {
    match Tallinn.with_ymd_and_hms(date.year(), date.month(), date.day(), 0, 0, 0) {
        LocalResult::Single(value) => Ok(value.with_timezone(&Utc)),
        LocalResult::Ambiguous(_, _) => Err(format!(
            "Ambiguous {KMD_PERIOD_TIMEZONE} midnight for {}",
            date
        )),
        LocalResult::None => Err(format!(
            "Invalid {KMD_PERIOD_TIMEZONE} midnight for {}",
            date
        )),
    }
}

// All 27 EU member state ISO 3166-1 alpha-2 country codes used for SQL
// filtering and VAT classification.
//
// Replaced by billing_common::vat_rates::{is_eu_country, get_eu_vat_rate, EU_COUNTRIES}
//
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    #[test]
    fn test_is_eu_country_recognizes_member_states() {
        assert!(vat_rates::is_eu_country("EE"));
        assert!(vat_rates::is_eu_country("DE"));
        assert!(vat_rates::is_eu_country("FR"));
        assert!(vat_rates::is_eu_country("IT"));
        assert!(vat_rates::is_eu_country("ES"));
        assert!(!vat_rates::is_eu_country("US"));
        assert!(!vat_rates::is_eu_country("GB"));
        assert!(!vat_rates::is_eu_country("CN"));
    }

    #[test]
    fn test_get_eu_vat_rate_returns_known_rates() {
        assert_eq!(vat_rates::get_eu_vat_rate("EE"), Some(24));
        assert_eq!(vat_rates::get_eu_vat_rate("FI"), Some(26));
        assert_eq!(vat_rates::get_eu_vat_rate("DE"), Some(19));
        assert_eq!(vat_rates::get_eu_vat_rate("HU"), Some(27));
        assert_eq!(vat_rates::get_eu_vat_rate("US"), None);
    }

    /// Verify that all 27 EU member states have a defined VAT rate and
    /// that the country code list matches the rate function.
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

        for (code, expected_rate) in &expected {
            assert!(
                vat_rates::EU_COUNTRIES.contains(&code.to_string()),
                "Country {code} missing from EU_COUNTRIES"
            );
            assert_eq!(
                vat_rates::get_eu_vat_rate(code),
                Some(*expected_rate),
                "Country {code} should have VAT rate {expected_rate}"
            );
        }

        // Verify the count is exactly 27
        assert_eq!(vat_rates::EU_COUNTRIES.len(), 27);
    }

    #[test]
    fn test_vat_return_due_date() {
        // January 2026 return due Feb 20, 2026
        let due = vat_return_due_date(2026, 1);
        assert_eq!(due.month(), 2);
        assert_eq!(due.day(), 20);
        assert_eq!(due.year(), 2026);

        // December 2025 return due Jan 20, 2026
        let due = vat_return_due_date(2025, 12);
        assert_eq!(due.month(), 1);
        assert_eq!(due.day(), 20);
        assert_eq!(due.year(), 2026);
    }

    #[test]
    fn test_kmd_period_bounds_use_tallinn_standard_time() {
        let (start, end) = kmd_period_bounds_utc(2026, 1).unwrap();

        assert_eq!(start, utc_dt(2025, 12, 31, 22, 0, 0));
        assert_eq!(end, utc_dt(2026, 1, 31, 22, 0, 0));
    }

    #[test]
    fn test_kmd_period_bounds_use_tallinn_daylight_time() {
        let (start, end) = kmd_period_bounds_utc(2026, 7).unwrap();

        assert_eq!(start, utc_dt(2026, 6, 30, 21, 0, 0));
        assert_eq!(end, utc_dt(2026, 7, 31, 21, 0, 0));
    }

    #[test]
    fn test_kmd_period_bounds_reject_invalid_month() {
        let err = kmd_period_bounds_utc(2026, 13).unwrap_err();

        assert!(err.contains("Invalid year/month"));
    }

    fn utc_dt(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
    ) -> DateTime<Utc> {
        chrono::NaiveDate::from_ymd_opt(year, month, day)
            .unwrap()
            .and_hms_opt(hour, minute, second)
            .unwrap()
            .and_utc()
    }

    #[test]
    fn test_vat_rate_bucket_serialization() {
        let bucket = VatRateBucket {
            rate: 24,
            taxable_amount_cents: 100000,
            vat_amount_cents: 24000,
            reason: None,
            invoice_count: 10,
        };
        let json = serde_json::to_value(&bucket).unwrap();
        assert_eq!(json["rate"], 24);
        assert_eq!(json["taxable_amount_cents"], 100000);
        assert_eq!(json["vat_amount_cents"], 24000);
        assert!(json["reason"].is_null());
    }

    #[test]
    fn test_vat_rate_bucket_with_reason_serialization() {
        let bucket = VatRateBucket {
            rate: 0,
            taxable_amount_cents: 50000,
            vat_amount_cents: 0,
            reason: Some("reverse_charge".to_string()),
            invoice_count: 5,
        };
        let json = serde_json::to_value(&bucket).unwrap();
        assert_eq!(json["rate"], 0);
        assert_eq!(json["reason"], "reverse_charge");
    }

    #[test]
    fn test_breakdown_aggregation() {
        let breakdown = VatBreakdown {
            rates: vec![
                VatRateBucket {
                    rate: 24,
                    taxable_amount_cents: 100000,
                    vat_amount_cents: 24000,
                    reason: None,
                    invoice_count: 10,
                },
                VatRateBucket {
                    rate: 0,
                    taxable_amount_cents: 50000,
                    vat_amount_cents: 0,
                    reason: Some("reverse_charge".to_string()),
                    invoice_count: 3,
                },
            ],
            total_taxable_cents: 150000,
            total_vat_cents: 24000,
            invoice_count: 13,
            tenant_count: 5,
        };
        let json = serde_json::to_value(&breakdown).unwrap();
        assert_eq!(json["total_taxable_cents"], 150000);
        assert_eq!(json["total_vat_cents"], 24000);
        assert_eq!(json["invoice_count"], 13);
        assert_eq!(json["rates"].as_array().unwrap().len(), 2);
    }
}
