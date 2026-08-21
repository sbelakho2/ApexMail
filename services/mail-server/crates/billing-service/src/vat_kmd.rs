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

/// KMD returns periods are calendar months in Europe/Tallinn converted to UTC.
pub const KMD_PERIOD_TIMEZONE: &str = "Europe/Tallinn";

/// Fix B — KMD (Estonian VAT) returns may only aggregate EUR invoices.
/// Every invoice-selection query in this module applies this filter;
/// non-EUR invoices are reported in `excluded_other_currency` instead.
pub(crate) const EUR_INVOICE_FILTER: &str = "UPPER(currency) = 'EUR'";

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

/// Non-EUR invoices excluded from the (EUR-only) KMD return, grouped by
/// currency so finance can reconcile them (Fix B).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExcludedCurrencyBucket {
    pub currency: String,
    pub taxable_amount_cents: i64,
    pub vat_amount_cents: i64,
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
    /// Non-EUR invoices seen in the period but excluded from the EUR KMD
    /// return. Absent in breakdowns stored before Fix B (serde default).
    #[serde(default)]
    pub excluded_other_currency: Vec<ExcludedCurrencyBucket>,
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
    /// Non-EUR invoices excluded from this EUR return (Fix B).
    #[serde(default)]
    pub excluded_other_currency: Vec<ExcludedCurrencyBucket>,
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

/// Compute the VAT return due date: 20th of the following month at
/// 23:59:59 Europe/Tallinn (local Estonian deadline), expressed in UTC
/// (Fix I14 — previously the wall clock was interpreted as UTC, making the
/// deadline 2–3 hours too early).
pub fn vat_return_due_date(year: i32, month: u32) -> DateTime<Utc> {
    let due_month = if month == 12 { 1 } else { month + 1 };
    let due_year = if month == 12 { year + 1 } else { year };

    let naive = chrono::NaiveDate::from_ymd_opt(due_year, due_month, 20)
        .unwrap_or_else(|| {
            chrono::NaiveDate::from_ymd_opt(year, month, 20)
                .expect("invariant: fallback year/month date is always valid")
        })
        .and_hms_opt(23, 59, 59)
        .expect("invariant: any NaiveDate supports 23:59:59");

    // 23:59:59 can never fall inside a DST transition window, so `Single`
    // is the only realistic outcome; the fallbacks cover the theoretical
    // ambiguous/invalid cases defensively.
    match Tallinn.from_local_datetime(&naive) {
        LocalResult::Single(value) => value.with_timezone(&Utc),
        LocalResult::Ambiguous(earliest, _) => earliest.with_timezone(&Utc),
        LocalResult::None => naive.and_utc(),
    }
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
                excluded_other_currency: breakdown.excluded_other_currency,
                kmd_id: r.id,
            }))
        }
        None => Ok(None),
    }
}

/// List every (year, month) period for which a KMD return row exists.
/// Used by the maintenance backfill to detect missed months (Fix I5).
pub async fn list_generated_kmd_periods(db: &PgPool) -> Result<Vec<(i32, u32)>, String> {
    let rows: Vec<(i32, i32)> = sqlx::query_as(
        "SELECT tax_year, tax_month FROM vat_kmd_returns ORDER BY tax_year, tax_month",
    )
    .fetch_all(db)
    .await
    .map_err(|e| format!("Failed to list KMD periods: {e}"))?;

    Ok(rows
        .into_iter()
        .filter_map(|(year, month)| u32::try_from(month).ok().map(|month| (year, month)))
        .collect())
}

/// Iterate months strictly after `from` through `to` (inclusive), bounded to
/// `cap` steps so a stale deployment cannot loop for decades (Fix I5).
pub(crate) fn month_steps(from: (i32, u32), to: (i32, u32), cap: usize) -> Vec<(i32, u32)> {
    let mut steps = Vec::new();
    let (mut year, mut month) = from;
    let mut remaining = cap;

    while remaining > 0 {
        month += 1;
        if month > 12 {
            month = 1;
            year += 1;
        }
        if (year, month) > to {
            break;
        }
        steps.push((year, month));
        remaining -= 1;
    }

    steps
}

/// True when `currency` is EUR (case-insensitive, whitespace-tolerant).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn is_eur_currency(currency: &str) -> bool {
    currency.trim().eq_ignore_ascii_case("EUR")
}

/// Resolve the KMD bucket (rate + reason) for one invoice aggregate.
///
/// Fix I4 — when the invoice row carries the rate/country captured at
/// creation (migration 101), those values win over the tenant's *current*
/// billing address, so an invoice charged 24 % EE VAT stays in the EE bucket
/// even if the address is later re-filed under a VAT-number-bearing country.
/// Rows created before migration 101 (NULL stored values) fall back to the
/// legacy current-address derivation.
/// TODO(vat-history): backfill billing_country/vat_rate for pre-101 invoices.
pub(crate) fn effective_vat_bucket(
    stored_country: Option<&str>,
    stored_rate: Option<i32>,
    current_country: Option<&str>,
    has_vat_number: bool,
) -> (i32, Option<&'static str>) {
    if let Some(rate) = stored_rate {
        let country = stored_country
            .or(current_country)
            .unwrap_or("EE")
            .to_uppercase();
        let is_eu = vat_rates::is_eu_country(&country);
        let reason = if country == "EE" {
            None
        } else if is_eu && rate == 0 {
            Some("reverse_charge")
        } else if is_eu {
            Some("eu_b2c")
        } else {
            Some("non_eu")
        };
        return (rate, reason);
    }

    // Legacy path: derive from the current billing address.
    let country = current_country
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("EE")
        .to_uppercase();
    let is_eu = vat_rates::is_eu_country(&country);

    if country == "EE" {
        return (vat_rates::ESTONIA_VAT_RATE, None);
    }
    if is_eu && has_vat_number {
        return (0, Some("reverse_charge"));
    }
    if is_eu {
        return (vat_rates::get_eu_vat_rate(&country).unwrap_or(0), Some("eu_b2c"));
    }
    (0, Some("non_eu"))
}

/// Generate a KMD VAT return for the given year/month by aggregating invoice
/// data from the database.
///
/// Fix B — only EUR invoices feed the Estonian VAT return; non-EUR invoices
/// are aggregated into `excluded_other_currency` so they stay visible to
/// finance without corrupting the EUR figures.
pub async fn generate_kmd_return(
    db: &PgPool,
    tax_year: i32,
    tax_month: u32,
) -> Result<VatKmdResult, String> {
    let (period_start, period_end) = kmd_period_bounds_utc(tax_year, tax_month)?;

    // Query invoice totals for the period (EUR only — Fix B).
    let totals: (i64, i64, i64, i64) = sqlx::query_as(&format!(
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
          AND {EUR_INVOICE_FILTER}
        "#,
    ))
    .bind(period_start)
    .bind(period_end)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("Failed to query invoice totals: {e}"))?
    .unwrap_or((0, 0, 0, 0));

    let (invoice_count, tenant_count, total_taxable_cents, total_vat_cents) = totals;

    // Non-EUR invoices excluded from the EUR return, grouped per currency.
    let excluded_rows: Vec<(String, i64, i64, i64)> = sqlx::query_as(&format!(
        r#"
        SELECT
            UPPER(currency) AS currency,
            COUNT(*)::bigint,
            COALESCE(SUM(subtotal), 0)::bigint,
            COALESCE(SUM(vat_total), 0)::bigint
        FROM invoices
        WHERE issued_at >= $1
          AND issued_at < $2
          AND status IN ('paid', 'pending')
          AND NOT ({EUR_INVOICE_FILTER})
        GROUP BY UPPER(currency)
        ORDER BY currency
        "#,
    ))
    .bind(period_start)
    .bind(period_end)
    .fetch_all(db)
    .await
    .map_err(|e| format!("Failed to query excluded-currency invoices: {e}"))?;

    let excluded_other_currency: Vec<ExcludedCurrencyBucket> = excluded_rows
        .into_iter()
        .map(|(currency, count, taxable, vat)| ExcludedCurrencyBucket {
            currency,
            invoice_count: count,
            taxable_amount_cents: taxable,
            vat_amount_cents: vat,
        })
        .collect();

    // Query rate breakdown. Fix I4 — prefer the country + VAT rate captured
    // on the invoice row at creation; fall back to the current billing
    // address only for pre-migration-101 rows (both stored values NULL).
    let rate_rows: Vec<(i64, i64, Option<String>, Option<i32>, Option<bool>)> = sqlx::query_as(
        r#"
        SELECT
            COALESCE(SUM(i.subtotal), 0)::bigint,
            COALESCE(SUM(i.vat_total), 0)::bigint,
            COALESCE(i.billing_country, ba.country, 'EE') AS country,
            i.vat_rate AS stored_vat_rate,
            (ba.vat_number IS NOT NULL AND ba.vat_number <> '') AS has_vat_number
        FROM invoices i
        LEFT JOIN billing_addresses ba ON ba.tenant_id = i.tenant_id
        WHERE i.issued_at >= $1
          AND i.issued_at < $2
          AND i.status IN ('paid', 'pending')
          AND UPPER(i.currency) = 'EUR'
        GROUP BY COALESCE(i.billing_country, ba.country, 'EE'), i.vat_rate,
                 (ba.vat_number IS NOT NULL AND ba.vat_number <> '')
        "#,
    )
    .bind(period_start)
    .bind(period_end)
    .fetch_all(db)
    .await
    .map_err(|e| format!("Failed to query rate breakdown: {e}"))?;

    let mut rates: Vec<VatRateBucket> = Vec::new();
    for (taxable, vat, country, stored_rate, has_vat_number) in &rate_rows {
        // When a stored rate exists it wins over the current-address
        // derivation; `has_vat_number` only matters for legacy rows.
        let (vat_rate, reason) = effective_vat_bucket(
            country.as_deref().filter(|_| stored_rate.is_some()),
            *stored_rate,
            country.as_deref(),
            has_vat_number.unwrap_or(false),
        );

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
        excluded_other_currency: excluded_other_currency.clone(),
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
        excluded_other_currency,
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
    use chrono::{Datelike, Timelike};

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

    // ------------------------------------------------------------------
    // Fix B — KMD aggregates only EUR; other currencies are reported
    // separately so finance can see them instead of them silently
    // inflating the Estonian VAT return.
    // ------------------------------------------------------------------

    #[test]
    fn test_is_eur_currency_case_insensitive() {
        assert!(is_eur_currency("EUR"));
        assert!(is_eur_currency("eur"));
        assert!(is_eur_currency(" Eur "));
        assert!(!is_eur_currency("USD"));
        assert!(!is_eur_currency(""));
        assert!(!is_eur_currency("EURO"));
    }

    #[test]
    fn test_kmd_invoice_queries_filter_to_eur() {
        assert!(EUR_INVOICE_FILTER.contains("UPPER(currency) = 'EUR'"));
    }

    #[test]
    fn test_excluded_currency_bucket_serialization() {
        let bucket = ExcludedCurrencyBucket {
            currency: "USD".into(),
            taxable_amount_cents: 12_345,
            vat_amount_cents: 0,
            invoice_count: 2,
        };
        let json = serde_json::to_value(&bucket).unwrap();
        assert_eq!(json["currency"], "USD");
        assert_eq!(json["taxable_amount_cents"], 12_345);
        assert_eq!(json["invoice_count"], 2);
    }

    #[test]
    fn test_breakdown_deserializes_legacy_payload_without_excluded_field() {
        // Breakdowns stored before the excluded_other_currency field existed
        // must still parse (serde default).
        let legacy = serde_json::json!({
            "rates": [],
            "total_taxable_cents": 0,
            "total_vat_cents": 0,
            "invoice_count": 0,
            "tenant_count": 0
        });
        let breakdown: VatBreakdown = serde_json::from_value(legacy).unwrap();
        assert!(breakdown.excluded_other_currency.is_empty());
    }

    // ------------------------------------------------------------------
    // Fix I4 — buckets derive from the invoice's own charged rate/country.
    // ------------------------------------------------------------------

    #[test]
    fn test_invoice_charged_ee_24_stays_in_ee_bucket_after_address_change() {
        // Invoice charged 24 % EE VAT; the tenant later files a VAT-number
        // bearing DE address. The KMD bucket must stay EE/24 %, not flip to
        // reverse charge.
        let (rate, reason) = effective_vat_bucket(Some("EE"), Some(24), Some("DE"), true);
        assert_eq!(rate, 24);
        assert_eq!(reason, None);
    }

    #[test]
    fn test_stored_rate_zero_keeps_reverse_charge_bucket() {
        let (rate, reason) = effective_vat_bucket(Some("DE"), Some(0), Some("DE"), true);
        assert_eq!(rate, 0);
        assert_eq!(reason, Some("reverse_charge"));
    }

    #[test]
    fn test_stored_eu_b2c_rate_uses_eu_b2c_reason() {
        let (rate, reason) = effective_vat_bucket(Some("FR"), Some(20), Some("FR"), false);
        assert_eq!(rate, 20);
        assert_eq!(reason, Some("eu_b2c"));
    }

    #[test]
    fn test_missing_stored_values_fall_back_to_current_address() {
        // Pre-migration rows: NULL stored rate/country — old behaviour.
        let (rate, reason) = effective_vat_bucket(None, None, Some("DE"), true);
        assert_eq!(rate, 0);
        assert_eq!(reason, Some("reverse_charge"));

        let (rate, reason) = effective_vat_bucket(None, None, None, false);
        assert_eq!(rate, vat_rates::ESTONIA_VAT_RATE);
        assert_eq!(reason, None);
    }

    // ------------------------------------------------------------------
    // Fix I14 — due date is 23:59:59 Europe/Tallinn, not UTC.
    // ------------------------------------------------------------------

    #[test]
    fn test_vat_return_due_date_is_tallinn_end_of_day() {
        use chrono_tz::Europe::Tallinn as TallinnTz;

        let tallinn = |due: DateTime<Utc>| due.with_timezone(&TallinnTz);

        // January 20 Tallinn is EET (UTC+2) → due date is 21:59:59Z.
        let due = tallinn(vat_return_due_date(2025, 12));
        assert_eq!(due.hour(), 23);
        assert_eq!(due.minute(), 59);
        assert_eq!(due.second(), 59);
        assert_eq!(format!("{}", due.format("%z")), "+0200");

        // July 20 Tallinn is EEST (UTC+3) → due date is 20:59:59Z.
        let due = tallinn(vat_return_due_date(2026, 6));
        assert_eq!(format!("{}", due.format("%z")), "+0300");
    }

    // ------------------------------------------------------------------
    // Fix I5 — backfill walks every missing month between the last
    // generated return and the target period.
    // ------------------------------------------------------------------

    #[test]
    fn test_month_steps_backfills_three_month_gap() {
        let steps = month_steps((2026, 3), (2026, 6), 24);
        assert_eq!(steps, vec![(2026, 4), (2026, 5), (2026, 6)]);
    }

    #[test]
    fn test_month_steps_wraps_year_boundary() {
        let steps = month_steps((2026, 11), (2027, 2), 24);
        assert_eq!(steps, vec![(2026, 12), (2027, 1), (2027, 2)]);
    }

    #[test]
    fn test_month_steps_is_bounded_and_empty_when_current() {
        assert!(month_steps((2026, 6), (2026, 6), 24).is_empty());
        assert_eq!(month_steps((2025, 1), (2027, 12), 5).len(), 5);
        assert!(month_steps((2027, 1), (2026, 1), 24).is_empty());
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
            excluded_other_currency: vec![ExcludedCurrencyBucket {
                currency: "USD".into(),
                taxable_amount_cents: 7_000,
                vat_amount_cents: 0,
                invoice_count: 1,
            }],
        };
        let json = serde_json::to_value(&breakdown).unwrap();
        assert_eq!(json["total_taxable_cents"], 150000);
        assert_eq!(json["total_vat_cents"], 24000);
        assert_eq!(json["invoice_count"], 13);
        assert_eq!(json["rates"].as_array().unwrap().len(), 2);
        assert_eq!(json["excluded_other_currency"][0]["currency"], "USD");
    }
}
