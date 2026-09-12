//! VAT recognition ledger materialization and KMD aggregation.
//!
//! The ledger table `vat_recognition_entries` (migration 218) is the single
//! source of truth for output VAT recognition. This module:
//!
//! 1. resolves the tenant's accounting basis from the dated
//!    `vat_accounting_bases` rows (delegating the pure precedence/timing
//!    logic to [`billing_common::vat_recognition`]);
//! 2. materializes the CURRENT recognition event for an invoice — under the
//!    general scheme the supply event, under `cash_special` the payment
//!    event or the third-month fallback, whichever is earlier;
//! 3. exposes the aggregation the KMD return uses.
//!
//! Reconciliation to the double-entry accounting core: every entry carries a
//! nullable `journal_entry_id`. That crate/table does not exist in this
//! workspace yet (checked at implementation time: no `journal_entries` /
//! `journal_lines` anywhere), so the ledger is currently self-contained and
//! the column is the documented reconciliation hook. Nothing here fabricates
//! journal links.
//!
//! The materializer is idempotent: it replaces the current
//! supply/payment/cash_special_due row for the (supply, scheme) pair inside
//! the caller's transaction, so replays and retries cannot double-count.

use billing_common::vat_recognition::{
    cash_special_fallback_date, recognition_event_type, recognition_period,
    resolve_accounting_scheme, RecognitionEventType, VatAccountingBasis, VatAccountingScheme,
};
use chrono::{DateTime, Datelike, NaiveDate, TimeZone, Utc};
use chrono_tz::Europe::Tallinn;
use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

use crate::vat_kmd::{ExcludedCurrencyBucket, VatRateBucket};

/// The ledger table KMD aggregates. Kept as a constant so tests can prove
/// the source is the recognition ledger and not `invoices.status`.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const RECOGNITION_TABLE: &str = "vat_recognition_entries";

/// KMD output derives from recognized entries in the filing period.
pub(crate) const KMD_RECOGNITION_TOTALS_SQL: &str = r#"
    SELECT
        COUNT(DISTINCT supply_id)::bigint,
        COUNT(DISTINCT tenant_id)::bigint,
        COALESCE(SUM(taxable_amount_cents), 0)::bigint,
        COALESCE(SUM(vat_amount_cents), 0)::bigint
    FROM vat_recognition_entries
    WHERE recognition_period = $1
      AND UPPER(currency) = 'EUR'
"#;

pub(crate) const KMD_RECOGNITION_EXCLUDED_SQL: &str = r#"
    SELECT
        UPPER(currency) AS currency,
        COUNT(DISTINCT supply_id)::bigint,
        COALESCE(SUM(taxable_amount_cents), 0)::bigint,
        COALESCE(SUM(vat_amount_cents), 0)::bigint
    FROM vat_recognition_entries
    WHERE recognition_period = $1
      AND NOT (UPPER(currency) = 'EUR')
    GROUP BY UPPER(currency)
    ORDER BY currency
"#;

pub(crate) const KMD_RECOGNITION_RATES_SQL: &str = r#"
    SELECT
        vat_rate,
        reason,
        COALESCE(SUM(taxable_amount_cents), 0)::bigint,
        COALESCE(SUM(vat_amount_cents), 0)::bigint,
        COUNT(DISTINCT supply_id)::bigint
    FROM vat_recognition_entries
    WHERE recognition_period = $1
      AND UPPER(currency) = 'EUR'
    GROUP BY vat_rate, reason
    ORDER BY vat_rate, reason
"#;

/// Map raw recognition-ledger rate rows into KMD buckets (pure, unit-tested).
/// Rows already carry the stored rate and reason, so no re-derivation from
/// the tenant's current address happens — the ledger is the consumed truth.
pub(crate) fn buckets_from_recognition_rows(
    rows: &[(f64, Option<String>, i64, i64, i64)],
) -> Vec<VatRateBucket> {
    rows.iter()
        .map(|(rate, reason, taxable, vat, supply_count)| VatRateBucket {
            rate: *rate,
            taxable_amount_cents: *taxable,
            vat_amount_cents: *vat,
            reason: reason.clone(),
            invoice_count: *supply_count,
        })
        .collect()
}

/// Map raw excluded-currency rows into KMD buckets (pure, unit-tested).
pub(crate) fn excluded_from_recognition_rows(
    rows: &[(String, i64, i64, i64)],
) -> Vec<ExcludedCurrencyBucket> {
    rows.iter()
        .map(
            |(currency, supply_count, taxable, vat)| ExcludedCurrencyBucket {
                currency: currency.clone(),
                invoice_count: *supply_count,
                taxable_amount_cents: *taxable,
                vat_amount_cents: *vat,
            },
        )
        .collect()
}

/// A materialized ledger row.
#[derive(Debug, Clone, PartialEq)]
pub struct RecognitionEntry {
    pub supply_id: String,
    pub tenant_id: String,
    pub invoice_id: Option<Uuid>,
    pub event_type: RecognitionEventType,
    pub taxable_event_at: DateTime<Utc>,
    pub recognition_period: String,
    pub taxable_amount_cents: i64,
    pub vat_rate: f64,
    pub vat_amount_cents: i64,
    pub currency: String,
    pub scheme: VatAccountingScheme,
    pub reason: Option<String>,
    pub source_document_id: Option<String>,
}

/// The classification KMD buckets use. Mirrors the stored rate/country, not
/// the tenant's current mutable address.
pub fn recognition_reason(country: &str, vat_rate: f64) -> &'static str {
    let country = country.trim().to_uppercase();
    if country == "EE" {
        "local"
    } else if billing_common::vat_rates::is_eu_country(&country) {
        if vat_rate == 0.0 {
            "reverse_charge"
        } else {
            "eu_b2c"
        }
    } else {
        "non_eu"
    }
}

/// Tallinn calendar date of an instant.
fn tallinn_date(instant: DateTime<Utc>) -> NaiveDate {
    instant.with_timezone(&Tallinn).date_naive()
}

/// Tallinn midnight of `date` as UTC — the instant a cash-accounting
/// fallback becomes taxable (same convention as the KMD period bounds).
fn tallinn_midnight_utc(date: NaiveDate) -> Result<DateTime<Utc>, String> {
    match Tallinn.with_ymd_and_hms(date.year(), date.month(), date.day(), 0, 0, 0) {
        chrono::LocalResult::Single(value) => Ok(value.with_timezone(&Utc)),
        chrono::LocalResult::Ambiguous(value, _) => Ok(value.with_timezone(&Utc)),
        chrono::LocalResult::None => Err(format!("invalid Europe/Tallinn midnight for {date}")),
    }
}

/// Inputs the materializer needs from the invoice row (kept separate from
/// SQL so the timing decision is unit-testable).
#[derive(Debug, Clone)]
pub struct InvoiceRecognitionInput {
    pub invoice_id: Uuid,
    pub tenant_id: String,
    pub currency: String,
    pub subtotal_cents: i64,
    pub vat_rate: f64,
    pub vat_cents: i64,
    pub issued_at: DateTime<Utc>,
    /// Set once the invoice is fully settled (invoice.payment allocations
    /// cover the total). `None` while unpaid.
    pub paid_at: Option<DateTime<Utc>>,
    pub billing_country: Option<String>,
}

/// Compute the ledger entry for an invoice, if any is recognized as of
/// `now`. Returns `None` when a cash-accounting supply is still unpaid and
/// its third-month fallback has not arrived — correctly recognising nothing
/// yet, rather than recognising early.
pub fn plan_recognition_entry(
    input: &InvoiceRecognitionInput,
    scheme: VatAccountingScheme,
    now: DateTime<Utc>,
) -> Result<Option<RecognitionEntry>, String> {
    let supply_date = tallinn_date(input.issued_at);
    let paid_date = input.paid_at.map(tallinn_date);
    let fallback = cash_special_fallback_date(supply_date);

    let (taxable_event_at, event_type) = match scheme {
        VatAccountingScheme::General => (
            input.issued_at,
            recognition_event_type(scheme, supply_date, paid_date),
        ),
        VatAccountingScheme::CashSpecial => {
            let paid_before_fallback = paid_date.map_or(false, |paid| paid < fallback);
            if paid_before_fallback {
                (
                    input.paid_at.expect("paid_date implies paid_at is present"),
                    RecognitionEventType::Payment,
                )
            } else if now.with_timezone(&Tallinn).date_naive() >= fallback {
                // Fallback fired (paid late or not at all).
                (
                    tallinn_midnight_utc(fallback)?,
                    recognition_event_type(scheme, supply_date, paid_date),
                )
            } else {
                // Unpaid and still inside the deferral window: no taxable
                // event yet.
                return Ok(None);
            }
        }
    };

    let taxable_date = tallinn_date(taxable_event_at);
    Ok(Some(RecognitionEntry {
        supply_id: input.invoice_id.to_string(),
        tenant_id: input.tenant_id.clone(),
        invoice_id: Some(input.invoice_id),
        event_type,
        taxable_event_at,
        recognition_period: recognition_period(taxable_date),
        taxable_amount_cents: input.subtotal_cents,
        vat_rate: input.vat_rate,
        vat_amount_cents: input.vat_cents,
        currency: input.currency.trim().to_uppercase(),
        scheme,
        reason: Some(
            recognition_reason(
                input.billing_country.as_deref().unwrap_or("EE"),
                input.vat_rate,
            )
            .to_string(),
        ),
        source_document_id: Some(input.invoice_id.to_string()),
    }))
}

/// Load the dated accounting bases and resolve the scheme for `tenant_id` on
/// `at`. Missing table (pre-213 deployment) falls back to `general`.
async fn resolve_scheme(
    executor: impl sqlx::PgExecutor<'_>,
    tenant_id: &str,
    at: NaiveDate,
) -> Result<VatAccountingScheme, String> {
    let rows: Vec<(
        Option<String>,
        String,
        NaiveDate,
        Option<NaiveDate>,
        Option<NaiveDate>,
        Option<String>,
    )> = sqlx::query_as(
        r#"
            SELECT tenant_id, scheme, effective_from, effective_to,
                   authorised_at, authorisation_reference
            FROM vat_accounting_bases
            WHERE tenant_id IS NULL OR tenant_id = $1
            "#,
    )
    .bind(tenant_id)
    .fetch_all(executor)
    .await
    .map_err(|error| format!("failed to load vat_accounting_bases: {error}"))?;

    let bases: Vec<VatAccountingBasis> = rows
        .into_iter()
        .filter_map(
            |(tenant_id, scheme, effective_from, effective_to, authorised_at, reference)| {
                Some(VatAccountingBasis {
                    tenant_id,
                    scheme: VatAccountingScheme::from_db(&scheme)?,
                    effective_from,
                    effective_to,
                    authorised_at,
                    authorisation_reference: reference,
                })
            },
        )
        .collect();

    Ok(resolve_accounting_scheme(&bases, tenant_id, at))
}

/// Materialize (replace) the current recognition entry for an invoice.
/// Idempotent: safe to call on invoice creation, payment, and from a sweep.
/// `paid_at` in the input drives the cash-accounting decision.
pub async fn materialize_invoice_recognition(
    executor: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    input: &InvoiceRecognitionInput,
    now: DateTime<Utc>,
) -> Result<Option<RecognitionEntry>, String> {
    let supply_date = tallinn_date(input.issued_at);
    let scheme = resolve_scheme(&mut **executor, &input.tenant_id, supply_date).await?;
    let planned = plan_recognition_entry(input, scheme, now)?;

    // Replace the current event row (if any) atomically. Corrections are
    // separate rows and are untouched.
    sqlx::query(
        r#"
        DELETE FROM vat_recognition_entries
        WHERE supply_id = $1
          AND scheme = $2
          AND event_type IN ('supply', 'payment', 'cash_special_due')
        "#,
    )
    .bind(input.invoice_id.to_string())
    .bind(scheme.as_str())
    .execute(&mut **executor)
    .await
    .map_err(|error| format!("failed to clear prior recognition entry: {error}"))?;

    let Some(entry) = planned else {
        return Ok(None);
    };

    sqlx::query(
        r#"
        INSERT INTO vat_recognition_entries (
            id, supply_id, tenant_id, invoice_id, event_type, taxable_event_at,
            recognition_period, taxable_amount_cents, vat_rate, vat_amount_cents,
            currency, scheme, reason, source_document_id
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
        )
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(&entry.supply_id)
    .bind(&entry.tenant_id)
    .bind(entry.invoice_id)
    .bind(entry.event_type.as_str())
    .bind(entry.taxable_event_at)
    .bind(&entry.recognition_period)
    .bind(entry.taxable_amount_cents)
    .bind(entry.vat_rate)
    .bind(entry.vat_amount_cents)
    .bind(&entry.currency)
    .bind(entry.scheme.as_str())
    .bind(&entry.reason)
    .bind(&entry.source_document_id)
    .execute(&mut **executor)
    .await
    .map_err(|error| format!("failed to insert recognition entry: {error}"))?;

    Ok(Some(entry))
}

/// Read one invoice and materialize its recognition. Runs its own
/// transaction; used by the Stripe settlement path after the local invoice
/// was marked paid (the row is re-read, so paid_at is visible).
pub async fn materialize_invoice_recognition_by_id(
    db: &PgPool,
    invoice_id: Uuid,
    now: DateTime<Utc>,
) -> Result<Option<RecognitionEntry>, String> {
    let row: Option<(
        String,
        String,
        i64,
        f64,
        i64,
        DateTime<Utc>,
        Option<DateTime<Utc>>,
        Option<String>,
    )> = sqlx::query_as(
        r#"
            SELECT tenant_id, currency, COALESCE(subtotal, amount, 0)::bigint,
                   COALESCE(vat_rate, 0)::double precision, COALESCE(vat_total, 0)::bigint,
                   issued_at, paid_at, billing_country
            FROM invoices
            WHERE id = $1
            "#,
    )
    .bind(invoice_id)
    .fetch_optional(db)
    .await
    .map_err(|error| format!("failed to load invoice {invoice_id} for recognition: {error}"))?;

    let Some((tenant_id, currency, subtotal, vat_rate, vat_total, issued_at, paid_at, country)) =
        row
    else {
        return Ok(None);
    };

    let input = InvoiceRecognitionInput {
        invoice_id,
        tenant_id,
        currency,
        subtotal_cents: subtotal,
        vat_rate,
        vat_cents: vat_total,
        issued_at,
        paid_at,
        billing_country: country,
    };

    let mut tx = db
        .begin()
        .await
        .map_err(|error| format!("failed to begin recognition transaction: {error}"))?;
    let entry = materialize_invoice_recognition(&mut tx, &input, now).await?;
    tx.commit()
        .await
        .map_err(|error| format!("failed to commit recognition entry: {error}"))?;
    Ok(entry)
}

/// Sweep materializer for cash-accounting invoices whose third-month
/// fallback has arrived while they were unpaid. Returns the number of
/// invoices materialized.
///
/// NOTE: scheduling is not wired into the maintenance loop by this change;
/// the function is exposed so operations can run it (and tests can call it).
pub async fn materialize_due_cash_special(db: &PgPool, now: DateTime<Utc>) -> Result<u64, String> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        r#"
        SELECT i.id
        FROM invoices i
        JOIN vat_accounting_bases b
          ON (b.tenant_id IS NULL OR b.tenant_id = i.tenant_id)
         AND b.scheme = 'cash_special'
         AND b.effective_from <= (i.issued_at AT TIME ZONE 'Europe/Tallinn')::date
         AND (b.effective_to IS NULL
              OR b.effective_to >= (i.issued_at AT TIME ZONE 'Europe/Tallinn')::date)
        WHERE i.issued_at <= ($1::timestamptz AT TIME ZONE 'Europe/Tallinn')::date - INTERVAL '2 months'
          AND i.status NOT IN ('void', 'uncollectible', 'draft')
          AND NOT EXISTS (
              SELECT 1 FROM vat_recognition_entries r
              WHERE r.supply_id = i.id::text
                AND r.scheme = 'cash_special'
                AND r.event_type IN ('payment', 'cash_special_due')
          )
        LIMIT 500
        "#,
    )
    .bind(now)
    .fetch_all(db)
    .await
    .map_err(|error| format!("failed to find due cash-special invoices: {error}"))?;

    let mut materialized = 0_u64;
    for (invoice_id,) in rows {
        match materialize_invoice_recognition_by_id(db, invoice_id, now).await {
            Ok(Some(_)) => materialized += 1,
            Ok(None) => {}
            Err(error) => {
                warn!(invoice_id = %invoice_id, error = %error, "cash-special recognition sweep failed for invoice");
            }
        }
    }
    Ok(materialized)
}

/// Backfill recognition entries for already-issued invoices (periods before
/// this ledger existed). `from`/`to` are inclusive recognition-period keys
/// (`YYYY-MM`) over the invoice issue month. Idempotent.
pub async fn backfill_recognition_from_invoices(
    db: &PgPool,
    from_period: &str,
    to_period: &str,
) -> Result<u64, String> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        r#"
        SELECT id
        FROM invoices
        WHERE to_char(issued_at AT TIME ZONE 'Europe/Tallinn', 'YYYY-MM') >= $1
          AND to_char(issued_at AT TIME ZONE 'Europe/Tallinn', 'YYYY-MM') <= $2
          AND status NOT IN ('void', 'uncollectible')
        ORDER BY issued_at
        "#,
    )
    .bind(from_period)
    .bind(to_period)
    .fetch_all(db)
    .await
    .map_err(|error| format!("failed to list invoices for recognition backfill: {error}"))?;

    let now = Utc::now();
    let mut written = 0_u64;
    for (invoice_id,) in rows {
        match materialize_invoice_recognition_by_id(db, invoice_id, now).await {
            Ok(Some(_)) => written += 1,
            Ok(None) => {}
            Err(error) => {
                warn!(invoice_id = %invoice_id, error = %error, "recognition backfill failed for invoice");
            }
        }
    }
    Ok(written)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn ts(year: i32, month: u32, day: u32) -> DateTime<Utc> {
        Tallinn
            .with_ymd_and_hms(year, month, day, 12, 0, 0)
            .single()
            .expect("unambiguous Tallinn noon")
            .with_timezone(&Utc)
    }

    fn input(issued_at: DateTime<Utc>, paid_at: Option<DateTime<Utc>>) -> InvoiceRecognitionInput {
        InvoiceRecognitionInput {
            invoice_id: Uuid::new_v4(),
            tenant_id: "tenant_A".into(),
            currency: "eur".into(),
            subtotal_cents: 10_000,
            vat_rate: 24.0,
            vat_cents: 2_400,
            issued_at,
            paid_at,
            billing_country: Some("EE".into()),
        }
    }

    // ── KMD aggregation source ────────────────────────────────────────

    #[test]
    fn kmd_aggregation_queries_the_recognition_ledger_not_invoice_status() {
        for sql in [
            KMD_RECOGNITION_TOTALS_SQL,
            KMD_RECOGNITION_EXCLUDED_SQL,
            KMD_RECOGNITION_RATES_SQL,
        ] {
            assert!(
                sql.contains(RECOGNITION_TABLE),
                "KMD must aggregate {RECOGNITION_TABLE}"
            );
            assert!(
                !sql.contains("FROM invoices") && !sql.contains("status = 'paid'"),
                "KMD must not derive VAT from invoice status: {sql}"
            );
            assert!(
                sql.contains("recognition_period"),
                "KMD period must come from the recognition period: {sql}"
            );
            assert!(
                sql.contains("COUNT(DISTINCT supply_id)"),
                "counts are supplies, not invoice-status rows: {sql}"
            );
        }
    }

    #[test]
    fn kmd_bucket_mapping_uses_ledger_rate_and_reason() {
        let rows = vec![
            (24.0_f64, Some("local".to_string()), 100_000, 24_000, 10),
            (0.0, Some("reverse_charge".to_string()), 50_000, 0, 3),
        ];
        let buckets = buckets_from_recognition_rows(&rows);
        assert_eq!(buckets.len(), 2);
        assert_eq!(buckets[0].rate, 24.0);
        assert_eq!(buckets[0].reason.as_deref(), Some("local"));
        assert_eq!(buckets[0].invoice_count, 10);
        assert_eq!(buckets[1].rate, 0.0);
        assert_eq!(buckets[1].reason.as_deref(), Some("reverse_charge"));
    }

    #[test]
    fn excluded_currency_mapping_uses_supply_counts() {
        let rows = vec![("USD".to_string(), 2, 7_000, 0)];
        let excluded = excluded_from_recognition_rows(&rows);
        assert_eq!(excluded.len(), 1);
        assert_eq!(excluded[0].currency, "USD");
        assert_eq!(excluded[0].invoice_count, 2);
    }

    // ── Recognition planning ──────────────────────────────────────────

    #[test]
    fn general_scheme_plans_a_supply_entry_at_issue() {
        let issued = ts(2026, 3, 15);
        let entry = plan_recognition_entry(
            &input(issued, None),
            VatAccountingScheme::General,
            ts(2026, 3, 16),
        )
        .expect("planning succeeds")
        .expect("general scheme recognises immediately");
        assert_eq!(entry.event_type, RecognitionEventType::Supply);
        assert_eq!(entry.taxable_event_at, issued);
        assert_eq!(entry.recognition_period, "2026-03");
        assert_eq!(entry.taxable_amount_cents, 10_000);
        assert_eq!(entry.vat_amount_cents, 2_400);
        assert_eq!(entry.reason.as_deref(), Some("local"));
        assert_eq!(entry.scheme, VatAccountingScheme::General);
    }

    #[test]
    fn cash_special_plans_nothing_until_paid_or_fallback() {
        let issued = ts(2026, 1, 15);
        // In March, unpaid: fallback (April 1) has not arrived.
        let planned = plan_recognition_entry(
            &input(issued, None),
            VatAccountingScheme::CashSpecial,
            ts(2026, 3, 15),
        )
        .expect("planning succeeds");
        assert!(
            planned.is_none(),
            "unpaid supply must not recognise before the third-month fallback"
        );

        // On April 1 the fallback fires.
        let entry = plan_recognition_entry(
            &input(issued, None),
            VatAccountingScheme::CashSpecial,
            ts(2026, 4, 1),
        )
        .expect("planning succeeds")
        .expect("fallback recognition");
        assert_eq!(entry.event_type, RecognitionEventType::CashSpecialDue);
        assert_eq!(entry.recognition_period, "2026-04");
    }

    #[test]
    fn cash_special_boundary_last_day_of_month_two_vs_first_day_of_month_three() {
        let issued = ts(2026, 1, 15);

        // Paid March 31 (last day of the second following month): recognise
        // on the payment date, in March.
        let paid = ts(2026, 3, 31);
        let entry = plan_recognition_entry(
            &input(issued, Some(paid)),
            VatAccountingScheme::CashSpecial,
            ts(2026, 4, 10),
        )
        .expect("planning succeeds")
        .expect("early payment recognition");
        assert_eq!(entry.event_type, RecognitionEventType::Payment);
        assert_eq!(entry.taxable_event_at, paid);
        assert_eq!(entry.recognition_period, "2026-03");

        // Paid April 1 (first day of the third following month): the
        // fallback date itself; recognition stays in April.
        let entry = plan_recognition_entry(
            &input(issued, Some(ts(2026, 4, 1))),
            VatAccountingScheme::CashSpecial,
            ts(2026, 4, 2),
        )
        .expect("planning succeeds")
        .expect("boundary recognition");
        assert_eq!(entry.event_type, RecognitionEventType::CashSpecialDue);
        assert_eq!(
            entry.taxable_event_at,
            super::tallinn_midnight_utc(NaiveDate::from_ymd_opt(2026, 4, 1).unwrap())
                .expect("Tallinn midnight")
        );
        assert_eq!(entry.recognition_period, "2026-04");
    }

    #[test]
    fn reasons_classify_by_stored_country_and_rate() {
        assert_eq!(recognition_reason("EE", 24.0), "local");
        assert_eq!(recognition_reason("DE", 0.0), "reverse_charge");
        assert_eq!(recognition_reason("FR", 20.0), "eu_b2c");
        assert_eq!(recognition_reason("US", 0.0), "non_eu");
    }
}
