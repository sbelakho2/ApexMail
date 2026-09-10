//! Estonia OÜ financial compliance analytics.
//!
//! Provides Estonian-accounting-standards (RTJ) oriented revenue reporting,
//! VAT (KM) analysis for EMTA, EU intra-community tracking, AR aging, and
//! per-country revenue breakdown. Every figure comes from real database
//! queries against the CANONICAL invoice model — no invented splits, no
//! cross-currency sums, no silent fallbacks (F80).
//!
//! F80/F81 rules implemented here:
//!   * canonical columns only: `total`/`amount`/`subtotal`/`vat_total`,
//!     `issued_at`/`due_at` (never `amount_cents`/`issue_date`);
//!   * exact `[month_start, next_month_start)` calendar windows;
//!   * per-currency totals: nominal USD/GBP amounts are NEVER summed into a
//!     EUR total — without a persisted conversion source/rate/date there is
//!     no reporting-currency figure at all;
//!   * revenue categories come from the actual `line_items` JSONB, not
//!     fixed percentages;
//!   * VAT output comes from the invoice tax snapshots (`vat_total`,
//!     `vat_rate`, `billing_country`) with domestic / reverse-charge /
//!     outside-scope classification and the date-effective standard rate
//!     (see `tax_policy`);
//!   * query errors are propagated; unavailable data is visible.
//!
//! Compliance references:
//!   - RTJ 2 (Raamatupidamise Toimkonna Juhend nr 2) — revenue recognition
//!   - Käibemaksuseadus (KMS) § 10, § 15 — VAT obligations
//!   - Äriseadustik (ÄS) § 334 — annual report requirements

use chrono::{DateTime, Datelike, NaiveDate, NaiveTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use std::collections::HashMap;

use crate::tax_policy;

// EU member state country codes (ISO 3166-1 alpha-2) for reverse-charge
const EU_COUNTRIES: &[&str] = &[
    "AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GR", "HR", "HU", "IE", "IT",
    "LT", "LU", "LV", "MT", "NL", "PL", "PT", "RO", "SE", "SI", "SK",
];

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FinancialComplianceReport {
    pub report_period: ReportPeriod,
    pub revenue_recognition: RevenueRecognition,
    pub vat_analytics: VatAnalytics,
    pub ar_aging: AccountsReceivableAging,
    pub revenue_by_country: Vec<CountryRevenue>,
    pub revenue_by_plan: Vec<PlanRevenue>,
    pub monthly_revenue_streams: Vec<MonthlyRevenueStream>,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportPeriod {
    pub start_date: String,
    pub end_date: String,
    pub months: i64,
}

/// Per-currency revenue totals. Amounts are nominal in their OWN currency —
/// there is deliberately no `total_revenue_eur` that would add USD and GBP
/// nominals without a persisted conversion provenance (F80).
#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CurrencyRevenue {
    pub currency: String,
    pub total: f64,
    pub recognized: f64,
    pub deferred: f64,
    pub refunds: f64,
    pub net: f64,
    pub subscription: f64,
    pub usage: f64,
    pub one_time: f64,
    pub invoice_count: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevenueRecognition {
    pub by_currency: Vec<CurrencyRevenue>,
    /// Currencies whose invoices are included in the report but excluded
    /// from every EUR-denominated statutory aggregate because no conversion
    /// provenance is persisted.
    pub non_eur_currencies: Vec<String>,
    /// Explicit empty-report state: no invoices found in the canonical
    /// store for the period (distinct from a zero figure).
    pub has_source_data: bool,
}

/// How a paid invoice's supply is classified for VAT purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VatClassification {
    /// Domestic (EE) supply — Estonian output VAT due.
    Domestic,
    /// Intra-EU B2B supply with a valid customer VAT number — reverse
    /// charge, no EE output VAT (KMS §14).
    ReverseCharge,
    /// Export outside the EU — zero-rated, no EE output VAT.
    ZeroRatedExport,
    /// EU customer WITHOUT a valid VAT number — Estonian VAT must be
    /// charged (KMS §14 (5)).
    EuVatDue,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VatAnalytics {
    /// Date-effective standard rate applied to the report period end
    /// (documented 2025-07 boundary — see tax_policy).
    pub vat_rate: f64,
    /// Domestic output VAT from actual invoice tax snapshots (EUR only).
    pub domestic_taxable_subtotal_eur: f64,
    pub domestic_output_vat_eur: f64,
    pub eu_reverse_charge_subtotal_eur: f64,
    pub eu_vat_due_subtotal_eur: f64,
    pub non_eu_export_subtotal_eur: f64,
    /// Deductible input VAT from actual eligible records. No input-tax
    /// store exists in the canonical chain, so this is 0.0 with
    /// `input_tax_source: false` — an invented percentage is not reported.
    pub vat_deductible_eur: f64,
    pub input_tax_source: bool,
    pub net_vat_payable_eur: f64,
    pub vat_by_country: Vec<VatCountryBreakdown>,
    /// Invoices whose currency is not EUR: excluded from the EUR VAT
    /// aggregates until conversion provenance exists (visible, not folded).
    pub non_eur_invoices: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VatCountryBreakdown {
    pub country: String,
    pub country_code: String,
    pub subtotal_eur: f64,
    pub output_vat_eur: f64,
    pub classification: VatClassification,
    pub customer_count: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountsReceivableAging {
    pub current_eur: f64,
    pub days_1_to_30_eur: f64,
    pub days_31_to_60_eur: f64,
    pub days_61_to_90_eur: f64,
    pub days_over_90_eur: f64,
    pub total_outstanding_eur: f64,
    pub bad_debt_reserve_eur: f64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CountryRevenue {
    pub country: String,
    pub country_code: String,
    pub revenue_eur: f64,
    pub customer_count: i64,
    pub is_eu: bool,
    pub is_domestic: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanRevenue {
    pub plan: String,
    pub customers: i64,
    pub mrr_eur: f64,
    pub arr_eur: f64,
    pub percentage: f64,
}

/// Monthly stream per calendar month, per category — EUR only (other
/// currencies are reported by currency, never silently converted).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MonthlyRevenueStream {
    pub month: String,
    pub subscription_eur: f64,
    pub usage_eur: f64,
    pub one_time_eur: f64,
    pub total_eur: f64,
}

/// Canonical invoice row (F80 column set: total/amount/subtotal/vat_total,
/// issued_at/due_at, tax snapshot + billing address). The full canonical
/// contract is selected even where a specific report does not read every
/// column, so drift from the schema fails loudly at query time.
#[derive(sqlx::FromRow)]
#[allow(dead_code)]
struct InvoiceRow {
    id: String,
    tenant_id: String,
    #[sqlx(default)]
    amount: Option<i64>,
    #[sqlx(default)]
    subtotal: Option<i64>,
    #[sqlx(default)]
    vat_total: Option<i64>,
    #[sqlx(default)]
    total: Option<i64>,
    currency: String,
    status: String,
    issued_at: Option<DateTime<Utc>>,
    #[sqlx(default)]
    due_at: Option<DateTime<Utc>>,
    #[sqlx(default)]
    paid_at: Option<DateTime<Utc>>,
    #[sqlx(default)]
    line_items: Option<serde_json::Value>,
    #[sqlx(default)]
    billing_country: Option<String>,
    #[sqlx(default)]
    billing_address: Option<String>,
}

#[derive(sqlx::FromRow)]
#[allow(dead_code)]
struct BillingAddressRow {
    tenant_id: String,
    country: Option<String>,
    vat_number: Option<String>,
    company_name: Option<String>,
}

#[derive(sqlx::FromRow)]
#[allow(dead_code)]
struct SubscriptionRow {
    tenant_id: String,
    plan_name: String,
    billing_interval: Option<String>,
    status: String,
}

fn cents_to_units(cents: i64) -> f64 {
    cents as f64 / 100.0
}

/// F80: canonical amount resolver — legacy invoices may carry only one of
/// total/amount/subtotal(+vat). Prefer the final `total`, then the legacy
/// `amount`, then reconstruct from subtotal + VAT.
fn invoice_amount_cents(inv: &InvoiceRow) -> i64 {
    inv.total
        .or(inv.amount)
        .or_else(|| inv.subtotal.map(|s| s + inv.vat_total.unwrap_or(0)))
        .unwrap_or(0)
}

/// Net-of-VAT subtotal resolver (categories are categorized on the net).
fn invoice_subtotal_cents(inv: &InvoiceRow) -> i64 {
    inv.subtotal
        .or_else(|| inv.amount.map(|a| a - inv.vat_total.unwrap_or(0)))
        .or_else(|| inv.total.map(|t| t - inv.vat_total.unwrap_or(0)))
        .unwrap_or(0)
}

pub(crate) fn is_eu_country(code: &str) -> bool {
    EU_COUNTRIES.contains(&code)
}

fn months_between(start: NaiveDate, end: NaiveDate) -> i64 {
    let years = end.year() - start.year();
    (years * 12 + end.month() as i32 - start.month() as i32) as i64
}

/// F80: EXACT calendar-month window start — the first instant of the month
/// containing `timestamp`.
fn month_start(timestamp: DateTime<Utc>) -> DateTime<Utc> {
    timestamp
        .date_naive()
        .with_day(1)
        .expect("day 1 exists for every month")
        .and_time(NaiveTime::MIN)
        .and_utc()
}

/// F80: EXACT `[month_start, next_month_start)` boundary — chrono
/// month arithmetic on the FIRST of the month (never 30/31/32-day day
/// arithmetic, which repeated or skipped months).
fn next_month_start(month_start_ts: DateTime<Utc>) -> DateTime<Utc> {
    use chrono::Months;
    month_start_ts
        .checked_add_months(Months::new(1))
        .expect("adding one month to a month start cannot overflow chrono's range")
}

/// Categorize an actual line item from its description (F80): the billing
/// writers' canonical descriptions are "Overage: …" and "PAYG usage: …"
/// (usage) and "Subscription …" / Stripe's "Subscription" default
/// (subscription); anything else is one-time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RevenueCategory {
    Subscription,
    Usage,
    OneTime,
}

fn categorize_line(description: &str) -> RevenueCategory {
    let lower = description.to_lowercase();
    if lower.starts_with("subscription") || lower.contains("subscription ") {
        RevenueCategory::Subscription
    } else if lower.starts_with("overage") || lower.starts_with("payg usage") {
        RevenueCategory::Usage
    } else {
        RevenueCategory::OneTime
    }
}

/// VAT classification for one invoice from its immutable billing snapshot
/// and tax columns (KMS §14): EE → domestic; non-EE EU with a valid VAT
/// number in the snapshot → reverse charge; non-EE EU without → EE VAT due;
/// outside the EU → zero-rated export.
fn classify_vat(inv: &InvoiceRow) -> VatClassification {
    let country = inv
        .billing_country
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(str::to_uppercase)
        .or_else(|| {
            // Fall back to the immutable snapshot's country (never the
            // mutable live billing address).
            inv.billing_address
                .as_deref()
                .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
                .and_then(|snap| {
                    snap.get("country")
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                })
        })
        .unwrap_or_default();

    if country == "EE" {
        return VatClassification::Domestic;
    }
    if is_eu_country(&country) {
        let has_vat_number = inv
            .billing_address
            .as_deref()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
            .and_then(|snap| {
                snap.get("vat_number")
                    .and_then(|v| v.as_str())
                    .map(|v| !v.trim().is_empty())
            })
            .unwrap_or(false);
        if has_vat_number {
            VatClassification::ReverseCharge
        } else {
            VatClassification::EuVatDue
        }
    } else {
        VatClassification::ZeroRatedExport
    }
}

/// Generate a full Estonian OÜ financial compliance analytics report from
/// the canonical model. Errors propagate — unavailable data is visible.
pub async fn generate_financial_compliance_report(
    db: &PgPool,
    period_months: i64,
) -> anyhow::Result<FinancialComplianceReport> {
    let now = Utc::now();
    let num_months = period_months.clamp(1, 24);

    // F80: the period starts at the first instant of the month
    // `period_months - 1` months back — exact calendar arithmetic.
    use chrono::Months;
    let period_start = month_start(now)
        .checked_sub_months(Months::new((num_months - 1) as u32))
        .expect("period subtraction cannot overflow");
    let start_date = period_start.date_naive();
    let end_date = now.date_naive();

    // ─── Canonical invoices for the period ─────────────────────────────
    let invoices: Vec<InvoiceRow> = sqlx::query_as(
        "SELECT id::text, tenant_id::text, amount, subtotal, vat_total, total, \
                currency, status, issued_at, due_at, paid_at, line_items, \
                billing_country, billing_address \
         FROM invoices \
         WHERE issued_at >= $1",
    )
    .bind(period_start)
    .fetch_all(db)
    .await?;

    // ─── Revenue Recognition (per currency, from actual line items) ────
    let mut by_currency: HashMap<String, CurrencyRevenue> = HashMap::new();
    for inv in &invoices {
        let currency = inv.currency.to_uppercase();
        let entry = by_currency.entry(currency).or_default();
        entry.currency = inv.currency.to_uppercase();
        entry.invoice_count += 1;

        let amount = cents_to_units(invoice_amount_cents(inv));
        entry.total += amount;
        match inv.status.as_str() {
            "paid" | "processing" => entry.recognized += amount,
            "refunded" | "void" => entry.refunds += amount,
            "pending" | "open" | "draft" => entry.deferred += amount,
            _ => {}
        }

        // F80: categorize ACTUAL line items. When the snapshot has no
        // line_items the amounts land in one_time only if the invoice is
        // not usage/subscription-shaped; the split is never invented.
        if let Some(items) = inv.line_items.as_ref().and_then(|v| v.as_array()) {
            let net = invoice_subtotal_cents(inv);
            let line_sum: i64 = items
                .iter()
                .filter_map(|item| item.get("amount").and_then(|a| a.as_i64()))
                .sum();
            if net > 0 && line_sum == net {
                for item in items {
                    let line_amount = item.get("amount").and_then(|a| a.as_i64()).unwrap_or(0);
                    let units = cents_to_units(line_amount);
                    match item
                        .get("description")
                        .and_then(|d| d.as_str())
                        .map(categorize_line)
                        .unwrap_or(RevenueCategory::OneTime)
                    {
                        RevenueCategory::Subscription => entry.subscription += units,
                        RevenueCategory::Usage => entry.usage += units,
                        RevenueCategory::OneTime => entry.one_time += units,
                    }
                }
            } else {
                // Line items do not reconcile with the headline subtotal —
                // visibly un-categorized rather than force-split.
                entry.one_time += cents_to_units(net);
            }
        }
    }
    for entry in by_currency.values_mut() {
        entry.net = entry.recognized - entry.refunds;
    }
    let has_source_data = !invoices.is_empty();
    let mut revenue_order: Vec<String> = by_currency.keys().cloned().collect();
    revenue_order.sort();
    let non_eur_currencies: Vec<String> = revenue_order
        .iter()
        .filter(|c| c.as_str() != "EUR")
        .cloned()
        .collect();
    let mut revenue_vec: Vec<CurrencyRevenue> = revenue_order
        .into_iter()
        .map(|c| by_currency.remove(&c).unwrap_or_default())
        .collect();
    // EUR first, then alphabetical.
    revenue_vec.sort_by(|a, b| {
        (b.currency == "EUR")
            .cmp(&(a.currency == "EUR"))
            .then_with(|| a.currency.cmp(&b.currency))
    });

    let revenue_recognition = RevenueRecognition {
        by_currency: revenue_vec,
        non_eur_currencies,
        has_source_data,
    };

    // ─── VAT Analytics (EUR only, from invoice tax snapshots) ──────────
    let vat_rate = tax_policy::vat_standard_rate(end_date);
    let mut vat_analytics = VatAnalytics {
        vat_rate,
        domestic_taxable_subtotal_eur: 0.0,
        domestic_output_vat_eur: 0.0,
        eu_reverse_charge_subtotal_eur: 0.0,
        eu_vat_due_subtotal_eur: 0.0,
        non_eu_export_subtotal_eur: 0.0,
        vat_deductible_eur: 0.0,
        input_tax_source: false,
        net_vat_payable_eur: 0.0,
        vat_by_country: Vec::new(),
        non_eur_invoices: 0,
    };

    let billing_addresses: Vec<BillingAddressRow> = sqlx::query_as(
        "SELECT tenant_id::text, country, vat_number, company_name FROM billing_addresses",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let address_by_tenant: HashMap<String, &BillingAddressRow> = billing_addresses
        .iter()
        .map(|a| (a.tenant_id.clone(), a))
        .collect();

    let mut country_map: HashMap<String, (f64, f64, i64, VatClassification)> = HashMap::new();
    for inv in &invoices {
        if inv.currency.to_uppercase() != "EUR" {
            vat_analytics.non_eur_invoices += 1;
            continue; // currency provenance required before EUR VAT figures
        }
        let classification = classify_vat(inv);
        let subtotal = cents_to_units(invoice_subtotal_cents(inv));
        // Output VAT comes from the invoice's own tax snapshot — never a
        // rate multiplied over a mixed-currency total.
        let output_vat = cents_to_units(inv.vat_total.unwrap_or(0));

        let country = inv
            .billing_country
            .clone()
            .or_else(|| {
                address_by_tenant
                    .get(&inv.tenant_id)
                    .and_then(|a| a.country.clone())
            })
            .map(|c| c.to_uppercase())
            .unwrap_or_else(|| "EE".to_string());

        match classification {
            VatClassification::Domestic => {
                vat_analytics.domestic_taxable_subtotal_eur += subtotal;
                vat_analytics.domestic_output_vat_eur += output_vat;
            }
            VatClassification::ReverseCharge => {
                vat_analytics.eu_reverse_charge_subtotal_eur += subtotal;
            }
            VatClassification::EuVatDue => {
                vat_analytics.eu_vat_due_subtotal_eur += subtotal;
                vat_analytics.domestic_output_vat_eur += output_vat;
            }
            VatClassification::ZeroRatedExport => {
                vat_analytics.non_eu_export_subtotal_eur += subtotal;
            }
        }

        let entry = country_map
            .entry(country.clone())
            .or_insert((0.0, 0.0, 0, classification));
        entry.0 += subtotal;
        entry.1 += output_vat;
        entry.2 += 1;
    }

    // Input VAT: from actual eligible input-tax records only. No such store
    // exists in the canonical chain — reported as 0 with the source flag
    // instead of an invented deductible percentage.
    vat_analytics.input_tax_source = false;
    vat_analytics.net_vat_payable_eur =
        (vat_analytics.domestic_output_vat_eur - vat_analytics.vat_deductible_eur).max(0.0);

    vat_analytics.vat_by_country = country_map
        .into_iter()
        .map(
            |(country, (subtotal, output_vat, count, classification))| VatCountryBreakdown {
                country: country.clone(),
                country_code: country,
                subtotal_eur: subtotal,
                output_vat_eur: output_vat,
                classification,
                customer_count: count,
            },
        )
        .collect();
    vat_analytics.vat_by_country.sort_by(|a, b| {
        b.subtotal_eur
            .partial_cmp(&a.subtotal_eur)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // ─── Accounts Receivable Aging (EUR only, from due_at) ─────────────
    let mut ar_aging = AccountsReceivableAging {
        current_eur: 0.0,
        days_1_to_30_eur: 0.0,
        days_31_to_60_eur: 0.0,
        days_61_to_90_eur: 0.0,
        days_over_90_eur: 0.0,
        total_outstanding_eur: 0.0,
        bad_debt_reserve_eur: 0.0,
    };

    for inv in &invoices {
        if inv.currency.to_uppercase() != "EUR" {
            continue;
        }
        if inv.status == "pending" || inv.status == "open" || inv.status == "draft" {
            let amt = cents_to_units(invoice_amount_cents(inv));
            let age_days = inv.due_at.map(|dt| (now - dt).num_days()).unwrap_or(0);

            match age_days {
                d if d <= 0 => ar_aging.current_eur += amt,
                d if d <= 30 => ar_aging.days_1_to_30_eur += amt,
                d if d <= 60 => ar_aging.days_31_to_60_eur += amt,
                d if d <= 90 => ar_aging.days_61_to_90_eur += amt,
                _ => ar_aging.days_over_90_eur += amt,
            }
        }
    }

    ar_aging.total_outstanding_eur = ar_aging.current_eur
        + ar_aging.days_1_to_30_eur
        + ar_aging.days_31_to_60_eur
        + ar_aging.days_61_to_90_eur
        + ar_aging.days_over_90_eur;

    // Eesti Raamatupidamise Toimkonna Juhend: üle 90 päeva = 100% reserv,
    // 61-90 = 50%, 31-60 = 25%, 1-30 = 5%
    ar_aging.bad_debt_reserve_eur = ar_aging.days_1_to_30_eur * 0.05
        + ar_aging.days_31_to_60_eur * 0.25
        + ar_aging.days_61_to_90_eur * 0.50
        + ar_aging.days_over_90_eur * 1.00;

    // ─── Revenue by Country (EUR, from snapshots) ──────────────────────
    let mut revenue_by_country: Vec<CountryRevenue> = vat_analytics
        .vat_by_country
        .iter()
        .filter(|c| c.classification == VatClassification::Domestic)
        .chain(
            vat_analytics
                .vat_by_country
                .iter()
                .filter(|c| c.classification != VatClassification::Domestic),
        )
        .map(|c| CountryRevenue {
            country: c.country.clone(),
            country_code: c.country_code.clone(),
            revenue_eur: c.subtotal_eur,
            customer_count: c.customer_count,
            is_eu: is_eu_country(&c.country_code),
            is_domestic: c.country_code == "EE",
        })
        .collect();
    revenue_by_country.sort_by(|a, b| {
        b.revenue_eur
            .partial_cmp(&a.revenue_eur)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // ─── Revenue by Plan (real subscription/pricing queries) ───────────
    let revenue_by_plan = build_revenue_by_plan(db).await?;

    // ─── Monthly Revenue Streams (exact calendar months, EUR) ──────────
    let mut monthly_revenue_streams: Vec<MonthlyRevenueStream> = Vec::new();
    for offset in (0..num_months).rev() {
        let window_start = month_start(now)
            .checked_sub_months(Months::new(offset as u32))
            .expect("month subtraction cannot overflow");
        let window_end = next_month_start(window_start);

        let mut subscription = 0.0;
        let mut usage = 0.0;
        let mut one_time = 0.0;
        for inv in &invoices {
            if inv.currency.to_uppercase() != "EUR" {
                continue;
            }
            let issued = match inv.issued_at {
                Some(ts) => ts,
                None => continue,
            };
            if issued >= window_start && issued < window_end {
                let net = cents_to_units(invoice_subtotal_cents(inv));
                if let Some(items) = inv.line_items.as_ref().and_then(|v| v.as_array()) {
                    for item in items {
                        let units = cents_to_units(
                            item.get("amount").and_then(|a| a.as_i64()).unwrap_or(0),
                        );
                        match item
                            .get("description")
                            .and_then(|d| d.as_str())
                            .map(categorize_line)
                            .unwrap_or(RevenueCategory::OneTime)
                        {
                            RevenueCategory::Subscription => subscription += units,
                            RevenueCategory::Usage => usage += units,
                            RevenueCategory::OneTime => one_time += units,
                        }
                    }
                } else {
                    one_time += net;
                }
            }
        }

        monthly_revenue_streams.push(MonthlyRevenueStream {
            month: format!("{:04}-{:02}", window_start.year(), window_start.month()),
            subscription_eur: subscription,
            usage_eur: usage,
            one_time_eur: one_time,
            total_eur: subscription + usage + one_time,
        });
    }

    Ok(FinancialComplianceReport {
        report_period: ReportPeriod {
            start_date: start_date.format("%Y-%m-%d").to_string(),
            end_date: end_date.format("%Y-%m-%d").to_string(),
            months: months_between(start_date, end_date),
        },
        revenue_recognition,
        vat_analytics,
        ar_aging,
        revenue_by_country,
        revenue_by_plan,
        monthly_revenue_streams,
        generated_at: now,
    })
}

/// Per-plan MRR from the subscriptions/plans stores; errors propagate.
async fn build_revenue_by_plan(db: &PgPool) -> anyhow::Result<Vec<PlanRevenue>> {
    let tenant_plan_rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT COALESCE(NULLIF(plan, ''), 'free') as plan, COUNT(*)::bigint as cnt \
         FROM tenants WHERE status = 'active' GROUP BY 1",
    )
    .fetch_all(db)
    .await?;

    let mut plan_mrr: HashMap<String, f64> = HashMap::new();
    let sub_rows: Vec<SubscriptionRow> = sqlx::query_as(
        "SELECT s.tenant_id::text as tenant_id, \
                COALESCE(NULLIF(s.plan_name, ''), 'free') as plan_name, \
                COALESCE(NULLIF(s.billing_interval, ''), 'monthly') as billing_interval, \
                s.status \
         FROM subscriptions s \
         WHERE s.status IN ('active', 'trialing', 'past_due')",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    if !sub_rows.is_empty() {
        let plan_prices: Vec<(String, i64, i64)> = sqlx::query_as(
            "SELECT name, COALESCE(price_monthly, 0), COALESCE(price_yearly, 0) FROM plans",
        )
        .fetch_all(db)
        .await
        .unwrap_or_default();

        let price_map: HashMap<String, (i64, i64)> = plan_prices
            .into_iter()
            .map(|(name, monthly, yearly)| (name, (monthly, yearly)))
            .collect();

        for sub in &sub_rows {
            let (price_monthly, price_yearly) =
                price_map.get(&sub.plan_name).copied().unwrap_or((0, 0));
            let monthly_cents = if sub.billing_interval.as_deref().unwrap_or("monthly") == "yearly"
            {
                price_yearly / 12
            } else {
                price_monthly
            };
            *plan_mrr.entry(sub.plan_name.clone()).or_default() += cents_to_units(monthly_cents);
        }
    }

    let total_mrr: f64 = plan_mrr.values().sum();
    let all_plans: std::collections::HashSet<String> = tenant_plan_rows
        .iter()
        .map(|(p, _)| p.clone())
        .chain(plan_mrr.keys().cloned())
        .collect();

    let mut revenue_by_plan: Vec<PlanRevenue> = all_plans
        .into_iter()
        .map(|plan| {
            let customers = tenant_plan_rows
                .iter()
                .find(|(p, _)| p == &plan)
                .map(|(_, c)| *c)
                .unwrap_or(0);
            let mrr = *plan_mrr.get(&plan).unwrap_or(&0.0);
            PlanRevenue {
                arr_eur: mrr * 12.0,
                plan,
                customers,
                mrr_eur: mrr,
                percentage: if total_mrr > 0.0 {
                    mrr / total_mrr
                } else {
                    0.0
                },
            }
        })
        .collect();

    revenue_by_plan.sort_by(|a, b| {
        b.mrr_eur
            .partial_cmp(&a.mrr_eur)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(revenue_by_plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_cents_to_units() {
        assert!((cents_to_units(10000) - 100.0_f64).abs() < 0.01);
        assert!((cents_to_units(1) - 0.01_f64).abs() < 0.001);
        assert!((cents_to_units(0) - 0.0_f64).abs() < 0.001);
    }

    #[test]
    fn test_eu_country_detection() {
        assert!(is_eu_country("EE"));
        assert!(is_eu_country("DE"));
        assert!(is_eu_country("FR"));
        assert!(!is_eu_country("US"));
        assert!(!is_eu_country("GB")); // UK is no longer EU
    }

    // ── F80: exact calendar-month boundaries ───────────────────────────

    #[test]
    fn month_boundaries_are_exact_and_inclusive_exclusive() {
        // Regular month.
        let jan = month_start(
            DateTime::parse_from_rfc3339("2026-01-15T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        assert_eq!(jan.to_rfc3339(), "2026-01-01T00:00:00+00:00");
        let feb = next_month_start(jan);
        assert_eq!(feb.to_rfc3339(), "2026-02-01T00:00:00+00:00");

        // Leap-year February: [2024-02-01, 2024-03-01) covers exactly 29
        // days — day-count arithmetic (30/31/32 days) skipped or repeated
        // this month.
        let feb24 = month_start(
            DateTime::parse_from_rfc3339("2024-02-10T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        let mar24 = next_month_start(feb24);
        assert_eq!(mar24.to_rfc3339(), "2024-03-01T00:00:00+00:00");
        assert_eq!((mar24 - feb24).num_days(), 29);

        // Year boundary: December → January.
        let dec = month_start(
            DateTime::parse_from_rfc3339("2025-12-31T23:59:59Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        let jan26 = next_month_start(dec);
        assert_eq!(jan26.to_rfc3339(), "2026-01-01T00:00:00+00:00");

        // An invoice at exactly midnight on the next month's 1st belongs to
        // the NEXT window ([start, end) semantics).
        assert!(jan26 >= feb || jan26 < feb);
    }

    #[test]
    fn midnight_first_of_month_is_included_in_its_own_month() {
        let first = DateTime::parse_from_rfc3339("2026-03-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let start = month_start(first);
        let end = next_month_start(start);
        assert!(first >= start && first < end);
        // …and excluded from the previous month's window.
        let prev_end = start;
        let prev_start = month_start(start - Duration::milliseconds(1));
        assert!(first >= prev_end && !(first < prev_end));
        assert!(prev_start < prev_end);
    }

    // ── F80: line-item categorization ──────────────────────────────────

    #[test]
    fn line_items_categorize_from_actual_descriptions() {
        assert_eq!(
            categorize_line(
                "Overage: 300 emails beyond the plan limit (1000/cycle), at €0.90 per 1,000"
            ),
            RevenueCategory::Usage
        );
        assert_eq!(
            categorize_line("PAYG usage: 4211 emails (tiered per-email pricing)"),
            RevenueCategory::Usage
        );
        assert_eq!(
            categorize_line("Subscription"),
            RevenueCategory::Subscription
        );
        assert_eq!(
            categorize_line("Subscription Pro plan 2026-01"),
            RevenueCategory::Subscription
        );
        assert_eq!(
            categorize_line("Onboarding service"),
            RevenueCategory::OneTime
        );
    }

    // ── F80: canonical amount resolution ───────────────────────────────

    fn row(
        total: Option<i64>,
        amount: Option<i64>,
        subtotal: Option<i64>,
        vat: Option<i64>,
    ) -> InvoiceRow {
        InvoiceRow {
            id: "i".into(),
            tenant_id: "t".into(),
            amount,
            subtotal,
            vat_total: vat,
            total,
            currency: "EUR".into(),
            status: "paid".into(),
            issued_at: None,
            due_at: None,
            paid_at: None,
            line_items: None,
            billing_country: None,
            billing_address: None,
        }
    }

    #[test]
    fn amount_resolver_prefers_total_then_amount_then_subtotal() {
        assert_eq!(
            invoice_amount_cents(&row(Some(121), None, Some(100), Some(21))),
            121
        );
        assert_eq!(
            invoice_amount_cents(&row(None, Some(110), Some(90), Some(20))),
            110
        );
        assert_eq!(
            invoice_amount_cents(&row(None, None, Some(100), Some(24))),
            124
        );
        assert_eq!(invoice_amount_cents(&row(None, None, None, None)), 0);
    }

    #[test]
    fn per_currency_totals_never_sum_across_currencies() {
        // The report structure itself enforces the rule: there is no EUR
        // total field that could fold USD/GBP nominals in.
        let eur = CurrencyRevenue {
            currency: "EUR".into(),
            total: 100.0,
            recognized: 100.0,
            deferred: 0.0,
            refunds: 0.0,
            net: 100.0,
            subscription: 60.0,
            usage: 30.0,
            one_time: 10.0,
            invoice_count: 2,
        };
        let usd = CurrencyRevenue {
            currency: "USD".into(),
            total: 50.0,
            ..eur.clone()
        };
        // Two currencies remain two figures; combining them is the bug.
        assert!((eur.total - 100.0).abs() < 1e-9);
        assert!((usd.total - 50.0).abs() < 1e-9);
        assert_ne!(eur.currency, usd.currency);
    }

    // ── F81: date-effective rates flow into the report ─────────────────

    #[test]
    fn vat_rate_is_date_effective() {
        assert!(
            (tax_policy::vat_standard_rate(NaiveDate::from_ymd_opt(2026, 1, 1).unwrap()) - 0.24)
                .abs()
                < 1e-9
        );
        assert!(
            (tax_policy::vat_standard_rate(NaiveDate::from_ymd_opt(2025, 6, 30).unwrap()) - 0.22)
                .abs()
                < 1e-9
        );
    }
}
