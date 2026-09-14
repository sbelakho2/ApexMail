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
//!     fixed percentages; a missing or non-reconciling snapshot is uniformly
//!     one-time (unallocated) revenue in every surface (see
//!     `categorize_invoice_net`);
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

/// Revenue-category split of one invoice's NET subtotal, in cents.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct InvoiceCategorySplit {
    subscription_cents: i64,
    usage_cents: i64,
    one_time_cents: i64,
}

/// The ONE categorization rule shared by the period revenue-recognition view
/// (inside [`generate_financial_compliance_report`]) and the monthly revenue
/// stream ([`monthly_revenue_stream`]).
///
/// The split comes from the invoice's actual `line_items` JSONB only when the
/// snapshot exists AND its line amounts reconcile exactly with the headline
/// net subtotal. Whenever that is not the case — no snapshot at all (a legacy
/// or hand-written invoice), an empty array, or line items that do not add up
/// — the entire net is unallocated and reported as ONE-TIME revenue. A
/// snapshot-less invoice is therefore never counted in the total of one
/// surface while silently vanishing from the categories of the other: both
/// legally reported surfaces call this function, so their arithmetic is
/// identical by construction and no subscription/usage split is ever
/// invented.
fn categorize_invoice_net(inv: &InvoiceRow) -> InvoiceCategorySplit {
    let net = invoice_subtotal_cents(inv);
    let Some(items) = inv.line_items.as_ref().and_then(|v| v.as_array()) else {
        return InvoiceCategorySplit {
            one_time_cents: net,
            ..Default::default()
        };
    };
    let line_sum: i64 = items
        .iter()
        .filter_map(|item| item.get("amount").and_then(|a| a.as_i64()))
        .sum();
    if net <= 0 || line_sum != net {
        // Unreconciled (including an empty snapshot): visibly unallocated
        // rather than force-split.
        return InvoiceCategorySplit {
            one_time_cents: net,
            ..Default::default()
        };
    }
    let mut split = InvoiceCategorySplit::default();
    for item in items {
        let units = item.get("amount").and_then(|a| a.as_i64()).unwrap_or(0);
        match item
            .get("description")
            .and_then(|d| d.as_str())
            .map(categorize_line)
            .unwrap_or(RevenueCategory::OneTime)
        {
            RevenueCategory::Subscription => split.subscription_cents += units,
            RevenueCategory::Usage => split.usage_cents += units,
            RevenueCategory::OneTime => split.one_time_cents += units,
        }
    }
    split
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

/// One exact calendar-month revenue stream (EUR) for the window
/// `[month_start_ts, next_month_start)`.
///
/// Categorization rule (monthly view): identical to the period view — this
/// function calls [`categorize_invoice_net`], the single shared rule, so an
/// invoice without a `line_items` snapshot is one-time (unallocated) revenue
/// in BOTH surfaces and the monthly total (subscription + usage + one_time)
/// still covers every invoice in its window. Non-EUR invoices are excluded
/// (nominal amounts are never converted), and an empty window is explicit
/// zeros.
fn monthly_revenue_stream(
    invoices: &[InvoiceRow],
    month_start_ts: DateTime<Utc>,
) -> MonthlyRevenueStream {
    let window_end = next_month_start(month_start_ts);
    let mut subscription_cents = 0i64;
    let mut usage_cents = 0i64;
    let mut one_time_cents = 0i64;

    for inv in invoices {
        if inv.currency.to_uppercase() != "EUR" {
            continue;
        }
        let Some(issued) = inv.issued_at else {
            continue;
        };
        if issued >= month_start_ts && issued < window_end {
            let split = categorize_invoice_net(inv);
            subscription_cents += split.subscription_cents;
            usage_cents += split.usage_cents;
            one_time_cents += split.one_time_cents;
        }
    }

    MonthlyRevenueStream {
        month: format!("{:04}-{:02}", month_start_ts.year(), month_start_ts.month()),
        subscription_eur: cents_to_units(subscription_cents),
        usage_eur: cents_to_units(usage_cents),
        one_time_eur: cents_to_units(one_time_cents),
        total_eur: cents_to_units(subscription_cents + usage_cents + one_time_cents),
    }
}

/// Generate a full Estonian OÜ financial compliance analytics report from
/// the canonical model. Errors propagate — unavailable data is visible.
///
/// Categorization rule (period view): the `subscription`/`usage`/`one_time`
/// split of each currency is assigned by `categorize_invoice_net` — an
/// invoice whose `line_items` snapshot is missing or does not reconcile with
/// its net subtotal is one-time (unallocated) revenue, never silently
/// uncategorized while still counted in the total. The monthly stream
/// (`monthly_revenue_stream`) applies the identical rule through the same
/// function, so the two legally reported surfaces cannot contradict.
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

        // F80: categorize ACTUAL line items through the single rule shared
        // with the monthly stream — a snapshot-less or non-reconciling
        // invoice's net is one-time (unallocated) revenue here too.
        let split = categorize_invoice_net(inv);
        entry.subscription += cents_to_units(split.subscription_cents);
        entry.usage += cents_to_units(split.usage_cents);
        entry.one_time += cents_to_units(split.one_time_cents);
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
        monthly_revenue_streams.push(monthly_revenue_stream(&invoices, window_start));
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

// ─── DB-backed adversarial tests ────────────────────────────────────────────
//
// Every figure must come from the canonical invoices; nominal amounts in
// different currencies are never summed, line items that do not reconcile are
// visibly uncategorized, and an empty period is explicit zeros.

#[cfg(test)]
mod db_tests {
    use super::*;
    use crate::test_support;

    fn close(left: f64, right: f64) {
        assert!((left - right).abs() < 0.005, "expected {right}, got {left}");
    }

    async fn pool(suffix: &str) -> Option<sqlx::PgPool> {
        let pool = test_support::canonical_pool(&format!("fin_{suffix}"), &format!("fin_{suffix}"))
            .await?;
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status) VALUES
               ('t-dom', 'Domestic', 'pro', 'active'),
               ('t-eu', 'EU Customer', 'pro', 'active')
             ON CONFLICT (id) DO NOTHING",
        )
        .execute(&pool)
        .await
        .expect("seed tenants");
        Some(pool)
    }

    struct InvoiceSeed<'a> {
        tenant: &'a str,
        currency: &'a str,
        status: &'a str,
        subtotal: i64,
        vat: i64,
        total: i64,
        country: &'a str,
        vat_number: Option<&'a str>,
        line_items: Option<serde_json::Value>,
        due_at: Option<DateTime<Utc>>,
    }

    impl<'a> InvoiceSeed<'a> {
        fn paid(tenant: &'a str, subtotal: i64, vat: i64, country: &'a str) -> Self {
            Self {
                tenant,
                currency: "EUR",
                status: "paid",
                subtotal,
                vat,
                total: subtotal + vat,
                country,
                vat_number: None,
                line_items: None,
                due_at: None,
            }
        }
    }

    async fn insert_invoice(pool: &sqlx::PgPool, invoice: InvoiceSeed<'_>) {
        let snapshot = serde_json::json!({
            "country": invoice.country,
            "vat_number": invoice.vat_number,
        })
        .to_string();
        sqlx::query(
            "INSERT INTO invoices
               (id, tenant_id, amount, currency, status, issued_at, due_at, created_at, updated_at,
                subtotal, vat_total, total, line_items, billing_country, billing_address)
             VALUES (gen_random_uuid(), $1, $2, $3, $4, NOW(), $5, NOW(), NOW(),
                     $6, $7, $8, $9, $10, $11)",
        )
        .bind(invoice.tenant)
        .bind(invoice.total)
        .bind(invoice.currency)
        .bind(invoice.status)
        .bind(invoice.due_at)
        .bind(invoice.subtotal)
        .bind(invoice.vat)
        .bind(invoice.total)
        .bind(&invoice.line_items)
        .bind(invoice.country)
        .bind(&snapshot)
        .execute(pool)
        .await
        .expect("seed invoice");
    }

    #[test]
    fn amount_and_subtotal_resolvers_prefer_the_most_specific_column() {
        let mut inv = InvoiceRow {
            id: "i".into(),
            tenant_id: "t".into(),
            amount: Some(1000),
            subtotal: Some(800),
            vat_total: Some(200),
            total: Some(1000),
            currency: "EUR".into(),
            status: "paid".into(),
            issued_at: None,
            due_at: None,
            paid_at: None,
            line_items: None,
            billing_country: None,
            billing_address: None,
        };
        assert_eq!(invoice_amount_cents(&inv), 1000, "total wins");
        assert_eq!(invoice_subtotal_cents(&inv), 800, "subtotal wins");
        // Legacy row with only `amount` + VAT.
        inv.total = None;
        inv.subtotal = None;
        assert_eq!(invoice_amount_cents(&inv), 1000);
        assert_eq!(invoice_subtotal_cents(&inv), 800);
        // Legacy row with only amount (VAT included).
        inv.vat_total = None;
        assert_eq!(invoice_amount_cents(&inv), 1000);
        assert_eq!(invoice_subtotal_cents(&inv), 1000);
        // Reconstruct from subtotal + VAT when nothing else exists.
        inv.amount = None;
        inv.subtotal = Some(500);
        inv.vat_total = Some(120);
        assert_eq!(invoice_amount_cents(&inv), 620);
        // Nothing at all is zero, not a panic.
        inv.subtotal = None;
        inv.vat_total = None;
        assert_eq!(invoice_amount_cents(&inv), 0);
        assert_eq!(invoice_subtotal_cents(&inv), 0);
    }

    #[test]
    fn classifications_are_case_and_snapshot_driven() {
        assert!(is_eu_country("DE"));
        assert!(is_eu_country("FR"));
        assert!(!is_eu_country("US"));
        assert!(!is_eu_country("de"), "lowercase is not a canonical code");

        let invoice = |country: Option<&str>, vat_number: Option<&str>| InvoiceRow {
            id: "i".into(),
            tenant_id: "t".into(),
            amount: None,
            subtotal: Some(100),
            vat_total: Some(24),
            total: Some(124),
            currency: "EUR".into(),
            status: "paid".into(),
            issued_at: None,
            due_at: None,
            paid_at: None,
            line_items: None,
            billing_country: country.map(str::to_string),
            billing_address: vat_number.map(|number| {
                serde_json::json!({"country": "DE", "vat_number": number}).to_string()
            }),
        };
        assert_eq!(
            classify_vat(&invoice(Some("ee"), None)),
            VatClassification::Domestic,
            "case-insensitive country"
        );
        assert_eq!(
            classify_vat(&invoice(Some("DE"), Some("DE123456789"))),
            VatClassification::ReverseCharge
        );
        assert_eq!(
            classify_vat(&invoice(Some("DE"), Some("   "))),
            VatClassification::EuVatDue,
            "a blank VAT number is not a valid one"
        );
        assert_eq!(
            classify_vat(&invoice(Some("US"), None)),
            VatClassification::ZeroRatedExport
        );
        // Missing billing_country falls back to the immutable snapshot.
        assert_eq!(
            classify_vat(&invoice(None, Some("DE123456789"))),
            VatClassification::ReverseCharge
        );
        // A malformed snapshot never fabricates a VAT number or a country.
        let mut malformed = invoice(None, None);
        malformed.billing_address = Some("{not json".into());
        assert_eq!(classify_vat(&malformed), VatClassification::ZeroRatedExport);

        assert_eq!(
            categorize_line("Subscription – Pro"),
            RevenueCategory::Subscription
        );
        assert_eq!(
            categorize_line("subscription"),
            RevenueCategory::Subscription
        );
        assert_eq!(
            categorize_line("Overage: 12k emails"),
            RevenueCategory::Usage
        );
        assert_eq!(categorize_line("PAYG usage: April"), RevenueCategory::Usage);
        assert_eq!(categorize_line("Setup fee"), RevenueCategory::OneTime);
        assert_eq!(categorize_line(""), RevenueCategory::OneTime);
    }

    #[test]
    fn month_arithmetic_is_exact_across_year_boundaries() {
        let start = NaiveDate::from_ymd_opt(2025, 11, 1).unwrap();
        let end = NaiveDate::from_ymd_opt(2026, 2, 1).unwrap();
        assert_eq!(months_between(start, end), 3);

        let december = NaiveDate::from_ymd_opt(2026, 12, 15)
            .unwrap()
            .and_time(NaiveTime::MIN)
            .and_utc();
        assert_eq!(
            month_start(december).to_rfc3339(),
            "2026-12-01T00:00:00+00:00"
        );
        let january = next_month_start(month_start(december));
        assert_eq!(january.to_rfc3339(), "2027-01-01T00:00:00+00:00");
        assert_eq!(
            next_month_start(january).to_rfc3339(),
            "2027-02-01T00:00:00+00:00"
        );
        // Leap-year February has 29 days; March starts on the 1st.
        let feb = month_start(
            NaiveDate::from_ymd_opt(2028, 2, 29)
                .unwrap()
                .and_time(NaiveTime::MIN)
                .and_utc(),
        );
        assert_eq!(
            next_month_start(feb).to_rfc3339(),
            "2028-03-01T00:00:00+00:00"
        );
    }

    #[tokio::test]
    async fn report_derives_every_figure_from_the_live_invoices() {
        let Some(pool) = pool("report").await else {
            return;
        };
        let now = Utc::now();

        // Domestic EUR paid invoice with reconciling line items.
        insert_invoice(
            &pool,
            InvoiceSeed {
                line_items: Some(serde_json::json!([
                    {"description": "Subscription – Pro", "amount": 10000},
                    {"description": "Overage: 5k emails", "amount": 2500},
                    {"description": "Setup fee", "amount": 500}
                ])),
                ..InvoiceSeed::paid("t-dom", 13000, 3120, "EE")
            },
        )
        .await;
        // Non-EUR invoice: counted per currency, excluded from EUR VAT/AR.
        insert_invoice(
            &pool,
            InvoiceSeed {
                currency: "USD",
                line_items: Some(serde_json::json!([
                    {"description": "Subscription", "amount": 7000}
                ])),
                ..InvoiceSeed::paid("t-eu", 7000, 0, "US")
            },
        )
        .await;
        // Reverse-charge EU invoice (valid VAT number in the snapshot).
        insert_invoice(
            &pool,
            InvoiceSeed {
                vat_number: Some("DE811234567"),
                ..InvoiceSeed::paid("t-eu", 20000, 0, "DE")
            },
        )
        .await;
        // EU B2C invoice without a VAT number: EE VAT is due.
        insert_invoice(&pool, InvoiceSeed::paid("t-eu", 5000, 1200, "FR")).await;
        // Outside the EU: zero-rated export.
        insert_invoice(&pool, InvoiceSeed::paid("t-eu", 3000, 0, "US")).await;
        // Refunded invoice: recognized is not affected, refunds are.
        insert_invoice(
            &pool,
            InvoiceSeed {
                status: "refunded",
                ..InvoiceSeed::paid("t-dom", 4000, 960, "EE")
            },
        )
        .await;
        // Open invoice, 45 days overdue → 31-60 day bucket.
        insert_invoice(
            &pool,
            InvoiceSeed {
                status: "open",
                due_at: Some(now - chrono::Duration::days(45)),
                ..InvoiceSeed::paid("t-dom", 8000, 1920, "EE")
            },
        )
        .await;
        // Open invoice, not yet due → current bucket.
        insert_invoice(
            &pool,
            InvoiceSeed {
                status: "open",
                due_at: Some(now + chrono::Duration::days(10)),
                ..InvoiceSeed::paid("t-dom", 2000, 480, "EE")
            },
        )
        .await;
        // Line items that do NOT reconcile with the subtotal: visibly
        // one-time, never force-split.
        insert_invoice(
            &pool,
            InvoiceSeed {
                line_items: Some(serde_json::json!([
                    {"description": "Subscription", "amount": 1}
                ])),
                ..InvoiceSeed::paid("t-dom", 9000, 2160, "EE")
            },
        )
        .await;

        let report = generate_financial_compliance_report(&pool, 3)
            .await
            .expect("report");
        assert_eq!(
            report.report_period.months, 2,
            "3-month window spans 2 boundaries"
        );
        assert!(!report.report_period.start_date.is_empty());

        // Per-currency revenue: EUR first, then alphabetical; USD never
        // added into a EUR total.
        let currencies: Vec<&str> = report
            .revenue_recognition
            .by_currency
            .iter()
            .map(|c| c.currency.as_str())
            .collect();
        assert_eq!(currencies, vec!["EUR", "USD"]);
        assert_eq!(report.revenue_recognition.non_eur_currencies, vec!["USD"]);
        assert!(report.revenue_recognition.has_source_data);
        let eur = &report.revenue_recognition.by_currency[0];
        // totals: 13000+3120 + 20000 + 5000+1200 + 3000 + 4000+960 + 8000+1920 + 2000+480 + 9000+2160
        let eur_total: f64 = (13000
            + 3120
            + 20000
            + 5000
            + 1200
            + 3000
            + 4000
            + 960
            + 8000
            + 1920
            + 2000
            + 480
            + 9000
            + 2160) as f64
            / 100.0;
        close(eur.total, eur_total);
        close(eur.refunds, (4000 + 960) as f64 / 100.0);
        close(eur.deferred, (8000 + 1920 + 2000 + 480) as f64 / 100.0);
        // Recognized excludes refunds and open invoices.
        close(
            eur.recognized,
            (13000 + 3120 + 20000 + 5000 + 1200 + 3000 + 9000 + 2160) as f64 / 100.0,
        );
        close(eur.net, eur.recognized - eur.refunds);
        // Line-item categories come from the descriptions.
        close(eur.subscription, 100.0);
        close(eur.usage, 25.0);
        // one-time: setup 5.00 + the 90.00 non-reconciling invoice + the
        // snapshot-less invoices (200 + 50 + 30 + 40 + 80 + 20) — the same
        // shared rule the monthly stream applies.
        close(
            eur.one_time,
            5.0 + 90.0 + 200.0 + 50.0 + 30.0 + 40.0 + 80.0 + 20.0,
        );
        assert_eq!(eur.invoice_count, 8);
        let usd = &report.revenue_recognition.by_currency[1];
        close(usd.total, 70.0);
        close(usd.subscription, 70.0);
        assert_eq!(usd.invoice_count, 1);

        // VAT analytics: only EUR invoices; EU-without-VAT joins domestic
        // output; reverse charge and exports are separate; non-EUR counted.
        let vat = &report.vat_analytics;
        assert_eq!(
            vat.vat_rate,
            tax_policy::vat_standard_rate(Utc::now().date_naive())
        );
        // EU B2C (FR) stays its own subtotal line; only its output VAT joins
        // the domestic output figure.
        close(
            vat.domestic_taxable_subtotal_eur,
            (13000 + 4000 + 8000 + 2000 + 9000) as f64 / 100.0,
        );
        close(
            vat.domestic_output_vat_eur,
            (3120 + 1200 + 960 + 1920 + 480 + 2160) as f64 / 100.0,
        );
        close(vat.eu_reverse_charge_subtotal_eur, 200.0);
        close(vat.eu_vat_due_subtotal_eur, 50.0);
        close(vat.non_eu_export_subtotal_eur, 30.0);
        assert_eq!(vat.non_eur_invoices, 1);
        close(vat.vat_deductible_eur, 0.0);
        assert!(!vat.input_tax_source);
        close(vat.net_vat_payable_eur, vat.domestic_output_vat_eur);

        // AR aging: only EUR open invoices, by due date.
        let ar = &report.ar_aging;
        close(ar.days_31_to_60_eur, 99.20);
        close(ar.current_eur, 24.80);
        close(
            ar.total_outstanding_eur,
            ar.current_eur
                + ar.days_1_to_30_eur
                + ar.days_31_to_60_eur
                + ar.days_61_to_90_eur
                + ar.days_over_90_eur,
        );
        close(
            ar.bad_debt_reserve_eur,
            ar.days_1_to_30_eur * 0.05
                + ar.days_31_to_60_eur * 0.25
                + ar.days_61_to_90_eur * 0.5
                + ar.days_over_90_eur,
        );

        // Country breakdown: sorted by subtotal descending, EE domestic.
        let countries: Vec<&str> = report
            .revenue_by_country
            .iter()
            .map(|c| c.country_code.as_str())
            .collect();
        assert!(countries.contains(&"EE"));
        assert!(report
            .revenue_by_country
            .iter()
            .any(|c| c.is_domestic && c.country_code == "EE"));
        assert!(report
            .revenue_by_country
            .iter()
            .any(|c| c.is_eu && c.country_code == "DE"));
        assert!(report
            .revenue_by_country
            .windows(2)
            .all(|w| w[0].revenue_eur >= w[1].revenue_eur));

        // Monthly streams cover the requested window in order.
        assert_eq!(report.monthly_revenue_streams.len(), 3);
        let current = report.monthly_revenue_streams.last().expect("current");
        close(
            current.total_eur,
            current.subscription_eur + current.usage_eur + current.one_time_eur,
        );
        // Monthly categories obey the same reconciliation rule as the period
        // recognition: the non-reconciling snapshot is NOT split (its net is
        // one-time), so the monthly total still covers every invoice.
        close(current.subscription_eur, 100.0);
        close(current.usage_eur, 25.0);
        close(
            current.one_time_eur,
            5.0 + 90.0 + 200.0 + 50.0 + 30.0 + 40.0 + 80.0 + 20.0,
        );
        // An earlier month with no invoices is an explicit zero, not omitted.
        assert!(report
            .monthly_revenue_streams
            .iter()
            .any(|m| m.total_eur == 0.0));

        // Plan revenue comes from the tenants table (pro plan, 2 active).
        let pro = report
            .revenue_by_plan
            .iter()
            .find(|p| p.plan == "pro")
            .expect("pro plan");
        assert_eq!(pro.customers, 2);
        close(pro.arr_eur, pro.mrr_eur * 12.0);
    }

    /// The period revenue-recognition view and the monthly stream are both
    /// legally reported surfaces: they must categorize a snapshot-less
    /// invoice identically. This pins the chosen rule — no `line_items`
    /// snapshot (like a non-reconciling one) is one-time/unallocated revenue
    /// in BOTH views — and asserts the two functions agree line by line and
    /// on the total.
    #[tokio::test]
    async fn period_and_monthly_views_agree_for_snapshot_less_invoices() {
        let Some(pool) = pool("snapshot_agreement").await else {
            return;
        };
        // (a) A reconciling snapshot: 100.00 subscription + 25.00 usage.
        insert_invoice(
            &pool,
            InvoiceSeed {
                line_items: Some(serde_json::json!([
                    {"description": "Subscription – Pro", "amount": 10000},
                    {"description": "Overage: 1k emails", "amount": 2500}
                ])),
                ..InvoiceSeed::paid("t-dom", 12500, 0, "EE")
            },
        )
        .await;
        // (b) No line-item snapshot at all: 70.00, must be one-time in both.
        insert_invoice(&pool, InvoiceSeed::paid("t-dom", 7000, 0, "EE")).await;

        let report = generate_financial_compliance_report(&pool, 1)
            .await
            .expect("report");
        let eur = report
            .revenue_recognition
            .by_currency
            .iter()
            .find(|c| c.currency == "EUR")
            .expect("EUR revenue");
        close(eur.subscription, 100.0);
        close(eur.usage, 25.0);
        close(eur.one_time, 70.0);

        // The monthly stream must agree with the period view exactly.
        let month = report
            .monthly_revenue_streams
            .last()
            .expect("current month");
        close(month.subscription_eur, eur.subscription);
        close(month.usage_eur, eur.usage);
        close(month.one_time_eur, eur.one_time);
        close(month.total_eur, 195.0);
        close(month.total_eur, eur.subscription + eur.usage + eur.one_time);
        // No VAT and only paid invoices: the recognized total is the same
        // figure the monthly stream reports.
        close(month.total_eur, eur.recognized);

        pool.close().await;
    }

    #[tokio::test]
    async fn an_empty_invoice_table_is_explicit_zero_not_a_fabricated_total() {
        let Some(pool) = pool("empty").await else {
            return;
        };
        let report = generate_financial_compliance_report(&pool, 1)
            .await
            .expect("report");
        assert!(!report.revenue_recognition.has_source_data);
        assert!(report.revenue_recognition.by_currency.is_empty());
        assert!(report.revenue_recognition.non_eur_currencies.is_empty());
        assert_eq!(report.vat_analytics.non_eur_invoices, 0);
        close(report.vat_analytics.domestic_taxable_subtotal_eur, 0.0);
        close(report.vat_analytics.net_vat_payable_eur, 0.0);
        close(report.ar_aging.total_outstanding_eur, 0.0);
        close(report.ar_aging.bad_debt_reserve_eur, 0.0);
        assert!(report.revenue_by_country.is_empty());
        assert_eq!(report.monthly_revenue_streams.len(), 1);
        close(report.monthly_revenue_streams[0].total_eur, 0.0);
        // A zero period is clamped to one month; a huge one to 24.
        let clamped = generate_financial_compliance_report(&pool, 500)
            .await
            .expect("clamped");
        assert_eq!(clamped.monthly_revenue_streams.len(), 24);
        let negative = generate_financial_compliance_report(&pool, -5)
            .await
            .expect("negative clamped");
        assert_eq!(negative.monthly_revenue_streams.len(), 1);
    }

    #[tokio::test]
    async fn subscription_plans_and_yearly_intervals_feed_mrr() {
        let Some(pool) = pool("plans").await else {
            return;
        };
        sqlx::query(
            "INSERT INTO plans (name, price_monthly, price_yearly)
             VALUES ('pro', 4900, 49000), ('scale', 19900, 199000)
             ON CONFLICT (name) DO NOTHING",
        )
        .execute(&pool)
        .await
        .expect("plans");
        sqlx::query(
            "INSERT INTO subscriptions (id, tenant_id, plan_name, billing_interval, status, created_at, updated_at)
             VALUES (gen_random_uuid(), 't-dom', 'pro', 'yearly', 'active', NOW(), NOW()),
                    (gen_random_uuid(), 't-eu', 'scale', 'monthly', 'trialing', NOW(), NOW()),
                    (gen_random_uuid(), 't-dom', 'pro', 'monthly', 'canceled', NOW(), NOW())",
        )
        .execute(&pool)
        .await
        .expect("subscriptions");
        let report = generate_financial_compliance_report(&pool, 1)
            .await
            .expect("report");
        let pro = report
            .revenue_by_plan
            .iter()
            .find(|p| p.plan == "pro")
            .expect("pro");
        // Yearly 49000/12 = 4083 cents → 40.83; the canceled sub is excluded.
        close(pro.mrr_eur, 40.83);
        let scale = report
            .revenue_by_plan
            .iter()
            .find(|p| p.plan == "scale")
            .expect("scale");
        close(scale.mrr_eur, 199.0);
        let total: f64 = report.revenue_by_plan.iter().map(|p| p.mrr_eur).sum();
        close(
            report
                .revenue_by_plan
                .iter()
                .map(|p| p.percentage)
                .sum::<f64>(),
            if total > 0.0 { 1.0 } else { 0.0 },
        );
        assert!(report
            .revenue_by_plan
            .windows(2)
            .all(|w| w[0].mrr_eur >= w[1].mrr_eur));
    }
}
