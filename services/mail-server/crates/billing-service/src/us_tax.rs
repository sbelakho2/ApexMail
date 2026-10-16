//! US sales tax (plan WP C2, SaaS-grade): per-state taxability, either-
//! criterion economic-nexus tracking, customer exemption certificates, early
//! warnings and a filing-ready per-state report.
//!
//! The whole tax stack before this module was EU-only (`vat_*` modules,
//! `invoices.vat_rate` / `vat_amount`). This module adds the US half for an
//! Estonia-based SaaS selling email-sending subscriptions to US customers,
//! with these hard rules:
//!
//! 1. **No invented rates, and never over-collect.** Rates, taxability and
//!    economic-nexus thresholds live in a committed, provenance-carrying
//!    data file (`billing-service/data/us_sales_tax.json`, embedded at build
//!    time, an operator may point `US_TAX_DATA_FILE` at another copy). It
//!    ships EMPTY: a row is a factual claim about a state's tax law, so it
//!    carries the state's own `sourceUrl` and the `retrieved` date the
//!    figures were read. Every row declares `taxability`
//!    (`taxable` | `not_taxable`); an absent or unrecognised value resolves
//!    to `not_taxable` — for a SaaS product, over-collecting where the
//!    product is exempt is the harmful direction. A `taxable` row REQUIRES a
//!    rate. [`UsTaxTable::parse`] validates every row and
//!    [`check_data_file`] renders the `--check` report.
//! 2. **Stale rates fail closed.** The stamp of the rate that will be USED
//!    (the combined rate when the row carries one, else the state rate)
//!    older than `US_TAX_MAX_AGE_DAYS` (default 120) makes the computation
//!    REFUSE with a named error ([`UsTaxError::StaleRateRow`]) — never a
//!    silent computation from a rate of unknown age. The invoice writer
//!    propagates the refusal (no invoice, retried, visible); it never issues
//!    a US invoice in a registered state without its tax.
//! 3. **Registration is an operator act, never a computed one.** The sweep
//!    tracks BOTH nexus measures (USD sales and transaction counts, plus the
//!    exempt portion), alerts on the FIRST crossing of whichever criteria
//!    the state's row declares (`sales` | `transactions` | `either`), and
//!    raises ONE early warning at `US_TAX_WARN_FRACTION` (default 0.8) of
//!    the threshold so registration/filing has lead time. It NEVER registers
//!    a state and NEVER charges tax — sales tax is computed only after the
//!    owner/accounting registers the state through the admin surface
//!    ([`register_state`], audited), which itself requires a usable row.
//!    `not_taxable` states are never evaluated, never asked to register, and
//!    never charged even if a registration row exists.
//! 4. **Customer exemptions are substantiated, never assumed.** A B2B
//!    customer buys under a resale/exemption certificate
//!    ([`us_tax_customer_exemptions`] storage, operator-managed and
//!    audited). At invoice time the certificate covering the state and not
//!    expired zeroes that state's tax line, is recorded on the invoice's tax
//!    snapshot, and the sale is still counted (separately, as exempt sales)
//!    toward nexus and the filing report. An expired or absent certificate
//!    is taxable.
//!
//! # Money
//!
//! Every amount is integer cents (`i64`); the rate is integer basis points
//! (`u32`, 7.25 % = 725) because US state rates are conventionally quoted in
//! whole or quarter basis points — no float ever touches a money path here
//! (the crate's `money_invariants` gate covers this file). The warn fraction
//! is parsed to integer basis points of the threshold (`0.8` → 8000). Tax is
//! rounded half-up ONCE per invoice line, exactly like the VAT module's
//! `vat_amount_half_up` convention: `(base × bps + 5_000) / 10_000`.
//!
//! # What counts toward the nexus window (both criteria tracked)
//!
//! Invoices whose `billing_country` is `US`, whose status is not `void`, and
//! whose `issued_at` lies in the state's window:
//!
//! * the **sales test** sums the invoice SUBTOTAL (the sales price — collected
//!   tax is not part of gross receipts), USD invoices only (the thresholds
//!   are USD figures; no FX source exists here, and inventing one would
//!   fabricate the number the threshold is compared against);
//! * the **transaction test** counts invoices in every currency (a
//!   transaction needs no conversion) — the two counts are both stored, and
//!   only the declared criterion(s) alert;
//! * an **exempt sale counts toward both tests**: the common statutory rule
//!   measures gross sales / all transactions, and the exemption changes who
//!   collects, not whether the sale happened. The exempt portion is tracked
//!   separately ([`NexusMeasures::exempt_cents`]) for reporting.
//!
//! A US invoice whose billing address carries no usable state code counts as
//! UNKNOWN: reported in the sweep result and the report, never assigned. US
//! invoices in a non-USD currency are reported per currency, never converted.
//!
//! # What is NOT built (named, not faked)
//!
//! * **Local (county/city/district) rates.** The file models a state-level
//!   rate plus an optional, separately-stamped `combinedRateBps` for
//!   home-rule states; the row's `notes` field is where the owner records
//!   what is not modelled. A single blended local rate would misstate every
//!   shipment address.
//! * **Filing.** Nothing files a US state return; the accounting service is
//!   the filer. This module produces the numbers ([`us_tax_report`], JSON +
//!   CSV), the warnings and the alerts.
//! * **Automatic registration.** Nothing registers with a state; that is the
//!   owner's legal act.
//! * **A tax line on the legacy manual admin invoice writer.** The
//!   api-server's operator-facing `POST /v1/billing/admin/tenants/:id/invoices`
//!   has its own SQL and its own (legacy) response contract, so it does not
//!   compute the stamped line (the operator typing line items chooses the
//!   amounts). It fails CLOSED instead of silently omitting the tax: a US
//!   invoice for a state with `status = 'registered'` is refused there by
//!   name. The product invoicing path (this crate's invoice writer) always
//!   applies the stamped line, for every invoice kind (subscription overage,
//!   PAYG usage, product-line and add-on lines — they all share
//!   [`crate::invoices::create_invoice_in_tx`]).
//! * **Credit notes do not carry a tax component.** A credit note reduces
//!   reported sales (attributed through the credited invoice's state
//!   snapshot); the report exposes the reduction explicitly instead of
//!   inventing a tax adjustment.

use std::collections::BTreeMap;

use chrono::{DateTime, Datelike, Months, NaiveDate, TimeZone, Utc};
use sqlx::PgPool;
use tracing::{debug, info, warn};

use crate::AppState;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Environment override for the rate/threshold data file path. Unset (the
/// default) reads the committed file embedded in this binary.
pub const US_TAX_DATA_FILE_ENV: &str = "US_TAX_DATA_FILE";

/// Environment override for the maximum age (days) of a rate row's
/// `retrieved` date. Older rows refuse to compute.
pub const US_TAX_MAX_AGE_DAYS_ENV: &str = "US_TAX_MAX_AGE_DAYS";

/// Environment override for the early-warning fraction of a state's nexus
/// threshold, as a decimal string (`0.8` = warn at 80 % of the threshold).
pub const US_TAX_WARN_FRACTION_ENV: &str = "US_TAX_WARN_FRACTION";

/// Default maximum age of a rate row, in days (plan WP C2). Quarterly
/// refresh: a rate row older than a quarter is not a current fact.
pub const DEFAULT_US_TAX_MAX_AGE_DAYS: u32 = 120;

/// Default early-warning fraction, in basis points of the threshold:
/// 8 000 = 0.8 (warn at 80 % of the threshold).
pub const DEFAULT_US_TAX_WARN_FRACTION_BPS: u32 = 8_000;

/// The schema version this build reads from the data file (v2 adds
/// taxability, the transaction criterion and the optional combined rate).
pub const US_TAX_SCHEMA_VERSION: u32 = 2;

/// Sanity bound for a state rate: 20 % in basis points. Above this the row
/// is a unit mistake (e.g. a percent written as basis points), not a rate.
pub const MAX_RATE_BPS: u32 = 2_000;

/// Sanity bounds for an economic-nexus threshold in USD cents: $1 to $100M.
pub const MIN_NEXUS_THRESHOLD_CENTS: i64 = 100;
pub const MAX_NEXUS_THRESHOLD_CENTS: i64 = 10_000_000_000;

/// Sanity bounds for an economic-nexus TRANSACTION threshold: 1 to one
/// million transactions (statutes run in the hundreds; a larger figure is a
/// unit mistake).
pub const MIN_NEXUS_THRESHOLD_TRANSACTIONS: i64 = 1;
pub const MAX_NEXUS_THRESHOLD_TRANSACTIONS: i64 = 1_000_000;

/// `finance_incidents.kind` of the threshold-crossing alert.
pub const NEXUS_ALERT_KIND: &str = "us_sales_tax_nexus_threshold";

/// `finance_incidents.kind` of the early-warning alert (raised once per
/// window at `US_TAX_WARN_FRACTION` of the threshold).
pub const NEXUS_WARNING_KIND: &str = "us_sales_tax_nexus_warning";

/// Version tag of the invoice provenance snapshot (v2 adds `rateKind`/
/// `stateRateBps`/`combinedRateBps` and the exemption record).
pub const US_SALES_TAX_SNAPSHOT_VERSION: u32 = 2;

/// Longest certificate id accepted from the operator surface.
pub const MAX_CERTIFICATE_ID_CHARS: usize = 200;

/// The ISO country code that selects the US tax path.
pub const US_COUNTRY_CODE: &str = "US";

/// The two-letter codes this module recognises in billing addresses and in
/// the data file: the 50 states, DC, and the inhabited territories. A code
/// outside this list in an invoice address counts as UNKNOWN (reported,
/// never assigned); inside the data file it is a validation error.
pub const US_STATE_CODES: &[&str; 56] = &[
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "DC", "FL", "GA", "HI", "ID", "IL", "IN", "IA",
    "KS", "KY", "LA", "ME", "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ", "NM",
    "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA",
    "WV", "WI", "WY", "AS", "GU", "MP", "PR", "VI",
];

/// Whether `code` is a recognised US state/territory postal code.
pub fn is_us_state_code(code: &str) -> bool {
    US_STATE_CODES.contains(&code)
}

/// Normalize a free-text `billing_addresses.state` value to a postal code:
/// trimmed, upper-cased, and ONLY when that yields a recognised code. Any
/// other text (`"California"`, `"N/A"`, empty) is `None` — an unrecognised
/// state is never guessed into a code.
pub fn normalize_state_code(raw: Option<&str>) -> Option<String> {
    let normalized = raw?.trim().to_ascii_uppercase();
    if is_us_state_code(&normalized) {
        Some(normalized)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Data file: shape, parse, validate
// ---------------------------------------------------------------------------

/// The nexus measurement window a state's statute uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NexusWindow {
    /// The calendar year (Jan 1 00:00:00 UTC of the evaluation year, to the
    /// next Jan 1). A new calendar year is a NEW window: a crossing alerts
    /// at most once per year, and a crossed state that is below again in the
    /// new year returns to `below`.
    CalendarYear,
    /// The trailing twelve months ending at the evaluation instant. A
    /// rolling window has no "new window" — a crossing stays sticky until
    /// the operator acts.
    Trailing12Months,
}

impl NexusWindow {
    /// The stored spelling (data file + `us_tax_nexus_states.nexus_window`).
    pub fn as_str(self) -> &'static str {
        match self {
            NexusWindow::CalendarYear => "calendar",
            NexusWindow::Trailing12Months => "trailing_12m",
        }
    }

    /// Parse the stored spelling.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "calendar" => Some(NexusWindow::CalendarYear),
            "trailing_12m" => Some(NexusWindow::Trailing12Months),
            _ => None,
        }
    }

    /// The `[start, end)` bounds of this window at `now`.
    pub fn bounds(self, now: DateTime<Utc>) -> (DateTime<Utc>, DateTime<Utc>) {
        match self {
            NexusWindow::CalendarYear => {
                let start = Utc
                    .with_ymd_and_hms(now.year(), 1, 1, 0, 0, 0)
                    .single()
                    .expect("Jan 1 00:00:00 UTC is unambiguous");
                let end = Utc
                    .with_ymd_and_hms(now.year() + 1, 1, 1, 0, 0, 0)
                    .single()
                    .expect("Jan 1 00:00:00 UTC is unambiguous");
                (start, end)
            }
            NexusWindow::Trailing12Months => {
                let start = now.checked_sub_months(Months::new(12)).unwrap_or(now);
                (start, now)
            }
        }
    }
}

/// Whether the product (the email-sending service) is taxable in a state.
///
/// An absent or unrecognised value resolves to [`Taxability::NotTaxable`]:
/// over-collecting where the product is exempt is the harmful direction, so
/// the safe default is never to charge. A `Taxable` row REQUIRES a rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Taxability {
    Taxable,
    NotTaxable,
}

impl Taxability {
    /// The stored spelling (data file + admin payloads).
    pub fn as_str(self) -> &'static str {
        match self {
            Taxability::Taxable => "taxable",
            Taxability::NotTaxable => "not_taxable",
        }
    }

    /// Resolve a raw file value: absent or anything that is not exactly
    /// `"taxable"` (trimmed, case-insensitively) is `NotTaxable` — the safe
    /// direction. The caller records the notice for `--check`/the admin read
    /// when the raw value was present but unrecognised, so the fallback is
    /// reported, never silent.
    pub fn resolve(raw: Option<&str>) -> (Self, Option<String>) {
        match raw {
            None => (Taxability::NotTaxable, None),
            Some(value) => {
                let trimmed = value.trim();
                if trimmed.eq_ignore_ascii_case("taxable") {
                    (Taxability::Taxable, None)
                } else if trimmed.eq_ignore_ascii_case("not_taxable") {
                    (Taxability::NotTaxable, None)
                } else {
                    (
                        Taxability::NotTaxable,
                        Some(format!(
                            "taxability {value:?} is not \"taxable\" or \"not_taxable\" — treated \
                             as not_taxable (never silently charge)"
                        )),
                    )
                }
            }
        }
    }
}

/// Which statutory nexus test(s) a state's row declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NexusCriteria {
    /// The gross-sales test only.
    Sales,
    /// The transaction-count test only.
    Transactions,
    /// Both, whichever is reached first.
    Either,
}

impl NexusCriteria {
    pub fn as_str(self) -> &'static str {
        match self {
            NexusCriteria::Sales => "sales",
            NexusCriteria::Transactions => "transactions",
            NexusCriteria::Either => "either",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "sales" => Some(NexusCriteria::Sales),
            "transactions" => Some(NexusCriteria::Transactions),
            "either" => Some(NexusCriteria::Either),
            _ => None,
        }
    }
}

/// Which rate of a row is used for computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateKind {
    /// The state-level rate (`rateBps`).
    State,
    /// The home-rule combined rate (`combinedRateBps`), which carries its own
    /// source + retrieved stamp and is preferred when present.
    Combined,
}

impl RateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RateKind::State => "state",
            RateKind::Combined => "combined",
        }
    }
}

/// The rate a row actually computes with, plus its own stamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveRate<'a> {
    pub rate_bps: u32,
    pub kind: RateKind,
    pub source_url: &'a str,
    pub retrieved: NaiveDate,
}

/// The resolved nexus declaration: exactly what the sweep compares and
/// alerts on. [`UsTaxStateRow::nexus_declaration`] returns the named data
/// error instead when the row declares a criterion whose threshold (or
/// window) is missing — the state is then refused, never evaluated against a
/// guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NexusDeclaration {
    pub criteria: NexusCriteria,
    pub sales_threshold_cents: Option<i64>,
    pub transaction_threshold: Option<i64>,
    pub window: NexusWindow,
}

/// One validated data-file row: a state's taxability, its rate (with an
/// optional combined rate), its economic-nexus criteria and their provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsTaxStateRow {
    /// Two-letter state code (upper-case, validated).
    pub state: String,
    /// Whether the product is taxable in the state (absent/invalid →
    /// `not_taxable`).
    pub taxability: Taxability,
    /// Notice when `taxability` was present but unrecognised (reported by
    /// `--check`/the admin read; the resolution is `not_taxable`).
    pub taxability_notice: Option<String>,
    /// Notice when a not_taxable row carries rate/threshold figures that are
    /// never used (reported, never silently dead).
    pub unused_figures_notice: Option<String>,
    /// State-level rate in basis points (725 = 7.25 %); REQUIRED iff taxable.
    pub rate_bps: Option<u32>,
    /// Optional home-rule combined rate in basis points, with its own stamp.
    pub combined_rate_bps: Option<u32>,
    pub combined_source_url: Option<String>,
    pub combined_retrieved: Option<NaiveDate>,
    /// The gross-sales nexus threshold in USD cents (declared or absent).
    pub nexus_threshold_cents: Option<i64>,
    /// The transaction-count nexus threshold (declared or absent).
    pub transaction_threshold: Option<i64>,
    /// The raw criteria spelling from the file (`None` = absent → `sales`).
    pub criteria_raw: Option<String>,
    /// The window thresholds are measured over; `None` when the row declares
    /// no thresholds (a `not_taxable` row).
    pub nexus_window: Option<NexusWindow>,
    /// The state's own page for the figures (https, non-empty).
    pub source_url: String,
    /// The date the figures were read from that page.
    pub retrieved: NaiveDate,
    /// Free-text caveats (what is NOT modelled), optional.
    pub notes: Option<String>,
}

impl UsTaxStateRow {
    /// The rate this row computes with: the combined rate when present (with
    /// its own stamp), else the state rate. `None` when the row computes no
    /// tax at all — a `not_taxable` row, whose (possibly present) figures are
    /// dead data reported by the notices.
    pub fn effective_rate(&self) -> Option<EffectiveRate<'_>> {
        if self.taxability == Taxability::NotTaxable {
            return None;
        }
        match (self.combined_rate_bps, self.rate_bps) {
            (Some(combined), _) => Some(EffectiveRate {
                rate_bps: combined,
                kind: RateKind::Combined,
                source_url: self
                    .combined_source_url
                    .as_deref()
                    .expect("a combined rate always carries its source (validated at parse)"),
                retrieved: self
                    .combined_retrieved
                    .expect("a combined rate always carries its retrieved date (validated)"),
            }),
            (None, Some(state)) => Some(EffectiveRate {
                rate_bps: state,
                kind: RateKind::State,
                source_url: &self.source_url,
                retrieved: self.retrieved,
            }),
            (None, None) => None,
        }
    }

    /// Resolve the row's nexus declaration.
    ///
    /// * `not_taxable` rows declare nothing — `Ok(None)`: the sweep skips
    ///   them (never asked to register) and no threshold exists to compare.
    /// * A usable declaration names exactly the declared criterion's
    ///   thresholds: `sales` needs `nexusThresholdCents`, `transactions`
    ///   needs `transactionThreshold`, `either` needs BOTH; a declared
    ///   criterion whose threshold is missing — or thresholds without a
    ///   declared window — is the named data error the sweep reports while
    ///   refusing to evaluate the state (never a guess).
    pub fn nexus_declaration(&self) -> Result<Option<NexusDeclaration>, String> {
        if self.taxability == Taxability::NotTaxable {
            return Ok(None);
        }
        let criteria = match self.criteria_raw.as_deref().map(str::trim) {
            None => NexusCriteria::Sales,
            Some(raw) => NexusCriteria::parse(raw).ok_or_else(|| {
                format!(
                    "criteria {raw:?} is not \"sales\", \"transactions\" or \"either\" — refusing \
                     to evaluate the state against a guessed criterion"
                )
            })?,
        };
        let sales = self.nexus_threshold_cents;
        let transactions = self.transaction_threshold;
        match (criteria, sales, transactions) {
            (NexusCriteria::Sales, None, _) => Err(
                "criteria \"sales\" declares no nexusThresholdCents — a row declaring a \
                 criterion whose threshold is missing is a data error"
                    .to_string(),
            ),
            (NexusCriteria::Sales, Some(_), Some(_)) => Err(
                "criteria \"sales\" also carries a transactionThreshold — declare criteria \
                 \"either\" to evaluate both, or drop the unused threshold"
                    .to_string(),
            ),
            (NexusCriteria::Transactions, _, None) => Err(
                "criteria \"transactions\" declares no transactionThreshold — a row declaring a \
                 criterion whose threshold is missing is a data error"
                    .to_string(),
            ),
            (NexusCriteria::Transactions, Some(_), Some(_)) => Err(
                "criteria \"transactions\" also carries a nexusThresholdCents — declare criteria \
                 \"either\" to evaluate both, or drop the unused threshold"
                    .to_string(),
            ),
            (NexusCriteria::Either, None, _) | (NexusCriteria::Either, _, None) => Err(
                "criteria \"either\" requires BOTH nexusThresholdCents and transactionThreshold \
                 — a row declaring a criterion whose threshold is missing is a data error"
                    .to_string(),
            ),
            (_, Some(_), _) | (_, _, Some(_)) => match self.nexus_window {
                Some(window) => Ok(Some(NexusDeclaration {
                    criteria,
                    sales_threshold_cents: sales,
                    transaction_threshold: transactions,
                    window,
                })),
                None => Err(
                    "the row declares nexus thresholds but no nexusWindow — refusing to \
                     evaluate the state against a guessed measurement window"
                        .to_string(),
                ),
            },
        }
    }
}

/// Parse/validation failures of the data file. Every variant names the
/// problem so `--check` is actionable.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UsTaxDataError {
    #[error("US sales tax data file is not valid JSON: {0}")]
    MalformedJson(String),
    #[error(
        "US sales tax data file declares schemaVersion {found}; this build reads {expected} \
         (upgrade the file or the build — never guess a version)"
    )]
    UnsupportedSchemaVersion { found: u32, expected: u32 },
    #[error("US sales tax data file row {index}: {problem}")]
    InvalidRow { index: usize, problem: String },
    #[error("US sales tax data file cannot be read ({path}): {reason}")]
    Unreadable { path: String, reason: String },
}

/// The validated rate/threshold table. Empty is valid (nothing to compute)
/// and is exactly what the committed file ships as.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UsTaxTable {
    /// Rows sorted by state code.
    rows: Vec<UsTaxStateRow>,
}

/// The raw data-file shape (strict: an unknown field is a typo, not a
/// silently ignored setting).
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UsTaxDataFile {
    schema_version: u32,
    #[serde(default)]
    instructions: Vec<String>,
    states: Vec<RawUsTaxStateRow>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawUsTaxStateRow {
    state: String,
    #[serde(default)]
    taxability: Option<String>,
    #[serde(default)]
    rate_bps: Option<u32>,
    #[serde(default)]
    combined_rate_bps: Option<u32>,
    #[serde(default)]
    combined_source_url: Option<String>,
    #[serde(default)]
    combined_retrieved: Option<String>,
    #[serde(default)]
    nexus_threshold_cents: Option<i64>,
    #[serde(default)]
    transaction_threshold: Option<i64>,
    #[serde(default)]
    criteria: Option<String>,
    #[serde(default)]
    nexus_window: Option<String>,
    source_url: String,
    retrieved: String,
    #[serde(default)]
    notes: Option<String>,
}

impl UsTaxTable {
    /// Parse and validate a data-file body.
    ///
    /// `today` is the validation clock: a `retrieved` date in the future is
    /// not a date a figure could have been read on and is rejected (a
    /// bad clock or a fabricated date must not become a fresh row).
    pub fn parse(json: &str, today: NaiveDate) -> Result<Self, UsTaxDataError> {
        Self::parse_with_instructions(json, today).map(|(table, _)| table)
    }

    /// Parse and validate, also returning the file's owner instructions
    /// (rendered by `--check` when nothing is configured yet, so the fill-in
    /// contract travels with the file).
    fn parse_with_instructions(
        json: &str,
        today: NaiveDate,
    ) -> Result<(Self, Vec<String>), UsTaxDataError> {
        let raw: UsTaxDataFile = serde_json::from_str(json)
            .map_err(|error| UsTaxDataError::MalformedJson(error.to_string()))?;
        if raw.schema_version != US_TAX_SCHEMA_VERSION {
            return Err(UsTaxDataError::UnsupportedSchemaVersion {
                found: raw.schema_version,
                expected: US_TAX_SCHEMA_VERSION,
            });
        }

        let mut rows: Vec<UsTaxStateRow> = Vec::with_capacity(raw.states.len());
        for (index, raw_row) in raw.states.into_iter().enumerate() {
            // A helper closure keeps every refusal naming its row.
            let invalid = |problem: String| UsTaxDataError::InvalidRow { index, problem };

            let state = raw_row.state.trim().to_ascii_uppercase();
            if state.len() != 2 || !state.chars().all(|c| c.is_ascii_alphabetic()) {
                return Err(invalid(format!(
                    "state {:?} is not a two-letter code",
                    raw_row.state
                )));
            }
            if !is_us_state_code(&state) {
                return Err(invalid(format!(
                    "state {state} is not a known US state/territory postal code"
                )));
            }
            if rows.iter().any(|row| row.state == state) {
                return Err(invalid(format!("state {state} appears more than once")));
            }

            let (taxability, taxability_notice) =
                Taxability::resolve(raw_row.taxability.as_deref());

            if let Some(rate_bps) = raw_row.rate_bps {
                if rate_bps > MAX_RATE_BPS {
                    return Err(invalid(format!(
                        "rateBps {rate_bps} is out of range (0..={MAX_RATE_BPS} basis points \
                         = 20 %) — basis points, not percent"
                    )));
                }
            }
            if let Some(combined_rate_bps) = raw_row.combined_rate_bps {
                if combined_rate_bps > MAX_RATE_BPS {
                    return Err(invalid(format!(
                        "combinedRateBps {combined_rate_bps} is out of range \
                         (0..={MAX_RATE_BPS} basis points = 20 %) — basis points, not percent"
                    )));
                }
            }
            if let Some(threshold) = raw_row.nexus_threshold_cents {
                if !(MIN_NEXUS_THRESHOLD_CENTS..=MAX_NEXUS_THRESHOLD_CENTS).contains(&threshold) {
                    return Err(invalid(format!(
                        "nexusThresholdCents {threshold} is out of range ({}..={} USD cents \
                         = $1..$100M) — cents, not dollars",
                        MIN_NEXUS_THRESHOLD_CENTS, MAX_NEXUS_THRESHOLD_CENTS
                    )));
                }
            }
            if let Some(threshold) = raw_row.transaction_threshold {
                if !(MIN_NEXUS_THRESHOLD_TRANSACTIONS..=MAX_NEXUS_THRESHOLD_TRANSACTIONS)
                    .contains(&threshold)
                {
                    return Err(invalid(format!(
                        "transactionThreshold {threshold} is out of range ({}..={} transactions)",
                        MIN_NEXUS_THRESHOLD_TRANSACTIONS, MAX_NEXUS_THRESHOLD_TRANSACTIONS
                    )));
                }
            }
            let nexus_window = match raw_row.nexus_window.as_deref().map(str::trim) {
                None => None,
                Some(raw) => Some(NexusWindow::parse(raw).ok_or_else(|| {
                    invalid(format!(
                        "nexusWindow {raw:?} must be \"calendar\" or \"trailing_12m\""
                    ))
                })?),
            };

            // A `taxable` row REQUIRES a rate: without one nothing could be
            // charged, so the row could never do its job.
            if taxability == Taxability::Taxable
                && raw_row.rate_bps.is_none()
                && raw_row.combined_rate_bps.is_none()
            {
                return Err(invalid(
                    "taxability \"taxable\" REQUIRES rateBps (or combinedRateBps) — a taxable row \
                     without a rate is not usable"
                        .to_string(),
                ));
            }
            // A `not_taxable` row carrying rates/thresholds is never charged
            // and never asked to register, so those figures are dead data —
            // reported loudly as a notice (never a silent contradiction,
            // never a reason to block the rest of the file: the safe
            // direction is not collecting, not refusing everything).
            let unused_figures_notice = (taxability == Taxability::NotTaxable
                && (raw_row.rate_bps.is_some()
                    || raw_row.combined_rate_bps.is_some()
                    || raw_row.nexus_threshold_cents.is_some()
                    || raw_row.transaction_threshold.is_some()))
            .then(|| {
                "the row resolves to not_taxable: its rate/threshold figures are NOT used (the \
                 state is never charged, never asked to register) — declare taxability \
                 \"taxable\" to collect"
                    .to_string()
            });

            // A combined rate is a total rate with its own provenance:
            // all three fields or none, so it can never be used without the
            // stamp of where (and when) the figure was read.
            let combined_source_url = raw_row
                .combined_source_url
                .map(|source| source.trim().to_string());
            let combined_retrieved = match raw_row.combined_retrieved.as_deref() {
                None => None,
                Some(raw) => {
                    let parsed =
                        NaiveDate::parse_from_str(raw.trim(), "%Y-%m-%d").map_err(|error| {
                            invalid(format!(
                                "combinedRetrieved {raw:?} is not a YYYY-MM-DD date: {error}"
                            ))
                        })?;
                    if parsed > today {
                        return Err(invalid(format!(
                            "combinedRetrieved {parsed} is in the future (today is {today}) — \
                             a rate cannot be fetched on a date that has not happened"
                        )));
                    }
                    Some(parsed)
                }
            };
            match (
                raw_row.combined_rate_bps,
                combined_source_url.as_deref(),
                combined_retrieved,
            ) {
                (None, None, None) => {}
                (Some(_), Some(source), Some(_)) => {
                    if source.is_empty() {
                        return Err(invalid(
                            "combinedSourceUrl is empty — a combined rate without its source is \
                             not usable"
                                .to_string(),
                        ));
                    }
                    if !source.starts_with("https://") {
                        return Err(invalid(format!(
                            "combinedSourceUrl {source:?} must be an https:// URL"
                        )));
                    }
                }
                _ => {
                    return Err(invalid(
                        "combinedRateBps requires combinedSourceUrl AND combinedRetrieved (all \
                         three or none) — a combined rate without its own stamp is not usable"
                            .to_string(),
                    ));
                }
            }

            let source_url = raw_row.source_url.trim().to_string();
            if source_url.is_empty() {
                return Err(invalid(
                    "sourceUrl is empty — a rate without its source is not usable".to_string(),
                ));
            }
            if !source_url.starts_with("https://") {
                return Err(invalid(format!(
                    "sourceUrl {source_url:?} must be an https:// URL"
                )));
            }
            let retrieved = NaiveDate::parse_from_str(raw_row.retrieved.trim(), "%Y-%m-%d")
                .map_err(|error| {
                    invalid(format!(
                        "retrieved {:?} is not a YYYY-MM-DD date: {error}",
                        raw_row.retrieved
                    ))
                })?;
            if retrieved > today {
                return Err(invalid(format!(
                    "retrieved {retrieved} is in the future (today is {today}) — a rate cannot be \
                     fetched on a date that has not happened"
                )));
            }
            rows.push(UsTaxStateRow {
                state,
                taxability,
                taxability_notice,
                unused_figures_notice,
                rate_bps: raw_row.rate_bps,
                combined_rate_bps: raw_row.combined_rate_bps,
                combined_source_url,
                combined_retrieved,
                nexus_threshold_cents: raw_row.nexus_threshold_cents,
                transaction_threshold: raw_row.transaction_threshold,
                criteria_raw: raw_row.criteria,
                nexus_window,
                source_url,
                retrieved,
                notes: raw_row.notes.filter(|note| !note.trim().is_empty()),
            });
        }

        rows.sort_by(|a, b| a.state.cmp(&b.state));
        Ok((UsTaxTable { rows }, raw.instructions))
    }

    /// The validated rows, sorted by state code.
    pub fn rows(&self) -> &[UsTaxStateRow] {
        &self.rows
    }

    /// How many states the table carries.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the table carries no states (the committed default).
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// The row for `state` (upper-case two-letter code), if any.
    pub fn row(&self, state: &str) -> Option<&UsTaxStateRow> {
        let state = state.trim().to_ascii_uppercase();
        self.rows.iter().find(|row| row.state == state)
    }
}

/// Days between a `retrieved` date and the evaluation date. Negative when the
/// date is in the future (only reachable when the validation clock moved
/// backwards since the load — treated as stale, never as fresh).
pub fn stamp_age_days(retrieved: NaiveDate, today: NaiveDate) -> i64 {
    (today - retrieved).num_days()
}

/// The stamp a row's figures are governed by: the rate actually used (the
/// combined rate's own stamp when present, else the state rate's) — or the
/// row's own `retrieved` date when no rate governs it (a `not_taxable` claim
/// is still a dated fact; dead figures on such a row are never used).
pub fn row_stamp_retrieved(row: &UsTaxStateRow) -> NaiveDate {
    if row.taxability == Taxability::NotTaxable {
        return row.retrieved;
    }
    row.effective_rate()
        .map(|rate| rate.retrieved)
        .unwrap_or(row.retrieved)
}

/// Days between a row's used stamp and the evaluation date.
pub fn row_age_days(row: &UsTaxStateRow, today: NaiveDate) -> i64 {
    stamp_age_days(row_stamp_retrieved(row), today)
}

/// Whether a row is fresh at `today` under `max_age_days` — the SAME rule
/// for the state rate and a combined rate: the stamp of the figure that will
/// be used governs (a stale stamp, whichever it is, refuses to compute).
pub fn is_row_fresh(row: &UsTaxStateRow, today: NaiveDate, max_age_days: u32) -> bool {
    let age = row_age_days(row, today);
    age >= 0 && age <= i64::from(max_age_days)
}

// ---------------------------------------------------------------------------
// Errors of the compute path
// ---------------------------------------------------------------------------

/// Failures of the US tax computation. Every variant is a REFUSAL — there is
/// deliberately no variant that yields a guessed tax amount.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UsTaxError {
    #[error("US sales tax data file unusable: {0}")]
    DataFile(#[from] UsTaxDataError),
    #[error(
        "US sales tax: state {state} is registered but the data file has NO rate row for it — \
         refusing to compute tax; add the state's rateBps/threshold/source/retrieved row"
    )]
    MissingRateRow { state: String },
    #[error(
        "US sales tax: state {state} rate row is STALE — read {retrieved}, {age_days} days old \
         at evaluation (max {max_age_days}, {env}=...); refusing to compute tax from a stale \
         rate. Refresh the row's figures and `retrieved` date from {rate_source}"
    )]
    StaleRateRow {
        state: String,
        retrieved: NaiveDate,
        age_days: i64,
        max_age_days: u32,
        env: &'static str,
        rate_source: String,
    },
    #[error(
        "US sales tax: {env}={raw:?} is not a whole number of days — refusing to guess the \
         maximum rate age"
    )]
    InvalidMaxAge { raw: String, env: &'static str },
    #[error(
        "US sales tax: the registration/exemption lookup for state {state} failed ({reason}) — \
         refusing to guess whether the state is registered or the sale exempt"
    )]
    RegistrationLookup { state: String, reason: String },
    #[error(
        "US sales tax: state {state} is not taxable for this product per the data file — a \
         not_taxable state is never registered and never charged; if the law changed, update the \
         row's taxability (with a fresh source/retrieved) first"
    )]
    NotTaxableState { state: String },
    #[error(
        "US sales tax: state {state}'s nexus declaration is a data error ({reason}) — refusing to \
         evaluate it against a guessed criterion or threshold"
    )]
    IncompleteNexusDeclaration { state: String, reason: String },
    #[error(
        "US sales tax: {env}={raw:?} is not a fraction between 0 and 1 (e.g. \"0.8\") — refusing \
         to guess the early-warning threshold"
    )]
    InvalidWarnFraction { raw: String, env: &'static str },
}

// ---------------------------------------------------------------------------
// Computation (pure, integer basis points)
// ---------------------------------------------------------------------------

/// Sales tax on one taxable amount: `base × bps / 10_000`, rounded half-up
/// ONCE (the VAT module's convention — see `billing_common`'s
/// `vat_amount_half_up`). Exact i128 intermediate; a negative base saturates
/// to zero tax (no credit is ever minted here).
pub fn sales_tax_cents(base_cents: i64, rate_bps: u32) -> i64 {
    let base = i128::from(base_cents.max(0));
    let rate = i128::from(rate_bps);
    // Half-up: add half the denominator before the exact division.
    let tax = (base * rate + 5_000) / 10_000;
    i64::try_from(tax).unwrap_or(i64::MAX)
}

/// The nexus verdict for one window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NexusVerdict {
    /// Observed taxable sales are below the threshold.
    Below,
    /// Observed taxable sales reached or exceeded the threshold (the
    /// statutory test: threshold − 1 cent is below, exactly the threshold
    /// is over).
    Crossed,
}

impl NexusVerdict {
    pub fn is_crossed(self) -> bool {
        matches!(self, NexusVerdict::Crossed)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            NexusVerdict::Below => "below",
            NexusVerdict::Crossed => "threshold_crossed",
        }
    }
}

/// Compare observed taxable sales against a threshold. Pure: the boundary
/// semantics ("meets or exceeds") live here and are pinned by tests.
pub fn evaluate_nexus(observed_cents: i64, threshold_cents: i64) -> NexusVerdict {
    if observed_cents >= threshold_cents {
        NexusVerdict::Crossed
    } else {
        NexusVerdict::Below
    }
}

// ---------------------------------------------------------------------------
// Data file loading (embedded default, operator override)
// ---------------------------------------------------------------------------

/// The committed default table, embedded at build time.
pub fn embedded_data_file() -> &'static str {
    include_str!("../data/us_sales_tax.json")
}

/// Resolve the data-file body: an operator-set `US_TAX_DATA_FILE` path when
/// present, else the embedded committed file. Returns `(source label, body)`.
pub fn data_file_source() -> Result<(String, String), UsTaxDataError> {
    match std::env::var(US_TAX_DATA_FILE_ENV) {
        Ok(path) if !path.trim().is_empty() => {
            let path = path.trim().to_string();
            let body =
                std::fs::read_to_string(&path).map_err(|error| UsTaxDataError::Unreadable {
                    path: path.clone(),
                    reason: error.to_string(),
                })?;
            Ok((path, body))
        }
        _ => Ok((
            "<embedded data/us_sales_tax.json>".to_string(),
            embedded_data_file().to_string(),
        )),
    }
}

/// The maximum age (days) a used rate row may have. Unset → the default;
/// set but unparseable → a named refusal (never a silent default).
pub fn max_age_days_from_env() -> Result<u32, UsTaxError> {
    match std::env::var(US_TAX_MAX_AGE_DAYS_ENV) {
        Ok(raw) if !raw.trim().is_empty() => {
            raw.trim()
                .parse::<u32>()
                .map_err(|_| UsTaxError::InvalidMaxAge {
                    raw: raw.trim().to_string(),
                    env: US_TAX_MAX_AGE_DAYS_ENV,
                })
        }
        _ => Ok(DEFAULT_US_TAX_MAX_AGE_DAYS),
    }
}

/// Parse a warning fraction like `0.8` into basis points of the threshold
/// (`8000`), in integer arithmetic only (no float ever touches a money path
/// in this file). Accepts `1`, `0.8`, `0.85`, `0.5`, …; rejects `0`, values
/// above 1, more than four decimal digits, and anything else — a refusal,
/// never a silent default.
pub fn parse_warn_fraction_bps(raw: &str) -> Option<u32> {
    let trimmed = raw.trim();
    let (whole, fraction_digits) = match trimmed.split_once('.') {
        None => (trimmed, ""),
        Some((whole, fraction)) => (whole, fraction),
    };
    if whole != "0" && whole != "1" {
        return None;
    }
    if fraction_digits.is_empty() && !trimmed.contains('.') {
        // A bare integer: only 1 is a valid fraction (1.0 = the crossing).
        return (whole == "1").then_some(10_000);
    }
    if fraction_digits.is_empty() || fraction_digits.len() > 4 {
        return None;
    }
    if !fraction_digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let fraction: u32 = fraction_digits.parse().ok()?;
    let scale = 10_u32.pow(4 - fraction_digits.len() as u32);
    let bps = if whole == "1" {
        // "1.x" is above 1 unless every fractional digit is zero.
        if fraction != 0 {
            return None;
        }
        10_000
    } else {
        fraction.saturating_mul(scale)
    };
    (1..=10_000).contains(&bps).then_some(bps)
}

/// The early-warning fraction from `US_TAX_WARN_FRACTION`. Unset → the
/// default (0.8); set but not a fraction → a named refusal.
pub fn warn_fraction_bps_from_env() -> Result<u32, UsTaxError> {
    match std::env::var(US_TAX_WARN_FRACTION_ENV) {
        Ok(raw) if !raw.trim().is_empty() => {
            parse_warn_fraction_bps(&raw).ok_or_else(|| UsTaxError::InvalidWarnFraction {
                raw: raw.trim().to_string(),
                env: US_TAX_WARN_FRACTION_ENV,
            })
        }
        _ => Ok(DEFAULT_US_TAX_WARN_FRACTION_BPS),
    }
}

/// The compute configuration: the validated table, where it came from, how
/// old a used row may be, and where the early warning fires.
#[derive(Debug, Clone)]
pub struct UsTaxConfig {
    pub table: UsTaxTable,
    pub source: String,
    pub max_age_days: u32,
    /// The early-warning fraction in basis points of the threshold
    /// (`8000` = 0.8 = warn at 80 %).
    pub warn_fraction_bps: u32,
}

impl UsTaxConfig {
    /// Load from the environment (embedded file unless `US_TAX_DATA_FILE`
    /// points elsewhere) and validate. Every failure is named.
    pub fn from_env(today: NaiveDate) -> Result<Self, UsTaxError> {
        #[cfg(test)]
        if let Some(config) = test_table_override() {
            return Ok(config);
        }
        let (source, body) = data_file_source()?;
        let table = UsTaxTable::parse(&body, today)?;
        let max_age_days = max_age_days_from_env()?;
        let warn_fraction_bps = warn_fraction_bps_from_env()?;
        Ok(UsTaxConfig {
            table,
            source,
            max_age_days,
            warn_fraction_bps,
        })
    }

    /// For tests and ops reporting: the row for `state`, or the named
    /// refusal if it is missing or stale. "Stale" means the stamp of the
    /// rate that will be USED (the combined rate's own stamp when present,
    /// else the state rate's).
    pub fn fresh_row(&self, state: &str, today: NaiveDate) -> Result<&UsTaxStateRow, UsTaxError> {
        let Some(row) = self.table.row(state) else {
            return Err(UsTaxError::MissingRateRow {
                state: state.trim().to_ascii_uppercase(),
            });
        };
        if !is_row_fresh(row, today, self.max_age_days) {
            let used = row.effective_rate();
            return Err(UsTaxError::StaleRateRow {
                state: row.state.clone(),
                retrieved: row_stamp_retrieved(row),
                age_days: row_age_days(row, today),
                max_age_days: self.max_age_days,
                env: US_TAX_MAX_AGE_DAYS_ENV,
                rate_source: used
                    .map(|rate| rate.source_url.to_string())
                    .unwrap_or_else(|| row.source_url.clone()),
            });
        }
        Ok(row)
    }
}

/// Test-only table override.
///
/// The money path must be provable end to end, but the rate table comes from
/// a committed file that ships EMPTY on purpose (a committed file with
/// invented rates would be a fabricated claim) and the process environment
/// cannot be mutated safely while the test binary runs in parallel. Tests
/// therefore install their own table here, serialized by [`TEST_TABLE_LOCK`];
/// production code has no such slot (`#[cfg(test)]`).
#[cfg(test)]
pub(crate) static TEST_TABLE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
static TEST_TABLE: std::sync::Mutex<Option<UsTaxConfig>> = std::sync::Mutex::new(None);

#[cfg(test)]
pub(crate) fn test_table_override() -> Option<UsTaxConfig> {
    TEST_TABLE.lock().ok().and_then(|guard| guard.clone())
}

#[cfg(test)]
pub(crate) fn set_test_table(config: Option<UsTaxConfig>) {
    *TEST_TABLE.lock().expect("US tax test table lock") = config;
}

/// The `--check` report over the data file (pure rendering; the caller
/// prints it).
#[derive(Debug, Clone)]
pub struct UsTaxDataCheckReport {
    pub source: String,
    pub max_age_days: u32,
    pub warn_fraction_bps: u32,
    pub today: NaiveDate,
    /// One line per state row: taxability, rate/thresholds, criteria and
    /// freshness at `today`, plus provenance.
    pub rows: Vec<String>,
    /// One line per per-state nexus-declaration data error (a declared
    /// criterion whose threshold/window is missing): the state is refused at
    /// evaluation time; `--check` exits non-zero while any is present.
    pub declaration_errors: Vec<String>,
    /// The file's owner instructions — rendered when the file carries no
    /// state yet, so the fill-in contract is what `--check` prints.
    pub instructions: Vec<String>,
}

impl UsTaxDataCheckReport {
    /// A human-readable multi-line report.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "US sales tax data: {} — {} state row(s), max age {} days, warn fraction {} bps of \
             the threshold, today {}\n",
            self.source,
            self.rows.len(),
            self.max_age_days,
            self.warn_fraction_bps,
            self.today
        ));
        if self.rows.is_empty() {
            out.push_str(
                "  (no states configured — no US sales tax is computed anywhere; fill the file \
                 to enable registered states)\n",
            );
            for line in &self.instructions {
                out.push_str("  | ");
                out.push_str(line);
                out.push('\n');
            }
        }
        for line in &self.rows {
            out.push_str("  ");
            out.push_str(line);
            out.push('\n');
        }
        if !self.declaration_errors.is_empty() {
            out.push_str("DATA ERRORS (the states below are refused at evaluation time):\n");
            for line in &self.declaration_errors {
                out.push_str("  ! ");
                out.push_str(line);
                out.push('\n');
            }
        }
        out
    }
}

/// Validate the configured data file and build the `--check` report.
pub fn check_data_file(today: NaiveDate) -> Result<UsTaxDataCheckReport, UsTaxError> {
    let (source, body) = data_file_source()?;
    let (table, instructions) = UsTaxTable::parse_with_instructions(&body, today)?;
    let max_age_days = max_age_days_from_env()?;
    let warn_fraction_bps = warn_fraction_bps_from_env()?;
    let mut declaration_errors = Vec::new();
    let mut rows = Vec::new();
    for row in table.rows() {
        let age = row_age_days(row, today);
        let freshness = if is_row_fresh(row, today, max_age_days) {
            format!("fresh ({age} days old)")
        } else {
            format!("STALE ({age} days old — will refuse to compute)")
        };
        let rate = row
            .effective_rate()
            .map(|rate| {
                format!(
                    "{} bps {}",
                    rate.rate_bps,
                    if rate.kind == RateKind::Combined {
                        "combined rate"
                    } else {
                        "state rate"
                    }
                )
            })
            .unwrap_or_else(|| "no rate (not_taxable)".to_string());
        let nexus = match row.nexus_declaration() {
            Ok(Some(declaration)) => format!(
                "criteria {} — sales threshold {} USD cents, transaction threshold {} ({})",
                declaration.criteria.as_str(),
                declaration
                    .sales_threshold_cents
                    .map(|threshold| threshold.to_string())
                    .unwrap_or_else(|| "n/a".to_string()),
                declaration
                    .transaction_threshold
                    .map(|threshold| threshold.to_string())
                    .unwrap_or_else(|| "n/a".to_string()),
                declaration.window.as_str()
            ),
            Ok(None) => {
                "nexus n/a (not_taxable — never evaluated, never asked to register)".to_string()
            }
            Err(reason) => {
                declaration_errors.push(format!("{}: {reason}", row.state));
                format!("DATA ERROR: {reason}")
            }
        };
        let mut taxability = row.taxability.as_str().to_string();
        if let Some(notice) = &row.taxability_notice {
            taxability.push_str(&format!(" NOTE: {notice}"));
        }
        if let Some(notice) = &row.unused_figures_notice {
            taxability.push_str(&format!(" NOTE: {notice}"));
        }
        rows.push(format!(
            "{}: {taxability} — {rate} — {nexus} — {freshness} — source {} retrieved {}",
            row.state, row.source_url, row.retrieved
        ));
    }
    Ok(UsTaxDataCheckReport {
        source,
        max_age_days,
        warn_fraction_bps,
        today,
        rows,
        declaration_errors,
        instructions,
    })
}

// ---------------------------------------------------------------------------
// Invoice-side computation
// ---------------------------------------------------------------------------

/// A computed sales-tax line, with the stamp that goes onto the invoice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsSalesTaxLine {
    pub state: String,
    /// The rate actually APPLIED: the combined rate when the row carries one,
    /// else the state rate.
    pub rate_bps: u32,
    /// Which rate that was.
    pub rate_kind: RateKind,
    /// The row's state-level rate (for the snapshot's transparency), when it
    /// has one.
    pub state_rate_bps: Option<u32>,
    /// The row's combined rate, when it has one.
    pub combined_rate_bps: Option<u32>,
    pub amount_cents: i64,
    pub source_url: String,
    pub retrieved: NaiveDate,
}

impl UsSalesTaxLine {
    /// The invoice line description, carrying the whole stamp: state, rate
    /// (and which rate), source and retrieval date. A legal document quoting
    /// a tax line must state what it was computed from.
    pub fn description(&self) -> String {
        // Integer formatting only: 725 bps → "7.25 %" (never a float).
        let percent = format!("{}.{:02} %", self.rate_bps / 100, self.rate_bps % 100);
        let kind = match self.rate_kind {
            RateKind::State => "state rate",
            RateKind::Combined => "combined rate",
        };
        format!(
            "US sales tax ({}) — {} {} — source {} retrieved {}",
            self.state, percent, kind, self.source_url, self.retrieved
        )
    }

    /// The provenance snapshot stored beside the amount
    /// (`invoices.us_sales_tax_snapshot`): which rate was used, both figures
    /// for transparency, and the stamp of the used one.
    pub fn snapshot_json(&self) -> serde_json::Value {
        serde_json::json!({
            "snapshotVersion": US_SALES_TAX_SNAPSHOT_VERSION,
            "state": self.state,
            "rateBps": self.rate_bps,
            "rateKind": self.rate_kind.as_str(),
            "stateRateBps": self.state_rate_bps,
            "combinedRateBps": self.combined_rate_bps,
            "amountCents": self.amount_cents,
            "source": self.source_url,
            "retrieved": self.retrieved.to_string(),
        })
    }
}

/// The exemption record written to an exempt sale's snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsSalesTaxExemption {
    pub state: String,
    pub certificate_id: String,
    /// The certificate's own expiry date; `None` = the certificate states
    /// none (recorded as such).
    pub certificate_expires_at: Option<NaiveDate>,
}

impl UsSalesTaxExemption {
    /// The exemption arm of the provenance snapshot: amount 0 WITH the
    /// substantiation (the certificate), so a zero-tax US invoice can never
    /// be confused with "no US tax context".
    pub fn snapshot_json(&self) -> serde_json::Value {
        serde_json::json!({
            "snapshotVersion": US_SALES_TAX_SNAPSHOT_VERSION,
            "state": self.state,
            "exempt": true,
            "certificateId": self.certificate_id,
            "certificateExpiresAt": self
                .certificate_expires_at
                .map(|date| date.to_string()),
            "amountCents": 0,
        })
    }
}

/// The US sales-tax decision for one invoice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsTaxDecision {
    /// No US tax context: not a US customer, no usable state, the state is
    /// not registered, the product is `not_taxable` there, or the tax rounds
    /// to zero. Nothing is recorded (the snapshot stays NULL).
    None,
    /// An exempt sale under a customer certificate: zero tax, snapshot
    /// recorded.
    Exempt(UsSalesTaxExemption),
    /// A taxed sale: the stamped line.
    Taxed(UsSalesTaxLine),
}

/// The one-round-trip tax context of an invoice's (customer, state): the
/// registration flag plus the applicable exemption certificate (all `None`
/// when none covers the sale; populated together by the lateral join).
#[derive(Debug, sqlx::FromRow)]
struct TaxContextRow {
    registered: bool,
    id: Option<uuid::Uuid>,
    tenant_id: Option<String>,
    state_code: Option<String>,
    certificate_id: Option<String>,
    expires_at: Option<NaiveDate>,
    note: Option<String>,
    created_by: Option<String>,
    updated_at: Option<DateTime<Utc>>,
    created_at: Option<DateTime<Utc>>,
}

impl TaxContextRow {
    /// The exemption row when the lateral join found one; every column is
    /// non-null together by construction, so any `None` means "no exemption".
    fn into_exemption(self) -> Option<UsTaxExemptionRow> {
        Some(UsTaxExemptionRow {
            id: self.id?,
            tenant_id: self.tenant_id?,
            state_code: self.state_code?,
            certificate_id: self.certificate_id?,
            expires_at: self.expires_at,
            note: self.note,
            created_by: self.created_by,
            updated_at: self.updated_at?,
            created_at: self.created_at?,
        })
    }
}

/// Resolve the US sales tax for one invoice.
///
/// The gate, in order — every step is a refusal, never a guess:
/// 1. customer country must be `US` (any other country: untouched);
/// 2. the billing address state must be a recognisable US postal code
///    (unrecognised/missing → nothing: the sweep reports those invoices as
///    UNKNOWN, an invoice never invents a state);
/// 3. the state must be `registered` by the operator (nothing otherwise —
///    the invoice carries the existing behavior);
/// 4. the state's data-file row must exist (a registered state with no row
///    is REFUSED by name: the row is the operator's claim that the state is
///    taxable at all) and must not be `not_taxable` (never charge where the
///    product is exempt — even a legacy registration row charges nothing);
/// 5. a customer exemption certificate covering the state and not expired at
///    the invoice date → an EXEMPT decision (zero tax, the certificate
///    recorded). An expired or absent certificate is taxable;
/// 6. the rate row's USED stamp must be fresh ([`UsTaxError`] otherwise: the
///    invoice is refused, never computed from a missing or stale rate);
/// 7. a tax rounding to 0 cents adds no line (nothing).
///
/// `config` is the caller's table (tests inject one); `None` loads the
/// configured source LAZILY — only after steps 1–3 established that this
/// invoice actually needs a rate, so a broken data file can never refuse a
/// US invoice that would not carry tax anyway.
pub async fn tax_decision_for_invoice<'e, E>(
    executor: E,
    config: Option<&UsTaxConfig>,
    tenant_id: &str,
    country: &str,
    state: Option<&str>,
    subtotal_cents: i64,
    today: NaiveDate,
) -> Result<UsTaxDecision, UsTaxError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    if !country.trim().eq_ignore_ascii_case(US_COUNTRY_CODE) {
        return Ok(UsTaxDecision::None);
    }
    let Some(state) = normalize_state_code(state) else {
        return Ok(UsTaxDecision::None);
    };
    // ONE round trip answers both questions the gate needs: is the state
    // registered, and does a non-expired exemption certificate cover this
    // customer's sale? An infrastructure failure REFUSES the invoice — an
    // unregistered state must not be taxed, a registered one must not escape
    // its tax, and a certificate must never be assumed.
    let context: TaxContextRow = sqlx::query_as(
        "SELECT \
             EXISTS(SELECT 1 FROM us_tax_nexus_states \
                    WHERE state_code = $2 AND status = 'registered') AS registered, \
             evidence.id, evidence.tenant_id, evidence.state_code, evidence.certificate_id, \
             evidence.expires_at, evidence.note, evidence.created_by, evidence.updated_at, \
             evidence.created_at \
         FROM (SELECT 1) AS singleton \
         LEFT JOIN LATERAL ( \
             SELECT id, tenant_id, state_code, certificate_id, expires_at, note, created_by, \
                    updated_at, created_at \
             FROM us_tax_customer_exemptions \
             WHERE tenant_id = $1 AND state_code = $2 \
               AND (expires_at IS NULL OR expires_at >= $3) \
             ORDER BY expires_at DESC NULLS FIRST, created_at DESC, id DESC \
             LIMIT 1 \
         ) AS evidence ON TRUE",
    )
    .bind(tenant_id)
    .bind(&state)
    .bind(today)
    .fetch_one(executor)
    .await
    .map_err(|error| UsTaxError::RegistrationLookup {
        state: state.clone(),
        reason: format!("registration/exemption lookup failed: {error}"),
    })?;
    if !context.registered {
        return Ok(UsTaxDecision::None);
    }

    let loaded;
    let config = match config {
        Some(config) => config,
        None => {
            loaded = UsTaxConfig::from_env(today)?;
            &loaded
        }
    };
    let Some(row) = config.table.row(&state) else {
        // The row is the operator's factual claim that this state charges
        // tax at all — a registered state without one is refused, never
        // guessed (not even an exemption can be applied to a state whose
        // taxability is unknown).
        return Err(UsTaxError::MissingRateRow { state });
    };
    if row.taxability == Taxability::NotTaxable {
        // Never charge where the product is exempt — even when a legacy
        // registration row exists. `--check` and the admin read surface the
        // contradiction for the operator.
        debug!(
            state = %state,
            "US sales tax: state is not_taxable in the data file — no tax line, even registered"
        );
        return Ok(UsTaxDecision::None);
    }

    // A substantiated exemption zeroes the tax BEFORE any rate is needed: an
    // exempt sale computes no tax, so a stale rate row cannot refuse it
    // (that would wrongly refuse a customer who owes nothing).
    if let Some(exemption) = context.into_exemption() {
        return Ok(UsTaxDecision::Exempt(UsSalesTaxExemption {
            state: state.clone(),
            certificate_id: exemption.certificate_id,
            certificate_expires_at: exemption.expires_at,
        }));
    }

    let row = config.fresh_row(&state, today)?;
    let used = row
        .effective_rate()
        .ok_or_else(|| UsTaxError::MissingRateRow {
            state: state.clone(),
        })?;
    let amount_cents = sales_tax_cents(subtotal_cents, used.rate_bps);
    if amount_cents <= 0 {
        debug!(
            state = %state,
            subtotal_cents,
            rate_bps = used.rate_bps,
            "US sales tax rounds to 0 cents — no line added"
        );
        return Ok(UsTaxDecision::None);
    }
    Ok(UsTaxDecision::Taxed(UsSalesTaxLine {
        state: row.state.clone(),
        rate_bps: used.rate_bps,
        rate_kind: used.kind,
        state_rate_bps: row.rate_bps,
        combined_rate_bps: row.combined_rate_bps,
        amount_cents,
        source_url: used.source_url.to_string(),
        retrieved: used.retrieved,
    }))
}

// ---------------------------------------------------------------------------
// Customer exemptions (B2B certificates) — storage and operator surface
// ---------------------------------------------------------------------------

/// One stored exemption certificate row (`us_tax_customer_exemptions`).
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct UsTaxExemptionRow {
    pub id: uuid::Uuid,
    pub tenant_id: String,
    pub state_code: String,
    pub certificate_id: String,
    pub expires_at: Option<NaiveDate>,
    pub note: Option<String>,
    pub created_by: Option<String>,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

const EXEMPTION_COLUMNS: &str = "id, tenant_id, state_code, certificate_id, expires_at, note, \
     created_by, updated_at, created_at";

/// Failures of the exemption surface. Every variant names the problem so the
/// admin route can render it as a validation error.
#[derive(Debug, thiserror::Error)]
pub enum ExemptionError {
    #[error("US sales tax: {0:?} is not a US state/territory postal code")]
    UnknownState(String),
    #[error("US sales tax: {0}")]
    InvalidCertificate(String),
    #[error("US sales tax: {0}")]
    InvalidExpiry(String),
    #[error(
        "US sales tax: tenant {0:?} does not exist — an exemption on a wrong id would \
             exempt nothing; fix the tenant id"
    )]
    UnknownTenant(String),
    #[error("US sales tax: exemption {0} not found")]
    NotFound(uuid::Uuid),
    #[error("US sales tax: {0}")]
    Database(String),
}

/// A certificate to store (`POST` body of the admin surface).
#[derive(Debug, Clone)]
pub struct ExemptionInput {
    pub tenant_id: String,
    pub state: String,
    pub certificate_id: String,
    pub expires_at: Option<NaiveDate>,
    pub note: Option<String>,
}

/// The certificate covering `(tenant, state)` at `as_of`, if any: the
/// latest-expiring non-expired one. An expiry is INCLUSIVE (a certificate
/// valid through its `expires_at` day); `expires_at IS NULL` means the
/// certificate states no expiry date and is valid until replaced or removed.
/// Selection is deterministic (latest expiry first, NULL first — "no
/// expiry" outranks any dated one; then newest created; then id) so the
/// certificate recorded on the snapshot is reproducible.
pub async fn find_applicable_exemption<'e, E>(
    executor: E,
    tenant_id: &str,
    state: &str,
    as_of: NaiveDate,
) -> Result<Option<UsTaxExemptionRow>, String>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query_as(&format!(
        "SELECT {EXEMPTION_COLUMNS} FROM us_tax_customer_exemptions \
         WHERE tenant_id = $1 AND state_code = $2 \
           AND (expires_at IS NULL OR expires_at >= $3) \
         ORDER BY expires_at DESC NULLS FIRST, created_at DESC, id DESC \
         LIMIT 1"
    ))
    .bind(tenant_id)
    .bind(state)
    .bind(as_of)
    .fetch_optional(executor)
    .await
    .map_err(|error| format!("exemption query failed: {error}"))
}

/// Every exemption row, optionally for one tenant (admin read).
pub async fn list_exemptions(
    db: &PgPool,
    tenant_id: Option<&str>,
) -> Result<Vec<UsTaxExemptionRow>, String> {
    let rows = match tenant_id {
        Some(tenant) => {
            sqlx::query_as(&format!(
                "SELECT {EXEMPTION_COLUMNS} FROM us_tax_customer_exemptions \
                 WHERE tenant_id = $1 ORDER BY state_code, certificate_id"
            ))
            .bind(tenant)
            .fetch_all(db)
            .await
        }
        None => {
            sqlx::query_as(&format!(
                "SELECT {EXEMPTION_COLUMNS} FROM us_tax_customer_exemptions \
                 ORDER BY tenant_id, state_code, certificate_id"
            ))
            .fetch_all(db)
            .await
        }
    };
    rows.map_err(|error| format!("US tax exemptions: list failed: {error}"))
}

/// Store (insert or replace) one certificate for `(tenant, state)`.
/// Operator-managed; the admin route audits it.
pub async fn upsert_exemption(
    db: &PgPool,
    input: &ExemptionInput,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<UsTaxExemptionRow, ExemptionError> {
    let state = normalize_state_code(Some(&input.state))
        .ok_or_else(|| ExemptionError::UnknownState(input.state.clone()))?;
    let certificate_id = input.certificate_id.trim().to_string();
    if certificate_id.is_empty() {
        return Err(ExemptionError::InvalidCertificate(
            "certificateId is empty — an exemption without its certificate id is not \
             substantiated"
                .to_string(),
        ));
    }
    if certificate_id.chars().count() > MAX_CERTIFICATE_ID_CHARS {
        return Err(ExemptionError::InvalidCertificate(format!(
            "certificateId is longer than {MAX_CERTIFICATE_ID_CHARS} characters"
        )));
    }
    let note = input
        .note
        .as_deref()
        .map(str::trim)
        .filter(|note| !note.is_empty())
        .map(str::to_string);
    if note
        .as_deref()
        .is_some_and(|note| note.chars().count() > 1_000)
    {
        return Err(ExemptionError::InvalidCertificate(
            "note must be ≤ 1000 characters".to_string(),
        ));
    }
    let tenant_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1)")
            .bind(&input.tenant_id)
            .fetch_one(db)
            .await
            .map_err(|error| ExemptionError::Database(error.to_string()))?;
    if !tenant_exists {
        return Err(ExemptionError::UnknownTenant(input.tenant_id.clone()));
    }

    let row: UsTaxExemptionRow = sqlx::query_as(&format!(
        "INSERT INTO us_tax_customer_exemptions \
             (tenant_id, state_code, certificate_id, expires_at, note, created_by, \
              created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $7) \
         ON CONFLICT (tenant_id, state_code, certificate_id) DO UPDATE SET \
             expires_at = EXCLUDED.expires_at, \
             note = EXCLUDED.note, \
             created_by = EXCLUDED.created_by, \
             updated_at = EXCLUDED.updated_at \
         RETURNING {EXEMPTION_COLUMNS}"
    ))
    .bind(&input.tenant_id)
    .bind(&state)
    .bind(&certificate_id)
    .bind(input.expires_at)
    .bind(&note)
    .bind(actor)
    .bind(now)
    .fetch_one(db)
    .await
    .map_err(|error| ExemptionError::Database(format!("upsert failed: {error}")))?;
    info!(
        tenant_id = %row.tenant_id,
        state = %row.state_code,
        certificate_id = %row.certificate_id,
        expires_at = ?row.expires_at,
        actor,
        "US tax exemption: certificate stored — sales in this state are exempt from now on \
         (issued invoices are never changed)"
    );
    Ok(row)
}

/// Remove one certificate. Returns the removed row (the audit entry records
/// what was removed). Taxability resumes for new invoices immediately.
pub async fn delete_exemption(
    db: &PgPool,
    id: uuid::Uuid,
    actor: &str,
) -> Result<UsTaxExemptionRow, ExemptionError> {
    let row: Option<UsTaxExemptionRow> = sqlx::query_as(&format!(
        "DELETE FROM us_tax_customer_exemptions WHERE id = $1 RETURNING {EXEMPTION_COLUMNS}"
    ))
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(|error| ExemptionError::Database(format!("delete failed: {error}")))?;
    let Some(row) = row else {
        return Err(ExemptionError::NotFound(id));
    };
    info!(
        tenant_id = %row.tenant_id,
        state = %row.state_code,
        certificate_id = %row.certificate_id,
        actor,
        "US tax exemption: certificate removed — new invoices in this state are taxable again"
    );
    Ok(row)
}

// ---------------------------------------------------------------------------
// Nexus sweep
// ---------------------------------------------------------------------------

/// One (state, currency) aggregate of US sales in a window.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UsSalesBucket {
    raw_state: String,
    currency: String,
    invoices: i64,
    taxable_cents: i64,
    /// The portion of `taxable_cents` sold under a customer exemption
    /// certificate (recorded on the invoice's tax snapshot).
    exempt_cents: i64,
}

/// Aggregate US sales by (billing-address state, currency) for invoices
/// issued in `[start, end)`. Gross sales include exempt sales (the common
/// statutory rule measures gross sales / all transactions); the exempt
/// portion is carried separately for reporting. The billing-address state is
/// read from the immutable snapshot (audit F08) as JSON: a snapshot that is
/// not a JSON object yields the empty string (the UNKNOWN bucket) instead of
/// an SQL error — one corrupt row must not blind the whole sweep. The report
/// queries below use the same expression.
const US_SALES_BY_STATE_SQL: &str = r#"
    SELECT
        UPPER(BTRIM(COALESCE(
            CASE WHEN billing_address IS JSON
                  AND jsonb_typeof(billing_address::jsonb) = 'object'
                 THEN billing_address::jsonb ->> 'state'
            END, ''))) AS raw_state,
        UPPER(BTRIM(COALESCE(currency, ''))) AS currency,
        COUNT(*)::bigint AS invoices,
        COALESCE(SUM(COALESCE(subtotal, amount, 0)), 0)::bigint AS taxable_cents,
        COALESCE(SUM(CASE WHEN us_sales_tax_snapshot ->> 'exempt' = 'true'
                          THEN COALESCE(subtotal, amount, 0) ELSE 0 END), 0)::bigint
            AS exempt_cents
    FROM invoices
    WHERE UPPER(BTRIM(COALESCE(billing_country, ''))) = 'US'
      AND COALESCE(status, '') <> 'void'
      AND issued_at >= $1
      AND issued_at < $2
    GROUP BY 1, 2
    ORDER BY 1, 2
"#;

async fn us_sales_by_state(
    db: &PgPool,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<Vec<UsSalesBucket>, String> {
    let rows: Vec<(String, String, i64, i64, i64)> = sqlx::query_as(US_SALES_BY_STATE_SQL)
        .bind(start)
        .bind(end)
        .fetch_all(db)
        .await
        .map_err(|error| format!("US tax nexus sweep: sales aggregation failed: {error}"))?;
    Ok(rows
        .into_iter()
        .map(
            |(raw_state, currency, invoices, taxable_cents, exempt_cents)| UsSalesBucket {
                raw_state,
                currency,
                invoices,
                taxable_cents,
                exempt_cents,
            },
        )
        .collect())
}

/// The two nexus measures the sweep tracks per state, plus the exempt
/// portion of the USD sales. BOTH criteria are always measured; only the
/// row's declared criterion(s) alert.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NexusMeasures {
    /// USD gross sales in the window (exempt sales included).
    pub sales_cents: i64,
    /// Transactions in the window, every currency (a transaction needs no
    /// FX conversion).
    pub transactions: i64,
    /// The portion of `sales_cents` sold under a customer exemption
    /// certificate.
    pub exempt_cents: i64,
}

/// Fold per-(state, currency) buckets into per-state measures: sales and
/// exempt dollars USD-only (the thresholds are USD figures), transactions
/// across currencies. Pure, so the sweep and the report agree.
fn fold_state_measures(buckets: &[UsSalesBucket]) -> BTreeMap<String, NexusMeasures> {
    let mut by_state: BTreeMap<String, NexusMeasures> = BTreeMap::new();
    for bucket in buckets {
        let Some(code) = normalize_state_code(Some(&bucket.raw_state)) else {
            continue;
        };
        let entry = by_state.entry(code).or_default();
        entry.transactions = entry.transactions.saturating_add(bucket.invoices.max(0));
        if bucket.currency == "USD" {
            entry.sales_cents = entry.sales_cents.saturating_add(bucket.taxable_cents);
            entry.exempt_cents = entry.exempt_cents.saturating_add(bucket.exempt_cents);
        }
    }
    by_state
}

/// US invoices the sweep can REPORT but never assign: those whose billing
/// address carries no recognisable state code, and those in a currency other
/// than USD (reported per currency — never converted, there is no FX source
/// in this repository).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UsUnassignedSales {
    pub unknown_state_invoices: u64,
    pub unknown_state_cents: i64,
    /// (currency, invoices, taxable cents) per non-USD currency.
    pub non_usd_invoices: Vec<(String, u64, i64)>,
}

/// Bucket the aggregates the sweep can only REPORT (unknown state, non-USD).
/// Pure, so the sweep and the admin read agree by construction.
fn bucket_unassigned_sales(buckets: &[UsSalesBucket]) -> UsUnassignedSales {
    let mut reported = UsUnassignedSales::default();
    for bucket in buckets {
        match normalize_state_code(Some(&bucket.raw_state)) {
            Some(_) if bucket.currency == "USD" => {}
            Some(_) => {
                // A recognised state, but not in USD: reported per currency,
                // never converted.
                match reported
                    .non_usd_invoices
                    .iter_mut()
                    .find(|(currency, _, _)| *currency == bucket.currency)
                {
                    Some((_, invoices, cents)) => {
                        *invoices += bucket.invoices.max(0) as u64;
                        *cents = cents.saturating_add(bucket.taxable_cents);
                    }
                    None => reported.non_usd_invoices.push((
                        bucket.currency.clone(),
                        bucket.invoices.max(0) as u64,
                        bucket.taxable_cents,
                    )),
                }
            }
            None => {
                // No usable state on the invoice: UNKNOWN, reported only.
                reported.unknown_state_invoices += bucket.invoices.max(0) as u64;
                reported.unknown_state_cents = reported
                    .unknown_state_cents
                    .saturating_add(bucket.taxable_cents);
            }
        }
    }
    reported.non_usd_invoices.sort_by(|a, b| a.0.cmp(&b.0));
    reported
}

/// The reported-not-assigned buckets over the trailing twelve months — the
/// same measurement the sweep reports, exposed so the admin read shows the
/// UNKNOWN bucket to the operator instead of leaving it in logs alone.
pub async fn unassigned_us_sales(
    db: &PgPool,
    now: DateTime<Utc>,
) -> Result<UsUnassignedSales, String> {
    let (start, end) = NexusWindow::Trailing12Months.bounds(now);
    let buckets = us_sales_by_state(db, start, end).await?;
    Ok(bucket_unassigned_sales(&buckets))
}

/// The sweep's run summary.
#[derive(Debug, Default, Clone)]
pub struct UsTaxSweepResult {
    /// States with a status row the sweep evaluated.
    pub states_evaluated: u64,
    /// Evaluated states observed below their declared threshold(s).
    pub states_below: u64,
    /// Evaluated states observed at/above their declared threshold(s).
    pub states_crossed: u64,
    /// States already `registered` (tracked, never alerted again).
    pub states_registered: u64,
    /// Crossing alerts raised by this run (one per state per window).
    pub alerts_raised: u64,
    /// Early warnings raised by this run (one per state per window).
    pub warnings_raised: u64,
    /// Evaluated states sitting at/above the warning fraction of a declared
    /// threshold (crossed states excluded).
    pub states_warned: u64,
    /// States the data file marks `not_taxable`: reported distinctly, never
    /// evaluated, never asked to register.
    pub states_not_taxable: Vec<String>,
    /// States with sales in the window but NO usable row in the data file —
    /// surfaced by name, never evaluated against an invented threshold.
    pub states_without_threshold_data: Vec<String>,
    /// States whose declared criterion is missing its threshold (or window):
    /// a data error — the state is refused and reported, never evaluated.
    pub states_invalid_nexus: Vec<(String, String)>,
    /// US invoices in the window whose billing address carries no
    /// recognisable state code: reported, never assigned to a state.
    pub unknown_state_invoices: u64,
    pub unknown_state_cents: i64,
    /// US invoices in the window in a non-USD currency: reported per
    /// currency, never converted (no FX source exists here).
    pub non_usd_invoices: Vec<(String, u64, i64)>,
    /// States whose evaluation failed (isolated; retried next sweep).
    pub failed_states: u64,
}

impl UsTaxSweepResult {
    /// Whether anything in this run deserves the operator's eyes (drives the
    /// maintenance log line).
    pub fn needs_attention(&self) -> bool {
        self.alerts_raised > 0
            || self.warnings_raised > 0
            || !self.states_not_taxable.is_empty()
            || !self.states_without_threshold_data.is_empty()
            || !self.states_invalid_nexus.is_empty()
            || self.unknown_state_invoices > 0
            || !self.non_usd_invoices.is_empty()
            || self.failed_states > 0
    }
}

/// One status row, as read back for the sweep and the admin surface.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UsTaxStatusRow {
    pub state_code: String,
    pub status: String,
    pub nexus_window: String,
    /// The declared criteria: `sales` | `transactions` | `either`.
    pub criteria: String,
    /// The gross-sales threshold; NULL for a `transactions`-only state.
    pub threshold_cents: Option<i64>,
    /// The transaction threshold; NULL for a `sales`-only state.
    pub transaction_threshold: Option<i64>,
    pub observed_cents: i64,
    pub observed_count: i64,
    pub observed_exempt_cents: i64,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub crossed_at: Option<DateTime<Utc>>,
    pub crossed_window_start: Option<DateTime<Utc>>,
    pub warned_at: Option<DateTime<Utc>>,
    pub warned_window_start: Option<DateTime<Utc>>,
    pub registered_at: Option<DateTime<Utc>>,
    pub registered_by: Option<String>,
    pub registration_note: Option<String>,
    pub last_evaluated_at: Option<DateTime<Utc>>,
    pub last_evaluation_error: Option<String>,
}

const STATUS_ROW_COLUMNS: &str = "state_code, status, nexus_window, criteria, threshold_cents, \
     transaction_threshold, observed_cents, observed_count, observed_exempt_cents, window_start, \
     window_end, crossed_at, crossed_window_start, warned_at, warned_window_start, registered_at, \
     registered_by, registration_note, last_evaluated_at, last_evaluation_error";

/// Every tracked state, for the admin read and the sweep's evaluation set.
pub async fn list_status_rows(db: &PgPool) -> Result<Vec<UsTaxStatusRow>, String> {
    sqlx::query_as(&format!(
        "SELECT {STATUS_ROW_COLUMNS} FROM us_tax_nexus_states ORDER BY state_code"
    ))
    .fetch_all(db)
    .await
    .map_err(|error| format!("US tax nexus: status query failed: {error}"))
}

/// The periodic nexus sweep: aggregate the window's taxable US sales per
/// state, compare against the committed thresholds, persist the per-state
/// status row, and raise ONE operator alert per state per window on a
/// crossing. It never registers and never charges.
///
/// Idempotent: a replay re-evaluates the same window, updates
/// `observed_cents`, and raises no second alert (the crossing transition is
/// a conditional UPDATE inside the row's transaction).
pub async fn sweep_us_tax_nexus(state: &AppState) -> Result<UsTaxSweepResult, String> {
    let now = Utc::now();
    let today = now.date_naive();
    let config =
        UsTaxConfig::from_env(today).map_err(|error| format!("US tax nexus sweep: {error}"))?;
    let table = &config.table;
    let source = config.source.clone();
    if table.is_empty() {
        info!(
            source = %source,
            "US tax nexus sweep: the rate/threshold file carries no states — nothing to \
             evaluate (never a threshold from thin air)"
        );
    }

    let mut result = UsTaxSweepResult::default();

    // Two aggregations: states measure either the calendar year or the
    // trailing twelve months, and each state is read from the window its own
    // row names (the file is the truth for which). The REPORTING buckets
    // (unknown-state and non-USD invoices) are measured over the trailing
    // twelve months — the widest single window, so nothing recent can hide.
    let (calendar_start, calendar_end) = NexusWindow::CalendarYear.bounds(now);
    let (trailing_start, trailing_end) = NexusWindow::Trailing12Months.bounds(now);
    let calendar_buckets = us_sales_by_state(&state.db, calendar_start, calendar_end).await?;
    let trailing_buckets = us_sales_by_state(&state.db, trailing_start, trailing_end).await?;

    // BOTH nexus measures per state: USD gross sales, transaction counts
    // (all currencies) and the exempt portion — always tracked, whichever
    // criterion the row declares.
    let measures_calendar = fold_state_measures(&calendar_buckets);
    let measures_trailing = fold_state_measures(&trailing_buckets);

    // Everything the sweep can only REPORT (unknown state, non-USD) comes
    // from the same pure bucketing the admin read uses.
    let reported = bucket_unassigned_sales(&trailing_buckets);
    result.unknown_state_invoices = reported.unknown_state_invoices;
    result.unknown_state_cents = reported.unknown_state_cents;
    result.non_usd_invoices = reported.non_usd_invoices;

    if result.unknown_state_invoices > 0 {
        warn!(
            unknown_state_invoices = result.unknown_state_invoices,
            unknown_state_cents = result.unknown_state_cents,
            "US tax nexus sweep: US invoices without a recognisable billing-address state — \
             reported as UNKNOWN, never assigned to a state"
        );
    }
    for (currency, invoices, cents) in &result.non_usd_invoices {
        warn!(
            currency = %currency,
            invoices,
            taxable_cents = cents,
            "US tax nexus sweep: US invoices in a non-USD currency are excluded from the \
             USD thresholds — never converted without an FX source"
        );
    }

    // The evaluation set: states with sales in the window, plus every row we
    // already track (a state with no sales this window still re-evaluates —
    // that is how a calendar-year row returns to `below` in the new year).
    let mut evaluation_codes: Vec<String> = measures_calendar
        .keys()
        .chain(measures_trailing.keys())
        .cloned()
        .collect();
    for row in list_status_rows(&state.db).await? {
        if !evaluation_codes.contains(&row.state_code) {
            evaluation_codes.push(row.state_code);
        }
    }
    evaluation_codes.sort();
    evaluation_codes.dedup();

    for code in evaluation_codes {
        let Some(table_row) = table.row(&code) else {
            // No threshold data: named, never evaluated against a guess.
            result.states_without_threshold_data.push(code.clone());
            let note = format!(
                "no row in the US tax data file ({source}) — not evaluated against an \
                 invented threshold; add the state's taxability/rate/threshold/source/retrieved \
                 row"
            );
            warn!(state = %code, "US tax nexus sweep: {note}");
            if let Err(error) = record_evaluation_error(&state.db, &code, &note).await {
                warn!(state = %code, error = %error, "US tax nexus sweep: error note failed");
            }
            continue;
        };
        if table_row.taxability == Taxability::NotTaxable {
            // The product is exempt in this state: nothing to register, no
            // threshold to measure — reported distinctly, never evaluated,
            // and a status row (if any) is left untouched (registration is
            // the operator's; the sweep never writes one).
            result.states_not_taxable.push(code.clone());
            debug!(
                state = %code,
                "US tax nexus sweep: state is not_taxable in the data file — skipped (never \
                 asked to register)"
            );
            continue;
        }
        let Some(declaration) = (match table_row.nexus_declaration() {
            Ok(declaration) => declaration,
            Err(reason) => {
                // A row declaring a criterion whose threshold is missing is a
                // data error: REFUSE to evaluate the state (never a guess)
                // and report it by name.
                result
                    .states_invalid_nexus
                    .push((code.clone(), reason.clone()));
                warn!(
                    state = %code,
                    reason = %reason,
                    "US tax nexus sweep: nexus declaration is a data error — state refused, \
                     not evaluated"
                );
                let note = format!(
                    "nexus declaration data error ({reason}) — not evaluated; fix the row in {source}"
                );
                let _ = record_evaluation_error(&state.db, &code, &note).await;
                continue;
            }
        }) else {
            // Unreachable: a not_taxable row returned above.
            continue;
        };
        let measures = match declaration.window {
            NexusWindow::CalendarYear => measures_calendar.get(&code).copied().unwrap_or_default(),
            NexusWindow::Trailing12Months => {
                measures_trailing.get(&code).copied().unwrap_or_default()
            }
        };
        match evaluate_state(
            &state.db,
            table_row,
            &declaration,
            measures,
            config.warn_fraction_bps,
            now,
        )
        .await
        {
            Ok(evaluation) => {
                result.states_evaluated += 1;
                match evaluation.outcome {
                    StateOutcome::Below => result.states_below += 1,
                    StateOutcome::Crossed => result.states_crossed += 1,
                    StateOutcome::Registered => result.states_registered += 1,
                }
                if evaluation.alert_raised {
                    result.alerts_raised += 1;
                }
                if evaluation.warn_raised {
                    result.warnings_raised += 1;
                }
                if evaluation.warn_armed || evaluation.warn_raised {
                    result.states_warned += 1;
                }
            }
            Err(error) => {
                // ONE failing state must not abort the sweep; it is retried
                // next run (its transaction committed nothing).
                result.failed_states += 1;
                warn!(state = %code, error = %error, "US tax nexus sweep: state failed — isolated");
                let _ = record_evaluation_error(&state.db, &code, &error).await;
            }
        }
    }

    info!(
        states_evaluated = result.states_evaluated,
        states_below = result.states_below,
        states_crossed = result.states_crossed,
        states_registered = result.states_registered,
        states_not_taxable = result.states_not_taxable.len(),
        alerts_raised = result.alerts_raised,
        warnings_raised = result.warnings_raised,
        without_threshold_data = result.states_without_threshold_data.len(),
        invalid_nexus_declarations = result.states_invalid_nexus.len(),
        unknown_state_invoices = result.unknown_state_invoices,
        failed_states = result.failed_states,
        "US tax nexus sweep complete (tracking only — registration and charging are operator \
         actions)"
    );
    if result.alerts_raised > 0 {
        metrics::counter!("apexmail_us_tax_nexus_crossings_total").increment(result.alerts_raised);
    }
    if result.warnings_raised > 0 {
        metrics::counter!("apexmail_us_tax_nexus_warnings_total").increment(result.warnings_raised);
    }
    if result.unknown_state_invoices > 0 {
        metrics::counter!("apexmail_us_tax_nexus_unknown_state_invoices_total")
            .increment(result.unknown_state_invoices);
    }
    Ok(result)
}

/// The outcome of evaluating one state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StateOutcome {
    Below,
    Crossed,
    Registered,
}

/// The status a state landed on, plus whether this run raised the crossing
/// alert and/or the early warning for it.
#[derive(Debug, Clone, Copy)]
struct StateEvaluation {
    outcome: StateOutcome,
    alert_raised: bool,
    warn_raised: bool,
    /// Sitting below the threshold but at/above the warning fraction (armed).
    warn_armed: bool,
}

/// Compare observed transactions against a count threshold — the same
/// "meets or exceeds" boundary as [`evaluate_nexus`].
pub fn evaluate_nexus_count(observed: i64, threshold: i64) -> NexusVerdict {
    evaluate_nexus(observed, threshold)
}

/// The verdict over the DECLARED criteria: crossed when ANY declared measure
/// reaches its threshold (the statutes trigger on whichever comes first).
/// Measures the row does not declare are never compared.
pub fn declared_verdict(declaration: &NexusDeclaration, measures: NexusMeasures) -> NexusVerdict {
    let sales_crossed = declaration
        .sales_threshold_cents
        .is_some_and(|threshold| evaluate_nexus(measures.sales_cents, threshold).is_crossed());
    let transactions_crossed = declaration.transaction_threshold.is_some_and(|threshold| {
        evaluate_nexus_count(measures.transactions, threshold).is_crossed()
    });
    if sales_crossed || transactions_crossed {
        NexusVerdict::Crossed
    } else {
        NexusVerdict::Below
    }
}

/// Whether one measure has reached the warning fraction of its threshold:
/// `observed × 10_000 ≥ threshold × warn_bps`, exact integer arithmetic.
pub fn warn_fraction_reached(observed: i64, threshold: i64, warn_bps: u32) -> bool {
    if threshold <= 0 {
        return false;
    }
    i128::from(observed.max(0)) * 10_000 >= i128::from(threshold) * i128::from(warn_bps)
}

/// Which declared measures sit at/above the warning fraction. A crossing is
/// the stronger signal (the crossing alert fires), so callers only warn when
/// the state is still below.
pub fn warn_triggers(
    declaration: &NexusDeclaration,
    measures: NexusMeasures,
    warn_bps: u32,
) -> Vec<&'static str> {
    let mut triggers = Vec::new();
    if let Some(threshold) = declaration.sales_threshold_cents {
        if warn_fraction_reached(measures.sales_cents, threshold, warn_bps) {
            triggers.push("sales");
        }
    }
    if let Some(threshold) = declaration.transaction_threshold {
        if warn_fraction_reached(measures.transactions, threshold, warn_bps) {
            triggers.push("transactions");
        }
    }
    triggers
}
/// The full content of a status row as this run wants it persisted.
struct StatusRowValues {
    state_code: String,
    status: &'static str,
    window: NexusWindow,
    criteria: NexusCriteria,
    threshold_cents: Option<i64>,
    transaction_threshold: Option<i64>,
    observed_cents: i64,
    observed_count: i64,
    observed_exempt_cents: i64,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    crossed_at: Option<DateTime<Utc>>,
    crossed_window_start: Option<DateTime<Utc>>,
    warned_at: Option<DateTime<Utc>>,
    warned_window_start: Option<DateTime<Utc>>,
    last_evaluated_at: DateTime<Utc>,
}

/// Persist one status row (insert on first sighting, update after). Runs on
/// the caller's transaction under the per-state advisory lock.
async fn upsert_status_row(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    values: &StatusRowValues,
) -> Result<(), String> {
    sqlx::query(
        "INSERT INTO us_tax_nexus_states (state_code, status, nexus_window, criteria, \
         threshold_cents, transaction_threshold, observed_cents, observed_count, \
         observed_exempt_cents, window_start, window_end, crossed_at, crossed_window_start, \
         warned_at, warned_window_start, last_evaluated_at, last_evaluation_error) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NULL) \
         ON CONFLICT (state_code) DO UPDATE SET \
             status = EXCLUDED.status, \
             nexus_window = EXCLUDED.nexus_window, \
             criteria = EXCLUDED.criteria, \
             threshold_cents = EXCLUDED.threshold_cents, \
             transaction_threshold = EXCLUDED.transaction_threshold, \
             observed_cents = EXCLUDED.observed_cents, \
             observed_count = EXCLUDED.observed_count, \
             observed_exempt_cents = EXCLUDED.observed_exempt_cents, \
             window_start = EXCLUDED.window_start, \
             window_end = EXCLUDED.window_end, \
             crossed_at = EXCLUDED.crossed_at, \
             crossed_window_start = EXCLUDED.crossed_window_start, \
             warned_at = EXCLUDED.warned_at, \
             warned_window_start = EXCLUDED.warned_window_start, \
             last_evaluated_at = EXCLUDED.last_evaluated_at, \
             last_evaluation_error = NULL, \
             updated_at = EXCLUDED.last_evaluated_at",
    )
    .bind(&values.state_code)
    .bind(values.status)
    .bind(values.window.as_str())
    .bind(values.criteria.as_str())
    .bind(values.threshold_cents)
    .bind(values.transaction_threshold)
    .bind(values.observed_cents)
    .bind(values.observed_count)
    .bind(values.observed_exempt_cents)
    .bind(values.window_start)
    .bind(values.window_end)
    .bind(values.crossed_at)
    .bind(values.crossed_window_start)
    .bind(values.warned_at)
    .bind(values.warned_window_start)
    .bind(values.last_evaluated_at)
    .execute(&mut **tx)
    .await
    .map_err(|error| format!("US tax nexus: status upsert failed: {error}"))?;
    Ok(())
}

/// Evaluate one state's window and persist its status row, in ONE
/// transaction: the row update and the crossing alert commit together, so an
/// alert can never be raised twice for one window (and a failed alert rolls
/// the flip back, to be retried).
///
/// Transitions:
/// * `registered` stays `registered` (the operator acted; tracking
///   continues, no alert is ever raised for a registered state);
/// * `below` → `threshold_crossed` when the window reaches the threshold:
///   the alert is raised ONCE;
/// * `threshold_crossed` stays sticky — for a CALENDAR window a new calendar
///   year is a new window instance (a fresh crossing alerts once for the new
///   year; a state below again in the new year returns to `below`), while a
///   ROLLING twelve-month window has no new window and never re-alerts;
/// * nothing here ever writes `registered` — that is the operator path.
async fn evaluate_state(
    db: &PgPool,
    table_row: &UsTaxStateRow,
    declaration: &NexusDeclaration,
    measures: NexusMeasures,
    warn_bps: u32,
    now: DateTime<Utc>,
) -> Result<StateEvaluation, String> {
    let state_code = table_row.state.as_str();
    let (window_start, window_end) = declaration.window.bounds(now);
    let crossed = declared_verdict(declaration, measures).is_crossed();
    let triggers = if crossed {
        Vec::new()
    } else {
        warn_triggers(declaration, measures, warn_bps)
    };

    let mut tx = db
        .begin()
        .await
        .map_err(|error| format!("US tax nexus: state tx failed: {error}"))?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("us-tax-nexus:{state_code}"))
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("US tax nexus: advisory lock failed: {error}"))?;

    let existing: Option<UsTaxStatusRow> = sqlx::query_as(&format!(
        "SELECT {STATUS_ROW_COLUMNS} FROM us_tax_nexus_states WHERE state_code = $1 FOR UPDATE"
    ))
    .bind(state_code)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| format!("US tax nexus: status row lookup failed: {error}"))?;

    // The desired end state, derived from the current row + this window's
    // verdict. `alert_raised`/`warn_raised` are set exactly when this run is
    // the one that crosses / first reaches the warning fraction.
    // Every branch below assigns `status` (and the alert records it needs);
    // the rest start from their cleared values.
    let status;
    let mut crossed_at = None;
    let mut crossed_window_start = None;
    let mut warned_at = None;
    let mut warned_window_start = None;
    let mut alert_raised = false;
    let mut warn_raised = false;
    let mut warn_armed = false;
    let outcome;
    match &existing {
        // Registered: tracked, never alerted or warned. Registration is the
        // operator's answer to the crossing; the records are preserved.
        Some(row) if row.status == "registered" => {
            status = "registered";
            crossed_at = row.crossed_at;
            crossed_window_start = row.crossed_window_start;
            warned_at = row.warned_at;
            warned_window_start = row.warned_window_start;
            outcome = StateOutcome::Registered;
        }
        Some(row) => {
            let sticky_crossed = row.status == "threshold_crossed";
            // A calendar year boundary (a later window start) is a NEW window
            // instance; a rolling twelve-month window never starts a new one
            // (its start advances every day, so it is deliberately excluded).
            let new_window_instance =
                declaration.window == NexusWindow::CalendarYear && window_start > row.window_start;
            if crossed {
                status = "threshold_crossed";
                outcome = StateOutcome::Crossed;
                if !sticky_crossed || new_window_instance {
                    // The crossing (or a new window's crossing): flip and
                    // alert ONCE; any earlier warning is superseded.
                    crossed_at = Some(now);
                    crossed_window_start = Some(window_start);
                    alert_raised = true;
                } else {
                    // Sticky: a replay neither re-alerts nor moves the record.
                    crossed_at = row.crossed_at;
                    crossed_window_start = row.crossed_window_start;
                    warned_at = row.warned_at;
                    warned_window_start = row.warned_window_start;
                }
            } else if sticky_crossed && !new_window_instance {
                // Sticky: a dip inside the same window (or any dip in a
                // rolling window) does not un-cross.
                status = "threshold_crossed";
                outcome = StateOutcome::Crossed;
                crossed_at = row.crossed_at;
                crossed_window_start = row.crossed_window_start;
                warned_at = row.warned_at;
                warned_window_start = row.warned_window_start;
            } else {
                // Below. A new calendar-year instance clears the old
                // crossing and resets the warning (a new window may warn
                // again); a rolling window's warning is sticky once raised.
                status = "below";
                outcome = StateOutcome::Below;
                let (previous_warned_at, previous_warned_window) = if new_window_instance {
                    (None, None)
                } else {
                    (row.warned_at, row.warned_window_start)
                };
                let already_warned = match declaration.window {
                    NexusWindow::CalendarYear => previous_warned_window == Some(window_start),
                    NexusWindow::Trailing12Months => previous_warned_at.is_some(),
                };
                warn_armed = !triggers.is_empty();
                if warn_armed && !already_warned {
                    warn_raised = true;
                    warned_at = Some(now);
                    warned_window_start = Some(window_start);
                } else {
                    warned_at = previous_warned_at;
                    warned_window_start = previous_warned_window;
                }
            }
        }
        // First sighting of the state (its address state is known, so the
        // row is created here at its evaluated status — never `registered`).
        None => {
            if crossed {
                status = "threshold_crossed";
                crossed_at = Some(now);
                crossed_window_start = Some(window_start);
                alert_raised = true;
                outcome = StateOutcome::Crossed;
            } else {
                status = "below";
                outcome = StateOutcome::Below;
                warn_armed = !triggers.is_empty();
                if warn_armed {
                    warn_raised = true;
                    warned_at = Some(now);
                    warned_window_start = Some(window_start);
                }
            }
        }
    }

    upsert_status_row(
        &mut tx,
        &StatusRowValues {
            state_code: state_code.to_string(),
            status,
            window: declaration.window,
            criteria: declaration.criteria,
            threshold_cents: declaration.sales_threshold_cents,
            transaction_threshold: declaration.transaction_threshold,
            observed_cents: measures.sales_cents,
            observed_count: measures.transactions,
            observed_exempt_cents: measures.exempt_cents,
            window_start,
            window_end,
            crossed_at,
            crossed_window_start,
            warned_at,
            warned_window_start,
            last_evaluated_at: now,
        },
    )
    .await?;

    if alert_raised {
        raise_nexus_alert(
            &mut tx,
            table_row,
            declaration,
            measures,
            window_start,
            window_end,
        )
        .await?;
        info!(
            state = %state_code,
            observed_cents = measures.sales_cents,
            observed_count = measures.transactions,
            criteria = declaration.criteria.as_str(),
            window = declaration.window.as_str(),
            "US tax nexus: threshold crossed — operator alert raised (registration is an \
             operator action; NO tax is charged until the state is registered)"
        );
    }
    if warn_raised {
        raise_warning_alert(
            &mut tx,
            table_row,
            &WarningContext {
                declaration,
                measures,
                warn_bps,
                triggers: &triggers,
            },
            window_start,
            window_end,
            now,
        )
        .await?;
        info!(
            state = %state_code,
            observed_cents = measures.sales_cents,
            observed_count = measures.transactions,
            triggers = ?triggers,
            warn_bps,
            window = declaration.window.as_str(),
            "US tax nexus: early warning raised at the configured fraction of the threshold — \
             registration/filing has lead time; NO tax is charged until the state is registered"
        );
    }

    tx.commit()
        .await
        .map_err(|error| format!("US tax nexus: state commit failed: {error}"))?;
    Ok(StateEvaluation {
        outcome,
        alert_raised,
        warn_raised,
        warn_armed,
    })
}

/// Raise the one durable operator alert for a crossing (the repo's finance
/// alerting convention: a `finance_incidents` row, status `open`, resolved by
/// finance). The row is inserted INSIDE the state transaction, so the flip
/// and its alert are atomic: a failed alert cannot leave a crossed state
/// un-alerted, and a committed flip can never alert twice.
async fn raise_nexus_alert(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    table_row: &UsTaxStateRow,
    declaration: &NexusDeclaration,
    measures: NexusMeasures,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
) -> Result<(), String> {
    let detail = serde_json::json!({
        "state": table_row.state,
        "observedCents": measures.sales_cents,
        "thresholdCents": declaration.sales_threshold_cents,
        "observedCount": measures.transactions,
        "transactionThreshold": declaration.transaction_threshold,
        "criteria": declaration.criteria.as_str(),
        "exemptCents": measures.exempt_cents,
        "windowKind": declaration.window.as_str(),
        "windowStart": window_start.to_rfc3339(),
        "windowEnd": window_end.to_rfc3339(),
        "rateFileSource": table_row.source_url,
        "rateFileRetrieved": table_row.retrieved.to_string(),
        "requiredAction": "Register with the state (admin surface: POST \
                           /v1/admin/billing/us-tax/states/:state/registration). Until then \
                           no sales tax is charged and no state return can be filed.",
    });
    sqlx::query(
        "INSERT INTO finance_incidents (kind, severity, status, detail) \
         VALUES ($1, 'high', 'open', $2)",
    )
    .bind(NEXUS_ALERT_KIND)
    .bind(detail)
    .execute(&mut **tx)
    .await
    .map_err(|error| format!("US tax nexus: crossing alert failed: {error}"))?;
    Ok(())
}

/// What an early warning is raised over: the declared criteria, the measures
/// behind them, the fraction that fired and which criterion(s) reached it.
struct WarningContext<'a> {
    declaration: &'a NexusDeclaration,
    measures: NexusMeasures,
    warn_bps: u32,
    triggers: &'a [&'static str],
}

/// Raise the one durable early warning for a window (`US_TAX_WARN_FRACTION` of
/// the threshold): a MEDIUM-grade `finance_incidents` row with the remaining
/// headroom and — when the window is a calendar year — the days left in it,
/// so registration/filing has lead time. Inserted INSIDE the state
/// transaction: the warned-marker write and its alert are atomic, so a failed
/// alert cannot leave a warned state un-alerted, nor can a committed warning
/// alert twice for one window.
async fn raise_warning_alert(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    table_row: &UsTaxStateRow,
    context: &WarningContext<'_>,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), String> {
    let declaration = context.declaration;
    let measures = context.measures;
    // A rolling twelve-month window has no determinable "days left"; a
    // calendar window's is exact.
    let days_left_in_window = match declaration.window {
        NexusWindow::CalendarYear => Some((window_end - now).num_days().max(0)),
        NexusWindow::Trailing12Months => None,
    };
    let detail = serde_json::json!({
        "state": table_row.state,
        "criteria": declaration.criteria.as_str(),
        "triggers": context.triggers,
        "warnFractionBps": context.warn_bps,
        "observedCents": measures.sales_cents,
        "thresholdCents": declaration.sales_threshold_cents,
        "remainingCents": declaration
            .sales_threshold_cents
            .map(|threshold| (threshold - measures.sales_cents).max(0)),
        "observedCount": measures.transactions,
        "transactionThreshold": declaration.transaction_threshold,
        "remainingCount": declaration
            .transaction_threshold
            .map(|threshold| (threshold - measures.transactions).max(0)),
        "exemptCents": measures.exempt_cents,
        "windowKind": declaration.window.as_str(),
        "windowStart": window_start.to_rfc3339(),
        "windowEnd": window_end.to_rfc3339(),
        "daysLeftInWindow": days_left_in_window,
        "rateFileSource": table_row.source_url,
        "rateFileRetrieved": table_row.retrieved.to_string(),
        "requiredAction": "Prepare to register with the state before the threshold is crossed \
                           (admin surface: POST /v1/admin/billing/us-tax/states/:state/registration). \
                           Until then no sales tax is charged and no state return can be filed.",
    });
    sqlx::query(
        "INSERT INTO finance_incidents (kind, severity, status, detail) \
         VALUES ($1, 'medium', 'open', $2)",
    )
    .bind(NEXUS_WARNING_KIND)
    .bind(detail)
    .execute(&mut **tx)
    .await
    .map_err(|error| format!("US tax nexus: early-warning alert failed: {error}"))?;
    Ok(())
}

/// Best-effort note of why a state could not be evaluated (its own committed
/// transaction so the note survives a rolled-back evaluation).
async fn record_evaluation_error(db: &PgPool, state: &str, reason: &str) -> Result<(), String> {
    sqlx::query(
        "UPDATE us_tax_nexus_states SET last_evaluation_error = $2, updated_at = NOW() \
         WHERE state_code = $1",
    )
    .bind(state)
    .bind(reason)
    .execute(db)
    .await
    .map_err(|error| format!("US tax nexus: evaluation-error note failed: {error}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Operator registration (the ONLY writer of `registered`)
// ---------------------------------------------------------------------------

/// The registration target an operator can set. `threshold_crossed` is
/// deliberately absent: that status is COMPUTED by the sweep, never assigned
/// by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationTarget {
    Registered,
    Below,
}

/// Failures of the registration surface.
#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    #[error("US sales tax: {0:?} is not a US state/territory postal code")]
    UnknownState(String),
    #[error(
        "US sales tax: cannot register {state} — the data file has no usable rate row for it \
         ({source_reason}); the state's invoices would be refused, so the rate row must land \
         first"
    )]
    UnusableRateRow {
        state: String,
        source_reason: String,
    },
    #[error(
        "US sales tax: cannot register {state} — the data file marks the product not_taxable \
         there, so registration would collect nothing; if the law changed, update the row \
         (taxability \"taxable\", a fresh rate and its retrieved date) first"
    )]
    NotTaxableState { state: String },
    #[error(
        "US sales tax: cannot register {state} — the row's nexus declaration is a data error \
         ({reason}); the sweep could not track it, so fix the row first"
    )]
    InvalidNexusDeclaration { state: String, reason: String },
    #[error("US sales tax: state {state} is not tracked — nothing to update")]
    NotTracked { state: String },
    #[error("US sales tax: {0}")]
    Database(String),
}

/// The window measures of one state: the same folds the sweep compares
/// against the thresholds (non-void US invoices; sales and exempt dollars
/// USD-only, transactions across currencies).
pub async fn state_window_measures(
    db: &PgPool,
    state: &str,
    window: NexusWindow,
    now: DateTime<Utc>,
) -> Result<NexusMeasures, String> {
    let (start, end) = window.bounds(now);
    let buckets = us_sales_by_state(db, start, end).await?;
    Ok(fold_state_measures(&buckets)
        .remove(state)
        .unwrap_or_default())
}

/// Register a state (owner/accounting act): from this moment, new invoices
/// for US customers in that state carry the sales-tax line — which requires a
/// usable (present, fresh, `taxable`) row whose nexus declaration is intact,
/// so registration is refused by name when any of that is missing. The row is
/// created when the state was never observed.
pub async fn register_state(
    db: &PgPool,
    config: &UsTaxConfig,
    state: &str,
    actor: &str,
    note: Option<&str>,
    now: DateTime<Utc>,
) -> Result<UsTaxStatusRow, RegistrationError> {
    let today = now.date_naive();
    let code = normalize_state_code(Some(state))
        .ok_or_else(|| RegistrationError::UnknownState(state.to_string()))?;
    // Taxability first: a `not_taxable` state is refused by NAME even when
    // its (dead) figures happen to be missing or stale, so the operator
    // learns the real reason.
    match config.table.row(&code) {
        None => {
            return Err(RegistrationError::UnusableRateRow {
                state: code.clone(),
                source_reason: UsTaxError::MissingRateRow {
                    state: code.clone(),
                }
                .to_string(),
            });
        }
        Some(row) if row.taxability == Taxability::NotTaxable => {
            return Err(RegistrationError::NotTaxableState { state: code });
        }
        Some(_) => {}
    }
    let table_row =
        config
            .fresh_row(&code, today)
            .map_err(|error| RegistrationError::UnusableRateRow {
                state: code.clone(),
                source_reason: error.to_string(),
            })?;
    let declaration = match table_row.nexus_declaration() {
        Ok(Some(declaration)) => declaration,
        Ok(None) => {
            return Err(RegistrationError::NotTaxableState { state: code });
        }
        Err(reason) => {
            return Err(RegistrationError::InvalidNexusDeclaration {
                state: code,
                reason,
            });
        }
    };
    let measures = state_window_measures(db, &code, declaration.window, now)
        .await
        .map_err(RegistrationError::Database)?;
    let (window_start, window_end) = declaration.window.bounds(now);

    let mut tx = db
        .begin()
        .await
        .map_err(|error| RegistrationError::Database(format!("tx failed: {error}")))?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("us-tax-nexus:{code}"))
        .execute(&mut *tx)
        .await
        .map_err(|error| RegistrationError::Database(format!("advisory lock failed: {error}")))?;

    // ONE statement covers both the first-registration INSERT and the
    // re-registration UPDATE; the registration columns are written only
    // here (the sweep's upsert deliberately never touches them). The
    // per-state advisory lock taken above serialises this against the sweep.
    sqlx::query(
        "INSERT INTO us_tax_nexus_states (state_code, status, nexus_window, criteria, \
         threshold_cents, transaction_threshold, observed_cents, observed_count, \
         observed_exempt_cents, window_start, window_end, registered_at, registered_by, \
         registration_note, last_evaluated_at, last_evaluation_error) \
         VALUES ($1, 'registered', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $11, \
                 NULL) \
         ON CONFLICT (state_code) DO UPDATE SET \
             status = 'registered', \
             nexus_window = EXCLUDED.nexus_window, \
             criteria = EXCLUDED.criteria, \
             threshold_cents = EXCLUDED.threshold_cents, \
             transaction_threshold = EXCLUDED.transaction_threshold, \
             observed_cents = EXCLUDED.observed_cents, \
             observed_count = EXCLUDED.observed_count, \
             observed_exempt_cents = EXCLUDED.observed_exempt_cents, \
             window_start = EXCLUDED.window_start, \
             window_end = EXCLUDED.window_end, \
             registered_at = EXCLUDED.registered_at, \
             registered_by = EXCLUDED.registered_by, \
             registration_note = EXCLUDED.registration_note, \
             last_evaluated_at = EXCLUDED.last_evaluated_at, \
             last_evaluation_error = NULL, \
             updated_at = EXCLUDED.last_evaluated_at",
    )
    .bind(&code)
    .bind(declaration.window.as_str())
    .bind(declaration.criteria.as_str())
    .bind(declaration.sales_threshold_cents)
    .bind(declaration.transaction_threshold)
    .bind(measures.sales_cents)
    .bind(measures.transactions)
    .bind(measures.exempt_cents)
    .bind(window_start)
    .bind(window_end)
    .bind(now)
    .bind(actor)
    .bind(note)
    .execute(&mut *tx)
    .await
    .map_err(|error| RegistrationError::Database(format!("registration write failed: {error}")))?;

    let row: UsTaxStatusRow = sqlx::query_as(&format!(
        "SELECT {STATUS_ROW_COLUMNS} FROM us_tax_nexus_states WHERE state_code = $1"
    ))
    .bind(&code)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| RegistrationError::Database(format!("readback failed: {error}")))?;
    tx.commit()
        .await
        .map_err(|error| RegistrationError::Database(format!("commit failed: {error}")))?;
    info!(
        state = %code,
        actor,
        "US tax nexus: state registered — sales tax now computes on new invoices \
         (never on past ones)"
    );
    Ok(row)
}

/// Unregister a state (the operator stops charging state tax): the row
/// returns to `below` and the crossing record is cleared, so a still-crossed
/// state alerts again on the next sweep. Deliberately independent of the data
/// file: removing tax must never be blocked by a rate-file problem.
pub async fn unregister_state(
    db: &PgPool,
    state: &str,
    actor: &str,
    note: Option<&str>,
    now: DateTime<Utc>,
) -> Result<UsTaxStatusRow, RegistrationError> {
    let code = normalize_state_code(Some(state))
        .ok_or_else(|| RegistrationError::UnknownState(state.to_string()))?;
    let mut tx = db
        .begin()
        .await
        .map_err(|error| RegistrationError::Database(format!("tx failed: {error}")))?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("us-tax-nexus:{code}"))
        .execute(&mut *tx)
        .await
        .map_err(|error| RegistrationError::Database(format!("advisory lock failed: {error}")))?;

    let updated = sqlx::query(
        "UPDATE us_tax_nexus_states SET status = 'below', registered_at = NULL, \
         registered_by = NULL, registration_note = $3, crossed_at = NULL, \
         crossed_window_start = NULL, warned_at = NULL, warned_window_start = NULL, \
         updated_at = $2 \
         WHERE state_code = $1",
    )
    .bind(&code)
    .bind(now)
    .bind(note)
    .execute(&mut *tx)
    .await
    .map_err(|error| RegistrationError::Database(format!("update failed: {error}")))?;
    if updated.rows_affected() == 0 {
        return Err(RegistrationError::NotTracked { state: code });
    }

    let row: UsTaxStatusRow = sqlx::query_as(&format!(
        "SELECT {STATUS_ROW_COLUMNS} FROM us_tax_nexus_states WHERE state_code = $1"
    ))
    .bind(&code)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| RegistrationError::Database(format!("readback failed: {error}")))?;
    tx.commit()
        .await
        .map_err(|error| RegistrationError::Database(format!("commit failed: {error}")))?;
    info!(
        state = %code,
        actor,
        "US tax nexus: state unregistered — sales tax no longer computes for it; a still-\
         crossed state alerts again on the next sweep"
    );
    Ok(row)
}

// ---------------------------------------------------------------------------
// Filing-ready per-state report (JSON + CSV) — the accountant's artifact
// ---------------------------------------------------------------------------

/// A validated reporting period: one calendar month, UTC, half-open
/// `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsTaxReportPeriod {
    pub year: i32,
    pub month: u32,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl UsTaxReportPeriod {
    /// Parse `YYYY-MM` (strict: four digits, month 01..12). Anything else is
    /// a named refusal — a period is never guessed.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        let Some((year_raw, month_raw)) = trimmed.split_once('-') else {
            return Err(format!("period {raw:?} is not YYYY-MM (e.g. \"2026-10\")"));
        };
        if year_raw.len() != 4 || month_raw.len() != 2 {
            return Err(format!("period {raw:?} is not YYYY-MM (e.g. \"2026-10\")"));
        }
        let year: i32 = year_raw
            .parse()
            .map_err(|_| format!("period {raw:?}: {year_raw:?} is not a four-digit year"))?;
        let month: u32 = month_raw
            .parse()
            .map_err(|_| format!("period {raw:?}: {month_raw:?} is not a two-digit month"))?;
        if !(1..=12).contains(&month) {
            return Err(format!("period {raw:?}: month {month} is not 01..12"));
        }
        let start = Utc
            .with_ymd_and_hms(year, month, 1, 0, 0, 0)
            .single()
            .ok_or_else(|| format!("period {raw:?} is not a real calendar month"))?;
        let end = if month == 12 {
            Utc.with_ymd_and_hms(year + 1, 1, 1, 0, 0, 0)
        } else {
            Utc.with_ymd_and_hms(year, month + 1, 1, 0, 0, 0)
        }
        .single()
        .expect("the first of a month is unambiguous");
        Ok(Self {
            year,
            month,
            start,
            end,
        })
    }

    /// The canonical `YYYY-MM` label.
    pub fn label(&self) -> String {
        format!("{:04}-{:02}", self.year, self.month)
    }
}

/// One rate stamp used on invoices of a state within the report period (from
/// the invoice tax snapshots — which rate was actually charged).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsTaxReportRateUsed {
    pub rate_bps: u32,
    pub rate_kind: String,
    pub source: String,
    pub retrieved: String,
    pub invoices: i64,
    pub tax_cents: i64,
}

/// The current data-file row for a state, as the report carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsTaxReportRateRow {
    pub taxability: String,
    pub rate_bps: Option<u32>,
    pub combined_rate_bps: Option<u32>,
    pub source_url: String,
    pub retrieved: String,
    pub fresh: bool,
    /// The declared criteria, or the named data error that refuses the state.
    pub criteria: Option<String>,
    pub nexus_declaration_error: Option<String>,
}

/// One state's filing figures (integer cents, USD only).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UsTaxReportState {
    pub state: String,
    /// `taxable` | `not_taxable` | `unknown_row` (no data-file row).
    pub taxability: String,
    /// `below` | `threshold_crossed` | `registered` | `not_tracked`.
    pub registration_status: String,
    pub invoice_count: i64,
    pub gross_sales_cents: i64,
    /// Sales on which tax was charged (gross, before credit-note netting).
    pub taxable_sales_cents: i64,
    /// Sales sold under an exemption certificate (gross, before netting).
    pub exempt_sales_cents: i64,
    pub tax_collected_cents: i64,
    pub credit_note_count: i64,
    /// Credits against invoices that carried tax, exempt sales, or neither.
    pub credited_taxed_cents: i64,
    pub credited_exempt_cents: i64,
    pub credited_other_cents: i64,
    /// `taxable − credited_taxed`; the filing number (may be negative when
    /// credits exceed the period's sales — reported as-is, never clamped).
    pub net_taxable_sales_cents: i64,
    /// `exempt − credited_exempt`.
    pub net_exempt_sales_cents: i64,
    pub rates_used: Vec<UsTaxReportRateUsed>,
    pub rate_row: Option<UsTaxReportRateRow>,
}

/// The USD totals across the report's states.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UsTaxReportTotals {
    pub invoice_count: i64,
    pub gross_sales_cents: i64,
    pub taxable_sales_cents: i64,
    pub exempt_sales_cents: i64,
    pub tax_collected_cents: i64,
    pub credit_note_count: i64,
    pub credited_taxed_cents: i64,
    pub credited_exempt_cents: i64,
    pub credited_other_cents: i64,
    pub net_taxable_sales_cents: i64,
    pub net_exempt_sales_cents: i64,
}

/// Non-USD US invoices of the period, per currency — reported, never
/// converted (there is no FX source in this repository).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsTaxReportNonUsd {
    pub currency: String,
    pub invoice_count: i64,
    pub gross_sales_cents: i64,
    pub tax_collected_cents: i64,
    pub credit_note_count: i64,
    pub credit_note_cents: i64,
}

/// What the report can only REPORT (never assign or convert): the honest
/// gaps of a filing month.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UsTaxReportGaps {
    pub unknown_state_invoices: i64,
    pub unknown_state_gross_cents: i64,
    pub unknown_state_tax_cents: i64,
    /// Credits against invoices whose address carries no recognisable state.
    pub unattributed_credit_note_count: i64,
    pub unattributed_credit_note_cents: i64,
    pub non_usd: Vec<UsTaxReportNonUsd>,
}

/// The filing-ready report: deterministic, integer cents, built from the DB
/// (the rate file only adds taxability/rate context).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsTaxReport {
    pub period: UsTaxReportPeriod,
    pub generated_at: DateTime<Utc>,
    pub rate_file_source: String,
    pub rate_file_max_age_days: u32,
    /// Set when the rate file could not be loaded: the DB figures are still
    /// reported (they are the filing truth), taxability context degrades to
    /// `unknown_row` and the reason is stated — never silently.
    pub rate_file_error: Option<String>,
    pub states: Vec<UsTaxReportState>,
    pub totals: UsTaxReportTotals,
    pub gaps: UsTaxReportGaps,
}

const REPORT_SALES_SQL: &str = r#"
    SELECT
        UPPER(BTRIM(COALESCE(
            CASE WHEN billing_address IS JSON
                  AND jsonb_typeof(billing_address::jsonb) = 'object'
                 THEN billing_address::jsonb ->> 'state'
            END, ''))) AS raw_state,
        UPPER(BTRIM(COALESCE(currency, ''))) AS currency,
        COUNT(*)::bigint AS invoices,
        COALESCE(SUM(COALESCE(subtotal, amount, 0)), 0)::bigint AS gross_cents,
        COALESCE(SUM(CASE WHEN us_sales_tax_cents > 0 THEN COALESCE(subtotal, amount, 0)
                          ELSE 0 END), 0)::bigint AS taxed_sales_cents,
        COALESCE(SUM(CASE WHEN us_sales_tax_snapshot ->> 'exempt' = 'true'
                          THEN COALESCE(subtotal, amount, 0) ELSE 0 END), 0)::bigint
            AS exempt_sales_cents,
        COALESCE(SUM(us_sales_tax_cents), 0)::bigint AS tax_collected_cents
    FROM invoices
    WHERE UPPER(BTRIM(COALESCE(billing_country, ''))) = 'US'
      AND COALESCE(status, '') <> 'void'
      AND issued_at >= $1 AND issued_at < $2
    GROUP BY 1, 2
"#;

const REPORT_RATES_SQL: &str = r#"
    SELECT
        UPPER(BTRIM(COALESCE(
            CASE WHEN billing_address IS JSON
                  AND jsonb_typeof(billing_address::jsonb) = 'object'
                 THEN billing_address::jsonb ->> 'state'
            END, ''))) AS raw_state,
        (us_sales_tax_snapshot ->> 'rateBps')::bigint AS rate_bps,
        COALESCE(us_sales_tax_snapshot ->> 'rateKind', 'state') AS rate_kind,
        COALESCE(us_sales_tax_snapshot ->> 'source', '') AS source,
        COALESCE(us_sales_tax_snapshot ->> 'retrieved', '') AS retrieved,
        COUNT(*)::bigint AS invoices,
        COALESCE(SUM(us_sales_tax_cents), 0)::bigint AS tax_cents
    FROM invoices
    WHERE UPPER(BTRIM(COALESCE(billing_country, ''))) = 'US'
      AND COALESCE(status, '') <> 'void'
      AND us_sales_tax_cents > 0
      AND issued_at >= $1 AND issued_at < $2
    GROUP BY 1, 2, 3, 4, 5
"#;

/// Credits attach to their invoice: the credited invoice's billing-address
/// state snapshot is the ONLY state attribution a credit note has (the
/// credit itself carries none), and the credit's own `created_at` month is
/// the period it reduces.
const REPORT_CREDITS_SQL: &str = r#"
    SELECT
        UPPER(BTRIM(COALESCE(
            CASE WHEN i.billing_address IS JSON
                  AND jsonb_typeof(i.billing_address::jsonb) = 'object'
                 THEN i.billing_address::jsonb ->> 'state'
            END, ''))) AS raw_state,
        UPPER(BTRIM(COALESCE(i.currency, ''))) AS currency,
        COUNT(*)::bigint AS credit_notes,
        COALESCE(SUM(cn.amount), 0)::bigint AS credited_cents,
        COALESCE(SUM(CASE WHEN i.us_sales_tax_cents > 0 THEN cn.amount ELSE 0 END), 0)::bigint
            AS credited_taxed_cents,
        COALESCE(SUM(CASE WHEN i.us_sales_tax_snapshot ->> 'exempt' = 'true'
                          THEN cn.amount ELSE 0 END), 0)::bigint AS credited_exempt_cents
    FROM credit_notes cn
    JOIN invoices i ON i.id = cn.invoice_id
    WHERE cn.created_at >= $1 AND cn.created_at < $2
    GROUP BY 1, 2
"#;

/// The per-currency non-USD gap bucket, created on first use.
fn non_usd_bucket<'a>(gaps: &'a mut UsTaxReportGaps, currency: &str) -> &'a mut UsTaxReportNonUsd {
    if let Some(index) = gaps
        .non_usd
        .iter()
        .position(|bucket| bucket.currency == currency)
    {
        return &mut gaps.non_usd[index];
    }
    gaps.non_usd.push(UsTaxReportNonUsd {
        currency: currency.to_string(),
        invoice_count: 0,
        gross_sales_cents: 0,
        tax_collected_cents: 0,
        credit_note_count: 0,
        credit_note_cents: 0,
    });
    let last = gaps.non_usd.len() - 1;
    &mut gaps.non_usd[last]
}

/// Build the filing report for `period` from the database. Deterministic:
/// states sorted by code, rate stamps sorted, integer cents only.
pub async fn us_tax_report(
    db: &PgPool,
    period: UsTaxReportPeriod,
    generated_at: DateTime<Utc>,
) -> Result<UsTaxReport, String> {
    let today = generated_at.date_naive();
    let (config, rate_file_error) = match UsTaxConfig::from_env(today) {
        Ok(config) => (Some(config), None),
        Err(error) => (None, Some(error.to_string())),
    };

    let sales_rows: Vec<(String, String, i64, i64, i64, i64, i64)> =
        sqlx::query_as(REPORT_SALES_SQL)
            .bind(period.start)
            .bind(period.end)
            .fetch_all(db)
            .await
            .map_err(|error| format!("US tax report: sales query failed: {error}"))?;
    let rate_rows: Vec<(String, i64, String, String, String, i64, i64)> =
        sqlx::query_as(REPORT_RATES_SQL)
            .bind(period.start)
            .bind(period.end)
            .fetch_all(db)
            .await
            .map_err(|error| format!("US tax report: rate-stamp query failed: {error}"))?;
    let credit_rows: Vec<(String, String, i64, i64, i64, i64)> = sqlx::query_as(REPORT_CREDITS_SQL)
        .bind(period.start)
        .bind(period.end)
        .fetch_all(db)
        .await
        .map_err(|error| format!("US tax report: credit-note query failed: {error}"))?;
    let status_rows = list_status_rows(db).await?;

    let mut states: BTreeMap<String, UsTaxReportState> = BTreeMap::new();
    let mut gaps = UsTaxReportGaps::default();

    // 1. Sales aggregates: recognized states (USD) become filing rows; every
    //    other shape is a reported gap.
    for (raw_state, currency, invoices, gross, taxed, exempt, tax) in sales_rows {
        match normalize_state_code(Some(&raw_state)) {
            Some(state) => {
                if currency == "USD" {
                    let row = states
                        .entry(state.clone())
                        .or_insert_with(|| UsTaxReportState {
                            state: state.clone(),
                            registration_status: "not_tracked".to_string(),
                            taxability: "unknown_row".to_string(),
                            ..UsTaxReportState::default()
                        });
                    row.invoice_count += invoices;
                    row.gross_sales_cents += gross;
                    row.taxable_sales_cents += taxed;
                    row.exempt_sales_cents += exempt;
                    row.tax_collected_cents += tax;
                } else {
                    let bucket = non_usd_bucket(&mut gaps, &currency);
                    bucket.invoice_count += invoices;
                    bucket.gross_sales_cents += gross;
                    bucket.tax_collected_cents += tax;
                }
            }
            None => {
                gaps.unknown_state_invoices += invoices;
                gaps.unknown_state_gross_cents += gross;
                gaps.unknown_state_tax_cents += tax;
            }
        }
    }

    // 2. Rate stamps actually used (from invoice snapshots).
    for (raw_state, rate_bps, rate_kind, source, retrieved, invoices, tax_cents) in rate_rows {
        let Some(state) = normalize_state_code(Some(&raw_state)) else {
            continue;
        };
        let Some(row) = states.get_mut(&state) else {
            continue;
        };
        row.rates_used.push(UsTaxReportRateUsed {
            rate_bps: u32::try_from(rate_bps.max(0)).unwrap_or(u32::MAX),
            rate_kind,
            source,
            retrieved,
            invoices,
            tax_cents,
        });
    }
    for row in states.values_mut() {
        row.rates_used
            .sort_by(|a, b| (a.rate_bps, &a.source).cmp(&(b.rate_bps, &b.source)));
    }

    // 3. Credit notes: reduce the state of the credited invoice; a credit
    //    whose invoice has no recognisable state (or is non-USD) is a
    //    reported gap, never assigned.
    for (raw_state, currency, count, credited, credited_taxed, credited_exempt) in credit_rows {
        match normalize_state_code(Some(&raw_state)) {
            Some(state) if currency == "USD" => {
                let Some(row) = states.get_mut(&state) else {
                    continue;
                };
                row.credit_note_count += count;
                row.credited_taxed_cents += credited_taxed;
                row.credited_exempt_cents += credited_exempt;
                row.credited_other_cents += credited - credited_taxed - credited_exempt;
            }
            Some(_) => {
                let bucket = non_usd_bucket(&mut gaps, &currency);
                bucket.credit_note_count += count;
                bucket.credit_note_cents += credited;
            }
            None => {
                gaps.unattributed_credit_note_count += count;
                gaps.unattributed_credit_note_cents += credited;
            }
        }
    }
    gaps.non_usd.sort_by(|a, b| a.currency.cmp(&b.currency));

    // 4. Tracked states appear even in a month with no sales (the
    //    accountant sees the zeros); rate-file context is attached to every
    //    row.
    for status in &status_rows {
        states
            .entry(status.state_code.clone())
            .or_insert_with(|| UsTaxReportState {
                state: status.state_code.clone(),
                registration_status: status.status.clone(),
                taxability: "unknown_row".to_string(),
                ..UsTaxReportState::default()
            });
    }
    for row in states.values_mut() {
        if let Some(status) = status_rows
            .iter()
            .find(|status| status.state_code == row.state)
        {
            row.registration_status = status.status.clone();
        }
        if let Some(config) = &config {
            if let Some(file_row) = config.table.row(&row.state) {
                row.taxability = file_row.taxability.as_str().to_string();
                let (criteria, nexus_error) = match file_row.nexus_declaration() {
                    Ok(Some(declaration)) => {
                        (Some(declaration.criteria.as_str().to_string()), None)
                    }
                    Ok(None) => (None, None),
                    Err(reason) => (None, Some(reason)),
                };
                row.rate_row = Some(UsTaxReportRateRow {
                    taxability: file_row.taxability.as_str().to_string(),
                    rate_bps: file_row.rate_bps,
                    combined_rate_bps: file_row.combined_rate_bps,
                    source_url: file_row.source_url.clone(),
                    retrieved: file_row.retrieved.to_string(),
                    fresh: is_row_fresh(file_row, today, config.max_age_days),
                    criteria,
                    nexus_declaration_error: nexus_error,
                });
            }
        }
        row.net_taxable_sales_cents = row.taxable_sales_cents - row.credited_taxed_cents;
        row.net_exempt_sales_cents = row.exempt_sales_cents - row.credited_exempt_cents;
    }

    let states: Vec<UsTaxReportState> = states.into_values().collect();
    let mut totals = UsTaxReportTotals::default();
    for row in &states {
        totals.invoice_count += row.invoice_count;
        totals.gross_sales_cents += row.gross_sales_cents;
        totals.taxable_sales_cents += row.taxable_sales_cents;
        totals.exempt_sales_cents += row.exempt_sales_cents;
        totals.tax_collected_cents += row.tax_collected_cents;
        totals.credit_note_count += row.credit_note_count;
        totals.credited_taxed_cents += row.credited_taxed_cents;
        totals.credited_exempt_cents += row.credited_exempt_cents;
        totals.credited_other_cents += row.credited_other_cents;
        totals.net_taxable_sales_cents += row.net_taxable_sales_cents;
        totals.net_exempt_sales_cents += row.net_exempt_sales_cents;
    }

    Ok(UsTaxReport {
        period,
        generated_at,
        rate_file_source: config
            .as_ref()
            .map(|config| config.source.clone())
            .unwrap_or_else(|| "<unavailable>".to_string()),
        rate_file_max_age_days: config
            .as_ref()
            .map(|config| config.max_age_days)
            .unwrap_or(DEFAULT_US_TAX_MAX_AGE_DAYS),
        rate_file_error,
        states,
        totals,
        gaps,
    })
}

impl UsTaxReport {
    /// The report as deterministic JSON (camelCase, integer cents).
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "reportVersion": 1,
            "period": self.period.label(),
            "periodStart": self.period.start.to_rfc3339(),
            "periodEnd": self.period.end.to_rfc3339(),
            "generatedAt": self.generated_at.to_rfc3339(),
            "basis": "USD invoices only; integer cents; sales are the invoice subtotal \
                      (collected tax is not gross receipts)",
            "rateFile": {
                "source": self.rate_file_source,
                "maxAgeDays": self.rate_file_max_age_days,
                "error": self.rate_file_error,
            },
            "states": self.states.iter().map(|row| serde_json::json!({
                "state": row.state,
                "taxability": row.taxability,
                "registrationStatus": row.registration_status,
                "invoiceCount": row.invoice_count,
                "grossSalesCents": row.gross_sales_cents,
                "taxableSalesCents": row.taxable_sales_cents,
                "exemptSalesCents": row.exempt_sales_cents,
                "taxCollectedCents": row.tax_collected_cents,
                "creditNoteCount": row.credit_note_count,
                "creditedTaxedCents": row.credited_taxed_cents,
                "creditedExemptCents": row.credited_exempt_cents,
                "creditedOtherCents": row.credited_other_cents,
                "netTaxableSalesCents": row.net_taxable_sales_cents,
                "netExemptSalesCents": row.net_exempt_sales_cents,
                "ratesUsed": row.rates_used.iter().map(|rate| serde_json::json!({
                    "rateBps": rate.rate_bps,
                    "rateKind": rate.rate_kind,
                    "source": rate.source,
                    "retrieved": rate.retrieved,
                    "invoices": rate.invoices,
                    "taxCents": rate.tax_cents,
                })).collect::<Vec<_>>(),
                "rateRow": row.rate_row.as_ref().map(|file_row| serde_json::json!({
                    "taxability": file_row.taxability,
                    "rateBps": file_row.rate_bps,
                    "combinedRateBps": file_row.combined_rate_bps,
                    "sourceUrl": file_row.source_url,
                    "retrieved": file_row.retrieved,
                    "fresh": file_row.fresh,
                    "criteria": file_row.criteria,
                    "nexusDeclarationError": file_row.nexus_declaration_error,
                })),
            })).collect::<Vec<_>>(),
            "totals": {
                "invoiceCount": self.totals.invoice_count,
                "grossSalesCents": self.totals.gross_sales_cents,
                "taxableSalesCents": self.totals.taxable_sales_cents,
                "exemptSalesCents": self.totals.exempt_sales_cents,
                "taxCollectedCents": self.totals.tax_collected_cents,
                "creditNoteCount": self.totals.credit_note_count,
                "creditedTaxedCents": self.totals.credited_taxed_cents,
                "creditedExemptCents": self.totals.credited_exempt_cents,
                "creditedOtherCents": self.totals.credited_other_cents,
                "netTaxableSalesCents": self.totals.net_taxable_sales_cents,
                "netExemptSalesCents": self.totals.net_exempt_sales_cents,
            },
            "gaps": {
                "unknownStateInvoices": self.gaps.unknown_state_invoices,
                "unknownStateGrossCents": self.gaps.unknown_state_gross_cents,
                "unknownStateTaxCents": self.gaps.unknown_state_tax_cents,
                "unattributedCreditNoteCount": self.gaps.unattributed_credit_note_count,
                "unattributedCreditNoteCents": self.gaps.unattributed_credit_note_cents,
                "nonUsd": self.gaps.non_usd.iter().map(|bucket| serde_json::json!({
                    "currency": bucket.currency,
                    "invoiceCount": bucket.invoice_count,
                    "grossSalesCents": bucket.gross_sales_cents,
                    "taxCollectedCents": bucket.tax_collected_cents,
                    "creditNoteCount": bucket.credit_note_count,
                    "creditNoteCents": bucket.credit_note_cents,
                })).collect::<Vec<_>>(),
                "creditNoteAttribution": "credit notes carry no state of their own; they are \
                                         attributed through the credited invoice's billing-address \
                                         state snapshot and dated by the credit's created_at \
                                         month",
            },
        })
    }

    /// The report as CSV: one row per state, then a TOTAL row. `ratesUsed`
    /// joins the stamps actually used in the period
    /// (`rateBps/rateKind/source/retrieved/invoices/taxCents`, `;`-joined).
    pub fn to_csv(&self) -> String {
        let mut out = String::new();
        out.push_str(
            "state,taxability,registrationStatus,invoiceCount,grossSalesCents,taxableSalesCents,\
             exemptSalesCents,taxCollectedCents,creditNoteCount,creditedTaxedCents,\
             creditedExemptCents,creditedOtherCents,netTaxableSalesCents,netExemptSalesCents,\
             ratesUsed\n",
        );
        for row in &self.states {
            let rates = row
                .rates_used
                .iter()
                .map(|rate| {
                    format!(
                        "{}/{}/{}/{}/{}/{}",
                        rate.rate_bps,
                        rate.rate_kind,
                        rate.source,
                        rate.retrieved,
                        rate.invoices,
                        rate.tax_cents
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                csv_field(&row.state),
                csv_field(&row.taxability),
                csv_field(&row.registration_status),
                row.invoice_count,
                row.gross_sales_cents,
                row.taxable_sales_cents,
                row.exempt_sales_cents,
                row.tax_collected_cents,
                row.credit_note_count,
                row.credited_taxed_cents,
                row.credited_exempt_cents,
                row.credited_other_cents,
                row.net_taxable_sales_cents,
                row.net_exempt_sales_cents,
                csv_field(&rates),
            ));
        }
        out.push_str(&format!(
            "TOTAL,,,{},{},{},{},{},{},{},{},{},{},{},\n",
            self.totals.invoice_count,
            self.totals.gross_sales_cents,
            self.totals.taxable_sales_cents,
            self.totals.exempt_sales_cents,
            self.totals.tax_collected_cents,
            self.totals.credit_note_count,
            self.totals.credited_taxed_cents,
            self.totals.credited_exempt_cents,
            self.totals.credited_other_cents,
            self.totals.net_taxable_sales_cents,
            self.totals.net_exempt_sales_cents,
        ));
        out
    }
}

/// RFC-4180-style escaping: quote when the field carries a comma, a quote or
/// a newline; double embedded quotes.
fn csv_field(raw: &str) -> String {
    if raw.contains(',') || raw.contains('"') || raw.contains('\n') || raw.contains('\r') {
        format!("\"{}\"", raw.replace('"', "\"\""))
    } else {
        raw.to_string()
    }
}

// ---------------------------------------------------------------------------
// Unit tests — the data file, the staleness gate, the money and the windows
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    /// A fixed validation clock for deterministic freshness assertions.
    fn today() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 10, 15).expect("valid date")
    }

    fn utc(year: i32, month: u32, day: u32, hour: u32, minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, minute, 0)
            .single()
            .expect("unambiguous instant")
    }

    /// One data-file row, as an owner would write it: a taxable state with a
    /// sales-criterion threshold.
    fn fixture_row(
        state: &str,
        rate_bps: u32,
        threshold_cents: i64,
        window: &str,
        retrieved: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "state": state,
            "taxability": "taxable",
            "rateBps": rate_bps,
            "nexusThresholdCents": threshold_cents,
            "nexusWindow": window,
            "sourceUrl": "https://example.gov/us-tax-fixture",
            "retrieved": retrieved,
        })
    }

    fn file_body(rows: &[serde_json::Value]) -> String {
        serde_json::json!({
            "schemaVersion": 2,
            "instructions": ["fixture"],
            "states": rows,
        })
        .to_string()
    }

    fn config(rows: &[serde_json::Value], max_age_days: u32) -> UsTaxConfig {
        UsTaxConfig {
            table: UsTaxTable::parse(&file_body(rows), today()).expect("fixture parses"),
            source: "test fixture".to_string(),
            max_age_days,
            warn_fraction_bps: DEFAULT_US_TAX_WARN_FRACTION_BPS,
        }
    }

    /// The COMMITTED file: it must stay valid, and it must stay EMPTY — a
    /// committed file carrying invented rates would be a fabricated claim
    /// about another jurisdiction's tax law.
    #[test]
    fn committed_rate_file_is_valid_empty_and_self_documenting() {
        let (table, instructions) =
            UsTaxTable::parse_with_instructions(embedded_data_file(), today())
                .expect("the committed data file must always validate");
        assert!(
            table.is_empty(),
            "the committed file ships empty on purpose; the owner fills states"
        );
        assert!(
            !instructions.is_empty(),
            "the committed file must document the fill-in contract for the owner"
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(embedded_data_file()).expect("valid JSON")
                ["schemaVersion"],
            US_TAX_SCHEMA_VERSION
        );
    }

    /// Every malformed shape is refused with a named error — `--check` must
    /// never pass a file that would make the money path guess.
    #[test]
    fn data_file_validation_refuses_every_bad_shape() {
        let cases: Vec<(String, &str)> = vec![
            (
                "{ not json".to_string(),
                "US sales tax data file is not valid JSON",
            ),
            (
                // v1 files are refused: this build reads the schema it can
                // honour, never an older shape.
                serde_json::json!({"schemaVersion": 1, "instructions": [], "states": []})
                    .to_string(),
                "schemaVersion 1",
            ),
            (
                serde_json::json!({"schemaVersion": 3, "instructions": [], "states": []})
                    .to_string(),
                "schemaVersion 3",
            ),
            (
                // A typo'd key must not be silently ignored.
                serde_json::json!({
                    "schemaVersion": 2, "instructions": [], "sttes": []
                })
                .to_string(),
                "not valid JSON",
            ),
            (
                file_body(&[serde_json::json!({
                    "state": "CA", "taxability": "taxable", "rateBps": 725,
                    "nexusThresholdCents": 50_000_000, "nexusWindow": "calendar",
                    "sourceUrl": "https://example.gov/x",
                    "retrieved": "2026-10-01", "rate": 725
                })]),
                "not valid JSON",
            ),
            (
                // A `taxable` row REQUIRES a rate.
                file_body(&[serde_json::json!({
                    "state": "CA", "taxability": "taxable",
                    "nexusThresholdCents": 50_000_000, "nexusWindow": "calendar",
                    "sourceUrl": "https://example.gov/x", "retrieved": "2026-10-01"
                })]),
                "REQUIRES rateBps",
            ),
            (
                // A combined rate without its own stamp is not usable.
                file_body(&[serde_json::json!({
                    "state": "CA", "taxability": "taxable", "rateBps": 725,
                    "combinedRateBps": 880,
                    "nexusThresholdCents": 50_000_000, "nexusWindow": "calendar",
                    "sourceUrl": "https://example.gov/x", "retrieved": "2026-10-01"
                })]),
                "combinedSourceUrl AND combinedRetrieved",
            ),
            (
                // The combined rate's own retrieved date obeys the same
                // no-future rule as the state stamp.
                file_body(&[serde_json::json!({
                    "state": "CA", "taxability": "taxable", "rateBps": 725,
                    "combinedRateBps": 880,
                    "combinedSourceUrl": "https://example.gov/combined",
                    "combinedRetrieved": "2026-10-16",
                    "nexusThresholdCents": 50_000_000, "nexusWindow": "calendar",
                    "sourceUrl": "https://example.gov/x", "retrieved": "2026-10-01"
                })]),
                "combinedRetrieved 2026-10-16 is in the future",
            ),
            (
                // A percent written as a combined basis points figure.
                file_body(&[serde_json::json!({
                    "state": "CA", "taxability": "taxable", "rateBps": 725,
                    "combinedRateBps": 88_000,
                    "combinedSourceUrl": "https://example.gov/combined",
                    "combinedRetrieved": "2026-10-01",
                    "nexusThresholdCents": 50_000_000, "nexusWindow": "calendar",
                    "sourceUrl": "https://example.gov/x", "retrieved": "2026-10-01"
                })]),
                "combinedRateBps",
            ),
            (
                // A dollar figure written where transactions belong.
                file_body(&[serde_json::json!({
                    "state": "CA", "taxability": "taxable", "rateBps": 725,
                    "transactionThreshold": 0, "criteria": "either",
                    "nexusThresholdCents": 50_000_000, "nexusWindow": "calendar",
                    "sourceUrl": "https://example.gov/x", "retrieved": "2026-10-01"
                })]),
                "transactions)",
            ),
            (
                file_body(&[fixture_row("ZZ", 725, 50_000_000, "calendar", "2026-10-01")]),
                "not a known US state",
            ),
            (
                file_body(&[fixture_row(
                    "California",
                    725,
                    50_000_000,
                    "calendar",
                    "2026-10-01",
                )]),
                "two-letter code",
            ),
            (
                // A percent written where basis points belong: 7.25 % = 725,
                // NOT 7.25.
                file_body(&[fixture_row(
                    "CA",
                    72_500,
                    50_000_000,
                    "calendar",
                    "2026-10-01",
                )]),
                "out of range",
            ),
            (
                // A dollar figure written where cents belong.
                file_body(&[fixture_row("CA", 725, 0, "calendar", "2026-10-01")]),
                "out of range",
            ),
            (
                file_body(&[fixture_row(
                    "CA",
                    725,
                    10_000_000_000_000,
                    "calendar",
                    "2026-10-01",
                )]),
                "out of range",
            ),
            (
                file_body(&[fixture_row(
                    "CA",
                    725,
                    50_000_000,
                    "quarterly",
                    "2026-10-01",
                )]),
                "nexusWindow",
            ),
            (
                file_body(&[serde_json::json!({
                    "state": "CA", "taxability": "taxable", "rateBps": 725,
                    "nexusThresholdCents": 50_000_000, "nexusWindow": "calendar",
                    "sourceUrl": "   ", "retrieved": "2026-10-01"
                })]),
                "sourceUrl is empty",
            ),
            (
                file_body(&[serde_json::json!({
                    "state": "CA", "taxability": "taxable", "rateBps": 725,
                    "nexusThresholdCents": 50_000_000, "nexusWindow": "calendar",
                    "sourceUrl": "http://example.gov/x", "retrieved": "2026-10-01"
                })]),
                "https://",
            ),
            (
                file_body(&[fixture_row("CA", 725, 50_000_000, "calendar", "2026-13-01")]),
                "YYYY-MM-DD",
            ),
            (
                // A rate cannot have been read tomorrow.
                file_body(&[fixture_row("CA", 725, 50_000_000, "calendar", "2026-10-16")]),
                "in the future",
            ),
        ];
        for (body, expected) in cases {
            let error = UsTaxTable::parse(&body, today())
                .expect_err(&format!("this body must be refused: {body}"));
            assert!(
                error.to_string().contains(expected),
                "error {error} must name {expected:?}"
            );
        }

        // Duplicate states are refused too (the second row is the ambiguity).
        let duplicated = file_body(&[
            fixture_row("CA", 725, 50_000_000, "calendar", "2026-10-01"),
            fixture_row("ca", 900, 50_000_000, "calendar", "2026-10-01"),
        ]);
        let error = UsTaxTable::parse(&duplicated, today()).expect_err("duplicate refused");
        assert!(error.to_string().contains("more than once"), "{error}");
    }

    /// Rows parse into the typed table, sorted, with the window normalised.
    #[test]
    fn data_file_rows_parse_sorted_and_normalised() {
        let table = UsTaxTable::parse(
            &file_body(&[
                fixture_row("tx", 625, 50_000_000, "trailing_12m", "2026-10-01"),
                fixture_row("CA", 725, 50_000_000, "calendar", "2026-10-01"),
            ]),
            today(),
        )
        .expect("valid file");
        assert_eq!(table.len(), 2);
        assert_eq!(table.rows()[0].state, "CA");
        assert_eq!(table.rows()[1].state, "TX");
        assert_eq!(
            table.rows()[1].nexus_window,
            Some(NexusWindow::Trailing12Months)
        );
        assert_eq!(
            table.rows()[0].nexus_window,
            Some(NexusWindow::CalendarYear)
        );
        assert_eq!(table.rows()[0].taxability, Taxability::Taxable);
        assert!(table.row("ca").is_some(), "lookup normalises the code");
        assert!(table.row("NY").is_none());
        assert!(!table.is_empty());
    }

    /// Taxability defaults to not_taxable: an absent field or an
    /// unrecognised spelling never charges, and the fallback is REPORTED
    /// (notices), never silent. Figures on a not_taxable row are dead data —
    /// reported as a notice, never a reason to block the file; the safe
    /// direction is not collecting, not refusing everything.
    #[test]
    fn taxability_defaults_to_not_taxable_and_reports_unknown_spellings() {
        let table = UsTaxTable::parse(
            &file_body(&[
                serde_json::json!({
                    "state": "CA", "nexusWindow": "calendar",
                    "sourceUrl": "https://example.gov/ca", "retrieved": "2026-10-01"
                }),
                serde_json::json!({
                    "state": "TX", "taxability": "taxablee", "rateBps": 625,
                    "nexusThresholdCents": 50_000_000, "nexusWindow": "calendar",
                    "sourceUrl": "https://example.gov/tx", "retrieved": "2026-10-01"
                }),
                serde_json::json!({
                    "state": "NY", "taxability": "not_taxable", "rateBps": 400,
                    "sourceUrl": "https://example.gov/ny", "retrieved": "2026-10-01"
                }),
            ]),
            today(),
        )
        .expect("all rows parse (the safe direction is never a file refusal)");
        for row in table.rows() {
            assert_eq!(row.taxability, Taxability::NotTaxable);
            assert_eq!(row.effective_rate(), None);
            assert_eq!(row.nexus_declaration().expect("not an error"), None);
        }
        let ca = table.row("CA").expect("CA");
        assert_eq!(ca.taxability_notice, None);
        assert_eq!(ca.unused_figures_notice, None, "no figures carried");

        let tx = table.row("TX").expect("TX");
        let notice = tx
            .taxability_notice
            .as_deref()
            .expect("unrecognised spelling is reported, not silent");
        assert!(notice.contains("taxablee"), "{notice}");
        assert!(notice.contains("not_taxable"), "{notice}");
        let unused = tx
            .unused_figures_notice
            .as_deref()
            .expect("the dead rate is reported");
        assert!(unused.contains("NOT used"), "{unused}");

        // Explicit not_taxable + figures: the same notice, no refusal.
        let ny = table.row("NY").expect("NY");
        assert_eq!(ny.taxability_notice, None);
        assert!(
            ny.unused_figures_notice.is_some(),
            "a not_taxable row's rate is dead data and must be reported"
        );
    }

    /// A declared criterion whose threshold (or window) is missing refuses
    /// the state with a named reason — and only when declared in the wrong
    /// shape, never for a clean row.
    #[test]
    fn nexus_declarations_require_exactly_the_declared_thresholds() {
        let parse_row = |value: serde_json::Value| -> UsTaxStateRow {
            UsTaxTable::parse(&file_body(&[value]), today())
                .expect("the row parses; the declaration check happens later")
                .rows()[0]
                .clone()
        };
        let taxable = |extra: serde_json::Value| {
            let mut base = serde_json::json!({
                "state": "CA", "taxability": "taxable", "rateBps": 725,
                "sourceUrl": "https://example.gov/ca", "retrieved": "2026-10-01"
            });
            let map = base.as_object_mut().expect("object");
            for (key, value) in extra.as_object().expect("object") {
                map.insert(key.clone(), value.clone());
            }
            base
        };

        // sales (the default) needs the sales threshold + window.
        let missing_sales = parse_row(taxable(serde_json::json!({
            "nexusWindow": "calendar"
        })));
        let error = missing_sales.nexus_declaration().expect_err("missing");
        assert!(error.contains("nexusThresholdCents"), "{error}");
        assert!(error.contains("data error"), "{error}");

        // …and a window.
        let missing_window = parse_row(taxable(serde_json::json!({
            "nexusThresholdCents": 50_000_000
        })));
        let error = missing_window.nexus_declaration().expect_err("missing");
        assert!(error.contains("nexusWindow"), "{error}");

        // sales must NOT also carry the transaction threshold (dead data).
        let sales_with_extra = parse_row(taxable(serde_json::json!({
            "nexusThresholdCents": 50_000_000, "transactionThreshold": 200,
            "nexusWindow": "calendar"
        })));
        let error = sales_with_extra.nexus_declaration().expect_err("extra");
        assert!(error.contains("either"), "{error}");

        // transactions needs the transaction threshold and no sales one.
        let transactions_missing = parse_row(taxable(serde_json::json!({
            "criteria": "transactions", "nexusWindow": "calendar"
        })));
        let error = transactions_missing
            .nexus_declaration()
            .expect_err("missing");
        assert!(error.contains("transactionThreshold"), "{error}");

        let transactions_ok = parse_row(taxable(serde_json::json!({
            "criteria": "transactions", "transactionThreshold": 200,
            "nexusWindow": "calendar"
        })));
        let declaration = transactions_ok
            .nexus_declaration()
            .expect("valid")
            .expect("declared");
        assert_eq!(declaration.criteria, NexusCriteria::Transactions);
        assert_eq!(declaration.transaction_threshold, Some(200));
        assert_eq!(declaration.sales_threshold_cents, None);

        // either needs BOTH.
        let either_missing = parse_row(taxable(serde_json::json!({
            "criteria": "either", "nexusThresholdCents": 50_000_000,
            "nexusWindow": "calendar"
        })));
        let error = either_missing.nexus_declaration().expect_err("missing");
        assert!(error.contains("BOTH"), "{error}");

        let either_ok = parse_row(taxable(serde_json::json!({
            "criteria": "either", "nexusThresholdCents": 50_000_000,
            "transactionThreshold": 200, "nexusWindow": "trailing_12m"
        })));
        let declaration = either_ok.nexus_declaration().expect("valid").expect("some");
        assert_eq!(declaration.criteria, NexusCriteria::Either);
        assert_eq!(declaration.window, NexusWindow::Trailing12Months);

        // An unrecognised criteria spelling is a data error too — never a
        // guessed criterion.
        let bad_criteria = parse_row(taxable(serde_json::json!({
            "criteria": "quarterly", "nexusThresholdCents": 50_000_000,
            "nexusWindow": "calendar"
        })));
        let error = bad_criteria.nexus_declaration().expect_err("bad");
        assert!(error.contains("quarterly"), "{error}");
    }

    /// The combined rate is preferred when present, with its OWN stamp — the
    /// same staleness rule applies to whichever stamp is used.
    #[test]
    fn combined_rate_is_preferred_with_its_own_stamp_and_staleness() {
        let combined = UsTaxTable::parse(
            &file_body(&[serde_json::json!({
                "state": "CA", "taxability": "taxable", "rateBps": 725,
                "combinedRateBps": 880,
                "combinedSourceUrl": "https://example.gov/ca-combined",
                "combinedRetrieved": "2026-10-10",
                "nexusThresholdCents": 50_000_000, "nexusWindow": "calendar",
                "sourceUrl": "https://example.gov/ca", "retrieved": "2026-01-01"
            })]),
            today(),
        )
        .expect("valid")
        .rows()[0]
            .clone();
        let used = combined.effective_rate().expect("a rate");
        assert_eq!(used.rate_bps, 880);
        assert_eq!(used.kind, RateKind::Combined);
        assert_eq!(used.source_url, "https://example.gov/ca-combined");
        assert_eq!(
            used.retrieved,
            NaiveDate::from_ymd_opt(2026, 10, 10).expect("date")
        );
        // The USED stamp governs freshness: the stale state stamp (286 days
        // old) does not refuse while the combined stamp is fresh…
        let config = UsTaxConfig {
            table: UsTaxTable::parse(
                &file_body(&[serde_json::json!({
                    "state": "CA", "taxability": "taxable", "rateBps": 725,
                    "combinedRateBps": 880,
                    "combinedSourceUrl": "https://example.gov/ca-combined",
                    "combinedRetrieved": "2026-10-10",
                    "nexusThresholdCents": 50_000_000, "nexusWindow": "calendar",
                    "sourceUrl": "https://example.gov/ca", "retrieved": "2026-01-01"
                })]),
                today(),
            )
            .expect("valid"),
            source: "test fixture".to_string(),
            max_age_days: 120,
            warn_fraction_bps: DEFAULT_US_TAX_WARN_FRACTION_BPS,
        };
        assert!(config.fresh_row("CA", today()).is_ok());
        // …while a stale COMBINED stamp refuses, naming the combined source.
        let stale_combined = UsTaxConfig {
            table: UsTaxTable::parse(
                &file_body(&[serde_json::json!({
                    "state": "CA", "taxability": "taxable", "rateBps": 725,
                    "combinedRateBps": 880,
                    "combinedSourceUrl": "https://example.gov/ca-combined",
                    "combinedRetrieved": "2026-01-01",
                    "nexusThresholdCents": 50_000_000, "nexusWindow": "calendar",
                    "sourceUrl": "https://example.gov/ca", "retrieved": "2026-10-10"
                })]),
                today(),
            )
            .expect("valid"),
            source: "test fixture".to_string(),
            max_age_days: 120,
            warn_fraction_bps: DEFAULT_US_TAX_WARN_FRACTION_BPS,
        };
        let error = stale_combined
            .fresh_row("CA", today())
            .expect_err("stale combined stamp refuses");
        assert!(error.to_string().contains("STALE"), "{error}");
        assert!(error.to_string().contains("ca-combined"), "{error}");

        // A state-rate-only row still uses the state stamp.
        let state_only = UsTaxTable::parse(
            &file_body(&[fixture_row("TX", 625, 50_000_000, "calendar", "2026-10-01")]),
            today(),
        )
        .expect("valid")
        .rows()[0]
            .clone();
        let used = state_only.effective_rate().expect("a rate");
        assert_eq!(used.kind, RateKind::State);
        assert_eq!(used.rate_bps, 625);
    }

    /// The warning fraction parser is integer-only, exact, and refuses
    /// everything it cannot honour.
    #[test]
    fn warn_fraction_parsing_is_exact_and_refuses_bad_values() {
        assert_eq!(DEFAULT_US_TAX_WARN_FRACTION_BPS, 8_000);
        assert_eq!(parse_warn_fraction_bps("0.8"), Some(8_000));
        assert_eq!(parse_warn_fraction_bps(" 0.80 "), Some(8_000));
        assert_eq!(parse_warn_fraction_bps("0.85"), Some(8_500));
        assert_eq!(parse_warn_fraction_bps("0.5"), Some(5_000));
        assert_eq!(parse_warn_fraction_bps("0.875"), Some(8_750));
        assert_eq!(parse_warn_fraction_bps("0.0001"), Some(1));
        assert_eq!(parse_warn_fraction_bps("1"), Some(10_000));
        assert_eq!(parse_warn_fraction_bps("1.0"), Some(10_000));
        for bad in [
            "", "0", "0.0", "1.5", "1.0001", "-0.5", ".8", "0.", "0.12345", "abc", "0,8", "8000",
        ] {
            assert_eq!(parse_warn_fraction_bps(bad), None, "{bad:?} must refuse");
        }
        let error = UsTaxError::InvalidWarnFraction {
            raw: "soon".to_string(),
            env: US_TAX_WARN_FRACTION_ENV,
        };
        assert!(
            error.to_string().contains("US_TAX_WARN_FRACTION"),
            "{error}"
        );
    }

    /// The warning threshold is exact at its boundary for BOTH measures, and
    /// a crossing is never a warning.
    #[test]
    fn warn_fraction_boundaries_are_exact_for_both_criteria() {
        let declaration = NexusDeclaration {
            criteria: NexusCriteria::Either,
            sales_threshold_cents: Some(10_000_000),
            transaction_threshold: Some(200),
            window: NexusWindow::CalendarYear,
        };
        // 0.8 × $100,000.00 = $80,000.00 exactly.
        let below = NexusMeasures {
            sales_cents: 7_999_999,
            transactions: 159,
            exempt_cents: 0,
        };
        assert!(warn_triggers(&declaration, below, 8_000).is_empty());
        let at_sales = NexusMeasures {
            sales_cents: 8_000_000,
            ..below
        };
        assert_eq!(warn_triggers(&declaration, at_sales, 8_000), vec!["sales"]);
        // 0.8 × 200 = 160 exactly.
        let at_count = NexusMeasures {
            sales_cents: 7_999_999,
            transactions: 160,
            exempt_cents: 0,
        };
        assert_eq!(
            warn_triggers(&declaration, at_count, 8_000),
            vec!["transactions"]
        );
        let both = NexusMeasures {
            sales_cents: 8_000_000,
            transactions: 160,
            exempt_cents: 0,
        };
        assert_eq!(
            warn_triggers(&declaration, both, 8_000),
            vec!["sales", "transactions"]
        );

        // The verdict boundaries: threshold − 1 below, exactly the
        // threshold crossed — for both measures.
        assert_eq!(evaluate_nexus_count(199, 200), NexusVerdict::Below);
        assert_eq!(evaluate_nexus_count(200, 200), NexusVerdict::Crossed);
        assert_eq!(evaluate_nexus_count(201, 200), NexusVerdict::Crossed);
        assert_eq!(declared_verdict(&declaration, below), NexusVerdict::Below);
        assert_eq!(
            declared_verdict(
                &declaration,
                NexusMeasures {
                    sales_cents: 9_999_999,
                    transactions: 200,
                    exempt_cents: 0
                }
            ),
            NexusVerdict::Crossed,
            "either criterion crossing is a crossing"
        );
        // A measure the row does not declare is never compared.
        let sales_only = NexusDeclaration {
            criteria: NexusCriteria::Sales,
            sales_threshold_cents: Some(10_000_000),
            transaction_threshold: None,
            window: NexusWindow::CalendarYear,
        };
        assert_eq!(
            declared_verdict(
                &sales_only,
                NexusMeasures {
                    sales_cents: 0,
                    transactions: 10_000,
                    exempt_cents: 0
                }
            ),
            NexusVerdict::Below
        );
        assert!(warn_triggers(
            &sales_only,
            NexusMeasures {
                sales_cents: 0,
                transactions: 10_000,
                exempt_cents: 0
            },
            8_000
        )
        .is_empty());
    }

    /// The report period parser is strict: a period is never guessed.
    #[test]
    fn report_period_parsing_is_strict() {
        let period = UsTaxReportPeriod::parse("2026-10").expect("valid");
        assert_eq!(period.year, 2026);
        assert_eq!(period.month, 10);
        assert_eq!(period.label(), "2026-10");
        assert_eq!(period.start, utc(2026, 10, 1, 0, 0));
        assert_eq!(period.end, utc(2026, 11, 1, 0, 0));
        let december = UsTaxReportPeriod::parse("2025-12").expect("valid");
        assert_eq!(december.end, utc(2026, 1, 1, 0, 0), "year rolls over");
        for bad in [
            "",
            "2026",
            "2026-1",
            "2026-13",
            "2026-00",
            "26-10",
            "2026-10-01",
            "2026/10",
            "abcd-10",
        ] {
            assert!(
                UsTaxReportPeriod::parse(bad).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    /// CSV fields are escaped per RFC 4180: a comma-bearing source URL cannot
    /// split a row.
    #[test]
    fn csv_fields_escape_commas_quotes_and_newlines() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("two\nlines"), "\"two\nlines\"");
        assert_eq!(csv_field(""), "");
    }

    /// The staleness gate is exact at its boundary, and a missing row is its
    /// own named refusal — the two ways a computation must never proceed.
    #[test]
    fn rate_rows_fail_closed_when_missing_or_stale() {
        // 2026-10-15 minus 2026-06-17 = exactly 120 days.
        let exact = config(
            &[fixture_row("CA", 725, 50_000_000, "calendar", "2026-06-17")],
            120,
        );
        assert!(
            exact.fresh_row("CA", today()).is_ok(),
            "exactly 120 days is fresh"
        );

        let one_over = config(
            &[fixture_row("CA", 725, 50_000_000, "calendar", "2026-06-16")],
            120,
        );
        let error = one_over
            .fresh_row("CA", today())
            .expect_err("121 days must refuse");
        match &error {
            UsTaxError::StaleRateRow {
                state,
                age_days,
                max_age_days,
                ..
            } => {
                assert_eq!(state, "CA");
                assert_eq!(*age_days, 121);
                assert_eq!(*max_age_days, 120);
            }
            other => panic!("expected StaleRateRow, got {other:?}"),
        }
        assert!(error.to_string().contains("STALE"), "{error}");
        assert!(
            error
                .to_string()
                .contains("https://example.gov/us-tax-fixture"),
            "the refusal names where to refresh from: {error}"
        );

        let missing = config(&[], 120);
        let error = missing
            .fresh_row("CA", today())
            .expect_err("a registered state with no row must refuse");
        assert!(
            matches!(error, UsTaxError::MissingRateRow { ref state } if state == "CA"),
            "{error}"
        );

        // A row is fresh for its whole max-age day count, then not.
        let row = UsTaxTable::parse(
            &file_body(&[fixture_row("CA", 725, 50_000_000, "calendar", "2026-10-15")]),
            today(),
        )
        .expect("valid")
        .rows()[0]
            .clone();
        assert!(is_row_fresh(&row, today(), 0), "a same-day row is fresh");
        assert!(!is_row_fresh(
            &row,
            today().succ_opt().expect("next day"),
            0
        ));
    }

    /// The `US_TAX_MAX_AGE_DAYS` override is honoured, and a value that is
    /// not a day count refuses instead of silently defaulting.
    #[test]
    fn max_age_override_refuses_unparseable_values() {
        assert_eq!(DEFAULT_US_TAX_MAX_AGE_DAYS, 120);
        let error = UsTaxError::InvalidMaxAge {
            raw: "soon".to_string(),
            env: US_TAX_MAX_AGE_DAYS_ENV,
        };
        assert!(error.to_string().contains("US_TAX_MAX_AGE_DAYS"), "{error}");
    }

    /// Sales tax rounds half-up ONCE, in integer basis points: the exact
    /// half-cent and just-below boundaries.
    #[test]
    fn sales_tax_rounds_half_up_once_per_line() {
        // 7.25 % of $1.00 = 7.25 cents → 7 (the fraction is under half).
        assert_eq!(sales_tax_cents(100, 725), 7);
        // 7.25 % of $1.04 = 7.54 cents → 8.
        assert_eq!(sales_tax_cents(104, 725), 8);
        // Exactly half a cent rounds UP: $10.00 × 5 bps = 0.5 cents → 1.
        assert_eq!(sales_tax_cents(1_000, 5), 1);
        // One cent less is under half: $9.99 × 5 bps = 0.4995 → 0.
        assert_eq!(sales_tax_cents(999, 5), 0);
        // 6 % of 8 cents = 0.48 → 0; of 9 cents = 0.54 → 1.
        assert_eq!(sales_tax_cents(8, 600), 0);
        assert_eq!(sales_tax_cents(9, 600), 1);
        // A zero rate and a zero/negative base are exactly zero, never a
        // credit.
        assert_eq!(sales_tax_cents(12_345, 0), 0);
        assert_eq!(sales_tax_cents(0, 725), 0);
        assert_eq!(sales_tax_cents(-500, 725), 0);
        // Large amounts keep exact integer precision: $1,000,000.00 at 20 %.
        assert_eq!(sales_tax_cents(100_000_000, 2_000), 20_000_000);
    }

    /// The nexus verdict at the exact boundary: threshold − 1 cent is below,
    /// exactly the threshold is a crossing.
    #[test]
    fn nexus_verdict_is_exact_at_the_threshold() {
        let threshold = 10_000_000; // $100,000.00
        assert_eq!(
            evaluate_nexus(threshold - 1, threshold),
            NexusVerdict::Below
        );
        assert_eq!(evaluate_nexus(threshold, threshold), NexusVerdict::Crossed);
        assert_eq!(
            evaluate_nexus(threshold + 1, threshold),
            NexusVerdict::Crossed
        );
        assert_eq!(evaluate_nexus(0, threshold), NexusVerdict::Below);
        assert!(NexusVerdict::Crossed.is_crossed());
        assert!(!NexusVerdict::Below.is_crossed());
        assert_eq!(NexusVerdict::Below.as_str(), "below");
        assert_eq!(NexusVerdict::Crossed.as_str(), "threshold_crossed");
    }

    /// The two windows have pinned, half-open bounds: `[start, end)`.
    #[test]
    fn nexus_windows_have_pinned_half_open_bounds() {
        let now = utc(2026, 10, 15, 12, 30);
        let (start, end) = NexusWindow::CalendarYear.bounds(now);
        assert_eq!(start, utc(2026, 1, 1, 0, 0));
        assert_eq!(end, utc(2027, 1, 1, 0, 0));
        // The instant at the start counts; the instant at the end does not.
        assert!(start <= now && now < end);
        assert!(!(utc(2025, 12, 31, 23, 59) >= start));
        assert!(utc(2026, 1, 1, 0, 0) >= start);
        assert!(utc(2026, 12, 31, 23, 59) < end);
        assert!(!(utc(2027, 1, 1, 0, 0) < end));

        let (start, end) = NexusWindow::Trailing12Months.bounds(now);
        assert_eq!(end, now);
        assert_eq!(start, utc(2025, 10, 15, 12, 30));

        // Calendar arithmetic clamps a leap day to the last valid day.
        let leap_day = utc(2028, 2, 29, 0, 0);
        let (start, _) = NexusWindow::Trailing12Months.bounds(leap_day);
        assert_eq!(start, utc(2027, 2, 28, 0, 0));

        assert_eq!(
            NexusWindow::parse("calendar"),
            Some(NexusWindow::CalendarYear)
        );
        assert_eq!(
            NexusWindow::parse(" trailing_12m "),
            Some(NexusWindow::Trailing12Months)
        );
        assert_eq!(NexusWindow::parse("year"), None);
        assert_eq!(NexusWindow::CalendarYear.as_str(), "calendar");
        assert_eq!(NexusWindow::Trailing12Months.as_str(), "trailing_12m");
    }

    /// State codes are normalised, never guessed: free text is UNKNOWN.
    #[test]
    fn state_codes_are_normalized_never_guessed() {
        assert_eq!(normalize_state_code(Some(" ca ")), Some("CA".to_string()));
        assert_eq!(normalize_state_code(Some("pr")), Some("PR".to_string()));
        assert_eq!(normalize_state_code(Some("California")), None);
        assert_eq!(normalize_state_code(Some("C")), None);
        assert_eq!(normalize_state_code(Some("")), None);
        assert_eq!(normalize_state_code(Some("N/A")), None);
        assert_eq!(normalize_state_code(None), None);
        assert!(is_us_state_code("DC"));
        assert!(!is_us_state_code("XX"));
        // The list is the standard 50 states + DC + the inhabited
        // territories, with no duplicates.
        assert_eq!(US_STATE_CODES.len(), 56);
        let mut sorted = US_STATE_CODES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 56, "no duplicates in the reference list");
        for code in US_STATE_CODES {
            assert_eq!(code.len(), 2, "{code} is a two-letter code");
            assert!(
                code.chars().all(|c| c.is_ascii_uppercase()),
                "{code} is upper-case"
            );
        }
    }

    /// The stamp on the tax line carries everything a reader needs to check
    /// the number: state, rate (and which rate), source, retrieved date —
    /// and the snapshot records both rated figures plus the used one.
    #[test]
    fn tax_line_stamp_carries_state_rate_source_and_retrieved_date() {
        let line = UsSalesTaxLine {
            state: "CA".to_string(),
            rate_bps: 725,
            rate_kind: RateKind::State,
            state_rate_bps: Some(725),
            combined_rate_bps: None,
            amount_cents: 790,
            source_url: "https://example.gov/us-tax-fixture".to_string(),
            retrieved: NaiveDate::from_ymd_opt(2026, 10, 1).expect("date"),
        };
        let description = line.description();
        assert!(description.contains("US sales tax (CA)"), "{description}");
        assert!(description.contains("7.25 %"), "{description}");
        assert!(description.contains("state rate"), "{description}");
        assert!(
            description.contains("https://example.gov/us-tax-fixture"),
            "{description}"
        );
        assert!(description.contains("2026-10-01"), "{description}");

        let snapshot = line.snapshot_json();
        assert_eq!(snapshot["snapshotVersion"], US_SALES_TAX_SNAPSHOT_VERSION);
        assert_eq!(snapshot["state"], "CA");
        assert_eq!(snapshot["rateBps"], 725);
        assert_eq!(snapshot["rateKind"], "state");
        assert_eq!(snapshot["stateRateBps"], 725);
        assert_eq!(snapshot["combinedRateBps"], serde_json::Value::Null);
        assert_eq!(snapshot["amountCents"], 790);
        assert_eq!(snapshot["source"], "https://example.gov/us-tax-fixture");
        assert_eq!(snapshot["retrieved"], "2026-10-01");
        assert_eq!(snapshot["exempt"], serde_json::Value::Null);

        // A combined-rate line says so in the description and records both.
        let combined = UsSalesTaxLine {
            rate_bps: 880,
            rate_kind: RateKind::Combined,
            state_rate_bps: Some(725),
            combined_rate_bps: Some(880),
            source_url: "https://example.gov/ca-combined".to_string(),
            ..line.clone()
        };
        let description = combined.description();
        assert!(description.contains("8.80 %"), "{description}");
        assert!(description.contains("combined rate"), "{description}");
        let snapshot = combined.snapshot_json();
        assert_eq!(snapshot["rateKind"], "combined");
        assert_eq!(snapshot["rateBps"], 880);
        assert_eq!(snapshot["stateRateBps"], 725);
        assert_eq!(snapshot["combinedRateBps"], 880);
        assert_eq!(snapshot["source"], "https://example.gov/ca-combined");

        // Whole-percent and sub-percent rates format exactly, never as a
        // float.
        let whole = UsSalesTaxLine {
            rate_bps: 700,
            ..line.clone()
        };
        assert!(
            whole.description().contains("7.00 %"),
            "{}",
            whole.description()
        );
        let tiny = UsSalesTaxLine {
            rate_bps: 5,
            ..line.clone()
        };
        assert!(
            tiny.description().contains("0.05 %"),
            "{}",
            tiny.description()
        );

        // The exemption snapshot: zero amount WITH its substantiation, so a
        // zero-tax invoice is never confused with "no US tax context".
        let exempt = UsSalesTaxExemption {
            state: "CA".to_string(),
            certificate_id: "MTC-12345".to_string(),
            certificate_expires_at: NaiveDate::from_ymd_opt(2027, 3, 31),
        };
        let snapshot = exempt.snapshot_json();
        assert_eq!(snapshot["snapshotVersion"], US_SALES_TAX_SNAPSHOT_VERSION);
        assert_eq!(snapshot["state"], "CA");
        assert_eq!(snapshot["exempt"], true);
        assert_eq!(snapshot["certificateId"], "MTC-12345");
        assert_eq!(snapshot["certificateExpiresAt"], "2027-03-31");
        assert_eq!(snapshot["amountCents"], 0);
        let open_ended = UsSalesTaxExemption {
            certificate_expires_at: None,
            ..exempt.clone()
        };
        assert_eq!(
            open_ended.snapshot_json()["certificateExpiresAt"],
            serde_json::Value::Null
        );
    }

    /// The `--check` report lists every row with its taxability, criteria
    /// and freshness, prints the owner instructions while nothing is
    /// configured, and surfaces per-state data errors separately.
    #[test]
    fn check_report_renders_rows_and_instructions() {
        let report = UsTaxDataCheckReport {
            source: "<embedded>".to_string(),
            max_age_days: 120,
            warn_fraction_bps: 8_000,
            today: today(),
            rows: vec!["CA: taxable — 725 bps state rate …".to_string()],
            declaration_errors: Vec::new(),
            instructions: vec!["fill me".to_string()],
        };
        let rendered = report.render();
        assert!(rendered.contains("<embedded>"), "{rendered}");
        assert!(rendered.contains("CA: taxable"), "{rendered}");
        assert!(rendered.contains("8000 bps"), "{rendered}");
        assert!(
            !rendered.contains("fill me"),
            "instructions render only when empty"
        );

        let empty = UsTaxDataCheckReport {
            rows: Vec::new(),
            ..report.clone()
        };
        let rendered = empty.render();
        assert!(rendered.contains("no states configured"), "{rendered}");
        assert!(rendered.contains("| fill me"), "{rendered}");

        let with_errors = UsTaxDataCheckReport {
            declaration_errors: vec!["TX: criteria \"either\" requires BOTH …".to_string()],
            ..report
        };
        let rendered = with_errors.render();
        assert!(rendered.contains("DATA ERRORS"), "{rendered}");
        assert!(rendered.contains("! TX:"), "{rendered}");

        // The committed file validates through the real entry point.
        let checked = check_data_file(today()).expect("committed file checks clean");
        assert!(checked.rows.is_empty());
        assert!(checked.declaration_errors.is_empty());
        assert_eq!(checked.max_age_days, DEFAULT_US_TAX_MAX_AGE_DAYS);
        assert_eq!(checked.warn_fraction_bps, DEFAULT_US_TAX_WARN_FRACTION_BPS);
        assert!(
            checked.instructions.len() > 5,
            "the fill-in contract travels"
        );
    }

    /// The freshness line of the check report names staleness explicitly.
    #[test]
    fn check_report_marks_stale_rows() {
        let table = UsTaxTable::parse(
            &file_body(&[
                fixture_row("CA", 725, 50_000_000, "calendar", "2026-10-01"),
                fixture_row("TX", 625, 50_000_000, "trailing_12m", "2026-04-01"),
            ]),
            today(),
        )
        .expect("valid");
        let rows: Vec<String> = table
            .rows()
            .iter()
            .map(|row| {
                let age = row_age_days(row, today());
                if is_row_fresh(row, today(), 120) {
                    format!("{}: fresh ({age} days old)", row.state)
                } else {
                    format!("{}: STALE ({age} days old)", row.state)
                }
            })
            .collect();
        assert_eq!(rows[0], "CA: fresh (14 days old)");
        assert!(rows[1].contains("TX: STALE (197 days old)"), "{rows:?}");
    }
}

// ---------------------------------------------------------------------------
// Adversarial coverage tests (DB backed) — the sweep, the operator surface
// and the stamped tax line end to end.
//
// Every test provisions its own canonical database clone (private, dropped on
// finish); `TEST_DATABASE_URL` unset → soft-skip (the workspace convention), a
// configured provisioning failure panics. The rate table comes from the test
// override (see [`set_test_table`]): the committed file ships empty on
// purpose, and the process environment cannot be mutated safely in a
// parallel test binary — so the money path is exercised against an explicit
// fixture table, serialized by [`TEST_TABLE_LOCK`].
// ---------------------------------------------------------------------------

#[cfg(test)]
mod coverage_adversarial {
    use super::*;
    use crate::invoices::{create_invoice, CreateInvoiceInput, InvoiceError, NewLineItem};
    use chrono::Duration;
    use sqlx::PgPool;
    use std::sync::Arc;
    use uuid::Uuid;

    struct Env {
        state: Arc<AppState>,
        pool: PgPool,
    }

    macro_rules! env_test {
        ($name:ident, |$e:ident| $body:block) => {
            #[tokio::test]
            async fn $name() {
                // Serialised: these tests install a process-wide rate table.
                let _table_guard = TEST_TABLE_LOCK.lock().await;
                let Some(owned) = crate::test_support::provision(stringify!($name)).await else {
                    return;
                };
                let $e = &Env {
                    state: owned.state.clone(),
                    pool: owned.pool.clone(),
                };
                $body
                set_test_table(None);
                owned.finish().await;
            }
        };
    }

    /// Test-only source label. Deliberately not a real state page: nothing in
    /// this file is shippable rate data.
    const FIXTURE_SOURCE: &str = "https://example.gov/us-tax-test-fixture";

    /// $100,000.00 — the fixture threshold most tests use.
    const THRESHOLD: i64 = 10_000_000;

    fn fixture_row(
        state: &str,
        rate_bps: u32,
        threshold_cents: i64,
        window: &str,
        retrieved: NaiveDate,
    ) -> serde_json::Value {
        serde_json::json!({
            "state": state,
            "taxability": "taxable",
            "rateBps": rate_bps,
            "nexusThresholdCents": threshold_cents,
            "nexusWindow": window,
            "sourceUrl": FIXTURE_SOURCE,
            "retrieved": retrieved.to_string(),
        })
    }

    fn today() -> NaiveDate {
        Utc::now().date_naive()
    }

    fn fixture_config(rows: &[serde_json::Value], max_age_days: u32) -> UsTaxConfig {
        fixture_config_with_warn(rows, max_age_days, DEFAULT_US_TAX_WARN_FRACTION_BPS)
    }

    fn fixture_config_with_warn(
        rows: &[serde_json::Value],
        max_age_days: u32,
        warn_fraction_bps: u32,
    ) -> UsTaxConfig {
        let body = serde_json::json!({
            "schemaVersion": 2,
            "instructions": ["fixture"],
            "states": rows,
        })
        .to_string();
        UsTaxConfig {
            table: UsTaxTable::parse(&body, today()).expect("fixture table parses"),
            source: "test fixture".to_string(),
            max_age_days,
            warn_fraction_bps,
        }
    }

    fn install_table(rows: &[serde_json::Value]) -> UsTaxConfig {
        let config = fixture_config(rows, 120);
        set_test_table(Some(config.clone()));
        config
    }

    async fn seed_tenant(env: &Env, tenant: &str, country: &str, state: Option<&str>) {
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status) VALUES ($1, $2, 'growth', 'active')
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant)
        .bind(format!("US tax {tenant}"))
        .execute(&env.pool)
        .await
        .expect("seed tenant");
        sqlx::query(
            "INSERT INTO billing_addresses (tenant_id, company_name, country, state)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (tenant_id) DO UPDATE SET country = $3, state = $4",
        )
        .bind(tenant)
        .bind(format!("US tax {tenant} OÜ"))
        .bind(country)
        .bind(state)
        .execute(&env.pool)
        .await
        .expect("seed billing address");
    }

    /// The tenant row an invoice needs (the sweep reads `invoices` alone, so
    /// no billing address row is required for these fixtures).
    async fn ensure_tenant(env: &Env, tenant: &str) {
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status) VALUES ($1, $2, 'growth', 'active')
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant)
        .bind(format!("US tax {tenant}"))
        .execute(&env.pool)
        .await
        .expect("ensure tenant");
    }

    /// Seed an invoice row directly: the sweep reads the invoices table, so
    /// fixtures are independent of the writer under test. (The long argument
    /// list is the fixture shape under test — each field is a dimension a case
    /// varies.)
    #[allow(clippy::too_many_arguments)]
    async fn seed_invoice(
        env: &Env,
        tenant: &str,
        currency: &str,
        country: &str,
        address: Option<serde_json::Value>,
        subtotal_cents: i64,
        issued_at: DateTime<Utc>,
        status: &str,
    ) -> Uuid {
        ensure_tenant(env, tenant).await;
        sqlx::query_scalar(
            "INSERT INTO invoices (
                 id, tenant_id, invoice_number, status, currency, amount, subtotal,
                 vat_total, total, issued_at, billing_country, billing_address,
                 us_sales_tax_cents, created_at, updated_at
             ) VALUES (
                 gen_random_uuid(), $1, $2, $3, $4, $5, $5, 0, $5, $6, $7, $8, 0, $6, $6
             ) RETURNING id",
        )
        .bind(tenant)
        .bind(format!("TAX-{}", Uuid::new_v4()))
        .bind(status)
        .bind(currency)
        .bind(subtotal_cents)
        .bind(issued_at)
        .bind(country)
        .bind(address.map(|value| value.to_string()))
        .fetch_one(&env.pool)
        .await
        .expect("seed invoice")
    }

    async fn status_row(env: &Env, state: &str) -> Option<UsTaxStatusRow> {
        list_status_rows(&env.pool)
            .await
            .expect("status rows")
            .into_iter()
            .find(|row| row.state_code == state)
    }

    async fn nexus_incidents(env: &Env) -> Vec<(String, String, serde_json::Value)> {
        sqlx::query_as(
            "SELECT kind, severity, detail FROM finance_incidents WHERE kind = $1 \
             ORDER BY created_at",
        )
        .bind(NEXUS_ALERT_KIND)
        .fetch_all(&env.pool)
        .await
        .expect("threshold alerts")
    }

    async fn nexus_warning_incidents(env: &Env) -> Vec<(String, String, serde_json::Value)> {
        sqlx::query_as(
            "SELECT kind, severity, detail FROM finance_incidents WHERE kind = $1 \
             ORDER BY created_at",
        )
        .bind(NEXUS_WARNING_KIND)
        .fetch_all(&env.pool)
        .await
        .expect("early warnings")
    }

    // ------------------------------------------------------------------
    // The nexus sweep
    // ------------------------------------------------------------------

    env_test!(
        sweep_alerts_exactly_once_at_the_threshold_and_replays_quietly,
        |env| {
            let tenant = "ustax_ca_crossing";
            let ca = fixture_row(
                "CA",
                725,
                THRESHOLD,
                "calendar",
                today() - Duration::days(1),
            );
            install_table(&[ca]);
            seed_tenant(env, tenant, "US", Some("CA")).await;

            // threshold − 1 cent: below, no alert, but TRACKED (the row is
            // created on first sighting).
            seed_invoice(
                env,
                tenant,
                "usd",
                "US",
                Some(serde_json::json!({ "state": "CA" })),
                THRESHOLD - 1,
                Utc::now() - Duration::days(10),
                "draft",
            )
            .await;
            let first = sweep_us_tax_nexus(&env.state).await.expect("first sweep");
            assert_eq!(first.states_evaluated, 1);
            assert_eq!(first.states_below, 1);
            assert_eq!(first.alerts_raised, 0, "threshold − 1 does not alert");
            // …but it IS past the warning fraction (0.8 × $100,000.00), so
            // the early warning fired exactly once — a warning-grade incident,
            // not the crossing alert.
            assert_eq!(first.warnings_raised, 1);
            assert_eq!(first.states_warned, 1);
            let row = status_row(env, "CA").await.expect("CA row exists");
            assert_eq!(row.status, "below");
            assert_eq!(row.observed_cents, THRESHOLD - 1);
            assert!(row.crossed_at.is_none());
            assert_eq!(row.threshold_cents, Some(THRESHOLD));
            assert_eq!(row.transaction_threshold, None);
            assert_eq!(row.criteria, "sales");
            assert_eq!(row.observed_count, 1, "transactions are tracked too");
            assert_eq!(row.observed_exempt_cents, 0);
            assert!(row.warned_at.is_some(), "the early warning is recorded");
            assert_eq!(row.warned_window_start, Some(row.window_start));
            assert_eq!(row.nexus_window, "calendar");
            assert!(row.last_evaluated_at.is_some());
            assert_eq!(nexus_incidents(env).await.len(), 0, "no crossing alert yet");
            let warnings = nexus_warning_incidents(env).await;
            assert_eq!(warnings.len(), 1, "one durable early warning");
            assert_eq!(warnings[0].1, "medium", "warning-grade, below high");
            assert_eq!(warnings[0].2["state"], "CA");
            assert_eq!(warnings[0].2["observedCents"], THRESHOLD - 1);
            assert_eq!(warnings[0].2["thresholdCents"], THRESHOLD);
            assert_eq!(warnings[0].2["remainingCents"], 1);
            assert_eq!(warnings[0].2["triggers"][0], "sales");
            assert!(
                warnings[0].2["daysLeftInWindow"].is_i64(),
                "a calendar window has a determinable days-left"
            );

            // A replay does not warn again (once per window).
            let warn_replay = sweep_us_tax_nexus(&env.state).await.expect("warn replay");
            assert_eq!(warn_replay.warnings_raised, 0);
            assert_eq!(nexus_warning_incidents(env).await.len(), 1);

            // Exactly the threshold: crossed, ONE alert.
            seed_invoice(
                env,
                tenant,
                "usd",
                "US",
                Some(serde_json::json!({ "state": "CA" })),
                1,
                Utc::now() - Duration::days(9),
                "draft",
            )
            .await;
            let second = sweep_us_tax_nexus(&env.state).await.expect("second sweep");
            assert_eq!(second.states_crossed, 1);
            assert_eq!(second.alerts_raised, 1, "the crossing alerts once");
            assert_eq!(second.states_below, 0);
            let row = status_row(env, "CA").await.expect("CA row");
            assert_eq!(row.status, "threshold_crossed");
            assert_eq!(row.observed_cents, THRESHOLD);
            assert!(row.crossed_at.is_some());
            assert_eq!(row.crossed_window_start, Some(row.window_start));
            assert!(
                row.warned_at.is_none(),
                "the crossing supersedes the warning record"
            );

            let incidents = nexus_incidents(env).await;
            assert_eq!(incidents.len(), 1, "one durable crossing alert");
            assert_eq!(
                nexus_warning_incidents(env).await.len(),
                1,
                "the earlier warning is history, not re-raised"
            );
            assert_eq!(incidents[0].0, NEXUS_ALERT_KIND);
            assert_eq!(incidents[0].1, "high");
            assert_eq!(incidents[0].2["state"], "CA");
            assert_eq!(incidents[0].2["observedCents"], THRESHOLD);
            assert_eq!(incidents[0].2["thresholdCents"], THRESHOLD);
            assert_eq!(incidents[0].2["windowKind"], "calendar");
            assert!(
                incidents[0].2["requiredAction"]
                    .as_str()
                    .expect("action")
                    .contains("Register"),
                "the alert names the operator act"
            );

            // Replay: idempotent — no second alert, no status drift.
            let replay = sweep_us_tax_nexus(&env.state).await.expect("replay");
            assert_eq!(replay.alerts_raised, 0, "a replay never re-alerts");
            assert_eq!(replay.states_crossed, 1);
            assert_eq!(nexus_incidents(env).await.len(), 1);
            let row = status_row(env, "CA").await.expect("CA row");
            assert_eq!(row.status, "threshold_crossed");
            assert_eq!(row.observed_cents, THRESHOLD);

            // Never registered by the sweep (a computed run can only compute).
            assert_eq!(row.registered_at, None);
            assert_eq!(replay.states_registered, 0);
        }
    );

    env_test!(
        sweep_reports_unknown_state_invoices_and_never_assigns_them,
        |env| {
            install_table(&[fixture_row(
                "CA",
                725,
                THRESHOLD,
                "calendar",
                today() - Duration::days(1),
            )]);
            let issued = Utc::now() - Duration::days(5);

            // Free text, absent, and corrupt billing snapshots: three
            // different UNKNOWN shapes, none of them assigned to a state.
            seed_invoice(
                env,
                "ustax_unknown_text",
                "usd",
                "US",
                Some(serde_json::json!({ "state": "California" })),
                3_000_000,
                issued,
                "draft",
            )
            .await;
            seed_invoice(
                env,
                "ustax_unknown_missing",
                "usd",
                "US",
                Some(serde_json::json!({})),
                2_000_000,
                issued,
                "draft",
            )
            .await;
            {
                // A non-JSON billing address must not break the aggregation
                // (the `IS JSON` guard) — it is simply unknown.
                seed_tenant(env, "ustax_unknown_corrupt", "US", None).await;
                sqlx::query(
                    "INSERT INTO invoices (
                         id, tenant_id, invoice_number, status, currency, amount, subtotal,
                         vat_total, total, issued_at, billing_country, billing_address,
                         us_sales_tax_cents, created_at, updated_at
                     ) VALUES (gen_random_uuid(), $1, $2, 'draft', 'usd', $3, $3, 0, $3, $4,
                               'US', 'not json at all', 0, $4, $4)",
                )
                .bind("ustax_unknown_corrupt")
                .bind(format!("TAX-{}", Uuid::new_v4()))
                .bind(1_000_000_i64)
                .bind(issued)
                .execute(&env.pool)
                .await
                .expect("corrupt snapshot row");
            }
            // A non-US customer with a US-looking state: untouched.
            seed_invoice(
                env,
                "ustax_unknown_ee",
                "eur",
                "EE",
                Some(serde_json::json!({ "state": "CA" })),
                9_000_000,
                issued,
                "draft",
            )
            .await;
            // A voided US invoice in CA: excluded from every figure.
            seed_invoice(
                env,
                "ustax_unknown_void",
                "usd",
                "US",
                Some(serde_json::json!({ "state": "CA" })),
                4_000_000,
                issued,
                "void",
            )
            .await;

            let result = sweep_us_tax_nexus(&env.state).await.expect("sweep");
            assert_eq!(result.unknown_state_invoices, 3, "three UNKNOWN invoices");
            assert_eq!(
                result.unknown_state_cents,
                3_000_000 + 2_000_000 + 1_000_000
            );
            assert_eq!(
                result.states_evaluated, 0,
                "an unknown state is reported, never evaluated"
            );
            assert!(
                list_status_rows(&env.pool).await.expect("rows").is_empty(),
                "no state row may be created from an unknown address"
            );
            assert!(
                result.states_without_threshold_data.is_empty(),
                "the EE invoice's CA-looking state is not a US sale at all"
            );
            assert!(result.non_usd_invoices.is_empty());
        }
    );

    env_test!(sweep_excludes_non_usd_and_window_outside_invoices, |env| {
        let ca = fixture_row(
            "CA",
            725,
            2_000_000,
            "calendar",
            today() - Duration::days(1),
        );
        let tx = fixture_row(
            "TX",
            625,
            2_000_000,
            "trailing_12m",
            today() - Duration::days(1),
        );
        install_table(&[ca, tx]);
        let now = Utc::now();
        let year_start = NexusWindow::CalendarYear.bounds(now).0;

        // CA (calendar window): exactly at the window start counts; the
        // instant before it does not; a EUR invoice is reported, not summed.
        seed_invoice(
            env,
            "ustax_window_ca",
            "usd",
            "US",
            Some(serde_json::json!({ "state": "CA" })),
            1_000_000,
            year_start,
            "draft",
        )
        .await;
        seed_invoice(
            env,
            "ustax_window_ca",
            "usd",
            "US",
            Some(serde_json::json!({ "state": "CA" })),
            7_000_000,
            year_start - Duration::seconds(1),
            "draft",
        )
        .await;
        seed_invoice(
            env,
            "ustax_window_ca",
            "eur",
            "US",
            Some(serde_json::json!({ "state": "CA" })),
            500_000,
            now - Duration::days(1),
            "draft",
        )
        .await;

        // TX (trailing 12m): 11 months ago counts, 13 months ago does not.
        seed_invoice(
            env,
            "ustax_window_tx",
            "usd",
            "US",
            Some(serde_json::json!({ "state": "TX" })),
            900_000,
            now - Months::new(11),
            "draft",
        )
        .await;
        seed_invoice(
            env,
            "ustax_window_tx",
            "usd",
            "US",
            Some(serde_json::json!({ "state": "TX" })),
            9_000_000,
            now - Months::new(13),
            "draft",
        )
        .await;

        let result = sweep_us_tax_nexus(&env.state).await.expect("sweep");
        assert_eq!(
            status_row(env, "CA").await.expect("CA row").observed_cents,
            1_000_000,
            "only the in-window USD invoice counts for CA"
        );
        assert_eq!(
            status_row(env, "TX").await.expect("TX row").observed_cents,
            900_000,
            "only the trailing-12m invoice counts for TX"
        );
        assert_eq!(
            result.non_usd_invoices,
            vec![("EUR".to_string(), 1, 500_000)],
            "a non-USD US invoice is reported per currency, never converted"
        );
        assert_eq!(result.unknown_state_invoices, 0);
        assert_eq!(result.states_below, 2);
        assert_eq!(result.alerts_raised, 0);
    });

    env_test!(sweep_names_states_whose_threshold_data_is_missing, |env| {
        // The file carries CA only; a TX invoice is never evaluated against
        // an invented threshold.
        install_table(&[fixture_row(
            "CA",
            725,
            THRESHOLD,
            "calendar",
            today() - Duration::days(1),
        )]);
        seed_invoice(
            env,
            "ustax_no_data",
            "usd",
            "US",
            Some(serde_json::json!({ "state": "TX" })),
            5_000_000,
            Utc::now() - Duration::days(3),
            "draft",
        )
        .await;
        let result = sweep_us_tax_nexus(&env.state).await.expect("sweep");
        assert_eq!(result.states_without_threshold_data, vec!["TX".to_string()]);
        assert_eq!(result.states_evaluated, 0);
        assert!(status_row(env, "TX").await.is_none(), "no row, no guess");
        assert_eq!(result.alerts_raised, 0);
    });

    env_test!(
        calendar_rollover_is_a_new_window_while_rolling_windows_never_re_alert,
        |env| {
            let ca = fixture_row(
                "CA",
                725,
                THRESHOLD,
                "calendar",
                today() - Duration::days(1),
            );
            let tx = fixture_row(
                "TX",
                625,
                THRESHOLD,
                "trailing_12m",
                today() - Duration::days(1),
            );
            install_table(&[ca, tx]);
            let now = Utc::now();
            let this_year = NexusWindow::CalendarYear.bounds(now).0;
            let last_year = NexusWindow::CalendarYear.bounds(now - Months::new(13)).0;

            seed_invoice(
                env,
                "ustax_rollover",
                "usd",
                "US",
                Some(serde_json::json!({ "state": "CA" })),
                THRESHOLD,
                now - Duration::days(2),
                "draft",
            )
            .await;
            seed_invoice(
                env,
                "ustax_rollover",
                "usd",
                "US",
                Some(serde_json::json!({ "state": "TX" })),
                THRESHOLD + 500,
                now - Duration::days(2),
                "draft",
            )
            .await;

            let first = sweep_us_tax_nexus(&env.state).await.expect("sweep");
            assert_eq!(first.alerts_raised, 2, "one alert per crossing state");
            assert_eq!(nexus_incidents(env).await.len(), 2);

            // Replay in the SAME window changes nothing, for either kind.
            let replay = sweep_us_tax_nexus(&env.state).await.expect("replay");
            assert_eq!(replay.alerts_raised, 0);
            assert_eq!(nexus_incidents(env).await.len(), 2);

            // Simulate a calendar year boundary: the stored window belongs to
            // last year, so this evaluation is a NEW window instance — its
            // crossing is its own once-per-window alert.
            sqlx::query(
                "UPDATE us_tax_nexus_states SET window_start = $2, crossed_window_start = $2 \
                 WHERE state_code = 'CA'",
            )
            .bind("CA")
            .bind(last_year)
            .execute(&env.pool)
            .await
            .expect("roll CA back to last year");
            // The same roll-back on the ROLLING state must NOT re-alert: a
            // trailing twelve-month window has no new window to alert for.
            sqlx::query(
                "UPDATE us_tax_nexus_states SET window_start = $2, crossed_window_start = $2 \
                 WHERE state_code = 'TX'",
            )
            .bind("TX")
            .bind(now - Months::new(24))
            .execute(&env.pool)
            .await
            .expect("roll TX back two years");

            let new_year = sweep_us_tax_nexus(&env.state).await.expect("sweep");
            assert_eq!(
                new_year.alerts_raised, 1,
                "only the calendar state re-crosses"
            );
            let incidents = nexus_incidents(env).await;
            assert_eq!(incidents.len(), 3);
            assert_eq!(incidents[2].2["state"], "CA");
            assert_eq!(incidents[2].2["windowStart"], this_year.to_rfc3339());

            // A calendar state that is BELOW in the new window returns to
            // `below` (the old crossing is history, no alert).
            sqlx::query("UPDATE invoices SET issued_at = $1 WHERE tenant_id = $2 AND $3 = $3")
                .bind(last_year)
                .bind("ustax_rollover")
                .bind(0_i32)
                .execute(&env.pool)
                .await
                .expect("move every invoice out of the current year");
            sqlx::query(
                "UPDATE us_tax_nexus_states SET window_start = $2, crossed_window_start = $2 \
                 WHERE state_code = 'CA'",
            )
            .bind("CA")
            .bind(last_year)
            .execute(&env.pool)
            .await
            .expect("roll CA back again");

            let below_again = sweep_us_tax_nexus(&env.state).await.expect("sweep");
            assert_eq!(below_again.alerts_raised, 0);
            let row = status_row(env, "CA").await.expect("CA row");
            assert_eq!(row.status, "below");
            assert_eq!(row.observed_cents, 0);
            assert!(row.crossed_at.is_none());
            assert_eq!(row.window_start, this_year);
        }
    );

    // ------------------------------------------------------------------
    // The operator registration surface
    // ------------------------------------------------------------------

    env_test!(
        registration_is_operator_only_and_unregistration_re_crosses,
        |env| {
            let config = install_table(&[fixture_row(
                "CA",
                725,
                THRESHOLD,
                "calendar",
                today() - Duration::days(1),
            )]);
            let now = Utc::now();
            seed_tenant(env, "ustax_register", "US", Some("CA")).await;
            seed_invoice(
                env,
                "ustax_register",
                "usd",
                "US",
                Some(serde_json::json!({ "state": "CA" })),
                THRESHOLD,
                now - Duration::days(2),
                "draft",
            )
            .await;

            let crossed = sweep_us_tax_nexus(&env.state).await.expect("sweep");
            assert_eq!(crossed.alerts_raised, 1);

            // The operator registers: the row flips and the audit fields land.
            let registered = register_state(
                &env.pool,
                &config,
                "ca",
                "owner@apexmail.test",
                Some("CDTFA"),
                now,
            )
            .await
            .expect("registration");
            assert_eq!(registered.status, "registered");
            assert_eq!(
                registered.registered_by.as_deref(),
                Some("owner@apexmail.test")
            );
            assert_eq!(registered.registration_note.as_deref(), Some("CDTFA"));
            assert!(registered.registered_at.is_some());
            assert_eq!(
                registered.observed_cents, THRESHOLD,
                "registration records the current window's sales"
            );

            // The sweep now tracks without alerting, and never un-registers.
            let after = sweep_us_tax_nexus(&env.state).await.expect("sweep");
            assert_eq!(after.states_registered, 1);
            assert_eq!(after.states_crossed, 0);
            assert_eq!(after.alerts_raised, 0, "a registered state never re-alerts");
            let row = status_row(env, "CA").await.expect("CA row");
            assert_eq!(row.status, "registered");
            assert_eq!(nexus_incidents(env).await.len(), 1);

            // Registration refuses a state with no usable rate row — the
            // state's invoices would be refused, so the row must land first.
            let error = register_state(&env.pool, &config, "TX", "owner@apexmail.test", None, now)
                .await
                .expect_err("no rate row");
            assert!(
                matches!(error, RegistrationError::UnusableRateRow { .. }),
                "{error}"
            );
            assert!(error.to_string().contains("TX"), "{error}");
            assert!(status_row(env, "TX").await.is_none());

            let unknown = register_state(&env.pool, &config, "ZZ", "owner", None, now)
                .await
                .expect_err("not a state code");
            assert!(
                matches!(unknown, RegistrationError::UnknownState(_)),
                "{unknown}"
            );

            // Unregistration clears the crossing, so a still-crossed state
            // alerts again on the next sweep (a deliberate operator reset).
            let unregistered = unregister_state(
                &env.pool,
                "CA",
                "owner@apexmail.test",
                Some("deregistered"),
                now,
            )
            .await
            .expect("unregister");
            assert_eq!(unregistered.status, "below");
            assert_eq!(unregistered.registered_at, None);
            assert_eq!(unregistered.crossed_at, None);
            assert_eq!(
                unregistered.registration_note.as_deref(),
                Some("deregistered")
            );

            let re_crossed = sweep_us_tax_nexus(&env.state).await.expect("sweep");
            assert_eq!(
                re_crossed.alerts_raised, 1,
                "a fresh crossing after a reset alerts"
            );
            assert_eq!(nexus_incidents(env).await.len(), 2);
            assert_eq!(
                status_row(env, "CA").await.expect("CA row").status,
                "threshold_crossed"
            );

            // Untracked states have nothing to unregister.
            let untracked = unregister_state(&env.pool, "NY", "owner", None, now)
                .await
                .expect_err("untracked");
            assert!(
                matches!(untracked, RegistrationError::NotTracked { .. }),
                "{untracked}"
            );
        }
    );

    // ------------------------------------------------------------------
    // The money path: the stamped sales-tax line on invoices
    // ------------------------------------------------------------------

    fn invoice_input(tenant: &str, description: &str, unit_price: i64) -> CreateInvoiceInput {
        let now = Utc::now();
        CreateInvoiceInput {
            tenant_id: tenant.to_string(),
            adyen_psp_reference: None,
            line_items: vec![NewLineItem {
                description: description.to_string(),
                quantity: 1,
                unit_price,
            }],
            period_start: now - Duration::days(30),
            period_end: now,
            due_at: None,
            currency: Some("usd".to_string()),
            overage_period: None,
            product_lines_period: None,
        }
    }

    async fn register_directly(env: &Env, state: &str) {
        // Simulates a registration made while the rate row was fresh (the
        // write path is covered by the registration test above).
        sqlx::query(
            "INSERT INTO us_tax_nexus_states (state_code, status, nexus_window, threshold_cents, \
             observed_cents, window_start, window_end, registered_at, registered_by, \
             last_evaluated_at) \
             VALUES ($1, 'registered', 'calendar', $2, 0, NOW(), NOW() + INTERVAL '1 year', \
                     NOW(), 'owner@apexmail.test', NOW())",
        )
        .bind(state)
        .bind(THRESHOLD)
        .execute(&env.pool)
        .await
        .expect("direct registration");
    }

    env_test!(
        invoice_writer_stamps_the_tax_line_only_for_registered_fresh_states,
        |env| {
            let config = install_table(&[
                fixture_row(
                    "CA",
                    725,
                    THRESHOLD,
                    "calendar",
                    today() - Duration::days(1),
                ),
                // 5 bps exists to pin the exact half-cent rounding case; it is
                // a test fixture, never shippable rate data.
                fixture_row("NY", 5, THRESHOLD, "calendar", today() - Duration::days(1)),
            ]);

            // A registered state with a fresh row: the line lands, stamped.
            seed_tenant(env, "ustax_inv_ca", "US", Some("CA")).await;
            register_state(
                &env.pool,
                &config,
                "CA",
                "owner@apexmail.test",
                None,
                Utc::now(),
            )
            .await
            .expect("register CA");
            let invoice =
                create_invoice(&env.pool, invoice_input("ustax_inv_ca", "Platform", 10_000))
                    .await
                    .expect("invoice with US tax");
            assert_eq!(invoice.subtotal, 10_000);
            assert_eq!(invoice.vat_total, 0, "a US customer carries no EU VAT");
            assert_eq!(invoice.us_sales_tax_cents, 725, "7.25 % of $100.00");
            assert_eq!(
                invoice.total,
                invoice.subtotal + invoice.vat_total + invoice.us_sales_tax_cents,
                "total = subtotal + VAT + US sales tax"
            );
            assert_eq!(invoice.line_items.len(), 2);
            let tax_line = invoice.line_items.last().expect("tax line");
            assert!(
                tax_line.description.contains("US sales tax (CA)"),
                "{:?}",
                tax_line
            );
            assert!(tax_line.description.contains("7.25 %"), "{:?}", tax_line);
            assert!(
                tax_line.description.contains(FIXTURE_SOURCE),
                "{:?}",
                tax_line
            );
            assert_eq!(tax_line.amount, 725);
            assert_eq!(tax_line.vat_rate, 0.0, "a US tax line is not a VAT line");
            assert_eq!(tax_line.vat_amount, 0);
            let snapshot = invoice
                .us_sales_tax_snapshot
                .as_ref()
                .expect("provenance snapshot");
            assert_eq!(snapshot["state"], "CA");
            assert_eq!(snapshot["rateBps"], 725);
            assert_eq!(snapshot["amountCents"], 725);
            assert_eq!(snapshot["source"], FIXTURE_SOURCE);
            assert_eq!(
                snapshot["retrieved"],
                (today() - Duration::days(1)).to_string()
            );

            // The persisted row carries the same pair (and the CHECK holds).
            let stored: (i64, Option<serde_json::Value>) = sqlx::query_as(
                "SELECT us_sales_tax_cents, us_sales_tax_snapshot FROM invoices WHERE id = $1",
            )
            .bind(invoice.id)
            .fetch_one(&env.pool)
            .await
            .expect("stored tax");
            assert_eq!(stored.0, 725);
            assert_eq!(
                stored.1.expect("stored snapshot")["rateBps"],
                serde_json::json!(725)
            );

            // The read paths decode the new columns back (the SELECT lists
            // gained them; a runtime type mismatch would surface here).
            let fetched = crate::invoices::get_invoice_by_id(&env.pool, invoice.id)
                .await
                .expect("invoice decode")
                .expect("invoice present");
            assert_eq!(fetched.us_sales_tax_cents, 725);
            assert_eq!(
                fetched.us_sales_tax_snapshot.expect("snapshot decodes")["state"],
                serde_json::json!("CA")
            );
            let listed = crate::invoices::list_invoices(&env.pool, "ustax_inv_ca", 10, 0)
                .await
                .expect("invoice list");
            assert_eq!(listed.len(), 1);
            assert_eq!(listed[0].us_sales_tax_cents, 725);

            // US sales tax never enters the EU VAT ledger (it is not VAT).
            let recognized: (i64, i64, Option<String>) = sqlx::query_as(
                "SELECT taxable_amount_cents, vat_amount_cents, reason \
                 FROM vat_recognition_entries WHERE invoice_id = $1",
            )
            .bind(invoice.id)
            .fetch_one(&env.pool)
            .await
            .expect("recognition entry");
            assert_eq!(recognized.0, 10_000, "the taxable base is the sales price");
            assert_eq!(recognized.1, 0, "US sales tax is NOT Estonian VAT");
            assert_eq!(recognized.2.as_deref(), Some("non_eu"));

            // Half-cent rounding reaches the invoice exactly once: $10.00 at
            // 5 bps = 0.5 cents → 1 cent.
            seed_tenant(env, "ustax_inv_half", "US", Some("NY")).await;
            register_state(
                &env.pool,
                &config,
                "NY",
                "owner@apexmail.test",
                None,
                Utc::now(),
            )
            .await
            .expect("register NY");
            let half = create_invoice(
                &env.pool,
                invoice_input("ustax_inv_half", "Platform", 1_000),
            )
            .await
            .expect("half-cent invoice");
            assert_eq!(half.us_sales_tax_cents, 1, "0.5 cents rounds half-up, once");
            assert_eq!(half.total, 1_001);

            // $1.04 at 7.25 % = 7.54 cents → 8.
            let rounded = create_invoice(&env.pool, invoice_input("ustax_inv_ca", "Over", 5_196))
                .await
                .expect("rounding invoice");
            assert_eq!(
                rounded.us_sales_tax_cents, 377,
                "7.25 % of $51.96 = 3.7671 → $3.77"
            );

            // A US customer in an UNREGISTERED state: no line, existing
            // behavior (and no refusal).
            seed_tenant(env, "ustax_inv_ny", "US", Some("NY")).await;
            sqlx::query("UPDATE us_tax_nexus_states SET status = 'below' WHERE state_code = 'NY'")
                .execute(&env.pool)
                .await
                .expect("un-register NY");
            let unregistered =
                create_invoice(&env.pool, invoice_input("ustax_inv_ny", "Platform", 10_000))
                    .await
                    .expect("unregistered state invoice");
            assert_eq!(unregistered.us_sales_tax_cents, 0);
            assert!(unregistered.us_sales_tax_snapshot.is_none());
            assert_eq!(unregistered.total, unregistered.subtotal);
            assert_eq!(unregistered.line_items.len(), 1);

            // A US customer whose address state is free text: never assigned,
            // never taxed.
            seed_tenant(env, "ustax_inv_text", "US", Some("California")).await;
            let free_text = create_invoice(
                &env.pool,
                invoice_input("ustax_inv_text", "Platform", 10_000),
            )
            .await
            .expect("free-text state invoice");
            assert_eq!(free_text.us_sales_tax_cents, 0);

            // A non-US customer with a US-looking state: untouched (pinned).
            seed_tenant(env, "ustax_inv_ee", "EE", Some("CA")).await;
            let eu = create_invoice(&env.pool, invoice_input("ustax_inv_ee", "Platform", 10_000))
                .await
                .expect("EU invoice");
            assert_eq!(eu.us_sales_tax_cents, 0);
            assert_eq!(eu.us_sales_tax_snapshot, None);
            assert!(eu.vat_total > 0, "the EU path is untouched");
            assert_eq!(eu.line_items.len(), 1, "no US line on an EU invoice");
        }
    );

    env_test!(
        registered_state_with_a_stale_rate_row_refuses_the_invoice,
        |env| {
            // 200 days old — past the 120-day default.
            let stale = fixture_config(
                &[fixture_row(
                    "CA",
                    725,
                    THRESHOLD,
                    "calendar",
                    today() - Duration::days(200),
                )],
                120,
            );
            let fresh = fixture_config(&[], 120);
            assert!(stale.fresh_row("CA", today()).is_err());
            set_test_table(Some(fresh));
            seed_tenant(env, "ustax_stale_ca", "US", Some("CA")).await;
            register_directly(env, "CA").await;
            set_test_table(Some(stale));

            // Fail closed: the invoice is refused by name, and NOTHING is written.
            let error = create_invoice(
                &env.pool,
                invoice_input("ustax_stale_ca", "Platform", 10_000),
            )
            .await
            .expect_err("a stale rate row refuses the invoice");
            match &error {
                InvoiceError::UsSalesTax(message) => {
                    assert!(message.contains("STALE"), "{message}");
                    assert!(message.contains("CA"), "{message}");
                    assert!(message.contains(FIXTURE_SOURCE), "{message}");
                }
                other => panic!("expected a US sales tax refusal, got {other:?}"),
            }
            let invoice_count: i64 =
                sqlx::query_scalar("SELECT COUNT(*)::bigint FROM invoices WHERE tenant_id = $1")
                    .bind("ustax_stale_ca")
                    .fetch_one(&env.pool)
                    .await
                    .expect("count");
            assert_eq!(invoice_count, 0, "a refused invoice writes nothing");

            // The refusal is scoped: an EU customer still bills normally with the
            // same (stale) table installed.
            seed_tenant(env, "ustax_stale_ee", "EE", None).await;
            let eu = create_invoice(
                &env.pool,
                invoice_input("ustax_stale_ee", "Platform", 10_000),
            )
            .await
            .expect("EU invoice is untouched by the US rate file");
            assert_eq!(eu.us_sales_tax_cents, 0);
            assert!(eu.vat_total > 0);

            // And a registered state with NO row at all refuses too, naming the
            // missing row.
            set_test_table(Some(fixture_config(&[], 120)));
            let error = create_invoice(
                &env.pool,
                invoice_input("ustax_stale_ca", "Platform", 10_000),
            )
            .await
            .expect_err("missing row refuses");
            assert!(
                error.to_string().contains("NO rate row"),
                "the refusal names the missing row: {error}"
            );
        }
    );

    // ------------------------------------------------------------------
    // Either-criterion nexus, taxability and the early warning
    // ------------------------------------------------------------------

    /// A fixture row declaring BOTH criteria (`either`).
    fn either_row(
        state: &str,
        rate_bps: u32,
        sales_threshold_cents: i64,
        transaction_threshold: i64,
        retrieved: NaiveDate,
    ) -> serde_json::Value {
        serde_json::json!({
            "state": state,
            "taxability": "taxable",
            "rateBps": rate_bps,
            "criteria": "either",
            "nexusThresholdCents": sales_threshold_cents,
            "transactionThreshold": transaction_threshold,
            "nexusWindow": "calendar",
            "sourceUrl": FIXTURE_SOURCE,
            "retrieved": retrieved.to_string(),
        })
    }

    /// A fixture row that is explicitly not_taxable.
    fn not_taxable_row(state: &str, retrieved: NaiveDate) -> serde_json::Value {
        serde_json::json!({
            "state": state,
            "taxability": "not_taxable",
            "sourceUrl": FIXTURE_SOURCE,
            "retrieved": retrieved.to_string(),
        })
    }

    // The sweep tracks BOTH criteria always and alerts on the FIRST crossing
    // of whichever the row declares: threshold − 1 transaction is below,
    // exactly the threshold crosses (once), +1 stays crossed quietly.
    env_test!(
        sweep_tracks_both_criteria_and_alerts_on_the_first_crossing,
        |env| {
            install_table(&[either_row(
                "TX",
                625,
                THRESHOLD,
                200,
                today() - Duration::days(1),
            )]);
            let tenant = "ustax_either_tx";
            let issued = Utc::now() - Duration::days(5);
            let address = serde_json::json!({ "state": "TX" });

            // 199 one-dollar invoices: the sales measure is far from its
            // threshold, the transaction measure is at threshold − 1.
            for _ in 0..199 {
                seed_invoice(
                    env,
                    tenant,
                    "usd",
                    "US",
                    Some(address.clone()),
                    100,
                    issued,
                    "draft",
                )
                .await;
            }
            let first = sweep_us_tax_nexus(&env.state).await.expect("first sweep");
            assert_eq!(first.states_below, 1);
            assert_eq!(first.alerts_raised, 0);
            assert_eq!(first.states_warned, 1, "199 ≥ 0.8 × 200");
            let row = status_row(env, "TX").await.expect("TX row");
            assert_eq!(row.criteria, "either");
            assert_eq!(row.threshold_cents, Some(THRESHOLD));
            assert_eq!(row.transaction_threshold, Some(200));
            assert_eq!(row.observed_count, 199, "counts are always tracked");
            assert_eq!(row.observed_cents, 19_900);

            // The 200th transaction: the count criterion crosses.
            seed_invoice(
                env,
                tenant,
                "usd",
                "US",
                Some(address.clone()),
                100,
                issued,
                "draft",
            )
            .await;
            let second = sweep_us_tax_nexus(&env.state).await.expect("second sweep");
            assert_eq!(second.states_crossed, 1);
            assert_eq!(second.alerts_raised, 1);
            let row = status_row(env, "TX").await.expect("TX row");
            assert_eq!(row.status, "threshold_crossed");
            assert_eq!(row.observed_count, 200);
            let incidents = nexus_incidents(env).await;
            assert_eq!(incidents.len(), 1);
            assert_eq!(incidents[0].2["criteria"], "either");
            assert_eq!(incidents[0].2["observedCount"], 200);
            assert_eq!(incidents[0].2["transactionThreshold"], 200);
            assert_eq!(incidents[0].2["observedCents"], 20_000);
            assert_eq!(incidents[0].2["thresholdCents"], THRESHOLD);

            // +1: sticky, quiet.
            seed_invoice(
                env,
                tenant,
                "usd",
                "US",
                Some(address),
                100,
                issued,
                "draft",
            )
            .await;
            let third = sweep_us_tax_nexus(&env.state).await.expect("third sweep");
            assert_eq!(third.alerts_raised, 0, "a crossed count does not re-alert");
            assert_eq!(
                status_row(env, "TX").await.expect("TX row").observed_count,
                201
            );
            assert_eq!(nexus_incidents(env).await.len(), 1);
        }
    );

    // A row declaring a criterion whose threshold is missing is a data
    // error: the state is REFUSED (no row, no evaluation, no alert) and
    // reported by name — never evaluated against an invented threshold.
    // not_taxable states are reported distinctly and never evaluated.
    env_test!(
        sweep_refuses_incomplete_declarations_and_skips_not_taxable_states,
        |env| {
            install_table(&[
                serde_json::json!({
                    "state": "TX",
                    "taxability": "taxable",
                    "rateBps": 625,
                    "criteria": "either",
                    "nexusThresholdCents": THRESHOLD,
                    "nexusWindow": "calendar",
                    "sourceUrl": FIXTURE_SOURCE,
                    "retrieved": (today() - Duration::days(1)).to_string(),
                }),
                not_taxable_row("NY", today() - Duration::days(1)),
            ]);
            let issued = Utc::now() - Duration::days(3);
            seed_invoice(
                env,
                "ustax_invalid_tx",
                "usd",
                "US",
                Some(serde_json::json!({ "state": "TX" })),
                THRESHOLD * 2,
                issued,
                "draft",
            )
            .await;
            seed_invoice(
                env,
                "ustax_invalid_ny",
                "usd",
                "US",
                Some(serde_json::json!({ "state": "NY" })),
                THRESHOLD * 2,
                issued,
                "draft",
            )
            .await;

            let result = sweep_us_tax_nexus(&env.state).await.expect("sweep");
            assert_eq!(result.states_evaluated, 0);
            assert_eq!(result.alerts_raised, 0);
            assert_eq!(result.states_not_taxable, vec!["NY".to_string()]);
            assert_eq!(result.states_invalid_nexus.len(), 1);
            let (state, reason) = &result.states_invalid_nexus[0];
            assert_eq!(state, "TX");
            assert!(reason.contains("BOTH"), "{reason}");
            assert!(
                status_row(env, "TX").await.is_none(),
                "a refused state gets no status row"
            );
            assert!(
                status_row(env, "NY").await.is_none(),
                "a not_taxable state is never tracked"
            );
            assert!(result.states_without_threshold_data.is_empty());
            assert!(nexus_incidents(env).await.is_empty());
        }
    );

    // not_taxable states never charge — not even when a (legacy)
    // registration row exists — and registration is refused for them.
    env_test!(
        not_taxable_states_never_charge_and_registration_is_refused,
        |env| {
            let config = install_table(&[
                fixture_row(
                    "CA",
                    725,
                    THRESHOLD,
                    "calendar",
                    today() - Duration::days(1),
                ),
                not_taxable_row("NY", today() - Duration::days(1)),
            ]);
            // CA: properly registered → the tax line lands.
            seed_tenant(env, "ustax_nt_ca", "US", Some("CA")).await;
            register_state(&env.pool, &config, "CA", "owner", None, Utc::now())
                .await
                .expect("register CA");
            let ca = create_invoice(&env.pool, invoice_input("ustax_nt_ca", "Platform", 10_000))
                .await
                .expect("CA invoice");
            assert_eq!(ca.us_sales_tax_cents, 725);

            // NY: a legacy registration row exists (simulating a state the
            // operator registered before the law/row changed)…
            sqlx::query(
                "INSERT INTO us_tax_nexus_states (state_code, status, nexus_window, \
                 threshold_cents, observed_cents, window_start, window_end, registered_at, \
                 last_evaluated_at) \
                 VALUES ('NY', 'registered', 'calendar', $1, 0, NOW(), NOW() + INTERVAL '1 year', \
                         NOW(), NOW())",
            )
            .bind(THRESHOLD)
            .execute(&env.pool)
            .await
            .expect("legacy NY registration");
            seed_tenant(env, "ustax_nt_ny", "US", Some("NY")).await;
            // …and the product path still charges NOTHING there.
            let ny = create_invoice(&env.pool, invoice_input("ustax_nt_ny", "Platform", 10_000))
                .await
                .expect("NY invoice issues untaxed");
            assert_eq!(ny.us_sales_tax_cents, 0);
            assert_eq!(ny.us_sales_tax_snapshot, None);
            assert_eq!(ny.total, ny.subtotal);
            assert_eq!(
                ny.line_items.len(),
                1,
                "no tax line for a not_taxable state"
            );

            // Registration for such a state is refused by name.
            let error = register_state(&env.pool, &config, "NY", "owner", None, Utc::now())
                .await
                .expect_err("not_taxable refuses registration");
            assert!(
                matches!(error, RegistrationError::NotTaxableState { .. }),
                "{error}"
            );
            assert!(error.to_string().contains("not_taxable"), "{error}");

            // The sweep reports NY distinctly, never evaluates it (the legacy
            // registration row is left untouched — the sweep never writes
            // registration state), and never alerts.
            let result = sweep_us_tax_nexus(&env.state).await.expect("sweep");
            assert_eq!(result.states_not_taxable, vec!["NY".to_string()]);
            assert_eq!(result.states_evaluated, 1, "only CA is evaluated");
            assert_eq!(result.states_registered, 1);
            assert_eq!(result.alerts_raised, 0);
            let ny_row = status_row(env, "NY").await.expect("NY legacy row");
            assert_eq!(ny_row.status, "registered");
            assert_eq!(ny_row.observed_cents, 0, "never evaluated, never touched");
        }
    );

    // The early warning fires ONCE per window at the configured fraction —
    // below the threshold — with the headroom and days-left, and the
    // crossing alert then stays its own exactly-once event.
    env_test!(
        early_warning_fires_once_before_the_crossing_which_alerts_once,
        |env| {
            set_test_table(Some(fixture_config_with_warn(
                &[fixture_row(
                    "CA",
                    725,
                    THRESHOLD,
                    "calendar",
                    today() - Duration::days(1),
                )],
                120,
                8_000,
            )));
            let tenant = "ustax_warn_ca";
            let issued = Utc::now() - Duration::days(5);
            let address = serde_json::json!({ "state": "CA" });

            // Below the warning fraction: silent.
            seed_invoice(
                env,
                tenant,
                "usd",
                "US",
                Some(address.clone()),
                7_999_999,
                issued,
                "draft",
            )
            .await;
            let quiet = sweep_us_tax_nexus(&env.state).await.expect("quiet sweep");
            assert_eq!(quiet.warnings_raised, 0);
            assert_eq!(quiet.states_warned, 0);
            assert!(status_row(env, "CA")
                .await
                .expect("row")
                .warned_at
                .is_none());
            assert!(nexus_warning_incidents(env).await.is_empty());

            // Exactly at 0.8 × threshold: ONE warning, no crossing alert.
            seed_invoice(
                env,
                tenant,
                "usd",
                "US",
                Some(address.clone()),
                1,
                issued,
                "draft",
            )
            .await;
            let warned = sweep_us_tax_nexus(&env.state).await.expect("warned sweep");
            assert_eq!(warned.warnings_raised, 1);
            assert_eq!(warned.alerts_raised, 0);
            let warnings = nexus_warning_incidents(env).await;
            assert_eq!(warnings.len(), 1);
            assert_eq!(warnings[0].1, "medium");
            assert_eq!(warnings[0].2["observedCents"], 8_000_000);
            assert_eq!(warnings[0].2["thresholdCents"], THRESHOLD);
            assert_eq!(warnings[0].2["remainingCents"], 2_000_000);
            assert_eq!(warnings[0].2["triggers"][0], "sales");
            let row = status_row(env, "CA").await.expect("row");
            assert!(row.warned_at.is_some());

            // Replay: no second warning.
            let replay = sweep_us_tax_nexus(&env.state).await.expect("replay");
            assert_eq!(replay.warnings_raised, 0);
            assert_eq!(nexus_warning_incidents(env).await.len(), 1);

            // Crossing: the (high) alert fires once; the warning is history.
            seed_invoice(
                env,
                tenant,
                "usd",
                "US",
                Some(address),
                2_000_000,
                issued,
                "draft",
            )
            .await;
            let crossed = sweep_us_tax_nexus(&env.state)
                .await
                .expect("crossing sweep");
            assert_eq!(crossed.alerts_raised, 1);
            assert_eq!(crossed.warnings_raised, 0);
            assert_eq!(nexus_incidents(env).await.len(), 1);
            assert_eq!(nexus_warning_incidents(env).await.len(), 1);
            let row = status_row(env, "CA").await.expect("row");
            assert_eq!(row.status, "threshold_crossed");
            assert!(
                row.warned_at.is_none(),
                "the crossing supersedes the warning"
            );

            let replay = sweep_us_tax_nexus(&env.state)
                .await
                .expect("crossing replay");
            assert_eq!(replay.alerts_raised, 0);
            assert_eq!(replay.warnings_raised, 0);
            assert_eq!(nexus_incidents(env).await.len(), 1);
            assert_eq!(nexus_warning_incidents(env).await.len(), 1);
        }
    );

    // ------------------------------------------------------------------
    // Exemptions and the combined rate on the money path
    // ------------------------------------------------------------------

    // A valid certificate zeroes the state's tax and lands on the snapshot;
    // expiry and removal flip the sale back to taxable; a certificate for
    // another state never exempts; the exempt sale still counts (separately)
    // toward nexus.
    env_test!(
        exemption_zeroes_tax_records_the_certificate_and_expiry_flips_back,
        |env| {
            let config = install_table(&[fixture_row(
                "CA",
                725,
                THRESHOLD,
                "calendar",
                today() - Duration::days(1),
            )]);
            seed_tenant(env, "ustax_exempt", "US", Some("CA")).await;
            register_state(&env.pool, &config, "CA", "owner", None, Utc::now())
                .await
                .expect("register CA");

            let stored = upsert_exemption(
                &env.pool,
                &ExemptionInput {
                    tenant_id: "ustax_exempt".to_string(),
                    state: "ca".to_string(),
                    certificate_id: "MTC-777".to_string(),
                    expires_at: Some(today() + Duration::days(30)),
                    note: Some("resale".to_string()),
                },
                "owner@apexmail.test",
                Utc::now(),
            )
            .await
            .expect("store exemption");
            assert_eq!(stored.state_code, "CA");
            assert_eq!(stored.certificate_id, "MTC-777");
            assert_eq!(stored.created_by.as_deref(), Some("owner@apexmail.test"));

            // The applicable-certificate lookup is deterministic.
            let found = find_applicable_exemption(&env.pool, "ustax_exempt", "CA", today())
                .await
                .expect("lookup")
                .expect("covered");
            assert_eq!(found.id, stored.id);

            // Exempt invoice: no tax line, the certificate on the snapshot.
            let exempt =
                create_invoice(&env.pool, invoice_input("ustax_exempt", "Platform", 10_000))
                    .await
                    .expect("exempt invoice");
            assert_eq!(exempt.us_sales_tax_cents, 0);
            assert_eq!(exempt.total, exempt.subtotal);
            assert_eq!(exempt.line_items.len(), 1, "no tax line when exempt");
            let snapshot = exempt
                .us_sales_tax_snapshot
                .as_ref()
                .expect("the certificate is recorded");
            assert_eq!(snapshot["exempt"], true);
            assert_eq!(snapshot["certificateId"], "MTC-777");
            assert_eq!(snapshot["state"], "CA");
            assert_eq!(snapshot["amountCents"], 0);
            assert_eq!(
                snapshot["certificateExpiresAt"],
                (today() + Duration::days(30)).to_string()
            );
            let stored_pair: (i64, Option<serde_json::Value>) = sqlx::query_as(
                "SELECT us_sales_tax_cents, us_sales_tax_snapshot FROM invoices WHERE id = $1",
            )
            .bind(exempt.id)
            .fetch_one(&env.pool)
            .await
            .expect("stored exemption pair");
            assert_eq!(stored_pair.0, 0);
            assert_eq!(stored_pair.1.expect("snapshot")["exempt"], true);

            // An EXPIRED certificate never exempts: the same certificate id
            // replaced with yesterday's expiry flips the sale back to taxable.
            upsert_exemption(
                &env.pool,
                &ExemptionInput {
                    tenant_id: "ustax_exempt".to_string(),
                    state: "CA".to_string(),
                    certificate_id: "MTC-777".to_string(),
                    expires_at: Some(today() - Duration::days(1)),
                    note: None,
                },
                "owner@apexmail.test",
                Utc::now(),
            )
            .await
            .expect("replace with expired");
            assert!(
                find_applicable_exemption(&env.pool, "ustax_exempt", "CA", today())
                    .await
                    .expect("lookup")
                    .is_none(),
                "an expired certificate is not applicable"
            );
            let taxable =
                create_invoice(&env.pool, invoice_input("ustax_exempt", "Platform", 10_000))
                    .await
                    .expect("taxable invoice");
            assert_eq!(taxable.us_sales_tax_cents, 725, "expired → taxable");

            // A certificate covering ANOTHER state never exempts this one.
            for row in list_exemptions(&env.pool, Some("ustax_exempt"))
                .await
                .expect("list")
            {
                delete_exemption(&env.pool, row.id, "owner@apexmail.test")
                    .await
                    .expect("delete");
            }
            upsert_exemption(
                &env.pool,
                &ExemptionInput {
                    tenant_id: "ustax_exempt".to_string(),
                    state: "TX".to_string(),
                    certificate_id: "TX-CERT".to_string(),
                    expires_at: None,
                    note: None,
                },
                "owner@apexmail.test",
                Utc::now(),
            )
            .await
            .expect("store TX certificate");
            let still_taxable =
                create_invoice(&env.pool, invoice_input("ustax_exempt", "Platform", 10_000))
                    .await
                    .expect("invoice with a TX certificate");
            assert_eq!(
                still_taxable.us_sales_tax_cents, 725,
                "a different state's certificate never exempts CA"
            );

            // The sweep counts the exempt sale within gross sales AND
            // separately as exempt cents (the common statutory rule counts
            // gross sales for nexus).
            let result = sweep_us_tax_nexus(&env.state).await.expect("sweep");
            assert_eq!(result.alerts_raised, 0);
            let row = status_row(env, "CA").await.expect("CA row");
            assert_eq!(row.observed_cents, 30_000, "all three invoices counted");
            assert_eq!(row.observed_exempt_cents, 10_000, "the exempt one apart");
            assert_eq!(row.observed_count, 3);

            // Unknown tenant ids are refused by name.
            let error = upsert_exemption(
                &env.pool,
                &ExemptionInput {
                    tenant_id: "no_such_tenant".to_string(),
                    state: "CA".to_string(),
                    certificate_id: "X".to_string(),
                    expires_at: None,
                    note: None,
                },
                "owner",
                Utc::now(),
            )
            .await
            .expect_err("unknown tenant");
            assert!(matches!(error, ExemptionError::UnknownTenant(_)), "{error}");
        }
    );

    // The combined rate is the rate invoices compute with when the row
    // carries one — stamped with its own source — and its own stamp obeys
    // the same fail-closed staleness rule.
    env_test!(
        combined_rate_is_used_stamped_and_fails_closed_when_stale,
        |env| {
            let combined_row = |state_retrieved: NaiveDate, combined_retrieved: NaiveDate| {
                serde_json::json!({
                    "state": "CA",
                    "taxability": "taxable",
                    "rateBps": 725,
                    "combinedRateBps": 880,
                    "combinedSourceUrl": "https://example.gov/us-tax-combined-fixture",
                    "combinedRetrieved": combined_retrieved.to_string(),
                    "nexusThresholdCents": THRESHOLD,
                    "nexusWindow": "calendar",
                    "sourceUrl": FIXTURE_SOURCE,
                    "retrieved": state_retrieved.to_string(),
                })
            };
            let fresh = fixture_config(
                &[combined_row(
                    today() - Duration::days(200),
                    today() - Duration::days(1),
                )],
                120,
            );
            set_test_table(Some(fresh.clone()));
            seed_tenant(env, "ustax_combined", "US", Some("CA")).await;
            register_state(&env.pool, &fresh, "CA", "owner", None, Utc::now())
                .await
                .expect("a fresh combined stamp registers");
            let invoice = create_invoice(
                &env.pool,
                invoice_input("ustax_combined", "Platform", 10_000),
            )
            .await
            .expect("combined-rate invoice");
            assert_eq!(
                invoice.us_sales_tax_cents, 880,
                "8.80 % combined, not 7.25 %"
            );
            assert_eq!(invoice.total, 10_880);
            let tax_line = invoice.line_items.last().expect("tax line");
            assert!(tax_line.description.contains("8.80 %"), "{tax_line:?}");
            assert!(
                tax_line.description.contains("combined rate"),
                "{tax_line:?}"
            );
            assert!(
                tax_line
                    .description
                    .contains("https://example.gov/us-tax-combined-fixture"),
                "{tax_line:?}"
            );
            let snapshot = invoice.us_sales_tax_snapshot.as_ref().expect("snapshot");
            assert_eq!(snapshot["rateKind"], "combined");
            assert_eq!(snapshot["rateBps"], 880);
            assert_eq!(snapshot["stateRateBps"], 725);
            assert_eq!(snapshot["combinedRateBps"], 880);
            assert_eq!(
                snapshot["source"],
                "https://example.gov/us-tax-combined-fixture"
            );

            // The combined stamp goes stale: the invoice is REFUSED, naming
            // the combined source (the used stamp governs).
            let stale = fixture_config(
                &[combined_row(
                    today() - Duration::days(1),
                    today() - Duration::days(200),
                )],
                120,
            );
            set_test_table(Some(stale));
            let error = create_invoice(
                &env.pool,
                invoice_input("ustax_combined", "Platform", 10_000),
            )
            .await
            .expect_err("a stale combined stamp refuses the invoice");
            assert!(error.to_string().contains("STALE"), "{error}");
            assert!(
                error
                    .to_string()
                    .contains("https://example.gov/us-tax-combined-fixture"),
                "the refusal names the combined source: {error}"
            );
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*)::bigint FROM invoices WHERE tenant_id = $1")
                    .bind("ustax_combined")
                    .fetch_one(&env.pool)
                    .await
                    .expect("count");
            assert_eq!(count, 1, "the refusal wrote nothing");
        }
    );

    // ------------------------------------------------------------------
    // Every invoice kind, and the filing report
    // ------------------------------------------------------------------

    async fn set_plan(env: &Env, tenant: &str, plan: &str) {
        sqlx::query("UPDATE tenants SET plan = $2 WHERE id = $1")
            .bind(tenant)
            .bind(plan)
            .execute(&env.pool)
            .await
            .expect("set plan");
    }

    async fn send_emails(env: &Env, tenant: &str, quantity: i64, at: DateTime<Utc>) {
        sqlx::query(
            "INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp) \
             VALUES (gen_random_uuid(), $1, 'emails_sent', $2, $3)",
        )
        .bind(tenant)
        .bind(quantity)
        .bind(at)
        .execute(&env.pool)
        .await
        .expect("metered emails");
    }

    // EVERY production invoice kind is taxed on the WHOLE subtotal when the
    // state is registered: subscription-overage, PAYG usage, contract
    // product lines, and add-on line invoices (dedicated IP / EU-only
    // routing / mailboxes). All writers share `create_invoice_in_tx`, so
    // this pins that nothing escapes through a different path.
    env_test!(
        every_invoice_kind_carries_the_tax_on_the_whole_subtotal,
        |env| {
            let config = install_table(&[fixture_row(
                "CA",
                725,
                THRESHOLD,
                "calendar",
                today() - Duration::days(1),
            )]);
            register_state(&env.pool, &config, "CA", "owner", None, Utc::now())
                .await
                .expect("register CA");
            let now = Utc::now();

            // (1) Subscription overage: the real sweep, end to end.
            let sub_tenant = "ustax_kind_sub";
            seed_tenant(env, sub_tenant, "US", Some("CA")).await;
            let overage_end = now - Duration::days(2);
            let overage_start = overage_end - Duration::days(30);
            sqlx::query(
            "INSERT INTO billing_periods (id, tenant_id, usage_kind, period_start, period_end, \
             currency, plan_name, email_allowance, overage_rate_millicents) \
             VALUES (gen_random_uuid(), $1, 'subscription', $2, $3, 'USD', 'growth', 1000, 35000)",
        )
        .bind(sub_tenant)
        .bind(overage_start)
        .bind(overage_end)
        .execute(&env.pool)
        .await
        .expect("subscription period");
            send_emails(env, sub_tenant, 1_500, overage_start + Duration::days(1)).await;
            let sweep = crate::overage::sweep_period_overage(&env.state)
                .await
                .expect("overage sweep");
            assert_eq!(sweep.invoices_created, 1, "the overage invoice issued");
            let overage_invoice: (i64, i64, String) = sqlx::query_as(
                "SELECT subtotal, us_sales_tax_cents, currency FROM invoices \
             WHERE tenant_id = $1 AND overage_period IS NOT NULL",
            )
            .bind(sub_tenant)
            .fetch_one(&env.pool)
            .await
            .expect("overage invoice");
            assert!(overage_invoice.0 > 0);
            assert_eq!(
                overage_invoice.1,
                sales_tax_cents(overage_invoice.0, 725),
                "subscription overage: tax on the whole subtotal"
            );
            assert_eq!(overage_invoice.2, "usd");

            // (2) PAYG usage: the same sweep's other half (a EUR invoice — the
            // PAYG snapshot currency; the tax is 7.25 % of the whole subtotal in
            // that currency, reported as a non-USD gap by the report).
            let payg_tenant = "ustax_kind_payg";
            seed_tenant(env, payg_tenant, "US", Some("CA")).await;
            set_plan(env, payg_tenant, "payg").await;
            let (month_start, month_end) = crate::overage::recent_completed_calendar_months(now)[0];
            send_emails(env, payg_tenant, 250_000, month_start + Duration::days(1)).await;
            let payg_sweep = crate::overage::sweep_period_overage(&env.state)
                .await
                .expect("payg sweep");
            assert!(
                payg_sweep.payg_invoices_created >= 1,
                "the PAYG invoice issued"
            );
            let payg_invoice: (i64, i64, String) = sqlx::query_as(
                "SELECT subtotal, us_sales_tax_cents, currency FROM invoices \
             WHERE tenant_id = $1 AND overage_period = $2",
            )
            .bind(payg_tenant)
            .bind(month_start)
            .fetch_one(&env.pool)
            .await
            .expect("payg invoice");
            assert!(payg_invoice.0 > 0);
            assert_eq!(
                payg_invoice.1,
                sales_tax_cents(payg_invoice.0, 725),
                "PAYG usage: tax on the whole subtotal"
            );
            assert_eq!(payg_invoice.2, "eur");
            assert!(month_end > month_start);

            // (3) Contract product lines: the real monthly sweep (Platform base
            // + subaccounts), a USD tenant.
            let pl_tenant = "ustax_kind_pl";
            seed_tenant(env, pl_tenant, "US", Some("CA")).await;
            sqlx::query(
                "UPDATE tenants SET settings = '{\"billingCurrency\":\"USD\"}' WHERE id = $1",
            )
            .bind(pl_tenant)
            .execute(&env.pool)
            .await
            .expect("billing currency");
            sqlx::query(
            "INSERT INTO product_line_contracts (tenant_id, product_line, status, active_from) \
             VALUES ($1, 'platform', 'active', $2)",
        )
        .bind(pl_tenant)
        .bind(month_start - Duration::days(40))
        .execute(&env.pool)
        .await
        .expect("platform contract");
            send_emails(env, pl_tenant, 10, month_start + Duration::days(2)).await;
            let pl_sweep = crate::product_lines::sweep_product_line_months(&env.state)
                .await
                .expect("product-line sweep");
            assert!(pl_sweep.invoices_created >= 1, "{pl_sweep:?}");
            let pl_invoice: (i64, i64, String) = sqlx::query_as(
                "SELECT subtotal, us_sales_tax_cents, currency FROM invoices \
             WHERE tenant_id = $1 AND product_lines_period = $2",
            )
            .bind(pl_tenant)
            .bind(month_start)
            .fetch_one(&env.pool)
            .await
            .expect("product-line invoice");
            assert!(pl_invoice.0 > 0);
            assert_eq!(
                pl_invoice.1,
                sales_tax_cents(pl_invoice.0, 725),
                "product lines: tax on the whole subtotal"
            );
            assert_eq!(pl_invoice.2, "usd");

            // (4) Add-on lines (dedicated IP, EU-only routing, mailboxes) on the
            // canonical writer: the tax is on the whole multi-line subtotal,
            // rounded half-up exactly once.
            let addon_tenant = "ustax_kind_addons";
            seed_tenant(env, addon_tenant, "US", Some("CA")).await;
            let addon_invoice = create_invoice(
                &env.pool,
                CreateInvoiceInput {
                    tenant_id: addon_tenant.to_string(),
                    adyen_psp_reference: None,
                    line_items: vec![
                        NewLineItem {
                            description: "Dedicated IP (2026-10) — 15.00/month".to_string(),
                            quantity: 1,
                            unit_price: 1_500,
                        },
                        NewLineItem {
                            description: "EU-only routing (2026-10) — 29.00/month".to_string(),
                            quantity: 1,
                            unit_price: 2_900,
                        },
                        NewLineItem {
                            description: "Mailboxes (2026-10) — 3 seats".to_string(),
                            quantity: 3,
                            unit_price: 900,
                        },
                    ],
                    period_start: now - Duration::days(30),
                    period_end: now,
                    due_at: None,
                    currency: Some("usd".to_string()),
                    overage_period: None,
                    product_lines_period: None,
                },
            )
            .await
            .expect("add-on invoice");
            assert_eq!(addon_invoice.subtotal, 7_100, "1500 + 2900 + 3×900");
            // 7.25 % of $71.00 = 5.1475 → $5.15 (half-up once).
            assert_eq!(addon_invoice.us_sales_tax_cents, 515);
            assert_eq!(addon_invoice.total, 7_615);
            assert_eq!(addon_invoice.line_items.len(), 4, "three add-ons + tax");
            let tax_line = addon_invoice.line_items.last().expect("tax line");
            assert_eq!(tax_line.vat_rate, 0.0);
            assert_eq!(tax_line.vat_amount, 0);
        }
    );

    // The filing report: per-state USD figures from the DB, credit notes
    // netting the period's taxable/exempt sales through the credited
    // invoice's state, and the honest gaps (unknown state, non-USD,
    // unattributed credits) — deterministic between runs, JSON and CSV.
    env_test!(
        report_nets_credit_notes_and_reports_gaps_deterministically,
        |env| {
            let config = install_table(&[
                fixture_row(
                    "CA",
                    725,
                    THRESHOLD,
                    "calendar",
                    today() - Duration::days(1),
                ),
                not_taxable_row("TX", today() - Duration::days(1)),
            ]);
            register_state(&env.pool, &config, "CA", "owner", None, Utc::now())
                .await
                .expect("register CA");

            // A taxed CA invoice (multi-line), an EXEMPT CA invoice, and a
            // TX invoice (not_taxable → no tax anywhere).
            seed_tenant(env, "ustax_report_ca", "US", Some("CA")).await;
            let taxed = create_invoice(
                &env.pool,
                CreateInvoiceInput {
                    line_items: vec![
                        NewLineItem {
                            description: "Platform base".to_string(),
                            quantity: 1,
                            unit_price: 8_000,
                        },
                        NewLineItem {
                            description: "Dedicated IP".to_string(),
                            quantity: 1,
                            unit_price: 2_000,
                        },
                    ],
                    ..invoice_input("ustax_report_ca", "ignored", 0)
                },
            )
            .await
            .expect("taxed invoice");
            assert_eq!(taxed.subtotal, 10_000);
            assert_eq!(taxed.us_sales_tax_cents, 725);

            upsert_exemption(
                &env.pool,
                &ExemptionInput {
                    tenant_id: "ustax_report_ca".to_string(),
                    state: "CA".to_string(),
                    certificate_id: "MTC-999".to_string(),
                    expires_at: Some(today() + Duration::days(90)),
                    note: None,
                },
                "owner",
                Utc::now(),
            )
            .await
            .expect("exemption");
            let exempt = create_invoice(
                &env.pool,
                invoice_input("ustax_report_ca", "Platform", 5_000),
            )
            .await
            .expect("exempt invoice");
            assert_eq!(exempt.us_sales_tax_cents, 0);
            assert!(exempt.us_sales_tax_snapshot.is_some());

            seed_tenant(env, "ustax_report_tx", "US", Some("TX")).await;
            let tx = create_invoice(
                &env.pool,
                invoice_input("ustax_report_tx", "Platform", 2_000),
            )
            .await
            .expect("TX invoice");
            assert_eq!(tx.us_sales_tax_cents, 0);

            // Gaps: an invoice with no recognisable state, and a non-USD one.
            let issued = Utc::now() - Duration::days(1);
            seed_invoice(
                env,
                "ustax_report_unknown",
                "usd",
                "US",
                Some(serde_json::json!({ "state": "California" })),
                3_000,
                issued,
                "draft",
            )
            .await;
            seed_invoice(
                env,
                "ustax_report_eur",
                "eur",
                "US",
                Some(serde_json::json!({ "state": "CA" })),
                4_000,
                issued,
                "draft",
            )
            .await;

            // Credit the taxed invoice: the credit is dated by ITS created_at
            // month and attributed through the credited invoice's state.
            sqlx::query("UPDATE invoices SET status = 'paid' WHERE id = $1")
                .bind(taxed.id)
                .execute(&env.pool)
                .await
                .expect("mark paid");
            crate::credit_notes::create_credit_note(
                &env.pool,
                crate::credit_notes::CreateCreditNoteInput {
                    invoice_id: taxed.id,
                    amount: 2_000,
                    reason: "service credit".to_string(),
                    tenant_id: "ustax_report_ca".to_string(),
                    idempotency_key: "ustax-report-credit".to_string(),
                },
            )
            .await
            .expect("credit note");

            let now = Utc::now();
            let period =
                UsTaxReportPeriod::parse(&now.format("%Y-%m").to_string()).expect("current month");
            let report = us_tax_report(&env.pool, period, now).await.expect("report");
            assert_eq!(report.rate_file_error, None);
            assert_eq!(report.rate_file_source, "test fixture");

            let ca = report
                .states
                .iter()
                .find(|row| row.state == "CA")
                .expect("CA row");
            assert_eq!(ca.taxability, "taxable");
            assert_eq!(ca.registration_status, "registered");
            assert_eq!(ca.invoice_count, 2);
            assert_eq!(ca.gross_sales_cents, 15_000);
            assert_eq!(ca.taxable_sales_cents, 10_000);
            assert_eq!(ca.exempt_sales_cents, 5_000);
            assert_eq!(ca.tax_collected_cents, 725);
            assert_eq!(ca.credit_note_count, 1);
            assert_eq!(ca.credited_taxed_cents, 2_000);
            assert_eq!(ca.credited_exempt_cents, 0);
            assert_eq!(
                ca.net_taxable_sales_cents, 8_000,
                "credits net taxable sales"
            );
            assert_eq!(ca.net_exempt_sales_cents, 5_000);
            assert_eq!(ca.rates_used.len(), 1);
            assert_eq!(ca.rates_used[0].rate_bps, 725);
            assert_eq!(ca.rates_used[0].rate_kind, "state");
            assert_eq!(ca.rates_used[0].invoices, 1);
            assert_eq!(ca.rates_used[0].tax_cents, 725);
            assert_eq!(
                ca.rate_row.as_ref().expect("rate row").taxability,
                "taxable"
            );

            let tx = report
                .states
                .iter()
                .find(|row| row.state == "TX")
                .expect("TX row");
            assert_eq!(tx.taxability, "not_taxable", "reported distinctly");
            assert_eq!(tx.registration_status, "not_tracked");
            assert_eq!(tx.taxable_sales_cents, 0);
            assert_eq!(tx.tax_collected_cents, 0);
            assert_eq!(tx.gross_sales_cents, 2_000);

            assert_eq!(report.totals.invoice_count, 3, "USD-attributed invoices");
            assert_eq!(report.totals.taxable_sales_cents, 10_000);
            assert_eq!(report.totals.exempt_sales_cents, 5_000);
            assert_eq!(report.totals.tax_collected_cents, 725);
            assert_eq!(report.totals.net_taxable_sales_cents, 8_000);

            assert_eq!(report.gaps.unknown_state_invoices, 1);
            assert_eq!(report.gaps.unknown_state_gross_cents, 3_000);
            assert_eq!(report.gaps.unattributed_credit_note_count, 0);
            assert_eq!(report.gaps.non_usd.len(), 1);
            assert_eq!(report.gaps.non_usd[0].currency, "EUR");
            assert_eq!(report.gaps.non_usd[0].invoice_count, 1);
            assert_eq!(report.gaps.non_usd[0].gross_sales_cents, 4_000);

            // JSON: deterministic, camelCase, integer cents.
            let json = report.to_json();
            assert_eq!(json["period"], period.label());
            assert_eq!(json["states"][0]["state"], "CA");
            assert_eq!(json["totals"]["taxCollectedCents"], 725);
            assert_eq!(json["gaps"]["unknownStateInvoices"], 1);

            // CSV: one row per state, then TOTAL; deterministic across runs.
            let csv = report.to_csv();
            let header = csv.lines().next().expect("header");
            assert!(
                header.starts_with("state,taxability,registrationStatus"),
                "{header}"
            );
            assert!(
                csv.contains("CA,taxable,registered,2,15000,10000,5000,725,1,2000,0,0,8000,5000,"),
                "{csv}"
            );
            assert!(
                csv.contains("TX,not_taxable,not_tracked,1,2000,0,0,0,0,0,0,0,0,0,"),
                "{csv}"
            );
            assert!(
                csv.contains("\nTOTAL,,,3,17000,10000,5000,725,1,2000,0,0,8000,5000,\n"),
                "{csv}"
            );
            let again = us_tax_report(&env.pool, period, now).await.expect("report");
            assert_eq!(csv, again.to_csv(), "the report is deterministic");
        }
    );
}
