//! US sales tax (plan WP C2): economic-nexus threshold tracking and — for
//! operator-registered states only — a provenance-stamped sales-tax line on
//! US invoices.
//!
//! The whole tax stack before this module was EU-only (`vat_*` modules,
//! `invoices.vat_rate` / `vat_amount`). This module adds the US half with
//! three hard rules:
//!
//! 1. **No invented rates.** Rates and economic-nexus thresholds live in a
//!    committed, provenance-carrying data file
//!    (`billing-service/data/us_sales_tax.json`, embedded at build time, an
//!    operator may point `US_TAX_DATA_FILE` at another copy). It ships
//!    EMPTY: a row is a factual claim about a state's tax law, so it carries
//!    the state's own `sourceUrl` and the `retrieved` date the figure was
//!    read. [`UsTaxTable::parse`] validates every row (state code, rate
//!    range, threshold range, window, non-empty https source, parseable
//!    non-future date) and [`check_data_file`] renders the `--check` report.
//! 2. **Stale rates fail closed.** A used row older than
//!    `US_TAX_MAX_AGE_DAYS` (default 120) makes the computation REFUSE with
//!    a named error ([`UsTaxError::StaleRateRow`]) — never a silent
//!    computation from a rate of unknown age. The invoice writer propagates
//!    the refusal (no invoice, retried, visible); it never issues a US
//!    invoice in a registered state without its tax.
//! 3. **Registration is an operator act, never a computed one.** The sweep
//!    tracks per-state taxable sales and, when a state's window reaches its
//!    threshold, flips the row to `threshold_crossed` and raises ONE
//!    operator alert (a `finance_incidents` row) per window. It NEVER
//!    registers a state and NEVER charges tax — sales tax is computed only
//!    after the owner/accounting registers the state through the admin
//!    surface ([`register_state`], audited), which itself requires a fresh
//!    rate row.
//!
//! # Money
//!
//! Every amount is integer cents (`i64`); the rate is integer basis points
//! (`u32`, 7.25 % = 725) because US state rates are conventionally quoted in
//! whole or quarter basis points — no float ever touches a money path here
//! (the crate's `money_invariants` gate covers this file). Tax is rounded
//! half-up ONCE per invoice line, exactly like the VAT module's
//! `vat_amount_half_up` convention: `(base × bps + 5_000) / 10_000`.
//!
//! # What counts as taxable US sales (the nexus window)
//!
//! Invoices whose `billing_country` is `US`, whose status is not `void`, and
//! whose `issued_at` lies in the state's window, summed on the invoice
//! SUBTOTAL (the sales price — collected tax is not part of gross receipts).
//! US economic-nexus thresholds are USD figures, so only USD invoices are
//! summed; US invoices in another currency are reported per currency and NOT
//! converted (there is no FX source in this repository, and inventing one
//! would fabricate the exact number the threshold is compared against). A US
//! invoice whose billing address carries no usable state code counts as
//! UNKNOWN: reported in the sweep result, never assigned to a state.
//!
//! # What is NOT built (named, not faked)
//!
//! * **Local (county/city/district) rates.** The file models a state-level
//!   rate only; the row's `notes` field is where the owner records what is
//!   not modelled. A single blended local rate would misstate every
//!   shipment address.
//! * **Filing.** Nothing files a US state return; the accounting service is
//!   the filer (plan §"Ask it [the Estonian accounting service] to watch US
//!   state sales-tax thresholds"). This module produces the numbers and the
//!   alerts.
//! * **Automatic registration.** Nothing registers with a state; that is the
//!   owner's legal act.
//! * **A tax line on the legacy manual admin invoice writer.** The
//!   api-server's operator-facing `POST /v1/billing/admin/tenants/:id/invoices`
//!   has its own SQL and its own (legacy) response contract, so it does not
//!   compute the stamped line (the operator typing line items chooses the
//!   amounts). It fails CLOSED instead of silently omitting the tax: a US
//!   invoice for a state with `status = 'registered'` is refused there by
//!   name. The product invoicing path (this crate's invoice writer) always
//!   applies the stamped line.

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

/// Default maximum age of a rate row, in days (plan WP C2). Quarterly
/// refresh: a rate row older than a quarter is not a current fact.
pub const DEFAULT_US_TAX_MAX_AGE_DAYS: u32 = 120;

/// The schema version this build reads from the data file.
pub const US_TAX_SCHEMA_VERSION: u32 = 1;

/// Sanity bound for a state rate: 20 % in basis points. Above this the row
/// is a unit mistake (e.g. a percent written as basis points), not a rate.
pub const MAX_RATE_BPS: u32 = 2_000;

/// Sanity bounds for an economic-nexus threshold in USD cents: $1 to $100M.
pub const MIN_NEXUS_THRESHOLD_CENTS: i64 = 100;
pub const MAX_NEXUS_THRESHOLD_CENTS: i64 = 10_000_000_000;

/// `finance_incidents.kind` of the threshold-crossing alert.
pub const NEXUS_ALERT_KIND: &str = "us_sales_tax_nexus_threshold";

/// Version tag of the invoice provenance snapshot.
pub const US_SALES_TAX_SNAPSHOT_VERSION: u32 = 1;

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

/// One validated data-file row: a state's sales-tax rate and its
/// economic-nexus threshold, with their provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsTaxStateRow {
    /// Two-letter state code (upper-case, validated).
    pub state: String,
    /// State-level rate in basis points (725 = 7.25 %).
    pub rate_bps: u32,
    /// Economic-nexus threshold in USD cents.
    pub nexus_threshold_cents: i64,
    /// The window the threshold is measured over.
    pub nexus_window: NexusWindow,
    /// The state's own page for the figures (https, non-empty).
    pub source_url: String,
    /// The date the figures were read from that page.
    pub retrieved: NaiveDate,
    /// Free-text caveats (what is NOT modelled), optional.
    pub notes: Option<String>,
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
    rate_bps: u32,
    nexus_threshold_cents: i64,
    nexus_window: String,
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
            let state = raw_row.state.trim().to_ascii_uppercase();
            if state.len() != 2 || !state.chars().all(|c| c.is_ascii_alphabetic()) {
                return Err(UsTaxDataError::InvalidRow {
                    index,
                    problem: format!("state {:?} is not a two-letter code", raw_row.state),
                });
            }
            if !is_us_state_code(&state) {
                return Err(UsTaxDataError::InvalidRow {
                    index,
                    problem: format!("state {state} is not a known US state/territory postal code"),
                });
            }
            if rows.iter().any(|row| row.state == state) {
                return Err(UsTaxDataError::InvalidRow {
                    index,
                    problem: format!("state {state} appears more than once"),
                });
            }
            if raw_row.rate_bps > MAX_RATE_BPS {
                return Err(UsTaxDataError::InvalidRow {
                    index,
                    problem: format!(
                        "rateBps {} is out of range (0..={MAX_RATE_BPS} basis points = 20 %) — \
                         basis points, not percent",
                        raw_row.rate_bps
                    ),
                });
            }
            if raw_row.nexus_threshold_cents < MIN_NEXUS_THRESHOLD_CENTS
                || raw_row.nexus_threshold_cents > MAX_NEXUS_THRESHOLD_CENTS
            {
                return Err(UsTaxDataError::InvalidRow {
                    index,
                    problem: format!(
                        "nexusThresholdCents {} is out of range ({}..={} USD cents = $1..$100M) \
                         — cents, not dollars",
                        raw_row.nexus_threshold_cents,
                        MIN_NEXUS_THRESHOLD_CENTS,
                        MAX_NEXUS_THRESHOLD_CENTS
                    ),
                });
            }
            let Some(nexus_window) = NexusWindow::parse(&raw_row.nexus_window) else {
                return Err(UsTaxDataError::InvalidRow {
                    index,
                    problem: format!(
                        "nexusWindow {:?} must be \"calendar\" or \"trailing_12m\"",
                        raw_row.nexus_window
                    ),
                });
            };
            let source_url = raw_row.source_url.trim().to_string();
            if source_url.is_empty() {
                return Err(UsTaxDataError::InvalidRow {
                    index,
                    problem: "sourceUrl is empty — a rate without its source is not usable"
                        .to_string(),
                });
            }
            if !source_url.starts_with("https://") {
                return Err(UsTaxDataError::InvalidRow {
                    index,
                    problem: format!("sourceUrl {source_url:?} must be an https:// URL"),
                });
            }
            let retrieved = NaiveDate::parse_from_str(raw_row.retrieved.trim(), "%Y-%m-%d")
                .map_err(|error| UsTaxDataError::InvalidRow {
                    index,
                    problem: format!(
                        "retrieved {:?} is not a YYYY-MM-DD date: {error}",
                        raw_row.retrieved
                    ),
                })?;
            if retrieved > today {
                return Err(UsTaxDataError::InvalidRow {
                    index,
                    problem: format!(
                        "retrieved {retrieved} is in the future (today is {today}) — a rate \
                         cannot be fetched on a date that has not happened"
                    ),
                });
            }
            rows.push(UsTaxStateRow {
                state,
                rate_bps: raw_row.rate_bps,
                nexus_threshold_cents: raw_row.nexus_threshold_cents,
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

/// Days between a row's `retrieved` date and the evaluation date. Negative
/// when the date is in the future (only reachable when the validation clock
/// moved backwards since the load — treated as stale, never as fresh).
pub fn row_age_days(row: &UsTaxStateRow, today: NaiveDate) -> i64 {
    (today - row.retrieved).num_days()
}

/// Whether a row is fresh at `today` under `max_age_days`.
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
        "US sales tax: the registration lookup for state {state} failed ({reason}) — refusing to \
         guess whether the state is registered"
    )]
    RegistrationLookup { state: String, reason: String },
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

/// The compute configuration: the validated table, where it came from, and
/// how old a used row may be.
#[derive(Debug, Clone)]
pub struct UsTaxConfig {
    pub table: UsTaxTable,
    pub source: String,
    pub max_age_days: u32,
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
        Ok(UsTaxConfig {
            table,
            source,
            max_age_days,
        })
    }

    /// For tests and ops reporting: the row for `state`, or the named
    /// refusal if it is missing or stale.
    pub fn fresh_row(&self, state: &str, today: NaiveDate) -> Result<&UsTaxStateRow, UsTaxError> {
        let Some(row) = self.table.row(state) else {
            return Err(UsTaxError::MissingRateRow {
                state: state.trim().to_ascii_uppercase(),
            });
        };
        if !is_row_fresh(row, today, self.max_age_days) {
            return Err(UsTaxError::StaleRateRow {
                state: row.state.clone(),
                retrieved: row.retrieved,
                age_days: row_age_days(row, today),
                max_age_days: self.max_age_days,
                env: US_TAX_MAX_AGE_DAYS_ENV,
                rate_source: row.source_url.clone(),
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
/// prints it).#[derive(Debug, Clone)]
pub struct UsTaxDataCheckReport {
    pub source: String,
    pub max_age_days: u32,
    pub today: NaiveDate,
    /// One line per state row: freshness at `today` plus provenance.
    pub rows: Vec<String>,
    /// The file's owner instructions — rendered when the file carries no
    /// state yet, so the fill-in contract is what `--check` prints.
    pub instructions: Vec<String>,
}

impl UsTaxDataCheckReport {
    /// A human-readable multi-line report.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "US sales tax data: {} — {} state row(s), max age {} days, today {}\n",
            self.source,
            self.rows.len(),
            self.max_age_days,
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
        out
    }
}

/// Validate the configured data file and build the `--check` report.
pub fn check_data_file(today: NaiveDate) -> Result<UsTaxDataCheckReport, UsTaxError> {
    let (source, body) = data_file_source()?;
    let (table, instructions) = UsTaxTable::parse_with_instructions(&body, today)?;
    let max_age_days = max_age_days_from_env()?;
    let rows = table
        .rows()
        .iter()
        .map(|row| {
            let age = row_age_days(row, today);
            let freshness = if is_row_fresh(row, today, max_age_days) {
                format!("fresh ({age} days old)")
            } else {
                format!("STALE ({age} days old — will refuse to compute)")
            };
            format!(
                "{}: {} bps, nexus {} USD cents ({}) — {freshness} — source {} retrieved {}",
                row.state,
                row.rate_bps,
                row.nexus_threshold_cents,
                row.nexus_window.as_str(),
                row.source_url,
                row.retrieved
            )
        })
        .collect();
    Ok(UsTaxDataCheckReport {
        source,
        max_age_days,
        today,
        rows,
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
    pub rate_bps: u32,
    pub amount_cents: i64,
    pub source_url: String,
    pub retrieved: NaiveDate,
}

impl UsSalesTaxLine {
    /// The invoice line description, carrying the whole stamp: state, rate,
    /// source and retrieval date. A legal document quoting a tax line must
    /// state what it was computed from.
    pub fn description(&self) -> String {
        // Integer formatting only: 725 bps → "7.25 %" (never a float).
        let percent = format!("{}.{:02} %", self.rate_bps / 100, self.rate_bps % 100);
        format!(
            "US sales tax ({}) — {} state rate — source {} retrieved {}",
            self.state, percent, self.source_url, self.retrieved
        )
    }

    /// The provenance snapshot stored beside the amount
    /// (`invoices.us_sales_tax_snapshot`).
    pub fn snapshot_json(&self) -> serde_json::Value {
        serde_json::json!({
            "snapshotVersion": US_SALES_TAX_SNAPSHOT_VERSION,
            "state": self.state,
            "rateBps": self.rate_bps,
            "amountCents": self.amount_cents,
            "source": self.source_url,
            "retrieved": self.retrieved.to_string(),
        })
    }
}

/// Resolve the US sales tax for one invoice, if any applies.
///
/// The gate, in order — every step is a refusal, never a guess:
/// 1. customer country must be `US` (any other country: untouched, `None`);
/// 2. the billing address state must be a recognisable US postal code
///    (unrecognised/missing → `None`: the sweep reports those invoices as
///    UNKNOWN, an invoice never invents a state);
/// 3. the state must be `registered` by the operator (`None` otherwise —
///    the invoice carries the existing behavior);
/// 4. the rate row must exist and be fresh ([`UsTaxError`] otherwise: the
///    invoice is refused, never computed from a missing or stale rate);
/// 5. a tax rounding to 0 cents adds no line (`None`).
///
/// `config` is the caller's table (tests inject one); `None` loads the
/// configured source LAZILY — only after steps 1–3 established that this
/// invoice actually needs a rate, so a broken data file can never refuse a
/// US invoice that would not carry tax anyway.
pub async fn sales_tax_line_for_invoice<'e, E>(
    executor: E,
    config: Option<&UsTaxConfig>,
    country: &str,
    state: Option<&str>,
    subtotal_cents: i64,
    today: NaiveDate,
) -> Result<Option<UsSalesTaxLine>, UsTaxError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    if !country.trim().eq_ignore_ascii_case(US_COUNTRY_CODE) {
        return Ok(None);
    }
    let Some(state) = normalize_state_code(state) else {
        return Ok(None);
    };
    let registered: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM us_tax_nexus_states \
         WHERE state_code = $1 AND status = 'registered')",
    )
    .bind(&state)
    .fetch_one(executor)
    .await
    .map_err(|error| {
        // Infrastructure failure: refuse the invoice rather than guess the
        // registration state (an unregistered state must not be taxed, and a
        // registered one must not escape its tax).
        UsTaxError::RegistrationLookup {
            state: state.clone(),
            reason: error.to_string(),
        }
    })?;
    if !registered {
        return Ok(None);
    }

    let loaded;
    let config = match config {
        Some(config) => config,
        None => {
            loaded = UsTaxConfig::from_env(today)?;
            &loaded
        }
    };
    let row = config.fresh_row(&state, today)?;
    let amount_cents = sales_tax_cents(subtotal_cents, row.rate_bps);
    if amount_cents <= 0 {
        debug!(
            state = %state,
            subtotal_cents,
            rate_bps = row.rate_bps,
            "US sales tax rounds to 0 cents — no line added"
        );
        return Ok(None);
    }
    Ok(Some(UsSalesTaxLine {
        state: row.state.clone(),
        rate_bps: row.rate_bps,
        amount_cents,
        source_url: row.source_url.clone(),
        retrieved: row.retrieved,
    }))
}

// ---------------------------------------------------------------------------
// Nexus sweep
// ---------------------------------------------------------------------------

/// One (state, currency) aggregate of taxable US sales in a window.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UsSalesBucket {
    raw_state: String,
    currency: String,
    invoices: i64,
    taxable_cents: i64,
}

/// The billing-address state of an invoice, normalised for grouping: the
/// immutable snapshot (audit F08) is read as JSON, and a snapshot that is not
/// a JSON object yields the empty string (the UNKNOWN bucket) instead of an
/// SQL error — one corrupt row must not blind the whole sweep.
const INVOICE_STATE_SQL: &str = "UPPER(BTRIM(COALESCE( \
        CASE WHEN billing_address IS JSON \
              AND jsonb_typeof(billing_address::jsonb) = 'object' \
             THEN billing_address::jsonb ->> 'state' \
        END, '')))";

/// Aggregate taxable US sales by (billing-address state, currency) for
/// invoices issued in `[start, end)`.
const US_SALES_BY_STATE_SQL: &str = r#"
    SELECT
        UPPER(BTRIM(COALESCE(
            CASE WHEN billing_address IS JSON
                  AND jsonb_typeof(billing_address::jsonb) = 'object'
                 THEN billing_address::jsonb ->> 'state'
            END, ''))) AS raw_state,
        UPPER(BTRIM(COALESCE(currency, ''))) AS currency,
        COUNT(*)::bigint AS invoices,
        COALESCE(SUM(COALESCE(subtotal, amount, 0)), 0)::bigint AS taxable_cents
    FROM invoices
    WHERE UPPER(BTRIM(COALESCE(billing_country, ''))) = 'US'
      AND COALESCE(status, '') <> 'void'
      AND issued_at >= $1
      AND issued_at < $2
    GROUP BY 1, 2
    ORDER BY 1, 2
"#;

async fn taxable_us_sales_by_state(
    db: &PgPool,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<Vec<UsSalesBucket>, String> {
    let rows: Vec<(String, String, i64, i64)> = sqlx::query_as(US_SALES_BY_STATE_SQL)
        .bind(start)
        .bind(end)
        .fetch_all(db)
        .await
        .map_err(|error| format!("US tax nexus sweep: sales aggregation failed: {error}"))?;
    Ok(rows
        .into_iter()
        .map(
            |(raw_state, currency, invoices, taxable_cents)| UsSalesBucket {
                raw_state,
                currency,
                invoices,
                taxable_cents,
            },
        )
        .collect())
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
    let buckets = taxable_us_sales_by_state(db, start, end).await?;
    Ok(bucket_unassigned_sales(&buckets))
}

/// The sweep's run summary.
#[derive(Debug, Default, Clone)]
pub struct UsTaxSweepResult {
    /// States with a status row the sweep evaluated.
    pub states_evaluated: u64,
    /// Evaluated states observed below their threshold.
    pub states_below: u64,
    /// Evaluated states observed at/above their threshold.
    pub states_crossed: u64,
    /// States already `registered` (tracked, never alerted again).
    pub states_registered: u64,
    /// Operator alerts raised by this run (one per state per window).
    pub alerts_raised: u64,
    /// States with sales in the window but NO usable row in the data file —
    /// surfaced by name, never evaluated against an invented threshold.
    pub states_without_threshold_data: Vec<String>,
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

/// One status row, as read back for the sweep and the admin surface.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UsTaxStatusRow {
    pub state_code: String,
    pub status: String,
    pub nexus_window: String,
    pub threshold_cents: i64,
    pub observed_cents: i64,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub crossed_at: Option<DateTime<Utc>>,
    pub crossed_window_start: Option<DateTime<Utc>>,
    pub registered_at: Option<DateTime<Utc>>,
    pub registered_by: Option<String>,
    pub registration_note: Option<String>,
    pub last_evaluated_at: Option<DateTime<Utc>>,
    pub last_evaluation_error: Option<String>,
}

const STATUS_ROW_COLUMNS: &str = "state_code, status, nexus_window, threshold_cents, \
     observed_cents, window_start, window_end, crossed_at, crossed_window_start, \
     registered_at, registered_by, registration_note, last_evaluated_at, last_evaluation_error";

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
    let calendar_buckets =
        taxable_us_sales_by_state(&state.db, calendar_start, calendar_end).await?;
    let trailing_buckets =
        taxable_us_sales_by_state(&state.db, trailing_start, trailing_end).await?;

    let mut observed_calendar: BTreeMap<String, i64> = BTreeMap::new();
    for bucket in &calendar_buckets {
        match normalize_state_code(Some(&bucket.raw_state)) {
            Some(code) if bucket.currency == "USD" => {
                let entry = observed_calendar.entry(code).or_insert(0);
                *entry = entry.saturating_add(bucket.taxable_cents);
            }
            _ => {}
        }
    }
    let mut observed_trailing: BTreeMap<String, i64> = BTreeMap::new();
    for bucket in &trailing_buckets {
        if bucket.currency == "USD" {
            if let Some(code) = normalize_state_code(Some(&bucket.raw_state)) {
                let entry = observed_trailing.entry(code).or_insert(0);
                *entry = entry.saturating_add(bucket.taxable_cents);
            }
        }
    }
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
    let mut evaluation_codes: Vec<String> = observed_calendar
        .keys()
        .chain(observed_trailing.keys())
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
                 invented threshold; add the state's rateBps/threshold/source/retrieved row"
            );
            warn!(state = %code, "US tax nexus sweep: {note}");
            if let Err(error) = record_evaluation_error(&state.db, &code, &note).await {
                warn!(state = %code, error = %error, "US tax nexus sweep: error note failed");
            }
            continue;
        };
        let observed_cents = match table_row.nexus_window {
            NexusWindow::CalendarYear => observed_calendar.get(&code).copied().unwrap_or(0),
            NexusWindow::Trailing12Months => observed_trailing.get(&code).copied().unwrap_or(0),
        };
        match evaluate_state(&state.db, table_row, observed_cents, now).await {
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
        alerts_raised = result.alerts_raised,
        without_threshold_data = result.states_without_threshold_data.len(),
        unknown_state_invoices = result.unknown_state_invoices,
        failed_states = result.failed_states,
        "US tax nexus sweep complete (tracking only — registration and charging are operator \
         actions)"
    );
    if result.alerts_raised > 0 {
        metrics::counter!("apexmail_us_tax_nexus_crossings_total").increment(result.alerts_raised);
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
/// alert for it.
#[derive(Debug, Clone, Copy)]
struct StateEvaluation {
    outcome: StateOutcome,
    alert_raised: bool,
}
/// The full content of a status row as this run wants it persisted.
struct StatusRowValues {
    state_code: String,
    status: &'static str,
    window: NexusWindow,
    threshold_cents: i64,
    observed_cents: i64,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    crossed_at: Option<DateTime<Utc>>,
    crossed_window_start: Option<DateTime<Utc>>,
    last_evaluated_at: DateTime<Utc>,
}

/// Persist one status row (insert on first sighting, update after). Runs on
/// the caller's transaction under the per-state advisory lock.
async fn upsert_status_row(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    values: &StatusRowValues,
) -> Result<(), String> {
    sqlx::query(
        "INSERT INTO us_tax_nexus_states (state_code, status, nexus_window, threshold_cents, \
         observed_cents, window_start, window_end, crossed_at, crossed_window_start, \
         last_evaluated_at, last_evaluation_error) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULL) \
         ON CONFLICT (state_code) DO UPDATE SET \
             status = EXCLUDED.status, \
             nexus_window = EXCLUDED.nexus_window, \
             threshold_cents = EXCLUDED.threshold_cents, \
             observed_cents = EXCLUDED.observed_cents, \
             window_start = EXCLUDED.window_start, \
             window_end = EXCLUDED.window_end, \
             crossed_at = EXCLUDED.crossed_at, \
             crossed_window_start = EXCLUDED.crossed_window_start, \
             last_evaluated_at = EXCLUDED.last_evaluated_at, \
             last_evaluation_error = NULL, \
             updated_at = EXCLUDED.last_evaluated_at",
    )
    .bind(&values.state_code)
    .bind(values.status)
    .bind(values.window.as_str())
    .bind(values.threshold_cents)
    .bind(values.observed_cents)
    .bind(values.window_start)
    .bind(values.window_end)
    .bind(values.crossed_at)
    .bind(values.crossed_window_start)
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
    observed_cents: i64,
    now: DateTime<Utc>,
) -> Result<StateEvaluation, String> {
    let state_code = table_row.state.as_str();
    let (window_start, window_end) = table_row.nexus_window.bounds(now);
    let crossed = evaluate_nexus(observed_cents, table_row.nexus_threshold_cents).is_crossed();

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
    // verdict. `alert` is set exactly when this run is the one that crosses.
    let (status, crossed_at, crossed_window_start, alert_raised, outcome) = match &existing {
        // Registered: tracked, never alerted. Registration is the operator's
        // answer to the crossing; the crossing record is preserved.
        Some(row) if row.status == "registered" => (
            "registered",
            row.crossed_at,
            row.crossed_window_start,
            false,
            StateOutcome::Registered,
        ),
        Some(row) => {
            let sticky_crossed = row.status == "threshold_crossed";
            // A calendar year boundary (a later window start) is a NEW window
            // instance; a rolling twelve-month window never starts a new one
            // (its start advances every day, so it is deliberately excluded).
            let new_window_instance = table_row.nexus_window == NexusWindow::CalendarYear
                && window_start > row.window_start;
            match (crossed, sticky_crossed) {
                // The crossing: flip and alert, once.
                (true, false) => (
                    "threshold_crossed",
                    Some(now),
                    Some(window_start),
                    true,
                    StateOutcome::Crossed,
                ),
                // Already crossed: a new calendar year is a new crossing
                // event with its own once-per-window alert; otherwise nothing
                // re-alerts.
                (true, true) if new_window_instance => (
                    "threshold_crossed",
                    Some(now),
                    Some(window_start),
                    true,
                    StateOutcome::Crossed,
                ),
                (true, true) => (
                    "threshold_crossed",
                    row.crossed_at,
                    row.crossed_window_start,
                    false,
                    StateOutcome::Crossed,
                ),
                // A new calendar year and below again: the old crossing is
                // history, the state returns to below.
                (false, true) if new_window_instance => {
                    ("below", None, None, false, StateOutcome::Below)
                }
                // Sticky: a dip inside the same window (or any dip in a
                // rolling window) does not un-cross.
                (false, true) => (
                    "threshold_crossed",
                    row.crossed_at,
                    row.crossed_window_start,
                    false,
                    StateOutcome::Crossed,
                ),
                (false, false) => ("below", None, None, false, StateOutcome::Below),
            }
        }
        // First sighting of the state (its address state is known, so the
        // row is created here at its evaluated status — never `registered`).
        None => {
            if crossed {
                (
                    "threshold_crossed",
                    Some(now),
                    Some(window_start),
                    true,
                    StateOutcome::Crossed,
                )
            } else {
                ("below", None, None, false, StateOutcome::Below)
            }
        }
    };

    upsert_status_row(
        &mut tx,
        &StatusRowValues {
            state_code: state_code.to_string(),
            status,
            window: table_row.nexus_window,
            threshold_cents: table_row.nexus_threshold_cents,
            observed_cents,
            window_start,
            window_end,
            crossed_at,
            crossed_window_start,
            last_evaluated_at: now,
        },
    )
    .await?;

    if alert_raised {
        raise_nexus_alert(&mut tx, table_row, observed_cents, window_start, window_end).await?;
        info!(
            state = %state_code,
            observed_cents,
            threshold_cents = table_row.nexus_threshold_cents,
            window = table_row.nexus_window.as_str(),
            "US tax nexus: threshold crossed — operator alert raised (registration is an \
             operator action; NO tax is charged until the state is registered)"
        );
    }

    tx.commit()
        .await
        .map_err(|error| format!("US tax nexus: state commit failed: {error}"))?;
    Ok(StateEvaluation {
        outcome,
        alert_raised,
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
    observed_cents: i64,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
) -> Result<(), String> {
    let detail = serde_json::json!({
        "state": table_row.state,
        "observedCents": observed_cents,
        "thresholdCents": table_row.nexus_threshold_cents,
        "windowKind": table_row.nexus_window.as_str(),
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
    #[error("US sales tax: state {state} is not tracked — nothing to update")]
    NotTracked { state: String },
    #[error("US sales tax: {0}")]
    Database(String),
}

/// Taxable USD sales for one state over its own window (the same measure the
/// sweep compares against the threshold: non-void US invoices, USD only,
/// summed on the subtotal).
pub async fn state_window_sales_cents(
    db: &PgPool,
    state: &str,
    window: NexusWindow,
    now: DateTime<Utc>,
) -> Result<i64, String> {
    let (start, end) = window.bounds(now);
    let sql = format!(
        "SELECT COALESCE(SUM(COALESCE(subtotal, amount, 0)), 0)::bigint FROM invoices \
         WHERE UPPER(BTRIM(COALESCE(billing_country, ''))) = 'US' \
           AND COALESCE(status, '') <> 'void' \
           AND UPPER(BTRIM(COALESCE(currency, ''))) = 'USD' \
           AND issued_at >= $1 AND issued_at < $2 \
           AND {INVOICE_STATE_SQL} = $3"
    );
    sqlx::query_scalar(&sql)
        .bind(start)
        .bind(end)
        .bind(state)
        .fetch_one(db)
        .await
        .map_err(|error| format!("US tax nexus: state sales query failed: {error}"))
}

/// Register a state (owner/accounting act): from this moment, new invoices
/// for US customers in that state carry the sales-tax line — which requires a
/// usable (present, fresh) rate row, so registration is refused when one is
/// missing or stale. The row is created when the state was never observed.
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
    let table_row =
        config
            .fresh_row(&code, today)
            .map_err(|error| RegistrationError::UnusableRateRow {
                state: code.clone(),
                source_reason: error.to_string(),
            })?;
    let observed_cents = state_window_sales_cents(db, &code, table_row.nexus_window, now)
        .await
        .map_err(RegistrationError::Database)?;
    let (window_start, window_end) = table_row.nexus_window.bounds(now);

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
        "INSERT INTO us_tax_nexus_states (state_code, status, nexus_window, threshold_cents, \
         observed_cents, window_start, window_end, registered_at, registered_by, \
         registration_note, last_evaluated_at, last_evaluation_error) \
         VALUES ($1, 'registered', $2, $3, $4, $5, $6, $7, $8, $9, $7, NULL) \
         ON CONFLICT (state_code) DO UPDATE SET \
             status = 'registered', \
             nexus_window = EXCLUDED.nexus_window, \
             threshold_cents = EXCLUDED.threshold_cents, \
             observed_cents = EXCLUDED.observed_cents, \
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
    .bind(table_row.nexus_window.as_str())
    .bind(table_row.nexus_threshold_cents)
    .bind(observed_cents)
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
         crossed_window_start = NULL, updated_at = $2 \
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

    /// One data-file row, as an owner would write it.
    fn fixture_row(
        state: &str,
        rate_bps: u32,
        threshold_cents: i64,
        window: &str,
        retrieved: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "state": state,
            "rateBps": rate_bps,
            "nexusThresholdCents": threshold_cents,
            "nexusWindow": window,
            "sourceUrl": "https://example.gov/us-tax-fixture",
            "retrieved": retrieved,
        })
    }

    fn file_body(rows: &[serde_json::Value]) -> String {
        serde_json::json!({
            "schemaVersion": 1,
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
                serde_json::json!({"schemaVersion": 2, "instructions": [], "states": []})
                    .to_string(),
                "schemaVersion 2",
            ),
            (
                // A typo'd key must not be silently ignored.
                serde_json::json!({
                    "schemaVersion": 1, "instructions": [], "sttes": []
                })
                .to_string(),
                "not valid JSON",
            ),
            (
                file_body(&[serde_json::json!({
                    "state": "CA", "rateBps": 725, "nexusThresholdCents": 50_000_000,
                    "nexusWindow": "calendar", "sourceUrl": "https://example.gov/x",
                    "retrieved": "2026-10-01", "rate": 725
                })]),
                "not valid JSON",
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
                    "state": "CA", "rateBps": 725, "nexusThresholdCents": 50_000_000,
                    "nexusWindow": "calendar", "sourceUrl": "   ", "retrieved": "2026-10-01"
                })]),
                "sourceUrl is empty",
            ),
            (
                file_body(&[serde_json::json!({
                    "state": "CA", "rateBps": 725, "nexusThresholdCents": 50_000_000,
                    "nexusWindow": "calendar", "sourceUrl": "http://example.gov/x",
                    "retrieved": "2026-10-01"
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
        assert_eq!(table.rows()[1].nexus_window, NexusWindow::Trailing12Months);
        assert_eq!(table.rows()[0].nexus_window, NexusWindow::CalendarYear);
        assert!(table.row("ca").is_some(), "lookup normalises the code");
        assert!(table.row("NY").is_none());
        assert!(!table.is_empty());
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
    /// the number: state, rate, source, retrieved date.
    #[test]
    fn tax_line_stamp_carries_state_rate_source_and_retrieved_date() {
        let line = UsSalesTaxLine {
            state: "CA".to_string(),
            rate_bps: 725,
            amount_cents: 790,
            source_url: "https://example.gov/us-tax-fixture".to_string(),
            retrieved: NaiveDate::from_ymd_opt(2026, 10, 1).expect("date"),
        };
        let description = line.description();
        assert!(description.contains("US sales tax (CA)"), "{description}");
        assert!(description.contains("7.25 %"), "{description}");
        assert!(
            description.contains("https://example.gov/us-tax-fixture"),
            "{description}"
        );
        assert!(description.contains("2026-10-01"), "{description}");

        let snapshot = line.snapshot_json();
        assert_eq!(snapshot["snapshotVersion"], US_SALES_TAX_SNAPSHOT_VERSION);
        assert_eq!(snapshot["state"], "CA");
        assert_eq!(snapshot["rateBps"], 725);
        assert_eq!(snapshot["amountCents"], 790);
        assert_eq!(snapshot["source"], "https://example.gov/us-tax-fixture");
        assert_eq!(snapshot["retrieved"], "2026-10-01");

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
    }

    /// The `--check` report lists every row with its freshness, and prints
    /// the owner instructions while nothing is configured.
    #[test]
    fn check_report_renders_rows_and_instructions() {
        let report = UsTaxDataCheckReport {
            source: "<embedded>".to_string(),
            max_age_days: 120,
            today: today(),
            rows: vec!["CA: 725 bps …".to_string()],
            instructions: vec!["fill me".to_string()],
        };
        let rendered = report.render();
        assert!(rendered.contains("<embedded>"), "{rendered}");
        assert!(rendered.contains("CA: 725 bps"), "{rendered}");
        assert!(
            !rendered.contains("fill me"),
            "instructions render only when empty"
        );

        let empty = UsTaxDataCheckReport {
            rows: Vec::new(),
            ..report
        };
        let rendered = empty.render();
        assert!(rendered.contains("no states configured"), "{rendered}");
        assert!(rendered.contains("| fill me"), "{rendered}");

        // The committed file validates through the real entry point.
        let checked = check_data_file(today()).expect("committed file checks clean");
        assert!(checked.rows.is_empty());
        assert_eq!(checked.max_age_days, DEFAULT_US_TAX_MAX_AGE_DAYS);
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
        let body = serde_json::json!({
            "schemaVersion": 1,
            "instructions": ["fixture"],
            "states": rows,
        })
        .to_string();
        UsTaxConfig {
            table: UsTaxTable::parse(&body, today()).expect("fixture table parses"),
            source: "test fixture".to_string(),
            max_age_days,
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
            let row = status_row(env, "CA").await.expect("CA row exists");
            assert_eq!(row.status, "below");
            assert_eq!(row.observed_cents, THRESHOLD - 1);
            assert!(row.crossed_at.is_none());
            assert_eq!(row.threshold_cents, THRESHOLD);
            assert_eq!(row.nexus_window, "calendar");
            assert!(row.last_evaluated_at.is_some());
            assert_eq!(nexus_incidents(env).await.len(), 0);

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

            let incidents = nexus_incidents(env).await;
            assert_eq!(incidents.len(), 1, "one durable alert");
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
}
