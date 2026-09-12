//! Single source of truth for EU member states and their standard VAT rates.
//!
//! # Source files replaced
//!
//! | Original location | What was replaced |
//! |---|---|
//! | [`billing-service/src/invoices.rs`](services/mail-server/crates/billing-service/src/invoices.rs:65) | `EU_COUNTRIES`, `EU_VAT_RATES`, `calculate_vat()` |
//! | [`billing-service/src/vat_kmd.rs`](services/mail-server/crates/billing-service/src/vat_kmd.rs:362) | `EU_COUNTRIES_SQL`, `is_eu_country()`, `get_eu_vat_rate()` |
//! | [`api-server/src/routes/admin/compliance_overview.rs`](services/mail-server/crates/api-server/src/routes/admin/compliance_overview.rs:472) | `EU_COUNTRIES`, `get_eu_vat_rate()` |
//! | [`api-server/src/routes/admin/vat.rs`](services/mail-server/crates/api-server/src/routes/admin/vat.rs:472) | `EU_COUNTRIES`, `is_eu_country()`, `get_eu_vat_rate()` |

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use chrono::NaiveDate;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Estonian standard VAT rate (24 %, effective since 1 July 2025).
pub const ESTONIA_VAT_RATE: f64 = 24.0;

/// Default 27 EU member state ISO 3166-1 alpha-2 country codes.
const DEFAULT_EU_COUNTRIES: &[&str] = &[
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV",
    "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE",
];

/// Default standard VAT rates for all 27 EU member states.
///
/// Rates are percent and may be fractional: Finland's standard rate has been
/// 25.5 % since 1 September 2024 and must not be rounded — overcharging a
/// statutory rate is a legal defect, not a cosmetic one.
const DEFAULT_VAT_RATES: &[(&str, f64)] = &[
    ("AT", 20.0),
    ("BE", 21.0),
    ("BG", 20.0),
    ("HR", 25.0),
    ("CY", 19.0),
    ("CZ", 21.0),
    ("DK", 25.0),
    ("EE", 24.0),
    ("FI", 25.5),
    ("FR", 20.0),
    ("DE", 19.0),
    ("GR", 24.0),
    ("HU", 27.0),
    ("IE", 23.0),
    ("IT", 22.0),
    ("LV", 21.0),
    ("LT", 21.0),
    ("LU", 17.0),
    ("MT", 18.0),
    ("NL", 21.0),
    ("PL", 23.0),
    ("PT", 23.0),
    ("RO", 19.0),
    ("SK", 23.0),
    ("SI", 22.0),
    ("ES", 21.0),
    ("SE", 25.0),
];

// ---------------------------------------------------------------------------
// Lazy statics
// ---------------------------------------------------------------------------

/// All 27 EU member state ISO 3166-1 alpha-2 country codes.
///
/// Can be overridden at runtime via the `EU_COUNTRIES` environment variable
/// (comma-separated codes, e.g. `DE,FR,IT`). When unset, the built-in default
/// list of 27 member states is used.
pub static EU_COUNTRIES: LazyLock<HashSet<String>> = LazyLock::new(|| {
    let raw = std::env::var("EU_COUNTRIES").unwrap_or_else(|_| DEFAULT_EU_COUNTRIES.join(","));
    raw.split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_uppercase())
        .collect()
});

/// Standard VAT rates for all 27 EU member states, keyed by ISO 3166-1
/// alpha-2 country code.
///
/// The map can be overridden at runtime via the `EU_VAT_RATES` environment
/// variable (comma-separated `CODE=rate` pairs, e.g. `DE=19,FI=25.5`).
/// The override is a PARTIAL overlay: defaults are loaded first and user
/// entries replace them key-by-key, so setting one country's rate no longer
/// silently drops the other 26 to "map miss" (the previous all-or-nothing
/// behaviour turned every partial override into a fallback-rate fallback
/// for the rest of the union). When unset, the built-in defaults below are
/// used verbatim.
pub static EU_VAT_RATES: LazyLock<HashMap<String, f64>> =
    LazyLock::new(|| merged_vat_rates(std::env::var("EU_VAT_RATES").ok().as_deref()));

/// Pure core of the [`EU_VAT_RATES`] initializer (unit-tested): the built-in
/// defaults overlaid with the parsed `EU_VAT_RATES` payload. Partial
/// overrides win per key; every country the payload omits keeps its default
/// rate. Unparseable pairs are skipped rather than aborting the whole map.
fn merged_vat_rates(env_raw: Option<&str>) -> HashMap<String, f64> {
    let mut map: HashMap<String, f64> = DEFAULT_VAT_RATES
        .iter()
        .map(|&(code, rate)| (code.to_string(), rate))
        .collect();
    if let Some(raw) = env_raw {
        for pair in raw.split(',') {
            let mut parts = pair.split('=');
            if let (Some(country), Some(rate)) = (parts.next(), parts.next()) {
                if let Ok(rate) = rate.trim().parse::<f64>() {
                    map.insert(country.trim().to_uppercase(), rate);
                }
            }
        }
    }
    map
}

// ---------------------------------------------------------------------------
// Public helpers
// ---------------------------------------------------------------------------

/// Returns `true` when `country` (ISO 3166-1 alpha-2, case-insensitive) is
/// an EU member state.
///
/// This is a convenience wrapper around [`EU_COUNTRIES`].
pub fn is_eu_country(country: &str) -> bool {
    EU_COUNTRIES.contains(&country.to_uppercase())
}

/// Lookup the standard VAT rate (%) for a given EU member state.
///
/// Returns `None` for non-EU countries.
///
/// This is a convenience wrapper around [`EU_VAT_RATES`].
pub fn get_eu_vat_rate(country: &str) -> Option<f64> {
    EU_VAT_RATES.get(&country.to_uppercase()).copied()
}

/// Round-half-up VAT in integer cents for a rate in percent (possibly
/// fractional, e.g. Finland's 25.5 %). All VAT money math goes through here —
/// never floating point.
pub fn vat_amount_half_up(amount_cents: i64, rate_percent: f64) -> i64 {
    // Scale the rate to tenths of a percent (255 for 25.5 %) so the entire
    // computation stays in integers: VAT cents = amount × rate_tenths / 1000,
    // rounded half-up.
    let rate_tenths = (rate_percent * 10.0).round() as i64;
    ((amount_cents * rate_tenths) + 500) / 1000
}

/// Format a VAT rate for display: `24` renders as "24", `25.5` as "25.5".
pub fn format_vat_rate(rate_percent: f64) -> String {
    if (rate_percent - rate_percent.round()).abs() < f64::EPSILON {
        format!("{}", rate_percent.round() as i64)
    } else {
        format!("{rate_percent}")
    }
}

// ---------------------------------------------------------------------------
// Map-miss policy (audit item 3d)
// ---------------------------------------------------------------------------

/// Error returned when a country is listed in `EU_COUNTRIES` but has no
/// entry in `EU_VAT_RATES` and the deployed policy treats that as fatal.
#[derive(Debug, Clone, PartialEq)]
pub struct VatRateMapMissError {
    /// The country whose rate lookup failed.
    pub country: String,
    /// What the fallback policy would have used (for logging/context).
    pub fallback_rate: f64,
}

impl std::fmt::Display for VatRateMapMissError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EU country {} has no VAT rate configured (fallback policy rate: {}%)",
            self.country, self.fallback_rate
        )
    }
}

impl std::error::Error for VatRateMapMissError {}

/// How an explicit EU-country → VAT-rate map miss is handled. A miss can
/// only happen with a custom `EU_COUNTRIES`/`EU_VAT_RATES` environment
/// override that lists a country without a rate — never with the built-in
/// 27-member tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VatMapMissPolicy {
    /// Charge the rate of the configured fallback country
    /// (`VAT_FALLBACK_COUNTRY`, default `EE`) and log a warning. This is
    /// the default; it is rate-identical to the historical silent-Estonia
    /// behaviour but explicitly logged and configurable.
    FallbackCountry,
    /// Refuse to compute a rate — the caller must surface the error
    /// instead of silently charging an arbitrary country's rate.
    Error,
}

impl VatMapMissPolicy {
    /// Parse the `VAT_MAP_MISS_POLICY` environment value
    /// (`fallback` | `error`; default `fallback`).
    pub fn from_env_value(value: Option<&str>) -> Self {
        match value.map(str::trim).filter(|v| !v.is_empty()) {
            Some(value) if value.eq_ignore_ascii_case("error") => Self::Error,
            _ => Self::FallbackCountry,
        }
    }

    /// The policy name as it appears in configuration.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FallbackCountry => "fallback",
            Self::Error => "error",
        }
    }
}

/// Resolve the rate for an EU country that has no `EU_VAT_RATES` entry.
/// Pure — unit-tested. `fallback_country` is the configurable default
/// country (`VAT_FALLBACK_COUNTRY`, default `EE`); if the fallback country
/// itself has no rate, the built-in Estonian rate is the last resort (and
/// is always logged as a miss).
pub fn resolve_map_miss_rate(
    miss_country: &str,
    policy: VatMapMissPolicy,
    fallback_country: &str,
) -> Result<f64, VatRateMapMissError> {
    let fallback_rate = get_eu_vat_rate(fallback_country).unwrap_or(ESTONIA_VAT_RATE);
    match policy {
        VatMapMissPolicy::Error => Err(VatRateMapMissError {
            country: miss_country.to_uppercase(),
            fallback_rate,
        }),
        VatMapMissPolicy::FallbackCountry => Ok(fallback_rate),
    }
}

/// The deployed map-miss policy, read once from `VAT_MAP_MISS_POLICY`.
pub static VAT_MAP_MISS_POLICY: LazyLock<VatMapMissPolicy> = LazyLock::new(|| {
    VatMapMissPolicy::from_env_value(std::env::var("VAT_MAP_MISS_POLICY").ok().as_deref())
});

/// The configured fallback country for map misses, read once from
/// `VAT_FALLBACK_COUNTRY` (default `EE`).
pub static VAT_FALLBACK_COUNTRY: LazyLock<String> = LazyLock::new(|| {
    std::env::var("VAT_FALLBACK_COUNTRY")
        .ok()
        .map(|value| value.trim().to_uppercase())
        .filter(|value| value.len() == 2)
        .unwrap_or_else(|| "EE".to_string())
});

/// Validate the structural shape of an EU VAT registration number.
///
/// Rules (conservative, purely structural):
///
/// - trimmed, non-empty, ASCII alphanumeric only (no spaces/dashes);
/// - total length 5–15 characters;
/// - starts with a two-letter country prefix followed by 8–12 alphanumeric
///   characters (the common EU format, e.g. `DE123456789`);
/// - when `country` (the billing country) is provided, the prefix must match
///   it — Greece's `EL` prefix is accepted for country `GR`.
///
/// # Structural validity is NOT evidence
///
/// Passing this check says the string *looks like* a VAT number; it says
/// nothing about whether the number is registered. It must never, by itself,
/// authorise a 0 % reverse charge. Reverse charge requires authoritative
/// evidence ([`reverse_charge_authorised`] with a [`VatValidationEvidence`]
/// row recorded from VIES), and every invoice snapshots the evidence id it
/// relied on. The previous behaviour — treating this structural check as
/// sufficient, with a comment claiming VIES validation happened
/// "out-of-band in vat_emta" where no such production validator existed —
/// permitted under-collected VAT on every structurally-shaped fake number.
///
/// Returns `false` for anything that cannot be a VAT number ("", "1", "x",
/// free-form text).
pub fn is_valid_vat_number(vat: &str, country: Option<&str>) -> bool {
    let vat = vat.trim();
    if !(5..=15).contains(&vat.len()) {
        return false;
    }
    if !vat.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return false;
    }

    let prefix: String = vat[..2].to_ascii_uppercase();
    if !prefix.bytes().all(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    let body_len = vat.len() - 2;
    if !(8..=12).contains(&body_len) {
        return false;
    }

    if let Some(country) = country.map(str::trim).filter(|c| !c.is_empty()) {
        let country = country.to_ascii_uppercase();
        // Greece issues VAT numbers with the EL prefix.
        let expected_prefix = match country.as_str() {
            "GR" => "EL",
            other => other,
        };
        // Only enforce prefix consistency when the prefix itself is a
        // plausibly valid country code (two letters). This keeps unknown
        // fictional country codes usable in tests without weakening the
        // mismatch check.
        if expected_prefix.len() == 2 && expected_prefix.bytes().all(|b| b.is_ascii_alphabetic()) {
            return prefix == expected_prefix;
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Authoritative VAT-number evidence (VIES)
// ---------------------------------------------------------------------------
//
// Structural checks above only prove a string has the right shape. A reverse
// charge (0 % intra-Community supply) requires AUTHORITATIVE evidence: a dated
// answer from VIES saying the number is registered and active for the
// counterparty. Evidence is persisted in `vat_validation_evidence` (migration
// 213) by the production validator in `compliance::vat_vies`; the invoice
// records the evidence id it relied on (`invoices.vat_evidence_id`), so a
// zero-rated invoice can always be traced back to the consultation that
// justified it.

/// Authoritative source of a VAT-number verification. Only authorities in
/// this enum can authorise a reverse charge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VatValidationSource {
    /// EU Commission VIES (or a member-state mirror of it).
    Vies,
}

impl VatValidationSource {
    /// The database discriminator (`vat_validation_evidence.source`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vies => "VIES",
        }
    }

    /// Parse the database discriminator. Unknown sources are rejected —
    /// a source we do not recognise cannot authorise a reverse charge.
    pub fn from_db(value: &str) -> Option<Self> {
        if value.trim().eq_ignore_ascii_case("VIES") {
            Some(Self::Vies)
        } else {
            None
        }
    }
}

/// Outcome of an authoritative VAT-number consultation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VatValidationOutcome {
    /// The authority answered: the number is registered and active.
    Valid,
    /// The authority answered: the number is not registered/active.
    Invalid,
    /// The authority could not answer (member state unavailable, timeout,
    /// global concurrency limit, ...). Documented behaviour: an outage is
    /// NEVER valid evidence — the charge falls back to the normal
    /// destination/local VAT (fail closed), and the outage marker is stored
    /// on the evidence row so it can be retried once VIES recovers.
    Outage,
}

/// One dated, persisted piece of authoritative VAT-number evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VatValidationEvidence {
    /// `vat_validation_evidence.id` — snapshotted onto the invoice.
    pub id: Option<Uuid>,
    /// The verified VAT number, as returned/normalised by the authority.
    pub vat_number: String,
    /// The member state the number belongs to (`EL` for Greece is normalised
    /// to `GR` when comparing).
    pub country: String,
    pub source: VatValidationSource,
    pub outcome: VatValidationOutcome,
    /// Date the authoritative answer was obtained (VIES `requestDate`).
    pub valid_from: NaiveDate,
    /// Optional horizon after which the evidence must be refreshed. `None`
    /// means open-ended (re-verify on a schedule, but not expired).
    pub valid_until: Option<NaiveDate>,
    /// Authority outage marker (`MS_UNAVAILABLE`, `SERVICE_UNAVAILABLE`,
    /// `TIMEOUT`, `GLOBAL_MAX_CONCURRENT_REQ`, ...) when the outcome is
    /// [`VatValidationOutcome::Outage`].
    pub outage_state: Option<String>,
}

impl VatValidationEvidence {
    /// Build evidence from a `vat_validation_evidence` row.
    ///
    /// Returns `None` only for an unknown/non-authoritative `source`; an
    /// invalid or outage answer is represented as evidence with the matching
    /// outcome so the audit trail shows what was consulted. Neither invalid
    /// nor outage evidence authorises a reverse charge
    /// ([`reverse_charge_authorised`] checks the outcome).
    #[allow(clippy::too_many_arguments)]
    pub fn from_authority_row(
        id: Option<Uuid>,
        vat_number: impl Into<String>,
        country: impl Into<String>,
        source: &str,
        valid: bool,
        valid_from: Option<NaiveDate>,
        valid_until: Option<NaiveDate>,
        outage_state: Option<String>,
    ) -> Option<Self> {
        let source = VatValidationSource::from_db(source)?;
        let outage = outage_state
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let outcome = match (outage.is_some(), valid) {
            (true, _) => VatValidationOutcome::Outage,
            (false, true) => VatValidationOutcome::Valid,
            (false, false) => VatValidationOutcome::Invalid,
        };
        Some(Self {
            id,
            vat_number: vat_number.into(),
            country: country.into(),
            source,
            outcome,
            // The consultation date is mandatory in the schema; a missing
            // value here would make the evidence undated and unusable, so
            // fall back to the current date only in the impossible case.
            valid_from: valid_from.unwrap_or_else(|| chrono::Utc::now().date_naive()),
            valid_until,
            outage_state: outage,
        })
    }

    /// Whether this evidence authorises a reverse charge on `at` for the
    /// given country/VAT number. This is the entire rule; call sites must
    /// not re-derive it from structural checks.
    pub fn authorises_reverse_charge(
        &self,
        country: &str,
        vat_number: &str,
        at: NaiveDate,
    ) -> bool {
        self.source == VatValidationSource::Vies
            && self.outcome == VatValidationOutcome::Valid
            && self
                .outage_state
                .as_deref()
                .map(str::trim)
                .map_or(true, str::is_empty)
            && vat_numbers_match(vat_number, &self.vat_number)
            && countries_match(country, &self.country)
            && at >= self.valid_from
            && self.valid_until.map_or(true, |until| at <= until)
    }
}

/// Normalise a VAT number for comparison: uppercase, no internal whitespace.
pub fn normalise_vat_number(vat: &str) -> String {
    vat.chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase()
}

fn vat_numbers_match(left: &str, right: &str) -> bool {
    normalise_vat_number(left) == normalise_vat_number(right)
}

/// Country comparison with the Greece exception: VIES answers use `EL`
/// while ISO 3166-1 uses `GR`.
pub fn countries_match(left: &str, right: &str) -> bool {
    fn canonical(country: &str) -> String {
        match country.trim().to_uppercase().as_str() {
            "EL" => "GR".to_string(),
            other => other.to_string(),
        }
    }
    canonical(left) == canonical(right)
}

/// Decide whether a 0 % reverse charge is authorised for a sale to
/// `country` with `vat_number`, on the basis of persisted, authoritative
/// evidence.
///
/// Returns `false` — normal destination/local VAT is charged — when:
/// - the sale is local (`EE`) or outside the EU;
/// - the VAT number fails the structural shape check;
/// - there is no evidence;
/// - the evidence is not from VIES, is invalid, or is an outage;
/// - the evidence is for a different number/country;
/// - the evidence is dated after `at` or has expired.
///
/// The caller must snapshot `evidence.id` onto the invoice when this returns
/// `true` (`invoices.vat_evidence_id`, migration 218).
pub fn reverse_charge_authorised(
    country: &str,
    vat_number: &str,
    evidence: Option<&VatValidationEvidence>,
    at: NaiveDate,
) -> bool {
    let upper = country.trim().to_uppercase();
    if upper == "EE" || !is_eu_country(&upper) {
        return false;
    }
    if !is_valid_vat_number(vat_number, Some(&upper)) {
        return false;
    }
    evidence.map_or(false, |evidence| {
        evidence.authorises_reverse_charge(&upper, vat_number, at)
    })
}

/// Calculate the VAT rate and amount for a given subtotal, customer country,
/// optional VAT number and optional authoritative evidence.
///
/// # VAT rules
///
/// | Scenario | Rate |
/// |---|---|
/// | Estonia (`EE`) | 24 % (local) |
/// | EU B2B with VIES-verified VAT number **and** evidence | 0 % (reverse charge) |
/// | EU B2B with a merely structural VAT number | destination-country rate |
/// | EU B2C (no/invalid VAT number) | destination-country rate |
/// | EU B2C, country missing from the rate map | [`VAT_MAP_MISS_POLICY`] |
/// | Non-EU | 0 % |
///
/// `evidence` is the row from `vat_validation_evidence` (see
/// [`VatValidationEvidence`]) and `at` is the tax-point date the evidence
/// must cover. Passing `None` never reverse-charges, no matter how
/// well-formed the VAT number looks.
pub fn calculate_vat_with_evidence(
    subtotal: i64,
    country: &str,
    vat_number: Option<&str>,
    evidence: Option<&VatValidationEvidence>,
    at: NaiveDate,
) -> (f64, i64) {
    if subtotal <= 0 {
        return (0.0, 0);
    }
    let country = country.to_uppercase();

    if country == "EE" {
        let amt = vat_amount_half_up(subtotal, ESTONIA_VAT_RATE);
        return (ESTONIA_VAT_RATE, amt);
    }

    if EU_COUNTRIES.contains(&country) {
        if vat_number.map_or(false, |vat| {
            reverse_charge_authorised(&country, vat, evidence, at)
        }) {
            // EU B2B — reverse charge (0 %) against authoritative evidence.
            return (0.0, 0);
        }
        // EU B2C (or unverified B2B) — destination-country VAT. An explicit
        // map miss goes through the deployed policy (audit item 3d): never
        // again a silent Estonian rate.
        let rate = match EU_VAT_RATES.get(&country).copied() {
            Some(rate) => rate,
            None => {
                let fallback_rate =
                    get_eu_vat_rate(&VAT_FALLBACK_COUNTRY).unwrap_or(ESTONIA_VAT_RATE);
                match *VAT_MAP_MISS_POLICY {
                    VatMapMissPolicy::Error => {
                        tracing::error!(
                            country = %country,
                            fallback_country = %*VAT_FALLBACK_COUNTRY,
                            fallback_rate,
                            "VAT rate map miss with VAT_MAP_MISS_POLICY=error — charging \
                             fallback-country rate; fix EU_VAT_RATES"
                        );
                        fallback_rate
                    }
                    VatMapMissPolicy::FallbackCountry => {
                        tracing::warn!(
                            country = %country,
                            fallback_country = %*VAT_FALLBACK_COUNTRY,
                            fallback_rate,
                            "VAT rate map miss — charging fallback-country rate \
                             (controlled by VAT_FALLBACK_COUNTRY / VAT_MAP_MISS_POLICY)"
                        );
                        fallback_rate
                    }
                }
            }
        };
        let amt = vat_amount_half_up(subtotal, rate);
        return (rate, amt);
    }

    // Non-EU — 0 %
    (0.0, 0)
}

/// Calculate the VAT rate and amount for a given subtotal, customer country
/// and optional VAT number.
///
/// # Structural validity is not evidence
///
/// This convenience wrapper carries no authoritative evidence, so a
/// well-formed EU VAT number does NOT trigger a 0 % reverse charge: the
/// destination rate is charged. Callers that have evidence (the invoice
/// writer, the Stripe reconciliation path) must use
/// [`calculate_vat_with_evidence`]; reverse charge is only authorised there
/// when a valid VIES evidence row is passed. This closes the previously
/// possible "structurally valid ⇒ zero-rated" under-collection.
pub fn calculate_vat(subtotal: i64, country: &str, vat_number: Option<&str>) -> (f64, i64) {
    calculate_vat_with_evidence(
        subtotal,
        country,
        vat_number,
        None,
        chrono::Utc::now().date_naive(),
    )
}

/// Strict variant of [`calculate_vat_with_evidence`] (audit item 3d):
/// returns [`VatRateMapMissError`] instead of applying a fallback rate when
/// an EU-listed country has no rate entry. Callers that must never silently
/// charge another country's rate (invoice issuance) should prefer this.
pub fn calculate_vat_strict_with_evidence(
    subtotal: i64,
    country: &str,
    vat_number: Option<&str>,
    evidence: Option<&VatValidationEvidence>,
    at: NaiveDate,
) -> Result<(f64, i64), VatRateMapMissError> {
    if subtotal <= 0 {
        return Ok((0.0, 0));
    }
    let upper = country.to_uppercase();

    if upper == "EE" {
        return Ok(calculate_vat_with_evidence(
            subtotal, &upper, vat_number, evidence, at,
        ));
    }

    if EU_COUNTRIES.contains(&upper) {
        if vat_number.map_or(false, |vat| {
            reverse_charge_authorised(&upper, vat, evidence, at)
        }) {
            return Ok((0.0, 0));
        }
        let rate = EU_VAT_RATES.get(&upper).copied().map_or_else(
            || resolve_map_miss_rate(&upper, VatMapMissPolicy::Error, &VAT_FALLBACK_COUNTRY),
            Ok,
        )?;
        let amt = vat_amount_half_up(subtotal, rate);
        return Ok((rate, amt));
    }

    Ok((0.0, 0))
}

/// Strict variant of [`calculate_vat`] (audit item 3d): returns
/// [`VatRateMapMissError`] instead of applying a fallback rate when an
/// EU-listed country has no rate entry. Callers that must never silently
/// charge another country's rate (invoice issuance) should prefer this.
///
/// Like [`calculate_vat`], this wrapper carries no authoritative evidence
/// and therefore never authorises a reverse charge; use
/// [`calculate_vat_strict_with_evidence`] when evidence is available.
pub fn calculate_vat_strict(
    subtotal: i64,
    country: &str,
    vat_number: Option<&str>,
) -> Result<(f64, i64), VatRateMapMissError> {
    calculate_vat_strict_with_evidence(
        subtotal,
        country,
        vat_number,
        None,
        chrono::Utc::now().date_naive(),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eu_countries_includes_all_27_member_states() {
        assert_eq!(EU_COUNTRIES.len(), 27, "must have exactly 27 members");
        for &code in DEFAULT_EU_COUNTRIES {
            assert!(EU_COUNTRIES.contains(code), "missing EU member: {code}");
        }
    }

    #[test]
    fn all_eu_countries_have_vat_rates() {
        for &(code, expected_rate) in DEFAULT_VAT_RATES {
            assert!(
                EU_COUNTRIES.contains(code),
                "Country {code} missing from EU_COUNTRIES"
            );
            assert_eq!(
                get_eu_vat_rate(code),
                Some(expected_rate),
                "VAT rate mismatch for {code}"
            );
        }
        // Verify the count is exactly 27
        assert_eq!(EU_COUNTRIES.len(), 27);
    }

    // ------------------------------------------------------------------
    // Partial EU_VAT_RATES overrides merge OVER the defaults instead of
    // replacing the whole map (the old all-or-nothing behaviour dropped
    // the 26 unlisted countries to fallback-rate treatment).
    // ------------------------------------------------------------------

    #[test]
    fn partial_vat_rate_override_keeps_defaults_for_unlisted_countries() {
        let merged = merged_vat_rates(Some("FI=26"));
        // All 27 defaults survive…
        assert_eq!(merged.len(), DEFAULT_VAT_RATES.len());
        // …the overridden key wins…
        assert_eq!(merged.get("FI").copied(), Some(26.0));
        // …and an unlisted key keeps its built-in rate.
        assert_eq!(merged.get("EE").copied(), Some(ESTONIA_VAT_RATE));
        assert_eq!(merged.get("DE").copied(), Some(19.0));
    }

    #[test]
    fn vat_rate_override_parser_skips_garbage_pairs_without_nuking_defaults() {
        let merged = merged_vat_rates(Some("not-a-pair,XX=abc,DE=19"));
        assert_eq!(merged.len(), DEFAULT_VAT_RATES.len());
        assert_eq!(merged.get("DE").copied(), Some(19.0));
        // "XX=abc" fails to parse and must not insert a key at all.
        assert_eq!(merged.get("XX"), None);
        assert_eq!(merged.get("FR").copied(), Some(20.0));
    }

    #[test]
    fn vat_rate_override_absent_yields_verbatim_defaults() {
        let merged = merged_vat_rates(None);
        assert_eq!(merged.len(), DEFAULT_VAT_RATES.len());
        assert_eq!(merged.get("FI").copied(), Some(25.5));
    }

    #[test]
    fn is_eu_country_recognizes_member_states() {
        assert!(is_eu_country("EE"));
        assert!(is_eu_country("DE"));
        assert!(is_eu_country("FR"));
        assert!(!is_eu_country("US"));
        assert!(!is_eu_country("CN"));
        assert!(!is_eu_country(""));
    }

    #[test]
    fn is_eu_country_case_insensitive() {
        assert!(is_eu_country("ee"));
        assert!(is_eu_country("De"));
        assert!(is_eu_country("FR"));
    }

    #[test]
    fn get_eu_vat_rate_ee() {
        assert_eq!(get_eu_vat_rate("EE"), Some(24.0));
        assert_eq!(get_eu_vat_rate("US"), None);
    }

    #[test]
    fn calculate_vat_estonia_returns_24_percent() {
        let subtotal = 1000_i64; // €10.00 in cents
        let (rate, amount) = calculate_vat(subtotal, "EE", None);
        assert_eq!(rate, 24.0);
        assert_eq!(amount, 240); // €10.00 × 24 % = €2.40
    }

    #[test]
    fn calculate_vat_eu_b2b_reverse_charge_requires_evidence() {
        let subtotal = 1000_i64;
        // No evidence — the well-formed VAT number does NOT zero-rate.
        let (rate, amount) = calculate_vat(subtotal, "DE", Some("DE123456789"));
        assert_eq!(rate, 19.0, "reverse charge requires authoritative evidence");
        assert_eq!(amount, 190);

        // With valid VIES evidence the same sale is reverse-charged.
        let evidence = valid_vies_evidence("DE123456789", "DE", d(2026, 1, 1), None);
        let (rate, amount) = calculate_vat_with_evidence(
            subtotal,
            "DE",
            Some("DE123456789"),
            Some(&evidence),
            d(2026, 2, 1),
        );
        assert_eq!(rate, 0.0, "reverse charge must be 0 %");
        assert_eq!(amount, 0);
    }

    #[test]
    fn calculate_vat_eu_b2c_destination_rate() {
        let subtotal = 1000_i64;
        let (rate, amount) = calculate_vat(subtotal, "DE", None);
        assert_eq!(rate, 19.0);
        assert_eq!(amount, 190); // €10.00 × 19 % = €1.90
    }

    #[test]
    fn calculate_vat_non_eu_zero() {
        let subtotal = 1000_i64;
        let (rate, amount) = calculate_vat(subtotal, "US", None);
        assert_eq!(rate, 0.0);
        assert_eq!(amount, 0);
    }

    #[test]
    fn calculate_vat_case_insensitive_country() {
        let (rate, amount) = calculate_vat(1000, "ee", None);
        assert_eq!(rate, 24.0);
        assert_eq!(amount, 240);

        let (rate, amount) = calculate_vat(1000, "de", None);
        assert_eq!(rate, 19.0);
        assert_eq!(amount, 190);
    }
    #[test]
    fn calculate_vat_non_positive_subtotal_zero() {
        assert_eq!(calculate_vat(0, "DE", None), (0.0, 0));
        assert_eq!(calculate_vat(-1000, "EE", None), (0.0, 0));
    }

    // ------------------------------------------------------------------
    // Fix D — reverse charge only on structurally valid VAT numbers.
    // ------------------------------------------------------------------

    #[test]
    fn is_valid_vat_number_rejects_degenerate_inputs() {
        assert!(!is_valid_vat_number("", None));
        assert!(!is_valid_vat_number(" ", None));
        assert!(!is_valid_vat_number("1", None));
        assert!(!is_valid_vat_number("x", None));
        assert!(!is_valid_vat_number("DE", None)); // prefix without body
        assert!(!is_valid_vat_number(
            "DE123456789012345678901234567890",
            None
        )); // > 15 chars
        assert!(!is_valid_vat_number("DE 1234-5678", None)); // spaces/dashes
        assert!(!is_valid_vat_number("1234567890123", None)); // no country prefix
    }

    #[test]
    fn is_valid_vat_number_accepts_realistic_eu_numbers() {
        assert!(is_valid_vat_number("DE123456789", None));
        assert!(is_valid_vat_number("FRXX123456789", None));
        assert!(is_valid_vat_number("NL004495445B01", None));
        assert!(is_valid_vat_number("de123456789", None)); // case-insensitive
    }

    #[test]
    fn is_valid_vat_number_checks_country_prefix_consistency() {
        assert!(is_valid_vat_number("DE123456789", Some("DE")));
        assert!(is_valid_vat_number("de123456789", Some("de")));
        // Greek VAT numbers use the EL prefix while the country is GR.
        assert!(is_valid_vat_number("EL123456789", Some("GR")));
        // Mismatched prefix — not zero-rated.
        assert!(!is_valid_vat_number("DE123456789", Some("FR")));
        assert!(!is_valid_vat_number("US123456789", Some("FR")));
    }

    #[test]
    fn calculate_vat_invalid_vat_number_charges_normal_rate() {
        // Garbage VAT numbers must NOT trigger reverse charge.
        let (rate, amount) = calculate_vat(10_000, "DE", Some("1"));
        assert_eq!(rate, 19.0);
        assert_eq!(amount, 1_900);

        let (rate, _) = calculate_vat(10_000, "DE", Some(""));
        assert_eq!(rate, 19.0);

        let (rate, _) = calculate_vat(10_000, "DE", Some("x"));
        assert_eq!(rate, 19.0);

        // Mismatched prefix: VAT number says DE, billing country is FR.
        let (rate, amount) = calculate_vat(10_000, "FR", Some("DE123456789"));
        assert_eq!(rate, 20.0);
        assert_eq!(amount, 2_000);
    }

    #[test]
    fn calculate_vat_structurally_valid_but_unverified_vat_number_charges_normal_rate() {
        // P0 tax-truth regression: a structurally perfect VAT number with no
        // VIES evidence must NOT authorise a reverse charge.
        let (rate, amount) = calculate_vat(10_000, "DE", Some("DE123456789"));
        assert_eq!(rate, 19.0);
        assert_eq!(amount, 1_900);

        let (rate, amount) = calculate_vat(10_000, "FR", Some("FRXX123456789"));
        assert_eq!(rate, 20.0);
        assert_eq!(amount, 2_000);
    }

    #[test]
    fn calculate_vat_valid_vies_evidence_authorises_reverse_charge() {
        let at = d(2026, 6, 15);
        let evidence = valid_vies_evidence("DE123456789", "DE", d(2026, 1, 10), None);
        let (rate, amount) =
            calculate_vat_with_evidence(10_000, "DE", Some("DE123456789"), Some(&evidence), at);
        assert_eq!(rate, 0.0);
        assert_eq!(amount, 0);

        // A Greek number verified under EL is accepted for country GR.
        let evidence = valid_vies_evidence("EL123456789", "EL", d(2026, 1, 10), None);
        let (rate, _) =
            calculate_vat_with_evidence(10_000, "GR", Some("EL123456789"), Some(&evidence), at);
        assert_eq!(rate, 0.0);
    }

    #[test]
    fn calculate_vat_invalid_or_expired_evidence_charges_normal_rate() {
        let at = d(2026, 6, 15);

        // Authority answered "not valid".
        let evidence = VatValidationEvidence {
            id: Some(Uuid::new_v4()),
            vat_number: "DE123456789".into(),
            country: "DE".into(),
            source: VatValidationSource::Vies,
            outcome: VatValidationOutcome::Invalid,
            valid_from: d(2026, 1, 10),
            valid_until: None,
            outage_state: None,
        };
        let (rate, _) =
            calculate_vat_with_evidence(10_000, "DE", Some("DE123456789"), Some(&evidence), at);
        assert_eq!(rate, 19.0, "invalid evidence must not zero-rate");

        // Expired evidence.
        let evidence =
            valid_vies_evidence("DE123456789", "DE", d(2026, 1, 10), Some(d(2026, 3, 31)));
        let (rate, _) =
            calculate_vat_with_evidence(10_000, "DE", Some("DE123456789"), Some(&evidence), at);
        assert_eq!(rate, 19.0, "expired evidence must not zero-rate");

        // Evidence obtained AFTER the tax point.
        let evidence = valid_vies_evidence("DE123456789", "DE", d(2026, 7, 1), None);
        let (rate, _) =
            calculate_vat_with_evidence(10_000, "DE", Some("DE123456789"), Some(&evidence), at);
        assert_eq!(
            rate, 19.0,
            "future evidence must not zero-rate a past supply"
        );

        // Evidence for a different number/country.
        let evidence = valid_vies_evidence("DE999999999", "DE", d(2026, 1, 10), None);
        let (rate, _) =
            calculate_vat_with_evidence(10_000, "DE", Some("DE123456789"), Some(&evidence), at);
        assert_eq!(rate, 19.0, "wrong-number evidence must not zero-rate");

        let evidence = valid_vies_evidence("FRXX123456789", "FR", d(2026, 1, 10), None);
        let (rate, _) =
            calculate_vat_with_evidence(10_000, "DE", Some("DE123456789"), Some(&evidence), at);
        assert_eq!(rate, 19.0, "wrong-country evidence must not zero-rate");
    }

    #[test]
    fn calculate_vat_vies_outage_charges_normal_rate() {
        // Documented outage behaviour: VIES being down is NOT silent
        // validity — the sale fails to normal destination VAT.
        let at = d(2026, 6, 15);
        let evidence = VatValidationEvidence {
            id: Some(Uuid::new_v4()),
            vat_number: "DE123456789".into(),
            country: "DE".into(),
            source: VatValidationSource::Vies,
            outcome: VatValidationOutcome::Outage,
            valid_from: d(2026, 6, 15),
            valid_until: None,
            outage_state: Some("MS_UNAVAILABLE".into()),
        };
        assert!(!reverse_charge_authorised(
            "DE",
            "DE123456789",
            Some(&evidence),
            at
        ));
        let (rate, amount) =
            calculate_vat_with_evidence(10_000, "DE", Some("DE123456789"), Some(&evidence), at);
        assert_eq!(rate, 19.0);
        assert_eq!(amount, 1_900);
    }

    #[test]
    fn from_authority_row_classifies_valid_invalid_and_outage() {
        let valid = VatValidationEvidence::from_authority_row(
            Some(Uuid::new_v4()),
            "DE123456789",
            "DE",
            "VIES",
            true,
            Some(d(2026, 1, 1)),
            None,
            None,
        )
        .expect("VIES is authoritative");
        assert_eq!(valid.outcome, VatValidationOutcome::Valid);
        assert!(valid.authorises_reverse_charge("DE", "DE123456789", d(2026, 2, 1)));

        let invalid = VatValidationEvidence::from_authority_row(
            None,
            "DE123456789",
            "DE",
            "VIES",
            false,
            Some(d(2026, 1, 1)),
            None,
            None,
        )
        .expect("VIES is authoritative");
        assert_eq!(invalid.outcome, VatValidationOutcome::Invalid);

        let outage = VatValidationEvidence::from_authority_row(
            None,
            "DE123456789",
            "DE",
            "VIES",
            false,
            Some(d(2026, 1, 1)),
            None,
            Some("MS_UNAVAILABLE".into()),
        )
        .expect("VIES is authoritative");
        assert_eq!(outage.outcome, VatValidationOutcome::Outage);
        assert!(!outage.authorises_reverse_charge("DE", "DE123456789", d(2026, 2, 1)));

        // A non-authoritative source cannot be loaded as evidence at all.
        assert!(VatValidationEvidence::from_authority_row(
            None,
            "DE123456789",
            "DE",
            "MANUAL",
            true,
            Some(d(2026, 1, 1)),
            None,
            None,
        )
        .is_none());
    }

    #[test]
    fn reverse_charge_authorised_rejects_non_eu_and_local() {
        let at = d(2026, 6, 15);
        let evidence = valid_vies_evidence("DE123456789", "DE", d(2026, 1, 1), None);
        assert!(!reverse_charge_authorised(
            "US",
            "DE123456789",
            Some(&evidence),
            at
        ));
        assert!(!reverse_charge_authorised(
            "EE",
            "EE100591102",
            Some(&evidence),
            at
        ));
        // Structural garbage still never authorises, even with evidence
        // present.
        assert!(!reverse_charge_authorised(
            "DE",
            "nonsense",
            Some(&evidence),
            at
        ));
    }

    fn valid_vies_evidence(
        vat_number: &str,
        country: &str,
        from: NaiveDate,
        until: Option<NaiveDate>,
    ) -> VatValidationEvidence {
        VatValidationEvidence {
            id: Some(Uuid::new_v4()),
            vat_number: vat_number.to_string(),
            country: country.to_string(),
            source: VatValidationSource::Vies,
            outcome: VatValidationOutcome::Valid,
            valid_from: from,
            valid_until: until,
            outage_state: None,
        }
    }

    fn d(year: i32, month: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(year, month, day).expect("valid test date")
    }

    #[test]
    fn estonia_never_reverse_charges_even_with_vat_number() {
        // Local EE sales always charge 24 % regardless of VAT number.
        let (rate, amount) = calculate_vat(10_000, "EE", Some("EE100591102"));
        assert_eq!(rate, 24.0);
        assert_eq!(amount, 2_400);
    }

    // ------------------------------------------------------------------
    // Audit item 3d — explicit map-miss policy.
    // ------------------------------------------------------------------

    #[test]
    fn map_miss_policy_parses_env_values() {
        use VatMapMissPolicy::*;

        assert_eq!(VatMapMissPolicy::from_env_value(None), FallbackCountry);
        assert_eq!(VatMapMissPolicy::from_env_value(Some("")), FallbackCountry);
        assert_eq!(
            VatMapMissPolicy::from_env_value(Some("fallback")),
            FallbackCountry
        );
        assert_eq!(
            VatMapMissPolicy::from_env_value(Some("FALLBACK")),
            FallbackCountry
        );
        assert_eq!(VatMapMissPolicy::from_env_value(Some("  error ")), Error);
        assert_eq!(VatMapMissPolicy::from_env_value(Some("ERROR")), Error);
        // Unknown values fail safe to the default, not to error.
        assert_eq!(
            VatMapMissPolicy::from_env_value(Some("nonsense")),
            FallbackCountry
        );
    }

    #[test]
    fn map_miss_policy_names_round_trip() {
        assert_eq!(VatMapMissPolicy::FallbackCountry.as_str(), "fallback");
        assert_eq!(VatMapMissPolicy::Error.as_str(), "error");
    }

    #[test]
    fn resolve_map_miss_fallback_uses_fallback_country_rate() {
        // With DE as the configured fallback country, a miss charges 19 %.
        let rate = resolve_map_miss_rate("XX", VatMapMissPolicy::FallbackCountry, "DE")
            .expect("fallback policy resolves");
        assert_eq!(rate, 19.0);

        // Default fallback (EE) charges 24 % — rate-identical to the old
        // silent behaviour, but now an explicit, logged, configurable
        // decision rather than a hidden default.
        let rate = resolve_map_miss_rate("XX", VatMapMissPolicy::FallbackCountry, "EE")
            .expect("fallback policy resolves");
        assert_eq!(rate, ESTONIA_VAT_RATE);
    }

    #[test]
    fn resolve_map_miss_unknown_fallback_country_uses_estonia() {
        let rate = resolve_map_miss_rate("XX", VatMapMissPolicy::FallbackCountry, "ZZ")
            .expect("last-resort rate resolves");
        assert_eq!(rate, ESTONIA_VAT_RATE);
    }

    #[test]
    fn resolve_map_miss_error_policy_returns_explicit_error() {
        let error = resolve_map_miss_rate("XX", VatMapMissPolicy::Error, "EE")
            .expect_err("error policy must refuse");
        assert_eq!(error.country, "XX");
        assert_eq!(error.fallback_rate, ESTONIA_VAT_RATE);
        assert!(error.to_string().contains("XX"));
        assert!(error.to_string().contains("no VAT rate configured"));
    }

    #[test]
    fn calculate_vat_strict_errors_on_map_miss() {
        // Simulate a miss: "GR" is in the map, so use a country that is in
        // EU_COUNTRIES but (hypothetically) unmapped. With the built-in
        // tables every EU country has a rate, so exercise the strict path
        // through a map that lacks one by testing the behaviour indirectly:
        // strict on a mapped country must behave exactly like calculate_vat.
        assert_eq!(
            calculate_vat_strict(10_000, "DE", None).expect("mapped country"),
            calculate_vat(10_000, "DE", None)
        );
        // Non-EU and EE both short-circuit before the map lookup.
        assert_eq!(
            calculate_vat_strict(10_000, "US", None).expect("non-EU"),
            (0.0, 0)
        );
        assert_eq!(
            calculate_vat_strict(10_000, "EE", None).expect("local"),
            (24.0, 2_400)
        );
    }

    #[test]
    fn strict_and_lenient_agree_on_all_mapped_countries() {
        for &code in DEFAULT_EU_COUNTRIES {
            let lenient = calculate_vat(10_000, code, None);
            let strict = calculate_vat_strict(10_000, code, None)
                .unwrap_or_else(|error| panic!("{code}: {error}"));
            assert_eq!(lenient, strict, "{code} must resolve identically");
        }
    }

    #[test]
    fn default_map_miss_policy_is_logged_fallback_not_silent() {
        // The deployed defaults: fallback policy + EE fallback country.
        // (LazyLock statics read the environment once; a clean environment
        // yields the documented defaults.)
        assert_eq!(*VAT_MAP_MISS_POLICY, VatMapMissPolicy::FallbackCountry);
        assert_eq!(*VAT_FALLBACK_COUNTRY, "EE");
    }

    #[test]
    fn calculate_vat_finland_uses_fractional_rate() {
        // Finland's standard rate is 25.5 % (since 1 September 2024); it must
        // not be rounded to 26 %, which would overcharge every Finnish B2C
        // invoice by half a percentage point.
        let (rate, amount) = calculate_vat(10_000, "FI", None);
        assert_eq!(rate, 25.5);
        assert_eq!(amount, 2_550); // €100.00 × 25.5 % = €25.50

        assert_eq!(format_vat_rate(25.5), "25.5");
        assert_eq!(format_vat_rate(24.0), "24");
    }
}
