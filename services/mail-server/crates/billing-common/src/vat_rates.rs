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

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Estonian standard VAT rate (24 %, effective since 1 July 2025).
pub const ESTONIA_VAT_RATE: i32 = 24;

/// Default 27 EU member state ISO 3166-1 alpha-2 country codes.
const DEFAULT_EU_COUNTRIES: &[&str] = &[
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV",
    "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE",
];

/// Default standard VAT rates for all 27 EU member states.
const DEFAULT_VAT_RATES: &[(&str, i32)] = &[
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
/// variable (comma-separated `CODE=rate` pairs, e.g. `DE=19,FR=20`).
/// When unset, the built-in defaults below are used.
pub static EU_VAT_RATES: LazyLock<HashMap<String, i32>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    if let Ok(raw) = std::env::var("EU_VAT_RATES") {
        for pair in raw.split(',') {
            let mut parts = pair.split('=');
            if let (Some(country), Some(rate)) = (parts.next(), parts.next()) {
                if let Ok(rate) = rate.trim().parse::<i32>() {
                    map.insert(country.trim().to_uppercase(), rate);
                }
            }
        }
    }
    if map.is_empty() {
        for &(code, rate) in DEFAULT_VAT_RATES {
            map.insert(code.to_string(), rate);
        }
    }
    map
});

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
pub fn get_eu_vat_rate(country: &str) -> Option<i32> {
    EU_VAT_RATES.get(&country.to_uppercase()).copied()
}

/// Calculate the VAT rate and amount for a given subtotal, customer country
/// and optional VAT number.
///
/// # VAT rules
///
/// | Scenario | Rate |
/// |---|---|
/// | Estonia (`EE`) | 24 % (local) |
/// | EU B2B with valid VAT number | 0 % (reverse charge) |
/// | EU B2C (no VAT number) | Destination-country rate (falls back to Estonia) |
/// | Non-EU | 0 % |
pub fn calculate_vat(subtotal: i64, country: &str, vat_number: Option<&str>) -> (i32, i64) {
    if subtotal <= 0 {
        return (0, 0);
    }
    let country = country.to_uppercase();

    if country == "EE" {
        let amt = ((subtotal * ESTONIA_VAT_RATE as i64) + 50) / 100;
        return (ESTONIA_VAT_RATE, amt);
    }

    if EU_COUNTRIES.contains(&country) {
        if vat_number.is_some() {
            // EU B2B — reverse charge (0 %)
            return (0, 0);
        }
        // EU B2C — destination-country VAT
        let rate = EU_VAT_RATES
            .get(&country)
            .copied()
            .unwrap_or(ESTONIA_VAT_RATE);
        let amt = ((subtotal * rate as i64) + 50) / 100;
        return (rate, amt);
    }

    // Non-EU — 0 %
    (0, 0)
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
        assert_eq!(get_eu_vat_rate("EE"), Some(24));
        assert_eq!(get_eu_vat_rate("US"), None);
    }

    #[test]
    fn calculate_vat_estonia_returns_24_percent() {
        let subtotal = 1000_i64; // €10.00 in cents
        let (rate, amount) = calculate_vat(subtotal, "EE", None);
        assert_eq!(rate, 24);
        assert_eq!(amount, 240); // €10.00 × 24 % = €2.40
    }

    #[test]
    fn calculate_vat_eu_b2b_reverse_charge() {
        let subtotal = 1000_i64;
        let (rate, amount) = calculate_vat(subtotal, "DE", Some("DE123456789"));
        assert_eq!(rate, 0, "reverse charge must be 0 %");
        assert_eq!(amount, 0);
    }

    #[test]
    fn calculate_vat_eu_b2c_destination_rate() {
        let subtotal = 1000_i64;
        let (rate, amount) = calculate_vat(subtotal, "DE", None);
        assert_eq!(rate, 19);
        assert_eq!(amount, 190); // €10.00 × 19 % = €1.90
    }

    #[test]
    fn calculate_vat_non_eu_zero() {
        let subtotal = 1000_i64;
        let (rate, amount) = calculate_vat(subtotal, "US", None);
        assert_eq!(rate, 0);
        assert_eq!(amount, 0);
    }

    #[test]
    fn calculate_vat_case_insensitive_country() {
        let (rate, amount) = calculate_vat(1000, "ee", None);
        assert_eq!(rate, 24);
        assert_eq!(amount, 240);

        let (rate, amount) = calculate_vat(1000, "de", None);
        assert_eq!(rate, 19);
        assert_eq!(amount, 190);
    }
    #[test]
    fn calculate_vat_non_positive_subtotal_zero() {
        assert_eq!(calculate_vat(0, "DE", None), (0, 0));
        assert_eq!(calculate_vat(-1000, "EE", None), (0, 0));
    }
}
