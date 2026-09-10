//! Versioned, date-effective Estonian tax policy (F81).
//!
//! One authoritative module for every statutory rate used by the compliance
//! helpers. Rates change on DOCUMENTED legal boundaries; pinning them as
//! scattered constants let a 20% VAT rate survive eighteen months after the
//! law changed. Each accessor takes the date the tax event applies to
//! (invoice issue date, payment period, distribution date) and returns the
//! rate in force on that date.
//!
//! Boundaries and sources (Estonian Tax and Customs Board / Riigi Teataja,
//! retrieved 2026-09-10):
//!
//! * Standard VAT (käibemaks):
//!   - 20% until 2024-06-30,
//!   - 22% from 2024-07-01 (KMS §14 amendment),
//!   - 24% from 2025-07-01 (the "July 2025 VAT change").
//! * Corporate income tax on distributed profits (TuMS §50): a distribution
//!   is taxed so that the NET amount and the tax form the gross. Until
//!   2024-12-31 the split is 80/20 (20% of gross); from 2025-01-01 it is
//!   78/22 (22% of gross). For a NET distribution N the tax is therefore
//!   N × 20/80 before 2025 and N × 22/78 from 2025 — the NET-TO-TAX
//!   fraction; applying 0.22 to a net amount would over-tax it.
//! * Withheld income tax (tulumaks): 20% until 2023-12-31; 22% from
//!   2024-01-01 (2024–2025 included a temporary 2% "security tax"
//!   component; the combined statutory withholding rate was 22%).
//! * Social tax: 33% (unchanged in the covered period).
//! * Unemployment insurance: 0.8% employer / 1.6% employee (unchanged).
//! * Funded pension (II pillar): an EMPLOYEE-SPECIFIC choice of 2%, 4% or
//!   6% of gross salary (0% when not participating or legally exempt) —
//!   never a single company-wide constant; see [`funded_pension_rates`]
//!   and migration 199's payroll inputs.
//!
//! This module is a software calculation policy, not certification of the
//! company's tax position; statutory filings require qualified accounting
//! review (the estonia_ou reports carry explicit not-ready states for that
//! reason).

use chrono::NaiveDate;

/// A dated tax-rate revision: `effective_from` is the FIRST day the rate
/// applies (inclusive).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateRevision {
    pub effective_from: NaiveDate,
    pub rate: f64,
}

/// Pick the rate in force on `date` from ascending-dated revisions.
fn rate_on(date: NaiveDate, revisions: &[RateRevision]) -> f64 {
    let mut current = revisions[0].rate;
    for revision in revisions {
        if date >= revision.effective_from {
            current = revision.rate;
        } else {
            break;
        }
    }
    current
}

/// Standard VAT rate in force on `date` (fraction, e.g. 0.24).
pub fn vat_standard_rate(date: NaiveDate) -> f64 {
    rate_on(
        date,
        &[
            RateRevision {
                effective_from: NaiveDate::from_ymd_opt(2000, 1, 1).unwrap(),
                rate: 0.20,
            },
            RateRevision {
                effective_from: NaiveDate::from_ymd_opt(2024, 7, 1).unwrap(),
                rate: 0.22,
            },
            RateRevision {
                effective_from: NaiveDate::from_ymd_opt(2025, 7, 1).unwrap(),
                rate: 0.24,
            },
        ],
    )
}

/// Income tax withheld from employment income in force on the payment date
/// (fraction).
pub fn income_tax_withheld_rate(date: NaiveDate) -> f64 {
    rate_on(
        date,
        &[
            RateRevision {
                effective_from: NaiveDate::from_ymd_opt(2000, 1, 1).unwrap(),
                rate: 0.20,
            },
            RateRevision {
                effective_from: NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
                rate: 0.22,
            },
        ],
    )
}

/// Net-to-tax fraction for dividend distributions in force on the
/// distribution date: multiply a NET distributed amount by this to get the
/// CIT due. 20/80 until end-2024, 22/78 from 2025-01-01.
pub fn dividend_tax_on_net(date: NaiveDate) -> f64 {
    if date >= NaiveDate::from_ymd_opt(2025, 1, 1).unwrap() {
        22.0 / 78.0
    } else {
        20.0 / 80.0
    }
}

/// Social tax rate on gross salary (employer share).
pub fn social_tax_rate(_date: NaiveDate) -> f64 {
    0.33
}

/// Unemployment insurance — employer share.
pub fn unemployment_insurance_employer_rate(_date: NaiveDate) -> f64 {
    0.008
}

/// Unemployment insurance — employee share.
pub fn unemployment_insurance_employee_rate(_date: NaiveDate) -> f64 {
    0.016
}

/// The allowed funded-pension (II pillar) participation choices as fractions
/// of gross salary. The applicable rate is an EMPLOYEE-SPECIFIC input
/// recorded per payment period (payroll_records.funded_pension_rate,
/// migration 199) — `0.0` covers non-participation and legal exemption.
pub fn funded_pension_allowed_rates() -> [f64; 4] {
    [0.00, 0.02, 0.04, 0.06]
}

/// Validate a funded-pension rate choice (None = unknown → the calculation
/// must surface the record as incomplete, not silently assume a rate).
pub fn is_valid_funded_pension_rate(rate: f64) -> bool {
    funded_pension_allowed_rates().contains(&rate)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).unwrap()
    }

    // ── VAT boundaries (the documented July 2025 change) ───────────────

    #[test]
    fn vat_before_july_2024_is_20_percent() {
        assert!((vat_standard_rate(d(2024, 6, 30)) - 0.20).abs() < 1e-9);
    }

    #[test]
    fn vat_from_july_2024_is_22_percent() {
        assert!((vat_standard_rate(d(2024, 7, 1)) - 0.22).abs() < 1e-9);
        assert!((vat_standard_rate(d(2025, 6, 30)) - 0.22).abs() < 1e-9);
    }

    #[test]
    fn vat_from_july_2025_is_24_percent() {
        assert!((vat_standard_rate(d(2025, 7, 1)) - 0.24).abs() < 1e-9);
        assert!((vat_standard_rate(d(2026, 1, 1)) - 0.24).abs() < 1e-9);
        assert!((vat_standard_rate(d(2026, 9, 10)) - 0.24).abs() < 1e-9);
    }

    // ── Withheld income tax ────────────────────────────────────────────

    #[test]
    fn income_tax_withheld_boundary() {
        assert!((income_tax_withheld_rate(d(2023, 12, 31)) - 0.20).abs() < 1e-9);
        assert!((income_tax_withheld_rate(d(2024, 1, 1)) - 0.22).abs() < 1e-9);
        assert!((income_tax_withheld_rate(d(2026, 5, 15)) - 0.22).abs() < 1e-9);
    }

    // ── Dividend net-to-tax fraction ───────────────────────────────────

    #[test]
    fn dividend_tax_fraction_boundary() {
        // Until end-2024: 20/80 (a 78 EUR net distribution owes 19.50 EUR).
        assert!((dividend_tax_on_net(d(2024, 12, 31)) - 0.25).abs() < 1e-9);
        // From 2025: 22/78 (a 78 EUR net distribution owes 22.00 EUR).
        assert!((dividend_tax_on_net(d(2025, 1, 1)) - 22.0 / 78.0).abs() < 1e-9);
        assert!((dividend_tax_on_net(d(2026, 3, 1)) - 22.0 / 78.0).abs() < 1e-9);
    }

    #[test]
    fn net_distribution_of_78_owes_22_from_2025() {
        let tax = (78.0_f64 * dividend_tax_on_net(d(2025, 6, 1)) * 100.0).round() / 100.0;
        assert!((tax - 22.0).abs() < 0.01);
    }

    #[test]
    fn merely_changing_020_to_022_misstates_the_tax() {
        // The naive "0.22 of net" understates the liability: the correct
        // net-to-tax fraction is 22/78 ≈ 0.282, not 0.22.
        let correct = 78.0 * dividend_tax_on_net(d(2025, 6, 1));
        let naive = 78.0 * 0.22;
        assert!(
            naive < correct - 4.0,
            "naive 0.22-of-net ({naive:.2}) must differ materially from the              22/78 fraction ({correct:.2})"
        );
        assert!((correct - 22.0).abs() < 0.01);
    }

    // ── Pension choices ────────────────────────────────────────────────

    #[test]
    fn pension_choices_are_employee_specific() {
        assert_eq!(funded_pension_allowed_rates(), [0.0, 0.02, 0.04, 0.06]);
        assert!(is_valid_funded_pension_rate(0.06));
        assert!(!is_valid_funded_pension_rate(0.03));
        assert!(!is_valid_funded_pension_rate(0.20));
    }

    // ── Stable unchanged rates ─────────────────────────────────────────

    #[test]
    fn social_and_unemployment_rates_are_stable() {
        let date = d(2026, 2, 1);
        assert!((social_tax_rate(date) - 0.33).abs() < 1e-9);
        assert!((unemployment_insurance_employer_rate(date) - 0.008).abs() < 1e-9);
        assert!((unemployment_insurance_employee_rate(date) - 0.016).abs() < 1e-9);
    }
}
