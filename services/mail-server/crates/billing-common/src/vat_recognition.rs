//! VAT recognition basis and taxable-event timing.
//!
//! A filed VAT return must recognise output VAT at the **taxable event**,
//! which is not the same as "the invoice row currently has status paid".
//! The old KMD aggregation (`PAID_INVOICE_FILTER = "status = 'paid'"`)
//! modelled a cash-receipts tax that does not generally exist: the default
//! Estonian/EU rule is accrual — VAT becomes chargeable when the supply is
//! made (KMS §11), regardless of payment.
//!
//! This module owns the two accounting bases the platform supports and the
//! date each one recognises:
//!
//! * [`VatAccountingScheme::General`] — VAT is recognised on the supply
//!   (invoice issue / supply date). No authorisation needed.
//! * [`VatAccountingScheme::CashSpecial`] — the special cash-accounting
//!   scheme. VAT is recognised when payment is received, **but** an unpaid
//!   supply becomes taxable on the first day of the third calendar month
//!   following the supply (KMS §11¹; the Estonian cash-accounting rule).
//!   This scheme requires an explicit, dated authorisation
//!   (`vat_accounting_bases.authorisation_reference`) and only applies from
//!   its `effective_from` date.
//!
//! The accounting basis is resolved per tenant and per tax-point date from
//! dated rows (migration 213, `vat_accounting_bases`); the resulting entries
//! live in `vat_recognition_entries`, and KMD aggregates **that ledger**
//! instead of invoice status. The recognition entries carry a nullable
//! `journal_entry_id` so the forthcoming double-entry accounting core can
//! link/reconcile each entry to its journal; until that crate lands, the
//! ledger is the source of truth on its own.

use chrono::{Datelike, NaiveDate};

/// The accounting basis under which output VAT is recognised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VatAccountingScheme {
    /// Accrual: recognised when the supply is made.
    General,
    /// Estonian special cash accounting: recognised on payment, or on the
    /// first day of the third calendar month following the supply when
    /// still unpaid.
    CashSpecial,
}

impl VatAccountingScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::General => "general",
            Self::CashSpecial => "cash_special",
        }
    }

    pub fn from_db(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "general" => Some(Self::General),
            "cash_special" => Some(Self::CashSpecial),
            _ => None,
        }
    }
}

/// A dated authorisation of an accounting basis (row of
/// `vat_accounting_bases`). `tenant_id = None` is the platform default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VatAccountingBasis {
    pub tenant_id: Option<String>,
    pub scheme: VatAccountingScheme,
    /// First day the basis applies (inclusive).
    pub effective_from: NaiveDate,
    /// Last day the basis applies (inclusive); `None` = open-ended.
    pub effective_to: Option<NaiveDate>,
    /// When the cash-accounting authorisation was granted.
    pub authorised_at: Option<NaiveDate>,
    /// The tax authority's authorisation reference. Mandatory for
    /// [`VatAccountingScheme::CashSpecial`] — an unauthorised cash basis is
    /// ignored by [`resolve_accounting_scheme`] and the supply falls back to
    /// the general scheme.
    pub authorisation_reference: Option<String>,
}

impl VatAccountingBasis {
    fn covers(&self, at: NaiveDate) -> bool {
        self.effective_from <= at && self.effective_to.map_or(true, |to| at <= to)
    }

    fn is_authorised(&self) -> bool {
        match self.scheme {
            VatAccountingScheme::General => true,
            VatAccountingScheme::CashSpecial => self
                .authorisation_reference
                .as_deref()
                .map(str::trim)
                .is_some_and(|reference| !reference.is_empty()),
        }
    }
}

/// Resolve the accounting basis for `tenant_id` on `at`.
///
/// Deterministic precedence:
/// 1. a covering tenant-specific row with the greatest `effective_from`;
/// 2. otherwise a covering platform-default row with the greatest
///    `effective_from`;
/// 3. otherwise [`VatAccountingScheme::General`].
///
/// A `cash_special` row without an authorisation reference is ignored (fail
/// to general), so a misconfigured/unauthorised row can never silently move
/// a tenant onto cash accounting.
pub fn resolve_accounting_scheme(
    bases: &[VatAccountingBasis],
    tenant_id: &str,
    at: NaiveDate,
) -> VatAccountingScheme {
    let newest = |tenant: Option<&str>| {
        bases
            .iter()
            .filter(|basis| basis.is_authorised() && basis.covers(at))
            .filter(|basis| basis.tenant_id.as_deref() == tenant)
            .max_by_key(|basis| basis.effective_from)
    };

    if let Some(basis) = newest(Some(tenant_id)) {
        return basis.scheme;
    }
    if let Some(basis) = newest(None) {
        return basis.scheme;
    }
    VatAccountingScheme::General
}

/// First day of the month `months` calendar months after `date`'s month.
/// Supports any month count; used with `3` for the cash-accounting fallback
/// (supply 2026-01-15 → 2026-04-01).
pub fn first_day_of_month_after(months: u32, date: NaiveDate) -> NaiveDate {
    let zero_based = u32::from(date.month0()) + months;
    let year = date.year() + (zero_based / 12) as i32;
    let month = (zero_based % 12) + 1;
    NaiveDate::from_ymd_opt(year, month, 1)
        .expect("invariant: month arithmetic always yields a valid date")
}

/// The cash-accounting fallback date: the first day of the third calendar
/// month following the supply ("unpaid supply becomes taxable").
pub fn cash_special_fallback_date(supply_date: NaiveDate) -> NaiveDate {
    first_day_of_month_after(3, supply_date)
}

/// The date on which output VAT is recognised under the cash-accounting
/// scheme: the earlier of the payment date and the third-month fallback.
///
/// * paid 2026-03-31 for a January supply → recognised 2026-03-31;
/// * paid 2026-04-01 → recognised 2026-04-01 (payment coincides with the
///   fallback, which had already made the supply taxable that day);
/// * paid 2026-04-15 → recognised 2026-04-01 (the fallback fired first);
/// * unpaid → recognised 2026-04-01.
pub fn cash_special_recognition_date(
    supply_date: NaiveDate,
    paid_at: Option<NaiveDate>,
) -> NaiveDate {
    let fallback = cash_special_fallback_date(supply_date);
    match paid_at {
        Some(paid) if paid < fallback => paid,
        _ => fallback,
    }
}

/// The taxable date for a supply under `scheme`.
pub fn recognition_date(
    scheme: VatAccountingScheme,
    supply_date: NaiveDate,
    paid_at: Option<NaiveDate>,
) -> NaiveDate {
    match scheme {
        VatAccountingScheme::General => supply_date,
        VatAccountingScheme::CashSpecial => cash_special_recognition_date(supply_date, paid_at),
    }
}

/// The recognition-period key (`YYYY-MM`) for a taxable date. Callers that
/// need the Estonian filing period convert the taxable instant to
/// `Europe/Tallinn` first; the calendar month is then unambiguous.
pub fn recognition_period(taxable_date: NaiveDate) -> String {
    format!("{:04}-{:02}", taxable_date.year(), taxable_date.month())
}

/// The ledger event that produced a recognition entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecognitionEventType {
    /// General scheme, recognised on the supply.
    Supply,
    /// Cash scheme, recognised because the customer paid.
    Payment,
    /// Cash scheme fallback: still unpaid on the first day of the third
    /// following month, so the supply became taxable.
    CashSpecialDue,
    /// Correction to a previously recognised amount (e.g. credit note).
    Correction,
}

impl RecognitionEventType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Supply => "supply",
            Self::Payment => "payment",
            Self::CashSpecialDue => "cash_special_due",
            Self::Correction => "correction",
        }
    }
}

/// The event type recognising a supply under `scheme` given its payment
/// state. `paid_at` is the date the invoice was (fully) settled, if any.
pub fn recognition_event_type(
    scheme: VatAccountingScheme,
    supply_date: NaiveDate,
    paid_at: Option<NaiveDate>,
) -> RecognitionEventType {
    match scheme {
        VatAccountingScheme::General => RecognitionEventType::Supply,
        VatAccountingScheme::CashSpecial => match paid_at {
            Some(paid) if paid < cash_special_fallback_date(supply_date) => {
                RecognitionEventType::Payment
            }
            _ => RecognitionEventType::CashSpecialDue,
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn d(year: i32, month: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(year, month, day).expect("valid test date")
    }

    // ── General scheme ────────────────────────────────────────────────

    #[test]
    fn general_scheme_recognizes_on_supply() {
        let supply = d(2026, 3, 15);
        assert_eq!(
            recognition_date(VatAccountingScheme::General, supply, None),
            supply
        );
        // Payment (even late) is irrelevant under accrual.
        assert_eq!(
            recognition_date(VatAccountingScheme::General, supply, Some(d(2026, 9, 1))),
            supply
        );
        assert_eq!(
            recognition_event_type(VatAccountingScheme::General, supply, None),
            RecognitionEventType::Supply
        );
        assert_eq!(recognition_period(supply), "2026-03");
    }

    // ── Cash special: the third-month boundary ────────────────────────

    #[test]
    fn cash_special_fallback_is_first_day_of_third_following_month() {
        // January supply: April 1 is the first day of the third calendar
        // month following January (Feb = 1st, Mar = 2nd, Apr = 3rd).
        assert_eq!(cash_special_fallback_date(d(2026, 1, 15)), d(2026, 4, 1));
        // December supply rolls into the next year.
        assert_eq!(cash_special_fallback_date(d(2026, 12, 10)), d(2027, 3, 1));
    }

    #[test]
    fn cash_special_boundary_last_day_of_month_two_vs_first_day_of_month_three() {
        let supply = d(2026, 1, 15);
        // Payment on the last day of the second following month (March 31)
        // recognises in March — the fallback has NOT fired yet.
        assert_eq!(
            cash_special_recognition_date(supply, Some(d(2026, 3, 31))),
            d(2026, 3, 31)
        );
        assert_eq!(
            recognition_event_type(
                VatAccountingScheme::CashSpecial,
                supply,
                Some(d(2026, 3, 31))
            ),
            RecognitionEventType::Payment
        );

        // Payment on the first day of the third following month (April 1)
        // recognises on the fallback date, in April.
        assert_eq!(
            cash_special_recognition_date(supply, Some(d(2026, 4, 1))),
            d(2026, 4, 1)
        );
        assert_eq!(
            recognition_event_type(
                VatAccountingScheme::CashSpecial,
                supply,
                Some(d(2026, 4, 1))
            ),
            RecognitionEventType::CashSpecialDue
        );
    }

    #[test]
    fn cash_special_unpaid_and_late_paid_recognize_on_fallback() {
        let supply = d(2026, 1, 15);
        // Never paid: taxable on the fallback date.
        assert_eq!(cash_special_recognition_date(supply, None), d(2026, 4, 1));
        // Paid long after: the fallback fired first.
        assert_eq!(
            cash_special_recognition_date(supply, Some(d(2026, 6, 20))),
            d(2026, 4, 1)
        );
        assert_eq!(
            recognition_event_type(VatAccountingScheme::CashSpecial, supply, None),
            RecognitionEventType::CashSpecialDue
        );
    }

    #[test]
    fn cash_special_early_payment_recognizes_on_payment_date() {
        let supply = d(2026, 5, 20);
        assert_eq!(
            cash_special_recognition_date(supply, Some(d(2026, 6, 2))),
            d(2026, 6, 2)
        );
        assert_eq!(recognition_period(d(2026, 6, 2)), "2026-06");
        // May supply, fallback is August 1.
        assert_eq!(cash_special_fallback_date(supply), d(2026, 8, 1));
    }

    // ── Dated resolution ──────────────────────────────────────────────

    fn cash_basis(from: NaiveDate, reference: Option<&str>) -> VatAccountingBasis {
        VatAccountingBasis {
            tenant_id: Some("tenant_A".into()),
            scheme: VatAccountingScheme::CashSpecial,
            effective_from: from,
            effective_to: None,
            authorised_at: Some(from),
            authorisation_reference: reference.map(str::to_string),
        }
    }

    #[test]
    fn scheme_resolution_respects_effective_dates() {
        let bases = vec![cash_basis(d(2026, 7, 1), Some("EMTA-2026-17"))];

        // Before the authorisation date, the general scheme applies.
        assert_eq!(
            resolve_accounting_scheme(&bases, "tenant_A", d(2026, 6, 30)),
            VatAccountingScheme::General
        );
        // From the effective date, cash accounting applies.
        assert_eq!(
            resolve_accounting_scheme(&bases, "tenant_A", d(2026, 7, 1)),
            VatAccountingScheme::CashSpecial
        );
        // Other tenants are unaffected.
        assert_eq!(
            resolve_accounting_scheme(&bases, "tenant_B", d(2026, 7, 1)),
            VatAccountingScheme::General
        );
    }

    #[test]
    fn scheme_resolution_ignores_unauthorised_cash_special() {
        let bases = vec![cash_basis(d(2026, 1, 1), None)];
        assert_eq!(
            resolve_accounting_scheme(&bases, "tenant_A", d(2026, 5, 1)),
            VatAccountingScheme::General,
            "cash_special without an authorisation reference must not apply"
        );
    }

    #[test]
    fn scheme_resolution_tenant_specific_beats_platform_default() {
        let bases = vec![
            VatAccountingBasis {
                tenant_id: None,
                scheme: VatAccountingScheme::CashSpecial,
                effective_from: d(2026, 1, 1),
                effective_to: None,
                authorised_at: Some(d(2026, 1, 1)),
                authorisation_reference: Some("DEFAULT".into()),
            },
            VatAccountingBasis {
                tenant_id: Some("tenant_A".into()),
                scheme: VatAccountingScheme::General,
                effective_from: d(2026, 2, 1),
                effective_to: None,
                authorised_at: None,
                authorisation_reference: None,
            },
        ];
        // Tenant A opted back into general from Feb.
        assert_eq!(
            resolve_accounting_scheme(&bases, "tenant_A", d(2026, 3, 1)),
            VatAccountingScheme::General
        );
        // Everyone else stays on the default cash basis.
        assert_eq!(
            resolve_accounting_scheme(&bases, "tenant_B", d(2026, 3, 1)),
            VatAccountingScheme::CashSpecial
        );
    }

    #[test]
    fn scheme_names_round_trip() {
        assert_eq!(VatAccountingScheme::General.as_str(), "general");
        assert_eq!(VatAccountingScheme::CashSpecial.as_str(), "cash_special");
        assert_eq!(
            VatAccountingScheme::from_db("CASH_SPECIAL"),
            Some(VatAccountingScheme::CashSpecial)
        );
        assert_eq!(VatAccountingScheme::from_db("nonsense"), None);
    }
}
