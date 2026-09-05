//! Proration calculation logic for plan changes.
//!
//! # Important
//!
//! This module uses the **actual** `days_in_period` derived from the
//! subscription's `current_period_end - current_period_start` timestamps.
//! For yearly subscriptions created by Stripe, this is typically 365 days
//! (or 366 in leap years), **not** a fixed 360-day convention.
//!
//! # Source files replaced
//!
//! | Original location | What was replaced |
//! |---|---|
//! | [`billing-service/src/routes.rs`](services/mail-server/crates/billing-service/src/routes.rs:920) | `prorated_amount()`, `ceil_day_count()`, `build_proration_explanation()` |
//! | [`api-server/src/routes/billing.rs`](services/mail-server/crates/api-server/src/routes/billing.rs:2048) | duplicate of the above |

/// Number of milliseconds in one standard day (24 × 60 × 60 × 1000).
pub const MILLISECONDS_PER_DAY: i64 = 86_400_000;

/// Format integer cents as a euro amount ("€123.45") using integer math only.
///
/// The platform bills exclusively in EUR; the previous `${:.2}` formatter
/// quoted a currency that is never charged and routed the amount through
/// f64. Display code everywhere (billing-service routes, api-server invoice
/// renderers, these explanation strings) must render euros with this
/// integer helper — money formatting never round-trips through a float.
pub fn cents_to_eur_string(cents: i64) -> String {
    // The sign leads the currency symbol ("-€59.18"): a negative amount
    // is a negative quantity of euros, and the explanation strings that
    // consume this formatter pass abs() anyway.
    let sign = if cents < 0 { "-" } else { "" };
    let abs = cents.unsigned_abs();
    format!("{}€{}.{:02}", sign, abs / 100, abs % 100)
}

/// Compute the ceiling number of days for a duration given in milliseconds.
///
/// Returns `0` when `duration_ms ≤ 0`.
pub fn ceil_day_count(duration_ms: i64) -> i64 {
    if duration_ms <= 0 {
        0
    } else {
        (duration_ms + MILLISECONDS_PER_DAY - 1) / MILLISECONDS_PER_DAY
    }
}

/// Compute the FLOOR number of days for a duration given in milliseconds.
///
/// Elapsed time must floor (a half-day elapsed has not consumed a whole
/// day yet); ceil-ing BOTH elapsed and period length discarded up to a full
/// day of remaining time on mid-period plan changes — a systematic
/// customer-unfavorable bias.
pub fn floor_day_count(duration_ms: i64) -> i64 {
    if duration_ms <= 0 {
        0
    } else {
        duration_ms / MILLISECONDS_PER_DAY
    }
}

/// Calculate the prorated amount for a given total price, remaining days and
/// total days in the billing period.
///
/// Uses `i128` arithmetic to avoid overflow, with rounding to nearest cent.
///
/// Returns `Ok(0)` when `days_remaining ≤ 0`.
/// Returns `Err` when `days_in_period ≤ 0` or arithmetic overflows.
pub fn prorated_amount(
    total_price_cents: i64,
    days_remaining: i64,
    days_in_period: i64,
) -> Result<i64, String> {
    if days_remaining <= 0 {
        return Ok(0);
    }
    if days_in_period <= 0 {
        return Err("Invalid period: daysInPeriod must be greater than 0".to_string());
    }

    let numerator = i128::from(total_price_cents)
        .checked_mul(i128::from(days_remaining))
        .ok_or_else(|| "Proration amount overflowed supported billing range".to_string())?;
    let denominator = i128::from(days_in_period);
    let rounded = numerator
        .checked_add(denominator / 2)
        .ok_or_else(|| "Proration amount overflowed supported billing range".to_string())?
        / denominator;

    i64::try_from(rounded)
        .map_err(|_| "Proration amount overflowed supported billing range".to_string())
}

/// Build a human-readable proration explanation string.
#[allow(clippy::too_many_arguments)]
pub fn build_proration_explanation(
    current_plan_display_name: &str,
    new_plan_display_name: &str,
    current_price: i64,
    new_price: i64,
    days_remaining: i64,
    days_in_period: i64,
    credit_amount: i64,
    charge_amount: i64,
    net_amount: i64,
) -> String {
    let format_currency = |cents: i64| cents_to_eur_string(cents.abs());

    let mut lines = vec![
        format!(
            "Plan change from {} to {}",
            current_plan_display_name, new_plan_display_name
        ),
        String::new(),
        format!(
            "Current period: {} days remaining out of {} days",
            days_remaining, days_in_period
        ),
        String::new(),
        format!(
            "Credit for unused {} time: {}",
            current_plan_display_name,
            format_currency(credit_amount)
        ),
        format!(
            "({} / {} days × {} days)",
            format_currency(current_price),
            days_in_period,
            days_remaining
        ),
        String::new(),
        format!(
            "Charge for {} remaining time: {}",
            new_plan_display_name,
            format_currency(charge_amount)
        ),
        format!(
            "({} / {} days × {} days)",
            format_currency(new_price),
            days_in_period,
            days_remaining
        ),
        String::new(),
    ];

    if net_amount > 0 {
        lines.push(format!("Net charge: {}", format_currency(net_amount)));
    } else if net_amount < 0 {
        lines.push(format!(
            "Net credit: {} (applied to next invoice)",
            format_currency(net_amount)
        ));
    } else {
        lines.push("No additional charge or credit".to_string());
    }

    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_day_count_rounds_down_and_never_discards_elapsed_time() {
        assert_eq!(floor_day_count(MILLISECONDS_PER_DAY - 1), 0);
        assert_eq!(floor_day_count(MILLISECONDS_PER_DAY), 1);
        // 15.5 days elapsed is 15 WHOLE days consumed — not 16. Together
        // with ceil(days_in_period) this credits the full fractional
        // remainder instead of discarding it.
        assert_eq!(
            floor_day_count(15 * MILLISECONDS_PER_DAY + MILLISECONDS_PER_DAY / 2),
            15
        );
    }

    #[test]
    fn mid_period_upgrade_keeps_the_fractional_remainder() {
        // 30-day period, 15.5 days elapsed at the upgrade instant.
        let days_in_period = ceil_day_count(30 * MILLISECONDS_PER_DAY);
        let days_elapsed = floor_day_count(15 * MILLISECONDS_PER_DAY + MILLISECONDS_PER_DAY / 2);
        assert_eq!(days_elapsed, 15);
        // The pre-fix pairing (ceil/ceil) yielded 30 - 16 = 14 remaining —
        // silently billing the customer for half a day they had not used.
        assert_eq!((days_in_period - days_elapsed).max(0), 15);
    }
    #[test]
    fn ceil_day_count_rounds_up() {
        // A duration of 1 ms less than a full day should still count as 1 day.
        assert_eq!(ceil_day_count(MILLISECONDS_PER_DAY - 1), 1);
        assert_eq!(ceil_day_count(MILLISECONDS_PER_DAY), 1);
        assert_eq!(ceil_day_count(MILLISECONDS_PER_DAY + 1), 2);
    }

    #[test]
    fn ceil_day_count_zero_or_negative_returns_zero() {
        assert_eq!(ceil_day_count(0), 0);
        assert_eq!(ceil_day_count(-1), 0);
        assert_eq!(ceil_day_count(-1000), 0);
    }

    #[test]
    fn prorated_amount_zero_when_no_days_remaining() {
        assert_eq!(prorated_amount(1000, 0, 30).unwrap(), 0);
        assert_eq!(prorated_amount(1000, -5, 30).unwrap(), 0);
    }

    #[test]
    fn prorated_amount_rejects_invalid_period() {
        assert!(prorated_amount(1000, 10, 0).is_err());
        assert!(prorated_amount(1000, 10, -1).is_err());
    }

    #[test]
    fn prorated_amount_half_period() {
        // 1000 cents over 30 days, 15 days remaining → 500 cents
        assert_eq!(prorated_amount(1000, 15, 30).unwrap(), 500);
    }

    #[test]
    fn prorated_amount_full_period() {
        // Full period remaining → full price
        assert_eq!(prorated_amount(12000, 365, 365).unwrap(), 12000);
    }

    #[test]
    fn prorated_amount_rounding() {
        // 1000 cents over 30 days, 10 days remaining → 333 cents (rounded)
        assert_eq!(prorated_amount(1000, 10, 30).unwrap(), 333);
    }

    #[test]
    fn yearly_proration_uses_365_days() {
        // Simulate a yearly subscription: $120.00 over 365 days, 180 days remaining
        let credit = prorated_amount(12000, 180, 365).unwrap();
        let charge = prorated_amount(24000, 180, 365).unwrap();

        // $120.00 / 365 days × 180 days = $59.18 (rounded)
        assert_eq!(credit, 5918);
        // $240.00 / 365 days × 180 days = $118.36 (rounded)
        assert_eq!(charge, 11836);
    }

    #[test]
    fn build_proration_explanation_includes_days_in_period() {
        let explanation = build_proration_explanation(
            "Starter", "Growth", 12000, 24000, 180, 365, 5918, 11836, 5918,
        );
        assert!(explanation.contains("365 days"));
        assert!(explanation.contains("€120.00 / 365 days × 180 days"));
        assert!(explanation.contains("€240.00 / 365 days × 180 days"));
        assert!(explanation.contains("Net charge: €59.18"));
    }

    #[test]
    fn build_proration_explanation_net_credit() {
        let explanation = build_proration_explanation(
            "Growth", "Starter", 24000, 12000, 180, 365, 11836, 5918, -5918,
        );
        assert!(explanation.contains("Net credit: €59.18"));
    }

    // ------------------------------------------------------------------
    // Euro display formatting — integer math only, never f64.
    // ------------------------------------------------------------------

    #[test]
    fn cents_to_eur_string_renders_two_fraction_digits() {
        assert_eq!(cents_to_eur_string(0), "€0.00");
        assert_eq!(cents_to_eur_string(5), "€0.05");
        assert_eq!(cents_to_eur_string(5918), "€59.18");
        assert_eq!(cents_to_eur_string(12000), "€120.00");
        assert_eq!(cents_to_eur_string(1_000_000), "€10000.00");
    }

    #[test]
    fn cents_to_eur_string_handles_negative_amounts() {
        // Net credits render with a leading sign; the explanation strings
        // pass `abs()` so the sign normally never reaches this path.
        assert_eq!(cents_to_eur_string(-5918), "-€59.18");
        assert_eq!(cents_to_eur_string(-5), "-€0.05");
    }

    #[test]
    fn build_proration_explanation_no_change() {
        let explanation =
            build_proration_explanation("Starter", "Starter", 12000, 12000, 0, 365, 0, 0, 0);
        assert!(explanation.contains("No additional charge or credit"));
    }
}
