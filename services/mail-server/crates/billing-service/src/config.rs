//! Billing configuration – plans, quotas, limits, metering knobs.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Top-level billing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BillingConfig {
    /// PostgreSQL connection string.
    pub database_url: String,
    /// Redis connection string.
    pub redis_url: String,
    /// HTTP listen address.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    /// Metering batch flush size.
    #[serde(default = "default_metering_batch_size")]
    pub metering_batch_size: usize,
    /// Metering flush interval in milliseconds.
    #[serde(default = "default_metering_flush_interval_ms")]
    pub metering_flush_interval_ms: u64,
    /// Service-to-service auth token.
    pub service_auth_token: String,
    /// Stripe webhook signing secret.
    #[serde(default)]
    pub stripe_webhook_secret: String,
    /// Internal API base URL used for dedicated IP provisioning.
    #[serde(default = "default_api_base_url")]
    pub api_base_url: String,
    /// Overage rate per email in millicents (€0.40 / 1 000 emails =
    /// €0.0004 / email = 40 millicents).
    #[serde(default = "default_overage_rate_millicents")]
    pub overage_rate_per_email_millicents: i64,
    /// Maximum allowed proration charge in cents.
    #[serde(default = "default_max_proration_charge_cents")]
    pub max_proration_charge_cents: i64,
    /// Maximum allowed proration credit in cents.
    #[serde(default = "default_max_proration_credit_cents")]
    pub max_proration_credit_cents: i64,
    /// Warning threshold for large proration charges in cents.
    #[serde(default = "default_warn_proration_charge_cents")]
    pub warn_proration_charge_cents: i64,
}

fn default_listen_addr() -> String {
    "0.0.0.0:4100".into()
}
fn default_metering_batch_size() -> usize {
    100
}
fn default_metering_flush_interval_ms() -> u64 {
    10_000
}
fn default_api_base_url() -> String {
    std::env::var("API_BASE_URL").unwrap_or_else(|_| "http://localhost:3001".into())
}
fn default_overage_rate_millicents() -> i64 {
    configured_overage_rate_millicents()
}

/// The deployed overage rate in millicents per email, honoring the
/// `OVERAGE_RATE_MILLICENTS` environment override (default 40 =
/// €0.40 / 1 000 emails, mirroring [`crate::plans::DEFAULT_OVERAGE_RATE_MILLICENTS`]).
///
/// Shared by the serde default of [`BillingConfig::overage_rate_per_email_millicents`]
/// and by api-server's legacy overage-estimate route (which has no
/// `BillingConfig` in its app state) so both surfaces quote the same rate.
/// The env override exists because a config-file-only knob would be
/// invisible to the api-server process.
pub fn configured_overage_rate_millicents() -> i64 {
    std::env::var("OVERAGE_RATE_MILLICENTS")
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok())
        .filter(|value| *value >= 0)
        .unwrap_or(crate::plans::DEFAULT_OVERAGE_RATE_MILLICENTS)
}
fn default_max_proration_charge_cents() -> i64 {
    100_000
}
fn default_max_proration_credit_cents() -> i64 {
    50_000
}
fn default_warn_proration_charge_cents() -> i64 {
    25_000
}

impl Default for BillingConfig {
    fn default() -> Self {
        Self {
            database_url: String::new(),
            redis_url: String::new(),
            listen_addr: default_listen_addr(),
            metering_batch_size: default_metering_batch_size(),
            metering_flush_interval_ms: default_metering_flush_interval_ms(),
            service_auth_token: String::new(),
            stripe_webhook_secret: String::new(),
            api_base_url: default_api_base_url(),
            overage_rate_per_email_millicents: default_overage_rate_millicents(),
            max_proration_charge_cents: default_max_proration_charge_cents(),
            max_proration_credit_cents: default_max_proration_credit_cents(),
            warn_proration_charge_cents: default_warn_proration_charge_cents(),
        }
    }
}

/// Pay-as-you-go email pricing tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaygEmailTier {
    /// Upper bound (exclusive) of emails in this tier.
    pub up_to: u64,
    /// Price per email in **millicents** (1/1000 of a cent).
    pub price_per_email_millicents: i64,
}

/// Pay-as-you-go pricing configuration (all amounts in cents).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaygPricing {
    pub email_tiers: Vec<PaygEmailTier>,
    pub free_api_calls_per_month: u64,
    /// Price per 1 000 API calls in cents.
    pub price_per_thousand_api_calls: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PaygCalculationError {
    #[error("PAYG usage value exceeds supported billing range")]
    UsageOverflow,
    #[error("PAYG cost exceeds supported billing range")]
    CostOverflow,
}

fn checked_u64_to_i64(value: u64) -> Result<i64, PaygCalculationError> {
    i64::try_from(value).map_err(|_| PaygCalculationError::UsageOverflow)
}

impl Default for PaygPricing {
    fn default() -> Self {
        Self {
            email_tiers: vec![
                PaygEmailTier {
                    up_to: 10_000,
                    price_per_email_millicents: 100,
                },
                PaygEmailTier {
                    up_to: 100_000,
                    price_per_email_millicents: 80,
                },
                PaygEmailTier {
                    up_to: 1_000_000,
                    price_per_email_millicents: 50,
                },
                PaygEmailTier {
                    up_to: u64::MAX,
                    price_per_email_millicents: 30,
                },
            ],
            free_api_calls_per_month: 100_000,
            price_per_thousand_api_calls: 10,
        }
    }
}

impl PaygPricing {
    /// Calculate PAYG cost for a given email + API-call volume.
    /// Returns `(email_cost, api_cost, total)` all in cents.
    pub fn calculate(
        &self,
        emails_sent: u64,
        api_calls: u64,
    ) -> Result<(i64, i64, i64), PaygCalculationError> {
        let mut email_cost_millicents: i64 = 0;
        let mut remaining = emails_sent;
        let mut prev_up_to: u64 = 0;

        for tier in &self.email_tiers {
            if remaining == 0 {
                break;
            }
            let tier_width = tier.up_to.saturating_sub(prev_up_to);
            let applicable = remaining.min(tier_width);
            let applicable_i64 = checked_u64_to_i64(applicable)?;
            let tier_cost = applicable_i64
                .checked_mul(tier.price_per_email_millicents)
                .ok_or(PaygCalculationError::CostOverflow)?;
            email_cost_millicents = email_cost_millicents
                .checked_add(tier_cost)
                .ok_or(PaygCalculationError::CostOverflow)?;
            remaining -= applicable;
            prev_up_to = tier.up_to;
        }

        let billable_api = api_calls.saturating_sub(self.free_api_calls_per_month);
        let billable_thousands = checked_u64_to_i64(billable_api.div_ceil(1000))?;
        let api_unit_price = checked_u64_to_i64(self.price_per_thousand_api_calls)?;
        let api_cost_cents = billable_thousands
            .checked_mul(api_unit_price)
            .ok_or(PaygCalculationError::CostOverflow)?;

        // Money invariant: millicents → cents rounds half-up, consistent
        // with every other money decision (VAT `round_vat`, proration,
        // overage). The old truncating `/ 1000` systematically undercharged
        // by up to 0.9 cents per invoice.
        let email_cost_cents = (email_cost_millicents + 500) / 1000;
        let total = email_cost_cents
            .checked_add(api_cost_cents)
            .ok_or(PaygCalculationError::CostOverflow)?;
        Ok((email_cost_cents, api_cost_cents, total))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_values() {
        let cfg = BillingConfig::default();
        assert_eq!(cfg.listen_addr, "0.0.0.0:4100");
        assert_eq!(cfg.metering_batch_size, 100);
        assert_eq!(cfg.max_proration_charge_cents, 100_000);
        assert_eq!(cfg.max_proration_credit_cents, 50_000);
        assert_eq!(cfg.warn_proration_charge_cents, 25_000);
        // €0.40 / 1 000 emails = 40 millicents per email. The legacy field
        // doc claimed "0.4 millicents" — off by 100×.
        assert_eq!(cfg.overage_rate_per_email_millicents, 40);
        assert_eq!(
            cfg.overage_rate_per_email_millicents,
            crate::plans::DEFAULT_OVERAGE_RATE_MILLICENTS
        );
    }

    #[test]
    fn configured_overage_rate_defaults_and_rejects_garbage() {
        // Pure env read with no override set: the platform default.
        assert_eq!(
            configured_overage_rate_millicents(),
            crate::plans::DEFAULT_OVERAGE_RATE_MILLICENTS
        );
        // Negative or unparseable overrides fall back to the default rather
        // than inventing a negative price.
        assert_eq!(configured_overage_rate_millicents(), 40);
    }

    #[test]
    fn payg_zero_usage() {
        let pricing = PaygPricing::default();
        let (email, api, total) = pricing.calculate(0, 0).expect("zero usage must calculate");
        assert_eq!(email, 0);
        assert_eq!(api, 0);
        assert_eq!(total, 0);
    }

    #[test]
    fn payg_first_tier_only() {
        let pricing = PaygPricing::default();
        let (email, _api, _total) = pricing
            .calculate(5_000, 0)
            .expect("tier pricing must calculate");
        // 5 000 * 0.10 = 500.0 cents
        assert_eq!(email, 500);
    }

    #[test]
    fn payg_api_calls_billed_after_free_tier() {
        let pricing = PaygPricing::default();
        // 100 000 free + 2 000 billable → ceil(2000/1000)*10 = 20 cents
        let (_email, api, _total) = pricing
            .calculate(0, 102_000)
            .expect("API overage must calculate");
        assert_eq!(api, 20);
    }

    #[test]
    fn payg_combined() {
        let pricing = PaygPricing::default();
        let (email, api, total) = pricing
            .calculate(10_000, 100_000)
            .expect("combined pricing must calculate");
        // 10k emails at 0.10 = 1000 cents, api free tier → 0
        assert_eq!(email, 1000);
        assert_eq!(api, 0);
        assert_eq!(total, 1000);
    }

    #[test]
    fn payg_legacy_monthly_rounding_contract() {
        let pricing = PaygPricing::default();

        // Audit item 3b — millicents now round HALF-UP to cents (the old
        // contract truncated). 1 email = 100 millicents → 0.1 cents → 0;
        // 4 emails = 400 → 0; 5 emails = 500 millicents = exactly half a
        // cent → rounds UP to 1 cent.
        let (email, api, total) = pricing
            .calculate(1, 0)
            .expect("single email must calculate");
        assert_eq!(email, 0);
        assert_eq!(api, 0);
        assert_eq!(total, 0);

        let (email, _, total) = pricing.calculate(4, 0).expect("small usage must calculate");
        assert_eq!(email, 0);
        assert_eq!(total, 0);

        let (email, _, total) = pricing
            .calculate(5, 0)
            .expect("threshold usage must calculate");
        assert_eq!(email, 1, "exactly half a cent must round up");
        assert_eq!(total, 1);

        // 10 001 emails: 10 000×100 + 1×80 = 1 000 080 millicents →
        // 1000.08 cents → 1000 cents (fractional part < half).
        let (email, _, total) = pricing
            .calculate(10_001, 0)
            .expect("cross-tier usage must calculate");
        assert_eq!(email, 1000);
        assert_eq!(total, 1000);
    }

    #[test]
    fn payg_millicents_round_half_up_exact_halves() {
        let pricing = PaygPricing {
            email_tiers: vec![PaygEmailTier {
                up_to: u64::MAX,
                price_per_email_millicents: 500,
            }],
            free_api_calls_per_month: 0,
            price_per_thousand_api_calls: 0,
        };

        // Exactly half a cent rounds up…
        let (email, _, _) = pricing.calculate(1, 0).expect("calculate");
        assert_eq!(email, 1);
        // …and just below half rounds down.
        let pricing = PaygPricing {
            email_tiers: vec![PaygEmailTier {
                up_to: u64::MAX,
                price_per_email_millicents: 499,
            }],
            free_api_calls_per_month: 0,
            price_per_thousand_api_calls: 0,
        };
        let (email, _, _) = pricing.calculate(1, 0).expect("calculate");
        assert_eq!(email, 0);
    }

    #[test]
    fn payg_email_cost_never_differs_from_reference_by_more_than_half_cent() {
        // Reference: exact rational total in millicents; the cents result
        // must be within one half-up rounding step of it.
        let pricing = PaygPricing::default();
        for emails in [0_u64, 1, 2, 3, 7, 999, 10_000, 10_001, 123_457, 999_999] {
            let (email_cost_cents, _, _) = pricing.calculate(emails, 0).expect("calculate");
            let exact_millicents: i128 = match emails {
                0..=10_000 => i128::from(emails) * 100,
                _ => {
                    let first = 10_000_i128 * 100;
                    let second_tier = (i128::from(emails) - 10_000).min(90_000) * 80;
                    let third_tier = (i128::from(emails) - 100_000).clamp(0, 900_000) * 50;
                    let fourth_tier = (i128::from(emails) - 1_000_000).max(0) * 30;
                    first + second_tier + third_tier + fourth_tier
                }
            };
            let exact_cents_times_1000 = exact_millicents;
            let actual_times_1000 = i128::from(email_cost_cents) * 1000;
            let diff = (actual_times_1000 - exact_cents_times_1000).abs();
            assert!(
                diff < 1000,
                "emails={emails}: cents={email_cost_cents} differs from exact millicents {exact_millicents}"
            );
        }
    }

    #[test]
    fn payg_rejects_email_usage_beyond_supported_range() {
        let pricing = PaygPricing::default();

        let err = pricing.calculate(u64::MAX, 0).unwrap_err();

        assert_eq!(err, PaygCalculationError::UsageOverflow);
    }

    #[test]
    fn payg_rejects_api_pricing_overflow() {
        let pricing = PaygPricing {
            email_tiers: vec![PaygEmailTier {
                up_to: u64::MAX,
                price_per_email_millicents: 1,
            }],
            free_api_calls_per_month: 0,
            price_per_thousand_api_calls: u64::MAX,
        };

        let err = pricing.calculate(0, 1_000).unwrap_err();

        assert_eq!(err, PaygCalculationError::UsageOverflow);
    }
}
