//! Billing configuration – plans, quotas, limits, metering knobs.

use serde::{Deserialize, Serialize};

/// Top-level billing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
/// Estonia VAT rate (percent).
    #[serde(default = "default_vat_rate")]
    pub estonia_vat_rate: u32,
/// Overage rate per email in cents ($0.40 / 1 000 = 0.04 cents).
    #[serde(default = "default_overage_rate_cents")]
    pub overage_rate_per_email_millicents: i64,
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
fn default_vat_rate() -> u32 {
    22
}
fn default_overage_rate_cents() -> i64 {
    40
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
            estonia_vat_rate: default_vat_rate(),
            overage_rate_per_email_millicents: default_overage_rate_cents(),
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

impl Default for PaygPricing {
    fn default() -> Self {
        Self {
            email_tiers: vec![
                PaygEmailTier { up_to: 10_000, price_per_email_millicents: 100 },
                PaygEmailTier { up_to: 100_000, price_per_email_millicents: 80 },
                PaygEmailTier { up_to: 1_000_000, price_per_email_millicents: 50 },
                PaygEmailTier { up_to: u64::MAX, price_per_email_millicents: 30 },
            ],
            free_api_calls_per_month: 100_000,
            price_per_thousand_api_calls: 10,
        }
    }
}

impl PaygPricing {
/// Calculate PAYG cost for a given email + API-call volume.
/// Returns `(email_cost, api_cost, total)` all in cents.
    pub fn calculate(&self, emails_sent: u64, api_calls: u64) -> (i64, i64, i64) {
        let mut email_cost_millicents: i64 = 0;
        let mut remaining = emails_sent;
        let mut prev_up_to: u64 = 0;

        for tier in &self.email_tiers {
            if remaining == 0 {
                break;
            }
            let tier_width = tier.up_to.saturating_sub(prev_up_to);
            let applicable = remaining.min(tier_width);
            let applicable_i64 = i64::try_from(applicable).unwrap_or(i64::MAX);
            email_cost_millicents = email_cost_millicents
                .saturating_add(applicable_i64.saturating_mul(tier.price_per_email_millicents));
            remaining -= applicable;
            prev_up_to = tier.up_to;
        }

        let billable_api = api_calls.saturating_sub(self.free_api_calls_per_month);
        let billable_thousands = i64::try_from((billable_api + 999) / 1000).unwrap_or(i64::MAX);
        let api_cost_cents = billable_thousands
            .saturating_mul(self.price_per_thousand_api_calls as i64);

        let email_cost_cents = (email_cost_millicents + 500) / 1000;
        let total = email_cost_cents + api_cost_cents;
        (email_cost_cents, api_cost_cents, total)
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
        assert_eq!(cfg.estonia_vat_rate, 22);
    }

    #[test]
    fn payg_zero_usage() {
        let pricing = PaygPricing::default();
        let (email, api, total) = pricing.calculate(0, 0);
        assert_eq!(email, 0);
        assert_eq!(api, 0);
        assert_eq!(total, 0);
    }

    #[test]
    fn payg_first_tier_only() {
        let pricing = PaygPricing::default();
        let (email, _api, _total) = pricing.calculate(5_000, 0);
// 5 000 * 0.10 = 500.0 cents
        assert_eq!(email, 500);
    }

    #[test]
    fn payg_api_calls_billed_after_free_tier() {
        let pricing = PaygPricing::default();
// 100 000 free + 2 000 billable → ceil(2000/1000)*10 = 20 cents
        let (_email, api, _total) = pricing.calculate(0, 102_000);
        assert_eq!(api, 20);
    }

    #[test]
    fn payg_combined() {
        let pricing = PaygPricing::default();
        let (email, api, total) = pricing.calculate(10_000, 100_000);
// 10k emails at 0.10 = 1000 cents, api free tier → 0
        assert_eq!(email, 1000);
        assert_eq!(api, 0);
        assert_eq!(total, 1000);
    }
}
