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
    pub overage_rate_per_email_cents: f64,
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
fn default_overage_rate_cents() -> f64 {
    0.04
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
            overage_rate_per_email_cents: default_overage_rate_cents(),
        }
    }
}

/// Pay-as-you-go email pricing tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaygEmailTier {
    /// Upper bound (exclusive) of emails in this tier.
    pub up_to: u64,
    /// Price per email in **cents**.
    pub price_per_email: f64,
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
                PaygEmailTier { up_to: 10_000, price_per_email: 0.10 },
                PaygEmailTier { up_to: 100_000, price_per_email: 0.08 },
                PaygEmailTier { up_to: 1_000_000, price_per_email: 0.05 },
                PaygEmailTier { up_to: u64::MAX, price_per_email: 0.03 },
            ],
            free_api_calls_per_month: 100_000,
            price_per_thousand_api_calls: 10,
        }
    }
}

impl PaygPricing {
    /// Calculate PAYG cost for a given email + API-call volume.
    /// Returns `(email_cost, api_cost, total)` all in cents.
    pub fn calculate(&self, emails_sent: u64, api_calls: u64) -> (f64, f64, f64) {
        let mut email_cost: f64 = 0.0;
        let mut remaining = emails_sent;
        let mut prev_up_to: u64 = 0;

        for tier in &self.email_tiers {
            if remaining == 0 {
                break;
            }
            let tier_width = tier.up_to.saturating_sub(prev_up_to);
            let applicable = remaining.min(tier_width);
            email_cost += applicable as f64 * tier.price_per_email;
            remaining -= applicable;
            prev_up_to = tier.up_to;
        }

        let billable_api = api_calls.saturating_sub(self.free_api_calls_per_month);
        let api_cost = ((billable_api + 999) / 1000) as f64
            * self.price_per_thousand_api_calls as f64;

        let total = email_cost + api_cost;
        (
            (email_cost * 100.0).round() / 100.0,
            (api_cost * 100.0).round() / 100.0,
            (total * 100.0).round() / 100.0,
        )
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
        assert_eq!(email, 0.0);
        assert_eq!(api, 0.0);
        assert_eq!(total, 0.0);
    }

    #[test]
    fn payg_first_tier_only() {
        let pricing = PaygPricing::default();
        let (email, _api, _total) = pricing.calculate(5_000, 0);
        // 5 000 * 0.10 = 500.0 cents
        assert!((email - 500.0).abs() < 0.01);
    }

    #[test]
    fn payg_api_calls_billed_after_free_tier() {
        let pricing = PaygPricing::default();
        // 100 000 free + 2 000 billable → ceil(2000/1000)*10 = 20 cents
        let (_email, api, _total) = pricing.calculate(0, 102_000);
        assert!((api - 20.0).abs() < 0.01);
    }

    #[test]
    fn payg_combined() {
        let pricing = PaygPricing::default();
        let (email, api, total) = pricing.calculate(10_000, 100_000);
        // 10k emails at 0.10 = 1000 cents, api free tier → 0
        assert!((email - 1000.0).abs() < 0.01);
        assert_eq!(api, 0.0);
        assert!((total - 1000.0).abs() < 0.01);
    }
}
