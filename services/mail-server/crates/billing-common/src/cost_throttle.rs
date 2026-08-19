//! Cross-service contract for temporary, cost-protection rate-limit caps.
//!
//! Billing writes an override only after a tenant reaches a critical cost
//! margin. The API applies it to that tenant's normal plan-derived limit. A
//! malformed override, or one that would raise a limit, is ignored.

use serde::{Deserialize, Serialize};

pub const COST_THROTTLE_KEY_PREFIX: &str = "apexmail:ratelimit:cost_throttle:";
pub const COST_THROTTLE_TTL_SECS: u64 = 24 * 60 * 60;
pub const COST_THROTTLE_VERSION: u8 = 1;
pub const CRITICAL_MARGIN_CAP_PERCENT: u8 = 50;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostThrottleOverride {
    pub version: u8,
    /// Percentage of the tenant's ordinary, plan-derived rate limit that may
    /// remain available while the override is active.
    pub cap_percent: u8,
    pub reason: CostThrottleReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostThrottleReason {
    LowMargin,
}

impl CostThrottleOverride {
    pub fn critical_low_margin() -> Self {
        Self {
            version: COST_THROTTLE_VERSION,
            cap_percent: CRITICAL_MARGIN_CAP_PERCENT,
            reason: CostThrottleReason::LowMargin,
        }
    }

    /// Return a positive cap strictly below `baseline`, or `None` when the
    /// payload is unsupported, malformed, or would increase/retain the limit.
    pub fn capped_limit(&self, baseline: u64) -> Option<u64> {
        if self.version != COST_THROTTLE_VERSION
            || self.cap_percent == 0
            || self.cap_percent >= 100
            || baseline <= 1
        {
            return None;
        }

        // Compute `baseline * cap_percent / 100` without overflowing a u64.
        let cap_percent = u64::from(self.cap_percent);
        let capped = (baseline / 100)
            .saturating_mul(cap_percent)
            .saturating_add((baseline % 100).saturating_mul(cap_percent) / 100);

        (capped > 0 && capped < baseline).then_some(capped)
    }
}

pub fn cost_throttle_key(tenant_id: &str) -> String {
    format!("{COST_THROTTLE_KEY_PREFIX}{tenant_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_margin_cap_halves_plan_derived_limit() {
        assert_eq!(
            CostThrottleOverride::critical_low_margin().capped_limit(6_000),
            Some(3_000)
        );
    }

    #[test]
    fn overrides_never_disable_or_expand_a_limit() {
        let mut override_ = CostThrottleOverride::critical_low_margin();
        assert_eq!(override_.capped_limit(1), None);

        override_.cap_percent = 0;
        assert_eq!(override_.capped_limit(600), None);
        override_.cap_percent = 100;
        assert_eq!(override_.capped_limit(600), None);
        override_.cap_percent = 101;
        assert_eq!(override_.capped_limit(600), None);
        override_.cap_percent = 50;
        override_.version = COST_THROTTLE_VERSION + 1;
        assert_eq!(override_.capped_limit(600), None);
    }

    #[test]
    fn cost_throttle_keys_are_tenant_scoped() {
        assert_eq!(
            cost_throttle_key("ten_123"),
            "apexmail:ratelimit:cost_throttle:ten_123"
        );
    }
}