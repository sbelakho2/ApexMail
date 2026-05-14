//! Configuration for the bounce-analytics crate.

use serde::Deserialize;

/// Configuration for bounce analytics aggregation and pattern detection.
#[derive(Debug, Clone, Deserialize)]
pub struct BounceAnalyticsConfig {
    /// Database URL for the Postgres instance.
    pub database_url: String,

    /// Interval in seconds between aggregation runs.
    #[serde(default = "default_aggregation_interval")]
    pub aggregation_interval_secs: u64,

    /// Number of recent days to include in aggregation windows.
    #[serde(default = "default_aggregation_window_days")]
    pub aggregation_window_days: i64,

    /// Threshold for burst detection: number of bounces per minute from same domain
    /// to trigger a burst alert.
    #[serde(default = "default_burst_threshold")]
    pub burst_threshold_per_minute: u32,

    /// Minimum bounce rate (as fraction) for a domain to be flagged as problematic.
    #[serde(default = "default_problematic_bounce_rate")]
    pub problematic_bounce_rate: f64,

    /// Minimum total sends for domain-level bounce rate to be considered reliable.
    #[serde(default = "default_min_sends_for_domain")]
    pub min_sends_for_domain: i64,

    /// Retention days for raw bounce event data used in analytics.
    #[serde(default = "default_retention_days")]
    pub retention_days: i64,

    /// Batch size for paginated queries.
    #[serde(default = "default_batch_size")]
    pub batch_size: i64,
}

fn default_aggregation_interval() -> u64 {
    300
}
fn default_aggregation_window_days() -> i64 {
    30
}
fn default_burst_threshold() -> u32 {
    10
}
fn default_problematic_bounce_rate() -> f64 {
    0.15
}
fn default_min_sends_for_domain() -> i64 {
    100
}
fn default_retention_days() -> i64 {
    90
}
fn default_batch_size() -> i64 {
    1000
}

impl Default for BounceAnalyticsConfig {
    fn default() -> Self {
        Self {
            database_url: String::new(),
            aggregation_interval_secs: default_aggregation_interval(),
            aggregation_window_days: default_aggregation_window_days(),
            burst_threshold_per_minute: default_burst_threshold(),
            problematic_bounce_rate: default_problematic_bounce_rate(),
            min_sends_for_domain: default_min_sends_for_domain(),
            retention_days: default_retention_days(),
            batch_size: default_batch_size(),
        }
    }
}

impl BounceAnalyticsConfig {
    /// Load configuration from environment variables.
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            database_url: std::env::var("DATABASE_URL")
                .map_err(|_| anyhow::anyhow!("DATABASE_URL must be set"))?,
            aggregation_interval_secs: std::env::var("BOUNCE_AGGREGATION_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(default_aggregation_interval),
            aggregation_window_days: std::env::var("BOUNCE_AGGREGATION_WINDOW_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(default_aggregation_window_days),
            burst_threshold_per_minute: std::env::var("BOUNCE_BURST_THRESHOLD_PER_MINUTE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(default_burst_threshold),
            problematic_bounce_rate: std::env::var("BOUNCE_PROBLEMATIC_RATE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(default_problematic_bounce_rate),
            min_sends_for_domain: std::env::var("BOUNCE_MIN_SENDS_FOR_DOMAIN")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(default_min_sends_for_domain),
            retention_days: std::env::var("BOUNCE_RETENTION_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(default_retention_days),
            batch_size: std::env::var("BOUNCE_BATCH_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(default_batch_size),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = BounceAnalyticsConfig::default();
        assert_eq!(config.aggregation_interval_secs, 300);
        assert_eq!(config.aggregation_window_days, 30);
        assert_eq!(config.burst_threshold_per_minute, 10);
        assert!((config.problematic_bounce_rate - 0.15).abs() < f64::EPSILON);
    }

    #[test]
    fn test_config_from_env() {
        std::env::set_var("DATABASE_URL", "postgres://localhost/test");
        std::env::set_var("BOUNCE_AGGREGATION_INTERVAL_SECS", "600");
        let config = BounceAnalyticsConfig::from_env().unwrap();
        assert_eq!(config.database_url, "postgres://localhost/test");
        assert_eq!(config.aggregation_interval_secs, 600);
        std::env::remove_var("DATABASE_URL");
        std::env::remove_var("BOUNCE_AGGREGATION_INTERVAL_SECS");
    }
}
