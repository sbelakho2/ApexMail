//! Operations service configuration loaded from environment variables.

use serde::{Deserialize, Serialize};

/// Top-level configuration for the ops service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsConfig {
    /// Interval in seconds between automatic health checks.
    pub health_check_interval_secs: u64,
    /// Minutes after which an incident is auto-resolved if no updates.
    pub incident_auto_resolve_mins: u64,
    /// Default number of days for an IP warmup schedule.
    pub warmup_default_days: u32,
    /// TCP port the HTTP server listens on.
    pub port: u16,
    /// PostgreSQL connection URL.
    pub database_url: String,
}

impl Default for OpsConfig {
    fn default() -> Self {
        Self {
            health_check_interval_secs: 30,
            incident_auto_resolve_mins: 120,
            warmup_default_days: 14,
            port: 4400,
            database_url: "postgres://localhost/apexmail".to_string(),
        }
    }
}

impl OpsConfig {
    /// Load configuration from environment variables, falling back to defaults.
    ///
    /// Recognised variables:
    /// - `OPS_HEALTH_CHECK_INTERVAL_SECS`
    /// - `OPS_INCIDENT_AUTO_RESOLVE_MINS`
    /// - `OPS_WARMUP_DEFAULT_DAYS`
    /// - `OPS_PORT`
    /// - `DATABASE_URL`
    pub fn from_env() -> Self {
        let default = Self::default();
        Self {
            health_check_interval_secs: std::env::var("OPS_HEALTH_CHECK_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default.health_check_interval_secs),
            incident_auto_resolve_mins: std::env::var("OPS_INCIDENT_AUTO_RESOLVE_MINS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default.incident_auto_resolve_mins),
            warmup_default_days: std::env::var("OPS_WARMUP_DEFAULT_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default.warmup_default_days),
            port: std::env::var("OPS_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default.port),
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or(default.database_url),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = OpsConfig::default();
        assert_eq!(cfg.health_check_interval_secs, 30);
        assert_eq!(cfg.incident_auto_resolve_mins, 120);
        assert_eq!(cfg.warmup_default_days, 14);
        assert_eq!(cfg.port, 4400);
    }

    #[test]
    fn test_from_env_uses_defaults_when_unset() {
        // Clear any previously set vars (best-effort; tests are run in process)
        std::env::remove_var("OPS_HEALTH_CHECK_INTERVAL_SECS");
        std::env::remove_var("OPS_INCIDENT_AUTO_RESOLVE_MINS");
        std::env::remove_var("OPS_WARMUP_DEFAULT_DAYS");
        std::env::remove_var("OPS_PORT");

        let cfg = OpsConfig::from_env();
        let def = OpsConfig::default();
        assert_eq!(cfg.health_check_interval_secs, def.health_check_interval_secs);
        assert_eq!(cfg.incident_auto_resolve_mins, def.incident_auto_resolve_mins);
        assert_eq!(cfg.warmup_default_days, def.warmup_default_days);
        assert_eq!(cfg.port, def.port);
    }
}
