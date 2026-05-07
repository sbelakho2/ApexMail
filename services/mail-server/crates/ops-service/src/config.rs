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
    /// Ops API key for authenticating requests (legacy, single key).
    pub ops_api_key: String,
    /// Comma-separated list of valid API keys for rotation support (O-23.5).
    /// When set, any of these keys are accepted in addition to `ops_api_key`.
    pub ops_api_keys: Vec<String>,
    /// Environment name (e.g. development, production).
    pub environment: String,
}

impl Default for OpsConfig {
    fn default() -> Self {
        Self {
            health_check_interval_secs: 30,
            incident_auto_resolve_mins: 120,
            warmup_default_days: 14,
            port: 4400,
            database_url: "postgres://localhost/apexmail".to_string(),
            ops_api_key: String::new(),
            ops_api_keys: Vec::new(),
            environment: "development".to_string(),
        }
    }
}

fn generated_ops_api_key() -> String {
    format!("ops_{}", uuid::Uuid::new_v4().simple())
}

impl OpsConfig {
    /// Load configuration from environment variables, falling back to defaults.
    /// Recognised variables:/// - `OPS_HEALTH_CHECK_INTERVAL_SECS`
    /// - `OPS_INCIDENT_AUTO_RESOLVE_MINS`
    /// - `OPS_WARMUP_DEFAULT_DAYS`
    /// - `OPS_PORT`
    /// - `DATABASE_URL`
    /// - `OPS_API_KEYS` (comma-separated; enables key rotation, O-23.5)
    pub fn from_env() -> Self {
        let default = Self::default();
        let environment = std::env::var("NODE_ENV").unwrap_or_else(|_| default.environment.clone());
        let config = Self {
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
            database_url: std::env::var("DATABASE_URL").unwrap_or(default.database_url),
            ops_api_key: std::env::var("OPS_API_KEY").unwrap_or_else(|_| generated_ops_api_key()),
            // O-23.5: Support key rotation via comma-separated OPS_API_KEYS
            ops_api_keys: std::env::var("OPS_API_KEYS")
                .map(|s| {
                    s.split(',')
                        .map(|k| k.trim().to_string())
                        .filter(|k| !k.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            environment,
        };
        if let Err(err) = config.validate() {
            tracing::warn!("Invalid ops-service config: {err}; falling back to defaults");
            let mut fallback = Self::default();
            fallback.environment = config.environment;
            fallback.ops_api_key = generated_ops_api_key();
            fallback.harden_production();
            return fallback;
        }
        let mut config = config;
        config.harden_production();
        config
    }
}

impl OpsConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.health_check_interval_secs == 0 {
            return Err("OPS_HEALTH_CHECK_INTERVAL_SECS must be > 0".into());
        }
        if self.incident_auto_resolve_mins == 0 {
            return Err("OPS_INCIDENT_AUTO_RESOLVE_MINS must be > 0".into());
        }
        if self.warmup_default_days == 0 {
            return Err("OPS_WARMUP_DEFAULT_DAYS must be > 0".into());
        }
        if self.port == 0 {
            return Err("OPS_PORT must be > 0".into());
        }
        if self.database_url.trim().is_empty() {
            return Err("DATABASE_URL must not be empty".into());
        }
        if self.ops_api_key.trim().is_empty() && self.ops_api_keys.is_empty() {
            return Err("OPS_API_KEY or OPS_API_KEYS must not be empty".into());
        }
        Ok(())
    }

    pub fn harden_production(&mut self) {
        if self.environment == "production" && self.ops_api_key.trim().is_empty() {
            self.ops_api_key = generated_ops_api_key();
            tracing::warn!(
                "SECURITY: OPS_API_KEY missing in production; generated an ephemeral runtime key (redacted)"
            );
        }
    }

    /// Return all valid API keys (legacy single + rotation set).
    pub fn all_api_keys(&self) -> Vec<String> {
        let mut keys = Vec::with_capacity(1 + self.ops_api_keys.len());
        if !self.ops_api_key.is_empty() {
            keys.push(self.ops_api_key.clone());
        }
        keys.extend(self.ops_api_keys.iter().filter(|k| !k.is_empty()).cloned());
        keys
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
        assert!(cfg.ops_api_key.is_empty());
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
        assert_eq!(
            cfg.health_check_interval_secs,
            def.health_check_interval_secs
        );
        assert_eq!(
            cfg.incident_auto_resolve_mins,
            def.incident_auto_resolve_mins
        );
        assert_eq!(cfg.warmup_default_days, def.warmup_default_days);
        assert_eq!(cfg.port, def.port);
        assert!(!cfg.ops_api_key.trim().is_empty());
    }
}
