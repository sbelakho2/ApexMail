//! Observability service configuration.
//!
//! Mirrors the TypeScript `config.ts` – server, database, Redis, tracing,
//! metrics, logging, and alerting settings sourced from environment variables.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Sub-configs
// ---------------------------------------------------------------------------

/// Tracing configuration (Jaeger / Zipkin / OTLP endpoints, sample rate).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    pub enabled: bool,
    pub service_name: String,
    pub service_version: String,
    pub environment: String,
    pub sample_rate: f64,
    pub jaeger_endpoint: String,
    pub zipkin_endpoint: String,
    pub otlp_endpoint: String,
}

/// Prometheus metrics collection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub prometheus_port: u16,
    pub default_labels: Vec<(String, String)>,
    pub histogram_buckets: Vec<f64>,
    pub aggregation_interval_ms: u64,
}

/// Structured logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
    pub include_timestamp: bool,
    pub include_trace_id: bool,
    pub sensitive_fields: Vec<String>,
    pub max_message_length: usize,
}

/// Alert dispatch configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    pub enabled: bool,
    pub webhook_urls: Vec<String>,
    pub slack_webhook: String,
    pub pagerduty_key: String,
    pub opsgenie_key: String,
    pub email_recipients: Vec<String>,
    pub cooldown_minutes: u64,
}

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

/// Root configuration for the observability service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
/// HTTP listen port.
    pub port: u16,
/// Runtime environment (`development`, `staging`, `production`).
    pub environment: String,
/// Application version tag.
    pub version: String,

// Database
    pub db_host: String,
    pub db_port: u16,
    pub database: String,
    pub db_user: String,
    pub db_password: String,
    pub db_pool_max: u32,

// Redis
    pub redis_host: String,
    pub redis_port: u16,
    pub redis_password: Option<String>,

// Sub-configs
    pub tracing: TracingConfig,
    pub metrics: MetricsConfig,
    pub logging: LoggingConfig,
    pub alerting: AlertConfig,

/// Log retention in days.
    pub log_retention_days: u32,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            port: 4400,
            environment: "development".into(),
            version: "1.0.0".into(),

            db_host: "localhost".into(),
            db_port: 5432,
            database: "apexmail".into(),
            db_user: "apexmail".into(),
            db_password: "change-me".into(),
            db_pool_max: 20,

            redis_host: "localhost".into(),
            redis_port: 6379,
            redis_password: None,

            tracing: TracingConfig {
                enabled: true,
                service_name: "apexmail".into(),
                service_version: "1.0.0".into(),
                environment: "development".into(),
                sample_rate: 1.0,
                jaeger_endpoint: "http://localhost:14268/api/traces".into(),
                zipkin_endpoint: "http://localhost:9411/api/v2/spans".into(),
                otlp_endpoint: "http://localhost:4318".into(),
            },

            metrics: MetricsConfig {
                enabled: true,
                prometheus_port: 9090,
                default_labels: vec![
                    ("service".into(), "apexmail".into()),
                    ("environment".into(), "development".into()),
                ],
                histogram_buckets: vec![
                    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
                ],
                aggregation_interval_ms: 15_000,
            },

            logging: LoggingConfig {
                level: "info".into(),
                format: "json".into(),
                include_timestamp: true,
                include_trace_id: true,
                sensitive_fields: vec![
                    "password".into(),
                    "token".into(),
                    "apiKey".into(),
                    "secret".into(),
                    "authorization".into(),
                    "creditCard".into(),
                    "ssn".into(),
                ],
                max_message_length: 10_000,
            },

            alerting: AlertConfig {
                enabled: false,
                webhook_urls: Vec::new(),
                slack_webhook: "disabled".into(),
                pagerduty_key: "disabled".into(),
                opsgenie_key: "disabled".into(),
                email_recipients: Vec::new(),
                cooldown_minutes: 15,
            },

            log_retention_days: 30,
        }
    }
}

impl ObservabilityConfig {
/// Build a config from environment variables (falls back to defaults).
    pub fn from_env() -> Result<Self, String> {
        fn env_or(key: &str, default: &str) -> String {
            std::env::var(key).unwrap_or_else(|_| default.to_string())
        }

        let default = Self::default();

        let config = Self {
            port: env_or("OBSERVABILITY_PORT", &default.port.to_string())
                .parse()
                .unwrap_or(default.port),
            environment: env_or("NODE_ENV", &default.environment),
            version: env_or("APP_VERSION", &default.version),

            db_host: env_or("DB_HOST", &default.db_host),
            db_port: env_or("DB_PORT", &default.db_port.to_string())
                .parse()
                .unwrap_or(default.db_port),
            database: env_or("DB_NAME", &default.database),
            db_user: env_or("DB_USER", &default.db_user),
            db_password: env_or("DB_PASSWORD", ""),
            db_pool_max: env_or("DB_POOL_MAX", &default.db_pool_max.to_string())
                .parse()
                .unwrap_or(default.db_pool_max),

            redis_host: env_or("REDIS_HOST", &default.redis_host),
            redis_port: env_or("REDIS_PORT", &default.redis_port.to_string())
                .parse()
                .unwrap_or(default.redis_port),
            redis_password: std::env::var("REDIS_PASSWORD").ok(),

            tracing: TracingConfig {
                enabled: env_or("TRACING_ENABLED", "true") != "false",
                service_name: env_or("SERVICE_NAME", &default.tracing.service_name),
                service_version: env_or("SERVICE_VERSION", &default.tracing.service_version),
                environment: env_or("NODE_ENV", &default.tracing.environment),
                sample_rate: env_or("TRACE_SAMPLE_RATE", "1.0")
                    .parse()
                    .unwrap_or(1.0),
                jaeger_endpoint: env_or("JAEGER_ENDPOINT", &default.tracing.jaeger_endpoint),
                zipkin_endpoint: env_or("ZIPKIN_ENDPOINT", &default.tracing.zipkin_endpoint),
                otlp_endpoint: env_or("OTLP_ENDPOINT", &default.tracing.otlp_endpoint),
            },

            metrics: MetricsConfig {
                enabled: env_or("METRICS_ENABLED", "true") != "false",
                prometheus_port: env_or("PROMETHEUS_PORT", &default.metrics.prometheus_port.to_string())
                    .parse()
                    .unwrap_or(default.metrics.prometheus_port),
                default_labels: default.metrics.default_labels.clone(),
                histogram_buckets: default.metrics.histogram_buckets.clone(),
                aggregation_interval_ms: env_or(
                    "METRICS_INTERVAL",
                    &default.metrics.aggregation_interval_ms.to_string(),
                )
                .parse()
                .unwrap_or(default.metrics.aggregation_interval_ms),
            },

            logging: LoggingConfig {
                level: env_or("LOG_LEVEL", &default.logging.level),
                format: env_or("LOG_FORMAT", &default.logging.format),
                include_timestamp: true,
                include_trace_id: true,
                sensitive_fields: default.logging.sensitive_fields.clone(),
                max_message_length: env_or("LOG_MAX_LENGTH", &default.logging.max_message_length.to_string())
                    .parse()
                    .unwrap_or(default.logging.max_message_length),
            },

            alerting: AlertConfig {
                enabled: env_or("ALERTING_ENABLED", "false") == "true",
                webhook_urls: env_or("ALERT_WEBHOOKS", "")
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect(),
                slack_webhook: env_or("SLACK_WEBHOOK", ""),
                pagerduty_key: env_or("PAGERDUTY_KEY", ""),
                opsgenie_key: env_or("OPSGENIE_KEY", ""),
                email_recipients: env_or("ALERT_EMAILS", "")
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect(),
                cooldown_minutes: env_or("ALERT_COOLDOWN", "15")
                    .parse()
                    .unwrap_or(15),
            },

            log_retention_days: env_or("LOG_RETENTION_DAYS", "30")
                .parse()
                .unwrap_or(30),
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.port == 0 {
            return Err("OBSERVABILITY_PORT must be > 0".into());
        }
        if self.db_port == 0 {
            return Err("DB_PORT must be > 0".into());
        }
        if self.db_pool_max == 0 {
            return Err("DB_POOL_MAX must be > 0".into());
        }
        if self.redis_port == 0 {
            return Err("REDIS_PORT must be > 0".into());
        }
        if self.metrics.prometheus_port == 0 {
            return Err("PROMETHEUS_PORT must be > 0".into());
        }
        if self.metrics.aggregation_interval_ms == 0 {
            return Err("METRICS_INTERVAL must be > 0".into());
        }
        if !(0.0..=1.0).contains(&self.tracing.sample_rate) {
            return Err("TRACE_SAMPLE_RATE must be between 0.0 and 1.0".into());
        }
        if self.logging.max_message_length == 0 {
            return Err("LOG_MAX_LENGTH must be > 0".into());
        }
        if self.alerting.cooldown_minutes == 0 {
            return Err("ALERT_COOLDOWN must be > 0".into());
        }
        if self.log_retention_days == 0 {
            return Err("LOG_RETENTION_DAYS must be > 0".into());
        }
        Ok(())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_values() {
        let cfg = ObservabilityConfig::default();
        assert_eq!(cfg.port, 4400);
        assert_eq!(cfg.environment, "development");
        assert!(cfg.tracing.enabled);
        assert!(!cfg.alerting.enabled);
        assert_eq!(cfg.metrics.histogram_buckets.len(), 11);
        assert_eq!(cfg.log_retention_days, 30);
        assert_eq!(cfg.db_pool_max, 20);
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let cfg = ObservabilityConfig::default();
        let json = serde_json::to_string(&cfg);
        assert!(json.is_ok());
        let deserialized: Option<ObservabilityConfig> =
            json.ok().and_then(|value| serde_json::from_str(&value).ok());
        assert_eq!(deserialized.as_ref().map(|value| value.port), Some(cfg.port));
        assert_eq!(
            deserialized
                .as_ref()
                .map(|value| value.tracing.sample_rate),
            Some(cfg.tracing.sample_rate)
        );
        assert_eq!(
            deserialized
                .as_ref()
                .map(|value| value.logging.sensitive_fields.clone()),
            Some(cfg.logging.sensitive_fields.clone())
        );
    }
}
