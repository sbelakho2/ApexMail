//! Observability service configuration.
//!
//! Server, database, Redis, tracing, metrics, logging, and alerting settings
//! sourced from environment variables.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Sub-configs
// ---------------------------------------------------------------------------

/// Tracing configuration (Jaeger / Zipkin / OTLP endpoints, sample rate).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub prometheus_port: u16,
    pub default_labels: Vec<(String, String)>,
    pub histogram_buckets: Vec<f64>,
    pub aggregation_interval_ms: u64,
}

/// Structured logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct AlertConfig {
    pub enabled: bool,
    pub webhook_urls: Vec<String>,
    pub slack_webhook: String,
    pub pagerduty_key: String,
    pub opsgenie_key: String,
    pub email_recipients: Vec<String>,
    pub cooldown_minutes: u64,
}

/// Persistence configuration for metrics and log data.
///
/// Controls whether in-memory metrics and logs are periodically flushed to
/// the database to survive process restarts. When `enabled`, the background
/// flush task runs every `flush_interval_ms` milliseconds and retains data
/// for `retention_days` days.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistenceConfig {
    /// Whether periodic persistence to the database is enabled.
    pub enabled: bool,
    /// Interval (ms) between flush cycles for metrics and log data.
    pub flush_interval_ms: u64,
    /// Number of days to retain persisted metric and log records.
    pub retention_days: u32,
}

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

/// Root configuration for the observability service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfig {
    /// HTTP listen port.
    pub port: u16,
    /// Runtime environment (`development`, `staging`, `production`).
    pub environment: String,
    /// Application version tag.
    pub version: String,
    /// Shared bearer token required for protected internal routes.
    pub internal_service_token: String,

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
    pub redis_db: i64,
    pub redis_password: Option<String>,

    // Sub-configs
    pub tracing: TracingConfig,
    pub metrics: MetricsConfig,
    pub logging: LoggingConfig,
    pub alerting: AlertConfig,
    pub persistence: PersistenceConfig,

    /// Log retention in days.
    pub log_retention_days: u32,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            port: 4400,
            environment: "development".into(),
            version: "1.0.0".into(),
            internal_service_token: String::new(),

            db_host: "127.0.0.1".into(),
            db_port: 5432,
            database: "apexmail".into(),
            db_user: "apexmail".into(),
            db_password: String::new(),
            db_pool_max: 20,

            redis_host: "127.0.0.1".into(),
            redis_port: 6379,
            redis_db: 0,
            redis_password: None,

            tracing: TracingConfig {
                enabled: true,
                service_name: "apexmail".into(),
                service_version: "1.0.0".into(),
                environment: "development".into(),
                sample_rate: 1.0,
                jaeger_endpoint: "http://jaeger:14268/api/traces".into(),
                zipkin_endpoint: "http://zipkin:9411/api/v2/spans".into(),
                otlp_endpoint: "http://otel-collector:4318".into(),
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

            persistence: PersistenceConfig {
                enabled: false,
                flush_interval_ms: 60_000,
                retention_days: 30,
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

        /// Read a secret: when the `<KEY>_FILE` variable (Docker secret
        /// convention) points at a readable file, the FILE WINS over the
        /// plain `<KEY>` variable. The prod compose overlay mounts the real
        /// secret via `_FILE` while the base environment still carries the
        /// public default value of `<KEY>` — an env-first policy would
        /// authenticate production with that public constant. Falls back to
        /// `<KEY>` (non-compose runs) and then to `default`.
        fn env_or_file(key: &str, default: &str) -> String {
            if let Ok(path) = std::env::var(format!("{key}_FILE")) {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    return content.trim().to_string();
                }
                tracing::warn!(
                    key,
                    path = %path,
                    "Secret file configured but unreadable — falling back to the environment variable"
                );
            }
            if let Ok(value) = std::env::var(key) {
                return value;
            }
            default.to_string()
        }

        let default = Self::default();

        let config = Self {
            port: env_or("OBSERVABILITY_PORT", &default.port.to_string())
                .parse()
                .unwrap_or(default.port),
            environment: env_or("NODE_ENV", &default.environment),
            version: env_or("APP_VERSION", &default.version),
            internal_service_token: env_or_file(
                "INTERNAL_SERVICE_TOKEN",
                &default.internal_service_token,
            ),

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
            redis_db: env_or("REDIS_DB", &default.redis_db.to_string())
                .parse()
                .unwrap_or(default.redis_db),
            redis_password: {
                let value = env_or_file("REDIS_PASSWORD", "");
                if value.is_empty() {
                    None
                } else {
                    Some(value)
                }
            },

            tracing: TracingConfig {
                enabled: env_or("TRACING_ENABLED", "true") != "false",
                service_name: env_or("SERVICE_NAME", &default.tracing.service_name),
                service_version: env_or("SERVICE_VERSION", &default.tracing.service_version),
                environment: env_or("NODE_ENV", &default.tracing.environment),
                sample_rate: env_or("TRACE_SAMPLE_RATE", "1.0").parse().unwrap_or(1.0),
                jaeger_endpoint: env_or("JAEGER_ENDPOINT", &default.tracing.jaeger_endpoint),
                zipkin_endpoint: env_or("ZIPKIN_ENDPOINT", &default.tracing.zipkin_endpoint),
                otlp_endpoint: env_or("OTLP_ENDPOINT", &default.tracing.otlp_endpoint),
            },

            metrics: MetricsConfig {
                enabled: env_or("METRICS_ENABLED", "true") != "false",
                prometheus_port: env_or(
                    "PROMETHEUS_PORT",
                    &default.metrics.prometheus_port.to_string(),
                )
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
                max_message_length: env_or(
                    "LOG_MAX_LENGTH",
                    &default.logging.max_message_length.to_string(),
                )
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
                cooldown_minutes: env_or("ALERT_COOLDOWN", "15").parse().unwrap_or(15),
            },

            persistence: PersistenceConfig {
                enabled: std::env::var("PERSISTENCE_ENABLED").as_deref() == Ok("true"),
                flush_interval_ms: env_or(
                    "PERSISTENCE_FLUSH_INTERVAL_MS",
                    &default.persistence.flush_interval_ms.to_string(),
                )
                .parse()
                .unwrap_or(default.persistence.flush_interval_ms),
                retention_days: env_or(
                    "PERSISTENCE_RETENTION_DAYS",
                    &default.persistence.retention_days.to_string(),
                )
                .parse()
                .unwrap_or(default.persistence.retention_days),
            },

            log_retention_days: env_or("LOG_RETENTION_DAYS", "30").parse().unwrap_or(30),
        };
        config.validate()?;
        Ok(config)
    }

    /// Build a Redis connection URL from the config.
    ///
    /// The password is percent-encoded per RFC 3986 (via `urlencoding`, which
    /// encodes every non-unreserved byte including `%`, `@`, `:`, `/`, `+`
    /// and space) so that special characters in the password cannot corrupt
    /// the URL. The redis crate percent-decodes the password component
    /// before authenticating, so the encoding round-trips exactly.
    pub fn redis_url(&self) -> String {
        match &self.redis_password {
            Some(pw) => format!(
                "redis://:{}@{}:{}/{}",
                urlencoding::encode(pw),
                self.redis_host,
                self.redis_port,
                self.redis_db
            ),
            None => format!(
                "redis://{}:{}/{}",
                self.redis_host, self.redis_port, self.redis_db
            ),
        }
    }

    /// Build a Postgres connection URL (credentials percent-encoded the same
    /// way as [`Self::redis_url`]) for the `system_alerts` persistence pool
    /// attached in bin/server.rs.
    pub fn db_url(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            urlencoding::encode(&self.db_user),
            urlencoding::encode(&self.db_password),
            self.db_host,
            self.db_port,
            self.database
        )
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.port == 0 {
            return Err("OBSERVABILITY_PORT must be > 0".into());
        }
        if self.internal_service_token.trim().is_empty() {
            return Err("INTERNAL_SERVICE_TOKEN must be set".into());
        }
        // F-07: Reject "off" log level — override to "warn" as minimum floor
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.logging.level.as_str()) {
            return Err(format!(
                "LOG_LEVEL '{}' is not valid; must be one of: {}",
                self.logging.level,
                valid_levels.join(", ")
            ));
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
        if self.redis_db < 0 {
            return Err("REDIS_DB must be >= 0".into());
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
        if self.persistence.enabled && self.persistence.flush_interval_ms == 0 {
            return Err(
                "PERSISTENCE_FLUSH_INTERVAL_MS must be > 0 when persistence is enabled".into(),
            );
        }
        if self.persistence.enabled && self.persistence.retention_days == 0 {
            return Err(
                "PERSISTENCE_RETENTION_DAYS must be > 0 when persistence is enabled".into(),
            );
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
    use std::sync::{Mutex, OnceLock};

    /// Serializes tests that mutate process environment variables (cargo
    /// test runs them in parallel inside one process).
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock poisoned")
    }

    #[test]
    fn test_default_config_values() {
        let cfg = ObservabilityConfig::default();
        assert_eq!(cfg.port, 4400);
        assert_eq!(cfg.environment, "development");
        assert!(cfg.internal_service_token.is_empty());
        assert!(cfg.tracing.enabled);
        assert!(!cfg.alerting.enabled);
        assert_eq!(cfg.metrics.histogram_buckets.len(), 11);
        assert_eq!(cfg.log_retention_days, 30);
        assert_eq!(cfg.db_pool_max, 20);
        assert!(!cfg.persistence.enabled);
        assert_eq!(cfg.persistence.flush_interval_ms, 60_000);
        assert_eq!(cfg.persistence.retention_days, 30);
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let cfg = ObservabilityConfig::default();
        let json = serde_json::to_string(&cfg);
        assert!(json.is_ok());
        let deserialized: Option<ObservabilityConfig> = json
            .ok()
            .and_then(|value| serde_json::from_str(&value).ok());
        assert_eq!(
            deserialized.as_ref().map(|value| value.port),
            Some(cfg.port)
        );
        assert_eq!(
            deserialized.as_ref().map(|value| value.tracing.sample_rate),
            Some(cfg.tracing.sample_rate)
        );
        assert_eq!(
            deserialized
                .as_ref()
                .map(|value| value.logging.sensitive_fields.clone()),
            Some(cfg.logging.sensitive_fields.clone())
        );
    }

    #[test]
    fn test_validate_requires_internal_service_token() {
        let cfg = ObservabilityConfig {
            internal_service_token: "   ".into(),
            ..Default::default()
        };

        let err = cfg.validate().unwrap_err();

        assert_eq!(err, "INTERNAL_SERVICE_TOKEN must be set");
    }

    #[test]
    fn test_redis_url_no_password() {
        let cfg = ObservabilityConfig::default();
        assert_eq!(cfg.redis_url(), "redis://127.0.0.1:6379/0");
    }

    #[test]
    fn test_redis_url_with_password_encoded() {
        let cfg = ObservabilityConfig {
            redis_password: Some("p@ss:w/ord+%".into()),
            redis_db: 2,
            ..Default::default()
        };
        assert_eq!(
            cfg.redis_url(),
            "redis://:p%40ss%3Aw%2Ford%2B%25@127.0.0.1:6379/2"
        );
    }

    #[test]
    fn test_validate_rejects_negative_redis_db() {
        let cfg = ObservabilityConfig {
            redis_db: -1,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_internal_service_token_reads_file_fallback() {
        let _guard = env_guard();

        std::env::remove_var("INTERNAL_SERVICE_TOKEN");
        let dir = std::env::temp_dir().join(format!("obs-token-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token.txt");
        std::fs::write(&path, "file-secret-token\n").unwrap();
        std::env::set_var("INTERNAL_SERVICE_TOKEN_FILE", &path);

        let cfg = ObservabilityConfig::from_env().unwrap();
        assert_eq!(cfg.internal_service_token, "file-secret-token");

        std::env::remove_var("INTERNAL_SERVICE_TOKEN_FILE");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// File-wins precedence: the prod compose overlay mounts the real secret
    /// via `_FILE` while the base environment still carries the public
    /// default of the plain variable — env-first authenticated production
    /// with a public constant.
    #[test]
    fn test_secret_file_takes_precedence_over_env_variable() {
        let _guard = env_guard();

        let dir = std::env::temp_dir().join(format!("obs-token-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token.txt");
        std::fs::write(&path, "file-secret-wins\n").unwrap();
        std::env::set_var(
            "INTERNAL_SERVICE_TOKEN",
            "dev-internal-service-token-change-me",
        );
        std::env::set_var("INTERNAL_SERVICE_TOKEN_FILE", &path);

        let cfg = ObservabilityConfig::from_env().unwrap();
        assert_eq!(
            cfg.internal_service_token, "file-secret-wins",
            "a readable secret file must override the env variable"
        );

        // Unreadable file → warn + fall back to the env variable (keeps
        // non-compose deployments working when the mount is missing).
        std::env::set_var("INTERNAL_SERVICE_TOKEN_FILE", dir.join("missing.txt"));
        let cfg = ObservabilityConfig::from_env().unwrap();
        assert_eq!(
            cfg.internal_service_token,
            "dev-internal-service-token-change-me"
        );

        // No file configured at all → plain env variable, then cleanup.
        std::env::remove_var("INTERNAL_SERVICE_TOKEN_FILE");
        let cfg = ObservabilityConfig::from_env().unwrap();
        assert_eq!(
            cfg.internal_service_token,
            "dev-internal-service-token-change-me"
        );

        std::env::remove_var("INTERNAL_SERVICE_TOKEN");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
