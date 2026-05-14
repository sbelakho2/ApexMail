//! Configuration for the analytics service.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalyticsConfig {
    pub database_url: String,
    pub redis_url: String,
    pub storage_path: String,
    pub compaction: CompactionConfig,
    pub reconciliation: ReconciliationConfig,
    pub clickhouse: ClickHouseConfig,
    /// HMAC-SHA256 key for salted email hashing in send-time optimizer (O-11.5).
    /// Leave empty to fall back to bare SHA-256.
    pub sto_hmac_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionConfig {
    pub enabled: bool,
    pub schedule_hour: u32,
    pub hot_retention_days: u32,
    pub cold_retention_days: u32,
    pub batch_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationConfig {
    pub enabled: bool,
    pub schedule_hour: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClickHouseConfig {
    pub url: String,
    pub database: String,
    pub user: String,
    pub password: String,
    pub max_connections: u32,
    pub query_timeout_secs: u64,
    /// Timeout in seconds for ClickHouse async insert operations (T-309).
    /// Prevents unbounded waits when ClickHouse is slow or unresponsive.
    /// Default: 30 seconds.
    pub insert_timeout_seconds: u64,
    /// Enable TLS for ClickHouse connection (O-11.2).
    pub tls_enabled: bool,
    /// Path to CA certificate file for ClickHouse TLS verification (O-11.2).
    pub ca_cert_path: String,
}

// ── defaults ───────────────────────────────────────────────────────────────────

impl Default for CompactionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            schedule_hour: 2,
            hot_retention_days: 90,
            cold_retention_days: 730,
            batch_size: 100_000,
        }
    }
}

impl Default for ReconciliationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            schedule_hour: 3,
        }
    }
}

impl Default for ClickHouseConfig {
    fn default() -> Self {
        Self {
            url: "http://clickhouse:8123".into(),
            database: "apexmail".into(),
            user: "default".into(),
            password: "".into(),
            max_connections: 20,
            query_timeout_secs: 30,
            insert_timeout_seconds: 30,
            tls_enabled: false,
            ca_cert_path: String::new(),
        }
    }
}

impl Default for AnalyticsConfig {
    fn default() -> Self {
        Self {
            database_url: String::new(),
            redis_url: "redis://127.0.0.1:6379".into(),
            storage_path: "/var/lib/apexmail/analytics".into(),
            compaction: CompactionConfig::default(),
            reconciliation: ReconciliationConfig::default(),
            clickhouse: ClickHouseConfig::default(),
            sto_hmac_key: String::new(),
        }
    }
}

impl AnalyticsConfig {
    pub fn from_env() -> Self {
        if let Err(error) = dotenvy::dotenv() {
            if !matches!(error, dotenvy::Error::Io(ref io) if io.kind() == std::io::ErrorKind::NotFound)
            {
                tracing::warn!("failed to load .env: {error}");
            }
        }
        let mut config = Self {
            database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
            redis_url: std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".into()),
            storage_path: std::env::var("ANALYTICS_STORAGE_PATH")
                .unwrap_or_else(|_| "/var/lib/apexmail/analytics".into()),
            compaction: CompactionConfig {
                enabled: std::env::var("ANALYTICS_COMPACTION_ENABLED")
                    .map(|v| v != "false" && v != "0")
                    .unwrap_or(true),
                hot_retention_days: std::env::var("ANALYTICS_HOT_RETENTION_DAYS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(90),
                cold_retention_days: std::env::var("ANALYTICS_COLD_RETENTION_DAYS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(730),
                batch_size: std::env::var("ANALYTICS_COMPACTION_BATCH_SIZE")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(100_000),
                ..Default::default()
            },
            reconciliation: ReconciliationConfig::default(),
            clickhouse: ClickHouseConfig {
                url: std::env::var("CLICKHOUSE_URL")
                    .unwrap_or_else(|_| "http://clickhouse:8123".into()),
                database: std::env::var("CLICKHOUSE_DATABASE")
                    .unwrap_or_else(|_| "apexmail".into()),
                user: std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "default".into()),
                password: std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_default(),
                max_connections: std::env::var("CLICKHOUSE_MAX_CONNECTIONS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(20),
                query_timeout_secs: 30,
                insert_timeout_seconds: std::env::var("CLICKHOUSE_INSERT_TIMEOUT_SECONDS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(30),
                tls_enabled: std::env::var("CLICKHOUSE_TLS_ENABLED")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(false),
                ca_cert_path: std::env::var("CLICKHOUSE_CA_CERT_PATH").unwrap_or_default(),
            },
            sto_hmac_key: std::env::var("ANALYTICS_STO_HMAC_KEY").unwrap_or_default(),
        };
        if let Err(err) = config.validate() {
            tracing::error!(error = %err, "Invalid analytics config; applying safe defaults");
            if config.database_url.trim().is_empty() {
                config.database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
                    "postgres://postgres:postgres@localhost:5432/apexmail".into()
                });
            }
            if config.redis_url.trim().is_empty() {
                config.redis_url =
                    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
            }
            if config.storage_path.trim().is_empty() {
                config.storage_path = "/var/lib/apexmail/analytics".into();
            }
            if config.compaction.batch_size == 0 {
                config.compaction.batch_size = 100_000;
            }
            if config.compaction.hot_retention_days == 0 {
                config.compaction.hot_retention_days = 90;
            }
            if config.compaction.cold_retention_days == 0 {
                config.compaction.cold_retention_days = 730;
            }
            if config.compaction.cold_retention_days < config.compaction.hot_retention_days {
                config.compaction.cold_retention_days = config.compaction.hot_retention_days;
            }
        }
        config
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.database_url.trim().is_empty() {
            return Err("DATABASE_URL must not be empty".into());
        }
        if self.redis_url.trim().is_empty() {
            return Err("REDIS_URL must not be empty".into());
        }
        if self.storage_path.trim().is_empty() {
            return Err("ANALYTICS_STORAGE_PATH must not be empty".into());
        }
        if self.compaction.batch_size == 0 {
            return Err("ANALYTICS_COMPACTION_BATCH_SIZE must be > 0".into());
        }
        if self.compaction.hot_retention_days == 0 || self.compaction.cold_retention_days == 0 {
            return Err("Retention days must be > 0".into());
        }
        if self.compaction.cold_retention_days < self.compaction.hot_retention_days {
            return Err("Cold retention days must be >= hot retention days".into());
        }
        if self.compaction.schedule_hour >= 24 || self.reconciliation.schedule_hour >= 24 {
            return Err("Schedule hours must be between 0 and 23".into());
        }
        if self.clickhouse.max_connections == 0 {
            return Err("CLICKHOUSE_MAX_CONNECTIONS must be > 0".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults() {
        let cfg = AnalyticsConfig::default();
        assert_eq!(cfg.compaction.hot_retention_days, 90);
        assert_eq!(cfg.compaction.cold_retention_days, 730);
        assert_eq!(cfg.compaction.batch_size, 100_000);
        assert_eq!(cfg.clickhouse.max_connections, 20);
        assert_eq!(cfg.clickhouse.insert_timeout_seconds, 30);
    }
}
