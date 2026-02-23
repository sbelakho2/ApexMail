//! Configuration for the analytics service.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsConfig {
    pub database_url: String,
    pub redis_url: String,
    pub storage_path: String,
    pub compaction: CompactionConfig,
    pub reconciliation: ReconciliationConfig,
    pub clickhouse: ClickHouseConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactionConfig {
    pub enabled: bool,
    pub schedule_hour: u32,
    pub hot_retention_days: u32,
    pub cold_retention_days: u32,
    pub batch_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationConfig {
    pub enabled: bool,
    pub schedule_hour: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClickHouseConfig {
    pub url: String,
    pub database: String,
    pub user: String,
    pub password: String,
    pub max_connections: u32,
    pub query_timeout_secs: u64,
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
            url: "http://localhost:8123".into(),
            database: "apexmail".into(),
            user: "default".into(),
            password: "".into(),
            max_connections: 20,
            query_timeout_secs: 30,
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
        }
    }
}

impl AnalyticsConfig {
    pub fn from_env() -> Self {
        let _ = dotenvy::dotenv();
        Self {
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
                user: std::env::var("CLICKHOUSE_USER")
                    .unwrap_or_else(|_| "default".into()),
                password: std::env::var("CLICKHOUSE_PASSWORD")
                    .unwrap_or_default(),
                max_connections: std::env::var("CLICKHOUSE_MAX_CONNECTIONS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(20),
                query_timeout_secs: 30,
            },
        }
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
    }
}
