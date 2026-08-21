//! Configuration for the HA service.

use serde::{Deserialize, Serialize};

// ── Enums ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingMode {
    ActiveActive,
    ActivePassive,
    RoundRobin,
    LatencyBased,
    GeoProximity,
    Weighted,
}

impl RoutingMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "active_active" | "active-active" => Some(Self::ActiveActive),
            "active_passive" | "active-passive" => Some(Self::ActivePassive),
            "round_robin" | "round-robin" => Some(Self::RoundRobin),
            "latency" | "latency_based" => Some(Self::LatencyBased),
            "geo_proximity" | "geo" => Some(Self::GeoProximity),
            "weighted" => Some(Self::Weighted),
            _ => None,
        }
    }
}

impl std::fmt::Display for RoutingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ActiveActive => write!(f, "active_active"),
            Self::ActivePassive => write!(f, "active_passive"),
            Self::RoundRobin => write!(f, "round_robin"),
            Self::LatencyBased => write!(f, "latency"),
            Self::GeoProximity => write!(f, "geo_proximity"),
            Self::Weighted => write!(f, "weighted"),
        }
    }
}

// ── Region Config ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegionConfig {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub role: String,
    pub weight: u32,
}

// ── Database Config ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub user: String,
    pub password: String,
    pub pool_max: u32,
    pub idle_timeout_ms: u64,
    pub connection_timeout_ms: u64,
    pub replica_host: Option<String>,
    pub replica_port: u16,
    pub replica_hosts: Vec<String>,
    pub standby_host: Option<String>,
    pub standby_port: u16,
}

impl DatabaseConfig {
    pub fn primary_url(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            self.user, self.password, self.host, self.port, self.database
        )
    }

    pub fn replica_url(&self) -> Option<String> {
        self.replica_host.as_ref().map(|h| {
            format!(
                "postgres://{}:{}@{}:{}/{}",
                self.user, self.password, h, self.replica_port, self.database
            )
        })
    }

    pub fn standby_url(&self) -> Option<String> {
        self.standby_host.as_ref().map(|h| {
            format!(
                "postgres://{}:{}@{}:{}/{}",
                self.user, self.password, h, self.standby_port, self.database
            )
        })
    }
}

// ── Redis Config ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisConfig {
    pub host: String,
    pub port: u16,
    pub password: Option<String>,
    pub db: u8,
    pub sentinel_master: String,
}

impl RedisConfig {
    pub fn url(&self) -> String {
        match &self.password {
            Some(p) => format!("redis://:{}@{}:{}/{}", p, self.host, self.port, self.db),
            None => format!("redis://{}:{}/{}", self.host, self.port, self.db),
        }
    }
}

// ── Failover Config ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailoverConfig {
    pub enabled: bool,
    pub threshold: u32,
    pub failback_enabled: bool,
    pub failback_delay_ms: u64,
}

// ── Health Config ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckConfig {
    pub interval_ms: u64,
    pub timeout_ms: u64,
}

// ── Replication Config ─────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicationConfig {
    pub enabled: bool,
    pub lag_threshold_ms: u64,
    pub sync_replication: bool,
    pub max_lag_ms: u64,
    pub critical_lag_ms: u64,
    pub warning_lag_ms: u64,
}

// ── Backup Config ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupConfig {
    pub enabled: bool,
    pub bucket: String,
    pub region: String,
    pub retention_days: u32,
    pub encryption_key: Option<String>,
    pub full_schedule: String,
    pub incremental_schedule: String,
    pub wal_archive_interval_secs: u64,
}

// ── Circuit Breaker Config ─────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitBreakerConfig {
    pub enabled: bool,
    pub threshold: u32,
    pub timeout_ms: u64,
    pub reset_timeout_ms: u64,
}

// ── Chaos Config ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChaosConfig {
    pub enabled: bool,
    pub failure_rate: f64,
}

// ── Multi-Region Config ────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiRegionConfig {
    pub cluster_id: String,
    pub node_id: String,
    pub region: String,
    pub availability_zone: String,
    pub regions: Vec<String>,
    pub primary_region: String,
    pub routing_mode: RoutingMode,
    pub health_check_interval_ms: u64,
    pub sync_interval_ms: u64,
}

// ── Top-Level Config ───────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub port: u16,
    pub environment: String,
    pub service_name: String,
    pub version: String,
    pub internal_api_key: String,
    pub admin_api_key: String,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub failover: FailoverConfig,
    pub health: HealthCheckConfig,
    pub replication: ReplicationConfig,
    pub backup: BackupConfig,
    pub circuit_breaker: CircuitBreakerConfig,
    pub chaos: ChaosConfig,
    pub multi_region: MultiRegionConfig,
    pub alerting_webhook: Option<String>,
    pub rpo_target_secs: u64,
    pub rto_target_secs: u64,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.into())
}
fn env_or_u16(key: &str, default: u16) -> u16 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
fn env_or_u32(key: &str, default: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
fn env_or_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
fn env_or_u8(key: &str, default: u8) -> u8 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
fn env_or_f64(key: &str, default: f64) -> f64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
fn env_or_bool(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .map(|v| v == "true" || v == "1")
        .unwrap_or(default)
}

fn generated_runtime_secret(label: &str) -> String {
    format!("{label}-{}", uuid::Uuid::new_v4().simple())
}

impl Config {
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self, String> {
        let data = std::fs::read_to_string(path.as_ref())
            .map_err(|e| format!("read HA config file: {e}"))?;
        serde_json::from_str(&data).map_err(|e| format!("parse HA config JSON: {e}"))
    }

    pub fn from_env() -> Self {
        let environment = env_or("NODE_ENV", "development");
        let pid = std::process::id();

        let mut config = Self {
            port: env_or_u16("HA_PORT", 4300),
            environment: environment.clone(),
            service_name: "apexmail-ha".into(),
            version: env_or("VERSION", "1.0.0"),
            internal_api_key: std::env::var("INTERNAL_API_KEY")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| generated_runtime_secret("ha-internal-api-key")),
            admin_api_key: std::env::var("ADMIN_API_KEY")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| generated_runtime_secret("ha-admin-api-key")),
            database: DatabaseConfig {
                host: env_or("DB_HOST", "127.0.0.1"),
                port: env_or_u16("DB_PORT", 5432),
                database: env_or("DB_NAME", "apexmail"),
                user: env_or("DB_USER", "apexmail"),
                password: env_or("DB_PASSWORD", ""),
                pool_max: env_or_u32("DB_POOL_MAX", 20),
                idle_timeout_ms: env_or_u64("DB_IDLE_TIMEOUT", 30000),
                connection_timeout_ms: env_or_u64("DB_CONNECTION_TIMEOUT", 3000),
                replica_host: std::env::var("DB_REPLICA_HOST").ok(),
                replica_port: env_or_u16("DB_REPLICA_PORT", 5432),
                replica_hosts: env_or("DB_REPLICA_HOSTS", "")
                    .split(',')
                    .filter(|s| !s.trim().is_empty())
                    .map(|s| s.trim().to_string())
                    .collect(),
                standby_host: std::env::var("DB_STANDBY_HOST").ok(),
                standby_port: env_or_u16("DB_STANDBY_PORT", 5432),
            },
            redis: RedisConfig {
                host: env_or("REDIS_HOST", "127.0.0.1"),
                port: env_or_u16("REDIS_PORT", 6379),
                password: std::env::var("REDIS_PASSWORD").ok(),
                db: env_or_u8("REDIS_DB", 0),
                sentinel_master: env_or("REDIS_SENTINEL_MASTER", "mymaster"),
            },
            failover: FailoverConfig {
                enabled: env_or_bool("FAILOVER_ENABLED", true),
                threshold: env_or_u32("FAILOVER_THRESHOLD", 3),
                // G.8: failback defaults to MANUAL. Automatic failback can
                // promote a lagging original primary and cause silent data
                // loss; operators must opt in with FAILBACK_ENABLED=true.
                failback_enabled: env_or_bool("FAILBACK_ENABLED", false),
                failback_delay_ms: env_or_u64("FAILBACK_DELAY", 300000),
            },
            health: HealthCheckConfig {
                interval_ms: env_or_u64("HEALTH_CHECK_INTERVAL", 5000),
                timeout_ms: env_or_u64("HEALTH_CHECK_TIMEOUT", 3000),
            },
            replication: ReplicationConfig {
                enabled: env_or_bool("REPLICATION_ENABLED", true),
                lag_threshold_ms: env_or_u64("REPLICATION_LAG_THRESHOLD", 30000),
                sync_replication: env_or_bool("SYNC_REPLICATION", false),
                max_lag_ms: env_or_u64("MAX_REPLICATION_LAG_MS", 30000),
                critical_lag_ms: env_or_u64("CRITICAL_LAG_THRESHOLD_MS", 60000),
                warning_lag_ms: env_or_u64("WARNING_LAG_THRESHOLD_MS", 10000),
            },
            backup: BackupConfig {
                enabled: env_or_bool("BACKUP_ENABLED", true),
                bucket: env_or("BACKUP_BUCKET", "apexmail-backups"),
                region: env_or("BACKUP_REGION", "us-east-1"),
                retention_days: env_or_u32("BACKUP_RETENTION_DAYS", 90),
                encryption_key: std::env::var("BACKUP_ENCRYPTION_KEY").ok(),
                full_schedule: env_or("FULL_BACKUP_SCHEDULE", "0 2 * * 0"),
                incremental_schedule: env_or("INCREMENTAL_BACKUP_SCHEDULE", "0 2 * * *"),
                wal_archive_interval_secs: env_or_u64("WAL_ARCHIVE_INTERVAL", 300),
            },
            circuit_breaker: CircuitBreakerConfig {
                enabled: env_or_bool("CIRCUIT_BREAKER_ENABLED", true),
                threshold: env_or_u32("CIRCUIT_BREAKER_THRESHOLD", 5),
                timeout_ms: env_or_u64("CIRCUIT_BREAKER_TIMEOUT", 30000),
                reset_timeout_ms: env_or_u64("CIRCUIT_BREAKER_RESET_TIMEOUT", 60000),
            },
            chaos: ChaosConfig {
                enabled: env_or_bool("CHAOS_ENABLED", false),
                failure_rate: env_or_f64("CHAOS_FAILURE_RATE", 0.01),
            },
            multi_region: MultiRegionConfig {
                cluster_id: env_or("CLUSTER_ID", "apexmail-cluster-1"),
                node_id: env_or("NODE_ID", &format!("node-{}", pid)),
                region: std::env::var("AWS_REGION")
                    .or_else(|_| std::env::var("REGION"))
                    .unwrap_or_else(|_| "us-east-1".into()),
                availability_zone: env_or("AVAILABILITY_ZONE", "us-east-1a"),
                regions: env_or("REGIONS", "us-east-1,us-west-2,eu-west-1")
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect(),
                primary_region: env_or("PRIMARY_REGION", "us-east-1"),
                routing_mode: RoutingMode::parse(&env_or("ROUTING_MODE", "latency"))
                    .unwrap_or(RoutingMode::LatencyBased),
                health_check_interval_ms: env_or_u64("REGION_HEALTH_CHECK_INTERVAL", 10000),
                sync_interval_ms: env_or_u64("CROSS_REGION_SYNC_INTERVAL", 30000),
            },
            alerting_webhook: std::env::var("ALERTING_WEBHOOK").ok(),
            rpo_target_secs: env_or_u64("RPO_TARGET", 60),
            rto_target_secs: env_or_u64("RTO_TARGET", 300),
        };
        config.harden_production();
        config
    }
}

impl Config {
    pub fn harden_production(&mut self) {
        if self.environment == "production" {
            if self.internal_api_key.trim().is_empty() {
                self.internal_api_key = generated_runtime_secret("ha-internal-api-key");
                tracing::warn!(
                    "SECURITY: INTERNAL_API_KEY missing in production; generated an ephemeral runtime key (redacted)"
                );
            }
            if self.admin_api_key.trim().is_empty() {
                self.admin_api_key = generated_runtime_secret("ha-admin-api-key");
                tracing::warn!(
                    "SECURITY: ADMIN_API_KEY missing in production; generated an ephemeral runtime key (redacted)"
                );
            }
            if self.database.password.is_empty() || self.database.password == "apexmail" {
                self.database.password = format!(
                    "auto-db-password-{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos()
                );
                tracing::warn!(
                    "SECURITY: DB_PASSWORD missing/weak in production; generated an ephemeral runtime password (redacted)"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let cfg = Config::from_env();
        assert_eq!(cfg.port, 4300);
        assert_eq!(cfg.service_name, "apexmail-ha");
        assert_eq!(cfg.database.pool_max, 20);
        assert_eq!(cfg.failover.threshold, 3);
        assert!(cfg.backup.enabled);
    }

    #[test]
    fn test_routing_mode_parse() {
        assert_eq!(
            RoutingMode::parse("latency"),
            Some(RoutingMode::LatencyBased)
        );
        assert_eq!(RoutingMode::parse("weighted"), Some(RoutingMode::Weighted));
        assert_eq!(
            RoutingMode::parse("round-robin"),
            Some(RoutingMode::RoundRobin)
        );
        assert!(RoutingMode::parse("invalid").is_none());
    }

    #[test]
    fn test_db_primary_url() {
        let db = DatabaseConfig {
            host: "db.example.com".into(),
            port: 5432,
            database: "apexmail".into(),
            user: "user".into(),
            password: "pass".into(),
            pool_max: 20,
            idle_timeout_ms: 30000,
            connection_timeout_ms: 3000,
            replica_host: None,
            replica_port: 5432,
            replica_hosts: vec![],
            standby_host: None,
            standby_port: 5432,
        };
        assert_eq!(
            db.primary_url(),
            "postgres://user:pass@db.example.com:5432/apexmail"
        );
        assert!(db.replica_url().is_none());
        assert!(db.standby_url().is_none());
    }

    #[test]
    fn test_db_replica_url() {
        let db = DatabaseConfig {
            host: "primary".into(),
            port: 5432,
            database: "db".into(),
            user: "u".into(),
            password: "p".into(),
            pool_max: 1,
            idle_timeout_ms: 1,
            connection_timeout_ms: 1,
            replica_host: Some("replica-1".into()),
            replica_port: 5433,
            replica_hosts: vec![],
            standby_host: Some("standby-1".into()),
            standby_port: 5434,
        };
        assert_eq!(
            db.replica_url().unwrap(),
            "postgres://u:p@replica-1:5433/db"
        );
        assert_eq!(
            db.standby_url().unwrap(),
            "postgres://u:p@standby-1:5434/db"
        );
    }

    #[test]
    fn test_redis_url() {
        let r = RedisConfig {
            host: "localhost".into(),
            port: 6379,
            password: None,
            db: 0,
            sentinel_master: "mymaster".into(),
        };
        assert_eq!(r.url(), "redis://localhost:6379/0");
    }

    #[test]
    fn file_config_rejects_unknown_fields() {
        let json = r#"{
            "port": 4300,
            "environment": "development",
            "service_name": "apexmail-ha",
            "version": "1.0.0",
            "internal_api_key": "internal",
            "admin_api_key": "admin",
            "database": {
                "host": "localhost", "port": 5432, "database": "apexmail",
                "user": "apexmail", "password": "secret", "pool_max": 20,
                "idle_timeout_ms": 30000, "connection_timeout_ms": 3000,
                "replica_host": null, "replica_port": 5432, "replica_hosts": [],
                "standby_host": null, "standby_port": 5432
            },
            "redis": {"host": "localhost", "port": 6379, "password": null, "db": 0, "sentinel_master": "mymaster"},
            "failover": {"enabled": true, "threshold": 3, "failback_enabled": true, "failback_delay_ms": 300000},
            "health": {"interval_ms": 5000, "timeout_ms": 3000},
            "replication": {"enabled": true, "lag_threshold_ms": 30000, "sync_replication": false, "max_lag_ms": 30000, "critical_lag_ms": 60000, "warning_lag_ms": 10000},
            "backup": {"enabled": true, "bucket": "backups", "region": "us-east-1", "retention_days": 90, "encryption_key": null, "full_schedule": "0 2 * * 0", "incremental_schedule": "0 2 * * *", "wal_archive_interval_secs": 300},
            "circuit_breaker": {"enabled": true, "threshold": 5, "timeout_ms": 30000, "reset_timeout_ms": 60000},
            "chaos": {"enabled": false, "failure_rate": 0.01},
            "multi_region": {"cluster_id": "cluster", "node_id": "node", "region": "us-east-1", "availability_zone": "us-east-1a", "regions": ["us-east-1"], "primary_region": "us-east-1", "routing_mode": "latency_based", "health_check_interval_ms": 10000, "sync_interval_ms": 30000},
            "alerting_webhook": null,
            "rpo_target_secs": 60,
            "rto_target_secs": 300,
            "unexpected": true
        }"#;
        let path = std::env::temp_dir().join(format!("ha-config-{}.json", uuid::Uuid::new_v4()));
        std::fs::write(&path, json).unwrap();
        let err = Config::from_file(&path).unwrap_err();
        let _ = std::fs::remove_file(&path);
        assert!(err.contains("unknown field"));
    }
}
