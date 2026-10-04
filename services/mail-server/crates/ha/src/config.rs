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

/// Errors raised while loading [`Config`] from the environment.
///
/// Hand-rolled mirror of the workspace's audit convention (`api-server`'s
/// `thiserror` `ConfigError`); this crate does not depend on `thiserror`,
/// so the `Display`/`Error` impls are spelled out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// A required environment variable is missing (or whitespace-only).
    MissingVar(String),
    /// An environment variable has a value production cannot accept.
    Invalid { var: String, reason: String },
    /// A production security check failed.
    SecurityCheck(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingVar(var) => write!(f, "missing required environment variable: {var}"),
            Self::Invalid { var, reason } => write!(f, "invalid value for {var}: {reason}"),
            Self::SecurityCheck(reason) => {
                write!(f, "production security check failed: {reason}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self, String> {
        let data = std::fs::read_to_string(path.as_ref())
            .map_err(|e| format!("read HA config file: {e}"))?;
        serde_json::from_str(&data).map_err(|e| format!("parse HA config JSON: {e}"))
    }

    /// Load configuration from the environment.
    ///
    /// SEC (external audit): missing `INTERNAL_API_KEY` / `ADMIN_API_KEY`
    /// used to be replaced by `generated_runtime_secret` values HERE —
    /// BEFORE `harden_production` ran, so its production checks could never
    /// fire and every production restart silently rotated the API keys. A
    /// missing `DB_PASSWORD` was "fixed" with a random password that could
    /// never authenticate. `from_env` is now fallible: the raw environment
    /// values are bound as-is (missing stays empty) and production
    /// credential requirements are enforced in `harden_production`, which
    /// returns [`ConfigError::MissingVar`] naming the variable (the server
    /// binary exits 78 / EX_CONFIG). Synthetic production credentials are
    /// never generated; development/test still generates ephemeral keys,
    /// loudly.
    pub fn from_env() -> Result<Self, ConfigError> {
        let environment = env_or("NODE_ENV", "development");
        let pid = std::process::id();

        let mut config = Self {
            port: env_or_u16("HA_PORT", 4300),
            environment: environment.clone(),
            service_name: "apexmail-ha".into(),
            version: env_or("VERSION", "1.0.0"),
            // Raw env values only: missing keys stay empty so
            // harden_production observes exactly what the environment
            // provided (the old pre-fill of generated secrets made its
            // production checks unreachable).
            internal_api_key: env_or("INTERNAL_API_KEY", ""),
            admin_api_key: env_or("ADMIN_API_KEY", ""),
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
        config.harden_production()?;
        Ok(config)
    }
}

impl Config {
    /// Production posture: validate the credential values the environment
    /// actually provided and REFUSE synthetic production credentials —
    /// development/test still generates ephemeral runtime keys, loudly.
    pub fn harden_production(&mut self) -> Result<(), ConfigError> {
        if self.environment == "production" {
            // No synthetic production credentials, ever: a missing variable
            // is a deployment error (the old code could never reach these
            // checks because from_env pre-filled generated secrets first).
            if self.internal_api_key.trim().is_empty() {
                return Err(ConfigError::MissingVar("INTERNAL_API_KEY".into()));
            }
            if self.admin_api_key.trim().is_empty() {
                return Err(ConfigError::MissingVar("ADMIN_API_KEY".into()));
            }
            if self.database.password.trim().is_empty() {
                return Err(ConfigError::MissingVar("DB_PASSWORD".into()));
            }
            if self.database.password == "apexmail" {
                return Err(ConfigError::Invalid {
                    var: "DB_PASSWORD".into(),
                    reason: "the well-known development default 'apexmail' is not \
                             acceptable in production"
                        .into(),
                });
            }
            // External audit #9: the failover↔fencing coupling is MECHANICAL
            // — failover with replicas but without data-plane fencing is a
            // startup-rejected deployment, not a warning.
            self.validate_failover_fencing_coupling()?;
        } else {
            // Development/test: ephemeral runtime keys are acceptable (every
            // restart rotates them) but must be loud.
            if self.internal_api_key.trim().is_empty() {
                self.internal_api_key = generated_runtime_secret("ha-internal-api-key");
                tracing::warn!(
                    "SECURITY: INTERNAL_API_KEY missing in development; generated an ephemeral runtime key (redacted)"
                );
            }
            if self.admin_api_key.trim().is_empty() {
                self.admin_api_key = generated_runtime_secret("ha-admin-api-key");
                tracing::warn!(
                    "SECURITY: ADMIN_API_KEY missing in development; generated an ephemeral runtime key (redacted)"
                );
            }
        }
        Ok(())
    }

    /// External audit #9 — mechanical failover↔fencing coupling.
    ///
    /// The automatic-failover coordinator FENCES the old primary (Redis
    /// `ha:fenced:{node}`, `crate::failover::fence_node`) before promoting
    /// the target. That fence only prevents a split brain if the data plane
    /// ENFORCES it (`APEXMAIL_HA_FENCING=true` — api-server mutating routes,
    /// worker claim loops and mta inbound MAIL refuse work while fenced).
    /// With failover enabled, replicas configured and enforcement off, a
    /// fenced old primary keeps accepting writes during and after the
    /// failover — exactly the split-brain window the machinery exists to
    /// close. Production therefore REJECTS the combination, naming the fix.
    pub fn validate_failover_fencing_coupling(&self) -> Result<(), ConfigError> {
        let fencing_enabled = matches!(
            std::env::var("APEXMAIL_HA_FENCING").as_deref(),
            Ok("true") | Ok("1")
        );
        if self.failover.enabled && !self.database.replica_hosts.is_empty() && !fencing_enabled {
            return Err(ConfigError::SecurityCheck(
                "FAILOVER_ENABLED=true with DB_REPLICA_HOSTS configured requires \
                 APEXMAIL_HA_FENCING=true — without data-plane fence enforcement a \
                 failover-fenced old primary keeps accepting writes (split brain). Fix \
                 ONE of: set APEXMAIL_HA_FENCING=true, or set FAILOVER_ENABLED=false, or \
                 clear DB_REPLICA_HOSTS."
                    .into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        // SEC fix: from_env is fallible now (production refuses synthetic
        // credentials); the default development test environment must load.
        let cfg = Config::from_env().expect("HA config loads in development");
        assert_eq!(cfg.port, 4300);
        assert_eq!(cfg.service_name, "apexmail-ha");
        assert_eq!(cfg.database.pool_max, 20);
        assert_eq!(cfg.failover.threshold, 3);
        assert!(cfg.backup.enabled);
        // Development keys are generated (or provided) — never left empty.
        assert!(!cfg.internal_api_key.is_empty());
        assert!(!cfg.admin_api_key.is_empty());
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
        let path = std::env::temp_dir().join(format!("ha-config-{}.json", uuid::Uuid::new_v4())); // nosemgrep: rust.lang.security.temp-dir.temp-dir — test fixture under a unique pid/uuid path — no predictable-name temp collision
        std::fs::write(&path, json).unwrap();
        let err = Config::from_file(&path).unwrap_err();
        let _ = std::fs::remove_file(&path);
        assert!(err.contains("unknown field"));
    }

    // ── SEC: production requires real credentials ──────────────

    /// Env helper: nextest runs every test in its own process, so process-env
    /// mutations here are deterministic; the module only touches the
    /// variables named in these tests.
    fn set_env(name: &str, value: &str) {
        std::env::set_var(name, value);
    }

    fn unset_env(name: &str) {
        std::env::remove_var(name);
    }

    /// Captures `tracing` output emitted inside `f` with a SCOPED subscriber
    /// (no global default installed — deterministic under nextest and plain
    /// `cargo test` alike).
    struct TestLogSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for TestLogSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log sink lock").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn capture_logs(f: impl FnOnce()) -> String {
        let buffer = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = std::sync::Arc::clone(&buffer);
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || TestLogSink(std::sync::Arc::clone(&sink)))
            .with_max_level(tracing::Level::WARN)
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        let captured = buffer.lock().expect("log sink lock").clone();
        String::from_utf8(captured).expect("captured logs are utf-8")
    }

    fn production_env_with(
        internal_api_key: Option<&str>,
        admin_api_key: Option<&str>,
        db_password: Option<&str>,
    ) {
        set_env("NODE_ENV", "production");
        match internal_api_key {
            Some(value) => set_env("INTERNAL_API_KEY", value),
            None => unset_env("INTERNAL_API_KEY"),
        }
        match admin_api_key {
            Some(value) => set_env("ADMIN_API_KEY", value),
            None => unset_env("ADMIN_API_KEY"),
        }
        match db_password {
            Some(value) => set_env("DB_PASSWORD", value),
            None => unset_env("DB_PASSWORD"),
        }
    }

    /// Production + missing INTERNAL_API_KEY → from_env errs with a message
    /// naming the variable (no ephemeral key is bound).
    #[test]
    fn test_production_missing_internal_api_key_is_refused() {
        production_env_with(None, Some("prod-admin-key"), Some("prod-db-password"));
        unset_env("DB_REPLICA_HOSTS"); // keep the failover↔fencing gate out of scope here

        let err = Config::from_env().unwrap_err();
        assert!(matches!(err, ConfigError::MissingVar(_)));
        assert!(
            err.to_string().contains("INTERNAL_API_KEY"),
            "error must name the missing variable, got: {err}"
        );
    }

    /// Production + missing ADMIN_API_KEY → same refusal, naming the variable.
    #[test]
    fn test_production_missing_admin_api_key_is_refused() {
        production_env_with(Some("prod-internal-key"), None, Some("prod-db-password"));
        unset_env("DB_REPLICA_HOSTS");

        let err = Config::from_env().unwrap_err();
        assert!(matches!(err, ConfigError::MissingVar(_)));
        assert!(
            err.to_string().contains("ADMIN_API_KEY"),
            "error must name the missing variable, got: {err}"
        );
    }

    /// Production + missing DB_PASSWORD → refusal (the old behavior generated
    /// a random password that could never authenticate — worse than useless).
    #[test]
    fn test_production_missing_db_password_is_refused() {
        production_env_with(Some("prod-internal-key"), Some("prod-admin-key"), None);
        unset_env("DB_REPLICA_HOSTS");

        let err = Config::from_env().unwrap_err();
        assert!(matches!(err, ConfigError::MissingVar(_)));
        assert!(
            err.to_string().contains("DB_PASSWORD"),
            "error must name the missing variable, got: {err}"
        );
    }

    /// Production + the well-known development default as DB_PASSWORD →
    /// refusal (the old code treated it as missing; it must not pass as a
    /// "real" credential now that generation is gone).
    #[test]
    fn test_production_weak_default_db_password_is_refused() {
        production_env_with(
            Some("prod-internal-key"),
            Some("prod-admin-key"),
            Some("apexmail"),
        );
        unset_env("DB_REPLICA_HOSTS");

        let err = Config::from_env().unwrap_err();
        assert!(matches!(err, ConfigError::Invalid { .. }));
        assert!(
            err.to_string().contains("DB_PASSWORD"),
            "error must name the offending variable, got: {err}"
        );
    }

    /// The bypass is dead: with all three variables provided, harden_production
    /// validated the REAL values and from_env returns them verbatim — no
    /// synthetic runtime credential ever replaces them.
    #[test]
    fn test_production_uses_the_values_the_environment_provided() {
        production_env_with(
            Some("prod-internal-key"),
            Some("prod-admin-key"),
            Some("prod-db-password"),
        );
        unset_env("DB_REPLICA_HOSTS"); // the credential assertions below are orthogonal to the failover↔fencing gate

        let cfg =
            Config::from_env().expect("production config with explicit credentials must load");
        assert_eq!(cfg.internal_api_key, "prod-internal-key");
        assert_eq!(cfg.admin_api_key, "prod-admin-key");
        assert_eq!(cfg.database.password, "prod-db-password");
        assert!(!cfg.internal_api_key.starts_with("ha-internal-api-key-"));
        assert!(!cfg.admin_api_key.starts_with("ha-admin-api-key-"));
        assert!(!cfg.database.password.starts_with("auto-db-password-"));
    }

    /// harden_production, directly: an empty INTERNAL_API_KEY under
    /// production is a hard error AND the field stays empty — the old code
    /// bound a generated secret BEFORE this method could ever check it.
    #[test]
    fn test_harden_production_refuses_empty_internal_api_key_without_generating() {
        production_env_with(
            Some("probe-internal-key"),
            Some("probe-admin-key"),
            Some("probe-db-password"),
        );
        unset_env("DB_REPLICA_HOSTS");
        let mut cfg =
            Config::from_env().expect("production config with explicit credentials must load");

        // Simulate the deployment variable the old code hid from this check.
        cfg.internal_api_key = String::new();
        let err = cfg.harden_production().unwrap_err();
        assert!(
            err.to_string().contains("INTERNAL_API_KEY"),
            "error must name the missing variable, got: {err}"
        );
        assert!(
            cfg.internal_api_key.is_empty(),
            "harden_production must not bind a generated credential"
        );
    }

    /// Development + missing keys → ephemeral generation works AND is logged;
    /// DB_PASSWORD stays empty in development (no fake credential there
    /// either).
    #[test]
    fn test_development_missing_keys_generate_ephemeral_and_are_logged() {
        set_env("NODE_ENV", "development");
        unset_env("INTERNAL_API_KEY");
        unset_env("ADMIN_API_KEY");

        let logs = capture_logs(|| {
            let cfg = Config::from_env().expect("development config must load");
            assert!(
                cfg.internal_api_key.starts_with("ha-internal-api-key-"),
                "ephemeral internal key expected, got: {}",
                cfg.internal_api_key
            );
            assert!(
                cfg.admin_api_key.starts_with("ha-admin-api-key-"),
                "ephemeral admin key expected, got: {}",
                cfg.admin_api_key
            );
            assert_eq!(
                cfg.database.password, "",
                "development must not invent a DB password"
            );
        });
        assert!(
            logs.contains("INTERNAL_API_KEY"),
            "internal key generation must be logged, got: {logs}"
        );
        assert!(
            logs.contains("ADMIN_API_KEY"),
            "admin key generation must be logged, got: {logs}"
        );
    }

    /// Pins the generated-vs-required transition: the SAME missing variables
    /// yield ephemeral keys in development and a hard error in production.
    #[test]
    fn test_generated_vs_required_transition_is_pinned_by_environment() {
        unset_env("INTERNAL_API_KEY");
        unset_env("ADMIN_API_KEY");
        set_env("DB_PASSWORD", "");

        set_env("NODE_ENV", "development");
        let dev = Config::from_env().expect("development generates ephemeral keys");
        assert!(dev.internal_api_key.starts_with("ha-internal-api-key-"));
        assert!(dev.admin_api_key.starts_with("ha-admin-api-key-"));

        set_env("NODE_ENV", "production");
        let prod_err = Config::from_env().unwrap_err();
        assert!(
            prod_err.to_string().contains("INTERNAL_API_KEY"),
            "production refuses the first missing variable, got: {prod_err}"
        );
    }

    // ── External audit #9: mechanical failover↔fencing coupling ────────

    /// Production + FAILOVER_ENABLED=true + DB_REPLICA_HOSTS + no
    /// APEXMAIL_HA_FENCING → startup REFUSED with an error naming the exact
    /// fix (failover fences the old primary, but the fence only prevents a
    /// split brain when the data plane enforces it).
    #[test]
    fn test_production_failover_with_replicas_requires_fencing() {
        production_env_with(
            Some("prod-internal-key"),
            Some("prod-admin-key"),
            Some("prod-db-password"),
        );
        set_env("FAILOVER_ENABLED", "true");
        set_env("DB_REPLICA_HOSTS", "db-replica-1,db-replica-2");
        unset_env("APEXMAIL_HA_FENCING");

        let err = Config::from_env().unwrap_err();
        assert!(matches!(err, ConfigError::SecurityCheck(_)));
        let message = err.to_string();
        for required in [
            "FAILOVER_ENABLED",
            "DB_REPLICA_HOSTS",
            "APEXMAIL_HA_FENCING=true",
            "FAILOVER_ENABLED=false",
        ] {
            assert!(
                message.contains(required),
                "the refusal must name the exact fix `{required}`, got: {message}"
            );
        }
    }

    /// `APEXMAIL_HA_FENCING=true` unblocks the exact same deployment.
    #[test]
    fn test_production_failover_with_replicas_and_fencing_loads() {
        production_env_with(
            Some("prod-internal-key"),
            Some("prod-admin-key"),
            Some("prod-db-password"),
        );
        set_env("FAILOVER_ENABLED", "true");
        set_env("DB_REPLICA_HOSTS", "db-replica-1");
        set_env("APEXMAIL_HA_FENCING", "true");

        let cfg = Config::from_env().expect("fencing enforcement satisfies the coupling gate");
        assert_eq!(cfg.database.replica_hosts, vec!["db-replica-1".to_string()]);
    }

    /// `APEXMAIL_HA_FENCING=1` — the same truthy spelling the data-plane
    /// fence gates accept — satisfies the coupling too.
    #[test]
    fn test_production_fencing_accepts_the_same_truthy_spellings_as_the_data_plane() {
        production_env_with(
            Some("prod-internal-key"),
            Some("prod-admin-key"),
            Some("prod-db-password"),
        );
        set_env("FAILOVER_ENABLED", "true");
        set_env("DB_REPLICA_HOSTS", "db-replica-1");
        set_env("APEXMAIL_HA_FENCING", "1");
        let cfg = Config::from_env().expect("APEXMAIL_HA_FENCING=1 must satisfy the gate");
        assert!(!cfg.database.replica_hosts.is_empty());

        set_env("APEXMAIL_HA_FENCING", "false");
        assert!(
            Config::from_env().is_err(),
            "APEXMAIL_HA_FENCING=false must NOT satisfy the gate"
        );
    }

    /// The gate is scoped to the real coupling: disabling failover OR
    /// removing the replica topology leaves nothing to fence, and the
    /// deployment loads.
    #[test]
    fn test_production_coupling_gate_only_binds_failover_plus_replicas() {
        production_env_with(
            Some("prod-internal-key"),
            Some("prod-admin-key"),
            Some("prod-db-password"),
        );
        set_env("DB_REPLICA_HOSTS", "db-replica-1");
        unset_env("APEXMAIL_HA_FENCING");

        set_env("FAILOVER_ENABLED", "false");
        let cfg = Config::from_env().expect("failover disabled — no fencing prerequisite");
        assert!(!cfg.failover.enabled);

        set_env("FAILOVER_ENABLED", "true");
        set_env("DB_REPLICA_HOSTS", "");
        let cfg = Config::from_env().expect("no replicas — no fencing prerequisite");
        assert!(cfg.database.replica_hosts.is_empty());
    }

    /// The validator, directly: all four combinations of the coupling
    /// matrix, independent of `from_env`.
    #[test]
    fn test_validate_failover_fencing_coupling_matrix() {
        fn coupling_config(failover_enabled: bool, replicas: usize) -> Config {
            let mut cfg = Config::from_env().expect("HA config must load in development");
            cfg.failover.enabled = failover_enabled;
            cfg.database.replica_hosts = (0..replicas).map(|i| format!("replica-{i}")).collect();
            cfg
        }

        set_env("APEXMAIL_HA_FENCING", "true");
        assert!(coupling_config(true, 2)
            .validate_failover_fencing_coupling()
            .is_ok());
        assert!(coupling_config(false, 2)
            .validate_failover_fencing_coupling()
            .is_ok());
        assert!(coupling_config(true, 0)
            .validate_failover_fencing_coupling()
            .is_ok());
        assert!(coupling_config(false, 0)
            .validate_failover_fencing_coupling()
            .is_ok());

        unset_env("APEXMAIL_HA_FENCING");
        let err = coupling_config(true, 2)
            .validate_failover_fencing_coupling()
            .expect_err("unfenced failover with replicas is refused");
        assert!(
            err.to_string().contains("APEXMAIL_HA_FENCING=true"),
            "{err}"
        );
        assert!(coupling_config(false, 2)
            .validate_failover_fencing_coupling()
            .is_ok());
        assert!(coupling_config(true, 0)
            .validate_failover_fencing_coupling()
            .is_ok());

        // Cleanup: never leak the coupling variables into sibling tests.
        unset_env("DB_REPLICA_HOSTS");
        set_env("FAILOVER_ENABLED", "true");
    }
}
