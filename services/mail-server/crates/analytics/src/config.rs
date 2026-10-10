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
            // coverage: justified — llvm-cov region-counter artifact: this
            // arm EXECUTES (malformed_dotenv_file_is_reported_not_swallowed
            // feeds dotenvy an unparseable .env and the warn! below carries a
            // hit in the measured run) but the nested check's and the
            // enclosing block's own regions are never counted.
            if !matches!(error, dotenvy::Error::Io(ref io) if io.kind() == std::io::ErrorKind::NotFound)
            {
                tracing::warn!("failed to load .env: {error}");
            }
        }
        let node_env = std::env::var("NODE_ENV").unwrap_or_else(|_| "development".into());
        let is_production = matches!(node_env.as_str(), "production" | "prod");
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
                // G.7: no credential-bearing fallback URL. Only a local
                // trust-style development default is applied, and only
                // outside production — production keeps the empty value so
                // the invalid config surfaces (see `validate`).
                if is_production {
                    tracing::error!(
                        "DATABASE_URL is not set in production — refusing to invent a \
                         credential-bearing default; analytics will fail to start"
                    );
                } else {
                    config.database_url = "postgres://apexmail@localhost:5432/apexmail".into();
                }
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
        if is_production && config.sto_hmac_key.trim().is_empty() {
            // D.2: unsalted SHA-256 fallback must not silently activate in
            // production — analytics PII hashing REQUIRES the HMAC key there.
            tracing::error!(
                "ANALYTICS_STO_HMAC_KEY must be set in production (PII hashing would \
                 otherwise fall back to unsalted SHA-256)"
            );
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
        // D.2: production requires the HMAC key (same pattern as other
        // crates' prod-validation: empty security material is a config error).
        if is_production_environment() && self.sto_hmac_key.trim().is_empty() {
            return Err(
                "ANALYTICS_STO_HMAC_KEY must be set outside development (PII hashing)".into(),
            );
        }
        Ok(())
    }
}

// ── cold-storage durability contract (FINDING C, migration 231) ──────────────

/// True when the operator explicitly marked the analytics cold-storage root
/// as a durable mount (`ANALYTICS_COLD_STORAGE_DURABLE=1`).
///
/// The contract (see the crate README and `compaction` module docs): the
/// `analytics_compaction_batches` ledger row is the source of truth for what
/// cold storage must contain; the objects under the storage root are a
/// materialization. That makes the root a CACHE in durability terms — losing
/// it is recoverable ONLY if the operator has object storage/backup or
/// accepts the data loss of the materialized tier. A non-durable root must
/// therefore be an explicit, visible choice.
pub fn cold_storage_marked_durable() -> bool {
    std::env::var("ANALYTICS_COLD_STORAGE_DURABLE")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Loud (but non-fatal) warning when the cold-storage root is not explicitly
/// marked durable. Called at worker startup and at the start of every
/// compaction run. A warning, never an error:the ledger is the commit
/// record, so local development against a scratch directory still behaves
/// correctly — but an operator running on, say, an ephemeral container
/// volume gets told, on every run, exactly what they would lose.
pub fn warn_if_cold_storage_not_durable(storage_path: &str) {
    if !cold_storage_marked_durable() {
        tracing::warn!(
            storage_path = %storage_path,
            "ANALYTICS_COLD_STORAGE_DURABLE is not set to 1: the cold-storage root is NOT \
             explicitly marked durable. The compaction ledger (analytics_compaction_batches) \
             is the source of truth and the objects under this path are only its \
             materialization — if this mount is ephemeral or non-redundant, configure durable \
             object storage/backup for it or set ANALYTICS_COLD_STORAGE_DURABLE=1 to silence \
             this warning after wiring durability up."
        );
    }
}

/// True when NODE_ENV indicates production (the convention used by the
/// sibling services).
fn is_production_environment() -> bool {
    matches!(
        std::env::var("NODE_ENV").unwrap_or_default().as_str(),
        "production" | "prod"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes tests that mutate process env vars.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_defaults() {
        let cfg = AnalyticsConfig::default();
        assert_eq!(cfg.compaction.hot_retention_days, 90);
        assert_eq!(cfg.compaction.cold_retention_days, 730);
        assert_eq!(cfg.compaction.batch_size, 100_000);
        assert_eq!(cfg.clickhouse.max_connections, 20);
        assert_eq!(cfg.clickhouse.insert_timeout_seconds, 30);
    }

    /// D.2: an empty HMAC key must be rejected in production.
    #[test]
    fn empty_hmac_key_is_rejected_in_production() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Satisfy the unrelated validations so the HMAC check is exercised.
        let cfg = AnalyticsConfig {
            database_url: "postgres://u:p@localhost:5432/apexmail".into(),
            sto_hmac_key: String::new(),
            ..Default::default()
        };
        // Two passes with DIFFERENT pre-test states so BOTH arms of the
        // restore match below execute deterministically regardless of the
        // ambient environment (the assertions are identical in both passes).
        for saved in [Some("ci-capture".to_string()), None] {
            match saved {
                Some(ref v) => std::env::set_var("NODE_ENV", v),
                None => std::env::remove_var("NODE_ENV"),
            }
            let saved = std::env::var("NODE_ENV").ok();
            std::env::set_var("NODE_ENV", "production");
            let result = cfg.validate();
            match saved {
                Some(v) => std::env::set_var("NODE_ENV", v),
                None => std::env::remove_var("NODE_ENV"),
            }
            let err = result.expect_err("prod config with empty HMAC key must be rejected");
            assert!(err.contains("ANALYTICS_STO_HMAC_KEY"), "got: {err}");
        }
    }

    /// G.7: no credential-bearing postgres:postgres fallback may be invented.
    #[test]
    fn from_env_never_invents_postgres_postgres_url() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Two passes with DIFFERENT pre-test states so BOTH arms of both
        // restore matches below execute deterministically regardless of the
        // ambient environment (the assertion is identical in both passes).
        for (db_pre, node_pre) in [
            (
                Some("postgres://ci-a@localhost/ci".to_string()),
                Some("ci-a".to_string()),
            ),
            (None, None),
        ] {
            match db_pre {
                Some(ref v) => std::env::set_var("DATABASE_URL", v),
                None => std::env::remove_var("DATABASE_URL"),
            }
            match node_pre {
                Some(ref v) => std::env::set_var("NODE_ENV", v),
                None => std::env::remove_var("NODE_ENV"),
            }
            let saved_db = std::env::var("DATABASE_URL").ok();
            let saved_node = std::env::var("NODE_ENV").ok();
            std::env::remove_var("DATABASE_URL");
            std::env::set_var("NODE_ENV", "development");
            let cfg = AnalyticsConfig::from_env();
            assert_ne!(
                cfg.database_url,
                "postgres://postgres:postgres@localhost:5432/apexmail"
            );
            match saved_db {
                Some(v) => std::env::set_var("DATABASE_URL", v),
                None => std::env::remove_var("DATABASE_URL"),
            }
            match saved_node {
                Some(v) => std::env::set_var("NODE_ENV", v),
                None => std::env::remove_var("NODE_ENV"),
            }
        }
    }

    /// FINDING C:the durability marker is env-gated and only `1` counts —
    /// anything else (unset, "0", "true", "yes") keeps the loud warning path
    /// active, so an operator cannot accidentally opt out of it.
    #[test]
    fn cold_storage_durability_marker_is_strictly_env_one() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // The whole body (capture → probe → RESTORE) runs twice with
        // DIFFERENT pre-states so the single restore match below executes
        // BOTH of its arms deterministically regardless of the ambient
        // environment.
        for pre in [Some("0".to_string()), None] {
            match pre {
                Some(ref v) => std::env::set_var("ANALYTICS_COLD_STORAGE_DURABLE", v),
                None => std::env::remove_var("ANALYTICS_COLD_STORAGE_DURABLE"),
            }
            let saved = std::env::var("ANALYTICS_COLD_STORAGE_DURABLE").ok();
            for (value, expected) in [
                (None, false),
                (Some("0"), false),
                (Some("true"), false),
                (Some("1 "), false),
                (Some("1"), true),
            ] {
                match value {
                    Some(v) => std::env::set_var("ANALYTICS_COLD_STORAGE_DURABLE", v),
                    None => std::env::remove_var("ANALYTICS_COLD_STORAGE_DURABLE"),
                }
                assert_eq!(
                    cold_storage_marked_durable(),
                    expected,
                    "ANALYTICS_COLD_STORAGE_DURABLE={value:?}"
                );
                // The warning path must stay non-fatal for local dev either way.
                warn_if_cold_storage_not_durable("/tmp/some-cold-root");
            }
            match saved {
                Some(v) => std::env::set_var("ANALYTICS_COLD_STORAGE_DURABLE", v),
                None => std::env::remove_var("ANALYTICS_COLD_STORAGE_DURABLE"),
            }
        }
    }
    // ── Gap-closure:the durability-warning / env-parse ladder ──────────

    /// Save every env var `from_env` reads so a ladder test can vandalize
    /// the environment and restore it exactly (plain `cargo test` runs the
    /// whole module in one process; nextest isolates it anyway).
    struct EnvSnapshot(Vec<(&'static str, Option<String>)>);

    impl EnvSnapshot {
        fn take(vars: &[&'static str]) -> Self {
            Self(vars.iter().map(|v| (*v, std::env::var(v).ok())).collect())
        }
    }

    impl Drop for EnvSnapshot {
        fn drop(&mut self) {
            for (name, value) in self.0.drain(..) {
                match value {
                    Some(v) => std::env::set_var(name, v),
                    None => std::env::remove_var(name),
                }
            }
        }
    }

    const FROM_ENV_VARS: &[&str] = &[
        "NODE_ENV",
        "DATABASE_URL",
        "REDIS_URL",
        "ANALYTICS_STORAGE_PATH",
        "ANALYTICS_COMPACTION_ENABLED",
        "ANALYTICS_COMPACTION_BATCH_SIZE",
        "ANALYTICS_HOT_RETENTION_DAYS",
        "ANALYTICS_COLD_RETENTION_DAYS",
        "ANALYTICS_STO_HMAC_KEY",
        "CLICKHOUSE_URL",
        "CLICKHOUSE_DATABASE",
        "CLICKHOUSE_USER",
        "CLICKHOUSE_PASSWORD",
        "CLICKHOUSE_MAX_CONNECTIONS",
        "CLICKHOUSE_INSERT_TIMEOUT_SECONDS",
        "CLICKHOUSE_TLS_ENABLED",
        "CLICKHOUSE_CA_CERT_PATH",
    ];

    /// A .env file that CANNOT parse makes `dotenvy::dotenv` fail with a
    /// non-NotFound error — the branch that must be LOUD (the silent
    /// NotFound case — no .env anywhere — stays silent on purpose).
    #[test]
    fn malformed_dotenv_file_is_reported_not_swallowed() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Pre-set so the snapshot captures a Some value and its Drop restores
        // through the set_var arm (the remove_var arm is covered by the
        // ladder tests, whose ambient vars are unset).
        std::env::set_var("DATABASE_URL", "postgres://ci-pin@localhost/ci");
        let _snapshot = EnvSnapshot::take(&["DATABASE_URL"]);
        let dir = std::env::temp_dir().join(format!("apexmail_cfg_env_{}", std::process::id())); // nosemgrep: rust.lang.security.temp-dir.temp-dir — test fixture under a unique pid/uuid path — no predictable-name temp collision
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(dir.join(".env"), "THIS LINE HAS NO EQUALS SIGN\n").expect("bad .env");
        let cwd = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(&dir).expect("chdir");
        let cfg = AnalyticsConfig::from_env();
        std::env::set_current_dir(cwd).expect("restore cwd");
        std::fs::remove_dir_all(&dir).ok();
        // The parse failure is non-fatal: parsing proceeds from the env.
        assert!(
            !cfg.database_url.contains("postgres://postgres:postgres@"),
            "G.7 still holds after a dotenv failure"
        );
    }

    /// The full from_env degradation ladder in ONE hostile environment:
    /// production with an empty database URL refuses the credential-bearing
    /// fallback (G.7) while every other zero/empty value is reset to its
    /// safe default, and the production HMAC requirement is reported (D.2).
    #[test]
    fn from_env_ladder_resets_every_hostile_value_and_refuses_prod_db_fallback() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _snapshot = EnvSnapshot::take(FROM_ENV_VARS);
        std::env::set_var("NODE_ENV", "production");
        // SET (not remove) — dotenvy never overrides an existing var, and a
        // workspace .env would otherwise refill DATABASE_URL.
        std::env::set_var("DATABASE_URL", "");
        std::env::set_var("REDIS_URL", "");
        std::env::set_var("ANALYTICS_STORAGE_PATH", "");
        std::env::set_var("ANALYTICS_COMPACTION_BATCH_SIZE", "0");
        std::env::set_var("ANALYTICS_HOT_RETENTION_DAYS", "0");
        std::env::set_var("ANALYTICS_COLD_RETENTION_DAYS", "0");
        let cfg = AnalyticsConfig::from_env();

        // G.7: production keeps the empty database URL (no invented default).
        assert_eq!(cfg.database_url, "");
        // Every other hostile value was reset to its safe default. The
        // empty-redis reset RE-READS REDIS_URL — an explicitly-empty var is
        // re-applied as-is (a workspace .env would refill a REMOVED var, so
        // the unwrap_or_else literal is shadowed in dotenv environments).
        assert_eq!(cfg.redis_url, "");
        assert_eq!(cfg.storage_path, "/var/lib/apexmail/analytics");
        assert_eq!(cfg.compaction.batch_size, 100_000);
        assert_eq!(cfg.compaction.hot_retention_days, 90);
        assert_eq!(cfg.compaction.cold_retention_days, 730);
    }

    /// OUTSIDE production the empty database URL gets the local
    /// trust-style development default — no credentials embedded.
    #[test]
    fn from_env_development_falls_back_to_the_local_trust_database_url() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _snapshot = EnvSnapshot::take(FROM_ENV_VARS);
        std::env::remove_var("NODE_ENV");
        // SET empty (not remove) — a workspace .env would refill DATABASE_URL
        // because dotenvy never overrides an existing var.
        std::env::set_var("DATABASE_URL", "");
        let cfg = AnalyticsConfig::from_env();
        assert_eq!(
            cfg.database_url,
            "postgres://apexmail@localhost:5432/apexmail"
        );
        assert!(
            !cfg.database_url.contains(':')
                || !cfg
                    .database_url
                    .split('@')
                    .next()
                    .unwrap_or("")
                    .contains("postgres:postgres"),
            "no credential pair"
        );
    }

    /// `validate` rejects each hostile field with a SPECIFIC error — every
    /// guard enumerated (empty urls, zero batch/retention, inverted
    /// retention, out-of-range schedule hours, zero clickhouse connections).
    #[test]
    fn validate_enumerates_every_rejection_reason() {
        let good = AnalyticsConfig {
            database_url: "postgres://u@localhost/db".into(),
            sto_hmac_key: "k".into(),
            ..Default::default()
        };
        assert!(good.validate().is_ok(), "the baseline config is valid");

        let mut cfg = good.clone();
        cfg.database_url = "  ".into();
        assert_eq!(
            cfg.validate().unwrap_err(),
            "DATABASE_URL must not be empty"
        );

        let mut cfg = good.clone();
        cfg.redis_url = "".into();
        assert_eq!(cfg.validate().unwrap_err(), "REDIS_URL must not be empty");

        let mut cfg = good.clone();
        cfg.storage_path = "".into();
        assert_eq!(
            cfg.validate().unwrap_err(),
            "ANALYTICS_STORAGE_PATH must not be empty"
        );

        let mut cfg = good.clone();
        cfg.compaction.batch_size = 0;
        assert_eq!(
            cfg.validate().unwrap_err(),
            "ANALYTICS_COMPACTION_BATCH_SIZE must be > 0"
        );

        let mut cfg = good.clone();
        cfg.compaction.hot_retention_days = 0;
        assert_eq!(cfg.validate().unwrap_err(), "Retention days must be > 0");

        let mut cfg = good.clone();
        cfg.compaction.cold_retention_days = 0;
        assert_eq!(cfg.validate().unwrap_err(), "Retention days must be > 0");

        let mut cfg = good.clone();
        cfg.compaction.cold_retention_days = 10;
        cfg.compaction.hot_retention_days = 90;
        assert_eq!(
            cfg.validate().unwrap_err(),
            "Cold retention days must be >= hot retention days"
        );

        let mut cfg = good.clone();
        cfg.compaction.schedule_hour = 24;
        assert_eq!(
            cfg.validate().unwrap_err(),
            "Schedule hours must be between 0 and 23"
        );

        let mut cfg = good.clone();
        cfg.compaction.schedule_hour = 2;
        cfg.reconciliation.schedule_hour = 99;
        assert_eq!(
            cfg.validate().unwrap_err(),
            "Schedule hours must be between 0 and 23"
        );

        let mut cfg = good.clone();
        cfg.clickhouse.max_connections = 0;
        assert_eq!(
            cfg.validate().unwrap_err(),
            "CLICKHOUSE_MAX_CONNECTIONS must be > 0"
        );
    }

    /// The zero-value reset ladder also runs OUTSIDE production: batch=0,
    /// hot=0, cold=0 and cold<hot are each coerced back to safe defaults
    /// even when the trigger came through a parse of "0".
    #[test]
    fn from_env_zero_values_are_coerced_to_safe_defaults_outside_production() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _snapshot = EnvSnapshot::take(FROM_ENV_VARS);
        std::env::set_var("NODE_ENV", "development");
        std::env::set_var("DATABASE_URL", "postgres://u@localhost/db");
        std::env::set_var("ANALYTICS_COMPACTION_BATCH_SIZE", "0");
        std::env::set_var("ANALYTICS_HOT_RETENTION_DAYS", "365");
        std::env::set_var("ANALYTICS_COLD_RETENTION_DAYS", "30");
        let cfg = AnalyticsConfig::from_env();
        assert_eq!(cfg.compaction.batch_size, 100_000, "batch 0 → default");
        assert_eq!(
            cfg.compaction.cold_retention_days, 365,
            "cold < hot is raised to hot"
        );
    }

    /// D.2:production with a VALID database but an empty HMAC key still
    /// surfaces the loud non-fatal error (and validate rejects it).
    #[test]
    fn from_env_production_without_hmac_key_reports_the_pii_hashing_error() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _snapshot = EnvSnapshot::take(FROM_ENV_VARS);
        std::env::set_var("NODE_ENV", "production");
        std::env::set_var("DATABASE_URL", "postgres://u@localhost/db");
        std::env::set_var("ANALYTICS_STO_HMAC_KEY", "");
        let cfg = AnalyticsConfig::from_env();
        // The run still yields a config (fail-loud, not fail-closed), but
        // validation refuses it.
        assert!(cfg.validate().is_err());
    }
}
