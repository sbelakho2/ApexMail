//! Configuration for the Isolation service.

use zeroize::Zeroizing;

use serde::{Deserialize, Serialize};

// ── Isolation Level ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum IsolationLevel {
    Shared,
    DedicatedSchema,
    DedicatedDatabase,
    DedicatedInstance,
}

impl std::fmt::Display for IsolationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shared => write!(f, "shared"),
            Self::DedicatedSchema => write!(f, "dedicated_schema"),
            Self::DedicatedDatabase => write!(f, "dedicated_database"),
            Self::DedicatedInstance => write!(f, "dedicated_instance"),
        }
    }
}

impl IsolationLevel {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "shared" => Some(Self::Shared),
            "dedicated_schema" => Some(Self::DedicatedSchema),
            "dedicated_database" => Some(Self::DedicatedDatabase),
            "dedicated_instance" => Some(Self::DedicatedInstance),
            _ => None,
        }
    }
}

// ── Quota Config ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaConfig {
    pub emails_per_month: i64,
    pub storage_bytes: i64,
    pub api_requests_per_minute: i64,
    pub webhooks_per_month: i64,
    pub contacts_limit: i64,
    pub templates_limit: i64,
    pub domains_limit: i64,
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            emails_per_month: 50_000,
            storage_bytes: 1_073_741_824, // 1 GB
            api_requests_per_minute: 100,
            webhooks_per_month: 10_000,
            contacts_limit: 10_000,
            templates_limit: 100,
            domains_limit: 5,
        }
    }
}

// ── Database / Redis / Security Config ─────────────────────

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub user: String,
    pub password: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub host: String,
    pub port: u16,
    pub password: Option<String>,
    pub db: u8,
}

impl RedisConfig {
    pub fn url(&self) -> String {
        if let Some(pw) = &self.password {
            // Percent-encode the password (RFC 3986) so special characters
            // like `@`, `:`, `/`, `+` cannot corrupt the URL.
            format!(
                "redis://:{}@{}:{}/{}",
                urlencoding::encode(pw),
                self.host,
                self.port,
                self.db
            )
        } else {
            format!("redis://{}:{}/{}", self.host, self.port, self.db)
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub encryption_key: Zeroizing<String>,
    pub data_key_rotation_days: i64,
    pub audit_retention_days: i64,
    pub session_timeout_minutes: i64,
}

#[derive(Debug, Clone)]
pub struct TenantConfig {
    pub max_workspaces_per_org: i32,
    pub max_users_per_workspace: i32,
    pub default_quota: QuotaConfig,
}

#[derive(Debug, Clone)]
pub struct CorsConfig {
    pub origins: Vec<String>,
}

// ── Top-Level Config ───────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub environment: String,
    pub internal_api_key: String,
    pub internal_api_keys: Vec<String>,
    /// Audit SM5 F15: require the edge-supplied `x-org-id` claim header on
    /// every request. The claim model previously failed OPEN when the
    /// header was absent ("internal service-to-service traffic"), so a
    /// client whose header was not stripped by the edge could reach any
    /// organization. Defaults to TRUE in production (fail-closed) and can
    /// be forced with `ISOLATION_REQUIRE_ORG_CLAIM=true|false`.
    pub require_org_claim: bool,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub tenant: TenantConfig,
    pub security: SecurityConfig,
    pub cors: CorsConfig,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_or_i64(key: &str, default: i64) -> i64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
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

fn env_or_i32(key: &str, default: i32) -> i32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn generated_runtime_secret(label: &str) -> String {
    format!("{label}-{}", uuid::Uuid::new_v4().simple())
}

/// Errors raised while loading [`Config`] from the environment.
///
/// Hand-rolled mirror of the workspace's audit convention (`api-server`'s
/// `thiserror` `ConfigError`); this crate does not depend on `thiserror`,
/// so the `Display`/`Error` impls are spelled out. Same shape as the `ha`
/// crate's `ConfigError`.
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
    /// Load configuration from the environment.
    ///
    /// SEC (external audit): production refusal for missing
    /// `TENANT_ENCRYPTION_KEY` / `ISOLATION_INTERNAL_API_KEY` used to run
    /// `std::process::exit(78)` from INSIDE this loader — untestable — and
    /// the dev/test fallback generated ephemeral keys SILENTLY. `from_env`
    /// is now fallible (the same shape as the `ha`/`compliance` crates):
    /// the raw environment values are read BEFORE anything is bound,
    /// production REFUSES (returning [`ConfigError::MissingVar`] naming the
    /// variable — the server binary logs it and exits 78 / EX_CONFIG), and
    /// development/test generation is ephemeral AND logged. No synthetic
    /// production credential is ever generated.
    pub fn from_env() -> Result<Self, ConfigError> {
        let environment = env_or("NODE_ENV", "development");
        let is_production = environment.eq_ignore_ascii_case("production")
            || environment.eq_ignore_ascii_case("prod");

        // Raw env values only, read BEFORE anything is bound: the production
        // checks must observe exactly what the environment provided (the
        // generation fallbacks below are unreachable in production).
        let encryption_key_env = std::env::var("TENANT_ENCRYPTION_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let internal_api_key_env = std::env::var("ISOLATION_INTERNAL_API_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let internal_api_keys_env: Vec<String> = std::env::var("ISOLATION_INTERNAL_API_KEYS")
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string)
                    .collect()
            })
            .unwrap_or_default();

        if is_production {
            // No synthetic production credentials, ever: a missing variable
            // is a deployment error. A regenerated tenant encryption key
            // would leave every persisted tenant ciphertext unreadable
            // after a restart, and a regenerated internal API key breaks
            // every service-to-service caller.
            if encryption_key_env.is_none() {
                return Err(ConfigError::MissingVar("TENANT_ENCRYPTION_KEY".into()));
            }
            if internal_api_key_env.is_none() && internal_api_keys_env.is_empty() {
                return Err(ConfigError::MissingVar("ISOLATION_INTERNAL_API_KEY".into()));
            }
        }

        // Development/test: ephemeral values are acceptable — every restart
        // rotates them — but they must be loud.
        let encryption_key = encryption_key_env.unwrap_or_else(|| {
            tracing::warn!(
                "SECURITY: TENANT_ENCRYPTION_KEY missing in development; generated an \
                 ephemeral runtime key (redacted)"
            );
            generated_runtime_secret("tenant-encryption-key")
        });
        let internal_api_key = internal_api_key_env
            .or_else(|| internal_api_keys_env.first().cloned())
            .unwrap_or_else(|| {
                tracing::warn!(
                    "SECURITY: ISOLATION_INTERNAL_API_KEY missing in development; generated \
                     an ephemeral runtime key (redacted)"
                );
                generated_runtime_secret("isolation-internal-api-key")
            });
        let mut internal_api_keys = internal_api_keys_env;
        if !internal_api_key.trim().is_empty()
            && !internal_api_keys.iter().any(|key| key == &internal_api_key)
        {
            internal_api_keys.insert(0, internal_api_key.clone());
        }

        Ok(Self {
            port: env_or_u16("ISOLATION_PORT", 4500),
            environment,
            internal_api_key,
            internal_api_keys,
            // Audit SM5 F15: fail-closed default — production REQUIRES the
            // org claim header; an explicit env knob can force either mode.
            require_org_claim: std::env::var("ISOLATION_REQUIRE_ORG_CLAIM")
                .ok()
                .map(|v| {
                    let v = v.trim().to_ascii_lowercase();
                    v == "true" || v == "1" || v == "yes" || v == "on"
                })
                .unwrap_or(is_production),
            database: DatabaseConfig {
                host: env_or("ISOLATION_DB_HOST", "127.0.0.1"),
                port: env_or_u16("ISOLATION_DB_PORT", 5432),
                database: env_or("ISOLATION_DB_NAME", "apexmail_isolation"),
                user: env_or("ISOLATION_DB_USER", "apexmail"),
                password: env_or("ISOLATION_DB_PASSWORD", ""),
                max_connections: env_or_u32("ISOLATION_DB_MAX_CONN", 20),
            },
            redis: RedisConfig {
                host: env_or("ISOLATION_REDIS_HOST", "127.0.0.1"),
                port: env_or_u16("ISOLATION_REDIS_PORT", 6379),
                password: std::env::var("ISOLATION_REDIS_PASSWORD").ok(),
                db: std::env::var("ISOLATION_REDIS_DB")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(3),
            },
            tenant: TenantConfig {
                max_workspaces_per_org: env_or_i32("MAX_WORKSPACES_PER_ORG", 50),
                max_users_per_workspace: env_or_i32("MAX_USERS_PER_WORKSPACE", 100),
                default_quota: QuotaConfig::default(),
            },
            security: SecurityConfig {
                encryption_key: Zeroizing::new(encryption_key),
                data_key_rotation_days: env_or_i64("DATA_KEY_ROTATION_DAYS", 90),
                audit_retention_days: env_or_i64("AUDIT_RETENTION_DAYS", 365),
                session_timeout_minutes: env_or_i64("SESSION_TIMEOUT_MINUTES", 30),
            },
            cors: CorsConfig {
                origins: env_or(
                    "CORS_ORIGINS",
                    "http://localhost:3000,http://127.0.0.1:3000",
                )
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        // SEC fix: from_env is fallible now (production refuses synthetic
        // credentials); the default development test environment must load.
        let cfg = Config::from_env().expect("isolation config loads in development");
        assert_eq!(cfg.port, 4500);
        assert_eq!(cfg.database.max_connections, 20);
        assert_eq!(cfg.tenant.max_workspaces_per_org, 50);
    }

    #[test]
    fn test_quota_defaults() {
        let q = QuotaConfig::default();
        assert_eq!(q.emails_per_month, 50_000);
        assert_eq!(q.contacts_limit, 10_000);
    }

    #[test]
    fn test_isolation_level_parse() {
        assert_eq!(
            IsolationLevel::parse("shared"),
            Some(IsolationLevel::Shared)
        );
        assert_eq!(
            IsolationLevel::parse("dedicated_schema"),
            Some(IsolationLevel::DedicatedSchema)
        );
        assert!(IsolationLevel::parse("invalid").is_none());
    }

    #[test]
    fn test_redis_url_no_password() {
        let r = RedisConfig {
            host: "localhost".into(),
            port: 6379,
            password: None,
            db: 0,
        };
        assert_eq!(r.url(), "redis://localhost:6379/0");
    }

    #[test]
    fn test_redis_url_with_password() {
        let r = RedisConfig {
            host: "redis.example.com".into(),
            port: 6380,
            password: Some("secret".into()),
            db: 2,
        };
        assert_eq!(r.url(), "redis://:secret@redis.example.com:6380/2");
    }

    #[test]
    fn test_redis_url_percent_encodes_special_characters() {
        let r = RedisConfig {
            host: "redis.example.com".into(),
            port: 6380,
            password: Some("p@ss:word/with space+plus".into()),
            db: 2,
        };
        assert_eq!(
            r.url(),
            "redis://:p%40ss%3Aword%2Fwith%20space%2Bplus@redis.example.com:6380/2"
        );
    }

    // ── SEC: production requires real secrets ──────────────────

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

    /// Production + missing TENANT_ENCRYPTION_KEY → from_env errs with a
    /// message naming the variable BEFORE anything is bound. A generated key
    /// here would leave every persisted tenant ciphertext unreadable after a
    /// restart.
    #[test]
    fn test_production_missing_tenant_encryption_key_is_refused() {
        set_env("NODE_ENV", "production");
        unset_env("TENANT_ENCRYPTION_KEY");
        set_env("ISOLATION_INTERNAL_API_KEY", "prod-internal-key");

        let err = Config::from_env().unwrap_err();
        assert!(matches!(err, ConfigError::MissingVar(_)));
        assert!(
            err.to_string().contains("TENANT_ENCRYPTION_KEY"),
            "error must name the missing variable, got: {err}"
        );
    }

    /// Production + missing ISOLATION_INTERNAL_API_KEY (and no key list) →
    /// same refusal, naming the variable. A regenerated key would break
    /// every service-to-service caller.
    #[test]
    fn test_production_missing_internal_api_key_is_refused() {
        set_env("NODE_ENV", "production");
        set_env(
            "TENANT_ENCRYPTION_KEY",
            "prod-tenant-encryption-key-0123456789abcdef",
        );
        unset_env("ISOLATION_INTERNAL_API_KEY");
        unset_env("ISOLATION_INTERNAL_API_KEYS");

        let err = Config::from_env().unwrap_err();
        assert!(matches!(err, ConfigError::MissingVar(_)));
        assert!(
            err.to_string().contains("ISOLATION_INTERNAL_API_KEY"),
            "error must name the missing variable, got: {err}"
        );
    }

    /// Whitespace-only values count as missing (the trim contract).
    #[test]
    fn test_production_whitespace_only_secrets_are_refused() {
        set_env("NODE_ENV", "production");
        set_env("TENANT_ENCRYPTION_KEY", "   ");
        set_env("ISOLATION_INTERNAL_API_KEY", "\t");

        let err = Config::from_env().unwrap_err();
        assert!(
            err.to_string().contains("TENANT_ENCRYPTION_KEY"),
            "error must name the first missing variable, got: {err}"
        );
    }

    /// Production + explicit values → loaded verbatim; nothing is generated
    /// or replaced.
    #[test]
    fn test_production_explicit_secrets_are_used_verbatim() {
        set_env("NODE_ENV", "production");
        set_env(
            "TENANT_ENCRYPTION_KEY",
            "explicit-prod-tenant-encryption-key",
        );
        set_env("ISOLATION_INTERNAL_API_KEY", "explicit-prod-internal-key");
        unset_env("ISOLATION_INTERNAL_API_KEYS");

        let cfg = Config::from_env().expect("production config with explicit secrets must load");
        assert_eq!(
            cfg.security.encryption_key.as_str(),
            "explicit-prod-tenant-encryption-key"
        );
        assert_eq!(cfg.internal_api_key, "explicit-prod-internal-key");
        assert!(!cfg
            .internal_api_key
            .starts_with("isolation-internal-api-key-"));
        assert!(!cfg
            .security
            .encryption_key
            .starts_with("tenant-encryption-key-"));
    }

    /// Production accepts `ISOLATION_INTERNAL_API_KEYS` alone (pre-existing
    /// behavior): the first list entry becomes the primary key — no
    /// generation, no refusal.
    #[test]
    fn test_production_accepts_key_list_without_single_key() {
        set_env("NODE_ENV", "production");
        set_env(
            "TENANT_ENCRYPTION_KEY",
            "prod-tenant-encryption-key-0123456789abcdef",
        );
        unset_env("ISOLATION_INTERNAL_API_KEY");
        set_env("ISOLATION_INTERNAL_API_KEYS", "prod-key-one, prod-key-two");

        let cfg = Config::from_env().expect("production key list must load");
        assert_eq!(cfg.internal_api_key, "prod-key-one");
        assert!(cfg.internal_api_keys.contains(&"prod-key-one".to_string()));
        assert!(cfg.internal_api_keys.contains(&"prod-key-two".to_string()));
    }

    /// Development + missing values → ephemeral generation works AND is
    /// logged (both values, both warnings).
    #[test]
    fn test_development_missing_secrets_generate_ephemeral_and_are_logged() {
        set_env("NODE_ENV", "development");
        unset_env("TENANT_ENCRYPTION_KEY");
        unset_env("ISOLATION_INTERNAL_API_KEY");
        unset_env("ISOLATION_INTERNAL_API_KEYS");

        let logs = capture_logs(|| {
            let cfg = Config::from_env().expect("development config must load");
            assert!(
                cfg.security
                    .encryption_key
                    .starts_with("tenant-encryption-key-"),
                "ephemeral encryption key expected (value redacted)"
            );
            assert!(
                cfg.internal_api_key
                    .starts_with("isolation-internal-api-key-"),
                "ephemeral internal key expected, got: {}",
                cfg.internal_api_key
            );
        });
        assert!(
            logs.contains("TENANT_ENCRYPTION_KEY"),
            "encryption key generation must be logged, got: {logs}"
        );
        assert!(
            logs.contains("ISOLATION_INTERNAL_API_KEY"),
            "internal key generation must be logged, got: {logs}"
        );
    }

    /// Pins the generated-vs-required transition: the SAME missing variables
    /// yield an ephemeral value in development and a hard error in production.
    #[test]
    fn test_generated_vs_required_transition_is_pinned_by_environment() {
        unset_env("TENANT_ENCRYPTION_KEY");
        unset_env("ISOLATION_INTERNAL_API_KEY");
        unset_env("ISOLATION_INTERNAL_API_KEYS");

        set_env("NODE_ENV", "development");
        let dev = Config::from_env().expect("development generates ephemeral values");
        assert!(dev
            .security
            .encryption_key
            .starts_with("tenant-encryption-key-"));
        assert!(dev
            .internal_api_key
            .starts_with("isolation-internal-api-key-"));

        set_env("NODE_ENV", "production");
        let prod_err = Config::from_env().unwrap_err();
        assert!(
            prod_err.to_string().contains("TENANT_ENCRYPTION_KEY"),
            "production refuses the first missing variable, got: {prod_err}"
        );
    }
}
