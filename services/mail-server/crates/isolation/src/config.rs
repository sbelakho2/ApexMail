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
            format!("redis://:{}@{}:{}/{}", pw, self.host, self.port, self.db)
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

impl Config {
    pub fn from_env() -> Self {
        let environment = env_or("NODE_ENV", "development");
        let is_production = environment.eq_ignore_ascii_case("production")
            || environment.eq_ignore_ascii_case("prod");
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
        if is_production && encryption_key_env.is_none() {
            tracing::error!(
                "SECURITY: TENANT_ENCRYPTION_KEY is required in production. \
                 Refusing to start with an ephemeral generated key — set the env \
                 variable to a 32-byte hex value and restart."
            );
            std::process::exit(78); // EX_CONFIG
        }
        if is_production && internal_api_key_env.is_none() && internal_api_keys_env.is_empty() {
            tracing::error!(
                "SECURITY: ISOLATION_INTERNAL_API_KEY is required in production. \
                 Refusing to start with an ephemeral generated key — set the env \
                 variable and restart."
            );
            std::process::exit(78); // EX_CONFIG
        }
        let encryption_key =
            encryption_key_env.unwrap_or_else(|| generated_runtime_secret("tenant-encryption-key"));
        let internal_api_key = internal_api_key_env.unwrap_or_else(|| {
            internal_api_keys_env
                .first()
                .cloned()
                .unwrap_or_else(|| generated_runtime_secret("isolation-internal-api-key"))
        });
        let mut internal_api_keys = internal_api_keys_env;
        if !internal_api_key.trim().is_empty()
            && !internal_api_keys.iter().any(|key| key == &internal_api_key)
        {
            internal_api_keys.insert(0, internal_api_key.clone());
        }

        Self {
            port: env_or_u16("ISOLATION_PORT", 4500),
            environment,
            internal_api_key,
            internal_api_keys,
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let cfg = Config::from_env();
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
}
