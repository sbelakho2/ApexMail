//! Configuration loaded from environment variables.
//!
//! Mirrors the Zod-validated config from the TypeScript API,
//! with production-safety checks on secret lengths.

use std::env;
use std::time::Duration;

/// Top-level configuration for the API server.
#[derive(Debug, Clone)]
pub struct Config {
    // ── Server ──────────────────────────────────────────────
    pub port: u16,
    pub host: String,
    pub base_url: String,
    pub environment: Environment,

    // ── Database ────────────────────────────────────────────
    pub db_host: String,
    pub db_port: u16,
    pub db_name: String,
    pub db_user: String,
    pub db_password: String,
    pub db_max_connections: u32,

    // ── Redis ───────────────────────────────────────────────
    pub redis_host: String,
    pub redis_port: u16,
    pub redis_password: Option<String>,
    pub redis_db: u8,

    // ── Auth ────────────────────────────────────────────────
    pub jwt_secret: String,
    pub jwt_expiry: Duration,
    pub api_key_hash_secret: String,

    // ── Rate limiting ───────────────────────────────────────
    pub rate_limit_window_ms: u64,
    pub rate_limit_max_requests: u64,

    // ── CORS ────────────────────────────────────────────────
    pub cors_origins: Vec<String>,
    pub trusted_proxies: Vec<String>,

    // ── Webhooks ────────────────────────────────────────────
    pub webhook_signing_secret: String,
    pub webhook_timeout_ms: u64,
    pub webhook_max_retries: u32,

    // ── Idempotency ─────────────────────────────────────────
    pub idempotency_ttl_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Development,
    Staging,
    Production,
}

impl Environment {
    pub fn is_production(&self) -> bool {
        matches!(self, Self::Production)
    }
}

/// Errors that can occur when building the config.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required environment variable: {0}")]
    MissingVar(String),
    #[error("invalid value for {var}: {reason}")]
    Invalid { var: String, reason: String },
    #[error("production security check failed: {0}")]
    SecurityCheck(String),
}

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_required(key: &str) -> Result<String, ConfigError> {
    env::var(key).map_err(|_| ConfigError::MissingVar(key.to_string()))
}

fn parse_u16(key: &str, val: &str) -> Result<u16, ConfigError> {
    val.parse::<u16>().map_err(|_| ConfigError::Invalid {
        var: key.to_string(),
        reason: format!("expected u16, got '{val}'"),
    })
}

fn parse_u32(key: &str, val: &str) -> Result<u32, ConfigError> {
    val.parse::<u32>().map_err(|_| ConfigError::Invalid {
        var: key.to_string(),
        reason: format!("expected u32, got '{val}'"),
    })
}

fn parse_u64(key: &str, val: &str) -> Result<u64, ConfigError> {
    val.parse::<u64>().map_err(|_| ConfigError::Invalid {
        var: key.to_string(),
        reason: format!("expected u64, got '{val}'"),
    })
}

fn parse_u8(key: &str, val: &str) -> Result<u8, ConfigError> {
    val.parse::<u8>().map_err(|_| ConfigError::Invalid {
        var: key.to_string(),
        reason: format!("expected u8, got '{val}'"),
    })
}

fn parse_duration_hours(key: &str, val: &str) -> Result<Duration, ConfigError> {
    // Accept formats: "24h", "1h", or plain seconds
    let trimmed = val.trim();
    if let Some(h) = trimmed.strip_suffix('h') {
        let hours: u64 = h.parse().map_err(|_| ConfigError::Invalid {
            var: key.to_string(),
            reason: format!("invalid hour value: '{h}'"),
        })?;
        Ok(Duration::from_secs(hours * 3600))
    } else {
        let secs: u64 = trimmed.parse().map_err(|_| ConfigError::Invalid {
            var: key.to_string(),
            reason: format!("expected duration like '24h' or seconds, got '{val}'"),
        })?;
        Ok(Duration::from_secs(secs))
    }
}

fn parse_csv(val: &str) -> Vec<String> {
    let items: Vec<String> = val.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    
    // Fix #60: Warn if both wildcard and specific origins are present.
    // With "*" in the list, specific origins are ignored.
    if items.iter().any(|s| s == "*") && items.len() > 1 {
        tracing::warn!(
            "CORS_ORIGINS contains '*' along with {} other origin(s). \
             The wildcard will take precedence and specific origins will be ignored.",
            items.len() - 1
        );
    }
    items
}

impl Config {
    /// Load configuration from environment variables.
    pub fn from_env() -> Result<Self, ConfigError> {
        let environment = match env_or("ENVIRONMENT", "development").to_lowercase().as_str() {
            "production" | "prod" => Environment::Production,
            "staging" => Environment::Staging,
            _ => Environment::Development,
        };

        let jwt_secret = env_required("JWT_SECRET")?;
        let api_key_hash_secret = env_required("API_KEY_HASH_SECRET")?;
        let webhook_signing_secret = env_required("WEBHOOK_SIGNING_SECRET")?;

        let config = Config {
            port: parse_u16("PORT", &env_or("PORT", "3000"))?,
            host: env_or("HOST", "0.0.0.0"),
            base_url: env_or("BASE_URL", "http://localhost:3000"),
            environment,

            db_host: env_or("DB_HOST", "localhost"),
            db_port: parse_u16("DB_PORT", &env_or("DB_PORT", "5432"))?,
            db_name: env_or("DB_NAME", "apexmail"),
            db_user: env_or("DB_USER", "apexmail"),
            db_password: env_or("DB_PASSWORD", ""),
            db_max_connections: parse_u32(
                "DB_MAX_CONNECTIONS",
                &env_or("DB_MAX_CONNECTIONS", "20"),
            )?,

            redis_host: env_or("REDIS_HOST", "localhost"),
            redis_port: parse_u16("REDIS_PORT", &env_or("REDIS_PORT", "6379"))?,
            redis_password: env::var("REDIS_PASSWORD").ok().filter(|s| !s.is_empty()),
            redis_db: parse_u8("REDIS_DB", &env_or("REDIS_DB", "0"))?,

            jwt_secret,
            jwt_expiry: parse_duration_hours("JWT_EXPIRY", &env_or("JWT_EXPIRY", "24h"))?,
            api_key_hash_secret,

            rate_limit_window_ms: parse_u64(
                "RATE_LIMIT_WINDOW_MS",
                &env_or("RATE_LIMIT_WINDOW_MS", "60000"),
            )?,
            rate_limit_max_requests: parse_u64(
                "RATE_LIMIT_MAX_REQUESTS",
                &env_or("RATE_LIMIT_MAX_REQUESTS", "1000"),
            )?,

            cors_origins: parse_csv(&env_or("CORS_ORIGINS", "*")),
            trusted_proxies: parse_csv(&env_or("TRUSTED_PROXIES", "")),

            webhook_signing_secret,
            webhook_timeout_ms: parse_u64(
                "WEBHOOK_TIMEOUT_MS",
                &env_or("WEBHOOK_TIMEOUT_MS", "5000"),
            )?,
            webhook_max_retries: parse_u32(
                "WEBHOOK_MAX_RETRIES",
                &env_or("WEBHOOK_MAX_RETRIES", "3"),
            )?,

            idempotency_ttl_seconds: parse_u64(
                "IDEMPOTENCY_TTL_SECONDS",
                &env_or("IDEMPOTENCY_TTL_SECONDS", "86400"),
            )?,
        };

        // Production security checks
        if config.environment.is_production() {
            config.validate_production()?;
        }

        Ok(config)
    }

    /// Build a Postgres connection URL from the config.
    ///
    /// User and password are percent-encoded so that special characters
    /// (like `@`, `:`, `/`) do not corrupt the URL.
    pub fn database_url(&self) -> String {
        use url::form_urlencoded;
        let encoded_user: String = form_urlencoded::byte_serialize(self.db_user.as_bytes()).collect();
        let encoded_pass: String = form_urlencoded::byte_serialize(self.db_password.as_bytes()).collect();
        format!(
            "postgres://{}:{}@{}:{}/{}",
            encoded_user, encoded_pass, self.db_host, self.db_port, self.db_name
        )
    }

    /// Build a Redis connection URL from the config.
    pub fn redis_url(&self) -> String {
        match &self.redis_password {
            Some(pw) => format!(
                "redis://:{}@{}:{}/{}",
                pw, self.redis_host, self.redis_port, self.redis_db
            ),
            None => format!(
                "redis://{}:{}/{}",
                self.redis_host, self.redis_port, self.redis_db
            ),
        }
    }

    /// Validate secrets and settings for production safety.
    fn validate_production(&self) -> Result<(), ConfigError> {
        if self.jwt_secret.len() < 32 {
            return Err(ConfigError::SecurityCheck(
                "JWT_SECRET must be at least 32 characters in production".into(),
            ));
        }
        if self.api_key_hash_secret.len() < 32 {
            return Err(ConfigError::SecurityCheck(
                "API_KEY_HASH_SECRET must be at least 32 characters in production".into(),
            ));
        }
        if self.webhook_signing_secret.len() < 32 {
            return Err(ConfigError::SecurityCheck(
                "WEBHOOK_SIGNING_SECRET must be at least 32 characters in production".into(),
            ));
        }
        // Fix #3: Reject empty DB password in production
        if self.db_password.is_empty() {
            return Err(ConfigError::SecurityCheck(
                "DB_PASSWORD must not be empty in production".into(),
            ));
        }
        // Fix #4: Check all secrets for dev defaults (including webhook_signing_secret)
        let dev_defaults = ["dev-secret", "secret", "changeme", "password"];
        for secret_name in ["jwt_secret", "api_key_hash_secret", "webhook_signing_secret"] {
            let value = match secret_name {
                "jwt_secret" => &self.jwt_secret,
                "api_key_hash_secret" => &self.api_key_hash_secret,
                "webhook_signing_secret" => &self.webhook_signing_secret,
                _ => unreachable!(),
            };
            if dev_defaults.iter().any(|d| value == *d) {
                return Err(ConfigError::SecurityCheck(
                    format!("{secret_name} must not use a dev default value in production"),
                ));
            }
        }
        if self.cors_origins.iter().any(|o| o == "*") {
            return Err(ConfigError::SecurityCheck(
                "wildcard CORS origin (*) is not allowed in production".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration_hours() {
        let d = parse_duration_hours("JWT_EXPIRY", "24h").unwrap();
        assert_eq!(d, Duration::from_secs(24 * 3600));

        let d = parse_duration_hours("JWT_EXPIRY", "3600").unwrap();
        assert_eq!(d, Duration::from_secs(3600));

        assert!(parse_duration_hours("JWT_EXPIRY", "invalid").is_err());
    }

    #[test]
    fn test_parse_csv() {
        let v = parse_csv("a, b, c");
        assert_eq!(v, vec!["a", "b", "c"]);

        let v = parse_csv("*");
        assert_eq!(v, vec!["*"]);

        let v = parse_csv("");
        assert!(v.is_empty());
    }

    #[test]
    fn test_production_security_checks() {
        let config = Config {
            port: 3000,
            host: "0.0.0.0".into(),
            base_url: "http://localhost:3000".into(),
            environment: Environment::Production,
            db_host: "localhost".into(),
            db_port: 5432,
            db_name: "apexmail".into(),
            db_user: "apexmail".into(),
            db_password: "password".into(),
            db_max_connections: 20,
            redis_host: "localhost".into(),
            redis_port: 6379,
            redis_password: None,
            redis_db: 0,
            jwt_secret: "short".into(), // too short
            jwt_expiry: Duration::from_secs(86400),
            api_key_hash_secret: "also-short".into(),
            rate_limit_window_ms: 60000,
            rate_limit_max_requests: 1000,
            cors_origins: vec!["https://app.example.com".into()],
            trusted_proxies: vec![],
            webhook_signing_secret: "short-webhook".into(),
            webhook_timeout_ms: 5000,
            webhook_max_retries: 3,
            idempotency_ttl_seconds: 86400,
        };
        assert!(config.validate_production().is_err());
    }
}
