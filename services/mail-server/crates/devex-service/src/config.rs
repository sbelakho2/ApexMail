//! DevEx service configuration — loaded from environment variables.

use std::env;

/// Configuration for the DevEx service.
#[derive(Debug, Clone)]
pub struct DevExConfig {
    pub port: u16,
    pub host: String,
    pub database_url: String,
    pub redis_url: String,
    pub webhook_signing_secret: String,
    pub cors_origins: Vec<String>,
    pub api_base_url: String,
    pub docs_base_url: String,
    pub current_api_version: String,
    pub supported_api_versions: Vec<String>,
    pub deprecated_api_versions: Vec<String>,
    pub sandbox_enabled: bool,
    pub max_webhook_endpoints_per_tenant: u32,
    pub node_env: String,
}

impl Default for DevExConfig {
    fn default() -> Self {
        Self {
            port: 4200,
            host: "0.0.0.0".into(),
            database_url: String::new(),
            redis_url: String::new(),
            webhook_signing_secret: String::new(),
            cors_origins: vec!["*".into()],
            api_base_url: "https://api.apexmail.ee".into(),
            docs_base_url: "https://docs.apexmail.ee".into(),
            current_api_version: "2024-01".into(),
            supported_api_versions: vec![
                "2024-01".into(),
                "2023-10".into(),
                "2023-06".into(),
            ],
            deprecated_api_versions: vec!["2023-01".into(), "2022-10".into()],
            sandbox_enabled: true,
            max_webhook_endpoints_per_tenant: 10,
            node_env: "development".into(),
        }
    }
}

impl DevExConfig {
    /// Load configuration from environment variables, falling back to defaults.
    pub fn from_env() -> Result<Self, ConfigError> {
        let node_env = env::var("NODE_ENV").unwrap_or_else(|_| "development".into());

        let cors_origins: Vec<String> = env::var("CORS_ORIGINS")
            .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
            .unwrap_or_else(|_| vec!["*".into()]);

        // Security: disallow wildcard CORS in production
        if node_env != "development" && cors_origins.contains(&"*".to_string()) {
            return Err(ConfigError::SecurityViolation(
                "Wildcard CORS origins are not allowed outside development".into(),
            ));
        }

        let supported_api_versions: Vec<String> = env::var("SUPPORTED_API_VERSIONS")
            .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_else(|_| vec![
                "2024-01".into(),
                "2023-10".into(),
                "2023-06".into(),
            ]);

        let deprecated_api_versions: Vec<String> = env::var("DEPRECATED_API_VERSIONS")
            .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_else(|_| vec!["2023-01".into(), "2022-10".into()]);

        Ok(Self {
            port: env::var("PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(4200),
            host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            database_url: env::var("DATABASE_URL").unwrap_or_default(),
            redis_url: env::var("REDIS_URL").unwrap_or_default(),
            webhook_signing_secret: env::var("WEBHOOK_SIGNING_SECRET").unwrap_or_default(),
            cors_origins,
            api_base_url: env::var("API_BASE_URL")
                .unwrap_or_else(|_| "https://api.apexmail.ee".into()),
            docs_base_url: env::var("DOCS_BASE_URL")
                .unwrap_or_else(|_| "https://docs.apexmail.ee".into()),
            current_api_version: env::var("CURRENT_API_VERSION")
                .unwrap_or_else(|_| "2024-01".into()),
            supported_api_versions,
            deprecated_api_versions,
            sandbox_enabled: env::var("SANDBOX_ENABLED")
                .map(|v| v != "false")
                .unwrap_or(true),
            max_webhook_endpoints_per_tenant: env::var("MAX_WEBHOOK_ENDPOINTS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
            node_env,
        })
    }

    /// Check whether a given API version string is currently supported (not deprecated).
    pub fn is_version_supported(&self, version: &str) -> bool {
        self.supported_api_versions.iter().any(|v| v == version)
    }

    /// Check whether a given API version string is deprecated.
    pub fn is_version_deprecated(&self, version: &str) -> bool {
        self.deprecated_api_versions.iter().any(|v| v == version)
    }
}

/// Errors that can occur while loading configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required environment variable: {0}")]
    MissingVar(String),
    #[error("security violation: {0}")]
    SecurityViolation(String),
    #[error("invalid value: {0}")]
    InvalidValue(String),
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = DevExConfig::default();
        assert_eq!(cfg.port, 4200);
        assert_eq!(cfg.host, "0.0.0.0");
        assert_eq!(cfg.current_api_version, "2024-01");
        assert_eq!(cfg.supported_api_versions.len(), 3);
        assert_eq!(cfg.deprecated_api_versions.len(), 2);
        assert!(cfg.sandbox_enabled);
    }

    #[test]
    fn test_is_version_supported() {
        let cfg = DevExConfig::default();
        assert!(cfg.is_version_supported("2024-01"));
        assert!(cfg.is_version_supported("2023-10"));
        assert!(!cfg.is_version_supported("2022-10"));
        assert!(!cfg.is_version_supported("9999-01"));
    }

    #[test]
    fn test_is_version_deprecated() {
        let cfg = DevExConfig::default();
        assert!(cfg.is_version_deprecated("2023-01"));
        assert!(cfg.is_version_deprecated("2022-10"));
        assert!(!cfg.is_version_deprecated("2024-01"));
    }
}
