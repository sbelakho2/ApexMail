use serde::{Deserialize, Serialize};
use std::env;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Sensitive string wrapper that zeroizes on drop ─────────────────────

/// A wrapper for sensitive strings that zeroizes memory on drop.
/// This prevents secrets from lingering in memory after use.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(s: String) -> Self {
        Self(s)
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

fn generated_dev_secret(label: &str) -> String {
    format!("dev-{label}-{}", uuid::Uuid::new_v4().simple())
}

// ── Enums ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnterprisePlan {
    Starter,
    Business,
    Scale,
    Enterprise,
    Private,
    Custom,
}

impl std::fmt::Display for EnterprisePlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Starter => write!(f, "starter"),
            Self::Business => write!(f, "business"),
            Self::Scale => write!(f, "scale"),
            Self::Enterprise => write!(f, "enterprise"),
            Self::Private => write!(f, "private"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SSOProviderType {
    Saml,
    Oidc,
    Okta,
    AzureAd,
    Google,
}

impl std::fmt::Display for SSOProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Saml => write!(f, "saml"),
            Self::Oidc => write!(f, "oidc"),
            Self::Okta => write!(f, "okta"),
            Self::AzureAd => write!(f, "azure_ad"),
            Self::Google => write!(f, "google"),
        }
    }
}

impl std::str::FromStr for SSOProviderType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "saml" => Ok(Self::Saml),
            "oidc" => Ok(Self::Oidc),
            "okta" => Ok(Self::Okta),
            "azure_ad" => Ok(Self::AzureAd),
            "google" => Ok(Self::Google),
            _ => Err(format!("Unknown SSO provider: {s}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VolumeAllocationMode {
    Fixed,
    Shared,
    Burst,
}

impl std::str::FromStr for VolumeAllocationMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "fixed" => Ok(Self::Fixed),
            "shared" => Ok(Self::Shared),
            "burst" => Ok(Self::Burst),
            _ => Err(format!("Unknown volume allocation mode: {s}")),
        }
    }
}

impl std::fmt::Display for VolumeAllocationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fixed => write!(f, "fixed"),
            Self::Shared => write!(f, "shared"),
            Self::Burst => write!(f, "burst"),
        }
    }
}

// ── Config sub-structs ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub name: String,
    pub user: String,
    pub password: String,
    pub ssl: bool,
    pub max_connections: u32,
    pub idle_timeout_secs: u64,
    pub connect_timeout_secs: u64,
}

impl DatabaseConfig {
    pub fn from_env() -> Self {
        Self {
            host: env::var("DB_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
            port: env::var("DB_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5432),
            name: env::var("DB_NAME").unwrap_or_else(|_| "apexmail".into()),
            user: env::var("DB_USER").unwrap_or_else(|_| "apexmail".into()),
            password: env::var("DB_PASSWORD").unwrap_or_default(),
            ssl: env::var("DB_SSL").map(|v| v == "true").unwrap_or(false),
            max_connections: 20,
            idle_timeout_secs: 30,
            connect_timeout_secs: 10,
        }
    }

    pub fn url(&self) -> String {
        let ssl = if self.ssl { "?sslmode=require" } else { "" };
        // URL-encode user and password to handle special characters
        let encoded_user = urlencoding::encode(&self.user);
        let encoded_password = urlencoding::encode(&self.password);
        format!(
            "postgres://{}:{}@{}:{}/{}{}",
            encoded_user, encoded_password, self.host, self.port, self.name, ssl
        )
    }
}

#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub host: String,
    pub port: u16,
    pub password: Option<String>,
    pub db: i64,
}

impl RedisConfig {
    pub fn from_env() -> Self {
        Self {
            host: env::var("REDIS_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
            port: env::var("REDIS_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(6379),
            password: env::var("REDIS_PASSWORD").ok().filter(|s| !s.is_empty()),
            db: env::var("REDIS_DB")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
        }
    }

    pub fn url(&self) -> String {
        match &self.password {
            Some(pw) => format!("redis://:{}@{}:{}/{}", pw, self.host, self.port, self.db),
            None => format!("redis://{}:{}/{}", self.host, self.port, self.db),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SamlConfig {
    pub enabled: bool,
    pub entity_id: String,
    pub acs_url: String,
    pub slo_url: String,
    pub certificate: String,
    /// Private key wrapped in SecretString for secure zeroize on drop
    pub private_key: SecretString,
    pub allow_sha1: bool,
}

#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub enabled: bool,
    pub client_id: String,
    pub client_secret: String,
    pub issuer: String,
    pub redirect_uri: String,
    pub scopes: String,
}

#[derive(Debug, Clone)]
pub struct SSOConfig {
    pub saml: SamlConfig,
    pub oidc: OidcConfig,
    pub encryption_key: String,
}

#[derive(Debug, Clone)]
pub struct WhiteLabelConfig {
    pub enabled: bool,
    pub custom_domain_prefix: String,
    pub default_logo_url: String,
    pub default_primary_color: String,
    pub default_company_name: String,
}

#[derive(Debug, Clone)]
pub struct SubAccountConfig {
    pub max_sub_accounts: i32,
    pub inherit_parent_settings: bool,
    pub volume_allocation_mode: VolumeAllocationMode,
}

#[derive(Debug, Clone)]
pub struct ComplianceEnvConfig {
    pub hipaa_enabled: bool,
    pub zero_retention_enabled: bool,
    pub data_residency_regions: Vec<String>,
    pub audit_retention_days: i32,
    pub data_residency: String,
}

#[derive(Debug, Clone)]
pub struct LogStreamEnvConfig {
    pub buffer_size: usize,
    pub flush_interval_ms: u64,
    pub compression: bool,
    pub max_retries: u32,
    pub encryption_key: String,
}

#[derive(Debug, Clone)]
pub struct TemplateConfig {
    pub max_spam_score: i32,
    pub require_review_for_new: bool,
    pub auto_approve_threshold: i32,
}

// ── Main Config ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub host: String,
    pub cors_origins: Vec<String>,
    pub node_env: String,
    pub jwt_secret: String,
    pub jwt_public_key_pem: String,
    pub db: DatabaseConfig,
    pub redis: RedisConfig,
    pub sso: SSOConfig,
    pub whitelabel: WhiteLabelConfig,
    pub sub_account: SubAccountConfig,
    pub compliance: ComplianceEnvConfig,
    pub log_stream: LogStreamEnvConfig,
    pub template: TemplateConfig,
}

impl Config {
    /// Load configuration from environment variables.
    pub fn from_env() -> Result<Self, String> {
        let node_env = env::var("NODE_ENV").unwrap_or_default();
        let is_production = node_env == "production" || node_env == "prod";

        let jwt_secret = match env::var("JWT_SECRET")
            .ok()
            .filter(|value| !value.trim().is_empty())
        {
            Some(secret) => secret,
            None if is_production => {
                return Err("JWT_SECRET environment variable must be set in production".into());
            }
            None => generated_dev_secret("enterprise-jwt"),
        };

        if is_production && jwt_secret.len() < 32 {
            return Err("JWT_SECRET must be at least 32 characters in production".into());
        }

        let jwt_public_key_pem = match env::var("JWT_PUBLIC_KEY_PEM")
            .ok()
            .filter(|value| !value.trim().is_empty())
        {
            Some(pem) => pem,
            None if is_production => {
                return Err(
                    "JWT_PUBLIC_KEY_PEM environment variable must be set in production".into(),
                );
            }
            None => String::new(),
        };

        // M-02: Reject SHA-1 SAML signatures in production
        let allow_sha1 = env::var("SAML_ALLOW_SHA1")
            .map(|v| v == "true")
            .unwrap_or(false);
        if is_production && allow_sha1 {
            return Err(
                "SAML_ALLOW_SHA1 is enabled which is insecure — SHA-1 signatures are deprecated. "
                    .into(),
            );
        }

        // H-02: In production, CORS_ORIGINS must not be wildcard
        let cors_origins_raw = env::var("CORS_ORIGINS").unwrap_or_else(|_| "*".into());
        if is_production && cors_origins_raw == "*" {
            return Err(
                "CORS_ORIGINS must be explicitly set to a comma-separated list of allowed origins in production; wildcard '*' is not allowed."
                    .into(),
            );
        }

        Ok(Self {
            port: env::var("PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3000),
            host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            cors_origins: cors_origins_raw
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
            node_env,
            jwt_secret,
            jwt_public_key_pem,
            db: DatabaseConfig::from_env(),
            redis: RedisConfig::from_env(),
            sso: {
                let base_url = env::var("BASE_URL").unwrap_or_else(|_| {
                    format!(
                        "http://{}:{}",
                        env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into()),
                        env::var("PORT")
                            .ok()
                            .and_then(|v| v.parse::<u16>().ok())
                            .unwrap_or(3000)
                    )
                });
                SSOConfig {
                    saml: SamlConfig {
                        enabled: env::var("SAML_ENABLED")
                            .map(|v| v == "true")
                            .unwrap_or(false),
                        entity_id: env::var("SAML_ENTITY_ID")
                            .unwrap_or_else(|_| "urn:apexmail:enterprise".into()),
                        acs_url: env::var("SAML_ACS_URL")
                            .unwrap_or_else(|_| format!("{base_url}/api/sso/saml/callback")),
                        slo_url: env::var("SAML_SLO_URL")
                            .unwrap_or_else(|_| format!("{base_url}/api/sso/saml/logout")),
                        certificate: env::var("SAML_CERTIFICATE").unwrap_or_default(),
                        private_key: SecretString::new(
                            env::var("SAML_PRIVATE_KEY").unwrap_or_default(),
                        ),
                        allow_sha1,
                    },
                    oidc: OidcConfig {
                        enabled: env::var("OIDC_ENABLED")
                            .map(|v| v == "true")
                            .unwrap_or(false),
                        client_id: env::var("OIDC_CLIENT_ID").unwrap_or_default(),
                        client_secret: env::var("OIDC_CLIENT_SECRET").unwrap_or_default(),
                        issuer: env::var("OIDC_ISSUER").unwrap_or_default(),
                        redirect_uri: env::var("OIDC_REDIRECT_URI")
                            .unwrap_or_else(|_| format!("{base_url}/api/sso/oidc/callback")),
                        scopes: env::var("OIDC_SCOPES")
                            .unwrap_or_else(|_| "openid profile email".into()),
                    },
                    encryption_key: env::var("SSO_ENCRYPTION_KEY").unwrap_or_default(),
                }
            },
            whitelabel: WhiteLabelConfig {
                enabled: env::var("WHITE_LABEL_ENABLED")
                    .map(|v| v == "true")
                    .unwrap_or(false),
                custom_domain_prefix: env::var("CUSTOM_DOMAIN_PREFIX")
                    .unwrap_or_else(|_| "mail".into()),
                default_logo_url: env::var("DEFAULT_LOGO_URL").unwrap_or_default(),
                default_primary_color: env::var("DEFAULT_PRIMARY_COLOR")
                    .unwrap_or_else(|_| "#dc2626".into()),
                default_company_name: env::var("DEFAULT_COMPANY_NAME")
                    .unwrap_or_else(|_| "ApexMail".into()),
            },
            sub_account: SubAccountConfig {
                max_sub_accounts: env::var("MAX_SUB_ACCOUNTS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(100),
                inherit_parent_settings: env::var("INHERIT_PARENT_SETTINGS")
                    .map(|v| v == "true")
                    .unwrap_or(true),
                volume_allocation_mode: env::var("VOLUME_ALLOCATION_MODE")
                    .unwrap_or_else(|_| "shared".into())
                    .parse()
                    .unwrap_or(VolumeAllocationMode::Shared),
            },
            compliance: ComplianceEnvConfig {
                hipaa_enabled: env::var("HIPAA_ENABLED")
                    .map(|v| v == "true")
                    .unwrap_or(false),
                zero_retention_enabled: env::var("ZERO_RETENTION_ENABLED")
                    .map(|v| v == "true")
                    .unwrap_or(false),
                data_residency_regions: env::var("DATA_RESIDENCY_REGIONS")
                    .unwrap_or_else(|_| "us,eu".into())
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect(),
                audit_retention_days: env::var("AUDIT_RETENTION_DAYS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(2555),
                data_residency: env::var("DATA_RESIDENCY").unwrap_or_default(),
            },
            log_stream: LogStreamEnvConfig {
                buffer_size: env::var("LOG_STREAM_BUFFER_SIZE")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(1000),
                flush_interval_ms: env::var("LOG_STREAM_FLUSH_INTERVAL")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(60000),
                compression: env::var("LOG_STREAM_COMPRESSION")
                    .map(|v| v != "false")
                    .unwrap_or(true),
                max_retries: env::var("LOG_STREAM_MAX_RETRIES")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(3),
                encryption_key: env::var("LOG_STREAM_ENCRYPTION_KEY").unwrap_or_default(),
            },
            template: TemplateConfig {
                max_spam_score: env::var("TEMPLATE_MAX_SPAM_SCORE")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(50),
                require_review_for_new: env::var("TEMPLATE_REQUIRE_REVIEW_NEW")
                    .map(|v| v != "false")
                    .unwrap_or(true),
                auto_approve_threshold: env::var("TEMPLATE_AUTO_APPROVE_THRESHOLD")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(10),
            },
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.port == 0 {
            return Err("PORT must be > 0".into());
        }
        if self.host.trim().is_empty() {
            return Err("HOST must not be empty".into());
        }
        if self.db.port == 0 {
            return Err("DB_PORT must be > 0".into());
        }
        if self.db.max_connections == 0 {
            return Err("DB_MAX_CONNECTIONS must be > 0".into());
        }
        if self.node_env == "production" && self.db.password.trim().is_empty() {
            return Err("DB_PASSWORD must be set in production".into());
        }
        if self.cors_origins.is_empty() {
            return Err("CORS_ORIGINS must not be empty".into());
        }

        // Validate JWT public key PEM in production
        if self.node_env == "production" && self.jwt_public_key_pem.trim().is_empty() {
            return Err("JWT_PUBLIC_KEY_PEM must be set in production".into());
        }

        // Validate SSO secrets when their features are enabled
        if self.sso.saml.enabled && self.sso.saml.private_key.expose_secret().is_empty() {
            return Err("SAML_PRIVATE_KEY must be set when SAML_ENABLED=true".into());
        }
        if self.sso.saml.enabled && self.sso.saml.certificate.is_empty() {
            return Err("SAML_CERTIFICATE must be set when SAML_ENABLED=true".into());
        }
        if self.sso.oidc.enabled && self.sso.oidc.client_secret.is_empty() {
            return Err("OIDC_CLIENT_SECRET must be set when OIDC_ENABLED=true".into());
        }
        if self.sso.oidc.enabled && self.sso.oidc.client_id.is_empty() {
            return Err("OIDC_CLIENT_ID must be set when OIDC_ENABLED=true".into());
        }
        if self.sso.oidc.enabled && self.sso.oidc.issuer.is_empty() {
            return Err("OIDC_ISSUER must be set when OIDC_ENABLED=true".into());
        }

        Ok(())
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        // Clear env to ensure defaults
        for key in &["PORT", "HOST", "DB_HOST", "DB_PORT", "JWT_SECRET"] {
            env::remove_var(key);
        }
        let cfg = Config::from_env().unwrap();
        assert_eq!(cfg.port, 3000);
        assert_eq!(cfg.host, "0.0.0.0");
        assert_eq!(cfg.db.host, "127.0.0.1");
        assert_eq!(cfg.db.port, 5432);
        assert_eq!(cfg.db.name, "apexmail");
        assert_eq!(cfg.db.max_connections, 20);
    }

    #[test]
    fn test_db_url() {
        let db = DatabaseConfig {
            host: "db.example.com".into(),
            port: 5433,
            name: "enterprise".into(),
            user: "admin".into(),
            password: "secret".into(),
            ssl: false,
            max_connections: 20,
            idle_timeout_secs: 30,
            connect_timeout_secs: 10,
        };
        assert_eq!(
            db.url(),
            "postgres://admin:secret@db.example.com:5433/enterprise"
        );
    }

    #[test]
    fn test_db_url_ssl() {
        let db = DatabaseConfig {
            host: "db.example.com".into(),
            port: 5432,
            name: "apexmail".into(),
            user: "u".into(),
            password: "p".into(),
            ssl: true,
            max_connections: 20,
            idle_timeout_secs: 30,
            connect_timeout_secs: 10,
        };
        assert!(db.url().ends_with("?sslmode=require"));
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
            host: "r.example.com".into(),
            port: 6380,
            password: Some("pass".into()),
            db: 2,
        };
        assert_eq!(r.url(), "redis://:pass@r.example.com:6380/2");
    }

    #[test]
    fn test_enterprise_plan_display() {
        assert_eq!(EnterprisePlan::Scale.to_string(), "scale");
        assert_eq!(EnterprisePlan::Private.to_string(), "private");
    }

    #[test]
    fn test_sso_provider_parse() {
        assert_eq!(
            "saml".parse::<SSOProviderType>().unwrap(),
            SSOProviderType::Saml
        );
        assert_eq!(
            "azure_ad".parse::<SSOProviderType>().unwrap(),
            SSOProviderType::AzureAd
        );
        assert!("unknown".parse::<SSOProviderType>().is_err());
    }

    #[test]
    fn test_volume_allocation_mode_parse() {
        assert_eq!(
            "fixed".parse::<VolumeAllocationMode>().unwrap(),
            VolumeAllocationMode::Fixed
        );
        assert_eq!(
            "burst".parse::<VolumeAllocationMode>().unwrap(),
            VolumeAllocationMode::Burst
        );
        assert!("invalid".parse::<VolumeAllocationMode>().is_err());
    }

    #[test]
    fn test_volume_allocation_mode_display() {
        assert_eq!(VolumeAllocationMode::Shared.to_string(), "shared");
    }

    #[test]
    fn test_compliance_defaults() {
        env::remove_var("HIPAA_ENABLED");
        env::remove_var("AUDIT_RETENTION_DAYS");
        let cfg = Config::from_env().unwrap();
        assert!(!cfg.compliance.hipaa_enabled);
        assert_eq!(cfg.compliance.audit_retention_days, 2555);
        assert_eq!(cfg.compliance.data_residency_regions, vec!["us", "eu"]);
    }

    #[test]
    fn test_template_defaults() {
        env::remove_var("TEMPLATE_MAX_SPAM_SCORE");
        let cfg = Config::from_env().unwrap();
        assert_eq!(cfg.template.max_spam_score, 50);
        assert!(cfg.template.require_review_for_new);
        assert_eq!(cfg.template.auto_approve_threshold, 10);
    }

    #[test]
    fn test_sub_account_defaults() {
        env::remove_var("MAX_SUB_ACCOUNTS");
        let cfg = Config::from_env().unwrap();
        assert_eq!(cfg.sub_account.max_sub_accounts, 100);
        assert!(cfg.sub_account.inherit_parent_settings);
        assert_eq!(
            cfg.sub_account.volume_allocation_mode,
            VolumeAllocationMode::Shared
        );
    }

    #[test]
    fn test_log_stream_defaults() {
        env::remove_var("LOG_STREAM_BUFFER_SIZE");
        let cfg = Config::from_env().unwrap();
        assert_eq!(cfg.log_stream.buffer_size, 1000);
        assert_eq!(cfg.log_stream.flush_interval_ms, 60000);
        assert!(cfg.log_stream.compression);
        assert_eq!(cfg.log_stream.max_retries, 3);
    }
}
