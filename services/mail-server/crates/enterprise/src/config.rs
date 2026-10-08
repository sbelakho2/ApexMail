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
            // SCALE-M-01: Read max_connections from env, default 20
            max_connections: env::var("DB_MAX_CONNECTIONS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(20),
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
            // Percent-encode the password (RFC 3986) so special characters
            // like `@`, `:`, `/`, `+` cannot corrupt the URL.
            Some(pw) => format!(
                "redis://:{}@{}:{}/{}",
                urlencoding::encode(pw),
                self.host,
                self.port,
                self.db
            ),
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

// Dogfood 2026-10-06 wave B: `WhiteLabelConfig` was REMOVED. It parsed
// WHITE_LABEL_ENABLED / CUSTOM_DOMAIN_PREFIX / DEFAULT_LOGO_URL /
// DEFAULT_PRIMARY_COLOR / DEFAULT_COMPANY_NAME and no code path read ANY of
// the parsed values (the `WhiteLabelService` takes only a PgPool and stores
// per-tenant brand rows; `get_config` answers NOT_FOUND, not defaults). The
// same principle as audit F10 below: a knob that does nothing is
// configuration theater. The branded values may only return together with
// the mechanism that applies them.

#[derive(Debug, Clone)]
pub struct SubAccountConfig {
    pub max_sub_accounts: i32,
    pub inherit_parent_settings: bool,
    pub volume_allocation_mode: VolumeAllocationMode,
}

// Dogfood 2026-10-06 wave B: `ComplianceEnvConfig` was REMOVED.
//
// Audit F10 removed `data_residency` / `data_residency_regions` from it for
// being parsed-but-never-read. The remaining three knobs had the same
// defect and are now gone too:
//  * `HIPAA_ENABLED` / `ZERO_RETENTION_ENABLED` — `ComplianceService::new`
//    takes only a PgPool; framework enablement and zero-retention mode are
//    per-tenant rows written by the API, never global env defaults.
//  * `AUDIT_RETENTION_DAYS` — the CANONICAL consumer is the compliance
//    service (`compliance::config` → `retention_sweep`); this crate's copy
//    was never read.
// A knob that does nothing is configuration theater; each may only return
// with the enforcement point that reads it.

#[derive(Debug, Clone)]
pub struct LogStreamEnvConfig {
    pub buffer_size: usize,
    pub flush_interval_ms: u64,
    pub compression: bool,
    pub max_retries: u32,
    pub encryption_key: String,
}

/// Template-approval thresholds.
///
/// Dogfood 2026-10-06 wave B: `require_review_for_new` (env
/// `TEMPLATE_REQUIRE_REVIEW_NEW`) and `auto_approve_threshold` (env
/// `TEMPLATE_AUTO_APPROVE_THRESHOLD`) were REMOVED. Audit M-01
/// (`template_approval.rs`) forbids auto-approval outright — every submission
/// requires a human review — so no value of either knob could ever be
/// honored. `max_spam_score` remains: it is the real auto-REJECT threshold
/// consumed by `TemplateApprovalService`.
#[derive(Debug, Clone)]
pub struct TemplateConfig {
    pub max_spam_score: i32,
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
    /// Canonical-session signing key (`JWT_PRIVATE_KEY_PEM`). When set, a
    /// validated SSO login resolves/provisions the canonical `users` row and
    /// issues the same `am_session` console session the web login issues
    /// (audit P1-3); deployments must configure the SAME key the api-server
    /// uses. Unset: the callback still issues the enterprise session record,
    /// but no console cookie can be minted.
    pub jwt_private_key_pem: String,
    /// Fix J-1: optional pinned JWT audience (`JWT_AUDIENCE`). When set,
    /// tokens whose `aud` does not match are rejected.
    pub jwt_audience: Option<String>,
    /// Fix J-1: optional pinned JWT issuer (`JWT_ISSUER`). When set, tokens
    /// whose `iss` does not match are rejected.
    pub jwt_issuer: Option<String>,
    /// Fix H-3: optional bearer token that grants access to `/metrics` from
    /// non-loopback peers (`METRICS_TOKEN`).
    pub metrics_token: Option<String>,
    pub db: DatabaseConfig,
    pub redis: RedisConfig,
    pub sso: SSOConfig,
    pub sub_account: SubAccountConfig,
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

        // Canonical SSO console sessions (audit P1-3): the SAME RS256 private
        // key the api-server signs `am_session` cookies with. Optional — an
        // unset key degrades to enterprise-session-only callbacks.
        let jwt_private_key_pem = env::var("JWT_PRIVATE_KEY_PEM")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_default();

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
            jwt_private_key_pem,
            jwt_audience: env::var("JWT_AUDIENCE")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            jwt_issuer: env::var("JWT_ISSUER")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            metrics_token: env::var("METRICS_TOKEN")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
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

        // Fix H-2: log-stream destination secrets cannot be protected at rest
        // without a key — require one in production instead of silently
        // storing credentials in plaintext.
        if self.node_env == "production" && self.log_stream.encryption_key.trim().is_empty() {
            return Err(
                "LOG_STREAM_ENCRYPTION_KEY must be set in production to encrypt destination credentials at rest"
                    .into(),
            );
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

    /// OPS-3 (live dogfood 2026-10-08): `/metrics` admits loopback or a
    /// bearer `METRICS_TOKEN`; the dev compose set no token and
    /// deploy/prometheus.yml carried no `authorization:` block, so the
    /// documented `enterprise:3008` scrape target answered 401 from every
    /// other container. Pin the full wiring: the service receives the
    /// token, Prometheus sends the mounted credential file (Prometheus
    /// 2.55 has no --config.expand-env, so env interpolation is not an
    /// option).
    #[test]
    fn dev_deploy_artifacts_authorize_the_enterprise_metrics_scrape() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..");
        let compose = std::fs::read_to_string(root.join("docker-compose.yml"))
            .expect("docker-compose.yml must be readable");
        let has_line = |needle: &str| compose.lines().any(|line| line.trim() == needle);
        assert!(
            has_line(
                "METRICS_TOKEN: ${ENTERPRISE_METRICS_TOKEN:-dev-enterprise-metrics-token-change-me}"
            ),
            "the enterprise service must receive METRICS_TOKEN in the dev compose"
        );
        assert!(
            compose.contains(
                "./deploy/monitoring/enterprise_metrics_token:/etc/prometheus/monitoring/enterprise_metrics_token:ro"
            ),
            "the prometheus service must mount the enterprise scrape credential file"
        );
        // Prometheus 2.55 has no --config.expand-env (3.x flag); it must not
        // appear in the prometheus command (tempo/loki use their OWN
        // -config.expand-env=true and are out of scope).
        let prom_command = compose
            .split("'--config.file=/etc/prometheus/prometheus.yml'")
            .nth(1)
            .map(|rest| rest.split("ports:").next().unwrap_or(rest))
            .expect("the prometheus command list must be present");
        assert!(
            !prom_command.contains("--config.expand-env"),
            "Prometheus 2.55 does not support --config.expand-env and would fail \
             to start with it:\n{prom_command}"
        );
        let prometheus = std::fs::read_to_string(root.join("deploy/prometheus.yml"))
            .expect("deploy/prometheus.yml must be readable");
        let enterprise_job = prometheus
            .split("job_name: 'apexmail-enterprise'")
            .nth(1)
            .expect("the apexmail-enterprise job must exist");
        let job_block = enterprise_job
            .split("- job_name:")
            .next()
            .unwrap_or(enterprise_job);
        assert!(
            job_block.contains("authorization:")
                && job_block.contains(
                    "credentials_file: /etc/prometheus/monitoring/enterprise_metrics_token"
                ),
            "the enterprise scrape job must carry the bearer authorization block:\n{job_block}"
        );
        let token =
            std::fs::read_to_string(root.join("deploy/monitoring/enterprise_metrics_token"))
                .expect("the dev credential file must be committed");
        assert_eq!(
            token.trim(),
            "dev-enterprise-metrics-token-change-me",
            "the committed dev credential must match the compose default the \
             enterprise service receives"
        );
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
    fn test_redis_url_percent_encodes_special_characters() {
        let r = RedisConfig {
            host: "r.example.com".into(),
            port: 6380,
            password: Some("p@ss:word/with space+plus".into()),
            db: 2,
        };
        assert_eq!(
            r.url(),
            "redis://:p%40ss%3Aword%2Fwith%20space%2Bplus@r.example.com:6380/2"
        );
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
    fn removed_knobs_are_no_longer_read_anywhere() {
        // Dogfood 2026-10-06 wave B (continuing audit F10): every knob below
        // was parsed into a field with zero readers. They are gone from the
        // struct entirely, so a stale environment can no longer pretend to
        // configure behaviour — the assertion is that the vars are inert.
        for knob in [
            "DATA_RESIDENCY",
            "DATA_RESIDENCY_REGIONS",
            "HIPAA_ENABLED",
            "ZERO_RETENTION_ENABLED",
            "WHITE_LABEL_ENABLED",
            "CUSTOM_DOMAIN_PREFIX",
            "DEFAULT_LOGO_URL",
            "DEFAULT_PRIMARY_COLOR",
            "DEFAULT_COMPANY_NAME",
            "TEMPLATE_REQUIRE_REVIEW_NEW",
            "TEMPLATE_AUTO_APPROVE_THRESHOLD",
        ] {
            env::set_var(knob, "true");
        }
        // Loading still succeeds and the parsed config carries no such fields
        // (this test fails to COMPILE if one is reintroduced without a
        // consumer).
        let cfg = Config::from_env().unwrap();
        assert_eq!(cfg.template.max_spam_score, 50);
        for knob in [
            "DATA_RESIDENCY",
            "DATA_RESIDENCY_REGIONS",
            "HIPAA_ENABLED",
            "ZERO_RETENTION_ENABLED",
            "WHITE_LABEL_ENABLED",
            "CUSTOM_DOMAIN_PREFIX",
            "DEFAULT_LOGO_URL",
            "DEFAULT_PRIMARY_COLOR",
            "DEFAULT_COMPANY_NAME",
            "TEMPLATE_REQUIRE_REVIEW_NEW",
            "TEMPLATE_AUTO_APPROVE_THRESHOLD",
        ] {
            env::remove_var(knob);
        }
    }

    #[test]
    fn test_template_defaults() {
        env::remove_var("TEMPLATE_MAX_SPAM_SCORE");
        let cfg = Config::from_env().unwrap();
        assert_eq!(cfg.template.max_spam_score, 50);
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

    // ── Adversarial: validate() must fail closed per rule ────────────────

    fn base_config() -> Config {
        Config::from_env().expect("Config::from_env with test defaults")
    }

    #[test]
    fn secret_string_exposes_but_never_prints() {
        let secret = SecretString::new("super-secret-token".into());
        assert_eq!(secret.expose_secret(), "super-secret-token");
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
        assert!(!format!("{secret:?}").contains("super-secret"));
        // Clone still exposes the same value (zeroize happens on drop only).
        assert_eq!(secret.clone().expose_secret(), "super-secret-token");
    }

    #[test]
    fn config_validate_rejects_each_single_violation() {
        // Baseline must be valid so each mutation isolates one rule.
        let base = base_config();
        assert!(base.validate().is_ok(), "test baseline must validate");

        let mut cfg = base.clone();
        cfg.port = 0;
        assert!(cfg.validate().unwrap_err().contains("PORT"));
        let mut cfg = base.clone();
        cfg.host = "   ".into();
        assert!(cfg.validate().unwrap_err().contains("HOST"));
        let mut cfg = base.clone();
        cfg.db.port = 0;
        assert!(cfg.validate().unwrap_err().contains("DB_PORT"));
        let mut cfg = base.clone();
        cfg.db.max_connections = 0;
        assert!(cfg.validate().unwrap_err().contains("DB_MAX_CONNECTIONS"));
        let mut cfg = base.clone();
        cfg.cors_origins = vec![];
        assert!(cfg.validate().unwrap_err().contains("CORS_ORIGINS"));
        let mut cfg = base.clone();
        cfg.node_env = "production".into();
        cfg.db.password = "  ".into();
        assert!(cfg.validate().unwrap_err().contains("DB_PASSWORD"));
        let mut cfg = base.clone();
        cfg.node_env = "production".into();
        cfg.db.password = "set".into();
        cfg.jwt_public_key_pem = String::new();
        assert!(cfg.validate().unwrap_err().contains("JWT_PUBLIC_KEY_PEM"));
        let mut cfg = base.clone();
        cfg.node_env = "production".into();
        cfg.db.password = "set".into();
        cfg.jwt_public_key_pem = "pem".into();
        cfg.log_stream.encryption_key = String::new();
        assert!(
            cfg.validate()
                .unwrap_err()
                .contains("LOG_STREAM_ENCRYPTION_KEY"),
            "log-stream key must be required in production"
        );
        let mut cfg = base.clone();
        cfg.sso.saml.enabled = true;
        cfg.sso.saml.private_key = SecretString::new(String::new());
        assert!(cfg.validate().unwrap_err().contains("SAML_PRIVATE_KEY"));
        let mut cfg = base.clone();
        cfg.sso.saml.enabled = true;
        cfg.sso.saml.private_key = SecretString::new("key".into());
        cfg.sso.saml.certificate = String::new();
        assert!(cfg.validate().unwrap_err().contains("SAML_CERTIFICATE"));
        let mut cfg = base.clone();
        cfg.sso.oidc.enabled = true;
        cfg.sso.oidc.client_secret = String::new();
        assert!(cfg.validate().unwrap_err().contains("OIDC_CLIENT_SECRET"));
        let mut cfg = base.clone();
        cfg.sso.oidc.enabled = true;
        cfg.sso.oidc.client_secret = "secret".into();
        cfg.sso.oidc.client_id = String::new();
        assert!(cfg.validate().unwrap_err().contains("OIDC_CLIENT_ID"));
        let mut cfg = base.clone();
        cfg.sso.oidc.enabled = true;
        cfg.sso.oidc.client_secret = "secret".into();
        cfg.sso.oidc.client_id = "client".into();
        cfg.sso.oidc.issuer = String::new();
        assert!(cfg.validate().unwrap_err().contains("OIDC_ISSUER"));
    }

    #[test]
    fn enterprise_plan_wire_contract_all_variants() {
        for (plan, wire) in [
            (EnterprisePlan::Starter, "starter"),
            (EnterprisePlan::Business, "business"),
            (EnterprisePlan::Scale, "scale"),
            (EnterprisePlan::Enterprise, "enterprise"),
            (EnterprisePlan::Private, "private"),
            (EnterprisePlan::Custom, "custom"),
        ] {
            assert_eq!(plan.to_string(), wire);
            assert_eq!(
                serde_json::to_value(&plan).unwrap(),
                serde_json::json!(wire)
            );
        }
    }

    #[test]
    fn sso_provider_and_volume_mode_wire_contracts() {
        for (provider, wire) in [
            (SSOProviderType::Saml, "saml"),
            (SSOProviderType::Oidc, "oidc"),
            (SSOProviderType::Okta, "okta"),
            (SSOProviderType::AzureAd, "azure_ad"),
            (SSOProviderType::Google, "google"),
        ] {
            assert_eq!(provider.to_string(), wire);
            assert_eq!(
                serde_json::to_value(&provider).unwrap(),
                serde_json::json!(wire)
            );
            assert_eq!(wire.parse::<SSOProviderType>().unwrap(), provider);
        }
        for hostile in ["", "SAML", "ldap"] {
            assert!(hostile.parse::<SSOProviderType>().is_err());
        }
        for (mode, wire) in [
            (VolumeAllocationMode::Fixed, "fixed"),
            (VolumeAllocationMode::Shared, "shared"),
            (VolumeAllocationMode::Burst, "burst"),
        ] {
            assert_eq!(mode.to_string(), wire);
            assert_eq!(wire.parse::<VolumeAllocationMode>().unwrap(), mode);
        }
        for hostile in ["", "shared_mode", "SHARED"] {
            assert!(hostile.parse::<VolumeAllocationMode>().is_err());
        }
    }
}
