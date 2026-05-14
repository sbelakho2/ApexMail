use serde::Deserialize;
use uuid::Uuid;

/// Top-level compliance service configuration, loaded from environment.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComplianceConfig {
    pub port: u16,
    pub database_url: String,
    pub redis_url: String,
    pub auth_token: String,
    pub cors_origin: String,

    pub risk: RiskScoringConfig,
    pub content: ContentScanningConfig,
    pub audit: AuditConfig,
    pub gdpr: GdprConfig,
    pub secrets: SecretsConfig,

    /// DSAR-specific rate limiting configuration.
    /// SEC-15: Stricter rate limits for Data Subject Access Request endpoints.
    pub dsar_rate_limit: DsarRateLimitConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskScoringConfig {
    pub spam_threshold: f64,
    pub phishing_threshold: f64,
    pub abuse_threshold: f64,
    pub max_daily_emails: i64,
    pub new_tenant_daily_limit: i64,
    pub warmup_days: i64,

    pub weights: RiskWeights,
    pub thresholds: RiskThresholds,
    pub base_limits: BaseLimits,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskWeights {
    pub spam_complaints: f64,
    pub bounce_rate: f64,
    pub phishing_detection: f64,
    pub content_violation: f64,
    pub sending_pattern: f64,
    pub account_age: f64,
    pub verification_status: f64,
    pub payment_history: f64,
    pub list_quality: f64,
    pub engagement_rate: f64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskThresholds {
    pub spam_complaint_rate: f64,
    pub bounce_rate: f64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaseLimits {
    pub max_daily_emails: i64,
    pub max_hourly_emails: i64,
    pub max_recipients: i64,
    pub max_attachment_size_mb: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentScanningConfig {
    pub enabled: bool,
    pub ocr_enabled: bool,
    pub spam_threshold: f64,
    pub max_attachment_size: usize,
    pub max_ocr_images: usize,
    pub banned_domains: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    pub retention_days: i64,
    pub hash_chain_enabled: bool,
    pub signing_key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GdprConfig {
    pub data_retention_days: i64,
    pub export_format: String,
    pub deletion_grace_period_days: i64,
    pub request_expiration_days: i64,
    pub export_expiration_days: i64,
    pub export_base_url: String,
    pub verify_base_url: String,
    pub consent_signing_key: String,
    /// Maximum number of message events to include in access requests (was hardcoded 1000).
    pub access_request_max_messages: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretsConfig {
    pub encryption_key: String,
    pub rotation_days: i64,
    pub max_versions_to_keep: i64,
}

/// DSAR (Data Subject Access Request) rate limit configuration.
///
/// SEC-15: DSAR endpoints require stricter rate limits than normal API routes.
/// See `docs/compliance/dsar-rate-limiting.md` for details.
///
/// | Limit Type            | Env Variable                   | Default |
/// |-----------------------|--------------------------------|---------|
/// | Per-user submission   | `DSAR_RATE_LIMIT_PER_USER`     | 1       |
/// | User window (seconds) | `DSAR_RATE_LIMIT_USER_WINDOW`  | 86400   |
/// | Per-tenant submission | `DSAR_RATE_LIMIT_PER_TENANT`   | 100     |
/// | Tenant window (secs)  | `DSAR_RATE_LIMIT_TENANT_WINDOW`| 86400   |
/// | Verification attempts | `DSAR_VERIFY_RATE_LIMIT`       | 5       |
/// | Verify window (secs)  | `DSAR_VERIFY_WINDOW_SECS`      | 3600    |
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsarRateLimitConfig {
    /// Maximum DSAR submissions per user (email) per window.
    pub per_user: u32,
    /// User-level window in seconds.
    pub user_window_secs: u64,
    /// Maximum DSAR submissions per tenant per window.
    pub per_tenant: u32,
    /// Tenant-level window in seconds.
    pub tenant_window_secs: u64,
    /// Maximum verification attempts per token hash per window.
    pub verify_attempts: u32,
    /// Verification window in seconds.
    pub verify_window_secs: u64,
}

impl Default for DsarRateLimitConfig {
    fn default() -> Self {
        Self {
            per_user: 1,
            user_window_secs: 86400,
            per_tenant: 100,
            tenant_window_secs: 86400,
            verify_attempts: 5,
            verify_window_secs: 3600,
        }
    }
}

impl ComplianceConfig {
    /// Load configuration from environment variables with sane defaults.
    pub fn from_env() -> Self {
        let node_env = std::env::var("NODE_ENV").unwrap_or_default();
        let is_production =
            node_env.eq_ignore_ascii_case("production") || node_env.eq_ignore_ascii_case("prod");

        let mut auth_token = env_or("COMPLIANCE_AUTH_TOKEN", "");
        let mut audit_signing_key = env_or("AUDIT_SIGNING_KEY", "");
        let mut secrets_encryption_key = env_or("SECRETS_ENCRYPTION_KEY", "");

        if is_production {
            if auth_token.trim().is_empty() {
                auth_token = format!("auto-compliance-token-{}", Uuid::new_v4());
                tracing::warn!(
                    "SECURITY: COMPLIANCE_AUTH_TOKEN missing in production; generated an ephemeral runtime token (redacted)"
                );
            }
            if audit_signing_key.trim().is_empty() {
                audit_signing_key = format!("auto-audit-signing-key-{}", Uuid::new_v4());
                tracing::warn!(
                    "SECURITY: AUDIT_SIGNING_KEY missing in production; generated an ephemeral runtime key (redacted)"
                );
            }
            if secrets_encryption_key.trim().is_empty() {
                secrets_encryption_key = format!("auto-secrets-key-{}", Uuid::new_v4());
                tracing::warn!(
                    "SECURITY: SECRETS_ENCRYPTION_KEY missing in production; generated an ephemeral runtime key (redacted)"
                );
            }
        }

        Self {
            port: env_or("COMPLIANCE_PORT", "3011").parse().unwrap_or(3011),
            database_url: env_or(
                "DATABASE_URL",
                "postgres://postgres:postgres@localhost:5432/apexmail",
            ),
            redis_url: env_or("REDIS_URL", "redis://localhost:6379"),
            auth_token,
            cors_origin: env_or("CORS_ORIGIN", ""),

            risk: RiskScoringConfig {
                spam_threshold: env_f64("RISK_SPAM_THRESHOLD", 0.7),
                phishing_threshold: env_f64("RISK_PHISHING_THRESHOLD", 0.5),
                abuse_threshold: env_f64("RISK_ABUSE_THRESHOLD", 0.6),
                max_daily_emails: env_i64("RISK_MAX_DAILY_EMAILS", 10_000),
                new_tenant_daily_limit: env_i64("RISK_NEW_TENANT_LIMIT", 100),
                warmup_days: env_i64("RISK_WARMUP_DAYS", 30),
                weights: RiskWeights {
                    spam_complaints: env_f64("RISK_WEIGHT_SPAM_COMPLAINTS", 1.5),
                    bounce_rate: env_f64("RISK_WEIGHT_BOUNCE_RATE", 1.2),
                    phishing_detection: env_f64("RISK_WEIGHT_PHISHING", 2.0),
                    content_violation: env_f64("RISK_WEIGHT_CONTENT_VIOLATION", 1.5),
                    sending_pattern: env_f64("RISK_WEIGHT_SENDING_PATTERN", 1.0),
                    account_age: env_f64("RISK_WEIGHT_ACCOUNT_AGE", 0.8),
                    verification_status: env_f64("RISK_WEIGHT_VERIFICATION", 0.7),
                    payment_history: env_f64("RISK_WEIGHT_PAYMENT", 0.9),
                    list_quality: env_f64("RISK_WEIGHT_LIST_QUALITY", 1.1),
                    engagement_rate: env_f64("RISK_WEIGHT_ENGAGEMENT", 0.6),
                },
                thresholds: RiskThresholds {
                    spam_complaint_rate: env_f64("RISK_THRESHOLD_SPAM_RATE", 0.1),
                    bounce_rate: env_f64("RISK_THRESHOLD_BOUNCE_RATE", 5.0),
                },
                base_limits: BaseLimits {
                    max_daily_emails: env_i64("RISK_BASE_MAX_DAILY", 10_000),
                    max_hourly_emails: env_i64("RISK_BASE_MAX_HOURLY", 1_000),
                    max_recipients: env_i64("RISK_BASE_MAX_RECIPIENTS", 500),
                    max_attachment_size_mb: env_i64("RISK_BASE_MAX_ATTACHMENT_SIZE", 25),
                },
            },

            content: ContentScanningConfig {
                enabled: env_or("CONTENT_SCANNING_ENABLED", "true") == "true",
                ocr_enabled: env_or("CONTENT_OCR_ENABLED", "true") == "true",
                spam_threshold: env_f64("CONTENT_SPAM_THRESHOLD", 50.0),
                max_attachment_size: env_or("CONTENT_MAX_ATTACHMENT_SIZE", "26214400")
                    .parse()
                    .unwrap_or(26_214_400),
                max_ocr_images: env_or("CONTENT_MAX_OCR_IMAGES", "5").parse().unwrap_or(5),
                banned_domains: env_or("CONTENT_BANNED_DOMAINS", "")
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.trim().to_lowercase())
                    .collect(),
            },

            audit: AuditConfig {
                retention_days: env_i64("AUDIT_RETENTION_DAYS", 365),
                hash_chain_enabled: env_or("AUDIT_HASH_CHAIN", "true") == "true",
                signing_key: audit_signing_key,
            },

            gdpr: GdprConfig {
                data_retention_days: env_i64("GDPR_RETENTION_DAYS", 730),
                export_format: env_or("GDPR_EXPORT_FORMAT", "json"),
                deletion_grace_period_days: env_i64("GDPR_DELETION_GRACE_PERIOD", 30),
                request_expiration_days: env_i64("GDPR_REQUEST_EXPIRATION_DAYS", 30),
                export_expiration_days: env_i64("GDPR_EXPORT_EXPIRATION_DAYS", 7),
                export_base_url: env_or("GDPR_EXPORT_BASE_URL", "https://exports.apexmail.ee"),
                verify_base_url: env_or("GDPR_VERIFY_BASE_URL", "https://gdpr.apexmail.ee"),
                consent_signing_key: env_or("CONSENT_SIGNING_KEY", ""),
                access_request_max_messages: env_i64("GDPR_ACCESS_MAX_MESSAGES", 10_000),
            },

            secrets: SecretsConfig {
                encryption_key: secrets_encryption_key,
                rotation_days: env_i64("SECRETS_ROTATION_DAYS", 90),
                max_versions_to_keep: env_i64("SECRETS_MAX_VERSIONS", 10),
            },

            dsar_rate_limit: DsarRateLimitConfig {
                per_user: env_or("DSAR_RATE_LIMIT_PER_USER", "1").parse().unwrap_or(1),
                user_window_secs: env_or("DSAR_RATE_LIMIT_USER_WINDOW", "86400")
                    .parse()
                    .unwrap_or(86400),
                per_tenant: env_or("DSAR_RATE_LIMIT_PER_TENANT", "100")
                    .parse()
                    .unwrap_or(100),
                tenant_window_secs: env_or("DSAR_RATE_LIMIT_TENANT_WINDOW", "86400")
                    .parse()
                    .unwrap_or(86400),
                verify_attempts: env_or("DSAR_VERIFY_RATE_LIMIT", "5").parse().unwrap_or(5),
                verify_window_secs: env_or("DSAR_VERIFY_WINDOW_SECS", "3600")
                    .parse()
                    .unwrap_or(3600),
            },
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_f64(key: &str, default: f64) -> f64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_i64(key: &str, default: i64) -> i64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = ComplianceConfig::from_env();
        assert_eq!(cfg.port, 3011);
        assert_eq!(cfg.risk.weights.phishing_detection, 2.0);
        assert_eq!(cfg.risk.base_limits.max_daily_emails, 10_000);
        assert_eq!(cfg.content.spam_threshold, 50.0);
        assert_eq!(cfg.audit.retention_days, 365);
        assert_eq!(cfg.gdpr.data_retention_days, 730);
        assert_eq!(cfg.secrets.rotation_days, 90);
        // SEC-15: DSAR rate limit defaults
        assert_eq!(cfg.dsar_rate_limit.per_user, 1);
        assert_eq!(cfg.dsar_rate_limit.per_tenant, 100);
        assert_eq!(cfg.dsar_rate_limit.verify_attempts, 5);
        assert_eq!(cfg.dsar_rate_limit.user_window_secs, 86400);
        assert_eq!(cfg.dsar_rate_limit.tenant_window_secs, 86400);
        assert_eq!(cfg.dsar_rate_limit.verify_window_secs, 3600);
    }
}
