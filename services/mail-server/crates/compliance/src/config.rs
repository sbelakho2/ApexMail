use serde::Deserialize;

/// Top-level compliance service configuration, loaded from environment.
#[derive(Debug, Clone, Deserialize)]
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
}

#[derive(Debug, Clone, Deserialize)]
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
pub struct RiskThresholds {
    pub spam_complaint_rate: f64,
    pub bounce_rate: f64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BaseLimits {
    pub max_daily_emails: i64,
    pub max_hourly_emails: i64,
    pub max_recipients: i64,
    pub max_attachment_size_mb: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ContentScanningConfig {
    pub enabled: bool,
    pub ocr_enabled: bool,
    pub spam_threshold: f64,
    pub max_attachment_size: usize,
    pub max_ocr_images: usize,
    pub banned_domains: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditConfig {
    pub retention_days: i64,
    pub hash_chain_enabled: bool,
    pub signing_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GdprConfig {
    pub data_retention_days: i64,
    pub export_format: String,
    pub deletion_grace_period_days: i64,
    pub request_expiration_days: i64,
    pub export_expiration_days: i64,
    pub export_base_url: String,
    pub verify_base_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecretsConfig {
    pub encryption_key: String,
    pub rotation_days: i64,
    pub max_versions_to_keep: i64,
}

impl ComplianceConfig {
    /// Load configuration from environment variables with sane defaults.
    pub fn from_env() -> Self {
        let node_env = std::env::var("NODE_ENV").unwrap_or_default();
        let is_production = node_env.eq_ignore_ascii_case("production") || node_env.eq_ignore_ascii_case("prod");

        let auth_token = env_or("COMPLIANCE_AUTH_TOKEN", "");
        let audit_signing_key = env_or("AUDIT_SIGNING_KEY", "");
        let secrets_encryption_key = env_or("SECRETS_ENCRYPTION_KEY", "");

        if is_production {
            if auth_token.trim().is_empty() {
                panic!("COMPLIANCE_AUTH_TOKEN must be set in production");
            }
            if audit_signing_key.trim().is_empty() {
                panic!("AUDIT_SIGNING_KEY must be set in production");
            }
            if secrets_encryption_key.trim().is_empty() {
                panic!("SECRETS_ENCRYPTION_KEY must be set in production");
            }
        }

        Self {
            port: env_or("COMPLIANCE_PORT", "3011").parse().unwrap_or(3011),
            database_url: env_or(
                "DATABASE_URL",
                "postgres://postgres@localhost:5432/apexmail",
            ),
            redis_url: env_or("REDIS_URL", "redis://localhost:6379"),
            auth_token,
            cors_origin: env_or("CORS_ORIGIN", "*"),

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
                max_ocr_images: env_or("CONTENT_MAX_OCR_IMAGES", "5")
                    .parse()
                    .unwrap_or(5),
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
                export_base_url: env_or(
                    "GDPR_EXPORT_BASE_URL",
                    "https://exports.apexmail.ee",
                ),
                verify_base_url: env_or(
                    "GDPR_VERIFY_BASE_URL",
                    "https://gdpr.apexmail.ee",
                ),
            },

            secrets: SecretsConfig {
                encryption_key: secrets_encryption_key,
                rotation_days: env_i64("SECRETS_ROTATION_DAYS", 90),
                max_versions_to_keep: env_i64("SECRETS_MAX_VERSIONS", 10),
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
    }
}
