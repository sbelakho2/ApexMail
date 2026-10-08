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

    /// Email addresses notified (via the breach workflow's ops log) when a
    /// breach report is recorded. BREACH_NOTIFICATION_EMAILS, comma-separated.
    pub breach_notification_emails: Vec<String>,
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
    /// Envelope sender for DSR verification emails queued by the outbox
    /// flush job (`dsr_outbox_flush`). MUST live on the platform's system
    /// domain (apexmail.ee) — the worker rejects rows whose sender does not
    /// match the verified system `domains` row.
    /// Env: `COMPLIANCE_SYSTEM_FROM` (default `noreply@apexmail.ee`).
    pub system_from_address: String,
    /// How many pending outbox rows one flush tick may queue.
    /// Env: `COMPLIANCE_DSR_FLUSH_BATCH` (default 25).
    pub outbox_flush_batch: i64,
    /// After this many failed delivery attempts an outbox row is marked
    /// `failed` and no longer retried (retention purges it with the
    /// request window). Env: `COMPLIANCE_DSR_FLUSH_MAX_ATTEMPTS` (default 5).
    pub outbox_flush_max_attempts: i64,
    /// ClickHouse erasure step (audit F1): the analytics `events` table is a
    /// real PII store (recipient addresses) and must be purged on Art. 17
    /// requests. Disabled by default so deployments without ClickHouse get an
    /// honest `skipped_not_configured` line on the deletion certificate
    /// instead of a silent gap.
    /// Env: `GDPR_CLICKHOUSE_ERASURE_ENABLED` (default "false").
    pub clickhouse_erasure_enabled: bool,
    /// Env: `CLICKHOUSE_URL` (default "http://clickhouse:8123" — the
    /// workspace-wide convention, same as the analytics/tracking crates).
    pub clickhouse_url: String,
    /// Env: `CLICKHOUSE_DATABASE` (default "apexmail").
    pub clickhouse_database: String,
    /// Env: `CLICKHOUSE_USER` (default "default").
    pub clickhouse_user: String,
    /// Env: `CLICKHOUSE_PASSWORD` (default "").
    pub clickhouse_password: String,
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

/// Errors raised while loading [`ComplianceConfig`] from the environment.
///
/// Shape mirrors the workspace's audit convention (`api-server`'s
/// `ConfigError`) so a missing production secret fails the same way in every
/// service.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required environment variable: {0}")]
    MissingVar(String),
    #[error("invalid value for {var}: {reason}")]
    Invalid { var: String, reason: String },
    #[error("production security check failed: {0}")]
    SecurityCheck(String),
}

impl ComplianceConfig {
    /// Load configuration from environment variables.
    ///
    /// SEC (external audit): an empty `COMPLIANCE_AUTH_TOKEN` /
    /// `SECRETS_ENCRYPTION_KEY` used to be replaced by an ephemeral
    /// `auto-*` value IN PRODUCTION. A regenerated encryption key made every
    /// persisted encrypted secret unreadable after a restart, and a
    /// regenerated auth token broke every dependent service's bearer token.
    /// Production now REFUSES to start (this returns
    /// [`ConfigError::MissingVar`]; the server binary exits 78 / EX_CONFIG)
    /// when either variable is missing. Ephemeral generation happens in
    /// development/test only, and is logged. The raw values are read BEFORE
    /// anything is bound, so the production checks observe exactly what the
    /// environment provided.
    pub fn from_env() -> Result<Self, ConfigError> {
        let node_env = std::env::var("NODE_ENV").unwrap_or_default();
        let is_production =
            node_env.eq_ignore_ascii_case("production") || node_env.eq_ignore_ascii_case("prod");

        let raw_auth_token = env_or("COMPLIANCE_AUTH_TOKEN", "");
        let raw_secrets_encryption_key = env_or("SECRETS_ENCRYPTION_KEY", "");
        let raw_audit_signing_key = env_or("AUDIT_SIGNING_KEY", "");

        let (auth_token, secrets_encryption_key, audit_signing_key) = if is_production {
            if raw_auth_token.trim().is_empty() {
                return Err(ConfigError::MissingVar("COMPLIANCE_AUTH_TOKEN".into()));
            }
            if raw_secrets_encryption_key.trim().is_empty() {
                return Err(ConfigError::MissingVar("SECRETS_ENCRYPTION_KEY".into()));
            }
            // I-4 continuity contract (unchanged): an auto-generated audit
            // signing key silently invalidates the hash-chain signatures on
            // every restart. Either the key is provided, or it is generated
            // ONCE and persisted to AUDIT_SIGNING_KEY_FILE; without a file
            // path the service refuses to start (fail fast, documented).
            let audit_signing_key = if raw_audit_signing_key.trim().is_empty() {
                let key_file = env_or("AUDIT_SIGNING_KEY_FILE", "");
                resolve_audit_signing_key(&key_file)
            } else {
                raw_audit_signing_key
            };
            (
                raw_auth_token,
                raw_secrets_encryption_key,
                audit_signing_key,
            )
        } else {
            // Development/test: ephemeral values are acceptable — every
            // restart rotates them — but they must be loud.
            let auth_token = if raw_auth_token.trim().is_empty() {
                tracing::warn!(
                    "SECURITY: COMPLIANCE_AUTH_TOKEN missing in development; generated an ephemeral runtime token (redacted)"
                );
                format!("auto-compliance-token-{}", Uuid::new_v4())
            } else {
                raw_auth_token
            };
            let secrets_encryption_key = if raw_secrets_encryption_key.trim().is_empty() {
                tracing::warn!(
                    "SECURITY: SECRETS_ENCRYPTION_KEY missing in development; generated an ephemeral runtime key (redacted)"
                );
                format!("auto-secrets-key-{}", Uuid::new_v4())
            } else {
                raw_secrets_encryption_key
            };
            (auth_token, secrets_encryption_key, raw_audit_signing_key)
        };

        Ok(Self {
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
                // G: default to the compliance service's own host (same as
                // verify_base_url) — exports are served by this crate's
                // GET /gdpr/exports/{id} route, not a third-party bucket.
                // Both URLs must ALWAYS be absolute: an empty env value
                // (compose default) falls back to the documented default.
                export_base_url: env_or_nonempty("GDPR_EXPORT_BASE_URL", "https://gdpr.apexmail.ee"),
                verify_base_url: env_or_nonempty("GDPR_VERIFY_BASE_URL", "https://gdpr.apexmail.ee"),
                consent_signing_key: env_or("CONSENT_SIGNING_KEY", ""),
                access_request_max_messages: env_i64("GDPR_ACCESS_MAX_MESSAGES", 10_000),
                system_from_address: env_or("COMPLIANCE_SYSTEM_FROM", "noreply@apexmail.ee"),
                outbox_flush_batch: env_i64("COMPLIANCE_DSR_FLUSH_BATCH", 25),
                outbox_flush_max_attempts: env_i64("COMPLIANCE_DSR_FLUSH_MAX_ATTEMPTS", 5),
                // F1: ClickHouse erasure step — same env names as the
                // analytics/tracking crates' ClickHouse clients.
                clickhouse_erasure_enabled: env_or("GDPR_CLICKHOUSE_ERASURE_ENABLED", "false")
                    == "true",
                clickhouse_url: env_or("CLICKHOUSE_URL", "http://clickhouse:8123"),
                clickhouse_database: env_or("CLICKHOUSE_DATABASE", "apexmail"),
                clickhouse_user: env_or("CLICKHOUSE_USER", "default"),
                clickhouse_password: env_or("CLICKHOUSE_PASSWORD", ""),
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

            breach_notification_emails: env_or("BREACH_NOTIFICATION_EMAILS", "")
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        })
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Like [`env_or`], but a variable that is SET-BUT-EMPTY (or whitespace-only)
/// counts as unset.
///
/// The shipped compose passes `GDPR_VERIFY_BASE_URL=` / `GDPR_EXPORT_BASE_URL=`
/// through as empty strings. `env_or` returned them verbatim, so every DSR
/// verification email carried a RELATIVE `/gdpr/verify/{id}` link and
/// `gdpr_exports.export_url` a relative `/gdpr/exports/{id}` path — links the
/// tracking service (correctly) refuses as an invalid redirect target, so the
/// printed link in the delivered mail is unclickable (dogfood 2026-10-08). An
/// empty value must fall back to the documented default, never produce a
/// relative link.
fn env_or_nonempty(key: &str, default: &str) -> String {
    match std::env::var(key) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => default.to_string(),
    }
}

/// I-4: resolve the audit signing key when `AUDIT_SIGNING_KEY` is unset in
/// production.
///
/// - `key_file` provided and readable with content → reuse the persisted key.
/// - `key_file` provided but empty/absent → generate once and persist, so the
///   key survives restarts (a per-restart key invalidates every archived
///   chain signature).
/// - No `key_file` → refuse to start (fail fast): returning an ephemeral key
///   here would silently break audit-chain verification after each restart.
fn resolve_audit_signing_key(key_file: &str) -> String {
    if key_file.trim().is_empty() {
        panic!(
            "AUDIT_SIGNING_KEY is not set in production and no AUDIT_SIGNING_KEY_FILE is \
             configured. An auto-generated key would invalidate audit chain signatures on \
             every restart. Set AUDIT_SIGNING_KEY, or set AUDIT_SIGNING_KEY_FILE so the \
             generated key can be persisted and reused."
        );
    }

    match std::fs::read_to_string(key_file) {
        Ok(existing) if !existing.trim().is_empty() => {
            tracing::warn!(
                file = key_file,
                "AUDIT_SIGNING_KEY missing in production; loaded persisted key from file"
            );
            existing.trim().to_string()
        }
        _ => {
            let generated = format!("auto-audit-signing-key-{}", Uuid::new_v4());
            match std::fs::write(key_file, &generated) {
                Ok(()) => {
                    tracing::warn!(
                        file = key_file,
                        "AUDIT_SIGNING_KEY missing in production; generated and persisted a new key"
                    );
                    generated
                }
                Err(e) => panic!(
                    "AUDIT_SIGNING_KEY is not set and the generated key could not be \
                     persisted to AUDIT_SIGNING_KEY_FILE ({key_file}): {e}"
                ),
            }
        }
    }
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
        // SEC fix: from_env is fallible now (production refuses ephemeral
        // secrets); the default development test environment must still load.
        let cfg = ComplianceConfig::from_env().expect("config loads in development");
        assert_eq!(cfg.port, 3011);
        assert_eq!(cfg.risk.weights.phishing_detection, 2.0);
        assert_eq!(cfg.risk.base_limits.max_daily_emails, 10_000);
        assert_eq!(cfg.content.spam_threshold, 50.0);
        assert_eq!(cfg.audit.retention_days, 365);
        assert_eq!(cfg.gdpr.data_retention_days, 730);
        assert_eq!(cfg.secrets.rotation_days, 90);
        // DSR outbox flush defaults (system sender on the platform domain).
        assert_eq!(cfg.gdpr.system_from_address, "noreply@apexmail.ee");
        assert_eq!(cfg.gdpr.outbox_flush_batch, 25);
        assert_eq!(cfg.gdpr.outbox_flush_max_attempts, 5);
        // F1: ClickHouse erasure step defaults (off unless explicitly enabled).
        assert!(!cfg.gdpr.clickhouse_erasure_enabled);
        assert_eq!(cfg.gdpr.clickhouse_url, "http://clickhouse:8123");
        assert_eq!(cfg.gdpr.clickhouse_database, "apexmail");
        // SEC-15: DSAR rate limit defaults
        assert_eq!(cfg.dsar_rate_limit.per_user, 1);
        assert_eq!(cfg.dsar_rate_limit.per_tenant, 100);
        assert_eq!(cfg.dsar_rate_limit.verify_attempts, 5);
        assert_eq!(cfg.dsar_rate_limit.user_window_secs, 86400);
        assert_eq!(cfg.dsar_rate_limit.tenant_window_secs, 86400);
        assert_eq!(cfg.dsar_rate_limit.verify_window_secs, 3600);
    }

    // ── I-4: audit signing key persistence ─────────────────────

    fn temp_key_file(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir(); // nosemgrep: rust.lang.security.temp-dir.temp-dir — test fixture under a unique pid/uuid path — no predictable-name temp collision
        path.push(format!("{}-{}", name, std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    /// A generated key is persisted and REUSED on the next start — the key
    /// must be stable across restarts for archived chain signatures to stay
    /// verifiable.
    #[test]
    fn test_audit_signing_key_generated_then_reused() {
        let path = temp_key_file("audit-key-persist-test");
        let _ = std::fs::remove_file(&path);

        let first = resolve_audit_signing_key(path.to_str().unwrap());
        assert!(!first.trim().is_empty());
        assert!(path.exists(), "key must be persisted to the file");

        let second = resolve_audit_signing_key(path.to_str().unwrap());
        assert_eq!(
            first, second,
            "persisted key must be reused, not regenerated"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Without a key file, production must fail fast instead of silently
    /// generating an ephemeral key.
    #[test]
    #[should_panic(expected = "AUDIT_SIGNING_KEY")]
    fn test_audit_signing_key_fails_fast_without_file() {
        let _ = resolve_audit_signing_key("");
    }

    // ── SEC: production refuses ephemeral auth/encryption secrets ──

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

    /// Production + missing COMPLIANCE_AUTH_TOKEN → from_env errs with a
    /// message naming the variable (before any ephemeral value is bound).
    #[test]
    fn test_production_missing_auth_token_is_refused() {
        set_env("NODE_ENV", "production");
        unset_env("COMPLIANCE_AUTH_TOKEN");
        set_env(
            "SECRETS_ENCRYPTION_KEY",
            "prod-secrets-key-0123456789abcdef",
        );
        set_env(
            "AUDIT_SIGNING_KEY",
            "prod-audit-signing-key-0123456789abcdef",
        );

        let err = ComplianceConfig::from_env().unwrap_err();
        assert!(matches!(err, ConfigError::MissingVar(_)));
        assert!(
            err.to_string().contains("COMPLIANCE_AUTH_TOKEN"),
            "error must name the missing variable, got: {err}"
        );
    }

    /// Production + missing SECRETS_ENCRYPTION_KEY → same refusal, naming the
    /// variable. A generated key here would make every persisted encrypted
    /// secret unreadable after a restart.
    #[test]
    fn test_production_missing_secrets_encryption_key_is_refused() {
        set_env("NODE_ENV", "production");
        set_env("COMPLIANCE_AUTH_TOKEN", "prod-auth-token");
        unset_env("SECRETS_ENCRYPTION_KEY");
        set_env(
            "AUDIT_SIGNING_KEY",
            "prod-audit-signing-key-0123456789abcdef",
        );

        let err = ComplianceConfig::from_env().unwrap_err();
        assert!(matches!(err, ConfigError::MissingVar(_)));
        assert!(
            err.to_string().contains("SECRETS_ENCRYPTION_KEY"),
            "error must name the missing variable, got: {err}"
        );
    }

    /// Whitespace-only values count as missing (the trim contract the old
    /// generation path also used).
    #[test]
    fn test_production_whitespace_only_secrets_are_refused() {
        set_env("NODE_ENV", "production");
        set_env("COMPLIANCE_AUTH_TOKEN", "   ");
        set_env("SECRETS_ENCRYPTION_KEY", "\t");
        set_env(
            "AUDIT_SIGNING_KEY",
            "prod-audit-signing-key-0123456789abcdef",
        );

        let err = ComplianceConfig::from_env().unwrap_err();
        assert!(
            err.to_string().contains("COMPLIANCE_AUTH_TOKEN"),
            "error must name the first missing variable, got: {err}"
        );
    }

    /// Production + explicit values → loaded verbatim; nothing is generated
    /// or replaced.
    #[test]
    fn test_production_explicit_secrets_are_used_verbatim() {
        set_env("NODE_ENV", "production");
        set_env("COMPLIANCE_AUTH_TOKEN", "explicit-prod-token");
        set_env("SECRETS_ENCRYPTION_KEY", "explicit-prod-encryption-key");
        set_env("AUDIT_SIGNING_KEY", "explicit-prod-audit-key");

        let cfg = ComplianceConfig::from_env()
            .expect("production config with explicit secrets must load");
        assert_eq!(cfg.auth_token, "explicit-prod-token");
        assert_eq!(cfg.secrets.encryption_key, "explicit-prod-encryption-key");
        assert_eq!(cfg.audit.signing_key, "explicit-prod-audit-key");
    }

    /// Dogfood 2026-10-08: the shipped compose sets `GDPR_VERIFY_BASE_URL=`
    /// and `GDPR_EXPORT_BASE_URL=` (SET but EMPTY). `env_or` returned the
    /// empty string verbatim, so the DSR verification email carried a
    /// RELATIVE `/gdpr/verify/{id}` link (and exports a relative
    /// `/gdpr/exports/{id}` path) — the tracking service (correctly) refuses
    /// those as invalid targets, making the printed link unclickable. Empty
    /// or whitespace-only must mean "unset": the documented absolute default
    /// applies, never a relative link.
    #[test]
    fn empty_gdpr_base_urls_fall_back_to_the_absolute_defaults() {
        set_env("NODE_ENV", "development");
        set_env("GDPR_VERIFY_BASE_URL", "");
        set_env("GDPR_EXPORT_BASE_URL", "   ");

        let cfg = ComplianceConfig::from_env().expect("development config must load");
        assert_eq!(
            cfg.gdpr.verify_base_url, "https://gdpr.apexmail.ee",
            "empty GDPR_VERIFY_BASE_URL must fall back to the absolute default"
        );
        assert_eq!(
            cfg.gdpr.export_base_url, "https://gdpr.apexmail.ee",
            "whitespace GDPR_EXPORT_BASE_URL must fall back to the absolute default"
        );
        let verify_url = format!(
            "{}/gdpr/verify/{}",
            cfg.gdpr.verify_base_url, "11111111-2222-3333-4444-555566667777"
        );
        assert!(
            verify_url.starts_with("https://"),
            "the emitted verification link must be absolute, got: {verify_url}"
        );
    }

    /// Development + missing values → ephemeral generation works AND is
    /// logged (both values, both warnings).
    #[test]
    fn test_development_missing_secrets_generate_ephemeral_and_are_logged() {
        set_env("NODE_ENV", "development");
        unset_env("COMPLIANCE_AUTH_TOKEN");
        unset_env("SECRETS_ENCRYPTION_KEY");

        let logs = capture_logs(|| {
            let cfg = ComplianceConfig::from_env().expect("development config must load");
            assert!(
                cfg.auth_token.starts_with("auto-compliance-token-"),
                "ephemeral token expected, got: {}",
                cfg.auth_token
            );
            assert!(
                cfg.secrets.encryption_key.starts_with("auto-secrets-key-"),
                "ephemeral key expected, got: {}",
                cfg.secrets.encryption_key
            );
        });
        assert!(
            logs.contains("COMPLIANCE_AUTH_TOKEN"),
            "token generation must be logged, got: {logs}"
        );
        assert!(
            logs.contains("SECRETS_ENCRYPTION_KEY"),
            "key generation must be logged, got: {logs}"
        );
    }

    /// Pins the generated-vs-required transition: the SAME missing variables
    /// yield an ephemeral value in development and a hard error in production.
    #[test]
    fn test_generated_vs_required_transition_is_pinned_by_environment() {
        unset_env("COMPLIANCE_AUTH_TOKEN");
        unset_env("SECRETS_ENCRYPTION_KEY");

        set_env("NODE_ENV", "development");
        let dev = ComplianceConfig::from_env().expect("development generates ephemeral values");
        assert!(dev.auth_token.starts_with("auto-compliance-token-"));
        assert!(dev.secrets.encryption_key.starts_with("auto-secrets-key-"));

        set_env("NODE_ENV", "production");
        let prod_err = ComplianceConfig::from_env().unwrap_err();
        assert!(
            prod_err.to_string().contains("COMPLIANCE_AUTH_TOKEN"),
            "production refuses the first missing variable, got: {prod_err}"
        );
    }
}
