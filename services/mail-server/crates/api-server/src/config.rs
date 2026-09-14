//! Configuration loaded from environment variables.
//!
//! Includes production-safety checks on secret lengths.

use std::env;
use std::time::Duration;

use kiwicaptcha::{SOLVER_MAX_ARGON2_M_KIB, SOLVER_MAX_ARGON2_TARGET_BITS, SOLVER_MAX_TARGET_BITS};

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
    pub api_replica_count: usize,
    /// Cluster-wide connection budget for PostgreSQL.
    ///
    /// This should be set to approximately `max_connections * expected_replica_count * 1.25`
    /// to leave ~20% headroom for other services (workers, MTAs, batch jobs).
    /// For example, if `max_connections=20` and `expected_replica_count=10`,
    /// a budget of 250 ensures all pods can connect while leaving buffer.
    pub db_cluster_connection_budget: Option<usize>,
    /// Expected number of replicas in the cluster (used for connection budget calculation).
    pub expected_replica_count: u32,

    /// T-304: Prepared statement cache capacity. 0 = disabled. Default: 500.
    pub statement_cache_capacity: usize,

    /// Global query timeout in seconds. Default: 30.
    pub query_timeout_seconds: u64,

    /// Optional replica database URL for read-only queries.
    /// If not set, all queries go to the primary.
    pub database_replica_url: Option<String>,

    // ── Redis ───────────────────────────────────────────────
    pub redis_host: String,
    pub redis_port: u16,
    pub redis_password: Option<String>,
    pub redis_db: u8,
    pub redis_pool_max_size: usize,

    // ── Auth ────────────────────────────────────────────────
    pub jwt_private_key_pem: String,
    pub jwt_public_key_pem: String,
    pub jwt_previous_public_keys_pem: Vec<String>,
    pub jwt_expiry: Duration,
    pub api_key_hash_secret: String,

    // ── Rate limiting ───────────────────────────────────────
    pub rate_limit_window_ms: u64,
    pub rate_limit_max_requests: u64,

    // ── Backpressure ────────────────────────────────────────
    pub max_inflight_requests: usize,

    // ── CORS ────────────────────────────────────────────────
    pub cors_origins: Vec<String>,
    pub trusted_proxies: Vec<String>,

    // ── UI surface routing ──────────────────────────────────
    pub ui_web_hosts: Vec<String>,
    pub ui_control_plane_hosts: Vec<String>,
    pub ui_marketing_hosts: Vec<String>,
    pub ui_marketing_surface: String,
    pub ui_default_surface: Option<String>,

    // ── Webhooks ────────────────────────────────────────────
    pub webhook_signing_secret: String,
    pub webhook_timeout_ms: u64,
    pub webhook_max_retries: u32,

    // ── Idempotency ─────────────────────────────────────────
    pub idempotency_ttl_seconds: u64,

    // ── AWS SES (dedicated IPs) ─────────────────────────────
    pub aws_region: String,
    pub ses_ip_pool_prefix: String,
    pub ses_default_warmup_days: u32,
    /// SES configuration set for event tracking (bounces, complaints, deliveries).
    pub ses_configuration_set: Option<String>,

    // ── OAuth / SSO ─────────────────────────────────────────
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,
    pub github_client_id: Option<String>,
    pub github_client_secret: Option<String>,
    pub oauth_redirect_base_url: String,

    // ── Session / Impersonation ─────────────────────────────
    pub session_secret: String,
    pub impersonation_secret: String,
    pub csrf_secret: String,
    /// Production-only strictness for the public-auth rate limiter: false
    /// disables the middleware OUTSIDE production (the test suite's parallel
    /// tests share one Redis and one socket-less fallback path bucket, which
    /// turns the 20/min cap into cross-test 429 coupling). Production always
    /// enforces the limiter regardless of this flag.
    pub public_rate_limit_enabled: bool,

    // ── Control Plane ───────────────────────────────────────
    /// Static API key used by the control-plane backend to authenticate
    /// internal requests. If set, X-API-Key matching this value bypasses
    /// the normal api_keys DB lookup and returns a super-admin identity.
    pub control_plane_api_key: Option<String>,
    /// Base URL of the sales-autopilot service — the canonical sales brain the
    /// control plane proxies to.
    ///
    /// Overridden by `SALES_AUTOPILOT_BASE_URL`; the compose stacks set it to
    /// `http://sales-autopilot:3010`. The default is a loopback address so a
    /// local (non-containerised) run reaches a service started on this host —
    /// it must never be a bind address like `0.0.0.0`, which is not a routable
    /// peer and would make every call fail from inside a container.
    pub sales_autopilot_base_url: String,
    pub internal_service_token: Option<String>,
    /// ai-service base URL for the grounded assistant (empty = assistant
    /// disabled; /v1/ai/chat then returns 503 with the support escalation).
    pub ai_service_base_url: String,
    /// Control-plane session hardening (`middleware::cp_auth`).
    pub cp_auth: CpAuthConfig,

    // ── Tracking / SSE ──────────────────────────────────────
    /// Shared HMAC secret with the tracking-service, used to issue short-lived
    /// SSE stream tokens. Must match the tracking-service `TRACKING_SECRET_KEY`.
    pub tracking_secret_key: String,

    // ── Billing documents ───────────────────────────────────
    pub billing_company_iban: String,
    pub billing_company_phone: String,

    // ── Metrics ──────────────────────────────────────────────
    /// Port for the dedicated Prometheus metrics HTTP endpoint (default:9090).
    /// Set to 0 to disable the metrics server.
    pub metrics_port: u16,

    // ── Email Grader ─────────────────────────────────────────
    /// Enable the email grader feature.
    pub grader_enabled: bool,
    /// Max grader requests per window per IP.
    pub grader_rate_limit: u32,
    /// Rate-limit window in seconds.
    pub grader_rate_window_seconds: u64,
    /// Cache TTL for domain checks in seconds.
    pub grader_cache_ttl_seconds: u64,
    /// Max body size for grader submissions in bytes.
    pub grader_max_body_size: usize,

    // ── Inbox Placement ─────────────────────────────────────
    /// Enable the inbox placement testing feature.
    pub placement_enabled: bool,
    /// Polling interval in seconds for the placement scheduler.
    pub placement_polling_interval_secs: u64,
    /// Maximum IMAP polling attempts per seed account.
    pub placement_max_polling_attempts: u32,
    /// Maximum seed accounts per test.
    pub placement_max_seeds_per_test: u32,
    /// Maximum tests per hour per tenant (rate limit).
    pub placement_max_tests_per_hour: u32,
    /// IMAP connection timeout in seconds.
    pub placement_imap_timeout_secs: u64,
    /// Whether to encrypt stored IMAP passwords.
    pub placement_encrypt_passwords: bool,
    /// Secret key used for field encryption of IMAP passwords.
    pub placement_encryption_secret: String,

    // ── KiwiCaptcha (native Rust proof-of-work CAPTCHA) ────
    /// KiwiCaptcha is a first-party, self-contained proof-of-work
    /// CAPTCHA — no external services, no iframe, no external JS.
    /// Enable KiwiCaptcha verification on auth routes (login, signup).
    pub kiwi_enabled: bool,
    /// WAF request screening (audit F-WIRING-1). Monitor mode by default:
    /// would-block verdicts are logged; `waf_enforce` turns them into 403s.
    pub waf_enabled: bool,
    pub waf_enforce: bool,
    /// HMAC secret key used to sign and verify KiwiCaptcha challenges.
    /// In development, set to "dev" to bypass verification.
    pub kiwi_secret_key: String,
    /// Proof-of-work algorithm for issued challenges ("sha256" | "argon2id").
    /// Decided explicitly, never inferred from a numeric flag.
    pub kiwi_algorithm: kiwicaptcha::PoWAlgorithm,
    /// Argon2id memory cost in KiB (ignored for SHA-256 challenges).
    /// Must satisfy m_kib >= 8 * p and be browser-solvable (<= 65536).
    pub kiwi_argon_m_kib: u32,
    /// Argon2id time cost.
    pub kiwi_argon_t: u32,
    /// Argon2id parallelism.
    pub kiwi_argon_p: u32,
    /// Required leading zero bits for SHA-256 challenges.
    /// Default 20 (~1M expected hashes = ~2-5s on a browser).
    pub kiwi_difficulty_bits: u32,
    /// Required leading zero bits for Argon2id challenges. Argon2id hashes are
    /// memory-hard and ~1000x slower than SHA-256, so the difficulty must be
    /// far lower (default 8, clamped to the browser-solvable ceiling).
    pub kiwi_argon2_difficulty_bits: u32,
    /// Challenge lifetime in seconds. Default 120.
    pub kiwi_challenge_ttl_secs: u64,
    /// Minimum acceptable solve duration in milliseconds. When set, it
    /// overrides the per-challenge difficulty-derived floor; 0 disables the
    /// check. Default: derived from difficulty at issuance.
    pub kiwi_min_duration_ms: Option<u64>,
    /// Global concurrency cap for Argon2id verification (0 = unlimited).
    /// Bounds aggregate memory-hard verification work across all nonces.
    /// Default 2.
    pub kiwi_argon2_max_concurrent: u32,
    /// Enforce telemetry-based bot rejection inside `verify_solution`. The
    /// telemetry is client-controlled and forgeable, so this is a
    /// defense-in-depth signal, never the security boundary. When enabled,
    /// clients that fail the heuristic (including clients that submit no
    /// telemetry at all) are rejected with BotDetected. Default false:
    /// telemetry defaults to OFF (the widget's default mode is "off" and
    /// enforcement must not reject every user whose page ships no telemetry).
    pub kiwi_enforce_telemetry: bool,
    /// Enable auto-tuning of difficulty based on server load. Default false.
    /// Only applies to SHA-256 challenges; Argon2id difficulty is static.
    pub kiwi_auto_tune: bool,
    /// Minimum target bits when auto-tuning is idle. Default 10.
    pub kiwi_auto_tune_min_bits: u32,
    /// Maximum target bits when auto-tuning is under peak load. Default 20.
    pub kiwi_auto_tune_max_bits: u32,

    // ── HTTP Client ─────────────────────────────────────────
    /// Timeout in seconds for the internal HTTP client used for outbound
    /// requests (webhooks, enrichment, etc.). Default: 30.
    pub http_client_timeout_secs: u64,

    // ── Internal TLS (SEC-104) ──────────────────────────────
    /// Whether to require TLS for internal service-to-service communication
    /// (traces, logs, metrics, inter-service API calls).
    /// When enabled, services present mutual TLS certificates.
    pub internal_tls_enabled: bool,
    /// Path to the CA certificate PEM file for verifying internal service certs.
    pub internal_tls_ca_cert_path: Option<String>,
    /// Path to the client certificate PEM file for mTLS.
    pub internal_tls_client_cert_path: Option<String>,
    /// Path to the client private key PEM file for mTLS.
    pub internal_tls_client_key_path: Option<String>,
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

fn generated_dev_secret(label: &str) -> String {
    format!("dev-{label}-{}", uuid::Uuid::new_v4().simple())
}

fn env_required(key: &str) -> Result<String, ConfigError> {
    env::var(key).map_err(|_| ConfigError::MissingVar(key.to_string()))
}

fn env_required_pem(key: &str) -> Result<String, ConfigError> {
    let raw = env_required(key)?;
    Ok(raw.replace("\\n", "\n"))
}

fn parse_optional_pem_list(value: Option<String>) -> Vec<String> {
    value
        .unwrap_or_default()
        .split("||")
        .map(|pem| pem.trim().replace("\\n", "\n"))
        .filter(|pem| !pem.is_empty())
        .collect()
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

fn parse_usize(key: &str, val: &str) -> Result<usize, ConfigError> {
    val.parse::<usize>().map_err(|_| ConfigError::Invalid {
        var: key.to_string(),
        reason: format!("expected usize, got '{val}'"),
    })
}

fn parse_duration_hours(key: &str, val: &str) -> Result<Duration, ConfigError> {
    // Accept formats:"24h", "1h", or plain seconds
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
    let items: Vec<String> = val
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

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

fn is_local_base_url(base_url: &str) -> bool {
    url::Url::parse(base_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        // `url::Url::host_str` keeps the brackets on IPv6 literals, so the
        // loopback spelling "[::1]" must be accepted alongside "::1".
        .map(|host| matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1" | "[::1]"))
        .unwrap_or(false)
}

/// Control-plane session hardening knobs, consumed by
/// `middleware::cp_auth` (the `require_cp_auth` gate on the admin route
/// group).
///
/// Defaults are safe: an EMPTY allowlist means every network is allowed —
/// the MFA-enabled + admin/owner-role session requirements are enforced
/// regardless of the allowlist. The session secret defaults to a generated
/// ephemeral value in development and is REQUIRED in production.
#[derive(Debug, Clone)]
pub struct CpAuthConfig {
    /// CIDR/IP allowlist for control-plane requests (CSV via
    /// `CP_ALLOWED_IPS`). Empty = all networks allowed.
    pub allowed_ips: Vec<String>,
    /// HMAC key signing `apexmail_cp_session` cookies
    /// (`CP_SESSION_SECRET`).
    pub session_secret: String,
    /// Idle timeout in seconds (`CP_SESSION_IDLE_TIMEOUT_SECS`): a CP
    /// session with no activity for this long is rejected.
    pub session_idle_timeout_secs: u64,
    /// Absolute lifetime ceiling in seconds
    /// (`CP_SESSION_ABSOLUTE_TIMEOUT_SECS`), regardless of activity.
    pub session_absolute_timeout_secs: u64,
}

impl Default for CpAuthConfig {
    fn default() -> Self {
        Self {
            allowed_ips: Vec::new(),
            session_secret: generated_dev_secret("cp-session-secret"),
            session_idle_timeout_secs: 900,
            session_absolute_timeout_secs: 14400,
        }
    }
}

impl CpAuthConfig {
    fn from_env() -> Result<Self, ConfigError> {
        let config = Self {
            allowed_ips: parse_csv(&env_or("CP_ALLOWED_IPS", "")),
            session_secret: env::var("CP_SESSION_SECRET")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| generated_dev_secret("cp-session-secret")),
            session_idle_timeout_secs: parse_u64(
                "CP_SESSION_IDLE_TIMEOUT_SECS",
                &env_or("CP_SESSION_IDLE_TIMEOUT_SECS", "900"),
            )?,
            session_absolute_timeout_secs: parse_u64(
                "CP_SESSION_ABSOLUTE_TIMEOUT_SECS",
                &env_or("CP_SESSION_ABSOLUTE_TIMEOUT_SECS", "14400"),
            )?,
        };
        if config.session_idle_timeout_secs == 0
            || config.session_idle_timeout_secs >= config.session_absolute_timeout_secs
        {
            return Err(ConfigError::Invalid {
                var: "CP_SESSION_IDLE_TIMEOUT_SECS".into(),
                reason: format!(
                    "must be > 0 and strictly less than CP_SESSION_ABSOLUTE_TIMEOUT_SECS ({})",
                    config.session_absolute_timeout_secs,
                ),
            });
        }
        Ok(config)
    }
}

fn default_cors_origins(environment: Environment, base_url: &str) -> Vec<String> {
    if environment == Environment::Development && is_local_base_url(base_url) {
        vec!["*".into()]
    } else {
        Vec::new()
    }
}

fn default_max_inflight_requests(db_max_connections: u32) -> usize {
    // Keep request concurrency close to the DB pool so database-heavy traffic
    // cannot build an unbounded queue in front of SQLx while still leaving a
    // small amount of headroom for non-DB routes.
    let db_connections = db_max_connections.max(1) as usize;
    std::cmp::max(16usize, db_connections.saturating_mul(3).saturating_div(2))
}

/// Default for [`Config::expected_replica_count`].
fn default_expected_replicas() -> u32 {
    3
}

fn default_query_timeout() -> u64 {
    30
}

/// Default value for the cluster connection budget when `DB_CLUSTER_CONNECTION_BUDGET`
/// is not set. Computed as 80% of `max_connections * 3` (3 being the default replica count).
fn default_db_cluster_connection_budget(max_connections: u32) -> usize {
    let total = max_connections as usize * default_expected_replicas() as usize;
    (total as f64 * 0.8) as usize
}

fn validate_db_connection_budget(
    db_max_connections: u32,
    api_replica_count: usize,
    expected_replica_count: u32,
    db_cluster_connection_budget: Option<usize>,
) -> Result<(), ConfigError> {
    if api_replica_count == 0 {
        return Err(ConfigError::Invalid {
            var: "API_REPLICA_COUNT".into(),
            reason: "must be greater than 0".into(),
        });
    }
    if let Some(budget) = db_cluster_connection_budget {
        let requested_connections = db_max_connections as usize * api_replica_count;
        if requested_connections > budget {
            return Err(ConfigError::Invalid {
                var: "DB_CLUSTER_CONNECTION_BUDGET".into(),
                reason: format!(
                    "DB_MAX_CONNECTIONS ({db_max_connections}) * API_REPLICA_COUNT ({api_replica_count}) exceeds shared DB budget ({budget}). Expected cluster replicas: {expected_replica_count}"
                ),
            });
        }
    } else {
        // When no explicit budget is set, compute a sensible default
        // and emit a warning if the estimated cluster total exceeds it.
        let budget = default_db_cluster_connection_budget(db_max_connections);
        let total_potential = db_max_connections as usize * api_replica_count;
        if total_potential > budget {
            tracing::warn!(
                "DB_CLUSTER_CONNECTION_BUDGET is not configured. Default budget is {budget} \
                 (80% of {db_max_connections} max_connections × 3 default replicas), but \
                 API_REPLICA_COUNT={api_replica_count} × DB_MAX_CONNECTIONS={db_max_connections} = \
                 {total_potential} potential connections. Set DB_CLUSTER_CONNECTION_BUDGET explicitly."
            );
        }
    }
    Ok(())
}

/// Validate rate limit configuration values at startup.
///
/// Checks that:
/// - `max_requests` is positive (> 0)
/// - `window_seconds` is in a reasonable range (>= 1, <= 86400)
pub fn validate_rate_limit_config(max_requests: u32, window_seconds: u64) -> Result<(), String> {
    if max_requests == 0 {
        return Err("rate_limit.max_requests must be > 0".to_string());
    }
    if window_seconds == 0 {
        return Err("rate_limit.window_seconds must be > 0".to_string());
    }
    if window_seconds > 86400 {
        return Err("rate_limit.window_seconds must be <= 86400 (24h)".to_string());
    }
    Ok(())
}

fn validate_secret(
    name: &str,
    value: &str,
    min_len: usize,
    disallowed_values: &[&str],
) -> Result<(), ConfigError> {
    let trimmed = value.trim();
    if trimmed.len() < min_len {
        return Err(ConfigError::SecurityCheck(format!(
            "{name} must be at least {min_len} characters in production"
        )));
    }

    let normalized = trimmed.to_ascii_lowercase();
    if disallowed_values
        .iter()
        .any(|candidate| normalized == candidate.to_ascii_lowercase())
    {
        return Err(ConfigError::SecurityCheck(format!(
            "{name} must not use a placeholder or development secret in production"
        )));
    }

    Ok(())
}

fn validate_required_setting(
    name: &str,
    value: &str,
    disallowed_values: &[&str],
) -> Result<(), ConfigError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::SecurityCheck(format!(
            "{name} must be set in production"
        )));
    }

    let normalized = trimmed.to_ascii_lowercase();
    if disallowed_values
        .iter()
        .any(|candidate| normalized == candidate.to_ascii_lowercase())
    {
        return Err(ConfigError::SecurityCheck(format!(
            "{name} must not use a placeholder value in production"
        )));
    }

    Ok(())
}

fn validate_https_url(name: &str, value: &str) -> Result<(), ConfigError> {
    let parsed = url::Url::parse(value).map_err(|error| {
        ConfigError::SecurityCheck(format!(
            "{name} must be a valid HTTPS URL in production: {error}"
        ))
    })?;
    if parsed.scheme() != "https" {
        return Err(ConfigError::SecurityCheck(format!(
            "{name} must use https in production"
        )));
    }
    Ok(())
}

fn normalize_host(host: &str) -> String {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(stripped) = host.strip_prefix('[') {
        if let Some((addr, _)) = stripped.split_once(']') {
            return addr.to_string();
        }
    }
    if host.matches(':').count() == 1 {
        return host.split(':').next().unwrap_or(&host).to_string();
    }
    host
}

impl Config {
    /// Whether the process is configured to deliver through SES. This mirrors
    /// the worker's shared transport parser: only an explicit `smtp` value
    /// selects SMTP; absent and unrecognized values use the SES default.
    pub fn ses_transport_enabled() -> bool {
        apexmail_lib::transport::email_transport_is_ses(
            env::var("EMAIL_TRANSPORT_TYPE").ok().as_deref(),
        )
    }

    /// Load configuration from environment variables.
    pub fn from_env() -> Result<Self, ConfigError> {
        let environment = match env_or("ENVIRONMENT", "development").to_lowercase().as_str() {
            "production" | "prod" => Environment::Production,
            "staging" => Environment::Staging,
            _ => Environment::Development,
        };
        let session_secret_env = env::var("SESSION_SECRET")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let impersonation_secret_env = env::var("IMPERSONATION_SECRET")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let csrf_secret_env = env::var("CSRF_SECRET")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let tracking_secret_key_env = env::var("TRACKING_SECRET_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty());

        let jwt_private_key_pem = env_required_pem("JWT_PRIVATE_KEY_PEM")?;
        let jwt_public_key_pem = env_required_pem("JWT_PUBLIC_KEY_PEM")?;
        let jwt_previous_public_keys_pem =
            parse_optional_pem_list(env::var("JWT_PREVIOUS_PUBLIC_KEYS_PEM").ok());
        let api_key_hash_secret = env_required("API_KEY_HASH_SECRET")?;
        let webhook_signing_secret = env_required("WEBHOOK_SIGNING_SECRET")?;
        let base_url = env_or("BASE_URL", "http://0.0.0.0:3000");
        let cors_origins = match env::var("CORS_ORIGINS") {
            Ok(value) => parse_csv(&value),
            Err(_) => default_cors_origins(environment, &base_url),
        };
        // SCALE-M-01: Increased default from 20 to 50 for production workloads.
        // Set DB_MAX_CONNECTIONS per-service to control connection pool budget.
        let db_max_connections =
            parse_u32("DB_MAX_CONNECTIONS", &env_or("DB_MAX_CONNECTIONS", "50"))?;
        let redis_pool_default =
            std::cmp::max(32usize, (db_max_connections as usize).saturating_mul(2));
        let redis_pool_default_str = redis_pool_default.to_string();
        let max_inflight_requests_default = default_max_inflight_requests(db_max_connections);
        let api_replica_count =
            parse_usize("API_REPLICA_COUNT", &env_or("API_REPLICA_COUNT", "1"))?;
        let expected_replica_count = parse_u32(
            "EXPECTED_REPLICA_COUNT",
            &env_or(
                "EXPECTED_REPLICA_COUNT",
                &default_expected_replicas().to_string(),
            ),
        )?;
        let statement_cache_capacity = parse_usize(
            "STATEMENT_CACHE_CAPACITY",
            &env_or("STATEMENT_CACHE_CAPACITY", "500"),
        )?;
        let query_timeout_seconds = parse_u64(
            "QUERY_TIMEOUT_SECONDS",
            &env_or(
                "QUERY_TIMEOUT_SECONDS",
                &default_query_timeout().to_string(),
            ),
        )?;
        let db_cluster_connection_budget = env::var("DB_CLUSTER_CONNECTION_BUDGET")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| parse_usize("DB_CLUSTER_CONNECTION_BUDGET", &value))
            .transpose()?;
        validate_db_connection_budget(
            db_max_connections,
            api_replica_count,
            expected_replica_count,
            db_cluster_connection_budget,
        )?;
        let max_inflight_requests = parse_usize(
            "MAX_INFLIGHT_REQUESTS",
            &env_or(
                "MAX_INFLIGHT_REQUESTS",
                &max_inflight_requests_default.to_string(),
            ),
        )?;
        if max_inflight_requests == 0 {
            return Err(ConfigError::Invalid {
                var: "MAX_INFLIGHT_REQUESTS".into(),
                reason: "must be greater than 0".into(),
            });
        }

        // Validate rate limiting configuration — zero or negative values would
        // silently disable rate limiting, leaving the API unprotected.
        let rate_limit_max_requests = parse_u64(
            "RATE_LIMIT_MAX_REQUESTS",
            &env_or("RATE_LIMIT_MAX_REQUESTS", "1000"),
        )?;
        let rate_limit_window_ms = parse_u64(
            "RATE_LIMIT_WINDOW_MS",
            &env_or("RATE_LIMIT_WINDOW_MS", "60000"),
        )?;
        if rate_limit_max_requests == 0 {
            return Err(ConfigError::Invalid {
                var: "RATE_LIMIT_MAX_REQUESTS".into(),
                reason: "must be greater than 0; a value of 0 would disable all rate limiting"
                    .into(),
            });
        }
        if rate_limit_window_ms == 0 {
            return Err(ConfigError::Invalid {
                var: "RATE_LIMIT_WINDOW_MS".into(),
                reason:
                    "must be greater than 0; a value of 0 would disable the rate limiting window"
                        .into(),
            });
        }

        let grader_enabled = env_or("GRADER_ENABLED", "true").parse().unwrap_or(true);
        let grader_rate_limit = parse_u32("GRADER_RATE_LIMIT", &env_or("GRADER_RATE_LIMIT", "10"))?;
        let grader_rate_window_seconds =
            parse_u64("GRADER_RATE_WINDOW", &env_or("GRADER_RATE_WINDOW", "60"))?;
        let grader_cache_ttl_seconds =
            parse_u64("GRADER_CACHE_TTL", &env_or("GRADER_CACHE_TTL", "300"))?;
        let grader_max_body_size = parse_usize(
            "GRADER_MAX_BODY_SIZE",
            &env_or("GRADER_MAX_BODY_SIZE", "1048576"),
        )?;

        let placement_enabled = env_or("PLACEMENT_ENABLED", "true").parse().unwrap_or(true);
        let placement_polling_interval_secs = parse_u64(
            "PLACEMENT_POLLING_INTERVAL",
            &env_or("PLACEMENT_POLLING_INTERVAL", "60"),
        )?;
        let placement_max_polling_attempts = parse_u32(
            "PLACEMENT_MAX_POLLING_ATTEMPTS",
            &env_or("PLACEMENT_MAX_POLLING_ATTEMPTS", "10"),
        )?;
        let placement_max_seeds_per_test = parse_u32(
            "PLACEMENT_MAX_SEEDS_PER_TEST",
            &env_or("PLACEMENT_MAX_SEEDS_PER_TEST", "50"),
        )?;
        let placement_max_tests_per_hour = parse_u32(
            "PLACEMENT_MAX_TESTS_PER_HOUR",
            &env_or("PLACEMENT_MAX_TESTS_PER_HOUR", "5"),
        )?;
        let placement_imap_timeout_secs = parse_u64(
            "PLACEMENT_IMAP_TIMEOUT",
            &env_or("PLACEMENT_IMAP_TIMEOUT", "30"),
        )?;
        let placement_encrypt_passwords = env_or("PLACEMENT_ENCRYPT_PASSWORDS", "true")
            .parse()
            .unwrap_or(true);
        let placement_encryption_secret =
            env_or("PLACEMENT_ENCRYPTION_SECRET", "change-me-in-production");

        // Safe default ON: the SSR auth forms verify the token and the pages
        // render the widget, so the out-of-the-box binary is protected. The
        // dev compose stack sets KIWI_ENABLED=false explicitly for local
        // iteration; disabling in production must be a deliberate act (a
        // startup warning fires below when it happens).
        let kiwi_enabled = env_or("KIWI_ENABLED", "true").parse().unwrap_or(true);
        // Monitor-first WAF (see the field docs): visible in logs from day
        // one, enforcement is a deliberate operator decision.
        let waf_enabled = env_or("WAF_ENABLED", "true").parse().unwrap_or(true);
        let waf_enforce = env_or("WAF_ENFORCE", "false").parse().unwrap_or(false);
        let kiwi_secret_key = env_or("KIWI_SECRET_KEY", "dev");
        if !kiwi_enabled {
            tracing::warn!(
                "KiwiCaptcha is DISABLED (KIWI_ENABLED=false): every login, signup, \
                 password-reset and control-plane-login form runs WITHOUT the \
                 proof-of-work CAPTCHA. Production deployments must not ship this way."
            );
        }
        // Proof-of-work algorithm: explicit, never inferred from a numeric
        // flag. KIWI_ALGORITHM accepts "sha256" (default) or "argon2id".
        let kiwi_algorithm_raw = env_or("KIWI_ALGORITHM", "sha256").to_ascii_lowercase();
        let kiwi_algorithm = if kiwi_algorithm_raw == "argon2id" {
            kiwicaptcha::PoWAlgorithm::Argon2id
        } else {
            kiwicaptcha::PoWAlgorithm::Sha256
        };
        // Argon2id memory cost (KiB). Only meaningful for Argon2id challenges;
        // SHA-256 challenges ignore it. The legacy env name KIWI_ARGON_M_KIB
        // remains accepted. Default 0 => SHA-256 mode is fully functional
        // without any Argon2 configuration.
        let kiwi_argon_m_kib = env::var("KIWI_ARGON_M_KIB")
            .or_else(|_| env::var("KIWI_PBKDF2_ITERATIONS"))
            .unwrap_or_else(|_| "0".into())
            .parse()
            .unwrap_or(0);
        // v5 issuance contract: argon2id t must be 3..=6 (crate MIN_ARGON_TIME,
        // browser driver ceiling 6 — the OLD default of 1 is rejected by both).
        let kiwi_argon_t = env_or("KIWI_ARGON_T", "3").parse().unwrap_or(3);
        let kiwi_argon_p = env_or("KIWI_ARGON_P", "1").parse().unwrap_or(1);
        // 20-bit difficulty = ~1M expected SHA-256 hashes = ~2-5s on a browser.
        // This matches FriendlyCaptcha (~2.5s) and Anubis difficulty-5 (~1M hashes).
        let kiwi_difficulty_bits = env_or("KIWI_DIFFICULTY_BITS", "20").parse().unwrap_or(20);
        // Argon2id difficulty: far lower than SHA-256 because every hash is
        // memory-hard. Clamped to the browser-solvable ceiling.
        let kiwi_argon2_difficulty_bits = env_or("KIWI_ARGON2_DIFFICULTY_BITS", "8")
            .parse()
            .unwrap_or(8)
            .min(SOLVER_MAX_ARGON2_TARGET_BITS);
        let kiwi_challenge_ttl_secs: u64 = env_or("KIWI_CHALLENGE_TTL_SECS", "120")
            .parse()
            .unwrap_or(120);
        let kiwi_min_duration_ms = env::var("KIWI_MIN_DURATION_MS")
            .ok()
            .and_then(|v| v.parse().ok());
        // Same protocol invariant as the core issuers: a floor at or above
        // the TTL leaves no acceptable submission time (TooFast before
        // expiry, Expired after). Fail fast at startup.
        if let Some(ms) = kiwi_min_duration_ms {
            if ms >= kiwi_challenge_ttl_secs.saturating_mul(1000) {
                panic!(
                    "KIWI_MIN_DURATION_MS ({ms}) must be < KIWI_CHALLENGE_TTL_SECS ({kiwi_challenge_ttl_secs}) * 1000"
                );
            }
        }
        let kiwi_argon2_max_concurrent = env::var("KIWI_ARGON2_MAX_CONCURRENT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2);
        let kiwi_enforce_telemetry = env::var("KIWI_ENFORCE_TELEMETRY")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let kiwi_auto_tune = env::var("KIWI_AUTO_TUNE")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let kiwi_auto_tune_min_bits = env_or("KIWI_AUTO_TUNE_MIN_BITS", "10")
            .parse()
            .unwrap_or(10);
        let kiwi_auto_tune_max_bits = env_or("KIWI_AUTO_TUNE_MAX_BITS", "20")
            .parse()
            .unwrap_or(20)
            .min(SOLVER_MAX_TARGET_BITS);
        if !environment.is_production() && kiwi_secret_key == "dev" {
            tracing::info!(
                "KiwiCaptcha configured with dev key — debug builds bypass \
                 verification; release builds still verify (HMAC under the dev key)"
            );
        }
        if kiwi_algorithm == kiwicaptcha::PoWAlgorithm::Argon2id
            && kiwi_argon_m_kib < 8 * kiwi_argon_p
        {
            tracing::error!(
                m_kib = kiwi_argon_m_kib,
                p = kiwi_argon_p,
                "KiwiCaptcha: Argon2id requires m_kib >= 8 * p — refusing to issue impossible challenges"
            );
            return Err(ConfigError::Invalid {
                var: "KIWI_ARGON_M_KIB".into(),
                reason: format!(
                    "must be >= 8 * KIWI_ARGON_P ({}), got {kiwi_argon_m_kib}",
                    kiwi_argon_p * 8
                ),
            });
        }
        if kiwi_algorithm == kiwicaptcha::PoWAlgorithm::Argon2id
            && kiwi_argon_m_kib > SOLVER_MAX_ARGON2_M_KIB
        {
            tracing::warn!(
                m_kib = kiwi_argon_m_kib,
                max = SOLVER_MAX_ARGON2_M_KIB,
                "KiwiCaptcha: Argon2id m_kib exceeds the browser-solvable ceiling — clamping"
            );
        }
        // The v5 contract (crate MIN_ARGON_TIME=3, driver ceiling t<=6, p==1
        // for libsodium cross-verification): an out-of-range t would make
        // issue_challenge error on EVERY request — fail fast at startup.
        if kiwi_algorithm == kiwicaptcha::PoWAlgorithm::Argon2id
            && (!(3..=6).contains(&kiwi_argon_t) || kiwi_argon_p != 1)
        {
            tracing::error!(
                t = kiwi_argon_t,
                p = kiwi_argon_p,
                "KiwiCaptcha: Argon2id requires t in 3..=6 and p == 1 (v5 issuance contract)"
            );
            return Err(ConfigError::Invalid {
                var: "KIWI_ARGON_T".into(),
                reason: format!(
                    "Argon2id requires t in 3..=6 and p == 1; got t={kiwi_argon_t} p={kiwi_argon_p}"
                ),
            });
        }

        let config = Config {
            port: parse_u16("PORT", &env_or("PORT", "3000"))?,
            host: env_or("HOST", "0.0.0.0"),
            base_url,
            environment,
            public_rate_limit_enabled: matches!(
                env_or("PUBLIC_RATE_LIMIT_ENABLED", "true")
                    .to_ascii_lowercase()
                    .as_str(),
                "true" | "1" | "yes" | "on"
            ),

            db_host: env_or("DB_HOST", "127.0.0.1"),
            db_port: parse_u16("DB_PORT", &env_or("DB_PORT", "5432"))?,
            db_name: env_or("DB_NAME", "apexmail"),
            db_user: env_or("DB_USER", "apexmail"),
            db_password: env_or("DB_PASSWORD", ""),
            db_max_connections,
            api_replica_count,
            db_cluster_connection_budget,
            expected_replica_count,
            statement_cache_capacity,
            query_timeout_seconds,
            database_replica_url: env::var("DATABASE_REPLICA_URL")
                .ok()
                .filter(|s| !s.is_empty()),

            redis_host: env_or("REDIS_HOST", "127.0.0.1"),
            redis_port: parse_u16("REDIS_PORT", &env_or("REDIS_PORT", "6379"))?,
            redis_password: env::var("REDIS_PASSWORD").ok().filter(|s| !s.is_empty()),
            redis_db: parse_u8("REDIS_DB", &env_or("REDIS_DB", "0"))?,
            redis_pool_max_size: parse_usize(
                "REDIS_POOL_MAX_SIZE",
                &env_or("REDIS_POOL_MAX_SIZE", &redis_pool_default_str),
            )?,

            jwt_private_key_pem,
            jwt_public_key_pem,
            jwt_previous_public_keys_pem,
            jwt_expiry: parse_duration_hours("JWT_EXPIRY", &env_or("JWT_EXPIRY", "24h"))?,
            api_key_hash_secret,

            rate_limit_window_ms,
            rate_limit_max_requests,
            max_inflight_requests,

            cors_origins,
            trusted_proxies: parse_csv(&env_or("TRUSTED_PROXIES", "")),

            ui_web_hosts: parse_csv(&env_or("UI_WEB_HOSTS", "app.apexmail.ee,127.0.0.1")),
            ui_control_plane_hosts: parse_csv(&env_or(
                "UI_CONTROL_PLANE_HOSTS",
                "admin.apexmail.ee,control.apexmail.ee",
            )),
            ui_marketing_hosts: parse_csv(&env_or(
                "UI_MARKETING_HOSTS",
                "apexmail.ee,www.apexmail.ee",
            )),
            ui_marketing_surface: env_or("UI_MARKETING_SURFACE", "marketing-zola"),
            ui_default_surface: env::var("UI_DEFAULT_SURFACE")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .or_else(|| {
                    if environment == Environment::Development {
                        Some("web".to_string())
                    } else {
                        None
                    }
                }),

            webhook_signing_secret,
            webhook_timeout_ms: parse_u64(
                "WEBHOOK_TIMEOUT_MS",
                &env_or("WEBHOOK_TIMEOUT_MS", "5000"),
            )?,
            webhook_max_retries: parse_u32(
                "WEBHOOK_MAX_RETRIES",
                &env_or("WEBHOOK_MAX_RETRIES", "10"),
            )?,

            idempotency_ttl_seconds: parse_u64(
                "IDEMPOTENCY_TTL_SECONDS",
                &env_or("IDEMPOTENCY_TTL_SECONDS", "86400"),
            )?,

            aws_region: env_or("AWS_REGION", "us-east-1"),
            ses_ip_pool_prefix: env_or("SES_IP_POOL_PREFIX", "apexmail"),
            ses_default_warmup_days: parse_u32(
                "SES_DEFAULT_WARMUP_DAYS",
                &env_or("SES_DEFAULT_WARMUP_DAYS", "14"),
            )?,
            ses_configuration_set: env::var("SES_CONFIGURATION_SET").ok(),

            google_client_id: env::var("GOOGLE_CLIENT_ID").ok(),
            google_client_secret: env::var("GOOGLE_CLIENT_SECRET").ok(),
            github_client_id: env::var("GITHUB_CLIENT_ID").ok(),
            github_client_secret: env::var("GITHUB_CLIENT_SECRET").ok(),
            oauth_redirect_base_url: env_or("OAUTH_REDIRECT_BASE_URL", "http://0.0.0.0:3000"),

            session_secret: session_secret_env
                .clone()
                .unwrap_or_else(|| generated_dev_secret("session-secret")),
            impersonation_secret: impersonation_secret_env
                .clone()
                .unwrap_or_else(|| generated_dev_secret("impersonation-secret")),
            csrf_secret: csrf_secret_env
                .clone()
                .unwrap_or_else(|| generated_dev_secret("csrf-secret")),

            control_plane_api_key: env::var("CONTROL_PLANE_API_KEY")
                .ok()
                .filter(|s| !s.is_empty()),
            sales_autopilot_base_url: env_or("SALES_AUTOPILOT_BASE_URL", "http://127.0.0.1:3010"),
            ai_service_base_url: env_or("AI_SERVICE_BASE_URL", "http://ai-service:3012"),
            internal_service_token: env::var("INTERNAL_SERVICE_TOKEN")
                .ok()
                .filter(|s| !s.is_empty()),
            cp_auth: CpAuthConfig::from_env()?,

            tracking_secret_key: tracking_secret_key_env
                .clone()
                .unwrap_or_else(|| generated_dev_secret("tracking-secret")),
            billing_company_iban: env_or("BILLING_COMPANY_IBAN", ""),
            billing_company_phone: env_or("BILLING_COMPANY_PHONE", ""),

            metrics_port: parse_u16("METRICS_PORT", &env_or("METRICS_PORT", "9090"))?,

            grader_enabled,
            grader_rate_limit,
            grader_rate_window_seconds,
            grader_cache_ttl_seconds,
            grader_max_body_size,

            placement_enabled,
            placement_polling_interval_secs,
            placement_max_polling_attempts,
            placement_max_seeds_per_test,
            placement_max_tests_per_hour,
            placement_imap_timeout_secs,
            placement_encrypt_passwords,
            placement_encryption_secret,

            kiwi_enabled,
            kiwi_secret_key,
            waf_enabled,
            waf_enforce,
            kiwi_algorithm,
            kiwi_argon_m_kib,
            kiwi_argon_t,
            kiwi_argon_p,
            kiwi_difficulty_bits,
            kiwi_argon2_difficulty_bits,
            kiwi_challenge_ttl_secs,
            kiwi_min_duration_ms,
            kiwi_argon2_max_concurrent,
            kiwi_enforce_telemetry,
            kiwi_auto_tune,
            kiwi_auto_tune_min_bits,
            kiwi_auto_tune_max_bits,

            http_client_timeout_secs: parse_u64(
                "HTTP_CLIENT_TIMEOUT_SECONDS",
                &env_or("HTTP_CLIENT_TIMEOUT_SECONDS", "30"),
            )?,

            // SEC-104: Internal TLS for service-to-service communication.
            // When INTERNAL_TLS_ENABLED=true, all internal traffic (traces,
            // logs, metrics, inter-service API) must use mutual TLS.
            internal_tls_enabled: env_or("INTERNAL_TLS_ENABLED", "false")
                .parse()
                .unwrap_or(false),
            internal_tls_ca_cert_path: env::var("INTERNAL_TLS_CA_CERT_PATH")
                .ok()
                .filter(|s| !s.is_empty()),
            internal_tls_client_cert_path: env::var("INTERNAL_TLS_CLIENT_CERT_PATH")
                .ok()
                .filter(|s| !s.is_empty()),
            internal_tls_client_key_path: env::var("INTERNAL_TLS_CLIENT_KEY_PATH")
                .ok()
                .filter(|s| !s.is_empty()),
        };

        // Production security checks
        if config.environment.is_production() {
            let cp_session_secret_env = env::var("CP_SESSION_SECRET")
                .ok()
                .filter(|value| !value.trim().is_empty());
            for (name, value) in [
                ("SESSION_SECRET", session_secret_env.as_deref()),
                ("IMPERSONATION_SECRET", impersonation_secret_env.as_deref()),
                ("CSRF_SECRET", csrf_secret_env.as_deref()),
                ("TRACKING_SECRET_KEY", tracking_secret_key_env.as_deref()),
                ("CP_SESSION_SECRET", cp_session_secret_env.as_deref()),
            ] {
                if value.is_none() {
                    return Err(ConfigError::MissingVar(name.to_string()));
                }
            }
            config.validate_production()?;
        }

        Ok(config)
    }

    /// Build a Postgres connection URL from the config.
    /// Build a Postgres connection URL. If the `DATABASE_URL` env var is set
    /// (e.g. by the Docker entrypoint wrapper or the `.env` file), use it
    /// verbatim so the caller controls sslmode and query params. Otherwise
    /// construct from the individual `db_*` config fields.
    /// User and password are percent-encoded so that special characters
    /// (like `@`, `:`, `/`) do not corrupt the URL.
    pub fn database_url(&self) -> String {
        if let Ok(url) = std::env::var("DATABASE_URL") {
            if !url.trim().is_empty() {
                return url;
            }
        }
        use url::form_urlencoded;
        let encoded_user: String =
            form_urlencoded::byte_serialize(self.db_user.as_bytes()).collect();
        let encoded_pass: String =
            form_urlencoded::byte_serialize(self.db_password.as_bytes()).collect();
        format!(
            "postgres://{}:{}@{}:{}/{}?sslmode=disable",
            encoded_user, encoded_pass, self.db_host, self.db_port, self.db_name
        )
    }

    /// Build a Redis connection URL from the config.
    ///
    /// The password is percent-encoded per RFC 3986 (via `urlencoding`, which
    /// encodes every non-unreserved byte including `%`, `@`, `:`, `/`, `+`
    /// and space) so that special characters in the password cannot corrupt
    /// the URL. The redis crate percent-decodes the password component
    /// before authenticating, so the encoding round-trips exactly.
    pub fn redis_url(&self) -> String {
        match &self.redis_password {
            Some(pw) => format!(
                "redis://:{}@{}:{}/{}",
                urlencoding::encode(pw),
                self.redis_host,
                self.redis_port,
                self.redis_db
            ),
            None => format!(
                "redis://{}:{}/{}",
                self.redis_host, self.redis_port, self.redis_db
            ),
        }
    }

    pub fn jwt_verification_public_keys(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.jwt_public_key_pem.as_str())
            .chain(self.jwt_previous_public_keys_pem.iter().map(String::as_str))
    }

    pub fn ui_surface_for_host<'a>(&'a self, host: Option<&str>) -> Option<&'a str> {
        let normalized = host.map(normalize_host);

        if let Some(host) = normalized.as_deref() {
            if self
                .ui_control_plane_hosts
                .iter()
                .any(|candidate| normalize_host(candidate) == host)
            {
                return Some("control-plane");
            }
            if self
                .ui_marketing_hosts
                .iter()
                .any(|candidate| normalize_host(candidate) == host)
            {
                return Some(self.ui_marketing_surface.as_str());
            }
            if self
                .ui_web_hosts
                .iter()
                .any(|candidate| normalize_host(candidate) == host)
            {
                return Some("web");
            }
        }

        self.ui_default_surface.as_deref()
    }

    pub fn is_explicit_web_host(&self, host: Option<&str>) -> bool {
        let Some(host) = host.map(normalize_host) else {
            return false;
        };

        self.ui_web_hosts
            .iter()
            .any(|candidate| normalize_host(candidate) == host)
    }

    /// Validate secrets and settings for production safety.
    fn validate_production(&self) -> Result<(), ConfigError> {
        if !self.jwt_private_key_pem.contains("BEGIN") {
            return Err(ConfigError::SecurityCheck(
                "JWT_PRIVATE_KEY_PEM must contain a valid PEM private key in production".into(),
            ));
        }
        if !self.jwt_public_key_pem.contains("BEGIN") {
            return Err(ConfigError::SecurityCheck(
                "JWT_PUBLIC_KEY_PEM must contain a valid PEM public key in production".into(),
            ));
        }
        for (index, public_key) in self.jwt_previous_public_keys_pem.iter().enumerate() {
            if !public_key.contains("BEGIN") {
                return Err(ConfigError::SecurityCheck(format!(
                    "JWT_PREVIOUS_PUBLIC_KEYS_PEM entry {index} must contain a valid PEM public key in production"
                )));
            }
        }
        const COMMON_PLACEHOLDERS: &[&str] = &[
            "dev-secret",
            "secret",
            "changeme",
            "change-me",
            "password",
            "replace-me",
            "replace_me",
        ];
        validate_secret(
            "API_KEY_HASH_SECRET",
            &self.api_key_hash_secret,
            32,
            COMMON_PLACEHOLDERS,
        )?;
        validate_secret(
            "WEBHOOK_SIGNING_SECRET",
            &self.webhook_signing_secret,
            32,
            COMMON_PLACEHOLDERS,
        )?;
        validate_secret(
            "SESSION_SECRET",
            &self.session_secret,
            32,
            &["dev-session-secret-change-me"],
        )?;
        validate_secret(
            "IMPERSONATION_SECRET",
            &self.impersonation_secret,
            32,
            &["dev-impersonation-secret-change-me"],
        )?;
        validate_secret(
            "CSRF_SECRET",
            &self.csrf_secret,
            32,
            &["dev-csrf-secret-change-me"],
        )?;
        // CP sessions gate platform administration; an ephemeral dev secret
        // must never sign them in production. (Timeout ordering is enforced
        // by CpAuthConfig::from_env for every environment.)
        validate_secret(
            "CP_SESSION_SECRET",
            &self.cp_auth.session_secret,
            32,
            &["dev-cp-session-secret-change-me-32ch"],
        )?;
        if self.db_password.is_empty() {
            return Err(ConfigError::SecurityCheck(
                "DB_PASSWORD must not be empty in production".into(),
            ));
        }
        if self.cors_origins.iter().any(|o| o == "*") {
            return Err(ConfigError::SecurityCheck(
                "wildcard CORS origin (*) is not allowed in production".into(),
            ));
        }
        if let Some(ref cp_key) = self.control_plane_api_key {
            validate_secret("CONTROL_PLANE_API_KEY", cp_key, 32, COMMON_PLACEHOLDERS)?;
        }
        validate_secret(
            "TRACKING_SECRET_KEY",
            &self.tracking_secret_key,
            32,
            &["dev-tracking-secret-change-me-32chars!!"],
        )?;
        validate_required_setting(
            "BILLING_COMPANY_IBAN",
            &self.billing_company_iban,
            &["UNCONFIGURED"],
        )?;
        validate_required_setting(
            "BILLING_COMPANY_PHONE",
            &self.billing_company_phone,
            &["UNCONFIGURED"],
        )?;
        if self.kiwi_enabled {
            // KiwiCaptcha is fully self-contained (no external service), so the
            // only production requirement is a strong HMAC secret key.
            validate_secret("KIWI_SECRET_KEY", &self.kiwi_secret_key, 16, &["dev"])?;
        }
        if self.placement_enabled && self.placement_encrypt_passwords {
            validate_secret(
                "PLACEMENT_ENCRYPTION_SECRET",
                &self.placement_encryption_secret,
                16,
                &["change-me-in-production"],
            )?;
        }
        validate_https_url("BASE_URL", &self.base_url)?;
        validate_https_url("OAUTH_REDIRECT_BASE_URL", &self.oauth_redirect_base_url)?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
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
    fn test_redis_url_no_password() {
        let cfg = Config {
            redis_host: "redis".into(),
            redis_port: 6379,
            redis_password: None,
            redis_db: 0,
            ..valid_production_config()
        };
        assert_eq!(cfg.redis_url(), "redis://redis:6379/0");
    }

    #[test]
    fn test_redis_url_plain_password() {
        let cfg = Config {
            redis_host: "redis".into(),
            redis_port: 6379,
            redis_password: Some("secret".into()),
            redis_db: 2,
            ..valid_production_config()
        };
        assert_eq!(cfg.redis_url(), "redis://:secret@redis:6379/2");
    }

    #[test]
    fn test_redis_url_percent_encodes_special_characters() {
        // `@`, `:`, `/`, `+`, space and `%` must not corrupt the URL. The
        // redis crate percent-decodes the password component before
        // authenticating, so the encoded form must round-trip to the original.
        for (password, expected) in [
            ("p@ss:word", "p%40ss%3Aword"),
            ("a/b+c d", "a%2Fb%2Bc%20d"),
            ("100%Secure", "100%25Secure"),
            ("emoji🦄key", "emoji%F0%9F%A6%84key"),
        ] {
            let cfg = Config {
                redis_host: "redis.example.com".into(),
                redis_port: 6380,
                redis_password: Some(password.into()),
                redis_db: 4,
                ..valid_production_config()
            };
            let url = cfg.redis_url();
            assert_eq!(url, format!("redis://:{expected}@redis.example.com:6380/4"));
            // The URL must parse, and the password component must decode back
            // to the original value (the redis crate decodes it on connect).
            let parsed = url::Url::parse(&url).unwrap();
            assert_eq!(parsed.password(), Some(expected));
            let decoded = urlencoding::decode(parsed.password().unwrap()).unwrap();
            assert_eq!(decoded, password);
        }
    }

    #[test]
    fn test_default_cors_origins_respects_environment_and_base_url() {
        assert_eq!(
            default_cors_origins(Environment::Development, "http://localhost:3000"),
            vec!["*"]
        );
        assert_eq!(
            default_cors_origins(Environment::Development, "http://127.0.0.1:3000"),
            vec!["*"]
        );
        assert!(
            default_cors_origins(Environment::Development, "https://app.example.com").is_empty()
        );
        assert!(default_cors_origins(Environment::Staging, "http://localhost:3000").is_empty());
    }

    #[test]
    fn default_max_inflight_requests_scales_from_db_pool() {
        assert_eq!(default_max_inflight_requests(1), 16);
        assert_eq!(default_max_inflight_requests(20), 30);
        assert_eq!(default_max_inflight_requests(128), 192);
    }

    #[test]
    fn db_connection_budget_rejects_oversized_replica_pool() {
        assert!(validate_db_connection_budget(20, 4, 3, Some(60)).is_err());
        assert!(validate_db_connection_budget(20, 3, 3, Some(60)).is_ok());
        assert!(validate_db_connection_budget(20, 0, 3, Some(60)).is_err());
    }

    pub(crate) fn valid_production_config() -> Config {
        Config {
            public_rate_limit_enabled: true,
            port: 3000,
            host: "0.0.0.0".into(),
            base_url: "https://app.example.com".into(),
            environment: Environment::Production,
            db_host: "localhost".into(),
            db_port: 5432,
            db_name: "apexmail".into(),
            db_user: "apexmail".into(),
            db_password: "correct-horse-battery-staple-db-password".into(),
            db_max_connections: 20,
            api_replica_count: 1,
            db_cluster_connection_budget: None,
            expected_replica_count: 3,
            statement_cache_capacity: 500,
            query_timeout_seconds: 30,
            database_replica_url: None,
            redis_host: "localhost".into(),
            redis_port: 6379,
            redis_password: None,
            redis_db: 0,
            redis_pool_max_size: 40,
            jwt_private_key_pem: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
                .into(),
            jwt_public_key_pem: "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----".into(),
            jwt_previous_public_keys_pem: vec![],
            jwt_expiry: Duration::from_secs(86400),
            api_key_hash_secret: "test-api-key-secret-12345678901234567890".into(),
            rate_limit_window_ms: 60000,
            rate_limit_max_requests: 1000,
            max_inflight_requests: 30,
            cors_origins: vec!["https://app.example.com".into()],
            trusted_proxies: vec![],
            ui_web_hosts: vec!["app.example.com".into()],
            ui_control_plane_hosts: vec!["admin.example.com".into()],
            ui_marketing_hosts: vec!["example.com".into()],
            ui_marketing_surface: "marketing-zola".into(),
            ui_default_surface: None,
            webhook_signing_secret: "test-webhook-signing-secret-1234567890".into(),
            webhook_timeout_ms: 5000,
            webhook_max_retries: 10,
            idempotency_ttl_seconds: 86400,
            aws_region: "us-east-1".into(),
            ses_ip_pool_prefix: "apexmail".into(),
            ses_default_warmup_days: 14,
            ses_configuration_set: None,
            google_client_id: None,
            google_client_secret: None,
            github_client_id: None,
            github_client_secret: None,
            oauth_redirect_base_url: "https://app.example.com".into(),
            session_secret: "test-session-secret-1234567890abcdef".into(),
            impersonation_secret: "test-impersonation-secret-1234567890".into(),
            csrf_secret: "test-csrf-secret-1234567890abcdef".into(),
            control_plane_api_key: Some("test-control-plane-api-key-1234567890".into()),
            sales_autopilot_base_url: "http://localhost:3010".into(),
            ai_service_base_url: "http://localhost:3012".into(),
            internal_service_token: None,
            cp_auth: Default::default(),
            tracking_secret_key: "test-tracking-secret-123456789012abcd".into(),
            billing_company_iban: "EE381010220123456789".into(),
            billing_company_phone: "+3721234567".into(),
            metrics_port: 9090,
            grader_enabled: false,
            grader_rate_limit: 10,
            grader_rate_window_seconds: 60,
            grader_cache_ttl_seconds: 300,
            grader_max_body_size: 1048576,

            placement_enabled: false,
            placement_polling_interval_secs: 60,
            placement_max_polling_attempts: 10,
            placement_max_seeds_per_test: 50,
            placement_max_tests_per_hour: 5,
            placement_imap_timeout_secs: 30,
            placement_encrypt_passwords: true,
            placement_encryption_secret: "test-placement-encryption-secret".into(),

            kiwi_enabled: true,
            kiwi_secret_key: "prod-kiwi-secret-key-67890".into(),
            waf_enabled: false,
            waf_enforce: false,
            kiwi_algorithm: kiwicaptcha::PoWAlgorithm::Sha256,
            kiwi_argon_m_kib: 0,
            kiwi_argon_t: 1,
            kiwi_argon_p: 1,
            kiwi_difficulty_bits: 20,
            kiwi_argon2_difficulty_bits: 8,
            kiwi_challenge_ttl_secs: 120,
            kiwi_min_duration_ms: None,
            kiwi_enforce_telemetry: true,
            kiwi_argon2_max_concurrent: 2,
            kiwi_auto_tune: false,
            kiwi_auto_tune_min_bits: 10,
            kiwi_auto_tune_max_bits: 20,
            http_client_timeout_secs: 30,
            internal_tls_enabled: false,
            internal_tls_ca_cert_path: None,
            internal_tls_client_cert_path: None,
            internal_tls_client_key_path: None,
        }
    }

    #[test]
    fn test_production_security_checks() {
        let mut config = valid_production_config();
        assert!(config.validate_production().is_ok());

        config.session_secret = "dev-session-secret-change-me".into();
        assert!(config.validate_production().is_err());

        let mut config = valid_production_config();
        config.impersonation_secret = "dev-impersonation-secret-change-me".into();
        assert!(config.validate_production().is_err());

        let mut config = valid_production_config();
        config.csrf_secret = "dev-csrf-secret-change-me".into();
        assert!(config.validate_production().is_err());

        let mut config = valid_production_config();
        config.tracking_secret_key = "dev-tracking-secret-change-me-32chars!!".into();
        assert!(config.validate_production().is_err());

        let mut config = valid_production_config();
        config.cors_origins = vec!["*".into()];
        assert!(config.validate_production().is_err());

        let mut config = valid_production_config();
        config.billing_company_iban = "UNCONFIGURED".into();
        assert!(config.validate_production().is_err());

        let mut config = valid_production_config();
        config.billing_company_phone.clear();
        assert!(config.validate_production().is_err());

        // KiwiCaptcha with a "dev" secret key must fail production validation.
        let mut config = valid_production_config();
        config.kiwi_secret_key = "dev".into();
        assert!(config.validate_production().is_err());

        // When KiwiCaptcha is disabled, the dev key is acceptable.
        let mut config = valid_production_config();
        config.kiwi_enabled = false;
        config.kiwi_secret_key = "dev".into();
        assert!(config.validate_production().is_ok());
    }

    #[test]
    fn ui_surface_for_host_prefers_explicit_host_maps() {
        let config = Config {
            public_rate_limit_enabled: false,
            port: 3000,
            host: "0.0.0.0".into(),
            base_url: "http://localhost:3000".into(),
            environment: Environment::Development,
            db_host: "localhost".into(),
            db_port: 5432,
            db_name: "apexmail".into(),
            db_user: "apexmail".into(),
            db_password: "password".into(),
            db_max_connections: 20,
            api_replica_count: 1,
            db_cluster_connection_budget: None,
            expected_replica_count: 3,
            statement_cache_capacity: 500,
            query_timeout_seconds: 30,
            database_replica_url: None,
            redis_host: "localhost".into(),
            redis_port: 6379,
            redis_password: None,
            redis_db: 0,
            redis_pool_max_size: 40,
            jwt_private_key_pem: "BEGIN TEST".into(),
            jwt_public_key_pem: "BEGIN TEST".into(),
            jwt_previous_public_keys_pem: vec![],
            jwt_expiry: Duration::from_secs(86400),
            api_key_hash_secret: "a-very-long-secret-value-for-tests-1234".into(),
            rate_limit_window_ms: 60000,
            rate_limit_max_requests: 1000,
            max_inflight_requests: 30,
            cors_origins: vec!["*".into()],
            trusted_proxies: vec![],
            ui_web_hosts: vec!["app.apexmail.ee".into(), "127.0.0.1".into()],
            ui_control_plane_hosts: vec!["admin.apexmail.ee".into(), "localhost".into()],
            ui_marketing_hosts: vec!["apexmail.ee".into()],
            ui_marketing_surface: "marketing-zola".into(),
            ui_default_surface: Some("web".into()),
            webhook_signing_secret: "test-webhook-signing-secret-1234567890".into(),
            webhook_timeout_ms: 5000,
            webhook_max_retries: 10,
            idempotency_ttl_seconds: 86400,
            aws_region: "us-east-1".into(),
            ses_ip_pool_prefix: "apexmail".into(),
            ses_default_warmup_days: 14,
            ses_configuration_set: None,
            google_client_id: None,
            google_client_secret: None,
            github_client_id: None,
            github_client_secret: None,
            oauth_redirect_base_url: "http://localhost:3000".into(),
            session_secret: "test-session-secret-1234567890ab".into(),
            impersonation_secret: "test-impersonation-secret-12345".into(),
            csrf_secret: "test-csrf-secret-1234567890abcd".into(),
            control_plane_api_key: None,
            sales_autopilot_base_url: "http://localhost:3010".into(),
            ai_service_base_url: "http://localhost:3012".into(),
            internal_service_token: None,
            cp_auth: Default::default(),
            tracking_secret_key: "test-tracking-secret-123456789012".into(),
            billing_company_iban: "EE381010220123456789".into(),
            billing_company_phone: "+3721234567".into(),
            metrics_port: 9090,
            grader_enabled: false,
            grader_rate_limit: 10,
            grader_rate_window_seconds: 60,
            grader_cache_ttl_seconds: 300,
            grader_max_body_size: 1048576,

            placement_enabled: false,
            placement_polling_interval_secs: 60,
            placement_max_polling_attempts: 10,
            placement_max_seeds_per_test: 50,
            placement_max_tests_per_hour: 5,
            placement_imap_timeout_secs: 30,
            placement_encrypt_passwords: true,
            placement_encryption_secret: "test-placement-encryption-secret".into(),

            kiwi_enabled: false,
            kiwi_secret_key: "dev".into(),
            waf_enabled: false,
            waf_enforce: false,
            kiwi_algorithm: kiwicaptcha::PoWAlgorithm::Sha256,
            kiwi_argon_m_kib: 0,
            kiwi_argon2_difficulty_bits: 8,
            kiwi_argon_t: 1,
            kiwi_argon_p: 1,
            kiwi_difficulty_bits: 20,
            kiwi_challenge_ttl_secs: 120,
            kiwi_min_duration_ms: None,
            kiwi_enforce_telemetry: true,
            kiwi_argon2_max_concurrent: 2,
            kiwi_auto_tune: false,
            kiwi_auto_tune_min_bits: 10,
            kiwi_auto_tune_max_bits: 20,
            http_client_timeout_secs: 30,
            internal_tls_enabled: false,
            internal_tls_ca_cert_path: None,
            internal_tls_client_cert_path: None,
            internal_tls_client_key_path: None,
        };

        assert_eq!(
            config.ui_surface_for_host(Some("app.apexmail.ee")),
            Some("web")
        );
        assert_eq!(config.ui_surface_for_host(Some("127.0.0.1")), Some("web"));
        assert_eq!(
            config.ui_surface_for_host(Some("localhost")),
            Some("control-plane")
        );
        assert_eq!(
            config.ui_surface_for_host(Some("admin.apexmail.ee:3002")),
            Some("control-plane")
        );
        assert_eq!(
            config.ui_surface_for_host(Some("apexmail.ee")),
            Some("marketing-zola")
        );
        assert_eq!(
            config.ui_surface_for_host(Some("unknown.example.com")),
            Some("web")
        );
        assert!(config.is_explicit_web_host(Some("app.apexmail.ee")));
        assert!(config.is_explicit_web_host(Some("127.0.0.1")));
        assert!(!config.is_explicit_web_host(Some("localhost")));
        assert!(!config.is_explicit_web_host(Some("unknown.example.com")));
    }

    #[test]
    fn validate_rate_limit_config_rejects_zero_values() {
        assert!(validate_rate_limit_config(0, 60).is_err());
        assert!(validate_rate_limit_config(100, 0).is_err());
    }

    #[test]
    fn validate_rate_limit_config_accepts_reasonable_values() {
        assert!(validate_rate_limit_config(100, 60).is_ok());
        assert!(validate_rate_limit_config(1, 1).is_ok());
    }

    #[test]
    fn validate_rate_limit_config_rejects_excessive_window() {
        assert!(validate_rate_limit_config(100, 86401).is_err());
    }
}

// ─── Adversarial configuration tests ───────────────────────────
//
// Env access is process-global: every test here runs inside an `EnvSandbox`
// that clears every variable `Config::from_env` reads and restores the
// original values on drop, behind a module-wide mutex.

#[cfg(test)]
mod adversarial_tests {
    use super::*;
    use std::ffi::OsString;

    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Every variable `Config::from_env` consults (plus the audit signer,
    /// which reads ENVIRONMENT at insert time in concurrent tests).
    const CONFIG_ENV_KEYS: &[&str] = &[
        "ENVIRONMENT",
        "AUDIT_SIGNING_KEY",
        "SESSION_SECRET",
        "IMPERSONATION_SECRET",
        "CSRF_SECRET",
        "TRACKING_SECRET_KEY",
        "JWT_PRIVATE_KEY_PEM",
        "JWT_PUBLIC_KEY_PEM",
        "JWT_PREVIOUS_PUBLIC_KEYS_PEM",
        "JWT_EXPIRY",
        "API_KEY_HASH_SECRET",
        "WEBHOOK_SIGNING_SECRET",
        "WEBHOOK_TIMEOUT_MS",
        "WEBHOOK_MAX_RETRIES",
        "IDEMPOTENCY_TTL_SECONDS",
        "BASE_URL",
        "CORS_ORIGINS",
        "PORT",
        "HOST",
        "PUBLIC_RATE_LIMIT_ENABLED",
        "DB_HOST",
        "DB_PORT",
        "DB_NAME",
        "DB_USER",
        "DB_PASSWORD",
        "DB_MAX_CONNECTIONS",
        "API_REPLICA_COUNT",
        "EXPECTED_REPLICA_COUNT",
        "DB_CLUSTER_CONNECTION_BUDGET",
        "STATEMENT_CACHE_CAPACITY",
        "QUERY_TIMEOUT_SECONDS",
        "DATABASE_URL",
        "DATABASE_REPLICA_URL",
        "REDIS_HOST",
        "REDIS_PORT",
        "REDIS_PASSWORD",
        "REDIS_DB",
        "REDIS_POOL_MAX_SIZE",
        "RATE_LIMIT_MAX_REQUESTS",
        "RATE_LIMIT_WINDOW_MS",
        "MAX_INFLIGHT_REQUESTS",
        "TRUSTED_PROXIES",
        "UI_WEB_HOSTS",
        "UI_CONTROL_PLANE_HOSTS",
        "UI_MARKETING_HOSTS",
        "UI_MARKETING_SURFACE",
        "UI_DEFAULT_SURFACE",
        "AWS_REGION",
        "SES_IP_POOL_PREFIX",
        "SES_DEFAULT_WARMUP_DAYS",
        "SES_CONFIGURATION_SET",
        "GOOGLE_CLIENT_ID",
        "GOOGLE_CLIENT_SECRET",
        "GITHUB_CLIENT_ID",
        "GITHUB_CLIENT_SECRET",
        "OAUTH_REDIRECT_BASE_URL",
        "CONTROL_PLANE_API_KEY",
        "SALES_AUTOPILOT_BASE_URL",
        "AI_SERVICE_BASE_URL",
        "INTERNAL_SERVICE_TOKEN",
        "CP_ALLOWED_IPS",
        "CP_SESSION_SECRET",
        "CP_SESSION_IDLE_TIMEOUT_SECS",
        "CP_SESSION_ABSOLUTE_TIMEOUT_SECS",
        "GRADER_ENABLED",
        "GRADER_RATE_LIMIT",
        "GRADER_RATE_WINDOW",
        "GRADER_CACHE_TTL",
        "GRADER_MAX_BODY_SIZE",
        "PLACEMENT_ENABLED",
        "PLACEMENT_POLLING_INTERVAL",
        "PLACEMENT_MAX_POLLING_ATTEMPTS",
        "PLACEMENT_MAX_SEEDS_PER_TEST",
        "PLACEMENT_MAX_TESTS_PER_HOUR",
        "PLACEMENT_IMAP_TIMEOUT",
        "PLACEMENT_ENCRYPT_PASSWORDS",
        "PLACEMENT_ENCRYPTION_SECRET",
        "KIWI_ENABLED",
        "KIWI_SECRET_KEY",
        "WAF_ENABLED",
        "WAF_ENFORCE",
        "KIWI_ALGORITHM",
        "KIWI_ARGON_M_KIB",
        "KIWI_PBKDF2_ITERATIONS",
        "KIWI_ARGON_T",
        "KIWI_ARGON_P",
        "KIWI_DIFFICULTY_BITS",
        "KIWI_ARGON2_DIFFICULTY_BITS",
        "KIWI_CHALLENGE_TTL_SECS",
        "KIWI_MIN_DURATION_MS",
        "KIWI_ARGON2_MAX_CONCURRENT",
        "KIWI_ENFORCE_TELEMETRY",
        "KIWI_AUTO_TUNE",
        "KIWI_AUTO_TUNE_MIN_BITS",
        "KIWI_AUTO_TUNE_MAX_BITS",
        "METRICS_PORT",
        "HTTP_CLIENT_TIMEOUT_SECONDS",
        "INTERNAL_TLS_ENABLED",
        "INTERNAL_TLS_CA_CERT_PATH",
        "INTERNAL_TLS_CLIENT_CERT_PATH",
        "INTERNAL_TLS_CLIENT_KEY_PATH",
        "EMAIL_TRANSPORT_TYPE",
    ];

    struct EnvSandbox {
        previous: Vec<(&'static str, Option<OsString>)>,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvSandbox {
        fn new() -> Self {
            let guard = ENV_MUTEX.lock().unwrap_or_else(|error| error.into_inner());
            let mut previous = Vec::with_capacity(CONFIG_ENV_KEYS.len());
            for key in CONFIG_ENV_KEYS {
                previous.push((*key, std::env::var_os(key)));
                std::env::remove_var(key);
            }
            Self {
                previous,
                _guard: guard,
            }
        }

        fn set(&self, key: &str, value: &str) {
            std::env::set_var(key, value);
        }

        /// Clear every variable `from_env` reads (the sandbox cleared them
        /// once at construction; helpers must be able to reset state).
        fn clear(&self) {
            for key in CONFIG_ENV_KEYS {
                std::env::remove_var(key);
            }
        }

        /// Minimal development environment: every REQUIRED variable set to a
        /// valid value, everything else cleared.
        fn minimal_dev(&self) {
            self.clear();
            self.set("ENVIRONMENT", "development");
            self.set("JWT_PRIVATE_KEY_PEM", "-----BEGIN PRIVATE KEY-----x");
            self.set("JWT_PUBLIC_KEY_PEM", "-----BEGIN PUBLIC KEY-----x");
            self.set("API_KEY_HASH_SECRET", "dev-api-key-hash-secret-0123456789");
            self.set(
                "WEBHOOK_SIGNING_SECRET",
                "dev-webhook-signing-secret-0123456789",
            );
        }
    }

    impl Drop for EnvSandbox {
        fn drop(&mut self) {
            for (key, value) in self.previous.drain(..) {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    /// Every production requirement, each one individually strong.
    fn strong_production(sandbox: &EnvSandbox) {
        sandbox.clear();
        sandbox.set("ENVIRONMENT", "production");
        sandbox.set(
            "AUDIT_SIGNING_KEY",
            "production-audit-signing-key-0123456789",
        );
        sandbox.set("JWT_PRIVATE_KEY_PEM", "-----BEGIN PRIVATE KEY-----x");
        sandbox.set("JWT_PUBLIC_KEY_PEM", "-----BEGIN PUBLIC KEY-----x");
        sandbox.set(
            "API_KEY_HASH_SECRET",
            "production-api-key-hash-secret-0123456789",
        );
        sandbox.set(
            "WEBHOOK_SIGNING_SECRET",
            "production-webhook-signing-secret-0123456789",
        );
        sandbox.set("SESSION_SECRET", "production-session-secret-0123456789ab");
        sandbox.set(
            "IMPERSONATION_SECRET",
            "production-impersonation-secret-0123456789",
        );
        sandbox.set("CSRF_SECRET", "production-csrf-secret-0123456789abcdef");
        sandbox.set(
            "TRACKING_SECRET_KEY",
            "production-tracking-secret-0123456789ab",
        );
        sandbox.set(
            "CP_SESSION_SECRET",
            "production-cp-session-secret-0123456789",
        );
        sandbox.set("DB_PASSWORD", "correct-horse-battery-staple");
        sandbox.set("BILLING_COMPANY_IBAN", "EE381010220123456789");
        sandbox.set("BILLING_COMPANY_PHONE", "+3721234567");
        sandbox.set("KIWI_SECRET_KEY", "production-kiwi-secret-0123456789");
        sandbox.set("BASE_URL", "https://app.apexmail.ee");
        sandbox.set("OAUTH_REDIRECT_BASE_URL", "https://app.apexmail.ee");
        sandbox.set("PLACEMENT_ENABLED", "false");
    }

    // ── pure helpers ────────────────────────────────────────────

    #[test]
    fn adversarial_config_parsers_and_validators() {
        // Integer parsers surface the variable name and the offending value.
        for (key, result) in [
            ("PORT", parse_u16("PORT", "70000")),
            ("DB_PORT", parse_u16("DB_PORT", "-1")),
        ] {
            match result {
                Err(ConfigError::Invalid { var, reason }) => {
                    assert_eq!(var, key);
                    assert!(reason.contains("u16"), "{reason}");
                }
                other => panic!("expected Invalid for {key}, got {other:?}"),
            }
        }
        assert_eq!(parse_u16("P", "65535").unwrap(), u16::MAX);
        assert_eq!(parse_u32("P", "4294967295").unwrap(), u32::MAX);
        assert_eq!(parse_u64("P", "18446744073709551615").unwrap(), u64::MAX);
        assert_eq!(parse_u8("P", "255").unwrap(), u8::MAX);
        assert_eq!(parse_usize("P", "0").unwrap(), 0);
        for result in [
            parse_u32("P", "x").err(),
            parse_u64("P", "-1").err(),
            parse_u8("P", "256").err(),
            parse_usize("P", "1.5").err(),
        ] {
            assert!(matches!(result, Some(ConfigError::Invalid { .. })));
        }

        // Duration: hours suffix or plain seconds, strictly parsed.
        assert_eq!(
            parse_duration_hours("JWT_EXPIRY", "2h").unwrap(),
            Duration::from_secs(7200)
        );
        assert_eq!(
            parse_duration_hours("JWT_EXPIRY", " 3600 ").unwrap(),
            Duration::from_secs(3600)
        );
        assert_eq!(
            parse_duration_hours("JWT_EXPIRY", "0").unwrap(),
            Duration::ZERO
        );
        for bad in ["", "1h30m", "-1", "1.5h", "abc", "99999999999999999999h"] {
            assert!(
                parse_duration_hours("JWT_EXPIRY", bad).is_err(),
                "{bad:?} must not parse"
            );
        }

        // PEM lists: `||` separated, trimmed, `\n` unescaped, empties dropped.
        assert!(parse_optional_pem_list(None).is_empty());
        assert!(parse_optional_pem_list(Some(String::new())).is_empty());
        assert!(parse_optional_pem_list(Some("||  ||".into())).is_empty());
        assert_eq!(
            parse_optional_pem_list(Some("a\\nb|| c ".into())),
            vec!["a\nb".to_string(), "c".to_string()]
        );

        // CSV: trims, drops empties, keeps every element (even "*" plus others).
        assert_eq!(parse_csv(" a ,, b "), vec!["a", "b"]);
        assert_eq!(parse_csv("*").len(), 1);
        assert_eq!(parse_csv("*,https://x").len(), 2);

        // env_required_pem unescapes and reports the missing variable.
        assert!(matches!(
            env_required("CONFIG_TEST_DEFINITELY_MISSING"),
            Err(ConfigError::MissingVar(name)) if name == "CONFIG_TEST_DEFINITELY_MISSING"
        ));
        std::env::set_var("CONFIG_TEST_PEM", "line1\\nline2");
        assert_eq!(env_required_pem("CONFIG_TEST_PEM").unwrap(), "line1\nline2");
        std::env::remove_var("CONFIG_TEST_PEM");

        // URL locality.
        assert!(is_local_base_url("http://localhost:3000"));
        assert!(is_local_base_url("https://127.0.0.1"));
        assert!(is_local_base_url("http://[::1]:8080"));
        assert!(!is_local_base_url("http://0.0.0.0:3000"));
        assert!(!is_local_base_url("https://app.example.com"));
        assert!(!is_local_base_url("not a url"));
        assert!(!is_local_base_url(""));

        // Host normalisation: ports, case, trailing dot, bracketed IPv6.
        assert_eq!(normalize_host("App.ApexMail.EE."), "app.apexmail.ee");
        assert_eq!(
            normalize_host("admin.apexmail.ee:3002"),
            "admin.apexmail.ee"
        );
        assert_eq!(normalize_host("[::1]:3000"), "::1");
        assert_eq!(normalize_host("[2001:db8::1]"), "2001:db8::1");
        assert_eq!(normalize_host("2001:db8::1"), "2001:db8::1");
        assert_eq!(normalize_host("  127.0.0.1  "), "127.0.0.1");

        // Connection-budget math and refusals.
        assert_eq!(default_db_cluster_connection_budget(0), 0);
        assert_eq!(default_db_cluster_connection_budget(20), 48);
        assert_eq!(default_max_inflight_requests(0), 16);
        assert!(validate_db_connection_budget(20, 0, 3, Some(60)).is_err());
        assert!(validate_db_connection_budget(20, 4, 3, Some(60)).is_err());
        assert!(validate_db_connection_budget(20, 3, 3, Some(60)).is_ok());
        // No explicit budget + oversized potential: warns, still Ok.
        assert!(validate_db_connection_budget(20, 100, 3, None).is_ok());

        // Secret and setting validators.
        assert!(validate_secret("S", " short ", 8, &[]).is_err());
        assert!(validate_secret("S", "CHANGEME", 4, &["changeme"]).is_err());
        assert!(validate_secret("S", "a-strong-secret-value", 4, &["changeme"]).is_ok());
        assert!(validate_required_setting("S", "   ", &[]).is_err());
        assert!(validate_required_setting("S", "UNCONFIGURED", &["unconfigured"]).is_err());
        assert!(validate_required_setting("S", "real", &["unconfigured"]).is_ok());
        assert!(validate_https_url("U", "not a url").is_err());
        assert!(validate_https_url("U", "http://x.test").is_err());
        assert!(validate_https_url("U", "https://x.test").is_ok());
        assert!(validate_rate_limit_config(100, 86_400).is_ok());
        assert!(validate_rate_limit_config(1, 86_401).is_err());
    }

    #[test]
    fn adversarial_config_urls_and_key_chain() {
        let _sandbox = EnvSandbox::new();
        let mut config = super::tests::valid_production_config();
        config.db_user = "user@name".into();
        config.db_password = "p@ss:w/rd".into();
        config.db_host = "db.internal".into();
        config.db_port = 6543;
        config.db_name = "apex".into();
        // Built URL percent-encodes credentials.
        std::env::remove_var("DATABASE_URL");
        let url = config.database_url();
        assert_eq!(
            url,
            "postgres://user%40name:p%40ss%3Aw%2Frd@db.internal:6543/apex?sslmode=disable"
        );
        // An explicit DATABASE_URL wins verbatim (sslmode and params intact).
        std::env::set_var("DATABASE_URL", "postgres://x:y@h:1/z?sslmode=require");
        assert_eq!(
            config.database_url(),
            "postgres://x:y@h:1/z?sslmode=require"
        );
        // A blank override falls back to the constructed URL.
        std::env::set_var("DATABASE_URL", "   ");
        assert!(config.database_url().starts_with("postgres://user%40name:"));

        // Redis URL: absent password vs empty password.
        config.redis_host = "redis.internal".into();
        config.redis_port = 6380;
        config.redis_db = 0;
        config.redis_password = None;
        assert_eq!(config.redis_url(), "redis://redis.internal:6380/0");
        config.redis_password = Some(String::new());
        assert_eq!(config.redis_url(), "redis://:@redis.internal:6380/0");

        // JWT verification chain: current key first, previous keys appended.
        config.jwt_public_key_pem = "current".into();
        config.jwt_previous_public_keys_pem = vec!["prev1".into(), "prev2".into()];
        assert_eq!(
            config.jwt_verification_public_keys().collect::<Vec<_>>(),
            vec!["current", "prev1", "prev2"]
        );

        // SES transport selection: only an explicit "smtp" opts out.
        std::env::remove_var("EMAIL_TRANSPORT_TYPE");
        assert!(Config::ses_transport_enabled());
        for value in ["", "  ", "ses", "SES"] {
            std::env::set_var("EMAIL_TRANSPORT_TYPE", value);
            assert!(Config::ses_transport_enabled(), "{value:?}");
        }
        std::env::set_var("EMAIL_TRANSPORT_TYPE", " SMTP ");
        assert!(!Config::ses_transport_enabled());
    }

    #[test]
    fn adversarial_config_ui_surface_routing() {
        let mut config = super::tests::valid_production_config();
        config.ui_web_hosts = vec!["app.apexmail.ee".into(), "127.0.0.1".into()];
        config.ui_control_plane_hosts = vec!["admin.apexmail.ee".into(), "localhost".into()];
        config.ui_marketing_hosts = vec!["apexmail.ee".into()];
        config.ui_marketing_surface = "marketing-zola".into();
        config.ui_default_surface = Some("web".into());

        // Case/port/trailing-dot variants all normalise before matching.
        assert_eq!(
            config.ui_surface_for_host(Some("APP.APEXMAIL.EE:443")),
            Some("web")
        );
        assert_eq!(
            config.ui_surface_for_host(Some("admin.apexmail.ee.")),
            Some("control-plane")
        );
        assert_eq!(config.ui_surface_for_host(Some("[::1]:3000")), Some("web"));
        assert_eq!(
            config.ui_surface_for_host(Some("APEXMAIL.EE")),
            Some("marketing-zola")
        );
        assert_eq!(
            config.ui_surface_for_host(Some("unknown.example")),
            Some("web")
        );
        assert_eq!(config.ui_surface_for_host(None), Some("web"));
        // No default surface outside development: unknown hosts map to None.
        config.ui_default_surface = None;
        assert_eq!(config.ui_surface_for_host(None), None);
        assert_eq!(config.ui_surface_for_host(Some("unknown.example")), None);
        assert!(!config.is_explicit_web_host(None));
        assert!(!config.is_explicit_web_host(Some("unknown.example")));
        assert!(config.is_explicit_web_host(Some("127.0.0.1:3000")));
    }

    #[test]
    fn adversarial_config_cp_auth_env_bounds() {
        let sandbox = EnvSandbox::new();
        let defaults = CpAuthConfig::from_env().unwrap();
        assert!(defaults.allowed_ips.is_empty());
        assert!(defaults.session_secret.starts_with("dev-cp-session-secret"));
        assert_eq!(defaults.session_idle_timeout_secs, 900);
        assert_eq!(defaults.session_absolute_timeout_secs, 14_400);

        // The idle timeout must be > 0 AND strictly below the absolute one.
        for (idle, absolute) in [("0", "100"), ("100", "100"), ("101", "100")] {
            sandbox.set("CP_SESSION_IDLE_TIMEOUT_SECS", idle);
            sandbox.set("CP_SESSION_ABSOLUTE_TIMEOUT_SECS", absolute);
            assert!(
                CpAuthConfig::from_env().is_err(),
                "idle={idle} absolute={absolute} must be refused"
            );
        }
        sandbox.set("CP_SESSION_IDLE_TIMEOUT_SECS", "60");
        sandbox.set("CP_SESSION_ABSOLUTE_TIMEOUT_SECS", "120");
        sandbox.set("CP_ALLOWED_IPS", "10.0.0.0/8, 192.168.0.0/16");
        sandbox.set("CP_SESSION_SECRET", "explicit-cp-secret");
        let config = CpAuthConfig::from_env().unwrap();
        assert_eq!(config.allowed_ips.len(), 2);
        assert_eq!(config.session_secret, "explicit-cp-secret");
        assert_eq!(config.session_idle_timeout_secs, 60);
        sandbox.set("CP_SESSION_IDLE_TIMEOUT_SECS", "not-a-number");
        assert!(matches!(
            CpAuthConfig::from_env(),
            Err(ConfigError::Invalid { var, .. }) if var == "CP_SESSION_IDLE_TIMEOUT_SECS"
        ));
    }

    // ── from_env: development defaults and overrides ────────────

    #[test]
    fn adversarial_config_from_env_dev_defaults_and_overrides() {
        let sandbox = EnvSandbox::new();
        sandbox.minimal_dev();
        let config = Config::from_env().expect("minimal development env must load");
        assert_eq!(config.environment, Environment::Development);
        assert_eq!(config.port, 3000);
        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.db_max_connections, 50);
        assert_eq!(config.api_replica_count, 1);
        assert_eq!(config.expected_replica_count, 3);
        assert_eq!(config.statement_cache_capacity, 500);
        assert_eq!(config.query_timeout_seconds, 30);
        assert_eq!(config.redis_pool_max_size, 100);
        assert_eq!(config.rate_limit_max_requests, 1000);
        assert_eq!(config.rate_limit_window_ms, 60_000);
        assert_eq!(config.max_inflight_requests, 75);
        // Default base URL is 0.0.0.0 (not a localhost host) -> no CORS.
        assert!(config.cors_origins.is_empty());
        assert_eq!(config.ui_default_surface.as_deref(), Some("web"));
        assert!(config.session_secret.starts_with("dev-session-secret-"));
        assert!(config
            .impersonation_secret
            .starts_with("dev-impersonation-secret-"));
        assert!(config.csrf_secret.starts_with("dev-csrf-secret-"));
        assert!(config
            .tracking_secret_key
            .starts_with("dev-tracking-secret-"));
        assert_eq!(config.jwt_expiry, Duration::from_secs(86_400));
        assert!(config.grader_enabled);
        assert!(config.placement_enabled);
        assert!(config.kiwi_enabled);
        assert!(config.waf_enabled);
        assert!(!config.waf_enforce);
        assert_eq!(config.kiwi_algorithm, kiwicaptcha::PoWAlgorithm::Sha256);
        assert_eq!(config.kiwi_difficulty_bits, 20);
        assert_eq!(config.kiwi_argon_t, 3);
        assert_eq!(config.kiwi_challenge_ttl_secs, 120);
        assert_eq!(config.metrics_port, 9090);
        assert!(config.public_rate_limit_enabled);
        assert!(config.control_plane_api_key.is_none());
        assert!(config.internal_service_token.is_none());

        // Explicit overrides are honoured, including truthy/duration forms.
        sandbox.set("PORT", "8080");
        sandbox.set("DB_MAX_CONNECTIONS", "10");
        sandbox.set("API_REPLICA_COUNT", "2");
        sandbox.set("EXPECTED_REPLICA_COUNT", "7");
        sandbox.set("DB_CLUSTER_CONNECTION_BUDGET", "999");
        sandbox.set("RATE_LIMIT_MAX_REQUESTS", "5");
        sandbox.set("RATE_LIMIT_WINDOW_MS", "1000");
        sandbox.set("MAX_INFLIGHT_REQUESTS", "7");
        sandbox.set("PUBLIC_RATE_LIMIT_ENABLED", "off");
        sandbox.set("JWT_EXPIRY", "2h");
        sandbox.set("CORS_ORIGINS", "https://a.test, https://b.test");
        sandbox.set("REDIS_DB", "3");
        sandbox.set("GRADER_ENABLED", "false");
        sandbox.set("PLACEMENT_ENABLED", "false");
        sandbox.set("KIWI_ENABLED", "false");
        sandbox.set("KIWI_SECRET_KEY", "dev");
        sandbox.set("WAF_ENABLED", "false");
        sandbox.set("WAF_ENFORCE", "true");
        sandbox.set("KIWI_MIN_DURATION_MS", "500");
        sandbox.set("CONTROL_PLANE_API_KEY", "cp-key");
        sandbox.set("INTERNAL_SERVICE_TOKEN", "token");
        sandbox.set("SES_CONFIGURATION_SET", "cfg-set");
        sandbox.set("INTERNAL_TLS_ENABLED", "true");
        sandbox.set("DATABASE_REPLICA_URL", "postgres://replica/db");
        sandbox.set("UI_DEFAULT_SURFACE", "control-plane");
        let config = Config::from_env().expect("override env must load");
        assert_eq!(config.port, 8080);
        assert_eq!(config.db_max_connections, 10);
        assert_eq!(config.api_replica_count, 2);
        assert_eq!(config.expected_replica_count, 7);
        assert_eq!(config.db_cluster_connection_budget, Some(999));
        assert_eq!(config.rate_limit_max_requests, 5);
        assert_eq!(config.max_inflight_requests, 7);
        assert!(!config.public_rate_limit_enabled);
        assert_eq!(config.jwt_expiry, Duration::from_secs(7200));
        assert_eq!(
            config.cors_origins,
            vec!["https://a.test", "https://b.test"]
        );
        assert_eq!(config.redis_db, 3);
        assert_eq!(config.redis_pool_max_size, 32, "max(32, 10*2)");
        assert!(!config.grader_enabled);
        assert!(!config.placement_enabled);
        assert!(!config.kiwi_enabled);
        assert!(!config.waf_enabled);
        assert!(config.waf_enforce);
        assert_eq!(config.kiwi_min_duration_ms, Some(500));
        assert_eq!(config.control_plane_api_key.as_deref(), Some("cp-key"));
        assert_eq!(config.internal_service_token.as_deref(), Some("token"));
        assert_eq!(config.ses_configuration_set.as_deref(), Some("cfg-set"));
        assert!(config.internal_tls_enabled);
        assert_eq!(
            config.database_replica_url.as_deref(),
            Some("postgres://replica/db")
        );
        assert_eq!(config.ui_default_surface.as_deref(), Some("control-plane"));
    }

    // ── from_env: refusals ──────────────────────────────────────

    #[test]
    fn adversarial_config_from_env_rejections() {
        let sandbox = EnvSandbox::new();
        sandbox.minimal_dev();
        std::env::remove_var("JWT_PRIVATE_KEY_PEM");
        assert!(matches!(
            Config::from_env(),
            Err(ConfigError::MissingVar(name)) if name == "JWT_PRIVATE_KEY_PEM"
        ));
        sandbox.minimal_dev();

        for (key, value) in [
            ("PORT", "abc"),
            ("REDIS_DB", "300"),
            ("DB_PORT", "0x10"),
            ("GRADER_RATE_LIMIT", "-1"),
            ("MAX_INFLIGHT_REQUESTS", "0"),
            ("RATE_LIMIT_MAX_REQUESTS", "0"),
            ("RATE_LIMIT_WINDOW_MS", "0"),
            ("API_REPLICA_COUNT", "0"),
            ("DB_CLUSTER_CONNECTION_BUDGET", "1"),
            ("STATEMENT_CACHE_CAPACITY", "nope"),
            ("QUERY_TIMEOUT_SECONDS", "nope"),
            ("WEBHOOK_TIMEOUT_MS", "nope"),
            ("IDEMPOTENCY_TTL_SECONDS", "nope"),
            ("METRICS_PORT", "99999"),
            ("HTTP_CLIENT_TIMEOUT_SECONDS", "nope"),
        ] {
            sandbox.minimal_dev();
            sandbox.set(key, value);
            let error = Config::from_env().err();
            let expected_var = if key == "DB_PORT" { "DB_PORT" } else { key };
            match error {
                Some(ConfigError::Invalid { var, .. }) => assert_eq!(var, expected_var),
                Some(ConfigError::MissingVar(name)) => {
                    panic!("{key}={value}: unexpected MissingVar({name})")
                }
                Some(ConfigError::SecurityCheck(reason)) => {
                    panic!("{key}={value}: unexpected SecurityCheck({reason})")
                }
                None => panic!("{key}={value} must be refused"),
            }
        }

        // KiwiCaptcha Argon2id contract: m_kib >= 8*p and t in 3..=6, p == 1.
        sandbox.minimal_dev();
        sandbox.set("KIWI_ALGORITHM", "argon2id");
        sandbox.set("KIWI_ARGON_M_KIB", "1");
        assert!(matches!(
            Config::from_env(),
            Err(ConfigError::Invalid { var, .. }) if var == "KIWI_ARGON_M_KIB"
        ));
        sandbox.set("KIWI_ARGON_M_KIB", "16384");
        sandbox.set("KIWI_ARGON_T", "1");
        assert!(matches!(
            Config::from_env(),
            Err(ConfigError::Invalid { var, .. }) if var == "KIWI_ARGON_T"
        ));
        sandbox.set("KIWI_ARGON_T", "7");
        assert!(Config::from_env().is_err());
        sandbox.set("KIWI_ARGON_T", "3");
        sandbox.set("KIWI_ARGON_P", "2");
        assert!(Config::from_env().is_err());
        sandbox.set("KIWI_ARGON_P", "1");
        // Argon2id difficulty is clamped to the browser-solvable ceiling.
        sandbox.set("KIWI_ARGON2_DIFFICULTY_BITS", "255");
        sandbox.set("KIWI_AUTO_TUNE_MAX_BITS", "255");
        let config = Config::from_env().expect("argon2id config must load");
        assert_eq!(config.kiwi_algorithm, kiwicaptcha::PoWAlgorithm::Argon2id);
        assert!(config.kiwi_argon2_difficulty_bits <= SOLVER_MAX_ARGON2_TARGET_BITS);
        assert!(config.kiwi_auto_tune_max_bits <= SOLVER_MAX_TARGET_BITS);
    }

    #[test]
    #[should_panic(expected = "KIWI_MIN_DURATION_MS")]
    fn adversarial_config_kiwi_min_duration_floor_panics() {
        let sandbox = EnvSandbox::new();
        sandbox.minimal_dev();
        // A floor at/above the TTL leaves no acceptable submission window.
        sandbox.set("KIWI_CHALLENGE_TTL_SECS", "10");
        sandbox.set("KIWI_MIN_DURATION_MS", "10000");
        let _ = Config::from_env();
    }

    // ── from_env: production gate ───────────────────────────────

    #[test]
    fn adversarial_config_production_gate() {
        let sandbox = EnvSandbox::new();
        sandbox.minimal_dev();
        sandbox.set("ENVIRONMENT", "production");
        // Explicit production secrets are required, not generated.
        assert!(matches!(
            Config::from_env(),
            Err(ConfigError::MissingVar(name)) if name == "SESSION_SECRET"
        ));

        strong_production(&sandbox);
        sandbox.set("API_KEY_HASH_SECRET", "short");
        assert!(matches!(
            Config::from_env(),
            Err(ConfigError::SecurityCheck(reason)) if reason.contains("API_KEY_HASH_SECRET")
        ));

        strong_production(&sandbox);
        sandbox.set("BASE_URL", "http://app.apexmail.ee");
        assert!(matches!(
            Config::from_env(),
            Err(ConfigError::SecurityCheck(reason)) if reason.contains("https")
        ));

        strong_production(&sandbox);
        sandbox.set("BILLING_COMPANY_IBAN", "UNCONFIGURED");
        assert!(matches!(
            Config::from_env(),
            Err(ConfigError::SecurityCheck(reason)) if reason.contains("BILLING_COMPANY_IBAN")
        ));

        strong_production(&sandbox);
        sandbox.set("CORS_ORIGINS", "*");
        assert!(matches!(
            Config::from_env(),
            Err(ConfigError::SecurityCheck(reason)) if reason.contains("wildcard")
        ));

        strong_production(&sandbox);
        sandbox.set("PLACEMENT_ENABLED", "true");
        sandbox.set("PLACEMENT_ENCRYPTION_SECRET", "change-me-in-production");
        assert!(matches!(
            Config::from_env(),
            Err(ConfigError::SecurityCheck(reason)) if reason.contains("PLACEMENT_ENCRYPTION_SECRET")
        ));

        // Fully strong production environment loads; the dev-only default
        // surface and wildcard CORS are gone.
        strong_production(&sandbox);
        let config = Config::from_env().expect("strong production env must load");
        assert_eq!(config.environment, Environment::Production);
        assert!(config.environment.is_production());
        assert!(config.ui_default_surface.is_none());
        assert!(config.cors_origins.is_empty());
        assert!(!config.placement_enabled);
        assert!(!config.session_secret.starts_with("dev-"));
    }

    #[test]
    fn adversarial_config_environment_aliases_and_previous_keys() {
        let sandbox = EnvSandbox::new();
        sandbox.minimal_dev();
        for (raw, expected) in [
            ("production", Environment::Production),
            ("PROD", Environment::Production),
            ("staging", Environment::Staging),
            ("Staging", Environment::Staging),
            ("weird", Environment::Development),
            ("", Environment::Development),
        ] {
            if expected == Environment::Production {
                strong_production(&sandbox);
            } else {
                sandbox.minimal_dev();
            }
            sandbox.set("ENVIRONMENT", raw);
            let config = Config::from_env().expect("valid env must load");
            assert_eq!(config.environment, expected, "ENVIRONMENT={raw:?}");
        }

        // Previous verification keys are split and unescaped.
        sandbox.minimal_dev();
        sandbox.set("JWT_PREVIOUS_PUBLIC_KEYS_PEM", "a\\nb||c");
        let config = Config::from_env().unwrap();
        assert_eq!(
            config.jwt_previous_public_keys_pem,
            vec!["a\nb".to_string(), "c".to_string()]
        );
    }

    #[test]
    fn adversarial_config_generated_secrets_and_env_or() {
        // Generated development secrets are unique per call and carry the
        // label prefix, so parallel test binaries never share a signing key.
        let first = generated_dev_secret("session-secret");
        let second = generated_dev_secret("session-secret");
        assert_ne!(first, second);
        assert!(first.starts_with("dev-session-secret-"));
        assert!(first.len() > "dev-session-secret-".len() + 30);

        // env_or: exact override wins, missing falls back, empty is a value.
        std::env::remove_var("CONFIG_ADVERSARIAL_MARKER");
        assert_eq!(env_or("CONFIG_ADVERSARIAL_MARKER", "fallback"), "fallback");
        std::env::set_var("CONFIG_ADVERSARIAL_MARKER", "");
        assert_eq!(env_or("CONFIG_ADVERSARIAL_MARKER", "fallback"), "");
        std::env::set_var("CONFIG_ADVERSARIAL_MARKER", "  spaced  ");
        assert_eq!(
            env_or("CONFIG_ADVERSARIAL_MARKER", "fallback"),
            "  spaced  ",
            "env_or must not trim"
        );
        std::env::remove_var("CONFIG_ADVERSARIAL_MARKER");

        // default_cors_origins: only development + a localhost base URL gets
        // the wildcard; IPv6 loopback counts as local (bracketed spelling).
        assert_eq!(
            default_cors_origins(Environment::Development, "http://[::1]:3000"),
            vec!["*"]
        );
        assert!(default_cors_origins(Environment::Staging, "http://localhost:3000").is_empty());
        assert!(
            default_cors_origins(Environment::Production, "https://app.apexmail.ee").is_empty()
        );
    }
}
