//! Configuration loaded from environment variables.
//!
//! Includes production-safety checks on secret lengths.

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

    // ── Control Plane ───────────────────────────────────────
    /// Static API key used by the control-plane backend to authenticate
    /// internal requests. If set, X-API-Key matching this value bypasses
    /// the normal api_keys DB lookup and returns a super-admin identity.
    pub control_plane_api_key: Option<String>,
    pub sales_autopilot_base_url: String,
    pub internal_service_token: Option<String>,

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

    // ── mCaptcha CAPTCHA ────────────────────────────────────
    /// mCaptcha is a privacy-preserving, proof-of-work based CAPTCHA system.
    /// Base URL of the mCaptcha server (e.g. "https://mcaptcha.example.com").
    pub mcaptcha_base_url: String,
    /// Site key issued by the mCaptcha server for this deployment.
    /// In development, set to "dev" to bypass verification.
    pub mcaptcha_site_key: String,
    /// Secret key used to verify the mCaptcha token server-side.
    /// In development, set to "dev" to bypass verification.
    pub mcaptcha_secret_key: String,
    /// Enable mCaptcha CAPTCHA verification on auth routes (login, signup).
    pub mcaptcha_enabled: bool,
    /// mCaptcha verification endpoint URL.
    pub mcaptcha_verify_url: String,
    /// Internal base URL of the self-hosted mCaptcha container, used by the
    /// Rust reverse proxy in `fallback_handler` to serve the `/mcaptcha/*`
    /// widget assets. This is a server-to-server call on the Docker network,
    /// so it is HTTP (not HTTPS). The browser-facing URL is `mcaptcha_base_url`.
    /// Default: "http://apexmail-mcaptcha-1:7000".
    pub mcaptcha_internal_url: String,

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

fn resolve_mcaptcha_secret_key(
    secret_key: Option<String>,
    legacy_secret: Option<String>,
) -> String {
    secret_key
        .or(legacy_secret)
        .unwrap_or_else(|| "dev".to_string())
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
        .map(|host| matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1"))
        .unwrap_or(false)
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

        let mcaptcha_base_url = env_or("MCAPTCHA_BASE_URL", "https://mcaptcha.example.com");
        let mcaptcha_site_key = env_or("MCAPTCHA_SITE_KEY", "dev");
        let mcaptcha_secret_key = resolve_mcaptcha_secret_key(
            env::var("MCAPTCHA_SECRET_KEY").ok(),
            env::var("MCAPTCHA_SECRET").ok(),
        );
        let mcaptcha_enabled = env_or("MCAPTCHA_ENABLED", "false").parse().unwrap_or(false);
        let mcaptcha_verify_url = env_or(
            "MCAPTCHA_VERIFY_URL",
            "https://demo.mcaptcha.org/api/v1/pow/siteverify",
        );
        // Internal container URL used by the api-server reverse proxy for the
        // `/mcaptcha/*` widget assets. Server-to-server on the Docker network
        // (HTTP), so it is separate from the browser-facing `mcaptcha_base_url`.
        let mcaptcha_internal_url = env_or(
            "MCAPTCHA_INTERNAL_URL",
            "http://apexmail-mcaptcha-1:7000",
        );
        if !environment.is_production()
            && (mcaptcha_site_key == "dev" || mcaptcha_secret_key == "dev")
        {
            tracing::info!(
                "mCaptcha configured with dev keys — CAPTCHA verification will be bypassed"
            );
        }

        let config = Config {
            port: parse_u16("PORT", &env_or("PORT", "3000"))?,
            host: env_or("HOST", "0.0.0.0"),
            base_url,
            environment,

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
                &env_or("WEBHOOK_MAX_RETRIES", "3"),
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
            sales_autopilot_base_url: env_or("SALES_AUTOPILOT_BASE_URL", "http://0.0.0.0:3010"),
            internal_service_token: env::var("INTERNAL_SERVICE_TOKEN")
                .ok()
                .filter(|s| !s.is_empty()),

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

            mcaptcha_base_url,
            mcaptcha_site_key,
            mcaptcha_secret_key,
            mcaptcha_enabled,
            mcaptcha_verify_url,
            mcaptcha_internal_url,

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
            for (name, value) in [
                ("SESSION_SECRET", session_secret_env.as_deref()),
                ("IMPERSONATION_SECRET", impersonation_secret_env.as_deref()),
                ("CSRF_SECRET", csrf_secret_env.as_deref()),
                ("TRACKING_SECRET_KEY", tracking_secret_key_env.as_deref()),
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
        if self.mcaptcha_enabled {
            validate_required_setting("MCAPTCHA_BASE_URL", &self.mcaptcha_base_url, &[""])?;
            validate_required_setting("MCAPTCHA_SITE_KEY", &self.mcaptcha_site_key, &["dev"])?;
            validate_secret(
                "MCAPTCHA_SECRET_KEY",
                &self.mcaptcha_secret_key,
                16,
                &["dev"],
            )?;
            validate_https_url("MCAPTCHA_BASE_URL", &self.mcaptcha_base_url)?;
            // MCAPTCHA_VERIFY_URL is a server-to-server call (api-server → mCaptcha).
            // When mCaptcha is self-hosted on the Docker network, it uses HTTP.
            // Only enforce HTTPS for external mCaptcha instances.
            if !self.mcaptcha_verify_url.contains("://apexmail-mcaptcha")
                && !self.mcaptcha_verify_url.contains("://mcaptcha")
                && !self.mcaptcha_verify_url.starts_with("http://captcha.apexmail.ee")
            {
                validate_https_url("MCAPTCHA_VERIFY_URL", &self.mcaptcha_verify_url)?;
            }
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

    fn valid_production_config() -> Config {
        Config {
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
            webhook_max_retries: 3,
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
            internal_service_token: None,
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

            mcaptcha_base_url: "https://mcaptcha.example.com".into(),
            mcaptcha_site_key: "prod-site-key-12345".into(),
            mcaptcha_secret_key: "prod-secret-key-67890".into(),
            mcaptcha_enabled: true,
            mcaptcha_verify_url: "https://demo.mcaptcha.org/api/v1/pow/siteverify".into(),
            mcaptcha_internal_url: "http://apexmail-mcaptcha-1:7000".into(),
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

        let mut config = valid_production_config();
        config.mcaptcha_site_key = "dev".into();
        assert!(config.validate_production().is_err());

        let mut config = valid_production_config();
        config.mcaptcha_secret_key = "dev".into();
        assert!(config.validate_production().is_err());

        assert_eq!(
            resolve_mcaptcha_secret_key(None, Some("legacy-secret-value".into())),
            "legacy-secret-value"
        );
        assert_eq!(
            resolve_mcaptcha_secret_key(
                Some("preferred-secret-value".into()),
                Some("legacy-secret-value".into())
            ),
            "preferred-secret-value"
        );

        let mut config = valid_production_config();
        config.mcaptcha_base_url = "http://mcaptcha.example.com".into();
        assert!(config.validate_production().is_err());

        let mut config = valid_production_config();
        config.mcaptcha_enabled = false;
        config.mcaptcha_site_key = "dev".into();
        config.mcaptcha_secret_key = "dev".into();
        assert!(config.validate_production().is_ok());
    }

    #[test]
    fn ui_surface_for_host_prefers_explicit_host_maps() {
        let config = Config {
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
            webhook_max_retries: 3,
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
            internal_service_token: None,
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

            mcaptcha_base_url: "https://mcaptcha.example.com".into(),
            mcaptcha_site_key: "dev".into(),
            mcaptcha_secret_key: "dev".into(),
            mcaptcha_enabled: false,
            mcaptcha_verify_url: "https://demo.mcaptcha.org/api/v1/pow/siteverify".into(),
            mcaptcha_internal_url: "http://apexmail-mcaptcha-1:7000".into(),
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
