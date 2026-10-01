//! AI service configuration.

use serde::{Deserialize, Serialize};

/// Top-level configuration for the AI service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiConfig {
    /// Explicit opt-in gate for the configured external model runtime.
    pub model_enabled: bool,
    /// External model inference endpoint (e.g. llama-server URL).
    pub model_endpoint: String,
    /// Model name passed to an OpenAI-compatible inference provider.
    pub model_name: String,
    /// Optional bearer credential for the model provider.
    #[serde(default, skip_serializing)]
    pub model_api_key: String,
    /// Per-request timeout enforced when calling the model provider.
    pub model_timeout_secs: u64,
    /// Embedding vector dimensionality.
    pub embedding_dim: usize,
    /// Maximum tokens for text generation.
    pub max_tokens: usize,
    /// Sampling temperature (0.0 = greedy).
    pub temperature: f64,
    /// Epsilon for epsilon-greedy bandit exploration.
    pub bandit_epsilon: f64,
    /// Look-back window in days for STO engagement data.
    pub sto_lookback_days: u32,
    /// Maximum number of inference requests allowed per window.
    pub inference_rate_limit: usize,
    /// Sliding window size for inference rate limiting.
    pub inference_rate_limit_window_secs: u64,
    /// Redis URL for distributed rate limiting (empty = no Redis, allow all).
    pub redis_url: String,
    /// Snapshot file used to persist bandit arm state across restarts.
    pub bandit_state_path: String,
    /// hex-encoded 32-byte AES-256-GCM key for bandit state encryption (O-10.1).
    /// Leave empty to disable encryption (plaintext JSON).
    pub bandit_encryption_key: String,
    /// Whether model output is sanitized with the ammonia allowlist before
    /// it is returned or persisted (O-10.2). Default `true`. `false` is a
    /// FAIL-CLOSED refusal: generative answers are refused with an honest
    /// error (chat returns 503) — disabling sanitization never creates an
    /// unsanitized output path.
    pub sanitize_ai_output: bool,
    /// Interval in seconds between periodic training checkpoint writes (O-10.3).
    pub checkpoint_interval_secs: u64,
    /// Directory path for training checkpoints (O-10.3).
    pub checkpoint_path: String,
    /// Operator-controlled executable that starts a reviewed offline training
    /// job. Empty means `/train` correctly returns unavailable.
    pub training_runner: String,
    /// Optional working directory supplied to the training runner.
    pub training_working_dir: String,
    /// Optional Postgres URL for authoritative tenant domain-record lookups.
    /// This is intentionally omitted from serialized status/config output.
    #[serde(default, skip_serializing)]
    pub database_url: String,
    /// P1-SECURITY: dedicated credential for the AI-control routes (`/train`,
    /// `/training/jobs/:job_id`, `/evaluate`, `/admin/reindex`). The universal
    /// `INTERNAL_SERVICE_TOKEN` must never authorize model lifecycle changes.
    /// REQUIRED in production (`APP_ENV` unset counts as production) — the
    /// service refuses to boot without it. Omitted from serialized output.
    #[serde(default, skip_serializing)]
    pub ai_admin_token: String,
    /// AWS region used by the active SES custom MAIL FROM configuration.
    pub aws_region: String,
    /// Shared deployment transport selection. Only explicit `smtp` selects the
    /// SMTP record contract; all other values select the SES contract.
    pub email_transport: String,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            model_enabled: false,
            model_endpoint: "http://127.0.0.1:8081/v1".into(),
            model_name: "apexmail-assistant".into(),
            model_api_key: String::new(),
            model_timeout_secs: 30,
            embedding_dim: 384,
            max_tokens: 768,
            temperature: 0.0,
            bandit_epsilon: 0.1,
            sto_lookback_days: 90,
            inference_rate_limit: 60,
            inference_rate_limit_window_secs: 60,
            redis_url: String::new(),
            bandit_state_path: "./data/ai-service/bandits.json".into(),
            bandit_encryption_key: String::new(),
            sanitize_ai_output: true,
            checkpoint_interval_secs: 60,
            checkpoint_path: "./data/ai-service/checkpoints/".into(),
            training_runner: String::new(),
            training_working_dir: String::new(),
            database_url: String::new(),
            ai_admin_token: String::new(),
            aws_region: "eu-central-1".into(),
            email_transport: String::new(),
        }
    }
}

impl AiConfig {
    /// Build config from environment variables, falling back to defaults.
    pub fn from_env() -> Result<Self, String> {
        let defaults = Self::default();
        let config = Self {
            model_enabled: env_bool("AI_MODEL_ENABLED", defaults.model_enabled)?,
            model_endpoint: std::env::var("AI_MODEL_ENDPOINT").unwrap_or(defaults.model_endpoint),
            model_name: std::env::var("AI_MODEL_NAME").unwrap_or(defaults.model_name),
            model_api_key: std::env::var("AI_MODEL_API_KEY").unwrap_or(defaults.model_api_key),
            model_timeout_secs: std::env::var("AI_MODEL_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(defaults.model_timeout_secs),
            embedding_dim: std::env::var("AI_EMBEDDING_DIM")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(defaults.embedding_dim),
            max_tokens: std::env::var("AI_MAX_TOKENS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(defaults.max_tokens),
            temperature: std::env::var("AI_TEMPERATURE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(defaults.temperature),
            bandit_epsilon: std::env::var("AI_BANDIT_EPSILON")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(defaults.bandit_epsilon),
            sto_lookback_days: std::env::var("AI_STO_LOOKBACK_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(defaults.sto_lookback_days),
            inference_rate_limit: std::env::var("AI_INFERENCE_RATE_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(defaults.inference_rate_limit),
            inference_rate_limit_window_secs: std::env::var("AI_INFERENCE_RATE_LIMIT_WINDOW_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(defaults.inference_rate_limit_window_secs),
            redis_url: std::env::var("AI_REDIS_URL").unwrap_or(defaults.redis_url),
            bandit_state_path: std::env::var("AI_BANDIT_STATE_PATH")
                .unwrap_or(defaults.bandit_state_path),
            bandit_encryption_key: std::env::var("AI_BANDIT_ENCRYPTION_KEY")
                .unwrap_or(defaults.bandit_encryption_key),
            sanitize_ai_output: std::env::var("AI_SANITIZE_AI_OUTPUT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(defaults.sanitize_ai_output),
            checkpoint_interval_secs: std::env::var("AI_CHECKPOINT_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(defaults.checkpoint_interval_secs),
            checkpoint_path: std::env::var("AI_CHECKPOINT_PATH")
                .unwrap_or(defaults.checkpoint_path),
            training_runner: std::env::var("AI_TRAINING_RUNNER")
                .unwrap_or(defaults.training_runner),
            training_working_dir: std::env::var("AI_TRAINING_WORKING_DIR")
                .unwrap_or(defaults.training_working_dir),
            database_url: std::env::var("AI_DATABASE_URL")
                .or_else(|_| std::env::var("DATABASE_URL"))
                .unwrap_or(defaults.database_url),
            ai_admin_token: std::env::var("AI_ADMIN_TOKEN").unwrap_or(defaults.ai_admin_token),
            aws_region: std::env::var("AWS_REGION").unwrap_or(defaults.aws_region),
            email_transport: std::env::var("EMAIL_TRANSPORT_TYPE")
                .unwrap_or(defaults.email_transport),
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.model_enabled && self.model_endpoint.trim().is_empty() {
            return Err("AI_MODEL_ENDPOINT must not be empty".into());
        }
        if self.model_enabled
            && !(self.model_endpoint.starts_with("http://")
                || self.model_endpoint.starts_with("https://"))
        {
            return Err("AI_MODEL_ENDPOINT must be http/https".into());
        }
        // SM9 #10: a bearer API key must never transit plaintext HTTP to a
        // non-loopback host. `http://` stays legitimate for the default
        // local sidecar (127.0.0.1), but anywhere else on the wire the
        // credential is network-observable — refuse the boot rather than
        // leak the key (fail closed).
        if self.model_enabled
            && !self.model_api_key.trim().is_empty()
            && is_non_loopback_http_endpoint(&self.model_endpoint)
        {
            return Err(
                "AI_MODEL_ENDPOINT uses plaintext http:// with a non-empty AI_MODEL_API_KEY: \
                 the bearer credential would transit the network unencrypted — use https:// \
                 or a loopback endpoint"
                    .into(),
            );
        }
        if self.model_enabled && self.model_name.trim().is_empty() {
            return Err("AI_MODEL_NAME must not be empty when AI_MODEL_ENABLED=true".into());
        }
        if self.model_timeout_secs == 0 || self.model_timeout_secs > 300 {
            return Err("AI_MODEL_TIMEOUT_SECS must be between 1 and 300".into());
        }
        if self.embedding_dim == 0 {
            return Err("AI_EMBEDDING_DIM must be > 0".into());
        }
        if self.max_tokens == 0 {
            return Err("AI_MAX_TOKENS must be > 0".into());
        }
        if !(0.0..=2.0).contains(&self.temperature) {
            return Err("AI_TEMPERATURE must be between 0.0 and 2.0".into());
        }
        if !(0.0..=1.0).contains(&self.bandit_epsilon) {
            return Err("AI_BANDIT_EPSILON must be between 0.0 and 1.0".into());
        }
        if self.sto_lookback_days == 0 {
            return Err("AI_STO_LOOKBACK_DAYS must be > 0".into());
        }
        if self.inference_rate_limit == 0 {
            return Err("AI_INFERENCE_RATE_LIMIT must be > 0".into());
        }
        if self.inference_rate_limit_window_secs == 0 {
            return Err("AI_INFERENCE_RATE_LIMIT_WINDOW_SECS must be > 0".into());
        }
        if self.bandit_state_path.trim().is_empty() {
            return Err("AI_BANDIT_STATE_PATH must not be empty".into());
        }
        if !self.bandit_encryption_key.is_empty() && self.bandit_encryption_key.len() != 64 {
            return Err("AI_BANDIT_ENCRYPTION_KEY must be 64 hex chars (32 bytes)".into());
        }
        if self.checkpoint_interval_secs == 0 {
            return Err("AI_CHECKPOINT_INTERVAL_SECS must be > 0".into());
        }
        if self.checkpoint_path.trim().is_empty() {
            return Err("AI_CHECKPOINT_PATH must not be empty".into());
        }
        if self.aws_region.trim().is_empty() {
            return Err("AWS_REGION must not be empty".into());
        }
        // P1-SECURITY: the AI-control credential is mandatory wherever
        // production traffic may be served. Same production detection as the
        // other services (sales-autopilot): APP_ENV == "production", and an
        // UNSET APP_ENV counts as production (fail closed). Without the
        // credential the service refuses to boot rather than serving
        // /train, /evaluate and /admin/reindex under the shared universal
        // INTERNAL_SERVICE_TOKEN.
        if is_production_mode() && self.ai_admin_token.trim().is_empty() {
            return Err(
                "AI_ADMIN_TOKEN must be set when APP_ENV is production (or unset): the \
                 universal INTERNAL_SERVICE_TOKEN must not authorize AI-control routes"
                    .into(),
            );
        }
        Ok(())
    }
}

/// Production detection following the workspace convention (see
/// sales-autopilot): `APP_ENV == "production"` case-insensitively — and an
/// UNSET `APP_ENV` is treated as production (fail closed).
pub fn is_production_mode() -> bool {
    std::env::var("APP_ENV")
        .map(|v| v.eq_ignore_ascii_case("production"))
        .unwrap_or(true)
}

/// SM9 #10: true when `endpoint` is an `http://` URL whose host is NOT a
/// proven loopback address (`localhost`, `127.0.0.0/8`, `::1`). Loopback
/// plaintext is the supported local-sidecar configuration; a hostname that
/// cannot be proven loopback is treated as remote (fail closed).
fn is_non_loopback_http_endpoint(endpoint: &str) -> bool {
    let Some(rest) = endpoint.trim().strip_prefix("http://") else {
        // https:// is always fine; schemeless values are rejected elsewhere.
        return false;
    };
    // Cut path/query/fragment, then drop userinfo if present.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    // Bracketed IPv6 literal first (a port follows the closing bracket).
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        stripped.split(']').next().unwrap_or(stripped)
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty() {
        return true; // malformed authority: assume remote
    }
    if host == "localhost" {
        return false;
    }
    if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        return !ip.is_loopback();
    }
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return !ip.is_loopback();
    }
    true
}

fn env_bool(name: &str, default: bool) -> Result<bool, String> {
    match std::env::var(name) {
        Ok(value) if value.eq_ignore_ascii_case("true") || value == "1" => Ok(true),
        Ok(value) if value.eq_ignore_ascii_case("false") || value == "0" => Ok(false),
        Ok(value) => Err(format!(
            "{name} must be true, false, 1, or 0; got {value:?}"
        )),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(format!("failed to read {name}: {error}")),
    }
}

/// Two-stage planner mode. Default OFF: single-pass generation (the model
/// classifies intent and calls tools natively); "on" restores the separate
/// planner round-trip.
pub fn planner_enabled() -> bool {
    std::env::var("AI_PIPELINE_PLANNER")
        .map(|v| v == "on" || v == "true" || v == "1")
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{EnvGuard, ENV_SERIAL};

    #[test]
    fn test_default_config() {
        let cfg = AiConfig::default();
        assert!(!cfg.model_enabled);
        assert_eq!(cfg.model_name, "apexmail-assistant");
        assert_eq!(cfg.model_timeout_secs, 30);
        assert_eq!(cfg.embedding_dim, 384);
        assert!((cfg.temperature - 0.0).abs() < f64::EPSILON);
        assert_eq!(cfg.sto_lookback_days, 90);
        assert!((cfg.bandit_epsilon - 0.1).abs() < f64::EPSILON);
        assert_eq!(cfg.max_tokens, 768);
        assert_eq!(cfg.inference_rate_limit, 60);
        assert_eq!(cfg.inference_rate_limit_window_secs, 60);
        assert_eq!(cfg.bandit_state_path, "./data/ai-service/bandits.json");
        assert!(cfg.bandit_encryption_key.is_empty());
        assert!(cfg.sanitize_ai_output);
        assert_eq!(cfg.checkpoint_interval_secs, 60);
        assert_eq!(cfg.checkpoint_path, "./data/ai-service/checkpoints/");
        assert!(cfg.training_runner.is_empty());
        assert!(cfg.database_url.is_empty());
        assert!(cfg.ai_admin_token.is_empty());
        assert_eq!(cfg.aws_region, "eu-central-1");
    }

    #[test]
    fn test_config_roundtrip_json() {
        let cfg = AiConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: AiConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.embedding_dim, cfg.embedding_dim);
        assert_eq!(parsed.model_endpoint, cfg.model_endpoint);
        assert_eq!(parsed.model_name, cfg.model_name);
        assert_eq!(parsed.bandit_state_path, cfg.bandit_state_path);
        assert_eq!(parsed.bandit_encryption_key, cfg.bandit_encryption_key);
        assert_eq!(parsed.sanitize_ai_output, cfg.sanitize_ai_output);
        assert_eq!(
            parsed.checkpoint_interval_secs,
            cfg.checkpoint_interval_secs
        );
        assert_eq!(parsed.checkpoint_path, cfg.checkpoint_path);
    }

    #[test]
    fn rejects_invalid_boolean_values() {
        assert!(matches!(
            env_bool("AI_UNUSED_TEST_BOOLEAN", false),
            Ok(false)
        ));
        assert!(env_bool_value("maybe").is_err());
    }

    /// SM9 #10: the gate recognizes exactly the loopback shapes (the
    /// supported local-sidecar configuration) and treats everything else —
    /// remote hostnames, remote IPs, malformed authorities — as remote.
    #[test]
    fn plaintext_http_gate_flags_only_non_loopback_hosts() {
        // Loopback plaintext stays allowed.
        assert!(!is_non_loopback_http_endpoint("http://127.0.0.1:8081/v1"));
        assert!(!is_non_loopback_http_endpoint("http://localhost/v1"));
        assert!(!is_non_loopback_http_endpoint("http://LOCALHOST:9000"));
        assert!(!is_non_loopback_http_endpoint("http://[::1]:9000/v1"));
        assert!(!is_non_loopback_http_endpoint("http://127.9.8.7/v1"));
        // https is never flagged.
        assert!(!is_non_loopback_http_endpoint("https://model.internal/v1"));
        // Everything else is remote.
        assert!(is_non_loopback_http_endpoint(
            "http://model.internal:8080/v1"
        ));
        assert!(is_non_loopback_http_endpoint("http://10.0.0.7:8080/v1"));
        assert!(is_non_loopback_http_endpoint("http://213.239.200.1/v1"));
        assert!(is_non_loopback_http_endpoint(
            "http://[2620:0:2d0:200::7]/v1"
        ));
        assert!(is_non_loopback_http_endpoint("http:///v1"), "empty host");
    }

    /// SM9 #10: a non-loopback http:// endpoint configured with an API key
    /// refuses to boot (the credential would transit plaintext); the same
    /// endpoint on loopback, or without a key, still loads.
    #[test]
    fn validate_refuses_api_key_over_plaintext_non_loopback_http() {
        let _serial = ENV_SERIAL.blocking_lock();
        let _guard = EnvGuard::with(&[("APP_ENV", Some("development"))]);
        let mut cfg = AiConfig {
            model_enabled: true,
            model_api_key: "sk-secret".into(),
            ..AiConfig::default()
        };
        cfg.model_endpoint = "http://model.internal:8080/v1".into();
        let err = cfg
            .validate()
            .expect_err("remote plaintext + key must refuse to boot");
        assert!(err.contains("http"), "the error names the problem: {err}");

        cfg.model_endpoint = "http://127.0.0.1:8081/v1".into();
        cfg.validate().expect("loopback plaintext stays allowed");

        cfg.model_endpoint = "http://model.internal:8080/v1".into();
        cfg.model_api_key = String::new();
        cfg.validate()
            .expect("no credential, no plaintext-key exposure");
    }

    /// P1-SECURITY: production boot refuses without the dedicated AI-admin
    /// credential — an unset APP_ENV counts as production (fail closed), and
    /// a loaded production config carries the credential.
    #[test]
    fn production_boots_require_ai_admin_token() {
        let _serial = ENV_SERIAL.blocking_lock();
        // APP_ENV unset → production → refusal.
        let _guard = EnvGuard::with(&[("APP_ENV", None), ("AI_ADMIN_TOKEN", None)]);
        assert!(
            AiConfig::from_env().is_err(),
            "production without AI_ADMIN_TOKEN must refuse to boot"
        );
        // Explicit production likewise.
        let _guard = EnvGuard::with(&[("APP_ENV", Some("production")), ("AI_ADMIN_TOKEN", None)]);
        assert!(AiConfig::from_env().is_err());
        // With the credential set, production config loads and carries it.
        let _guard = EnvGuard::with(&[
            ("APP_ENV", Some("Production")),
            ("AI_ADMIN_TOKEN", Some("admin-secret")),
        ]);
        let cfg = AiConfig::from_env().expect("production config with AI_ADMIN_TOKEN");
        assert_eq!(cfg.ai_admin_token, "admin-secret");
        // A non-production deployment still loads without the credential.
        let _guard = EnvGuard::with(&[("APP_ENV", Some("development")), ("AI_ADMIN_TOKEN", None)]);
        assert!(AiConfig::from_env().is_ok());
        // And the credential is never serialized into status/config output.
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(!json.contains("admin-secret"), "{json}");
    }

    fn env_bool_value(value: &str) -> Result<bool, String> {
        match value {
            "true" | "1" => Ok(true),
            "false" | "0" => Ok(false),
            _ => Err("invalid boolean".into()),
        }
    }
}
