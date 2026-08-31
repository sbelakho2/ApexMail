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
    /// Whether to sanitize AI-generated HTML output with ammonia (O-10.2).
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
        Ok(())
    }
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

    fn env_bool_value(value: &str) -> Result<bool, String> {
        match value {
            "true" | "1" => Ok(true),
            "false" | "0" => Ok(false),
            _ => Err("invalid boolean".into()),
        }
    }
}
