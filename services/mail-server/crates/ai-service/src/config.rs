//! AI service configuration.

use serde::{Deserialize, Serialize};

/// Top-level configuration for the AI service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    /// External model inference endpoint (e.g. llama-server URL).
    pub model_endpoint: String,
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
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            model_endpoint: "http://127.0.0.1:8081".into(),
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
        }
    }
}

impl AiConfig {
    /// Build config from environment variables, falling back to defaults.
    pub fn from_env() -> Result<Self, String> {
        let defaults = Self::default();
        let config = Self {
            model_endpoint: std::env::var("AI_MODEL_ENDPOINT").unwrap_or(defaults.model_endpoint),
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
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.model_endpoint.trim().is_empty() {
            return Err("AI_MODEL_ENDPOINT must not be empty".into());
        }
        if !(self.model_endpoint.starts_with("http://")
            || self.model_endpoint.starts_with("https://"))
        {
            return Err("AI_MODEL_ENDPOINT must be http/https".into());
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = AiConfig::default();
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
    }

    #[test]
    fn test_config_roundtrip_json() {
        let cfg = AiConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: AiConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.embedding_dim, cfg.embedding_dim);
        assert_eq!(parsed.model_endpoint, cfg.model_endpoint);
        assert_eq!(parsed.bandit_state_path, cfg.bandit_state_path);
        assert_eq!(parsed.bandit_encryption_key, cfg.bandit_encryption_key);
        assert_eq!(parsed.sanitize_ai_output, cfg.sanitize_ai_output);
        assert_eq!(
            parsed.checkpoint_interval_secs,
            cfg.checkpoint_interval_secs
        );
        assert_eq!(parsed.checkpoint_path, cfg.checkpoint_path);
    }
}
