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
        }
    }
}

impl AiConfig {
    /// Build config from environment variables, falling back to defaults.
    pub fn from_env() -> Self {
        let defaults = Self::default();
        let config = Self {
            model_endpoint: std::env::var("AI_MODEL_ENDPOINT")
                .unwrap_or(defaults.model_endpoint),
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
        };
        if let Err(err) = config.validate() {
            panic!("Invalid AI config: {err}");
        }
        config
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.model_endpoint.trim().is_empty() {
            return Err("AI_MODEL_ENDPOINT must not be empty".into());
        }
        if !(self.model_endpoint.starts_with("http://") || self.model_endpoint.starts_with("https://")) {
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
    }

    #[test]
    fn test_config_roundtrip_json() {
        let cfg = AiConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: AiConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.embedding_dim, cfg.embedding_dim);
        assert_eq!(parsed.model_endpoint, cfg.model_endpoint);
    }
}
