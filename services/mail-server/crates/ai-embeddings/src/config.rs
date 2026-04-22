use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct EmbeddingsConfig {
    pub server: ServerConfig,
    pub inference: InferenceConfig,
    pub store: StoreConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InferenceConfig {
/// URL of the inference server (llama-server or ONNX sidecar)
    pub url: String,
/// Model identifier
    #[serde(default = "default_model")]
    pub model: String,
/// Embedding dimension
    #[serde(default = "default_dimension")]
    pub dimension: usize,
/// Max concurrent embedding requests
    #[serde(default = "default_concurrency")]
    pub max_concurrency: usize,
/// Request timeout in milliseconds
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
/// Pooling strategy
    #[serde(default)]
    pub pooling: PoolingStrategy,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PoolingStrategy {
    #[default]
    Mean,
    Cls,
    Max,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StoreConfig {
/// Max vectors in the store
    #[serde(default = "default_max_vectors")]
    pub max_vectors: usize,
/// LRU eviction after this many entries
    #[serde(default = "default_eviction_threshold")]
    pub eviction_threshold: usize,
}

fn default_host() -> String { "0.0.0.0".to_string() }
fn default_port() -> u16 { 9090 }
fn default_model() -> String { "all-MiniLM-L6-v2".to_string() }
fn default_dimension() -> usize { 384 }
fn default_concurrency() -> usize { 8 }
fn default_timeout_ms() -> u64 { 30_000 }
fn default_max_vectors() -> usize { 100_000 }
fn default_eviction_threshold() -> usize { 90_000 }

impl EmbeddingsConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.server.host.trim().is_empty() {
            return Err("HOST must not be empty".into());
        }
        if self.server.port == 0 {
            return Err("PORT must be > 0".into());
        }
        if self.inference.url.trim().is_empty() {
            return Err("INFERENCE_URL must not be empty".into());
        }
        if !(self.inference.url.starts_with("http://") || self.inference.url.starts_with("https://")) {
            return Err("INFERENCE_URL must be http/https".into());
        }
        if self.inference.dimension == 0 {
            return Err("DIMENSION must be > 0".into());
        }
        if self.inference.max_concurrency == 0 {
            return Err("MAX_CONCURRENCY must be > 0".into());
        }
        if self.inference.timeout_ms == 0 {
            return Err("TIMEOUT_MS must be > 0".into());
        }
        if self.store.max_vectors == 0 {
            return Err("MAX_VECTORS must be > 0".into());
        }
        if self.store.eviction_threshold == 0 {
            return Err("EVICTION_THRESHOLD must be > 0".into());
        }
        if self.store.eviction_threshold > self.store.max_vectors {
            return Err("EVICTION_THRESHOLD must be <= MAX_VECTORS".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let json = r#"{
            "server": {},
            "inference": { "url": "http://localhost:8080" },
            "store": {}
        }"#;
        let cfg: EmbeddingsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.server.port, 9090);
        assert_eq!(cfg.inference.dimension, 384);
        assert_eq!(cfg.inference.max_concurrency, 8);
        assert_eq!(cfg.store.max_vectors, 100_000);
        assert_eq!(cfg.inference.pooling, PoolingStrategy::Mean);
    }

    #[test]
    fn test_pooling_strategies() {
        let json = r#"{"server":{},"inference":{"url":"http://x","pooling":"cls"},"store":{}}"#;
        let cfg: EmbeddingsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.inference.pooling, PoolingStrategy::Cls);
    }
}
