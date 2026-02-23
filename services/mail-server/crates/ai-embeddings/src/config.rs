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
