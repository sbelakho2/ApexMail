use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─── Embedding Vector ──────────────────────────────────────────

/// A stored embedding vector with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingVector {
    pub id: Uuid,
    pub text: String,
    pub vector: Vec<f32>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
/// Access timestamp for LRU eviction
    pub last_accessed: DateTime<Utc>,
}

/// Result from a similarity search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub id: Uuid,
    pub text: String,
    pub score: f64,
    pub metadata: serde_json::Value,
}

// ─── Errors ────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum EmbeddingError {
    #[error("Inference server error: {0}")]
    InferenceError(String),

    #[error("Vector dimension mismatch: got {got}, expected {expected}")]
    DimensionMismatch { got: usize, expected: usize },

    #[error("Store full: {count}/{max} vectors")]
    StoreFull { count: usize, max: usize },

    #[error("Vector not found: {id}")]
    NotFound { id: Uuid },

    #[error("Text too long: {len} chars (max {max})")]
    TextTooLong { len: usize, max: usize },

    #[error("Empty text input")]
    EmptyText,

    #[error("Batch too large: {size} (max {max})")]
    BatchTooLarge { size: usize, max: usize },

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

// ─── Chunking types ────────────────────────────────────────────

/// Configuration for text chunking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkConfig {
    pub chunk_size: usize,
    pub chunk_overlap: usize,
    pub separators: Vec<String>,
}

impl Default for ChunkConfig {
    fn default() -> Self {
        Self {
            chunk_size: 512,
            chunk_overlap: 64,
            separators: vec![
                "\n\n".to_string(),
                "\n".to_string(),
                ". ".to_string(),
                " ".to_string(),
            ],
        }
    }
}

/// A chunk of text with position info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextChunk {
    pub text: String,
    pub start_offset: usize,
    pub end_offset: usize,
    pub index: usize,
}

// ─── Inference types ───────────────────────────────────────────

/// Request to the inference server.
#[derive(Debug, Serialize)]
pub struct InferenceRequest {
    pub input: Vec<String>,
    pub model: String,
}

/// Response from the inference server.
#[derive(Debug, Deserialize)]
pub struct InferenceResponse {
    pub data: Vec<InferenceEmbedding>,
}

#[derive(Debug, Deserialize)]
pub struct InferenceEmbedding {
    pub embedding: Vec<f32>,
    pub index: usize,
}

// ─── Store stats ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreStats {
    pub total_vectors: usize,
    pub dimension: usize,
    pub memory_bytes: usize,
    pub oldest_access: Option<DateTime<Utc>>,
    pub newest_access: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedding_vector_serialization() {
        let v = EmbeddingVector {
            id: Uuid::new_v4(),
            text: "hello world".to_string(),
            vector: vec![0.1, 0.2, 0.3],
            metadata: serde_json::json!({"source": "test"}),
            created_at: Utc::now(),
            last_accessed: Utc::now(),
        };
        let json = serde_json::to_string(&v).unwrap();
        let de: EmbeddingVector = serde_json::from_str(&json).unwrap();
        assert_eq!(de.text, "hello world");
        assert_eq!(de.vector.len(), 3);
    }

    #[test]
    fn test_chunk_config_defaults() {
        let cfg = ChunkConfig::default();
        assert_eq!(cfg.chunk_size, 512);
        assert_eq!(cfg.chunk_overlap, 64);
        assert_eq!(cfg.separators.len(), 4);
    }

    #[test]
    fn test_error_display() {
        let err = EmbeddingError::DimensionMismatch {
            got: 256,
            expected: 384,
        };
        assert!(err.to_string().contains("256"));
        assert!(err.to_string().contains("384"));

        let err = EmbeddingError::EmptyText;
        assert!(err.to_string().contains("Empty"));
    }

    #[test]
    fn test_search_result_ordering() {
        let r1 = SearchResult {
            id: Uuid::new_v4(),
            text: "a".to_string(),
            score: 0.9,
            metadata: serde_json::json!({}),
        };
        let r2 = SearchResult {
            id: Uuid::new_v4(),
            text: "b".to_string(),
            score: 0.7,
            metadata: serde_json::json!({}),
        };
        assert!(r1.score > r2.score);
    }

    #[test]
    fn test_store_stats() {
        let stats = StoreStats {
            total_vectors: 1000,
            dimension: 384,
            memory_bytes: 1536000,
            oldest_access: Some(Utc::now()),
            newest_access: Some(Utc::now()),
        };
        assert_eq!(stats.total_vectors, 1000);
        assert_eq!(stats.memory_bytes, 1536000);
    }
}
