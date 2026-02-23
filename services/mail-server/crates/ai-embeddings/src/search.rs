//! Search API for the vector store.

use uuid::Uuid;

use crate::embeddings::{cosine_similarity, EmbeddingService};
use crate::types::{EmbeddingError, SearchResult};
use crate::vector_store::VectorStore;

/// High-level search interface combining embedding generation and vector search.
pub struct SearchEngine<'a> {
    embedding_service: &'a EmbeddingService,
    vector_store: &'a VectorStore,
}

impl<'a> SearchEngine<'a> {
    pub fn new(embedding_service: &'a EmbeddingService, vector_store: &'a VectorStore) -> Self {
        Self {
            embedding_service,
            vector_store,
        }
    }

    /// Search by text query — generates embedding then searches.
    pub async fn search_by_text(
        &self,
        query: &str,
        top_k: usize,
        min_score: Option<f64>,
    ) -> Result<Vec<SearchResult>, EmbeddingError> {
        let query_vector = self.embedding_service.embed(query).await?;
        let mut results = self.vector_store.search(&query_vector, top_k);

        if let Some(threshold) = min_score {
            results.retain(|r| r.score >= threshold);
        }

        Ok(results)
    }

    /// Search by raw vector — skips embedding generation.
    pub fn search_by_vector(
        &self,
        vector: &[f32],
        top_k: usize,
        min_score: Option<f64>,
    ) -> Vec<SearchResult> {
        let mut results = self.vector_store.search(vector, top_k);

        if let Some(threshold) = min_score {
            results.retain(|r| r.score >= threshold);
        }

        results
    }

    /// Add text with auto-embedding to the store.
    pub async fn add_text(
        &self,
        text: String,
        metadata: serde_json::Value,
    ) -> Result<Uuid, EmbeddingError> {
        let vector = self.embedding_service.embed(&text).await?;
        self.vector_store.add(text, vector, metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embeddings::l2_normalize;
    use crate::vector_store::VectorStore;

    #[test]
    fn test_search_by_vector() {
        let store = VectorStore::new(3, 1000, 900);
        store.add("similar".into(), l2_normalize(vec![0.9, 0.1, 0.0]), serde_json::json!({})).unwrap();
        store.add("different".into(), l2_normalize(vec![0.0, 0.0, 1.0]), serde_json::json!({})).unwrap();

        let config = crate::config::InferenceConfig {
            url: "http://localhost:8080".into(),
            model: "test".into(),
            dimension: 3,
            max_concurrency: 4,
            timeout_ms: 5000,
            pooling: crate::config::PoolingStrategy::Mean,
        };
        let svc = EmbeddingService::new(config);
        let engine = SearchEngine::new(&svc, &store);

        let query = l2_normalize(vec![1.0, 0.0, 0.0]);
        let results = engine.search_by_vector(&query, 1, None);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].text, "similar");
    }

    #[test]
    fn test_search_with_min_score() {
        let store = VectorStore::new(3, 1000, 900);
        store.add("close".into(), l2_normalize(vec![0.99, 0.01, 0.0]), serde_json::json!({})).unwrap();
        store.add("far".into(), l2_normalize(vec![0.0, 0.0, 1.0]), serde_json::json!({})).unwrap();

        let config = crate::config::InferenceConfig {
            url: "http://localhost:8080".into(),
            model: "test".into(),
            dimension: 3,
            max_concurrency: 4,
            timeout_ms: 5000,
            pooling: crate::config::PoolingStrategy::Mean,
        };
        let svc = EmbeddingService::new(config);
        let engine = SearchEngine::new(&svc, &store);

        let query = l2_normalize(vec![1.0, 0.0, 0.0]);
        let results = engine.search_by_vector(&query, 10, Some(0.5));
        // Only "close" should pass the threshold
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].text, "close");
    }

    #[test]
    fn test_search_empty_results() {
        let store = VectorStore::new(3, 1000, 900);

        let config = crate::config::InferenceConfig {
            url: "http://localhost:8080".into(),
            model: "test".into(),
            dimension: 3,
            max_concurrency: 4,
            timeout_ms: 5000,
            pooling: crate::config::PoolingStrategy::Mean,
        };
        let svc = EmbeddingService::new(config);
        let engine = SearchEngine::new(&svc, &store);

        let query = l2_normalize(vec![1.0, 0.0, 0.0]);
        let results = engine.search_by_vector(&query, 5, None);
        assert!(results.is_empty());
    }
}
