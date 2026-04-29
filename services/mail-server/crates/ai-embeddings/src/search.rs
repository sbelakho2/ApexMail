//! Search API for the vector store.

use uuid::Uuid;

use crate::embeddings::EmbeddingService;
use crate::types::{EmbeddingError, SearchResult};
use crate::vector_store::VectorStore;

/// High-level search interface combining embedding generation and vector search.
pub struct SearchEngine<'a> {
    embedding_service: &'a EmbeddingService,
    vector_store: &'a VectorStore,
}

fn metadata_with_tenant_scope(metadata: serde_json::Value, tenant_id: &str) -> serde_json::Value {
    let mut scoped = match metadata {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    scoped.insert("tenant_id".into(), tenant_id.into());
    serde_json::Value::Object(scoped)
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
        tenant_id: &str,
    ) -> Result<Vec<SearchResult>, EmbeddingError> {
        let query_vector = self.embedding_service.embed(query).await?;
        let mut results = self.vector_store.search(&query_vector, top_k, tenant_id);

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
        tenant_id: &str,
    ) -> Vec<SearchResult> {
        let mut results = self.vector_store.search(vector, top_k, tenant_id);

        if let Some(threshold) = min_score {
            results.retain(|r| r.score >= threshold);
        }

        results
    }

/// Add text with auto-embedding to the store.
    pub async fn add_text(
        &self,
        text: String,
        tenant_id: &str,
        metadata: serde_json::Value,
    ) -> Result<Uuid, EmbeddingError> {
        let vector = self.embedding_service.embed(&text).await?;
        self.vector_store
            .add(text, vector, metadata_with_tenant_scope(metadata, tenant_id))
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
        store.add("similar".into(), l2_normalize(vec![0.9, 0.1, 0.0]), serde_json::json!({"tenant_id":"tenant-a"})).unwrap();
        store.add("different".into(), l2_normalize(vec![0.0, 0.0, 1.0]), serde_json::json!({"tenant_id":"tenant-a"})).unwrap();

        let config = crate::config::InferenceConfig {
            url: "http://localhost:8080".into(),
            model: "test".into(),
            dimension: 3,
            max_concurrency: 4,
            timeout_ms: 5000,
            pooling: crate::config::PoolingStrategy::Mean,
        };
        let svc = EmbeddingService::new(config).unwrap();
        let engine = SearchEngine::new(&svc, &store);

        let query = l2_normalize(vec![1.0, 0.0, 0.0]);
        let results = engine.search_by_vector(&query, 1, None, "tenant-a");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].text, "similar");
    }

    #[test]
    fn test_search_with_min_score() {
        let store = VectorStore::new(3, 1000, 900);
        store.add("close".into(), l2_normalize(vec![0.99, 0.01, 0.0]), serde_json::json!({"tenant_id":"tenant-a"})).unwrap();
        store.add("far".into(), l2_normalize(vec![0.0, 0.0, 1.0]), serde_json::json!({"tenant_id":"tenant-a"})).unwrap();

        let config = crate::config::InferenceConfig {
            url: "http://localhost:8080".into(),
            model: "test".into(),
            dimension: 3,
            max_concurrency: 4,
            timeout_ms: 5000,
            pooling: crate::config::PoolingStrategy::Mean,
        };
        let svc = EmbeddingService::new(config).unwrap();
        let engine = SearchEngine::new(&svc, &store);

        let query = l2_normalize(vec![1.0, 0.0, 0.0]);
        let results = engine.search_by_vector(&query, 10, Some(0.5), "tenant-a");
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
        let svc = EmbeddingService::new(config).unwrap();
        let engine = SearchEngine::new(&svc, &store);

        let query = l2_normalize(vec![1.0, 0.0, 0.0]);
        let results = engine.search_by_vector(&query, 5, None, "tenant-a");
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_by_vector_filters_other_tenants() {
        let store = VectorStore::new(3, 1000, 900);
        store.add("tenant-a".into(), l2_normalize(vec![1.0, 0.0, 0.0]), serde_json::json!({"tenant_id":"tenant-a"})).unwrap();
        store.add("tenant-b".into(), l2_normalize(vec![1.0, 0.0, 0.0]), serde_json::json!({"tenant_id":"tenant-b"})).unwrap();

        let config = crate::config::InferenceConfig {
            url: "http://localhost:8080".into(),
            model: "test".into(),
            dimension: 3,
            max_concurrency: 4,
            timeout_ms: 5000,
            pooling: crate::config::PoolingStrategy::Mean,
        };
        let svc = EmbeddingService::new(config).unwrap();
        let engine = SearchEngine::new(&svc, &store);

        let query = l2_normalize(vec![1.0, 0.0, 0.0]);
        let results = engine.search_by_vector(&query, 10, None, "tenant-a");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].text, "tenant-a");
    }
}
