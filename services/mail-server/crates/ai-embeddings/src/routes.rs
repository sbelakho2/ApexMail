//! HTTP routes for the AI embeddings service.

use axum::{
    extract::{Json, State},
    http::StatusCode,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::config::EmbeddingsConfig;
use crate::embeddings::EmbeddingService;
use crate::vector_store::VectorStore;

pub struct AppState {
    pub embedding_service: EmbeddingService,
    pub vector_store: VectorStore,
    pub config: EmbeddingsConfig,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/embed", post(embed_handler))
        .route("/vectors", post(add_vector_handler))
        .route("/search", post(search_handler))
        .route("/stats", get(stats_handler))
        .route("/health", get(health_handler))
        .with_state(state)
}

// ─── Request / Response types ──────────────────────────────────

#[derive(Deserialize)]
struct EmbedRequest {
    texts: Vec<String>,
}

#[derive(Deserialize)]
struct AddVectorRequest {
    text: String,
    vector: Vec<f32>,
    #[serde(default)]
    metadata: serde_json::Value,
}

#[derive(Deserialize)]
struct SearchRequest {
    vector: Vec<f32>,
    #[serde(default = "default_top_k")]
    top_k: usize,
    min_score: Option<f64>,
}

fn default_top_k() -> usize { 10 }

// ─── Handlers ──────────────────────────────────────────────────

async fn embed_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EmbedRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.embedding_service.embed_batch(&req.texts).await {
        Ok(vectors) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "embeddings": vectors,
                "count": vectors.len(),
                "dimension": state.embedding_service.dimension(),
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

async fn add_vector_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddVectorRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.vector_store.add(req.text, req.vector, req.metadata) {
        Ok(id) => (
            StatusCode::CREATED,
            Json(serde_json::json!({"id": id})),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

async fn search_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SearchRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let mut results = state.vector_store.search(&req.vector, req.top_k);
    if let Some(min) = req.min_score {
        results.retain(|r| r.score >= min);
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({"results": results, "count": results.len()})),
    )
}

async fn stats_handler(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let stats = state.vector_store.stats();
    (StatusCode::OK, Json(serde_json::to_value(&stats).unwrap()))
}

async fn health_handler() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "healthy"})),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    #[test]
    fn test_router_creation() {
        let config = EmbeddingsConfig {
            server: ServerConfig { host: "0.0.0.0".into(), port: 9090 },
            inference: InferenceConfig {
                url: "http://localhost:8080".into(),
                model: "test".into(),
                dimension: 384,
                max_concurrency: 4,
                timeout_ms: 5000,
                pooling: PoolingStrategy::Mean,
            },
            store: StoreConfig { max_vectors: 1000, eviction_threshold: 900 },
        };
        let state = Arc::new(AppState {
            embedding_service: EmbeddingService::new(config.inference.clone()),
            vector_store: VectorStore::new(384, 1000, 900),
            config,
        });
        let _router = router(state);
    }

    #[test]
    fn test_search_request_defaults() {
        let json = r#"{"vector": [1.0, 0.0, 0.0]}"#;
        let req: SearchRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.top_k, 10);
        assert!(req.min_score.is_none());
    }
}
