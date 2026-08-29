//! HTTP routes for the AI embeddings service.

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Json, State},
    http::{header::AUTHORIZATION, Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tower_http::timeout::TimeoutLayer;

use crate::config::EmbeddingsConfig;
use crate::embeddings::EmbeddingService;
use crate::vector_store::VectorStore;

pub struct AppState {
    pub embedding_service: EmbeddingService,
    pub vector_store: VectorStore,
    pub config: EmbeddingsConfig,
    pub service_token: String,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/embed", post(embed_handler))
        .route("/vectors", post(add_vector_handler))
        .route("/search", post(search_handler))
        .route("/stats", get(stats_handler))
        .route("/health", get(health_handler))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_service_token,
        ))
        .layer(DefaultBodyLimit::max(5 * 1024 * 1024)) // 5 MB — embedding batches / vectors
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .with_state(state)
}

async fn require_service_token(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if req.uri().path() == "/health" {
        return Ok(next.run(req).await);
    }
    if state.service_token.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let provided = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok().map(String::from))
        .or_else(|| {
            req.headers()
                .get(AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|raw| raw.trim().strip_prefix("Bearer ").map(String::from))
        });
    if provided
        .as_deref()
        .is_some_and(|p| apexmail_lib::timing_safe_compare(p, &state.service_token))
    {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

// ─── Request / Response types ──────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmbedRequest {
    texts: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddVectorRequest {
    text: String,
    vector: Vec<f32>,
    tenant_id: String,
    #[serde(default)]
    metadata: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchRequest {
    vector: Vec<f32>,
    tenant_id: String,
    #[serde(default = "default_top_k")]
    top_k: usize,
    min_score: Option<f64>,
}

fn default_top_k() -> usize {
    10
}

/// F11:top_k must be 1..=100. Unbounded top_k cloned the whole-corpus
/// min-heap per search request (a trivially triggerable memory/CPU spike);
/// values outside the range are rejected with 400.
const MAX_TOP_K: usize = 100;

/// F11:validate a requested top_k (1..=100 inclusive).
fn validate_top_k(top_k: usize) -> Result<(), &'static str> {
    if top_k == 0 {
        Err("top_k must be at least 1")
    } else if top_k > MAX_TOP_K {
        Err("top_k must be at most 100")
    } else {
        Ok(())
    }
}

/// Maximum number of texts accepted per /embed batch. Unbounded batches let
/// a single request monopolize the inference sidecar.
const MAX_EMBED_BATCH: usize = 256;

/// Maximum characters per embedded text. Longer inputs are rejected rather
/// than silently truncated so callers notice.
const MAX_EMBED_TEXT_CHARS: usize = 8_192;

// ─── Handlers ──────────────────────────────────────────────────

async fn embed_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EmbedRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if req.texts.len() > MAX_EMBED_BATCH {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("texts batch of {} exceeds the maximum of {} entries", req.texts.len(), MAX_EMBED_BATCH)
            })),
        );
    }
    if let Some(len) = req.texts.iter().map(|t| t.chars().count()).max() {
        if len > MAX_EMBED_TEXT_CHARS {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("text of {len} chars exceeds the maximum of {MAX_EMBED_TEXT_CHARS} chars per entry")
                })),
            );
        }
    }
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
    let mut metadata = match req.metadata {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    metadata.insert("tenant_id".into(), req.tenant_id.into());

    match state
        .vector_store
        .add(req.text, req.vector, serde_json::Value::Object(metadata))
    {
        Ok(id) => (StatusCode::CREATED, Json(serde_json::json!({"id": id}))),
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
    // F11:reject out-of-range top_k before touching the heap.
    if let Err(msg) = validate_top_k(req.top_k) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": msg })),
        );
    }
    let mut results = state
        .vector_store
        .search(&req.vector, req.top_k, &req.tenant_id);
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
    match serde_json::to_value(&stats) {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": err.to_string()})),
        ),
    }
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
            server: ServerConfig {
                host: "0.0.0.0".into(),
                port: 9090,
            },
            inference: InferenceConfig {
                url: "http://localhost:8080".into(),
                model: "test".into(),
                dimension: 384,
                max_concurrency: 4,
                timeout_ms: 5000,
                pooling: PoolingStrategy::Mean,
                sidecar_tls_enabled: false,
                sidecar_tls_ca_path: String::new(),
            },
            store: StoreConfig {
                max_vectors: 1000,
                eviction_threshold: 900,
                persistence_hmac_key: String::new(),
            },
        };
        let state = Arc::new(AppState {
            embedding_service: EmbeddingService::new(config.inference.clone()).unwrap(),
            vector_store: VectorStore::new(384, 1000, 900, vec![]),
            config,
            service_token: "test-key".into(),
        });
        let _router = router(state);
    }

    /// F11:top_k is clamped to 1..=100 — 0 and >100 are rejected.
    #[test]
    fn test_validate_top_k_range() {
        assert!(validate_top_k(0).is_err(), "top_k=0 must be rejected");
        assert!(validate_top_k(1).is_ok(), "top_k=1 is the minimum");
        assert!(validate_top_k(10).is_ok());
        assert!(
            validate_top_k(MAX_TOP_K).is_ok(),
            "top_k=100 is the maximum"
        );
        assert!(validate_top_k(101).is_err(), "top_k=101 must be rejected");
        assert!(validate_top_k(usize::MAX).is_err());
        // Error messages guide the caller.
        assert_eq!(validate_top_k(0).unwrap_err(), "top_k must be at least 1");
        assert_eq!(
            validate_top_k(500).unwrap_err(),
            "top_k must be at most 100"
        );
    }

    #[test]
    fn test_search_request_defaults() {
        let json = r#"{"vector": [1.0, 0.0, 0.0], "tenant_id": "tenant-a"}"#;
        let req: SearchRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.top_k, 10);
        assert!(req.min_score.is_none());
        assert_eq!(req.tenant_id, "tenant-a");
    }

    fn test_state() -> Arc<AppState> {
        let config = EmbeddingsConfig {
            server: ServerConfig {
                host: "127.0.0.1".into(),
                port: 9090,
            },
            inference: InferenceConfig {
                url: "http://localhost:8080".into(),
                model: "test".into(),
                dimension: 384,
                max_concurrency: 4,
                timeout_ms: 5000,
                pooling: PoolingStrategy::Mean,
                sidecar_tls_enabled: false,
                sidecar_tls_ca_path: String::new(),
            },
            store: StoreConfig {
                max_vectors: 1000,
                eviction_threshold: 900,
                persistence_hmac_key: String::new(),
            },
        };
        Arc::new(AppState {
            embedding_service: EmbeddingService::new(config.inference.clone()).unwrap(),
            vector_store: VectorStore::new(384, 1000, 900, vec![]),
            config,
            service_token: "test-key".into(),
        })
    }

    async fn embed_response(body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        use tower::ServiceExt;
        let router = router(test_state());
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/embed")
                    .method("POST")
                    .header("x-api-key", "test-key")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test]
    async fn embed_rejects_oversized_batches() {
        let texts: Vec<String> = (0..257).map(|i| format!("text {i}")).collect();
        let (status, body) = embed_response(serde_json::json!({"texts": texts})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"]
            .as_str()
            .unwrap()
            .contains("exceeds the maximum"));
    }

    #[tokio::test]
    async fn embed_rejects_oversized_single_text() {
        let long = "x".repeat(8_193);
        let (status, body) = embed_response(serde_json::json!({"texts": [long]})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().unwrap().contains("chars"));
    }

    #[tokio::test]
    async fn embed_accepts_batch_at_the_cap() {
        // A batch exactly at the cap passes validation and only fails later
        // when the (unreachable) inference sidecar is contacted.
        let texts: Vec<String> = (0..256).map(|i| format!("text {i}")).collect();
        let (status, body) = embed_response(serde_json::json!({"texts": texts})).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body["error"].as_str().is_some());
    }
}
