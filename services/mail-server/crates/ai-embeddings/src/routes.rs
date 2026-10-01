//! HTTP routes for the AI embeddings service.

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Json, State},
    http::{header::AUTHORIZATION, HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tower_http::timeout::TimeoutLayer;

use crate::auth::ServiceAuth;
use crate::config::EmbeddingsConfig;
use crate::embeddings::EmbeddingService;
use crate::vector_store::VectorStore;

/// SM9 #6: the gateway-asserted tenant identity header (the ai-service
/// "P1-SECURITY" convention). The control-plane gateway sets it AFTER its
/// own authorization, so a holder of the shared internal service token can
/// never name an arbitrary tenant in the request body and act as it.
pub const TENANT_HEADER: &str = "x-apexmail-tenant-id";

pub struct AppState {
    pub embedding_service: EmbeddingService,
    pub vector_store: VectorStore,
    pub config: EmbeddingsConfig,
    /// P1 #6: the resolved per-workload credential. The universal
    /// `INTERNAL_SERVICE_TOKEN` authorizes nothing here once the dedicated
    /// `AI_EMBEDDINGS_AUTH_TOKEN` is configured.
    pub service_auth: ServiceAuth,
    /// SM9 #6: DEV-ONLY escape hatch (`AI_EMBEDDINGS_TRUST_BODY_TENANT`).
    /// When `false` (the default), `/vectors` and `/search` require the
    /// gateway-asserted [`TENANT_HEADER`] cross-checked against the body
    /// `tenant_id`. Never enable outside a local, gateway-less dev run.
    pub trust_body_tenant: bool,
}

/// SM9 #6: resolve the tenant scope for `/vectors` and `/search`.
///
/// The gateway-asserted [`TENANT_HEADER`] is REQUIRED: absent (or empty) is
/// a 401 and a mismatch with the body `tenant_id` is a 403 — both fail
/// closed. `trust_body_tenant` (the `AI_EMBEDDINGS_TRUST_BODY_TENANT`
/// escape hatch) restores the old body-trusting behavior for local,
/// gateway-less dev runs only.
fn resolve_tenant_scope(
    headers: &HeaderMap,
    body_tenant: &str,
    trust_body_tenant: bool,
) -> Result<(), (StatusCode, String)> {
    if trust_body_tenant {
        return Ok(());
    }
    let asserted = headers
        .get(TENANT_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                format!(
                    "missing required {TENANT_HEADER} header: the gateway must assert the \
                     authenticated tenant identity (AI_EMBEDDINGS_TRUST_BODY_TENANT is the \
                     dev-only escape hatch)"
                ),
            )
        })?;
    if asserted != body_tenant.trim() {
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "{TENANT_HEADER} ({asserted}) does not match the body tenant_id \
                 ({body_tenant}) — refusing a cross-tenant scope"
            ),
        ));
    }
    Ok(())
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
    let provided = provided.as_deref().unwrap_or("");
    // INTERNAL_SERVICE_TOKEN no longer authorizes anything here — call out
    // the unmigrated caller loudly (it is refused either way).
    if state.service_auth.is_refused_universal_attempt(provided) {
        tracing::warn!(
            "request refused: the universal INTERNAL_SERVICE_TOKEN was presented but \
             AI_EMBEDDINGS_AUTH_TOKEN is configured — migrate this caller to the \
             dedicated per-workload token"
        );
    }
    if state.service_auth.authorize(provided) {
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
    headers: HeaderMap,
    Json(req): Json<AddVectorRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    // SM9 #6: the caller's tenant scope is gateway-asserted, not just
    // body-asserted — fail closed on absence/mismatch.
    if let Err((status, msg)) =
        resolve_tenant_scope(&headers, &req.tenant_id, state.trust_body_tenant)
    {
        return (status, Json(serde_json::json!({ "error": msg })));
    }
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
    headers: HeaderMap,
    Json(req): Json<SearchRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    // SM9 #6: identity before capability — the tenant scope is validated
    // before any search work happens.
    if let Err((status, msg)) =
        resolve_tenant_scope(&headers, &req.tenant_id, state.trust_body_tenant)
    {
        return (status, Json(serde_json::json!({ "error": msg })));
    }
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
        Err(err) => {
            // coverage: justified — StoreStats derives Serialize over plain
            // numeric fields, so to_value is infallible; the arm guards
            // future field types only.
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": err.to_string()})),
            )
        }
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
            // P1 #6: tests build the resolved per-workload `ServiceAuth` — a
            // single credential, the universal token refuses.
            service_auth: crate::auth::ServiceAuth::resolve(Some("test-key"), None, false)
                .expect("test auth resolves"),
            // SM9 #6: gateway tenant assertion is ON by default.
            trust_body_tenant: false,
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
            // P1 #6: the resolved per-workload `ServiceAuth` replaces the bare
            // token string.
            service_auth: crate::auth::ServiceAuth::resolve(Some("test-key"), None, false)
                .expect("test auth resolves"),
            // SM9 #6: gateway tenant assertion is ON by default.
            trust_body_tenant: false,
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

    // ── Adversarial: auth ordering + vector/search handler contracts ────

    fn auth_request(method: &str, uri: &str, token: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            builder = builder.header("x-api-key", token);
        }
        builder.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn health_is_public_but_everything_else_requires_the_token() {
        use tower::ServiceExt;
        let app = router(test_state());
        let response = app
            .clone()
            .oneshot(auth_request("GET", "/health", None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // No token → 401; wrong token → 401; bearer token → 200.
        for token in [None, Some("wrong")] {
            let response = app
                .clone()
                .oneshot(auth_request("GET", "/stats", token))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{token:?}");
        }
        let mut request = auth_request("GET", "/stats", None);
        request.headers_mut().insert(
            axum::http::header::AUTHORIZATION,
            "Bearer test-key".parse().unwrap(),
        );
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // An empty configured token locks everything but /health.
        let template = test_state();
        let empty_token_state = Arc::new(AppState {
            embedding_service: EmbeddingService::new(template.config.inference.clone())
                .expect("service"),
            vector_store: VectorStore::new(384, 1000, 900, vec![]),
            config: template.config.clone(),
            service_auth: crate::auth::ServiceAuth::resolve(None, None, false)
                .expect("deny-all auth resolves"),
            trust_body_tenant: false,
        });
        let locked = router(empty_token_state);
        let response = locked
            .clone()
            .oneshot(auth_request("GET", "/health", None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = locked
            .oneshot(auth_request("GET", "/stats", Some("anything")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // ── P1 #6: per-workload token semantics over HTTP ────────────────────

    /// When `AI_EMBEDDINGS_AUTH_TOKEN` is configured it is the ONLY accepted
    /// credential; the universal `INTERNAL_SERVICE_TOKEN` gets 401.
    #[tokio::test]
    async fn dedicated_token_authorizes_and_universal_token_is_refused() {
        use tower::ServiceExt;
        let template = test_state();
        let auth = crate::auth::ServiceAuth::resolve(
            Some("dedicated-secret"),
            Some("universal-legacy"),
            false,
        )
        .expect("dedicated auth resolves");
        let state = Arc::new(AppState {
            embedding_service: EmbeddingService::new(template.config.inference.clone())
                .expect("service"),
            vector_store: VectorStore::new(384, 1000, 900, vec![]),
            config: template.config.clone(),
            service_auth: auth,
            trust_body_tenant: false,
        });
        let app = router(state);
        let probe = |app: axum::Router, key: &'static str| {
            let app = app.clone();
            async move {
                let mut builder = Request::builder().method("GET").uri("/stats");
                if !key.is_empty() {
                    builder = builder.header("x-api-key", key);
                }
                app.oneshot(builder.body(Body::empty()).unwrap())
                    .await
                    .unwrap()
                    .status()
            }
        };

        assert_eq!(
            probe(app.clone(), "dedicated-secret").await,
            StatusCode::OK,
            "dedicated token passes"
        );
        assert_eq!(
            probe(app.clone(), "universal-legacy").await,
            StatusCode::UNAUTHORIZED,
            "the universal token must be refused once the dedicated one is set"
        );
        assert_eq!(probe(app, "").await, StatusCode::UNAUTHORIZED);
    }

    /// Legacy fallback (dedicated env unset): the universal token still
    /// authenticates outside production — migration-safe behavior.
    #[tokio::test]
    async fn unset_dedicated_token_keeps_universal_token_working() {
        use tower::ServiceExt;
        let template = test_state();
        let auth = crate::auth::ServiceAuth::resolve(None, Some("universal-legacy"), false)
            .expect("legacy auth resolves");
        let state = Arc::new(AppState {
            embedding_service: EmbeddingService::new(template.config.inference.clone())
                .expect("service"),
            vector_store: VectorStore::new(384, 1000, 900, vec![]),
            config: template.config.clone(),
            service_auth: auth,
            trust_body_tenant: false,
        });
        let app = router(state);
        let response = app
            .oneshot(auth_request("GET", "/stats", Some("universal-legacy")))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "legacy token still works"
        );
    }

    #[tokio::test]
    async fn add_and_search_handlers_enforce_dimension_and_top_k() {
        use tower::ServiceExt;
        let state = test_state();
        let app = router(state.clone());

        // The state's store dimension (384) shapes the valid payloads.
        let mut unit = vec![0.0f32; 384];
        unit[0] = 1.0;

        // Dimension mismatch is a 400 from the store validation.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/vectors")
                    .header("x-api-key", "test-key")
                    .header(TENANT_HEADER, "tenant-a")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "text": "short",
                            "vector": [1.0, 0.0],
                            "tenant_id": "tenant-a"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // A valid vector is created (201) with the tenant scope attached.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/vectors")
                    .header("x-api-key", "test-key")
                    .header(TENANT_HEADER, "tenant-a")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "text": "valid",
                            "vector": unit.clone(),
                            "tenant_id": "tenant-a",
                            "metadata": {"source": "test"}
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(state.vector_store.len(), 1);

        // top_k=0 and top_k=101 are refused before searching.
        for top_k in [0usize, 101] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/search")
                        .header("x-api-key", "test-key")
                        .header(TENANT_HEADER, "tenant-a")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::json!({
                                "vector": unit.clone(),
                                "tenant_id": "tenant-a",
                                "top_k": top_k
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "top_k={top_k}");
        }

        // A valid search returns the tenant's row; a foreign tenant sees none.
        let search = |tenant: &'static str| {
            let app = app.clone();
            let unit = unit.clone();
            async move {
                app.oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/search")
                        .header("x-api-key", "test-key")
                        .header(TENANT_HEADER, tenant)
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::json!({
                                "vector": unit,
                                "tenant_id": tenant,
                                "top_k": 5,
                                "min_score": 0.9
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap()
            }
        };
        let response = search("tenant-a").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["count"], 1);
        assert_eq!(json["results"][0]["text"], "valid");

        let response = search("tenant-b").await;
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["count"], 0, "cross-tenant search must be empty");
    }

    /// An EMPTY batch short-circuits the `max()` length guard (the
    /// `if let` falls through) and the inference sidecar is never contacted:
    /// the handler answers 200 with zero embeddings. A `/search` WITHOUT
    /// `min_score` skips the retain filter entirely.
    #[tokio::test]
    async fn empty_embed_batch_succeeds_and_min_score_is_optional() {
        use tower::ServiceExt;
        let state = test_state();
        let app = router(state.clone());

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/embed")
                    .header("x-api-key", "test-key")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::json!({ "texts": [] }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "an empty batch is legal");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["embeddings"].as_array().unwrap().len(), 0, "{json}");
        assert_eq!(json["count"], 0, "{json}");
        assert_eq!(
            json["dimension"], 384,
            "the service reports its configured dimension"
        );

        // A search with NO min_score answers without the retain filter.
        let mut unit = vec![0.0f32; 384];
        unit[0] = 1.0;
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/search")
                    .header("x-api-key", "test-key")
                    .header(TENANT_HEADER, "tenant-a")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "vector": unit,
                            "tenant_id": "tenant-a",
                            "top_k": 5
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["count"], 0, "the store is empty in this test: {json}");
        assert_eq!(json["results"].as_array().unwrap().len(), 0, "{json}");
    }

    // ── SM9 #6: gateway-asserted tenant identity on /vectors + /search ──

    /// POST a JSON body to `path` with (optionally) a tenant header.
    async fn post_with_tenant(
        app: axum::Router,
        path: &'static str,
        body: serde_json::Value,
        tenant_header: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        use tower::ServiceExt;
        let mut builder = Request::builder()
            .method("POST")
            .uri(path)
            .header("x-api-key", "test-key")
            .header("content-type", "application/json");
        if let Some(tenant) = tenant_header {
            builder = builder.header(TENANT_HEADER, tenant);
        }
        let response = app
            .oneshot(
                builder
                    .body(Body::from(body.to_string()))
                    .expect("request body"),
            )
            .await
            .expect("response");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    fn search_body(tenant: &str) -> serde_json::Value {
        let mut unit = vec![0.0f32; 384];
        unit[0] = 1.0;
        serde_json::json!({ "vector": unit, "tenant_id": tenant, "top_k": 5 })
    }

    /// SM9 #6: WITHOUT the gateway-asserted header both tenant routes fail
    /// closed with 401 — a holder of the shared service token can no longer
    /// name an arbitrary tenant in the body and act as it.
    #[tokio::test]
    async fn missing_tenant_header_is_unauthorized_on_vectors_and_search() {
        let app = router(test_state());

        let (status, body) = post_with_tenant(
            app.clone(),
            "/vectors",
            serde_json::json!({"text": "t", "vector": vec![0.0f32; 384], "tenant_id": "tenant-a"}),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert!(body["error"].as_str().unwrap().contains(TENANT_HEADER));

        let (status, body) = post_with_tenant(app, "/search", search_body("tenant-a"), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    }

    /// SM9 #6: a header that names a DIFFERENT tenant than the body is a 403.
    #[tokio::test]
    async fn mismatched_tenant_header_is_forbidden() {
        let app = router(test_state());

        let (status, body) = post_with_tenant(
            app.clone(),
            "/vectors",
            serde_json::json!({"text": "t", "vector": vec![0.0f32; 384], "tenant_id": "tenant-a"}),
            Some("tenant-evil"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(body["error"].as_str().unwrap().contains("does not match"));

        let (status, body) =
            post_with_tenant(app, "/search", search_body("tenant-a"), Some("tenant-evil")).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }

    /// SM9 #6: header and body AGREEING authorizes, and the store stays
    /// scoped to the agreed tenant.
    #[tokio::test]
    async fn matching_tenant_header_authorizes_and_stores_scoped() {
        let state = test_state();
        let app = router(state.clone());

        let (status, body) = post_with_tenant(
            app,
            "/vectors",
            serde_json::json!({
                "text": "scoped row",
                "vector": vec![1.0f32; 384],
                "tenant_id": "tenant-a"
            }),
            Some("tenant-a"),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(state.vector_store.len(), 1);
    }

    /// SM9 #6: the `AI_EMBEDDINGS_TRUST_BODY_TENANT` escape hatch (dev-only)
    /// removes the header requirement — that is exactly why it must default
    /// to false and never run outside a local, gateway-less environment.
    #[tokio::test]
    async fn trust_body_tenant_escape_hatch_removes_the_header_requirement() {
        let template = test_state();
        let dev_state = Arc::new(AppState {
            embedding_service: EmbeddingService::new(template.config.inference.clone())
                .expect("service"),
            vector_store: VectorStore::new(384, 1000, 900, vec![]),
            config: template.config.clone(),
            service_auth: crate::auth::ServiceAuth::resolve(Some("test-key"), None, false)
                .expect("test auth resolves"),
            trust_body_tenant: true,
        });
        let app = router(dev_state);

        // No header at all: the body tenant is trusted (dev behavior).
        let mut unit = vec![0.0f32; 384];
        unit[0] = 1.0;
        let (status, body) = post_with_tenant(
            app.clone(),
            "/vectors",
            serde_json::json!({"text": "dev", "vector": unit, "tenant_id": "dev-tenant"}),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");

        let (status, _) = post_with_tenant(app, "/search", search_body("dev-tenant"), None).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// SM9 #6: the scope resolver unit contract — trim-tolerant, empty
    /// header values count as absent, whitespace-only body tenants must
    /// match exactly after trimming.
    #[test]
    fn tenant_scope_resolver_unit_contract() {
        let mut headers = HeaderMap::new();
        // Absent → 401.
        assert_eq!(
            resolve_tenant_scope(&headers, "tenant-a", false)
                .unwrap_err()
                .0,
            StatusCode::UNAUTHORIZED
        );
        // Empty/whitespace header counts as absent → 401.
        headers.insert(TENANT_HEADER, "   ".parse().unwrap());
        assert_eq!(
            resolve_tenant_scope(&headers, "tenant-a", false)
                .unwrap_err()
                .0,
            StatusCode::UNAUTHORIZED
        );
        // Mismatch → 403.
        headers.insert(TENANT_HEADER, "tenant-b".parse().unwrap());
        assert_eq!(
            resolve_tenant_scope(&headers, "tenant-a", false)
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );
        // Agreement (trimmed) → Ok; and the escape hatch skips everything.
        headers.insert(TENANT_HEADER, " tenant-a ".parse().unwrap());
        assert!(resolve_tenant_scope(&headers, "tenant-a ", false).is_ok());
        assert!(resolve_tenant_scope(&HeaderMap::new(), "anything", true).is_ok());
    }
}
