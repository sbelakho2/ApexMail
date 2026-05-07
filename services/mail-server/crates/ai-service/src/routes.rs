//! Axum HTTP routes for the AI service.

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, State},
    http::{header::AUTHORIZATION, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tower_http::timeout::TimeoutLayer;

use crate::{
    analytics::AnalyticsPredictor,
    assistant::AiAssistant,
    bandits::BanditOptimizer,
    config::AiConfig,
    content::ContentOptimizer,
    inference::InferenceEngine,
    sto::SendTimeOptimizer,
    training::{TrainingConfig, TrainingManager},
    types::AiError,
};

// ── Shared application state ─────────────────────────────────────

/// Redis-backed rate limiter key prefix for inference requests.
const INFERENCE_RATE_LIMIT_KEY: &str = "ai:inference_rate";

/// Shared state for all route handlers.
pub struct AppState {
    pub config: AiConfig,
    pub analytics: AnalyticsPredictor,
    pub assistant: AiAssistant,
    pub bandits: BanditOptimizer,
    pub content: ContentOptimizer,
    pub inference: InferenceEngine,
    pub sto: SendTimeOptimizer,
    pub training: TrainingManager,
    pub service_token: String,
    /// Optional Redis connection pool for distributed rate limiting (C-08).
    pub redis_pool: Option<deadpool_redis::Pool>,
}

impl AppState {
    pub fn new(config: AiConfig) -> Result<Self, AiError> {
        // O-10.1: Pass encryption key if configured, else None for plaintext
        let enc_key: Option<&str> = if config.bandit_encryption_key.is_empty() {
            None
        } else {
            Some(&config.bandit_encryption_key)
        };
        let bandits = BanditOptimizer::with_state_path(
            config.bandit_epsilon,
            &config.bandit_state_path,
            enc_key,
        )?;

        // Attempt to create a Redis pool for distributed rate limiting.
        // If no URL is configured or connection fails, rate limiting is a no-op.
        let redis_pool = if config.redis_url.is_empty() {
            None
        } else {
            match deadpool_redis::Config::from_url(&config.redis_url)
                .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            {
                Ok(pool) => Some(pool),
                Err(e) => {
                    tracing::warn!(
                        "failed to create Redis pool for rate limiting (C-08): {e}; \
                         inference rate limiting will be disabled"
                    );
                    None
                }
            }
        };

        Ok(Self {
            bandits,
            config,
            analytics: AnalyticsPredictor::new(),
            assistant: AiAssistant::new(),
            content: ContentOptimizer::new(),
            inference: InferenceEngine::new(),
            sto: SendTimeOptimizer::new(),
            training: TrainingManager::new(),
            service_token: std::env::var("INTERNAL_SERVICE_TOKEN").unwrap_or_default(),
            redis_pool,
        })
    }
}

// ── Request / Response types ─────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PredictRequest {
    pub model_id: String,
    pub input: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuggestRequest {
    pub topic: String,
    #[serde(default = "default_tone")]
    pub tone: String,
    #[serde(default = "default_count")]
    pub count: usize,
}

fn default_tone() -> String {
    "friendly".into()
}
fn default_count() -> usize {
    3
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptimizeTimeRequest {
    pub engagement_data: Vec<(u8, u8, f64)>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainRequest {
    pub model_id: String,
    #[serde(default)]
    pub config: TrainingConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BanditRewardRequest {
    pub arm_id: String,
    pub reward: f64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentScoreRequest {
    pub subject: String,
}

#[derive(Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Json<Self> {
        Json(Self {
            success: true,
            data: Some(data),
            error: None,
        })
    }

    pub fn err(msg: impl Into<String>) -> (StatusCode, Json<Self>) {
        Self::err_with_status(StatusCode::INTERNAL_SERVER_ERROR, msg)
    }

    pub fn err_with_status(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<Self>) {
        (
            status,
            Json(Self {
                success: false,
                data: None,
                error: Some(msg.into()),
            }),
        )
    }
}

// ── Handlers ─────────────────────────────────────────────────────

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "service": "ai-service",
    }))
}

async fn predict_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PredictRequest>,
) -> impl IntoResponse {
    // C-08: Distributed rate limiting via Redis.
    // Falls back to allowing the request if Redis is unavailable (no local mutex).
    if let Some(ref pool) = state.redis_pool {
        let max_requests = state.config.inference_rate_limit;
        let window_secs = state.config.inference_rate_limit_window_secs;

        match enforce_redis_rate_limit(pool, max_requests, window_secs).await {
            Ok(true) => { /* within limit — proceed */ }
            Ok(false) => {
                let (status, body) = ApiResponse::<()>::err_with_status(
                    StatusCode::TOO_MANY_REQUESTS,
                    "inference rate limit exceeded",
                );
                return (status, body).into_response();
            }
            Err(_) => {
                // Redis error — allow request rather than degrading open.
                tracing::warn!("Redis rate-limit check failed, allowing request");
            }
        }
    }

    match state.inference.run_prediction(&req.model_id, req.input) {
        Ok(pred) => (StatusCode::OK, ApiResponse::ok(pred)).into_response(),
        Err(e) => {
            let (status, body) = ApiResponse::<()>::err(e.to_string());
            (status, body).into_response()
        }
    }
}

/// Check a Redis-backed fixed-window rate limit using INCR + EXPIRE.
///
/// Returns `Ok(true)` if the request is within the limit,
/// `Ok(false)` if rate-limited, or `Err(())` if Redis is unreachable.
async fn enforce_redis_rate_limit(
    pool: &deadpool_redis::Pool,
    max_requests: usize,
    window_secs: u64,
) -> Result<bool, ()> {
    let mut conn = pool.get().await.map_err(|_| ())?;

    // Fixed window based on current epoch second divided by window size.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let window = now_secs / window_secs;
    let key = format!("{}:{}", INFERENCE_RATE_LIMIT_KEY, window);

    let count: usize = redis::cmd("INCR")
        .arg(&key)
        .query_async(&mut *conn)
        .await
        .map_err(|_| ())?;

    if count == 1 {
        // First request in this window — set TTL (twice the window for safety).
        let _: Result<(), _> = redis::cmd("EXPIRE")
            .arg(&key)
            .arg(window_secs * 2)
            .query_async(&mut *conn)
            .await;
    }

    Ok(count <= max_requests)
}

async fn suggest_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SuggestRequest>,
) -> impl IntoResponse {
    let suggestions = state
        .assistant
        .suggest_subject_lines(&req.topic, &req.tone, req.count);
    ApiResponse::ok(suggestions)
}

async fn optimize_time_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<OptimizeTimeRequest>,
) -> impl IntoResponse {
    match state.sto.find_optimal_time(&req.engagement_data) {
        Some(slot) => (StatusCode::OK, ApiResponse::ok(slot)).into_response(),
        None => {
            let (status, body) = ApiResponse::<()>::err("no engagement data provided");
            (status, body).into_response()
        }
    }
}

async fn list_models_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let models = state.inference.list_models();
    ApiResponse::ok(models)
}

async fn train_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TrainRequest>,
) -> impl IntoResponse {
    let job = state.training.start_job(&req.model_id, &req.config).await;
    (StatusCode::CREATED, ApiResponse::ok(job))
}

async fn bandits_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let stats = state.bandits.get_stats();
    ApiResponse::ok(stats)
}

async fn bandit_reward_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BanditRewardRequest>,
) -> impl IntoResponse {
    match state.bandits.record_reward(&req.arm_id, req.reward).await {
        Ok(()) => (StatusCode::OK, ApiResponse::ok("recorded")).into_response(),
        Err(e) => {
            let (status, body) = ApiResponse::<()>::err(e.to_string());
            (status, body).into_response()
        }
    }
}

async fn content_score_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ContentScoreRequest>,
) -> impl IntoResponse {
    let score = state.content.score_subject_line(&req.subject);
    ApiResponse::ok(serde_json::json!({ "score": score }))
}

// ── Router builder ───────────────────────────────────────────────

/// Build the Axum [`Router`] with shared state.
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/predict", post(predict_handler))
        .route("/suggest", post(suggest_handler))
        .route("/optimize-time", post(optimize_time_handler))
        .route("/models", get(list_models_handler))
        .route("/train", post(train_handler))
        .route("/bandits", get(bandits_handler))
        .route("/bandits/reward", post(bandit_reward_handler))
        .route("/content/score", post(content_score_handler))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_service_token,
        ))
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024)) // 2 MB
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

/// Build `AppState` with default config (convenience for tests / quick starts).
pub fn default_app_state() -> Arc<AppState> {
    #[cfg(test)]
    let mut config = AiConfig::default();
    #[cfg(not(test))]
    let config = AiConfig::default();
    #[cfg(test)]
    {
        config.bandit_state_path = std::env::temp_dir()
            .join(format!(
                "apexmail-ai-bandits-test-{}.json",
                uuid::Uuid::new_v4()
            ))
            .display()
            .to_string();
    }
    Arc::new(AppState::new(config).expect("default ai app state"))
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Model, ModelStatus, ModelType};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt; // for `oneshot`

    fn app() -> Router {
        let mut state = default_app_state();
        Arc::get_mut(&mut state)
            .expect("exclusive test state")
            .service_token = "test-key".into();
        // Register a model so prediction works
        state.inference.register_model(Model {
            id: "m1".into(),
            name: "test".into(),
            version: "1".into(),
            model_type: ModelType::Classification,
            accuracy: 0.9,
            trained_at: chrono::Utc::now(),
            status: ModelStatus::Ready,
        });
        build_router(state)
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let router = app();
        let req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_suggest_endpoint() {
        let router = app();
        let body = serde_json::json!({
            "topic": "email marketing",
            "tone": "urgent",
            "count": 2,
        });
        let req = Request::builder()
            .uri("/suggest")
            .method("POST")
            .header("x-api-key", "test-key")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_content_score_endpoint() {
        let router = app();
        let body = serde_json::json!({ "subject": "🔥 Big sale today!" });
        let req = Request::builder()
            .uri("/content/score")
            .method("POST")
            .header("x-api-key", "test-key")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_predict_endpoint_succeeds_without_redis() {
        // When no Redis pool is configured, the rate limiter is a no-op
        // and all requests should succeed.
        let mut state = default_app_state();
        let state_mut = Arc::get_mut(&mut state).expect("exclusive test state");
        state_mut.service_token = "test-key".into();
        state_mut.inference.register_model(Model {
            id: "m1".into(),
            name: "test".into(),
            version: "1".into(),
            model_type: ModelType::Classification,
            accuracy: 0.9,
            trained_at: chrono::Utc::now(),
            status: ModelStatus::Ready,
        });
        let router = build_router(state);
        let body = serde_json::json!({
            "model_id": "m1",
            "input": {"feature": 42},
        });

        let req = Request::builder()
            .uri("/predict")
            .method("POST")
            .header("x-api-key", "test-key")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
