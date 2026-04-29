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
use parking_lot::Mutex;
use std::time::{Duration, Instant};
use std::sync::Arc;
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
};

// ── Shared application state ─────────────────────────────────────

struct RateLimitWindow {
    started_at: Instant,
    count: usize,
}

struct RequestRateLimiter {
    window: Mutex<RateLimitWindow>,
    max_requests: usize,
    interval: Duration,
}

impl RequestRateLimiter {
    fn new(max_requests: usize, interval: Duration) -> Self {
        Self {
            window: Mutex::new(RateLimitWindow {
                started_at: Instant::now(),
                count: 0,
            }),
            max_requests,
            interval,
        }
    }

    fn allow(&self, now: Instant) -> bool {
        let mut window = self.window.lock();
        if now.duration_since(window.started_at) >= self.interval {
            window.started_at = now;
            window.count = 0;
        }

        if window.count >= self.max_requests {
            return false;
        }

        window.count += 1;
        true
    }
}

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
    inference_rate_limiter: RequestRateLimiter,
}

impl AppState {
    pub fn new(config: AiConfig) -> Self {
        let inference_rate_limiter = RequestRateLimiter::new(
            config.inference_rate_limit,
            Duration::from_secs(config.inference_rate_limit_window_secs),
        );
        Self {
            bandits: BanditOptimizer::new(config.bandit_epsilon),
            config,
            analytics: AnalyticsPredictor::new(),
            assistant: AiAssistant::new(),
            content: ContentOptimizer::new(),
            inference: InferenceEngine::new(),
            sto: SendTimeOptimizer::new(),
            training: TrainingManager::new(),
            service_token: std::env::var("INTERNAL_SERVICE_TOKEN").unwrap_or_default(),
            inference_rate_limiter,
        }
    }
}

// ── Request / Response types ─────────────────────────────────────

#[derive(Deserialize)]
pub struct PredictRequest {
    pub model_id: String,
    pub input: serde_json::Value,
}

#[derive(Deserialize)]
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
pub struct OptimizeTimeRequest {
    pub engagement_data: Vec<(u8, u8, f64)>,
}

#[derive(Deserialize)]
pub struct TrainRequest {
    pub model_id: String,
    #[serde(default)]
    pub config: TrainingConfig,
}

#[derive(Deserialize)]
pub struct BanditRewardRequest {
    pub arm_id: String,
    pub reward: f64,
}

#[derive(Deserialize)]
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
    if !state.inference_rate_limiter.allow(Instant::now()) {
        let (status, body) = ApiResponse::<()>::err_with_status(
            StatusCode::TOO_MANY_REQUESTS,
            "inference rate limit exceeded",
        );
        return (status, body).into_response();
    }

    match state.inference.run_prediction(&req.model_id, req.input) {
        Ok(pred) => (StatusCode::OK, ApiResponse::ok(pred)).into_response(),
        Err(e) => {
            let (status, body) = ApiResponse::<()>::err(e.to_string());
            (status, body).into_response()
        }
    }
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
    let job = state.training.start_job(&req.model_id, &req.config);
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
    match state.bandits.record_reward(&req.arm_id, req.reward) {
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
        .route_layer(middleware::from_fn_with_state(state.clone(), require_service_token))
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
    if provided.as_deref().is_some_and(|p| apexmail_lib::timing_safe_compare(p, &state.service_token)) {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

/// Build `AppState` with default config (convenience for tests / quick starts).
pub fn default_app_state() -> Arc<AppState> {
    Arc::new(AppState::new(AiConfig::default()))
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
    async fn test_predict_endpoint_is_rate_limited() {
        let mut state = default_app_state();
        let state_mut = Arc::get_mut(&mut state).expect("exclusive test state");
        state_mut.service_token = "test-key".into();
        state_mut.inference_rate_limiter = RequestRateLimiter::new(1, Duration::from_secs(60));
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

        let first = Request::builder()
            .uri("/predict")
            .method("POST")
            .header("x-api-key", "test-key")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let first_resp = router.clone().oneshot(first).await.unwrap();
        assert_eq!(first_resp.status(), StatusCode::OK);

        let second = Request::builder()
            .uri("/predict")
            .method("POST")
            .header("x-api-key", "test-key")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let second_resp = router.oneshot(second).await.unwrap();
        assert_eq!(second_resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
