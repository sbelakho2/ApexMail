//! Authenticated AI service HTTP routes.
//!
//! Deterministic helpers remain available, while model inference and training
//! use an explicitly configured provider and runner. No route fabricates model
//! output or marks a training job complete without a real runner artifact.

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Path, State},
    http::{header::AUTHORIZATION, HeaderMap, Request, StatusCode},
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
    assistant::AiAssistant,
    config::AiConfig,
    content::ContentOptimizer,
    domain_dns::DomainDnsStore,
    inference::{InferenceConfig, LlmClient},
    sto::SendTimeOptimizer,
    training::TrainingManager,
    types::{AiError, Model, ModelStatus, ModelType},
};

/// Shared state for the AI API. All model and training configuration is
/// deployment-controlled; HTTP request bodies cannot select endpoints, keys,
/// runner paths, or artifact paths.
pub struct AppState {
    pub assistant: AiAssistant,
    pub content: ContentOptimizer,
    pub sto: SendTimeOptimizer,
    pub llm: LlmClient,
    pub training: TrainingManager,
    pub domain_dns: Option<DomainDnsStore>,
    pub model_name: String,
    pub model_enabled: bool,
    pub training_enabled: bool,
    pub request_timeout: Duration,
    pub service_token: String,
}

impl AppState {
    pub fn from_config(config: AiConfig, service_token: String) -> Result<Self, String> {
        let inference = InferenceConfig::from_ai_config(&config);
        let model_name = inference.model.clone();
        let model_enabled = inference.enabled;
        let request_timeout = inference.timeout.saturating_add(Duration::from_secs(5));
        let training_enabled = !config.training_runner.trim().is_empty();
        let domain_dns = if config.database_url.trim().is_empty() {
            None
        } else {
            Some(DomainDnsStore::new(
                &config.database_url,
                &config.aws_region,
                Some(&config.email_transport),
            )?)
        };

        Ok(Self {
            assistant: AiAssistant::new(),
            content: ContentOptimizer::new(),
            sto: SendTimeOptimizer::new(),
            llm: LlmClient::new(inference),
            training: TrainingManager::new(&config),
            domain_dns,
            model_name,
            model_enabled,
            training_enabled,
            request_timeout,
            service_token,
        })
    }

    pub fn from_environment() -> Result<Self, String> {
        let config = AiConfig::from_env()?;
        Self::from_config(
            config,
            std::env::var("INTERNAL_SERVICE_TOKEN").unwrap_or_default(),
        )
    }
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
pub struct ContentScoreRequest {
    pub subject: String,
}

/// Structured input supplied to the configured text model. The configured
/// server-side model is the only model allowed by this endpoint.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PredictRequest {
    pub model_id: String,
    pub input: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainRequest {
    pub model_id: String,
    pub epochs: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluateRequest {
    pub predictions: Vec<bool>,
    pub labels: Vec<bool>,
}

/// The tenant assertion is accepted only after the internal-service-token
/// middleware authenticates the upstream control plane. This route is not a
/// public customer authentication boundary; the API server must authorize the
/// caller before forwarding its tenant identity.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainDnsRequest {
    pub domain: String,
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

    pub fn err_with_status(
        status: StatusCode,
        message: impl Into<String>,
    ) -> (StatusCode, Json<Self>) {
        (
            status,
            Json(Self {
                success: false,
                data: None,
                error: Some(message.into()),
            }),
        )
    }
}

fn api_error(error: AiError) -> Response {
    let status =
        StatusCode::from_u16(error.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let (status, response) = ApiResponse::<()>::err_with_status(status, error.to_string());
    (status, response).into_response()
}

async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "service": "ai-service",
        "capabilities": [
            "deterministic_subject_suggestions",
            "engagement_score_selection",
            "subject_scoring",
            "configured_remote_model_inference",
            "governed_offline_training",
        ],
        "model_runtime_enabled": state.model_enabled,
        "configured_model": state.model_enabled.then_some(&state.model_name),
        "training_runner_configured": state.training_enabled,
        "authoritative_domain_dns_available": state.domain_dns.is_some(),
        "note": "Model provider reachability is checked by a real inference request; disabled or unreachable runtimes fail closed.",
    }))
}

async fn suggest_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SuggestRequest>,
) -> Response {
    let topic = request.topic.trim();
    if topic.is_empty() {
        return api_error(AiError::InvalidInput("topic must not be empty".into()));
    }
    if topic.chars().count() > 240 {
        return api_error(AiError::InvalidInput(
            "topic must not exceed 240 characters".into(),
        ));
    }
    if request.count == 0 || request.count > 5 {
        return api_error(AiError::InvalidInput(
            "count must be between 1 and 5".into(),
        ));
    }

    let suggestions =
        state
            .assistant
            .suggest_subject_lines(topic, request.tone.trim(), request.count);
    ApiResponse::ok(serde_json::json!({
        "suggestions": suggestions,
        "method": "deterministic_template_heuristic",
    }))
    .into_response()
}

async fn optimize_time_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<OptimizeTimeRequest>,
) -> Response {
    if request.engagement_data.is_empty() {
        return api_error(AiError::InvalidInput(
            "engagement_data must not be empty".into(),
        ));
    }
    if request.engagement_data.len() > 10_000 {
        return api_error(AiError::InvalidInput(
            "engagement_data must contain at most 10000 entries".into(),
        ));
    }
    if request.engagement_data.iter().any(|(hour, day, score)| {
        *hour > 23 || *day > 6 || !score.is_finite() || !(0.0..=1.0).contains(score)
    }) {
        return api_error(AiError::InvalidInput(
            "each entry must have hour 0..23, day_of_week 0..6, and score 0.0..1.0".into(),
        ));
    }

    match state.sto.find_optimal_time(&request.engagement_data) {
        Some(slot) => ApiResponse::ok(serde_json::json!({
            "slot": slot,
            "method": "highest_supplied_engagement_score",
        }))
        .into_response(),
        None => api_error(AiError::InvalidInput(
            "engagement_data must not be empty".into(),
        )),
    }
}

async fn content_score_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ContentScoreRequest>,
) -> Response {
    let subject = request.subject.trim();
    if subject.is_empty() {
        return api_error(AiError::InvalidInput("subject must not be empty".into()));
    }
    if subject.chars().count() > 240 {
        return api_error(AiError::InvalidInput(
            "subject must not exceed 240 characters".into(),
        ));
    }

    let score = state.content.score_subject_line(subject);
    ApiResponse::ok(serde_json::json!({
        "score": score,
        "method": "deterministic_subject_heuristic",
    }))
    .into_response()
}

async fn list_models_handler(State(state): State<Arc<AppState>>) -> Response {
    let model = Model {
        id: state.model_name.clone(),
        name: state.model_name.clone(),
        version: "deployment-configured".into(),
        model_type: ModelType::GenerativeText,
        accuracy: None,
        trained_at: None,
        status: if state.model_enabled {
            ModelStatus::Ready
        } else {
            ModelStatus::Deprecated
        },
    };

    ApiResponse::ok(serde_json::json!({
        "models": [model],
        "runtime_enabled": state.model_enabled,
        "warning": (!state.model_enabled).then_some("Set AI_MODEL_ENABLED=true and configure a provider before inference can run."),
    }))
    .into_response()
}

async fn predict_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<PredictRequest>,
) -> Response {
    if request.model_id.trim().is_empty() || request.model_id.len() > 128 {
        return api_error(AiError::InvalidInput("invalid model_id".into()));
    }
    if request.input.is_null() {
        return api_error(AiError::InvalidInput("input must not be null".into()));
    }

    match state
        .llm
        .predict(request.model_id.trim(), request.input)
        .await
    {
        Ok(prediction) => ApiResponse::ok(prediction).into_response(),
        Err(error) => api_error(error),
    }
}

async fn train_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<TrainRequest>,
) -> Response {
    if request.model_id.trim() != state.model_name {
        return api_error(AiError::ModelNotFound(request.model_id));
    }
    match state.training.start_job(&state.model_name, request.epochs).await {
        Ok(job) => ApiResponse::ok(serde_json::json!({
            "job": job,
            "promotion": "Training completion does not promote a model. Review the runner's evaluation artifact before release.",
        }))
        .into_response(),
        Err(error) => api_error(error),
    }
}

async fn training_job_handler(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<String>,
) -> Response {
    match state.training.get_job(&job_id) {
        Ok(job) => ApiResponse::ok(job).into_response(),
        Err(error) => api_error(error),
    }
}

async fn evaluation_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<EvaluateRequest>,
) -> Response {
    match state
        .training
        .evaluate(&request.predictions, &request.labels)
    {
        Ok(metrics) => ApiResponse::ok(metrics).into_response(),
        Err(error) => api_error(error),
    }
}

async fn domain_dns_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<DomainDnsRequest>,
) -> Response {
    let tenant_id = match headers
        .get("x-apexmail-tenant-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(tenant_id) => tenant_id,
        None => {
            return api_error(AiError::InvalidInput(
                "x-apexmail-tenant-id is required for an authenticated domain lookup".into(),
            ));
        }
    };
    let store = match &state.domain_dns {
        Some(store) => store,
        None => {
            return api_error(AiError::ModelUnavailable(
                "authoritative domain data is not configured; set AI_DATABASE_URL or DATABASE_URL"
                    .into(),
            ));
        }
    };

    match store.records_for_domain(tenant_id, &request.domain).await {
        Ok(records) => ApiResponse::ok(records).into_response(),
        Err(error) => api_error(error),
    }
}

/// Build the Axum [`Router`] with shared state.
pub fn build_router(state: Arc<AppState>) -> Router {
    let timeout = state.request_timeout;
    Router::new()
        .route("/health", get(health))
        .route("/suggest", post(suggest_handler))
        .route("/optimize-time", post(optimize_time_handler))
        .route("/content/score", post(content_score_handler))
        .route("/models", get(list_models_handler))
        .route("/predict", post(predict_handler))
        .route("/train", post(train_handler))
        .route("/training/jobs/:job_id", get(training_job_handler))
        .route("/evaluate", post(evaluation_handler))
        .route("/domains/dns-records", post(domain_dns_handler))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_service_token,
        ))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(TimeoutLayer::new(timeout))
        .with_state(state)
}

async fn require_service_token(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if request.uri().path() == "/health" {
        return Ok(next.run(request).await);
    }
    if state.service_token.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let provided = request
        .headers()
        .get("x-api-key")
        .and_then(|value| value.to_str().ok().map(String::from))
        .or_else(|| {
            request
                .headers()
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|raw| raw.trim().strip_prefix("Bearer ").map(String::from))
        });

    if provided
        .as_deref()
        .is_some_and(|value| apexmail_lib::timing_safe_compare(value, &state.service_token))
    {
        Ok(next.run(request).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

/// Build application state from deployment configuration.
pub fn default_app_state() -> Result<Arc<AppState>, String> {
    Ok(Arc::new(AppState::from_environment()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn app() -> Router {
        let state = Arc::new(
            AppState::from_config(AiConfig::default(), "test-key".into())
                .expect("valid default configuration"),
        );
        build_router(state)
    }

    fn authenticated_json_request(uri: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .method("POST")
            .header("x-api-key", "test-key")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&body).expect("serialize request"),
            ))
            .expect("build request")
    }

    #[tokio::test]
    async fn health_is_public_and_reports_runtime_readiness() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn helpers_and_model_control_plane_require_service_authentication() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/models")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn subject_suggestions_remain_available_as_heuristics() {
        let response = app()
            .oneshot(authenticated_json_request(
                "/suggest",
                serde_json::json!({"topic":"email marketing", "tone":"urgent", "count":2}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn restored_model_routes_fail_closed_when_not_configured() {
        let response = app()
            .oneshot(authenticated_json_request(
                "/predict",
                serde_json::json!({"model_id":"apexmail-assistant", "input":{"prompt":"Hello"}}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let response = app()
            .oneshot(authenticated_json_request(
                "/train",
                serde_json::json!({"model_id":"apexmail-assistant", "epochs":1}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn evaluation_uses_real_metrics() {
        let response = app()
            .oneshot(authenticated_json_request(
                "/evaluate",
                serde_json::json!({"predictions":[true, false], "labels":[true, false]}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn domain_dns_route_is_registered_and_fails_closed_without_data_source() {
        let mut request = authenticated_json_request(
            "/domains/dns-records",
            serde_json::json!({"domain":"example.com"}),
        );
        request.headers_mut().insert(
            "x-apexmail-tenant-id",
            "00000000-0000-0000-0000-000000000001".parse().unwrap(),
        );
        let response = app().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
