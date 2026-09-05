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
    governor::RateGovernor,
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
    /// Grounded chat (docs retrieval + verifier + escalation). Built from
    /// the same inference config as `llm`.
    pub chat: crate::chat::ChatService,
    /// Docs corpus pool (None when AI_DATABASE_URL/DATABASE_URL unset —
    /// chat then fails closed to escalation).
    pub docs_pool: Option<sqlx::PgPool>,
    pub training: TrainingManager,
    pub domain_dns: Option<DomainDnsStore>,
    pub model_name: String,
    pub model_enabled: bool,
    pub training_enabled: bool,
    pub request_timeout: Duration,
    pub service_token: String,
    /// Enforces `inference_rate_limit` per `inference_rate_limit_window_secs`
    /// for model-inference routes, keyed by the authenticated tenant identity.
    pub rate_governor: RateGovernor,
}

impl AppState {
    pub async fn from_config(config: AiConfig, service_token: String) -> Result<Self, String> {
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

        // Docs corpus pool for grounded chat + the indexer. Reuses the same
        // DATABASE_URL as DomainDnsStore; small pool (indexing + point reads).
        let docs_pool = if config.database_url.trim().is_empty() {
            None
        } else {
            match sqlx::postgres::PgPoolOptions::new()
                .max_connections(4)
                .acquire_timeout(std::time::Duration::from_secs(8))
                .connect(&config.database_url)
                .await
            {
                Ok(pool) => Some(pool),
                Err(e) => {
                    tracing::warn!(error = %e, "ai-service: docs pool unavailable; grounded chat will fail closed");
                    None
                }
            }
        };
        let chat = crate::chat::ChatService::new(&config, docs_pool.clone());

        Ok(Self {
            assistant: AiAssistant::new(),
            content: ContentOptimizer::new(),
            sto: SendTimeOptimizer::new(),
            chat,
            docs_pool,
            llm: LlmClient::new(inference),
            training: TrainingManager::new(&config),
            domain_dns,
            model_name,
            model_enabled,
            training_enabled,
            request_timeout,
            service_token,
            rate_governor: RateGovernor::new(
                config.inference_rate_limit,
                Duration::from_secs(config.inference_rate_limit_window_secs),
            ),
        })
    }

    pub async fn from_environment() -> Result<Self, String> {
        let config = AiConfig::from_env()?;
        Self::from_config(
            config,
            std::env::var("INTERNAL_SERVICE_TOKEN").unwrap_or_default(),
        )
        .await
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
            "grounded_chat",
            "docs_reindex",
        ],
        "model_runtime_enabled": state.model_enabled,
        "configured_model": state.model_enabled.then_some(&state.model_name),
        "training_runner_configured": state.training_enabled,
        "authoritative_domain_dns_available": state.domain_dns.is_some(),
        "grounded_chat_docs_available": state.docs_pool.is_some(),
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

/// Maximum length accepted for a forwarded `x-apexmail-tenant-id` value used
/// as an inference rate-limit key.
const MAX_TENANT_RATE_KEY_LEN: usize = 64;

/// Rate-limit bucket used when no tenant identity is forwarded at all — i.e.
/// genuinely tenant-less internal calls from the authenticated control plane
/// (batch jobs, health probes). A header that is PRESENT but invalid is
/// rejected instead of landing here (see [`tenant_rate_key_from_headers`]).
const CONTROL_PLANE_RATE_KEY: &str = "_control-plane";

/// Resolve the inference rate-limit key for a request.
///
/// Auth-context note: `require_service_token` authenticates the upstream
/// control plane with ONE shared internal service token and exposes no
/// per-caller identity — nothing about the tenant is bound to the token.
/// The tenant identity therefore arrives only via the `x-apexmail-tenant-id`
/// header the control plane forwards after its own authorization, so the key
/// must at least be bounded: length and charset are validated (UUID/ULID
/// shapes pass) so a caller cannot mint arbitrary or oversized rate-limit
/// identities. A present-but-invalid header is a 400; an absent (or blank)
/// header falls back to [`CONTROL_PLANE_RATE_KEY`].
fn tenant_rate_key_from_headers(headers: &HeaderMap) -> Result<String, &'static str> {
    // Absent header → the documented control-plane fallback. A PRESENT
    // header that cannot even be read as UTF-8 text is a rejection: treating
    // it as absent would let opaque bytes masquerade as tenant-less calls.
    let Some(value) = headers.get("x-apexmail-tenant-id") else {
        return Ok(CONTROL_PLANE_RATE_KEY.to_string());
    };
    let raw = value
        .to_str()
        .map_err(|_| "must be valid UTF-8 header text")?
        .trim();
    if raw.is_empty() {
        return Ok(CONTROL_PLANE_RATE_KEY.to_string());
    }
    if raw.len() > MAX_TENANT_RATE_KEY_LEN {
        return Err("must be at most 64 characters");
    }
    if !raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
    {
        return Err("only [A-Za-z0-9._:-] are allowed");
    }
    Ok(raw.to_string())
}

async fn predict_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<PredictRequest>,
) -> Response {
    if request.model_id.trim().is_empty() || request.model_id.len() > 128 {
        return api_error(AiError::InvalidInput("invalid model_id".into()));
    }
    if request.input.is_null() {
        return api_error(AiError::InvalidInput("input must not be null".into()));
    }

    // Enforce the configured inference rate limit per tenant. The upstream
    // control plane is authenticated by the service-token middleware (which
    // carries no per-caller identity — see `tenant_rate_key_from_headers`);
    // the tenant header is accepted only in validated, bounded form, and the
    // `_control-plane` fallback applies only when it is absent.
    let rate_key = match tenant_rate_key_from_headers(&headers) {
        Ok(key) => key,
        Err(reason) => {
            return api_error(AiError::InvalidInput(format!(
                "invalid x-apexmail-tenant-id header: {reason}"
            )));
        }
    };
    if !state.rate_governor.allow(&rate_key) {
        return api_error(AiError::RateLimited(format!(
            "inference rate limit of {} requests per {}s exceeded; retry later",
            state.rate_governor.limit(),
            state.rate_governor.window().as_secs()
        )));
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

// ── Grounded chat ─────────────────────────────────────────────────────────

/// POST /chat — called by the authenticated control plane (api-server) with
/// the END USER's tenant/user identity. This service never authenticates the
/// end user itself; the token-authenticated caller asserts identity, and the
/// caller assembles the account context from its own tenant-scoped queries.
async fn chat_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<crate::chat::ChatRequest>,
) -> Response {
    // Per-tenant rate limit, mirroring /predict. The caller forwards the
    // end user's tenant via the header; a malformed header is rejected.
    let tenant = match tenant_rate_key_from_headers(&headers) {
        Ok(key) => key,
        Err(reason) => {
            return error_response_json(
                StatusCode::BAD_REQUEST,
                &format!("invalid x-apexmail-tenant-id: {reason}"),
            )
        }
    };
    // The header is set by the trusted gateway AFTER it authorized that
    // tenant; the body tenant is caller-supplied. When both are present
    // they must agree — otherwise the request would bill/limit one tenant
    // while executing (and potentially leaking) as another.
    if tenant != CONTROL_PLANE_RATE_KEY && tenant != req.tenant_id {
        tracing::warn!(
            header_tenant = %tenant,
            "chat request tenant mismatch between x-apexmail-tenant-id and body tenant_id"
        );
        return error_response_json(
            StatusCode::FORBIDDEN,
            "tenant identity mismatch between x-apexmail-tenant-id and tenant_id",
        );
    }
    if !state.rate_governor.allow(&tenant) {
        return error_response_json(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
    }
    if req.message.trim().is_empty() {
        return error_response_json(StatusCode::BAD_REQUEST, "message must not be empty");
    }
    if req.tenant_id.trim().is_empty() || req.user_id.trim().is_empty() {
        return error_response_json(
            StatusCode::BAD_REQUEST,
            "tenant_id and user_id are required",
        );
    }

    match state.chat.chat(&req).await {
        Ok((resp, audit)) => {
            state.chat.persist_audit(&audit).await;
            Json(resp).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "chat handler failed");
            error_response_json(
                StatusCode::SERVICE_UNAVAILABLE,
                "assistant unavailable; escalate to support@apexmail.ee",
            )
        }
    }
}

/// POST /admin/reindex — rebuild the docs index from AI_DOCS_DIR. Safe to
/// call repeatedly (idempotent upsert; prunes superseded versions).
async fn reindex_handler(State(state): State<Arc<AppState>>) -> Response {
    let Some(pool) = &state.docs_pool else {
        return error_response_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "docs database not configured (AI_DATABASE_URL)",
        );
    };
    let dir = crate::retrieval::docs_dir();
    match crate::retrieval::reindex(pool, &dir).await {
        Ok(count) => Json(serde_json::json!({
            "indexed_chunks": count,
            "docs_version": crate::retrieval::docs_version(&dir),
        }))
        .into_response(),
        Err(e) => error_response_json(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

/// POST /admin/chat/history — a tenant's chat audit rows (newest first),
/// tenant-scoped by REQUIREMENT (never defaults to the control-plane bucket).
async fn chat_history_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let Some(pool) = &state.docs_pool else {
        return error_response_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "docs database not configured",
        );
    };
    let Some(tenant) = body.get("tenant_id").and_then(|v| v.as_str()) else {
        return error_response_json(StatusCode::BAD_REQUEST, "tenant_id is required");
    };
    let limit = body
        .get("limit")
        .and_then(|v| v.as_i64())
        .unwrap_or(50)
        .clamp(1, 200);
    match sqlx::query_as::<_, (String, String, String, String, bool, chrono::DateTime<chrono::Utc>)>(
        "SELECT role, content, docs_version, user_id, escalated, created_at          FROM ai_chat_messages WHERE tenant_id = $1          ORDER BY created_at DESC LIMIT $2",
    )
    .bind(tenant)
    .bind(limit)
    .fetch_all(pool)
    .await
    {
        Ok(rows) => Json(serde_json::json!({
            "tenant_id": tenant,
            "messages": rows.iter().map(|(role, content, dv, user, esc, ts)| serde_json::json!({
                "role": role, "content": content, "user_id": user,
                "escalated": esc, "docs_version": dv, "created_at": ts.to_rfc3339(),
            })).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(e) => error_response_json(StatusCode::INTERNAL_SERVER_ERROR, &format!("history query failed: {e}")),
    }
}

fn error_response_json(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
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
        .route("/chat", post(chat_handler))
        .route("/admin/reindex", post(reindex_handler))
        .route("/admin/chat/history", post(chat_history_handler))
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
pub async fn default_app_state() -> Result<Arc<AppState>, String> {
    Ok(Arc::new(AppState::from_environment().await?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn app() -> Router {
        let state = Arc::new(
            AppState::from_config(AiConfig::default(), "test-key".into())
                .await
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
            .await
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
            .await
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
            .await
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
            .await
            .oneshot(authenticated_json_request(
                "/predict",
                serde_json::json!({"model_id":"apexmail-assistant", "input":{"prompt":"Hello"}}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let response = app()
            .await
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
            .await
            .oneshot(authenticated_json_request(
                "/evaluate",
                serde_json::json!({"predictions":[true, false], "labels":[true, false]}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn predict_enforces_the_configured_inference_rate_limit() {
        // Default config: 60 requests / 60s window. Requests 1..=60 hit the
        // (disabled) runtime and fail closed with 503; request 61 is the
        // N+1 rapid call and must be rejected with 429 before inference.
        let app = app().await;
        for _ in 0..60 {
            let response = app
                .clone()
                .oneshot(authenticated_json_request(
                    "/predict",
                    serde_json::json!({"model_id":"apexmail-assistant", "input":{"prompt":"Hello"}}),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
        let response = app
            .oneshot(authenticated_json_request(
                "/predict",
                serde_json::json!({"model_id":"apexmail-assistant", "input":{"prompt":"Hello"}}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
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
        let response = app().await.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    fn authenticated_chat_request(tenant_header: Option<&str>, body_tenant: &str) -> Request<Body> {
        let mut builder = Request::builder()
            .uri("/chat")
            .method("POST")
            .header("x-api-key", "test-key")
            .header("content-type", "application/json");
        if let Some(tenant) = tenant_header {
            builder = builder.header("x-apexmail-tenant-id", tenant);
        }
        builder
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "tenant_id": body_tenant,
                    "user_id": "user-1",
                    "message": "What does the Pro plan cost?",
                    "history": []
                }))
                .expect("serialize request"),
            ))
            .expect("build request")
    }

    /// The gateway-set tenant header and the body tenant must agree when
    /// both are present: without the cross-check, a caller could bill one
    /// tenant's rate bucket while executing as another.
    #[tokio::test]
    async fn chat_rejects_tenant_header_body_mismatch() {
        let app = app().await;
        let response = app
            .clone()
            .oneshot(authenticated_chat_request(
                Some("00000000-0000-0000-0000-000000000001"),
                "99999999-9999-9999-9999-999999999999",
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "mismatched identity must be rejected"
        );

        // Matching identities proceed (escalation answer: no model runtime
        // in tests) — and the absent header keeps the control-plane bucket.
        let response = app
            .clone()
            .oneshot(authenticated_chat_request(
                Some("00000000-0000-0000-0000-000000000001"),
                "00000000-0000-0000-0000-000000000001",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = app
            .oneshot(authenticated_chat_request(None, "99999999-9999-9999-9999-999999999999"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn tenant_rate_key_validator_direct_cases() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            tenant_rate_key_from_headers(&headers).unwrap(),
            "_control-plane"
        );
        headers.insert(
            "x-apexmail-tenant-id",
            "00000000-0000-0000-0000-000000000001".parse().unwrap(),
        );
        assert_eq!(
            tenant_rate_key_from_headers(&headers).unwrap(),
            "00000000-0000-0000-0000-000000000001"
        );
        // Raw non-ASCII bytes in the header (HeaderValue allows them).
        headers.insert(
            "x-apexmail-tenant-id",
            axum::http::HeaderValue::from_bytes(b"ten\xC3\xA9nt").unwrap(),
        );
        let res = tenant_rate_key_from_headers(&headers);
        assert!(res.is_err(), "non-ASCII must be rejected, got {res:?}");
    }

    fn authenticated_predict_with_tenant(tenant: &str) -> Request<Body> {
        Request::builder()
            .uri("/predict")
            .method("POST")
            .header("x-api-key", "test-key")
            .header("x-apexmail-tenant-id", tenant)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "model_id": "apexmail-assistant",
                    "input": {"prompt": "Hello"}
                }))
                .expect("serialize request"),
            ))
            .expect("build request")
    }

    /// Malformed / oversized tenant headers must never become rate-limit
    /// identities — they are rejected with 400 before the governor sees them.
    #[tokio::test]
    async fn predict_rejects_malformed_tenant_rate_key_headers() {
        let app = app().await;
        let bad_headers: [String; 4] = [
            "bad tenant!".into(),                    // illegal characters
            "tenant/../../etc".into(),               // path-ish junk
            "ten\u{00e9}nt".into(),                  // non-ASCII
            "x".repeat(MAX_TENANT_RATE_KEY_LEN + 1), // oversized
        ];
        for bad in bad_headers {
            let response = app
                .clone()
                .oneshot(authenticated_predict_with_tenant(&bad))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "tenant header {:?} must be rejected, not bucketed",
                if bad.len() > 80 {
                    format!("{}…", &bad[..80])
                } else {
                    bad.clone()
                }
            );
        }
    }

    /// Validated keys bucket correctly (isolated per tenant) and the absent
    /// header still falls back to the shared `_control-plane` bucket.
    #[tokio::test]
    async fn predict_rate_limit_buckets_by_validated_tenant_key() {
        let app = app().await;
        let body = serde_json::json!({"model_id":"apexmail-assistant", "input":{"prompt":"Hello"}});

        // Exhaust tenant-b's bucket (limit 60/window 60s): every allowed
        // request still returns 503 (runtime disabled), the 61st is 429.
        for _ in 0..60 {
            let response = app
                .clone()
                .oneshot(authenticated_predict_with_tenant(
                    "01J8XQ7VT9HZZK3WB2GDYB6XYZ",
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
        let response = app
            .clone()
            .oneshot(authenticated_predict_with_tenant(
                "01J8XQ7VT9HZZK3WB2GDYB6XYZ",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        // A different valid tenant has its own, untouched bucket.
        let response = app
            .clone()
            .oneshot(authenticated_predict_with_tenant(
                "00000000-0000-0000-0000-000000000001",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        // Absent header → the documented `_control-plane` fallback bucket,
        // also untouched by tenant-b's exhaustion.
        let response = app
            .clone()
            .oneshot(authenticated_json_request("/predict", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
