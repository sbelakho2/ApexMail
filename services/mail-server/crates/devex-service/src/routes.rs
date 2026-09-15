//! Axum HTTP routes for the DevEx service.
//!
//! Mirrors the Hono routes defined in `apps/devex/src/routes/devex.ts`.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Query, State},
    http::{header::AUTHORIZATION, HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Serialize;
use tower_http::timeout::TimeoutLayer;

use crate::config::DevExConfig;
use crate::onboarding::OnboardingService;
use crate::openapi::OpenApiGenerator;
use crate::sdk_manager::SdkManager;
use crate::versioning::VersionRegistry;
use crate::webhook_tester::WebhookTester;

// ── Shared application state ─────────────────────────────────────────────────

/// Shared state injected into every handler via `State<AppState>`.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<DevExConfig>,
    pub versions: Arc<VersionRegistry>,
    pub sdk_manager: Arc<SdkManager>,
    pub openapi: Arc<OpenApiGenerator>,
    pub onboarding: Arc<OnboardingService>,
    pub webhook_tester: Arc<WebhookTester>,
    pub service_token: String,
}

impl AppState {
    /// Build `AppState` from a `DevExConfig`.
    pub fn from_config(cfg: DevExConfig) -> Result<Self, crate::types::DevExError> {
        let openapi = OpenApiGenerator::new(&cfg.current_api_version, &cfg.api_base_url);
        // O-20.2: Pass all signing secrets for rotation support
        let webhook_tester = WebhookTester::new(cfg.webhook_signing_secrets.clone())?;
        Ok(Self {
            config: Arc::new(cfg),
            versions: Arc::new(VersionRegistry::new()),
            sdk_manager: Arc::new(SdkManager::new()),
            openapi: Arc::new(openapi),
            onboarding: Arc::new(OnboardingService::new()),
            webhook_tester: Arc::new(webhook_tester),
            service_token: std::env::var("INTERNAL_SERVICE_TOKEN").unwrap_or_default(),
        })
    }
}

// ── Router factory ───────────────────────────────────────────────────────────

/// Build the complete axum `Router` for the DevEx service.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/versions", get(handle_versions))
        .route("/sdks", get(handle_sdks))
        .route("/webhooks/test", axum::routing::post(handle_webhook_test))
        .route("/openapi.json", get(handle_openapi))
        .route("/onboarding/checklist", get(handle_onboarding_checklist))
        .route("/health", get(handle_health))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_service_token,
        ))
        .layer(DefaultBodyLimit::max(256 * 1024)) // 256 KB
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .with_state(state)
}

async fn require_service_token(
    State(state): State<AppState>,
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

// ── Handlers ─────────────────────────────────────────────────────────────────

/// GET /versions — list all API versions.
async fn handle_versions(State(state): State<AppState>) -> impl IntoResponse {
    let versions = state.versions.list_versions();
    let current = &state.config.current_api_version;
    Json(serde_json::json!({
        "current": current,
        "versions": versions,
    }))
}

/// GET /sdks — list available SDKs.
async fn handle_sdks(State(state): State<AppState>) -> impl IntoResponse {
    let sdks = state.sdk_manager.list_sdks();
    let items: Vec<serde_json::Value> = sdks
        .iter()
        .map(|s| {
            serde_json::json!({
                "language": s.language,
                "name": s.language.display_name(),
                "package_name": s.package_name,
                "latest_version": s.latest_version,
                "install_command": s.install_command,
                "package_manager": s.language.package_manager(),
            })
        })
        .collect();
    Json(serde_json::json!({ "sdks": items }))
}

/// Request body for POST /webhooks/test.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookTestRequest {
    pub url: String,
    #[serde(default = "default_event_type")]
    pub event_type: String,
}

fn default_event_type() -> String {
    "message.delivered".into()
}

/// POST /webhooks/test — fire a test webhook.
async fn handle_webhook_test(
    State(state): State<AppState>,
    Json(body): Json<WebhookTestRequest>,
) -> impl IntoResponse {
    match state
        .webhook_tester
        .send_test_webhook(&body.url, &body.event_type)
        .await
    {
        Ok(result) => match serde_json::to_value(result) {
            Ok(value) => (StatusCode::OK, Json(value)).into_response(),
            Err(e) => {
                tracing::error!(error = %e, "Failed to serialize webhook test result");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": "failed to serialize response" })),
                )
                    .into_response()
            }
        },
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// GET /openapi.json — return the OpenAPI spec.
async fn handle_openapi(State(state): State<AppState>) -> impl IntoResponse {
    let spec = state.openapi.generate_spec();
    Json(spec)
}

/// GET /onboarding/checklist — return the onboarding checklist.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OnboardingQuery {
    tenant_id: Option<String>,
}

async fn handle_onboarding_checklist(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<OnboardingQuery>,
) -> impl IntoResponse {
    let tenant_id = query.tenant_id.or_else(|| tenant_id_from_headers(&headers));

    let Some(tenant_id) = tenant_id else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "tenant_id is required" })),
        )
            .into_response();
    };

    let checklist = state.onboarding.get_checklist(&tenant_id);
    Json(checklist).into_response()
}

/// Health response.
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

/// GET /health — basic health check.
async fn handle_health() -> impl IntoResponse {
    Json(HealthResponse {
        status: "healthy",
        service: "devex",
    })
}

fn tenant_id_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-apexmail-tenant-id")
        .or_else(|| headers.get("x-tenant-id"))
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_state() -> Result<AppState, crate::types::DevExError> {
        let mut state = AppState::from_config(DevExConfig::default())?;
        state.service_token = "test-key".into();
        Ok(state)
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let state = test_state();
        assert!(state.is_ok());
        let app = if let Ok(state) = state {
            build_router(state)
        } else {
            return;
        };
        let req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "healthy");
        assert_eq!(json["service"], "devex");
    }

    #[tokio::test]
    async fn test_versions_endpoint() {
        let state = test_state();
        assert!(state.is_ok());
        let app = if let Ok(state) = state {
            build_router(state)
        } else {
            return;
        };
        let req = Request::builder()
            .uri("/versions")
            .header("x-api-key", "test-key")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["current"], "2024-01");
        assert!(json["versions"].as_array().unwrap().len() >= 5);
    }

    #[tokio::test]
    async fn test_sdks_endpoint() {
        let state = test_state();
        assert!(state.is_ok());
        let app = if let Ok(state) = state {
            build_router(state)
        } else {
            return;
        };
        let req = Request::builder()
            .uri("/sdks")
            .header("x-api-key", "test-key")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let sdks = json["sdks"].as_array().unwrap();
        assert_eq!(sdks.len(), 5);
    }

    // ── Adversarial: auth matrix, listing surfaces, hostile webhook URL ──

    fn state_with_token(token: &str) -> Result<AppState, crate::types::DevExError> {
        let mut state = AppState::from_config(DevExConfig::default())?;
        state.service_token = token.into();
        Ok(state)
    }

    #[tokio::test]
    async fn auth_matrix_guards_everything_but_health() {
        use tower::ServiceExt;
        let state = state_with_token("test-key").expect("state");
        let app = build_router(state);

        for uri in [
            "/versions",
            "/sdks",
            "/openapi.json",
            "/onboarding/checklist",
        ] {
            let resp = app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }

        // Bearer and x-api-key both work.
        let mut request = Request::builder().uri("/sdks").body(Body::empty()).unwrap();
        request.headers_mut().insert(
            axum::http::header::AUTHORIZATION,
            "Bearer test-key".parse().unwrap(),
        );
        let resp = app.clone().oneshot(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // x-api-key is accepted too; the checklist additionally requires a
        // tenant header, so its absence is a caller error (400), proving the
        // request got PAST auth.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/onboarding/checklist")
                    .header("x-api-key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // An unconfigured token locks everything but /health.
        let locked = build_router(state_with_token("").expect("state"));
        let resp = locked
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = locked
            .oneshot(
                Request::builder()
                    .uri("/sdks")
                    .header("x-api-key", "anything")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn sdks_and_openapi_surfaces_answer_with_real_payloads() {
        use tower::ServiceExt;
        let app = build_router(state_with_token("test-key").expect("state"));

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/sdks")
                    .header("x-api-key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.is_array() || json["sdks"].is_array(), "{json}");

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/openapi.json")
                    .header("x-api-key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["openapi"].is_string() || json["info"].is_object(),
            "{json}"
        );
    }

    #[tokio::test]
    async fn webhook_test_endpoint_refuses_private_targets() {
        use tower::ServiceExt;
        let app = build_router(state_with_token("test-key").expect("state"));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/test")
                    .header("x-api-key", "test-key")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "url": "http://127.0.0.1:9/hook",
                            "event_type": "message.delivered"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["error"].as_str().unwrap().contains("private/internal"),
            "{json}"
        );
    }
}
