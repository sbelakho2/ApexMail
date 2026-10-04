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

use crate::auth::ServiceAuth;
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
    /// P1 #6: per-workload credentials — the dedicated `DEVEX_AUTH_TOKEN`
    /// is the only accepted secret when configured; the universal token is
    /// legacy fallback (non-production).
    pub service_auth: ServiceAuth,
}

impl AppState {
    /// Build `AppState` from a `DevExConfig`.
    ///
    /// P1 #6: the per-workload credential is resolved from the environment
    /// LENIENTLY here (no production refusal) so config-driven construction
    /// never fails on auth grounds; the binary enforces the production boot
    /// refusal via `ServiceAuth::from_env()` — which yields the identical
    /// resolution — before serving traffic.
    pub fn from_config(cfg: DevExConfig) -> Result<Self, crate::types::DevExError> {
        let openapi = OpenApiGenerator::new(&cfg.current_api_version, &cfg.api_base_url);
        // O-20.2: Pass all signing secrets for rotation support
        let webhook_tester = WebhookTester::new(cfg.webhook_signing_secrets.clone())?;
        let dedicated = std::env::var(crate::auth::DEDICATED_TOKEN_ENV).ok();
        let universal = std::env::var("INTERNAL_SERVICE_TOKEN").ok();
        let service_auth = ServiceAuth::resolve(dedicated.as_deref(), universal.as_deref(), false)
            .map_err(crate::types::DevExError::Validation)?;
        Ok(Self {
            config: Arc::new(cfg),
            versions: Arc::new(VersionRegistry::new()),
            sdk_manager: Arc::new(SdkManager::new()),
            openapi: Arc::new(openapi),
            onboarding: Arc::new(OnboardingService::new()),
            webhook_tester: Arc::new(webhook_tester),
            service_auth,
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
    let provided = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok().map(String::from))
        .or_else(|| {
            req.headers()
                .get(AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|raw| raw.trim().strip_prefix("Bearer ").map(String::from))
        })
        .unwrap_or_default();
    if state.service_auth.authorize(&provided) {
        return Ok(next.run(req).await);
    }
    // P1 #6: a configured dedicated token means the universal
    // INTERNAL_SERVICE_TOKEN no longer authorizes anything here — call out
    // unmigrated callers loudly (they get 401 either way).
    if state.service_auth.is_refused_universal_attempt(&provided) {
        tracing::warn!(
            "request refused: the universal INTERNAL_SERVICE_TOKEN was presented but \
             DEVEX_AUTH_TOKEN is configured — the caller must migrate to the dedicated \
             per-workload token"
        );
    }
    Err(StatusCode::UNAUTHORIZED)
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
            // coverage: justified — the Ok arm needs a completed webhook
            // round-trip to a PUBLIC host (send_test_webhook resolves DNS and
            // performs a live HTTP POST); offline CI can only reach the
            // validated-refusal arm below.
            Ok(value) => (StatusCode::OK, Json(value)).into_response(),
            Err(e) => {
                // coverage: justified — WebhookTestResult derives Serialize
                // over plain fields, so to_value is infallible; the arm
                // guards future field types only.
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
        // P1 #6: tests install the resolved per-workload `ServiceAuth`
        // (single accepted token) instead of the bare `service_token` field.
        state.service_auth = crate::auth::ServiceAuth::resolve(Some("test-key"), None, false)
            .expect("test auth resolves");
        Ok(state)
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let state = test_state();
        assert!(state.is_ok());
        let app = if let Ok(state) = state {
            build_router(state)
        } else {
            // coverage: justified — defensive early-return; from_config
            // cannot fail in this environment (default signing secrets,
            // lenient auth), so the else arm is unreachable.
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
            // coverage: justified — defensive early-return (see
            // test_health_endpoint).
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
            // coverage: justified — defensive early-return (see
            // test_health_endpoint).
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
        // P1 #6: the resolved per-workload `ServiceAuth` replaces the bare
        // `service_token` field. An EMPTY token resolves to the deny-all
        // auth (nothing accepted), matching the old empty-string behavior.
        state.service_auth =
            crate::auth::ServiceAuth::resolve((!token.is_empty()).then_some(token), None, false)
                .expect("test auth resolves");
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

    // ── P1 #6: per-workload token semantics over HTTP ────────────────────

    /// When `DEVEX_AUTH_TOKEN` is configured it is the ONLY accepted
    /// credential; the universal `INTERNAL_SERVICE_TOKEN` gets 401.
    #[tokio::test]
    async fn dedicated_token_authorizes_and_universal_token_is_refused() {
        let mut state = AppState::from_config(DevExConfig::default()).expect("state");
        state.service_auth = crate::auth::ServiceAuth::resolve(
            Some("dedicated-secret"),
            Some("universal-legacy"),
            false,
        )
        .expect("dedicated auth resolves");
        let app = build_router(state);
        let probe = |app: Router, key: &'static str| async move {
            let mut builder = Request::builder().uri("/sdks");
            if !key.is_empty() {
                builder = builder.header("x-api-key", key);
            }
            app.oneshot(builder.body(Body::empty()).unwrap())
                .await
                .unwrap()
        };

        let resp = probe(app.clone(), "dedicated-secret").await;
        assert_eq!(resp.status(), StatusCode::OK, "dedicated token passes");
        let resp = probe(app.clone(), "universal-legacy").await;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "the universal token must be refused once the dedicated one is set"
        );
        let resp = probe(app, "").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Legacy fallback (dedicated env unset): the universal token still
    /// authenticates outside production — migration-safe behavior.
    #[tokio::test]
    async fn unset_dedicated_token_keeps_universal_token_working() {
        let mut state = AppState::from_config(DevExConfig::default()).expect("state");
        state.service_auth =
            crate::auth::ServiceAuth::resolve(None, Some("universal-legacy"), false)
                .expect("legacy auth resolves");
        let app = build_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/sdks")
                    .header("x-api-key", "universal-legacy")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "legacy token still works");
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

    /// Omitting `event_type` falls back to the documented default (the serde
    /// default function runs), and `/onboarding/checklist` with a tenant
    /// serves the checklist (200) instead of the missing-tenant 400.
    #[tokio::test]
    async fn webhook_default_event_type_and_onboarding_with_tenant() {
        use tower::ServiceExt;
        let app = build_router(state_with_token("test-key").expect("state"));

        // No `event_type` field: `default_event_type` supplies
        // "message.delivered"; the request still fails offline on the
        // private-target refusal, proving the body parsed with the default.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/test")
                    .header("x-api-key", "test-key")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "url": "http://127.0.0.1:9/hook" }).to_string(),
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
            "the default event type parsed and reached the SSRF guard: {json}"
        );

        // An explicit tenant id (query param) serves the checklist.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/onboarding/checklist?tenant_id=t_123")
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
        assert_eq!(
            json["tenant_id"], "t_123",
            "the checklist names the tenant: {json}"
        );
        let items = json["items"]
            .as_array()
            .expect("checklist items array: {json}");
        assert!(!items.is_empty(), "the checklist carries items: {json}");
        assert!(json["progress_pct"].is_number(), "{json}");

        // The tenant may also arrive via header instead of query param.
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/onboarding/checklist")
                    .header("x-api-key", "test-key")
                    .header("x-apexmail-tenant-id", "t_header")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "header tenant resolves too");
    }
}
