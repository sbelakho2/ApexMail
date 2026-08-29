//! HTTP routes for the template renderer service.

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

use crate::cache::TemplateCache;
use crate::config::RendererConfig;
use crate::plaintext::html_to_plaintext;
use crate::sandbox::Sandbox;
use crate::transpiler;
use crate::types::{RenderMetadata, RenderOptions, RenderResult, TemplateError, STARTER_TEMPLATE};

// ─── App State ─────────────────────────────────────────────────

pub struct AppState {
    pub db: sqlx::PgPool,
    pub sandbox: Sandbox,
    pub cache: TemplateCache,
    pub config: RendererConfig,
    pub service_token: String,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/render", post(render_handler))
        .route("/validate", post(validate_handler))
        .route("/starter", get(starter_handler))
        .route("/health", get(health_handler))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_service_token,
        ))
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024)) // 2 MB
        // HTTP-level cap. The sandbox work itself runs on a blocking thread
        // (see `render_handler`), so this layer can actually fire and release
        // the async worker instead of being stuck behind CPU-bound code.
        .layer(TimeoutLayer::new(Duration::from_secs(
            state.config.server.request_timeout_secs,
        )))
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
struct RenderRequest {
    source: String,
    #[serde(default)]
    props: serde_json::Value,
    #[serde(default = "default_true")]
    generate_plaintext: bool,
    #[serde(default)]
    minify: bool,
    subject: Option<String>,
    /// Fallback substituted for missing merge fields (default: empty string).
    #[serde(default)]
    missing_field_fallback: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidateRequest {
    source: String,
}

// ─── Handlers ──────────────────────────────────────────────────

async fn render_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RenderRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let opts = RenderOptions {
        props: req.props,
        generate_plaintext: req.generate_plaintext,
        minify: req.minify,
        subject: req.subject,
        missing_field_fallback: req.missing_field_fallback.clone(),
    };

    // The sandbox execute is CPU-bound (regex scans, html5ever parse,
    // minify). Running it inline on the async worker starves the runtime:
    // the TimeoutLayer cannot fire while a future is stuck inside a poll,
    // so one slow render used to hang the whole request (and worker) until
    // the sandbox finished. `spawn_blocking` moves it off the worker — the
    // future yields Pending, the 30s HTTP timeout can fire (408), and the
    // worker keeps serving other requests.
    let sandbox = state.sandbox.clone();
    let blocking_source = req.source.clone();
    let blocking_opts = opts.clone();
    let result = match tokio::task::spawn_blocking(move || {
        sandbox.execute(&blocking_source, &blocking_opts)
    })
    .await
    {
        Ok(result) => result,
        Err(join_err) => {
            tracing::error!(error = %join_err, "render blocking task panicked");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "RENDER_TASK_FAILED",
                    "message": "render task failed unexpectedly",
                })),
            );
        }
    };

    match result {
        Ok(result) => {
            let plaintext = if opts.generate_plaintext {
                Some(html_to_plaintext(&result.html))
            } else {
                None
            };

            // Subject-bound resolution also strips CR/LF/NUL (header
            // injection hardening — see the transpiler's subject variant).
            let subject = opts.subject.as_ref().map(|s| {
                transpiler::resolve_placeholders_subject_reported(
                    s,
                    &opts.props,
                    opts.missing_field_fallback.as_deref().unwrap_or(""),
                )
                .html
            });

            let render_result = RenderResult {
                html: result.html.clone(),
                plaintext: plaintext.clone(),
                subject,
                metadata: RenderMetadata {
                    render_time_ms: result.execution_time.as_millis() as u64,
                    html_size_bytes: result.html.len(),
                    plaintext_size_bytes: plaintext.as_ref().map(|p| p.len()),
                    cached: false,
                },
                warnings: result.warnings,
            };

            (
                StatusCode::OK,
                Json(serde_json::to_value(&render_result).unwrap_or_else(|e| {
                    serde_json::json!({"error": "serialization_failed", "message": e.to_string()})
                })),
            )
        }
        Err(e) => {
            let status = match &e {
                TemplateError::SourceTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
                TemplateError::OutputTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
                TemplateError::Timeout { .. } => StatusCode::GATEWAY_TIMEOUT,
                TemplateError::ForbiddenModule { .. } => StatusCode::FORBIDDEN,
                TemplateError::NotFound { .. } => StatusCode::NOT_FOUND,
                _ => StatusCode::BAD_REQUEST,
            };
            (
                status,
                Json(serde_json::json!({
                    "error": e.code().to_string(),
                    "message": e.to_string(),
                })),
            )
        }
    }
}

async fn validate_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ValidateRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let result = transpiler::validate_source(&req.source, state.config.sandbox.max_source_length);
    (
        StatusCode::OK,
        Json(serde_json::to_value(&result).unwrap_or_else(
            |e| serde_json::json!({"error": "serialization_failed", "message": e.to_string()}),
        )),
    )
}

async fn starter_handler() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "template": STARTER_TEMPLATE,
        })),
    )
}

async fn health_handler() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::OK,
        Json(serde_json::json!({ "status": "healthy" })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    fn test_config() -> RendererConfig {
        RendererConfig {
            db: DatabaseConfig {
                url: "postgres://localhost/test".to_string(),
                max_connections: 5,
            },
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 9080,
                request_timeout_secs: 30,
            },
            sandbox: SandboxConfig {
                timeout_ms: 5000,
                max_memory_bytes: 64 * 1024 * 1024,
                max_source_length: 512 * 1024,
                max_output_length: 2 * 1024 * 1024,
                trusted_html_props: Vec::new(),
            },
            cache: CacheConfig {
                max_entries: 100,
                ttl_secs: 60,
            },
        }
    }

    #[tokio::test]
    async fn test_router_creation() {
        // Just verifies router builds without panic
        let config = test_config();
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let state = Arc::new(AppState {
            db: pool,
            sandbox: Sandbox::new(config.sandbox.clone()),
            cache: TemplateCache::new(config.cache.max_entries, config.cache.ttl_secs),
            config,
            service_token: "test-key".into(),
        });
        let _router = router(state);
    }

    #[test]
    fn test_render_request_deserialization() {
        let json = r#"{
            "source": "<p>Hello</p>",
            "props": {"name": "World"},
            "minify": true
        }"#;
        let req: RenderRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.source, "<p>Hello</p>");
        assert!(req.generate_plaintext); // default
        assert!(req.minify);
    }

    #[test]
    fn test_error_status_codes() {
        let err = TemplateError::SourceTooLarge {
            size: 1000,
            max: 100,
        };
        assert_eq!(err.code().to_string(), "SOURCE_TOO_LARGE");

        let err = TemplateError::Timeout { ms: 5000 };
        assert_eq!(err.code().to_string(), "SANDBOX_TIMEOUT");

        let err = TemplateError::ForbiddenModule {
            module: "fs".into(),
        };
        assert_eq!(err.code().to_string(), "FORBIDDEN_MODULE");
    }

    /// A CPU-bound render that outruns the HTTP timeout must produce a 408
    /// (tower-http 0.5 `TimeoutLayer`) instead of hanging the request on a
    /// blocked async worker, and the runtime must stay responsive while the
    /// render is stuck.
    ///
    /// The sandbox's own 60s timeout deliberately cannot fire here (it only
    /// checks between phases), so the only thing that can bound this request
    /// is the HTTP layer — which requires the sandbox work to run off the
    /// async worker (`spawn_blocking`).
    #[tokio::test]
    async fn render_handler_slow_render_times_out_and_runtime_stays_responsive() {
        use tower::ServiceExt;

        let config = RendererConfig {
            db: DatabaseConfig {
                url: "postgres://localhost/test".to_string(),
                max_connections: 5,
            },
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 9080,
                request_timeout_secs: 1,
            },
            sandbox: SandboxConfig {
                timeout_ms: 60_000, // sandbox's own checks must NOT fire first
                max_memory_bytes: 64 * 1024 * 1024,
                max_source_length: 512 * 1024,
                max_output_length: 2 * 1024 * 1024,
                trusted_html_props: Vec::new(),
            },
            cache: CacheConfig {
                max_entries: 100,
                ttl_secs: 60,
            },
        };
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let state = Arc::new(AppState {
            db: pool,
            sandbox: Sandbox::new(config.sandbox.clone()),
            cache: TemplateCache::new(config.cache.max_entries, config.cache.ttl_secs),
            config,
            service_token: "test-key".into(),
        });
        let app = router(state);

        // ~120KB of alternating <pre> regions (12 bytes each): minification's
        // per-region scan is quadratic, so this legitimately burns CPU well
        // past the 1s HTTP cap while staying a perfectly legal template.
        let source = "<pre>a</pre>".repeat(10_000);
        assert!(source.len() < 512 * 1024);

        let body = serde_json::json!({ "source": source, "minify": true });
        let render_req = Request::builder()
            .method("POST")
            .uri("/render")
            .header("x-api-key", "test-key")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let health_req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let (render_outcome, health_outcome) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(5), app.clone().oneshot(render_req)),
            tokio::time::timeout(Duration::from_millis(2_000), app.oneshot(health_req)),
        );

        let health_resp = health_outcome
            .expect("/health must stay responsive while a render is stuck")
            .unwrap(); // Router's error type is Infallible
        assert_eq!(health_resp.status(), StatusCode::OK);

        let resp = render_outcome
            .expect("render request must resolve via the HTTP timeout, not hang")
            .expect("render oneshot must not error");
        assert_eq!(
            resp.status(),
            StatusCode::REQUEST_TIMEOUT,
            "slow render must be cut off by the HTTP timeout layer"
        );
    }
}
