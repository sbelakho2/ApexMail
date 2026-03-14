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

use crate::config::RendererConfig;
use crate::plaintext::html_to_plaintext;
use crate::sandbox::Sandbox;
use crate::transpiler;
use crate::types::{
    RenderMetadata, RenderOptions, RenderResult, TemplateError, STARTER_TEMPLATE,
};
use crate::cache::TemplateCache;

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
    if provided.as_deref().map_or(false, |p| apexmail_lib::timing_safe_compare(p, &state.service_token)) {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

// ─── Request / Response types ──────────────────────────────────

#[derive(Deserialize)]
struct RenderRequest {
    source: String,
    #[serde(default)]
    props: serde_json::Value,
    #[serde(default = "default_true")]
    generate_plaintext: bool,
    #[serde(default)]
    minify: bool,
    subject: Option<String>,
}

fn default_true() -> bool { true }

#[derive(Deserialize)]
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
    };

    match state.sandbox.execute(&req.source, &opts) {
        Ok(result) => {
            let plaintext = if opts.generate_plaintext {
                Some(html_to_plaintext(&result.html))
            } else {
                None
            };

            let subject = opts
                .subject
                .as_ref()
                .map(|s| transpiler::resolve_placeholders(s, &opts.props));

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
    let result = transpiler::validate_source(
        &req.source,
        state.config.sandbox.max_source_length,
    );
    (StatusCode::OK, Json(serde_json::to_value(&result).unwrap_or_else(|e| {
        serde_json::json!({"error": "serialization_failed", "message": e.to_string()})
    })))
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
            },
            sandbox: SandboxConfig {
                timeout_ms: 5000,
                max_memory_bytes: 64 * 1024 * 1024,
                max_source_length: 512 * 1024,
                max_output_length: 2 * 1024 * 1024,
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
        let err = TemplateError::SourceTooLarge { size: 1000, max: 100 };
        assert_eq!(err.code().to_string(), "SOURCE_TOO_LARGE");

        let err = TemplateError::Timeout { ms: 5000 };
        assert_eq!(err.code().to_string(), "SANDBOX_TIMEOUT");

        let err = TemplateError::ForbiddenModule { module: "fs".into() };
        assert_eq!(err.code().to_string(), "FORBIDDEN_MODULE");
    }
}
