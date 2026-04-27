//! Axum routes for the PDF renderer service.
//!
//! Routes://! - `POST /v1/pdf/render` — render template → PDF bytes (streaming)
//! - `POST /v1/pdf/render/json` — render template → JSON with base64 PDF
//! - `GET /health` — health check

use std::time::Duration;

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Json, State},
    http::{header, header::AUTHORIZATION, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use serde_json::json;
use std::sync::Arc;
use tower_http::timeout::TimeoutLayer;
use tracing::{error, info};

use crate::compiler::{self, RenderError, RenderRequest, RenderResponse};

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

struct ServiceAuth {
    service_token: String,
}

async fn require_service_token(
    State(state): State<Arc<ServiceAuth>>,
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

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the PDF renderer Axum router.
pub fn pdf_router(service_token: String) -> Router {
    let auth = Arc::new(ServiceAuth { service_token });
    Router::new()
        .route("/health", get(health))
        .route("/v1/pdf/render", post(render_pdf_stream))
        .route("/v1/pdf/render/json", post(render_pdf_json))
        .route_layer(middleware::from_fn_with_state(auth, require_service_token))
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024)) // 2 MB
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Health check — returns 200 OK with template count.
async fn health() -> impl IntoResponse {
    let template_count = crate::world::TEMPLATES.len();
    Json(json!({
        "status": "healthy",
        "service": "pdf-renderer",
        "templates": template_count,
    }))
}

/// Render a PDF and stream it as `application/pdf`.
/// Request body:
/// ```json
/// { "template":"invoice", "data":{ ... } }
/// ```
/// Response: raw PDF bytes with `Content-Type: application/pdf`.
async fn render_pdf_stream(Json(req): Json<RenderRequest>) -> Result<Response, PdfApiError> {
    info!(template = %req.template, "PDF render request (stream)");

    let pdf_bytes = compiler::render_pdf(&req.template, &req.data)
        .map_err(PdfApiError::Render)?;

    let filename = format!("{}-{}.pdf", req.template, chrono::Utc::now().format("%Y%m%d"));

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/pdf"),
            (
                header::CONTENT_DISPOSITION,
                &format!("attachment; filename=\"{filename}\""),
            ),
            (header::CACHE_CONTROL, "no-store"),
        ],
        pdf_bytes,
    )
        .into_response())
}

/// Render a PDF and return it as base64-encoded JSON.
/// Useful for clients that can't handle binary responses directly.
async fn render_pdf_json(Json(req): Json<RenderRequest>) -> Result<Json<RenderResponse>, PdfApiError> {
    info!(template = %req.template, "PDF render request (JSON)");

    let pdf_bytes = compiler::render_pdf(&req.template, &req.data)
        .map_err(PdfApiError::Render)?;

    use base64::Engine;
    let pdf_base64 = base64::engine::general_purpose::STANDARD.encode(&pdf_bytes);

    Ok(Json(RenderResponse {
        pdf_base64: Some(pdf_base64),
        size: pdf_bytes.len(),
        template: req.template,
    }))
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum PdfApiError {
    Render(RenderError),
}

impl IntoResponse for PdfApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            PdfApiError::Render(RenderError::World(e)) => {
                (StatusCode::NOT_FOUND, format!("Template error: {e}"))
            }
            PdfApiError::Render(e) => {
                error!(error = %e, "PDF render failed");
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Render error: {e}"))
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_route_skips_service_auth() {
        let app = pdf_router(String::new());

        let response = app
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn render_route_requires_service_token() {
        let app = pdf_router("super-secret".into());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/pdf/render")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"template":"invoice","data":{}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
