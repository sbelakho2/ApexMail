//! Axum routes for the PDF renderer service.
//!
//! Routes:
//! - `POST /v1/pdf/render` — render template → PDF bytes (streaming)
//! - `POST /v1/pdf/render/json` — render template → JSON with base64 PDF
//! - `GET  /health` — health check

use axum::{
    extract::Json,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use serde_json::json;
use tracing::{error, info};

use crate::compiler::{self, RenderError, RenderRequest, RenderResponse};

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the PDF renderer Axum router.
pub fn pdf_router() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/pdf/render", post(render_pdf_stream))
        .route("/v1/pdf/render/json", post(render_pdf_json))
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
///
/// Request body:
/// ```json
/// { "template": "invoice", "data": { ... } }
/// ```
///
/// Response: raw PDF bytes with `Content-Type: application/pdf`
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
///
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
