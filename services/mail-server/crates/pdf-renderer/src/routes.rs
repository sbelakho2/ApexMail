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
use crate::world::WorldError;

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
    if provided
        .as_deref()
        .is_some_and(|p| apexmail_lib::timing_safe_compare(p, &state.service_token))
    {
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

/// Reduce a template name to the filename-safe charset `[A-Za-z0-9_-]`
/// (same allowlist as [`crate::world::validate_template_name`]) so the
/// Content-Disposition header can never carry header/path metacharacters.
fn sanitize_filename_component(template: &str) -> String {
    let cleaned: String = template
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if cleaned.is_empty() {
        "document".to_string()
    } else {
        cleaned
    }
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
        .await
        .map_err(PdfApiError::Render)?;

    let filename = format!(
        "{}-{}.pdf",
        sanitize_filename_component(&req.template),
        chrono::Utc::now().format("%Y%m%d")
    );

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
async fn render_pdf_json(
    Json(req): Json<RenderRequest>,
) -> Result<Json<RenderResponse>, PdfApiError> {
    info!(template = %req.template, "PDF render request (JSON)");

    let pdf_bytes = compiler::render_pdf(&req.template, &req.data)
        .await
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
            // Path-shaped/invalid template names are caller errors: 400, and
            // the name is not echoed back into the response.
            PdfApiError::Render(RenderError::World(WorldError::InvalidTemplateName(_))) => {
                (StatusCode::BAD_REQUEST, "invalid template name".to_string())
            }
            PdfApiError::Render(RenderError::World(e)) => {
                (StatusCode::NOT_FOUND, format!("Template error: {e}"))
            }
            PdfApiError::Render(e) => {
                error!(error = %e, "PDF render failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Render error: {e}"),
                )
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

    #[tokio::test]
    async fn render_route_rejects_path_shaped_template_names_with_400() {
        // Regression: `../../`-style names were joined onto
        // PDF_TEMPLATES_DIR and read whatever they resolved to. They must
        // now be rejected as caller errors before any filesystem access.
        let app = pdf_router("super-secret".into());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/pdf/render")
                    .header("x-api-key", "super-secret")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"template":"../../etc/passwd","data":{}}"#.to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // A valid-charset but unknown template stays a 404.
        let app = pdf_router("super-secret".into());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/pdf/render")
                    .header("x-api-key", "super-secret")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"template":"no_such_template","data":{}}"#.to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn filename_component_is_sanitized_to_the_template_charset() {
        // Even a name that somehow slipped through validation can never put
        // metacharacters into Content-Disposition.
        assert_eq!(sanitize_filename_component("invoice"), "invoice");
        assert_eq!(sanitize_filename_component("a../../x"), "ax");
        assert_eq!(sanitize_filename_component("qbr-2026_v2"), "qbr-2026_v2");
        assert_eq!(sanitize_filename_component("///"), "document");
    }

    // ── Adversarial: auth matrix, happy paths, filename sanitizing ──────

    #[tokio::test]
    async fn render_endpoints_stream_and_encode_real_pdfs() {
        let app = pdf_router("super-secret".into());
        let body = serde_json::json!({
            "template": "invoice",
            "data": { "invoice_number": "INV-1", "total": 12400 }
        })
        .to_string();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/pdf/render")
                    .header("x-api-key", "super-secret")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let disposition = response.headers()[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .to_string();
        assert!(disposition.contains("filename=\"invoice-"), "{disposition}");
        assert!(disposition.ends_with(".pdf\""), "{disposition}");
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(bytes.starts_with(b"%PDF-"));

        // Bearer auth works on the JSON endpoint.
        let mut request = Request::builder()
            .method("POST")
            .uri("/v1/pdf/render/json")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();
        request.headers_mut().insert(
            header::AUTHORIZATION,
            "Bearer super-secret".parse().unwrap(),
        );
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            json["pdf_base64"].as_str().unwrap(),
        )
        .unwrap();
        assert!(decoded.starts_with(b"%PDF-"));
        assert_eq!(json["size"].as_u64().unwrap() as usize, decoded.len());
    }

    #[tokio::test]
    async fn unknown_template_is_404_and_empty_token_locks_render() {
        let app = pdf_router("super-secret".into());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/pdf/render/json")
                    .header("x-api-key", "super-secret")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"template":"no-such-template","data":{}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // An unconfigured token rejects every protected route.
        let locked = pdf_router(String::new());
        let response = locked
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/pdf/render")
                    .header("x-api-key", "anything")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"template":"invoice","data":{}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn filename_component_sanitizer_strips_metacharacters() {
        assert_eq!(sanitize_filename_component("invoice"), "invoice");
        assert_eq!(sanitize_filename_component("a-b_c9"), "a-b_c9");
        assert_eq!(sanitize_filename_component("../../etc/passwd"), "etcpasswd");
        assert_eq!(sanitize_filename_component("a\"b\r\nX"), "abX");
        assert_eq!(sanitize_filename_component("..."), "document");
        assert_eq!(sanitize_filename_component(""), "document");
    }
}
