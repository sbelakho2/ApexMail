//! Accept-Header-based API versioning middleware.
//!
//! In addition to URL-path versioning (`/v1/`), this middleware allows callers to
//! specify an API version via the `Accept` header using the media type parameter
//! `version`:
//!
//! ```http
//! Accept: application/json; version=1
//! ```
//!
//! When the version is present and does not match the current major API version,
//! the middleware returns a `406 Not Acceptable` response with a clear error
//! message listing the supported versions.
//!
//! # Migration strategy
//!
//! This is a **soft-negotiation** layer: the URL path remains the canonical
//! routing mechanism. The Accept header acts as a secondary check so that
//! API clients can opt in to a specific version and receive early feedback
//! when that version is deprecated.
//!
//! When a new major version is introduced (e.g. `/v2/`), update `CURRENT_VERSION`
//! and add deprecation warnings for the old version.

use axum::extract::Request;
use axum::http::header::ACCEPT;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// The current major API version supported by this server.
const CURRENT_VERSION: &str = "1";

/// Additional past versions that are still accepted (deprecated but not removed).
const SUPPORTED_VERSIONS: &[&str] = &["1"];

/// Axum middleware that inspects the `Accept` header for a `version` media-type
/// parameter and rejects requests targeting an unsupported API version.
///
/// The check is **opt-in**: if no version parameter is present the request
/// proceeds as normal (backward compatible). When a version IS specified it
/// must match one of the supported versions.
pub async fn api_versioning_middleware(
    req: Request,
    next: Next,
) -> Response {
    // Extract version from Accept header: application/json; version=1
    if let Some(requested_version) = extract_version_from_accept(req.headers()) {
        if !SUPPORTED_VERSIONS.contains(&requested_version.as_str()) {
            tracing::warn!(
                requested_version = %requested_version,
                current_version = CURRENT_VERSION,
                "Unsupported API version in Accept header"
            );
            return (
                StatusCode::NOT_ACCEPTABLE,
                axum::Json(serde_json::json!({
                    "error": {
                        "code": "UNSUPPORTED_API_VERSION",
                        "message": format!(
                            "API version '{}' is not supported. Current version: {}",
                            requested_version, CURRENT_VERSION
                        ),
                        "supported_versions": SUPPORTED_VERSIONS,
                    }
                })),
            )
                .into_response();
        }
    }

    next.run(req).await
}

/// Extract the API version from the `Accept` header, if present.
///
/// Looks for a `version` media-type parameter:
/// - `application/json; version=1` → Some("1")
/// - `application/json` → None
/// - `application/json; version=abc` → None (invalid)
fn extract_version_from_accept(headers: &axum::http::HeaderMap) -> Option<String> {
    let accept_value = headers.get(ACCEPT)?.to_str().ok()?;

    // Parse media-type parameters using a simple scanner
    for part in accept_value.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("version=") {
            let v = value.trim().to_string();
            // Must be a positive integer
            if v.parse::<u64>().is_ok() {
                return Some(v);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::HeaderValue;
    use axum::http::Request;

    #[tokio::test]
    async fn no_version_header_passes() {
        let req = Request::builder()
            .uri("/v1/messages")
            .body(Body::empty())
            .unwrap();
        let resp = api_versioning_middleware(req, next_ok()).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn valid_version_passes() {
        let req = Request::builder()
            .uri("/v1/messages")
            .header(ACCEPT, "application/json; version=1")
            .body(Body::empty())
            .unwrap();
        let resp = api_versioning_middleware(req, next_ok()).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn invalid_version_rejected() {
        let req = Request::builder()
            .uri("/v1/messages")
            .header(ACCEPT, "application/json; version=2")
            .body(Body::empty())
            .unwrap();
        let resp = api_versioning_middleware(req, next_ok()).await;
        assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE);

        let body = resp.into_body();
        let bytes = axum::body::to_bytes(body, 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["code"], "UNSUPPORTED_API_VERSION");
    }

    #[tokio::test]
    async fn malformed_version_ignored() {
        let req = Request::builder()
            .uri("/v1/messages")
            .header(ACCEPT, "application/json; version=abc")
            .body(Body::empty())
            .unwrap();
        let resp = api_versioning_middleware(req, next_ok()).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    fn test_extract_version_from_accept() {
        let mut headers = axum::http::HeaderMap::new();
        assert_eq!(extract_version_from_accept(&headers), None);

        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        assert_eq!(extract_version_from_accept(&headers), None);

        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json; version=1"),
        );
        assert_eq!(extract_version_from_accept(&headers), Some("1".to_string()));

        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json; version=abc"),
        );
        assert_eq!(extract_version_from_accept(&headers), None);
    }

    /// Helper that returns a 200 OK response for the next middleware.
    async fn next_ok() -> axum::response::Response {
        axum::http::Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap()
    }
}
