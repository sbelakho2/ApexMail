//! Request logging middleware that adds `X-Request-ID` and logs
//! method, path, status, and duration.

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use std::time::Instant;
use uuid::Uuid;

/// Axum middleware:injects `X-Request-ID` and logs the request lifecycle.
pub async fn request_logger(
    mut req: Request,
    next: Next,
) -> Response {
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| Uuid::new_v4().to_string());

// Attach to extensions so downstream handlers can read it.
    req.extensions_mut().insert(RequestId(request_id.clone()));

    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let start = Instant::now();
    let mut response = next.run(req).await;
    let duration = start.elapsed();

    let status = response.status().as_u16();

    tracing::info!(
        request_id = %request_id,
        method = %method,
        path = %path,
        status = status,
        duration_ms = duration.as_millis() as u64,
        "request completed"
    );

// Set X-Request-ID on response
    if let Ok(val) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", val);
    }

    response
}

/// Newtype so handlers can extract the request ID from extensions.
#[derive(Debug, Clone)]
pub struct RequestId(pub String);

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_id_newtype() {
        let id = RequestId("req_abc123".into());
        assert_eq!(id.0, "req_abc123");
    }

    #[test]
    fn test_uuid_generation_is_unique() {
        let a = Uuid::new_v4().to_string();
        let b = Uuid::new_v4().to_string();
        assert_ne!(a, b);
    }
}
