//! Request logging middleware that adds `X-Request-ID`, normalizes JSON
//! error envelopes, and logs method, path, status, and duration.

use axum::body::{to_bytes, Body};
use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use serde::Serialize;
use std::time::Instant;
use uuid::Uuid;

#[derive(Debug, Serialize)]
struct ErrorEnvelope {
    error: NormalizedErrorDetail,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NormalizedErrorDetail {
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<Vec<String>>,
    request_id: String,
}

fn default_error_code(status: StatusCode) -> &'static str {
    match status {
        StatusCode::BAD_REQUEST => "BAD_REQUEST",
        StatusCode::UNAUTHORIZED => "UNAUTHORIZED",
        StatusCode::FORBIDDEN => "FORBIDDEN",
        StatusCode::NOT_FOUND => "NOT_FOUND",
        StatusCode::CONFLICT => "CONFLICT",
        StatusCode::PAYLOAD_TOO_LARGE => "PAYLOAD_TOO_LARGE",
        StatusCode::REQUEST_TIMEOUT => "REQUEST_TIMEOUT",
        StatusCode::TOO_MANY_REQUESTS => "RATE_LIMIT_EXCEEDED",
        StatusCode::SERVICE_UNAVAILABLE => "SERVICE_UNAVAILABLE",
        _ => "INTERNAL_ERROR",
    }
}

fn extract_details(value: Option<&serde_json::Value>) -> Option<Vec<String>> {
    value
        .and_then(|details| details.as_array())
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .filter(|entries| !entries.is_empty())
}

fn normalize_error_payload(
    status: StatusCode,
    payload: &serde_json::Value,
    request_id: &str,
) -> Option<serde_json::Value> {
    let (code, message, details) = match payload {
        serde_json::Value::Object(root) => match root.get("error") {
            Some(serde_json::Value::String(message)) => (
                root.get("code")
                    .and_then(|value| value.as_str())
                    .unwrap_or(default_error_code(status))
                    .to_string(),
                message.clone(),
                extract_details(root.get("details")),
            ),
            Some(serde_json::Value::Object(error)) => (
                error
                    .get("code")
                    .and_then(|value| value.as_str())
                    .or_else(|| root.get("code").and_then(|value| value.as_str()))
                    .unwrap_or(default_error_code(status))
                    .to_string(),
                error
                    .get("message")
                    .and_then(|value| value.as_str())
                    .or_else(|| root.get("message").and_then(|value| value.as_str()))
                    .unwrap_or_else(|| status.canonical_reason().unwrap_or("request failed"))
                    .to_string(),
                extract_details(error.get("details"))
                    .or_else(|| extract_details(root.get("details"))),
            ),
            _ => {
                let message = root
                    .get("message")
                    .and_then(|value| value.as_str())
                    .map(String::from)?;
                (
                    root.get("code")
                        .and_then(|value| value.as_str())
                        .unwrap_or(default_error_code(status))
                        .to_string(),
                    message,
                    extract_details(root.get("details")),
                )
            }
        },
        serde_json::Value::String(message) => (
            default_error_code(status).to_string(),
            message.clone(),
            None,
        ),
        _ => return None,
    };

    serde_json::to_value(ErrorEnvelope {
        error: NormalizedErrorDetail {
            code,
            message,
            details,
            request_id: request_id.to_string(),
        },
    })
    .ok()
}

async fn normalize_error_response(response: Response, request_id: &str) -> Response {
    let status = response.status();
    if !status.is_client_error() && !status.is_server_error() {
        return response;
    }

    let is_json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));
    if !is_json {
        return response;
    }

    let (mut parts, body) = response.into_parts();
    let body_bytes = match to_bytes(body, 64 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(request_id = %request_id, error = %error, "Failed to buffer error response body");
            let fallback = serde_json::to_vec(&ErrorEnvelope {
                error: NormalizedErrorDetail {
                    code: default_error_code(status).to_string(),
                    message: status
                        .canonical_reason()
                        .unwrap_or("request failed")
                        .to_string(),
                    details: None,
                    request_id: request_id.to_string(),
                },
            })
            .unwrap_or_else(|_| br#"{"error":{"code":"INTERNAL_ERROR","message":"request failed","requestId":"unknown"}}"#.to_vec());
            parts.headers.remove(header::CONTENT_LENGTH);
            return Response::from_parts(parts, Body::from(fallback));
        }
    };

    let payload: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(request_id = %request_id, error = %error, "Failed to parse JSON error response body");
            return Response::from_parts(parts, Body::from(body_bytes));
        }
    };

    let Some(normalized) = normalize_error_payload(status, &payload, request_id) else {
        return Response::from_parts(parts, Body::from(body_bytes));
    };

    let normalized_bytes = match serde_json::to_vec(&normalized) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(request_id = %request_id, error = %error, "Failed to serialize normalized error response body");
            return Response::from_parts(parts, Body::from(body_bytes));
        }
    };

    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(normalized_bytes))
}

/// Axum middleware:injects `X-Request-ID` and logs the request lifecycle.
pub async fn request_logger(mut req: Request, next: Next) -> Response {
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
    let response = next.run(req).await;
    let duration = start.elapsed();

    let mut response = normalize_error_response(response, &request_id).await;

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
    use axum::body::to_bytes;
    use axum::response::IntoResponse;
    use axum::Json;
    use http::StatusCode as HttpStatus;

    async fn response_json(resp: Response) -> serde_json::Value {
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

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

    #[tokio::test]
    async fn normalizes_legacy_string_error_responses() {
        let response = (
            HttpStatus::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Operation failed" })),
        )
            .into_response();

        let response = normalize_error_response(response, "req_123").await;
        let json = response_json(response).await;

        assert_eq!(json["error"]["code"], "BAD_REQUEST");
        assert_eq!(json["error"]["message"], "Operation failed");
        assert_eq!(json["error"]["requestId"], "req_123");
    }

    #[tokio::test]
    async fn preserves_standardized_error_details_and_adds_request_id() {
        let response = (
            HttpStatus::BAD_REQUEST,
            Json(serde_json::json!({
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "validation failed",
                    "details": ["email is required"]
                }
            })),
        )
            .into_response();

        let response = normalize_error_response(response, "req_456").await;
        let json = response_json(response).await;

        assert_eq!(json["error"]["code"], "VALIDATION_ERROR");
        assert_eq!(json["error"]["message"], "validation failed");
        assert_eq!(json["error"]["details"][0], "email is required");
        assert_eq!(json["error"]["requestId"], "req_456");
    }
}
