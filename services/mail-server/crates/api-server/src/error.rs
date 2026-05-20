//! Unified API response envelope and error type.
//!
//! All API responses follow the standard envelope:
//!
//! **Success:**
//! ```json
//! {"data": {...}, "error": null, "meta": null}
//! ```
//! **Error:**
//! ```json
//! {"data": null, "error": {"code": "NOT_FOUND", "message": "Resource not found", "details": null}, "meta": null}
//! ```

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

// ─── Response envelope ─────────────────────────────────────────

/// Standard API response envelope.
///
/// Every endpoint returns this shape so clients always know where to
/// find data, errors, and metadata.
#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub data: Option<T>,
    pub error: Option<ErrorDetail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

impl<T: Serialize> ApiResponse<T> {
    /// Build a success response with just data.
    pub fn success(data: T) -> Self {
        Self {
            data: Some(data),
            error: None,
            meta: None,
        }
    }

    /// Build a success response with data and metadata (e.g. pagination info).
    pub fn success_with_meta(data: T, meta: serde_json::Value) -> Self {
        Self {
            data: Some(data),
            error: None,
            meta: Some(meta),
        }
    }
}

/// Shorthand helper so handlers can return `success(data)`.
pub fn success<T: Serialize>(data: T) -> Json<ApiResponse<T>> {
    Json(ApiResponse::success(data))
}

/// Shorthand helper returning data + metadata.
pub fn success_with_meta<T: Serialize>(data: T, meta: serde_json::Value) -> Json<ApiResponse<T>> {
    Json(ApiResponse::success_with_meta(data, meta))
}

// ─── Error body ────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub data: Option<serde_json::Value>,
    pub error: Option<ErrorDetail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Vec<String>>,
}

// ─── ApiError enum ─────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),

    #[error("{0}")]
    Unauthorized(String),

    #[error("{0}")]
    Forbidden(String),

    #[error("{0}")]
    NotFound(String),

    #[error("{0}")]
    Conflict(String),

    #[error("rate limit exceeded")]
    RateLimited,

    #[error("{0}")]
    RateLimitedMessage(String),

    #[error("{0}")]
    PayloadTooLarge(String),

    #[error("request timeout")]
    Timeout,

    #[error("{0}")]
    Internal(String),

    #[error("{0}")]
    ServiceUnavailable(String),

    #[error("validation failed")]
    Validation(Vec<String>),
}

impl ApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::RateLimited | Self::RateLimitedMessage(_) => StatusCode::TOO_MANY_REQUESTS,
            Self::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Timeout => StatusCode::REQUEST_TIMEOUT,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Validation(_) => StatusCode::BAD_REQUEST,
        }
    }

    fn code_str(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "BAD_REQUEST",
            Self::Unauthorized(_) => "UNAUTHORIZED",
            Self::Forbidden(_) => "FORBIDDEN",
            Self::NotFound(_) => "NOT_FOUND",
            Self::Conflict(_) => "CONFLICT",
            Self::RateLimited | Self::RateLimitedMessage(_) => "RATE_LIMIT_EXCEEDED",
            Self::PayloadTooLarge(_) => "PAYLOAD_TOO_LARGE",
            Self::Timeout => "REQUEST_TIMEOUT",
            Self::Internal(_) => "INTERNAL_ERROR",
            Self::ServiceUnavailable(_) => "SERVICE_UNAVAILABLE",
            Self::Validation(_) => "VALIDATION_ERROR",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let details = if let Self::Validation(ref v) = self {
            Some(v.clone())
        } else {
            None
        };

        let message = match &self {
            Self::Internal(msg) => {
                tracing::error!(error = %msg, "Internal API error");
                "internal server error".to_string()
            }
            _ => self.to_string(),
        };

        let body = ErrorBody {
            data: None,
            error: Some(ErrorDetail {
                code: self.code_str().to_string(),
                message,
                details,
            }),
            meta: None,
        };

        (status, Json(body)).into_response()
    }
}

// ─── From impls ────────────────────────────────────────────────

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::RowNotFound => Self::NotFound("resource not found".into()),
            _ => {
                tracing::error!(error = %err, "database error");
                Self::Internal("database error".into())
            }
        }
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(err: serde_json::Error) -> Self {
        Self::BadRequest(format!("invalid JSON: {err}"))
    }
}

impl From<deadpool_redis::PoolError> for ApiError {
    fn from(err: deadpool_redis::PoolError) -> Self {
        tracing::error!(error = %err, "redis pool error");
        Self::Internal("cache unavailable".into())
    }
}

impl From<redis::RedisError> for ApiError {
    fn from(err: redis::RedisError) -> Self {
        tracing::error!(error = %err, "redis error");
        Self::Internal("cache error".into())
    }
}

impl From<jsonwebtoken::errors::Error> for ApiError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        use jsonwebtoken::errors::ErrorKind;
        match err.kind() {
            ErrorKind::ExpiredSignature => Self::Unauthorized("token expired".into()),
            _ => Self::Unauthorized("invalid token".into()),
        }
    }
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use http::StatusCode as HttpStatus;

    async fn response_json(resp: Response) -> (HttpStatus, serde_json::Value) {
        let status = resp.status();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        (status, json)
    }

    #[tokio::test]
    async fn test_not_found_response() {
        let err = ApiError::NotFound("user not found".into());
        let resp = err.into_response();
        let (status, json) = response_json(resp).await;

        assert_eq!(status, HttpStatus::NOT_FOUND);
        assert_eq!(json["error"]["code"], "NOT_FOUND");
        assert_eq!(json["error"]["message"], "user not found");
        assert!(json["data"].is_null());
    }

    #[tokio::test]
    async fn test_validation_includes_details() {
        let err = ApiError::Validation(vec!["email is required".into(), "name too long".into()]);
        let resp = err.into_response();
        let (status, json) = response_json(resp).await;

        assert_eq!(status, HttpStatus::BAD_REQUEST);
        assert_eq!(json["error"]["code"], "VALIDATION_ERROR");
        let details = json["error"]["details"].as_array().unwrap();
        assert_eq!(details.len(), 2);
        assert!(json["data"].is_null());
    }

    #[tokio::test]
    async fn test_rate_limited_response() {
        let resp = ApiError::RateLimited.into_response();
        let (status, json) = response_json(resp).await;

        assert_eq!(status, HttpStatus::TOO_MANY_REQUESTS);
        assert_eq!(json["error"]["code"], "RATE_LIMIT_EXCEEDED");
        assert!(json["data"].is_null());
    }

    #[tokio::test]
    async fn test_rate_limited_message_response() {
        let resp =
            ApiError::RateLimitedMessage("try again in a few minutes".into()).into_response();
        let (status, json) = response_json(resp).await;

        assert_eq!(status, HttpStatus::TOO_MANY_REQUESTS);
        assert_eq!(json["error"]["code"], "RATE_LIMIT_EXCEEDED");
        assert_eq!(json["error"]["message"], "try again in a few minutes");
        assert!(json["data"].is_null());
    }

    #[tokio::test]
    async fn test_internal_hides_details() {
        let resp = ApiError::Internal("pg connection refused".into()).into_response();
        let (status, json) = response_json(resp).await;

        assert_eq!(status, HttpStatus::INTERNAL_SERVER_ERROR);
        assert_eq!(json["error"]["code"], "INTERNAL_ERROR");
        assert!(json["data"].is_null());
    }

    #[tokio::test]
    async fn test_sqlx_row_not_found_maps_to_404() {
        let err: ApiError = sqlx::Error::RowNotFound.into();
        let resp = err.into_response();
        assert_eq!(resp.status(), HttpStatus::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_success_envelope() {
        let resp = success(serde_json::json!({"id": "123"}));
        let body = serde_json::to_value(resp.0).unwrap();
        assert_eq!(body["data"]["id"], "123");
        assert!(body["error"].is_null());
    }

    #[tokio::test]
    async fn test_success_envelope_with_meta() {
        let meta = serde_json::json!({"page": 1, "total": 100});
        let resp = success_with_meta(serde_json::json!({"items": []}), meta);
        let body = serde_json::to_value(resp.0).unwrap();
        assert_eq!(body["meta"]["page"], 1);
        assert_eq!(body["meta"]["total"], 100);
        assert!(body["error"].is_null());
    }
}
