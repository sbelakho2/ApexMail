//! Unified API error type that serialises to a consistent JSON envelope.
//!
//! ```json
//! {"error":{"code":"NOT_FOUND", "message":"Resource not found"}}
//! ```

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

// ─── Error body ────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: ErrorDetail,
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
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
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
            Self::RateLimited => "RATE_LIMIT_EXCEEDED",
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
            error: ErrorDetail {
                code: self.code_str().to_string(),
                message,
                details,
            },
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
    }

    #[tokio::test]
    async fn test_rate_limited_response() {
        let resp = ApiError::RateLimited.into_response();
        let (status, json) = response_json(resp).await;

        assert_eq!(status, HttpStatus::TOO_MANY_REQUESTS);
        assert_eq!(json["error"]["code"], "RATE_LIMIT_EXCEEDED");
    }

    #[tokio::test]
    async fn test_internal_hides_details() {
        let resp = ApiError::Internal("pg connection refused".into()).into_response();
        let (status, json) = response_json(resp).await;

        assert_eq!(status, HttpStatus::INTERNAL_SERVER_ERROR);
        assert_eq!(json["error"]["code"], "INTERNAL_ERROR");
    }

    #[tokio::test]
    async fn test_sqlx_row_not_found_maps_to_404() {
        let err: ApiError = sqlx::Error::RowNotFound.into();
        let resp = err.into_response();
        assert_eq!(resp.status(), HttpStatus::NOT_FOUND);
    }
}
