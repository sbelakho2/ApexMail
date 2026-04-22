//! Standard error codes used across all ApexMail services.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
// Auth
    Unauthorized,
    Forbidden,
    TokenExpired,
    TokenBlacklisted,
    InvalidApiKey,
    InsufficientScopes,
// Validation
    ValidationError,
    InvalidInput,
    PayloadTooLarge,
    NullByteDetected,
// Rate limiting
    RateLimitExceeded,
// Resources
    NotFound,
    Conflict,
    Gone,
// Server
    InternalError,
    ServiceUnavailable,
    RequestTimeout,
    GatewayTimeout,
// Business
    DomainNotVerified,
    SuppressionExists,
    WebhookDeliveryFailed,
    QuotaExceeded,
    InvalidTemplate,
    MessageCancelled,
    IdempotencyConflict,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Unauthorized => "UNAUTHORIZED",
            Self::Forbidden => "FORBIDDEN",
            Self::TokenExpired => "TOKEN_EXPIRED",
            Self::TokenBlacklisted => "TOKEN_BLACKLISTED",
            Self::InvalidApiKey => "INVALID_API_KEY",
            Self::InsufficientScopes => "INSUFFICIENT_SCOPES",
            Self::ValidationError => "VALIDATION_ERROR",
            Self::InvalidInput => "INVALID_INPUT",
            Self::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
            Self::NullByteDetected => "NULL_BYTE_DETECTED",
            Self::RateLimitExceeded => "RATE_LIMIT_EXCEEDED",
            Self::NotFound => "NOT_FOUND",
            Self::Conflict => "CONFLICT",
            Self::Gone => "GONE",
            Self::InternalError => "INTERNAL_ERROR",
            Self::ServiceUnavailable => "SERVICE_UNAVAILABLE",
            Self::RequestTimeout => "REQUEST_TIMEOUT",
            Self::GatewayTimeout => "GATEWAY_TIMEOUT",
            Self::DomainNotVerified => "DOMAIN_NOT_VERIFIED",
            Self::SuppressionExists => "SUPPRESSION_EXISTS",
            Self::WebhookDeliveryFailed => "WEBHOOK_DELIVERY_FAILED",
            Self::QuotaExceeded => "QUOTA_EXCEEDED",
            Self::InvalidTemplate => "INVALID_TEMPLATE",
            Self::MessageCancelled => "MESSAGE_CANCELLED",
            Self::IdempotencyConflict => "IDEMPOTENCY_CONFLICT",
        };
        write!(f, "{}", s)
    }
}

impl ErrorCode {
    pub fn http_status(&self) -> u16 {
        match self {
            Self::Unauthorized | Self::TokenExpired | Self::TokenBlacklisted | Self::InvalidApiKey => 401,
            Self::Forbidden | Self::InsufficientScopes => 403,
            Self::NotFound => 404,
            Self::Conflict | Self::IdempotencyConflict | Self::SuppressionExists => 409,
            Self::Gone | Self::MessageCancelled => 410,
            Self::PayloadTooLarge => 413,
            Self::ValidationError | Self::InvalidInput | Self::NullByteDetected | Self::InvalidTemplate => 400,
            Self::RateLimitExceeded | Self::QuotaExceeded => 429,
            Self::RequestTimeout => 408,
            Self::GatewayTimeout => 504,
            Self::ServiceUnavailable | Self::WebhookDeliveryFailed => 503,
            Self::InternalError => 500,
            Self::DomainNotVerified => 422,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_display() {
        assert_eq!(ErrorCode::Unauthorized.to_string(), "UNAUTHORIZED");
        assert_eq!(ErrorCode::NotFound.to_string(), "NOT_FOUND");
        assert_eq!(ErrorCode::RateLimitExceeded.to_string(), "RATE_LIMIT_EXCEEDED");
    }

    #[test]
    fn test_http_status_codes() {
        assert_eq!(ErrorCode::Unauthorized.http_status(), 401);
        assert_eq!(ErrorCode::Forbidden.http_status(), 403);
        assert_eq!(ErrorCode::NotFound.http_status(), 404);
        assert_eq!(ErrorCode::RateLimitExceeded.http_status(), 429);
        assert_eq!(ErrorCode::InternalError.http_status(), 500);
        assert_eq!(ErrorCode::ValidationError.http_status(), 400);
        assert_eq!(ErrorCode::PayloadTooLarge.http_status(), 413);
    }

    #[test]
    fn test_all_codes_have_valid_status() {
        let codes = [
            ErrorCode::Unauthorized, ErrorCode::Forbidden, ErrorCode::TokenExpired,
            ErrorCode::TokenBlacklisted, ErrorCode::InvalidApiKey, ErrorCode::InsufficientScopes,
            ErrorCode::ValidationError, ErrorCode::InvalidInput, ErrorCode::PayloadTooLarge,
            ErrorCode::NullByteDetected, ErrorCode::RateLimitExceeded, ErrorCode::NotFound,
            ErrorCode::Conflict, ErrorCode::Gone, ErrorCode::InternalError,
            ErrorCode::ServiceUnavailable, ErrorCode::RequestTimeout, ErrorCode::GatewayTimeout,
            ErrorCode::DomainNotVerified, ErrorCode::SuppressionExists,
            ErrorCode::WebhookDeliveryFailed, ErrorCode::QuotaExceeded,
            ErrorCode::InvalidTemplate, ErrorCode::MessageCancelled, ErrorCode::IdempotencyConflict,
        ];
        for code in codes {
            let status = code.http_status();
            assert!(status >= 400 && status < 600, "{}: {}", code, status);
        }
    }
}
