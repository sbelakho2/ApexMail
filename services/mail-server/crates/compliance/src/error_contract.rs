use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: ErrorBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    #[serde(rename = "type")]
    pub error_type: String,
    pub code: String,
    pub message: String,
    pub field: Option<String>,
    pub request_id: String,
    pub documentation_url: String,
    pub retryable: bool,
    pub retry_after: Option<u64>,
}

impl ApiError {
    pub fn new(
        error_type: &str,
        code: &str,
        message: &str,
        field: Option<&str>,
        request_id: &str,
        documentation_url: &str,
        retryable: bool,
        retry_after: Option<u64>,
    ) -> Self {
        Self {
            error: ErrorBody {
                error_type: error_type.to_string(),
                code: code.to_string(),
                message: message.to_string(),
                field: field.map(|f| f.to_string()),
                request_id: request_id.to_string(),
                documentation_url: documentation_url.to_string(),
                retryable,
                retry_after,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorType {
    AuthenticationFailure,
    PermissionFailure,
    InvalidSender,
    UnverifiedDomain,
    SuppressedRecipient,
    RateLimit,
    QuotaExceeded,
    PayloadTooLarge,
    AttachmentFailure,
    TemplateFailure,
    ScheduleFailure,
    IdempotencyConflict,
    BillingRestriction,
    AccountReview,
    AbuseSuspension,
    InternalFailure,
    ValidationError,
}

impl ErrorType {
    pub fn http_status(&self) -> u16 {
        match self {
            Self::AuthenticationFailure => 401,
            Self::PermissionFailure => 403,
            Self::InvalidSender => 400,
            Self::UnverifiedDomain => 400,
            Self::SuppressedRecipient => 422,
            Self::RateLimit => 429,
            Self::QuotaExceeded => 429,
            Self::PayloadTooLarge => 413,
            Self::AttachmentFailure => 422,
            Self::TemplateFailure => 422,
            Self::ScheduleFailure => 422,
            Self::IdempotencyConflict => 409,
            Self::BillingRestriction => 402,
            Self::AccountReview => 403,
            Self::AbuseSuspension => 451,
            Self::InternalFailure => 500,
            Self::ValidationError => 422,
        }
    }

    pub fn retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimit
                | Self::QuotaExceeded
                | Self::InternalFailure
        )
    }

    pub fn requires_customer_action(&self) -> &'static str {
        match self {
            Self::AuthenticationFailure => "Check your API key or authentication credentials.",
            Self::PermissionFailure => "Verify you have the required scopes and permissions.",
            Self::InvalidSender => "Provide a valid sender address that is authorized for your account.",
            Self::UnverifiedDomain => "Verify your sending domain in the dashboard before using it.",
            Self::SuppressedRecipient => "This recipient is suppressed. Review suppression list or contact support.",
            Self::RateLimit => "Reduce your request rate or request a rate-limit increase.",
            Self::QuotaExceeded => "Upgrade your plan or wait for quota to reset.",
            Self::PayloadTooLarge => "Reduce the size of your request payload.",
            Self::AttachmentFailure => "Check attachment size, format, and count against documented limits.",
            Self::TemplateFailure => "Fix template variable errors or missing required fields.",
            Self::ScheduleFailure => "Check that the scheduled time is in the future and within the scheduling window.",
            Self::IdempotencyConflict => "Use a different idempotency key or check if the request already succeeded.",
            Self::BillingRestriction => "Check your billing status or update payment method.",
            Self::AccountReview => "Your account is under review. Contact support for status.",
            Self::AbuseSuspension => "Your account has been suspended due to policy violation. Contact support.",
            Self::InternalFailure => "Retry the request. If the error persists, contact support.",
            Self::ValidationError => "Check the documented field constraints and correct your request.",
        }
    }
}

impl std::fmt::Display for ErrorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::AuthenticationFailure => "authentication_failure",
            Self::PermissionFailure => "permission_failure",
            Self::InvalidSender => "invalid_sender",
            Self::UnverifiedDomain => "unverified_domain",
            Self::SuppressedRecipient => "suppressed_recipient",
            Self::RateLimit => "rate_limit",
            Self::QuotaExceeded => "quota_exceeded",
            Self::PayloadTooLarge => "payload_too_large",
            Self::AttachmentFailure => "attachment_failure",
            Self::TemplateFailure => "template_failure",
            Self::ScheduleFailure => "schedule_failure",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::BillingRestriction => "billing_restriction",
            Self::AccountReview => "account_review",
            Self::AbuseSuspension => "abuse_suspension",
            Self::InternalFailure => "internal_failure",
            Self::ValidationError => "validation_error",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorCatalog {
    pub entries: Vec<ErrorCatalogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorCatalogEntry {
    pub error_type: String,
    pub code: String,
    pub http_status: u16,
    pub message: String,
    pub retryable: bool,
    pub affected_field: Option<String>,
    pub required_customer_action: String,
    pub stable_code: String,
    pub documentation_fragment: String,
}

impl ErrorCatalog {
    pub fn all() -> Self {
        let entries: Vec<ErrorCatalogEntry> = [
            ErrorType::AuthenticationFailure,
            ErrorType::PermissionFailure,
            ErrorType::InvalidSender,
            ErrorType::UnverifiedDomain,
            ErrorType::SuppressedRecipient,
            ErrorType::RateLimit,
            ErrorType::QuotaExceeded,
            ErrorType::PayloadTooLarge,
            ErrorType::AttachmentFailure,
            ErrorType::TemplateFailure,
            ErrorType::ScheduleFailure,
            ErrorType::IdempotencyConflict,
            ErrorType::BillingRestriction,
            ErrorType::AccountReview,
            ErrorType::AbuseSuspension,
            ErrorType::InternalFailure,
            ErrorType::ValidationError,
        ]
        .iter()
        .map(|e| ErrorCatalogEntry {
            error_type: e.to_string(),
            code: e.to_string(),
            http_status: e.http_status(),
            message: e.to_string(),
            retryable: e.retryable(),
            affected_field: None,
            required_customer_action: e.requires_customer_action().to_string(),
            stable_code: e.to_string(),
            documentation_fragment: format!("/api/errors#{}", e.to_string()),
        })
        .collect();

        ErrorCatalog { entries }
    }

    pub fn find_by_type(&self, error_type: &str) -> Option<&ErrorCatalogEntry> {
        self.entries
            .iter()
            .find(|e| e.error_type == error_type)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishedLimits {
    pub request_size_bytes: u64,
    pub recipient_count: u32,
    pub attachment_count: u32,
    pub attachment_size_bytes: u64,
    pub allowed_mime_types: Vec<String>,
    pub subject_length_bytes: u32,
    pub header_count: u32,
    pub header_total_size_bytes: u64,
    pub template_size_bytes: u64,
    pub variable_count: u32,
    pub batch_size: u32,
    pub scheduling_horizon_days: u32,
    pub api_rate_per_second: u32,
    pub smtp_rate_per_minute: u32,
    pub smtp_max_connections: u32,
    pub webhook_count: u32,
    pub webhook_retries: u32,
    pub retention_days: u32,
    pub export_max_records: u32,
    pub inbound_max_size_bytes: u64,
    pub domain_count: u32,
    pub ip_pool_count: u32,
}

impl Default for PublishedLimits {
    fn default() -> Self {
        Self {
            request_size_bytes: 10 * 1024 * 1024,   // 10 MB
            recipient_count: 1000,
            attachment_count: 25,
            attachment_size_bytes: 25 * 1024 * 1024, // 25 MB
            allowed_mime_types: vec![
                "application/pdf".into(),
                "image/png".into(),
                "image/jpeg".into(),
                "image/gif".into(),
                "text/csv".into(),
                "text/plain".into(),
                "application/zip".into(),
            ],
            subject_length_bytes: 998,
            header_count: 50,
            header_total_size_bytes: 16 * 1024,
            template_size_bytes: 1024 * 1024,        // 1 MB
            variable_count: 200,
            batch_size: 1000,
            scheduling_horizon_days: 72,
            api_rate_per_second: 600,
            smtp_rate_per_minute: 300,
            smtp_max_connections: 50,
            webhook_count: 25,
            webhook_retries: 15,
            retention_days: 45,
            export_max_records: 500_000,
            inbound_max_size_bytes: 30 * 1024 * 1024, // 30 MB
            domain_count: 100,
            ip_pool_count: 10,
        }
    }
}

impl PublishedLimits {
    pub fn all_limit_names() -> Vec<&'static str> {
        vec![
            "request_size_bytes",
            "recipient_count",
            "attachment_count",
            "attachment_size_bytes",
            "allowed_mime_types",
            "subject_length_bytes",
            "header_count",
            "header_total_size_bytes",
            "template_size_bytes",
            "variable_count",
            "batch_size",
            "scheduling_horizon_days",
            "api_rate_per_second",
            "smtp_rate_per_minute",
            "smtp_max_connections",
            "webhook_count",
            "webhook_retries",
            "retention_days",
            "export_max_records",
            "inbound_max_size_bytes",
            "domain_count",
            "ip_pool_count",
        ]
    }

    pub fn get_limit(&self, name: &str) -> Option<serde_json::Value> {
        match name {
            "request_size_bytes" => Some(serde_json::json!(self.request_size_bytes)),
            "recipient_count" => Some(serde_json::json!(self.recipient_count)),
            "attachment_count" => Some(serde_json::json!(self.attachment_count)),
            "attachment_size_bytes" => Some(serde_json::json!(self.attachment_size_bytes)),
            "allowed_mime_types" => Some(serde_json::json!(self.allowed_mime_types)),
            "subject_length_bytes" => Some(serde_json::json!(self.subject_length_bytes)),
            "header_count" => Some(serde_json::json!(self.header_count)),
            "header_total_size_bytes" => Some(serde_json::json!(self.header_total_size_bytes)),
            "template_size_bytes" => Some(serde_json::json!(self.template_size_bytes)),
            "variable_count" => Some(serde_json::json!(self.variable_count)),
            "batch_size" => Some(serde_json::json!(self.batch_size)),
            "scheduling_horizon_days" => Some(serde_json::json!(self.scheduling_horizon_days)),
            "api_rate_per_second" => Some(serde_json::json!(self.api_rate_per_second)),
            "smtp_rate_per_minute" => Some(serde_json::json!(self.smtp_rate_per_minute)),
            "smtp_max_connections" => Some(serde_json::json!(self.smtp_max_connections)),
            "webhook_count" => Some(serde_json::json!(self.webhook_count)),
            "webhook_retries" => Some(serde_json::json!(self.webhook_retries)),
            "retention_days" => Some(serde_json::json!(self.retention_days)),
            "export_max_records" => Some(serde_json::json!(self.export_max_records)),
            "inbound_max_size_bytes" => Some(serde_json::json!(self.inbound_max_size_bytes)),
            "domain_count" => Some(serde_json::json!(self.domain_count)),
            "ip_pool_count" => Some(serde_json::json!(self.ip_pool_count)),
            _ => None,
        }
    }
}

/// Validate that an error response matches the standard error contract.
pub fn validate_error_response(response: &ApiError) -> Result<(), Vec<String>> {
    let mut errors: Vec<String> = Vec::new();

    if response.error.error_type.is_empty() {
        errors.push("error.type is required and must not be empty".into());
    }
    if response.error.code.is_empty() {
        errors.push("error.code is required and must not be empty".into());
    }
    if response.error.message.is_empty() {
        errors.push("error.message is required and must not be empty".into());
    }
    if response.error.request_id.is_empty() {
        errors.push("error.request_id is required and must not be empty".into());
    }
    if response.error.documentation_url.is_empty() {
        errors.push("error.documentation_url is required and must not be empty".into());
    }

    let catalog = ErrorCatalog::all();
    if catalog.find_by_type(&response.error.error_type).is_none() {
        errors.push(format!(
            "Unknown error type '{}' — must be one of the documented catalog",
            response.error.error_type
        ));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_error_constructs_json_matching_contract() {
        let err = ApiError::new(
            "validation_error",
            "invalid_recipient",
            "The recipient address is not valid.",
            Some("to[0]"),
            "req_01KABC",
            "https://docs.apexmail.com/api/errors#invalid_recipient",
            false,
            None,
        );

        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["error"]["type"], "validation_error");
        assert_eq!(json["error"]["code"], "invalid_recipient");
        assert_eq!(json["error"]["message"], "The recipient address is not valid.");
        assert_eq!(json["error"]["field"], "to[0]");
        assert_eq!(json["error"]["request_id"], "req_01KABC");
        assert_eq!(json["error"]["documentation_url"], "https://docs.apexmail.com/api/errors#invalid_recipient");
        assert_eq!(json["error"]["retryable"], false);
        assert!(json["error"]["retry_after"].is_null());
    }

    #[test]
    fn test_api_error_retryable_serialization() {
        let err = ApiError::new(
            "rate_limit",
            "rate_limit",
            "Too many requests",
            None,
            "req_02",
            "https://docs.apexmail.com/api/errors#rate_limit",
            true,
            Some(30),
        );

        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["error"]["retryable"], true);
        assert_eq!(json["error"]["retry_after"], 30);
    }

    #[test]
    fn test_validate_error_response_passes_valid() {
        let err = ApiError::new(
            "validation_error",
            "invalid_recipient",
            "Bad recipient",
            None,
            "req_01",
            "https://docs.example.com/errors",
            false,
            None,
        );
        let result = validate_error_response(&err);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_error_response_fails_unknown_type() {
        let err = ApiError::new(
            "nonexistent_error",
            "bad_code",
            "msg",
            None,
            "req_01",
            "https://docs.example.com",
            false,
            None,
        );
        let result = validate_error_response(&err);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("Unknown error type")));
    }

    #[test]
    fn test_error_catalog_has_all_17_types() {
        let catalog = ErrorCatalog::all();
        assert_eq!(catalog.entries.len(), 17);

        let types: Vec<&str> = catalog.entries.iter().map(|e| e.error_type.as_str()).collect();
        assert!(types.contains(&"authentication_failure"));
        assert!(types.contains(&"validation_error"));
        assert!(types.contains(&"internal_failure"));
        assert!(types.contains(&"abuse_suspension"));
        assert!(types.contains(&"billing_restriction"));
    }

    #[test]
    fn test_published_limits_has_all_22_fields() {
        let limits = PublishedLimits::default();
        let names = PublishedLimits::all_limit_names();
        assert_eq!(names.len(), 22);

        for name in &names {
            assert!(limits.get_limit(name).is_some(), "Missing limit: {}", name);
        }
    }
}
