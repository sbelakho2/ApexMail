use serde::Serialize;

use crate::ErrorCode;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ErrorEnvelope {
    pub error: ErrorDetail,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Vec<String>>,
}

impl ErrorEnvelope {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            error: ErrorDetail {
                code: code.to_string(),
                message: message.into(),
                details: None,
            },
        }
    }

    pub fn with_details(code: ErrorCode, message: impl Into<String>, details: Vec<String>) -> Self {
        Self {
            error: ErrorDetail {
                code: code.to_string(),
                message: message.into(),
                details: Some(details),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_envelope_serializes_shared_code_and_message() {
        let body = ErrorEnvelope::new(ErrorCode::NotFound, "plan not found");
        let json = serde_json::to_value(body).expect("serializes");

        assert_eq!(json["error"]["code"], "NOT_FOUND");
        assert_eq!(json["error"]["message"], "plan not found");
        assert!(json["error"].get("details").is_none());
    }
}
