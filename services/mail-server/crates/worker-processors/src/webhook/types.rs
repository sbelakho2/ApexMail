//! Webhook processor types.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Webhook job from queue.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WebhookJob {
    pub id: String,
    #[sqlx(rename = "webhookId")]
    pub webhook_id: String,
    #[sqlx(rename = "tenantId")]
    pub tenant_id: String,
    #[sqlx(rename = "eventType")]
    pub event_type: String,
    pub payload: serde_json::Value,
    pub url: String,
    pub secret: String,
    pub headers: Option<serde_json::Value>,
    pub attempt: i32,
    #[sqlx(rename = "maxRetries")]
    pub max_retries: i32,
    #[sqlx(rename = "retryDelay")]
    pub retry_delay: i32,
    #[sqlx(rename = "backoffMultiplier")]
    pub backoff_multiplier: f64,
    #[sqlx(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}

/// Result of a webhook delivery attempt.
#[derive(Debug, Clone)]
pub struct WebhookDeliveryResult {
    pub success: bool,
    pub status_code: Option<u16>,
    pub response_time_ms: u64,
    pub error: Option<String>,
    pub response_body: Option<String>,
    /// Retry-After header value in milliseconds (from 429/503 responses).
    pub retry_after_ms: Option<u64>,
}

/// Webhook delivery record for storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDelivery {
    pub id: String,
    pub webhook_id: String,
    pub tenant_id: String,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub status_code: Option<u16>,
    pub response_time_ms: u64,
    pub response_body: Option<String>,
    pub attempt: i32,
    pub delivered_at: DateTime<Utc>,
}

/// Maximum concurrent webhooks per tenant.
pub const MAX_CONCURRENT_PER_TENANT: usize = 5;

/// Maximum webhook payload size in bytes (1 MB).
pub const MAX_WEBHOOK_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Maximum response body to read (1 KB).
pub const MAX_RESPONSE_BYTES: usize = 1024;

/// DNS cache TTL in seconds.
const DNS_CACHE_TTL_SECS_DEFAULT: u64 = 60;

/// DNS cache max entries.
const DNS_CACHE_MAX_ENTRIES_DEFAULT: u64 = 500;

pub fn dns_cache_ttl_secs() -> u64 {
    std::env::var("WEBHOOK_DNS_CACHE_TTL_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DNS_CACHE_TTL_SECS_DEFAULT)
}

pub fn dns_cache_max_entries() -> u64 {
    std::env::var("WEBHOOK_DNS_CACHE_MAX_ENTRIES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DNS_CACHE_MAX_ENTRIES_DEFAULT)
}

/// Signature version for HMAC.
pub const SIGNATURE_VERSION: &str = "sha256=";

/// Default blocked hostnames for SSRF protection.
pub const BLOCKED_HOSTNAMES: &[&str] = &[
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "[::1]",
    "metadata.google.internal",
    "instance-data",
    "kubernetes.default",
    "kubernetes.default.svc",
    // AWS metadata
    "169.254.169.254",
];

/// Per-job success record for batch flushing.
#[derive(Debug, Clone)]
pub struct PendingSuccess {
    pub job: WebhookJob,
    pub result: WebhookDeliveryResult,
}

impl WebhookJob {
    /// Get custom headers as HashMap.
    pub fn get_headers(&self) -> HashMap<String, String> {
        self.headers
            .as_ref()
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default()
    }

    /// Calculate next retry delay with exponential backoff.
    pub fn next_retry_delay_ms(&self) -> i64 {
        let multiplier = if self.backoff_multiplier.is_finite() && self.backoff_multiplier > 0.0 {
            self.backoff_multiplier
        } else {
            2.0 // Default exponential backoff
        };
        let delay = self.retry_delay as f64 * multiplier.powi((self.attempt - 1).max(0));
        (delay as i64).min(3600_000) // Cap at 1 hour
    }
}

impl WebhookDeliveryResult {
    /// Create a successful result.
    pub fn success(status_code: u16, response_time_ms: u64, response_body: Option<String>) -> Self {
        Self {
            success: true,
            status_code: Some(status_code),
            response_time_ms,
            error: None,
            response_body,
            retry_after_ms: None,
        }
    }

    /// Create a failed result.
    pub fn failure(
        status_code: Option<u16>,
        response_time_ms: u64,
        error: String,
        response_body: Option<String>,
        retry_after_ms: Option<u64>,
    ) -> Self {
        Self {
            success: false,
            status_code,
            response_time_ms,
            error: Some(error),
            response_body,
            retry_after_ms,
        }
    }

    /// Check if status code is retryable.
    pub fn is_retryable(&self) -> bool {
        match self.status_code {
            Some(code) => code >= 500 || code == 408 || code == 429,
            None => true, // Network errors are retryable
        }
    }
}

/// Truncate large payload fields to stay within size limit.
pub fn truncate_payload(payload: &serde_json::Value, max_bytes: usize) -> serde_json::Value {
    const TRUNCATION_NOTICE: &str = "[truncated — payload exceeded size limit]";
    const LARGE_FIELD_KEYS: &[&str] = &[
        "html",
        "htmlBody",
        "textBody",
        "text",
        "content",
        "body",
        "raw_message",
        "rawMessage",
    ];

    fn truncate_value(value: &serde_json::Value, threshold: usize) -> serde_json::Value {
        match value {
            serde_json::Value::Object(obj) => {
                let mut new_obj = serde_json::Map::new();
                for (key, val) in obj {
                    let new_val = if let serde_json::Value::String(s) = val {
                        if LARGE_FIELD_KEYS.contains(&key.as_str()) && s.len() > threshold {
                            let truncated = format!(
                                "{}{}",
                                &s[..threshold.min(s.len() / 2)],
                                TRUNCATION_NOTICE
                            );
                            serde_json::Value::String(truncated)
                        } else {
                            val.clone()
                        }
                    } else {
                        truncate_value(val, threshold)
                    };
                    new_obj.insert(key.clone(), new_val);
                }
                serde_json::Value::Object(new_obj)
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.iter().map(|v| truncate_value(v, threshold)).collect())
            }
            other => other.clone(),
        }
    }

    let truncated = truncate_value(payload, 1024);
    let serialized = match serde_json::to_string(&truncated) {
        Ok(value) => value,
        Err(_) => return truncated,
    };

    if serialized.len() > max_bytes {
        // Aggressive truncation
        truncate_value(&truncated, 256)
    } else {
        truncated
    }
}
