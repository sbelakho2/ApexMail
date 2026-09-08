//! Webhook processor types.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
/// Webhook job from queue.
///
/// O-16.3 fix: `secret` zeroization is applied at the point of use in
/// `sign_payload()` rather than in this struct because `sqlx::FromRow`
/// does not support `Zeroizing<String>` decoding.
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
    /// Webhook signing secret.
    /// Note: `Zeroizing<String>` is not used here because `sqlx::FromRow`
    /// does not implement decoding for `Zeroizing<String>`. Zeroization
    /// is applied at the point of use in `sign_payload()` (O-16.3).
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

    /// Next retry delay on the FIXED retry ladder (review 2026-09-08 §7).
    ///
    /// Infrastructure webhooks must survive multi-hour customer outages:
    /// the old exponential curve (1s·2^n, capped at 1h) exhausted three
    /// retries within minutes, turning a brief outage into permanent
    /// event loss. The published schedule is now:
    ///
    ///   attempt 1 delivers immediately; on failure retry after
    ///   30s, 2m, 10m, 30m, 1h, 3h, 6h, 12h, 24h
    ///
    /// (10 total attempts, at-least-once semantics unchanged). The
    /// stored `retry_delay`/`backoff_multiplier` fields are kept for
    /// schema compatibility but no longer shape the curve.
    pub fn next_retry_delay_ms(&self) -> i64 {
        const RETRY_LADDER_MS: [i64; 9] = [
            30_000,     // 30s
            120_000,    // 2m
            600_000,    // 10m
            1_800_000,  // 30m
            3_600_000,  // 1h
            10_800_000, // 3h
            21_600_000, // 6h
            43_200_000, // 12h
            86_400_000, // 24h
        ];
        // `attempt` is 1-based and counts the attempt that just failed:
        // after attempt 1 wait RETRY_LADDER_MS[0], after attempt 9 wait
        // the last rung; attempt 10+ is exhaustion, not scheduling.
        let idx = (self.attempt.max(1) as usize).clamp(1, RETRY_LADDER_MS.len()) - 1;
        RETRY_LADDER_MS[idx]
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
                            // Char-boundary-safe truncation: slicing with
                            // `&s[..n]` panics on multi-byte UTF-8 (webhook
                            // payloads routinely contain non-ASCII). Take
                            // `threshold` CHARACTERS instead (same pattern as
                            // reply_handler::classifier).
                            let truncated: String =
                                s.chars().take(threshold.min(s.len() / 2)).collect();
                            let truncated = format!("{}{}", truncated, TRUNCATION_NOTICE);
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

#[cfg(test)]
mod truncate_tests {
    use super::truncate_payload;
    use serde_json::json;

    #[test]
    fn truncate_payload_handles_multibyte_utf8_without_panic() {
        // 4-byte emoji + CJK, repeated past the 256-byte large-field
        // threshold: `&s[..n]` byte-slicing would panic when the cut lands
        // mid-codepoint (which it does — every char here is multibyte).
        let unit = "🎉🎉中文"; // 4+4+3+3 = 14 bytes
        let body = unit.repeat(96); // 1344 bytes > 1024 first-pass threshold
        let payload = json!({ "body": body });
        let truncated = truncate_payload(&payload, 1024);
        let s = truncated.get("body").unwrap().as_str().unwrap();
        assert!(s.contains("[truncated"));
        // The cut must land on a char boundary (this iteration panics if not).
        assert!(s.chars().count() > 0);
    }

    #[test]
    fn truncate_payload_leaves_small_payloads_untouched() {
        let payload = json!({ "body": "small", "nested": { "text": "also small" } });
        let out = truncate_payload(&payload, 1024);
        assert_eq!(out, payload);
    }
}
