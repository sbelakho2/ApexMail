//! Webhook processor — HTTP delivery with SSRF protection.
//!
//! This module handles webhook delivery:
//! - SSRF protection (DNS validation, private IP blocking)
//! - HMAC signature generation
//! - Circuit breakers per endpoint
//! - Retry with exponential backoff
//! - Dead letter queue for failed deliveries

mod processor;
mod ssrf;
mod types;

pub use processor::WebhookProcessor;
pub use ssrf::{is_private_ip, SsrfValidator};
pub use types::{
    truncate_payload, PendingSuccess, WebhookDelivery, WebhookDeliveryResult, WebhookJob,
    BLOCKED_HOSTNAMES, DNS_CACHE_MAX_ENTRIES, DNS_CACHE_TTL_SECS, MAX_CONCURRENT_PER_TENANT,
    MAX_RESPONSE_BYTES, MAX_WEBHOOK_PAYLOAD_BYTES, SIGNATURE_VERSION,
};
