//! Email processor — SMTP/SES delivery with DKIM, tracking, warmup, rate limiting.
//!
//! This module handles the email sending pipeline:
//! - SMTP/SES transport abstraction
//! - DKIM signing
//! - Tracking pixel/link injection
//! - IP warmup schedule enforcement
//! - Per-IP rate limiting
//! - Circuit breakers for SMTP endpoints

mod processor;
mod tracking;
mod transport;
mod types;

pub use processor::EmailProcessor;
pub use tracking::{add_tracking_pixel, encode_tracking_id, rewrite_links, TrackingPayload};
pub use transport::{create_transport, create_transport_from_config, EmailTransport, SesTransport, SmtpTransport};
pub use types::{
    Attachment, CachedSuppression, DkimConfig, Domain, EmailJob, PreparedEmail, RateLimitResult,
    SendOutcome, SendResult, Suppression, WarmupLimits,
};
