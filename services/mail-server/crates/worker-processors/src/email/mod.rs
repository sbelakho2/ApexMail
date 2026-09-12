//! Email processor — SMTP/SES delivery with DKIM, tracking, warmup, rate limiting.
//!
//! This module handles the email sending pipeline://! - SMTP/SES transport abstraction
//! - Hybrid routing:dedicated IPs → self-hosted, shared → SES
//! - DKIM signing
//! - Tracking pixel/link injection
//! - IP warmup schedule enforcement
//! - Per-IP rate limiting
//! - Circuit breakers for SMTP endpoints

mod processor;
mod tracking;
mod transport;
mod transport_router;
mod types;

pub use processor::EmailProcessor;
pub use tracking::{add_tracking_pixel, encode_tracking_id, rewrite_links, TrackingPayload};
pub use transport::{
    create_transport, create_transport_from_config, EmailTransport, SesTransport, SmtpTransport,
    APEXMAIL_ROUTE_HEADER, APEXMAIL_ROUTE_VALUE_PREFIX, APEXMAIL_SOURCE_IP_REPLY_HEADER,
};
pub use transport_router::{transport_kind_for, TransportKind};
pub use types::{
    Attachment, CachedSuppression, DeliveryReceipt, DeliveryRoute, DkimConfig, Domain, EmailJob,
    PreparedEmail, RateLimitResult, SendOutcome, Suppression, WarmupIpIdentity,
};
