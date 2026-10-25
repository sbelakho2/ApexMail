//! Email processor, SMTP/SES delivery with DKIM, tracking, warmup, rate limiting.
//!
//! This module handles the email sending pipeline://! - SMTP/SES transport abstraction
//! - Hybrid routing:dedicated IPs → self-hosted, shared → SES
//! - DKIM signing
//! - Tracking pixel/link injection
//! - IP warmup schedule enforcement
//! - Per-IP rate limiting
//! - Circuit breakers for SMTP endpoints

mod dlp;
mod outbound_mta;
mod processor;
mod sales;
mod tracking;
mod transport;
mod transport_router;
mod types;

pub use dlp::{EngineDlpScanner, PreSendDlpScanner, PreSendVerdict};
pub use outbound_mta::{OutboundMtaTransport, RelaySubmitter};
pub use processor::EmailProcessor;
pub use sales::{
    create_sales_transport, plan_sales_route, sales_route_guard_violation, PlannedSalesRoute,
    SalesSend, SalesTransport, SALES_HOLD_DKIM_DISABLED, SALES_HOLD_DOMAIN_NOT_ALLOWED,
    SALES_HOLD_ROUTE_GUARD, SALES_HOLD_SOURCE_IP_MISSING, SALES_HOLD_TRANSPORT_UNAVAILABLE,
    SALES_HOLD_TRANSPORT_UNCONFIGURED,
};
pub use tracking::{add_tracking_pixel, encode_tracking_id, rewrite_links, TrackingPayload};
pub use transport::{
    create_transport, create_transport_from_config, create_transport_from_config_with_db,
    EmailTransport, HybridTransport, SesTransport, SmtpTransport, APEXMAIL_ROUTE_HEADER,
    APEXMAIL_ROUTE_VALUE_PREFIX, APEXMAIL_SOURCE_IP_REPLY_HEADER,
};
pub use transport_router::{transport_kind_for, TransportKind};
pub use types::{
    Attachment, CachedSuppression, DedicatedIp, DeliveryReceipt, DeliveryRoute, DkimConfig, Domain,
    EmailJob, PreparedEmail, RateLimitResult, SendOutcome, Suppression,
};
