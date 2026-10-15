#![allow(clippy::doc_lazy_continuation)]
//! Mail Common - Shared types, configuration, and utilities
//!
//! This crate provides common functionality used across all mail server components.

#![deny(unsafe_code)]
pub mod config;
pub mod error;
pub mod hot_config;
#[cfg(feature = "axum")]
pub mod internal_auth;
pub mod pii;
pub mod routing_mode;
pub mod security;
pub mod ssrf;
pub mod warmup;

pub use config::Config;
pub use error::{Error, Result};
pub use routing_mode::{
    eu_only_addon_enabled, ResolvedRoutingMode, RoutingMode, ADDONS_SETTINGS_KEY,
    EU_ONLY_ADDON_SETTINGS_KEY, ROUTING_MODE_SETTINGS_KEY,
};
pub use security::{
    generate_correlation_id, global_security_correlator, ingest_security_event, CompositeAlert,
    CorrelationContext, SecurityAction, SecurityCorrelator, SecurityEvent, SecuritySeverity,
    SecuritySystem,
};
pub use ssrf::{is_localhost, is_private_or_reserved_host, is_private_or_reserved_ip};

/// Re-export commonly used types
pub use chrono::{DateTime, Utc};
pub use uuid::Uuid;
