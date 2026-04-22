//! Mail Common - Shared types, configuration, and utilities
//!
//! This crate provides common functionality used across all mail server components.

pub mod config;
pub mod error;
pub mod hot_config;
#[cfg(feature = "axum")]
pub mod internal_auth;
pub mod pii;
pub mod security;
pub mod warmup;

pub use config::Config;
pub use error::{Error, Result};
pub use security::{
	generate_correlation_id,
	global_security_correlator,
	ingest_security_event,
	CompositeAlert,
	CorrelationContext,
	SecurityAction,
	SecurityCorrelator,
	SecurityEvent,
	SecuritySeverity,
	SecuritySystem,
};

/// Re-export commonly used types
pub use chrono::{DateTime, Utc};
pub use uuid::Uuid;
