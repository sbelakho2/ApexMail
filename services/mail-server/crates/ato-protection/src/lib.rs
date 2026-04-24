//! # ATO Protection — Account Takeover Prevention
//!
//! Multi-layered defense against account takeover attacks://!
//! 1. **Impossible travel detection** — Haversine-distance analysis of login geolocations
//! 2. **Session fingerprinting** — Device/browser/network signature tracking
//! 3. **Behavioral profiling** — Login pattern modeling (time-of-day, frequency)
//! 4. **Risk scoring** — Composite risk score driving adaptive MFA decisions
//!
//! ## Usage
//!
//! ```rust,no_run
//! use ato_protection::engine::AtoEngine;
//! use ato_protection::session::LoginEvent;
//!
//! let engine = AtoEngine::new();
//! let event = LoginEvent {
//! user_id:"user123".into(),
//! ip_address:"203.0.113.50".into(),
//! user_agent:"Mozilla/5.0 ...".into(),
//! latitude:Some(40.7128),
//! longitude:Some(-74.0060),
//! timestamp:chrono::Utc::now(),
//! success:true,
//! tls_fingerprint:None,
//! };
//! let risk = engine.evaluate(&event);
//! ```

#![deny(clippy::unwrap_used)]
#![warn(missing_docs)]

pub mod config;
pub mod geo;
pub mod lockout_backend;
pub mod session;
pub mod behavior;
pub mod engine;
pub mod tls_fingerprint;

use thiserror::Error;

/// ATO protection errors
#[derive(Debug, Error)]
pub enum AtoError {
/// Session not found
    #[error("Session not found: {0}")]
    SessionNotFound(String),

/// User has no login history
    #[error("No history for user: {0}")]
    NoHistory(String),

/// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}
