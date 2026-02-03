//! Mail Common - Shared types, configuration, and utilities
//!
//! This crate provides common functionality used across all mail server components.

pub mod config;
pub mod error;

pub use config::Config;
pub use error::{Error, Result};

/// Re-export commonly used types
pub use chrono::{DateTime, Utc};
pub use uuid::Uuid;
