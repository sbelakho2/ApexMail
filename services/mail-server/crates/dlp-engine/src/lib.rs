//! # DLP Engine — Data Loss Prevention
//!
//! Prevents sensitive data from leaving the organization via email://!
//! 1. **PII detection** — Credit card numbers (Luhn), SSNs, passport numbers, phone numbers
//! 2. **Sensitive content scanning** — Regex + keyword pattern matching for confidential markers
//! 3. **Entropy analysis** — Detects potential secrets/keys via Shannon entropy
//! 4. **Document watermarking** — Adds invisible watermarks to outbound attachments
//! 5. **Policy engine** — Configurable rules to block, quarantine, or audit
//!
//! ## Design
//!
//! The DLP engine operates inline on outbound email, scanning both body text
//! and attachment content. It produces a `DlpVerdict` with findings and a
//! recommended action.

#![deny(clippy::unwrap_used)]
#![warn(missing_docs)]

pub mod attachment;
pub mod config;
pub mod content_policy;
pub mod engine;
pub mod entropy;
pub mod pii;

use thiserror::Error;

/// DLP errors
#[derive(Debug, Error)]
pub enum DlpError {
    /// Pattern compilation failed
    #[error("Pattern error: {0}")]
    PatternError(String),

    /// Content scanning error
    #[error("Scan error: {0}")]
    ScanError(String),

    /// Policy violation
    #[error("Policy violation: {0}")]
    PolicyViolation(String),
}
