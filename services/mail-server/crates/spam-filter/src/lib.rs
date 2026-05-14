#![allow(clippy::doc_lazy_continuation)]

//! # ApexMail Spam Filter
//!
//! Multi-layered spam and phishing detection providing://!
//! - **Naive Bayes Classifier**:Trained on spam/ham corpus with online learning.
//! - **Header Analysis**:Validates SPF/DKIM/DMARC alignment, detects forged
//! headers, missing Message-ID, suspicious Received chains.
//! - **Content Scoring**:Aho-Corasick multi-pattern matching against known
//! spam/phishing phrases with weighted scoring.
//! - **URL Reputation**:Extracts and analyzes URLs for phishing indicators
//! (IDN homograph attacks, URL shorteners, suspicious TLDs).
//! - **Attachment Scoring**:Flags dangerous MIME types (.exe, .scr, .js, etc.).
//! - **Composite Scoring Engine**:Combines all signals into a final score
//! with configurable thresholds for ham/spam/reject.

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![warn(missing_docs)]

pub mod bayesian;
pub mod config;
pub mod content_scorer;
pub mod engine;
pub mod header_analyzer;
pub mod url_analyzer;

pub use config::SpamConfig;
pub use engine::{SpamEngine, SpamVerdict};

/// Spam filter errors
#[derive(Debug, thiserror::Error)]
pub enum SpamError {
    /// Configuration error
    #[error("Spam filter config error: {0}")]
    Config(String),
    /// Model error
    #[error("Model error: {0}")]
    Model(String),
    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}
