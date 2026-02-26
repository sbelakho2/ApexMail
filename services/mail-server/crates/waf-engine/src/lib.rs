//! # ApexMail WAF Engine
//!
//! A pure-Rust Web Application Firewall providing:
//!
//! - **SQL Injection Prevention**: AST-based SQL parser that detects structural
//!   manipulation rather than relying on fragile regex patterns.
//! - **XSS Prevention**: HTML/JS token-level analysis that catches obfuscated
//!   payloads (encoded entities, polyglot payloads, DOM-based XSS).
//! - **Path Traversal Detection**: Canonicalization and jail-break detection.
//! - **Command Injection Detection**: Shell metacharacter and chaining detection.
//! - **OWASP CRS-Compatible Rule Engine**: Aho-Corasick multi-pattern matching
//!   with anomaly scoring (paranoia levels 1-4).
//! - **Request Anomaly Scoring**: Combines multiple signals into a composite
//!   threat score with configurable blocking thresholds.
//!
//! ## Architecture
//!
//! ```text
//! Request → [Decoder] → [Rule Engine] → [SQL AST] → [XSS Analyzer] → Decision
//!              ↓             ↓               ↓             ↓
//!          URL-decode    Aho-Corasick    Token Parser   HTML Lexer
//!          HTML-decode   Anomaly Score   Structure Δ    Event Attrs
//!          Base64        Pattern Match   Tautology      Script Tags
//! ```

#![deny(clippy::unwrap_used)]
#![warn(missing_docs)]

pub mod config;
pub mod decoder;
pub mod detection;
pub mod engine;
pub mod fast_path;
pub mod json_graphql;
pub mod rules;
pub mod sql_analyzer;
pub mod xss_analyzer;


pub use config::WafConfig;
pub use engine::{WafEngine, WafDecision, ThreatInfo, HttpRequest};

/// Anomaly score threshold levels (OWASP CRS compatible)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParanoiaLevel {
    /// Level 1: Low false positives, catches obvious attacks
    Low = 1,
    /// Level 2: Moderate — recommended for production
    Medium = 2,
    /// Level 3: High — may have false positives
    High = 3,
    /// Level 4: Paranoid — maximum security, requires tuning
    Paranoid = 4,
}

/// WAF inspection result
#[derive(Debug, Clone)]
pub enum WafVerdict {
    /// Request is clean
    Allow,
    /// Request matched rules but below threshold — log only
    Monitor {
        /// Anomaly score
        score: u32,
        /// Matched rules
        matches: Vec<RuleMatch>,
    },
    /// Request blocked
    Block {
        /// Anomaly score
        score: u32,
        /// Matched rules
        matches: Vec<RuleMatch>,
        /// HTTP status to return (403 or 400)
        status: u16,
    },
}

/// A single matched WAF rule
#[derive(Debug, Clone)]
pub struct RuleMatch {
    /// Rule ID (e.g., 942100 for SQLi)
    pub rule_id: u32,
    /// Category
    pub category: AttackCategory,
    /// Severity score contributed
    pub score: u32,
    /// Human-readable message
    pub message: String,
    /// Which part of the request matched
    pub location: MatchLocation,
    /// The matched payload snippet (truncated)
    pub matched_data: String,
}

/// Attack categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttackCategory {
    /// SQL Injection
    SqlInjection,
    /// Cross-Site Scripting
    Xss,
    /// Path Traversal / Local File Inclusion
    PathTraversal,
    /// Command Injection
    CommandInjection,
    /// Remote Code Execution
    Rce,
    /// Protocol violation
    ProtocolViolation,
    /// Request anomaly (unusual headers, encoding, etc.)
    RequestAnomaly,
}

/// Where in the request the match occurred
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchLocation {
    /// URL path
    Path,
    /// Query string parameter
    QueryParam(String),
    /// Request body
    Body,
    /// HTTP header
    Header(String),
    /// Cookie value
    Cookie(String),
}

/// WAF errors
#[derive(Debug, thiserror::Error)]
pub enum WafError {
    /// Configuration error
    #[error("WAF config error: {0}")]
    Config(String),
    /// Rule compilation error
    #[error("Rule compilation error: {0}")]
    RuleCompile(String),
    /// Internal error
    #[error("WAF internal error: {0}")]
    Internal(String),
}
