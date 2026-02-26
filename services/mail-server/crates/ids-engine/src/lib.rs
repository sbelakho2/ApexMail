//! # ApexMail IDS/IPS Engine
//!
//! Network-level Intrusion Detection/Prevention System providing:
//!
//! - **Signature-Based Detection**: Aho-Corasick multi-pattern engine compiled
//!   from Suricata/ET-compatible rule syntax for known exploit payloads.
//! - **Protocol Anomaly Detection**: Validates SMTP, HTTP, DNS, and TLS protocol
//!   state machines to catch malformed traffic used in exploits.
//! - **Payload Hashing**: SHA-256 hash matching against known malicious payloads.
//! - **Connection Tracking**: Stateful tracking of TCP sessions to detect
//!   port scans, SYN floods, and connection-based anomalies.
//! - **Alert & Action Pipeline**: Configurable responses (alert, drop, reject)
//!   with severity-based escalation.

#![deny(clippy::unwrap_used)]
#![warn(missing_docs)]

pub mod config;
pub mod connection_tracker;
pub mod engine;
pub mod protocol_analyzer;
pub mod signature;

pub use config::IdsConfig;
pub use engine::{IdsEngine, IdsVerdict, Alert, AlertSeverity};
pub use signature::{Signature, SignatureSet, SignatureAction};
pub use connection_tracker::ConnectionTracker;

/// IDS errors
#[derive(Debug, thiserror::Error)]
pub enum IdsError {
    /// Signature compilation error
    #[error("Signature error: {0}")]
    Signature(String),
    /// Configuration error
    #[error("Config error: {0}")]
    Config(String),
    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}
