#![allow(clippy::doc_lazy_continuation)]
//! # Threat Intelligence — Feed Ingestion & Reputation
//!
//! Aggregates threat intelligence from multiple sources to provide
//! real-time IP/domain reputation scoring for the mail pipeline://!
//! 1. **Feed ingestion** — Parses Spamhaus DROP, AbuseIPDB CSV, Cymru bogon lists,
//! and other standard formats
//! 2. **IP blocklist** — Efficient in-memory IP set (v4/v6) with CIDR support
//! 3. **Domain blocklist** — Exact + wildcard domain matching
//! 4. **Reputation scoring** — Multi-source composite score //! 5. **TTL management** — Automatic expiration of stale entries
//!
//! ## Design
//!
//! The threat-intel store is designed for concurrent reads with infrequent writes
//! (feed refresh). All lookups are O(1) via DashMap, with CIDR queries using
//! precomputed prefix masks.

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![warn(missing_docs)]

pub mod background_task;
pub mod config;
pub mod domain_blocklist;
pub mod engine;
pub mod ip_blocklist;
pub mod reputation;
pub mod stix_taxii;

pub use engine::ThreatIntelEngine;
pub use ip_blocklist::{
    IpBlockEntry, IpBlocklist, Ipv6Blocklist, ThreatCategory, UnifiedIpBlocklist,
};

use thiserror::Error;

/// Threat intel errors
#[derive(Debug, Error)]
pub enum ThreatIntelError {
    /// Feed parsing error
    #[error("Feed parse error: {0}")]
    ParseError(String),

    /// Network error during feed fetch
    #[error("Fetch error: {0}")]
    FetchError(String),

    /// Invalid IP address
    #[error("Invalid IP: {0}")]
    InvalidIp(String),

    /// Invalid CIDR notation
    #[error("Invalid CIDR: {0}")]
    InvalidCidr(String),
}
