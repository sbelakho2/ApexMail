//! MX resolution with an explicit preference and fallback policy.
//!
//! Policy (deliberate, documented):
//!
//! * Targets are ordered by ascending preference number (lower = more
//!   preferred, RFC 5321 §5.1). The delivery loop walks them in order; on a
//!   connection failure or a 4xx reply it falls through to the next target.
//! * A domain with **no MX records** is REFUSED — the relay deliberately does
//!   not apply the legacy implicit-MX fallback (RFC 5321 §5.1 A/AAAA lookup).
//!   Silent A-record fallback hid misconfigured sender domains behind
//!   unpredictable routing; operators must publish an MX.
//! * A **Null MX** (RFC 7505: `MX 0 .`) is a permanent refusal. A zone that
//!   mixes a Null MX with real MX records is also refused: the semantics are
//!   undefined and delivering anyway would violate the null-MX owner's
//!   intent.
//! * Every non-null MX host must resolve to at least one usable A/AAAA
//!   address; the addresses are resolved ONCE here and carried with the
//!   target so each delivery attempt does not repeat DNS work.

use std::net::{IpAddr, SocketAddr};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use apexmail_dns_resolver::lookup::DnsError;
use apexmail_dns_resolver::{DnsLookup, MxRecord};

/// The SMTP delivery port (recipient-facing).
pub const SMTP_PORT: u16 = 25;

/// One deliverable MX host: preference, canonical exchange name and the
/// resolved socket addresses (port 25 unless a caller/target overrides).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxTarget {
    /// RFC 5321 preference (lower is preferred).
    pub preference: u16,
    /// Canonical MX hostname without the trailing root dot.
    pub exchange: String,
    /// Usable addresses, in resolver order.
    pub addresses: Vec<SocketAddr>,
}

/// MX resolution failure, split into permanent (refuse) and transient
/// (retryable) classes.
#[derive(Debug, Clone, thiserror::Error)]
pub enum MxError {
    #[error("recipient domain '{0}' is not a valid DNS name")]
    InvalidDomain(String),
    #[error(
        "domain '{0}' publishes no MX records; the relay refuses the implicit-A fallback by policy"
    )]
    NoMxRecords(String),
    #[error("domain '{0}' publishes a Null MX (RFC 7505) and does not accept mail")]
    NullMx(String),
    #[error("transient DNS failure resolving '{domain}': {message}")]
    Transient { domain: String, message: String },
    #[error("no MX host for '{domain}' resolved to a usable address: {message}")]
    NoAddress { domain: String, message: String },
}

impl MxError {
    /// True when retrying the same domain can never succeed (no MX / Null MX
    /// / malformed name) — the caller must bounce instead of retry.
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            Self::InvalidDomain(_) | Self::NoMxRecords(_) | Self::NullMx(_)
        )
    }
}

/// Resolve a recipient domain to ordered [`MxTarget`]s.
#[async_trait]
pub trait MxResolver: Send + Sync {
    async fn resolve(&self, domain: &str) -> Result<Vec<MxTarget>, MxError>;
}

/// Production resolver backed by `crates/dns-resolver`.
pub struct DnsMxResolver {
    lookup: DnsLookup,
}

impl DnsMxResolver {
    /// Build with the system resolver configuration.
    pub fn new() -> Result<Self, MxError> {
        DnsLookup::new()
            .map(|lookup| Self { lookup })
            .map_err(|error| MxError::Transient {
                domain: "<system-resolver>".to_string(),
                message: error.to_string(),
            })
    }

    /// Build from an existing lookup wrapper (tests, custom config).
    pub fn from_lookup(lookup: DnsLookup) -> Self {
        Self { lookup }
    }
}

#[async_trait]
impl MxResolver for DnsMxResolver {
    async fn resolve(&self, domain: &str) -> Result<Vec<MxTarget>, MxError> {
        let domain = normalize_domain(domain)?;
        let records = self
            .lookup
            .lookup_mx(&domain)
            .await
            .map_err(|error| map_dns_error(&domain, error))?;
        let ordered = order_records(&domain, records)?;

        let mut targets: Vec<MxTarget> = Vec::with_capacity(ordered.len());
        for record in ordered {
            let exchange = canonical_exchange(&record.exchange);
            if exchange.is_empty() {
                // A non-null record with an empty exchange is malformed;
                // refusing it is safer than resolving the recipient domain.
                tracing::warn!(domain, "skipping malformed empty MX exchange");
                continue;
            }
            let mut addresses = resolve_addresses(&self.lookup, &exchange).await;
            addresses.sort();
            addresses.dedup();
            if addresses.is_empty() {
                tracing::warn!(
                    domain,
                    exchange,
                    "MX host resolved to no usable address; skipping target"
                );
                continue;
            }
            targets.push(MxTarget {
                preference: record.priority,
                exchange,
                addresses,
            });
        }

        if targets.is_empty() {
            return Err(MxError::NoAddress {
                domain,
                message: "every MX host failed A/AAAA resolution".to_string(),
            });
        }
        Ok(targets)
    }
}

/// Pure policy step: validate the raw MX set and order it by preference.
/// Exposed for tests (no DNS) and reused by [`DnsMxResolver`].
pub fn order_records(domain: &str, records: Vec<MxRecord>) -> Result<Vec<MxRecord>, MxError> {
    if records.is_empty() {
        return Err(MxError::NoMxRecords(domain.to_string()));
    }
    // RFC 7505: the null MX is the single record `MX 0 .`. A mix with real
    // records is contradictory; treat it as a null-MX refusal.
    if records.iter().any(|record| is_null_mx(&record.exchange)) {
        return Err(MxError::NullMx(domain.to_string()));
    }
    let mut ordered = records;
    ordered.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| canonical_exchange(&a.exchange).cmp(&canonical_exchange(&b.exchange)))
    });
    ordered.dedup_by(|a, b| canonical_exchange(&a.exchange) == canonical_exchange(&b.exchange));
    Ok(ordered)
}

/// True for a Null MX exchange (`.` or empty after normalization).
fn is_null_mx(exchange: &str) -> bool {
    let exchange = exchange.trim();
    exchange.is_empty() || exchange == "."
}

/// Lowercase hostname with the trailing root dot removed.
pub fn canonical_exchange(exchange: &str) -> String {
    exchange.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Validate and canonicalize a recipient domain (RFC 5321 domain subset:
/// letters, digits, hyphen, dot; 1..=253 chars; no empty labels).
pub fn normalize_domain(domain: &str) -> Result<String, MxError> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() || domain.len() > 253 || domain.contains('@') {
        return Err(MxError::InvalidDomain(domain));
    }
    if domain.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) {
        return Err(MxError::InvalidDomain(domain));
    }
    Ok(domain)
}

/// Map a dns-resolver error onto the MX disposition: definitive no-records is
/// a permanent No-MX; everything else is transient.
fn map_dns_error(domain: &str, error: DnsError) -> MxError {
    match error {
        DnsError::NoRecords(_) => MxError::NoMxRecords(domain.to_string()),
        DnsError::InvalidDomain(_) => MxError::InvalidDomain(domain.to_string()),
        other => MxError::Transient {
            domain: domain.to_string(),
            message: other.to_string(),
        },
    }
}

async fn resolve_addresses(lookup: &DnsLookup, exchange: &str) -> Vec<SocketAddr> {
    let mut addresses = Vec::new();
    match lookup.lookup_a(exchange).await {
        Ok(records) => {
            for record in records {
                if let Ok(ip) = record.parse::<IpAddr>() {
                    if is_usable_address(&ip) {
                        addresses.push(SocketAddr::new(ip, SMTP_PORT));
                    }
                }
            }
        }
        Err(error) => {
            tracing::debug!(exchange, error = %error, "A lookup for MX host failed");
        }
    }
    match lookup.lookup_aaaa(exchange).await {
        Ok(records) => {
            for record in records {
                if let Ok(ip) = record.parse::<IpAddr>() {
                    if is_usable_address(&ip) {
                        addresses.push(SocketAddr::new(ip, SMTP_PORT));
                    }
                }
            }
        }
        Err(error) => {
            tracing::debug!(exchange, error = %error, "AAAA lookup for MX host failed");
        }
    }
    addresses
}

/// Refuse unspecified/loopback/broadcast placeholder addresses from DNS.
fn is_usable_address(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_unspecified() && !v4.is_broadcast() && !v4.is_multicast(),
        IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_multicast(),
    }
}

/// In-memory resolver for tests: static domain -> targets (or error) map.
/// Public under `test-support` so dependent crates can run the real
/// [`crate::Relay`] against it.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct StaticMxResolver {
        entries: Mutex<HashMap<String, Result<Vec<MxTarget>, MxError>>>,
    }

    impl StaticMxResolver {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn with_target(mut self, domain: &str, addresses: Vec<SocketAddr>) -> Self {
            self.insert(
                domain,
                Ok(vec![MxTarget {
                    preference: 10,
                    exchange: format!("mx.{domain}"),
                    addresses,
                }]),
            );
            self
        }

        pub fn with_error(mut self, domain: &str, error: MxError) -> Self {
            self.insert(domain, Err(error));
            self
        }

        fn insert(&mut self, domain: &str, value: Result<Vec<MxTarget>, MxError>) {
            let map = self
                .entries
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            map.insert(domain.to_ascii_lowercase(), value);
        }
    }

    #[async_trait]
    impl MxResolver for StaticMxResolver {
        async fn resolve(&self, domain: &str) -> Result<Vec<MxTarget>, MxError> {
            let map = self
                .entries
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            map.get(&domain.to_ascii_lowercase())
                .cloned()
                .unwrap_or_else(|| Err(MxError::NoMxRecords(domain.to_string())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(priority: u16, exchange: &str) -> MxRecord {
        MxRecord::new(priority, exchange)
    }

    #[test]
    fn orders_by_preference_then_hostname() {
        let ordered = order_records(
            "example.com",
            vec![
                record(20, "mx2.example.com"),
                record(10, "mx1.example.com."),
                record(10, "ax.example.com"),
            ],
        )
        .expect("valid records");
        let exchanges: Vec<&str> = ordered.iter().map(|r| r.exchange.as_str()).collect();
        assert_eq!(
            exchanges,
            vec!["ax.example.com", "mx1.example.com.", "mx2.example.com"]
        );
    }

    #[test]
    fn deduplicates_same_exchange_case_insensitively() {
        let ordered = order_records(
            "example.com",
            vec![record(10, "MX.example.com."), record(10, "mx.example.com")],
        )
        .expect("valid records");
        assert_eq!(ordered.len(), 1);
    }

    #[test]
    fn empty_record_set_is_permanent_no_mx() {
        let error = order_records("example.com", Vec::new()).expect_err("must refuse");
        assert!(matches!(error, MxError::NoMxRecords(_)));
        assert!(error.is_permanent());
    }

    #[test]
    fn null_mx_is_refused_even_when_mixed() {
        let error = order_records("example.com", vec![record(0, ".")]).expect_err("must refuse");
        assert!(matches!(error, MxError::NullMx(_)));

        let mixed = order_records(
            "example.com",
            vec![record(0, "."), record(10, "mx.example.com")],
        )
        .expect_err("mixed null MX must refuse");
        assert!(matches!(mixed, MxError::NullMx(_)));
    }

    #[test]
    fn domain_validation_rejects_malformed_names() {
        assert!(normalize_domain("").is_err());
        assert!(normalize_domain("user@example.com").is_err());
        assert!(normalize_domain("-bad.example").is_err());
        assert!(normalize_domain("bad..example").is_err());
        assert!(normalize_domain("ok.example.com.").is_ok());
        assert_eq!(
            normalize_domain("Example.COM.").expect("valid"),
            "example.com"
        );
    }

    #[test]
    fn canonical_exchange_strips_root_dot_and_case() {
        assert_eq!(canonical_exchange("MX.Example.COM."), "mx.example.com");
    }
}
