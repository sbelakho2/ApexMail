//! IP blocklist with CIDR support
//!
//! Stores blocked IP addresses and CIDR ranges. Supports://! - Individual IPv4 addresses
//! - Individual IPv6 addresses //! - CIDR notation (e.g., 192.168.0.0/16, 2001:db8::/32)
//! - Source attribution (which feed added the entry)
//! - TTL-based expiration

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

/// A blocklist entry
#[derive(Debug, Clone)]
pub struct IpBlockEntry {
/// The blocked IP or CIDR
    pub cidr: String,
/// Source feed name
    pub source: String,
/// Threat category
    pub category: ThreatCategory,
/// Confidence score (0.0 - 10.0)
    pub confidence: f64,
/// When this entry was added
    pub added_at: DateTime<Utc>,
/// When this entry expires
    pub expires_at: DateTime<Utc>,
}

/// Threat category for an IP
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThreatCategory {
/// Known spam source
    Spam,
/// Known malware C2/distribution
    Malware,
/// Botnet member
    Botnet,
/// Brute force / scanner
    Scanner,
/// Phishing infrastructure
    Phishing,
/// Hijacked netblock
    Hijacked,
/// Bogon / unallocated
    Bogon,
/// Generic bad reputation
    BadReputation,
}

impl std::fmt::Display for ThreatCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatCategory::Spam => write!(f, "SPAM"),
            ThreatCategory::Malware => write!(f, "MALWARE"),
            ThreatCategory::Botnet => write!(f, "BOTNET"),
            ThreatCategory::Scanner => write!(f, "SCANNER"),
            ThreatCategory::Phishing => write!(f, "PHISHING"),
            ThreatCategory::Hijacked => write!(f, "HIJACKED"),
            ThreatCategory::Bogon => write!(f, "BOGON"),
            ThreatCategory::BadReputation => write!(f, "BAD_REP"),
        }
    }
}

/// CIDR range for matching
#[derive(Debug, Clone)]
struct CidrRange {
    network: u32,
    mask: u32,
/// Prefix length for sorting (more specific = higher priority)
    prefix_len: u8,
    entry: Arc<IpBlockEntry>,
}

/// Thread-safe IP blocklist
#[derive(Clone)]
pub struct IpBlocklist {
/// Exact IP matches (for /32 entries)
    exact: Arc<DashMap<u32, Arc<IpBlockEntry>>>,
/// CIDR ranges (for prefix matches)
    cidrs: Arc<parking_lot::RwLock<Vec<CidrRange>>>,
/// Maximum entries
    max_entries: usize,
}

impl IpBlocklist {
/// Create a new IP blocklist
    pub fn new(max_entries: usize) -> Self {
        Self {
            exact: Arc::new(DashMap::new()),
            cidrs: Arc::new(parking_lot::RwLock::new(Vec::new())),
            max_entries,
        }
    }

/// Add an individual IP to the blocklist
    pub fn add_ip(&self, ip: Ipv4Addr, entry: IpBlockEntry) -> bool {
        if self.exact.len() >= self.max_entries {
            return false;
        }
        let ip_u32 = u32::from(ip);
        self.exact.insert(ip_u32, Arc::new(entry));
        true
    }

/// Add a CIDR range to the blocklist
    pub fn add_cidr(&self, cidr_str: &str, entry: IpBlockEntry) -> Result<(), crate::ThreatIntelError> {
        let (network, prefix_len) = parse_cidr(cidr_str)?;
        let mask = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
        let masked_network = network & mask;

        let mut cidrs = self.cidrs.write();
        cidrs.push(CidrRange {
            network: masked_network,
            mask,
            prefix_len,
            entry: Arc::new(entry),
        });
        Ok(())
    }

/// Optimize CIDR list by sorting (most specific prefixes first)
/// Call this after bulk loading entries for faster lookups
    pub fn optimize(&self) {
        let mut cidrs = self.cidrs.write();
// Sort by prefix length descending (more specific = checked first)
        cidrs.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));
    }

/// Check if an IP is blocked
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<Arc<IpBlockEntry>> {
        let ip_u32 = u32::from(ip);
        let now = Utc::now();

// Check exact match first
        if let Some(entry) = self.exact.get(&ip_u32) {
            if entry.expires_at > now {
                return Some(entry.clone());
            }
        }

// Check CIDR ranges
        let cidrs = self.cidrs.read();
        for range in cidrs.iter() {
            if (ip_u32 & range.mask) == range.network && range.entry.expires_at > now {
                return Some(range.entry.clone());
            }
        }

        None
    }

/// Check if an IP string is blocked
    pub fn lookup_str(&self, ip_str: &str) -> Option<Arc<IpBlockEntry>> {
        ip_str.parse::<Ipv4Addr>().ok().and_then(|ip| self.lookup(ip))
    }

/// Number of exact entries
    pub fn exact_count(&self) -> usize {
        self.exact.len()
    }

/// Number of CIDR ranges
    pub fn cidr_count(&self) -> usize {
        self.cidrs.read().len()
    }

/// Remove expired entries
    pub fn purge_expired(&self) -> usize {
        let now = Utc::now();
        let mut removed = 0;

// Purge exact entries
        self.exact.retain(|_, entry| {
            let keep = entry.expires_at > now;
            if !keep {
                removed += 1;
            }
            keep
        });

// Purge CIDR ranges
        let mut cidrs = self.cidrs.write();
        let before = cidrs.len();
        cidrs.retain(|range| range.entry.expires_at > now);
        removed += before - cidrs.len();

        removed
    }
}

impl Default for IpBlocklist {
    fn default() -> Self {
        Self::new(1_000_000)
    }
}

/// Minimum allowed CIDR prefix length to prevent overly broad blocks.
/// /8 is the largest allowed (16 million IPs). /0-/7 are rejected to prevent
/// accidental or malicious internet-wide blocks.
const MIN_CIDR_PREFIX_LEN: u8 = 8;

/// Parse a CIDR string like "192.168.0.0/16"
/// # Security
/// - Rejects prefix lengths 0-7 to prevent blocking the entire internet or large portions of it.
/// - Rejects prefix lengths > 32 (invalid for IPv4).
/// - Use `MIN_CIDR_PREFIX_LEN` constant to see the minimum allowed prefix.
fn parse_cidr(cidr: &str) -> Result<(u32, u8), crate::ThreatIntelError> {
    let parts: Vec<&str> = cidr.trim().split('/').collect();
    if parts.len() != 2 {
        return Err(crate::ThreatIntelError::InvalidCidr(cidr.into()));
    }

    let ip: Ipv4Addr = parts[0].parse()
        .map_err(|_| crate::ThreatIntelError::InvalidIp(parts[0].into()))?;
    let prefix_len: u8 = parts[1].parse()
        .map_err(|_| crate::ThreatIntelError::InvalidCidr(cidr.into()))?;

// Security:Reject prefix lengths that are too broad (0-7 would block huge swaths of internet)
    if prefix_len < MIN_CIDR_PREFIX_LEN {
        return Err(crate::ThreatIntelError::InvalidCidr(
            format!(
                "Prefix length {} is too broad (minimum is /{}). Rejecting to prevent accidental internet-wide blocks.",
                prefix_len, MIN_CIDR_PREFIX_LEN
            ),
        ));
    }

    if prefix_len > 32 {
        return Err(crate::ThreatIntelError::InvalidCidr(
            format!("Prefix length {} > 32", prefix_len),
        ));
    }

    Ok((u32::from(ip), prefix_len))
}

/// Parse a Spamhaus DROP format feed
pub fn parse_spamhaus_drop(content: &str, source: &str, ttl_secs: u64) -> Vec<(String, IpBlockEntry)> {
    let now = Utc::now();
    let expires = now + chrono::Duration::seconds(ttl_secs as i64);

    content
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with(';')
        })
        .filter_map(|line| {
            let cidr = line.split(';').next()?.trim();
            if cidr.contains('/') {
                Some((
                    cidr.to_string(),
                    IpBlockEntry {
                        cidr: cidr.to_string(),
                        source: source.to_string(),
                        category: ThreatCategory::Hijacked,
                        confidence: 9.0,
                        added_at: now,
                        expires_at: expires,
                    },
                ))
            } else {
                None
            }
        })
        .collect()
}

/// Parse a plain-text IP list (one IP/CIDR per line, # comments)
pub fn parse_plain_text_list(content: &str, source: &str, category: ThreatCategory, ttl_secs: u64) -> Vec<(String, IpBlockEntry)> {
    let now = Utc::now();
    let expires = now + chrono::Duration::seconds(ttl_secs as i64);

    content
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .map(|line| {
            let entry = line.trim().to_string();
            let block_entry = IpBlockEntry {
                cidr: entry.clone(),
                source: source.to_string(),
                category,
                confidence: 7.0,
                added_at: now,
                expires_at: expires,
            };
            (entry, block_entry)
        })
        .collect()
}

// =============================================================================
// IPv6 Blocklist
// =============================================================================

/// CIDR range for IPv6 matching
#[derive(Debug, Clone)]
struct Ipv6CidrRange {
    network: u128,
    mask: u128,
/// Prefix length for sorting (more specific = higher priority)
    prefix_len: u8,
    entry: Arc<IpBlockEntry>,
}

/// Thread-safe IPv6 blocklist
#[derive(Clone)]
pub struct Ipv6Blocklist {
/// Exact IPv6 matches (for /128 entries)
    exact: Arc<DashMap<u128, Arc<IpBlockEntry>>>,
/// CIDR ranges (for prefix matches)
    cidrs: Arc<parking_lot::RwLock<Vec<Ipv6CidrRange>>>,
/// Maximum entries
    max_entries: usize,
}

impl Ipv6Blocklist {
/// Create a new IPv6 blocklist
    pub fn new(max_entries: usize) -> Self {
        Self {
            exact: Arc::new(DashMap::new()),
            cidrs: Arc::new(parking_lot::RwLock::new(Vec::new())),
            max_entries,
        }
    }

/// Add an individual IPv6 to the blocklist
    pub fn add_ip(&self, ip: Ipv6Addr, entry: IpBlockEntry) -> bool {
        if self.exact.len() >= self.max_entries {
            return false;
        }
        let ip_u128 = u128::from(ip);
        self.exact.insert(ip_u128, Arc::new(entry));
        true
    }

/// Add a CIDR range to the blocklist
    pub fn add_cidr(&self, cidr_str: &str, entry: IpBlockEntry) -> Result<(), crate::ThreatIntelError> {
        let (network, prefix_len) = parse_ipv6_cidr(cidr_str)?;
        let mask = if prefix_len == 0 { 0 } else { !0u128 << (128 - prefix_len) };
        let masked_network = network & mask;

        let mut cidrs = self.cidrs.write();
        cidrs.push(Ipv6CidrRange {
            network: masked_network,
            mask,
            prefix_len,
            entry: Arc::new(entry),
        });
        Ok(())
    }

/// Optimize CIDR list by sorting (most specific prefixes first)
/// Call this after bulk loading entries for faster lookups
    pub fn optimize(&self) {
        let mut cidrs = self.cidrs.write();
        cidrs.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));
    }

/// Check if an IPv6 is blocked
    pub fn lookup(&self, ip: Ipv6Addr) -> Option<Arc<IpBlockEntry>> {
        let ip_u128 = u128::from(ip);
        let now = Utc::now();

// Check exact match first
        if let Some(entry) = self.exact.get(&ip_u128) {
            if entry.expires_at > now {
                return Some(entry.clone());
            }
        }

// Check CIDR ranges
        let cidrs = self.cidrs.read();
        for range in cidrs.iter() {
            if (ip_u128 & range.mask) == range.network && range.entry.expires_at > now {
                return Some(range.entry.clone());
            }
        }

        None
    }

/// Check if an IPv6 string is blocked
    pub fn lookup_str(&self, ip_str: &str) -> Option<Arc<IpBlockEntry>> {
        ip_str.parse::<Ipv6Addr>().ok().and_then(|ip| self.lookup(ip))
    }

/// Number of exact entries
    pub fn exact_count(&self) -> usize {
        self.exact.len()
    }

/// Number of CIDR ranges
    pub fn cidr_count(&self) -> usize {
        self.cidrs.read().len()
    }

/// Remove expired entries
    pub fn purge_expired(&self) -> usize {
        let now = Utc::now();
        let mut removed = 0;

// Purge exact entries
        self.exact.retain(|_, entry| {
            let keep = entry.expires_at > now;
            if !keep {
                removed += 1;
            }
            keep
        });

// Purge CIDR ranges
        let mut cidrs = self.cidrs.write();
        let before = cidrs.len();
        cidrs.retain(|range| range.entry.expires_at > now);
        removed += before - cidrs.len();

        removed
    }
}

impl Default for Ipv6Blocklist {
    fn default() -> Self {
        Self::new(500_000)
    }
}

/// Parse an IPv6 CIDR string like "2001:db8::/32"
fn parse_ipv6_cidr(cidr: &str) -> Result<(u128, u8), crate::ThreatIntelError> {
    let parts: Vec<&str> = cidr.trim().split('/').collect();
    if parts.len() != 2 {
        return Err(crate::ThreatIntelError::InvalidCidr(cidr.into()));
    }

    let ip: Ipv6Addr = parts[0].parse()
        .map_err(|_| crate::ThreatIntelError::InvalidIp(parts[0].into()))?;
    let prefix_len: u8 = parts[1].parse()
        .map_err(|_| crate::ThreatIntelError::InvalidCidr(cidr.into()))?;

    if prefix_len > 128 {
        return Err(crate::ThreatIntelError::InvalidCidr(
            format!("IPv6 prefix length {} > 128", prefix_len),
        ));
    }

    Ok((u128::from(ip), prefix_len))
}

// =============================================================================
// Unified IP Blocklist (handles both IPv4 and IPv6)
// =============================================================================

/// Unified blocklist that handles both IPv4 and IPv6
#[derive(Clone)]
pub struct UnifiedIpBlocklist {
/// IPv4 blocklist storage.
    pub v4: IpBlocklist,
/// IPv6 blocklist storage.
    pub v6: Ipv6Blocklist,
}

impl UnifiedIpBlocklist {
/// Create a unified blocklist with independent capacities for IPv4 and IPv6.
    pub fn new(max_v4: usize, max_v6: usize) -> Self {
        Self {
            v4: IpBlocklist::new(max_v4),
            v6: Ipv6Blocklist::new(max_v6),
        }
    }

/// Lookup any IP address string (auto-detects v4 vs v6)
    pub fn lookup_str(&self, ip_str: &str) -> Option<Arc<IpBlockEntry>> {
// Try IPv4 first (more common)
        if let Some(entry) = self.v4.lookup_str(ip_str) {
            return Some(entry);
        }
// Then try IPv6
        self.v6.lookup_str(ip_str)
    }

/// Add a CIDR range (auto-detects v4 vs v6)
    pub fn add_cidr(&self, cidr_str: &str, entry: IpBlockEntry) -> Result<(), crate::ThreatIntelError> {
// Heuristic:IPv6 addresses contain colons
        if cidr_str.contains(':') {
            self.v6.add_cidr(cidr_str, entry)
        } else {
            self.v4.add_cidr(cidr_str, entry)
        }
    }

/// Remove expired entries from both blocklists
    pub fn purge_expired(&self) -> usize {
        self.v4.purge_expired() + self.v6.purge_expired()
    }

/// Optimize both blocklists for faster lookups
/// Call after bulk loading entries
    pub fn optimize(&self) {
        self.v4.optimize();
        self.v6.optimize();
    }
}

impl Default for UnifiedIpBlocklist {
    fn default() -> Self {
        Self::new(1_000_000, 500_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(cidr: &str) -> IpBlockEntry {
        IpBlockEntry {
            cidr: cidr.into(),
            source: "test".into(),
            category: ThreatCategory::Spam,
            confidence: 9.0,
            added_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
        }
    }

    #[test]
    fn test_exact_ip_lookup() {
        let bl = IpBlocklist::new(1000);
        let ip: Ipv4Addr = "192.168.1.1".parse().expect("valid IP");
        bl.add_ip(ip, make_entry("192.168.1.1"));
        assert!(bl.lookup(ip).is_some());
        assert!(bl.lookup("10.0.0.1".parse().expect("valid")).is_none());
    }

    #[test]
    fn test_cidr_lookup() {
        let bl = IpBlocklist::new(1000);
        bl.add_cidr("10.0.0.0/8", make_entry("10.0.0.0/8")).expect("valid CIDR");
        assert!(bl.lookup("10.1.2.3".parse().expect("valid")).is_some());
        assert!(bl.lookup("10.255.0.1".parse().expect("valid")).is_some());
        assert!(bl.lookup("11.0.0.1".parse().expect("valid")).is_none());
    }

    #[test]
    fn test_cidr_24() {
        let bl = IpBlocklist::new(1000);
        bl.add_cidr("192.168.1.0/24", make_entry("192.168.1.0/24")).expect("valid");
        assert!(bl.lookup("192.168.1.100".parse().expect("valid")).is_some());
        assert!(bl.lookup("192.168.2.100".parse().expect("valid")).is_none());
    }

    #[test]
    fn test_string_lookup() {
        let bl = IpBlocklist::new(1000);
        bl.add_ip("1.2.3.4".parse().expect("valid"), make_entry("1.2.3.4"));
        assert!(bl.lookup_str("1.2.3.4").is_some());
        assert!(bl.lookup_str("5.6.7.8").is_none());
        assert!(bl.lookup_str("not-an-ip").is_none());
    }

    #[test]
    fn test_parse_spamhaus_drop() {
        let content = "; Spamhaus DROP List\n; Last-Modified: 2024-01-01\n\n1.2.3.0/24 ; SBL000001\n5.6.0.0/16 ; SBL000002\n";
        let entries = parse_spamhaus_drop(content, "Spamhaus DROP", 86400);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, "1.2.3.0/24");
        assert_eq!(entries[1].0, "5.6.0.0/16");
    }

    #[test]
    fn test_parse_plain_text() {
        let content = "# Comment\n192.168.0.0/16\n10.0.0.0/8\n# Another comment\n";
        let entries = parse_plain_text_list(content, "test", ThreatCategory::Bogon, 3600);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_expired_entries() {
        let bl = IpBlocklist::new(1000);
        let ip: Ipv4Addr = "1.2.3.4".parse().expect("valid");
        let mut entry = make_entry("1.2.3.4");
        entry.expires_at = Utc::now() - chrono::Duration::hours(1); // Already expired
        bl.add_ip(ip, entry);
        assert!(bl.lookup(ip).is_none(), "Expired entry should not match");
    }

    #[test]
    fn test_purge_expired() {
        let bl = IpBlocklist::new(1000);
        let mut expired_entry = make_entry("1.2.3.4");
        expired_entry.expires_at = Utc::now() - chrono::Duration::hours(1);
        bl.add_ip("1.2.3.4".parse().expect("valid"), expired_entry);
        bl.add_ip("5.6.7.8".parse().expect("valid"), make_entry("5.6.7.8"));

        let removed = bl.purge_expired();
        assert_eq!(removed, 1);
        assert_eq!(bl.exact_count(), 1);
    }

    #[test]
    fn test_invalid_cidr() {
        let bl = IpBlocklist::new(1000);
        assert!(bl.add_cidr("not-a-cidr", make_entry("x")).is_err());
        assert!(bl.add_cidr("1.2.3.4/33", make_entry("x")).is_err());
    }

// =========================================================================
// IPv6 Tests
// =========================================================================

    #[test]
    fn test_ipv6_exact_lookup() {
        let bl = Ipv6Blocklist::new(1000);
        let ip: Ipv6Addr = "2001:db8::1".parse().expect("valid IPv6");
        bl.add_ip(ip, make_entry("2001:db8::1"));
        assert!(bl.lookup(ip).is_some());
        assert!(bl.lookup("2001:db8::2".parse().expect("valid")).is_none());
    }

    #[test]
    fn test_ipv6_cidr_lookup() {
        let bl = Ipv6Blocklist::new(1000);
        bl.add_cidr("2001:db8::/32", make_entry("2001:db8::/32")).expect("valid CIDR");
        assert!(bl.lookup("2001:db8::1".parse().expect("valid")).is_some());
        assert!(bl.lookup("2001:db8:1234::5678".parse().expect("valid")).is_some());
        assert!(bl.lookup("2001:db9::1".parse().expect("valid")).is_none());
    }

    #[test]
    fn test_ipv6_cidr_48() {
        let bl = Ipv6Blocklist::new(1000);
        bl.add_cidr("2001:db8:abcd::/48", make_entry("2001:db8:abcd::/48")).expect("valid");
        assert!(bl.lookup("2001:db8:abcd::1".parse().expect("valid")).is_some());
        assert!(bl.lookup("2001:db8:abcd:ffff::1".parse().expect("valid")).is_some());
        assert!(bl.lookup("2001:db8:abce::1".parse().expect("valid")).is_none());
    }

    #[test]
    fn test_ipv6_string_lookup() {
        let bl = Ipv6Blocklist::new(1000);
        bl.add_ip("::1".parse().expect("valid"), make_entry("::1"));
        assert!(bl.lookup_str("::1").is_some());
        assert!(bl.lookup_str("::2").is_none());
        assert!(bl.lookup_str("not-an-ip").is_none());
    }

    #[test]
    fn test_ipv6_invalid_cidr() {
        let bl = Ipv6Blocklist::new(1000);
        assert!(bl.add_cidr("not-a-cidr", make_entry("x")).is_err());
        assert!(bl.add_cidr("2001:db8::/129", make_entry("x")).is_err());
    }

    #[test]
    fn test_ipv6_purge_expired() {
        let bl = Ipv6Blocklist::new(1000);
        let mut expired = make_entry("2001:db8::1");
        expired.expires_at = Utc::now() - chrono::Duration::hours(1);
        bl.add_ip("2001:db8::1".parse().expect("valid"), expired);
        bl.add_ip("2001:db8::2".parse().expect("valid"), make_entry("2001:db8::2"));

        let removed = bl.purge_expired();
        assert_eq!(removed, 1);
        assert_eq!(bl.exact_count(), 1);
    }

// =========================================================================
// Unified Blocklist Tests
// =========================================================================

    #[test]
    fn test_unified_lookup() {
        let ubl = UnifiedIpBlocklist::new(1000, 1000);
        ubl.v4.add_ip("1.2.3.4".parse().expect("valid"), make_entry("1.2.3.4"));
        ubl.v6.add_ip("2001:db8::1".parse().expect("valid"), make_entry("2001:db8::1"));

        assert!(ubl.lookup_str("1.2.3.4").is_some());
        assert!(ubl.lookup_str("2001:db8::1").is_some());
        assert!(ubl.lookup_str("5.6.7.8").is_none());
        assert!(ubl.lookup_str("2001:db9::1").is_none());
    }

    #[test]
    fn test_unified_add_cidr_auto_detect() {
        let ubl = UnifiedIpBlocklist::new(1000, 1000);
        ubl.add_cidr("10.0.0.0/8", make_entry("10.0.0.0/8")).expect("valid v4");
        ubl.add_cidr("2001:db8::/32", make_entry("2001:db8::/32")).expect("valid v6");

        assert!(ubl.lookup_str("10.1.2.3").is_some());
        assert!(ubl.lookup_str("2001:db8::1234").is_some());
    }
}
