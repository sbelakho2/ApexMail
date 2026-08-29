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
    entry: Arc<IpBlockEntry>,
}

impl CidrRange {
    /// Last address covered by this range (inclusive).
    fn end(&self) -> u32 {
        self.network | !self.mask
    }
}

/// Sorted interval index for O(log n) CIDR stabbing queries.
/// `ranges` is sorted by `network`; `prefix_max_end[i]` is the running
/// maximum of `end()` over `ranges[0..=i]` (non-decreasing), enabling a
/// binary-search containment check.
#[derive(Debug, Default)]
struct CidrIndex {
    ranges: Vec<CidrRange>,
    prefix_max_end: Vec<u32>,
}

impl CidrIndex {
    fn build(mut ranges: Vec<CidrRange>) -> Self {
        ranges.sort_by_key(|r| r.network);
        let mut prefix_max_end = Vec::with_capacity(ranges.len());
        let mut max_end = 0u32;
        for r in &ranges {
            max_end = max_end.max(r.end());
            prefix_max_end.push(max_end);
        }
        Self {
            ranges,
            prefix_max_end,
        }
    }

    /// Find a range containing `ip` (any match). Uses two binary searches;
    /// O(log n).
    fn find(&self, ip: u32) -> Option<&CidrRange> {
        // All ranges with network <= ip are candidates.
        let candidates = self.ranges.partition_point(|r| r.network <= ip);
        if candidates == 0 {
            return None;
        }
        // prefix_max_end is non-decreasing:first index whose running max
        // covers ip. If none within the candidate prefix covers ip, miss.
        let j = self.prefix_max_end.partition_point(|&e| e < ip);
        if j >= candidates {
            return None;
        }
        // At the first index where prefix_max_end >= ip, that range's own
        // end must be the new maximum, so ranges[j] contains ip.
        Some(&self.ranges[j])
    }
}

/// Thread-safe IP blocklist
#[derive(Clone)]
pub struct IpBlocklist {
    /// Exact IP matches (for /32 entries)
    exact: Arc<DashMap<u32, Arc<IpBlockEntry>>>,
    /// CIDR ranges (for prefix matches)
    cidrs: Arc<parking_lot::RwLock<Vec<CidrRange>>>,
    /// Lazily rebuilt sorted index over `cidrs` (None = stale).
    index: Arc<parking_lot::RwLock<Option<Arc<CidrIndex>>>>,
    /// Maximum entries (applies to exact AND CIDR storage)
    max_entries: usize,
}

impl IpBlocklist {
    /// Create a new IP blocklist
    pub fn new(max_entries: usize) -> Self {
        Self {
            exact: Arc::new(DashMap::new()),
            cidrs: Arc::new(parking_lot::RwLock::new(Vec::new())),
            index: Arc::new(parking_lot::RwLock::new(None)),
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

    /// Add a CIDR range to the blocklist.
    /// The CIDR store is bounded by the same `max_entries` cap as exact
    /// entries — previously CIDR ranges were appended without any limit,
    /// so a hostile or misbehaving feed could grow memory without bound.
    pub fn add_cidr(
        &self,
        cidr_str: &str,
        entry: IpBlockEntry,
    ) -> Result<(), crate::ThreatIntelError> {
        {
            let cidrs = self.cidrs.read();
            if cidrs.len() >= self.max_entries {
                return Err(crate::ThreatIntelError::BlocklistFull {
                    max_entries: self.max_entries,
                });
            }
        }
        let (network, prefix_len) = parse_cidr(cidr_str)?;
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        let masked_network = network & mask;

        let mut cidrs = self.cidrs.write();
        cidrs.push(CidrRange {
            network: masked_network,
            mask,
            entry: Arc::new(entry),
        });
        drop(cidrs);
        // Invalidate the sorted index; rebuilt lazily on next lookup.
        *self.index.write() = None;
        Ok(())
    }

    /// Optimize CIDR list (rebuild the sorted interval index).
    /// Call this after bulk loading entries for faster lookups
    pub fn optimize(&self) {
        let cidrs = self.cidrs.read().clone();
        let built = Arc::new(CidrIndex::build(cidrs));
        *self.index.write() = Some(built);
    }

    fn ensure_index(&self) -> Arc<CidrIndex> {
        if let Some(idx) = self.index.read().clone() {
            return idx;
        }
        let cidrs = self.cidrs.read().clone();
        let built = Arc::new(CidrIndex::build(cidrs));
        *self.index.write() = Some(Arc::clone(&built));
        built
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

        // CIDR lookup:binary search over the sorted interval index.
        let index = self.ensure_index();
        if let Some(range) = index.find(ip_u32) {
            if range.entry.expires_at > now {
                return Some(range.entry.clone());
            }
            // Rare path:the indexed hit is expired. Fall back to a linear
            // scan so a stale entry cannot shadow a live overlapping one.
            let cidrs = self.cidrs.read();
            for range in cidrs.iter() {
                if (ip_u32 & range.mask) == range.network && range.entry.expires_at > now {
                    return Some(range.entry.clone());
                }
            }
        }

        None
    }

    /// Check if an IP string is blocked
    pub fn lookup_str(&self, ip_str: &str) -> Option<Arc<IpBlockEntry>> {
        ip_str
            .parse::<Ipv4Addr>()
            .ok()
            .and_then(|ip| self.lookup(ip))
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
        drop(cidrs);
        *self.index.write() = None;

        removed
    }

    /// Remove all entries (exact and CIDR) that originate from `source`.
    /// Used by per-source feed-refresh merging so a refreshed feed replaces
    /// only its own entries (audit F6). Returns the number removed.
    pub fn remove_source(&self, source: &str) -> usize {
        let mut removed = 0;
        self.exact.retain(|_, entry| {
            let keep = !entry.source.eq_ignore_ascii_case(source);
            if !keep {
                removed += 1;
            }
            keep
        });
        let mut cidrs = self.cidrs.write();
        let before = cidrs.len();
        cidrs.retain(|range| !range.entry.source.eq_ignore_ascii_case(source));
        removed += before - cidrs.len();
        drop(cidrs);
        *self.index.write() = None;
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

    let ip: Ipv4Addr = parts[0]
        .parse()
        .map_err(|_| crate::ThreatIntelError::InvalidIp(parts[0].into()))?;
    let prefix_len: u8 = parts[1]
        .parse()
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
        return Err(crate::ThreatIntelError::InvalidCidr(format!(
            "Prefix length {} > 32",
            prefix_len
        )));
    }

    Ok((u32::from(ip), prefix_len))
}

/// Parse a Spamhaus DROP format feed
pub fn parse_spamhaus_drop(
    content: &str,
    source: &str,
    ttl_secs: u64,
) -> Vec<(String, IpBlockEntry)> {
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
pub fn parse_plain_text_list(
    content: &str,
    source: &str,
    category: ThreatCategory,
    ttl_secs: u64,
) -> Vec<(String, IpBlockEntry)> {
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
    entry: Arc<IpBlockEntry>,
}

impl Ipv6CidrRange {
    fn end(&self) -> u128 {
        self.network | !self.mask
    }
}

/// Sorted interval index for O(log n) IPv6 CIDR stabbing queries
/// (same construction as the IPv4 [`CidrIndex`]).
#[derive(Debug, Default)]
struct Ipv6CidrIndex {
    ranges: Vec<Ipv6CidrRange>,
    prefix_max_end: Vec<u128>,
}

impl Ipv6CidrIndex {
    fn build(mut ranges: Vec<Ipv6CidrRange>) -> Self {
        ranges.sort_by_key(|r| r.network);
        let mut prefix_max_end = Vec::with_capacity(ranges.len());
        let mut max_end = 0u128;
        for r in &ranges {
            max_end = max_end.max(r.end());
            prefix_max_end.push(max_end);
        }
        Self {
            ranges,
            prefix_max_end,
        }
    }

    fn find(&self, ip: u128) -> Option<&Ipv6CidrRange> {
        let candidates = self.ranges.partition_point(|r| r.network <= ip);
        if candidates == 0 {
            return None;
        }
        let j = self.prefix_max_end.partition_point(|&e| e < ip);
        if j >= candidates {
            return None;
        }
        Some(&self.ranges[j])
    }
}

/// Thread-safe IPv6 blocklist
#[derive(Clone)]
pub struct Ipv6Blocklist {
    /// Exact IPv6 matches (for /128 entries)
    exact: Arc<DashMap<u128, Arc<IpBlockEntry>>>,
    /// CIDR ranges (for prefix matches)
    cidrs: Arc<parking_lot::RwLock<Vec<Ipv6CidrRange>>>,
    /// Lazily rebuilt sorted index over `cidrs` (None = stale).
    index: Arc<parking_lot::RwLock<Option<Arc<Ipv6CidrIndex>>>>,
    /// Maximum entries
    max_entries: usize,
}

impl Ipv6Blocklist {
    /// Create a new IPv6 blocklist
    pub fn new(max_entries: usize) -> Self {
        Self {
            exact: Arc::new(DashMap::new()),
            cidrs: Arc::new(parking_lot::RwLock::new(Vec::new())),
            index: Arc::new(parking_lot::RwLock::new(None)),
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

    /// Add a CIDR range to the blocklist (bounded by `max_entries`).
    pub fn add_cidr(
        &self,
        cidr_str: &str,
        entry: IpBlockEntry,
    ) -> Result<(), crate::ThreatIntelError> {
        {
            let cidrs = self.cidrs.read();
            if cidrs.len() >= self.max_entries {
                return Err(crate::ThreatIntelError::BlocklistFull {
                    max_entries: self.max_entries,
                });
            }
        }
        let (network, prefix_len) = parse_ipv6_cidr(cidr_str)?;
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u128 << (128 - prefix_len)
        };
        let masked_network = network & mask;

        let mut cidrs = self.cidrs.write();
        cidrs.push(Ipv6CidrRange {
            network: masked_network,
            mask,
            entry: Arc::new(entry),
        });
        drop(cidrs);
        *self.index.write() = None;
        Ok(())
    }

    /// Optimize CIDR list (rebuild the sorted interval index).
    /// Call this after bulk loading entries for faster lookups
    pub fn optimize(&self) {
        let cidrs = self.cidrs.read().clone();
        let built = Arc::new(Ipv6CidrIndex::build(cidrs));
        *self.index.write() = Some(built);
    }

    fn ensure_index(&self) -> Arc<Ipv6CidrIndex> {
        if let Some(idx) = self.index.read().clone() {
            return idx;
        }
        let cidrs = self.cidrs.read().clone();
        let built = Arc::new(Ipv6CidrIndex::build(cidrs));
        *self.index.write() = Some(Arc::clone(&built));
        built
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

        // CIDR lookup:binary search over the sorted interval index.
        let index = self.ensure_index();
        if let Some(range) = index.find(ip_u128) {
            if range.entry.expires_at > now {
                return Some(range.entry.clone());
            }
            let cidrs = self.cidrs.read();
            for range in cidrs.iter() {
                if (ip_u128 & range.mask) == range.network && range.entry.expires_at > now {
                    return Some(range.entry.clone());
                }
            }
        }

        None
    }

    /// Check if an IPv6 string is blocked
    pub fn lookup_str(&self, ip_str: &str) -> Option<Arc<IpBlockEntry>> {
        ip_str
            .parse::<Ipv6Addr>()
            .ok()
            .and_then(|ip| self.lookup(ip))
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
        drop(cidrs);
        *self.index.write() = None;

        removed
    }

    /// Remove all entries (exact and CIDR) that originate from `source`
    /// (per-source refresh merging, audit F6).
    pub fn remove_source(&self, source: &str) -> usize {
        let mut removed = 0;
        self.exact.retain(|_, entry| {
            let keep = !entry.source.eq_ignore_ascii_case(source);
            if !keep {
                removed += 1;
            }
            keep
        });
        let mut cidrs = self.cidrs.write();
        let before = cidrs.len();
        cidrs.retain(|range| !range.entry.source.eq_ignore_ascii_case(source));
        removed += before - cidrs.len();
        drop(cidrs);
        *self.index.write() = None;
        removed
    }
}

impl Default for Ipv6Blocklist {
    fn default() -> Self {
        Self::new(500_000)
    }
}

/// Minimum allowed IPv6 CIDR prefix length. Mirrors the IPv4 guard:prefixes
/// /0 through /7 cover astronomically large swaths of the address space and
/// are rejected to prevent accidental or malicious internet-wide blocks.
const MIN_IPV6_CIDR_PREFIX_LEN: u8 = 8;

/// Parse an IPv6 CIDR string like "2001:db8::/32"
/// # Security
/// - Rejects prefix lengths 0-7 (internet-wide / near-internet-wide blocks),
///   mirroring the IPv4 `MIN_CIDR_PREFIX_LEN` guard.
/// - Rejects prefix lengths > 128 (invalid for IPv6).
fn parse_ipv6_cidr(cidr: &str) -> Result<(u128, u8), crate::ThreatIntelError> {
    let parts: Vec<&str> = cidr.trim().split('/').collect();
    if parts.len() != 2 {
        return Err(crate::ThreatIntelError::InvalidCidr(cidr.into()));
    }

    let ip: Ipv6Addr = parts[0]
        .parse()
        .map_err(|_| crate::ThreatIntelError::InvalidIp(parts[0].into()))?;
    let prefix_len: u8 = parts[1]
        .parse()
        .map_err(|_| crate::ThreatIntelError::InvalidCidr(cidr.into()))?;

    // Security:reject overly broad prefixes ("::/0" blocks EVERYTHING).
    if prefix_len < MIN_IPV6_CIDR_PREFIX_LEN {
        return Err(crate::ThreatIntelError::InvalidCidr(format!(
            "IPv6 prefix length {} is too broad (minimum is /{}). Rejecting to prevent accidental internet-wide blocks.",
            prefix_len, MIN_IPV6_CIDR_PREFIX_LEN
        )));
    }

    if prefix_len > 128 {
        return Err(crate::ThreatIntelError::InvalidCidr(format!(
            "IPv6 prefix length {} > 128",
            prefix_len
        )));
    }

    Ok((u128::from(ip), prefix_len))
}

/// Parse a hosts-file style feed where each line is `<IP> <domain>`
/// (one or more whitespace separators), e.g. the ThreatFox hostfile export.
/// Lines may carry a `#` comment suffix. Only the IP column is used.
pub fn parse_hosts_file(
    content: &str,
    source: &str,
    category: ThreatCategory,
    ttl_secs: u64,
) -> Vec<(String, IpBlockEntry)> {
    let now = Utc::now();
    let expires = now + chrono::Duration::seconds(ttl_secs as i64);

    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            // Strip trailing comment.
            let line = line.split('#').next()?.trim();
            let mut cols = line.split_whitespace();
            let ip = cols.next()?;
            // A hosts line must have a second column (the domain); a lone
            // token is a plain IP list, handled by parse_plain_text_list.
            let _domain = cols.next()?;
            if ip.parse::<Ipv4Addr>().is_ok() || ip.parse::<Ipv6Addr>().is_ok() {
                Some((
                    ip.to_string(),
                    IpBlockEntry {
                        cidr: ip.to_string(),
                        source: source.to_string(),
                        category,
                        confidence: 7.0,
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

/// Parse a URL-per-line feed (e.g. abuse.ch URLhaus `text` export) and
/// extract the HOST of each URL as an IP entry when it is a literal IP
/// address. Non-IP hosts are ignored here — use
/// [`crate::domain_blocklist::parse_url_list_domains`] for those.
pub fn parse_url_list_ips(
    content: &str,
    source: &str,
    category: ThreatCategory,
    ttl_secs: u64,
) -> Vec<(String, IpBlockEntry)> {
    let now = Utc::now();
    let expires = now + chrono::Duration::seconds(ttl_secs as i64);

    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let host = url_host(line)?;
            if host.parse::<Ipv4Addr>().is_ok() || host.parse::<Ipv6Addr>().is_ok() {
                Some((
                    host.to_string(),
                    IpBlockEntry {
                        cidr: host.to_string(),
                        source: source.to_string(),
                        category,
                        confidence: 7.0,
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

/// Extract the host portion of a URL-ish line without a full URL parser:
/// strips an optional scheme, then takes everything up to the first
/// `/`, `?`, or whitespace. Bracketed IPv6 literals are unbracketed.
pub(crate) fn url_host(line: &str) -> Option<&str> {
    let rest = if let Some(idx) = line.find("://") {
        &line[idx + 3..]
    } else if !line.contains('/') && line.contains('.') {
        line // bare host[:port]
    } else {
        return None;
    };
    let end = rest
        .find(|c: char| c == '/' || c == '?' || c.is_whitespace())
        .unwrap_or(rest.len());
    let host_port = &rest[..end];
    let host = host_port
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(host_port);
    let host = host.trim_matches(|c| c == '[' || c == ']');
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
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

    /// Add an exact IP entry from a string (auto-detects v4 vs v6).
    /// Returns false when the address does not parse or capacity is full.
    pub fn add_ip_str(&self, ip_str: &str, entry: IpBlockEntry) -> bool {
        if let Ok(v4) = ip_str.parse::<Ipv4Addr>() {
            self.v4.add_ip(v4, entry)
        } else if let Ok(v6) = ip_str.parse::<Ipv6Addr>() {
            self.v6.add_ip(v6, entry)
        } else {
            false
        }
    }

    /// Total number of exact entries across v4 and v6.
    pub fn exact_count(&self) -> usize {
        self.v4.exact_count() + self.v6.exact_count()
    }

    /// Total number of CIDR entries across v4 and v6.
    pub fn cidr_count(&self) -> usize {
        self.v4.cidr_count() + self.v6.cidr_count()
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
    pub fn add_cidr(
        &self,
        cidr_str: &str,
        entry: IpBlockEntry,
    ) -> Result<(), crate::ThreatIntelError> {
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

    /// Remove all entries (v4 and v6, exact and CIDR) that originate from
    /// `source` (per-source refresh merging, audit F6).
    pub fn remove_source(&self, source: &str) -> usize {
        self.v4.remove_source(source) + self.v6.remove_source(source)
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
        bl.add_cidr("10.0.0.0/8", make_entry("10.0.0.0/8"))
            .expect("valid CIDR");
        assert!(bl.lookup("10.1.2.3".parse().expect("valid")).is_some());
        assert!(bl.lookup("10.255.0.1".parse().expect("valid")).is_some());
        assert!(bl.lookup("11.0.0.1".parse().expect("valid")).is_none());
    }

    #[test]
    fn test_cidr_24() {
        let bl = IpBlocklist::new(1000);
        bl.add_cidr("192.168.1.0/24", make_entry("192.168.1.0/24"))
            .expect("valid");
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
        bl.add_cidr("2001:db8::/32", make_entry("2001:db8::/32"))
            .expect("valid CIDR");
        assert!(bl.lookup("2001:db8::1".parse().expect("valid")).is_some());
        assert!(bl
            .lookup("2001:db8:1234::5678".parse().expect("valid"))
            .is_some());
        assert!(bl.lookup("2001:db9::1".parse().expect("valid")).is_none());
    }

    #[test]
    fn test_ipv6_cidr_48() {
        let bl = Ipv6Blocklist::new(1000);
        bl.add_cidr("2001:db8:abcd::/48", make_entry("2001:db8:abcd::/48"))
            .expect("valid");
        assert!(bl
            .lookup("2001:db8:abcd::1".parse().expect("valid"))
            .is_some());
        assert!(bl
            .lookup("2001:db8:abcd:ffff::1".parse().expect("valid"))
            .is_some());
        assert!(bl
            .lookup("2001:db8:abce::1".parse().expect("valid"))
            .is_none());
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
        bl.add_ip(
            "2001:db8::2".parse().expect("valid"),
            make_entry("2001:db8::2"),
        );

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
        ubl.v4
            .add_ip("1.2.3.4".parse().expect("valid"), make_entry("1.2.3.4"));
        ubl.v6.add_ip(
            "2001:db8::1".parse().expect("valid"),
            make_entry("2001:db8::1"),
        );

        assert!(ubl.lookup_str("1.2.3.4").is_some());
        assert!(ubl.lookup_str("2001:db8::1").is_some());
        assert!(ubl.lookup_str("5.6.7.8").is_none());
        assert!(ubl.lookup_str("2001:db9::1").is_none());
    }

    #[test]
    fn test_unified_add_cidr_auto_detect() {
        let ubl = UnifiedIpBlocklist::new(1000, 1000);
        ubl.add_cidr("10.0.0.0/8", make_entry("10.0.0.0/8"))
            .expect("valid v4");
        ubl.add_cidr("2001:db8::/32", make_entry("2001:db8::/32"))
            .expect("valid v6");

        assert!(ubl.lookup_str("10.1.2.3").is_some());
        assert!(ubl.lookup_str("2001:db8::1234").is_some());
    }

    // ── Security-fix regression tests ──

    #[test]
    fn test_ipv6_internet_wide_cidr_rejected() {
        let bl = Ipv6Blocklist::new(1000);
        assert!(bl.add_cidr("::/0", make_entry("::/0")).is_err());
        assert!(bl.add_cidr("::/7", make_entry("::/7")).is_err());
        // Reasonable prefixes still accepted.
        assert!(bl
            .add_cidr("2001:db8::/32", make_entry("2001:db8::/32"))
            .is_ok());
    }

    #[test]
    fn test_ipv6_exact_and_cidr_lookup() {
        let bl = Ipv6Blocklist::new(1000);
        let ip: Ipv6Addr = "2001:db8::1".parse().expect("valid ipv6");
        assert!(bl.add_ip(ip, make_entry("2001:db8::1")));
        assert!(bl.lookup(ip).is_some());
        // CIDR containment
        assert!(bl
            .add_cidr("2620:0:2d0::/48", make_entry("2620:0:2d0::/48"))
            .is_ok());
        let inside: Ipv6Addr = "2620:0:2d0:1::dead".parse().expect("valid ipv6");
        assert!(
            bl.lookup(inside).is_some(),
            "IPv6 CIDR containment must work"
        );
    }

    #[test]
    fn test_cidr_entries_are_capped() {
        // max_entries now bounds the CIDR store too (previously unbounded).
        let bl = IpBlocklist::new(10);
        for i in 0..10u32 {
            let cidr = format!("10.{}.0.0/24", i);
            bl.add_cidr(&cidr, make_entry(&cidr)).expect("within cap");
        }
        assert!(
            bl.add_cidr("10.99.0.0/24", make_entry("10.99.0.0/24"))
                .is_err(),
            "CIDR store must respect the capacity cap"
        );
    }

    #[test]
    fn test_cidr_lookup_fast_on_100k_ranges() {
        let bl = IpBlocklist::new(200_000);
        for i in 0..100_000u32 {
            let cidr = format!("{}.{}.0.0/24", (i >> 8) & 0xFF, i & 0xFF);
            bl.add_cidr(&cidr, make_entry(&cidr)).expect("insert");
        }
        bl.optimize();

        let start = std::time::Instant::now();
        let mut hits = 0;
        for i in 0..10_000u32 {
            let ip = Ipv4Addr::new(((i >> 8) & 0xFF) as u8, (i & 0xFF) as u8, 0, 7);
            if bl.lookup(ip).is_some() {
                hits += 1;
            }
        }
        let elapsed = start.elapsed();
        assert_eq!(hits, 10_000, "every /24 range must contain its member");
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "10k lookups over 100k sorted ranges must be fast (took {elapsed:?})"
        );
    }

    #[test]
    fn test_hosts_file_parsing() {
        // ThreatFox hostfile format:"IP domain" per line.
        let content = "# comment\n1.2.3.4 evil.com\n5.6.7.8 bad.example # trailing\n\nnot-a-pair\n";
        let entries = parse_hosts_file(content, "threatfox", ThreatCategory::Malware, 3600);
        assert_eq!(entries.len(), 2, "got {entries:?}");
        assert_eq!(entries[0].0, "1.2.3.4");
        assert_eq!(entries[1].0, "5.6.7.8");
    }

    #[test]
    fn test_url_list_ip_extraction() {
        // URLhaus text format:one URL per line.
        let content = "https://198.51.100.9/payload.bin\nhttp://good.example.com/page\nhttp://203.0.113.5/x?a=1\n";
        let ips = parse_url_list_ips(content, "urlhaus", ThreatCategory::Malware, 3600);
        let hosts: Vec<&str> = ips.iter().map(|(h, _)| h.as_str()).collect();
        assert!(hosts.contains(&"198.51.100.9"), "got {hosts:?}");
        assert!(hosts.contains(&"203.0.113.5"), "got {hosts:?}");
        assert!(!hosts.contains(&"good.example.com"));
    }
}
