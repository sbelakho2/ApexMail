//! Domain blocklist — exact and wildcard domain matching

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::sync::Arc;

/// A domain blocklist entry
#[derive(Debug, Clone)]
pub struct DomainBlockEntry {
    /// The blocked domain
    pub domain: String,
    /// Source feed name
    pub source: String,
    /// Confidence score (0.0 - 10.0)
    pub confidence: f64,
    /// Category
    pub category: String,
    /// When added
    pub added_at: DateTime<Utc>,
    /// When it expires
    pub expires_at: DateTime<Utc>,
}

/// Thread-safe domain blocklist
#[derive(Clone)]
pub struct DomainBlocklist {
    /// Exact domain matches
    exact: Arc<DashMap<String, DomainBlockEntry>>,
    /// Maximum entries
    max_entries: usize,
}

impl DomainBlocklist {
    /// Create a new domain blocklist
    pub fn new(max_entries: usize) -> Self {
        Self {
            exact: Arc::new(DashMap::new()),
            max_entries,
        }
    }

    /// Add a domain to the blocklist
    pub fn add(&self, domain: &str, entry: DomainBlockEntry) -> bool {
        if self.exact.len() >= self.max_entries {
            return false;
        }
        let normalized = domain.to_lowercase().trim_end_matches('.').to_string();
        self.exact.insert(normalized, entry);
        true
    }

    /// Look up a domain, checking exact match and parent domain wildcards.
    /// The walk climbs toward the registrable parent (e.g.
    /// `a.b.c.d.evil.com` → … → `evil.com`), stopping once a two-label
    /// apex (the presumable registrable domain) has been checked.
    ///
    /// There is no fixed walk cap: a 5-label cap was a shipped bypass —
    /// nesting six subdomains in front of a blocked domain evaded the
    /// blocklist entirely. The work is bounded by the hostname itself
    /// (DNS limits names to 253 bytes, so the walk is at most ~126 hops
    /// over a handful of map lookups each, terminated by the two-label
    /// apex rule below).
    pub fn lookup(&self, domain: &str) -> Option<DomainBlockEntry> {
        let normalized = domain.to_lowercase();
        let normalized = normalized.trim_end_matches('.');
        let now = Utc::now();

        // Exact match
        if let Some(entry) = self.exact.get(normalized) {
            if entry.expires_at > now {
                return Some(entry.clone());
            }
        }

        // Walk up the domain hierarchy toward the registrable parent.
        let mut parts = normalized;
        while let Some(dot_pos) = parts.find('.') {
            parts = &parts[dot_pos + 1..];
            if let Some(entry) = self.exact.get(parts) {
                if entry.expires_at > now {
                    return Some(entry.clone());
                }
            }
            // Apex heuristic:once the remaining name has two labels
            // ("evil.com") we have checked the presumable registrable
            // domain — stop. Multi-part public suffixes (co.uk) may need
            // one extra level, which the walk reaches naturally.
            if parts.matches('.').count() <= 1 {
                break;
            }
        }

        None
    }

    /// Number of entries
    pub fn count(&self) -> usize {
        self.exact.len()
    }

    /// Remove expired entries
    pub fn purge_expired(&self) -> usize {
        let now = Utc::now();
        let mut removed = 0;
        self.exact.retain(|_, entry| {
            let keep = entry.expires_at > now;
            if !keep {
                removed += 1;
            }
            keep
        });
        removed
    }
}

impl Default for DomainBlocklist {
    fn default() -> Self {
        Self::new(500_000)
    }
}

/// Parse a plain-text domain list (one domain per line, # comments)
pub fn parse_domain_list(
    content: &str,
    source: &str,
    category: &str,
    ttl_secs: u64,
) -> Vec<DomainBlockEntry> {
    let now = Utc::now();
    let expires = now + chrono::Duration::seconds(ttl_secs as i64);

    content
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.starts_with(';')
        })
        .map(|line| {
            let domain = line.trim().to_lowercase();
            DomainBlockEntry {
                domain,
                source: source.into(),
                confidence: 8.0,
                category: category.into(),
                added_at: now,
                expires_at: expires,
            }
        })
        .collect()
}

/// Parse a URL-per-line feed (e.g. abuse.ch URLhaus `text` export) and
/// extract the HOST of each URL as a domain entry. Literal-IP hosts are
/// skipped (they belong in the IP blocklist).
pub fn parse_url_list_domains(
    content: &str,
    source: &str,
    category: &str,
    ttl_secs: u64,
) -> Vec<DomainBlockEntry> {
    let now = Utc::now();
    let expires = now + chrono::Duration::seconds(ttl_secs as i64);

    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let host = crate::ip_blocklist::url_host(line)?;
            if host.parse::<std::net::Ipv4Addr>().is_ok()
                || host.parse::<std::net::Ipv6Addr>().is_ok()
            {
                return None; // IP literal — IP blocklist territory
            }
            if !host.contains('.') {
                return None;
            }
            Some(DomainBlockEntry {
                domain: host.to_lowercase(),
                source: source.into(),
                confidence: 7.0,
                category: category.into(),
                added_at: now,
                expires_at: expires,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(domain: &str) -> DomainBlockEntry {
        DomainBlockEntry {
            domain: domain.into(),
            source: "test".into(),
            confidence: 9.0,
            category: "malware".into(),
            added_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
        }
    }

    #[test]
    fn test_exact_match() {
        let bl = DomainBlocklist::new(1000);
        bl.add("evil.com", make_entry("evil.com"));
        assert!(bl.lookup("evil.com").is_some());
        assert!(bl.lookup("good.com").is_none());
    }

    #[test]
    fn test_subdomain_match() {
        let bl = DomainBlocklist::new(1000);
        bl.add("evil.com", make_entry("evil.com"));
        // Subdomains of blocked parent should match
        assert!(bl.lookup("sub.evil.com").is_some());
        assert!(bl.lookup("deep.sub.evil.com").is_some());
    }

    #[test]
    fn test_case_insensitive() {
        let bl = DomainBlocklist::new(1000);
        bl.add("Evil.COM", make_entry("Evil.COM"));
        assert!(bl.lookup("evil.com").is_some());
        assert!(bl.lookup("EVIL.COM").is_some());
    }

    #[test]
    fn test_trailing_dot() {
        let bl = DomainBlocklist::new(1000);
        bl.add("evil.com.", make_entry("evil.com."));
        assert!(bl.lookup("evil.com").is_some());
        assert!(bl.lookup("evil.com.").is_some());
    }

    #[test]
    fn test_expired_domain() {
        let bl = DomainBlocklist::new(1000);
        let mut entry = make_entry("old.com");
        entry.expires_at = Utc::now() - chrono::Duration::hours(1);
        bl.add("old.com", entry);
        assert!(bl.lookup("old.com").is_none());
    }

    #[test]
    fn test_parse_domain_list() {
        let content = "# Phishing domains\nevil.com\nmalware.tk\n# End\n";
        let entries = parse_domain_list(content, "test", "phishing", 3600);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].domain, "evil.com");
    }

    #[test]
    fn test_purge_expired() {
        let bl = DomainBlocklist::new(1000);
        let mut expired = make_entry("old.com");
        expired.expires_at = Utc::now() - chrono::Duration::hours(1);
        bl.add("old.com", expired);
        bl.add("current.com", make_entry("current.com"));

        let removed = bl.purge_expired();
        assert_eq!(removed, 1);
        assert_eq!(bl.count(), 1);
    }

    #[test]
    fn test_deep_subdomain_matches_registrable_parent() {
        let bl = DomainBlocklist::new(1000);
        assert!(bl.add("evil.com", make_entry("evil.com")));
        // 4-label prefix:a.b.c.d.evil.com must reach the evil.com block.
        assert!(
            bl.lookup("a.b.c.d.evil.com").is_some(),
            "deep subdomain must match its registrable parent"
        );
        // 5-label prefix:still within the old walk cap.
        assert!(bl.lookup("x.a.b.c.d.evil.com").is_some());
        // Fail-first regression: the old 5-label walk cap meant an attacker
        // could bypass the evil.com block simply by nesting 6+ subdomains
        // (z.y.x.a.b.c.d.evil.com was NOT matched). The walk must reach the
        // registrable domain regardless of depth; work is bounded by the
        // number of labels in the hostname itself.
        assert!(
            bl.lookup("z.y.x.a.b.c.d.evil.com").is_some(),
            "arbitrarily deep subdomain must still match its registrable parent"
        );
    }

    #[test]
    fn test_url_list_domain_extraction() {
        let content = "https://198.51.100.9/payload.bin\nhttp://bad.example.com/page\nhttp://worse.example.org/x\n";
        let entries = parse_url_list_domains(content, "urlhaus", "malware", 3600);
        let domains: Vec<&str> = entries.iter().map(|e| e.domain.as_str()).collect();
        assert!(!domains.contains(&"198.51.100.9"), "IP literals excluded");
        assert!(domains.contains(&"bad.example.com"), "got {domains:?}");
        assert!(domains.contains(&"worse.example.org"), "got {domains:?}");
    }
}
