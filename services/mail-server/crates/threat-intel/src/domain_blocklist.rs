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
    /// Parent domain walk is capped at 3 levels to prevent abuse from
    /// deeply-nested subdomains (e.g., a.b.c.d.e.f.evil.com) which could
    /// cause excessive DashMap lookups per request.
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

        // Walk up the domain hierarchy, capped at 3 levels
        let mut parts = normalized;
        let mut walk_count = 0;
        const MAX_DOMAIN_WALK: usize = 3;
        while let Some(dot_pos) = parts.find('.') {
            if walk_count >= MAX_DOMAIN_WALK {
                break;
            }
            parts = &parts[dot_pos + 1..];
            walk_count += 1;
            if let Some(entry) = self.exact.get(parts) {
                if entry.expires_at > now {
                    return Some(entry.clone());
                }
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
}
