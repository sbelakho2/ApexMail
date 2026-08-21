//! High-level cached DNS resolver combining DnsLookup + DnsCache.

use tracing::debug;

use crate::cache::{CachedResult, DnsCache};
use crate::config::DnsConfig;
use crate::lookup::{DnsError, DnsLookup};
use crate::records::*;

/// High-level cached DNS resolver.
pub struct CachedDnsResolver {
    lookup: DnsLookup,
    cache: DnsCache,
}

impl CachedDnsResolver {
    /// Create a new cached resolver.
    pub fn new(config: &DnsConfig) -> Result<Self, DnsError> {
        Ok(Self {
            lookup: DnsLookup::from_config(config)?,
            cache: DnsCache::new(config),
        })
    }

    /// Create with default configuration.
    pub fn default_resolver() -> Result<Self, DnsError> {
        Self::new(&DnsConfig::default())
    }

    /// Lookup MX records with caching.
    pub async fn mx(&self, domain: &str) -> Result<Vec<MxRecord>, DnsError> {
        let cache_key = format!("mx:{domain}");

        if let Some(CachedResult::Records(recs)) = self.cache.get(&cache_key) {
            return Ok(recs
                .iter()
                .filter_map(|r| {
                    let parts: Vec<&str> = r.splitn(2, ' ').collect();
                    if parts.len() == 2 {
                        Some(MxRecord::new(parts[0].parse().unwrap_or(10), parts[1]))
                    } else {
                        None
                    }
                })
                .collect());
        }

        if let Some(CachedResult::NxDomain) = self.cache.get(&cache_key) {
            return Err(DnsError::NoRecords(domain.to_string()));
        }

        match self.lookup.lookup_mx_with_ttl(domain).await {
            Ok(result) if result.records.is_empty() => {
                self.cache.insert_negative(&cache_key);
                Err(DnsError::NoRecords(domain.to_string()))
            }
            Ok(result) => {
                let cached: Vec<String> = result
                    .records
                    .iter()
                    .map(|r| format!("{} {}", r.priority, r.exchange))
                    .collect();
                self.cache.insert_with_ttl(&cache_key, cached, result.ttl);
                Ok(result.records)
            }
            // E-1:transient lookup errors (timeout, SERVFAIL, network) are
            // NEVER negative-cached — a cached failure turned a blip into a
            // full negative-TTL window in which deliverability checks said
            // "no records". Propagate the error so the caller can retry;
            // only definitive NXDOMAIN/NoRecords results are cached.
            Err(e) => Err(e),
        }
    }

    /// Lookup SPF record with caching.
    pub async fn spf(&self, domain: &str) -> Result<Option<SpfRecord>, DnsError> {
        let cache_key = format!("spf:{domain}");

        if let Some(CachedResult::Records(recs)) = self.cache.get(&cache_key) {
            return Ok(recs.first().and_then(|r| SpfRecord::parse(r)));
        }

        match self.lookup.lookup_spf_with_ttl(domain).await? {
            Some(result) => {
                self.cache.insert_with_ttl(
                    &cache_key,
                    vec![result.records.raw.clone()],
                    result.ttl,
                );
                Ok(Some(result.records))
            }
            None => {
                self.cache.insert_negative(&cache_key);
                Ok(None)
            }
        }
    }

    /// Lookup DKIM record with caching.
    pub async fn dkim(&self, selector: &str, domain: &str) -> Result<Option<DkimRecord>, DnsError> {
        let cache_key = format!("dkim:{selector}._domainkey.{domain}");

        if let Some(CachedResult::Records(recs)) = self.cache.get(&cache_key) {
            return Ok(recs.first().and_then(|r| DkimRecord::parse(r)));
        }

        match self.lookup.lookup_dkim_with_ttl(selector, domain).await? {
            Some(result) => {
                self.cache.insert_with_ttl(
                    &cache_key,
                    vec![result.records.raw.clone()],
                    result.ttl,
                );
                Ok(Some(result.records))
            }
            None => {
                self.cache.insert_negative(&cache_key);
                Ok(None)
            }
        }
    }

    /// Lookup DMARC record with caching.
    pub async fn dmarc(&self, domain: &str) -> Result<Option<DmarcPolicy>, DnsError> {
        let cache_key = format!("dmarc:{domain}");

        if let Some(CachedResult::Records(recs)) = self.cache.get(&cache_key) {
            return Ok(recs.first().and_then(|r| DmarcPolicy::parse(r)));
        }

        match self.lookup.lookup_dmarc_with_ttl(domain).await? {
            Some(result) => {
                self.cache.insert_with_ttl(
                    &cache_key,
                    vec![result.records.raw.clone()],
                    result.ttl,
                );
                Ok(Some(result.records))
            }
            None => {
                self.cache.insert_negative(&cache_key);
                Ok(None)
            }
        }
    }

    /// Validate domain can receive email (with cache).
    pub async fn can_receive_email(&self, domain: &str) -> Result<bool, DnsError> {
        let cache_key = format!("can_receive:{domain}");

        if let Some(CachedResult::Records(recs)) = self.cache.get(&cache_key) {
            return Ok(recs.first().map(|r| r == "true").unwrap_or(false));
        }

        let result = self.lookup.can_receive_email(domain).await?;
        self.cache.insert(&cache_key, vec![result.to_string()]);
        Ok(result)
    }

    /// Invalidate all cached records for a domain.
    /// #184:DKIM cache key uses `dkim:{selector}._domainkey.{domain}` format,
    /// so we cannot simply invalidate `dkim:{domain}`. Instead, perform a broader
    /// invalidation of all keys matching the domain suffix.
    pub fn invalidate_domain(&self, domain: &str) {
        debug!(domain, "Invalidating DNS cache for domain");
        for prefix in &["mx", "spf", "dmarc", "can_receive"] {
            self.cache.invalidate(&format!("{prefix}:{domain}"));
        }
        // DKIM keys are stored as `dkim:{selector}._domainkey.{domain}`,
        // so we need to invalidate by suffix match
        self.cache.invalidate_by_domain_suffix(domain);
    }

    /// Clear entire cache.
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Cache statistics.
    pub fn cache_size(&self) -> u64 {
        self.cache.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_resolver_creation() {
        let resolver = CachedDnsResolver::default_resolver();
        assert!(resolver.is_ok());
    }

    #[test]
    fn test_cached_resolver_from_config() {
        let config = DnsConfig {
            cache_ttl_secs: 60,
            max_cache_entries: 100,
            ..DnsConfig::default()
        };
        let resolver = CachedDnsResolver::new(&config);
        assert!(resolver.is_ok());
    }

    #[test]
    fn test_cached_resolver_invalidate() {
        let resolver = CachedDnsResolver::default_resolver();
        assert!(resolver.is_ok());
        if let Ok(resolver) = resolver {
            resolver.invalidate_domain("example.com");
            // Should not panic
            assert_eq!(resolver.cache_size(), 0);
        }
    }

    #[test]
    fn test_cached_resolver_clear() {
        let resolver = CachedDnsResolver::default_resolver();
        assert!(resolver.is_ok());
        if let Ok(resolver) = resolver {
            resolver.clear_cache();
            assert_eq!(resolver.cache_size(), 0);
        }
    }

    // ── E-1: transient lookup errors are never negative-cached ────────────

    #[tokio::test]
    async fn mx_lookup_errors_are_not_cached() {
        // Point the resolver at an unreachable nameserver with a short
        // timeout so the lookup fails transiently (timeout / io error —
        // NOT an NXDOMAIN). The failure must propagate and leave the cache
        // EMPTY: the old code negative-cached the error, making every
        // deliverability check for that domain fail for a full negative-TTL
        // window after a single network blip.
        let config = crate::config::DnsConfig {
            nameservers: vec!["127.0.0.1:1".to_string()],
            query_timeout_ms: 50,
            retries: 0,
            ..crate::config::DnsConfig::default()
        };
        let resolver = CachedDnsResolver::new(&config).expect("resolver construction");

        let outcome = resolver.mx("example.com").await;
        assert!(outcome.is_err(), "unreachable nameserver must yield an error");
        assert!(
            resolver.cache_size() == 0,
            "transient errors must not be cached (positive or negative)"
        );

        // A second attempt still consults the (still-failing) resolver
        // instead of being short-circuited by a cached failure.
        let outcome = resolver.mx("example.com").await;
        assert!(outcome.is_err());
        assert!(resolver.cache_size() == 0);
    }

    // ── E-2: invalidate_domain reaches DKIM selector keys ─────────────────

    #[test]
    fn invalidate_domain_invalidates_dkim_selector_keys() {
        let resolver = CachedDnsResolver::default_resolver().expect("resolver construction");
        resolver.cache.insert(
            "dkim:sel1._domainkey.example.com",
            vec!["v=DKIM1; k=rsa; p=OLD".into()],
        );
        resolver
            .cache
            .insert("mx:example.com", vec!["10 mx.example.com".into()]);

        resolver.invalidate_domain("example.com");

        assert!(
            resolver.cache.get("dkim:sel1._domainkey.example.com").is_none(),
            "DKIM selector keys must be invalidated with the domain"
        );
        assert!(
            resolver.cache.get("mx:example.com").is_none(),
            "plain domain keys must be invalidated as before"
        );
    }
}
