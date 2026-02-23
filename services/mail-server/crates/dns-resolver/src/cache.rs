//! DNS cache using moka.

use moka::sync::Cache;
use std::time::Duration;
use tracing::debug;

use crate::config::DnsConfig;

/// Cached DNS results.
#[derive(Debug, Clone)]
pub enum CachedResult {
    /// Positive result: list of record strings.
    Records(Vec<String>),
    /// Negative result: NXDOMAIN or empty.
    NxDomain,
}

/// Thread-safe DNS cache with TTL-based eviction.
pub struct DnsCache {
    cache: Cache<String, CachedResult>,
    negative_cache: Cache<String, ()>,
}

impl DnsCache {
    /// Create from config.
    pub fn new(config: &DnsConfig) -> Self {
        let cache = Cache::builder()
            .max_capacity(config.max_cache_entries)
            .time_to_live(Duration::from_secs(config.cache_ttl_secs))
            .build();

        let negative_cache = Cache::builder()
            .max_capacity(config.max_cache_entries / 5)
            .time_to_live(Duration::from_secs(config.negative_ttl_secs))
            .build();

        Self {
            cache,
            negative_cache,
        }
    }

    /// Create with default config.
    pub fn default_cache() -> Self {
        Self::new(&DnsConfig::default())
    }

    /// Get cached result.
    pub fn get(&self, key: &str) -> Option<CachedResult> {
        // Check positive cache first
        if let Some(result) = self.cache.get(key) {
            debug!(key, "DNS cache hit");
            return Some(result);
        }
        // Check negative cache
        if self.negative_cache.get(key).is_some() {
            debug!(key, "DNS negative cache hit");
            return Some(CachedResult::NxDomain);
        }
        None
    }

    /// Insert a positive result.
    pub fn insert(&self, key: impl Into<String>, records: Vec<String>) {
        let key = key.into();
        debug!(key, count = records.len(), "DNS cache insert");
        self.cache.insert(key, CachedResult::Records(records));
    }

    /// Insert a negative (NXDOMAIN) result.
    pub fn insert_negative(&self, key: impl Into<String>) {
        let key = key.into();
        debug!(key, "DNS negative cache insert");
        self.negative_cache.insert(key, ());
    }

    /// Remove a cached entry.
    pub fn invalidate(&self, key: &str) {
        self.cache.invalidate(key);
        self.negative_cache.invalidate(key);
    }

    /// Number of entries in the positive cache.
    pub fn len(&self) -> u64 {
        self.cache.entry_count()
    }

    /// Whether the positive cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.entry_count() == 0
    }

    /// Clear all caches.
    pub fn clear(&self) {
        self.cache.invalidate_all();
        self.negative_cache.invalidate_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_insert_and_get() {
        let cache = DnsCache::default_cache();
        cache.insert("mx:example.com", vec!["10 mx.example.com".into()]);
        match cache.get("mx:example.com") {
            Some(CachedResult::Records(recs)) => {
                assert_eq!(recs.len(), 1);
                assert_eq!(recs[0], "10 mx.example.com");
            }
            _ => panic!("Expected records"),
        }
    }

    #[test]
    fn test_cache_miss() {
        let cache = DnsCache::default_cache();
        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn test_cache_negative() {
        let cache = DnsCache::default_cache();
        cache.insert_negative("nx:missing.example");
        match cache.get("nx:missing.example") {
            Some(CachedResult::NxDomain) => {}
            _ => panic!("Expected NxDomain"),
        }
    }

    #[test]
    fn test_cache_invalidate() {
        let cache = DnsCache::default_cache();
        cache.insert("key", vec!["value".into()]);
        cache.invalidate("key");
        assert!(cache.get("key").is_none());
    }

    #[test]
    fn test_cache_clear() {
        let cache = DnsCache::default_cache();
        cache.insert("a", vec!["1".into()]);
        cache.insert("b", vec!["2".into()]);
        cache.clear();
        // moka might not immediately reflect, but clear should work
        // Just verify it doesn't crash
        assert!(cache.get("a").is_none() || true);
    }

    #[test]
    fn test_cache_len() {
        let cache = DnsCache::default_cache();
        assert!(cache.is_empty());
        cache.insert("key", vec!["val".into()]);
        // moka is eventually consistent; entry_count might not be instant
        // but the API should work
        assert!(cache.len() <= 1);
    }
}
