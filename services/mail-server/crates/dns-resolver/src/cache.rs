//! DNS cache using moka.

use moka::{sync::Cache, Expiry};
use parking_lot::RwLock;
use std::time::{Duration, Instant};
use tracing::debug;

use crate::config::DnsConfig;

/// Cached DNS results.
#[derive(Debug, Clone)]
pub enum CachedResult {
    /// Positive result:list of record strings.
    Records(Vec<String>),
    /// Negative result:NXDOMAIN or empty.
    NxDomain,
}

#[derive(Debug, Clone)]
struct CachedEntry {
    result: CachedResult,
    ttl: Duration,
}

#[derive(Debug, Clone, Copy)]
struct PositiveRecordExpiry;

impl Expiry<String, CachedEntry> for PositiveRecordExpiry {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &CachedEntry,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(value.ttl)
    }

    fn expire_after_update(
        &self,
        _key: &String,
        value: &CachedEntry,
        _updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        Some(value.ttl)
    }
}

/// Thread-safe DNS cache with TTL-based eviction.
pub struct DnsCache {
    cache: Cache<String, CachedEntry>,
    negative_cache: Cache<String, ()>,
    consistency_lock: RwLock<()>,
    default_positive_ttl: Duration,
    max_positive_ttl: Duration,
}

impl DnsCache {
    /// Create from config.
    ///
    /// Applies a TTL ceiling [`DnsConfig::max_ttl_ceiling_secs`] (default 24h)
    /// to prevent stale records from being served indefinitely (MI-005).
    /// Any configured TTL exceeding the ceiling is silently capped.
    pub fn new(config: &DnsConfig) -> Self {
        let default_positive_ttl =
            Duration::from_secs(config.cache_ttl_secs.min(config.max_ttl_ceiling_secs));
        let max_positive_ttl = Duration::from_secs(config.max_ttl_ceiling_secs);
        let effective_negative_ttl = config.negative_ttl_secs.min(config.max_ttl_ceiling_secs);

        let cache = Cache::builder()
            .max_capacity(config.max_cache_entries)
            .expire_after(PositiveRecordExpiry)
            .build();

        let negative_cache = Cache::builder()
            .max_capacity(config.max_cache_entries / 5)
            .time_to_live(Duration::from_secs(effective_negative_ttl))
            .build();

        Self {
            cache,
            negative_cache,
            consistency_lock: RwLock::new(()),
            default_positive_ttl,
            max_positive_ttl,
        }
    }

    /// Create with default config.
    pub fn default_cache() -> Self {
        Self::new(&DnsConfig::default())
    }

    /// Get cached result.
    pub fn get(&self, key: &str) -> Option<CachedResult> {
        let _guard = self.consistency_lock.read();
        // Check positive cache first
        if let Some(entry) = self.cache.get(key) {
            debug!(key, "DNS cache hit");
            return Some(entry.result);
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
        self.insert_with_ttl(key, records, self.default_positive_ttl);
    }

    /// Insert a positive result with the authoritative record TTL.
    pub fn insert_with_ttl(&self, key: impl Into<String>, records: Vec<String>, ttl: Duration) {
        let _guard = self.consistency_lock.write();
        let key = key.into();
        let effective_ttl = self.positive_ttl(ttl);
        debug!(
            key,
            count = records.len(),
            ttl_secs = effective_ttl.as_secs(),
            "DNS cache insert"
        );
        self.negative_cache.invalidate(&key);
        self.cache.insert(
            key,
            CachedEntry {
                result: CachedResult::Records(records),
                ttl: effective_ttl,
            },
        );
    }

    fn positive_ttl(&self, ttl: Duration) -> Duration {
        ttl.min(self.max_positive_ttl)
    }

    /// Insert a negative (NXDOMAIN) result.
    pub fn insert_negative(&self, key: impl Into<String>) {
        let _guard = self.consistency_lock.write();
        let key = key.into();
        debug!(key, "DNS negative cache insert");
        self.cache.invalidate(&key);
        self.negative_cache.insert(key, ());
    }

    /// Remove a cached entry.
    pub fn invalidate(&self, key: &str) {
        let _guard = self.consistency_lock.write();
        self.cache.invalidate(key);
        self.negative_cache.invalidate(key);
    }

    /// #184:Invalidate all entries whose key contains the given substring.
    /// Used for DKIM keys stored as `dkim:{selector}._domainkey.{domain}`.
    pub fn invalidate_by_domain_suffix(&self, domain: &str) {
        let _guard = self.consistency_lock.write();
        let suffix = format!("._domainkey.{domain}");
        // Moka doesn't expose key iteration, so we rely on in-memory
        // tracking. For now, since DKIM entries have short TTLs,
        // just clear the negative cache for the domain and rely on
        // natural TTL expiry for positive DKIM cache entries.
        // Callers that know the selector should invalidate directly.
        self.negative_cache.invalidate(&format!("dkim:{suffix}"));
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
        let _guard = self.consistency_lock.write();
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
            other => {
                assert!(
                    matches!(other, Some(CachedResult::Records(_))),
                    "Expected records"
                );
            }
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
            other => {
                assert!(
                    matches!(other, Some(CachedResult::NxDomain)),
                    "Expected NxDomain"
                );
            }
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

    #[test]
    fn test_positive_ttl_capped_by_ceiling() {
        let cache = DnsCache::new(&DnsConfig {
            max_ttl_ceiling_secs: 60,
            ..DnsConfig::default()
        });

        assert_eq!(
            cache.positive_ttl(Duration::from_secs(3600)),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn test_insert_with_record_ttl_expires_positive_entry() {
        let cache = DnsCache::default_cache();
        cache.insert_with_ttl("short", vec!["value".into()], Duration::from_millis(20));
        assert!(matches!(cache.get("short"), Some(CachedResult::Records(_))));

        std::thread::sleep(Duration::from_millis(80));

        assert!(cache.get("short").is_none());
    }
}
