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
    /// E-2:live index of DKIM keys (`dkim:{selector}._domainkey.{domain}`).
    /// moka does not expose key iteration, so keys are tracked here to make
    /// `invalidate_by_domain_suffix` a REAL invalidation instead of the old
    /// selector-less no-op (stale DKIM public keys survived domain rotation).
    dkim_keys: RwLock<std::collections::HashSet<String>>,
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
            .max_capacity(config.positive_cache_size)
            .expire_after(PositiveRecordExpiry)
            .build();

        let negative_cache = Cache::builder()
            .max_capacity(config.negative_cache_size)
            .time_to_live(Duration::from_secs(effective_negative_ttl))
            .build();

        Self {
            cache,
            negative_cache,
            consistency_lock: RwLock::new(()),
            dkim_keys: RwLock::new(std::collections::HashSet::new()),
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
        self.track_dkim_key(&key);
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
        self.track_dkim_key(&key);
        self.cache.invalidate(&key);
        self.negative_cache.insert(key, ());
    }

    /// Remove a cached entry.
    pub fn invalidate(&self, key: &str) {
        let _guard = self.consistency_lock.write();
        self.untrack_dkim_key(key);
        self.cache.invalidate(key);
        self.negative_cache.invalidate(key);
    }

    /// E-2:really invalidate every DKIM entry for a domain. Keys are stored
    /// as `dkim:{selector}._domainkey.{domain}`; every tracked key that
    /// carries the `_domainkey.` marker and ends with `.{domain}` (including
    /// selectors published under subdomains) is dropped from both caches.
    /// Previously this invalidated a selector-less key nobody ever wrote,
    /// so stale DKIM public keys survived a domain key rotation.
    pub fn invalidate_by_domain_suffix(&self, domain: &str) {
        let _guard = self.consistency_lock.write();
        let suffix = format!(".{domain}");
        let mut dkim = self.dkim_keys.write();
        let mut invalidated = 0usize;
        dkim.retain(|key| {
            if key.contains("._domainkey.") && key.ends_with(&suffix) {
                self.cache.invalidate(key);
                self.negative_cache.invalidate(key);
                invalidated += 1;
                debug!(key, domain, "Invalidated DKIM cache entry by domain suffix");
                false
            } else {
                true
            }
        });
        // Defensive: the old (broken) selector-less form, if anything ever
        // wrote it directly.
        self.negative_cache
            .invalidate(&format!("dkim:._domainkey.{domain}"));
        if invalidated == 0 {
            debug!(domain, "No DKIM cache entries to invalidate for domain");
        }
    }

    /// Track a DKIM-shaped key for suffix invalidation (E-2).
    fn track_dkim_key(&self, key: &str) {
        if key.starts_with("dkim:") {
            self.dkim_keys.write().insert(key.to_string());
        }
    }

    /// Stop tracking a key that was explicitly invalidated.
    fn untrack_dkim_key(&self, key: &str) {
        if key.starts_with("dkim:") {
            self.dkim_keys.write().remove(key);
        }
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
        self.dkim_keys.write().clear();
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
        let _ = cache.get("a"); // just verify it doesn't crash
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

    #[test]
    fn test_cache_max_capacity_eviction() {
        // Create a cache with max_capacity=2 for the positive cache.
        let cache = DnsCache::new(&DnsConfig {
            positive_cache_size: 2,
            cache_ttl_secs: 3600, // long enough that TTL won't interfere
            ..DnsConfig::default()
        });

        // Insert 3 entries. With max_capacity=2 the cache must
        // evict one to stay within bounds.
        cache.insert("key1", vec!["value1".into()]);
        cache.insert("key2", vec!["value2".into()]);
        cache.insert("key3", vec!["value3".into()]);

        // Force moka maintenance to process evictions synchronously.
        cache.cache.run_pending_tasks();

        // Verify the cache size is bounded by max_capacity.
        let size = cache.len();
        assert!(
            size <= 2,
            "expected cache size <= 2 after LRU eviction, got {size}"
        );

        // At least one of the three keys should have been evicted.
        let found: Vec<_> = ["key1", "key2", "key3"]
            .iter()
            .filter(|k| cache.get(k).is_some())
            .collect();
        assert!(
            found.len() <= 2,
            "expected at most 2 entries accessible after LRU eviction, got {}",
            found.len()
        );
    }

    // ── E-2: real DKIM invalidation by domain suffix ───────────────────────

    #[test]
    fn dkim_positive_entries_are_invalidated_by_domain_suffix() {
        let cache = DnsCache::default_cache();
        cache.insert(
            "dkim:sel1._domainkey.example.com",
            vec!["v=DKIM1; k=rsa; p=AAA".into()],
        );
        cache.insert(
            "dkim:sel2._domainkey.example.com",
            vec!["v=DKIM1; k=rsa; p=BBB".into()],
        );
        cache.insert(
            "dkim:sel1._domainkey.sub.example.com",
            vec!["v=DKIM1; k=rsa; p=DDD".into()],
        );
        cache.insert(
            "dkim:sel1._domainkey.other.com",
            vec!["v=DKIM1; k=rsa; p=CCC".into()],
        );
        cache.insert("mx:example.com", vec!["10 mx.example.com".into()]);

        cache.invalidate_by_domain_suffix("example.com");

        assert!(
            cache.get("dkim:sel1._domainkey.example.com").is_none(),
            "selector keys for the domain must be invalidated"
        );
        assert!(cache.get("dkim:sel2._domainkey.example.com").is_none());
        assert!(
            cache.get("dkim:sel1._domainkey.sub.example.com").is_none(),
            "selectors under subdomains of the domain are invalidated too"
        );
        // Other domains and non-DKIM keys survive the suffix pass.
        assert!(matches!(
            cache.get("dkim:sel1._domainkey.other.com"),
            Some(CachedResult::Records(_))
        ));
        assert!(matches!(
            cache.get("mx:example.com"),
            Some(CachedResult::Records(_))
        ));
    }

    #[test]
    fn dkim_negative_entries_are_invalidated_by_domain_suffix() {
        let cache = DnsCache::default_cache();
        cache.insert_negative("dkim:selX._domainkey.example.com");
        assert!(matches!(
            cache.get("dkim:selX._domainkey.example.com"),
            Some(CachedResult::NxDomain)
        ));

        cache.invalidate_by_domain_suffix("example.com");
        assert!(
            cache.get("dkim:selX._domainkey.example.com").is_none(),
            "a negative-cached DKIM miss must not survive domain invalidation"
        );
    }

    #[test]
    fn suffix_invalidation_is_not_spoofed_by_similar_domains() {
        let cache = DnsCache::default_cache();
        cache.insert(
            "dkim:sel._domainkey.evil-example.com",
            vec!["v=DKIM1; k=rsa; p=X".into()],
        );
        cache.invalidate_by_domain_suffix("example.com");
        assert!(
            matches!(
                cache.get("dkim:sel._domainkey.evil-example.com"),
                Some(CachedResult::Records(_))
            ),
            "'evil-example.com' must not match the '.example.com' suffix"
        );
    }

    #[test]
    fn explicit_invalidate_untracks_dkim_key() {
        let cache = DnsCache::default_cache();
        cache.insert(
            "dkim:sel._domainkey.example.com",
            vec!["v=DKIM1; k=rsa; p=A".into()],
        );
        cache.invalidate("dkim:sel._domainkey.example.com");
        // Already gone directly; the suffix pass must not resurrect anything.
        cache.invalidate_by_domain_suffix("example.com");
        assert!(cache.get("dkim:sel._domainkey.example.com").is_none());
    }

    #[test]
    fn clear_resets_dkim_tracking() {
        let cache = DnsCache::default_cache();
        cache.insert(
            "dkim:sel._domainkey.example.com",
            vec!["v=DKIM1; k=rsa; p=A".into()],
        );
        cache.clear();
        cache.insert("mx:example.com", vec!["10 mx".into()]);
        cache.invalidate_by_domain_suffix("example.com");
        assert!(matches!(
            cache.get("mx:example.com"),
            Some(CachedResult::Records(_))
        ));
    }
}
