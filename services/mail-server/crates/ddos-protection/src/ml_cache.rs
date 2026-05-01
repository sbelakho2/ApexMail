//! ML Anomaly Score Caching
//!
//! Provides a time-based cache for Isolation Forest anomaly scores to prevent
//! re-computing expensive ML predictions on every request during flood attacks.
//! //! ## Design Rationale
//! //! The Isolation Forest model runs O(num_trees * log(sample_size)) per prediction.
//! Under a 100K RPS attack, this becomes a bottleneck. Since behavioral patterns
//! don't change significantly within a 5-10 second window, we cache scores per IP
//! and session fingerprint.
//!
//! ## Cache Key Strategy
//! //! - Primary key:IP address (most common attack vector)
//! - Secondary key:Session fingerprint (for detecting distributed botnets)
//! - Expiration:10 seconds (configurable)
//!
//! ## Thread Safety
//!
//! Uses DashMap for lock-free concurrent access.

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Cached anomaly score entry
#[derive(Debug, Clone)]
pub struct CachedScore {
    /// The anomaly score (0.0 - 1.0)
    pub score: f64,
    /// Whether the score indicates an anomaly
    pub is_anomalous: bool,
    /// When the score was computed
    pub computed_at: Instant,
    /// How many times this cache entry has been hit
    pub hit_count: u64,
}

impl CachedScore {
    /// Check if the cache entry has expired
    pub fn is_expired(&self, ttl: Duration) -> bool {
        self.computed_at.elapsed() > ttl
    }
}

/// Configuration for the ML score cache
#[derive(Debug, Clone)]
pub struct MlCacheConfig {
    /// How long to cache scores (default:10 seconds)
    pub ttl: Duration,
    /// Maximum number of cached entries (default:100,000)
    pub max_entries: usize,
    /// Whether caching is enabled
    pub enabled: bool,
}

impl Default for MlCacheConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(10),
            max_entries: 100_000,
            enabled: true,
        }
    }
}

/// Thread-safe ML score cache
pub struct MlScoreCache {
    /// IP-based cache
    ip_cache: DashMap<String, CachedScore>,
    /// Session fingerprint-based cache
    session_cache: DashMap<String, CachedScore>,
    /// Configuration
    config: MlCacheConfig,
    /// Cache hit counter
    hits: AtomicU64,
    /// Cache miss counter
    misses: AtomicU64,
    /// Last cleanup time
    last_cleanup: parking_lot::RwLock<Instant>,
}

impl MlScoreCache {
    /// Create a new ML score cache
    pub fn new(config: MlCacheConfig) -> Self {
        Self {
            ip_cache: DashMap::with_capacity(config.max_entries / 2),
            session_cache: DashMap::with_capacity(config.max_entries / 2),
            config,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            last_cleanup: parking_lot::RwLock::new(Instant::now()),
        }
    }

    /// Create a new cache with default configuration
    pub fn with_defaults() -> Self {
        Self::new(MlCacheConfig::default())
    }

    /// Look up a cached score by IP address.
    /// Returns None if not cached or if the entry has expired.
    pub fn get_by_ip(&self, ip: &str) -> Option<CachedScore> {
        if !self.config.enabled {
            return None;
        }

        if let Some(mut entry) = self.ip_cache.get_mut(ip) {
            if entry.is_expired(self.config.ttl) {
                // Entry expired, will be cleaned up later
                drop(entry);
                self.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            // Update hit count
            entry.hit_count += 1;
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Some(entry.clone());
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Look up a cached score by session fingerprint.
    pub fn get_by_session(&self, session_fingerprint: &str) -> Option<CachedScore> {
        if !self.config.enabled {
            return None;
        }

        if let Some(mut entry) = self.session_cache.get_mut(session_fingerprint) {
            if entry.is_expired(self.config.ttl) {
                drop(entry);
                self.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            entry.hit_count += 1;
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Some(entry.clone());
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Store a score in the IP cache
    pub fn put_by_ip(&self, ip: &str, score: f64, is_anomalous: bool) {
        if !self.config.enabled {
            return;
        }

        // Check capacity before inserting
        self.maybe_cleanup();

        self.ip_cache.insert(
            ip.to_string(),
            CachedScore {
                score,
                is_anomalous,
                computed_at: Instant::now(),
                hit_count: 0,
            },
        );
    }

    /// Store a score in the session cache
    pub fn put_by_session(&self, session_fingerprint: &str, score: f64, is_anomalous: bool) {
        if !self.config.enabled {
            return;
        }

        self.maybe_cleanup();

        self.session_cache.insert(
            session_fingerprint.to_string(),
            CachedScore {
                score,
                is_anomalous,
                computed_at: Instant::now(),
                hit_count: 0,
            },
        );
    }

    /// Perform cleanup if enough time has passed since last cleanup
    fn maybe_cleanup(&self) {
        let last = *self.last_cleanup.read();

        // Only cleanup every 30 seconds to avoid thrashing
        if last.elapsed() < Duration::from_secs(30) {
            return;
        }

        // Try to acquire write lock without blocking
        if let Some(mut last_guard) = self.last_cleanup.try_write() {
            *last_guard = Instant::now();
            drop(last_guard);
            self.cleanup_expired();
        }
    }

    /// Remove expired entries from both caches
    pub fn cleanup_expired(&self) {
        let ttl = self.config.ttl;

        // Remove expired IP cache entries
        self.ip_cache.retain(|_, v| !v.is_expired(ttl));

        // Remove expired session cache entries
        self.session_cache.retain(|_, v| !v.is_expired(ttl));

        // If still over capacity, remove oldest entries
        let total = self.ip_cache.len() + self.session_cache.len();
        if total > self.config.max_entries {
            // Evict entries with lowest hit counts
            let target_size = self.config.max_entries * 3 / 4;
            let to_remove = total - target_size;

            // Simple eviction:remove entries based on computed_at (oldest first)
            // This is a heuristic; a proper LRU would be more sophisticated
            let mut ip_entries: Vec<_> = self
                .ip_cache
                .iter()
                .map(|r| (r.key().clone(), r.computed_at))
                .collect();
            ip_entries.sort_by_key(|(_, t)| *t);

            for (key, _) in ip_entries.into_iter().take(to_remove / 2) {
                self.ip_cache.remove(&key);
            }

            let mut session_entries: Vec<_> = self
                .session_cache
                .iter()
                .map(|r| (r.key().clone(), r.computed_at))
                .collect();
            session_entries.sort_by_key(|(_, t)| *t);

            for (key, _) in session_entries.into_iter().take(to_remove / 2) {
                self.session_cache.remove(&key);
            }
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> MlCacheStats {
        MlCacheStats {
            ip_cache_size: self.ip_cache.len(),
            session_cache_size: self.session_cache.len(),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            hit_rate: self.hit_rate(),
        }
    }

    /// Calculate cache hit rate
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;

        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }

    /// Clear the cache (useful for testing)
    pub fn clear(&self) {
        self.ip_cache.clear();
        self.session_cache.clear();
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct MlCacheStats {
    /// Number of entries in IP cache
    pub ip_cache_size: usize,
    /// Number of entries in session cache
    pub session_cache_size: usize,
    /// Total cache hits
    pub hits: u64,
    /// Total cache misses
    pub misses: u64,
    /// Hit rate (0.0 - 1.0)
    pub hit_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_cache_basic() {
        let cache = MlScoreCache::with_defaults();

        // Miss initially
        assert!(cache.get_by_ip("192.168.1.1").is_none());

        // Put and get
        cache.put_by_ip("192.168.1.1", 0.8, true);
        let entry = cache.get_by_ip("192.168.1.1");
        assert!(entry.is_some(), "entry should be cached");
        if let Some(entry) = entry {
            assert_eq!(entry.score, 0.8);
            assert!(entry.is_anomalous);
        }
    }

    #[test]
    fn test_cache_expiry() {
        let config = MlCacheConfig {
            ttl: Duration::from_millis(50),
            max_entries: 100,
            enabled: true,
        };
        let cache = MlScoreCache::new(config);

        cache.put_by_ip("192.168.1.1", 0.5, false);

        // Should be present immediately
        assert!(cache.get_by_ip("192.168.1.1").is_some());

        // Wait for expiry
        thread::sleep(Duration::from_millis(100));

        // Should be gone now (or marked expired)
        assert!(cache.get_by_ip("192.168.1.1").is_none());
    }

    #[test]
    fn test_cache_stats() {
        let cache = MlScoreCache::with_defaults();

        // Generate some misses
        cache.get_by_ip("1.1.1.1");
        cache.get_by_ip("2.2.2.2");

        // Generate some hits
        cache.put_by_ip("3.3.3.3", 0.5, false);
        cache.get_by_ip("3.3.3.3");
        cache.get_by_ip("3.3.3.3");

        let stats = cache.stats();
        assert_eq!(stats.misses, 2);
        assert_eq!(stats.hits, 2);
        assert!(stats.hit_rate > 0.0);
    }

    #[test]
    fn test_cache_disabled() {
        let config = MlCacheConfig {
            ttl: Duration::from_secs(60),
            max_entries: 100,
            enabled: false,
        };
        let cache = MlScoreCache::new(config);

        cache.put_by_ip("192.168.1.1", 0.8, true);
        assert!(cache.get_by_ip("192.168.1.1").is_none());
    }

    #[test]
    fn test_session_cache() {
        let cache = MlScoreCache::with_defaults();

        let fingerprint = "abc123fingerprint";

        cache.put_by_session(fingerprint, 0.9, true);
        let entry = cache.get_by_session(fingerprint);
        assert!(entry.is_some(), "entry should be cached");
        if let Some(entry) = entry {
            assert_eq!(entry.score, 0.9);
            assert!(entry.is_anomalous);
        }
    }
}
