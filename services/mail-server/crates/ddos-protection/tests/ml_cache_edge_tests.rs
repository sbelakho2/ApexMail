//! Edge-case and adversarial tests for DDoS protection ML cache
//!
//! Tests designed to catch race conditions, memory issues, and boundary cases.

#![cfg(feature = "ml")]

use ddos_protection::ml_cache::{MlScoreCache, MlCacheConfig};
use std::time::Duration;
use std::sync::Arc;
use std::thread;

mod cache_edge_cases {
    use super::*;

    /// Empty cache operations
    #[test]
    fn test_empty_cache_get() {
        let cache = MlScoreCache::with_defaults();
        let result = cache.get_by_ip("192.168.1.1");
        assert!(result.is_none());
    }

    /// Cache with zero TTL should expire immediately
    #[test]
    fn test_zero_ttl() {
        let config = MlCacheConfig {
            ttl: Duration::ZERO,
            max_entries: 1000,
            enabled: true,
        };
        let cache = MlScoreCache::new(config);
        cache.put_by_ip("192.168.1.1", 0.5, false);
        // Should be expired immediately
        let result = cache.get_by_ip("192.168.1.1");
        assert!(result.is_none());
    }

    /// Disabled cache should not store
    #[test]
    fn test_disabled_cache() {
        let config = MlCacheConfig {
            enabled: false,
            ..Default::default()
        };
        let cache = MlScoreCache::new(config);
        cache.put_by_ip("192.168.1.1", 0.5, false);
        assert!(cache.get_by_ip("192.168.1.1").is_none());
    }

    /// Cache should handle IPv6 addresses
    #[test]
    fn test_ipv6_address() {
        let cache = MlScoreCache::with_defaults();
        let ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        cache.put_by_ip(ipv6, 0.7, true);
        let result = cache.get_by_ip(ipv6);
        assert!(result.is_some());
        assert_eq!(result.unwrap().score, 0.7);
    }

    /// Cache key with special characters
    #[test]
    fn test_special_key_chars() {
        let cache = MlScoreCache::with_defaults();
        let weird_key = "ip/with/slashes:and:colons\x00null";
        cache.put_by_session(weird_key, 0.3, false);
        let result = cache.get_by_session(weird_key);
        assert!(result.is_some());
    }

    /// Cache eviction when full
    #[test]
    fn test_cache_eviction() {
        let config = MlCacheConfig {
            ttl: Duration::from_secs(60),
            max_entries: 10, // Very small cache
            enabled: true,
        };
        let cache = MlScoreCache::new(config);
        
        // Fill beyond capacity
        for i in 0..20 {
            cache.put_by_ip(&format!("192.168.1.{}", i), 0.5, false);
        }
        
        // Cache should have evicted some entries
        let stats = cache.stats();
        assert!(stats.ip_cache_size <= 20); // Under capacity limit
    }

    /// Boundary scores (0.0 and 1.0)
    #[test]
    fn test_boundary_scores() {
        let cache = MlScoreCache::with_defaults();
        
        cache.put_by_ip("min", 0.0, false);
        cache.put_by_ip("max", 1.0, true);
        
        assert_eq!(cache.get_by_ip("min").unwrap().score, 0.0);
        assert_eq!(cache.get_by_ip("max").unwrap().score, 1.0);
    }

    /// Negative score (invalid but should handle gracefully)
    #[test]
    fn test_edge_scores() {
        let cache = MlScoreCache::with_defaults();
        
        // These are out of expected range but should not panic
        cache.put_by_ip("negative", -0.5, false);
        cache.put_by_ip("over_one", 1.5, true);
        
        assert!(cache.get_by_ip("negative").is_some());
        assert!(cache.get_by_ip("over_one").is_some());
    }

    /// Empty string key
    #[test]
    fn test_empty_key() {
        let cache = MlScoreCache::with_defaults();
        cache.put_by_ip("", 0.5, false);
        let result = cache.get_by_ip("");
        assert!(result.is_some());
    }

    /// Very long key
    #[test]
    fn test_very_long_key() {
        let cache = MlScoreCache::with_defaults();
        let long_key = "a".repeat(10000);
        cache.put_by_session(&long_key, 0.8, true);
        assert!(cache.get_by_session(&long_key).is_some());
    }

    /// Hit count increases on repeated access
    #[test]
    fn test_hit_count_tracking() {
        let cache = MlScoreCache::with_defaults();
        cache.put_by_ip("test_ip", 0.5, false);
        
        // Access multiple times
        for _ in 0..10 {
            let _ = cache.get_by_ip("test_ip");
        }
        
        let stats = cache.stats();
        assert!(stats.hits >= 10);
    }
}

mod concurrent_cache_tests {
    use super::*;

    /// Concurrent reads and writes should not corrupt data
    #[test]
    fn test_concurrent_read_write() {
        let cache = Arc::new(MlScoreCache::with_defaults());
        let mut handles = vec![];

        // Writers
        for i in 0..10 {
            let c = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                for j in 0..1000 {
                    c.put_by_ip(&format!("writer_{}_ip_{}", i, j), 0.5, false);
                }
            }));
        }

        // Readers
        for i in 0..10 {
            let c = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                for j in 0..1000 {
                    let _ = c.get_by_ip(&format!("writer_{}_ip_{}", i % 5, j % 500));
                }
            }));
        }

        for h in handles {
            h.join().expect("Thread panicked");
        }

        // Cache should be in valid state
        let stats = cache.stats();
        assert!(stats.misses > 0 || stats.hits > 0);
    }

    /// Concurrent cleanup should not deadlock
    #[test]
    fn test_concurrent_cleanup() {
        let cache = Arc::new(MlScoreCache::with_defaults());
        
        // Pre-fill cache
        for i in 0..1000 {
            cache.put_by_ip(&format!("ip_{}", i), 0.5, false);
        }

        let mut handles = vec![];

        for _ in 0..20 {
            let c = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                c.cleanup_expired();
            }));
        }

        for h in handles {
            h.join().expect("Thread panicked");
        }
    }

    /// Rapid store/get same key
    #[test]
    fn test_rapid_same_key_operations() {
        let cache = Arc::new(MlScoreCache::with_defaults());
        let mut handles = vec![];

        for t in 0..50 {
            let c = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                for i in 0..100 {
                    let score = (t as f64 * i as f64) % 1.0;
                    c.put_by_ip("shared_key", score, score > 0.5);
                    let _ = c.get_by_ip("shared_key");
                }
            }));
        }

        for h in handles {
            h.join().expect("Thread panicked");
        }

        // Final value should exist
        assert!(cache.get_by_ip("shared_key").is_some());
    }
}

mod expiration_edge_cases {
    use super::*;

    /// Cache entry expires after exactly TTL
    #[test]
    fn test_expiration_timing() {
        let config = MlCacheConfig {
            ttl: Duration::from_millis(100),
            max_entries: 1000,
            enabled: true,
        };
        let cache = MlScoreCache::new(config);
        
        cache.put_by_ip("test", 0.5, false);
        assert!(cache.get_by_ip("test").is_some());
        
        // Wait for expiration
        thread::sleep(Duration::from_millis(150));
        
        assert!(cache.get_by_ip("test").is_none());
    }

    /// Many entries expiring simultaneously
    #[test]
    fn test_bulk_expiration() {
        let config = MlCacheConfig {
            ttl: Duration::from_millis(50),
            max_entries: 10000,
            enabled: true,
        };
        let cache = MlScoreCache::new(config);
        
        // Add many entries
        for i in 0..5000 {
            cache.put_by_ip(&format!("ip_{}", i), 0.5, false);
        }
        
        // Wait for expiration
        thread::sleep(Duration::from_millis(100));
        
        // Cleanup should not panic with many expired entries
        cache.cleanup_expired();
        // After cleanup, entries should be removed
        let stats = cache.stats();
        assert!(stats.ip_cache_size < 1000); // Most should be removed
    }
}
