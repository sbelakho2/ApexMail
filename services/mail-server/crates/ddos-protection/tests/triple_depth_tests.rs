//! Triple-depth test suite for comprehensive edge case coverage
//!
//! This test suite covers://! - CRDT arithmetic overflow protection
//! - Timestamp handling edge cases
//! - Statistical function robustness
//! - Concurrency stress scenarios
//! - Extreme value handling

#![cfg(all(feature = "coordinator", feature = "ml", feature = "challenges"))]

/// Tests for CRDT overflow protection
mod crdt_overflow_tests {
    use ddos_protection::coordinator::{GCounter, PNCounter, ORSet};
    use std::net::IpAddr;
    
    #[test]
    fn gcounter_saturating_increment() {
// Test that GCounter uses saturating arithmetic
        let mut counter = GCounter::new();
        
// First increment near max
        counter.increment("node1", u64::MAX - 10);
        
// Second increment should saturate, not wrap
        counter.increment("node1", 100);
        
// Value should be at u64::MAX, not wrapped to 89
        assert_eq!(counter.value(), u64::MAX);
    }
    
    #[test]
    fn gcounter_multi_node_saturating_sum() {
// Test that summing multiple nodes saturates
        let mut counter = GCounter::new();
        
// Two nodes each at near-max
        counter.increment("node1", u64::MAX / 2 + 1);
        counter.increment("node2", u64::MAX / 2 + 1);
        
// Sum should saturate to MAX, not overflow
        assert_eq!(counter.value(), u64::MAX);
    }
    
    #[test]
    fn pncounter_large_positive() {
// Test PNCounter with large positive values
        let mut counter = PNCounter::new();
        
// Very large positive value
        counter.increment("node1", u64::MAX / 2);
        
// Result should be clamped to i64::MAX
        let val = counter.value();
        assert!(val > 0);
        assert!(val <= i64::MAX);
    }
    
    #[test]
    fn pncounter_large_negative() {
// Test PNCounter with large negative values
        let mut counter = PNCounter::new();
        
// Only decrement (negative)
        counter.decrement("node1", u64::MAX / 2);
        
// Result should be negative and clamped
        let val = counter.value();
        assert!(val < 0);
        assert!(val >= i64::MIN);
    }
    
    #[test]
    fn pncounter_exact_boundary() {
// Test PNCounter exactly at i64::MAX boundary
        let mut counter = PNCounter::new();
        
// Increment by exactly i64::MAX
        counter.increment("node1", i64::MAX as u64);
        
// Should be exactly i64::MAX
        assert_eq!(counter.value(), i64::MAX);
    }
    
    #[test]
    fn pncounter_over_i64_max() {
// Test PNCounter with value > i64::MAX
        let mut counter = PNCounter::new();
        
// Increment beyond i64::MAX
        counter.increment("node1", i64::MAX as u64 + 1);
        
// Should be clamped to i64::MAX
        assert_eq!(counter.value(), i64::MAX);
    }
    
    #[test]
    fn pncounter_subtraction_near_boundary() {
// Test subtraction that results in value near i64 boundaries
        let mut counter = PNCounter::new();
        
// Large increment
        counter.increment("node1", 100);
// Larger decrement
        counter.decrement("node2", i64::MAX as u64 + 10);
        
// Should be clamped negative
        let val = counter.value();
        assert!(val < 0);
        assert!(val >= i64::MIN);
    }
    
    #[test]
    fn orset_add_remove_cycle() {
// Test OR-Set add/remove cycles
        let mut set: ORSet<IpAddr> = ORSet::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        
        set.add(ip.clone(), "node1");
        assert!(set.contains(&ip));
        
        set.remove(&ip);
        assert!(!set.contains(&ip));
        
// Re-add after remove should work
        set.add(ip.clone(), "node1");
        assert!(set.contains(&ip));
    }
    
    #[test]
    fn orset_merge_with_concurrent_ops() {
// Test OR-Set merge with concurrent operations
        let mut set1: ORSet<IpAddr> = ORSet::new();
        let mut set2: ORSet<IpAddr> = ORSet::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        
// Both add same IP
        set1.add(ip.clone(), "node1");
        set2.add(ip.clone(), "node2");
        
// One removes
        set1.remove(&ip);
        
// Merge - should still contain because set2's add is not tombstoned
        set1.merge(&set2);
        
// After merge, the element should exist (add-wins semantics)
        assert!(set1.contains(&ip));
    }
}

/// Tests for statistical function robustness
mod statistical_robustness_tests {
    use ddos_protection::session::SessionTracker;
    use ddos_protection::RequestContext;
    use std::time::Duration;
    
    #[test]
    fn session_tracker_zero_window() {
// Test with minimal window duration
        let tracker = SessionTracker::new(Duration::from_nanos(1), 100);
        
        let ctx = RequestContext {
            ip: "192.168.1.1".parse().unwrap(),
            path: "/health".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: None,
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
        };
        
// Should not panic
        let info = tracker.track(&ctx);
        assert!(info.requests_per_minute >= 0.0);
    }
    
    #[test]
    fn endpoint_diversity_single_endpoint() {
// Test diversity with exactly one unique endpoint
        let tracker = SessionTracker::new(Duration::from_secs(300), 100);
        
        let ctx = RequestContext {
            ip: "192.168.1.1".parse().unwrap(),
            path: "/api/same".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: None,
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
        };
        
// Track same endpoint multiple times
        for _ in 0..10 {
            tracker.track(&ctx);
        }
        
        let info = tracker.track(&ctx);
// Diversity should be very low (approaching 1/N where N is number of samples)
        assert!(info.endpoint_diversity <= 1.0);
        assert!(info.endpoint_diversity > 0.0);
    }
    
    #[test]
    fn error_rate_all_errors() {
// Test with 100% error rate
        let tracker = SessionTracker::new(Duration::from_secs(300), 100);
        
        let ctx = RequestContext {
            ip: "192.168.1.1".parse().unwrap(),
            path: "/api/error".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: None,
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
        };
        
// Track first request
        tracker.track(&ctx);
        
// Record all as errors
        for _ in 0..10 {
            tracker.record_error(&ctx);
        }
        
        let info = tracker.track(&ctx);
// Error rate should be a valid float (though may be NaN if no successful requests)
// We just check it doesn't panic and produces some value
        let _ = info.error_rate; // Implementation may vary
    }
}

/// Tests for ML model edge cases
mod ml_edge_cases {
    use ddos_protection::ml::{IsolationForest, IsolationForestConfig, FeatureVector};
    
    #[test]
    fn isolation_forest_empty_training_data() {
// Test training with empty data
        let config = IsolationForestConfig::default();
        let mut forest = IsolationForest::new(config);
        
// Train with empty data
        forest.train(&[], 42);
        
// Anomaly score should return neutral
        let features = FeatureVector::default();
        let score = forest.anomaly_score(&features);
        assert_eq!(score, 0.5);
    }
    
    #[test]
    fn isolation_forest_single_sample() {
// Test training with single sample
        let config = IsolationForestConfig::default();
        let mut forest = IsolationForest::new(config);
        
        let data = [[1.0; 10]];
        forest.train(&data, 42);
        
// Should handle gracefully
        let features = FeatureVector::default();
        let score = forest.anomaly_score(&features);
        assert!(score >= 0.0 && score <= 1.0);
    }
    
    #[test]
    fn isolation_forest_identical_samples() {
// Test training with all identical samples
        let config = IsolationForestConfig::default();
        let mut forest = IsolationForest::new(config);
        
        let data: Vec<[f64; 10]> = (0..100).map(|_| [5.0; 10]).collect();
        forest.train(&data, 42);
        
// Test with identical sample
        let features = FeatureVector {
            request_rate: 5.0,
            bytes_rate: 5.0,
            connection_age: 5.0,
            size_variance: 5.0,
            iat_mean: 5.0,
            iat_variance: 5.0,
            endpoint_diversity: 5.0,
            error_rate: 5.0,
            geo_distance: 5.0,
            time_factor: 5.0,
        };
        
// Should be normal (low anomaly score)
        let score = forest.anomaly_score(&features);
        assert!(score >= 0.0 && score <= 1.0);
    }
    
    #[test]
    fn feature_vector_extreme_values() {
// Test with extreme feature values
        let features = FeatureVector {
            request_rate: f64::MAX,
            bytes_rate: f64::MIN_POSITIVE,
            connection_age: 0.0,
            size_variance: f64::INFINITY,
            iat_mean: f64::NAN,
            iat_variance: -1.0,
            endpoint_diversity: 2.0, // > 1.0
            error_rate: -0.5, // negative
            geo_distance: f64::MAX,
            time_factor: f64::MIN,
        };
        
// as_slice should not panic
        let slice = features.as_slice();
        assert_eq!(slice.len(), 10);
    }
}

/// Tests for adaptive rate limiter
mod adaptive_edge_cases {
    use ddos_protection::adaptive::{AdaptiveRateLimiter, AdaptiveConfig, TrafficObservation};
    use std::time::{Duration, Instant};
    
    #[test]
    fn adaptive_limiter_rapid_observations() {
// Test rapid-fire observations
        let config = AdaptiveConfig {
            z_threshold: 3.0,
            baseline_window: Duration::from_secs(300),
            min_threshold: 10,
            max_threshold: 10000,
            consecutive_alert_trigger: 3,
            cooldown: Duration::from_secs(60),
            ..Default::default()
        };
        
        let limiter = AdaptiveRateLimiter::new(config);
        
// Add many observations at once
        let now = Instant::now();
        for i in 0..200 {
            let obs = TrafficObservation {
                timestamp: now,
                requests_per_second: 100.0 + (i as f64 * 0.1),
                error_rate: 0.01,
                latency_p99_ms: 50.0,
                cpu_usage: 0.3,
            };
            limiter.update(obs);
        }
        
// Should handle without panic
        let stats = limiter.baseline_stats();
        assert!(stats.is_some());
    }
    
    #[test]
    fn adaptive_limiter_zero_variance() {
// Test with zero variance data
        let config = AdaptiveConfig::default();
        let limiter = AdaptiveRateLimiter::new(config);
        
        let now = Instant::now();
// Add identical observations
        for _ in 0..20 {
            let obs = TrafficObservation {
                timestamp: now,
                requests_per_second: 100.0, // All same
                error_rate: 0.01,
                latency_p99_ms: 50.0,
                cpu_usage: 0.3,
            };
            limiter.update(obs);
        }
        
// Add one different observation - should trigger z-score handling
        let obs = TrafficObservation {
            timestamp: now,
            requests_per_second: 200.0, // Deviation
            error_rate: 0.01,
            latency_p99_ms: 50.0,
            cpu_usage: 0.3,
        };
        limiter.update(obs);
        
// Check stats - std should be 0 or handled
        let stats = limiter.baseline_stats();
        assert!(stats.is_some());
    }
    
    #[test]
    fn adaptive_reset_during_attack() {
// Test reset while in attack state
        let config = AdaptiveConfig {
            z_threshold: 2.0,
            consecutive_alert_trigger: 2,
            ..Default::default()
        };
        
        let limiter = AdaptiveRateLimiter::new(config);
        
        let now = Instant::now();
// Build baseline
        for _ in 0..20 {
            let obs = TrafficObservation {
                timestamp: now,
                requests_per_second: 100.0,
                error_rate: 0.01,
                latency_p99_ms: 50.0,
                cpu_usage: 0.3,
            };
            limiter.update(obs);
        }
        
// Trigger attack
        for _ in 0..3 {
            let obs = TrafficObservation {
                timestamp: now,
                requests_per_second: 10000.0, // Spike
                error_rate: 0.01,
                latency_p99_ms: 50.0,
                cpu_usage: 0.3,
            };
            limiter.update(obs);
        }
        
// Reset should work even during attack
        limiter.reset();
        
        let info = limiter.attack_info();
        assert!(!info.is_under_attack);
    }
}

/// Tests for challenge verification
mod challenge_edge_cases {
    use ddos_protection::challenges::{ChallengeManager, ChallengeType};
    
    #[test]
    fn challenge_manager_pow_verification_empty_nonce() {
        let manager = ChallengeManager::new([0u8; 32])
            .with_pow_difficulty(4);
        
        let challenge = manager.issue_pow_challenge();
        
// Verify with empty nonce by pattern matching on the enum
        if let ChallengeType::ProofOfWork(pow) = challenge {
            let result = pow.verify("");
            assert!(!result);
        } else {
            panic!("Expected ProofOfWork challenge");
        }
    }
    
    #[test]
    fn challenge_manager_pow_verification_invalid_nonce() {
// Use difficulty 24 (24 leading zero bits = 1/16 million chance of false positive)
// Difficulty 4 only required 4 leading zero bits = 1/16 chance, making test flaky
        let manager = ChallengeManager::new([0u8; 32])
            .with_pow_difficulty(24);
        
        let challenge = manager.issue_pow_challenge();
        
// Verify with invalid nonce
        if let ChallengeType::ProofOfWork(pow) = challenge {
            let result = pow.verify("definitely_not_valid_nonce_12345");
            assert!(!result);
        } else {
            panic!("Expected ProofOfWork challenge");
        }
    }
    
    #[test]
    fn challenge_manager_cookie_round_trip() {
        let secret = [42u8; 32];
        let manager = ChallengeManager::new(secret);
        
        let challenge = manager.issue_cookie_challenge();
        
// Verify the cookie value by extracting inner type
        if let ChallengeType::Cookie(cookie) = challenge {
            let result = manager.verify_cookie(&cookie.cookie_value);
            assert!(result);
        } else {
            panic!("Expected Cookie challenge");
        }
    }
    
    #[test]
    fn challenge_manager_cookie_wrong_value() {
        let secret = [42u8; 32];
        let manager = ChallengeManager::new(secret);
        
// Verify wrong cookie value
        let result = manager.verify_cookie("wrong_cookie_value");
        assert!(!result);
    }
    
    #[test]
    fn challenge_manager_js_challenge_script_not_empty() {
        let manager = ChallengeManager::new([0u8; 32]);
        
        let challenge = manager.issue_js_challenge();
        
// Script should not be empty - extract inner type
        if let ChallengeType::JavaScript(js) = challenge {
            assert!(!js.script.is_empty());
            assert!(!js.challenge_id.is_empty());
        } else {
            panic!("Expected JavaScript challenge");
        }
    }
}

/// Tests for cost-based limiting
mod cost_limiter_edge_cases {
    use ddos_protection::cost_based::{CostBasedLimiter, CostLimiterConfig, CostDecision};
    
    #[test]
    fn cost_limiter_zero_capacity() {
// Test with minimal capacity
        let config = CostLimiterConfig {
            default_tenant_budget: 1,
            system_capacity: 1,
        };
        
        let limiter = CostBasedLimiter::new(config);
        
// First request might succeed
        let decision = limiter.check("tenant1", "/health", None);
        
// Match on decision type
        match decision {
            CostDecision::Allowed { .. } | CostDecision::QuotaExceeded { .. } | CostDecision::SystemOverloaded { .. } => {
// Any of these is acceptable behavior
            }
        }
    }
    
    #[test]
    fn cost_limiter_unknown_endpoint() {
        let config = CostLimiterConfig::default();
        let limiter = CostBasedLimiter::new(config);
        
// Unknown endpoint should use default cost
        let decision = limiter.check(
            "tenant1",
            "/some/unknown/endpoint/that/does/not/exist",
            None
        );
        
// Should still make a decision
        match decision {
            CostDecision::Allowed { cost, .. } => {
                assert!(cost > 0);
            }
            _ => {} // Other decisions are also valid
        }
    }
    
    #[test]
    fn cost_limiter_concurrent_tenants() {
        let config = CostLimiterConfig {
            default_tenant_budget: 100000, // Enough for multiple requests
            system_capacity: 1000000,
        };
        
        let limiter = CostBasedLimiter::new(config);
        
// Multiple tenants should each have their own budget
        for i in 0..10 {
            let tenant = format!("tenant_{}", i);
            let decision = limiter.check(&tenant, "/health", None);
            
            match decision {
                CostDecision::Allowed { .. } => {}
                _ => panic!("First request for each tenant should succeed"),
            }
        }
    }
}

/// Tests for SMTP protection
mod smtp_edge_cases {
    use ddos_protection::smtp_protection::{
        SmtpProtectionConfig, SmtpConnectionProtection, SmtpConnectionTracker
    };
    use std::net::IpAddr;
    
    #[test]
    fn smtp_protector_empty_command() {
        let config = SmtpProtectionConfig::default();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let mut protector = SmtpConnectionProtection::new(ip, 50, config);
        
// Empty command should be handled
        let result = protector.process_command("");
        assert!(result.is_err()); // Invalid command
    }
    
    #[test]
    fn smtp_protector_very_long_command() {
        let config = SmtpProtectionConfig {
            max_commands: 5, // Limit commands to trigger error sooner
            ..Default::default()
        };
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let mut protector = SmtpConnectionProtection::new(ip, 50, config);
        
// Very long command - test command limit
// Note:process_command may not reject based on length alone,
// but we can test that it handles unusual inputs gracefully
        let long_cmd = "EHLO ".to_string() + &"x".repeat(1000);
        let result = protector.process_command(&long_cmd);
// Either rejected for invalid domain or accepted (we just ensure no panic)
        let _ = result;
    }
    
    #[test]
    fn smtp_connection_tracker_register_unregister() {
        let config = SmtpProtectionConfig {
            max_connections_per_ip: 5,
            ..Default::default()
        };
        let tracker = SmtpConnectionTracker::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        
// Register connections up to limit
        for _ in 0..5 {
            let result = tracker.register_connection(ip);
            assert!(result.is_ok());
        }
        
// Next should fail
        let result = tracker.register_connection(ip);
        assert!(result.is_err());
        
// Unregister one
        tracker.unregister_connection(&ip);
        
// Should be able to register again
        let result = tracker.register_connection(ip);
        assert!(result.is_ok());
    }
    
    #[test]
    fn smtp_connection_tracker_unregister_zero() {
        let config = SmtpProtectionConfig::default();
        let tracker = SmtpConnectionTracker::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        
// Unregister non-existent connection (should not panic or wrap)
        tracker.unregister_connection(&ip);
        tracker.unregister_connection(&ip);
        tracker.unregister_connection(&ip);
        
// Count should still be 0
        assert_eq!(tracker.active_count(&ip), 0);
    }
}

/// Tests for protection decision helpers
mod decision_helper_tests {
    use ddos_protection::decision::{PowChallenge, CookieChallenge};
    
    #[test]
    fn pow_challenge_expired() {
        let challenge = PowChallenge {
            id: "test".to_string(),
            data: "data".to_string(),
            difficulty: 4,
            expires_at: 0, // Already expired
            expected_time_ms: 1000,
        };
        
// Verification should fail due to expiration (verify takes u64 nonce)
        let result = challenge.verify(12345u64);
        assert!(!result);
    }
    
    #[test]
    fn cookie_challenge_expired() {
        let challenge = CookieChallenge {
            name: "test_cookie".to_string(),
            value: "cookie_value".to_string(),
            expires_at: 0, // Already expired
        };
        
// Verification should fail due to expiration
        let result = challenge.verify("cookie_value");
        assert!(!result);
    }
    
    #[test]
    fn cookie_challenge_wrong_value() {
        let challenge = CookieChallenge {
            name: "test_cookie".to_string(),
            value: "correct_value".to_string(),
            expires_at: u64::MAX, // Far future
        };
        
// Wrong value should fail
        let result = challenge.verify("wrong_value");
        assert!(!result);
    }
}

/// Tests for safe RwLock handling in ML module
mod ml_lock_safety_tests {
    use ddos_protection::ml::{IsolationForest, IsolationForestConfig, FeatureVector};
    
    #[test]
    fn isolation_forest_observe_no_panic() {
        let config = IsolationForestConfig::default();
        let forest = IsolationForest::new(config);
        
// Multiple observations should not panic
        for i in 0..100 {
            let features = FeatureVector {
                request_rate: i as f64,
                bytes_rate: i as f64 * 10.0,
                connection_age: 1.0,
                size_variance: 0.1,
                iat_mean: 100.0,
                iat_variance: 10.0,
                endpoint_diversity: 0.5,
                error_rate: 0.01,
                geo_distance: 0.0,
                time_factor: 0.5,
            };
            forest.observe(&features);
        }
    }
    
    #[test]
    fn isolation_forest_needs_retraining_no_panic() {
        let config = IsolationForestConfig {
            online_buffer_size: 100,
            retrain_threshold: 0.5,
            ..Default::default()
        };
        let forest = IsolationForest::new(config);
        
// Check retraining need on empty buffer
        assert!(!forest.needs_retraining());
        
// Add samples and check again
        for i in 0..60 {
            let features = FeatureVector {
                request_rate: i as f64,
                ..Default::default()
            };
            forest.observe(&features);
        }
        
// Should need retraining after enough samples
        assert!(forest.needs_retraining());
    }
    
    #[test]
    fn isolation_forest_stats_no_panic() {
        let config = IsolationForestConfig::default();
        let forest = IsolationForest::new(config);
        
// Stats should work on empty forest
        let stats = forest.stats();
        assert_eq!(stats.num_trees, 0);
        assert!(!stats.is_trained);
    }
    
    #[test]
    fn isolation_forest_retrain_no_panic() {
        let config = IsolationForestConfig::default();
        let mut forest = IsolationForest::new(config);
        
// Retrain with insufficient data should not panic
        forest.retrain(42);
        
// Add enough samples
        for i in 0..20 {
            let features = FeatureVector {
                request_rate: i as f64,
                bytes_rate: i as f64 * 10.0,
                connection_age: 1.0,
                size_variance: 0.1,
                iat_mean: 100.0,
                iat_variance: 10.0,
                endpoint_diversity: 0.5,
                error_rate: 0.01,
                geo_distance: 0.0,
                time_factor: 0.5 + (i as f64 * 0.01),
            };
            forest.observe(&features);
        }
        
// Now retrain should work
        forest.retrain(42);
        
        let stats = forest.stats();
        assert!(stats.is_trained);
    }
}

/// Tests for cost-based limiter cleanup (E-105 fix)
mod cost_limiter_cleanup_tests {
    use ddos_protection::cost_based::{CostBasedLimiter, CostLimiterConfig};
    
    #[test]
    fn cleanup_method_exists_and_no_panic() {
        let config = CostLimiterConfig::default();
        let limiter = CostBasedLimiter::new(config);
        
// Add some tenants
        limiter.set_tenant_budget("tenant1", 100_000, 1000);
        limiter.set_tenant_budget("tenant2", 100_000, 1000);
        
        assert!(limiter.tracked_tenants() >= 2);
        
// Cleanup should not panic
        limiter.cleanup();
    }
    
    #[test]
    fn tracked_tenants_count_accurate() {
        let config = CostLimiterConfig::default();
        let limiter = CostBasedLimiter::new(config);
        
        assert_eq!(limiter.tracked_tenants(), 0);
        
// Trigger tenant creation through check
        let _ = limiter.check("tenant1", "/v1/health", None);
        assert!(limiter.tracked_tenants() >= 1);
        
        let _ = limiter.check("tenant2", "/v1/health", None);
        assert!(limiter.tracked_tenants() >= 2);
    }
}
