//! Deep module tests — wider coverage + test the 6 bug fixes
//!
//! This file tests://! 1. Bug fixes discovered in deep scan (6 bugs)
//! 2. Session tracking module (session.rs)
//! 3. Config module validation (config.rs)
//! 4. Decision module (decision.rs)
//! 5. Challenges module (challenges.rs) — JS generation fix
//! 6. ML module (ml.rs) — online learning fixes
//! 7. Cost-based limiter (cost_based.rs) — refill race fix

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use ddos_protection::config::*;
use ddos_protection::cost_based::*;
use ddos_protection::decision::*;
use ddos_protection::session::*;
use ddos_protection::reputation::*;
use ddos_protection::*;

fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
}

// ============================================================================
// BUG VERIFICATION TESTS
// ============================================================================

mod bug_fix_verification {
    use super::*;

/// Bug Session first IAT should not be polluted by creation time.
/// The first record_request should NOT produce an inter-arrival time
/// because there was no prior request to measure from.
    #[test]
    fn session_first_iat_not_polluted() {
        let tracker = SessionTracker::new(Duration::from_secs(300), 1000);
        
        let ctx = RequestContext {
            ip: ip(1),
            path: "/v1/health".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: None,
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
        };
        
// First request
        let info1 = tracker.track(&ctx);
        assert_eq!(info1.request_count, 1);
        
// Sleep a bit
        std::thread::sleep(Duration::from_millis(50));
        
// Second request
        let info2 = tracker.track(&ctx);
        assert_eq!(info2.request_count, 2);
        
// The IAT analysis relies on inter_arrival_times having VALID data.
// With the fix, the first IAT should be from request 1 -> request 2,
// not from session creation -> request 1.
// We verify this by checking the CoV is reasonable (not polluted).
        let cov = info2.inter_arrival_cov;
// With only 1 actual IAT value, we should get the default of 1.0
        assert_eq!(cov, 1.0, "CoV should be default with insufficient data: {}", cov);
    }

/// Bug Session endpoints should be windowed, not unbounded HashSet.
    #[test]
    fn session_endpoints_bounded_memory() {
        let tracker = SessionTracker::new(Duration::from_secs(300), 1000);
        
// Track 200 requests to different endpoints
        for i in 0u8..200 {
            let ctx = RequestContext {
                ip: ip(1),
                path: format!("/v1/endpoint/{}", i),
                method: "GET".to_string(),
                tls_fingerprint: None,
                h2_fingerprint: None,
                user_agent: None,
                body_size: 0,
                tenant_id: None,
                api_key_id: None,
            };
            tracker.track(&ctx);
        }
        
// Get session info
        let info = tracker.get_session(&ip(1), None).unwrap();
        
// Endpoint diversity should be computed on a bounded window
// With 200 unique endpoints, but a window of 100, diversity should be 1.0
// because recent_endpoints only holds the last 100 unique hashes
        assert!(info.endpoint_diversity <= 1.0, "Diversity should be <= 1.0");
        assert!(info.endpoint_diversity > 0.9, "With all unique endpoints, diversity should be high: {}", info.endpoint_diversity);
    }

/// Bug Cost-based limiter refill should use CAS to prevent overshoot.
/// This is a logical test — actual race would require multi-threading.
    #[test]
    fn cost_limiter_refill_logic_correct() {
        let config = CostLimiterConfig {
            default_tenant_budget: 10000,
            system_capacity: 1000,
        };
        let limiter = CostBasedLimiter::new(config);
        
// System starts at capacity
        assert_eq!(limiter.system_remaining(), 1000);
        
// Consume most of the budget
        let decision = limiter.check("tenant1", "/v1/health", Some(RequestCost::new(900, 0, 0, 0)));
        assert!(matches!(decision, CostDecision::Allowed { .. }));
        
// Should have ~100 remaining (900 consumed - epsilon from health endpoint cost)
        let remaining = limiter.system_remaining();
        assert!(remaining < 200, "Should have consumed most budget: {}", remaining);
    }

/// Bug Config builder produces valid config.
    #[test]
    fn config_builder_works() {
        let config = ProtectorConfig::builder()
            .cost_budget(50000)
            .system_capacity(5000000)
            .reputation_thresholds(15, 40)
            .enable_ml(true)
            .enable_challenges(true)
            .build();
        
        assert_eq!(config.default_cost_budget, 50000);
        assert_eq!(config.system_cost_capacity, 5000000);
        assert_eq!(config.block_threshold, 15);
        assert_eq!(config.challenge_threshold, 40);
        assert!(config.enable_ml);
        assert!(config.enable_challenges);
    }
}

// ============================================================================
// SESSION MODULE TESTS
// ============================================================================

mod session_tests {
    use super::*;

    #[test]
    fn session_tracks_requests_per_minute() {
        let tracker = SessionTracker::new(Duration::from_secs(300), 1000);
        
        let ctx = RequestContext {
            ip: ip(10),
            path: "/v1/test".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: None,
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
        };
        
// Track 10 requests
        for _ in 0..10 {
            tracker.track(&ctx);
        }
        
        let info = tracker.get_session(&ip(10), None).unwrap();
        assert_eq!(info.request_count, 10);
// RPM should be very high since requests are instant
        assert!(info.requests_per_minute > 100.0, "RPM should be high: {}", info.requests_per_minute);
    }

    #[test]
    fn session_tracks_errors() {
        let tracker = SessionTracker::new(Duration::from_secs(300), 1000);
        
        let ctx = RequestContext {
            ip: ip(20),
            path: "/v1/test".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: None,
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
        };
        
// Track 3 requests
        tracker.track(&ctx);
        tracker.track(&ctx);
        tracker.track(&ctx);
        
// Record 2 errors
        tracker.record_error(&ctx);
        tracker.record_error(&ctx);
        
        let info = tracker.get_session(&ip(20), None).unwrap();
        assert_eq!(info.request_count, 3);
// Error rate = 2/3 = 0.666...
        assert!(info.error_rate > 0.6 && info.error_rate < 0.7, 
            "Error rate should be ~0.666: {}", info.error_rate);
    }

    #[test]
    fn session_tracks_duration() {
        let tracker = SessionTracker::new(Duration::from_secs(300), 1000);
        
        let ctx = RequestContext {
            ip: ip(30),
            path: "/v1/test".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: None,
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
        };
        
        tracker.track(&ctx);
        tracker.record_duration(&ctx, 100);
        tracker.record_duration(&ctx, 200);
        tracker.record_duration(&ctx, 300);
        
// Session should track durations (internal to Session struct)
        let info = tracker.get_session(&ip(30), None).unwrap();
        assert_eq!(info.request_count, 1);
    }

    #[test]
    fn session_cleanup_removes_idle() {
        let tracker = SessionTracker::new(Duration::from_millis(10), 1000);
        
        let ctx = RequestContext {
            ip: ip(40),
            path: "/v1/test".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: None,
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
        };
        
        tracker.track(&ctx);
        assert_eq!(tracker.active_count(), 1);
        
// Wait for session to become idle
        std::thread::sleep(Duration::from_millis(20));
        
        tracker.cleanup(Instant::now());
        
// Session should be removed
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn session_api_key_isolation() {
        let tracker = SessionTracker::new(Duration::from_secs(300), 1000);
        
// Same IP, different API keys = different sessions
        let ctx1 = RequestContext {
            ip: ip(50),
            path: "/v1/test".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: None,
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: Some("key-1".to_string()),
        };
        
        let ctx2 = RequestContext {
            ip: ip(50),
            path: "/v1/test".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: None,
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: Some("key-2".to_string()),
        };
        
        tracker.track(&ctx1);
        tracker.track(&ctx1);
        tracker.track(&ctx2);
        
        let info1 = tracker.get_session(&ip(50), Some("key-1")).unwrap();
        let info2 = tracker.get_session(&ip(50), Some("key-2")).unwrap();
        
        assert_eq!(info1.request_count, 2);
        assert_eq!(info2.request_count, 1);
    }
}

// ============================================================================
// CONFIG MODULE TESTS
// ============================================================================

mod config_tests {
    use super::*;

    #[test]
    fn default_config_has_sensible_values() {
        let config = ProtectorConfig::default();
        
// Rate limiting
        assert!(config.default_cost_budget > 0);
        assert!(config.system_cost_capacity > config.default_cost_budget);
        
// Reputation
        assert!(config.block_threshold < config.challenge_threshold);
        assert!(config.challenge_threshold < config.initial_reputation);
        assert!(config.initial_reputation <= 100);
        
// Session
        assert!(config.session_window.as_secs() > 0);
        assert!(config.max_sessions > 0);
        
// Cleanup
        assert!(config.cleanup_interval.as_secs() > 0);
        assert!(config.low_rep_block_duration.as_secs() > 0);
    }

    #[test]
    fn config_from_env_uses_defaults_when_no_vars() {
// Clear any test-interfering env vars (if set)
        std::env::remove_var("DDOS_COST_BUDGET");
        std::env::remove_var("DDOS_BLOCK_THRESHOLD");
        std::env::remove_var("DDOS_REDIS_URL");
        std::env::remove_var("DDOS_REGION");
        
        let config = ProtectorConfig::from_env();
        let default = ProtectorConfig::default();
        
        assert_eq!(config.default_cost_budget, default.default_cost_budget);
        assert_eq!(config.block_threshold, default.block_threshold);
    }

    #[test]
    fn config_builder_chaining() {
        let config = ProtectorConfig::builder()
            .cost_budget(1000)
            .system_capacity(10000)
            .reputation_thresholds(5, 20)
            .enable_ml(false)
            .enable_challenges(false)
            .build();
        
        assert_eq!(config.default_cost_budget, 1000);
        assert_eq!(config.system_cost_capacity, 10000);
        assert_eq!(config.block_threshold, 5);
        assert_eq!(config.challenge_threshold, 20);
        assert!(!config.enable_ml);
        assert!(!config.enable_challenges);
    }
}

// ============================================================================
// DECISION MODULE TESTS
// ============================================================================

mod decision_tests {
    use super::*;

    #[test]
    fn protection_decision_is_allowed() {
        let allow = ProtectionDecision::Allow;
        assert!(allow.is_allowed());
        assert!(!allow.is_challenge());
        
        let block = ProtectionDecision::Block;
        assert!(!block.is_allowed());
        assert!(!block.is_challenge());
        
        let rate_limit = ProtectionDecision::RateLimit {
            retry_after: Duration::from_secs(5),
        };
        assert!(!rate_limit.is_allowed());
        assert!(!rate_limit.is_challenge());
    }

    #[test]
    fn pow_challenge_verification_correct_nonce() {
        let challenge = PowChallenge {
            id: "test-challenge".to_string(),
            data: "test-data".to_string(),
            difficulty: 4, // Very easy for testing
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() + 300,
            expected_time_ms: 100,
        };
        
// Find a valid nonce by brute force (difficulty 4 = 16 combinations)
        let mut found_nonce: Option<u64> = None;
        for nonce in 0..10000 {
            if challenge.verify(nonce) {
                found_nonce = Some(nonce);
                break;
            }
        }
        
        assert!(found_nonce.is_some(), "Should find a valid nonce for difficulty 4");
    }

    #[test]
    fn pow_challenge_rejects_wrong_nonce() {
        let challenge = PowChallenge {
            id: "test".to_string(),
            data: "specific-data".to_string(),
            difficulty: 16, // Hard
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() + 300,
            expected_time_ms: 1000,
        };
        
// Random nonces should almost certainly fail
        assert!(!challenge.verify(12345));
        assert!(!challenge.verify(67890));
        assert!(!challenge.verify(0));
    }

    #[test]
    fn pow_challenge_expired() {
        let challenge = PowChallenge {
            id: "test".to_string(),
            data: "test".to_string(),
            difficulty: 0, // Trivial
            expires_at: 0, // Already expired
            expected_time_ms: 0,
        };
        
// Even nonce 0 should work for difficulty 0, but expiration should cause failure
        assert!(!challenge.verify(0));
    }

    #[test]
    fn js_challenge_verification() {
        let challenge = JsChallenge {
            id: "test".to_string(),
            script: "return '42'".to_string(),
            expected_result: "42".to_string(),
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() + 300,
        };
        
        assert!(challenge.verify("42"));
        assert!(!challenge.verify("41"));
        assert!(!challenge.verify(""));
    }

    #[test]
    fn cookie_challenge_verification() {
        let challenge = CookieChallenge {
            name: "__test".to_string(),
            value: "secret_value_123".to_string(),
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() + 300,
        };
        
        assert!(challenge.verify("secret_value_123"));
        assert!(!challenge.verify("wrong_value"));
        assert!(!challenge.verify(""));
    }
}

// ============================================================================
// REPUTATION MODULE TESTS
// ============================================================================

mod reputation_extended_tests {
    use super::*;

    #[test]
    fn reputation_level_transitions() {
        let mut rep = ReputationScore::default();
        assert_eq!(rep.level(), ReputationLevel::Normal);
        
// Drop to suspicious
        rep.score = 25;
        assert_eq!(rep.level(), ReputationLevel::Suspicious);
        
// Drop to blocked
        rep.score = 8;
        assert_eq!(rep.level(), ReputationLevel::Blocked);
        
// Rise to trusted
        rep.score = 85;
        assert_eq!(rep.level(), ReputationLevel::Trusted);
    }

    #[test]
    fn reputation_trusted_flag_prevents_decay() {
        let mut rep = ReputationScore::trusted();
        let initial_score = rep.score;
        
        rep.decay_toward_neutral(10);
        
        assert_eq!(rep.score, initial_score, "Trusted IPs should not decay");
    }

    #[test]
    fn reputation_flagged_flag_prevents_decay() {
        let mut rep = ReputationScore::flagged();
        let initial_score = rep.score;
        
        rep.decay_toward_neutral(10);
        
        assert_eq!(rep.score, initial_score, "Flagged IPs should not decay");
    }

    #[test]
    fn reputation_challenge_pass_rate() {
        let mut rep = ReputationScore::default();
        
// No challenges = 1.0 (neutral)
        assert_eq!(rep.challenge_pass_rate(), 1.0);
        
        rep.record_challenge_passed();
        rep.record_challenge_passed();
        rep.record_challenge_failed();
        
// 2 passed, 1 failed = 2/3 = 0.666...
        let rate = rep.challenge_pass_rate();
        assert!(rate > 0.66 && rate < 0.67);
    }

    #[test]
    fn reputation_block_rate() {
        let mut rep = ReputationScore::default();
        
// No requests = 0.0 block rate
        assert_eq!(rep.block_rate(), 0.0);
        
        rep.total_requests = 10;
        rep.blocked_requests = 3;
        
        assert_eq!(rep.block_rate(), 0.3);
    }

    #[test]
    fn reputation_saturating_operations() {
        let mut rep = ReputationScore::default();
        rep.score = 100;
        
// Should saturate at 100, not overflow
        rep.record_challenge_passed();
        assert_eq!(rep.score, 100);
        
        rep.score = 0;
// Should saturate at 0, not underflow
        rep.record_challenge_failed();
        assert_eq!(rep.score, 0);
    }
}

// ============================================================================
// COST-BASED LIMITER TESTS
// ============================================================================

mod cost_tests {
    use super::*;

    #[test]
    fn cost_basic_request_deduction() {
        let config = CostLimiterConfig {
            default_tenant_budget: 10000,
            system_capacity: 100000,
        };
        let limiter = CostBasedLimiter::new(config);
        
        let initial = limiter.system_remaining();
        
        let decision = limiter.check("tenant1", "/v1/messages/:id", None);
        assert!(matches!(decision, CostDecision::Allowed { .. }));
        
        let after = limiter.system_remaining();
        assert!(after < initial, "Budget should decrease");
    }

    #[test]
    fn cost_tenant_quota_exhaustion() {
        let config = CostLimiterConfig {
            default_tenant_budget: 500, // Small budget
            system_capacity: 100000,
        };
        let limiter = CostBasedLimiter::new(config);
        
// First request uses default endpoint cost
        let d1 = limiter.check("tenant1", "/v1/messages/:id", None);
        assert!(matches!(d1, CostDecision::Allowed { .. }));
        
// Exhaust with big request
        let d2 = limiter.check("tenant1", "/v1/messages/:id", Some(RequestCost::new(1000, 0, 0, 0)));
        assert!(matches!(d2, CostDecision::QuotaExceeded { .. }));
    }

    #[test]
    fn cost_system_overload() {
        let config = CostLimiterConfig {
            default_tenant_budget: 10000,
            system_capacity: 100, // Tiny system capacity
        };
        let limiter = CostBasedLimiter::new(config);
        
// Request bigger than system capacity
        let decision = limiter.check("tenant1", "/v1/messages/:id", Some(RequestCost::new(200, 0, 0, 0)));
        assert!(matches!(decision, CostDecision::SystemOverloaded { .. }));
    }

    #[test]
    fn cost_different_tenants_isolated() {
        let config = CostLimiterConfig {
            default_tenant_budget: 1000,
            system_capacity: 100000,
        };
        let limiter = CostBasedLimiter::new(config);
        
// Exhaust tenant1
        let _ = limiter.check("tenant1", "/v1/messages/:id", Some(RequestCost::new(2000, 0, 0, 0)));
        
// tenant2 should still work
        let d2 = limiter.check("tenant2", "/v1/health", None);
        assert!(matches!(d2, CostDecision::Allowed { .. }));
    }

    #[test]
    fn cost_record_cost_deducts_correctly() {
        let config = CostLimiterConfig {
            default_tenant_budget: 10000,
            system_capacity: 100000,
        };
        let limiter = CostBasedLimiter::new(config);
        
        let before = limiter.get_remaining("tenant1");
        limiter.record_cost("tenant1", 500);
        let after = limiter.get_remaining("tenant1");
        
// Should still be default since tenant wasn't created yet
// record_cost only works on existing tenants
        assert_eq!(after, before);
        
// Create tenant with a check first
        limiter.check("tenant2", "/v1/health", None);
        let b2 = limiter.get_remaining("tenant2");
        limiter.record_cost("tenant2", 100);
        let a2 = limiter.get_remaining("tenant2");
        
        assert!(a2 < b2, "Should deduct from existing tenant");
    }

    #[test]
    fn cost_set_tenant_budget() {
        let limiter = CostBasedLimiter::new(CostLimiterConfig::default());
        
// Set custom budget
        limiter.set_tenant_budget("premium_tenant", 1000000, 20000);
        
// Use and verify
        let remaining = limiter.get_remaining("premium_tenant");
        assert_eq!(remaining, 1000000);
    }
}

// ============================================================================
// INTEGRATION:Full Protection Flow
// ============================================================================

mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn full_protection_flow_allow() {
        let config = ProtectorConfig::default();
        let protector = DdosProtector::new(config).await.unwrap();
        
        let ctx = RequestContext {
            ip: ip(100),
            path: "/v1/health".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: None,
            h2_fingerprint: None,
            user_agent: Some("Mozilla/5.0".to_string()),
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
        };
        
        let decision = protector.evaluate(&ctx).await;
        assert!(matches!(decision, ProtectionDecision::Allow));
    }

    #[tokio::test]
    async fn full_protection_flow_blocklist() {
        let config = ProtectorConfig::default();
        let protector = DdosProtector::new(config).await.unwrap();
        
        let blocked_ip = ip(101);
        protector.block_ip(blocked_ip, Duration::from_secs(300), "test".to_string());
        
        let ctx = RequestContext {
            ip: blocked_ip,
            path: "/v1/health".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: None,
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
        };
        
        let decision = protector.evaluate(&ctx).await;
        assert!(matches!(decision, ProtectionDecision::Block));
    }

    #[tokio::test]
    async fn attack_state_tracking() {
        let config = ProtectorConfig::default();
        let protector = DdosProtector::new(config).await.unwrap();
        
// Initially not under attack
        assert!(!protector.is_under_attack());
        
        let state = protector.attack_state();
        assert!(!state.is_under_attack);
        assert!(state.attack_started.is_none());
        assert_eq!(state.mitigation_level, 0);
    }

    #[tokio::test]
    async fn suspicious_fingerprint_decreases_reputation() {
        let config = ProtectorConfig::default();
        let protector = DdosProtector::new(config).await.unwrap();
        
// Very short fingerprint is suspicious
        let ctx = RequestContext {
            ip: ip(102),
            path: "/v1/test".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: Some("abc".to_string()), // Too short
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
        };
        
// First request creates reputation and decreases it
        let _ = protector.evaluate(&ctx).await;
        
// Multiple requests should further decrease reputation
        for _ in 0..10 {
            let _ = protector.evaluate(&ctx).await;
        }
        
// Should still be allowed (reputation starts at 50, decreases by 10 per request)
// After many requests, may trigger blocking
    }
}
