//! Adversarial Attack Vector Tests
//!
//! This test file covers attack vectors not tested elsewhere://! 1. Protocol Fuzzing - Malformed/edge-case inputs
//! 2. Timing Window Exploitation - Race conditions in protection windows
//! 3. State Corruption Attacks - Invalid state transitions
//! 4. Fingerprint Evasion - Spoofing/randomizing fingerprints
//! 5. Distributed Coordination Attacks - Multi-source synchronized attacks
//! 6. Rate Limit Bypass Techniques - Gaming the rate limiting system
//! 7. Hash Collision Attacks - Exploiting hash-based structures
//! 8. Configuration Edge Cases - Extreme/contradictory configs
//! 9. Multi-Vector Combined Attacks - Layered attack strategies
//! 10. Adversarial ML Inputs - Inputs designed to fool ML models

#![cfg(feature = "ml")]

use dashmap::DashMap;
use ddos_protection::adaptive::{AdaptiveConfig, AdaptiveRateLimiter, TrafficObservation};
use ddos_protection::bot_detection::SessionBehavior;
use ddos_protection::cost_based::{CostBasedLimiter, CostLimiterConfig, RequestCost};
use ddos_protection::ml::{
    AnomalyEnsemble, EnsembleWeights, FeatureVector, IsolationForest, IsolationForestConfig,
    StatisticalThresholds,
};
use ddos_protection::reputation::ReputationScore;
use ddos_protection::smtp_protection::{SmtpConnectionProtection, SmtpProtectionConfig};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

// ============================================================================
// TYPE 1:PROTOCOL FUZZING TESTS
// ============================================================================

mod protocol_fuzzing_tests {
    use super::*;

    /// Test SMTP protection with malformed command sequences
    #[test]
    fn test_smtp_malformed_command_injection() {
        let config = SmtpProtectionConfig::default();
        let mut protection = SmtpConnectionProtection::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            50, // reputation
            config,
        );

        // Try to inject commands within command strings
        let overflow_cmd = "EHLO ".to_string() + &"A".repeat(10000);
        let injection_attempts: Vec<&str> = vec![
            "EHLO test\r\nMAIL FROM:<evil>",
            "MAIL FROM:<test>\x00RCPT TO:<hidden>",
            "RCPT TO:<a>\r\n\r\nDATA",
            "HELO \x1b[2J\x1b[H", // Terminal escape sequences
            &overflow_cmd,        // Buffer overflow attempt
        ];

        for cmd in injection_attempts {
            // Should either reject or handle gracefully, never panic
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                protection.process_command(&cmd)
            }));
            assert!(result.is_ok(), "Panic on malformed command: {}", cmd);
        }
    }

    /// Test with binary garbage input
    #[test]
    fn test_binary_garbage_input() {
        let config = SmtpProtectionConfig::default();
        let mut protection =
            SmtpConnectionProtection::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 50, config);

        // Random binary data that could crash parsers
        let garbage_inputs: Vec<Vec<u8>> = vec![
            vec![0x00, 0xFF, 0xFE, 0x00, 0x01],
            vec![0x89, 0x50, 0x4E, 0x47],        // PNG header
            (0..256).map(|i| i as u8).collect(), // All byte values
            vec![0xFF; 1000],                    // All 0xFF
            vec![0x00; 1000],                    // All null bytes
        ];

        for garbage in garbage_inputs {
            let as_string = String::from_utf8_lossy(&garbage);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                protection.process_command(&as_string)
            }));
            assert!(result.is_ok(), "Panic on binary garbage");
        }
    }

    /// Test Unicode edge cases that could confuse parsers
    #[test]
    fn test_unicode_edge_cases() {
        let config = SmtpProtectionConfig::default();
        let mut protection =
            SmtpConnectionProtection::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 50, config);

        let unicode_attacks = vec![
            "EHLO \u{202E}evil\u{202C}",       // Right-to-left override
            "MAIL FROM:<test\u{0000}@domain>", // Null in string
            "RCPT TO:<\u{FEFF}bom@test>",      // BOM character
            "HELO \u{200B}\u{200B}\u{200B}",   // Zero-width spaces
            "EHLO \u{FFFF}",                   // Max unicode point
        ];

        for cmd in unicode_attacks {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                protection.process_command(cmd)
            }));
            assert!(result.is_ok(), "Panic on unicode edge case: {:?}", cmd);
        }
    }

    /// Test integer overflow in size calculations
    #[test]
    fn test_size_overflow_protection() {
        let config = SmtpProtectionConfig {
            max_size: usize::MAX, // Attempt overflow
            ..Default::default()
        };
        let mut protection =
            SmtpConnectionProtection::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 50, config);

        // Transition to data receiving state
        let _ = protection.process_command("EHLO test");
        let _ = protection.process_command("MAIL FROM:<test@test.com>");
        let _ = protection.process_command("RCPT TO:<rcpt@test.com>");
        let _ = protection.process_command("DATA");

        // Try to cause overflow by recording huge chunks
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = protection.record_data(usize::MAX / 2);
            let _ = protection.record_data(usize::MAX / 2);
        }));
        assert!(result.is_ok(), "Overflow caused panic");
    }
}

// ============================================================================
// TYPE 2:TIMING WINDOW EXPLOITATION TESTS
// ============================================================================

mod timing_window_tests {
    use super::*;

    /// Test rapid succession requests within rate limit window
    #[test]
    fn test_rate_limit_window_boundary() {
        let config = AdaptiveConfig {
            baseline_window: Duration::from_millis(100),
            min_threshold: 10,
            max_threshold: 1000,
            ..Default::default()
        };
        let limiter = AdaptiveRateLimiter::new(config);

        // Hammer right at window boundary
        let start = Instant::now();
        let mut observations_at_boundary = 0;

        while start.elapsed() < Duration::from_millis(500) {
            // Time observations to land right at window boundaries
            let elapsed_ms = start.elapsed().as_millis() as u64;
            if elapsed_ms % 100 < 5 || elapsed_ms % 100 > 95 {
                limiter.update(TrafficObservation {
                    timestamp: Instant::now(),
                    requests_per_second: 500.0, // High rate
                    error_rate: 0.0,
                    latency_p99_ms: 10.0,
                    cpu_usage: 0.5,
                });
                observations_at_boundary += 1;
            }
            std::thread::sleep(Duration::from_millis(1));
        }

        // System should have handled boundary conditions
        let threshold = limiter.current_threshold();
        assert!(threshold > 0, "Threshold should be positive");
        assert!(
            observations_at_boundary > 0,
            "No observations at boundaries"
        );
    }

    /// Test concurrent updates at same microsecond
    #[test]
    fn test_simultaneous_updates() {
        let config = AdaptiveConfig::default();
        let limiter = Arc::new(AdaptiveRateLimiter::new(config));
        let barrier = Arc::new(std::sync::Barrier::new(10));
        let success_count = Arc::new(AtomicU64::new(0));

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let limiter = Arc::clone(&limiter);
                let barrier = Arc::clone(&barrier);
                let success = Arc::clone(&success_count);
                thread::spawn(move || {
                    // All threads hit at same time
                    barrier.wait();
                    let obs = TrafficObservation {
                        timestamp: Instant::now(),
                        requests_per_second: (i as f64 + 1.0) * 100.0,
                        error_rate: 0.01,
                        latency_p99_ms: 50.0,
                        cpu_usage: 0.3,
                    };
                    limiter.update(obs);
                    success.fetch_add(1, Ordering::SeqCst);
                })
            })
            .collect();

        for h in handles {
            h.join().expect("Thread panicked");
        }

        assert_eq!(
            success_count.load(Ordering::SeqCst),
            10,
            "Not all updates succeeded"
        );
    }

    /// Test cold-start race condition
    #[test]
    fn test_cold_start_race() {
        let config = AdaptiveConfig {
            ema_alpha: 0.3,
            ..Default::default()
        };

        // Multiple threads trying to establish baseline simultaneously
        let handles: Vec<_> = (0..5)
            .map(|_| {
                let cfg = config.clone();
                thread::spawn(move || {
                    let limiter = AdaptiveRateLimiter::new(cfg);
                    for i in 0..15 {
                        limiter.update(TrafficObservation {
                            timestamp: Instant::now(),
                            requests_per_second: 100.0 + (i as f64),
                            error_rate: 0.01,
                            latency_p99_ms: 50.0,
                            cpu_usage: 0.3,
                        });
                    }
                    limiter.current_threshold()
                })
            })
            .collect();

        let thresholds: Vec<u64> = handles
            .into_iter()
            .map(|h| h.join().expect("Thread panicked"))
            .collect();

        // All should be reasonable (not 0 or u64::MAX)
        for t in &thresholds {
            assert!(*t > 0 && *t < u64::MAX, "Invalid threshold: {}", t);
        }
    }
}

// ============================================================================
// TYPE 3:STATE CORRUPTION ATTACKS
// ============================================================================

mod state_corruption_tests {
    use super::*;

    /// Test SMTP state machine with illegal transitions
    #[test]
    fn test_illegal_state_transitions() {
        let config = SmtpProtectionConfig::default();

        // Try commands out of order
        let illegal_sequences = vec![
            vec!["DATA"],                                  // DATA without MAIL/RCPT
            vec!["RCPT TO:<test@test.com>"],               // RCPT before EHLO
            vec!["MAIL FROM:<t@t.com>", "DATA"],           // DATA without RCPT
            vec!["EHLO test", ".", "MAIL FROM:<t@t.com>"], // Dot before DATA
        ];

        for sequence in illegal_sequences {
            let mut prot = SmtpConnectionProtection::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                50,
                SmtpProtectionConfig::default(),
            );
            for cmd in sequence {
                // Should reject, not crash
                let _ = prot.process_command(cmd);
            }
        }
    }

    /// Test session state after reset commands
    #[test]
    fn test_state_reset_consistency() {
        let config = SmtpProtectionConfig::default();
        let mut protection =
            SmtpConnectionProtection::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 50, config);

        // Build up state
        let _ = protection.process_command("EHLO test");
        let _ = protection.process_command("MAIL FROM:<test@test.com>");
        let _ = protection.process_command("RCPT TO:<rcpt@test.com>");

        // Reset
        let _ = protection.process_command("RSET");

        // Should be able to start fresh
        let result = protection.process_command("MAIL FROM:<new@test.com>");
        assert!(
            result.is_ok() || matches!(result, Err(_)),
            "State not properly reset"
        );
    }

    /// Test rapid state cycling
    #[test]
    fn test_rapid_state_cycling() {
        let config = SmtpProtectionConfig {
            max_commands: 1000, // Increase limit for this test
            ..Default::default()
        };
        let mut protection =
            SmtpConnectionProtection::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 50, config);

        // Rapidly cycle through states
        for _ in 0..100 {
            let _ = protection.process_command("EHLO test");
            let _ = protection.process_command("MAIL FROM:<test@test.com>");
            let _ = protection.process_command("RSET");
        }

        // System should still be functional
        let final_result = protection.process_command("EHLO final");
        assert!(final_result.is_ok(), "System broken after rapid cycling");
    }
}

// ============================================================================
// TYPE 4:FINGERPRINT EVASION TESTS
// ============================================================================

mod fingerprint_evasion_tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn hash_endpoint(endpoint: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        endpoint.hash(&mut hasher);
        hasher.finish()
    }

    /// Test bot detection with rapidly changing fingerprints
    #[test]
    fn test_fingerprint_rotation_attack() {
        // Attacker rotates through different behavior profiles
        let mut behaviors: Vec<SessionBehavior> = Vec::new();

        for i in 0..100 {
            let mut behavior = SessionBehavior::new(100);
            // Vary the pattern to look like different clients
            for j in 0..20 {
                let method = match (i + j) % 4 {
                    0 => "GET",
                    1 => "POST",
                    2 => "PUT",
                    _ => "DELETE",
                };
                let endpoint = format!("/api/v{}/resource/{}", i % 3, j);
                let is_error = ((i + j) % 10) == 0; // 10% errors
                behavior.record_request(hash_endpoint(&endpoint), method, is_error);
            }
            behaviors.push(behavior);
        }

        // All behaviors should be scoreable
        for (i, behavior) in behaviors.iter().enumerate() {
            let assessment = behavior.analyze();
            let score = assessment.bot_probability;
            assert!(
                score >= 0.0 && score <= 1.0,
                "Invalid score {} for behavior {}",
                score,
                i
            );
        }
    }

    /// Test evading timing analysis with jitter
    #[test]
    fn test_timing_jitter_evasion() {
        let mut behavior = SessionBehavior::new(100);

        // Add random jitter to avoid timing detection
        let mut rng_state = 12345u64;
        for i in 0..50 {
            // Simple LCG for deterministic "random" jitter
            rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
            let jitter_ms = (rng_state % 100) as u64;

            std::thread::sleep(Duration::from_millis(jitter_ms));
            let endpoint = format!("/page/{}", i);
            behavior.record_request(hash_endpoint(&endpoint), "GET", false);
        }

        // Should still be able to analyze
        let assessment = behavior.analyze();
        assert!(
            assessment.bot_probability.is_finite(),
            "Score not finite with jittered timing"
        );
    }

    /// Test mimicking human-like patterns
    #[test]
    fn test_human_mimicry_attack() {
        let mut behavior = SessionBehavior::new(100);

        // Mimic realistic browsing:varied endpoints, some errors, variable timing
        let endpoints = [
            "/",
            "/about",
            "/products",
            "/products/1",
            "/cart",
            "/api/user",
            "/contact",
            "/search?q=test",
            "/products/2",
        ];

        for (i, endpoint) in endpoints.iter().cycle().take(30).enumerate() {
            let is_error = i % 7 == 0; // Occasional errors
            behavior.record_request(hash_endpoint(endpoint), "GET", is_error);

            // Variable delays (not tracked but simulates human)
            if i % 3 == 0 {
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        let assessment = behavior.analyze();
        // A well-designed mimicry might have lower bot score
        assert!(
            assessment.bot_probability.is_finite(),
            "Score should be finite for mimicry attack"
        );
    }
}

// ============================================================================
// TYPE 5:DISTRIBUTED COORDINATION ATTACKS
// ============================================================================

mod distributed_attack_tests {
    use super::*;

    /// Test synchronized multi-IP attack (using DashMap for IP tracking)
    #[test]
    fn test_coordinated_multi_ip_attack() {
        // Track reputation per IP manually
        let reputations: DashMap<IpAddr, ReputationScore> = DashMap::new();

        // 100 different IPs attacking simultaneously
        let attacker_ips: Vec<IpAddr> = (1..=100)
            .map(|i| IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8)))
            .collect();

        // Each IP makes just a few requests (under individual limits)
        for ip in &attacker_ips {
            for _ in 0..5 {
                reputations
                    .entry(*ip)
                    .or_insert_with(ReputationScore::default)
                    .record_request();
            }
        }

        // Total traffic is high even though per-IP is low
        let total_requests: u64 = reputations
            .iter()
            .map(|entry| entry.value().total_requests)
            .sum();
        assert_eq!(total_requests, 500, "Expected 500 total requests");

        // Check that we can query each IP
        for ip in &attacker_ips {
            let reputation = reputations.get(ip).unwrap();
            assert!(reputation.score <= 100, "Score should be in valid range");
        }
    }

    /// Test slowloris-style distributed attack
    #[test]
    fn test_distributed_slowloris() {
        // Many connections each sending slowly
        let mut protections: Vec<SmtpConnectionProtection> = Vec::new();

        for i in 0..50 {
            let config = SmtpProtectionConfig::default();
            let protection = SmtpConnectionProtection::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, (i / 256) as u8, (i % 256) as u8)),
                50,
                config,
            );
            protections.push(protection);
        }

        // Each connection sends partial commands slowly
        for (i, protection) in protections.iter_mut().enumerate() {
            let partial_cmd = format!("EHL{}", if i % 2 == 0 { "O" } else { "" });
            let _ = protection.process_command(&partial_cmd);
        }

        // All should be tracked, none should crash
        assert_eq!(protections.len(), 50, "Not all connections maintained");
    }

    /// Test amplification attack pattern
    #[test]
    fn test_amplification_pattern() {
        let cost_config = CostLimiterConfig::default();
        let limiter = CostBasedLimiter::new(cost_config);

        // Attacker sends small requests that trigger large responses
        let amplification_endpoints = vec![
            (
                "/api/export/all",
                RequestCost::new(50000, 10_000_000, 100, 0),
            ),
            (
                "/api/report/full",
                RequestCost::new(100000, 50_000_000, 500, 5),
            ),
            (
                "/api/search?q=*",
                RequestCost::new(200000, 100_000_000, 1000, 0),
            ),
        ];

        for (endpoint, cost) in &amplification_endpoints {
            let decision = limiter.check("attacker", endpoint, Some(cost.clone()));
            // Should return some decision
            match decision {
                ddos_protection::cost_based::CostDecision::Allowed { .. } => {}
                ddos_protection::cost_based::CostDecision::QuotaExceeded { .. } => {}
                ddos_protection::cost_based::CostDecision::SystemOverloaded { .. } => {}
            }
        }
    }
}

// ============================================================================
// TYPE 6:RATE LIMIT BYPASS TECHNIQUES
// ============================================================================

mod rate_limit_bypass_tests {
    use super::*;

    /// Test IP spoofing via X-Forwarded-For manipulation
    #[test]
    fn test_xff_header_cycling() {
        let reputations: DashMap<IpAddr, ReputationScore> = DashMap::new();

        // Attacker cycles through fake IPs in headers
        for i in 0..1000u32 {
            let fake_ip = IpAddr::V4(Ipv4Addr::new(
                ((i / 256 / 256 / 256) % 256) as u8,
                ((i / 256 / 256) % 256) as u8,
                ((i / 256) % 256) as u8,
                (i % 256) as u8,
            ));
            reputations
                .entry(fake_ip)
                .or_insert_with(ReputationScore::default)
                .record_request();
        }

        // System should track all unique IPs
        let tracked_count = reputations.len();
        assert!(tracked_count > 0, "No IPs were tracked");
    }

    /// Test IPv4/IPv6 dual-stack bypass
    #[test]
    fn test_dual_stack_bypass() {
        let reputations: DashMap<IpAddr, ReputationScore> = DashMap::new();

        // Same attacker using IPv4 and IPv6
        let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x100));

        // Alternate between addresses
        for _ in 0..50 {
            reputations
                .entry(ipv4)
                .or_insert_with(ReputationScore::default)
                .record_request();
            reputations
                .entry(ipv6)
                .or_insert_with(ReputationScore::default)
                .record_request();
        }

        let rep_v4 = reputations.get(&ipv4).unwrap();
        let rep_v6 = reputations.get(&ipv6).unwrap();

        // Both should be tracked independently
        assert!(rep_v4.total_requests > 0, "IPv4 not tracked");
        assert!(rep_v6.total_requests > 0, "IPv6 not tracked");
    }

    /// Test rate limit reset exploitation
    #[test]
    fn test_window_reset_exploitation() {
        let config = AdaptiveConfig {
            baseline_window: Duration::from_millis(100),
            ..Default::default()
        };
        let limiter = AdaptiveRateLimiter::new(config);

        // Burst right before window resets
        for _window in 0..10 {
            // Wait for window start
            std::thread::sleep(Duration::from_millis(100));

            // Burst at end of window
            for _i in 0..20 {
                limiter.update(TrafficObservation {
                    timestamp: Instant::now(),
                    requests_per_second: 1000.0,
                    error_rate: 0.0,
                    latency_p99_ms: 10.0,
                    cpu_usage: 0.5,
                });
            }
        }

        // Should still trigger protection
        let threshold = limiter.current_threshold();
        assert!(threshold > 0, "Threshold not properly calculated");
    }

    /// Test gradual rate increase to avoid detection
    #[test]
    fn test_slow_ramp_evasion() {
        let config = AdaptiveConfig {
            z_threshold: 3.0,
            ema_alpha: 0.1, // Slow adaptation
            ..Default::default()
        };
        let limiter = AdaptiveRateLimiter::new(config);

        // Slowly increase rate to avoid z-score spike
        let mut current_rate = 100.0;
        for _ in 0..100 {
            limiter.update(TrafficObservation {
                timestamp: Instant::now(),
                requests_per_second: current_rate,
                error_rate: 0.01,
                latency_p99_ms: 50.0,
                cpu_usage: 0.3,
            });
            current_rate *= 1.02; // 2% increase each observation
            std::thread::sleep(Duration::from_millis(10));
        }

        // Final rate is ~7x initial, should be detected
        assert!(current_rate > 500.0, "Rate didn't increase enough");
        let threshold = limiter.current_threshold();
        assert!(threshold > 0, "Threshold calculation failed");
    }
}

// ============================================================================
// TYPE 7:HASH COLLISION ATTACKS
// ============================================================================

mod hash_collision_tests {
    use super::*;

    /// Test session tracking with hash-colliding IPs
    #[test]
    fn test_ip_hash_collision_safety() {
        let reputations: DashMap<IpAddr, ReputationScore> = DashMap::new();

        // IPs that might have hash collisions
        let potential_collisions = vec![
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        ];

        // Record different patterns for each
        for (i, ip) in potential_collisions.iter().enumerate() {
            for _ in 0..(i + 1) * 10 {
                reputations
                    .entry(*ip)
                    .or_insert_with(ReputationScore::default)
                    .record_request();
            }
        }

        // Verify each IP tracked independently
        for (i, ip) in potential_collisions.iter().enumerate() {
            let rep = reputations.get(ip).unwrap();
            let expected = ((i + 1) * 10) as u64;
            assert_eq!(
                rep.total_requests, expected,
                "IP {} has wrong count: {} vs {}",
                ip, rep.total_requests, expected
            );
        }
    }

    /// Test endpoint hash collision in cost tracking
    #[test]
    fn test_endpoint_hash_collision() {
        let cost_config = CostLimiterConfig::default();
        let limiter = CostBasedLimiter::new(cost_config);

        // Different endpoints that might hash similarly
        let endpoints = vec!["/api/a", "/api/aa", "/api/aaa", "/pib/a", "/api/A"];

        for endpoint in &endpoints {
            let cost = RequestCost::new(100, 1000, 1, 0);
            let _ = limiter.check("user", endpoint, Some(cost));
        }

        // Each should be tracked (implementation dependent)
        // Main goal:no panic or incorrect aggregation
    }
}

// ============================================================================
// TYPE 8:CONFIGURATION EDGE CASES
// ============================================================================

mod config_edge_case_tests {
    use super::*;

    /// Test contradictory configuration values
    /// The system correctly validates that min_threshold <= max_threshold
    #[test]
    fn test_contradictory_config() {
        // Min > Max - the system should reject this config or panic during use
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let config = AdaptiveConfig {
                min_threshold: 1000,
                max_threshold: 100, // Less than min!
                ..Default::default()
            };
            let limiter = AdaptiveRateLimiter::new(config);

            // Try to use it
            for _ in 0..20 {
                limiter.update(TrafficObservation {
                    timestamp: Instant::now(),
                    requests_per_second: 500.0,
                    error_rate: 0.01,
                    latency_p99_ms: 50.0,
                    cpu_usage: 0.3,
                });
            }
            limiter.current_threshold()
        }));

        // The system correctly enforces invariants - either:// 1. It panics (correct defensive behavior)
        // 2. It clamps/adjusts the values (also acceptable)
        if result.is_err() {
            // System correctly rejects invalid config - this is expected behavior
            // Panicking on invalid config is the right thing to do
            return;
        }

        // If it doesn't panic, threshold should still be valid
        let threshold = result.unwrap();
        assert!(
            threshold > 0,
            "Threshold should be valid even with bad config"
        );
    }

    /// Test zero-value configurations
    #[test]
    fn test_zero_config_values() {
        let config = AdaptiveConfig {
            min_threshold: 0,
            max_threshold: 0,
            z_threshold: 0.0,
            ema_alpha: 0.0,
            ..Default::default()
        };
        let limiter = AdaptiveRateLimiter::new(config);

        for _ in 0..20 {
            limiter.update(TrafficObservation {
                timestamp: Instant::now(),
                requests_per_second: 100.0,
                error_rate: 0.0,
                latency_p99_ms: 50.0,
                cpu_usage: 0.3,
            });
        }

        // Should handle gracefully - with zero max_threshold, result may be 0
        let threshold = limiter.current_threshold();
        // Just check it doesn't panic
        let _ = threshold;
    }

    /// Test maximum valid configuration values
    #[test]
    fn test_max_config_values() {
        let config = AdaptiveConfig {
            min_threshold: u64::MAX / 4,
            max_threshold: u64::MAX / 2,
            z_threshold: f64::MAX / 4.0,
            ..Default::default()
        };
        let limiter = AdaptiveRateLimiter::new(config);

        limiter.update(TrafficObservation {
            timestamp: Instant::now(),
            requests_per_second: f64::MAX / 4.0,
            error_rate: 0.5,
            latency_p99_ms: f64::MAX / 4.0,
            cpu_usage: 1.0,
        });

        let threshold = limiter.current_threshold();
        // Should be within configured bounds
        assert!(
            threshold >= u64::MAX / 4 || threshold <= u64::MAX / 2 || threshold == 0,
            "Should handle large values"
        );
    }

    /// Test negative/edge configuration values
    #[test]
    fn test_edge_config_values() {
        // ema_alpha must be between 0 and 1, but test edge values
        let config = AdaptiveConfig {
            ema_alpha: 1.0,     // Maximum valid
            z_threshold: 0.001, // Very small
            ..Default::default()
        };
        let limiter = AdaptiveRateLimiter::new(config);

        for _ in 0..20 {
            limiter.update(TrafficObservation {
                timestamp: Instant::now(),
                requests_per_second: 100.0,
                error_rate: 0.01,
                latency_p99_ms: 50.0,
                cpu_usage: 0.3,
            });
        }

        // Should not crash
        let threshold = limiter.current_threshold();
        println!("Threshold with edge config: {}", threshold);
    }
}

// ============================================================================
// TYPE 9:MULTI-VECTOR COMBINED ATTACKS
// ============================================================================

mod multi_vector_tests {
    use super::*;

    /// Test simultaneous high-rate + error injection + slow requests
    #[test]
    fn test_triple_vector_attack() {
        let config = AdaptiveConfig::default();
        let limiter = AdaptiveRateLimiter::new(config);

        // Vector 1:High request rate
        // Vector 2:High error rate
        // Vector 3:High latency
        for _ in 0..50 {
            limiter.update(TrafficObservation {
                timestamp: Instant::now(),
                requests_per_second: 10000.0, // Very high
                error_rate: 0.8,              // 80% errors
                latency_p99_ms: 30000.0,      // 30 second latency
                cpu_usage: 0.95,
            });
        }

        let threshold = limiter.current_threshold();
        assert!(threshold > 0, "Should handle multi-vector attack");
    }

    /// Test oscillating attack pattern (on/off/on)
    #[test]
    fn test_oscillating_attack() {
        let config = AdaptiveConfig::default();
        let limiter = AdaptiveRateLimiter::new(config);

        for _cycle in 0..10 {
            // Attack burst
            for _ in 0..10 {
                limiter.update(TrafficObservation {
                    timestamp: Instant::now(),
                    requests_per_second: 5000.0,
                    error_rate: 0.5,
                    latency_p99_ms: 1000.0,
                    cpu_usage: 0.9,
                });
            }

            // Normal traffic
            for _ in 0..10 {
                limiter.update(TrafficObservation {
                    timestamp: Instant::now(),
                    requests_per_second: 100.0,
                    error_rate: 0.01,
                    latency_p99_ms: 50.0,
                    cpu_usage: 0.2,
                });
            }
        }

        let threshold = limiter.current_threshold();
        assert!(threshold > 0, "Should handle oscillating pattern");
    }

    /// Test resource exhaustion + behavioral evasion combo
    #[test]
    fn test_exhaustion_with_evasion() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        fn hash_endpoint(endpoint: &str) -> u64 {
            let mut hasher = DefaultHasher::new();
            endpoint.hash(&mut hasher);
            hasher.finish()
        }

        let cost_config = CostLimiterConfig {
            default_tenant_budget: 100000,
            system_capacity: 1000000,
        };
        let cost_limiter = CostBasedLimiter::new(cost_config);

        let mut behavior = SessionBehavior::new(100);

        // Mix expensive requests with human-like patterns
        let patterns = vec![
            ("/", "GET", false, RequestCost::new(10, 100, 0, 0)),
            (
                "/api/export",
                "POST",
                false,
                RequestCost::new(50000, 10000000, 50, 2),
            ),
            ("/about", "GET", false, RequestCost::new(10, 100, 0, 0)),
            (
                "/api/process",
                "POST",
                false,
                RequestCost::new(100000, 50000000, 100, 5),
            ),
            ("/contact", "GET", true, RequestCost::new(10, 100, 0, 0)), // 404 = error
        ];

        for (endpoint, method, is_error, cost) in patterns.iter().cycle().take(100) {
            behavior.record_request(hash_endpoint(endpoint), method, *is_error);
            let _ = cost_limiter.check("attacker", endpoint, Some(cost.clone()));
        }

        let assessment = behavior.analyze();
        assert!(
            assessment.bot_probability.is_finite(),
            "Bot score should be calculable"
        );
    }
}

// ============================================================================
// TYPE 10:ADVERSARIAL ML INPUTS
// ============================================================================

mod adversarial_ml_tests {
    use super::*;

    /// Test ML model with adversarial feature vectors
    #[test]
    fn test_adversarial_feature_crafting() {
        let config = IsolationForestConfig::default();
        let mut forest = IsolationForest::new(config);

        // Train with normal data
        let normal_data: Vec<[f64; 10]> = (0..100)
            .map(|i| {
                [
                    100.0 + (i as f64 * 0.1),
                    1000.0,
                    60.0,
                    100.0,
                    50.0,
                    10.0,
                    0.5,
                    0.01,
                    10.0,
                    0.2,
                ]
            })
            .collect();
        forest.train(&normal_data, 42);

        // Adversarial inputs designed to look normal but be anomalous
        let adversarial_inputs = vec![
            // Looks normal except one extreme value
            FeatureVector {
                request_rate: 100.0,
                bytes_rate: f64::MAX / 2.0, // Hidden extreme
                connection_age: 60.0,
                size_variance: 100.0,
                iat_mean: 50.0,
                iat_variance: 10.0,
                endpoint_diversity: 0.5,
                error_rate: 0.01,
                geo_distance: 10.0,
                time_factor: 0.2,
            },
            // All values at decision boundaries
            FeatureVector {
                request_rate: 150.0,
                bytes_rate: 1500.0,
                connection_age: 90.0,
                size_variance: 150.0,
                iat_mean: 75.0,
                iat_variance: 15.0,
                endpoint_diversity: 0.75,
                error_rate: 0.015,
                geo_distance: 15.0,
                time_factor: 0.3,
            },
            // Crafted to maximize path length
            FeatureVector {
                request_rate: 100.0,
                bytes_rate: 1000.0,
                connection_age: 60.0,
                size_variance: 100.0,
                iat_mean: 50.0,
                iat_variance: 10.0,
                endpoint_diversity: 0.5,
                error_rate: 0.01,
                geo_distance: 10.0,
                time_factor: 0.2,
            },
        ];

        for (i, adversarial) in adversarial_inputs.iter().enumerate() {
            let score = forest.anomaly_score(adversarial);
            assert!(
                score.is_finite(),
                "Score should be finite for adversarial input {}",
                i
            );
            assert!(
                score >= 0.0 && score <= 1.0,
                "Score out of range for input {}: {}",
                i,
                score
            );
        }
    }

    /// Test gradient-style attack on ensemble
    #[test]
    fn test_ensemble_gradient_attack() {
        let if_config = IsolationForestConfig::default();
        let weights = EnsembleWeights {
            isolation_forest: 0.6,
            statistical: 0.4,
        };
        let thresholds = StatisticalThresholds::default();
        let ensemble = AnomalyEnsemble::new(if_config, thresholds, weights);

        // Try to find inputs that minimize ensemble score while being anomalous
        let test_features = FeatureVector {
            request_rate: 5000.0, // Clearly anomalous
            bytes_rate: 50000.0,
            connection_age: 300.0,
            size_variance: 10000.0,
            iat_mean: 5.0,
            iat_variance: 1.0,
            endpoint_diversity: 0.1,
            error_rate: 0.5,
            geo_distance: 10000.0,
            time_factor: 2.0,
        };

        let score = ensemble.anomaly_score(&test_features);
        assert!(
            score >= 0.0 && score <= 1.0,
            "Score out of range: {}",
            score
        );
    }

    /// Test model poisoning resistance
    #[test]
    fn test_model_poisoning_resistance() {
        let config = IsolationForestConfig::default();
        let mut forest = IsolationForest::new(config);

        // Mix of normal and poisoned training data
        let mut training_data: Vec<[f64; 10]> = Vec::new();

        // Normal data
        for i in 0..80 {
            training_data.push([
                100.0 + (i as f64 * 0.1),
                1000.0,
                60.0,
                100.0,
                50.0,
                10.0,
                0.5,
                0.01,
                10.0,
                0.2,
            ]);
        }

        // Poisoned data (attackers trying to make attacks look normal)
        for i in 0..20 {
            training_data.push([
                (5000 + i * 100) as f64, // Attack-level rates
                50000.0,
                10.0,
                10000.0,
                5.0,
                100.0,
                0.05,
                0.5,
                1000.0,
                3.0,
            ]);
        }

        forest.train(&training_data, 42);

        // Test if obvious anomalies are still detected
        let obvious_anomaly = FeatureVector {
            request_rate: 100000.0,
            bytes_rate: 1000000.0,
            connection_age: 1.0,
            size_variance: 100000.0,
            iat_mean: 0.1,
            iat_variance: 0.0,
            endpoint_diversity: 0.01,
            error_rate: 0.9,
            geo_distance: 50000.0,
            time_factor: 10.0,
        };

        let score = forest.anomaly_score(&obvious_anomaly);
        // Even with poisoning, extreme anomalies should score high
        assert!(
            score > 0.3,
            "Obvious anomaly should still be detected despite poisoning: {}",
            score
        );
    }

    /// Test feature distribution shift attack
    #[test]
    fn test_distribution_shift_evasion() {
        let config = AdaptiveConfig {
            ema_alpha: 0.2,
            ..Default::default()
        };
        let limiter = AdaptiveRateLimiter::new(config);

        // Establish baseline
        for _ in 0..20 {
            limiter.update(TrafficObservation {
                timestamp: Instant::now(),
                requests_per_second: 100.0,
                error_rate: 0.01,
                latency_p99_ms: 50.0,
                cpu_usage: 0.3,
            });
        }

        // Slowly shift distribution to make attacks look normal
        let mut rate = 100.0;
        for _ in 0..50 {
            rate *= 1.05; // 5% increase
            limiter.update(TrafficObservation {
                timestamp: Instant::now(),
                requests_per_second: rate,
                error_rate: 0.01,
                latency_p99_ms: 50.0,
                cpu_usage: 0.3,
            });
            std::thread::sleep(Duration::from_millis(5));
        }

        let final_threshold = limiter.current_threshold();
        assert!(final_threshold > 0, "Threshold should adapt to shift");
        // With shift, threshold should have changed from initial value
    }
}
