//! Realistic attack scenario tests for the DDoS protection system.
//!
//! Philosophy:Every test models a real attack pattern. If a test fails,
//! the CODE is wrong, not the test. Tests are designed to find bugs, not
//! to confirm happy paths.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

// ============================================================================
// Imports
// ============================================================================

use ddos_protection::adaptive::*;
use ddos_protection::bot_detection::*;
use ddos_protection::cost_based::*;
use ddos_protection::middleware::*;
use ddos_protection::reputation::*;
use ddos_protection::smtp_protection::*;
use ddos_protection::*;

fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
}

fn hash_ep(s: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

// ============================================================================
// MODULE 1:SMTP Protection — Realistic Attack Scenarios
// ============================================================================

mod smtp_attacks {
    use super::*;

    /// BUG VERIFICATION:Tarpit delay must escalate progressively.
    /// Previously, once tarpit activated, record_invalid was never called again,
    /// so the delay stayed constant. This test verifies the fix.
    #[test]
    fn tarpit_escalates_progressively_under_sustained_invalid_commands() {
        let config = SmtpProtectionConfig {
            strict_mode: false,
            max_invalid: 3,
            tarpit_delay: Duration::from_secs(2),
            ..SmtpProtectionConfig::default()
        };
        let mut prot = SmtpConnectionProtection::new(ip(1), 50, config);

        // Send 3 invalid commands — at threshold, no tarpit yet
        for i in 0..3 {
            let cmd = format!("GARBAGE{}", i);
            let action = prot.process_command(&cmd).unwrap();
            assert_eq!(
                action,
                SmtpAction::Reject("500 Unrecognized command"),
                "Command {} should be rejected, not tarpitted",
                i
            );
        }
        assert_eq!(prot.invalid_commands(), 3);
        assert!(
            prot.should_tarpit().is_none(),
            "At max_invalid, not over — no tarpit"
        );

        // 4th invalid:1 over limit → 1 * 2s = 2s
        let action = prot.process_command("JUNK4").unwrap();
        assert_eq!(
            action,
            SmtpAction::Tarpit(Duration::from_secs(2)),
            "4th invalid should tarpit for 2s (1 over * 2s base)"
        );

        // 5th invalid:2 over limit → 2 * 2s = 4s (MUST escalate)
        let action = prot.process_command("JUNK5").unwrap();
        assert_eq!(
            action,
            SmtpAction::Tarpit(Duration::from_secs(4)),
            "5th invalid should tarpit for 4s (2 over * 2s base)"
        );

        // 6th invalid:3 over limit → 3 * 2s = 6s
        let action = prot.process_command("JUNK6").unwrap();
        assert_eq!(
            action,
            SmtpAction::Tarpit(Duration::from_secs(6)),
            "6th invalid should tarpit for 6s (3 over * 2s base)"
        );

        // 10th invalid:7 over limit → 7 * 2s = 14s
        for _ in 0..4 {
            let _ = prot.process_command("MORE_JUNK");
        }
        assert_eq!(
            prot.should_tarpit(),
            Some(Duration::from_secs(14)),
            "After 10 invalids, tarpit should be 7 * 2s = 14s"
        );
    }

    /// Attack:Slowloris sends data at just barely above/below threshold near
    /// second boundaries. Previously integer division masked the real rate.
    /// BUG VERIFICATION:check_data_rate uses float division.
    #[test]
    fn slowloris_detected_at_subsecond_boundaries() {
        let config = SmtpProtectionConfig {
            min_data_rate_bps: 100, // 100 bytes/sec minimum
            ..SmtpProtectionConfig::default()
        };
        let prot = SmtpConnectionProtection::new(ip(2), 50, config);

        // 100 bytes in 1.99 seconds = 50.25 bps real rate — should FAIL
        // Old code:100 / as_secs(1.99) = 100 / 1 = 100 bps → PASS (bug!)
        // Fixed code:100 / 1.99 = 50.25 bps → FAIL (correct)
        let result = prot.check_data_rate(100, Duration::from_millis(1990));
        assert!(
            result.is_err(),
            "100 bytes in 1.99s = 50 bps, should fail 100 bps minimum"
        );

        // 200 bytes in 1.99 seconds = 100.5 bps — should PASS
        let result = prot.check_data_rate(200, Duration::from_millis(1990));
        assert!(
            result.is_ok(),
            "200 bytes in 1.99s = 100.5 bps, should pass 100 bps minimum"
        );

        // Edge case:exactly at threshold
        let result = prot.check_data_rate(100, Duration::from_secs(1));
        assert!(
            result.is_ok(),
            "100 bytes in 1s = 100 bps, exactly at threshold, should pass"
        );

        // Just under threshold
        let result = prot.check_data_rate(99, Duration::from_secs(1));
        assert!(
            result.is_err(),
            "99 bytes in 1s = 99 bps, under threshold, should fail"
        );
    }

    /// Attack:Attacker opens many connections but never sends EHLO, holding
    /// resources with NOOP spam.
    #[test]
    fn noop_spam_before_greeting_consumes_command_budget() {
        let mut config = SmtpProtectionConfig::default();
        config.max_commands = 20;
        let mut prot = SmtpConnectionProtection::new(ip(3), 50, config);

        // NOOP is valid from Connected state, but it eats command budget.
        // max_commands=20 means 20 commands are allowed (commands_received > 20 triggers error).
        for _ in 0..20 {
            let action = prot.process_command("NOOP").unwrap();
            assert_eq!(action, SmtpAction::Continue);
        }

        // 21st command → max_commands exceeded
        let result = prot.process_command("NOOP");
        assert!(
            matches!(result, Err(SmtpProtectionError::TooManyCommands)),
            "21st command should exhaust the budget (max_commands=20 allows 20)"
        );
    }

    /// QUIT always disconnects immediately, even under tarpit.
    /// This is correct — holding an attacker who wants to leave wastes OUR resources.
    #[test]
    fn quit_bypasses_tarpit_even_after_many_invalids() {
        let config = SmtpProtectionConfig {
            strict_mode: false,
            max_invalid: 1,
            tarpit_delay: Duration::from_secs(10),
            ..SmtpProtectionConfig::default()
        };
        let mut prot = SmtpConnectionProtection::new(ip(4), 50, config);

        // Trigger tarpit
        prot.process_command("BOGUS1").unwrap(); // 1st invalid
        prot.process_command("BOGUS2").unwrap(); // 2nd invalid, now tarpitted

        assert!(prot.should_tarpit().is_some(), "Should be tarpitting");

        // QUIT must bypass tarpit
        let action = prot.process_command("QUIT").unwrap();
        assert_eq!(
            action,
            SmtpAction::Disconnect,
            "QUIT must always disconnect, even when tarpitted"
        );
    }

    /// BUG VERIFICATION:unregister_connection cannot underflow the atomic counter.
    #[test]
    fn unregister_connection_does_not_underflow() {
        let config = SmtpProtectionConfig::default();
        let tracker = SmtpConnectionTracker::new(config);
        let addr = ip(5);

        // Register one connection
        tracker.register_connection(addr).unwrap();
        assert_eq!(tracker.active_count(&addr), 1);

        // Unregister it
        tracker.unregister_connection(&addr);
        assert_eq!(tracker.active_count(&addr), 0);

        // Double unregister — should NOT underflow to u64::MAX
        tracker.unregister_connection(&addr);
        assert_eq!(
            tracker.active_count(&addr),
            0,
            "Double unregister must not wrap to u64::MAX"
        );

        // Triple unregister from a fresh IP that was never registered
        tracker.unregister_connection(&ip(99));
        assert_eq!(tracker.active_count(&ip(99)), 0);

        // After all this, registering should work normally
        tracker.register_connection(addr).unwrap();
        assert_eq!(tracker.active_count(&addr), 1);
    }

    /// Attack:Connection rate-limit exhaustion followed by rapid reconnect
    #[test]
    fn connection_rate_limit_enforced_within_window() {
        let config = SmtpProtectionConfig {
            conn_rate_per_minute: 3,
            max_connections_per_ip: 100,
            ..SmtpProtectionConfig::default()
        };
        let tracker = SmtpConnectionTracker::new(config);
        let addr = ip(6);

        // Fill rate limit
        for _i in 0..3 {
            tracker.register_connection(addr).unwrap();
            tracker.unregister_connection(&addr); // Close immediately
        }

        // Next connection within same minute should be rate-limited
        let result = tracker.register_connection(addr);
        assert!(
            matches!(result, Err(SmtpProtectionError::ConnectionRateLimited)),
            "4th connection within 1 minute with limit of 3 should be rate-limited"
        );
    }

    /// Attack:RSET loop to reset transaction state and avoid DATA phase forever
    #[test]
    fn rset_loop_doesnt_bypass_command_limit() {
        let mut config = SmtpProtectionConfig::default();
        config.max_commands = 10;
        let mut prot = SmtpConnectionProtection::new(ip(7), 50, config);

        prot.process_command("EHLO test.com").unwrap(); // command 1
                                                        // RSET loop:commands 2-10
        for _ in 0..9 {
            prot.process_command("RSET").unwrap();
        }
        // 11th command → exceeds max_commands=10
        let result = prot.process_command("RSET");
        assert!(
            matches!(result, Err(SmtpProtectionError::TooManyCommands)),
            "RSET loop should be bounded by max_commands"
        );
    }

    /// Verify RSET is invalid from Connected state (no prior EHLO)
    #[test]
    fn rset_from_connected_state_is_invalid() {
        let config = SmtpProtectionConfig::default();
        let mut prot = SmtpConnectionProtection::new(ip(8), 50, config);

        assert_eq!(prot.state(), SmtpState::Connected);
        let result = prot.process_command("RSET");
        // RSET is only valid from GreetingReceived, MailFrom, RcptTo, Data, DataReceiving
        // From Connected state, it should be invalid
        assert!(
            result.is_err(),
            "RSET from Connected state (before EHLO) should be rejected"
        );
    }
}

// ============================================================================
// MODULE 2:Adaptive Rate Limiter — Realistic Attack Scenarios
// ============================================================================

mod adaptive_attacks {
    use super::*;

    /// BUG VERIFICATION:With zero std dev, an attack spike is still detected.
    /// Previously z_score was forced to 0.0 when std=0, missing the attack entirely.
    #[test]
    fn attack_detected_against_constant_rate_baseline() {
        let config = AdaptiveConfig {
            consecutive_alert_trigger: 2,
            cooldown: Duration::from_millis(100),
            z_threshold: 3.0,
            baseline_window: Duration::from_secs(300),
            ..AdaptiveConfig::default()
        };
        let limiter = AdaptiveRateLimiter::new(config);

        // Feed 15 identical observations:perfectly constant baseline, std = 0
        for _ in 0..15 {
            limiter.update(TrafficObservation {
                timestamp: Instant::now(),
                requests_per_second: 100.0,
                error_rate: 0.01,
                latency_p99_ms: 50.0,
                cpu_usage: 0.3,
            });
        }

        let stats = limiter.baseline_stats().unwrap();
        assert!(
            stats.rps_std < 0.001,
            "Baseline std should be ~0: {}",
            stats.rps_std
        );
        assert!(!limiter.is_under_attack());

        // Spike to 10x — must be detected even though std = 0
        limiter.update(TrafficObservation {
            timestamp: Instant::now(),
            requests_per_second: 1000.0,
            error_rate: 0.01,
            latency_p99_ms: 50.0,
            cpu_usage: 0.3,
        });
        limiter.update(TrafficObservation {
            timestamp: Instant::now(),
            requests_per_second: 1000.0,
            error_rate: 0.01,
            latency_p99_ms: 50.0,
            cpu_usage: 0.3,
        });

        assert!(
            limiter.is_under_attack(),
            "Attack must be detected even with zero-std baseline"
        );
    }

    /// Attack:Gradual ramp-up that stays within normal std deviation, then sudden spike
    #[test]
    fn gradual_ramp_then_spike_detected() {
        let config = AdaptiveConfig {
            consecutive_alert_trigger: 2,
            attack_factor: 0.3, // Lower factor to ensure clear difference
            min_threshold: 10,
            max_threshold: 100_000,
            ..AdaptiveConfig::default()
        };
        let limiter = AdaptiveRateLimiter::new(config);

        // Build baseline with some natural variance (490-510 rps)
        // Higher baseline to avoid cold-start threshold conflicts
        for i in 0..20 {
            let rps = 500.0 + (i as f64 % 10.0) - 5.0; // 495-505 range
            limiter.update(TrafficObservation {
                timestamp: Instant::now(),
                requests_per_second: rps,
                error_rate: 0.01,
                latency_p99_ms: 50.0,
                cpu_usage: 0.3,
            });
        }

        let pre = limiter.current_threshold();
        assert!(!limiter.is_under_attack());

        // Sudden spike to 10,000 rps
        for _ in 0..3 {
            limiter.update(TrafficObservation {
                timestamp: Instant::now(),
                requests_per_second: 10_000.0,
                error_rate: 0.01,
                latency_p99_ms: 50.0,
                cpu_usage: 0.3,
            });
        }

        assert!(
            limiter.is_under_attack(),
            "Spike to 10,000 from ~500 baseline must trigger attack detection"
        );
        assert!(
            limiter.current_threshold() < pre,
            "Threshold must tighten during attack: {} should be < {}",
            limiter.current_threshold(),
            pre
        );
    }

    /// EMA threshold converges toward ideal over many stable observations
    #[test]
    fn ema_converges_toward_ideal_threshold() {
        let config = AdaptiveConfig {
            ema_alpha: 0.3, // Faster convergence for testing
            headroom_factor: 1.5,
            min_threshold: 10,
            max_threshold: 100_000,
            ..AdaptiveConfig::default()
        };
        let limiter = AdaptiveRateLimiter::new(config);

        // Feed 100 stable observations at 200 rps
        for _ in 0..100 {
            limiter.update(TrafficObservation {
                timestamp: Instant::now(),
                requests_per_second: 200.0,
                error_rate: 0.01,
                latency_p99_ms: 50.0,
                cpu_usage: 0.3,
            });
        }

        // Ideal threshold = 200 * 1.5 = 300
        let threshold = limiter.current_threshold();
        // With EMA alpha=0.3 and 100 iterations, should be very close to 300
        assert!(
            threshold >= 250 && threshold <= 350,
            "Threshold should converge near 300 (200 * 1.5), got: {}",
            threshold
        );
    }

    /// Threshold stays clamped to configured bounds
    #[test]
    fn threshold_clamped_under_extreme_traffic() {
        let config = AdaptiveConfig {
            min_threshold: 50,
            max_threshold: 500,
            ema_alpha: 0.5,
            headroom_factor: 1.5,
            ..AdaptiveConfig::default()
        };
        let limiter = AdaptiveRateLimiter::new(config);

        // Very high traffic
        for _ in 0..30 {
            limiter.update(TrafficObservation {
                timestamp: Instant::now(),
                requests_per_second: 100_000.0,
                error_rate: 0.01,
                latency_p99_ms: 50.0,
                cpu_usage: 0.3,
            });
        }
        assert!(
            limiter.current_threshold() <= 500,
            "Threshold must not exceed max: {}",
            limiter.current_threshold()
        );

        // Very low traffic
        limiter.reset();
        for _ in 0..30 {
            limiter.update(TrafficObservation {
                timestamp: Instant::now(),
                requests_per_second: 1.0,
                error_rate: 0.01,
                latency_p99_ms: 50.0,
                cpu_usage: 0.3,
            });
        }
        assert!(
            limiter.current_threshold() >= 50,
            "Threshold must not drop below min: {}",
            limiter.current_threshold()
        );
    }
}

// ============================================================================
// MODULE 3:Bot Detection — Realistic Attack Scenarios
// ============================================================================

mod bot_attacks {
    use super::*;

    /// BUG VERIFICATION:First inter-arrival time is no longer polluted by
    /// the gap between tracker creation and first request.
    #[test]
    fn first_request_does_not_pollute_timing_analysis() {
        let mut behavior = SessionBehavior::new(100);

        // Simulate real bot:requests exactly 50ms apart
        // With the old code, the first IAT would be (50ms + creation gap),
        // potentially hundreds of ms, polluting the regularity score.
        for _ in 0..15 {
            behavior.record_request(hash_ep("/api/test"), "GET", false);
            std::thread::sleep(Duration::from_millis(5));
        }

        let assessment = behavior.analyze();
        assert!(assessment.has_sufficient_data);
        // With proper fix:14 inter-arrival times (first request doesn't create one)
        // All should be ~5ms apart → very regular → high timing_regularity
        assert!(
            assessment.signals.timing_regularity >= 0.7,
            "Bot with regular timing should score high: {}",
            assessment.signals.timing_regularity
        );
    }

    /// BUG VERIFICATION:Endpoint concentration is windowed and doesn't /// dilute over time. A bot that hits diverse endpoints early but then /// concentrates should be detected.
    #[test]
    fn endpoint_concentration_is_windowed_not_cumulative() {
        let mut behavior = SessionBehavior::new(50);

        // Phase 1:50 diverse endpoint hits (fills the window)
        for i in 0..50 {
            behavior.record_request(hash_ep(&format!("/api/resource/{}", i)), "GET", false);
        }

        // At this point, concentration should be low (diverse)
        let assessment1 = behavior.analyze();
        assert!(
            assessment1.signals.endpoint_concentration < 0.5,
            "Diverse phase should have low concentration: {}",
            assessment1.signals.endpoint_concentration
        );

        // Phase 2:Now the bot concentrates on a single endpoint for 50 requests
        // This should push out the diverse history from the window
        for _ in 0..50 {
            behavior.record_request(hash_ep("/api/target"), "GET", false);
        }

        let assessment2 = behavior.analyze();
        // With the fix, the window only contains the last 50 requests (all /api/target)
        assert!(
            assessment2.signals.endpoint_concentration >= 0.7,
            "After concentrated phase, windowed concentration should be high: {}",
            assessment2.signals.endpoint_concentration
        );
    }

    /// Attack:Credential stuffing bot that hammers login with different creds
    #[test]
    fn credential_stuffing_bot_detected() {
        let mut behavior = SessionBehavior::new(200);

        // Rapid login attempts, single endpoint, high error rate
        for i in 0..100 {
            let is_error = i >= 2; // 98% failure rate
            behavior.record_request(hash_ep("/api/login"), "POST", is_error);
        }

        let assessment = behavior.analyze();
        assert!(assessment.has_sufficient_data);

        // Should flag:single endpoint + high errors + regular timing
        assert!(
            assessment.signals.endpoint_concentration >= 0.7,
            "Single endpoint should have high concentration: {}",
            assessment.signals.endpoint_concentration
        );
        assert!(
            assessment.signals.error_anomaly >= 0.5,
            "98% error rate should flag: {}",
            assessment.signals.error_anomaly
        );
        assert!(
            assessment.bot_probability > 0.5,
            "Credential stuffing bot should have high probability: {}",
            assessment.bot_probability
        );
    }

    /// Normal human user:diverse browsing, varied timing, some errors
    #[test]
    fn normal_human_browsing_scores_low() {
        let mut behavior = SessionBehavior::new(200);

        let endpoints = [
            "/",
            "/api/messages",
            "/api/templates",
            "/api/domains",
            "/api/settings",
            "/api/analytics",
            "/api/users",
            "/api/billing",
            "/api/keys",
            "/api/logs",
        ];

        for i in 0..30 {
            let ep = endpoints[i % endpoints.len()];
            let method = if i % 5 == 0 { "POST" } else { "GET" };
            let is_error = i == 7 || i == 22; // Occasional errors
            behavior.record_request(hash_ep(ep), method, is_error);
            // Variable delays (would be more variable in real scenario)
            std::thread::sleep(Duration::from_millis(if i % 3 == 0 { 1 } else { 5 }));
        }

        let assessment = behavior.analyze();
        assert!(assessment.has_sufficient_data);
        assert!(
            assessment.signals.endpoint_concentration < 0.5,
            "Diverse browsing should have low concentration: {}",
            assessment.signals.endpoint_concentration
        );
        assert!(
            assessment.signals.error_anomaly < 0.5,
            "Low error rate should score low: {}",
            assessment.signals.error_anomaly
        );
    }

    /// Bot that always hits the same endpoint with zero errors is suspicious
    #[test]
    fn zero_error_rate_with_high_volume_is_suspicious() {
        let mut behavior = SessionBehavior::new(200);

        // 100 requests, zero errors, single endpoint
        for _ in 0..100 {
            behavior.record_request(hash_ep("/api/data"), "GET", false);
        }

        let assessment = behavior.analyze();
        // After 50 requests with zero errors, this should be flagged
        assert!(
            assessment.signals.error_anomaly >= 0.4,
            "Zero errors after 100 requests should be suspicious: {}",
            assessment.signals.error_anomaly
        );
    }

    /// Sequence entropy:repetitive single-endpoint bot vs diverse human
    #[test]
    fn sequence_entropy_distinguishes_bot_from_human() {
        // Bot:same endpoint repeatedly
        let mut bot = SessionBehavior::new(100);
        let ep = hash_ep("/api/scrape");
        for _ in 0..50 {
            bot.record_request(ep, "GET", false);
        }
        let bot_entropy = bot.sequence_entropy();

        // Human:varied endpoints
        let mut human = SessionBehavior::new(100);
        let eps: Vec<u64> = (0..15).map(|i| hash_ep(&format!("/page/{}", i))).collect();
        for (_i, ep) in eps.iter().cycle().take(50).enumerate() {
            human.record_request(*ep, "GET", false);
        }
        let human_entropy = human.sequence_entropy();

        assert!(
            bot_entropy < human_entropy,
            "Bot entropy ({}) should be lower than human entropy ({})",
            bot_entropy,
            human_entropy
        );
        assert!(
            bot_entropy < 0.5,
            "Bot entropy should be very low: {}",
            bot_entropy
        );
        assert!(
            human_entropy > 1.0,
            "Human entropy should be higher: {}",
            human_entropy
        );
    }
}

// ============================================================================
// MODULE 4:Cost-Based Rate Limiting — Realistic Attack Scenarios
// ============================================================================

mod cost_attacks {
    use super::*;

    /// BUG VERIFICATION:system_budget does not underflow to u64::MAX
    /// when record_cost is called with more than remaining budget.
    #[test]
    fn system_budget_does_not_underflow_via_record_cost() {
        let config = CostLimiterConfig {
            default_tenant_budget: 100,
            system_capacity: 1000,
        };
        let limiter = CostBasedLimiter::new(config);

        // Record more cost than the system has
        limiter.record_cost("tenant1", 5000);

        let remaining = limiter.system_remaining();
        assert_eq!(
            remaining, 0,
            "System budget should be 0, not u64::MAX. Got: {}",
            remaining
        );
    }

    /// BUG VERIFICATION:check deduction doesn't underflow under concurrent load
    #[test]
    fn system_budget_doesnt_underflow_via_check() {
        let config = CostLimiterConfig {
            default_tenant_budget: 100_000_000,
            system_capacity: 100,
        };
        let limiter = CostBasedLimiter::new(config);

        // First check burns some budget
        let result = limiter.check("t1", "/v1/health", Some(RequestCost::new(10, 0, 0, 0)));
        assert!(matches!(result, CostDecision::Allowed { .. }));

        // Many more checks should eventually hit system overload, not underflow
        for _ in 0..100 {
            let _ = limiter.check("t1", "/v1/health", Some(RequestCost::new(10, 0, 0, 0)));
        }

        let remaining = limiter.system_remaining();
        assert!(
            remaining <= 100,
            "System budget should be at or near 0, got: {}",
            remaining
        );
        // Critically:it should never be u64::MAX or near it
        assert!(
            remaining < 1_000_000,
            "System budget must not underflow to huge value: {}",
            remaining
        );
    }

    /// Attack:tenant exhaustion — one tenant shouldn't affect another
    #[test]
    fn tenant_isolation_under_exhaustion() {
        let config = CostLimiterConfig {
            default_tenant_budget: 1_000,
            system_capacity: 100_000_000,
        };
        let limiter = CostBasedLimiter::new(config);

        // Tenant A exhausts their budget
        for _ in 0..20 {
            let _ = limiter.check("tenant_a", "/v1/messages/send", None);
        }

        // Tenant A should be limited
        let result = limiter.check("tenant_a", "/v1/messages/send", None);
        assert!(
            matches!(result, CostDecision::QuotaExceeded { .. }),
            "Exhausted tenant should be rate-limited"
        );

        // Tenant B should still work
        let result = limiter.check("tenant_b", "/v1/health", None);
        assert!(
            matches!(result, CostDecision::Allowed { .. }),
            "Different tenant should not be affected"
        );
    }

    /// Endpoint cost weighting:expensive endpoints exhaust budget faster
    #[test]
    fn expensive_endpoints_consume_budget_faster() {
        let config = CostLimiterConfig {
            default_tenant_budget: 200_000,
            system_capacity: 100_000_000,
        };
        let limiter = CostBasedLimiter::new(config);

        // Check how many batch sends we can do
        let mut count = 0;
        loop {
            match limiter.check("t1", "/v1/messages/send/batch", None) {
                CostDecision::Allowed { .. } => count += 1,
                _ => break,
            }
            if count > 1000 {
                break;
            } // Safety valve
        }

        // Batch send is very expensive (50000 cpu_us + 10MB memory + 50 IO + 10 external)
        // = 50000 + 10240 + 500 + 1000 = 61740 per request
        // Budget 200_000 / 61740 ≈ 3.2 requests
        assert!(
            count <= 5,
            "Expensive batch endpoint should exhaust budget in ~3 requests, did: {}",
            count
        );
        assert!(
            count >= 2,
            "Should allow at least 2 batch requests, did: {}",
            count
        );
    }

    /// Custom cost values override endpoint registry
    #[test]
    fn custom_cost_overrides_registry() {
        let config = CostLimiterConfig {
            default_tenant_budget: 100,
            system_capacity: 100_000_000,
        };
        let limiter = CostBasedLimiter::new(config);

        // Use custom cheap cost for an expensive endpoint
        let cheap = RequestCost::new(1, 0, 0, 0); // 1 cost unit
        let result = limiter.check("t1", "/v1/messages/send/batch", Some(cheap));
        assert!(
            matches!(result, CostDecision::Allowed { cost: 1, .. }),
            "Custom cost should override registry"
        );
    }
}

// ============================================================================
// MODULE 5:Reputation System — Realistic Scenarios
// ============================================================================

mod reputation_attacks {
    use super::*;

    /// Reputation starts neutral and degrades under attack
    #[test]
    fn reputation_degrades_under_sustained_failures() {
        let mut rep = ReputationScore::default();
        assert_eq!(rep.score, 50);
        assert_eq!(rep.level(), ReputationLevel::Normal);

        // Simulate failed challenges
        for _ in 0..3 {
            rep.record_challenge_failed(); // -10 each
        }
        assert_eq!(rep.score, 20);
        assert_eq!(rep.level(), ReputationLevel::Suspicious);

        // Two more failures
        rep.record_challenge_failed();
        rep.record_challenge_failed();
        assert_eq!(rep.score, 0);
        assert_eq!(rep.level(), ReputationLevel::Blocked);
    }

    /// Reputation recovers through passed challenges
    #[test]
    fn reputation_recovers_through_good_behavior() {
        let mut rep = ReputationScore::default();
        rep.score = 10; // Start low

        // Pass 10 challenges:+5 each
        for _ in 0..10 {
            rep.record_challenge_passed();
        }
        assert_eq!(rep.score, 60);
        assert_eq!(rep.level(), ReputationLevel::Normal);
    }

    /// Decay toward neutral respects trusted/flagged status
    #[test]
    fn trusted_ips_dont_decay() {
        let mut rep = ReputationScore::trusted();
        assert_eq!(rep.score, 90);

        rep.decay_toward_neutral(10);
        assert_eq!(rep.score, 90, "Trusted IPs should not decay");
    }

    #[test]
    fn flagged_ips_dont_decay() {
        let mut rep = ReputationScore::flagged();
        assert_eq!(rep.score, 20);

        rep.decay_toward_neutral(10);
        assert_eq!(rep.score, 20, "Flagged IPs should not decay");
    }

    /// Score is bounded 0-100
    #[test]
    fn score_stays_bounded() {
        let mut rep = ReputationScore::default();
        rep.score = 98;
        rep.record_challenge_passed(); // +5, should cap at 100
        assert_eq!(rep.score, 100);

        rep.score = 3;
        rep.record_challenge_failed(); // -10, should floor at 0
        assert_eq!(rep.score, 0);

        // Saturating operations
        rep.score = 0;
        rep.record_blocked(); // -5, still 0
        assert_eq!(rep.score, 0);
    }

    /// Challenge pass rate calculation
    #[test]
    fn challenge_pass_rate_accurate() {
        let mut rep = ReputationScore::default();

        // No challenges = neutral (1.0)
        assert!((rep.challenge_pass_rate() - 1.0).abs() < f64::EPSILON);

        rep.record_challenge_passed();
        rep.record_challenge_passed();
        rep.record_challenge_failed();
        // 2/3 = 0.6667
        assert!((rep.challenge_pass_rate() - 2.0 / 3.0).abs() < 0.001);
    }
}

// ============================================================================
// MODULE 6:Middleware — IP Extraction & Integration
// ============================================================================

mod middleware_tests {
    use super::*;

    /// X-Forwarded-For spoofing:attacker sends fake IP in XFF
    #[test]
    fn xff_spoofing_takes_first_entry() {
        let direct: IpAddr = "192.168.1.1".parse().unwrap();
        // Attacker's real IP is in the rightmost position (appended by proxy)
        // but we take the left-most (client-reported). This is a known design choice.
        let result = extract_client_ip(
            None,
            Some("10.0.0.1, 172.16.0.1, 192.168.1.1"),
            None,
            direct,
        );
        assert_eq!(
            result,
            "10.0.0.1".parse::<IpAddr>().unwrap(),
            "XFF should extract first (leftmost) IP"
        );
    }

    /// Invalid headers fall through gracefully
    #[test]
    fn invalid_headers_fall_through_to_direct() {
        let direct: IpAddr = "192.168.1.1".parse().unwrap();
        let result = extract_client_ip(
            Some("not-an-ip"),
            Some("also-not-valid"),
            Some("nope"),
            direct,
        );
        assert_eq!(
            result, direct,
            "All invalid headers should fallback to direct IP"
        );
    }

    /// BUG VERIFICATION:Suspicious fingerprint penalty affects current request
    #[tokio::test]
    async fn suspicious_fingerprint_decreases_reputation_for_current_request() {
        let config = ProtectorConfig::default();
        let protector = DdosProtector::new(config).await.unwrap();
        let test_ip: IpAddr = "10.0.0.50".parse().unwrap();

        // Send many requests with a suspicious short fingerprint
        // Each request should penalize reputation by 10
        for _ in 0..5 {
            let ctx = RequestContext {
                ip: test_ip,
                path: "/v1/health".to_string(),
                method: "GET".to_string(),
                tls_fingerprint: Some("abc".to_string()), // Very short = suspicious
                h2_fingerprint: None,
                user_agent: None,
                body_size: 0,
                tenant_id: None,
                api_key_id: None,
            };
            let _ = protector.evaluate(&ctx).await;
        }

        // After 5 requests with -10 each:50 → 40 → 30 → 20 → 10 → 0
        // With the fix, each evaluate re-reads after decrement, so threshold
        // checks work correctly. The IP should eventually be blocked.
        let ctx = RequestContext {
            ip: test_ip,
            path: "/v1/health".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: Some("abc".to_string()),
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
        };
        let decision = protector.evaluate(&ctx).await;
        assert!(
            matches!(decision, ProtectionDecision::Block),
            "IP with score 0 from repeated suspicious fingerprints should be blocked, got: {:?}",
            decision
        );
    }

    /// Clean IP is allowed through
    #[tokio::test]
    async fn clean_request_allowed() {
        let config = ProtectorConfig::default();
        let protector = DdosProtector::new(config).await.unwrap();

        let ctx = RequestContext {
            ip: "1.2.3.4".parse().unwrap(),
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

    /// Blocked IP stays blocked until expiry
    #[tokio::test]
    async fn blocked_ip_stays_blocked() {
        let config = ProtectorConfig::default();
        let protector = DdosProtector::new(config).await.unwrap();

        let test_ip: IpAddr = "10.0.0.1".parse().unwrap();
        protector.block_ip(test_ip, Duration::from_secs(300), "test".to_string());

        assert!(protector.is_blocked(&test_ip));

        // Multiple requests should all be blocked
        for _ in 0..5 {
            let ctx = RequestContext {
                ip: test_ip,
                path: "/".to_string(),
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
    }
}

// ============================================================================
// MODULE 7:Cross-Module Integration — Realistic Multi-Layer Attack Scenarios
// ============================================================================

mod integration_attacks {
    use super::*;

    /// Full SMTP session:Connect → EHLO → MAIL → RCPT → DATA → end-of-data → QUIT
    #[test]
    fn complete_legitimate_smtp_session() {
        let config = SmtpProtectionConfig::default();
        let tracker = SmtpConnectionTracker::new(config.clone());
        let addr = ip(10);

        // Register connection
        tracker.register_connection(addr).unwrap();
        let mut prot = SmtpConnectionProtection::new(addr, 50, config);

        assert_eq!(prot.state(), SmtpState::Connected);

        // EHLO
        assert_eq!(
            prot.process_command("EHLO mail.example.com").unwrap(),
            SmtpAction::Continue
        );
        assert_eq!(prot.state(), SmtpState::GreetingReceived);

        // MAIL FROM
        assert_eq!(
            prot.process_command("MAIL FROM:<sender@example.com>")
                .unwrap(),
            SmtpAction::Continue
        );

        // RCPT TO (multiple)
        assert_eq!(
            prot.process_command("RCPT TO:<r1@example.com>").unwrap(),
            SmtpAction::Continue
        );
        assert_eq!(
            prot.process_command("RCPT TO:<r2@example.com>").unwrap(),
            SmtpAction::Continue
        );

        // DATA
        assert_eq!(prot.process_command("DATA").unwrap(), SmtpAction::Continue);
        assert!(matches!(prot.state(), SmtpState::DataReceiving { .. }));

        // Record data
        prot.record_data(5000).unwrap();
        prot.check_data_rate(5000, Duration::from_secs(1)).unwrap();

        // QUIT
        assert_eq!(
            prot.process_command("QUIT").unwrap(),
            SmtpAction::Disconnect
        );

        // Unregister
        tracker.unregister_connection(&addr);
        assert_eq!(tracker.active_count(&addr), 0);
    }

    /// SMTP attack:attacker connects, sends garbage, gets tarpitted, delays escalate,
    /// eventually QUITs
    #[test]
    fn smtp_attack_lifecycle_with_escalating_tarpit() {
        let config = SmtpProtectionConfig {
            strict_mode: false,
            max_invalid: 2,
            tarpit_delay: Duration::from_secs(1),
            max_commands: 50,
            ..SmtpProtectionConfig::default()
        };
        let mut prot = SmtpConnectionProtection::new(ip(11), 50, config);

        // Phase 1:Probing with invalid commands
        let a1 = prot.process_command("XYZZY").unwrap();
        assert_eq!(a1, SmtpAction::Reject("500 Unrecognized command"));
        let a2 = prot.process_command("VRFY ALL").unwrap();
        // VRFY from Connected state is invalid
        assert_eq!(a2, SmtpAction::Reject("503 Bad sequence of commands"));

        // 2 invalids at limit, no tarpit yet
        assert!(prot.should_tarpit().is_none());

        // Phase 2:More garbage → tarpit escalation starts
        let a3 = prot.process_command("HACK1").unwrap();
        assert_eq!(a3, SmtpAction::Tarpit(Duration::from_secs(1))); // 1 over

        let a4 = prot.process_command("HACK2").unwrap();
        assert_eq!(a4, SmtpAction::Tarpit(Duration::from_secs(2))); // 2 over

        let a5 = prot.process_command("HACK3").unwrap();
        assert_eq!(a5, SmtpAction::Tarpit(Duration::from_secs(3))); // 3 over

        // Phase 3:Attacker gives up
        let quit = prot.process_command("QUIT").unwrap();
        assert_eq!(quit, SmtpAction::Disconnect);
    }

    /// Reputation + Cost interaction:low-reputation IP on expensive endpoint
    #[test]
    fn reputation_score_math_is_consistent() {
        let mut rep = ReputationScore::default();
        assert_eq!(rep.score, 50);

        // Simulate a session:some good, some bad
        rep.record_request();
        rep.record_request();
        rep.record_challenge_passed(); // +5 → 55
        rep.record_rate_limit(); // -2 → 53
        rep.record_challenge_failed(); // -10 → 43
        rep.record_blocked(); // -5 → 38

        assert_eq!(rep.score, 38);
        assert_eq!(rep.level(), ReputationLevel::Normal);
        assert_eq!(rep.total_requests, 2);
        assert_eq!(rep.challenges_passed, 1);
        assert_eq!(rep.challenges_failed, 1);
        assert_eq!(rep.rate_limit_hits, 1);
        assert_eq!(rep.blocked_requests, 1);
    }

    /// Adaptive + Bot detection:a bot session during an attack
    #[test]
    fn bot_during_adaptive_attack() {
        // Set up adaptive limiter detecting an attack
        let config = AdaptiveConfig {
            consecutive_alert_trigger: 2,
            ..AdaptiveConfig::default()
        };
        let limiter = AdaptiveRateLimiter::new(config);

        // Build baseline
        for i in 0..20 {
            limiter.update(TrafficObservation {
                timestamp: Instant::now(),
                requests_per_second: 100.0 + (i as f64 % 5.0),
                error_rate: 0.01,
                latency_p99_ms: 50.0,
                cpu_usage: 0.3,
            });
        }

        // Trigger attack
        limiter.update(TrafficObservation {
            timestamp: Instant::now(),
            requests_per_second: 5000.0,
            error_rate: 0.01,
            latency_p99_ms: 50.0,
            cpu_usage: 0.3,
        });
        limiter.update(TrafficObservation {
            timestamp: Instant::now(),
            requests_per_second: 5000.0,
            error_rate: 0.01,
            latency_p99_ms: 50.0,
            cpu_usage: 0.3,
        });

        assert!(limiter.is_under_attack());

        // Meanwhile, analyze a suspicious session
        let mut behavior = SessionBehavior::new(100);
        let ep = hash_ep("/api/data");
        for _ in 0..50 {
            behavior.record_request(ep, "GET", false);
        }

        let assessment = behavior.analyze();
        assert!(assessment.has_sufficient_data);
        assert!(
            assessment.bot_probability > 0.3,
            "Bot during attack should have elevated probability: {}",
            assessment.bot_probability
        );

        // Both systems agree something is wrong
        assert!(limiter.is_under_attack() && assessment.bot_probability > 0.3);
    }
}

// ============================================================================
// MODULE 8:Property-Based / Invariant Tests
// ============================================================================

mod invariant_tests {
    use super::*;

    /// SMTP state machine never allows skipping required states
    #[test]
    fn smtp_state_machine_requires_ehlo_before_mail() {
        let config = SmtpProtectionConfig::default();
        let mut prot = SmtpConnectionProtection::new(ip(20), 50, config);

        // DATA before RCPT TO
        let result = prot.process_command("DATA");
        assert!(result.is_err());

        // RCPT TO before MAIL FROM (even if EHLO was sent)
        let mut prot = SmtpConnectionProtection::new(ip(20), 50, SmtpProtectionConfig::default());
        prot.process_command("EHLO test.com").unwrap();
        let result = prot.process_command("RCPT TO:<a@b.com>");
        assert!(result.is_err());

        // MAIL FROM before EHLO
        let mut prot = SmtpConnectionProtection::new(ip(20), 50, SmtpProtectionConfig::default());
        let result = prot.process_command("MAIL FROM:<a@b.com>");
        assert!(result.is_err());
    }

    /// Reputation score always stays in 0-100 range
    #[test]
    fn reputation_always_bounded_under_extreme_operations() {
        let mut rep = ReputationScore::default();

        // Extreme failures
        for _ in 0..1000 {
            rep.record_challenge_failed();
            rep.record_blocked();
        }
        assert!(rep.score <= 100, "Score overflowed: {}", rep.score);

        // Extreme successes
        rep = ReputationScore::default();
        for _ in 0..1000 {
            rep.record_challenge_passed();
        }
        assert!(rep.score <= 100, "Score overflowed: {}", rep.score);
    }

    /// Adaptive threshold always stays within configured bounds under any input
    #[test]
    fn adaptive_threshold_bounded_under_random_input() {
        let config = AdaptiveConfig {
            min_threshold: 50,
            max_threshold: 10_000,
            consecutive_alert_trigger: 2,
            ..AdaptiveConfig::default()
        };
        let limiter = AdaptiveRateLimiter::new(config);

        // Feed a wild mix of traffic patterns
        let rps_values = [
            0.0,
            0.001,
            1.0,
            100.0,
            10_000.0,
            1_000_000.0,
            f64::MAX / 2.0,
        ];
        for &rps in rps_values.iter().cycle().take(100) {
            limiter.update(TrafficObservation {
                timestamp: Instant::now(),
                requests_per_second: rps,
                error_rate: 0.5,
                latency_p99_ms: 100.0,
                cpu_usage: 0.8,
            });

            let t = limiter.current_threshold();
            assert!(
                t >= 50 && t <= 10_000,
                "Threshold out of bounds: {} (min=50, max=10000)",
                t
            );
        }
    }

    /// Bot probability always in [0, 1]
    #[test]
    fn bot_probability_always_in_unit_range() {
        let mut behavior = SessionBehavior::new(200);

        // Edge case:all same endpoint, all errors, rapid fire
        for _ in 0..200 {
            behavior.record_request(hash_ep("/spam"), "POST", true);
        }

        let assessment = behavior.analyze();
        assert!(
            assessment.bot_probability >= 0.0 && assessment.bot_probability <= 1.0,
            "Bot probability out of range: {}",
            assessment.bot_probability
        );

        // Edge case:all different endpoints, no errors
        let mut behavior2 = SessionBehavior::new(200);
        for i in 0..200 {
            behavior2.record_request(hash_ep(&format!("/ep/{}", i)), "GET", false);
        }
        let assessment2 = behavior2.analyze();
        assert!(
            assessment2.bot_probability >= 0.0 && assessment2.bot_probability <= 1.0,
            "Bot probability out of range: {}",
            assessment2.bot_probability
        );
    }

    /// Connection tracker:active count never goes negative
    #[test]
    fn connection_count_never_negative() {
        let config = SmtpProtectionConfig {
            max_connections_per_ip: 100,
            ..SmtpProtectionConfig::default()
        };
        let tracker = SmtpConnectionTracker::new(config);
        let addr = ip(30);

        // Register 5, unregister 10 — count should stay at 0
        for _ in 0..5 {
            tracker.register_connection(addr).unwrap();
        }
        for _ in 0..10 {
            tracker.unregister_connection(&addr);
        }

        assert_eq!(
            tracker.active_count(&addr),
            0,
            "Active count should be 0 after excess unregisters"
        );

        // Should still be able to register
        tracker.register_connection(addr).unwrap();
        assert_eq!(tracker.active_count(&addr), 1);
    }
}
