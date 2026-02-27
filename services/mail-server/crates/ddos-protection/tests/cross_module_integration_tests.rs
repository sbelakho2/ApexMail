//! # Cross-Module Integration Tests
//!
//! Tests that verify multiple DDoS protection modules working together.
//! Each test exercises interaction between 2+ modules under realistic scenarios.

use ddos_protection::{
    adaptive::{AdaptiveConfig, AdaptiveRateLimiter, TrafficObservation},
    bot_detection::SessionBehavior,
    config::ProtectorConfig,
    decision::ProtectionDecision,
    middleware::{evaluate_request, extract_client_ip, RequestContextBuilder},
    reputation::ReputationScore,
    smtp_protection::*,
    DdosProtector, RequestContext,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::time::{Duration, Instant};

fn hash_ep(path: &str) -> u64 {
    let mut h = DefaultHasher::new();
    path.hash(&mut h);
    h.finish()
}

fn make_ctx(ip: &str, path: &str, method: &str) -> RequestContext {
    RequestContextBuilder::new(ip.parse().unwrap(), path, method).build()
}

// ═══════════════════════════════════════════════════════════════
//  SCENARIO 1: Full Pipeline — allowed request flows through all layers
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_full_pipeline_allows_normal_traffic() {
    let config = ProtectorConfig::default();
    let protector = DdosProtector::new(config).await.unwrap();

    for i in 0..20 {
        let ctx = make_ctx(
            &format!("10.0.0.{}", i % 10),
            "/v1/health",
            "GET",
        );
        let decision = protector.evaluate(&ctx).await;
        assert!(
            decision.is_allowed(),
            "Normal request #{} should be allowed, got: {:?}",
            i,
            decision
        );
    }
}

// ═══════════════════════════════════════════════════════════════
//  SCENARIO 2: Blocklist → immediate block, bypasses all other layers
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_blocked_ip_bypasses_all_layers() {
    let config = ProtectorConfig::default();
    let protector = DdosProtector::new(config).await.unwrap();
    let ip: IpAddr = "172.16.0.1".parse().unwrap();

    protector.block_ip(ip, Duration::from_secs(600), "integration_test".to_string());

    // Even with valid fingerprint and low cost, should be blocked
    let ctx = RequestContextBuilder::new(ip, "/v1/health", "GET")
        .tls_fingerprint("t13d1517h2_8daaf6152771_e5627efa2ab1")
        .user_agent("Mozilla/5.0 Chrome/120")
        .tenant_id("trusted-customer")
        .build();

    let decision = protector.evaluate(&ctx).await;
    assert!(matches!(decision, ProtectionDecision::Block));
}

// ═══════════════════════════════════════════════════════════════
//  SCENARIO 3: Suspicious fingerprint + repeated requests → reputation decay
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_suspicious_fingerprint_degrades_reputation() {
    let config = ProtectorConfig {
        block_threshold: 10,
        ..ProtectorConfig::default()
    };
    let protector = DdosProtector::new(config).await.unwrap();
    let ip: IpAddr = "203.0.113.42".parse().unwrap();
    let trusted_ip: IpAddr = "203.0.113.43".parse().unwrap();

    // Baseline trusted traffic should stay allowed.
    let trusted_warmup = RequestContextBuilder::new(trusted_ip, "/v1/health", "GET")
        .tls_fingerprint("t13d1517h2_8daaf6152771_e5627efa2ab1")
        .build();
    let warmup_decision = protector.evaluate(&trusted_warmup).await;
    assert!(
        matches!(warmup_decision, ProtectionDecision::Allow),
        "Trusted warmup should be allowed, got: {:?}",
        warmup_decision
    );

    // Mix suspicious signals: malformed JA4 + very short token.
    // This should degrade reputation on every request for this IP.
    let suspicious_fingerprints = ["not-a-ja4", "ab", "cd", "ef", "gh"];
    let mut saw_block = false;
    for (idx, fp) in suspicious_fingerprints.into_iter().enumerate() {
        let ctx = RequestContextBuilder::new(ip, "/v1/messages/send", "POST")
            .tls_fingerprint(fp)
            .build();
        let decision = protector.evaluate(&ctx).await;

        if idx < 4 {
            assert!(
                matches!(decision, ProtectionDecision::Allow),
                "Request #{} should still be pre-block threshold, got: {:?}",
                idx + 1,
                decision
            );
        } else {
            assert!(
                matches!(decision, ProtectionDecision::Block),
                "Request #{} should cross block threshold, got: {:?}",
                idx + 1,
                decision
            );
            saw_block = true;
        }
    }
    assert!(saw_block, "Expected suspicious sequence to eventually block");

    // Once blocked, subsequent requests from this IP remain blocked.
    let ctx = RequestContextBuilder::new(ip, "/v1/health", "GET")
        .tls_fingerprint("valid_enough_fingerprint_here")
        .build();
    let decision = protector.evaluate(&ctx).await;
    assert!(
        matches!(decision, ProtectionDecision::Block),
        "After repeated suspicious fingerprints, should be blocked: {:?}",
        decision
    );

    // Ensure unrelated trusted IP does not inherit penalties.
    let trusted_ctx = RequestContextBuilder::new(trusted_ip, "/v1/health", "GET")
        .tls_fingerprint("t13d1517h2_8daaf6152771_e5627efa2ab1")
        .build();
    let trusted_decision = protector.evaluate(&trusted_ctx).await;
    assert!(
        matches!(trusted_decision, ProtectionDecision::Allow),
        "Trusted IP should remain allowed, got: {:?}",
        trusted_decision
    );
}

#[tokio::test]
async fn test_suspicious_fingerprint_penalty_is_ip_scoped() {
    let config = ProtectorConfig {
        block_threshold: 20,
        ..ProtectorConfig::default()
    };
    let protector = DdosProtector::new(config).await.unwrap();
    let attacker_ip: IpAddr = "198.51.100.120".parse().unwrap();
    let normal_ip: IpAddr = "198.51.100.121".parse().unwrap();

    for _ in 0..4 {
        let attacker_ctx = RequestContextBuilder::new(attacker_ip, "/v1/messages/send", "POST")
            .tls_fingerprint("xy")
            .build();
        let _ = protector.evaluate(&attacker_ctx).await;
    }

    let attacker_followup = RequestContextBuilder::new(attacker_ip, "/v1/health", "GET")
        .tls_fingerprint("t13d1517h2_8daaf6152771_e5627efa2ab1")
        .build();
    let attacker_decision = protector.evaluate(&attacker_followup).await;
    assert!(
        matches!(attacker_decision, ProtectionDecision::Block),
        "Attacker IP should be blocked after repeated suspicious fingerprints, got: {:?}",
        attacker_decision
    );

    let normal_ctx = RequestContextBuilder::new(normal_ip, "/v1/health", "GET")
        .tls_fingerprint("t13d1517h2_8daaf6152771_e5627efa2ab1")
        .build();
    let normal_decision = protector.evaluate(&normal_ctx).await;
    assert!(
        matches!(normal_decision, ProtectionDecision::Allow),
        "Non-attacker IP should remain allowed, got: {:?}",
        normal_decision
    );
}

// ═══════════════════════════════════════════════════════════════
//  SCENARIO 4: Middleware integration — evaluates and translates decisions
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_middleware_translates_block_to_403() {
    let config = ProtectorConfig::default();
    let protector = DdosProtector::new(config).await.unwrap();

    let ip: IpAddr = "198.51.100.5".parse().unwrap();
    protector.block_ip(ip, Duration::from_secs(300), "test".to_string());

    let ctx = RequestContextBuilder::new(ip, "/api/data", "GET").build();
    let action = evaluate_request(&protector, &ctx).await;

    match action {
        ddos_protection::middleware::MiddlewareAction::Block { status } => {
            assert_eq!(status, 403);
        }
        other => panic!("Expected Block(403), got: {:?}", other),
    }
}

#[tokio::test]
async fn test_middleware_allow_maps_correctly() {
    let config = ProtectorConfig::default();
    let protector = DdosProtector::new(config).await.unwrap();

    let ctx = RequestContextBuilder::new("1.2.3.4".parse().unwrap(), "/health", "GET").build();
    let action = evaluate_request(&protector, &ctx).await;

    assert!(matches!(
        action,
        ddos_protection::middleware::MiddlewareAction::Allow
    ));
}

// ═══════════════════════════════════════════════════════════════
//  SCENARIO 5: SMTP + Connection Tracker — concurrent limit enforcement
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_smtp_connection_exhaustion_and_recovery() {
    let config = SmtpProtectionConfig {
        max_connections_per_ip: 3,
        ..SmtpProtectionConfig::default()
    };
    let tracker = SmtpConnectionTracker::new(config.clone());
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    // Exhaust connections
    tracker.register_connection(ip).unwrap();
    tracker.register_connection(ip).unwrap();
    tracker.register_connection(ip).unwrap();

    // 4th should fail
    assert!(tracker.register_connection(ip).is_err());

    // Simulate one connection ending a full SMTP session first
    let mut conn = SmtpConnectionProtection::new(ip, 50, config);
    conn.process_command("EHLO test.com").unwrap();
    conn.process_command("MAIL FROM:<a@b.com>").unwrap();
    conn.process_command("RCPT TO:<c@d.com>").unwrap();
    conn.process_command("QUIT").unwrap();
    assert_eq!(conn.state(), SmtpState::Quit);

    // Unregister it
    tracker.unregister_connection(&ip);
    assert_eq!(tracker.active_count(&ip), 2);

    // Now a new connection should be allowed
    tracker.register_connection(ip).unwrap();
    assert_eq!(tracker.active_count(&ip), 3);
}

// ═══════════════════════════════════════════════════════════════
//  SCENARIO 6: SMTP tarpit integrates with reputation
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_smtp_tarpit_based_on_reputation_and_invalids() {
    let config = SmtpProtectionConfig {
        strict_mode: false,
        max_invalid: 2,
        tarpit_delay: Duration::from_secs(5),
        ..SmtpProtectionConfig::default()
    };

    // Low reputation → tarpit from the start
    let low_rep = SmtpConnectionProtection::new("10.0.0.1".parse().unwrap(), 10, config.clone());
    assert_eq!(low_rep.should_tarpit(), Some(Duration::from_secs(2)));

    // Good reputation, no tarpit initially
    let mut good_rep = SmtpConnectionProtection::new("10.0.0.2".parse().unwrap(), 80, config);
    assert!(good_rep.should_tarpit().is_none());

    // Send invalid commands past threshold
    good_rep.process_command("XYZZY1").unwrap(); // invalid #1
    good_rep.process_command("XYZZY2").unwrap(); // invalid #2
    good_rep.process_command("XYZZY3").unwrap(); // invalid #3 → over max_invalid=2

    // Now tarpit kicks in: (3 - 2) * 5s = 5s
    assert_eq!(good_rep.should_tarpit(), Some(Duration::from_secs(5)));
}

// ═══════════════════════════════════════════════════════════════
//  SCENARIO 7: Bot detection + adaptive limiter — attack coordination
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_bot_detection_feeds_adaptive_limiter() {
    // Simulate: bot detected → observe high RPS → adaptive limiter tightens

    let adaptive_config = AdaptiveConfig {
        consecutive_alert_trigger: 2,
        cooldown: Duration::from_millis(50),
        ..AdaptiveConfig::default()
    };
    let limiter = AdaptiveRateLimiter::new(adaptive_config);

    // Build baseline
    for i in 0..20 {
        limiter.update(TrafficObservation {
            timestamp: Instant::now(),
            requests_per_second: 100.0 + (i as f64 % 5.0),
            error_rate: 0.02,
            latency_p99_ms: 50.0,
            cpu_usage: 0.3,
        });
    }

    let pre_attack_threshold = limiter.current_threshold();

    // Simultaneously, bot detection flags automated traffic
    let mut behavior = SessionBehavior::new(100);
    let ep = hash_ep("/api/scrape");
    for _ in 0..30 {
        behavior.record_request(ep, "GET", false);
    }
    let assessment = behavior.analyze();
    assert!(
        assessment.has_sufficient_data,
        "Should have enough data for assessment"
    );

    // Bot is generating a traffic spike
    limiter.update(TrafficObservation {
        timestamp: Instant::now(),
        requests_per_second: 5000.0,
        error_rate: 0.01,
        latency_p99_ms: 200.0,
        cpu_usage: 0.8,
    });
    limiter.update(TrafficObservation {
        timestamp: Instant::now(),
        requests_per_second: 5000.0,
        error_rate: 0.01,
        latency_p99_ms: 300.0,
        cpu_usage: 0.9,
    });

    assert!(limiter.is_under_attack());
    assert!(
        limiter.current_threshold() < pre_attack_threshold,
        "Attack should tighten threshold: {} >= {}",
        limiter.current_threshold(),
        pre_attack_threshold
    );
}

// ═══════════════════════════════════════════════════════════════
//  SCENARIO 8: IP extraction → DDoS evaluation pipeline
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_ip_extraction_feeds_into_ddos_pipeline() {
    let config = ProtectorConfig::default();
    let protector = DdosProtector::new(config).await.unwrap();

    // Simulate proxy setup: real IP in XFF
    let real_ip = extract_client_ip(
        None,
        Some("203.0.113.50, 10.0.0.1"),
        None,
        "10.0.0.1".parse().unwrap(),
    );

    assert_eq!(real_ip, "203.0.113.50".parse::<IpAddr>().unwrap());

    // Block the real IP
    protector.block_ip(real_ip, Duration::from_secs(300), "test".to_string());

    // Build context with the extracted IP
    let ctx = RequestContextBuilder::new(real_ip, "/api/data", "GET").build();
    let decision = protector.evaluate(&ctx).await;

    assert!(matches!(decision, ProtectionDecision::Block));
}

// ═══════════════════════════════════════════════════════════════
//  SCENARIO 9: Reputation scoring integration
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_reputation_decay_and_recovery() {
    let mut rep = ReputationScore::default();
    assert_eq!(rep.score, 50);

    // Simulates failed challenges (from challenge system)
    rep.record_challenge_failed(); // -10
    rep.record_challenge_failed(); // -10
    assert_eq!(rep.score, 30);
    assert_eq!(rep.level(), ddos_protection::reputation::ReputationLevel::Suspicious);

    // Decay toward neutral
    for _ in 0..10 {
        rep.decay_toward_neutral(2);
    }
    assert_eq!(rep.score, 50); // Should cap at 50

    // Good behavior: pass challenges
    rep.record_challenge_passed(); // +5
    rep.record_challenge_passed(); // +5
    assert_eq!(rep.score, 60);
    assert_eq!(rep.level(), ddos_protection::reputation::ReputationLevel::Normal);
}

// ═══════════════════════════════════════════════════════════════
//  SCENARIO 10: Cost-based limiter interacts with DDoS system
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_cost_exhaustion_produces_rate_limit() {
    let config = ProtectorConfig {
        default_cost_budget: 500,
        system_cost_capacity: 100_000,
        ..ProtectorConfig::default()
    };
    let protector = DdosProtector::new(config).await.unwrap();

    let ip: IpAddr = "192.168.1.100".parse().unwrap();

    // Hit expensive endpoint repeatedly until budget exhausted
    let mut limited = false;
    for _ in 0..20 {
        let ctx = RequestContextBuilder::new(ip, "/v1/messages/send", "POST")
            .tenant_id("test-tenant")
            .build();
        let decision = protector.evaluate(&ctx).await;
        if matches!(decision, ProtectionDecision::RateLimit { .. }) {
            limited = true;
            break;
        }
    }

    assert!(limited, "Should eventually be rate limited after exhausting cost budget");
}

// ═══════════════════════════════════════════════════════════════
//  SCENARIO 11: Block expiration works end-to-end
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_block_expiration() {
    let config = ProtectorConfig::default();
    let protector = DdosProtector::new(config).await.unwrap();

    let ip: IpAddr = "10.0.0.99".parse().unwrap();

    // Block for a very short time
    protector.block_ip(ip, Duration::from_millis(50), "short_block".to_string());

    // Initially blocked
    assert!(protector.is_blocked(&ip));

    // Wait for expiration
    std::thread::sleep(Duration::from_millis(100));

    // Should no longer be blocked
    assert!(!protector.is_blocked(&ip));

    // Request should now be allowed
    let ctx = RequestContextBuilder::new(ip, "/health", "GET").build();
    let decision = protector.evaluate(&ctx).await;
    assert!(decision.is_allowed());
}

// ═══════════════════════════════════════════════════════════════
//  SCENARIO 12: Multiple IPs interacting — isolation check
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_ip_isolation() {
    let config = ProtectorConfig::default();
    let protector = DdosProtector::new(config).await.unwrap();

    let good_ip: IpAddr = "10.0.0.1".parse().unwrap();
    let bad_ip: IpAddr = "10.0.0.2".parse().unwrap();

    // Block the bad IP
    protector.block_ip(bad_ip, Duration::from_secs(600), "bad_actor".to_string());

    // Good IP should not be affected
    let ctx = RequestContextBuilder::new(good_ip, "/v1/messages", "GET").build();
    let decision = protector.evaluate(&ctx).await;
    assert!(decision.is_allowed(), "Good IP should be unaffected by bad IP block");

    // Bad IP should still be blocked
    let ctx = RequestContextBuilder::new(bad_ip, "/v1/messages", "GET").build();
    let decision = protector.evaluate(&ctx).await;
    assert!(matches!(decision, ProtectionDecision::Block));
}

// ═══════════════════════════════════════════════════════════════
//  SCENARIO 13: SMTP full session under multiple IPs
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_smtp_tracker_multiple_ips_isolation() {
    let config = SmtpProtectionConfig {
        max_connections_per_ip: 2,
        ..SmtpProtectionConfig::default()
    };
    let tracker = SmtpConnectionTracker::new(config);

    let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
    let ip_b: IpAddr = "10.0.0.2".parse().unwrap();

    // Fill up IP A
    tracker.register_connection(ip_a).unwrap();
    tracker.register_connection(ip_a).unwrap();
    assert!(tracker.register_connection(ip_a).is_err());

    // IP B should still have capacity
    tracker.register_connection(ip_b).unwrap();
    tracker.register_connection(ip_b).unwrap();
    assert!(tracker.register_connection(ip_b).is_err());

    // Cleanup IP A
    tracker.unregister_connection(&ip_a);
    tracker.unregister_connection(&ip_a);

    // IP A should be back to 0
    assert_eq!(tracker.active_count(&ip_a), 0);
    // IP B still at limit
    assert_eq!(tracker.active_count(&ip_b), 2);
}

// ═══════════════════════════════════════════════════════════════
//  SCENARIO 14: Adaptive limiter recovery feeds back to normal
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_adaptive_attack_then_recovery_cycle() {
    let config = AdaptiveConfig {
        consecutive_alert_trigger: 2,
        cooldown: Duration::from_millis(10),
        attack_factor: 0.3, // Lower factor to ensure clear difference
        headroom_factor: 1.5,
        min_threshold: 10,
        max_threshold: 10_000,
        ..AdaptiveConfig::default()
    };
    let limiter = AdaptiveRateLimiter::new(config);

    // Phase 1: Build stable baseline at 500 rps (higher to avoid cold-start threshold conflicts)
    for i in 0..25 {
        limiter.update(TrafficObservation {
            timestamp: Instant::now(),
            requests_per_second: 500.0 + (i as f64 % 5.0),
            error_rate: 0.01,
            latency_p99_ms: 30.0,
            cpu_usage: 0.2,
        });
    }
    let baseline_threshold = limiter.current_threshold();
    assert!(!limiter.is_under_attack());

    // Phase 2: Attack spike
    limiter.update(TrafficObservation {
        timestamp: Instant::now(),
        requests_per_second: 8000.0,
        error_rate: 0.2,
        latency_p99_ms: 500.0,
        cpu_usage: 0.95,
    });
    limiter.update(TrafficObservation {
        timestamp: Instant::now(),
        requests_per_second: 8000.0,
        error_rate: 0.3,
        latency_p99_ms: 800.0,
        cpu_usage: 0.99,
    });
    assert!(limiter.is_under_attack());
    let attack_threshold = limiter.current_threshold();
    assert!(attack_threshold < baseline_threshold,
        "Attack threshold {} should be < baseline threshold {}", 
        attack_threshold, baseline_threshold);

    // Phase 3: Recovery after cooldown
    std::thread::sleep(Duration::from_millis(20));

    for _ in 0..10 {
        limiter.update(TrafficObservation {
            timestamp: Instant::now(),
            requests_per_second: 500.0, // Match baseline RPS
            error_rate: 0.01,
            latency_p99_ms: 30.0,
            cpu_usage: 0.2,
        });
    }
    assert!(!limiter.is_under_attack());
    let recovery_threshold = limiter.current_threshold();
    assert!(
        recovery_threshold > attack_threshold,
        "Recovery threshold should be higher than attack: {} <= {}",
        recovery_threshold,
        attack_threshold
    );
}

// ═══════════════════════════════════════════════════════════════
//  SCENARIO 15: Builder pattern completeness
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_request_context_builder_to_full_ctx() {
    let ctx = RequestContextBuilder::new("192.168.1.1".parse().unwrap(), "/v1/messages/send", "POST")
        .tls_fingerprint("t13d1517h2_8daaf6152771_e5627efa2ab1")
        .h2_fingerprint("settings_hash|frame_hash|prio_hash")
        .user_agent("ApexMail-SDK/1.0")
        .body_size(2048)
        .tenant_id("acme-corp")
        .api_key_id("key_live_xyz")
        .build();

    assert_eq!(ctx.ip, "192.168.1.1".parse::<IpAddr>().unwrap());
    assert_eq!(ctx.path, "/v1/messages/send");
    assert_eq!(ctx.method, "POST");
    assert_eq!(ctx.tls_fingerprint.as_deref(), Some("t13d1517h2_8daaf6152771_e5627efa2ab1"));
    assert_eq!(ctx.h2_fingerprint.as_deref(), Some("settings_hash|frame_hash|prio_hash"));
    assert_eq!(ctx.user_agent.as_deref(), Some("ApexMail-SDK/1.0"));
    assert_eq!(ctx.body_size, 2048);
    assert_eq!(ctx.tenant_id.as_deref(), Some("acme-corp"));
    assert_eq!(ctx.api_key_id.as_deref(), Some("key_live_xyz"));
}
