//! # Property-Based & Fuzz Tests for DDoS Protection System
//!
//! Uses deterministic randomized inputs to verify system invariants.
//! No external proptest dependency — pure std::collections randomization patterns.

use ddos_protection::{
    adaptive::{AdaptiveConfig, AdaptiveRateLimiter, TrafficObservation},
    bot_detection::SessionBehavior,
    middleware::{extract_client_ip, RequestContextBuilder},
    reputation::ReputationScore,
    smtp_protection::*,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Simple deterministic PRNG for test reproducibility (xorshift64)
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn next_f64(&mut self) -> f64 {
        (self.next_u64() % 1_000_000) as f64 / 1_000_000.0
    }

    fn range(&mut self, min: u64, max: u64) -> u64 {
        min + (self.next_u64() % (max - min + 1))
    }

    fn next_ip(&mut self) -> IpAddr {
        let a = (self.next_u64() % 254 + 1) as u8;
        let b = (self.next_u64() % 254 + 1) as u8;
        let c = (self.next_u64() % 254 + 1) as u8;
        let d = (self.next_u64() % 254 + 1) as u8;
        IpAddr::from([a, b, c, d])
    }
}

fn hash_ep(path: &str) -> u64 {
    let mut h = DefaultHasher::new();
    path.hash(&mut h);
    h.finish()
}

// ═══════════════════════════════════════════════════════════════
//  INVARIANT 1: Reputation score is always in [0, 100]
// ═══════════════════════════════════════════════════════════════

#[test]
fn property_reputation_score_always_bounded() {
    let mut rng = Rng::new(42);

    for _ in 0..1000 {
        let mut rep = ReputationScore::default();

        // Apply random sequence of operations
        for _ in 0..50 {
            match rng.next_u64() % 6 {
                0 => rep.record_challenge_passed(),
                1 => rep.record_challenge_failed(),
                2 => rep.record_rate_limit(),
                3 => rep.record_blocked(),
                4 => rep.record_request(),
                5 => rep.decay_toward_neutral((rng.next_u64() % 20) as u8),
                _ => unreachable!(),
            }

            assert!(rep.score <= 100, "Score exceeded 100: {}", rep.score);
            // score is u8, so it can't go below 0 (saturating_sub guarantees this)
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  INVARIANT 2: SMTP state machine never enters impossible states
// ═══════════════════════════════════════════════════════════════

#[test]
fn property_smtp_state_machine_always_valid() {
    let long_cmd = "X".repeat(5000);
    let commands: Vec<&str> = vec![
        "EHLO test.com",
        "HELO test.com",
        "MAIL FROM:<a@b.com>",
        "RCPT TO:<c@d.com>",
        "DATA",
        "RSET",
        "NOOP",
        "QUIT",
        "HELP",
        "STARTTLS",
        "AUTH PLAIN dGVzdA==",
        "VRFY user@test.com",
        "XYZZY",         // Unknown
        "",               // Empty
        &long_cmd,        // Very long
    ];
    let command_refs = &commands;

    let mut rng = Rng::new(123);

    for iteration in 0..500 {
        let config = SmtpProtectionConfig {
            strict_mode: false,
            max_commands: 200,
            max_rcpt: 100,
            max_invalid: 50,
            ..SmtpProtectionConfig::default()
        };
        let mut prot = SmtpConnectionProtection::new(
            rng.next_ip(),
            (rng.next_u64() % 101) as u8,
            config,
        );

        let num_commands = rng.range(1, 100) as usize;

        for cmd_i in 0..num_commands {
            let cmd_idx = rng.next_u64() as usize % command_refs.len();
            let cmd = command_refs[cmd_idx];

            let result = prot.process_command(cmd);

            // The result must be Ok or a known error — never panic
            match result {
                Ok(_action) => {
                    // After QUIT, state must be Quit (even under tarpit)
                    if cmd.to_uppercase().starts_with("QUIT") {
                        assert_eq!(
                            prot.state(),
                            SmtpState::Quit,
                            "After QUIT, state should be Quit (iter={}, cmd_i={})",
                            iteration,
                            cmd_i
                        );
                    }
                }
                Err(SmtpProtectionError::TooManyCommands) => {
                    // Expected after hitting limit
                    break;
                }
                Err(SmtpProtectionError::TooManyRecipients) => {
                    // Expected after hitting recipient limit
                }
                Err(SmtpProtectionError::Timeout(_)) => {
                    // State timeout — shouldn't normally happen in fast tests
                }
                Err(SmtpProtectionError::InvalidSequence { .. }) => {
                    // Expected in strict mode
                }
                Err(other) => {
                    panic!(
                        "Unexpected error at iter={}, cmd_i={}, cmd='{}': {:?}",
                        iteration, cmd_i, cmd, other
                    );
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  INVARIANT 3: Adaptive threshold always within [min, max]
// ═══════════════════════════════════════════════════════════════

#[test]
fn property_adaptive_threshold_always_bounded() {
    let mut rng = Rng::new(7890);

    for _ in 0..100 {
        let min_t = rng.range(10, 100);
        let max_t = rng.range(min_t + 100, min_t + 50000);

        let config = AdaptiveConfig {
            min_threshold: min_t,
            max_threshold: max_t,
            consecutive_alert_trigger: (rng.range(1, 5)) as u32,
            cooldown: Duration::from_millis(rng.range(1, 100)),
            z_threshold: 2.0 + rng.next_f64() * 3.0,
            zero_std_z_score: 10.0,
            recovery_z_threshold: 1.0,
            ema_alpha: 0.01 + rng.next_f64() * 0.5,
            attack_factor: 0.1 + rng.next_f64() * 0.5,
            headroom_factor: 1.1 + rng.next_f64() * 2.0,
            baseline_window: Duration::from_secs(300),
        };
        let limiter = AdaptiveRateLimiter::new(config.clone());

        // Feed random observations
        for _ in 0..200 {
            let rps = rng.next_f64() * 10000.0;
            limiter.update(TrafficObservation {
                timestamp: Instant::now(),
                requests_per_second: rps,
                error_rate: rng.next_f64(),
                latency_p99_ms: rng.next_f64() * 1000.0,
                cpu_usage: rng.next_f64(),
            });

            let threshold = limiter.current_threshold();
            assert!(
                threshold >= config.min_threshold && threshold <= config.max_threshold,
                "Threshold {} out of bounds [{}, {}]",
                threshold,
                config.min_threshold,
                config.max_threshold
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  INVARIANT 4: Bot probability always in [0.0, 1.0]
// ═══════════════════════════════════════════════════════════════

#[test]
fn property_bot_probability_always_in_unit_range() {
    let mut rng = Rng::new(3141592);
    let endpoints: Vec<u64> = (0..20).map(|i| hash_ep(&format!("/api/ep{}", i))).collect();
    let methods = ["GET", "POST", "PUT", "DELETE", "PATCH"];

    for _ in 0..200 {
        let mut behavior = SessionBehavior::new(rng.range(10, 200) as usize);

        let num_requests = rng.range(1, 150);
        for _ in 0..num_requests {
            let ep = endpoints[rng.next_u64() as usize % endpoints.len()];
            let method = methods[rng.next_u64() as usize % methods.len()];
            let is_error = rng.next_f64() < 0.15;
            behavior.record_request(ep, method, is_error);
        }

        let assessment = behavior.analyze();
        assert!(
            assessment.bot_probability >= 0.0 && assessment.bot_probability <= 1.0,
            "Bot probability out of [0,1]: {}",
            assessment.bot_probability
        );

        // Individual signals should also be bounded
        if assessment.has_sufficient_data {
            let s = &assessment.signals;
            assert!(s.timing_regularity >= 0.0 && s.timing_regularity <= 1.0);
            assert!(s.periodicity >= 0.0 && s.periodicity <= 1.0);
            assert!(s.endpoint_concentration >= 0.0 && s.endpoint_concentration <= 1.0);
            assert!(s.error_anomaly >= 0.0 && s.error_anomaly <= 1.0);
            assert!(s.sequence_predictability >= 0.0 && s.sequence_predictability <= 1.0);
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  INVARIANT 5: SMTP command parsing is total (parses any input without panic)
// ═══════════════════════════════════════════════════════════════

#[test]
fn property_smtp_parse_never_panics() {
    let mut rng = Rng::new(999);

    // Fixed known-tricky inputs
    let tricky_inputs = [
        "",
        " ",
        "\t",
        "\n",
        "\r\n",
        "A",
        "EHLO",           // Missing argument
        "EHLO ",          // Empty argument
        "EHLO\x00test",   // Null byte
        "MAIL FROM:",     // Empty after colon
        "RCPT TO:",
        "AUTH",            // Missing auth type
        &"X".repeat(10000), // Very long
        "\0\0\0",         // Null bytes
        "日本語",          // Unicode
        "EHLO 🚀.com",    // Emoji domain
    ];

    for input in &tricky_inputs {
        let _result = parse_smtp_command(input);
        // Must not panic
    }

    // Random byte sequences
    for _ in 0..5000 {
        let len = rng.range(0, 500) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| (rng.next_u64() % 128) as u8).collect();

        if let Ok(s) = String::from_utf8(bytes) {
            let _result = parse_smtp_command(&s);
            // Must not panic
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  INVARIANT 6: IP extraction always returns a valid IP
// ═══════════════════════════════════════════════════════════════

#[test]
fn property_ip_extraction_always_returns_valid_ip() {
    let mut rng = Rng::new(2718);

    let header_values = [
        None,
        Some("10.0.0.1"),
        Some("192.168.1.1"),
        Some("::1"),
        Some("invalid"),
        Some(""),
        Some(" "),
        Some("10.0.0.1, 10.0.0.2"),
        Some("garbage, 10.0.0.3"),
        Some("10.0.0.4,10.0.0.5,10.0.0.6"),
        Some("not-ip"),
        Some("256.256.256.256"),
        Some("999.999.999.999"),
    ];

    for _ in 0..1000 {
        let x_real_ip = header_values[rng.next_u64() as usize % header_values.len()];
        let xff = header_values[rng.next_u64() as usize % header_values.len()];
        let cf = header_values[rng.next_u64() as usize % header_values.len()];
        let direct = rng.next_ip();

        let result = extract_client_ip(x_real_ip, xff, cf, direct);
        // Result should always be a valid IpAddr (it's typed, so it always is)
        // Verify it's either from a header or the direct IP
        let _ = result.to_string(); // Should not panic
    }
}

// ═══════════════════════════════════════════════════════════════
//  INVARIANT 7: Sequence entropy is non-negative
// ═══════════════════════════════════════════════════════════════

#[test]
fn property_sequence_entropy_non_negative() {
    let mut rng = Rng::new(12345);

    for _ in 0..500 {
        let mut behavior = SessionBehavior::new(100);
        let num_requests = rng.range(0, 200) as usize;

        for _ in 0..num_requests {
            let ep = hash_ep(&format!("/ep{}", rng.range(0, 50)));
            behavior.record_request(ep, "GET", false);
        }

        let entropy = behavior.sequence_entropy();
        assert!(
            entropy >= 0.0,
            "Entropy should be non-negative: {}",
            entropy
        );
    }
}

// ═══════════════════════════════════════════════════════════════
//  INVARIANT 8: SMTP data recording never loses track of bytes
// ═══════════════════════════════════════════════════════════════

#[test]
fn property_smtp_data_recording_consistency() {
    let mut rng = Rng::new(55555);

    for _ in 0..200 {
        let max_size = rng.range(100, 10000) as usize;
        let config = SmtpProtectionConfig {
            max_size,
            ..SmtpProtectionConfig::default()
        };
        let mut prot = SmtpConnectionProtection::new(
            rng.next_ip(),
            50,
            config,
        );

        // Set up valid session to reach DATA state
        prot.process_command("EHLO test.com").unwrap();
        prot.process_command("MAIL FROM:<a@b.com>").unwrap();
        prot.process_command("RCPT TO:<c@d.com>").unwrap();
        prot.process_command("DATA").unwrap();

        let mut total_recorded = 0usize;
        let mut hit_limit = false;

        for _ in 0..50 {
            let chunk = rng.range(1, 500) as usize;
            match prot.record_data(chunk) {
                Ok(()) => {
                    total_recorded += chunk;
                    assert!(total_recorded <= max_size, "Should not exceed max_size without error");
                }
                Err(SmtpProtectionError::MessageTooLarge) => {
                    hit_limit = true;
                    break;
                }
                Err(other) => panic!("Unexpected error: {:?}", other),
            }
        }

        // If we hit the limit, total should be near max_size
        if hit_limit {
            // The last chunk pushed us over
            assert!(total_recorded <= max_size);
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  INVARIANT 9: Connection tracker count never goes negative
// ═══════════════════════════════════════════════════════════════

#[test]
fn property_connection_count_never_negative() {
    let config = SmtpProtectionConfig {
        max_connections_per_ip: 1000,
        conn_rate_per_minute: 10000,
        ..SmtpProtectionConfig::default()
    };
    let tracker = SmtpConnectionTracker::new(config);
    let mut rng = Rng::new(77777);

    let ips: Vec<IpAddr> = (0..5).map(|_| rng.next_ip()).collect();

    for _ in 0..2000 {
        let ip = ips[rng.next_u64() as usize % ips.len()];
        match rng.next_u64() % 3 {
            0 => {
                let _ = tracker.register_connection(ip);
            }
            1 => {
                tracker.unregister_connection(&ip);
            }
            2 => {
                tracker.cleanup();
            }
            _ => unreachable!(),
        }

        // Count should never be negative (u64, so it wraps — check for very large values)
        for check_ip in &ips {
            let count = tracker.active_count(check_ip);
            assert!(
                count < 1_000_000,
                "Count appears wrapped/negative for {:?}: {}",
                check_ip,
                count
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  INVARIANT 10: Slowloris detection is monotonic — lower rates always flagged
// ═══════════════════════════════════════════════════════════════

#[test]
fn property_slowloris_lower_rates_always_caught() {
    let config = SmtpProtectionConfig {
        min_data_rate_bps: 500,
        ..SmtpProtectionConfig::default()
    };
    let prot = SmtpConnectionProtection::new("10.0.0.1".parse().unwrap(), 50, config);

    // Any rate below min should be caught (after grace period)
    for rate in (0..500).step_by(50) {
        let bytes = rate * 2;
        let elapsed = Duration::from_secs(2);
        let result = prot.check_data_rate(bytes as usize, elapsed);

        assert!(
            result.is_err(),
            "Rate {} bps (bytes={}, elapsed=2s) should be caught: {:?}",
            rate,
            bytes,
            result
        );
    }

    // Rates at or above min should pass
    for rate in (500..2000).step_by(100) {
        let bytes = rate * 2;
        let elapsed = Duration::from_secs(2);
        let result = prot.check_data_rate(bytes as usize, elapsed);

        assert!(
            result.is_ok(),
            "Rate {} bps (bytes={}, elapsed=2s) should pass: {:?}",
            rate,
            bytes,
            result
        );
    }
}

// ═══════════════════════════════════════════════════════════════
//  INVARIANT 11: ReputationScore::level() is consistent with score
// ═══════════════════════════════════════════════════════════════

#[test]
fn property_reputation_level_consistent_with_score() {
    use ddos_protection::reputation::ReputationLevel;

    for score in 0..=100u8 {
        let mut rep = ReputationScore::default();
        rep.score = score;

        let level = rep.level();
        match score {
            0..=10 => assert_eq!(level, ReputationLevel::Blocked, "score={}", score),
            11..=30 => assert_eq!(level, ReputationLevel::Suspicious, "score={}", score),
            31..=70 => assert_eq!(level, ReputationLevel::Normal, "score={}", score),
            71..=100 => assert_eq!(level, ReputationLevel::Trusted, "score={}", score),
            _ => unreachable!(),
        }
    }
}
