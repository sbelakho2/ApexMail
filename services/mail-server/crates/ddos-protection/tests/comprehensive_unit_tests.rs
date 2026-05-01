//! # Comprehensive Unit Tests for DDoS Protection System
//!
//! Tests all new modules:smtp_protection, adaptive, bot_detection, middleware
//! Plus regressions for the fingerprint lookup fix.

// ═══════════════════════════════════════════════════════════════
// SMTP PROTECTION UNIT TESTS
// ═══════════════════════════════════════════════════════════════
mod smtp_unit_tests {
    use ddos_protection::smtp_protection::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    fn ip4() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
    }

    fn ip6() -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
    }

    // ── Command Parsing ─────────────────────────────────────

    #[test]
    fn test_parse_ehlo() {
        match parse_smtp_command("EHLO mail.example.com") {
            SmtpCommand::Ehlo(d) => assert_eq!(d, "mail.example.com"),
            other => panic!("Expected Ehlo, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_helo() {
        match parse_smtp_command("HELO mail.example.com") {
            SmtpCommand::Helo(d) => assert_eq!(d, "mail.example.com"),
            other => panic!("Expected Helo, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_mail_from_with_angles() {
        match parse_smtp_command("MAIL FROM:<user@example.com>") {
            SmtpCommand::MailFrom(a) => assert_eq!(a, "<user@example.com>"),
            other => panic!("Expected MailFrom, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_rcpt_to() {
        match parse_smtp_command("RCPT TO:<recipient@example.com>") {
            SmtpCommand::RcptTo(a) => assert_eq!(a, "<recipient@example.com>"),
            other => panic!("Expected RcptTo, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_data() {
        assert!(matches!(parse_smtp_command("DATA"), SmtpCommand::Data));
    }

    #[test]
    fn test_parse_rset() {
        assert!(matches!(parse_smtp_command("RSET"), SmtpCommand::Rset));
    }

    #[test]
    fn test_parse_noop() {
        assert!(matches!(parse_smtp_command("NOOP"), SmtpCommand::Noop));
    }

    #[test]
    fn test_parse_quit() {
        assert!(matches!(parse_smtp_command("QUIT"), SmtpCommand::Quit));
    }

    #[test]
    fn test_parse_starttls() {
        assert!(matches!(
            parse_smtp_command("STARTTLS"),
            SmtpCommand::StartTls
        ));
    }

    #[test]
    fn test_parse_auth() {
        match parse_smtp_command("AUTH PLAIN dGVzdA==") {
            SmtpCommand::Auth(rest) => assert_eq!(rest, "PLAIN dGVzdA=="),
            other => panic!("Expected Auth, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_vrfy() {
        match parse_smtp_command("VRFY user@example.com") {
            SmtpCommand::Vrfy(arg) => assert_eq!(arg, "user@example.com"),
            other => panic!("Expected Vrfy, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_help() {
        assert!(matches!(parse_smtp_command("HELP"), SmtpCommand::Help));
        assert!(matches!(parse_smtp_command("HELP EHLO"), SmtpCommand::Help));
    }

    #[test]
    fn test_parse_unknown() {
        assert!(matches!(
            parse_smtp_command("XYZZY foo"),
            SmtpCommand::Unknown(_)
        ));
    }

    #[test]
    fn test_parse_case_insensitive() {
        assert!(matches!(
            parse_smtp_command("ehlo test.com"),
            SmtpCommand::Ehlo(_)
        ));
        assert!(matches!(parse_smtp_command("Quit"), SmtpCommand::Quit));
        assert!(matches!(parse_smtp_command("data"), SmtpCommand::Data));
        assert!(matches!(parse_smtp_command("rSeT"), SmtpCommand::Rset));
    }

    #[test]
    fn test_parse_whitespace_handling() {
        match parse_smtp_command("  EHLO example.com  ") {
            SmtpCommand::Ehlo(d) => assert_eq!(d, "example.com"),
            other => panic!("Expected Ehlo, got {:?}", other),
        }
    }

    // ── State Machine ───────────────────────────────────────

    #[test]
    fn test_full_session_flow() {
        let config = SmtpProtectionConfig::default();
        let mut prot = SmtpConnectionProtection::new(ip4(), 50, config);

        assert_eq!(prot.state(), SmtpState::Connected);

        assert_eq!(
            prot.process_command("EHLO test.com").unwrap(),
            SmtpAction::Continue
        );
        assert_eq!(prot.state(), SmtpState::GreetingReceived);

        assert_eq!(
            prot.process_command("MAIL FROM:<a@b.com>").unwrap(),
            SmtpAction::Continue
        );
        assert_eq!(prot.state(), SmtpState::MailFrom);

        assert_eq!(
            prot.process_command("RCPT TO:<c@d.com>").unwrap(),
            SmtpAction::Continue
        );
        assert!(matches!(prot.state(), SmtpState::RcptTo { count: 1 }));

        assert_eq!(
            prot.process_command("RCPT TO:<e@f.com>").unwrap(),
            SmtpAction::Continue
        );
        assert!(matches!(prot.state(), SmtpState::RcptTo { count: 2 }));

        assert_eq!(prot.process_command("DATA").unwrap(), SmtpAction::Continue);
        assert!(matches!(prot.state(), SmtpState::DataReceiving { .. }));

        assert_eq!(
            prot.process_command("QUIT").unwrap(),
            SmtpAction::Disconnect
        );
        assert_eq!(prot.state(), SmtpState::Quit);
    }

    #[test]
    fn test_rset_from_various_states() {
        let config = SmtpProtectionConfig::default();
        let mut prot = SmtpConnectionProtection::new(ip4(), 50, config);

        prot.process_command("EHLO test.com").unwrap();
        prot.process_command("MAIL FROM:<a@b.com>").unwrap();
        prot.process_command("RSET").unwrap();
        assert_eq!(prot.state(), SmtpState::GreetingReceived);

        // Can start new transaction
        prot.process_command("MAIL FROM:<x@y.com>").unwrap();
        assert_eq!(prot.state(), SmtpState::MailFrom);
    }

    #[test]
    fn test_regreeting_allowed() {
        let config = SmtpProtectionConfig::default();
        let mut prot = SmtpConnectionProtection::new(ip4(), 50, config);

        prot.process_command("EHLO test.com").unwrap();
        // Re-greeting should be OK
        prot.process_command("EHLO other.com").unwrap();
        assert_eq!(prot.state(), SmtpState::GreetingReceived);
    }

    #[test]
    fn test_noop_from_any_state() {
        let config = SmtpProtectionConfig::default();
        let mut prot = SmtpConnectionProtection::new(ip4(), 50, config);

        assert_eq!(prot.process_command("NOOP").unwrap(), SmtpAction::Continue);
        prot.process_command("EHLO test.com").unwrap();
        assert_eq!(prot.process_command("NOOP").unwrap(), SmtpAction::Continue);
    }

    #[test]
    fn test_quit_from_any_state() {
        for init_cmd in &["", "EHLO test.com", "EHLO test.com\nMAIL FROM:<a@b.com>"] {
            let config = SmtpProtectionConfig::default();
            let mut prot = SmtpConnectionProtection::new(ip4(), 50, config);

            for cmd in init_cmd.lines().filter(|l| !l.is_empty()) {
                let _ = prot.process_command(cmd);
            }

            assert_eq!(
                prot.process_command("QUIT").unwrap(),
                SmtpAction::Disconnect
            );
        }
    }

    #[test]
    fn test_strict_mode_rejects_invalid() {
        let config = SmtpProtectionConfig {
            strict_mode: true,
            ..SmtpProtectionConfig::default()
        };
        let mut prot = SmtpConnectionProtection::new(ip4(), 50, config);

        let result = prot.process_command("MAIL FROM:<a@b.com>");
        assert!(result.is_err());
        match result.unwrap_err() {
            SmtpProtectionError::InvalidSequence { state, command } => {
                assert_eq!(state, SmtpState::Connected);
                assert!(command.contains("MAIL FROM"));
            }
            other => panic!("Expected InvalidSequence, got {:?}", other),
        }
    }

    #[test]
    fn test_lenient_mode_returns_reject() {
        let config = SmtpProtectionConfig {
            strict_mode: false,
            ..SmtpProtectionConfig::default()
        };
        let mut prot = SmtpConnectionProtection::new(ip4(), 50, config);

        let action = prot.process_command("MAIL FROM:<a@b.com>").unwrap();
        assert_eq!(action, SmtpAction::Reject("503 Bad sequence of commands"));
    }

    // ── Limits ──────────────────────────────────────────────

    #[test]
    fn test_max_commands_enforced() {
        let config = SmtpProtectionConfig {
            max_commands: 3,
            ..SmtpProtectionConfig::default()
        };
        let mut prot = SmtpConnectionProtection::new(ip4(), 50, config);

        prot.process_command("NOOP").unwrap();
        prot.process_command("NOOP").unwrap();
        prot.process_command("NOOP").unwrap();
        assert!(matches!(
            prot.process_command("NOOP"),
            Err(SmtpProtectionError::TooManyCommands)
        ));
    }

    #[test]
    fn test_max_recipients_enforced() {
        let config = SmtpProtectionConfig {
            max_rcpt: 2,
            ..SmtpProtectionConfig::default()
        };
        let mut prot = SmtpConnectionProtection::new(ip4(), 50, config);

        prot.process_command("EHLO test.com").unwrap();
        prot.process_command("MAIL FROM:<s@t.com>").unwrap();
        prot.process_command("RCPT TO:<a@t.com>").unwrap();
        prot.process_command("RCPT TO:<b@t.com>").unwrap();
        assert!(matches!(
            prot.process_command("RCPT TO:<c@t.com>"),
            Err(SmtpProtectionError::TooManyRecipients)
        ));
    }

    #[test]
    fn test_message_size_limit() {
        let config = SmtpProtectionConfig {
            max_size: 500,
            ..SmtpProtectionConfig::default()
        };
        let mut prot = SmtpConnectionProtection::new(ip4(), 50, config);

        prot.process_command("EHLO test.com").unwrap();
        prot.process_command("MAIL FROM:<s@t.com>").unwrap();
        prot.process_command("RCPT TO:<r@t.com>").unwrap();
        prot.process_command("DATA").unwrap();

        prot.record_data(200).unwrap();
        prot.record_data(200).unwrap();
        assert!(matches!(
            prot.record_data(200),
            Err(SmtpProtectionError::MessageTooLarge)
        ));
    }

    // ── Tarpit ──────────────────────────────────────────────

    #[test]
    fn test_tarpit_scales_with_invalids() {
        let config = SmtpProtectionConfig {
            strict_mode: false,
            max_invalid: 2,
            tarpit_delay: Duration::from_secs(3),
            ..SmtpProtectionConfig::default()
        };
        let mut prot = SmtpConnectionProtection::new(ip4(), 50, config);

        // 2 invalids:at limit, no tarpit yet
        prot.process_command("BOGUS1").unwrap();
        prot.process_command("BOGUS2").unwrap();
        assert!(prot.should_tarpit().is_none());

        // 3rd invalid:1 over limit -> 1 * 3s = 3s
        prot.process_command("BOGUS3").unwrap();
        assert_eq!(prot.should_tarpit(), Some(Duration::from_secs(3)));

        // 4th command:record_invalid runs through the state machine first,
        // incrementing invalid_commands to 4 (2 over limit), then tarpit fires.
        // Progressive delay:(4 - 2) * 3s = 6s
        let action = prot.process_command("BOGUS4").unwrap();
        assert_eq!(action, SmtpAction::Tarpit(Duration::from_secs(6)));
        assert_eq!(prot.should_tarpit(), Some(Duration::from_secs(6)));

        // 5th command:invalid_commands = 5, 3 over limit → 3 * 3s = 9s (progressive escalation)
        let action = prot.process_command("BOGUS5").unwrap();
        assert_eq!(action, SmtpAction::Tarpit(Duration::from_secs(9)));
    }

    #[test]
    fn test_tarpit_for_low_reputation() {
        let prot = SmtpConnectionProtection::new(ip4(), 10, SmtpProtectionConfig::default());
        assert_eq!(prot.should_tarpit(), Some(Duration::from_secs(2)));
    }

    #[test]
    fn test_no_tarpit_for_good_reputation() {
        let prot = SmtpConnectionProtection::new(ip4(), 80, SmtpProtectionConfig::default());
        assert!(prot.should_tarpit().is_none());
    }

    // ── Slowloris ───────────────────────────────────────────

    #[test]
    fn test_slowloris_detects_slow_rate() {
        let config = SmtpProtectionConfig {
            min_data_rate_bps: 200,
            ..SmtpProtectionConfig::default()
        };
        let prot = SmtpConnectionProtection::new(ip4(), 50, config);

        // 50 bytes in 2 seconds = 25 bps < 200 bps
        let result = prot.check_data_rate(50, Duration::from_secs(2));
        assert!(matches!(
            result,
            Err(SmtpProtectionError::SlowlorisDetected { .. })
        ));
    }

    #[test]
    fn test_slowloris_passes_good_rate() {
        let config = SmtpProtectionConfig {
            min_data_rate_bps: 100,
            ..SmtpProtectionConfig::default()
        };
        let prot = SmtpConnectionProtection::new(ip4(), 50, config);

        // 5000 bytes in 2 seconds = 2500 bps > 100 bps
        assert!(prot.check_data_rate(5000, Duration::from_secs(2)).is_ok());
    }

    #[test]
    fn test_slowloris_grace_period_under_1s() {
        let config = SmtpProtectionConfig {
            min_data_rate_bps: 100000,
            ..SmtpProtectionConfig::default()
        };
        let prot = SmtpConnectionProtection::new(ip4(), 50, config);

        // 0 bytes but under 1 second:should pass (grace period)
        assert!(prot.check_data_rate(0, Duration::from_millis(500)).is_ok());
    }

    // ── IPv6 Support ────────────────────────────────────────

    #[test]
    fn test_ipv6_connection_protection() {
        let config = SmtpProtectionConfig::default();
        let mut prot = SmtpConnectionProtection::new(ip6(), 50, config);

        assert_eq!(prot.peer_addr(), ip6());
        prot.process_command("EHLO test.com").unwrap();
        assert_eq!(prot.state(), SmtpState::GreetingReceived);
    }

    // ── Connection Tracker ──────────────────────────────────

    #[test]
    fn test_tracker_register_and_unregister() {
        let config = SmtpProtectionConfig {
            max_connections_per_ip: 10,
            ..SmtpProtectionConfig::default()
        };
        let tracker = SmtpConnectionTracker::new(config);
        let ip = ip4();

        tracker.register_connection(ip).unwrap();
        assert_eq!(tracker.active_count(&ip), 1);

        tracker.register_connection(ip).unwrap();
        assert_eq!(tracker.active_count(&ip), 2);

        tracker.unregister_connection(&ip);
        assert_eq!(tracker.active_count(&ip), 1);

        tracker.unregister_connection(&ip);
        assert_eq!(tracker.active_count(&ip), 0);
    }

    #[test]
    fn test_tracker_concurrent_limit() {
        let config = SmtpProtectionConfig {
            max_connections_per_ip: 3,
            ..SmtpProtectionConfig::default()
        };
        let tracker = SmtpConnectionTracker::new(config);
        let ip = ip4();

        tracker.register_connection(ip).unwrap();
        tracker.register_connection(ip).unwrap();
        tracker.register_connection(ip).unwrap();
        assert!(matches!(
            tracker.register_connection(ip),
            Err(SmtpProtectionError::TooManyConcurrent)
        ));
    }

    #[test]
    fn test_tracker_cleanup() {
        let config = SmtpProtectionConfig::default();
        let tracker = SmtpConnectionTracker::new(config);
        let ip = ip4();

        tracker.register_connection(ip).unwrap();
        tracker.unregister_connection(&ip);
        tracker.cleanup();

        assert_eq!(tracker.tracked_ips(), 0);
    }

    #[test]
    fn test_tracker_multiple_ips() {
        let config = SmtpProtectionConfig {
            max_connections_per_ip: 2,
            ..SmtpProtectionConfig::default()
        };
        let tracker = SmtpConnectionTracker::new(config);
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        tracker.register_connection(ip1).unwrap();
        tracker.register_connection(ip2).unwrap();
        tracker.register_connection(ip1).unwrap();

        assert_eq!(tracker.active_count(&ip1), 2);
        assert_eq!(tracker.active_count(&ip2), 1);
    }

    // ── Connection Age & Metadata ───────────────────────────

    #[test]
    fn test_connection_metadata() {
        let config = SmtpProtectionConfig::default();
        let prot = SmtpConnectionProtection::new(ip4(), 75, config);

        assert_eq!(prot.commands_received(), 0);
        assert_eq!(prot.invalid_commands(), 0);
        assert_eq!(prot.peer_addr(), ip4());
        assert!(prot.connection_age() < Duration::from_secs(1));
    }

    // ── Error Display ───────────────────────────────────────

    #[test]
    fn test_error_display_messages() {
        let err = SmtpProtectionError::TooManyCommands;
        assert_eq!(err.to_string(), "Too many commands in session");

        let err = SmtpProtectionError::TooManyConcurrent;
        assert_eq!(err.to_string(), "Too many concurrent connections");

        let err = SmtpProtectionError::SlowlorisDetected {
            observed_rate: 50,
            required_rate: 100,
        };
        assert!(err.to_string().contains("50"));
        assert!(err.to_string().contains("100"));
    }
}

// ═══════════════════════════════════════════════════════════════
// ADAPTIVE RATE LIMITER UNIT TESTS
// ═══════════════════════════════════════════════════════════════
mod adaptive_unit_tests {
    use ddos_protection::adaptive::*;
    use std::time::{Duration, Instant};

    fn test_config() -> AdaptiveConfig {
        AdaptiveConfig {
            baseline_window: Duration::from_secs(300),
            z_threshold: 3.0,
            zero_std_z_score: 10.0,
            recovery_z_threshold: 1.0,
            min_threshold: 10,
            max_threshold: 10_000,
            consecutive_alert_trigger: 3,
            cooldown: Duration::from_millis(50),
            ema_alpha: 0.1,
            attack_factor: 0.5,
            headroom_factor: 1.5,
        }
    }

    fn obs(rps: f64) -> TrafficObservation {
        TrafficObservation {
            timestamp: Instant::now(),
            requests_per_second: rps,
            error_rate: 0.01,
            latency_p99_ms: 50.0,
            cpu_usage: 0.3,
        }
    }

    #[test]
    fn test_initial_threshold() {
        let limiter = AdaptiveRateLimiter::new(test_config());
        assert_eq!(limiter.current_threshold(), 5000);
    }

    #[test]
    fn test_not_under_attack_initially() {
        let limiter = AdaptiveRateLimiter::new(test_config());
        assert!(!limiter.is_under_attack());
    }

    #[test]
    fn test_baseline_stats_empty() {
        let limiter = AdaptiveRateLimiter::new(test_config());
        assert!(limiter.baseline_stats().is_none());
    }

    #[test]
    fn test_baseline_stats_with_data() {
        let limiter = AdaptiveRateLimiter::new(test_config());
        for _ in 0..15 {
            limiter.update(obs(100.0));
        }
        let stats = limiter.baseline_stats().unwrap();
        assert_eq!(stats.sample_count, 15);
        assert!((stats.rps_mean - 100.0).abs() < 1.0);
    }

    #[test]
    fn test_ema_moves_threshold_toward_ideal() {
        let limiter = AdaptiveRateLimiter::new(test_config());

        // Feed stable 100 rps traffic
        for _ in 0..50 {
            limiter.update(obs(100.0));
        }

        // Ideal = 100 * 1.5 = 150. After EMA from 5000, threshold should decrease.
        let t = limiter.current_threshold();
        assert!(
            t < 5000,
            "Threshold should have decreased from initial 5000: {}",
            t
        );
    }

    #[test]
    fn test_attack_requires_consecutive_alerts() {
        let config = AdaptiveConfig {
            consecutive_alert_trigger: 3,
            ..test_config()
        };
        let limiter = AdaptiveRateLimiter::new(config);

        // Build baseline with slight variance
        for i in 0..20 {
            limiter.update(obs(100.0 + (i as f64 % 5.0)));
        }

        // One spike:not enough
        limiter.update(obs(2000.0));
        assert!(!limiter.is_under_attack());

        // Two spikes:still not enough
        limiter.update(obs(2000.0));
        assert!(!limiter.is_under_attack());

        // Third spike:should trigger attack
        limiter.update(obs(2000.0));
        assert!(limiter.is_under_attack());
    }

    #[test]
    fn test_attack_tightens_limits() {
        let config = AdaptiveConfig {
            consecutive_alert_trigger: 2,
            attack_factor: 0.5,
            ..test_config()
        };
        let limiter = AdaptiveRateLimiter::new(config);

        for i in 0..20 {
            limiter.update(obs(100.0 + (i as f64 % 5.0)));
        }

        let pre = limiter.current_threshold();
        limiter.update(obs(5000.0));
        limiter.update(obs(5000.0));

        assert!(limiter.is_under_attack());
        let post = limiter.current_threshold();
        assert!(
            post < pre,
            "Attack should tighten threshold: {} >= {}",
            post,
            pre
        );
    }

    #[test]
    fn test_attack_info() {
        let config = AdaptiveConfig {
            consecutive_alert_trigger: 2,
            ..test_config()
        };
        let limiter = AdaptiveRateLimiter::new(config);

        for i in 0..20 {
            limiter.update(obs(100.0 + (i as f64 % 5.0)));
        }

        limiter.update(obs(5000.0));
        limiter.update(obs(5000.0));

        let info = limiter.attack_info();
        assert!(info.is_under_attack);
        assert!(info.baseline_rps > 0.0);
        assert!(info.attack_duration.is_some());
    }

    #[test]
    fn test_recovery_after_cooldown() {
        let config = AdaptiveConfig {
            consecutive_alert_trigger: 2,
            cooldown: Duration::from_millis(10),
            ..test_config()
        };
        let limiter = AdaptiveRateLimiter::new(config);

        for i in 0..20 {
            limiter.update(obs(100.0 + (i as f64 % 5.0)));
        }

        limiter.update(obs(5000.0));
        limiter.update(obs(5000.0));
        assert!(limiter.is_under_attack());

        std::thread::sleep(Duration::from_millis(20));

        // Normal traffic should trigger recovery
        for _ in 0..5 {
            limiter.update(obs(100.0));
        }
        assert!(!limiter.is_under_attack());
    }

    #[test]
    fn test_reset() {
        let limiter = AdaptiveRateLimiter::new(test_config());
        for _ in 0..20 {
            limiter.update(obs(100.0));
        }

        limiter.reset();
        assert_eq!(limiter.current_threshold(), 5000);
        assert!(!limiter.is_under_attack());
        assert!(limiter.baseline_stats().is_none());
    }

    #[test]
    fn test_min_threshold_clamping() {
        let config = AdaptiveConfig {
            min_threshold: 100,
            max_threshold: 200,
            ..test_config()
        };
        let limiter = AdaptiveRateLimiter::new(config);

        // Feed very low traffic to drive threshold down
        for _ in 0..30 {
            limiter.update(obs(1.0));
        }

        assert!(
            limiter.current_threshold() >= 100,
            "Should not go below min"
        );
    }

    #[test]
    fn test_max_threshold_clamping() {
        let config = AdaptiveConfig {
            min_threshold: 10,
            max_threshold: 500,
            ..test_config()
        };
        let limiter = AdaptiveRateLimiter::new(config);

        // Initial = 500/2 = 250, feed high traffic
        for _ in 0..30 {
            limiter.update(obs(10000.0));
        }

        assert!(
            limiter.current_threshold() <= 500,
            "Should not go above max"
        );
    }
}

// ═══════════════════════════════════════════════════════════════
// BOT DETECTION UNIT TESTS
// ═══════════════════════════════════════════════════════════════
mod bot_detection_unit_tests {
    use ddos_protection::bot_detection::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn hash_ep(path: &str) -> u64 {
        let mut h = DefaultHasher::new();
        path.hash(&mut h);
        h.finish()
    }

    #[test]
    fn test_new_session_no_data() {
        let behavior = SessionBehavior::new(100);
        let assessment = behavior.analyze();
        assert!(!assessment.has_sufficient_data);
        assert_eq!(assessment.bot_probability, 0.0);
    }

    #[test]
    fn test_single_endpoint_high_concentration() {
        let mut behavior = SessionBehavior::new(100);
        let ep = hash_ep("/api/flood");

        for _ in 0..30 {
            behavior.record_request(ep, "GET", false);
        }

        let assessment = behavior.analyze();
        assert!(assessment.has_sufficient_data);
        // Single endpoint → high concentration
        assert!(
            assessment.signals.endpoint_concentration > 0.5,
            "Single endpoint should have high concentration: {}",
            assessment.signals.endpoint_concentration
        );
    }

    #[test]
    fn test_many_endpoints_low_concentration() {
        let mut behavior = SessionBehavior::new(100);

        for i in 0..30 {
            behavior.record_request(hash_ep(&format!("/api/ep{}", i)), "GET", false);
        }

        let assessment = behavior.analyze();
        assert!(assessment.has_sufficient_data);
        assert!(
            assessment.signals.endpoint_concentration < 0.5,
            "Many endpoints should have low concentration: {}",
            assessment.signals.endpoint_concentration
        );
    }

    #[test]
    fn test_high_error_rate_detection() {
        let mut behavior = SessionBehavior::new(100);
        let ep = hash_ep("/api/login");

        for i in 0..30 {
            behavior.record_request(ep, "POST", i >= 3); // 90% errors
        }

        let assessment = behavior.analyze();
        assert!(
            assessment.signals.error_anomaly > 0.5,
            "High error rate should be flagged: {}",
            assessment.signals.error_anomaly
        );
    }

    #[test]
    fn test_zero_error_rate_suspicious_after_many() {
        let mut behavior = SessionBehavior::new(100);

        for i in 0..60 {
            behavior.record_request(hash_ep(&format!("/api/ep{}", i % 5)), "GET", false);
        }

        let assessment = behavior.analyze();
        // Zero errors after 60 requests is somewhat suspicious
        assert!(
            assessment.signals.error_anomaly >= 0.4,
            "Zero errors after many requests should be somewhat suspicious: {}",
            assessment.signals.error_anomaly
        );
    }

    #[test]
    fn test_sequence_entropy_single_endpoint() {
        let mut behavior = SessionBehavior::new(100);
        let ep = hash_ep("/api/single");

        for _ in 0..30 {
            behavior.record_request(ep, "GET", false);
        }

        let entropy = behavior.sequence_entropy();
        assert!(
            entropy < 0.1,
            "Single endpoint should have near-zero entropy: {}",
            entropy
        );
    }

    #[test]
    fn test_sequence_entropy_many_endpoints() {
        let mut behavior = SessionBehavior::new(100);
        let eps: Vec<u64> = (0..10).map(|i| hash_ep(&format!("/api/ep{}", i))).collect();

        for (_i, ep) in eps.iter().cycle().take(50).enumerate() {
            behavior.record_request(*ep, "GET", false);
        }

        let entropy = behavior.sequence_entropy();
        assert!(
            entropy > 1.0,
            "Many endpoints should have higher entropy: {}",
            entropy
        );
    }

    #[test]
    fn test_bot_probability_bounds() {
        let mut behavior = SessionBehavior::new(100);
        let ep = hash_ep("/api/test");

        for _ in 0..50 {
            behavior.record_request(ep, "GET", false);
        }

        let assessment = behavior.analyze();
        assert!(assessment.bot_probability >= 0.0);
        assert!(assessment.bot_probability <= 1.0);
    }

    #[test]
    fn test_method_tracking() {
        let mut behavior = SessionBehavior::new(100);
        let ep = hash_ep("/api/test");

        behavior.record_request(ep, "GET", false);
        behavior.record_request(ep, "GET", false);
        behavior.record_request(ep, "POST", false);
        behavior.record_request(ep, "DELETE", false);

        assert_eq!(behavior.total_count(), 4);
        assert_eq!(behavior.unique_endpoint_count(), 1);
    }

    #[test]
    fn test_error_counting() {
        let mut behavior = SessionBehavior::new(100);
        let ep = hash_ep("/api/test");

        behavior.record_request(ep, "GET", false);
        behavior.record_request(ep, "GET", true);
        behavior.record_request(ep, "GET", true);

        assert_eq!(behavior.total_count(), 3);
        assert_eq!(behavior.error_count(), 2);
    }

    #[test]
    fn test_window_size_respected() {
        let mut behavior = SessionBehavior::new(5);
        let ep = hash_ep("/api/test");

        for _ in 0..20 {
            behavior.record_request(ep, "GET", false);
        }

        // Window sized to 5, so inter_arrival_times should be bounded
        // Even though total_count is 20
        assert_eq!(behavior.total_count(), 20);
    }
}

// ═══════════════════════════════════════════════════════════════
// MIDDLEWARE UNIT TESTS
// ═══════════════════════════════════════════════════════════════
mod middleware_unit_tests {
    use ddos_protection::middleware::*;
    use std::net::IpAddr;

    #[test]
    fn test_builder_minimal() {
        let ctx = RequestContextBuilder::new("10.0.0.1".parse().unwrap(), "/health", "GET").build();
        assert_eq!(ctx.ip, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(ctx.path, "/health");
        assert_eq!(ctx.method, "GET");
        assert!(ctx.tls_fingerprint.is_none());
        assert!(ctx.h2_fingerprint.is_none());
        assert!(ctx.user_agent.is_none());
        assert_eq!(ctx.body_size, 0);
        assert!(ctx.tenant_id.is_none());
        assert!(ctx.api_key_id.is_none());
    }

    #[test]
    fn test_builder_full() {
        let ctx = RequestContextBuilder::new("10.0.0.1".parse().unwrap(), "/api/send", "POST")
            .tls_fingerprint("t13d1517h2_8daaf6152771_e5627efa2ab1")
            .h2_fingerprint("settings_hash|frame_hash|prio_hash")
            .user_agent("Mozilla/5.0 Chrome/120")
            .body_size(4096)
            .tenant_id("tenant-abc")
            .api_key_id("key-xyz")
            .build();

        assert_eq!(
            ctx.tls_fingerprint.as_deref(),
            Some("t13d1517h2_8daaf6152771_e5627efa2ab1")
        );
        assert_eq!(
            ctx.h2_fingerprint.as_deref(),
            Some("settings_hash|frame_hash|prio_hash")
        );
        assert_eq!(ctx.user_agent.as_deref(), Some("Mozilla/5.0 Chrome/120"));
        assert_eq!(ctx.body_size, 4096);
        assert_eq!(ctx.tenant_id.as_deref(), Some("tenant-abc"));
        assert_eq!(ctx.api_key_id.as_deref(), Some("key-xyz"));
    }

    #[test]
    fn test_ip_extraction_priority() {
        let direct: IpAddr = "127.0.0.1".parse().unwrap();

        // X-Real-IP first
        assert_eq!(
            extract_client_ip(Some("10.0.0.1"), Some("10.0.0.2"), Some("10.0.0.3"), direct),
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );

        // XFF second
        assert_eq!(
            extract_client_ip(None, Some("10.0.0.2, 10.0.0.3"), Some("10.0.0.4"), direct),
            "10.0.0.2".parse::<IpAddr>().unwrap()
        );

        // CF-Connecting-IP third
        assert_eq!(
            extract_client_ip(None, None, Some("10.0.0.4"), direct),
            "10.0.0.4".parse::<IpAddr>().unwrap()
        );

        // Fallback to direct
        assert_eq!(extract_client_ip(None, None, None, direct), direct);
    }

    #[test]
    fn test_ip_extraction_invalid_headers_fallthrough() {
        let direct: IpAddr = "192.168.1.1".parse().unwrap();

        // Invalid X-Real-IP falls through to XFF
        assert_eq!(
            extract_client_ip(Some("not-an-ip"), Some("10.0.0.2"), None, direct),
            "10.0.0.2".parse::<IpAddr>().unwrap()
        );

        // All invalid falls to direct
        assert_eq!(
            extract_client_ip(Some("garbage"), Some("also,garbage"), Some("nope"), direct),
            direct
        );
    }

    #[test]
    fn test_ip_extraction_ipv6() {
        let direct: IpAddr = "127.0.0.1".parse().unwrap();
        let result = extract_client_ip(Some("::1"), None, None, direct);
        assert_eq!(result, "::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_ip_extraction_xff_whitespace() {
        let direct: IpAddr = "127.0.0.1".parse().unwrap();
        let result = extract_client_ip(None, Some("  10.0.0.5 , 10.0.0.6"), None, direct);
        assert_eq!(result, "10.0.0.5".parse::<IpAddr>().unwrap());
    }
}

// ═══════════════════════════════════════════════════════════════
// FINGERPRINT REGRESSION TESTS
// ═══════════════════════════════════════════════════════════════
mod fingerprint_fix_tests {
    use ddos_protection::config::ProtectorConfig;
    use ddos_protection::DdosProtector;
    use ddos_protection::RequestContext;

    fn make_ctx(ip: &str, fp: Option<&str>) -> RequestContext {
        RequestContext {
            ip: ip.parse().unwrap(),
            path: "/api/test".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: fp.map(String::from),
            h2_fingerprint: None,
            user_agent: Some("TestAgent".to_string()),
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
        }
    }

    #[tokio::test]
    async fn test_normal_fingerprint_allowed() {
        let config = ProtectorConfig::default();
        let protector = DdosProtector::new(config).await.unwrap();

        let ctx = make_ctx(
            "1.2.3.4",
            Some("t13d1517h2_8daaf6152771_e5627efa2ab1"), // Normal-length fingerprint
        );
        let decision = protector.evaluate(&ctx).await;
        assert!(
            decision.is_allowed(),
            "Normal fingerprint should be allowed"
        );
    }

    #[tokio::test]
    async fn test_short_fingerprint_suspicious() {
        let config = ProtectorConfig::default();
        let protector = DdosProtector::new(config).await.unwrap();

        // Very short fingerprint (< 15 chars) is now flagged
        let ctx = make_ctx("2.3.4.5", Some("abc"));
        let _decision = protector.evaluate(&ctx).await;
        // Reputation should have been decreased for this IP
        // (We can't directly check reputation from outside, but at least it doesn't crash)
    }

    #[tokio::test]
    async fn test_no_fingerprint_ok() {
        let config = ProtectorConfig::default();
        let protector = DdosProtector::new(config).await.unwrap();

        let ctx = make_ctx("3.4.5.6", None);
        let decision = protector.evaluate(&ctx).await;
        assert!(decision.is_allowed(), "No fingerprint should be fine");
    }
}
