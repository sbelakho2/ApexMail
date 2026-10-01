//! # Wiring Verification Tests
//!
//! These tests verify that security and infrastructure components are correctly
//! wired together and actually perform their intended functions end-to-end.
//!
//! Unlike unit tests that test components in isolation, these tests verify://! 1. Components are registered in the dependency injection / middleware stack
//! 2. Components receive actual requests, not mocked inputs
//! 3. Component outputs flow through to the response
//! 4. Error handling propagates correctly through the stack

// ===========================================================================
// RATE LIMITER WIRING TESTS (audit SM12 F8 rewrite)
// ===========================================================================

/// Verify the REAL `apexmail-rate-limiter` primitives: the previous version
/// of this module incremented a local `u64` and a local `HashMap` — it never
/// touched the crate its header claimed to test. Every test below drives the
/// production types (`SlidingWindowCounter`, `KeyedRateLimiter`,
/// `GovernorLimiter`).
#[cfg(test)]
mod rate_limiter_wiring {
    use apexmail_rate_limiter::{
        GovernorLimiter, KeyedRateLimiter, RateLimitConfig, SlidingWindowCounter,
    };
    use std::time::Duration;

    #[test]
    fn sliding_window_counter_increments_and_blocks() {
        // The production SlidingWindowCounter must count EVERY admitted
        // request, deny past the threshold, and report the real count.
        let counter = SlidingWindowCounter::from_params(Duration::from_secs(60), 10);

        for i in 0..10 {
            let decision = counter.check_and_increment();
            assert!(
                decision.is_allowed(),
                "request {} within the limit must pass",
                i + 1
            );
        }
        assert_eq!(
            counter.current_count(),
            10,
            "the counter must track all admitted requests"
        );

        let eleventh = counter.check_and_increment();
        assert!(
            eleventh.is_denied(),
            "the 11th request must be denied — an always-allow limiter is not wired"
        );
        // A denied request must not consume budget.
        assert_eq!(counter.current_count(), 10, "denials must not count");
    }

    #[test]
    fn sliding_window_counter_rolls_windows() {
        let window = Duration::from_millis(60);
        let counter = SlidingWindowCounter::from_params(window, 2);

        assert!(counter.check_and_increment().is_allowed());
        assert!(counter.check_and_increment().is_allowed());
        assert!(counter.check_and_increment().is_denied());

        // Idle past two full windows: the budget must fully reset.
        std::thread::sleep(window * 2 + Duration::from_millis(25));
        assert!(
            counter.check_and_increment().is_allowed(),
            "window rollover must re-admit after events age out"
        );
    }

    #[test]
    fn keyed_rate_limiter_separates_tenants() {
        // Per-tenant isolation on the REAL KeyedRateLimiter: tenant A
        // exhausting its own bucket must leave tenant B untouched. The old
        // local-HashMap version could never catch a shared-bucket regression.
        let limiter = KeyedRateLimiter::from_params(/* rps */ 10, /* burst */ 3, /* max_keys */ 100);

        for _ in 0..3 {
            assert!(
                limiter.check("tenant_a").is_allowed(),
                "tenant_a within burst must pass"
            );
        }
        assert!(
            limiter.check("tenant_a").is_denied(),
            "tenant_a must be denied once its own bucket is drained"
        );

        assert!(
            limiter.check("tenant_b").is_allowed(),
            "tenant_b must keep its own isolated budget"
        );
        assert!(
            limiter.check("tenant_c").is_allowed(),
            "an unseen tenant starts with a fresh budget"
        );

        assert_eq!(
            limiter.key_count(),
            3,
            "each tenant must own exactly one limiter key"
        );
        assert!(
            limiter.total_denied() >= 1,
            "the aggregate denial counter must observe the denial"
        );
        // Removing a tenant's key resets it to a fresh budget.
        limiter.remove("tenant_a");
        assert!(
            limiter.check("tenant_a").is_allowed(),
            "a removed key must re-provision a fresh bucket"
        );
    }

    #[test]
    fn governor_limiter_enforces_burst_then_refills() {
        // The token-bucket primitive: `burst` immediate admissions, denial
        // beyond it, and (configured rps) refill over time.
        let config = RateLimitConfig::new(100).with_burst(4);
        let limiter = GovernorLimiter::new(&config);
        assert_eq!(
            limiter.burst_size(),
            4,
            "burst_size must echo the production config"
        );

        for _ in 0..4 {
            assert!(limiter.check().is_allowed(), "burst tokens must pass");
        }
        assert!(
            limiter.check().is_denied(),
            "past the burst the governor must deny"
        );

        // ~1s at rps=100 refills ~100 tokens, far more than the 4 drained:
        // the bucket must be replenished (a stub that never refills fails).
        std::thread::sleep(Duration::from_millis(1100));
        assert!(
            limiter.check().is_allowed(),
            "the token bucket must refill at the configured rate"
        );
    }

    #[test]
    fn rate_limit_config_builder_holds_its_parameters() {
        let config = RateLimitConfig::new(25).with_burst(7);
        assert_eq!(config.requests_per_second.get(), 25);
        assert_eq!(config.effective_burst().get(), 7);
        // burst below rps is clamped up to a usable bucket, never to zero.
        let tiny = RateLimitConfig::new(5).with_burst(0);
        assert!(
            tiny.effective_burst().get() >= 1,
            "effective_burst must never be zero — a zero bucket denies everything"
        );
    }
}

// ===========================================================================
// CIRCUIT BREAKER WIRING TESTS // ===========================================================================

#[cfg(test)]
mod circuit_breaker_wiring {
    use std::time::Duration;
    use worker_processors::common::{CircuitBreaker, CircuitBreakerConfig};

    #[test]
    fn test_circuit_breaker_state_machine() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            open_duration: Duration::from_millis(100),
            success_threshold: 2,
            window_duration: Duration::from_secs(60),
        };
        let cb = CircuitBreaker::new(config);

        // Initially closed
        assert!(cb.is_allowed(), "Should start in Closed state");

        // Record failures below threshold
        cb.record_failure();
        cb.record_failure();
        assert!(cb.is_allowed(), "Should still be Closed after 2 failures");

        // Third failure should open the circuit
        cb.record_failure();
        assert!(!cb.is_allowed(), "Should be Open after 3 failures");
    }

    #[test]
    fn test_circuit_breaker_recovery() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_millis(10),
            success_threshold: 1,
            window_duration: Duration::from_secs(60),
        };
        let cb = CircuitBreaker::new(config);

        // Open the circuit
        cb.record_failure();
        assert!(!cb.is_allowed(), "Circuit should be open");

        // Wait for open duration
        std::thread::sleep(Duration::from_millis(20));

        // Should now be in half-open, allowing a test request
        assert!(cb.is_allowed(), "Circuit should transition to HalfOpen");

        // Success should close the circuit
        cb.record_success();
        assert!(
            cb.is_allowed(),
            "Circuit should be Closed after success in HalfOpen"
        );
    }
}

// ===========================================================================
// WAF ENGINE WIRING TESTS
// ===========================================================================

#[cfg(test)]
mod waf_engine_wiring {
    use std::net::{IpAddr, Ipv4Addr};
    use waf_engine::{HttpRequest, WafConfig, WafEngine};

    #[test]
    fn test_waf_engine_processes_normal_requests() {
        let config = WafConfig::default();
        let engine = WafEngine::new(config);

        let headers: Vec<(String, String)> = vec![
            ("Host".to_string(), "api.example.com".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];

        // Normal request should pass
        let req = HttpRequest {
            client_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            method: "GET",
            path: "/api/users",
            query_string: None,
            headers: &headers,
            body: None,
        };

        let result = engine.inspect(&req);

        // Normal request should have low score
        assert!(
            result.total_score < 5,
            "Normal request should have low anomaly score"
        );
    }

    #[test]
    fn test_waf_detects_sql_injection() {
        let config = WafConfig::default();
        let engine = WafEngine::new(config);

        let headers: Vec<(String, String)> =
            vec![("Host".to_string(), "api.example.com".to_string())];

        // SQL injection in query string
        let req = HttpRequest {
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            method: "GET",
            path: "/api/users",
            query_string: Some("id=1%27%20OR%20%271%27%3D%271"), // URL-encoded:' OR '1'='1
            headers: &headers,
            body: None,
        };

        let result = engine.inspect(&req);

        // WAF should flag this as suspicious
        assert!(
            result.total_score > 0 || !result.matches.is_empty(),
            "WAF must detect SQL injection patterns, got score={}",
            result.total_score
        );
    }

    #[test]
    fn test_waf_detects_xss() {
        let config = WafConfig::default();
        let engine = WafEngine::new(config);

        let headers: Vec<(String, String)> = vec![
            ("Host".to_string(), "api.example.com".to_string()),
            ("Content-Type".to_string(), "text/plain".to_string()),
        ];

        // XSS in body
        let req = HttpRequest {
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            method: "POST",
            path: "/api/comments",
            query_string: None,
            headers: &headers,
            body: Some("<script>alert('xss')</script>"),
        };

        let result = engine.inspect(&req);

        assert!(
            result.total_score > 0 || !result.matches.is_empty(),
            "WAF must detect XSS patterns, got score={}",
            result.total_score
        );
    }
}

// ===========================================================================
// DLP ENGINE WIRING TESTS
// ===========================================================================

#[cfg(test)]
mod dlp_engine_wiring {
    use dlp_engine::engine::{DlpAction, DlpEngine};

    #[test]
    fn test_dlp_engine_allows_normal_content() {
        let engine = DlpEngine::new();

        // Normal email content
        let content = "Hello, I wanted to follow up on our meeting yesterday. Best regards, John.";
        let verdict = engine.scan(content, Some("example.com"));

        assert_eq!(
            verdict.action,
            DlpAction::Allow,
            "Normal content should be allowed"
        );
    }

    #[test]
    fn test_dlp_engine_detects_credit_cards() {
        let engine = DlpEngine::new();

        // Content with credit card number (Visa test card)
        let content = "Please process payment with card: 4111111111111111";
        let verdict = engine.scan(content, Some("external.com"));

        assert!(
            !verdict.pii_findings.is_empty() || verdict.risk_score > 0.0,
            "DLP must detect credit card numbers"
        );
    }

    #[test]
    fn test_dlp_engine_detects_ssn() {
        let engine = DlpEngine::new();

        // Content with SSN
        let content = "Employee SSN: 123-45-6789";
        let verdict = engine.scan(content, Some("external.com"));

        assert!(
            !verdict.pii_findings.is_empty() || verdict.risk_score > 0.0,
            "DLP must detect SSN patterns"
        );
    }
}

// ===========================================================================
// IDS ENGINE WIRING TESTS
// ===========================================================================

#[cfg(test)]
mod ids_engine_wiring {
    use ids_engine::{AlertSeverity, IdsConfig, IdsEngine};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_ids_engine_initialization() {
        let config = IdsConfig::default();
        let engine = IdsEngine::new(config);

        // Engine should initialize successfully with built-in signatures
        assert!(engine.is_ok(), "IDS engine must initialize successfully");
    }

    #[test]
    fn test_ids_engine_inspects_normal_traffic() {
        let config = IdsConfig::default();
        let engine = IdsEngine::new(config).expect("Failed to create IDS engine");

        // Normal HTTP request should not trigger high-severity alerts
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let normal_payload = b"GET /api/health HTTP/1.1\r\nHost: example.com\r\n\r\n";

        let (_verdict, alerts) = engine.inspect(src_ip, 80, "tcp", normal_payload);

        // Normal traffic should not be blocked
        let has_critical = alerts.iter().any(|a| a.severity == AlertSeverity::Critical);

        assert!(
            !has_critical,
            "Normal HTTP request should not trigger critical alerts"
        );
    }
}

// ===========================================================================
// SPAM FILTER WIRING TESTS
// ===========================================================================

#[cfg(test)]
mod spam_filter_wiring {
    use spam_filter::engine::SpamClass;
    use spam_filter::SpamEngine;

    #[test]
    fn test_spam_filter_scores_normal_messages() {
        let engine = SpamEngine::new();

        // Create headers for a normal email
        let headers: Vec<(String, String)> = vec![
            ("From".to_string(), "sender@example.com".to_string()),
            ("To".to_string(), "recipient@example.com".to_string()),
            ("Subject".to_string(), "Meeting follow-up".to_string()),
            ("Message-ID".to_string(), "<abc123@example.com>".to_string()),
            (
                "Date".to_string(),
                "Mon, 01 Jan 2024 12:00:00 +0000".to_string(),
            ),
        ];

        // Normal email body
        let body = "Hello, I wanted to follow up on our meeting yesterday.";

        let verdict = engine.analyze(body, &headers, None);

        assert!(
            verdict.score < 5.0,
            "Normal email should have low spam score, got {}",
            verdict.score
        );
        assert_eq!(
            verdict.classification,
            SpamClass::Ham,
            "Normal email should be classified as Ham"
        );
    }

    #[test]
    fn test_spam_filter_detects_spam_patterns() {
        let engine = SpamEngine::new();

        // Suspicious headers (missing Message-ID, suspicious Reply-To)
        let headers: Vec<(String, String)> = vec![
            ("From".to_string(), "winner@prize.xyz".to_string()),
            ("To".to_string(), "victim@example.com".to_string()),
            ("Subject".to_string(), "YOU WON $1,000,000!!!".to_string()),
            ("Reply-To".to_string(), "different@address.com".to_string()),
        ];

        // Spammy content
        let body = "CONGRATULATIONS!!! You have WON $1,000,000!!! Click HERE NOW to claim your PRIZE!!! Act IMMEDIATELY or you will LOSE!!!";

        let verdict = engine.analyze(body, &headers, None);

        assert!(
            verdict.score > 3.0 || verdict.classification != SpamClass::Ham,
            "Spam filter must detect obvious spam patterns, got score={}, class={:?}",
            verdict.score,
            verdict.classification
        );
    }
}

// ===========================================================================
// ATO PROTECTION WIRING TESTS
// ===========================================================================

#[cfg(test)]
mod ato_protection_wiring {
    use ato_protection::engine::{AtoAction, AtoEngine};
    use ato_protection::session::LoginEvent;
    use chrono::Utc;

    #[test]
    fn test_ato_engine_evaluates_login_risk() {
        let engine = AtoEngine::new();

        // First normal login should have low risk
        let event = LoginEvent {
            user_id: "user123".to_string(),
            ip_address: "192.168.1.1".to_string(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string(),
            latitude: Some(40.7128),
            longitude: Some(-74.0060),
            timestamp: Utc::now(),
            success: true,
            tls_fingerprint: None,
            device_fingerprint: None,
        };

        let verdict = engine.evaluate(&event);

        assert!(
            verdict.risk_score < 5.0,
            "First normal login should have low risk, got {}",
            verdict.risk_score
        );
    }

    #[test]
    fn test_ato_engine_detects_failed_login_abuse() {
        let engine = AtoEngine::new();

        // Record multiple failed login attempts
        for _ in 0..10 {
            let event = LoginEvent {
                user_id: "target_user".to_string(),
                ip_address: "192.168.1.100".to_string(),
                user_agent: "Mozilla/5.0".to_string(),
                latitude: None,
                longitude: None,
                timestamp: Utc::now(),
                success: false,
                tls_fingerprint: None,
                device_fingerprint: None,
            };
            engine.evaluate(&event);
        }

        // Next failed attempt should have high risk
        let event = LoginEvent {
            user_id: "target_user".to_string(),
            ip_address: "192.168.1.100".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            latitude: None,
            longitude: None,
            timestamp: Utc::now(),
            success: false,
            tls_fingerprint: None,
            device_fingerprint: None,
        };

        let verdict = engine.evaluate(&event);

        assert!(
            verdict.action == AtoAction::Block
                || verdict.action == AtoAction::RequireMfa
                || verdict.risk_score > 5.0,
            "Multiple failed logins must increase risk, got action={:?}, score={}",
            verdict.action,
            verdict.risk_score
        );
    }
}

// ===========================================================================
// THREAT INTEL WIRING TESTS
// ===========================================================================

#[cfg(test)]
mod threat_intel_wiring {
    use threat_intel::engine::ThreatAction;
    use threat_intel::ThreatIntelEngine;

    #[test]
    fn test_threat_intel_checks_ips() {
        let engine = ThreatIntelEngine::new();

        // Check a public IP (not in default blocklists)
        let result = engine.check_ip("8.8.8.8");

        // Should not be flagged as a threat by default
        assert!(
            result.action == ThreatAction::Allow || result.action == ThreatAction::Flag,
            "Public DNS IPs should not be blocked by default"
        );
    }

    #[test]
    fn test_threat_intel_checks_domains() {
        let engine = ThreatIntelEngine::new();

        // Check a known safe domain
        let result = engine.check_domain("google.com");

        assert!(
            result.action == ThreatAction::Allow,
            "Known safe domains should be allowed"
        );
    }
}

// ===========================================================================
// SANDBOX WIRING TESTS
// ===========================================================================

#[cfg(test)]
mod sandbox_wiring {
    use sandbox::engine::SandboxEngine;

    #[test]
    fn test_sandbox_analyzes_benign_content() {
        let engine = SandboxEngine::new();

        // Analyze benign text file content
        let benign = b"Hello, World! This is a normal text file.";
        let result = engine.analyze(benign, Some("readme.txt"));

        assert!(result.is_ok(), "Sandbox must successfully analyze files");

        let verdict = result.unwrap();
        assert!(
            verdict.risk_score < 0.5,
            "Benign content should have low risk score, got {}",
            verdict.risk_score
        );
    }

    #[test]
    fn test_sandbox_handles_file_types() {
        let engine = SandboxEngine::new();

        // Test with a suspicious file extension
        let content = b"MZ"; // Minimal PE header
        let result = engine.analyze(content, Some("malware.exe"));

        assert!(result.is_ok(), "Sandbox must handle executable files");

        let verdict = result.unwrap();
        // .exe files should have elevated risk even if content is minimal
        assert!(
            verdict.risk_score > 0.0 || !verdict.findings.is_empty(),
            "Executable files should be flagged for inspection"
        );
    }
}

// ===========================================================================
// OBSERVABILITY WIRING TESTS
// ===========================================================================

#[cfg(test)]
mod observability_wiring {
    use observability_service::trace_collector::TraceCollector;
    use observability_service::types::{SpanKind, SpanStatus, TraceSpan};
    use std::collections::HashMap;

    #[test]
    fn test_trace_collector_records_spans() {
        let collector = TraceCollector::new();

        assert!(collector.is_empty(), "Should start empty");

        let span = TraceSpan {
            trace_id: "abc123".to_string(),
            span_id: "span1".to_string(),
            parent_span_id: None,
            operation_name: "http.request".to_string(),
            service_name: "api-server".to_string(),
            start_time: chrono::Utc::now(),
            end_time: Some(chrono::Utc::now()),
            duration_ms: Some(150),
            status: SpanStatus::Ok,
            kind: SpanKind::Server,
            status_message: None,
            attributes: HashMap::new(),
            events: Vec::new(),
        };

        collector.record_span(span);

        assert!(!collector.is_empty(), "Collector must record spans");
        assert_eq!(collector.len(), 1, "Collector must track span count");
    }

    #[test]
    fn test_trace_collector_search() {
        let collector = TraceCollector::new();

        // Record multiple spans
        for i in 0..5 {
            let span = TraceSpan {
                trace_id: format!("trace{}", i / 2),
                span_id: format!("span{}", i),
                parent_span_id: None,
                operation_name: if i % 2 == 0 {
                    "http.request".to_string()
                } else {
                    "db.query".to_string()
                },
                service_name: "api-server".to_string(),
                start_time: chrono::Utc::now(),
                end_time: Some(chrono::Utc::now()),
                duration_ms: Some(((i + 1) * 100) as i64),
                status: SpanStatus::Ok,
                kind: SpanKind::Server,
                status_message: None,
                attributes: HashMap::new(),
                events: Vec::new(),
            };
            collector.record_span(span);
        }

        // Search for http.request operations
        let http_spans = collector.search(Some("http.request"), None);
        assert_eq!(http_spans.len(), 3, "Should find all http.request spans");

        // Search for slow spans
        let slow_spans = collector.search(None, Some(300));
        assert!(slow_spans.len() >= 2, "Should find slow spans");
    }
}
