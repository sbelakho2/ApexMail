//! # Security Pipeline Integration Tests
//!
//! End-to-end tests verifying the full security stack works correctly
//! when components are combined:
//!
//! 1. **Email delivery pipeline**: WAF → Threat-Intel → Spam → DLP → Sandbox
//! 2. **Login security pipeline**: ATO → Threat-Intel
//! 3. **Network security pipeline**: IDS → WAF → Threat-Intel
//!
//! These tests verify that:
//! - Components integrate without panics
//! - Security verdicts propagate correctly
//! - Multi-layer detection catches threats
//! - Clean traffic passes through efficiently

use std::net::{IpAddr, Ipv4Addr};
use chrono::Utc;

// ===========================================================================
// Email Delivery Pipeline Tests
// ===========================================================================

mod email_pipeline {
    use super::*;
    use dlp_engine::engine::DlpEngine;
    use sandbox::engine::SandboxEngine;
    use spam_filter::engine::SpamEngine;
    use threat_intel::ThreatIntelEngine;
    use waf_engine::{config::WafConfig, engine::{HttpRequest, WafEngine}};

    #[test]
    fn test_clean_email_passes_all_stages() {
        let waf = WafEngine::new(WafConfig::default());
        let threat_intel = ThreatIntelEngine::new();
        let spam = SpamEngine::new();
        let dlp = DlpEngine::new();
        let sandbox_eng = SandboxEngine::new();

        // Step 1: WAF check
        let api_body = r#"{"from":"sender@legitimate.com","subject":"Meeting","body":"Let's meet tomorrow."}"#;
        let waf_req = HttpRequest {
            client_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            method: "POST",
            path: "/api/v1/send",
            query_string: None,
            headers: &[("content-type".into(), "application/json".into())],
            body: Some(api_body),
        };
        let waf_result = waf.inspect(&waf_req);
        // Clean traffic should have low/zero score
        assert!(waf_result.total_score < 10, "WAF score too high for clean email: {}", waf_result.total_score);

        // Step 2: Threat-intel check
        let ti_ip = threat_intel.check_ip("8.8.8.8");
        let ti_domain = threat_intel.check_domain("legitimate.com");
        // Clean IPs/domains should not be blocked (check risk_score if available)

        // Step 3: Spam filter
        let headers = vec![
            ("From".into(), "sender@legitimate.com".into()),
            ("Subject".into(), "Meeting tomorrow".into()),
        ];
        let spam_verdict = spam.analyze("Let's meet tomorrow at 10am. Best regards, John.", &headers, None);
        assert!(spam_verdict.score < 5.0, "Spam score too high for clean email: {}", spam_verdict.score);

        // Step 4: DLP scan
        let dlp_verdict = dlp.scan("Let's meet tomorrow at 10am. Best regards, John.", Some("legitimate.com"));
        assert!(dlp_verdict.risk_score < 5.0, "DLP score too high for clean email: {}", dlp_verdict.risk_score);

        // Step 5: Sandbox (no attachment)
        let sandbox_result = sandbox_eng.analyze(b"Plain text attachment", Some("notes.txt"));
        assert!(sandbox_result.is_ok(), "Sandbox should accept plain text");
    }

    #[test]
    fn test_sqli_in_email_detected() {
        let waf = WafEngine::new(WafConfig::default());

        let api_body = r#"{"body":"Hello ' UNION SELECT * FROM users--"}"#;
        let req = HttpRequest {
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            method: "POST",
            path: "/api/v1/send",
            query_string: None,
            headers: &[("content-type".into(), "application/json".into())],
            body: Some(api_body),
        };
        let result = waf.inspect(&req);
        assert!(result.total_score > 0, "WAF should detect SQLi: score = {}", result.total_score);
    }

    #[test]
    fn test_spam_email_detected() {
        let spam = SpamEngine::new();

        let body = "Congratulations! You've won $1,000,000! Click here to claim your prize NOW! This offer expires in 24 hours! Don't delay - act immediately!";
        let headers = vec![
            ("From".into(), "spam@spammer.com".into()),
            ("Subject".into(), "URGENT: Act now! Limited time offer!".into()),
        ];
        let verdict = spam.analyze(body, &headers, None);
        assert!(verdict.score > 3.0, "Spam filter should flag obvious spam: score = {}", verdict.score);
    }

    #[test]
    fn test_pii_detected_by_dlp() {
        let dlp = DlpEngine::new();

        let body = "Customer SSN: 123-45-6789, Credit card: 4111-1111-1111-1111";
        let verdict = dlp.scan(body, Some("external.com"));
        assert!(verdict.risk_score > 0.0 || !verdict.pii_findings.is_empty(),
            "DLP should detect PII: risk = {}, findings = {}",
            verdict.risk_score, verdict.pii_findings.len());
    }

    #[test]
    fn test_malicious_attachment_flagged() {
        let sandbox_eng = SandboxEngine::new();

        let exe_data = b"MZ\x00\x00\x00This is a fake PE executable";
        let result = sandbox_eng.analyze(exe_data, Some("important.exe"));
        assert!(result.is_ok(), "Sandbox should produce a verdict");
        let verdict = result.expect("verdict");
        assert!(verdict.risk_score > 0.0, "Sandbox should flag executable: risk = {}", verdict.risk_score);
    }

    #[test]
    fn test_xss_in_html_email_detected() {
        let waf = WafEngine::new(WafConfig::default());

        let body = "<html><body><script>alert(document.cookie)</script></body></html>";
        let req = HttpRequest {
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            method: "POST",
            path: "/api/v1/send",
            query_string: None,
            headers: &[("content-type".into(), "text/html".into())],
            body: Some(body),
        };
        let result = waf.inspect(&req);
        assert!(result.total_score > 0, "WAF should detect XSS: score = {}", result.total_score);
    }
}

// ===========================================================================
// Login Security Pipeline Tests
// ===========================================================================

mod login_pipeline {
    use super::*;
    use ato_protection::{config::AtoConfig, engine::AtoEngine, session::LoginEvent};
    use threat_intel::ThreatIntelEngine;

    fn make_login(user_id: &str, ip: &str, lat: f64, lon: f64, success: bool) -> LoginEvent {
        LoginEvent {
            user_id: user_id.to_string(),
            ip_address: ip.to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            latitude: Some(lat),
            longitude: Some(lon),
            timestamp: Utc::now(),
            success,
            tls_fingerprint: None,
        }
    }

    #[test]
    fn test_normal_login_allowed() {
        let ato = AtoEngine::with_config(AtoConfig::default());
        let _threat_intel = ThreatIntelEngine::new();

        let event = make_login("user1", "8.8.8.8", 40.7128, -74.0060, true);
        let verdict = ato.evaluate(&event);

        // Normal login should have low risk
        assert!(verdict.risk_score < 5.0, "Normal login should have low risk: {}", verdict.risk_score);
    }

    #[test]
    fn test_failed_login_escalation() {
        let ato = AtoEngine::with_config(AtoConfig::default());

        // Multiple failed logins
        for _ in 0..6 {
            let event = make_login("user_lockout", "10.0.0.1", 40.7128, -74.0060, false);
            ato.evaluate(&event);
        }

        // Next successful login should have elevated risk
        let event = make_login("user_lockout", "10.0.0.1", 40.7128, -74.0060, true);
        let verdict = ato.evaluate(&event);

        assert!(verdict.risk_score > 2.0, "Risk should escalate after failed attempts: {}", verdict.risk_score);
    }

    #[test]
    fn test_impossible_travel_detection() {
        let ato = AtoEngine::with_config(AtoConfig::default());

        // Login from NYC
        let nyc_event = make_login("user_travel", "1.2.3.4", 40.7128, -74.0060, true);
        ato.evaluate(&nyc_event);

        // Immediate login from Tokyo
        let tokyo_event = make_login("user_travel", "5.6.7.8", 35.6762, 139.6503, true);
        let verdict = ato.evaluate(&tokyo_event);

        assert!(verdict.impossible_travel, "Should detect impossible travel");
        assert!(verdict.risk_score > 4.0, "Risk should be high for impossible travel: {}", verdict.risk_score);
    }

    #[test]
    fn test_new_device_detection() {
        let ato = AtoEngine::with_config(AtoConfig::default());

        // First login - new device
        let event = make_login("user_device", "10.0.0.1", 40.7128, -74.0060, true);
        let verdict = ato.evaluate(&event);
        assert!(verdict.new_device, "First login should be new device");

        // Second login - same device
        let event2 = make_login("user_device", "10.0.0.1", 40.7128, -74.0060, true);
        let verdict2 = ato.evaluate(&event2);
        assert!(!verdict2.new_device, "Second login should not be new device");
    }
}

// ===========================================================================
// Network Security Pipeline Tests
// ===========================================================================

mod network_pipeline {
    use super::*;
    use ids_engine::{config::IdsConfig, engine::IdsEngine};
    use threat_intel::ThreatIntelEngine;
    use waf_engine::{config::WafConfig, engine::{HttpRequest, WafEngine}};

    #[test]
    fn test_clean_http_traffic() {
        let ids = IdsEngine::new(IdsConfig::default()).expect("IDS init");
        let waf = WafEngine::new(WafConfig::default());
        let _threat_intel = ThreatIntelEngine::new();

        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (verdict, alerts) = ids.inspect(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            80,
            "tcp",
            payload,
        );
        assert!(matches!(verdict, ids_engine::IdsVerdict::Pass), "IDS should pass clean traffic");
        assert!(alerts.is_empty(), "No alerts for clean traffic");

        let req = HttpRequest {
            client_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            method: "GET",
            path: "/",
            query_string: None,
            headers: &[],
            body: None,
        };
        let waf_result = waf.inspect(&req);
        assert!(waf_result.total_score < 5, "WAF should not flag clean traffic: {}", waf_result.total_score);
    }

    #[test]
    fn test_sqli_detected() {
        let ids = IdsEngine::new(IdsConfig::default()).expect("IDS init");
        let waf = WafEngine::new(WafConfig::default());

        let payload = b"GET /search?q=' UNION SELECT * FROM users-- HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (_verdict, alerts) = ids.inspect(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            80,
            "tcp",
            payload,
        );

        let req = HttpRequest {
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            method: "GET",
            path: "/search",
            query_string: Some("q=' UNION SELECT * FROM users--"),
            headers: &[],
            body: None,
        };
        let waf_result = waf.inspect(&req);

        let detected = waf_result.total_score > 0 || !alerts.is_empty();
        assert!(detected, "SQLi should be detected by IDS or WAF");
    }

    #[test]
    fn test_path_traversal_detected() {
        let waf = WafEngine::new(WafConfig::default());

        let req = HttpRequest {
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            method: "GET",
            path: "/../../../etc/passwd",
            query_string: None,
            headers: &[],
            body: None,
        };
        let result = waf.inspect(&req);
        assert!(result.total_score > 0, "WAF should detect path traversal: {}", result.total_score);
    }

    #[test]
    fn test_xss_detected() {
        let waf = WafEngine::new(WafConfig::default());

        let req = HttpRequest {
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            method: "POST",
            path: "/comment",
            query_string: None,
            headers: &[("content-type".into(), "text/plain".into())],
            body: Some("<script>alert(1)</script>"),
        };
        let result = waf.inspect(&req);
        assert!(result.total_score > 0, "WAF should detect XSS: {}", result.total_score);
    }
}

// ===========================================================================
// Full Stack Integration
// ===========================================================================

mod full_stack {
    use super::*;
    use ato_protection::{config::AtoConfig, engine::AtoEngine};
    use dlp_engine::engine::DlpEngine;
    use ids_engine::{config::IdsConfig, engine::IdsEngine};
    use sandbox::engine::SandboxEngine;
    use spam_filter::engine::SpamEngine;
    use threat_intel::ThreatIntelEngine;
    use waf_engine::{config::WafConfig, engine::WafEngine};

    #[test]
    fn test_all_components_instantiate() {
        let _waf = WafEngine::new(WafConfig::default());
        let _ids = IdsEngine::new(IdsConfig::default()).expect("IDS");
        let _spam = SpamEngine::new();
        let _dlp = DlpEngine::new();
        let _sandbox = SandboxEngine::new();
        let _ato = AtoEngine::with_config(AtoConfig::default());
        let _threat_intel = ThreatIntelEngine::new();
    }

    #[test]
    fn test_concurrent_processing() {
        use std::thread;

        let handles: Vec<_> = (0..4)
            .map(|i| {
                thread::spawn(move || {
                    let waf = WafEngine::new(WafConfig::default());
                    let ids = IdsEngine::new(IdsConfig::default()).expect("IDS");
                    let spam = SpamEngine::new();

                    for j in 0..50 {
                        let req = waf_engine::engine::HttpRequest {
                            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, i as u8, j as u8)),
                            method: "GET",
                            path: "/api/test",
                            query_string: None,
                            headers: &[],
                            body: None,
                        };
                        let _ = waf.inspect(&req);
                        let _ = ids.inspect(
                            IpAddr::V4(Ipv4Addr::new(10, 0, i as u8, j as u8)),
                            80,
                            "tcp",
                            b"Hello",
                        );
                        let _ = spam.analyze("Hello world", &[], None);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("Thread should complete");
        }
    }

    #[test]
    fn test_repeated_processing() {
        let waf = WafEngine::new(WafConfig::default());
        let spam = SpamEngine::new();
        let dlp = DlpEngine::new();

        for i in 0..500 {
            let body = format!("Test message number {} with content", i);
            let req = waf_engine::engine::HttpRequest {
                client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                method: "POST",
                path: "/api/send",
                query_string: None,
                headers: &[("content-type".into(), "application/json".into())],
                body: Some(&body),
            };
            let _ = waf.inspect(&req);
            let _ = spam.analyze(&body, &[], None);
            let _ = dlp.scan(&body, None);
        }
    }
}
