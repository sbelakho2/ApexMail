//! # Security Pipeline Integration Tests
//!
//! End-to-end tests verifying the full security stack works correctly
//! when components are combined://!
//! 1. **Email delivery pipeline**:WAF → Threat-Intel → Spam → DLP → Sandbox
//! 2. **Login security pipeline**:ATO → Threat-Intel
//! 3. **Network security pipeline**:IDS → WAF → Threat-Intel
//!
//! These tests verify that://! - Components integrate without panics
//! - Security verdicts propagate correctly
//! - Multi-layer detection catches threats
//! - Clean traffic passes through efficiently

use chrono::Utc;
use std::net::{IpAddr, Ipv4Addr};

// ===========================================================================
// Email Delivery Pipeline Tests
// ===========================================================================

mod email_pipeline {
    use super::*;
    use dlp_engine::engine::DlpEngine;
    use sandbox::engine::SandboxEngine;
    use spam_filter::engine::SpamEngine;
    use threat_intel::ThreatIntelEngine;
    use waf_engine::{
        config::WafConfig,
        engine::{HttpRequest, WafEngine},
    };

    #[test]
    fn test_clean_email_passes_all_stages() {
        let waf = WafEngine::new(WafConfig::default());
        let threat_intel = ThreatIntelEngine::new();
        let spam = SpamEngine::new();
        let dlp = DlpEngine::new();
        let sandbox_eng = SandboxEngine::new();

        // Step 1:WAF check
        let api_body =
            r#"{"from":"sender@legitimate.com","subject":"Meeting","body":"Let's meet tomorrow."}"#;
        let waf_req = HttpRequest {
            client_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            method: "POST",
            path: "/v1/messages",
            query_string: None,
            headers: &[("content-type".into(), "application/json".into())],
            body: Some(api_body),
        };
        let waf_result = waf.inspect(&waf_req);
        // Clean traffic should have low/zero score
        assert!(
            waf_result.total_score < 10,
            "WAF score too high for clean email: {}",
            waf_result.total_score
        );

        // Step 2:Threat-intel check — the verdicts are ASSERTED, not bound
        // and dropped (audit SM12 F15): a clean IP and domain must classify
        // exactly Allow by the production reputation scorer.
        let ti_ip = threat_intel.check_ip("8.8.8.8");
        assert_eq!(
            ti_ip.action,
            threat_intel::engine::ThreatAction::Allow,
            "clean IP must classify Allow, got {} ({})",
            ti_ip.action,
            ti_ip.summary
        );
        let ti_domain = threat_intel.check_domain("legitimate.com");
        assert_eq!(
            ti_domain.action,
            threat_intel::engine::ThreatAction::Allow,
            "clean domain must classify Allow, got {} ({})",
            ti_domain.action,
            ti_domain.summary
        );

        // Step 3:Spam filter
        let headers = vec![
            ("From".into(), "sender@legitimate.com".into()),
            ("Subject".into(), "Meeting tomorrow".into()),
        ];
        let spam_verdict = spam.analyze(
            "Let's meet tomorrow at 10am. Best regards, John.",
            &headers,
            None,
        );
        assert!(
            spam_verdict.score < 5.0,
            "Spam score too high for clean email: {}",
            spam_verdict.score
        );
        assert_eq!(
            spam_verdict.classification,
            spam_filter::engine::SpamClass::Ham,
            "clean email must classify exactly Ham, got {:?}",
            spam_verdict.classification
        );

        // Step 4:DLP scan — clean content must be an exact Allow with zero
        // findings, not merely "a low number".
        let dlp_verdict = dlp.scan(
            "Let's meet tomorrow at 10am. Best regards, John.",
            Some("legitimate.com"),
        );
        assert!(
            dlp_verdict.risk_score < 5.0,
            "DLP score too high for clean email: {}",
            dlp_verdict.risk_score
        );
        assert_eq!(
            dlp_verdict.action,
            dlp_engine::engine::DlpAction::Allow,
            "clean content must be an exact DLP Allow, got {:?}",
            dlp_verdict.action
        );
        assert!(
            dlp_verdict.pii_findings.is_empty(),
            "clean content must produce zero PII findings, got {:?}",
            dlp_verdict.pii_findings
        );

        // Step 5:Sandbox (no attachment)
        let sandbox_result = sandbox_eng.analyze(b"Plain text attachment", Some("notes.txt"));
        assert!(sandbox_result.is_ok(), "Sandbox should accept plain text");
        let sandbox_verdict = sandbox_result.expect("verdict");
        assert!(
            sandbox_verdict.risk_score < 0.5,
            "plain text must carry a low sandbox risk, got {}",
            sandbox_verdict.risk_score
        );
        assert!(
            sandbox_verdict.findings.is_empty(),
            "plain text must produce zero sandbox findings, got {:?}",
            sandbox_verdict.findings
        );
    }

    #[test]
    fn test_sqli_in_email_detected() {
        let waf = WafEngine::new(WafConfig::default());

        let api_body = r#"{"body":"Hello ' UNION SELECT * FROM users --"}"#;
        let req = HttpRequest {
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            method: "POST",
            path: "/v1/messages",
            query_string: None,
            headers: &[("content-type".into(), "application/json".into())],
            body: Some(api_body),
        };
        let result = waf.inspect(&req);
        // Exact-category assertion (SM12 F15): a single low-value rule from
        // ANY category must not satisfy this test — the SQLi classifier
        // itself must fire with a meaningful score.
        let sqli = result
            .matches
            .iter()
            .find(|m| m.category == waf_engine::AttackCategory::SqlInjection)
            .expect("WAF must classify the payload as SqlInjection");
        assert!(
            sqli.score >= 3,
            "the SqlInjection rule must contribute a real score, got {}",
            sqli.score
        );
        assert!(
            result.total_score >= sqli.score,
            "total_score must include the SqlInjection match: {} < {}",
            result.total_score,
            sqli.score
        );
    }

    #[test]
    fn test_spam_email_detected() {
        let spam = SpamEngine::new();

        // Same shape the spam-filter crate's own suite classifies as Spam:
        // spammy content + a Reply-To mismatch + failed authentication.
        let body = "Congratulations! You have won a million dollars! Click here: \
                    https://bit.ly/scam to wire transfer now! Act now! Limited time! Urgent!!!!!!!";
        let headers = vec![
            ("From".into(), "spam@spammer.com".into()),
            ("Reply-To".into(), "money@different.com".into()),
        ];
        let verdict = spam.analyze(body, &headers, Some("spf=fail; dkim=fail"));
        assert!(
            verdict.score > 3.0,
            "Spam filter should flag obvious spam: score = {}",
            verdict.score
        );
        // Exact classification (SM12 F15): a high score with a Ham label is
        // a verdict-propagation bug even if the number looks fine.
        assert!(
            matches!(
                verdict.classification,
                spam_filter::engine::SpamClass::Spam | spam_filter::engine::SpamClass::Reject
            ),
            "obvious spam must classify Spam/Reject, got {:?} (score {})",
            verdict.classification,
            verdict.score
        );
    }

    #[test]
    fn test_pii_detected_by_dlp() {
        let dlp = DlpEngine::new();

        let body = "Customer SSN: 123-45-6789, Credit card: 4111-1111-1111-1111";
        let verdict = dlp.scan(body, Some("external.com"));
        // Exact-category assertions (SM12 F15): both detector types must
        // fire — an OR-composite let a single finding pass for both.
        let types: Vec<_> = verdict.pii_findings.iter().map(|f| f.pii_type).collect();
        assert!(
            types.contains(&dlp_engine::pii::PiiType::Ssn),
            "DLP must detect the SSN, got finding types {types:?}"
        );
        assert!(
            types.contains(&dlp_engine::pii::PiiType::CreditCard),
            "DLP must detect the credit card, got finding types {types:?}"
        );
        assert!(
            verdict.risk_score >= 5.0,
            "two PII hits must push the risk score to a real minimum, got {}",
            verdict.risk_score
        );
    }

    #[test]
    fn test_malicious_attachment_flagged() {
        let sandbox_eng = SandboxEngine::new();

        let exe_data = b"MZ\x00\x00\x00This is a fake PE executable";
        let result = sandbox_eng.analyze(exe_data, Some("important.exe"));
        assert!(result.is_ok(), "Sandbox should produce a verdict");
        let verdict = result.expect("verdict");
        assert!(
            !verdict.findings.is_empty(),
            "an executable attachment must produce at least one finding"
        );
        assert!(
            verdict.risk_score >= 1.0,
            "an executable attachment must carry a substantive risk score, got {}",
            verdict.risk_score
        );
    }

    #[test]
    fn test_xss_in_html_email_detected() {
        let waf = WafEngine::new(WafConfig::default());

        let body = "<html><body><script>alert(document.cookie)</script></body></html>";
        let req = HttpRequest {
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            method: "POST",
            path: "/v1/messages",
            query_string: None,
            headers: &[("content-type".into(), "text/html".into())],
            body: Some(body),
        };
        let result = waf.inspect(&req);
        assert!(
            result
                .matches
                .iter()
                .any(|m| m.category == waf_engine::AttackCategory::Xss && m.score > 0),
            "WAF must classify the payload as Xss with a real score, matches: {:?}",
            result.matches
        );
        assert!(
            result.total_score > 0,
            "WAF should detect XSS: score = {}",
            result.total_score
        );
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
            device_fingerprint: None,
        }
    }

    #[test]
    fn test_normal_login_allowed() {
        let ato = AtoEngine::with_config(AtoConfig::default());
        let _threat_intel = ThreatIntelEngine::new();

        let event = make_login("user1", "8.8.8.8", 40.7128, -74.0060, true);
        let verdict = ato.evaluate(&event);

        // Normal login should have low risk
        assert!(
            verdict.risk_score < 5.0,
            "Normal login should have low risk: {}",
            verdict.risk_score
        );
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

        assert!(
            verdict.risk_score > 2.0,
            "Risk should escalate after failed attempts: {}",
            verdict.risk_score
        );
    }

    #[test]
    fn test_impossible_travel_detection() {
        let ato = AtoEngine::with_config(AtoConfig::default());

        // Login from NYC
        let nyc_event = make_login("user_travel", "1.2.3.4", 40.7128, -74.0060, true);
        ato.evaluate(&nyc_event);

        // Login from Tokyo 30 minutes later — ~10,850 km in half an hour is
        // physically impossible. (A ~0s gap is deliberately NOT flagged: the
        // engine's tolerance floors skip sub-2-minute gaps because mobile/
        // CGNAT GeoIP resolves to distant PoPs and clock skew produces
        // non-monotonic timestamps — see ato-protection geo.rs.)
        let mut tokyo_event = make_login("user_travel", "5.6.7.8", 35.6762, 139.6503, true);
        tokyo_event.timestamp = Utc::now() + chrono::Duration::minutes(30);
        let verdict = ato.evaluate(&tokyo_event);

        assert!(verdict.impossible_travel, "Should detect impossible travel");
        assert!(
            verdict.risk_score > 4.0,
            "Risk should be high for impossible travel: {}",
            verdict.risk_score
        );
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
        assert!(
            !verdict2.new_device,
            "Second login should not be new device"
        );
    }
}

// ===========================================================================
// Network Security Pipeline Tests
// ===========================================================================

mod network_pipeline {
    use super::*;
    use ids_engine::{config::IdsConfig, engine::IdsEngine};
    use threat_intel::ThreatIntelEngine;
    use waf_engine::{
        config::WafConfig,
        engine::{HttpRequest, WafEngine},
    };

    #[test]
    fn test_clean_http_traffic() {
        let ids = IdsEngine::new(IdsConfig::default()).expect("IDS init");
        let waf = WafEngine::new(WafConfig::default());
        let _threat_intel = ThreatIntelEngine::new();

        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (verdict, alerts) =
            ids.inspect(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 80, "tcp", payload);
        assert!(
            matches!(verdict, ids_engine::IdsVerdict::Pass),
            "IDS should pass clean traffic"
        );
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
        assert!(
            waf_result.total_score < 5,
            "WAF should not flag clean traffic: {}",
            waf_result.total_score
        );
    }

    #[test]
    fn test_sqli_detected() {
        let ids = IdsEngine::new(IdsConfig::default()).expect("IDS init");
        let waf = WafEngine::new(WafConfig::default());

        let payload =
            b"GET /search?q=' UNION SELECT * FROM users -- HTTP/1.1\r\nHost:example.com\r\n\r\n";
        // The sqli signatures are http-scoped (Signature.protocol == "http");
        // inspecting as "tcp" skips them by design.
        let (verdict, alerts) =
            ids.inspect(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80, "http", payload);

        let req = HttpRequest {
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            method: "GET",
            path: "/search",
            query_string: Some("q=' UNION SELECT * FROM users --"),
            headers: &[],
            body: None,
        };
        let waf_result = waf.inspect(&req);

        // SM12 F15: this used to be `waf > 0 || !alerts.is_empty()` — a
        // single low-value WAF rule could mask a dead IDS (and vice versa).
        // Each engine is asserted on its OWN classification now.
        assert!(
            waf_result
                .matches
                .iter()
                .any(|m| m.category == waf_engine::AttackCategory::SqlInjection),
            "WAF must classify the query as SqlInjection, matches: {:?}",
            waf_result.matches
        );
        let sqli_alerts: Vec<_> = alerts.iter().filter(|a| a.category == "sqli").collect();
        assert!(
            !sqli_alerts.is_empty(),
            "IDS must raise its sqli-signature alert, got alerts: {:?}",
            alerts
        );
        assert!(
            sqli_alerts
                .iter()
                .all(|a| a.action != ids_engine::IdsVerdict::Pass),
            "a raised sqli alert must recommend a non-Pass action: {:?}",
            sqli_alerts
        );
        assert!(
            !matches!(verdict, ids_engine::IdsVerdict::Pass),
            "an attack payload must not yield an overall IDS Pass verdict, got {:?}",
            verdict
        );
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
        assert!(
            result.total_score > 0,
            "WAF should detect path traversal: {}",
            result.total_score
        );
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
        assert!(
            result.total_score > 0,
            "WAF should detect XSS: {}",
            result.total_score
        );
    }
}

// ===========================================================================
// Full Stack Integration
// ===========================================================================

mod full_stack {
    use super::*;
    use ato_protection::{config::AtoConfig, engine::AtoEngine};
    use dlp_engine::config::DlpConfig;
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

        // Run 500 iterations — this exercises the engines under moderate
        // repetitive load.  No explicit resource-cleanup assertion is performed
        // because each iteration processes independent, ephemeral data and the
        // engines are pure stateless analyzers (no cross-iteration state leaks).
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

    /// Verify that a WAF engine with a pared-down config (all feature flags
    /// disabled) still processes a request without panicking — this serves as
    /// an invariant-violation regression test proving the engine handles the
    /// degenerate case gracefully.
    #[test]
    fn test_waf_minimal_config_does_not_panic() {
        let cfg = WafConfig {
            enable_sqli: false,
            enable_xss: false,
            enable_path_traversal: false,
            enable_command_injection: false,
            enable_protocol_checks: false,
            enable_nosqli: false,
            enable_ssrf: false,
            enable_smuggling: false,
            ..WafConfig::default()
        };
        let waf = WafEngine::new(cfg);
        let req = waf_engine::engine::HttpRequest {
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            method: "GET",
            path: "/",
            query_string: None,
            headers: &[],
            body: None,
        };
        let _result = waf.inspect(&req);
    }

    /// Verify that an IDS engine created with extreme configuration values
    /// (zero-length thresholds) does not panic — confirming the engine's
    /// parameter validation is robust against degenerate inputs.
    #[test]
    fn test_ids_extreme_config_does_not_panic() {
        let cfg = IdsConfig {
            max_connections: 0,
            connection_timeout_secs: 0,
            portscan_threshold: 0,
            portscan_window_secs: 0,
            syn_flood_threshold: 0,
            max_payload_inspect: 0,
            ..IdsConfig::default()
        };
        let ids = IdsEngine::new(cfg).expect("IDS engine creation should not fail");
        let _result = ids.inspect(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80, "tcp", b"test");
    }

    /// Verify that a DLP engine with all detection features disabled still
    /// handles scan requests without panicking.
    #[test]
    fn test_dlp_minimal_config_does_not_panic() {
        let cfg = DlpConfig {
            detect_credit_cards: false,
            detect_ssn: false,
            detect_phone_numbers: false,
            detect_email_addresses: false,
            detect_secrets: false,
            ..DlpConfig::default()
        };
        let dlp = DlpEngine::with_config(cfg);
        let _result = dlp.scan("some content", None);
    }
}

// ===========================================================================
// CHAINED PIPELINE (audit SM12 F15)
// ===========================================================================

/// The module doc always claimed "verdicts propagate correctly", but nothing
/// pipelined: every engine was fed independently and the intermediate verdicts
/// were dropped. This module chains ONE message through the production stack
/// in delivery order — WAF → threat-intel → spam → DLP → sandbox — aggregates
/// the per-stage verdicts the way the platform's rejection policy does (ANY
/// hard-reject vote rejects the message), and asserts each engine's exact
/// classification. `A > 0 || B` composites are banned by construction: every
/// stage has its own minimum-score or exact-category assertion, so one
/// engine's regression cannot be masked by its neighbours.
mod chained_pipeline {
    use chrono::Utc;
    use dlp_engine::engine::{DlpAction, DlpEngine};
    use sandbox::engine::SandboxEngine;
    use spam_filter::engine::SpamEngine;
    use threat_intel::domain_blocklist::DomainBlockEntry;
    use threat_intel::engine::ThreatAction;
    use threat_intel::ip_blocklist::{IpBlockEntry, ThreatCategory};
    use threat_intel::ThreatIntelEngine;
    use waf_engine::{
        config::WafConfig,
        engine::{HttpRequest, WafEngine},
    };

    /// The combined decision the pipeline produces from the stage verdicts.
    #[derive(Debug, PartialEq, Eq)]
    enum PipelineVerdict {
        Deliver,
        Reject,
    }

    struct StageRecord {
        stage: &'static str,
        hard_reject: bool,
        detail: String,
    }

    /// Aggregate: a message is deliverable only when NO stage voted a hard
    /// reject. This is the propagation the module doc promised.
    fn combine(stages: &[StageRecord]) -> PipelineVerdict {
        if stages.iter().any(|s| s.hard_reject) {
            PipelineVerdict::Reject
        } else {
            PipelineVerdict::Deliver
        }
    }

    /// The known-bad sender infrastructure this suite feeds into the threat
    /// intel blocklists, so the TI stage produces a real Block verdict
    /// instead of a vacuous default Allow.
    const BAD_SENDER_IP: &str = "203.0.113.66";
    const BAD_SENDER_DOMAIN: &str = "chained-pipeline-malware.example";
    /// The feed name declared in the engine config: unconfigured feeds carry
    /// trust 3.0 by design and can never produce Block (Enforce) outcomes.
    const TEST_FEED: &str = "integration-test-feed";

    /// A TI engine whose config declares this suite's feed as a trusted
    /// (9.5) ENFORCE feed — the same posture production blocklist feeds run
    /// under — so the fed entries can drive a hard Block.
    fn block_capable_threat_intel() -> ThreatIntelEngine {
        let mut config = threat_intel::config::ThreatIntelConfig::default();
        config.feeds.insert(
            0,
            threat_intel::config::FeedSource {
                name: TEST_FEED.into(),
                url: "https://feeds.invalid/integration-test.txt".into(),
                format: threat_intel::config::FeedFormat::PlainText,
                refresh_interval_secs: 3600,
                enabled: true,
                trust_score: 9.5,
                enforcement_mode: threat_intel::config::FeedEnforcementMode::Enforce,
            },
        );
        ThreatIntelEngine::with_config(config)
    }

    fn feed_threat_intel(engine: &ThreatIntelEngine) {
        let now = Utc::now();
        let ip_entry = IpBlockEntry {
            cidr: format!("{BAD_SENDER_IP}/32"),
            source: TEST_FEED.into(),
            category: ThreatCategory::Malware,
            confidence: 9.5,
            added_at: now,
            expires_at: now + chrono::Duration::hours(1),
        };
        let domain_entry = DomainBlockEntry {
            domain: BAD_SENDER_DOMAIN.into(),
            source: TEST_FEED.into(),
            confidence: 9.5,
            category: "malware".into(),
            added_at: now,
            expires_at: now + chrono::Duration::hours(1),
        };
        let applied = engine.apply_feed_refresh(
            vec![(format!("{BAD_SENDER_IP}/32"), ip_entry)],
            vec![(BAD_SENDER_DOMAIN.into(), domain_entry)],
        );
        assert!(
            applied,
            "the test feed refresh must be applied — without it the TI stage is untested"
        );
    }

    fn run_pipeline(
        body: &str,
        sender_domain: &str,
        sender_ip: &str,
        auth_results: Option<&str>,
        attachment: Option<(&[u8], &str)>,
    ) -> PipelineVerdict {
        let waf = WafEngine::new(WafConfig::default());
        let threat_intel = block_capable_threat_intel();
        feed_threat_intel(&threat_intel);
        let spam = SpamEngine::new();
        let dlp = DlpEngine::new();
        let sandbox = SandboxEngine::new();

        let mut stages: Vec<StageRecord> = Vec::new();

        // ── Stage 1: WAF on the API submission ─────────────────────────
        let waf_req = HttpRequest {
            client_ip: sender_ip.parse().expect("sender ip literal"),
            method: "POST",
            path: "/v1/messages",
            query_string: None,
            headers: &[("content-type".into(), "application/json".into())],
            body: Some(body),
        };
        let waf_result = waf.inspect(&waf_req);
        stages.push(StageRecord {
            stage: "waf",
            hard_reject: waf_result.total_score >= 10,
            detail: format!("total_score={}", waf_result.total_score),
        });

        // ── Stage 2: threat intel on sender IP + envelope domain ───────
        let ti = threat_intel.check(Some(sender_ip), Some(sender_domain));
        stages.push(StageRecord {
            stage: "threat_intel",
            hard_reject: ti.action == ThreatAction::Block,
            detail: format!("action={}", ti.action),
        });

        // ── Stage 3: spam filter on the composed message ───────────────
        let headers = vec![
            ("From".into(), format!("sender@{sender_domain}")),
            ("Subject".into(), "Pipeline verification".into()),
        ];
        let spam_verdict = spam.analyze(body, &headers, auth_results);
        stages.push(StageRecord {
            stage: "spam",
            hard_reject: matches!(
                spam_verdict.classification,
                spam_filter::engine::SpamClass::Reject
            ),
            detail: format!(
                "class={:?} score={}",
                spam_verdict.classification, spam_verdict.score
            ),
        });

        // ── Stage 4: DLP on the body ───────────────────────────────────
        let dlp_verdict = dlp.scan(body, Some(sender_domain));
        stages.push(StageRecord {
            stage: "dlp",
            hard_reject: dlp_verdict.action == DlpAction::Block,
            detail: format!(
                "action={:?} risk={} findings={}",
                dlp_verdict.action,
                dlp_verdict.risk_score,
                dlp_verdict.pii_findings.len()
            ),
        });

        // ── Stage 5: sandbox on the (optional) attachment ──────────────
        if let Some((content, name)) = attachment {
            let sandbox_verdict = sandbox
                .analyze(content, Some(name))
                .expect("sandbox verdict");
            stages.push(StageRecord {
                stage: "sandbox",
                hard_reject: sandbox_verdict.risk_score >= 1.0,
                detail: format!(
                    "risk={} findings={}",
                    sandbox_verdict.risk_score,
                    sandbox_verdict.findings.len()
                ),
            });
        }

        for s in &stages {
            println!(
                "pipeline stage {}: hard_reject={} ({})",
                s.stage, s.hard_reject, s.detail
            );
        }
        combine(&stages)
    }

    #[test]
    fn hostile_message_is_rejected_by_the_chained_pipeline() {
        // One message carrying four independent signals: SQL injection
        // (WAF), block-listed sender infrastructure (threat intel), spam
        // content with failed authentication (spam), and PII (DLP).
        let body = "Congratulations! You have won a million dollars! Click here: \
                    https://bit.ly/scam to wire transfer now! Act now! Urgent!!!!!!! \
                    Also customer SSN: 123-45-6789 and card 4111111111111111. \
                    ' UNION SELECT * FROM users --";
        let verdict = run_pipeline(
            body,
            BAD_SENDER_DOMAIN,
            BAD_SENDER_IP,
            Some("spf=fail; dkim=fail"),
            None,
        );

        // The combined verdict must be a REJECT (at least one hard vote).
        assert_eq!(
            verdict,
            PipelineVerdict::Reject,
            "a message with injection + blocklisted sender + PII must be rejected end-to-end"
        );

        // Per-engine minimums — every stage must independently classify:
        let waf = WafEngine::new(WafConfig::default());
        let waf_result = waf.inspect(&HttpRequest {
            client_ip: BAD_SENDER_IP.parse().unwrap(),
            method: "POST",
            path: "/v1/messages",
            query_string: None,
            headers: &[("content-type".into(), "application/json".into())],
            body: Some(body),
        });
        assert!(
            waf_result
                .matches
                .iter()
                .any(|m| m.category == waf_engine::AttackCategory::SqlInjection),
            "WAF stage must classify the injection, matches: {:?}",
            waf_result.matches
        );

        let ti = block_capable_threat_intel();
        feed_threat_intel(&ti);
        let ti_verdict = ti.check(Some(BAD_SENDER_IP), Some(BAD_SENDER_DOMAIN));
        assert_eq!(
            ti_verdict.action,
            ThreatAction::Block,
            "TI stage must Block the fed feed entries, got {} ({})",
            ti_verdict.action,
            ti_verdict.summary
        );

        let spam = SpamEngine::new();
        let spam_headers = vec![
            ("From".into(), format!("sender@{BAD_SENDER_DOMAIN}")),
            ("Subject".into(), "Pipeline verification".into()),
        ];
        let spam_verdict = spam.analyze(body, &spam_headers, Some("spf=fail; dkim=fail"));
        assert!(
            matches!(
                spam_verdict.classification,
                spam_filter::engine::SpamClass::Spam | spam_filter::engine::SpamClass::Reject
            ),
            "spam stage must classify the hostile body Spam/Reject, got {:?} (score {})",
            spam_verdict.classification,
            spam_verdict.score
        );

        let dlp = DlpEngine::new();
        let dlp_verdict = dlp.scan(body, Some(BAD_SENDER_DOMAIN));
        let types: Vec<_> = dlp_verdict
            .pii_findings
            .iter()
            .map(|f| f.pii_type)
            .collect();
        assert!(
            types.contains(&dlp_engine::pii::PiiType::Ssn)
                && types.contains(&dlp_engine::pii::PiiType::CreditCard),
            "DLP stage must detect SSN AND credit card, got {types:?}"
        );
    }

    #[test]
    fn clean_message_is_delivered_by_the_chained_pipeline() {
        let body = "Hi team, the quarterly report is attached to the shared drive. Best, Ana.";
        let verdict = run_pipeline(body, "legitimate.example", "8.8.8.8", None, None);
        assert_eq!(
            verdict,
            PipelineVerdict::Deliver,
            "a clean message must pass every stage and be delivered"
        );
    }

    #[test]
    fn malicious_attachment_rejects_an_otherwise_clean_message() {
        // Propagation check: ONLY the sandbox stage votes — the verdict must
        // still flip to Reject, proving stage output reaches the decision.
        let body = "Please find the requested document attached.";
        let verdict = run_pipeline(
            body,
            "legitimate.example",
            "8.8.8.8",
            None,
            Some((b"MZ\x90\x00 fake payload binary".as_slice(), "invoice.exe")),
        );
        assert_eq!(
            verdict,
            PipelineVerdict::Reject,
            "an executable attachment must flip the combined verdict to Reject"
        );
    }
}
