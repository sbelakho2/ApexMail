//! Adversarial regression tests for the 2026-08 security audit fixes.
//!
//! Each test targets a specific verified vulnerability. Tests fail when the
//! vulnerable behavior is present; they pass once the fix is in place.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;
use waf_engine::{HttpRequest, WafConfig, WafDecision, WafEngine};

fn client_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
}

fn is_blocked(engine: &WafEngine, req: &HttpRequest<'_>) -> bool {
    matches!(engine.inspect(req).decision, WafDecision::Block(_))
}

// ═══════════════════════════════════════════════════════════════════
// FIX B — O(n²) HTML entity decode (decoder self-DoS)
// ═══════════════════════════════════════════════════════════════════

mod fix_b_entity_decode {
    use super::*;
    use waf_engine::decoder::html_entity_decode;

    #[test]
    fn entity_decode_basics_match_reference() {
        assert_eq!(html_entity_decode("&amp;"), "&");
        assert_eq!(html_entity_decode("&#65;"), "A");
        assert_eq!(html_entity_decode("&#x41;"), "A");
        assert_eq!(html_entity_decode("&lt;script&gt;"), "<script>");
        assert_eq!(html_entity_decode("&#60;script&#62;"), "<script>");
        assert_eq!(html_entity_decode("&#x3C;script&#x3E;"), "<script>");
    }

    #[test]
    fn entity_decode_unknown_and_bare_ampersand() {
        // Unknown entity passes through untouched
        assert_eq!(html_entity_decode("&unknown;"), "&unknown;");
        // Bare ampersand stays literal
        assert_eq!(html_entity_decode("&"), "&");
        assert_eq!(html_entity_decode("&&&&"), "&&&&");
        // Ampersand with no terminator within entity bound stays literal
        assert_eq!(html_entity_decode("&amp"), "&amp");
        assert_eq!(html_entity_decode("a & b"), "a & b");
    }

    #[test]
    fn entity_decode_numeric_overflow_is_safe() {
        // Out-of-range codepoint does not panic and passes through
        assert_eq!(html_entity_decode("&#999999999;"), "&#999999999;");
        assert_eq!(html_entity_decode("&#99999999999;"), "&#99999999999;");
        // Surrogate codepoints are invalid scalar values → literal
        assert_eq!(html_entity_decode("&#xD800;"), "&#xD800;");
        // Max valid scalar decodes
        assert_eq!(html_entity_decode("&#x10FFFF;"), "\u{10FFFF}");
    }

    #[test]
    fn entity_decode_long_tail_ampersand_is_linear() {
        // '&' followed by > 32 chars then ';' — old decoder scanned the whole
        // tail for every '&'. Output must treat the '&' as literal.
        let input = format!("&{};", "x".repeat(200));
        assert_eq!(html_entity_decode(&input), input);
    }

    #[test]
    fn entity_decode_megabyte_of_ampersands_completes_fast() {
        // Memory/time bomb: 1 MB of '&' was ~10^11 ops before the fix.
        let bomb = "&".repeat(1_048_576);
        let start = Instant::now();
        let decoded = html_entity_decode(&bomb);
        let elapsed = start.elapsed();
        assert_eq!(decoded, bomb);
        assert!(
            elapsed.as_secs() < 2,
            "1MB of '&' took too long: {elapsed:?} (O(n²) regression)"
        );
    }

    #[test]
    fn entity_decode_mixed_entities_and_junk_linear() {
        let mut input = String::with_capacity(1 << 20);
        for i in 0..65_536 {
            input.push_str("&amp;&#65;&#x41;&bogus;&");
            if i % 64 == 0 {
                input.push_str(&"x".repeat(40));
            }
        }
        let start = Instant::now();
        let _ = html_entity_decode(&input);
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_secs() < 2,
            "mixed 1MB entity input took too long: {elapsed:?}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// FIX C — byte-slice panic on multibyte body at truncation boundary
// ═══════════════════════════════════════════════════════════════════

mod fix_c_multibyte_truncation {
    use super::*;

    #[test]
    fn multibyte_char_straddling_body_boundary_does_not_panic() {
        let engine = WafEngine::new(WafConfig::default());
        let max_body_size = WafConfig::default().max_body_size;

        // 'a' * (max-2) + 3×3-byte multibyte chars → the 1MB boundary splits
        // the middle character's UTF-8 sequence.
        let mut body = "a".repeat(max_body_size - 2);
        body.push_str("日本語");
        assert!(body.len() > max_body_size);

        let req = HttpRequest {
            client_ip: client_ip(),
            method: "POST",
            path: "/api/comments",
            query_string: None,
            headers: &[("Content-Type".to_string(), "text/plain".to_string())],
            body: Some(&body),
        };
        // Must not panic; inspection completes and yields a decision.
        let info = engine.inspect(&req);
        assert!(info.total_score < u32::MAX);
    }

    #[test]
    fn multibyte_boundary_attack_payload_still_detected() {
        let engine = WafEngine::new(WafConfig::default());
        let max_body_size = WafConfig::default().max_body_size;
        // Payload: filler to (max-2), then a multibyte char straddling the
        // boundary, then <script> AFTER the boundary (should be truncated
        // away), and a second <script> placed before the boundary.
        let mut body = String::new();
        body.push_str("<script>alert(1)</script>");
        body.push_str(&"a".repeat(max_body_size - 2 - body.len() - 3));
        body.push('日'); // multibyte near boundary
        body.push_str("<script>x</script>"); // past boundary — truncated
        let req = HttpRequest {
            client_ip: client_ip(),
            method: "POST",
            path: "/c",
            query_string: None,
            headers: &[],
            body: Some(&body),
        };
        let info = engine.inspect(&req);
        assert!(
            is_blocked(&engine, &req),
            "script before boundary must still be detected, score={}",
            info.total_score
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// FIX D — null-byte fast-path bypass
// ═══════════════════════════════════════════════════════════════════

mod fix_d_null_byte_bypass {
    use super::*;

    #[test]
    fn nul_inside_script_tag_is_detected() {
        // `<scr\0ipt>` defeats the Aho-Corasick "<script" literal when NUL
        // bytes are not stripped before fast-path matching.
        let engine = WafEngine::new(WafConfig::default());
        let body = "<scr\0ipt>alert(1)</scr\0ipt>";
        let req = HttpRequest {
            client_ip: client_ip(),
            method: "POST",
            path: "/comment",
            query_string: None,
            headers: &[],
            body: Some(body),
        };
        assert!(
            is_blocked(&engine, &req),
            "`<scr\\0ipt>` must be detected after NUL stripping in canonicalization"
        );
    }

    #[test]
    fn nul_obfuscated_query_opens_sqli_gate() {
        // `sel%00ect` decodes to `sel\0ect` — after NUL strip the value is
        // `select`, which must reach the SQL analyzer (rule 920400 must also
        // fire for the raw null byte in the query string).
        let engine = WafEngine::new(WafConfig::default());
        let req = HttpRequest {
            client_ip: client_ip(),
            method: "GET",
            path: "/items",
            query_string: Some("q=sel%00ect"),
            headers: &[],
            body: None,
        };
        let info = engine.inspect(&req);
        assert!(
            info.matches.iter().any(|m| m.rule_id == 920400),
            "null byte in query string must fire 920400"
        );
        assert!(is_blocked(&engine, &req));
    }

    #[test]
    fn nul_byte_in_body_and_headers_fire_920400() {
        let engine = WafEngine::new(WafConfig::default());
        let body = "field=va\0lue";
        let req = HttpRequest {
            client_ip: client_ip(),
            method: "POST",
            path: "/submit",
            query_string: None,
            headers: &[("X-Custom".to_string(), "he\0ader".to_string())],
            body: Some(body),
        };
        let info = engine.inspect(&req);
        assert!(
            info.matches
                .iter()
                .any(|m| m.rule_id == 920400
                    && matches!(m.location, waf_engine::MatchLocation::Body)),
            "null byte in body must fire 920400"
        );
        assert!(
            info.matches.iter().any(|m| m.rule_id == 920400
                && matches!(m.location, waf_engine::MatchLocation::Header(_))),
            "null byte in header value must fire 920400"
        );
    }

    #[test]
    fn canonicalize_strips_nul_bytes() {
        assert_eq!(
            waf_engine::decoder::canonicalize_input("sel%00ect", 3, true),
            "select"
        );
        assert_eq!(
            waf_engine::decoder::canonicalize_input("<scr\0ipt>", 3, false),
            "<script>"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// FIX E — SQLi fast-path exclusion bypass + GtEq/LtEq tautologies
// ═══════════════════════════════════════════════════════════════════

mod fix_e_sqli_gate_bypass {
    use super::*;

    #[test]
    fn boolean_blind_no_keyword_reaches_analyzer() {
        // `1 and 2>1` has no SQL keyword/quote — previously never reached
        // the AST analyzer.
        let engine = WafEngine::new(WafConfig::default());
        let req = HttpRequest {
            client_ip: client_ip(),
            method: "GET",
            path: "/users",
            query_string: Some("id=1+and+2>1"),
            headers: &[],
            body: None,
        };
        let info = engine.inspect(&req);
        assert!(
            info.matches.iter().any(|m| m.rule_id == 942100),
            "`1 and 2>1` must be analyzed as boolean-blind tautology, got {:?}",
            info.matches.iter().map(|m| m.rule_id).collect::<Vec<_>>()
        );
        assert!(is_blocked(&engine, &req));
    }

    #[test]
    fn gteq_tautology_detected() {
        let engine = WafEngine::new(WafConfig::default());
        for payload in ["id=1>=1", "id=2>=2"] {
            let req = HttpRequest {
                client_ip: client_ip(),
                method: "GET",
                path: "/users",
                query_string: Some(payload),
                headers: &[],
                body: None,
            };
            let info = engine.inspect(&req);
            assert!(
                info.matches.iter().any(|m| m.rule_id == 942100),
                "{payload} must fire 942100"
            );
            assert!(is_blocked(&engine, &req), "{payload} must be blocked");
        }
    }

    #[test]
    fn lteq_tautology_detected() {
        let engine = WafEngine::new(WafConfig::default());
        let req = HttpRequest {
            client_ip: client_ip(),
            method: "GET",
            path: "/users",
            query_string: Some("id=1<=1"),
            headers: &[],
            body: None,
        };
        let info = engine.inspect(&req);
        assert!(
            info.matches.iter().any(|m| m.rule_id == 942100),
            "`1<=1` must fire 942100"
        );
        assert!(is_blocked(&engine, &req));
    }

    #[test]
    fn comparison_gate_opens_for_digit_comparisons() {
        // The fast-path gate itself must treat digit-adjacent comparison
        // operators as an inclusion signal.
        assert!(waf_engine::fast_path::fast_path_sqli("1 and 2>1"));
        assert!(waf_engine::fast_path::fast_path_sqli("1>=1"));
        assert!(waf_engine::fast_path::fast_path_sqli("1 <= 1"));
        // Bare comparisons are also an inclusion signal.
        assert!(waf_engine::fast_path::fast_path_sqli("2>1"));
        // Benign prose without comparison ops must not open the gate on
        // random words containing "and".
        assert!(!waf_engine::fast_path::fast_path_sqli("coffee and tea"));
        assert!(!waf_engine::fast_path::fast_path_sqli("hello world"));
    }
}

// ═══════════════════════════════════════════════════════════════════
// FIX F — path allowlist prefix bypass
// ═══════════════════════════════════════════════════════════════════

mod fix_f_allowlist_prefix {
    use super::*;

    fn engine_with_static() -> WafEngine {
        let mut cfg = WafConfig::default();
        cfg.allowlist_paths.push("/static".to_string());
        WafEngine::new(cfg)
    }

    #[test]
    fn allowlist_does_not_match_prefix_extension() {
        // `/staticX/admin` must NOT be allowlisted by entry "/static"
        let e = engine_with_static();
        let req = HttpRequest {
            client_ip: client_ip(),
            method: "GET",
            path: "/staticX/admin",
            query_string: Some("q=1+UNION+SELECT+1"),
            headers: &[],
            body: None,
        };
        assert!(
            is_blocked(&e, &req),
            "`/staticX/...` must not be allowlisted by `/static`"
        );
    }

    #[test]
    fn allowlist_traversal_still_checked() {
        // `/static/../../etc/passwd` matches the allowlist entry by prefix,
        // but traversal must STILL be analyzed on allowlisted paths.
        let e = engine_with_static();
        let req = HttpRequest {
            client_ip: client_ip(),
            method: "GET",
            path: "/static/../../etc/passwd",
            query_string: None,
            headers: &[],
            body: None,
        };
        let info = e.inspect(&req);
        assert!(
            info.matches
                .iter()
                .any(|m| m.rule_id == 930100 || m.rule_id == 930200),
            "`/static/../../etc/passwd` must fire traversal rules even though allowlisted"
        );
        assert!(is_blocked(&e, &req));
    }

    #[test]
    fn allowlisted_static_asset_stays_clean() {
        let e = engine_with_static();
        let req = HttpRequest {
            client_ip: client_ip(),
            method: "GET",
            path: "/static/css/app.css",
            query_string: None,
            headers: &[],
            body: None,
        };
        let info = e.inspect(&req);
        assert!(
            !matches!(info.decision, WafDecision::Block(_)),
            "legit static asset must stay allowed, score={}",
            info.total_score
        );
    }

    #[test]
    fn exact_allowlisted_path_is_allowlisted() {
        // Path exactly equal to the entry is allowlisted (segment-prefix
        // matching must not break exact matches).
        let e = engine_with_static();
        let req = HttpRequest {
            client_ip: client_ip(),
            method: "GET",
            path: "/static",
            query_string: None,
            headers: &[("Host".to_string(), "example.com".to_string())],
            body: None,
        };
        let info = e.inspect(&req);
        assert_eq!(info.total_score, 0, "exact allowlisted path stays clean");
    }
}

// ═══════════════════════════════════════════════════════════════════
// FIX K6 — backslash-obfuscated command injection
// ═══════════════════════════════════════════════════════════════════

mod fix_k6_backslash_cmdi {
    use super::*;

    #[test]
    fn backslash_obfuscated_cat_passwd_blocked() {
        // `;c\at /etc/passwd` — backslash inside the command name bypassed
        // literal command matching.
        let engine = WafEngine::new(WafConfig::default());
        let req = HttpRequest {
            client_ip: client_ip(),
            method: "GET",
            path: "/ping",
            query_string: Some("host=8.8.8.8%3Bc%5Cat+/etc/passwd"),
            headers: &[],
            body: None,
        };
        assert!(
            is_blocked(&engine, &req),
            "`;c\\at /etc/passwd` must be blocked"
        );
    }

    #[test]
    fn backslash_obfuscated_whoami_blocked() {
        let engine = WafEngine::new(WafConfig::default());
        let req = HttpRequest {
            client_ip: client_ip(),
            method: "POST",
            path: "/exec",
            query_string: None,
            headers: &[],
            body: Some("cmd=;w\\hoami"),
        };
        assert!(is_blocked(&engine, &req), "`;w\\hoami` must be blocked");
    }
}

// ═══════════════════════════════════════════════════════════════════
// FIX K7 — enforce configured request size limits (dead config)
// ═══════════════════════════════════════════════════════════════════

mod fix_k7_size_limits {
    use super::*;

    #[test]
    fn oversized_url_blocked_with_400() {
        let engine = WafEngine::new(WafConfig {
            max_url_length: 128,
            ..Default::default()
        });
        let long_path = format!("/a/{}", "x".repeat(300));
        let req = HttpRequest {
            client_ip: client_ip(),
            method: "GET",
            path: &long_path,
            query_string: None,
            headers: &[],
            body: None,
        };
        let info = engine.inspect(&req);
        assert!(
            matches!(info.decision, WafDecision::Block(400)),
            "oversized URL must block with 400, got {:?}",
            info.decision
        );
    }

    #[test]
    fn url_within_limit_not_blocked_for_length() {
        let engine = WafEngine::new(WafConfig {
            max_url_length: 128,
            ..Default::default()
        });
        let req = HttpRequest {
            client_ip: client_ip(),
            method: "GET",
            path: "/api/v1/users?limit=10",
            query_string: None,
            headers: &[],
            body: None,
        };
        let info = engine.inspect(&req);
        assert!(!matches!(info.decision, WafDecision::Block(_)));
    }

    #[test]
    fn too_many_query_params_blocked() {
        let engine = WafEngine::new(WafConfig {
            max_query_params: 5,
            ..Default::default()
        });
        let qs = (0..20)
            .map(|i| format!("p{i}=1"))
            .collect::<Vec<_>>()
            .join("&");
        let req = HttpRequest {
            client_ip: client_ip(),
            method: "GET",
            path: "/api",
            query_string: Some(&qs),
            headers: &[],
            body: None,
        };
        assert!(matches!(
            engine.inspect(&req).decision,
            WafDecision::Block(400)
        ));
    }

    #[test]
    fn too_many_headers_blocked() {
        let engine = WafEngine::new(WafConfig {
            max_headers: 3,
            ..Default::default()
        });
        let headers: Vec<(String, String)> = (0..10)
            .map(|i| (format!("X-H{i}"), "v".to_string()))
            .collect();
        let req = HttpRequest {
            client_ip: client_ip(),
            method: "GET",
            path: "/api",
            query_string: None,
            headers: &headers,
            body: None,
        };
        assert!(matches!(
            engine.inspect(&req).decision,
            WafDecision::Block(400)
        ));
    }

    #[test]
    fn oversized_header_value_blocked() {
        let engine = WafEngine::new(WafConfig {
            max_header_value_length: 32,
            ..Default::default()
        });
        let headers = vec![("X-Long".to_string(), "z".repeat(200))];
        let req = HttpRequest {
            client_ip: client_ip(),
            method: "GET",
            path: "/api",
            query_string: None,
            headers: &headers,
            body: None,
        };
        assert!(matches!(
            engine.inspect(&req).decision,
            WafDecision::Block(400)
        ));
    }

    #[test]
    fn normal_request_not_affected_by_default_limits() {
        let engine = WafEngine::new(WafConfig::default());
        let headers: Vec<(String, String)> = (0..10)
            .map(|i| (format!("X-H{i}"), "v".to_string()))
            .collect();
        let req = HttpRequest {
            client_ip: client_ip(),
            method: "GET",
            path: "/api/v1/health",
            query_string: Some("a=1&b=2"),
            headers: &headers,
            body: None,
        };
        assert!(!matches!(
            engine.inspect(&req).decision,
            WafDecision::Block(_)
        ));
    }
}

// ═══════════════════════════════════════════════════════════════════
// FIX K8 — event-handler gaps (`onpointerover`, `onanimationstart`, ws-=)
// ═══════════════════════════════════════════════════════════════════

mod fix_k8_event_handlers {
    use super::*;

    #[test]
    fn onpointerover_with_tab_blocked() {
        let engine = WafEngine::new(WafConfig::default());
        let req = HttpRequest {
            client_ip: client_ip(),
            method: "POST",
            path: "/note",
            query_string: None,
            headers: &[],
            body: Some("<div onpointerover=\talert(1)>hover</div>"),
        };
        assert!(
            is_blocked(&engine, &req),
            "`onpointerover=\\t` must be blocked"
        );
    }

    #[test]
    fn onanimationstart_blocked() {
        let engine = WafEngine::new(WafConfig::default());
        let req = HttpRequest {
            client_ip: client_ip(),
            method: "POST",
            path: "/note",
            query_string: None,
            headers: &[],
            body: Some("<div onanimationstart=alert(1)>x</div>"),
        };
        assert!(
            is_blocked(&engine, &req),
            "onanimationstart must be blocked"
        );
    }

    #[test]
    fn whitespace_before_equals_all_handlers() {
        // `onerror\t=\t` style obfuscation must work for ALL handlers,
        // not just the small hardcoded subset.
        let engine = WafEngine::new(WafConfig::default());
        for payload in [
            "<div onpointerover\t=\talert(1)>x</div>",
            "<div onanimationstart =alert(1)>x</div>",
            "<div ontransitionend\n=\nalert(1)>x</div>",
        ] {
            let req = HttpRequest {
                client_ip: client_ip(),
                method: "POST",
                path: "/note",
                query_string: None,
                headers: &[],
                body: Some(payload),
            };
            assert!(
                is_blocked(&engine, &req),
                "whitespace-obfuscated handler must be blocked: {payload}"
            );
        }
    }
}

// End of audit regression tests.
