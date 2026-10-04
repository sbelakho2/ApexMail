//! Core security & UX regression tests.
//!
//! These tests validate critical security properties across auth, RBAC,
//! webhook signing, XSS escaping, SSRF blocking, and session management.
//! All tests are fail-first:they must detect the bug before the fix.

// ═══════════════════════════════════════════════════════════════════════════
// UI Foundation — XSS Escaping
// ═══════════════════════════════════════════════════════════════════════════

mod ui_xss {
    use ui_foundation::shell::{
        ControlPlaneShell, ImpersonationBanner, MarketingShell, OperationalBanner, ShellHeader,
        WebDashboardShell,
    };

    /// HTML-injection vectors that must never appear un-escaped in HTML output.
    /// Note:`javascript:` URIs without HTML metacharacters are only dangerous
    /// in href/src attribute contexts, not in text content where these values
    /// are rendered, so they are not included here.
    const XSS_PAYLOADS: &[&str] = &[
        "<script>alert('xss')</script>",
        "<img src=x onerror=\"alert(1)\">",
        "<svg/onload=alert(1)>",
        "\" onfocus=\"alert(1)\" autofocus=\"",
        "<iframe src=\"javascript:alert(1)\"></iframe>",
        "<body onload=alert(1)>",
        "'><script>alert(String.fromCharCode(88,83,83))</script>",
    ];

    fn must_not_contain_raw(html: &str, payload: &str) {
        assert!(
            !html.contains(payload),
            "raw XSS payload escaped into rendered HTML: {payload}"
        );
    }

    #[test]
    fn xss_header_search_all_vectors() {
        for payload in XSS_PAYLOADS {
            let html = ShellHeader {
                search_query: payload,
                unread_count: 0,
                avatar_fallback: "AM",
                mobile_menu_open: false,
                user_context: None,
            }
            .render_html();
            must_not_contain_raw(&html, payload);
        }
    }

    #[test]
    fn xss_impersonation_banner_all_fields() {
        for payload in XSS_PAYLOADS {
            let html = ImpersonationBanner {
                tenant_id: payload,
                operator_name: payload,
                time_remaining: payload,
                end_session_error: Some(payload),
                ending_session: false,
            }
            .render_html();
            must_not_contain_raw(&html, payload);
        }
    }

    #[test]
    fn xss_control_plane_banner_message() {
        for payload in XSS_PAYLOADS {
            let html = ControlPlaneShell {
                mobile_menu_open: false,
                user_role: "admin",
                page_title: "Security",
                page_description: "Security status",
                current_path: "/cp",
                csrf_token: "",
                banners: vec![OperationalBanner {
                    tone: "critical",
                    message: payload,
                }],
                child_html: "<p>safe</p>",
            }
            .render_html();
            must_not_contain_raw(&html, payload);
        }
    }

    #[test]
    fn xss_web_shell_does_not_double_escape_safe_child() {
        let child = "<section class=\"safe\">Hello &amp; World</section>";
        let html = WebDashboardShell {
            sidebar_collapsed: false,
            mobile_menu_open: false,
            child_html: child,
            current_path: "/dashboard",
            csrf_token: "",
            header: ShellHeader {
                search_query: "safe",
                unread_count: 0,
                avatar_fallback: "X",
                mobile_menu_open: false,
                user_context: None,
            },
            impersonation_banner: None,
            toast_surface: None,
        }
        .render_html();
        // child_html is trusted content and must be injected as-is
        assert!(
            html.contains(child),
            "trusted child_html must not be double-escaped"
        );
    }

    #[test]
    fn xss_marketing_shell_passes_child_through() {
        let child = "<div>Product</div>";
        let html = MarketingShell { child_html: child }.render_html();
        assert!(html.contains(child));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// RBAC — Scope Enforcement
// ═══════════════════════════════════════════════════════════════════════════

mod rbac {
    use api_server::middleware::auth::{require_scopes, AuthUser};

    fn user_with_scopes(scopes: Vec<&str>) -> AuthUser {
        AuthUser {
            tenant_id: "ten_test".into(),
            user_id: Some("usr_test".into()),
            api_key_id: None,
            session_id: None,
            scopes: scopes.into_iter().map(String::from).collect(),
        }
    }

    fn api_key_with_scopes(scopes: Vec<&str>) -> AuthUser {
        AuthUser {
            tenant_id: "ten_test".into(),
            user_id: None,
            api_key_id: Some("key_test".into()),
            session_id: None,
            scopes: scopes.into_iter().map(String::from).collect(),
        }
    }

    // ── Positive path ──────────────────────────────────────────

    #[test]
    fn wildcard_grants_everything() {
        let user = user_with_scopes(vec!["*"]);
        assert!(require_scopes(&user, &["messages:send", "admin:delete"]).is_ok());
    }

    #[test]
    fn exact_match_grants_access() {
        let user = user_with_scopes(vec!["messages:send", "messages:read"]);
        assert!(require_scopes(&user, &["messages:send"]).is_ok());
    }

    #[test]
    fn empty_required_scopes_always_pass() {
        let user = user_with_scopes(vec![]);
        assert!(require_scopes(&user, &[]).is_ok());
    }

    // ── Negative path ──────────────────────────────────────────

    #[test]
    fn missing_scope_denied() {
        let user = user_with_scopes(vec!["messages:read"]);
        let result = require_scopes(&user, &["messages:send"]);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("messages:send"),
            "error must name the missing scope"
        );
    }

    #[test]
    fn empty_user_scopes_denied() {
        let user = user_with_scopes(vec![]);
        assert!(require_scopes(&user, &["messages:read"]).is_err());
    }

    #[test]
    fn partial_match_insufficient() {
        let user = user_with_scopes(vec!["messages:read"]);
        // User has read but not send — requiring both must fail
        assert!(require_scopes(&user, &["messages:read", "messages:send"]).is_err());
    }

    #[test]
    fn substring_scope_no_match() {
        // "messages:read_all" must NOT match "messages:read"
        let user = user_with_scopes(vec!["messages:read_all"]);
        assert!(require_scopes(&user, &["messages:read"]).is_err());
    }

    #[test]
    fn prefix_scope_no_match() {
        // "messages:" must NOT match "messages:read"
        let user = user_with_scopes(vec!["messages:"]);
        assert!(require_scopes(&user, &["messages:read"]).is_err());
    }

    // ── Role-based scope matrices ──────────────────────────────

    #[test]
    fn viewer_cannot_mutate() {
        let viewer = user_with_scopes(vec![
            "messages:read",
            "domains:read",
            "templates:read",
            "events:read",
            "analytics:read",
            "contacts:read",
        ]);
        let write_scopes = &[
            "messages:send",
            "domains:write",
            "templates:write",
            "contacts:write",
            "webhooks:write",
            "campaigns:write",
            "suppressions:write",
        ];
        for scope in write_scopes {
            assert!(
                require_scopes(&viewer, &[scope]).is_err(),
                "viewer must NOT have {scope}"
            );
        }
    }

    #[test]
    fn developer_cannot_manage_webhooks_or_campaigns() {
        let developer = user_with_scopes(vec![
            "messages:send",
            "messages:read",
            "domains:read",
            "templates:read",
            "templates:write",
            "events:read",
            "analytics:read",
            "contacts:read",
            "contacts:write",
        ]);
        assert!(require_scopes(&developer, &["webhooks:write"]).is_err());
        assert!(require_scopes(&developer, &["campaigns:write"]).is_err());
        assert!(require_scopes(&developer, &["suppressions:write"]).is_err());
    }

    #[test]
    fn api_key_scopes_enforced_same_as_user() {
        let key = api_key_with_scopes(vec!["messages:read"]);
        assert!(require_scopes(&key, &["messages:read"]).is_ok());
        assert!(require_scopes(&key, &["messages:send"]).is_err());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Webhook Signature Verification
// ═══════════════════════════════════════════════════════════════════════════

mod webhook_security {
    use devex_service::webhook_tester::WebhookTester;

    #[test]
    fn sign_verify_roundtrip() {
        let secret = "whsec_test_secret_32_chars_long!!";
        let tester = WebhookTester::new(vec![secret.to_string()]).unwrap();
        let body = b"{\"type\":\"email.delivered\",\"data\":{}}";
        let sig = tester.sign_payload(body);
        assert!(
            tester.verify_signature(body, &sig),
            "signature must verify with correct secret"
        );
    }

    #[test]
    fn wrong_secret_rejects() {
        let tester = WebhookTester::new(vec!["correct_secret".to_string()]).unwrap();
        let body = b"{\"type\":\"test\"}";
        let sig = tester.sign_payload(body);
        let wrong_tester = WebhookTester::new(vec!["wrong_secret".to_string()]).unwrap();
        assert!(
            !wrong_tester.verify_signature(body, &sig),
            "wrong secret must fail verification"
        );
    }

    #[test]
    fn tampered_body_rejects() {
        let secret = "whsec_tamper_test_secret_32chrs!";
        let tester = WebhookTester::new(vec![secret.to_string()]).unwrap();
        let original = b"{\"type\":\"email.delivered\"}";
        let sig = tester.sign_payload(original);
        let tampered = b"{\"type\":\"email.bounced\"}";
        assert!(
            !tester.verify_signature(tampered, &sig),
            "tampered body must fail verification"
        );
    }

    #[test]
    fn empty_body_signs_and_verifies() {
        let secret = "whsec_empty_body_test_32_chars!!";
        let tester = WebhookTester::new(vec![secret.to_string()]).unwrap();
        let body = b"";
        let sig = tester.sign_payload(body);
        assert!(tester.verify_signature(body, &sig));
    }

    #[test]
    fn malformed_signature_headers_rejected() {
        let secret = "whsec_malformed_test_secret_32!!";
        let tester = WebhookTester::new(vec![secret.to_string()]).unwrap();
        let body = b"test";
        assert!(!tester.verify_signature(body, ""));
        assert!(!tester.verify_signature(body, "garbage"));
        assert!(!tester.verify_signature(body, "t=,v1="));
        assert!(!tester.verify_signature(body, "v1=abc"));
        assert!(!tester.verify_signature(body, "t=123"));
        assert!(!tester.verify_signature(body, "t=123,v1=0000000000"));
    }

    #[test]
    fn signature_format_is_correct() {
        let tester = WebhookTester::new(vec!["test_secret".to_string()]).unwrap();
        let sig = tester.sign_payload(b"body");
        assert!(sig.starts_with("t="), "signature must start with timestamp");
        assert!(sig.contains(",v1="), "signature must contain v1= component");
        let parts: Vec<&str> = sig.split(',').collect();
        assert_eq!(parts.len(), 2, "signature must have exactly 2 components");
    }

    #[test]
    fn payload_structure_is_valid() {
        let payload = WebhookTester::build_test_payload("message.bounced");
        assert_eq!(payload["type"], "message.bounced");
        assert!(payload["test"].as_bool().unwrap());
        assert!(
            payload["id"].as_str().unwrap().starts_with("evt_"),
            "event ID must have evt_ prefix"
        );
        assert!(payload["created_at"].is_string());
        assert!(payload["data"].is_object());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Auth — Password & Token Security
// ═══════════════════════════════════════════════════════════════════════════

mod auth_security {
    use apexmail_lib::crypto;

    #[test]
    fn argon2_hash_and_verify_roundtrip() {
        let password = "V3ry$ecurePa$$w0rd!";
        let hash = crypto::hash_password(password).expect("hashing must succeed");
        assert!(
            hash.starts_with("$argon2"),
            "hash must use Argon2 algorithm, got: {}",
            &hash[..20]
        );
        assert!(
            crypto::verify_password(password, &hash).expect("verify must not error"),
            "correct password must verify"
        );
    }

    #[test]
    fn wrong_password_fails_verification() {
        let hash = crypto::hash_password("CorrectHorse!Battery1").unwrap();
        let result = crypto::verify_password("WrongPassword!123", &hash).unwrap();
        assert!(!result, "wrong password must not verify");
    }

    #[test]
    fn different_passwords_produce_different_hashes() {
        let h1 = crypto::hash_password("Password1!abc").unwrap();
        let h2 = crypto::hash_password("Password2!abc").unwrap();
        assert_ne!(h1, h2, "different passwords must produce different hashes");
    }

    #[test]
    fn same_password_produces_different_hashes_due_to_salt() {
        let h1 = crypto::hash_password("SamePassword!1").unwrap();
        let h2 = crypto::hash_password("SamePassword!1").unwrap();
        assert_ne!(
            h1, h2,
            "same password must produce different hashes (random salt)"
        );
    }

    #[test]
    fn hmac_api_key_hash_is_deterministic() {
        let key = "am_live_test_key_123456789";
        let secret = "test_hash_secret_32_characters!!";
        let h1 = crypto::hash_api_key_with_secret(key, secret);
        let h2 = crypto::hash_api_key_with_secret(key, secret);
        assert_eq!(h1, h2, "HMAC hash must be deterministic");
    }

    #[test]
    fn hmac_api_key_different_secrets_produce_different_hashes() {
        let key = "am_live_test_key_123456789";
        let h1 = crypto::hash_api_key_with_secret(key, "secret_one_32_characters_long!!");
        let h2 = crypto::hash_api_key_with_secret(key, "secret_two_32_characters_long!!");
        assert_ne!(h1, h2, "different secrets must produce different hashes");
    }

    #[test]
    fn legacy_sha256_differs_from_hmac_hash() {
        let key = "am_live_test_key_123456789";
        let legacy = crypto::hash_api_key(key);
        let hmac = crypto::hash_api_key_with_secret(key, "any_secret");
        assert_ne!(legacy, hmac, "legacy SHA-256 must differ from HMAC-SHA256");
    }

    #[test]
    fn bcrypt_hash_detected_before_argon2_verify() {
        // Simulate a bcrypt hash (from the old change_password path)
        // Argon2 verify_password must return Err, not a false positive
        let bcrypt_hash = "$2b$12$LJ3m4ys8Rp9gXPfBH9J9KuW5Eky0Zxy7v1X8X9X0X0X0X0X0X0X0";
        let result = crypto::verify_password("test", bcrypt_hash);
        // Must either error or return false — never panic or return true
        if let Ok(verified) = result {
            assert!(!verified, "bcrypt hash must not verify as Argon2")
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SSRF Protection (audit SM12 F7 rewrite)
// ═══════════════════════════════════════════════════════════════════════════

mod ssrf_protection {
    use std::net::IpAddr;

    // The REAL predicate used by the production webhook tester
    // (devex-service::webhook_tester::is_private_ip). The previous version of
    // this module asserted on a local copy that "mirrored" the logic — a
    // regression that dropped, say, cloud-metadata coverage there stayed
    // green here. Now the production function itself is under test: if its
    // range coverage shrinks, these tests fail.
    use devex_service::webhook_tester::is_private_ip;

    fn ip(v: &str) -> IpAddr {
        v.parse().expect("test IP literal")
    }

    #[test]
    fn blocks_private_ipv4_ranges() {
        for ip_str in [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.255.255",
        ] {
            assert!(
                is_private_ip(&ip(ip_str)),
                "{ip_str} must be blocked as private"
            );
        }
    }

    #[test]
    fn blocks_loopback() {
        for ip_str in ["127.0.0.1", "127.0.0.2", "127.255.255.254", "::1"] {
            assert!(
                is_private_ip(&ip(ip_str)),
                "{ip_str} must be blocked as loopback"
            );
        }
    }

    #[test]
    fn blocks_link_local_including_cloud_metadata() {
        for ip_str in ["169.254.0.1", "169.254.169.254"] {
            assert!(
                is_private_ip(&ip(ip_str)),
                "{ip_str} must be blocked as link-local (AWS/GCP metadata endpoint)"
            );
        }
        // The production predicate also covers unique-local IPv6.
        assert!(
            is_private_ip(&ip("fe80::1")),
            "fe80::1 must be blocked as v6 link-local"
        );
        assert!(
            is_private_ip(&ip("fd00::1")),
            "fd00::1 must be blocked as v6 unique-local"
        );
    }

    #[test]
    fn blocks_cgnat_documentation_broadcast_and_unspecified() {
        for (ip_str, why) in [
            ("100.64.0.1", "CGNAT 100.64/10"),
            ("192.0.2.1", "documentation TEST-NET-1"),
            ("198.51.100.7", "documentation TEST-NET-2"),
            ("203.0.113.5", "documentation TEST-NET-3"),
            ("255.255.255.255", "broadcast"),
            ("0.0.0.0", "unspecified v4"),
            ("::", "unspecified v6"),
        ] {
            assert!(
                is_private_ip(&ip(ip_str)),
                "{ip_str} must be blocked ({why}) — a dropped range is an SSRF hole"
            );
        }
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6_wrappers_of_private_addresses() {
        // The mapped form must be judged by the EMBEDDED address, so a
        // global-looking v6 wrapper cannot smuggle a private v4 target.
        for ip_str in [
            "::ffff:10.0.0.1",
            "::ffff:192.168.1.10",
            "::ffff:169.254.169.254",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                is_private_ip(&ip(ip_str)),
                "{ip_str} (IPv4-mapped private) must be blocked"
            );
        }
    }

    #[test]
    fn allows_public_ips() {
        for ip_str in ["8.8.8.8", "1.1.1.1", "151.101.1.140", "104.18.32.7"] {
            assert!(
                !is_private_ip(&ip(ip_str)),
                "{ip_str} must be allowed as public — over-blocking breaks outbound webhooks"
            );
        }
        assert!(
            !is_private_ip(&ip("::ffff:8.8.8.8")),
            "a mapped PUBLIC address stays allowed"
        );
    }
}
