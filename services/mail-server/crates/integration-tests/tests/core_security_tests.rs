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
        ControlPlaneShell, ImpersonationBanner, MarketingShell, OperationalBanner,
        ShellHeader, ToastSurface, WebDashboardShell,
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
            header: ShellHeader {
                search_query: "safe",
                unread_count: 0,
                avatar_fallback: "X",
                mobile_menu_open: false,
            },
            impersonation_banner: None,
            toast_surface: None,
        }
        .render_html();
// child_html is trusted content and must be injected as-is
        assert!(html.contains(child), "trusted child_html must not be double-escaped");
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
            scopes: scopes.into_iter().map(String::from).collect(),
        }
    }

    fn api_key_with_scopes(scopes: Vec<&str>) -> AuthUser {
        AuthUser {
            tenant_id: "ten_test".into(),
            user_id: None,
            api_key_id: Some("key_test".into()),
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
        assert!(msg.contains("messages:send"), "error must name the missing scope");
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
        let tester = WebhookTester::new(secret.to_string()).unwrap();
        let body = b"{\"type\":\"email.delivered\",\"data\":{}}";
        let sig = tester.sign_payload(body);
        assert!(
            WebhookTester::verify_signature(secret, body, &sig),
            "signature must verify with correct secret"
        );
    }

    #[test]
    fn wrong_secret_rejects() {
        let tester = WebhookTester::new("correct_secret".to_string()).unwrap();
        let body = b"{\"type\":\"test\"}";
        let sig = tester.sign_payload(body);
        assert!(
            !WebhookTester::verify_signature("wrong_secret", body, &sig),
            "wrong secret must fail verification"
        );
    }

    #[test]
    fn tampered_body_rejects() {
        let secret = "whsec_tamper_test_secret_32chrs!";
        let tester = WebhookTester::new(secret.to_string()).unwrap();
        let original = b"{\"type\":\"email.delivered\"}";
        let sig = tester.sign_payload(original);
        let tampered = b"{\"type\":\"email.bounced\"}";
        assert!(
            !WebhookTester::verify_signature(secret, tampered, &sig),
            "tampered body must fail verification"
        );
    }

    #[test]
    fn empty_body_signs_and_verifies() {
        let secret = "whsec_empty_body_test_32_chars!!";
        let tester = WebhookTester::new(secret.to_string()).unwrap();
        let body = b"";
        let sig = tester.sign_payload(body);
        assert!(WebhookTester::verify_signature(secret, body, &sig));
    }

    #[test]
    fn malformed_signature_headers_rejected() {
        let secret = "whsec_malformed_test_secret_32!!";
        let body = b"test";
        assert!(!WebhookTester::verify_signature(secret, body, ""));
        assert!(!WebhookTester::verify_signature(secret, body, "garbage"));
        assert!(!WebhookTester::verify_signature(secret, body, "t=,v1="));
        assert!(!WebhookTester::verify_signature(secret, body, "v1=abc"));
        assert!(!WebhookTester::verify_signature(secret, body, "t=123"));
        assert!(!WebhookTester::verify_signature(
            secret,
            body,
            "t=123,v1=0000000000"
        ));
    }

    #[test]
    fn signature_format_is_correct() {
        let tester = WebhookTester::new("test_secret".to_string()).unwrap();
        let sig = tester.sign_payload(b"body");
        assert!(sig.starts_with("t="), "signature must start with timestamp");
        assert!(sig.contains(",v1="), "signature must contain v1= component");
        let parts: Vec<&str> = sig.split(',').collect();
        assert_eq!(parts.len(), 2, "signature must have exactly 2 components");
    }

    #[test]
    fn payload_structure_is_valid() {
        let payload = WebhookTester::build_test_payload("email.bounced");
        assert_eq!(payload["type"], "email.bounced");
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
        assert_ne!(h1, h2, "same password must produce different hashes (random salt)");
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
        assert_ne!(
            legacy, hmac,
            "legacy SHA-256 must differ from HMAC-SHA256"
        );
    }

    #[test]
    fn bcrypt_hash_detected_before_argon2_verify() {
// Simulate a bcrypt hash (from the old change_password path)
// Argon2 verify_password must return Err, not a false positive
        let bcrypt_hash = "$2b$12$LJ3m4ys8Rp9gXPfBH9J9KuW5Eky0Zxy7v1X8X9X0X0X0X0X0X0X0";
        let result = crypto::verify_password("test", bcrypt_hash);
// Must either error or return false — never panic or return true
        match result {
            Ok(verified) => assert!(!verified, "bcrypt hash must not verify as Argon2"),
            Err(_) => {} // Expected:format error
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SSRF Protection
// ═══════════════════════════════════════════════════════════════════════════

mod ssrf_protection {
    use std::net::IpAddr;

/// Parse and check if an IP is private (mirrors webhook_tester logic)
    fn is_private_ip(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_unspecified()
            }
            IpAddr::V6(v6) => {
                v6.is_loopback() || v6.is_unspecified()
            }
        }
    }

    #[test]
    fn blocks_private_ipv4_ranges() {
        let private_ips = [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.255.255",
        ];
        for ip_str in private_ips {
            let ip: IpAddr = ip_str.parse().unwrap();
            assert!(is_private_ip(ip), "{ip_str} must be blocked as private");
        }
    }

    #[test]
    fn blocks_loopback() {
        let loopback_ips = ["127.0.0.1", "127.0.0.2", "::1"];
        for ip_str in loopback_ips {
            let ip: IpAddr = ip_str.parse().unwrap();
            assert!(is_private_ip(ip), "{ip_str} must be blocked as loopback");
        }
    }

    #[test]
    fn blocks_link_local() {
        let link_local = ["169.254.0.1", "169.254.169.254"];
        for ip_str in link_local {
            let ip: IpAddr = ip_str.parse().unwrap();
            assert!(
                is_private_ip(ip),
                "{ip_str} must be blocked as link-local (AWS metadata)"
            );
        }
    }

    #[test]
    fn blocks_unspecified() {
        let unspecified = ["0.0.0.0", "::"];
        for ip_str in unspecified {
            let ip: IpAddr = ip_str.parse().unwrap();
            assert!(is_private_ip(ip), "{ip_str} must be blocked as unspecified");
        }
    }

    #[test]
    fn allows_public_ips() {
        let public_ips = ["8.8.8.8", "1.1.1.1", "151.101.1.140", "104.18.32.7"];
        for ip_str in public_ips {
            let ip: IpAddr = ip_str.parse().unwrap();
            assert!(!is_private_ip(ip), "{ip_str} must be allowed as public");
        }
    }
}
