//! Adversarial security contract — the "perfect security" invariants attacked
//! from every surface a hostile client can reach.
//!
//! Invariants (each test names the one it enforces):
//!   1. Tenant isolation: no path reads or mutates another tenant's resources
//!      even with crafted IDs, path traversal, unicode, or oversized IDs.
//!   2. AuthN/AuthZ: role and scope checks fail closed; missing session,
//!      expired session, wrong role → honest refusal (not 500, not silent empty).
//!   3. CSRF: every state-changing POST rejects missing/wrong/replayed tokens.
//!   4. Injection: XSS in every HTML sink; SQLi in every dynamic filter;
//!      header injection in email/redirects; path traversal in file/asset paths.
//!   5. SSRF: webhook/test URLs refuse loopback, link-local, metadata IPs,
//!      DNS-rebinding shapes.
//!   6. Secrets: tokens/API keys never appear in logs/HTML except reveal-once
//!      receipts; comparison is constant-time where required.
//!   7. Idempotency: double-submit of create/charge/send must not double-apply.
//!
//! Style matches the workspace adversarial suites (`enterprise/tests/
//! adversarial_deep.rs`, `billing-service/tests/coverage_adversarial.rs`):
//! each DB-backed test provisions its OWN canonical database through
//! `migrator::test_support::fresh_canonical_db`; a configured provisioning
//! failure panics, an unset `TEST_DATABASE_URL` soft-skips. Pure contracts
//! always run.

// ── Provisioning ────────────────────────────────────────────────────────

/// Provision a private canonical database for one test and return BOTH the
/// pool and the URL of THAT database — `create_pool_pair` in the app harness
/// must target the same per-test database as `pool`, never the base
/// `TEST_DATABASE_URL` (which would silently point AppState at the wrong DB).
async fn pool_for(_test: &str) -> Option<(sqlx::PgPool, String)> {
    let base_url = migrator::test_support::test_database_url()?;
    let db_only = base_url
        .rsplit_once('/')
        .map(|(_, d)| d.split('?').next().unwrap_or(d))
        .unwrap_or("apexmail")
        .to_string();
    // PostgreSQL identifiers cap at 63 bytes; a pure-UUID suffix stays well
    // under that even with a long base database name.
    let db_name = format!(
        "{db_only}_as{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    let pool = match migrator::test_support::fresh_canonical_db(&base_url, &db_name).await {
        Ok(Some(pool)) => pool,
        Ok(None) => panic!(
            "TEST_DATABASE_URL is configured but the canonical test database {db_name} \
             could not be provisioned"
        ),
        Err(error) => panic!("{}", error.panic_message()),
    };
    let url = migrator::test_support::database_url_for(&base_url, &db_name);
    Some((pool, url))
}

/// DB-backed test macro (workspace convention): soft-skips without
/// `TEST_DATABASE_URL`, panics on a configured-but-broken provision.
/// `$pool` binds the pool; `$url` binds the matching per-test database URL.
macro_rules! db_test {
    ($name:ident, $pool:ident, $url:ident, $body:block) => {
        #[tokio::test]
        async fn $name() {
            let Some(($pool, $url)) = pool_for(stringify!($name)).await else {
                eprintln!("skipping {}: no TEST_DATABASE_URL", stringify!($name));
                return;
            };
            $body
        }
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. CSRF — token forging / expiry / secret binding
// ═══════════════════════════════════════════════════════════════════════════

/// Invariant 3: every state-changing POST rejects missing/wrong/replayed
/// tokens. These pure cases attack the token verifier itself
/// (`api_server::routes::csrf::validate_csrf_token`) — the same function the
/// JSON surface and the `/web/*` form twin call.
mod csrf_token_contract {
    use api_server::routes::csrf::validate_csrf_token;
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    const SECRET: &str = "adversarial-csrf-secret-32-bytes!!";

    /// Mint a token whose nonce is the caller's, signed with `secret`.
    /// Mirrors `ui_foundation::csrf::generate_csrf_token` (the production
    /// mint path) so the verifier is tested against its real counterpart.
    fn mint(nonce: &str, secret: &str) -> String {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
        mac.update(nonce.as_bytes());
        let sig = engine.encode(mac.finalize().into_bytes());
        format!("{}.{}", engine.encode(nonce.as_bytes()), sig)
    }

    fn fresh_nonce() -> String {
        format!(
            "{}:{}",
            chrono::Utc::now().timestamp_millis(),
            uuid::Uuid::new_v4()
        )
    }

    #[test]
    fn forged_token_signed_with_wrong_secret_is_rejected() {
        // Attacker harvests a token minted for another deployment / steals a
        // token and re-signs its nonce under a secret they control.
        let nonce = fresh_nonce();
        let attacker_token = mint(&nonce, "attacker-controlled-secret-key!");
        let result = validate_csrf_token(&attacker_token, SECRET);
        assert!(
            result.is_err(),
            "a token signed with the wrong secret must not validate: {attacker_token}"
        );
    }

    #[test]
    fn empty_and_malformed_tokens_are_rejected() {
        for bad in [
            "",
            ".",
            "not-a-token",
            "only-one-part",
            "a.b.c",
            "....",
            "\u{0}",
            // Valid base64 halves but the wrong separator / empty sig.
            "AAAA.",
            ".AAAA",
        ] {
            assert!(
                validate_csrf_token(bad, SECRET).is_err(),
                "malformed CSRF token must be rejected: {bad:?}"
            );
        }
    }

    /// A signature minted under a DIFFERENT secret must never validate —
    /// including over an empty or non-timestamp nonce (the only way to pass
    /// the HMAC is to already hold the server secret).
    #[test]
    fn wrong_secret_cannot_forge_any_nonce_shape() {
        for nonce in ["", "not-a-timestamp", "0", "9999999999999"] {
            let forged = mint(nonce, "attacker-secret-key-32-bytes-long!");
            assert!(
                validate_csrf_token(&forged, SECRET).is_err(),
                "wrong-secret token over nonce {nonce:?} must not validate"
            );
        }
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let token = mint(&fresh_nonce(), SECRET);
        let (nonce_b64, sig_b64) = token.split_once('.').expect("two parts");
        // Flip the first signature character.
        let mut sig: Vec<u8> = sig_b64.bytes().collect();
        sig[0] = if sig[0] == b'A' { b'B' } else { b'A' };
        let tampered = format!(
            "{nonce_b64}.{}",
            String::from_utf8(sig).expect("ascii base64")
        );
        assert!(
            validate_csrf_token(&tampered, SECRET).is_err(),
            "a bit-flipped signature must not validate"
        );
    }

    #[test]
    fn signature_is_bound_to_the_exact_nonce() {
        let nonce_a = fresh_nonce();
        let nonce_b = fresh_nonce();
        let token_a = mint(&nonce_a, SECRET);
        let (_nonce_a_b64, sig_a) = token_a.split_once('.').expect("two parts");
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let swapped = format!("{}.{}", engine.encode(nonce_b.as_bytes()), sig_a);
        assert!(
            validate_csrf_token(&swapped, SECRET).is_err(),
            "reusing a signature under a different nonce must fail"
        );
    }

    #[test]
    fn expired_token_is_rejected() {
        // Two hours old — past the 1-hour window.
        let stale = format!(
            "{}:{}",
            chrono::Utc::now().timestamp_millis() - 2 * 3600 * 1000,
            uuid::Uuid::new_v4()
        );
        let token = mint(&stale, SECRET);
        let result = validate_csrf_token(&token, SECRET);
        assert!(result.is_err(), "an expired token must not validate");
        let message = format!("{}", result.unwrap_err());
        assert!(
            message.to_lowercase().contains("expired"),
            "the refusal must name expiry, got: {message}"
        );
    }

    #[test]
    fn far_future_token_is_rejected() {
        // A token stamped an hour into the future never expires under a
        // lower-bound-only check (audit J). It must be refused outright.
        let future = format!(
            "{}:{}",
            chrono::Utc::now().timestamp_millis() + 3600 * 1000,
            uuid::Uuid::new_v4()
        );
        let token = mint(&future, SECRET);
        let result = validate_csrf_token(&token, SECRET);
        assert!(
            result.is_err(),
            "a far-future-stamped token must not validate (never-expiring bypass)"
        );
    }

    #[test]
    fn fresh_token_round_trips() {
        // Positive control: the adversary suite must also catch over-blocking.
        let token = mint(&fresh_nonce(), SECRET);
        assert!(
            validate_csrf_token(&token, SECRET).is_ok(),
            "a fresh, correctly signed token must validate"
        );
        assert!(
            validate_csrf_token(&token, "a-different-secret-entirely!!").is_err(),
            "the same token must fail under a different secret"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. SSRF — URL / host / IP refusal shapes
// ═══════════════════════════════════════════════════════════════════════════

/// Invariant 5: webhook/test URLs refuse loopback, link-local, metadata IPs
/// (169.254.169.254), and DNS-rebinding shapes. The production predicates
/// under test are `devex_service::webhook_tester::is_private_ip` (the IP
/// arm) and `WebhookTester::send_test_webhook`'s URL guard (the host arm) —
/// if either shrinks, these fail.
mod ssrf_url_contract {
    use devex_service::webhook_tester::{is_private_ip, WebhookTester};
    use std::net::IpAddr;

    fn tester() -> WebhookTester {
        WebhookTester::new(vec!["whsec_adversarial_ssrf_secret_32ch!".into()])
            .expect("signing secret configured")
    }

    fn ip(v: &str) -> IpAddr {
        v.parse().expect("test IP literal")
    }

    /// URL shapes an attacker reaches for when probing cloud metadata,
    /// loopback services, or DNS-rebinding pivots. Each must be refused
    /// BEFORE any outbound connection.
    const HOSTILE_URLS: &[(&str, &str)] = &[
        ("http://127.0.0.1/hook", "loopback v4"),
        ("http://127.0.0.1:8080/hook", "loopback with port"),
        ("http://[::1]/hook", "loopback v6 literal"),
        (
            "http://169.254.169.254/latest/meta-data/",
            "AWS/GCP metadata",
        ),
        (
            "http://169.254.169.254/computeMetadata/v1/",
            "GCP metadata path",
        ),
        ("http://[::ffff:169.254.169.254]/hook", "mapped metadata"),
        ("http://[::ffff:127.0.0.1]/hook", "mapped loopback"),
        ("http://10.0.0.5/hook", "RFC1918"),
        ("http://192.168.1.1/hook", "RFC1918"),
        ("http://172.16.0.1/hook", "RFC1918"),
        ("http://0.0.0.0/hook", "unspecified"),
        ("http://localhost/hook", "localhost name"),
        (
            "http://metadata.google.internal/computeMetadata/v1/",
            "GCP metadata name",
        ),
        ("http://service.internal/hook", "internal hostname suffix"),
        ("http://printer.local/hook", "mDNS suffix"),
        // Decimal IPv4 form of 127.0.0.1 — WHATWG URL parsing normalises
        // this to the loopback address before the host check runs.
        ("http://2130706433/hook", "decimal-encoded loopback"),
        // Octal / hex encoded loopback shapes.
        ("http://0177.0.0.1/hook", "octal loopback"),
        ("http://0x7f.0.0.1/hook", "hex loopback"),
    ];

    #[tokio::test]
    async fn hostile_urls_are_refused_before_any_delivery() {
        let tester = tester();
        for (url, why) in HOSTILE_URLS {
            let result = tester.send_test_webhook(url, "message.delivered").await;
            assert!(
                result.is_err(),
                "{url} ({why}) must be refused by the SSRF guard, got: {result:?}"
            );
            // The refusal must be a validation-style error, not a transport
            // timeout (i.e. the guard fired BEFORE dialling).
            let error = result.unwrap_err().to_string();
            assert!(
                error.contains("private/internal")
                    || error.contains("not allowed")
                    || error.contains("Invalid webhook URL")
                    || error.contains("Only http/https")
                    || error.contains("must have a host")
                    || error.contains("could not be resolved"),
                "{url} ({why}) must fail the SSRF/URL guard, got: {error}"
            );
        }
    }

    #[tokio::test]
    async fn non_http_schemes_are_refused() {
        let tester = tester();
        for url in [
            "ftp://example.com/hook",
            "file:///etc/passwd",
            "gopher://example.com:70/",
            "dict://example.com:2628/",
            "javascript:alert(1)",
        ] {
            let result = tester.send_test_webhook(url, "message.delivered").await;
            assert!(result.is_err(), "non-HTTP scheme must be refused: {url}");
        }
    }

    #[test]
    fn ip_predicate_blocks_metadata_and_rebinding_wrappers() {
        for (ip_str, why) in [
            ("169.254.169.254", "cloud metadata"),
            ("169.254.0.1", "link-local"),
            ("127.0.0.1", "loopback"),
            ("::1", "loopback v6"),
            ("fe80::1", "v6 link-local"),
            ("fd00::1", "v6 unique-local"),
            ("::ffff:169.254.169.254", "v4-mapped metadata"),
            ("::ffff:127.0.0.1", "v4-mapped loopback"),
            ("100.64.0.1", "CGNAT"),
            ("0.0.0.0", "unspecified"),
        ] {
            assert!(
                is_private_ip(&ip(ip_str)),
                "{ip_str} ({why}) must be blocked — a dropped range is an SSRF hole"
            );
        }
        // Over-blocking breaks legitimate outbound webhooks.
        for ip_str in ["8.8.8.8", "1.1.1.1", "::ffff:8.8.8.8"] {
            assert!(
                !is_private_ip(&ip(ip_str)),
                "{ip_str} is public and must stay allowed"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Injection — XSS sinks, header injection, open redirect
// ═══════════════════════════════════════════════════════════════════════════

/// Invariant 4: XSS payloads must be escaped or stripped in every renderer
/// sink reachable from tenant-controlled strings (name / subject / html_body
/// / list name). Sinks under test: the template-renderer placeholder
/// pipeline and the ui-foundation list/text primitives.
mod xss_sink_contract {
    use template_renderer::transpiler::resolve_placeholders;

    /// Payload class: raw tags, event-handler breakouts, `javascript:`
    /// hrefs, SVG vectors, attribute-breakout quotes.
    const PAYLOADS: &[&str] = &[
        "<script>alert('xss')</script>",
        "\" onfocus=\"alert(1)\" autofocus=\"",
        "javascript:alert(1)",
        "<svg/onload=alert(1)>",
        "<img src=x onerror=\"alert(1)\">",
        "'><script>alert(String.fromCharCode(88,83,83))</script>",
        "<iframe src=\"javascript:alert(1)\"></iframe>",
    ];

    #[test]
    fn template_props_are_html_escaped_in_every_interpolation() {
        for payload in PAYLOADS {
            let html = format!("<p>Hello {{{{ name }}}} — {{{{ subject }}}}</p>");
            let props = serde_json::json!({
                "name": payload,
                "subject": payload,
            });
            let rendered = resolve_placeholders(&html, &props);
            assert!(
                !rendered.contains(payload),
                "raw XSS payload leaked into rendered HTML: {payload} → {rendered}"
            );
            // The escaped form must be present for tag-shaped payloads.
            if payload.contains('<') {
                assert!(
                    rendered.contains("&lt;") || rendered.contains("&#x27;"),
                    "tag payload must appear escaped: {payload} → {rendered}"
                );
            }
        }
    }

    #[test]
    fn javascript_urls_are_neutralised_in_href_src() {
        for payload in [
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            "javascript&colon;alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ] {
            let html = format!("<a href=\"{{{{ link }}}}\">x</a>");
            let props = serde_json::json!({ "link": payload });
            let rendered = resolve_placeholders(&html, &props);
            assert!(
                !rendered.to_lowercase().contains("javascript:"),
                "javascript: URI must be neutralised in href: {payload} → {rendered}"
            );
            assert!(
                !rendered.to_lowercase().contains("data:text/html"),
                "data:text/html URI must be neutralised in href: {payload} → {rendered}"
            );
        }
    }

    #[test]
    fn list_row_text_cannot_break_out_of_cells() {
        use ui_foundation::view_data::{DataCell, DataRowData, ListPageData, TableData};

        for payload in PAYLOADS {
            let mut data = ListPageData {
                title: "Lists".into(),
                description: "d".into(),
                base_path: "/lists".into(),
                ..Default::default()
            };
            data.table = Some(TableData {
                columns: vec!["Name".into()],
                rows: vec![DataRowData {
                    id: "l1".into(),
                    cells: vec![DataCell::text(payload)],
                }],
            });
            let html = ui_foundation::leptos_views::data_list_page(&data, "list");
            assert!(
                !html.contains(payload),
                "list cell leaked raw XSS payload: {payload}"
            );
            if payload.contains('<') {
                assert!(
                    html.contains("&lt;"),
                    "list cell must escape tags: {payload} → {html}"
                );
            }
        }
    }

    #[test]
    fn select_option_labels_and_values_cannot_break_out() {
        use ui_foundation::primitives::{NativeSelect, SelectOption};

        for payload in PAYLOADS {
            let html = NativeSelect {
                id: "id1",
                name: "list_ids",
                options: vec![SelectOption {
                    value: payload,
                    label: payload,
                    disabled: false,
                    selected: true,
                }],
                required: false,
                multiple: true,
                size: Some(4),
            }
            .render_html();
            assert!(
                !html.contains(payload),
                "select markup leaked raw XSS payload: {payload} → {html}"
            );
            if payload.contains('"') || payload.contains('<') {
                assert!(
                    html.contains("&quot;") || html.contains("&lt;"),
                    "select markup must escape attribute/tag metas: {payload} → {html}"
                );
            }
        }
    }
}

/// Invariant 4 (header injection / open redirect arm): CR/LF/NUL must never
/// survive into a header-bound string, and redirect targets must refuse
/// open-redirect shapes.
mod header_and_redirect_contract {
    use api_server::routes::web::consent_safe_return_to;
    use template_renderer::transpiler::strip_header_control_chars;

    #[test]
    fn header_bound_strings_lose_crlf_and_nul() {
        for (raw, must_not_contain) in [
            ("Subject\r\nBcc: attacker@evil.com", "\r"),
            ("Subject\r\nBcc: attacker@evil.com", "\n"),
            ("name\u{0}injected", "\u{0}"),
            ("a\r\nb\r\nc", "\r\n"),
        ] {
            let cleaned = strip_header_control_chars(raw);
            assert!(
                !cleaned.contains(must_not_contain),
                "header-bound string still carries {must_not_contain:?}: {cleaned:?}"
            );
        }
        // Readable text must survive (only the control bytes are stripped).
        assert_eq!(
            strip_header_control_chars("Hello World"),
            "Hello World",
            "clean text must be untouched"
        );
        // CRLF becomes spaces — the visible text stays, the injection dies.
        let mixed = strip_header_control_chars("Hello\r\nWorld");
        assert!(
            !mixed.contains('\r') && !mixed.contains('\n'),
            "CRLF must be gone: {mixed:?}"
        );
        assert!(mixed.contains("Hello") && mixed.contains("World"));
    }

    #[test]
    fn open_redirect_shapes_fall_back_to_root() {
        // Same-origin relative paths survive; every hop-away shape is "/".
        assert_eq!(consent_safe_return_to(Some("/dashboard")), "/dashboard");
        assert_eq!(consent_safe_return_to(None), "/");
        assert_eq!(consent_safe_return_to(Some("")), "/");
        for evil in [
            "//evil.com/steal",
            "/\\evil.com",
            "https://evil.com/",
            "http://apexmail.ee/upgrade", // plain HTTP is never a safe hop
            "https://evil-apexmail.ee/",
            "https://apexmail.ee.evil.com/",
            "javascript:alert(1)",
            "/path\r\nSet-Cookie: session=hijacked",
            "/path\nLocation: https://evil.com",
            "https://attacker@apexmail.ee/",
        ] {
            assert_eq!(
                consent_safe_return_to(Some(evil)),
                "/",
                "hostile return_to must fall back to / : {evil}"
            );
        }
        // Absolute HTTPS on the apexmail.ee family is the one allowed hop.
        assert_eq!(
            consent_safe_return_to(Some("https://app.apexmail.ee/campaigns")),
            "https://app.apexmail.ee/campaigns"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. AuthZ — scope fail-closed + Free-plan entitlement
// ═══════════════════════════════════════════════════════════════════════════

/// Invariant 2: role and scope checks fail closed. A `messages:read` key
/// cannot send; a `contacts:read` key cannot write; an empty scope set can
/// do nothing; substring/prefix lookalikes do not match.
mod authz_scope_contract {
    use api_server::middleware::auth::{require_scopes, AuthUser};

    fn key_with(scopes: &[&str]) -> AuthUser {
        AuthUser {
            tenant_id: "ten_adv".into(),
            user_id: None,
            api_key_id: Some("key_adv".into()),
            session_id: None,
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[test]
    fn messages_read_cannot_send() {
        let reader = key_with(&["messages:read"]);
        let result = require_scopes(&reader, &["messages:send"]);
        assert!(result.is_err(), "messages:read must not authorize send");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("messages:send"),
            "refusal must name the missing scope: {msg}"
        );
    }

    #[test]
    fn contacts_read_cannot_write() {
        let reader = key_with(&["contacts:read"]);
        assert!(
            require_scopes(&reader, &["contacts:write"]).is_err(),
            "contacts:read must not authorize write"
        );
    }

    #[test]
    fn empty_scope_set_denies_everything() {
        let none = key_with(&[]);
        for scope in [
            "messages:read",
            "messages:send",
            "contacts:write",
            "api-keys:write",
            "admin:delete",
        ] {
            assert!(
                require_scopes(&none, &[scope]).is_err(),
                "empty scopes must deny {scope}"
            );
        }
    }

    #[test]
    fn lookalike_scopes_never_match() {
        // Substring and prefix tricks against the exact-match contract.
        for (held, required) in [
            ("messages:read_all", "messages:read"),
            ("messages:", "messages:read"),
            ("*read", "messages:read"),
            ("messages:read ", "messages:read"), // trailing space
            ("MESSAGES:READ", "messages:read"),  // case
            ("messages:read\u{0}", "messages:read"),
        ] {
            let user = key_with(&[held]);
            assert!(
                require_scopes(&user, &[required]).is_err(),
                "held scope {held:?} must NOT satisfy required {required:?}"
            );
        }
    }

    #[test]
    fn partial_matrix_is_insufficient() {
        // Holding one of two required scopes is a refusal, not a partial grant.
        let user = key_with(&["messages:read"]);
        assert!(
            require_scopes(&user, &["messages:read", "messages:send"]).is_err(),
            "partial match must deny"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. Secrets — constant-time compare + reveal-once DTO shapes
// ═══════════════════════════════════════════════════════════════════════════

/// Invariant 6: secret material is compared in constant time where required,
/// and the list/get DTOs structurally cannot carry the raw credential.
mod secrets_contract {
    use api_server::middleware::auth::AuthUser;
    use api_server::routes::auth::{ApiKeyInfo, CreateApiKeyResponse};

    #[test]
    fn timing_safe_compare_fails_closed_on_mismatch_and_length() {
        let compare = apexmail_lib::crypto::timing_safe_compare;
        assert!(compare("same-value", "same-value"));
        assert!(!compare("same-value", "same-valuf"), "one-char diff");
        assert!(!compare("short", "shorter"), "length diff");
        assert!(!compare("", "a"), "empty vs non-empty");
        assert!(compare("", ""), "two empties match");
        // A secret compared against a prefix of itself must not match.
        let secret = "am_live_super_secret_token";
        assert!(!compare(secret, "am_live_super_secret"), "prefix");
        assert!(!compare("am_live_super_secret", secret), "prefix reversed");
    }

    #[test]
    fn api_key_list_dto_cannot_serialize_a_secret() {
        // `ApiKeyInfo` has no `key` field at all — serialize and assert the
        // raw-secret shape is structurally absent from the list/get surface.
        let info = ApiKeyInfo {
            id: "key-1".into(),
            name: "prod".into(),
            key_prefix: "am_live_…abcd".into(),
            scopes: serde_json::json!(["messages:send"]),
            last_used_at: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            expires_at: None,
        };
        let json = serde_json::to_string(&info).expect("serialize");
        assert!(
            !json.contains("\"key\""),
            "list DTO must not carry a `key` field: {json}"
        );
        assert!(
            !json.contains("am_live_"),
            "list DTO must not carry raw key material (prefix display only): {json}"
        );
    }

    #[test]
    fn create_response_is_the_only_reveal_surface() {
        // The create receipt is allowed to carry the secret ONCE. Pin the
        // shape so a future DTO merge cannot quietly re-expose it elsewhere.
        let receipt = CreateApiKeyResponse {
            id: "key-1".into(),
            key: "am_live_REDACTED_FOR_TEST".into(),
            key_prefix: "am_live_…abcd".into(),
            name: "prod".into(),
            scopes: vec!["messages:send".into()],
            created_at: "2026-01-01T00:00:00Z".into(),
            expires_at: Some("2026-04-01T00:00:00Z".into()),
        };
        let json = serde_json::to_string(&receipt).expect("serialize");
        assert!(
            json.contains("am_live_REDACTED_FOR_TEST"),
            "create receipt must carry the once-shown secret: {json}"
        );
        // And the list DTO — serializing a sibling — must not.
        let list_item = ApiKeyInfo {
            id: "key-1".into(),
            name: "prod".into(),
            key_prefix: "am_live_…abcd".into(),
            scopes: serde_json::json!(["messages:send"]),
            last_used_at: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            expires_at: None,
        };
        let list_json = serde_json::to_string(&list_item).expect("serialize");
        assert!(
            !list_json.contains("am_live_REDACTED_FOR_TEST"),
            "list DTO must never echo the revealed secret"
        );
    }

    #[test]
    fn auth_user_debug_redacts_identity() {
        // RS-H-06: Debug output must not dump full tenant/user/session ids.
        let user = AuthUser {
            tenant_id: "ten_super_secret_tenant_id".into(),
            user_id: Some("usr_super_secret_user_id".into()),
            api_key_id: Some("key_super_secret_key_id".into()),
            session_id: Some("ses_super_secret_session_id".into()),
            scopes: vec!["*".into()],
        };
        let debug = format!("{user:?}");
        assert!(
            !debug.contains("ten_super_secret_tenant_id"),
            "Debug must redact the full tenant id: {debug}"
        );
        assert!(
            !debug.contains("usr_super_secret_user_id"),
            "Debug must redact the full user id: {debug}"
        );
        assert!(
            debug.contains("REDACTED"),
            "session_id must print as REDACTED: {debug}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// DB-backed adversarial HTTP suite
// ═══════════════════════════════════════════════════════════════════════════

/// Shared harness for the DB-backed half: the REAL `build_app` router over a
/// canonical database, with two hostile tenants and their API keys.
mod db_harness {
    use api_server::{
        app::build_app,
        config::{Config, Environment},
        ses_provider::SesIpProvider,
        state::AppStateInner,
    };
    use axum::Router;
    use deadpool_redis::Config as RedisConfig;
    use sqlx::PgPool;
    use std::sync::{Mutex, Once};

    pub fn test_config() -> Config {
        Config {
            ai_service_base_url: String::new(),
            cp_auth: Default::default(),
            pdf_renderer_auth_token: None,
            template_renderer_auth_token: None,
            devex_auth_token: None,
            ai_embeddings_auth_token: None,
            public_rate_limit_enabled: false,
            port: 3000,
            host: "0.0.0.0".into(),
            base_url: "http://localhost:3000".into(),
            environment: Environment::Development,
            db_host: "localhost".into(),
            db_port: 5432,
            db_name: "apexmail".into(),
            db_user: "apexmail".into(),
            db_password: "password".into(),
            db_max_connections: 20,
            api_replica_count: 1,
            db_cluster_connection_budget: None,
            expected_replica_count: 3,
            statement_cache_capacity: 500,
            query_timeout_seconds: 30,
            database_replica_url: None,
            redis_host: "localhost".into(),
            redis_port: 6379,
            redis_password: None,
            redis_db: 0,
            redis_pool_max_size: 40,
            jwt_private_key_pem: "BEGIN TEST".into(),
            jwt_public_key_pem: "BEGIN TEST".into(),
            jwt_previous_public_keys_pem: vec![],
            jwt_expiry: std::time::Duration::from_secs(86_400),
            api_key_hash_secret: "test-api-key-secret-12345678901234567890".into(),
            rate_limit_window_ms: 60_000,
            rate_limit_max_requests: 1_000_000,
            max_inflight_requests: 80,
            cors_origins: vec!["*".into()],
            trusted_proxies: vec![],
            ui_web_hosts: vec!["app.apexmail.ee".into(), "localhost".into()],
            ui_control_plane_hosts: vec!["admin.apexmail.ee".into()],
            ui_marketing_hosts: vec!["apexmail.ee".into()],
            ui_marketing_surface: "marketing-zola".into(),
            ui_default_surface: Some("web".into()),
            webhook_signing_secret: "test-webhook-signing-secret-1234567890".into(),
            webhook_timeout_ms: 5_000,
            webhook_max_retries: 10,
            idempotency_ttl_seconds: 86_400,
            aws_region: "us-east-1".into(),
            ses_ip_pool_prefix: "apexmail".into(),
            ses_default_warmup_days: 14,
            ses_configuration_set: None,
            google_client_id: None,
            google_client_secret: None,
            github_client_id: None,
            github_client_secret: None,
            oauth_redirect_base_url: "http://localhost:3000".into(),
            billing_company_iban: "EE381010220123456789".into(),
            billing_company_phone: "+3721234567".into(),
            session_secret: "test-session-secret-1234567890ab".into(),
            impersonation_secret: "test-impersonation-secret-12345".into(),
            csrf_secret: "test-csrf-secret-1234567890abcd".into(),
            control_plane_api_key: None,
            sales_autopilot_base_url: "http://localhost:3010".into(),
            internal_service_token: None,
            tracking_secret_key: "test-tracking-secret-123456789012".into(),
            metrics_port: 9090,
            grader_enabled: false,
            grader_rate_limit: 10,
            grader_rate_window_seconds: 60,
            grader_cache_ttl_seconds: 300,
            grader_max_body_size: 1_048_576,
            placement_enabled: false,
            placement_polling_interval_secs: 60,
            placement_max_polling_attempts: 60,
            placement_max_seeds_per_test: 50,
            placement_max_tests_per_hour: 10,
            placement_imap_timeout_secs: 30,
            placement_encrypt_passwords: false,
            placement_encryption_secret: "test-placement-encryption-secret-32b".into(),
            http_client_timeout_secs: 10,
            internal_tls_enabled: false,
            internal_tls_ca_cert_path: None,
            internal_tls_client_cert_path: None,
            internal_tls_client_key_path: None,
            kiwi_enabled: false,
            kiwi_secret_key: "dev".into(),
            waf_enabled: false,
            waf_enforce: false,
            kiwi_algorithm: kiwicaptcha::PoWAlgorithm::Sha256,
            kiwi_argon_m_kib: 0,
            kiwi_argon_t: 2,
            kiwi_argon_p: 1,
            kiwi_difficulty_bits: 16,
            kiwi_argon2_difficulty_bits: 8,
            kiwi_challenge_ttl_secs: 120,
            kiwi_min_duration_ms: None,
            kiwi_enforce_telemetry: true,
            kiwi_argon2_max_concurrent: 2,
            kiwi_auto_tune: false,
            kiwi_auto_tune_min_bits: 10,
            kiwi_auto_tune_max_bits: 24,
        }
    }

    static AWS_ENV_LOCK: Mutex<()> = Mutex::new(());
    static AWS_ONCE: Once = Once::new();

    fn ensure_aws_test_env() {
        let _guard = AWS_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        AWS_ONCE.call_once(|| {
            std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
            if std::env::var("AWS_ACCESS_KEY_ID").is_err() {
                std::env::set_var("AWS_ACCESS_KEY_ID", "test");
            }
            if std::env::var("AWS_SECRET_ACCESS_KEY").is_err() {
                std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
            }
        });
    }

    /// Soft-skip gate for behaviours whose production guarantee is
    /// Redis-backed (idempotency cache). Unset/unreachable `TEST_REDIS_URL`
    /// returns false and the caller early-returns — the same contract the
    /// session env harness uses. A configured-but-broken Redis is still a
    /// soft skip here (the middleware itself fails open when Redis is down;
    /// the durable send-ledger is the other arm of that contract).
    pub async fn redis_available() -> bool {
        let Ok(url) = std::env::var("TEST_REDIS_URL") else {
            return false;
        };
        if url.trim().is_empty() {
            return false;
        }
        let Ok(pool) =
            RedisConfig::from_url(&url).create_pool(Some(deadpool_redis::Runtime::Tokio1))
        else {
            return false;
        };
        let Ok(mut conn) = pool.get().await else {
            return false;
        };
        deadpool_redis::redis::cmd("PING")
            .query_async::<String>(&mut *conn)
            .await
            .is_ok()
    }

    /// Two tenants, each with an API key. `database_url` MUST be the URL of
    /// the same database `pool` is connected to. Returns
    /// (app, pool, a_key, a_tenant, b_key, b_tenant).
    pub async fn two_tenant_app(
        pool: PgPool,
        database_url: &str,
    ) -> (Router, PgPool, String, String, String, String) {
        ensure_aws_test_env();

        let tenant_a = seed_tenant(&pool, "adva").await;
        let tenant_b = seed_tenant(&pool, "advb").await;
        let key_a = seed_api_key(&pool, &tenant_a, &["*"]).await;
        let key_b = seed_api_key(&pool, &tenant_b, &["*"]).await;

        let pools = apexmail_db::pool::create_pool_pair(database_url, None, 2, 0)
            .await
            .expect("pool pair");
        let redis_url =
            std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:1".to_string());
        let redis = RedisConfig::from_url(&redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("lazy redis pool");

        let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_sesv2::config::Region::new("us-east-1"))
            .load()
            .await;
        let ses_provider = SesIpProvider::new(
            aws_sdk_sesv2::Client::new(&aws_config),
            pool.clone(),
            "apexmail".into(),
            "us-east-1".into(),
        );

        let state = AppStateInner::new(
            pool.clone(),
            pools,
            redis,
            test_config(),
            reqwest::Client::new(),
            ses_provider,
            None,
        )
        .await
        .expect("app state");
        (build_app(state), pool, key_a, tenant_a, key_b, tenant_b)
    }

    pub async fn seed_tenant(pool: &PgPool, prefix: &str) -> String {
        let id = apexmail_lib::id::generate_id(prefix, 20);
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
             VALUES ($1, 'adversarial tenant', $2, 'free', 'active', NOW(), NOW())",
        )
        .bind(&id)
        .bind(format!("slug-{id}"))
        .execute(pool)
        .await
        .expect("seed tenant");
        id
    }

    pub async fn seed_api_key(pool: &PgPool, tenant_id: &str, scopes: &[&str]) -> String {
        let raw_key = apexmail_lib::id::generate_api_key(true);
        let key_hash = apexmail_lib::hash_api_key_with_secret(
            &raw_key,
            "test-api-key-secret-12345678901234567890",
        );
        sqlx::query(
            "INSERT INTO api_keys (id, tenant_id, name, key_prefix, key_hash, scopes, created_at, updated_at)
             VALUES ($1, $2, 'adversarial fixture', 'am_test_', $3, $4::jsonb, NOW(), NOW())",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(tenant_id)
        .bind(&key_hash)
        .bind(serde_json::json!(scopes).to_string())
        .execute(pool)
        .await
        .expect("seed api key");
        raw_key
    }

    /// Seed a resource row owned by `tenant_id` and return its id.
    pub async fn seed_template(pool: &PgPool, tenant_id: &str, name: &str) -> String {
        let id = apexmail_lib::id::generate_id("", 26);
        sqlx::query(
            "INSERT INTO templates (id, tenant_id, name, subject, html_body, version, status, created_at, updated_at)
             VALUES ($1, $2, $3, 'subj', '<p>ok</p>', 1, 'active', NOW(), NOW())",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(name)
        .execute(pool)
        .await
        .expect("seed template");
        id
    }

    pub async fn seed_contact(pool: &PgPool, tenant_id: &str, email: &str) -> uuid::Uuid {
        let id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO contacts (id, tenant_id, email, name, status, created_at, updated_at)
             VALUES ($1, $2, $3, 'Adv Contact', 'subscribed', NOW(), NOW())",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(email)
        .execute(pool)
        .await
        .expect("seed contact");
        id
    }

    /// Grant one runtime feature through the same override table the admin
    /// surface writes (e.g. "webhooks_enabled", "custom_templates"). Lets an
    /// SSRF test reach URL validation instead of dying on the plan gate.
    pub async fn grant_feature(pool: &PgPool, tenant_id: &str, flag_key: &str) {
        sqlx::query(
            "INSERT INTO feature_flag_overrides (flag_key, tenant_id, tenant_name, value, created_at)
             VALUES ($1, $2, $3, 'true'::jsonb, NOW())",
        )
        .bind(flag_key)
        .bind(tenant_id)
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("grant feature override");
    }

    pub fn get(path: &str, key: &str) -> Request<Body> {
        Request::get(path)
            .header("x-api-key", key)
            .body(Body::empty())
            .unwrap()
    }

    pub fn post_json(path: &str, key: &str, body: serde_json::Value) -> Request<Body> {
        Request::post(path)
            .header("x-api-key", key)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    pub fn post_json_with_headers(
        path: &str,
        key: &str,
        body: serde_json::Value,
        extra: &[(&str, &str)],
    ) -> Request<Body> {
        let mut builder = Request::post(path)
            .header("x-api-key", key)
            .header("content-type", "application/json");
        for (name, value) in extra {
            builder = builder.header(*name, *value);
        }
        builder
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    pub async fn body_text(resp: axum::http::Response<Body>) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8_lossy(&bytes).to_string()
    }
}

// ─── Invariant 1: tenant isolation + path/ID abuse ──────────────────────

mod cross_tenant_and_ids {
    use super::db_harness::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    /// A token from tenant A + a resource id from tenant B must never return
    /// B's data. 403/404 only — never 200 with foreign bytes.
    db_test!(cross_tenant_reads_are_404_never_200, pool, db_url, {
        let (app, pool, key_a, _ten_a, key_b, ten_b) = two_tenant_app(pool, &db_url).await;

        let tpl_b = seed_template(&pool, &ten_b, "tenant-b-secret-template").await;
        let contact_b = seed_contact(&pool, &ten_b, "b-secret@example.com").await;

        // Template read with A's token.
        let resp = app
            .clone()
            .oneshot(get(&format!("/v1/templates/{tpl_b}"), &key_a))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "cross-tenant template read must be 404, got {}",
            resp.status()
        );
        let text = body_text(resp).await;
        assert!(
            !text.contains("tenant-b-secret-template"),
            "foreign template name leaked: {text}"
        );

        // Contact read with A's token.
        let resp = app
            .clone()
            .oneshot(get(&format!("/v1/contacts/{contact_b}"), &key_a))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let text = body_text(resp).await;
        assert!(
            !text.contains("b-secret@example.com"),
            "foreign contact email leaked: {text}"
        );

        // Sanity: B can still read its own row (the refusal is isolation,
        // not a broken route).
        let resp = app
            .clone()
            .oneshot(get(&format!("/v1/templates/{tpl_b}"), &key_b))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "owner must still read its own template"
        );
    });

    db_test!(
        cross_tenant_writes_are_404_and_leave_the_row_untouched,
        pool,
        db_url,
        {
            let (app, pool, key_a, _ten_a, _key_b, ten_b) = two_tenant_app(pool, &db_url).await;
            let tpl_b = seed_template(&pool, &ten_b, "untouchable").await;

            // A tries to overwrite B's template (PUT /v1/templates/:id is the
            // update verb — see templates::router).
            let resp = app
                .clone()
                .oneshot(
                    Request::put(format!("/v1/templates/{tpl_b}"))
                        .header("x-api-key", &key_a)
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&serde_json::json!({
                                "name": "pwned",
                                "subject": "pwned",
                                "html_body": "<p>pwned</p>"
                            }))
                            .unwrap(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "cross-tenant template update must be 404, got {}",
                resp.status()
            );
            let name: String =
                sqlx::query_scalar("SELECT name FROM templates WHERE id = $1 AND tenant_id = $2")
                    .bind(&tpl_b)
                    .bind(&ten_b)
                    .fetch_one(&pool)
                    .await
                    .expect("re-read template");
            assert_eq!(name, "untouchable", "cross-tenant write mutated the row");
        }
    );

    db_test!(cross_tenant_api_key_revoke_is_404, pool, db_url, {
        let (app, pool, key_a, _ten_a, key_b, ten_b) = two_tenant_app(pool, &db_url).await;

        // Seed an extra key for B and try to revoke it with A's token.
        let b_extra = seed_api_key(&pool, &ten_b, &["messages:read"]).await;
        let b_extra_id: String =
            sqlx::query_scalar("SELECT id::text FROM api_keys WHERE key_hash = $1")
                .bind(apexmail_lib::hash_api_key_with_secret(
                    &b_extra,
                    "test-api-key-secret-12345678901234567890",
                ))
                .fetch_one(&pool)
                .await
                .expect("lookup key id");

        let resp = app
            .clone()
            .oneshot(
                Request::delete(format!("/v1/auth/api-keys/{b_extra_id}"))
                    .header("x-api-key", &key_a)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "cross-tenant API key revoke must be 404"
        );

        // The key still authenticates — the revoke did not land.
        let resp = app
            .clone()
            .oneshot(get("/v1/contacts", &key_b))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "victim key must still work after a cross-tenant revoke attempt"
        );
    });

    /// Crafted path IDs: `../`, `..%2f`, NUL, 10k-char, UUID case variants,
    /// unicode homoglyphs. Every one must be a controlled 400/404 — never a
    /// 500 (that is a parse-bug signal) and never another tenant's row.
    db_test!(crafted_path_ids_never_500_or_leak, pool, db_url, {
        let (app, _pool, key_a, _ten_a, _key_b, _ten_b) = two_tenant_app(pool, &db_url).await;

        let hostile_ids: Vec<String> = vec![
            "../".into(),
            "..%2f".into(),
            "..%2f..%2f..%2fetc%2fpasswd".into(),
            "%00".into(),
            "1\u{0}2".into(),
            "a".repeat(10_000),
            // UUID case variants of a syntactically valid id.
            "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE".into(),
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
            // Homoglyph / RTL / zero-width shapes.
            "\u{202E}admin".into(),
            "ten\u{200B}ant".into(),
            "\u{FF41}\u{FF44}\u{FF4D}\u{FF49}\u{FF4E}".into(),
            // Percent-encoded traversal and SQL-ish id abuse.
            "%2e%2e%2f".into(),
            "' OR 1=1--".into(),
            "1; DROP TABLE templates;--".into(),
        ];

        for id in hostile_ids {
            for path in [
                format!("/v1/templates/{id}"),
                format!("/v1/contacts/{id}"),
                format!("/v1/domains/{id}"),
                format!("/v1/campaigns/{id}"),
            ] {
                let resp = app.clone().oneshot(get(&path, &key_a)).await.unwrap();
                let status = resp.status();
                assert!(
                    status == StatusCode::BAD_REQUEST
                        || status == StatusCode::NOT_FOUND
                        || status == StatusCode::UNPROCESSABLE_ENTITY,
                    "crafted id must be a controlled 4xx on {path}, got {status}"
                );
                assert_ne!(
                    status,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "crafted id must never surface as 500 on {path}"
                );
                let text = body_text(resp).await;
                assert!(
                    !text.contains("tenant-b")
                        && !text.contains("secret")
                        && !text.contains("password")
                        && !text.contains("pg::"),
                    "error body leaked internals on {path}: {text}"
                );
            }
        }
    });
}

// ─── Invariant 3 (HTTP): CSRF on /web/* form POSTs ─────────────────────

mod csrf_web_forms {
    use super::db_harness::*;
    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    use tower::ServiceExt;

    /// POST /web/auth/login without `_csrf`, with an empty `_csrf`, and with
    /// a wrong-secret signature. All three must refuse with the PRG "session
    /// expired" flash and must NOT set a session cookie.
    db_test!(
        web_login_rejects_missing_empty_and_forged_csrf,
        pool,
        db_url,
        {
            let (app, _pool, _key_a, _ten_a, _key_b, _ten_b) = two_tenant_app(pool, &db_url).await;

            let cases: Vec<(&str, String)> = vec![
                ("missing", "email=a%40b.com&password=x".to_string()),
                ("empty", "email=a%40b.com&password=x&_csrf=".to_string()),
                (
                    "forged",
                    format!(
                        "email=a%40b.com&password=x&_csrf={}",
                        ui_foundation::csrf::generate_csrf_token(
                            "attacker-secret-not-the-server-secret"
                        )
                    ),
                ),
                (
                    "garbage",
                    "email=a%40b.com&password=x&_csrf=not.a.token".to_string(),
                ),
            ];

            for (label, form_body) in cases {
                let resp = app
                    .clone()
                    .oneshot(
                        Request::post("/web/auth/login")
                            .header("content-type", "application/x-www-form-urlencoded")
                            .body(Body::from(form_body))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let status = resp.status();
                assert_eq!(
                    status,
                    StatusCode::SEE_OTHER,
                    "CSRF-{label}: form POST must PRG-redirect on CSRF failure, got {status}"
                );
                // No session cookie may be issued on a CSRF refusal.
                let set_cookies: Vec<String> = resp
                    .headers()
                    .get_all(header::SET_COOKIE)
                    .iter()
                    .filter_map(|v| v.to_str().ok().map(str::to_string))
                    .collect();
                assert!(
                    !set_cookies.iter().any(|c| c.starts_with("am_session=")),
                    "CSRF-{label}: a refused POST must not set am_session: {set_cookies:?}"
                );
                // The refusal is the honest "session expired" flash, not a 500.
                let flash_cookie = set_cookies
                    .iter()
                    .find(|c| c.contains("apexmail_flash="))
                    .cloned();
                if let Some(cookie) = flash_cookie {
                    let flashes = api_server::routes::web::decode_flash_from_cookie_header(
                        &cookie,
                        &test_config().csrf_secret,
                    );
                    let text = flashes
                        .iter()
                        .map(|f| f.text.as_str())
                        .collect::<Vec<_>>()
                        .join(" ");
                    assert!(
                        text.to_lowercase().contains("session expired")
                            || text.to_lowercase().contains("reload"),
                        "CSRF-{label}: flash must name the CSRF refusal, got: {text:?}"
                    );
                }
            }
        }
    );

    /// Replayed token: a VALID token whose `_csrf` value does not match the
    /// double-submit cookie is refused (the cookie is the browser binding).
    db_test!(web_login_rejects_token_cookie_mismatch, pool, db_url, {
        let (app, _pool, _key_a, _ten_a, _key_b, _ten_b) = two_tenant_app(pool, &db_url).await;

        let token = ui_foundation::csrf::generate_csrf_token(&test_config().csrf_secret);
        let other_token = ui_foundation::csrf::generate_csrf_token(&test_config().csrf_secret);

        let resp = app
            .clone()
            .oneshot(
                Request::post("/web/auth/login")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("cookie", &format!("csrf_token={other_token}"))
                    .body(Body::from(format!(
                        "email=a%40b.com&password=x&_csrf={token}"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SEE_OTHER,
            "token/cookie mismatch must refuse"
        );
        let set_cookies: Vec<String> = resp
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_string))
            .collect();
        assert!(
            !set_cookies.iter().any(|c| c.starts_with("am_session=")),
            "token/cookie mismatch must not set am_session"
        );
    });
}

// ─── Invariant 2 (HTTP): scope + Free-plan entitlement ─────────────────

mod authz_http {
    use super::db_harness::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    db_test!(read_scopes_cannot_send_or_write_over_http, pool, db_url, {
        let (app, _pool, _key_a, ten_a, _key_b, _ten_b) = two_tenant_app(pool, &db_url).await;
        let reader = seed_api_key(&pool, &ten_a, &["messages:read", "contacts:read"]).await;

        // messages:read cannot POST /v1/messages.
        let resp = app
            .clone()
            .oneshot(post_json(
                "/v1/messages",
                &reader,
                serde_json::json!({
                    "from": "a@example.com",
                    "to": ["b@example.com"],
                    "subject": "s",
                    "text": "t"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "messages:read must not send, got {}",
            resp.status()
        );
        let text = body_text(resp).await;
        assert!(
            text.contains("messages:send"),
            "refusal must name the missing scope: {text}"
        );

        // contacts:read cannot POST /v1/contacts.
        let resp = app
            .clone()
            .oneshot(post_json(
                "/v1/contacts",
                &reader,
                serde_json::json!({ "email": "new@example.com" }),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "contacts:read must not write, got {}",
            resp.status()
        );
    });

    db_test!(free_plan_cannot_use_custom_templates, pool, db_url, {
        let (app, _pool, key_free, ten_free, _key_b, _ten_b) = two_tenant_app(pool, &db_url).await;
        // two_tenant_app already seeds `plan='free'`. A templates:write key
        // still hits the custom_templates entitlement gate.
        let writer = seed_api_key(&pool, &ten_free, &["templates:write", "templates:read"]).await;
        let _ = key_free;

        let resp = app
            .clone()
            .oneshot(post_json(
                "/v1/templates",
                &writer,
                serde_json::json!({
                    "name": "Adv Template",
                    "subject": "Hello",
                    "html_body": "<p>hi</p>"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "Free plan must not create custom templates, got {}",
            resp.status()
        );
        let text = body_text(resp).await;
        assert!(
            !text.contains("Adv Template"),
            "a refused create must not echo stored state: {text}"
        );
    });

    db_test!(missing_api_key_is_401_not_empty_200, pool, db_url, {
        let (app, _pool, _key_a, _ten_a, _key_b, _ten_b) = two_tenant_app(pool, &db_url).await;

        for path in [
            "/v1/contacts",
            "/v1/templates",
            "/v1/messages",
            "/v1/domains",
            "/v1/auth/api-keys",
        ] {
            let resp = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "unauthenticated GET {path} must be 401, got {}",
                resp.status()
            );
            let text = body_text(resp).await;
            // Honest refusal — not a silent empty list.
            assert!(
                text.contains("authentication") || text.contains("missing") || text.contains("401"),
                "unauthenticated {path} must explain the refusal: {text}"
            );
        }
    });
}

// ─── Invariant 4 (HTTP): XSS + SQLi shapes in live surfaces ────────────

mod injection_http {
    use super::db_harness::*;
    use axum::http::StatusCode;
    use tower::ServiceExt;

    db_test!(sqli_shapes_in_filters_do_not_error_or_leak, pool, db_url, {
        let (app, _pool, key_a, _ten_a, _key_b, _ten_b) = two_tenant_app(pool, &db_url).await;

        let payloads = [
            "' OR 1=1--",
            "'; DROP TABLE contacts;--",
            "%00",
            "\u{2018} OR 1=1--", // unicode left single quote
            "\" OR \"\"=\"",
            "1 UNION SELECT key_hash FROM api_keys--",
            "%' UNION SELECT NULL--",
        ];

        for payload in payloads {
            // Live filter parameters: contacts.tag (jsonb containment),
            // messages.status / sort_by (allowlisted column), messages.cursor
            // (keyset decode). A hostile value must be a controlled 4xx or an
            // empty page — never 500, never a widened result set.
            for path in [
                format!("/v1/contacts?tag={}", urlencoding_lite(payload)),
                format!("/v1/messages?status={}", urlencoding_lite(payload)),
                format!("/v1/messages?sort_by={}", urlencoding_lite(payload)),
                format!("/v1/messages?cursor={}", urlencoding_lite(payload)),
            ] {
                let resp = app.clone().oneshot(get(&path, &key_a)).await.unwrap();
                let status = resp.status();
                assert_ne!(
                    status,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "SQLi shape must never surface as 500 on {path}"
                );
                let text = body_text(resp).await;
                // No credential material in any filter response.
                assert!(
                    !text.contains("key_hash")
                        && !text.contains("am_test_")
                        && !text.contains("argon2")
                        && !text.contains("$2"),
                    "filter response leaked credential material on {path}: {text}"
                );
                // A tautology must not dump another tenant's rows.
                assert!(
                    !text.contains("tenant-b") && !text.contains("b-secret@example.com"),
                    "SQLi shape may have widened the result set on {path}: {text}"
                );
            }
        }
    });

    /// XSS through the template RENDER sink: `{{name}}` / `{{subject}}`
    /// placeholders are filled from tenant-controlled variables and the
    /// result is HTML. Every payload must come back escaped (templates.rs
    /// `substitute` runs `html_escape` on every value).
    db_test!(
        xss_variables_are_escaped_in_template_render,
        pool,
        db_url,
        {
            let (app, pool, _key_a, ten_a, _key_b, _ten_b) = two_tenant_app(pool, &db_url).await;
            // Free plan cannot CREATE templates — seed one directly so the test
            // targets the render sink, not the entitlement gate.
            let tpl_id = seed_template(&pool, &ten_a, "Hello {{name}} — {{subject}}").await;
            // seed_template writes name='Hello {{name}} — {{subject}}' into the
            // name column and html_body='<p>ok</p>'. Re-point html_body/subject
            // at the placeholder template the render path substitutes.
            sqlx::query("UPDATE templates SET subject = $1, html_body = $2 WHERE id = $3")
                .bind("Hello {{name}}")
                .bind("<p>Dear {{name}}, {{subject}}</p>")
                .bind(&tpl_id)
                .execute(&pool)
                .await
                .expect("retarget template placeholders");

            let reader = seed_api_key(&pool, &ten_a, &["templates:read"]).await;

            let payloads = [
                "<script>alert('xss')</script>",
                "\" onfocus=\"alert(1)\" autofocus=\"",
                "<svg/onload=alert(1)>",
                "javascript:alert(1)",
            ];

            for payload in payloads {
                let resp = app
                    .clone()
                    .oneshot(post_json(
                        &format!("/v1/templates/{tpl_id}/render"),
                        &reader,
                        serde_json::json!({
                            "variables": {
                                "name": payload,
                                "subject": payload,
                            }
                        }),
                    ))
                    .await
                    .unwrap();
                assert_eq!(
                    resp.status(),
                    StatusCode::OK,
                    "render must succeed for hostile variables, got {}",
                    resp.status()
                );
                let text = body_text(resp).await;
                assert!(
                    !text.contains(payload),
                    "render leaked the raw XSS payload: {payload} → {text}"
                );
                if payload.contains('<') {
                    assert!(
                        text.contains("&lt;") || text.contains("&#x27;") || text.contains("&quot;"),
                        "render must escape tag/attr payloads: {payload} → {text}"
                    );
                }
            }
        }
    );

    /// Minimal URL encoder for query values (avoids an extra dependency).
    fn urlencoding_lite(value: &str) -> String {
        let mut out = String::new();
        for byte in value.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(byte as char)
                }
                _ => out.push_str(&format!("%{byte:02X}")),
            }
        }
        out
    }
}

// ─── Invariant 5 (HTTP): webhook create SSRF ────────────────────────────

mod ssrf_http {
    use super::db_harness::*;
    use axum::http::StatusCode;
    use tower::ServiceExt;

    db_test!(
        webhook_create_refuses_private_and_metadata_targets,
        pool,
        db_url,
        {
            let (app, pool, _key_a, ten_a, _key_b, _ten_b) = two_tenant_app(pool, &db_url).await;
            // Reach the URL validator, not the plan gate: grant the webhooks
            // capability so the SSRF arm is what answers.
            grant_feature(&pool, &ten_a, "webhooks_enabled").await;
            let writer = seed_api_key(&pool, &ten_a, &["webhooks:write", "webhooks:read"]).await;

            let hostile_urls = [
                "http://127.0.0.1/hook",
                "http://169.254.169.254/latest/meta-data/",
                "http://[::1]/hook",
                "http://2130706433/hook",
                "https://metadata.google.internal/computeMetadata/v1/",
                "http://10.0.0.1/hook",
                "https://service.internal/hook",
            ];

            for url in hostile_urls {
                let resp = app
                    .clone()
                    .oneshot(post_json(
                        "/v1/webhooks",
                        &writer,
                        serde_json::json!({
                            "url": url,
                            "events": ["message.delivered"]
                        }),
                    ))
                    .await
                    .unwrap();
                let status = resp.status();
                assert!(
                    status == StatusCode::BAD_REQUEST
                        || status == StatusCode::FORBIDDEN
                        || status == StatusCode::UNPROCESSABLE_ENTITY,
                    "SSRF target {url} must be refused with a 4xx, got {status}"
                );
                let text = body_text(resp).await;
                assert!(
                    text.to_lowercase().contains("private")
                        || text.to_lowercase().contains("https")
                        || text.to_lowercase().contains("reserved")
                        || text.to_lowercase().contains("invalid"),
                    "SSRF refusal must name the guard for {url}: {text}"
                );
            }

            // A row must not exist for any of the refused URLs.
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM webhooks WHERE tenant_id = $1")
                    .bind(&ten_a)
                    .fetch_one(&pool)
                    .await
                    .expect("count webhooks");
            assert_eq!(count, 0, "no webhook row may be persisted for an SSRF URL");
        }
    );
}

// ─── Invariant 6 (HTTP): reveal-once API keys ───────────────────────────

mod reveal_once_http {
    use super::db_harness::*;
    use axum::http::StatusCode;
    use tower::ServiceExt;

    db_test!(
        api_key_secret_is_revealed_once_and_never_again,
        pool,
        db_url,
        {
            let (app, _pool, _key_a, ten_a, _key_b, _ten_b) = two_tenant_app(pool, &db_url).await;
            // Wildcard minter: `authorize_scope_issuance` lets a `*` holder mint
            // any registered scope (restricted holders may only mint their own).
            let minter = seed_api_key(&pool, &ten_a, &["*"]).await;

            let resp = app
                .clone()
                .oneshot(post_json(
                    "/v1/auth/api-keys",
                    &minter,
                    serde_json::json!({
                        "name": "reveal-once key",
                        "scopes": ["messages:read"]
                    }),
                ))
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::CREATED,
                "key create must succeed for a scoped minter, got {}",
                resp.status()
            );
            let created = body_text(resp).await;
            let created_json: serde_json::Value =
                serde_json::from_str(&created).expect("create response is JSON");
            let raw_secret = created_json["key"].as_str().unwrap_or_else(|| {
                panic!("create response must carry the raw key once: {created}")
            });
            assert!(
                raw_secret.starts_with("am_"),
                "raw key must use the am_ prefix: {raw_secret}"
            );

            // List: the secret must not appear anywhere in the body.
            let resp = app
                .clone()
                .oneshot(get("/v1/auth/api-keys", &minter))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let list = body_text(resp).await;
            assert!(
                !list.contains(raw_secret),
                "list leaked the revealed API key secret"
            );
            assert!(
                !list.contains("\"key\""),
                "list DTO must not carry a `key` field: {list}"
            );

            // A second create with a fresh name returns a DIFFERENT secret
            // (and the old one stays unrepeated).
            let resp = app
                .clone()
                .oneshot(post_json(
                    "/v1/auth/api-keys",
                    &minter,
                    serde_json::json!({
                        "name": "reveal-once key 2",
                        "scopes": ["messages:read"]
                    }),
                ))
                .await
                .unwrap();
            let second = body_text(resp).await;
            assert!(
                !second.contains(raw_secret),
                "a later create must not re-reveal an earlier secret"
            );
        }
    );
}

// ─── Invariant 7: idempotency — double-submit applies once ──────────────

mod idempotency_http {
    use super::db_harness::*;
    use axum::http::StatusCode;
    use tower::ServiceExt;

    db_test!(
        same_idempotency_key_creates_exactly_one_contact,
        pool,
        db_url,
        {
            let (app, pool, _key_a, ten_a, _key_b, _ten_b) = two_tenant_app(pool, &db_url).await;
            let writer = seed_api_key(&pool, &ten_a, &["contacts:write", "contacts:read"]).await;

            let idem = format!("adv-idem-{}", uuid::Uuid::new_v4());
            let body = serde_json::json!({ "email": "idem@example.com", "name": "Idem" });

            let first = app
                .clone()
                .oneshot(post_json_with_headers(
                    "/v1/contacts",
                    &writer,
                    body.clone(),
                    &[("idempotency-key", &idem)],
                ))
                .await
                .unwrap();
            let first_status = first.status();
            assert!(
                first_status == StatusCode::CREATED || first_status == StatusCode::OK,
                "first submit must create, got {first_status}"
            );
            let first_text = body_text(first).await;

            let second = app
                .clone()
                .oneshot(post_json_with_headers(
                    "/v1/contacts",
                    &writer,
                    body.clone(),
                    &[("idempotency-key", &idem)],
                ))
                .await
                .unwrap();
            let second_status = second.status();
            let second_text = body_text(second).await;

            // Replay is either the cached first response (same id) or an explicit
            // conflict — never a second resource. (Without Redis the (tenant,email)
            // unique index still caps the row count; the cached-same-id arm needs
            // the Redis accelerator.)
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM contacts WHERE tenant_id = $1 AND email = $2",
            )
            .bind(&ten_a)
            .bind("idem@example.com")
            .fetch_one(&pool)
            .await
            .expect("count contacts");
            assert_eq!(
                count, 1,
                "double-submit with one Idempotency-Key must create exactly one row"
            );

            if second_status == StatusCode::CREATED || second_status == StatusCode::OK {
                // Same resource id on replay.
                let first_id = extract_id(&first_text);
                let second_id = extract_id(&second_text);
                assert_eq!(
                    first_id, second_id,
                    "idempotent replay must return the SAME resource id"
                );
            } else {
                assert_eq!(
                    second_status,
                    StatusCode::CONFLICT,
                    "a divergent replay is 409, got {second_status}: {second_text}"
                );
            }
        }
    );

    db_test!(
        same_idempotency_key_with_a_different_body_is_409,
        pool,
        db_url,
        {
            if !redis_available().await {
                eprintln!(
                    "skipping same_idempotency_key_with_a_different_body_is_409: \
                 TEST_REDIS_URL unset/unreachable (the idempotency cache is Redis-backed)"
                );
                return;
            }
            let (app, pool, _key_a, ten_a, _key_b, _ten_b) = two_tenant_app(pool, &db_url).await;
            let writer = seed_api_key(&pool, &ten_a, &["contacts:write"]).await;

            let idem = format!("adv-idem-div-{}", uuid::Uuid::new_v4());
            let _ = app
                .clone()
                .oneshot(post_json_with_headers(
                    "/v1/contacts",
                    &writer,
                    serde_json::json!({ "email": "one@example.com" }),
                    &[("idempotency-key", &idem)],
                ))
                .await
                .unwrap();

            let divergent = app
                .clone()
                .oneshot(post_json_with_headers(
                    "/v1/contacts",
                    &writer,
                    serde_json::json!({ "email": "two@example.com" }),
                    &[("idempotency-key", &idem)],
                ))
                .await
                .unwrap();
            let status = divergent.status();
            assert!(
                status == StatusCode::CONFLICT
                    || status == StatusCode::BAD_REQUEST
                    || status == StatusCode::UNPROCESSABLE_ENTITY,
                "same key + different body must refuse the second write, got {status}"
            );

            // Exactly one of the two emails landed.
            let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM contacts WHERE tenant_id = $1 AND email IN ('one@example.com','two@example.com')",
        )
        .bind(&ten_a)
        .fetch_one(&pool)
        .await
        .expect("count");
            assert_eq!(count, 1, "divergent replay must not create a second row");
        }
    );

    fn extract_id(text: &str) -> String {
        let json: serde_json::Value = serde_json::from_str(text).unwrap_or(serde_json::json!({}));
        json["id"]
            .as_str()
            .or_else(|| json["data"]["id"].as_str())
            .unwrap_or_default()
            .to_string()
    }
}
