//! Cross-cutting adversarial tests for shared primitives: HTML escaping,
//! flash cookies, CSRF token binding, and confirmation signatures.
//!
//! These are the last line of defense when a new sink forgets to escape or a
//! workflow replays the wrong form. Failures here are systemic.

use ui_foundation::flash::{self, FlashMessage};
use ui_foundation::primitives::*;

/// XSS payload battery must never survive any text/attribute sink intact.
const XSS: &[&str] = &[
    "<script>alert(1)</script>",
    "\" onfocus=\"alert(1)",
    "' onfocus='alert(1)",
    "</option><script>alert(1)</script>",
    "javascript:alert(1)",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "\"><iframe src=javascript:alert(1)>",
];

#[test]
fn input_never_renders_raw_xss_payloads() {
    for payload in XSS {
        let html = Input {
            input_type: "text",
            value: payload,
            placeholder: payload,
            variant: "default",
            size: "default",
            left_icon: None,
            right_icon: None,
            error: Some(payload),
            disabled: false,
            autocomplete: None,
            required: false,
            name: Some("n"),
            id: Some("x"),
        }
        .render_html();
        assert!(
            !html.contains("<script>") && !html.contains("<img src=x") && !html.contains("<svg/"),
            "raw XSS survived Input: {payload} in {html}"
        );
        if payload.contains('<') {
            // Only tag-shaped payloads contain a `<` to escape; requiring
            // `&lt;` for an attribute-break payload (" onfocus="alert(1))
            // demanded an entity that no input can produce.
            assert!(
                html.contains("&lt;"),
                "payload must be escaped: {payload} in {html}"
            );
        }
        if payload.contains('"') {
            assert!(
                html.contains("&quot;") || html.contains("&#34;"),
                "attribute-break payload must escape its quote: {payload} in {html}"
            );
        }
    }
}

#[test]
fn native_select_never_renders_raw_xss_payloads() {
    for payload in XSS {
        let html = NativeSelect {
            id: "s",
            name: "n",
            options: vec![SelectOption {
                value: payload,
                label: payload,
                disabled: false,
                selected: true,
            }],
            required: false,
            multiple: false,
            size: None,
        }
        .render_html();
        assert!(
            !html.contains("<script>") && !html.contains("<img src=x"),
            "raw XSS survived NativeSelect: {payload} in {html}"
        );
    }
}

#[test]
fn textarea_never_renders_raw_script_breakout() {
    for payload in XSS {
        let html = Textarea {
            value: payload,
            placeholder: payload,
            variant: "default",
            resize: "vertical",
            max_length: Some(100),
            show_count: false,
            name: Some("body"),
            id: Some("t"),
        }
        .render_html();
        assert!(
            !html.contains("<script>"),
            "raw script in textarea: {payload} in {html}"
        );
    }
}

#[test]
fn native_checkbox_label_is_escaped() {
    for payload in XSS {
        let html = NativeCheckbox {
            id: "c",
            name: "c",
            checked: true,
            label: payload,
        }
        .render_html();
        assert!(
            !html.contains("<script>") && !html.contains("<img src=x"),
            "raw XSS in checkbox label: {payload} in {html}"
        );
    }
}

#[test]
fn badge_text_is_escaped() {
    for payload in XSS {
        let html = Badge {
            text: payload,
            variant: "outline",
            size: "default",
            icon: None,
        }
        .render_html();
        assert!(
            !html.contains("<script>") && !html.contains("<img src=x"),
            "raw XSS in badge: {payload} in {html}"
        );
    }
}

/// Flash cookies are attacker-visible. Encoding must be reversible only
/// with the secret; garbage must not panic or decode as success.
#[test]
fn flash_decode_rejects_tampered_and_garbage_without_panic() {
    let secret = "test-secret-value-for-flash";
    let messages = vec![FlashMessage::success("Saved.")];
    let ok = flash::encode_flash_cookie(&messages, secret);
    assert!(!ok.is_empty());

    // Round-trip with the correct secret.
    let decoded = flash::decode_flash_cookie(&ok, secret).expect("valid cookie decodes");
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].text, "Saved.");

    // Wrong secret must not decode.
    assert!(
        flash::decode_flash_cookie(&ok, "other-secret").is_none(),
        "wrong secret must not decode flash"
    );

    // Tampered / garbage must not panic and must not decode as success.
    let mut tampered = ok.clone();
    // Force a mid-string mutation so the HMAC no longer matches.
    let mid = tampered.len() / 2;
    tampered.insert(mid, '!');
    assert!(
        flash::decode_flash_cookie(&tampered, secret).is_none(),
        "tampered cookie must not decode: {tampered}"
    );
    for garbage in ["", "not-base64!!!", "AAAA", "a.b.c"] {
        assert!(
            flash::decode_flash_cookie(garbage, secret).is_none(),
            "garbage must not decode: {garbage:?}"
        );
    }
}

/// CSRF tokens must be a genuine HMAC of their own nonce (the api-server
/// consumer contract). Mutants must fail that check.
#[test]
fn csrf_tokens_fail_closed_under_forgery() {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let secret = "csrf-secret-abc";
    let token = ui_foundation::csrf::generate_csrf_token(secret);
    assert_eq!(token.matches('.').count(), 1, "token shape: {token}");

    let verifies = |nonce_b64: &str, signature: &str, key: &str| -> bool {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let Ok(raw) = engine.decode(nonce_b64) else {
            return false;
        };
        let mut mac = match <Hmac<Sha256>>::new_from_slice(key.as_bytes()) {
            Ok(m) => m,
            Err(_) => return false,
        };
        mac.update(&raw);
        engine.encode(mac.finalize().into_bytes()) == signature
    };

    let (nonce_b64, sig_b64) = token.split_once('.').expect("two parts");
    assert!(verifies(nonce_b64, sig_b64, secret), "valid token verifies");
    assert!(
        !verifies(nonce_b64, sig_b64, "wrong-secret"),
        "secret binding"
    );
    assert!(!verifies(nonce_b64, "AAAA", secret), "forged signature");
    assert!(!verifies("AAAA", sig_b64, secret), "forged nonce");
    assert!(!verifies("", sig_b64, secret), "empty nonce");
}

/// Confirmation signatures (destructive confirm links) must bind intent +
/// resource + expiry. Tampering and expiry must fail closed.
#[test]
fn confirmation_signatures_bind_intent_resource_and_expiry() {
    let secret = "confirm-secret";
    let now = 1_700_000_000i64;
    let expires = now + 900; // 15 minutes
    let token = flash::sign_confirmation(secret, "delete-campaign", "c_1", expires);

    assert!(
        flash::verify_confirmation(secret, &token, "delete-campaign", "c_1", now),
        "fresh signed token must verify"
    );
    assert!(
        !flash::verify_confirmation(secret, &token, "delete-list", "c_1", now),
        "wrong intent must not verify"
    );
    assert!(
        !flash::verify_confirmation(secret, &token, "delete-campaign", "c_2", now),
        "wrong resource must not verify"
    );
    assert!(
        !flash::verify_confirmation("other", &token, "delete-campaign", "c_1", now),
        "wrong secret must not verify"
    );
    assert!(
        !flash::verify_confirmation(secret, &token, "delete-campaign", "c_1", expires + 1),
        "expired token must not verify"
    );
    assert!(!flash::verify_confirmation(
        secret,
        "",
        "delete-campaign",
        "c_1",
        now
    ));
    assert!(!flash::verify_confirmation(
        secret,
        "!!!",
        "delete-campaign",
        "c_1",
        now
    ));
    assert!(!flash::verify_confirmation(
        secret,
        "999.sig",
        "delete-campaign",
        "c_1",
        now
    ));
}
