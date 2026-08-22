//! Signed flash messages and destructive-action confirmation tokens for
//! the zero-JavaScript SSR surfaces.
//!
//! The console uses the PRG (Post/Redirect/Get) pattern exclusively: form
//! POSTs redirect to a GET of the referring view, and the outcome is
//! carried by a **signed, single-use-ish, short-lived flash cookie** that
//! the next render decodes and shows as a banner (success / field errors),
//! then clears. No client-side code is involved anywhere.
//!
//! - [`encode_flash_cookie`] / [`decode_flash_cookie`]: HMAC-SHA256-signed
//!   cookie payload (`v1.<base64url(json)>.<base64url(hmac)>`).
//! - [`sign_confirmation`] / [`verify_confirmation`]: HMAC over
//!   `intent + resource id + expiry` for the GET `/confirm` flow used by
//!   destructive actions (delete campaign/list/domain/…). The signature
//!   proves the confirmation link was produced by this server for this
//!   exact action and has not expired.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Flash message severity. Drives the banner styling and iconography.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlashKind {
    Success,
    Error,
    Info,
}

impl FlashKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Error => "error",
            Self::Info => "info",
        }
    }
}

/// One flash message rendered as a banner on the next GET.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlashMessage {
    pub kind: FlashKind,
    pub text: String,
}

impl FlashMessage {
    pub fn success(text: impl Into<String>) -> Self {
        Self {
            kind: FlashKind::Success,
            text: text.into(),
        }
    }

    pub fn error(text: impl Into<String>) -> Self {
        Self {
            kind: FlashKind::Error,
            text: text.into(),
        }
    }

    pub fn info(text: impl Into<String>) -> Self {
        Self {
            kind: FlashKind::Info,
            text: text.into(),
        }
    }
}

fn b64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64_decode(input: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .ok()
}

fn sign(secret: &str, payload: &[u8]) -> String {
    let mut mac = <Hmac<Sha256>>::new_from_slice(secret.as_bytes()).expect("flash HMAC key error");
    mac.update(payload);
    b64_encode(&mac.finalize().into_bytes())
}

fn verify_signature(secret: &str, payload: &[u8], signature: &str) -> bool {
    let Some(expected) = b64_decode(signature) else {
        return false;
    };
    let mut mac = <Hmac<Sha256>>::new_from_slice(secret.as_bytes()).expect("flash HMAC key error");
    mac.update(payload);
    mac.verify_slice(&expected).is_ok()
}

/// Name of the cookie that carries flash messages between the POST
/// response and the following GET render.
pub const FLASH_COOKIE_NAME: &str = "apexmail_flash";

/// How long a flash cookie stays valid (seconds). Flash is meant to be
/// read by the immediately following navigation; anything older is stale.
pub const FLASH_MAX_AGE_SECS: i64 = 60;

/// Default validity window for confirmation signatures.
pub const CONFIRMATION_DEFAULT_TTL_SECS: i64 = 15 * 60;

/// Serialize + sign the flash messages for a `Set-Cookie` value.
pub fn encode_flash_cookie(messages: &[FlashMessage], secret: &str) -> String {
    let payload =
        serde_json::to_vec(messages).expect("flash messages must serialize (plain strings)");
    let payload_b64 = b64_encode(&payload);
    let signature = sign(secret, payload_b64.as_bytes());
    format!("v1.{payload_b64}.{signature}")
}

/// Verify + deserialize a flash cookie value. Returns `None` on any
/// tampering, malformed input, or bad signature — never panics.
pub fn decode_flash_cookie(value: &str, secret: &str) -> Option<Vec<FlashMessage>> {
    let rest = value.strip_prefix("v1.")?;
    let (payload_b64, signature) = rest.rsplit_once('.')?;
    if !verify_signature(secret, payload_b64.as_bytes(), signature) {
        return None;
    }
    let payload = b64_decode(payload_b64)?;
    // Bound the decoded size before parsing to resist cookie stuffing.
    if payload.len() > 8 * 1024 {
        return None;
    }
    serde_json::from_slice(&payload).ok()
}

/// Build the `Set-Cookie` header value that stores the flash messages.
pub fn flash_set_cookie(messages: &[FlashMessage], secret: &str, secure: bool) -> String {
    format!(
        "{FLASH_COOKIE_NAME}={}; Path=/; Max-Age={FLASH_MAX_AGE_SECS}; HttpOnly; SameSite=Lax{}",
        encode_flash_cookie(messages, secret),
        if secure { "; Secure" } else { "" },
    )
}

/// Build the `Set-Cookie` header value that clears the flash cookie.
pub fn flash_clear_cookie(secure: bool) -> String {
    format!(
        "{FLASH_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax{}",
        if secure { "; Secure" } else { "" }
    )
}

/// Produce the signed confirmation token for a destructive intent.
/// `expires_at_unix` bounds the link's validity; the token binds the exact
/// `intent` (e.g. `delete-campaign`) and `resource_id`, so a token for one
/// action cannot be replayed against another.
pub fn sign_confirmation(
    secret: &str,
    intent: &str,
    resource_id: &str,
    expires_at_unix: i64,
) -> String {
    let payload = format!("{intent}:{resource_id}:{expires_at_unix}");
    let sig = sign(secret, payload.as_bytes());
    format!("{expires_at_unix}.{sig}")
}

/// Verify a confirmation token against the current time. Fails closed on
/// expiry, tampering, or malformed input.
pub fn verify_confirmation(
    secret: &str,
    token: &str,
    intent: &str,
    resource_id: &str,
    now_unix: i64,
) -> bool {
    let Some((expiry, sig)) = token.split_once('.') else {
        return false;
    };
    let Ok(expires_at) = expiry.parse::<i64>() else {
        return false;
    };
    if now_unix > expires_at {
        return false;
    }
    let payload = format!("{intent}:{resource_id}:{expires_at}");
    verify_signature(secret, payload.as_bytes(), sig)
}

/// Convenience wrapper that signs with `now + ttl`.
pub fn sign_confirmation_for_ttl(
    secret: &str,
    intent: &str,
    resource_id: &str,
    now_unix: i64,
    ttl_secs: i64,
) -> String {
    sign_confirmation(secret, intent, resource_id, now_unix + ttl_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-flash-secret-0123456789";

    #[test]
    fn flash_cookie_round_trips() {
        let messages = vec![
            FlashMessage::success("Campaign created."),
            FlashMessage::error("Email is not valid."),
        ];
        let cookie = encode_flash_cookie(&messages, SECRET);
        assert!(cookie.starts_with("v1."));
        assert_eq!(cookie.matches('.').count(), 2);
        assert_eq!(decode_flash_cookie(&cookie, SECRET), Some(messages));
    }

    #[test]
    fn flash_cookie_rejects_wrong_secret() {
        let cookie = encode_flash_cookie(&[FlashMessage::info("hi")], SECRET);
        assert!(decode_flash_cookie(&cookie, "other-secret").is_none());
    }

    #[test]
    fn flash_cookie_rejects_tampering() {
        let cookie = encode_flash_cookie(&[FlashMessage::info("hello")], SECRET);
        // Flip one character inside the base64 payload (signature kept).
        let (prefix, rest) = cookie.split_at(cookie.find('.').unwrap() + 1);
        let mut chars: Vec<char> = rest.chars().collect();
        let flip = if chars[0] == 'A' { 'B' } else { 'A' };
        chars[0] = flip;
        let tampered = format!("{prefix}{}", chars.into_iter().collect::<String>());
        assert_ne!(cookie, tampered);
        assert!(decode_flash_cookie(&tampered, SECRET).is_none());
        // Truncated / malformed values never panic.
        assert!(decode_flash_cookie("", SECRET).is_none());
        assert!(decode_flash_cookie("v1.only", SECRET).is_none());
        assert!(decode_flash_cookie("v2.a.b", SECRET).is_none());
    }

    #[test]
    fn flash_cookie_rejects_oversized_payloads() {
        let big = vec![FlashMessage::info("x".repeat(64 * 1024)); 1];
        let cookie = encode_flash_cookie(&big, SECRET);
        assert!(decode_flash_cookie(&cookie, SECRET).is_none());
    }

    #[test]
    fn flash_set_cookie_carries_http_only_same_site() {
        let cookie = flash_set_cookie(&[FlashMessage::success("ok")], SECRET, false);
        assert!(cookie.starts_with("apexmail_flash="));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(!cookie.contains("Secure"));
        assert!(flash_set_cookie(&[FlashMessage::success("ok")], SECRET, true).contains("Secure"));
        assert!(flash_clear_cookie(false).contains("Max-Age=0"));
    }

    #[test]
    fn confirmation_signature_round_trips() {
        let token = sign_confirmation_for_ttl(SECRET, "delete-campaign", "c_1", 1_000, 300);
        assert!(verify_confirmation(
            SECRET,
            &token,
            "delete-campaign",
            "c_1",
            1_100
        ));
        // Expired.
        assert!(!verify_confirmation(
            SECRET,
            &token,
            "delete-campaign",
            "c_1",
            1_400
        ));
        // Wrong intent or resource: fails closed.
        assert!(!verify_confirmation(
            SECRET,
            &token,
            "delete-list",
            "c_1",
            1_100
        ));
        assert!(!verify_confirmation(
            SECRET,
            &token,
            "delete-campaign",
            "c_2",
            1_100
        ));
        // Wrong secret.
        assert!(!verify_confirmation(
            "other",
            &token,
            "delete-campaign",
            "c_1",
            1_100
        ));
        // Malformed.
        assert!(!verify_confirmation(
            SECRET,
            "garbage",
            "delete-campaign",
            "c_1",
            1_100
        ));
        assert!(!verify_confirmation(
            SECRET,
            "abc.def",
            "delete-campaign",
            "c_1",
            1_100
        ));
    }

    #[test]
    fn confirmation_tokens_differ_per_resource() {
        let a = sign_confirmation(SECRET, "delete-campaign", "a", 5_000);
        let b = sign_confirmation(SECRET, "delete-campaign", "b", 5_000);
        assert_ne!(a, b);
    }
}
