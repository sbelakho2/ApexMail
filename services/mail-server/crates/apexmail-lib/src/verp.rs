//! VERP v2 — cryptographically authenticated bounce envelope tokens.
//!
//! The legacy (v1) VERP return path
//! `bounces+{message_id}={recipient_domain}={recipient_local}@{verp_domain}`
//! is *attributable* but not *authentic*: message id and recipient are
//! plaintext, so anyone who learns the pair can manufacture the matching
//! bounce address and drive the suppression pipeline. v2 replaces that
//! grammar with an opaque, HMAC-authenticated token:
//!
//! ```text
//! bounces+v2.<token>@{verp_domain}
//! token = base64url_nopad(payload_json) "." base64url_nopad(HMAC-SHA256(secret, payload_bytes))
//! payload_json = {"v":"v2","q":"<queue/send id>","t":"<tenant>","r":"<recipient>","e":<expiry_unix>}
//! ```
//!
//! Contract:
//! * the token is bound to (queue/send id, tenant, recipient, expiry) — all
//!   four claims are covered by the MAC;
//! * a verifier recomputes the MAC over the exact decoded payload bytes
//!   (never over a re-serialization) and rejects the token on any mismatch;
//! * an expired token is rejected even when the MAC is valid;
//! * on ANY failure the embedded claims must not be trusted — the caller may
//!   record the attempt as an observation but must not suppress or otherwise
//!   act on it;
//! * v1 addresses stay parseable for read-compatibility only. They carry no
//!   authentication and therefore can never authorize suppression. See
//!   `crates/mta/src/servers/bounce.rs` for the documented retirement
//!   condition.
//!
//! The secret is `VERP_HMAC_SECRET` (>= 32 bytes, identical in the worker
//! that mints tokens and the MTA that verifies them); startup fails fast in
//! production when it is missing (see `mta::config::MtaConfig::validate`).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Address local-part prefix that identifies a v2 VERP return path.
pub const VERP_V2_ADDRESS_PREFIX: &str = "bounces+v2.";

/// Payload version marker. Bumping this invalidates older tokens.
pub const VERP_V2_PAYLOAD_VERSION: &str = "v2";

/// Domain-separation prefix mixed into the MAC input so a token cannot be
/// confused with another HMAC-signed artifact that happens to share the
/// secret.
const VERP_V2_MAC_CONTEXT: &[u8] = b"apexmail.verp.v2\0";

/// Hard upper bound on a token's length (an address-local-part sanity cap;
/// the bounce parser also enforces envelope length limits).
pub const VERP_V2_MAX_TOKEN_LEN: usize = 1024;

/// Minimum length of the shared secret accepted by [`mint_verp_v2_token`]
/// callers at configuration time (256 bits when ASCII).
pub const VERP_V2_MIN_SECRET_LEN: usize = 32;

/// Claims authenticated by a v2 VERP token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerpV2Claims {
    /// Queue/send identity: `email_queue.id` (the same value the bounce
    /// server's `lookup_sent_message` resolves).
    pub queue_id: String,
    /// Owning tenant (`email_queue.tenant_id`).
    pub tenant_id: String,
    /// Envelope recipient the mail was sent to.
    pub recipient: String,
    /// Unix expiry; tokens at/after this instant are rejected.
    pub expires_at: i64,
}

/// Wire form of the token payload. Kept private: callers only ever see
/// [`VerpV2Claims`], so the JSON key names are not part of the contract.
#[derive(Debug, Serialize, Deserialize)]
struct VerpV2Payload {
    v: String,
    q: String,
    t: String,
    r: String,
    e: i64,
}

/// Why a v2 token failed verification. Every variant is non-authoritative:
/// the caller must not trust `q`/`t`/`r`/`e`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerpV2Error {
    /// Not `bounces+v2.`-shaped, bad base64, bad JSON, missing/empty claims.
    Malformed,
    /// MAC recomputation did not match — forged or corrupted token.
    BadSignature,
    /// MAC valid but the expiry claim is at/before the supplied `now`.
    Expired,
    /// The verifier has no `VERP_HMAC_SECRET`, so nothing can be
    /// authenticated. Treated exactly like a bad signature: the claims are
    /// not trusted.
    Unconfigured,
}

impl std::fmt::Display for VerpV2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => write!(f, "malformed VERP v2 token"),
            Self::BadSignature => write!(f, "VERP v2 token signature mismatch"),
            Self::Expired => write!(f, "VERP v2 token expired"),
            Self::Unconfigured => write!(f, "VERP v2 secret is not configured"),
        }
    }
}

impl std::error::Error for VerpV2Error {}

fn mac_bytes(secret: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC-SHA256 accepts any key length");
    mac.update(VERP_V2_MAC_CONTEXT);
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

/// Mint an authenticated v2 token for `claims`. The claims are embedded in
/// the token (base64url JSON, integrity-protected by the MAC) so verification
/// is stateless: no database row is required for MAC tokens.
pub fn mint_verp_v2_token(secret: &[u8], claims: &VerpV2Claims) -> String {
    let payload = VerpV2Payload {
        v: VERP_V2_PAYLOAD_VERSION.to_string(),
        q: claims.queue_id.clone(),
        t: claims.tenant_id.clone(),
        r: claims.recipient.clone(),
        e: claims.expires_at,
    };
    let payload_bytes =
        serde_json::to_vec(&payload).expect("VERP v2 payload serialization is infallible");
    let signature = mac_bytes(secret, &payload_bytes);
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&payload_bytes),
        URL_SAFE_NO_PAD.encode(signature)
    )
}

/// Build the full v2 return path `bounces+v2.<token>@domain`.
pub fn verp_v2_address(secret: &[u8], claims: &VerpV2Claims, verp_domain: &str) -> String {
    format!(
        "{}{}@{}",
        VERP_V2_ADDRESS_PREFIX,
        mint_verp_v2_token(secret, claims),
        verp_domain
    )
}

/// Extract the raw token from a `bounces+v2.<token>` local part, if the
/// local part uses the v2 grammar. Does NOT authenticate anything.
pub fn verp_v2_token_from_local(local: &str) -> Option<&str> {
    let token = local.strip_prefix(VERP_V2_ADDRESS_PREFIX)?;
    let token = token.trim();
    if token.is_empty() || token.len() > VERP_V2_MAX_TOKEN_LEN {
        return None;
    }
    if !token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return None;
    }
    Some(token)
}

/// Verify a v2 token by recomputing its MAC. `now_unix` is the verifier's
/// clock (passed explicitly so expiry is testable).
///
/// Order of checks: shape → MAC → expiry → claim sanity. The payload is not
/// parsed until the MAC has been validated, and even then only the
/// authenticated claims are returned.
pub fn verify_verp_v2_token(
    secret: &[u8],
    token: &str,
    now_unix: i64,
) -> Result<VerpV2Claims, VerpV2Error> {
    let token = token.trim();
    if token.is_empty() || token.len() > VERP_V2_MAX_TOKEN_LEN {
        return Err(VerpV2Error::Malformed);
    }
    let (payload_b64, sig_b64) = token.split_once('.').ok_or(VerpV2Error::Malformed)?;
    if payload_b64.is_empty() || sig_b64.is_empty() {
        return Err(VerpV2Error::Malformed);
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| VerpV2Error::Malformed)?;
    let provided_sig = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| VerpV2Error::Malformed)?;
    if provided_sig.len() != 32 {
        return Err(VerpV2Error::Malformed);
    }

    // Constant-time compare of the recomputed MAC against the provided one
    // (both rendered as hex for the shared timing-safe helper).
    let expected = mac_bytes(secret, &payload_bytes);
    if !crate::crypto::timing_safe_compare(&hex::encode(&provided_sig), &hex::encode(expected)) {
        return Err(VerpV2Error::BadSignature);
    }

    let payload: VerpV2Payload =
        serde_json::from_slice(&payload_bytes).map_err(|_| VerpV2Error::Malformed)?;
    if payload.v != VERP_V2_PAYLOAD_VERSION
        || payload.q.is_empty()
        || payload.t.is_empty()
        || payload.r.is_empty()
    {
        return Err(VerpV2Error::Malformed);
    }
    if now_unix >= payload.e {
        return Err(VerpV2Error::Expired);
    }
    Ok(VerpV2Claims {
        queue_id: payload.q,
        tenant_id: payload.t,
        recipient: payload.r,
        expires_at: payload.e,
    })
}

/// Verify a full address local part of the form `bounces+v2.<token>`.
pub fn verify_verp_v2_local(
    secret: &[u8],
    local: &str,
    now_unix: i64,
) -> Result<VerpV2Claims, VerpV2Error> {
    let token = verp_v2_token_from_local(local).ok_or(VerpV2Error::Malformed)?;
    verify_verp_v2_token(secret, token, now_unix)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn claims(expiry: i64) -> VerpV2Claims {
        VerpV2Claims {
            queue_id: "0e2d1c34-9a56-4f18-8f0a-3f4c5d6e7a89".into(),
            tenant_id: "ten_abc".into(),
            recipient: "user@example.com".into(),
            expires_at: expiry,
        }
    }

    #[test]
    fn round_trip_returns_bound_claims() {
        let token = mint_verp_v2_token(SECRET, &claims(2_000_000_000));
        let verified = verify_verp_v2_token(SECRET, &token, 1_000_000_000).unwrap();
        assert_eq!(verified, claims(2_000_000_000));
    }

    #[test]
    fn forged_token_is_rejected_and_claims_not_trusted() {
        // Flip one payload character: the MAC no longer matches, and the
        // verifier must not return the (now attacker-controlled) claims.
        let token = mint_verp_v2_token(SECRET, &claims(2_000_000_000));
        let (payload, sig) = token.split_once('.').unwrap();
        let mut tampered = payload.to_string();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        let forged = format!("{tampered}.{sig}");
        assert_eq!(
            verify_verp_v2_token(SECRET, &forged, 1_000_000_000),
            Err(VerpV2Error::BadSignature)
        );
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let token = mint_verp_v2_token(SECRET, &claims(2_000_000_000));
        assert_eq!(
            verify_verp_v2_token(b"another-secret-another-secret-32", &token, 1_000_000_000),
            Err(VerpV2Error::BadSignature)
        );
    }

    #[test]
    fn expired_token_is_rejected_even_with_valid_mac() {
        let token = mint_verp_v2_token(SECRET, &claims(1_000));
        assert_eq!(
            verify_verp_v2_token(SECRET, &token, 1_000),
            Err(VerpV2Error::Expired),
            "expiry is inclusive: a token at its expiry instant is dead"
        );
        assert_eq!(verify_verp_v2_token(SECRET, &token, 999), Ok(claims(1_000)));
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        assert_eq!(
            verify_verp_v2_token(SECRET, "", 1),
            Err(VerpV2Error::Malformed)
        );
        assert_eq!(
            verify_verp_v2_token(SECRET, "not-a-token", 1),
            Err(VerpV2Error::Malformed)
        );
        assert_eq!(
            verify_verp_v2_token(SECRET, "AAAA.BBBB", 1),
            Err(VerpV2Error::Malformed),
            "valid base64 that is not a signature must not be accepted"
        );
    }

    #[test]
    fn address_round_trip_and_prefix_extraction() {
        let address = verp_v2_address(SECRET, &claims(2_000_000_000), "bounces.apexmail.ee");
        assert!(address.starts_with("bounces+v2."));
        assert!(address.ends_with("@bounces.apexmail.ee"));
        let local = address.split('@').next().unwrap();
        let verified = verify_verp_v2_local(SECRET, local, 1_000_000_000).unwrap();
        assert_eq!(verified.recipient, "user@example.com");
    }

    #[test]
    fn token_shape_rejects_whitespace_and_control_characters() {
        assert!(verp_v2_token_from_local("bounces+v2.").is_none());
        assert!(verp_v2_token_from_local("bounces+v2.a b").is_none());
        assert!(verp_v2_token_from_local("bounces+v2.abc\r\ndef").is_none());
        assert!(verp_v2_token_from_local("bounces+v3.abc").is_none());
        assert_eq!(
            verp_v2_token_from_local("bounces+v2.abc-def_ghi"),
            Some("abc-def_ghi")
        );
    }
}
