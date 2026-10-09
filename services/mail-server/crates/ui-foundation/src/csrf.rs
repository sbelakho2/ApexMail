//! CSRF token generation for server-side rendered forms.
//!
//! Generates HMAC-SHA256 signed tokens matching the validation logic in
//! `api-server/src/routes/csrf.rs`. This allows SSR view functions to
//! embed real CSRF tokens into hidden form inputs instead of placeholders.

/// Generate a CSRF token signed with the given secret.
///
/// The token format is: `base64(nonce).base64(hmac-sha256(nonce))`
/// where nonce = `"{timestamp_ms}:{uuid}"`.
///
/// This is the same format produced by `get_csrf_token` in
/// `api-server/src/routes/csrf.rs` and validated by `validate_csrf_token`.
pub fn generate_csrf_token(secret: &str) -> String {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let now = chrono::Utc::now().timestamp_millis();
    let random = uuid::Uuid::new_v4();
    let nonce = format!("{now}:{random}");

    let nonce_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce.as_bytes());

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("CSRF HMAC key error");
    mac.update(nonce.as_bytes());
    let sig = mac.finalize().into_bytes();
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);

    format!("{nonce_b64}.{sig_b64}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_csrf_token_format() {
        let secret = "test-secret-for-unit-tests";
        let token = generate_csrf_token(secret);

        // Token should contain exactly one dot separator
        assert!(token.contains('.'));
        assert_eq!(token.matches('.').count(), 1);

        // Both parts should be non-empty base64
        let parts: Vec<&str> = token.splitn(2, '.').collect();
        assert_eq!(parts.len(), 2);
        assert!(!parts[0].is_empty());
        assert!(!parts[1].is_empty());

        // Should be URL-safe base64 (no + or /)
        assert!(!parts[0].contains('+'));
        assert!(!parts[0].contains('/'));
        assert!(!parts[1].contains('+'));
        assert!(!parts[1].contains('/'));
    }

    #[test]
    fn test_generate_csrf_token_unique_per_call() {
        let secret = "another-test-secret";
        let token1 = generate_csrf_token(secret);
        let token2 = generate_csrf_token(secret);

        // Each call should produce a different token (due to UUID nonce)
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_generate_csrf_token_different_secrets() {
        let token1 = generate_csrf_token("secret-a");
        let token2 = generate_csrf_token("secret-b");

        assert_ne!(token1, token2);
    }

    /// Review §5.1 csrf.rs: extend the consumer/secret-binding coverage so a
    /// malformed rendered token cannot silently break every workflow. The
    /// token the views embed must be a genuine HMAC of its own nonce, with
    /// the documented `<ms>:<uuid>` nonce — exactly what the api-server's
    /// `validate_csrf_token` recomputes.
    #[test]
    fn generated_token_verifies_against_the_consumer_contract() {
        use base64::Engine;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let secret = "csrf-consumer-binding-secret";
        let token = generate_csrf_token(secret);
        let (nonce_b64, sig_b64) = token.split_once('.').expect("token has two parts");
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        // The api-server contract: signature == HMAC-SHA256(secret, nonce),
        // base64url. Any placeholder or truncated token fails this check.
        let verifies = |nonce_b64: &str, signature: &str, key: &str| {
            let Ok(raw) = engine.decode(nonce_b64) else {
                return false;
            };
            let mut mac = <Hmac<Sha256>>::new_from_slice(key.as_bytes()).expect("hmac key");
            mac.update(&raw);
            engine.encode(mac.finalize().into_bytes()) == signature
        };
        assert!(verifies(nonce_b64, sig_b64, secret), "embedded token");
        assert!(
            !verifies(nonce_b64, sig_b64, "another-secret"),
            "secret binding"
        );
        assert!(!verifies("", sig_b64, secret), "empty nonce");
        assert!(!verifies(nonce_b64, "", secret), "empty signature");
        assert!(
            !verifies(&engine.encode(b"1700000000000:other"), sig_b64, secret),
            "signature is bound to this exact nonce"
        );

        // Documented nonce shape: "<unix-ms>:<uuid>".
        let nonce = engine.decode(nonce_b64).expect("nonce is base64url");
        let nonce = String::from_utf8(nonce).expect("nonce is utf8");
        let (timestamp, uuid) = nonce.split_once(':').expect("nonce is ts:uuid");
        let timestamp: i64 = timestamp.parse().expect("timestamp is millis");
        assert!(timestamp > 1_700_000_000_000, "millisecond timestamp");
        uuid::Uuid::parse_str(uuid).expect("uuid part");
    }
}
