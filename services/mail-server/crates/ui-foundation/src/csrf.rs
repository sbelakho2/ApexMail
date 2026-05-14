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
}
