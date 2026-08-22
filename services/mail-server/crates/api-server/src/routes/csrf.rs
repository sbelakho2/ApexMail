//! CSRF token endpoint.
//!
//! Generates CSRF tokens using HMAC-SHA256 with a server secret.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::error::ApiError;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(get_csrf_token))
}

// ─── Response ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct CsrfResponse {
    pub token: String,
}

// ─── Handler ───────────────────────────────────────────────────

async fn get_csrf_token(
    State(state): State<AppState>,
) -> Result<(HeaderMap, Json<CsrfResponse>), ApiError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    // Generate a unique nonce with timestamp
    let now = chrono::Utc::now().timestamp_millis();
    let random = uuid::Uuid::new_v4();
    let nonce = format!("{now}:{random}");

    // Sign with CSRF secret
    let mut mac = Hmac::<Sha256>::new_from_slice(state.config.csrf_secret.as_bytes())
        .map_err(|_| ApiError::Internal("CSRF HMAC key error".into()))?;
    mac.update(nonce.as_bytes());
    let sig = mac.finalize().into_bytes();
    let sig_b64 = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, sig);

    let token = format!(
        "{}.{sig_b64}",
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            nonce.as_bytes(),
        )
    );

    // Set CSRF cookie alongside JSON response
    let cookie_value = format!(
        "csrf_token={token}; HttpOnly; Path=/; Max-Age=3600; SameSite=Strict{}",
        if state.config.environment.is_production() {
            "; Secure"
        } else {
            ""
        }
    );

    let mut headers = HeaderMap::new();
    let val = cookie_value.parse().map_err(|e| {
        tracing::error!(error = %e, "failed to build CSRF cookie header");
        ApiError::Internal("failed to set CSRF cookie".into())
    })?;
    headers.insert("Set-Cookie", val);
    headers.insert(
        "Cache-Control",
        "no-store, no-cache, must-revalidate".parse().map_err(|e| {
            tracing::error!(error = %e, "failed to parse Cache-Control header value");
            ApiError::Internal("failed to set security headers".into())
        })?,
    );

    Ok((headers, Json(CsrfResponse { token })))
}

// ─── CSRF validation helper for other handlers ────────────────

/// Validate a CSRF token from a request header against the cookie.
pub fn validate_csrf_token(token: &str, secret: &str) -> Result<(), ApiError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let parts: Vec<&str> = token.rsplitn(2, '.').collect();
    if parts.len() != 2 {
        return Err(ApiError::Forbidden("invalid CSRF token format".into()));
    }
    let (sig_part, nonce_part) = (parts[0], parts[1]);

    // Decode nonce
    let nonce_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        nonce_part,
    )
    .map_err(|_| ApiError::Forbidden("invalid CSRF token".into()))?;

    // Verify signature
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| ApiError::Internal("CSRF HMAC key error".into()))?;
    mac.update(&nonce_bytes);

    let sig_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, sig_part)
            .map_err(|_| ApiError::Forbidden("invalid CSRF token".into()))?;

    mac.verify_slice(&sig_bytes)
        .map_err(|_| ApiError::Forbidden("CSRF token validation failed".into()))?;

    // Check timestamp: tokens are valid for 1 hour, and — audit J — a token
    // stamped MORE than `CSRF_MAX_FUTURE_SKEW_MS` into the future is rejected
    // outright. Previously only the lower bound was enforced, so a token
    // minted with a far-future timestamp (e.g. by a client with a spoofed
    // clock, or an attacker who obtained the HMAC secret for one token)
    // never expired.
    if let Ok(nonce_str) = std::str::from_utf8(&nonce_bytes) {
        if let Some(ts_str) = nonce_str.split(':').next() {
            if let Ok(ts) = ts_str.parse::<i64>() {
                let now = chrono::Utc::now().timestamp_millis();
                let max_age_ms = 3600 * 1000; // 1 hour
                if now - ts > max_age_ms {
                    return Err(ApiError::Forbidden("CSRF token expired".into()));
                }
                if ts - now > CSRF_MAX_FUTURE_SKEW_MS {
                    return Err(ApiError::Forbidden(
                        "CSRF token timestamp is too far in the future".into(),
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Allowed clock skew for CSRF token timestamps (audit J): tokens stamped
/// further into the future than this are rejected as never-expiring.
const CSRF_MAX_FUTURE_SKEW_MS: i64 = 5 * 60 * 1000;

// ─── Form CSRF validation (no cookie required) ─────────────────

/// Validate a CSRF token from the `X-CSRF-Token` header of an auth form POST.
///
/// Unlike [`validate_session_csrf`] (which requires a `csrf_token` cookie),
/// auth-form submissions carry their CSRF token from an SSR-embedded hidden
/// input.  This function extracts it from the header and verifies the HMAC
/// signature directly.
pub fn validate_form_csrf(headers: &HeaderMap, csrf_secret: &str) -> Result<(), ApiError> {
    let header_token = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| ApiError::Forbidden("missing X-CSRF-Token header".into()))?;

    validate_csrf_token(header_token, csrf_secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mint_csrf_token(secret: &str, nonce: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let nonce_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            nonce.as_bytes(),
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(nonce.as_bytes());
        let sig = mac.finalize().into_bytes();
        let sig_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, sig);
        format!("{nonce_b64}.{sig_b64}")
    }

    #[test]
    fn test_csrf_token_generation_and_validation() {
        let secret = "test-csrf-secret";
        let nonce = "12345:some-uuid";
        let token = mint_csrf_token(secret, nonce);
        // Cannot validate because timestamp check (12345 ms ago) is expired
        // so just check the format
        assert!(token.contains('.'));
    }

    #[test]
    fn csrf_token_with_current_timestamp_validates() {
        let secret = "test-csrf-secret";
        let now = chrono::Utc::now().timestamp_millis();
        let token = mint_csrf_token(secret, &format!("{now}:uuid"));
        assert!(validate_csrf_token(&token, secret).is_ok());
    }

    #[test]
    fn csrf_token_expired_is_rejected() {
        let secret = "test-csrf-secret";
        let two_hours_ago = chrono::Utc::now().timestamp_millis() - 2 * 3600 * 1000;
        let token = mint_csrf_token(secret, &format!("{two_hours_ago}:uuid"));
        match validate_csrf_token(&token, secret) {
            Err(ApiError::Forbidden(message)) => {
                assert!(message.contains("expired"), "unexpected message: {message}");
            }
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }

    #[test]
    fn csrf_token_with_far_future_timestamp_is_rejected() {
        // Audit J: a correctly signed token stamped an hour into the future
        // used to pass validation forever (only the lower age bound was
        // checked). It must now be rejected.
        let secret = "test-csrf-secret";
        let future = chrono::Utc::now().timestamp_millis() + 3600 * 1000;
        let token = mint_csrf_token(secret, &format!("{future}:uuid"));
        match validate_csrf_token(&token, secret) {
            Err(ApiError::Forbidden(message)) => {
                assert!(message.contains("future"), "unexpected message: {message}");
            }
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }

    #[test]
    fn csrf_token_with_small_future_skew_is_accepted() {
        // 1 minute of clock skew between client and server is normal.
        let secret = "test-csrf-secret";
        let slightly_future = chrono::Utc::now().timestamp_millis() + 60 * 1000;
        let token = mint_csrf_token(secret, &format!("{slightly_future}:uuid"));
        assert!(validate_csrf_token(&token, secret).is_ok());
    }

    #[test]
    fn csrf_token_with_wrong_secret_or_bad_format_is_rejected() {
        let now = chrono::Utc::now().timestamp_millis();
        let token = mint_csrf_token("right-secret", &format!("{now}:uuid"));
        assert!(validate_csrf_token(&token, "wrong-secret").is_err());
        assert!(validate_csrf_token("no-dot-token", "secret").is_err());
        // Tampered signature.
        let tampered = format!("{}X", &token[..token.len() - 1]);
        assert!(validate_csrf_token(&tampered, "right-secret").is_err());
    }
}
