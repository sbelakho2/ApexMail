//! Session introspection endpoint.
//!
//! Provides current session state including impersonation status.

use super::helpers::extract_cookie;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::error::ApiError;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(get_session))
}

// ─── Response types ────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub authenticated: bool,
    pub impersonation: Option<ImpersonationInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ImpersonationInfo {
    pub tenant_id: String,
    pub operator_id: String,
    pub operator_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

// ─── Handler ───────────────────────────────────────────────────

async fn get_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SessionResponse>, ApiError> {
// Check for E2E bypass (non-production only)
    if !state.config.environment.is_production() {
        if let Ok(e2e_mode) = std::env::var("E2E_TEST_MODE") {
            if e2e_mode == "true" {
                if let Some(provided) = headers.get("x-e2e-bypass-key") {
                    if let Ok(expected) = std::env::var("E2E_BYPASS_KEY") {
                        if let Ok(provided_str) = provided.to_str() {
                            if constant_time_eq(provided_str.as_bytes(), expected.as_bytes()) {
                                return Ok(Json(SessionResponse {
                                    authenticated: true,
                                    impersonation: None,
                                    session_type: Some("e2e".into()),
                                    user: None,
                                }));
                            }
                        }
                    }
                }
            }
        }
    }

    let mut response = SessionResponse {
        authenticated: false,
        impersonation: None,
        session_type: None,
        user: None,
    };

// Check for impersonation session cookie
    let impersonation_token = extract_cookie(&headers, "impersonation_session");
    if let Some(token) = impersonation_token {
        if let Ok(payload) = verify_session_token(&token, &state.config.session_secret) {
            if payload.token_type.as_deref() == Some("impersonation") {
                response.authenticated = true;
                response.impersonation = Some(ImpersonationInfo {
                    tenant_id: payload.tenant_id.unwrap_or_default(),
                    operator_id: payload.operator_id.unwrap_or_default(),
                    operator_name: payload.operator_name.unwrap_or_else(|| "Operator".into()),
                    exp: payload.exp,
                    expires_at: payload.exp,
                });
                response.session_type = Some("impersonation".into());
            }
        }
    }

// Check regular user session if no impersonation
    if !response.authenticated {
        let user_token = extract_cookie(&headers, "am_session")
            .or_else(|| {
                headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Bearer "))
                    .map(|s| s.to_string())
            });

        if let Some(token) = user_token {
// Validate JWT against our public key
            let key = jsonwebtoken::DecodingKey::from_rsa_pem(
                state.config.jwt_public_key_pem.as_bytes(),
            );
            if let Ok(key) = key {
                let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
                validation.set_required_spec_claims(&["exp", "sub", "tenant_id"]);
                if let Ok(token_data) = jsonwebtoken::decode::<crate::middleware::auth::JwtClaims>(
                    &token, &key, &validation,
                ) {
                    let claims = token_data.claims;
                    let user_id = claims.sub.clone();
                    if !user_id.is_empty() {
// Check user still exists and is active
                        let user: Option<(String, String, Option<String>, String)> =
                            sqlx::query_as(
                                "SELECT id, email, name, role FROM users WHERE id = $1 AND status = 'active'",
                            )
                            .bind(&user_id)
                            .fetch_optional(&state.db)
                            .await?;

                        if let Some((id, email, name, role)) = user {
                            response.authenticated = true;
                            response.session_type = Some("user".into());
                            response.user = Some(serde_json::json!({
                                "id": id,
                                "email": email,
                                "name": name,
                                "role": role,
                            }));
                        }
                    }
                }
            }
        }
    }

    Ok(Json(response))
}

// ─── Helpers ───────────────────────────────────────────────────

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[derive(Debug, serde::Deserialize)]
struct SessionPayload {
    #[serde(rename = "type")]
    token_type: Option<String>,
    tenant_id: Option<String>,
    operator_id: Option<String>,
    operator_name: Option<String>,
    exp: Option<i64>,
}

fn verify_session_token(token: &str, secret: &str) -> Result<SessionPayload, ApiError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

// Token format:base64url(payload).base64url(signature)
    let parts: Vec<&str> = token.rsplitn(2, '.').collect();
    if parts.len() != 2 {
        return Err(ApiError::Unauthorized("invalid session token format".into()));
    }
    let (sig_part, payload_part) = (parts[0], parts[1]);

// Verify HMAC
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| ApiError::Internal("HMAC key error".into()))?;
    mac.update(payload_part.as_bytes());

    let sig_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        sig_part,
    )
    .map_err(|_| ApiError::Unauthorized("invalid session token signature encoding".into()))?;

    mac.verify_slice(&sig_bytes)
        .map_err(|_| ApiError::Unauthorized("invalid session token signature".into()))?;

// Decode payload
    let payload_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        payload_part,
    )
    .map_err(|_| ApiError::Unauthorized("invalid session token payload".into()))?;

    let payload: SessionPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|_| ApiError::Unauthorized("invalid session token payload".into()))?;

// Check expiry
    if let Some(exp) = payload.exp {
        let now_ms = chrono::Utc::now().timestamp_millis();
        if now_ms > exp {
            return Err(ApiError::Unauthorized("session token expired".into()));
        }
    }

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            "am_session=abc123; impersonation_session=xyz789"
                .parse()
                .unwrap(),
        );
        assert_eq!(extract_cookie(&headers, "am_session"), Some("abc123".into()));
        assert_eq!(
            extract_cookie(&headers, "impersonation_session"),
            Some("xyz789".into())
        );
        assert_eq!(extract_cookie(&headers, "nonexistent"), None);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }
}
