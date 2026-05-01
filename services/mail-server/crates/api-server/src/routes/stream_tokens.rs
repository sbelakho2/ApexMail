//! SSE stream token issuance endpoint.
//!
//! `POST /v1/stream/token`
//!
//! Authenticated users call this endpoint to receive a short-lived HMAC-SHA256
//! signed JWT that can be sent as a Bearer token to the tracking-service's
//! SSE endpoint (`GET /v1/stream`).
//!
//! The token is intentionally://! - Short-lived (5 minutes) to limit replay window.
//! - Signed with HMAC-SHA256 using the shared `TRACKING_SECRET_KEY`
//! (the same key the tracking-service uses to verify).
//! - Scoped to `["stream"]` — the tracking-service rejects tokens without
//! this scope.
//!
//! This endpoint requires standard API authentication (Bearer JWT or X-API-Key).

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/token", post(create_stream_token))
}

/// Request body (optional:allows specifying filters embedded in token).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateStreamTokenRequest {
    /// Optional:restrict token to specific event types.
    #[serde(default)]
    pub events: Option<Vec<String>>,
    /// Optional:restrict token to a specific message ID.
    #[serde(default)]
    pub message_id: Option<String>,
    /// Optional:token TTL in seconds (max 3600, default 300).
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u64,
}

fn default_ttl() -> u64 {
    300
}

/// Response with the signed SSE token.
#[derive(Debug, Serialize)]
pub struct StreamTokenResponse {
    /// The HMAC-SHA256 signed JWT for SSE connections.
    pub token: String,
    /// Expiration Unix timestamp.
    pub expires_at: u64,
    /// SSE endpoint URL hint. Send `token` as `Authorization: Bearer <token>`.
    pub stream_url: String,
}

/// `POST /v1/stream/token` — issue a short-lived SSE stream token.
async fn create_stream_token(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Json(body): Json<CreateStreamTokenRequest>,
) -> Result<(StatusCode, Json<StreamTokenResponse>), ApiError> {
    // Clamp TTL:60s minimum, 3600s maximum
    let ttl = body.ttl_seconds.clamp(60, 3600);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let exp = now + ttl;

    // Build JWT claims
    let claims = StreamTokenClaims {
        sub: auth_user
            .user_id
            .unwrap_or_else(|| auth_user.api_key_id.unwrap_or_default()),
        tenant_id: auth_user.tenant_id.clone(),
        scopes: vec!["stream".to_string()],
        exp,
        iat: now,
        events: body.events,
        message_id: body.message_id,
    };

    let claims_json = serde_json::to_vec(&claims)
        .map_err(|e| ApiError::Internal(format!("failed to serialize token claims: {e}")))?;

    // Construct the JWT:base64url(header).base64url(claims).base64url(signature)
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = b64.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = b64.encode(&claims_json);
    let signing_input = format!("{header}.{payload}");

    // HMAC-SHA256 signature with the shared tracking secret
    use hmac::Mac;
    let mut mac =
        hmac::Hmac::<sha2::Sha256>::new_from_slice(state.config.tracking_secret_key.as_bytes())
            .map_err(|_| ApiError::Internal("HMAC key error".into()))?;
    mac.update(signing_input.as_bytes());
    let signature = mac.finalize().into_bytes();
    let sig_b64 = b64.encode(signature);

    let token = format!("{signing_input}.{sig_b64}");

    Ok((
        StatusCode::CREATED,
        Json(StreamTokenResponse {
            token,
            expires_at: exp,
            stream_url: "/v1/stream".to_string(),
        }),
    ))
}

/// Claims embedded in the SSE stream token (matches tracking-service's
/// `StreamClaims` deserialization).
#[derive(Debug, Serialize)]
struct StreamTokenClaims {
    /// User ID or API key ID.
    pub sub: String,
    /// Tenant ID.
    pub tenant_id: String,
    /// Scopes — always `["stream"]`.
    pub scopes: Vec<String>,
    /// Expiration (Unix timestamp).
    pub exp: u64,
    /// Issued-at (Unix timestamp).
    pub iat: u64,
    /// Optional event type filter (informational, also enforced client-side).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<String>>,
    /// Optional message ID filter (informational).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_ttl() {
        assert_eq!(default_ttl(), 300);
    }

    #[test]
    fn test_ttl_clamping() {
        // Min
        assert_eq!(10u64.clamp(60, 3600), 60);
        // Normal
        assert_eq!(300u64.clamp(60, 3600), 300);
        // Max
        assert_eq!(7200u64.clamp(60, 3600), 3600);
    }
}
