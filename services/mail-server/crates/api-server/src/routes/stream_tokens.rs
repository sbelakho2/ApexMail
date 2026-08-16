//! SSE stream token issuance endpoint.
//!
//! `POST /v1/stream/token`
//!
//! Authenticated users call this endpoint to receive a short-lived RS256
//! signed JWT that can be sent as a Bearer token to the tracking-service's
//! SSE endpoint (`GET /v1/stream`).
//!
//! The token is intentionally:
//! - Short-lived (5 minutes) to limit replay window.
//! - Signed with RS256 using the application's RSA private key
//!   (the same public key the tracking-service uses to verify).
//! - Scoped to `["stream"]` — the tracking-service rejects tokens without
//!   this scope.
//!
//! SECURITY (SEC-119): All JWT operations use RS256 (asymmetric) to prevent
//! algorithm confusion attacks. HS256 is not used for any JWT tokens.
//!
//! This endpoint requires standard API authentication (Bearer JWT or X-API-Key).

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
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
    /// The RS256-signed JWT for SSE connections.
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
    // Reading the live event stream is read-level access to message data.
    require_scopes(&auth_user, &["messages:read"])?;

    // The token's `sub` must identify a concrete principal. Without this
    // check an identity carrying neither user_id nor api_key_id would
    // mint a token with an empty `sub`.
    let sub = match (auth_user.user_id.as_deref(), auth_user.api_key_id.as_deref()) {
        (Some(user_id), _) => user_id.to_string(),
        (None, Some(api_key_id)) => api_key_id.to_string(),
        (None, None) => {
            tracing::warn!(
                tenant_id = %auth_user.tenant_id,
                "stream token request without a user or API key identity — rejected"
            );
            return Err(ApiError::Unauthorized(
                "stream tokens require an authenticated user or API key".into(),
            ));
        }
    };

    // Clamp TTL:60s minimum, 3600s maximum
    let ttl = body.ttl_seconds.clamp(60, 3600);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let exp = now + ttl;

    // Build JWT claims
    let claims = StreamTokenClaims {
        sub,
        tenant_id: auth_user.tenant_id.clone(),
        scopes: vec!["stream".to_string()],
        exp,
        iat: now,
        // Discriminates stream tokens from session tokens: the api-server
        // rejects any Bearer token whose typ is set and != "session", so a
        // stream token can never be replayed as an API session token.
        typ: "stream",
        events: body.events,
        message_id: body.message_id,
    };

    // Sign with RS256 using the application's RSA private key
    let token = encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(state.config.jwt_private_key_pem.as_bytes())
            .map_err(|e| ApiError::Internal(format!("invalid JWT private key: {e}")))?,
    )
    .map_err(|e| ApiError::Internal(format!("failed to encode stream token: {e}")))?;

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
    /// Token type — always "stream" (session tokens use "session").
    pub typ: &'static str,
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
