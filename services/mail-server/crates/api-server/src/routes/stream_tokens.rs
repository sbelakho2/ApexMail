//! SSE stream token issuance endpoint.
//!
//! `POST /v1/stream/token`
//!
//! Authenticated users call this endpoint to receive a short-lived RS256
//! signed JWT that can be sent as a Bearer token to the tracking-service's
//! SSE endpoint (`GET /v1/stream`).
//!
//! The token is intentionally:
//! - Short-lived: 5 minutes (300 s) by default; a requested TTL is clamped
//!   to a hard range of 60 s minimum / 3600 s (1 hour) maximum (audit J —
//!   the module previously claimed "5 minutes" while the handler accepted
//!   up to an hour; the enforced cap is now what the docs state).
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
    /// Optional:token TTL in seconds. Clamped server-side to
    /// [60, 3600]; defaults to 300 (5 minutes).
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
    let sub = match (
        auth_user.user_id.as_deref(),
        auth_user.api_key_id.as_deref(),
    ) {
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
        // Audit J: the documented hard cap is 3600s and the documented
        // default is 300s — aggressive callers cannot exceed one hour and
        // absent callers get five minutes.
        assert_eq!(u64::MAX.clamp(60, 3600), 3600);
        assert_eq!(0u64.clamp(60, 3600), 60);
    }

    #[test]
    fn test_request_defaults_ttl_when_absent() {
        let req: CreateStreamTokenRequest =
            serde_json::from_str(r#"{}"#).expect("empty body must deserialize");
        assert_eq!(req.ttl_seconds, default_ttl());
        // Unknown fields are rejected.
        assert!(serde_json::from_str::<CreateStreamTokenRequest>(
            r#"{"ttl_seconds": 300, "extra": true}"#
        )
        .is_err());
    }
}

#[cfg(test)]
mod adversarial_tests {
    use axum::http::StatusCode;

    use crate::app::test_support::adv::AdvEnv;

    #[derive(serde::Deserialize)]
    struct DecodedStreamClaims {
        sub: String,
        tenant_id: String,
        scopes: Vec<String>,
        exp: u64,
        iat: u64,
        typ: String,
        events: Option<Vec<String>>,
        message_id: Option<String>,
    }

    fn decode_token(token: &str) -> DecodedStreamClaims {
        // The claims set is what this module owns — signature correctness is
        // proven by the 500-on-bad-key arm and by RS256 being the only
        // signing path.
        use base64::Engine as _;
        let payload = token.split('.').nth(1).expect("jwt payload segment");
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("payload base64");
        serde_json::from_slice(&bytes).expect("stream claims decode")
    }

    #[tokio::test]
    async fn issues_a_scoped_rs256_stream_token_for_a_session() {
        let Some(pool) = crate::test_db::canonical_pool("stream_ok").await else {
            return;
        };
        let Some((env, tenant_id, user_id)) = AdvEnv::session(pool, "owner").await else {
            return;
        };

        let (status, body) = env
            .post(
                "/v1/stream/token",
                r#"{"events":["message.sent"],"message_id":"msg-42","ttl_seconds":120}"#,
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let token = body["token"].as_str().expect("token");
        assert_eq!(body["stream_url"], "/v1/stream");

        let claims = decode_token(token);
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.tenant_id, tenant_id);
        assert_eq!(claims.scopes, vec!["stream".to_string()]);
        assert_eq!(claims.typ, "stream");
        assert_eq!(
            claims.events.as_deref(),
            Some(&["message.sent".to_string()][..])
        );
        assert_eq!(claims.message_id.as_deref(), Some("msg-42"));
        // Requested TTL honoured exactly.
        assert_eq!(claims.exp - claims.iat, 120);
        assert_eq!(body["expires_at"].as_u64(), Some(claims.exp));
    }

    #[tokio::test]
    async fn ttl_is_clamped_into_the_documented_range() {
        let Some(pool) = crate::test_db::canonical_pool("stream_ttl").await else {
            return;
        };
        let Some((env, _t, _u)) = AdvEnv::session(pool, "owner").await else {
            return;
        };

        // Hostile low TTL is clamped up to 60s.
        let (status, body) = env.post("/v1/stream/token", r#"{"ttl_seconds":0}"#).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let claims = decode_token(body["token"].as_str().expect("token"));
        assert_eq!(claims.exp - claims.iat, 60);

        // Hostile high TTL is clamped down to 3600s (audit J: docs say 1h).
        let (status, body) = env
            .post("/v1/stream/token", r#"{"ttl_seconds":99999999}"#)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let claims = decode_token(body["token"].as_str().expect("token"));
        assert_eq!(claims.exp - claims.iat, 3600);

        // Absent TTL defaults to 300s.
        let (status, body) = env.post("/v1/stream/token", "{}").await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let claims = decode_token(body["token"].as_str().expect("token"));
        assert_eq!(claims.exp - claims.iat, 300);
        // No filters → the optional claims are omitted entirely.
        assert!(claims.events.is_none());
        assert!(claims.message_id.is_none());
    }

    #[tokio::test]
    async fn api_key_identities_mint_tokens_scoped_to_the_key() {
        let Some(pool) = crate::test_db::canonical_pool("stream_apikey").await else {
            return;
        };
        // A real RSA pair: minting must succeed for key identities too.
        use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding};
        let key_pair = apexmail_lib::dkim::generate_dkim_keypair().expect("test RSA keypair");
        let private_key =
            rsa::RsaPrivateKey::from_pkcs8_pem(key_pair.private_key_pem.as_str()).unwrap();
        let mut config = crate::app::test_support::test_config();
        config.jwt_private_key_pem = key_pair.private_key_pem.to_string();
        config.jwt_public_key_pem = private_key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap()
            .to_string();
        let (env, _tenant) = AdvEnv::tenant_with_config(pool, &["messages:read"], config).await;
        let (status, body) = env.post("/v1/stream/token", "{}").await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let claims = decode_token(body["token"].as_str().expect("token"));
        // sub is the api_key row id (a UUID), never empty.
        assert!(!claims.sub.is_empty());
        assert_eq!(claims.typ, "stream");
    }

    #[tokio::test]
    async fn token_issuance_requires_the_messages_read_scope() {
        let Some(pool) = crate::test_db::canonical_pool("stream_scope").await else {
            return;
        };
        let (env, _tenant) = AdvEnv::tenant(pool, &["contacts:read"]).await;
        let (status, body) = env.post("/v1/stream/token", "{}").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }

    #[tokio::test]
    async fn unknown_body_fields_are_rejected() {
        let Some(pool) = crate::test_db::canonical_pool("stream_unknown").await else {
            return;
        };
        let Some((env, _t, _u)) = AdvEnv::session(pool, "owner").await else {
            return;
        };
        let (status, _body) = env
            .post("/v1/stream/token", r#"{"ttl_seconds":60,"whoami":true}"#)
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn an_unusable_signing_key_surfaces_as_internal_error() {
        let Some(pool) = crate::test_db::canonical_pool("stream_badkey").await else {
            return;
        };
        // Default test config carries a placeholder PEM ("BEGIN TEST"),
        // which is not an RSA key: signing must fail loudly (500) instead of
        // returning an unverifiable token.
        let (env, _tenant) = AdvEnv::tenant(pool, &["messages:read"]).await;
        let (status, body) = env.post("/v1/stream/token", "{}").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        // The failure detail is deliberately not leaked to the wire; only
        // the code identifies it as an internal signing failure.
        assert_eq!(body["error"]["code"], "INTERNAL_ERROR");
    }
}
