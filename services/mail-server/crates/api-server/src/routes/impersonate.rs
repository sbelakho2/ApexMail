//! Impersonation endpoints.
//!
//! Allows platform operators to impersonate tenant accounts.
//! All impersonation events are audit-logged.
//! CRITICAL SECURITY: All endpoints require admin-level (*) scope.

use super::helpers::extract_cookie;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, require_system_tenant, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(start_impersonation))
        .route("/end", post(end_impersonation))
}

// ─── Request / Response types ──────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImpersonateRequest {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct EndImpersonationResponse {
    pub success: bool,
}

#[derive(Debug, Deserialize)]
struct ImpersonationTokenPayload {
    #[serde(rename = "type")]
    token_type: Option<String>,
    #[serde(rename = "tenantId")]
    tenant_id: Option<String>,
    #[serde(rename = "operatorId")]
    operator_id: Option<String>,
    #[serde(rename = "operatorName")]
    operator_name: Option<String>,
    exp: Option<i64>,
    jti: Option<String>,
}

// ─── Start impersonation ──────────────────────────────────────

async fn start_impersonation(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<ImpersonateRequest>,
) -> Result<Response, ApiError> {
    // CRITICAL: Only platform admins can start impersonation sessions.
    // Audit D: `require_scopes(&["*"])` alone is NOT sufficient — every
    // customer tenant owner also carries the wildcard scope (see
    // `scopes_for_role`), which would let any tenant admin mint an
    // impersonation session. Impersonation is a control-plane capability
    // and additionally requires the system tenant.
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&auth)?;

    if body.token.is_empty() {
        return Err(ApiError::BadRequest("missing impersonation token".into()));
    }

    // Validate the impersonation token
    let payload = verify_impersonation_token(&body.token, &state.config.impersonation_secret)?;

    // Validate token type
    if payload.token_type.as_deref() != Some("impersonation") {
        return Err(ApiError::Unauthorized(
            "invalid impersonation token type".into(),
        ));
    }

    let tenant_id = payload
        .tenant_id
        .as_deref()
        .ok_or_else(|| ApiError::BadRequest("missing tenant_id in impersonation token".into()))?;
    let operator_id = payload
        .operator_id
        .as_deref()
        .ok_or_else(|| ApiError::BadRequest("missing operator_id in impersonation token".into()))?;
    let operator_name = payload.operator_name.as_deref().unwrap_or("Operator");
    // Audit D: `exp` and `jti` are mandatory — `verify_impersonation_token`
    // already rejected missing/expired/too-long-lived tokens, and the jti is
    // consumed single-use below. `unwrap_or(0)`/`unwrap_or_default()` used to
    // silently accept tokens with no expiry at all.
    let exp = payload
        .exp
        .ok_or_else(|| ApiError::Unauthorized("impersonation token missing expiry".into()))?;
    let jti = payload
        .jti
        .as_deref()
        .filter(|jti| !jti.is_empty())
        .ok_or_else(|| ApiError::Unauthorized("impersonation token missing token ID".into()))?;

    // Audit D: consume-on-use — the jti is recorded in Redis with a TTL for
    // the remaining token lifetime, so a captured token cannot be replayed.
    // Fails CLOSED when Redis is unavailable (a replayable impersonation
    // session is worse than a temporarily unavailable one).
    consume_impersonation_jti(&state, jti, exp).await?;

    // Audit log the impersonation start before creating the session cookie.
    write_impersonation_audit_log(
        &state,
        "impersonation_session_started",
        jti,
        tenant_id,
        serde_json::json!({
            "operator_id": operator_id,
            "operator_name": operator_name,
            "token_id": jti,
        }),
    )
    .await?;

    tracing::info!(
        operator_id = %operator_id,
        operator_name = %operator_name,
        tenant_id = %tenant_id,
        token_id = %jti,
        "Impersonation session started"
    );

    // Create session token for the impersonation
    let session_payload = serde_json::json!({
        "type": "impersonation",
        "tenantId": tenant_id,
        "operatorId": operator_id,
        "operatorName": operator_name,
        "tokenId": jti,
        "exp": exp,
    });
    let session_token = create_signed_token(&session_payload, &state.config.session_secret)?;

    // Calculate cookie max-age from token expiry
    let now_ms = chrono::Utc::now().timestamp_millis();
    let max_age_secs = if exp > now_ms {
        (exp - now_ms) / 1000
    } else {
        3600 // Default 1 hour
    };

    let mut response = Redirect::to("/dashboard").into_response();
    let cookie = format!(
        "impersonation_session={session_token}; HttpOnly; Path=/; Max-Age={max_age_secs}; SameSite=Strict{}",
        if state.config.environment.is_production() { "; Secure" } else { "" }
    );
    let val = cookie.parse().map_err(|e| {
        tracing::error!(error = %e, "failed to build impersonation cookie header");
        ApiError::Internal("failed to set impersonation cookie".into())
    })?;
    response.headers_mut().insert("Set-Cookie", val);

    Ok(response)
}

// ─── End impersonation ────────────────────────────────────────

async fn end_impersonation(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    // CRITICAL: Only platform admins can end impersonation sessions.
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&auth)?;

    // Try to read the impersonation cookie for audit logging
    let imp_token = extract_cookie(&headers, "impersonation_session");
    if let Some(token) = imp_token {
        if let Ok(payload) = verify_session_token_soft(&token, &state.config.session_secret) {
            // Audit log the end before clearing the impersonation cookie.
            write_impersonation_audit_log(
                &state,
                "impersonation_session_ended",
                payload
                    .get("tokenId")
                    .and_then(|v| v.as_str())
                    .unwrap_or(""),
                payload
                    .get("tenantId")
                    .and_then(|v| v.as_str())
                    .unwrap_or(""),
                payload.clone(),
            )
            .await?;

            tracing::info!(
                operator_id = payload
                    .get("operatorId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown"),
                tenant_id = payload
                    .get("tenantId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown"),
                "Impersonation session ended"
            );
        }
    }

    // Clear the impersonation cookie
    let mut response = (
        StatusCode::OK,
        Json(EndImpersonationResponse { success: true }),
    )
        .into_response();

    let clear_cookie = format!(
        "impersonation_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict{}",
        if state.config.environment.is_production() {
            "; Secure"
        } else {
            ""
        }
    );
    let val = clear_cookie.parse().map_err(|e| {
        tracing::error!(error = %e, "failed to build clear-impersonation cookie header");
        ApiError::Internal("failed to clear impersonation cookie".into())
    })?;
    response.headers_mut().insert("Set-Cookie", val);

    Ok(response)
}

async fn write_impersonation_audit_log(
    state: &AppState,
    action: &str,
    resource_id: &str,
    tenant_id: &str,
    metadata: serde_json::Value,
) -> Result<(), ApiError> {
    crate::audit_log::insert_audit_log(
        &state.db,
        Some(tenant_id),
        None,
        action,
        "session",
        Some(resource_id),
        metadata,
        None,
        None,
    )
    .await
    .map_err(|error| {
        tracing::error!(error = %error, action = %action, resource_id = %resource_id, tenant_id = %tenant_id, "failed to write impersonation audit log");
        ApiError::Internal("impersonation audit logging failed".into())
    })?;

    Ok(())
}

// ─── Token helpers ─────────────────────────────────────────────

/// Server-side maximum impersonation-token lifetime (audit D): tokens whose
/// `exp` is further than 1 hour in the future are rejected even though they
/// are correctly signed, so a leaked signing secret cannot mint
/// never-expiring sessions.
const MAX_IMPERSONATION_TOKEN_TTL_MS: i64 = 60 * 60 * 1000;

fn verify_impersonation_token(
    token: &str,
    secret: &str,
) -> Result<ImpersonationTokenPayload, ApiError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let parts: Vec<&str> = token.rsplitn(2, '.').collect();
    if parts.len() != 2 {
        return Err(ApiError::Unauthorized(
            "invalid impersonation token format".into(),
        ));
    }
    let (sig_part, payload_part) = (parts[0], parts[1]);

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| ApiError::Internal("HMAC key error".into()))?;
    mac.update(payload_part.as_bytes());

    let sig_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, sig_part)
            .map_err(|_| ApiError::Unauthorized("invalid token signature encoding".into()))?;

    mac.verify_slice(&sig_bytes)
        .map_err(|_| ApiError::Unauthorized("invalid impersonation token signature".into()))?;

    let payload_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        payload_part,
    )
    .map_err(|_| ApiError::Unauthorized("invalid token payload encoding".into()))?;

    let payload: ImpersonationTokenPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|_| ApiError::Unauthorized("invalid token payload".into()))?;

    // Audit D: expiry is MANDATORY. Previously `if let Some(exp)` meant a
    // token without `exp` never expired — a permanent impersonation backdoor.
    let exp = payload
        .exp
        .ok_or_else(|| ApiError::Unauthorized("impersonation token missing expiry".into()))?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    if now_ms > exp {
        return Err(ApiError::Unauthorized("impersonation token expired".into()));
    }
    // Cap the server-side lifetime: reject tokens that promise to live
    // longer than the 1-hour maximum.
    if exp - now_ms > MAX_IMPERSONATION_TOKEN_TTL_MS {
        return Err(ApiError::Unauthorized(
            "impersonation token lifetime exceeds the maximum of 1 hour".into(),
        ));
    }

    Ok(payload)
}

/// Consume an impersonation token's `jti` single-use (audit D).
///
/// Records the jti in Redis (`SET NX EX`) for the token's remaining lifetime
/// plus a small buffer. A second presentation of the same jti is rejected as
/// a replay. Fails CLOSED (503) when Redis is unavailable so tokens cannot be
/// replayed during an outage.
async fn consume_impersonation_jti(
    state: &AppState,
    jti: &str,
    exp_ms: i64,
) -> Result<(), ApiError> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let remaining_ms = (exp_ms - now_ms).max(0);
    // Keep the tombstone slightly longer than the token's own validity.
    let ttl_secs =
        ((remaining_ms + 5_000) / 1000).clamp(1, MAX_IMPERSONATION_TOKEN_TTL_MS / 1000 + 5) as u64;

    let key = format!("apexmail:impersonation_used:{jti}");
    let mut conn = state.redis.get().await.map_err(|error| {
        tracing::error!(error = %error, "Redis unavailable for impersonation single-use check");
        ApiError::ServiceUnavailable(
            "impersonation is temporarily unavailable — try again later".into(),
        )
    })?;

    let newly_set: Option<String> = deadpool_redis::redis::cmd("SET")
        .arg(&key)
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(ttl_secs)
        .query_async(&mut *conn)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "Redis SET NX failed for impersonation single-use check");
            ApiError::ServiceUnavailable(
                "impersonation is temporarily unavailable — try again later".into(),
            )
        })?;

    if newly_set.is_none() {
        tracing::warn!(token_id = %jti, "rejected replay of impersonation token");
        return Err(ApiError::Unauthorized(
            "impersonation token has already been used".into(),
        ));
    }

    Ok(())
}

fn create_signed_token(payload: &serde_json::Value, secret: &str) -> Result<String, ApiError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let payload_json = serde_json::to_vec(payload)
        .map_err(|e| ApiError::Internal(format!("token serialization failed: {e}")))?;
    let payload_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &payload_json,
    );

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| ApiError::Internal("HMAC key error".into()))?;
    mac.update(payload_b64.as_bytes());
    let sig = mac.finalize().into_bytes();
    let sig_b64 = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, sig);

    Ok(format!("{payload_b64}.{sig_b64}"))
}

fn verify_session_token_soft(token: &str, secret: &str) -> Result<serde_json::Value, ()> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let parts: Vec<&str> = token.rsplitn(2, '.').collect();
    if parts.len() != 2 {
        return Err(());
    }
    let (sig_part, payload_part) = (parts[0], parts[1]);

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|_| ())?;
    mac.update(payload_part.as_bytes());
    let sig_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, sig_part)
            .map_err(|_| ())?;
    mac.verify_slice(&sig_bytes).map_err(|_| ())?;

    let payload_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        payload_part,
    )
    .map_err(|_| ())?;

    serde_json::from_slice(&payload_bytes).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_verify_signed_token() {
        let payload = serde_json::json!({"type": "impersonation", "tenantId": "t1"});
        let secret = "test-secret";
        let token = create_signed_token(&payload, secret).unwrap();
        assert!(token.contains('.'));

        // Verify the soft verification also works
        let decoded = verify_session_token_soft(&token, secret).unwrap();
        assert_eq!(decoded["type"], "impersonation");
        assert_eq!(decoded["tenantId"], "t1");
    }

    #[test]
    fn test_create_signed_token_tamper_detection() {
        let payload = serde_json::json!({"type": "impersonation"});
        let token = create_signed_token(&payload, "secret1").unwrap();
        // Should fail with different secret
        assert!(verify_session_token_soft(&token, "wrong-secret").is_err());
    }

    // ── Audit D: mandatory expiry, expiry enforcement, lifetime cap ──

    fn impersonation_token(secret: &str, exp: Option<i64>, jti: Option<&str>) -> String {
        let mut payload = serde_json::json!({
            "type": "impersonation",
            "tenantId": "ten_victim",
            "operatorId": "op_admin",
        });
        if let Some(exp) = exp {
            payload["exp"] = exp.into();
        }
        if let Some(jti) = jti {
            payload["jti"] = jti.into();
        }
        create_signed_token(&payload, secret).unwrap()
    }

    #[test]
    fn impersonation_token_without_expiry_is_rejected() {
        // A correctly signed token carrying no `exp` used to be valid
        // forever — it must now be rejected outright.
        let token = impersonation_token("secret", None, Some("jti-1"));
        match verify_impersonation_token(&token, "secret") {
            Err(ApiError::Unauthorized(message)) => {
                assert!(message.contains("expiry"), "unexpected message: {message}");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn impersonation_token_expired_is_rejected() {
        let expired = chrono::Utc::now().timestamp_millis() - 1000;
        let token = impersonation_token("secret", Some(expired), Some("jti-2"));
        match verify_impersonation_token(&token, "secret") {
            Err(ApiError::Unauthorized(message)) => {
                assert!(message.contains("expired"), "unexpected message: {message}");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn impersonation_token_lifetime_capped_at_one_hour() {
        let now_ms = chrono::Utc::now().timestamp_millis();
        // Valid for 2 hours — within signature validity but over the cap.
        let too_long = now_ms + 2 * 60 * 60 * 1000;
        let token = impersonation_token("secret", Some(too_long), Some("jti-3"));
        match verify_impersonation_token(&token, "secret") {
            Err(ApiError::Unauthorized(message)) => {
                assert!(message.contains("maximum"), "unexpected message: {message}");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }

        // Valid for 30 minutes — accepted.
        let reasonable = now_ms + 30 * 60 * 1000;
        let token = impersonation_token("secret", Some(reasonable), Some("jti-4"));
        let payload = verify_impersonation_token(&token, "secret")
            .expect("30-minute impersonation token must validate");
        assert_eq!(payload.tenant_id.as_deref(), Some("ten_victim"));
    }

    #[test]
    fn impersonation_token_with_wrong_signature_is_rejected() {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let token = impersonation_token("right-secret", Some(now_ms + 60_000), Some("jti-5"));
        assert!(verify_impersonation_token(&token, "wrong-secret").is_err());
    }

    #[test]
    fn impersonation_token_garbage_format_is_rejected() {
        assert!(verify_impersonation_token("not-a-token", "secret").is_err());
        assert!(verify_impersonation_token("only-one-part", "secret").is_err());
        // Tampered payload (signature no longer matches).
        let now_ms = chrono::Utc::now().timestamp_millis();
        let token = impersonation_token("secret", Some(now_ms + 60_000), Some("jti-6"));
        let (payload, sig) = token.rsplit_once('.').unwrap();
        let tampered = format!("{payload}X.{sig}");
        assert!(verify_impersonation_token(&tampered, "secret").is_err());
    }
}
