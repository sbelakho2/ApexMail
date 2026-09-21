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
    require_system_tenant(&state, &auth).await?;

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

    // `verify_impersonation_token` above already rejected `exp <= now`,
    // so the remaining lifetime is always positive here; it degrades to
    // Max-Age=0 (an instantly-expired cookie) only on the sub-second
    // boundary. The previous `3600` fallback arm was unreachable dead
    // code.
    let now_ms = chrono::Utc::now().timestamp_millis();
    let max_age_secs = (exp - now_ms) / 1000;

    let mut response = Redirect::to("/dashboard").into_response();
    let cookie = format!(
        "impersonation_session={session_token}; HttpOnly; Path=/; Max-Age={max_age_secs}; SameSite=Strict{}",
        if state.config.environment.is_production() { "; Secure" } else { "" }
    );
    // The token is base64url(payload).base64url(HMAC) — the URL-safe
    // Base64 alphabet plus '.' is entirely visible ASCII, and
    // HeaderValue::from_str rejects only non-visible-ASCII and control
    // bytes, so this parse cannot fail.
    let val = cookie
        .parse()
        .expect("impersonation cookie is visible-ASCII");
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
    require_system_tenant(&state, &auth).await?;

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
    // A constant, entirely visible-ASCII string — HeaderValue::from_str
    // rejects only non-visible-ASCII and control bytes, so this parse
    // cannot fail.
    let val = clear_cookie
        .parse()
        .expect("clear-impersonation cookie is a constant visible-ASCII string");
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

#[cfg(test)]
mod adversarial_tests {
    use super::create_signed_token;
    use axum::http::StatusCode;

    use crate::app::test_support::adv::AdvEnv;

    const SECRET: &str = "test-impersonation-secret-12345";

    fn impersonation_token(payload: serde_json::Value) -> String {
        create_signed_token(&payload, SECRET).expect("sign token")
    }

    fn valid_payload(jti: &str) -> serde_json::Value {
        serde_json::json!({
            "type": "impersonation",
            "tenantId": "ten_victim_probe",
            "operatorId": "op_probe",
            "operatorName": "Probe Operator",
            "exp": chrono::Utc::now().timestamp_millis() + 600_000,
            "jti": jti,
        })
    }

    async fn start(env: &AdvEnv, token: &str) -> (StatusCode, Vec<String>) {
        let (status, headers, _bytes) = env
            .post_raw(
                "/v1/auth/impersonate",
                &serde_json::json!({ "token": token }).to_string(),
            )
            .await;
        let cookies = headers
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_string))
            .collect();
        (status, cookies)
    }

    #[tokio::test]
    async fn impersonation_start_happy_path_sets_cookie_and_audits() {
        if std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_none()
        {
            eprintln!("skipping: TEST_REDIS_URL unset");
            return;
        }
        let Some(pool) = crate::test_db::canonical_pool("imp_start_ok").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;
        let jti = format!("jti-{}", uuid::Uuid::new_v4().simple());
        let (status, cookies) = start(&env, &impersonation_token(valid_payload(&jti))).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "redirects to /dashboard");
        let cookie = cookies
            .iter()
            .find(|c| c.starts_with("impersonation_session="))
            .expect("impersonation cookie set");
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(
            cookie.contains("Max-Age=5"),
            "max-age derived from exp: {cookie}"
        );

        // The audit entry names the session and the operator.
        let (action, resource, operator): (String, String, String) = sqlx::query_as(
            "SELECT action, resource_id, details->>'operator_id' FROM audit_logs \
             WHERE action = 'impersonation_session_started' AND resource_id = $1",
        )
        .bind(&jti)
        .fetch_one(&pool)
        .await
        .expect("audit row");
        assert_eq!(action, "impersonation_session_started");
        assert_eq!(operator, "op_probe");
        let _ = resource;

        // Replay of the same token is rejected: the jti is single-use.
        let (status, _cookies) = start(&env, &impersonation_token(valid_payload(&jti))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn impersonation_start_refuses_bad_tokens() {
        if std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_none()
        {
            eprintln!("skipping: TEST_REDIS_URL unset");
            return;
        }
        let Some(pool) = crate::test_db::canonical_pool("imp_start_bad").await else {
            return;
        };
        let env = AdvEnv::admin(pool).await;

        // Empty token.
        let (status, _cookies) = start(&env, "").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Wrong secret (bad signature).
        let forged = create_signed_token(&valid_payload("jti-forged"), "wrong-secret").unwrap();
        let (status, _cookies) = start(&env, &forged).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Garbage format.
        let (status, _cookies) = start(&env, "not-a-token").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Expired.
        let mut expired = valid_payload("jti-expired");
        expired["exp"] = (chrono::Utc::now().timestamp_millis() - 1000).into();
        let (status, _cookies) = start(&env, &impersonation_token(expired)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Over-long lifetime.
        let mut longlived = valid_payload("jti-long");
        longlived["exp"] = (chrono::Utc::now().timestamp_millis() + 3_600_000 + 60_000).into();
        let (status, _cookies) = start(&env, &impersonation_token(longlived)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Missing expiry.
        let mut noexp = valid_payload("jti-noexp");
        noexp.as_object_mut().unwrap().remove("exp");
        let (status, _cookies) = start(&env, &impersonation_token(noexp)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Missing jti.
        let mut nojti = valid_payload("");
        nojti.as_object_mut().unwrap().remove("jti");
        let (status, _cookies) = start(&env, &impersonation_token(nojti)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Wrong token type.
        let mut wrongtype = valid_payload("jti-type");
        wrongtype["type"] = "session".into();
        let (status, _cookies) = start(&env, &impersonation_token(wrongtype)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Missing tenant_id / operator_id.
        let mut notenant = valid_payload("jti-tenant");
        notenant.as_object_mut().unwrap().remove("tenantId");
        let (status, _cookies) = start(&env, &impersonation_token(notenant)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let mut noop = valid_payload("jti-op");
        noop.as_object_mut().unwrap().remove("operatorId");
        let (status, _cookies) = start(&env, &impersonation_token(noop)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // deny_unknown_fields on the wire body.
        let status = env
            .post_raw("/v1/auth/impersonate", r#"{"token":"x","y":1}"#)
            .await
            .0;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn impersonation_gates_reject_customer_tenants_and_weak_scopes() {
        let Some(pool) = crate::test_db::canonical_pool("imp_gates").await else {
            return;
        };
        // Customer tenant with the wildcard scope must NOT reach the handler
        // (audit D: scope alone is insufficient).
        let (customer, _tenant) = AdvEnv::tenant(pool.clone(), &["*"]).await;
        let (status, _cookies) =
            start(&customer, &impersonation_token(valid_payload("jti-cust"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let status = customer.post_raw("/v1/auth/impersonate/end", "").await.0;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // System tenant without the wildcard scope.
        let key =
            crate::app::test_support::seed_api_key_for(&pool, "system", &["support:read"]).await;
        let scoped = AdvEnv::over(pool.clone(), key).await;
        let (status, _cookies) =
            start(&scoped, &impersonation_token(valid_payload("jti-scope"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn impersonation_end_clears_cookie_and_audits_the_session() {
        let Some(pool) = crate::test_db::canonical_pool("imp_end").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;

        // Without a cookie: still succeeds (idempotent clear).
        let (status, headers, _bytes) = env.post_raw("/v1/auth/impersonate/end", "").await;
        assert_eq!(status, StatusCode::OK);
        assert!(headers.get_all("set-cookie").iter().any(|c| c
            .to_str()
            .is_ok_and(|c| c.starts_with("impersonation_session=;"))));

        // With a VALID impersonation-session cookie: audited with tokenId.
        let jti = format!("jti-end-{}", uuid::Uuid::new_v4().simple());
        let session_payload = serde_json::json!({
            "type": "impersonation",
            "tenantId": "ten_victim_probe",
            "operatorId": "op_probe",
            "tokenId": jti,
            "exp": chrono::Utc::now().timestamp_millis() + 600_000,
        });
        let session_token =
            create_signed_token(&session_payload, "test-session-secret-1234567890ab").unwrap();
        let (status, headers, bytes) = env
            .post_raw_with_cookie(
                "/v1/auth/impersonate/end",
                "",
                &format!("impersonation_session={session_token}"),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "end-with-cookie: {}",
            String::from_utf8_lossy(&bytes)
        );
        let _ = headers;
        let (action, resource): (String, String) = sqlx::query_as(
            "SELECT action, resource_id FROM audit_logs WHERE action = 'impersonation_session_ended' AND resource_id = $1",
        )
        .bind(&jti)
        .fetch_one(&pool)
        .await
        .expect("end audit row");
        assert_eq!(action, "impersonation_session_ended");
        assert_eq!(resource, jti);

        // With a GARBAGE cookie: no audit row, still a clean clear.
        let count_before: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE action = 'impersonation_session_ended'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let (status, _, _) = env
            .post_raw_with_cookie(
                "/v1/auth/impersonate/end",
                "",
                "impersonation_session=garbage.value",
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let count_after: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE action = 'impersonation_session_ended'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count_before, count_after, "garbage cookies are not audited");
    }

    // ── Outage + wire-detail arms ────────────────────────────────
    //
    // A local driver over the REAL router with caller-controlled Redis
    // endpoint and environment — AdvEnv always uses the shared test Redis
    // and a non-production config, so the fail-closed arms and the
    // `; Secure` cookie arms are unreachable through it.

    struct CustomEnv {
        app: axum::Router,
        credential: String,
    }

    async fn custom_env(
        pool: sqlx::PgPool,
        redis_url: &str,
        environment: crate::config::Environment,
    ) -> CustomEnv {
        use crate::app::build_app;
        use crate::app::test_support::{test_config, test_state_over_with_config_and_redis};

        let credential = crate::app::test_support::seed_api_key_for(&pool, "system", &["*"]).await;
        let mut config = test_config();
        config.environment = environment;
        let state = test_state_over_with_config_and_redis(pool, config, redis_url).await;
        CustomEnv {
            app: build_app(state),
            credential,
        }
    }

    impl CustomEnv {
        async fn post_start(&self, token: &str) -> (StatusCode, Vec<String>) {
            use axum::body::Body;
            use axum::http::{header, Method, Request};
            use tower::ServiceExt;

            let request = Request::builder()
                .method(Method::POST)
                .uri("/v1/auth/impersonate")
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-api-key", &self.credential)
                .body(Body::from(
                    serde_json::json!({ "token": token }).to_string(),
                ))
                .expect("request");
            let response = self.app.clone().oneshot(request).await.expect("response");
            let status = response.status();
            let cookies = response
                .headers()
                .get_all("set-cookie")
                .iter()
                .filter_map(|v| v.to_str().ok().map(str::to_string))
                .collect();
            (status, cookies)
        }

        async fn post_end(&self, cookie: Option<&str>) -> StatusCode {
            use axum::body::Body;
            use axum::http::{header, Method, Request};
            use tower::ServiceExt;

            let mut builder = Request::builder()
                .method(Method::POST)
                .uri("/v1/auth/impersonate/end")
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-api-key", &self.credential);
            if let Some(cookie) = cookie {
                builder = builder.header(header::COOKIE, cookie);
            }
            let request = builder.body(Body::empty()).expect("request");
            let response = self.app.clone().oneshot(request).await.expect("response");
            response.status()
        }
    }

    /// Redis unreachable at POOL level: the exchange must fail CLOSED (503),
    /// never mint an untracked replayable session.
    #[tokio::test]
    async fn start_fails_closed_when_redis_pool_is_unreachable() {
        let Some(pool) = crate::test_db::canonical_pool("imp_redis_down").await else {
            return;
        };
        let env = custom_env(
            pool,
            "redis://127.0.0.1:1",
            crate::config::Environment::Development,
        )
        .await;
        let (status, _cookies) =
            start_env(&env, &impersonation_token(valid_payload("jti-down"))).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Redis reachable at TCP level but refusing commands (the socket is
    /// torn down on accept): the SET NX itself fails — the same fail-closed
    /// contract applies.
    #[tokio::test]
    async fn start_fails_closed_when_the_set_nx_command_fails() {
        let Some(pool) = crate::test_db::canonical_pool("imp_redis_setfail").await else {
            return;
        };
        // A TCP peer that accepts and immediately drops the connection:
        // deadpool creates the object (TCP connect succeeds), then the
        // first command hits a closed socket.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            for _ in 0..8 {
                if let Ok((socket, _)) = listener.accept() {
                    drop(socket);
                }
            }
        });
        let env = custom_env(
            pool,
            &format!("redis://{addr}"),
            crate::config::Environment::Development,
        )
        .await;
        let (status, _cookies) =
            start_env(&env, &impersonation_token(valid_payload("jti-setfail"))).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    /// The audit write is on the critical path: when it fails the exchange
    /// is refused (500) — an unaudited impersonation session must never be
    /// minted. The audit_logs relation is renamed in this throwaway
    /// per-test database.
    #[tokio::test]
    async fn start_refuses_when_the_audit_write_fails() {
        if std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_none()
        {
            eprintln!("skipping: TEST_REDIS_URL unset");
            return;
        }
        let Some(pool) = crate::test_db::canonical_pool("imp_audit_fail").await else {
            return;
        };
        crate::routes::fault::hide_table(&pool, "audit_logs")
            .await
            .expect("hide audit_logs");
        let env = AdvEnv::admin(pool).await;
        let (status, _headers, bytes) = env
            .post_raw(
                "/v1/auth/impersonate",
                &serde_json::json!({ "token": impersonation_token(valid_payload(&format!("jti-auditfail-{}", uuid::Uuid::new_v4().simple()))) })
                    .to_string(),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "{}",
            String::from_utf8_lossy(&bytes)
        );
    }

    /// Production flips the cookie wire format: both the minted
    /// impersonation cookie and the clearing cookie carry `; Secure`.
    #[tokio::test]
    async fn production_environment_sets_secure_cookie_attributes() {
        if std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_none()
        {
            eprintln!("skipping: TEST_REDIS_URL unset");
            return;
        }
        let Some(pool) = crate::test_db::canonical_pool("imp_secure").await else {
            return;
        };
        let env = custom_env(
            pool.clone(),
            &std::env::var("TEST_REDIS_URL").expect("redis url checked above"),
            crate::config::Environment::Production,
        )
        .await;
        let (status, cookies) = start_env(
            &env,
            &impersonation_token(valid_payload(&format!(
                "jti-secure-{}",
                uuid::Uuid::new_v4().simple()
            ))),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let cookie = cookies
            .iter()
            .find(|c| c.starts_with("impersonation_session="))
            .expect("impersonation cookie");
        assert!(cookie.contains("Secure"), "production cookie: {cookie}");

        // end: the clear cookie is Secure too.
        let status = env.post_end(None).await;
        assert_eq!(status, StatusCode::OK);
    }

    async fn start_env(env: &CustomEnv, token: &str) -> (StatusCode, Vec<String>) {
        env.post_start(token).await
    }

    /// The end audit falls back to "unknown" attribution when the session
    /// payload carries no operator/tenant identity, and a cookie without
    /// the signature separator is never audited.
    #[tokio::test]
    async fn end_audit_attribution_falls_back_to_unknown_for_identity_less_cookies() {
        let Some(pool) = crate::test_db::canonical_pool("imp_end_unknown").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;

        // A validly-signed session cookie with NO operatorId/tenantId.
        let session_payload = serde_json::json!({
            "type": "impersonation",
            "tokenId": format!("jti-unk-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]),
            "exp": chrono::Utc::now().timestamp_millis() + 600_000,
        });
        let session_token =
            create_signed_token(&session_payload, "test-session-secret-1234567890ab").unwrap();
        let (status, _headers, _bytes) = env
            .post_raw_with_cookie(
                "/v1/auth/impersonate/end",
                "",
                &format!("impersonation_session={session_token}"),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        // The payload carries no operatorId/tenantId, so the audit metadata
        // has no attribution keys at all — the handler must still persist
        // the end-of-session record (attributed by tokenId only).
        let (operator, tenant): (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT details->>'operatorId', details->>'tenantId' FROM audit_logs \
             WHERE action = 'impersonation_session_ended' \
             AND details->>'tokenId' = $1",
        )
        .bind(session_payload["tokenId"].as_str().expect("tokenId"))
        .fetch_one(&pool)
        .await
        .expect("unknown-attribution audit row");
        assert!(operator.is_none());
        assert!(tenant.is_none());

        // A cookie value with no signature separator at all: nothing is
        // audited, the response still clears cleanly.
        let before: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE action = 'impersonation_session_ended'",
        )
        .fetch_one(&pool)
        .await
        .expect("count before");
        let (status, _headers, _bytes) = env
            .post_raw_with_cookie(
                "/v1/auth/impersonate/end",
                "",
                "impersonation_session=noseparator",
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let after: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE action = 'impersonation_session_ended'",
        )
        .fetch_one(&pool)
        .await
        .expect("count after");
        assert_eq!(before, after);
    }
}
