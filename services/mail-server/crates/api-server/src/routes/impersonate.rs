//! Impersonation endpoints.
//!
//! Allows platform operators to impersonate tenant accounts.
//! All impersonation events are audit-logged.

use super::helpers::extract_cookie;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
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
    Json(body): Json<ImpersonateRequest>,
) -> Result<Response, ApiError> {
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
    let exp = payload.exp.unwrap_or(0);
    let jti = payload.jti.as_deref().unwrap_or_default();

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
    headers: HeaderMap,
) -> Result<Response, ApiError> {
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
    sqlx::query(
        "INSERT INTO audit_logs (timestamp, action, resource_type, resource_id, tenant_id, metadata)
         VALUES (NOW(), $1, 'session', $2, $3, $4::jsonb)",
    )
    .bind(action)
    .bind(resource_id)
    .bind(tenant_id)
    .bind(metadata)
    .execute(&state.db)
    .await
    .map_err(|error| {
        tracing::error!(error = %error, action = %action, resource_id = %resource_id, tenant_id = %tenant_id, "failed to write impersonation audit log");
        ApiError::Internal("impersonation audit logging failed".into())
    })?;

    Ok(())
}

// ─── Token helpers ─────────────────────────────────────────────

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

    // Check expiry
    if let Some(exp) = payload.exp {
        let now_ms = chrono::Utc::now().timestamp_millis();
        if now_ms > exp {
            return Err(ApiError::Unauthorized("impersonation token expired".into()));
        }
    }

    Ok(payload)
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
}
