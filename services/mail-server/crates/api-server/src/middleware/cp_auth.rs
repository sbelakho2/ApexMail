use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::net::IpAddr;

use crate::error::ApiError;
use crate::routes::helpers::extract_cookie;
use crate::state::AppState;
use ipnetwork::IpNetwork;

const CP_SESSION_COOKIE_NAME: &str = "apexmail_cp_session";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpSessionClaims {
    pub sub: String,
    pub tenant_id: String,
    pub email: String,
    pub role: String,
    pub mfa_enabled: bool,
    pub iat: i64,
    pub last_active: i64,
    pub exp: i64,
}

#[derive(Debug, Clone)]
pub struct CpAuthUser {
    pub user_id: String,
    pub tenant_id: String,
    pub email: String,
    pub role: String,
}

fn validate_cidr_allowed(client_ip: IpAddr, allowed_ips: &[String]) -> bool {
    if allowed_ips.is_empty() {
        return true;
    }

    allowed_ips.iter().any(|cidr| {
        cidr.trim()
            .parse::<IpNetwork>()
            .ok()
            .is_some_and(|net| net.contains(client_ip))
    })
}

pub(crate) fn is_cp_route(path: &str) -> bool {
    path.starts_with("/cp/") || path.starts_with("/v1/admin/")
}

pub fn create_cp_session_token(claims: &CpSessionClaims, secret: &str) -> String {
    let payload = serde_json::to_string(claims).expect("CpSessionClaims serialization should not fail");
    let payload_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload.as_bytes());

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC-SHA256 key should be valid");
    mac.update(payload_b64.as_bytes());
    let sig = mac.finalize().into_bytes();
    let sig_b64 = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, sig);

    format!("{payload_b64}.{sig_b64}")
}

fn verify_cp_session_token(token: &str, secret: &str) -> Result<CpSessionClaims, ApiError> {
    let parts: Vec<&str> = token.rsplitn(2, '.').collect();
    if parts.len() != 2 {
        return Err(ApiError::Unauthorized("invalid CP session token format".into()));
    }
    let (sig_str, payload_str) = (parts[0], parts[1]);

    let sig_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        sig_str,
    )
    .map_err(|_| ApiError::Unauthorized("invalid CP session signature encoding".into()))?;

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| ApiError::Internal("HMAC key error".into()))?;
    mac.update(payload_str.as_bytes());

    mac.verify_slice(&sig_bytes)
        .map_err(|_| ApiError::Unauthorized("invalid CP session signature".into()))?;

    let payload_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        payload_str,
    )
    .map_err(|_| ApiError::Unauthorized("invalid CP session payload encoding".into()))?;

    serde_json::from_slice::<CpSessionClaims>(&payload_bytes)
        .map_err(|_| ApiError::Unauthorized("invalid CP session payload".into()))
}

pub(crate) fn build_cp_session_cookie(token: &str, max_age_secs: i64, secure: bool) -> String {
    format!(
        "{CP_SESSION_COOKIE_NAME}={token}; HttpOnly; Path=/; Max-Age={max_age_secs}; SameSite=Strict{}",
        if secure { "; Secure" } else { "" }
    )
}

pub(crate) fn build_clear_cp_session_cookie(secure: bool) -> String {
    format!(
        "{CP_SESSION_COOKIE_NAME}=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict{}",
        if secure { "; Secure" } else { "" }
    )
}

pub async fn refresh_cp_session_activity(
    state: &AppState,
    existing: &CpSessionClaims,
) -> Result<(String, CpSessionClaims), ApiError> {
    let now = Utc::now().timestamp();
    let absolute_expiry = existing.iat + state.config.cp_session_absolute_timeout_secs as i64;

    if now >= absolute_expiry || now >= existing.exp {
        return Err(ApiError::Unauthorized("CP session expired".into()));
    }

    let idle_deadline = existing.last_active + state.config.cp_session_idle_timeout_secs as i64;
    if now > idle_deadline {
        return Err(ApiError::Unauthorized("CP session idle timeout".into()));
    }

    let updated = CpSessionClaims {
        sub: existing.sub.clone(),
        tenant_id: existing.tenant_id.clone(),
        email: existing.email.clone(),
        role: existing.role.clone(),
        mfa_enabled: existing.mfa_enabled,
        iat: existing.iat,
        last_active: now,
        exp: absolute_expiry,
    };

    let token = create_cp_session_token(&updated, &state.config.cp_session_secret);
    Ok((token, updated))
}

pub async fn require_cp_auth(
    axum::extract::State(state): axum::extract::State<AppState>,
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, ApiError> {
    let path = req.uri().path().to_string();

    // ── IP allowlist enforcement ────────────────────────────
    if !state.config.cp_allowed_ips.is_empty() {
        if let Some(axum::extract::ConnectInfo(addr)) = connect_info {
            if !validate_cidr_allowed(addr.ip(), &state.config.cp_allowed_ips) {
                log_cp_access(&state, None, &path, StatusCode::FORBIDDEN.as_u16(), "cp_ip_denied").await;
                return Err(ApiError::Forbidden("access denied from this network".into()));
            }
        }
    }

    // ── Extract CP session cookie ───────────────────────────
    let headers = req.headers().clone();
    let token = match extract_cookie(&headers, CP_SESSION_COOKIE_NAME) {
        Some(t) if !t.is_empty() => t,
        _ => {
            log_cp_access(&state, None, &path, StatusCode::UNAUTHORIZED.as_u16(), "cp_missing_session").await;
            return Err(ApiError::Unauthorized("control-plane authentication required".into()));
        }
    };

    // ── Verify token ────────────────────────────────────────
    let claims = match verify_cp_session_token(&token, &state.config.cp_session_secret) {
        Ok(c) => c,
        Err(e) => {
            log_cp_access(&state, None, &path, StatusCode::UNAUTHORIZED.as_u16(), "cp_invalid_token").await;
            return Err(e);
        }
    };

    // ── Validate role ───────────────────────────────────────
    if !matches!(claims.role.as_str(), "admin" | "owner") {
        log_cp_access(&state, Some(&claims.email), &path, StatusCode::FORBIDDEN.as_u16(), "cp_insufficient_role").await;
        return Err(ApiError::Forbidden("admin or owner role required for control plane".into()));
    }

    // ── Enforce MFA ─────────────────────────────────────────
    if !claims.mfa_enabled {
        log_cp_access(&state, Some(&claims.email), &path, StatusCode::FORBIDDEN.as_u16(), "cp_mfa_required").await;
        return Err(ApiError::Forbidden("MFA is required for control-plane access".into()));
    }

    // ── Validate timeouts ───────────────────────────────────
    let now = Utc::now().timestamp();
    if now >= claims.exp {
        log_cp_access(&state, Some(&claims.email), &path, StatusCode::UNAUTHORIZED.as_u16(), "cp_session_expired").await;
        return Err(ApiError::Unauthorized("CP session expired".into()));
    }

    let idle_deadline = claims.last_active + state.config.cp_session_idle_timeout_secs as i64;
    if now > idle_deadline {
        log_cp_access(&state, Some(&claims.email), &path, StatusCode::UNAUTHORIZED.as_u16(), "cp_session_idle").await;
        return Err(ApiError::Unauthorized("CP session idle timeout — please log in again".into()));
    }

    // ── Verify user still exists and is active ──────────────
    let user_status: Option<(String,)> = sqlx::query_as(
        "SELECT status FROM users WHERE id = $1::uuid AND tenant_id = $2"
    )
    .bind(&claims.sub)
    .bind(&claims.tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "CP auth user status check failed");
        ApiError::Internal("authentication error".into())
    })?;

    match user_status {
        None => {
            log_cp_access(&state, Some(&claims.email), &path, StatusCode::UNAUTHORIZED.as_u16(), "cp_user_missing").await;
            return Err(ApiError::Unauthorized("user no longer exists".into()));
        }
        Some((status,)) if status != "active" => {
            log_cp_access(&state, Some(&claims.email), &path, StatusCode::FORBIDDEN.as_u16(), "cp_user_inactive").await;
            return Err(ApiError::Forbidden(format!("account is {status}")));
        }
        _ => {}
    }

    // ── Refresh session active timestamp ────────────────────
    let (new_token, updated_claims) = refresh_cp_session_activity(&state, &claims).await?;

    // ── Insert CP auth user into extensions ─────────────────
    let cp_user = CpAuthUser {
        user_id: claims.sub,
        tenant_id: claims.tenant_id.clone(),
        email: claims.email.clone(),
        role: claims.role.clone(),
    };

    let (mut parts, body) = req.into_parts();
    parts.extensions.insert(cp_user.clone());
    parts.extensions.insert(updated_claims);
    req = axum::http::Request::from_parts(parts, body);

    log_cp_access(&state, Some(&cp_user.email), &path, StatusCode::OK.as_u16(), "cp_access").await;

    let mut response = next.run(req).await;

    let cookie = build_cp_session_cookie(
        &new_token,
        state.config.cp_session_absolute_timeout_secs as i64,
        state.config.environment.is_production(),
    );
    response
        .headers_mut()
        .insert("Set-Cookie", cookie.parse().expect("valid cookie header"));

    Ok(response)
}

async fn log_cp_access(
    state: &AppState,
    email: Option<&str>,
    path: &str,
    status_code: u16,
    outcome: &str,
) {
    let redacted = email.map(|e| {
        if e.contains('@') {
            mail_common::pii::redact_email(e).to_string()
        } else {
            format!("id#{}", &e.chars().take(8).collect::<String>())
        }
    });

    tracing::info!(
        target: "cp_access",
        email = ?redacted,
        path = %path,
        status = status_code,
        outcome = %outcome,
        "CP access event"
    );

    let status_ok = status_code < 400;
    let _ = sqlx::query(
        "INSERT INTO cp_access_log (id, email, path, status_code, outcome, created_at)
         VALUES (gen_random_uuid(), $1, $2, $3, $4, NOW())",
    )
    .bind(redacted)
    .bind(path)
    .bind(status_code as i32)
    .bind(if status_ok { "allowed" } else { outcome })
    .execute(&state.db)
    .await;
}

#[axum::async_trait]
impl FromRequestParts<AppState> for CpAuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<CpAuthUser>()
            .cloned()
            .ok_or_else(|| ApiError::Unauthorized("control-plane authentication required".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> String {
        "test-cp-session-secret-1234567890ab".into()
    }

    #[test]
    fn test_cp_session_token_roundtrip() {
        let claims = CpSessionClaims {
            sub: "usr_test_001".into(),
            tenant_id: "ten_test_001".into(),
            email: "admin@apexmail.ee".into(),
            role: "admin".into(),
            mfa_enabled: true,
            iat: 1000000,
            last_active: 1000000,
            exp: 2000000,
        };

        let token = create_cp_session_token(&claims, &test_secret());
        let decoded = verify_cp_session_token(&token, &test_secret()).unwrap();

        assert_eq!(decoded.sub, claims.sub);
        assert_eq!(decoded.role, claims.role);
        assert_eq!(decoded.mfa_enabled, claims.mfa_enabled);
        assert_eq!(decoded.iat, claims.iat);
    }

    #[test]
    fn test_cp_session_token_tamper_detection() {
        let claims = CpSessionClaims {
            sub: "usr_test_001".into(),
            tenant_id: "ten_test_001".into(),
            email: "admin@apexmail.ee".into(),
            role: "admin".into(),
            mfa_enabled: true,
            iat: 1000000,
            last_active: 1000000,
            exp: 2000000,
        };

        let token = create_cp_session_token(&claims, &test_secret());
        // Flip a byte in the signature to simulate tampering
        let mut tampered = token.clone();
        let last_char = tampered.pop().unwrap();
        tampered.push(if last_char == 'A' { 'B' } else { 'A' });

        assert!(verify_cp_session_token(&tampered, &test_secret()).is_err());
    }

    #[test]
    fn test_cp_session_token_wrong_secret() {
        let claims = CpSessionClaims {
            sub: "usr_test_001".into(),
            tenant_id: "ten_test_001".into(),
            email: "admin@apexmail.ee".into(),
            role: "admin".into(),
            mfa_enabled: true,
            iat: 1000000,
            last_active: 1000000,
            exp: 2000000,
        };

        let token = create_cp_session_token(&claims, &test_secret());
        assert!(verify_cp_session_token(&token, "different-secret-key-here-xxxx").is_err());
    }

    #[test]
    fn test_cidr_validation() {
        let allowed = vec!["10.0.0.0/8".into(), "127.0.0.1/32".into()];

        assert!(validate_cidr_allowed("127.0.0.1".parse().unwrap(), &allowed));
        assert!(validate_cidr_allowed("10.5.5.5".parse().unwrap(), &allowed));
        assert!(!validate_cidr_allowed("192.168.1.1".parse().unwrap(), &allowed));
        assert!(validate_cidr_allowed("127.0.0.1".parse().unwrap(), &[]));
    }
}
