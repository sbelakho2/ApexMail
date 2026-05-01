//! Authentication routes: login, logout, refresh, register, reset password, and API key management.

use super::helpers::{
    clamp_limit, default_limit, extract_cookie, hash_token, html_escape, token_blacklist_key,
};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{
    invalidate_api_key_cache, session_revocation_key, validate_session_csrf, AuthUser, JwtClaims,
};
use crate::state::AppState;

const SYSTEM_TENANT_ID: &str = "system_internal_tenant01";
const LOGIN_FAILURE_THRESHOLD: i64 = 5;
const LOGIN_FAILURE_WINDOW_SECS: u64 = 5 * 60;
const LOGIN_LOCKOUT_BASE_SECS: u64 = 15 * 60;
const LOGIN_LOCKOUT_MAX_SECS: u64 = 24 * 60 * 60;
const LOGIN_LOCKOUT_ESCALATION_WINDOW_SECS: u64 = 24 * 60 * 60;
const DEFAULT_API_KEY_EXPIRY_DAYS: i64 = 90;
const MAX_API_KEY_EXPIRY_DAYS: i64 = 365;
const MFA_CHALLENGE_TTL_SECS: u64 = 10 * 60;
const MFA_CHALLENGE_PREFIX: &str = "apexmail:auth:mfa_challenge:";
const MFA_SECRET_BYTES: usize = 20;

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(db_error) if db_error.code().as_deref() == Some("23505"))
}

fn verify_password_or_log(password: &str, hash: &str, subject: &str) -> bool {
    let result = if hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$")
    {
        bcrypt::verify(password, hash).map_err(|error| error.to_string())
    } else if hash.starts_with("$argon2") {
        apexmail_lib::verify_password(password, hash).map_err(|error| error.to_string())
    } else {
        Err("unknown password hash scheme".into())
    };

    match result {
        Ok(valid) => valid,
        Err(error) => {
            tracing::warn!(error = %error, subject = %subject, "password verification failed");
            false
        }
    }
}

fn scopes_for_role(role: &str) -> Vec<String> {
    match role {
        "admin" | "owner" => vec!["*".into()],
        "developer" => vec![
            "messages:send".into(),
            "messages:read".into(),
            "domains:read".into(),
            "templates:read".into(),
            "templates:write".into(),
            "events:read".into(),
            "analytics:read".into(),
            "contacts:read".into(),
            "contacts:write".into(),
        ],
        "viewer" => vec![
            "messages:read".into(),
            "domains:read".into(),
            "templates:read".into(),
            "events:read".into(),
            "analytics:read".into(),
            "contacts:read".into(),
        ],
        _ => vec!["messages:read".into()],
    }
}

fn role_requires_mfa(role: &str) -> bool {
    matches!(role, "admin" | "owner")
}

fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let mut output = String::new();
    let mut buffer: u16 = 0;
    let mut bits_left: u8 = 0;

    for &byte in bytes {
        buffer = (buffer << 8) | u16::from(byte);
        bits_left += 8;

        while bits_left >= 5 {
            let index = ((buffer >> (bits_left - 5)) & 0x1f) as usize;
            output.push(ALPHABET[index] as char);
            bits_left -= 5;
        }
    }

    if bits_left > 0 {
        let index = ((buffer << (5 - bits_left)) & 0x1f) as usize;
        output.push(ALPHABET[index] as char);
    }

    output
}

fn generate_mfa_secret() -> String {
    let mut secret = [0u8; MFA_SECRET_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    base32_encode(&secret)
}

fn build_mfa_otpauth_url(email: &str, secret: &str) -> String {
    let label = format!("ApexMail:{email}");
    let encoded_label: String = url::form_urlencoded::byte_serialize(label.as_bytes()).collect();
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("secret", secret);
    serializer.append_pair("issuer", "ApexMail");
    serializer.append_pair("algorithm", "SHA256");
    serializer.append_pair("digits", "6");
    serializer.append_pair("period", "30");

    format!("otpauth://totp/{encoded_label}?{}", serializer.finish())
}

fn mfa_challenge_key(token: &str) -> String {
    format!("{MFA_CHALLENGE_PREFIX}{token}")
}

fn validate_password_strength(password: &str) -> Result<(), ApiError> {
    if password.len() < 12 || password.len() > 128 {
        return Err(ApiError::Validation(vec![
            "password must be 12-128 characters".into(),
        ]));
    }

    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| c.is_ascii_punctuation());
    if !has_lower || !has_upper || !has_digit || !has_special {
        return Err(ApiError::Validation(vec![
            "password must include uppercase, lowercase, number, and special character".into(),
        ]));
    }

    Ok(())
}

fn authenticated_user_id(auth: &AuthUser) -> Result<&str, ApiError> {
    auth.user_id
        .as_deref()
        .ok_or_else(|| ApiError::Unauthorized("user session required".into()))
}

fn register_response() -> RegisterResponse {
    RegisterResponse {
        success: true,
        message: "If the email is eligible, a verification message has been sent.".into(),
    }
}

fn build_action_link(base_url: &str, path: &str, email: &str, token: &str) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("token", token);
    serializer.append_pair("email", email);
    format!(
        "{}{path}?{}",
        base_url.trim_end_matches('/'),
        serializer.finish(),
    )
}

fn normalized_login_identifier(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

fn login_failure_key(identifier: &str) -> String {
    format!("apexmail:auth:failures:{}", hash_token(identifier))
}

fn login_lock_key(identifier: &str) -> String {
    format!("apexmail:auth:lock:{}", hash_token(identifier))
}

fn login_lockout_counter_key(identifier: &str) -> String {
    format!("apexmail:auth:lockouts:{}", hash_token(identifier))
}

fn login_lockout_duration(lockout_count: i64) -> u64 {
    let exponent = lockout_count.saturating_sub(1).clamp(0, 7) as u32;
    LOGIN_LOCKOUT_BASE_SECS
        .saturating_mul(1_u64 << exponent)
        .min(LOGIN_LOCKOUT_MAX_SECS)
}

async fn login_lock_ttl(
    redis_pool: &deadpool_redis::Pool,
    identifier: &str,
) -> Result<Option<i64>, ApiError> {
    let mut conn = redis_pool.get().await?;
    let ttl: i64 = deadpool_redis::redis::cmd("TTL")
        .arg(login_lock_key(identifier))
        .query_async(&mut *conn)
        .await?;
    Ok((ttl > 0).then_some(ttl))
}

async fn record_login_failure(
    redis_pool: &deadpool_redis::Pool,
    identifier: &str,
) -> Result<(), ApiError> {
    let failure_key = login_failure_key(identifier);
    let lock_key = login_lock_key(identifier);
    let lockout_counter_key = login_lockout_counter_key(identifier);
    let identifier_hash = hash_token(identifier);

    let mut conn = redis_pool.get().await?;
    let failures: i64 = deadpool_redis::redis::cmd("INCR")
        .arg(&failure_key)
        .query_async(&mut *conn)
        .await?;

    if failures == 1 {
        let _: i64 = deadpool_redis::redis::cmd("EXPIRE")
            .arg(&failure_key)
            .arg(LOGIN_FAILURE_WINDOW_SECS)
            .query_async(&mut *conn)
            .await?;
    }

    if failures < LOGIN_FAILURE_THRESHOLD {
        return Ok(());
    }

    let lockouts: i64 = deadpool_redis::redis::cmd("INCR")
        .arg(&lockout_counter_key)
        .query_async(&mut *conn)
        .await?;

    if lockouts == 1 {
        let _: i64 = deadpool_redis::redis::cmd("EXPIRE")
            .arg(&lockout_counter_key)
            .arg(LOGIN_LOCKOUT_ESCALATION_WINDOW_SECS)
            .query_async(&mut *conn)
            .await?;
    }

    let duration = login_lockout_duration(lockouts);
    let _: () =
        deadpool_redis::redis::AsyncCommands::set_ex(&mut *conn, &lock_key, "1", duration).await?;
    let _: i64 = deadpool_redis::redis::AsyncCommands::del(&mut *conn, &failure_key).await?;

    tracing::warn!(
        identifier_hash = %identifier_hash,
        failures = failures,
        lockouts = lockouts,
        lockout_seconds = duration,
        "login account temporarily locked after repeated failures"
    );

    Ok(())
}

async fn clear_login_failures(
    redis_pool: &deadpool_redis::Pool,
    identifier: &str,
) -> Result<(), ApiError> {
    let failure_key = login_failure_key(identifier);
    let mut conn = redis_pool.get().await?;
    let _: i64 = deadpool_redis::redis::AsyncCommands::del(&mut *conn, &failure_key).await?;
    Ok(())
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum MfaChallengeKind {
    Setup,
    Verify,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MfaChallengeState {
    user_id: String,
    tenant_id: String,
    email: String,
    name: Option<String>,
    role: String,
    secret: String,
    kind: MfaChallengeKind,
}

async fn store_mfa_challenge(
    redis_pool: &deadpool_redis::Pool,
    challenge: &MfaChallengeState,
) -> Result<String, ApiError> {
    let token = apexmail_lib::id::generate_id("mfa", 22);
    let key = mfa_challenge_key(&token);
    let payload = serde_json::to_string(challenge).map_err(|error| {
        ApiError::Internal(format!("failed to serialize MFA challenge: {error}"))
    })?;

    let mut conn = redis_pool.get().await?;
    let _: () = deadpool_redis::redis::AsyncCommands::set_ex(
        &mut *conn,
        &key,
        payload,
        MFA_CHALLENGE_TTL_SECS,
    )
    .await?;

    Ok(token)
}

async fn load_mfa_challenge(
    redis_pool: &deadpool_redis::Pool,
    token: &str,
) -> Result<MfaChallengeState, ApiError> {
    let mut conn = redis_pool.get().await?;
    let key = mfa_challenge_key(token);
    let payload: Option<String> =
        deadpool_redis::redis::AsyncCommands::get(&mut *conn, &key).await?;
    let payload =
        payload.ok_or_else(|| ApiError::Unauthorized("invalid or expired MFA challenge".into()))?;

    serde_json::from_str(&payload)
        .map_err(|error| ApiError::Internal(format!("failed to decode MFA challenge: {error}")))
}

async fn delete_mfa_challenge(
    redis_pool: &deadpool_redis::Pool,
    token: &str,
) -> Result<(), ApiError> {
    let key = mfa_challenge_key(token);
    let mut conn = redis_pool.get().await?;
    let _: i64 = deadpool_redis::redis::AsyncCommands::del(&mut *conn, &key).await?;
    Ok(())
}

async fn revoke_user_sessions(
    redis_pool: &deadpool_redis::Pool,
    tenant_id: &str,
    user_id: &str,
    ttl_secs: u64,
) -> Result<(), ApiError> {
    let mut conn = redis_pool.get().await?;
    let key = session_revocation_key(tenant_id, user_id);
    let revoked_after = Utc::now().timestamp();

    let _: () =
        deadpool_redis::redis::AsyncCommands::set_ex(&mut *conn, &key, revoked_after, ttl_secs)
            .await?;

    Ok(())
}

async fn enqueue_verification_email(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    base_url: &str,
    email: &str,
    token: &str,
) -> Result<(), sqlx::Error> {
    let verification_link = build_action_link(base_url, "/verify-email", email, token);
    let safe_email = html_escape(email);
    let safe_link = html_escape(&verification_link);
    let html_body = format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/></head><body style="font-family:sans-serif;line-height:1.6;color:#1a1a1a;max-width:560px;margin:0 auto;padding:24px">
<h2 style="color:#2563EB">Verify Your ApexMail Account</h2>
<p>Finish setting up <strong>{safe_email}</strong> by confirming this email address.</p>
<p><a href="{safe_link}" style="display:inline-block;padding:12px 28px;background:#2563EB;color:#fff;border-radius:8px;text-decoration:none;font-weight:600">Verify email</a></p>
<p style="font-size:13px;color:#666">This link expires in 24 hours.</p>
<hr style="border:none;border-top:1px solid #e5e5e5;margin:24px 0"/>
<p style="font-size:12px;color:#999">&copy; 2026 ApexMail &middot; <a href="https://apexmail.ee" style="color:#999">apexmail.ee</a></p>
</body></html>"#,
    );
    let text_body = format!(
        "Verify Your ApexMail Account\n\nConfirm {email} by visiting: {verification_link}\n\nThis link expires in 24 hours.\n\n© 2026 ApexMail — https://apexmail.ee",
    );

    sqlx::query(
        "INSERT INTO messages (id, tenant_id, from_email, to_emails, subject, html_body, text_body, status, tags, created_at)
         VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, 'queued', $8::jsonb, NOW())",
    )
    .bind(apexmail_lib::id::generate_id("msg", 22))
    .bind(SYSTEM_TENANT_ID)
    .bind("noreply@apexmail.ee")
    .bind(serde_json::json!([email]))
    .bind("Verify your ApexMail account")
    .bind(&html_body)
    .bind(&text_body)
    .bind(serde_json::json!(["system", "verification"]))
    .execute(&mut **tx)
    .await?;

    Ok(())
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/login", post(login))
        .route("/mfa/verify", post(complete_mfa_challenge))
        .route("/register", post(register))
        .route("/signup", post(register))
        .route("/verify-email", get(verify_email))
        .route("/reset-password", post(reset_password))
        .route("/api-keys", post(create_api_key).get(list_api_keys))
        .route("/api-keys/:id", delete(revoke_api_key))
        .route("/logout", post(logout))
        .route("/refresh", post(refresh_token))
        .route("/change-password", post(change_password))
        .route("/sessions/revoke", post(revoke_session))
}

pub fn control_plane_alias_router() -> Router<AppState> {
    Router::new()
        .route("/login", post(login))
        .route("/mfa/verify", post(complete_mfa_challenge))
        .route("/register", post(register))
        .route("/signup", post(register))
        .route("/verify-email", get(verify_email))
        .route("/reset-password", post(reset_password))
        .route("/logout", post(logout))
        .route("/refresh", post(refresh_token))
}

// ─── Request / Response types ──────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    #[serde(default, rename = "mfaCode", alias = "mfa_code")]
    pub mfa_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SessionAuthResponse {
    pub expires_at: String,
    pub user: UserInfo,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MfaChallengeResponse {
    pub status: String,
    pub challenge_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub otpauth_url: Option<String>,
}

impl MfaChallengeResponse {
    fn verify(challenge_token: String) -> Self {
        Self {
            status: "mfa_required".into(),
            challenge_token,
            secret: None,
            otpauth_url: None,
        }
    }

    fn setup(challenge_token: String, email: &str, secret: &str) -> Self {
        Self {
            status: "mfa_setup_required".into(),
            challenge_token,
            secret: Some(secret.to_string()),
            otpauth_url: Some(build_mfa_otpauth_url(email, secret)),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub tenant_id: String,
    pub role: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteMfaChallengeRequest {
    pub challenge_token: String,
    #[serde(rename = "mfaCode", alias = "mfa_code")]
    pub mfa_code: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub expires_in_days: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct CreateApiKeyResponse {
    pub id: String,
    pub key: String,
    pub key_prefix: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyInfo {
    pub id: String,
    pub name: String,
    pub key_prefix: String,
    pub scopes: serde_json::Value,
    pub last_used_at: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListApiKeysQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub cursor: Option<i64>,
}

fn build_session_cookie(token: &str, max_age_secs: i64, secure: bool) -> String {
    format!(
        "am_session={token}; HttpOnly; Path=/; Max-Age={max_age_secs}; SameSite=Lax{}",
        if secure { "; Secure" } else { "" }
    )
}

fn build_clear_session_cookie(secure: bool) -> String {
    format!(
        "am_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax{}",
        if secure { "; Secure" } else { "" }
    )
}

fn insert_private_no_store_headers(headers: &mut HeaderMap) {
    headers.insert(
        "Cache-Control",
        HeaderValue::from_static("no-store, private"),
    );
    headers.insert("Pragma", HeaderValue::from_static("no-cache"));
}

fn no_store_json_response<T: Serialize>(status: StatusCode, body: T) -> Response {
    let mut headers = HeaderMap::new();
    insert_private_no_store_headers(&mut headers);
    (status, headers, Json(body)).into_response()
}

fn build_user_info(user: &UserRow) -> UserInfo {
    UserInfo {
        id: user.id.clone(),
        email: user.email.clone(),
        name: user.name.clone(),
        tenant_id: user.tenant_id.clone(),
        role: user.role.clone(),
    }
}

fn issue_session_response(state: &AppState, user: &UserRow) -> Result<Response, ApiError> {
    let expiry_secs = state.config.jwt_expiry.as_secs() as i64;
    let now = Utc::now();
    let exp = now + ChronoDuration::seconds(expiry_secs);

    let claims = JwtClaims {
        sub: user.id.to_string(),
        tenant_id: user.tenant_id.to_string(),
        scopes: scopes_for_role(&user.role),
        exp: exp.timestamp(),
        iat: now.timestamp(),
    };

    let token = encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(state.config.jwt_private_key_pem.as_bytes()).map_err(|e| {
            ApiError::Internal(format!("invalid JWT private key configuration: {e}"))
        })?,
    )
    .map_err(|e| ApiError::Internal(format!("token generation failed: {e}")))?;

    let mut headers = HeaderMap::new();
    insert_private_no_store_headers(&mut headers);
    let cookie = build_session_cookie(
        &token,
        expiry_secs,
        state.config.environment.is_production(),
    );
    let value = cookie.parse().map_err(|e| {
        tracing::error!(error = %e, "failed to build session cookie header");
        ApiError::Internal("failed to set session cookie".into())
    })?;
    headers.insert("Set-Cookie", value);

    Ok((
        headers,
        Json(SessionAuthResponse {
            expires_at: exp.to_rfc3339(),
            user: build_user_info(user),
        }),
    )
        .into_response())
}

async fn insert_auth_audit_log(
    state: &AppState,
    tenant_id: &str,
    user_id: &str,
    action: &str,
    metadata: serde_json::Value,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO audit_logs (id, tenant_id, user_id, action, resource_type, metadata, created_at)
         VALUES (gen_random_uuid(), $1, $2, $3, 'auth', $4::jsonb, NOW())",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(action)
    .bind(metadata)
    .execute(&state.db)
    .await?;

    Ok(())
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    let mut parts = auth.splitn(2, ' ');
    let scheme = parts.next()?.trim();
    let token = parts.next().unwrap_or("").trim();
    if scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() {
        Some(token.to_string())
    } else {
        None
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub email: String,
    pub password: String,
    #[serde(default, rename = "confirmPassword", alias = "confirm_password")]
    pub confirm_password: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ResetPasswordResponse {
    pub success: bool,
    pub message: String,
}

// ─── Handlers ──────────────────────────────────────────────────

async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginRequest>,
) -> Result<Response, ApiError> {
    if body.email.is_empty() || body.password.is_empty() {
        return Err(ApiError::Validation(vec![
            "email and password are required".into(),
        ]));
    }

    let login_identifier = normalized_login_identifier(&body.email);
    if login_lock_ttl(&state.redis, &login_identifier)
        .await?
        .is_some()
    {
        return Err(ApiError::RateLimited);
    }

    let user = sqlx::query_as::<_, UserRow>(
        "SELECT id, tenant_id, email, name, password_hash, role, status, mfa_enabled, mfa_secret
         FROM users WHERE LOWER(email) = LOWER($1)",
    )
    .bind(&body.email)
    .fetch_optional(&state.db)
    .await?;

    let Some(user) = user else {
        record_login_failure(&state.redis, &login_identifier).await?;
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    };

    if user.status != "active" {
        return Err(ApiError::Forbidden("account is not active".into()));
    }

    let valid = verify_password_or_log(&body.password, &user.password_hash, &user.email);

    if !valid {
        record_login_failure(&state.redis, &login_identifier).await?;
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }

    clear_login_failures(&state.redis, &login_identifier).await?;

    if role_requires_mfa(&user.role) {
        if user.mfa_enabled {
            let secret = user
                .mfa_secret
                .as_deref()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    ApiError::Forbidden("MFA is not configured for this admin account".into())
                })?;

            if let Some(mfa_code) = body.mfa_code.as_deref() {
                if !apexmail_lib::mfa::verify_totp_code(secret, mfa_code) {
                    record_login_failure(&state.redis, &login_identifier).await?;
                    return Err(ApiError::Unauthorized("invalid MFA code".into()));
                }
            } else {
                let challenge_token = store_mfa_challenge(
                    &state.redis,
                    &MfaChallengeState {
                        user_id: user.id.clone(),
                        tenant_id: user.tenant_id.clone(),
                        email: user.email.clone(),
                        name: user.name.clone(),
                        role: user.role.clone(),
                        secret: secret.to_string(),
                        kind: MfaChallengeKind::Verify,
                    },
                )
                .await?;

                return Ok(no_store_json_response(
                    StatusCode::ACCEPTED,
                    MfaChallengeResponse::verify(challenge_token),
                ));
            }
        } else {
            let secret = generate_mfa_secret();
            let challenge_token = store_mfa_challenge(
                &state.redis,
                &MfaChallengeState {
                    user_id: user.id.clone(),
                    tenant_id: user.tenant_id.clone(),
                    email: user.email.clone(),
                    name: user.name.clone(),
                    role: user.role.clone(),
                    secret: secret.clone(),
                    kind: MfaChallengeKind::Setup,
                },
            )
            .await?;

            return Ok(no_store_json_response(
                StatusCode::ACCEPTED,
                MfaChallengeResponse::setup(challenge_token, &user.email, &secret),
            ));
        }
    }

    issue_session_response(&state, &user)
}

async fn complete_mfa_challenge(
    State(state): State<AppState>,
    Json(body): Json<CompleteMfaChallengeRequest>,
) -> Result<Response, ApiError> {
    if body.challenge_token.trim().is_empty() {
        return Err(ApiError::Validation(vec![
            "challenge_token is required".into()
        ]));
    }
    if body.mfa_code.trim().is_empty() {
        return Err(ApiError::Validation(vec!["mfa_code is required".into()]));
    }

    let challenge = load_mfa_challenge(&state.redis, &body.challenge_token).await?;
    let login_identifier = normalized_login_identifier(&challenge.email);
    if !apexmail_lib::mfa::verify_totp_code(&challenge.secret, &body.mfa_code) {
        record_login_failure(&state.redis, &login_identifier).await?;
        return Err(ApiError::Unauthorized("invalid MFA code".into()));
    }

    clear_login_failures(&state.redis, &login_identifier).await?;

    let mut user = sqlx::query_as::<_, UserRow>(
        "SELECT id, tenant_id, email, name, password_hash, role, status, mfa_enabled, mfa_secret
         FROM users WHERE id = $1 AND tenant_id = $2",
    )
    .bind(&challenge.user_id)
    .bind(&challenge.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::Unauthorized("user no longer exists".into()))?;

    if user.status != "active" {
        return Err(ApiError::Forbidden(format!("account is {}", user.status)));
    }

    match challenge.kind {
        MfaChallengeKind::Setup => {
            sqlx::query(
                "UPDATE users
                 SET mfa_secret = $1, mfa_enabled = true, updated_at = NOW()
                 WHERE id = $2 AND tenant_id = $3",
            )
            .bind(&challenge.secret)
            .bind(&challenge.user_id)
            .bind(&challenge.tenant_id)
            .execute(&state.db)
            .await?;

            insert_auth_audit_log(
                &state,
                &challenge.tenant_id,
                &challenge.user_id,
                "auth.mfa_enabled",
                serde_json::json!({
                    "role": challenge.role,
                    "enforced_for_admin": true,
                }),
            )
            .await?;

            user.mfa_enabled = true;
            user.mfa_secret = Some(challenge.secret.clone());
        }
        MfaChallengeKind::Verify => {
            let current_secret = user
                .mfa_secret
                .as_deref()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| ApiError::Unauthorized("MFA is no longer configured".into()))?;
            if !user.mfa_enabled || current_secret != challenge.secret {
                return Err(ApiError::Unauthorized(
                    "MFA challenge is no longer valid".into(),
                ));
            }
        }
    }

    delete_mfa_challenge(&state.redis, &body.challenge_token).await?;
    issue_session_response(&state, &user)
}

#[derive(sqlx::FromRow)]
struct UserRow {
    id: String,
    tenant_id: String,
    email: String,
    name: Option<String>,
    password_hash: String,
    role: String,
    status: String,
    mfa_enabled: bool,
    mfa_secret: Option<String>,
}

// ─── Registration types ────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    pub company_name: String,
    pub email: String,
    pub name: String,
    pub password: String,
    #[serde(default = "default_plan")]
    pub plan: String,
}

fn default_plan() -> String {
    "free".into()
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyEmailQuery {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyEmailResponse {
    pub success: bool,
    pub message: String,
}

// ─── Registration handler ──────────────────────────────────────

async fn register(
    State(state): State<AppState>,
    Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), ApiError> {
    // Validate input
    if body.company_name.is_empty() || body.company_name.len() > 100 {
        return Err(ApiError::Validation(vec![
            "company_name must be 1-100 characters".into(),
        ]));
    }
    if body.email.is_empty() || body.email.len() > 254 {
        return Err(ApiError::Validation(vec!["invalid email address".into()]));
    }
    if body.name.is_empty() || body.name.len() > 100 {
        return Err(ApiError::Validation(vec![
            "name must be 1-100 characters".into()
        ]));
    }
    validate_password_strength(&body.password)?;

    // Validate plan
    let valid_plans = [
        "free",
        "starter",
        "pro",
        "growth",
        "scale",
        "enterprise",
        "payg",
    ];
    if !valid_plans.contains(&body.plan.as_str()) {
        return Err(ApiError::Validation(vec![format!(
            "invalid plan: {}",
            body.plan
        )]));
    }

    let email_lower = body.email.to_lowercase();

    // Check if email already exists
    let existing: Option<String> =
        sqlx::query_scalar("SELECT id FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1")
            .bind(&email_lower)
            .fetch_optional(&state.db)
            .await?;

    if existing.is_some() {
        return Ok((StatusCode::ACCEPTED, Json(register_response())));
    }

    // Generate IDs and slug
    let tenant_id = apexmail_lib::id::generate_id("", 26);
    let user_id = apexmail_lib::id::generate_id("", 26);
    let slug = generate_slug(&body.company_name);
    let now = Utc::now();

    // Hash password
    let password_hash = apexmail_lib::crypto::hash_password(&body.password)
        .map_err(|e| ApiError::Internal(format!("password hashing failed: {e}")))?;

    // Generate verification token
    let verification_token = apexmail_lib::id::generate_verification_token();
    let verification_token_hash = hash_token(&verification_token);
    let verification_expires = now + ChronoDuration::hours(24);

    let mut tx = state.db.begin().await.map_err(|error| {
        tracing::error!(error = %error, "failed to begin registration transaction");
        ApiError::Internal("database error".into())
    })?;

    // Create tenant
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
    )
    .bind(&tenant_id)
    .bind(&body.company_name)
    .bind(&slug)
    .bind(&body.plan)
    .bind("pending")
    .bind(serde_json::json!({}))
    .bind(serde_json::json!({}))
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|error| {
        tracing::error!(error = %error, tenant_id = %tenant_id, "failed to create tenant during registration");
        ApiError::Internal("database error".into())
    })?;

    // Create user with owner role
    match sqlx::query(
        "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status, 
                           email_verified, mfa_enabled, metadata, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(&user_id)
    .bind(&tenant_id)
    .bind(&email_lower)
    .bind(&body.name)
    .bind(&password_hash)
    .bind("owner")
    .bind("active")
    .bind(false) // email_verified = false until verified
    .bind(false) // mfa_enabled
    .bind(serde_json::json!({
        "verification_token_hash": verification_token_hash,
        "verification_expires": verification_expires.to_rfc3339(),
    }))
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await
    {
        Ok(_) => {}
        Err(error) if is_unique_violation(&error) => {
            let _ = tx.rollback().await;
            return Ok((StatusCode::ACCEPTED, Json(register_response())));
        }
        Err(error) => {
            tracing::error!(error = %error, user_id = %user_id, tenant_id = %tenant_id, "failed to create user during registration");
            return Err(ApiError::Internal("database error".into()));
        }
    }

    enqueue_verification_email(&mut tx, &state.config.base_url, &email_lower, &verification_token)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, tenant_id = %tenant_id, user_id = %user_id, "failed to queue verification email during registration");
            ApiError::Internal("database error".into())
        })?;

    tx.commit().await.map_err(|error| {
        tracing::error!(error = %error, tenant_id = %tenant_id, user_id = %user_id, "failed to commit registration transaction");
        ApiError::Internal("database error".into())
    })?;

    tracing::info!(
        tenant_id = %tenant_id,
        user_id = %user_id,
        plan = %body.plan,
        "New tenant registered"
    );

    Ok((StatusCode::ACCEPTED, Json(register_response())))
}

fn generate_slug(company_name: &str) -> String {
    let base: String = company_name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let slug = base.trim_matches('-').to_string();
    // Add random suffix for uniqueness
    format!("{}-{}", slug, &Uuid::new_v4().to_string()[..8])
}

// ─── Email verification handler ────────────────────────────────

async fn verify_email(
    State(state): State<AppState>,
    Query(params): Query<VerifyEmailQuery>,
) -> Result<Json<VerifyEmailResponse>, ApiError> {
    Ok(Json(verify_email_token(&state, &params.token).await?))
}

pub(crate) async fn verify_email_token(
    state: &AppState,
    token: &str,
) -> Result<VerifyEmailResponse, ApiError> {
    if token.is_empty() || token.len() > 128 {
        return Err(ApiError::Validation(vec![
            "invalid verification token".into()
        ]));
    }

    let token_hash = hash_token(token);

    // Find user with matching verification token
    let user: Option<(String, String, serde_json::Value)> = sqlx::query_as(
        "SELECT id, tenant_id, metadata FROM users 
            WHERE metadata->>'verification_token_hash' = $1
         AND email_verified = false
         LIMIT 1",
    )
    .bind(&token_hash)
    .fetch_optional(&state.db)
    .await?;

    let (user_id, tenant_id, metadata) = match user {
        Some(u) => u,
        None => {
            return Err(ApiError::BadRequest(
                "invalid or expired verification token".into(),
            ));
        }
    };

    // Check expiry
    if let Some(expires_str) = metadata
        .get("verification_expires")
        .and_then(|v| v.as_str())
    {
        if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(expires_str) {
            if Utc::now() > expires {
                return Err(ApiError::BadRequest(
                    "verification token has expired".into(),
                ));
            }
        }
    }

    // Mark email as verified
    sqlx::query(
        "UPDATE users SET email_verified = true, 
            metadata = metadata - 'verification_token_hash' - 'verification_token' - 'verification_expires',
         updated_at = NOW()
         WHERE id = $1"
    )
    .bind(&user_id)
    .execute(&state.db)
    .await?;

    // Activate tenant
    sqlx::query("UPDATE tenants SET status = 'active', updated_at = NOW() WHERE id = $1")
        .bind(&tenant_id)
        .execute(&state.db)
        .await?;

    tracing::info!(user_id = %user_id, tenant_id = %tenant_id, "Email verified");

    Ok(VerifyEmailResponse {
        success: true,
        message: "Email verified successfully. You can now log in.".into(),
    })
}

async fn create_api_key(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<CreateApiKeyResponse>), ApiError> {
    if body.name.is_empty() {
        return Err(ApiError::Validation(vec!["name is required".into()]));
    }

    let raw_key = apexmail_lib::id::generate_api_key(false);
    let key_hash =
        apexmail_lib::hash_api_key_with_secret(&raw_key, &state.config.api_key_hash_secret);
    // The persisted prefix must fit the api_keys.prefix VARCHAR(10) column.
    // If the key is unusually short, store at most 8 chars (or half the key)
    // to avoid exposing the full key.
    let prefix_len = if raw_key.len() >= 10 {
        10
    } else {
        raw_key.len().min(8).max(raw_key.len() / 2)
    };
    let key_prefix = raw_key[..prefix_len].to_string();

    let id = apexmail_lib::id::generate_id("key", 22);
    let now = Utc::now();
    let expires_at = Some(resolve_api_key_expiry(body.expires_in_days, now)?);

    sqlx::query(
        "INSERT INTO api_keys (id, tenant_id, user_id, name, prefix, key_hash, scopes, expires_at, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(&id)
    .bind(auth.tenant_id)
    .bind(auth.user_id.as_deref())
    .bind(&body.name)
    .bind(&key_prefix)
    .bind(&key_hash)
    .bind(serde_json::json!(body.scopes))
    .bind(expires_at)
    .bind(now)
    .execute(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateApiKeyResponse {
            id,
            key: raw_key,
            key_prefix,
            name: body.name,
            scopes: body.scopes,
            created_at: now.to_rfc3339(),
            expires_at: expires_at.map(|value| value.to_rfc3339()),
        }),
    ))
}

async fn list_api_keys(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ListApiKeysQuery>,
) -> Result<Json<Vec<ApiKeyInfo>>, ApiError> {
    let offset = params.cursor.unwrap_or(params.offset).clamp(0, 100_000);
    let rows = sqlx::query_as::<_, ApiKeyInfoRow>(
        "SELECT id, name, prefix AS key_prefix, scopes, last_used_at, created_at, expires_at
         FROM api_keys WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(auth.tenant_id)
    .bind(clamp_limit(params.limit, 200))
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    let keys: Vec<ApiKeyInfo> = rows
        .into_iter()
        .map(|r| ApiKeyInfo {
            id: r.id,
            name: r.name,
            key_prefix: r.key_prefix,
            scopes: r.scopes,
            last_used_at: r.last_used_at.map(|t| t.to_rfc3339()),
            created_at: r.created_at.to_rfc3339(),
            expires_at: r.expires_at.map(|value| value.to_rfc3339()),
        })
        .collect();

    Ok(Json(keys))
}

#[derive(sqlx::FromRow)]
struct ApiKeyInfoRow {
    id: String,
    name: String,
    key_prefix: String,
    scopes: serde_json::Value,
    last_used_at: Option<chrono::DateTime<Utc>>,
    created_at: chrono::DateTime<Utc>,
    expires_at: Option<chrono::DateTime<Utc>>,
}

fn resolve_api_key_expiry(
    expires_in_days: Option<i64>,
    now: chrono::DateTime<Utc>,
) -> Result<chrono::DateTime<Utc>, ApiError> {
    let days = expires_in_days.unwrap_or(DEFAULT_API_KEY_EXPIRY_DAYS);
    if !(1..=MAX_API_KEY_EXPIRY_DAYS).contains(&days) {
        return Err(ApiError::Validation(vec![format!(
            "expires_in_days must be between 1 and {MAX_API_KEY_EXPIRY_DAYS}"
        )]));
    }

    Ok(now + ChronoDuration::days(days))
}

async fn revoke_api_key(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let deleted_key_hash: Option<String> = sqlx::query_scalar(
        "DELETE FROM api_keys WHERE id = $1 AND tenant_id = $2 RETURNING key_hash",
    )
    .bind(id)
    .bind(auth.tenant_id)
    .fetch_optional(&state.db)
    .await?;

    let Some(key_hash) = deleted_key_hash else {
        return Err(ApiError::NotFound("API key not found".into()));
    };

    invalidate_api_key_cache(&key_hash, &state).await;

    Ok(StatusCode::NO_CONTENT)
}

async fn reset_password(
    State(state): State<AppState>,
    Json(body): Json<ResetPasswordRequest>,
) -> Result<Json<ResetPasswordResponse>, ApiError> {
    if body.token.is_empty() || body.token.len() > 128 {
        return Err(ApiError::Validation(vec![
            "invalid password reset token".into()
        ]));
    }
    if body.email.is_empty() || body.email.len() > 254 {
        return Err(ApiError::Validation(vec!["invalid email address".into()]));
    }
    if let Some(confirm_password) = &body.confirm_password {
        if confirm_password != &body.password {
            return Err(ApiError::Validation(vec![
                "password confirmation does not match".into(),
            ]));
        }
    }
    validate_password_strength(&body.password)?;

    let token_hash = hash_token(&body.token);
    let email = body.email.trim().to_lowercase();
    let user: Option<(String, String, serde_json::Value)> = sqlx::query_as(
        "SELECT id, status, metadata FROM users
         WHERE LOWER(email) = LOWER($1)
                     AND metadata->>'password_reset_token_hash' = $2
         LIMIT 1",
    )
    .bind(&email)
    .bind(&token_hash)
    .fetch_optional(&state.db)
    .await?;

    let Some((user_id, status, metadata)) = user else {
        return Err(ApiError::BadRequest(
            "invalid or expired reset token".into(),
        ));
    };

    if status != "active" {
        return Err(ApiError::Forbidden(format!("account is {status}")));
    }

    if let Some(expires_str) = metadata
        .get("password_reset_expires")
        .and_then(|value| value.as_str())
    {
        if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(expires_str) {
            if Utc::now() > expires {
                return Err(ApiError::BadRequest(
                    "password reset token has expired".into(),
                ));
            }
        }
    }

    let password_hash = apexmail_lib::hash_password(&body.password)
        .map_err(|error| ApiError::Internal(format!("password hashing failed: {error}")))?;

    sqlx::query(
        "UPDATE users
         SET password_hash = $1,
             metadata = metadata - 'password_reset_token_hash' - 'password_reset_token' - 'password_reset_expires',
             updated_at = NOW()
         WHERE id = $2",
    )
    .bind(password_hash)
    .bind(&user_id)
    .execute(&state.db)
    .await?;

    Ok(Json(ResetPasswordResponse {
        success: true,
        message: "Password updated successfully.".into(),
    }))
}

async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: Option<AuthUser>,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    let session_token = extract_cookie(&headers, "am_session");
    if session_token.is_some() {
        validate_session_csrf(&headers, &state.config.csrf_secret)?;
    }

    let token_to_blacklist = session_token.or_else(|| extract_bearer_token(&headers));

    if let Some(token) = token_to_blacklist {
        let key = token_blacklist_key(&token);
        if let Ok(mut conn) = state.redis.get().await {
            let ttl = state.config.jwt_expiry.as_secs();
            let _: Result<(), _> =
                deadpool_redis::redis::AsyncCommands::set_ex(&mut *conn, &key, "1", ttl).await;
        }
    }

    if let Some(auth_user) = auth.as_ref() {
        if let Some(user_id) = auth_user.user_id.as_deref() {
            revoke_user_sessions(
                &state.redis,
                &auth_user.tenant_id,
                user_id,
                state.config.jwt_expiry.as_secs(),
            )
            .await?;
        }
    }

    let mut headers = HeaderMap::new();
    let clear_cookie = build_clear_session_cookie(state.config.environment.is_production());
    let value = clear_cookie.parse().map_err(|e| {
        tracing::error!(error = %e, "failed to build clear-session cookie header");
        ApiError::Internal("failed to clear session cookie".into())
    })?;
    headers.insert("Set-Cookie", value);

    Ok((headers, StatusCode::NO_CONTENT))
}

async fn refresh_token(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<SessionAuthResponse>), ApiError> {
    let token = extract_cookie(&headers, "am_session")
        .ok_or_else(|| ApiError::Unauthorized("active session required".into()))?;
    validate_session_csrf(&headers, &state.config.csrf_secret)?;

    // Decode existing token to get claims
    let key = jsonwebtoken::DecodingKey::from_rsa_pem(state.config.jwt_public_key_pem.as_bytes())
        .map_err(|e| {
        ApiError::Internal(format!("invalid JWT public key configuration: {e}"))
    })?;
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_required_spec_claims(&["exp", "sub", "tenant_id"]);

    let token_data = jsonwebtoken::decode::<JwtClaims>(&token, &key, &validation)?;
    let old_claims = token_data.claims;

    let user_id = old_claims.sub.clone();
    let _tenant_id = old_claims.tenant_id.clone();

    let user = sqlx::query_as::<_, UserRow>(
        "SELECT id, tenant_id, email, name, password_hash, role, status FROM users WHERE id = $1",
    )
    .bind(&user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("user not found".into()))?;

    // Fix #21: Reject refresh if the user is no longer active.
    if user.status != "active" {
        return Err(ApiError::Forbidden(format!("account is {}", user.status)));
    }

    // Fix #20: Blacklist the old token so it cannot be reused.
    {
        let bl_key = token_blacklist_key(&token);
        if let Ok(mut conn) = state.redis.get().await {
            let ttl = state.config.jwt_expiry.as_secs();
            let _: Result<(), _> =
                deadpool_redis::redis::AsyncCommands::set_ex(&mut *conn, &bl_key, "1", ttl).await;
        }
    }

    let expiry_secs = state.config.jwt_expiry.as_secs() as i64;
    let now = Utc::now();
    let exp = now + ChronoDuration::seconds(expiry_secs);

    let claims = JwtClaims {
        sub: user.id.to_string(),
        tenant_id: user.tenant_id.to_string(),
        scopes: scopes_for_role(&user.role),
        exp: exp.timestamp(),
        iat: now.timestamp(),
    };

    let token = encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(state.config.jwt_private_key_pem.as_bytes()).map_err(|e| {
            ApiError::Internal(format!("invalid JWT private key configuration: {e}"))
        })?,
    )
    .map_err(|e| ApiError::Internal(format!("token generation failed: {e}")))?;

    let mut headers = HeaderMap::new();
    insert_private_no_store_headers(&mut headers);
    let cookie = build_session_cookie(
        &token,
        expiry_secs,
        state.config.environment.is_production(),
    );
    let value = cookie.parse().map_err(|e| {
        tracing::error!(error = %e, "failed to build session cookie header on refresh");
        ApiError::Internal("failed to set session cookie".into())
    })?;
    headers.insert("Set-Cookie", value);

    Ok((
        headers,
        Json(SessionAuthResponse {
            expires_at: exp.to_rfc3339(),
            user: UserInfo {
                id: user.id,
                email: user.email,
                name: user.name,
                tenant_id: user.tenant_id,
                role: user.role,
            },
        }),
    ))
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use deadpool_redis::Config as RedisConfig;

    #[test]
    fn test_login_request_deserialisation() {
        let json = r#"{"email":"a@b.com","password":"secret"}"#;
        let req: LoginRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.email, "a@b.com");
        assert!(req.mfa_code.is_none());
    }

    #[test]
    fn test_login_request_accepts_mfa_code_alias() {
        let json = r#"{"email":"a@b.com","password":"secret","mfaCode":"123456"}"#;
        let req: LoginRequest = serde_json::from_str(json).unwrap();

        assert_eq!(req.mfa_code.as_deref(), Some("123456"));
    }

    #[test]
    fn test_login_request_rejects_unknown_fields() {
        let json = r#"{"email":"a@b.com","password":"secret","unexpected":true}"#;

        assert!(serde_json::from_str::<LoginRequest>(json).is_err());
    }

    #[test]
    fn test_session_auth_response_serialisation() {
        let resp = SessionAuthResponse {
            expires_at: "2026-01-01T00:00:00Z".into(),
            user: UserInfo {
                id: Uuid::nil().to_string(),
                email: "a@b.com".into(),
                name: None,
                tenant_id: Uuid::nil().to_string(),
                role: "admin".into(),
            },
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["user"]["role"], "admin");
        assert!(json.get("token").is_none());
    }

    #[test]
    fn test_create_api_key_request_defaults() {
        let json = r#"{"name":"prod","scopes":["messages:send"]}"#;
        let req: CreateApiKeyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "prod");
        assert!(req.expires_in_days.is_none());
    }

    #[test]
    fn test_create_api_key_request_rejects_unknown_fields() {
        let json =
            r#"{"name":"prod","scopes":["messages:send"],"expires_in_days":30,"oops":"extra"}"#;

        assert!(serde_json::from_str::<CreateApiKeyRequest>(json).is_err());
    }

    #[test]
    fn test_api_key_info_serialisation() {
        let info = ApiKeyInfo {
            id: Uuid::nil().to_string(),
            name: "test".into(),
            key_prefix: "am_live_abc".into(),
            scopes: serde_json::json!(["*"]),
            last_used_at: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            expires_at: Some("2026-04-01T00:00:00Z".into()),
        };
        let json = serde_json::to_value(&info).unwrap();
        assert!(json["last_used_at"].is_null());
        assert_eq!(json["expires_at"], "2026-04-01T00:00:00Z");
    }

    #[test]
    fn test_resolve_api_key_expiry_defaults_to_ninety_days() {
        let now = Utc::now();
        let expires_at = resolve_api_key_expiry(None, now).expect("default expiry should resolve");

        assert_eq!(
            expires_at,
            now + ChronoDuration::days(DEFAULT_API_KEY_EXPIRY_DAYS)
        );
    }

    #[test]
    fn test_resolve_api_key_expiry_rejects_out_of_range_values() {
        let now = Utc::now();

        assert!(matches!(
            resolve_api_key_expiry(Some(0), now),
            Err(ApiError::Validation(_))
        ));
        assert!(matches!(
            resolve_api_key_expiry(Some(MAX_API_KEY_EXPIRY_DAYS + 1), now),
            Err(ApiError::Validation(_))
        ));
    }

    #[test]
    fn test_register_response_does_not_leak_verification_token_or_internal_ids() {
        let json = serde_json::to_value(register_response()).unwrap();

        assert_eq!(json["success"], true);
        assert!(json.get("message").is_some());
        assert!(json.get("tenant_id").is_none());
        assert!(json.get("user_id").is_none());
        assert!(json.get("verification_token").is_none());
    }

    #[test]
    fn test_hash_token_is_deterministic() {
        assert_eq!(hash_token("abc"), hash_token("abc"));
        assert_ne!(hash_token("abc"), hash_token("def"));
    }

    #[test]
    fn test_verify_password_or_log_accepts_argon2_hashes() {
        let password = "StrongPassword1!";
        let hash = apexmail_lib::hash_password(password).unwrap();

        assert!(verify_password_or_log(
            password,
            &hash,
            "argon2-user@example.com"
        ));
        assert!(!verify_password_or_log(
            "WrongPassword1!",
            &hash,
            "argon2-user@example.com"
        ));
    }

    #[test]
    fn test_verify_password_or_log_accepts_bcrypt_hashes() {
        let password = "StrongPassword1!";
        let hash = bcrypt::hash(password, 4).unwrap();

        assert!(verify_password_or_log(
            password,
            &hash,
            "bcrypt-user@example.com"
        ));
        assert!(!verify_password_or_log(
            "WrongPassword1!",
            &hash,
            "bcrypt-user@example.com"
        ));
    }

    #[test]
    fn test_validate_password_strength_requires_ascii_special_character() {
        assert!(validate_password_strength("StrongPassword1!").is_ok());
        assert!(matches!(
            validate_password_strength("Password123é"),
            Err(ApiError::Validation(_))
        ));
    }

    #[test]
    fn test_authenticated_user_id_requires_user_session() {
        let auth = AuthUser {
            tenant_id: "tenant_123".into(),
            user_id: None,
            api_key_id: Some("key_123".into()),
            scopes: vec!["messages:read".into()],
        };

        assert!(matches!(
            authenticated_user_id(&auth),
            Err(ApiError::Unauthorized(message)) if message == "user session required"
        ));
    }

    #[test]
    fn test_authenticated_user_id_returns_string_identifier_without_conversion() {
        let auth = AuthUser {
            tenant_id: "tenant_123".into(),
            user_id: Some("usr_01hxyz".into()),
            api_key_id: None,
            scopes: vec!["messages:read".into()],
        };

        assert_eq!(authenticated_user_id(&auth).unwrap(), "usr_01hxyz");
    }

    #[test]
    fn test_reset_password_request_aliases() {
        let json = r#"{"token":"tok","email":"user@example.com","password":"StrongPassword1!","confirmPassword":"StrongPassword1!"}"#;
        let req: ResetPasswordRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.confirm_password.as_deref(), Some("StrongPassword1!"));
    }

    #[test]
    fn test_reset_password_request_rejects_unknown_fields() {
        let json = r#"{"token":"tok","email":"user@example.com","password":"StrongPassword1!","confirmPassword":"StrongPassword1!","extra":"nope"}"#;

        assert!(serde_json::from_str::<ResetPasswordRequest>(json).is_err());
    }

    #[test]
    fn test_scopes_for_role_mapping() {
        assert_eq!(scopes_for_role("owner"), vec!["*".to_string()]);
        assert!(scopes_for_role("developer").contains(&"messages:send".to_string()));
        assert_eq!(scopes_for_role("member"), vec!["messages:read".to_string()]);
    }

    #[test]
    fn test_role_requires_mfa_for_admin_and_owner_only() {
        assert!(role_requires_mfa("admin"));
        assert!(role_requires_mfa("owner"));
        assert!(!role_requires_mfa("developer"));
    }

    #[test]
    fn test_base32_encode_matches_known_secret() {
        assert_eq!(base32_encode(b"Hello!\xDE\xAD\xBE\xEF"), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn test_build_mfa_otpauth_url_contains_expected_fields() {
        let url = build_mfa_otpauth_url("owner@example.com", "JBSWY3DPEHPK3PXP");

        assert!(url.starts_with("otpauth://totp/ApexMail%3Aowner%40example.com?"));
        assert!(url.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(url.contains("issuer=ApexMail"));
        assert!(url.contains("algorithm=SHA256"));
    }

    #[test]
    fn test_mfa_challenge_key_namespaces_tokens() {
        assert_eq!(
            mfa_challenge_key("mfa_123"),
            "apexmail:auth:mfa_challenge:mfa_123"
        );
    }

    #[test]
    fn test_complete_mfa_challenge_request_aliases() {
        let json = r#"{"challenge_token":"mfa_123","mfaCode":"654321"}"#;
        let req: CompleteMfaChallengeRequest = serde_json::from_str(json).unwrap();

        assert_eq!(req.challenge_token, "mfa_123");
        assert_eq!(req.mfa_code, "654321");
    }

    #[test]
    fn test_complete_mfa_challenge_request_rejects_unknown_fields() {
        let json = r#"{"challenge_token":"mfa_123","mfaCode":"654321","unexpected":1}"#;

        assert!(serde_json::from_str::<CompleteMfaChallengeRequest>(json).is_err());
    }

    #[test]
    fn test_login_lockout_duration_escalates_and_caps() {
        assert_eq!(login_lockout_duration(1), 900);
        assert_eq!(login_lockout_duration(2), 1800);
        assert_eq!(login_lockout_duration(3), 3600);
        assert_eq!(login_lockout_duration(10), LOGIN_LOCKOUT_MAX_SECS);
    }

    #[test]
    fn test_login_lockout_keys_hash_identifiers() {
        let key = login_failure_key("Owner@Example.com");
        assert!(key.starts_with("apexmail:auth:failures:"));
        assert!(!key.contains("Owner@Example.com"));
        assert_ne!(key, login_failure_key("owner2@example.com"));
    }

    #[test]
    fn test_revoke_user_sessions_uses_tenant_scoped_revocation_key() {
        let key = session_revocation_key("ten_test_001", "usr_test_001");
        assert_eq!(
            key,
            "apexmail:session_revoked_after:ten_test_001:usr_test_001"
        );
    }

    #[tokio::test]
    async fn test_record_login_failure_sets_lock_when_redis_is_available() {
        let redis_url =
            std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let pool = match RedisConfig::from_url(&redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        {
            Ok(pool) => pool,
            Err(_) => return,
        };

        let mut conn = match pool.get().await {
            Ok(conn) => conn,
            Err(_) => return,
        };
        let ping: Result<String, _> = deadpool_redis::redis::cmd("PING")
            .query_async(&mut *conn)
            .await;
        if ping.is_err() {
            return;
        }
        drop(conn);

        let identifier = format!("lockout-{}@example.com", Uuid::new_v4());
        let failure_key = login_failure_key(&identifier);
        let lock_key = login_lock_key(&identifier);
        let counter_key = login_lockout_counter_key(&identifier);

        if let Ok(mut conn) = pool.get().await {
            let _: Result<i64, _> = deadpool_redis::redis::cmd("DEL")
                .arg(&[
                    failure_key.as_str(),
                    lock_key.as_str(),
                    counter_key.as_str(),
                ])
                .query_async(&mut *conn)
                .await;
        }

        for _ in 0..(LOGIN_FAILURE_THRESHOLD - 1) {
            record_login_failure(&pool, &identifier).await.unwrap();
        }
        assert!(login_lock_ttl(&pool, &identifier).await.unwrap().is_none());

        record_login_failure(&pool, &identifier).await.unwrap();
        assert!(
            login_lock_ttl(&pool, &identifier)
                .await
                .unwrap()
                .unwrap_or_default()
                > 0
        );

        if let Ok(mut conn) = pool.get().await {
            let _: Result<i64, _> = deadpool_redis::redis::cmd("DEL")
                .arg(&[
                    failure_key.as_str(),
                    lock_key.as_str(),
                    counter_key.as_str(),
                ])
                .query_async(&mut *conn)
                .await;
        }
    }
}

// ─── Change Password / Session Revoke ──────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

async fn change_password(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user_id = authenticated_user_id(&auth)?;

    if body.current_password == body.new_password {
        return Err(ApiError::Validation(vec![
            "new password must be different from current password".into(),
        ]));
    }
    validate_password_strength(&body.new_password)?;

    #[derive(sqlx::FromRow)]
    struct PasswordHashRow {
        password_hash: Option<String>,
    }

    // Verify current password
    let user =
        sqlx::query_as::<_, PasswordHashRow>("SELECT password_hash FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| ApiError::NotFound("user not found".into()))?;

    let password_hash = user
        .password_hash
        .as_deref()
        .ok_or_else(|| ApiError::Unauthorized("No password set".into()))?;
    let valid = verify_password_or_log(&body.current_password, password_hash, user_id);

    if !valid {
        return Err(ApiError::Unauthorized("Invalid current password".into()));
    }

    // Hash and update
    let new_hash = apexmail_lib::hash_password(&body.new_password)
        .map_err(|error| ApiError::Internal(format!("Password hashing failed: {error}")))?;

    sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2")
        .bind(new_hash)
        .bind(user_id)
        .execute(&state.db)
        .await?;

    Ok(Json(serde_json::json!({ "changed": true })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeSessionRequest {
    /// Optional: revoke a specific session ID. If omitted, revokes all other sessions.
    #[serde(default)]
    pub session_id: Option<String>,
}

async fn revoke_session(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<RevokeSessionRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user_id = authenticated_user_id(&auth)?;

    let affected = if let Some(session_id) = &body.session_id {
        // Revoke single session
        sqlx::query("DELETE FROM sessions WHERE id = $1 AND user_id = $2")
            .bind(session_id)
            .bind(user_id)
            .execute(&state.db)
            .await?
            .rows_affected()
    } else {
        // Revoke all sessions except current - if no specific session provided,
        // revoke all other sessions (we don't have session_id in auth context)
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&state.db)
            .await?
            .rows_affected()
    };

    Ok(Json(serde_json::json!({ "revoked": affected })))
}
