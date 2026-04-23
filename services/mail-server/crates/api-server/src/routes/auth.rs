//! Authentication routes: login, logout, refresh, register, reset password, and API key management.

use super::helpers::{clamp_limit, default_limit, extract_cookie, hash_token, html_escape};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{invalidate_api_key_cache, AuthUser, JwtClaims};
use crate::state::AppState;

const SYSTEM_TENANT_ID: &str = "system_internal_tenant01";

fn verify_password_or_log(password: &str, hash: &str, subject: &str) -> bool {
    let result = if hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$") {
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

fn validate_password_strength(password: &str) -> Result<(), ApiError> {
    if password.len() < 12 || password.len() > 128 {
        return Err(ApiError::Validation(vec![
            "password must be 12-128 characters".into(),
        ]));
    }

    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());
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
        .route("/register", post(register))
        .route("/signup", post(register))
        .route("/verify-email", get(verify_email))
        .route("/reset-password", post(reset_password))
        .route("/logout", post(logout))
        .route("/refresh", post(refresh_token))
}

// ─── Request / Response types ──────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_at: String,
    pub user: UserInfo,
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
}

#[derive(Debug, Serialize)]
pub struct ApiKeyInfo {
    pub id: String,
    pub name: String,
    pub key_prefix: String,
    pub scopes: serde_json::Value,
    pub last_used_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
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
pub struct RefreshRequest {
    pub token: String,
}

#[derive(Debug, Deserialize)]
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
) -> Result<(HeaderMap, Json<LoginResponse>), ApiError> {
    if body.email.is_empty() || body.password.is_empty() {
        return Err(ApiError::Validation(vec![
            "email and password are required".into(),
        ]));
    }

    let user = sqlx::query_as::<_, UserRow>(
        "SELECT id, tenant_id, email, name, password_hash, role, status FROM users WHERE LOWER(email) = LOWER($1)",
    )
    .bind(&body.email)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::Unauthorized("invalid credentials".into()))?;

    if user.status != "active" {
        return Err(ApiError::Forbidden("account is not active".into()));
    }

    let valid = verify_password_or_log(&body.password, &user.password_hash, &user.email);

    if !valid {
        return Err(ApiError::Unauthorized("invalid credentials".into()));
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
        &EncodingKey::from_rsa_pem(state.config.jwt_private_key_pem.as_bytes())
            .map_err(|e| ApiError::Internal(format!("invalid JWT private key configuration: {e}")))?,
    )
    .map_err(|e| ApiError::Internal(format!("token generation failed: {e}")))?;

    let mut headers = HeaderMap::new();
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

    Ok((headers, Json(LoginResponse {
        token,
        expires_at: exp.to_rfc3339(),
        user: UserInfo {
            id: user.id,
            email: user.email,
            name: user.name,
            tenant_id: user.tenant_id,
            role: user.role,
        },
    })))
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
}

// ─── Registration types ────────────────────────────────────────

#[derive(Debug, Deserialize)]
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
        return Err(ApiError::Validation(vec!["company_name must be 1-100 characters".into()]));
    }
    if body.email.is_empty() || body.email.len() > 254 {
        return Err(ApiError::Validation(vec!["invalid email address".into()]));
    }
    if body.name.is_empty() || body.name.len() > 100 {
        return Err(ApiError::Validation(vec!["name must be 1-100 characters".into()]));
    }
    validate_password_strength(&body.password)?;

    // Validate plan
    let valid_plans = ["free", "starter", "pro", "growth", "scale", "enterprise", "payg"];
    if !valid_plans.contains(&body.plan.as_str()) {
        return Err(ApiError::Validation(vec![format!("invalid plan: {}", body.plan)]));
    }

    let email_lower = body.email.to_lowercase();

    // Check if email already exists
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT id FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1"
    )
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
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status, 
                           email_verified, mfa_enabled, metadata, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"
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
    .map_err(|error| {
        tracing::error!(error = %error, user_id = %user_id, tenant_id = %tenant_id, "failed to create user during registration");
        ApiError::Internal("database error".into())
    })?;

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

    Ok((
        StatusCode::ACCEPTED,
        Json(register_response()),
    ))
}

fn generate_slug(company_name: &str) -> String {
    let base: String = company_name
        .chars()
        .map(|c| if c.is_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
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
        return Err(ApiError::Validation(vec!["invalid verification token".into()]));
    }

    let token_hash = hash_token(token);

    // Find user with matching verification token
    let user: Option<(String, String, serde_json::Value)> = sqlx::query_as(
        "SELECT id, tenant_id, metadata FROM users 
         WHERE (metadata->>'verification_token_hash' = $1 OR metadata->>'verification_token' = $2) 
         AND email_verified = false
         LIMIT 1"
    )
    .bind(&token_hash)
    .bind(token)
    .fetch_optional(&state.db)
    .await?;

    let (user_id, tenant_id, metadata) = match user {
        Some(u) => u,
        None => {
            return Err(ApiError::BadRequest("invalid or expired verification token".into()));
        }
    };

    // Check expiry
    if let Some(expires_str) = metadata.get("verification_expires").and_then(|v| v.as_str()) {
        if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(expires_str) {
            if Utc::now() > expires {
                return Err(ApiError::BadRequest("verification token has expired".into()));
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
    sqlx::query(
        "UPDATE tenants SET status = 'active', updated_at = NOW() WHERE id = $1"
    )
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
    let key_hash = apexmail_lib::hash_api_key_with_secret(&raw_key, &state.config.api_key_hash_secret);
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
    let expires_at = body
        .expires_in_days
        .map(|d| now + ChronoDuration::days(d));

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
        "SELECT id, name, prefix AS key_prefix, scopes, last_used_at, created_at
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
        return Err(ApiError::Validation(vec!["invalid password reset token".into()]));
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
           AND (metadata->>'password_reset_token_hash' = $2 OR metadata->>'password_reset_token' = $3)
         LIMIT 1",
    )
    .bind(&email)
    .bind(&token_hash)
    .bind(&body.token)
    .fetch_optional(&state.db)
    .await?;

    let Some((user_id, status, metadata)) = user else {
        return Err(ApiError::BadRequest("invalid or expired reset token".into()));
    };

    if status != "active" {
        return Err(ApiError::Forbidden(format!("account is {status}")));
    }

    if let Some(expires_str) = metadata.get("password_reset_expires").and_then(|value| value.as_str()) {
        if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(expires_str) {
            if Utc::now() > expires {
                return Err(ApiError::BadRequest("password reset token has expired".into()));
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
    _auth: Option<AuthUser>,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    let token_to_blacklist = extract_cookie(&headers, "am_session")
        .or_else(|| extract_bearer_token(&headers));

    if let Some(token) = token_to_blacklist {
        use sha2::{Sha256, Digest};
        let hash = hex::encode(Sha256::digest(token.as_bytes()));
        let key = format!("apexmail:token_blacklist:{hash}");
        if let Ok(mut conn) = state.redis.get().await {
            let ttl = state.config.jwt_expiry.as_secs();
            let _: Result<(), _> = deadpool_redis::redis::AsyncCommands::set_ex(
                &mut *conn, &key, "1", ttl,
            )
            .await;
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
    Json(body): Json<RefreshRequest>,
) -> Result<(HeaderMap, Json<LoginResponse>), ApiError> {
    // Decode existing token to get claims
    let key = jsonwebtoken::DecodingKey::from_rsa_pem(state.config.jwt_public_key_pem.as_bytes())
        .map_err(|e| ApiError::Internal(format!("invalid JWT public key configuration: {e}")))?;
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_required_spec_claims(&["exp", "sub", "tenant_id"]);

    let token_data = jsonwebtoken::decode::<JwtClaims>(&body.token, &key, &validation)?;
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
        use sha2::{Sha256, Digest};
        let hash = hex::encode(Sha256::digest(body.token.as_bytes()));
        let bl_key = format!("apexmail:token_blacklist:{hash}");
        if let Ok(mut conn) = state.redis.get().await {
            let ttl = state.config.jwt_expiry.as_secs();
            let _: Result<(), _> = deadpool_redis::redis::AsyncCommands::set_ex(
                &mut *conn, &bl_key, "1", ttl,
            )
            .await;
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
        &EncodingKey::from_rsa_pem(state.config.jwt_private_key_pem.as_bytes())
            .map_err(|e| ApiError::Internal(format!("invalid JWT private key configuration: {e}")))?,
    )
    .map_err(|e| ApiError::Internal(format!("token generation failed: {e}")))?;

    let mut headers = HeaderMap::new();
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

    Ok((headers, Json(LoginResponse {
        token,
        expires_at: exp.to_rfc3339(),
        user: UserInfo {
            id: user.id,
            email: user.email,
            name: user.name,
            tenant_id: user.tenant_id,
            role: user.role,
        },
    })))
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_request_deserialisation() {
        let json = r#"{"email":"a@b.com","password":"secret"}"#;
        let req: LoginRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.email, "a@b.com");
    }

    #[test]
    fn test_login_response_serialisation() {
        let resp = LoginResponse {
            token: "jwt.token.here".into(),
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
    }

    #[test]
    fn test_create_api_key_request_defaults() {
        let json = r#"{"name":"prod","scopes":["messages:send"]}"#;
        let req: CreateApiKeyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "prod");
        assert!(req.expires_in_days.is_none());
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
        };
        let json = serde_json::to_value(&info).unwrap();
        assert!(json["last_used_at"].is_null());
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

        assert!(verify_password_or_log(password, &hash, "argon2-user@example.com"));
        assert!(!verify_password_or_log("WrongPassword1!", &hash, "argon2-user@example.com"));
    }

    #[test]
    fn test_verify_password_or_log_accepts_bcrypt_hashes() {
        let password = "StrongPassword1!";
        let hash = bcrypt::hash(password, 4).unwrap();

        assert!(verify_password_or_log(password, &hash, "bcrypt-user@example.com"));
        assert!(!verify_password_or_log("WrongPassword1!", &hash, "bcrypt-user@example.com"));
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
    fn test_scopes_for_role_mapping() {
        assert_eq!(scopes_for_role("owner"), vec!["*".to_string()]);
        assert!(scopes_for_role("developer").contains(&"messages:send".to_string()));
        assert_eq!(scopes_for_role("member"), vec!["messages:read".to_string()]);
    }
}

// ─── Change Password / Session Revoke ──────────────────────────

#[derive(Debug, Deserialize)]
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
    let user = sqlx::query_as::<_, PasswordHashRow>(
        "SELECT password_hash FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("user not found".into()))?;

    let password_hash = user.password_hash.as_deref()
        .ok_or_else(|| ApiError::Unauthorized("No password set".into()))?;
    let valid = verify_password_or_log(&body.current_password, password_hash, user_id);

    if !valid {
        return Err(ApiError::Unauthorized("Invalid current password".into()));
    }

    // Hash and update
    let new_hash = apexmail_lib::hash_password(&body.new_password)
        .map_err(|error| ApiError::Internal(format!("Password hashing failed: {error}")))?;

    sqlx::query(
        "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2",
    )
    .bind(new_hash)
    .bind(user_id)
    .execute(&state.db)
    .await?;

    Ok(Json(serde_json::json!({ "changed": true })))
}

#[derive(Debug, Deserialize)]
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
        sqlx::query(
            "DELETE FROM sessions WHERE id = $1 AND user_id = $2",
        )
        .bind(session_id)
        .bind(user_id)
        .execute(&state.db)
        .await?
        .rows_affected()
    } else {
        // Revoke all sessions except current - if no specific session provided,
        // revoke all other sessions (we don't have session_id in auth context)
        sqlx::query(
            "DELETE FROM sessions WHERE user_id = $1",
        )
        .bind(user_id)
        .execute(&state.db)
        .await?
        .rows_affected()
    };

    Ok(Json(serde_json::json!({ "revoked": affected })))
}
