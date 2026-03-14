//! Authentication routes: login, logout, refresh, register, API key management.

use super::helpers::{extract_cookie, clamp_limit, default_limit};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{delete, post, get};
use axum::{Json, Router};
use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{AuthUser, JwtClaims};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/login", post(login))
        .route("/register", post(register))
        .route("/verify-email", get(verify_email))
        .route("/api-keys", post(create_api_key).get(list_api_keys))
        .route("/api-keys/:id", delete(revoke_api_key))
        .route("/logout", post(logout))
        .route("/refresh", post(refresh_token))
        .route("/change-password", post(change_password))
        .route("/sessions/revoke", post(revoke_session))
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

    // Fix #47: If password_hash cannot be parsed (e.g., SCIM placeholder), treat as invalid credentials
    // rather than internal error to avoid leaking hash format information.
    let valid = apexmail_lib::crypto::verify_password(&body.password, &user.password_hash)
        .unwrap_or(false);

    if !valid {
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }

    let expiry_secs = state.config.jwt_expiry.as_secs() as i64;
    let now = Utc::now();
    let exp = now + ChronoDuration::seconds(expiry_secs);

    // Fix #24: Assign scopes based on user role instead of blanket wildcard.
    let scopes = match user.role.as_str() {
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
    };

    let claims = JwtClaims {
        sub: user.id.to_string(),
        tenant_id: user.tenant_id.to_string(),
        scopes,
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
    pub tenant_id: String,
    pub user_id: String,
    pub verification_token: String,
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
    if body.password.len() < 12 || body.password.len() > 128 {
        return Err(ApiError::Validation(vec!["password must be 12-128 characters".into()]));
    }

    // Validate password strength
    let has_lower = body.password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = body.password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = body.password.chars().any(|c| c.is_ascii_digit());
    let has_special = body.password.chars().any(|c| !c.is_alphanumeric());
    if !has_lower || !has_upper || !has_digit || !has_special {
        return Err(ApiError::Validation(vec![
            "password must include uppercase, lowercase, number, and special character".into()
        ]));
    }

    // Validate plan
    let valid_plans = ["free", "starter", "pro", "growth", "scale", "enterprise", "payg"];
    if !valid_plans.contains(&body.plan.as_str()) {
        return Err(ApiError::Validation(vec![format!("invalid plan: {}", body.plan)]));
    }

    let email_lower = body.email.to_lowercase();

    // Check if email already exists
    let existing: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1"
    )
    .bind(&email_lower)
    .fetch_optional(&state.db)
    .await?;

    if existing.is_some() {
        return Err(ApiError::Conflict("an account with this email already exists".into()));
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
    let verification_expires = now + ChronoDuration::hours(24);

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
    .execute(&state.db)
    .await?;

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
        "verification_token": &verification_token,
        "verification_expires": verification_expires.to_rfc3339(),
    }))
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await?;

    tracing::info!(
        tenant_id = %tenant_id,
        user_id = %user_id,
        plan = %body.plan,
        "New tenant registered"
    );

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            tenant_id,
            user_id,
            verification_token,
            message: "Account created. Please verify your email.".into(),
        }),
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
    if params.token.is_empty() || params.token.len() > 128 {
        return Err(ApiError::Validation(vec!["invalid verification token".into()]));
    }

    // Find user with matching verification token
    let user: Option<(Uuid, Uuid, serde_json::Value)> = sqlx::query_as(
        "SELECT id, tenant_id, metadata FROM users 
         WHERE metadata->>'verification_token' = $1 
         AND email_verified = false
         LIMIT 1"
    )
    .bind(&params.token)
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
         metadata = metadata - 'verification_token' - 'verification_expires',
         updated_at = NOW()
         WHERE id = $1"
    )
    .bind(user_id)
    .execute(&state.db)
    .await?;

    // Activate tenant
    sqlx::query(
        "UPDATE tenants SET status = 'active', updated_at = NOW() WHERE id = $1"
    )
    .bind(tenant_id)
    .execute(&state.db)
    .await?;

    tracing::info!(user_id = %user_id, tenant_id = %tenant_id, "Email verified");

    Ok(Json(VerifyEmailResponse {
        success: true,
        message: "Email verified successfully. You can now log in.".into(),
    }))
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
    let key_hash = apexmail_lib::crypto::hash_api_key(&raw_key);
    // Fix #23: Safely limit prefix length. If key is shorter than 15 chars, store
    // at most 8 chars (or half the key) to avoid exposing the full key.
    let prefix_len = if raw_key.len() >= 15 {
        15
    } else {
        raw_key.len().min(8).max(raw_key.len() / 2)
    };
    let key_prefix = raw_key[..prefix_len].to_string();

    let id = Uuid::new_v4();
    let now = Utc::now();
    let expires_at = body
        .expires_in_days
        .map(|d| now + ChronoDuration::days(d));

    sqlx::query(
        "INSERT INTO api_keys (id, tenant_id, name, key_hash, key_prefix, scopes, expires_at, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(id)
    .bind(auth.tenant_id)
    .bind(&body.name)
    .bind(&key_hash)
    .bind(&key_prefix)
    .bind(serde_json::json!(body.scopes))
    .bind(expires_at)
    .bind(now)
    .execute(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateApiKeyResponse {
            id: id.to_string(),
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
        "SELECT id, name, key_prefix, scopes, last_used_at, created_at
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
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let result = sqlx::query(
        "DELETE FROM api_keys WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(auth.tenant_id)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("API key not found".into()));
    }

    Ok(StatusCode::NO_CONTENT)
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
        scopes: old_claims.scopes,
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
                id: String::nil(),
                email: "a@b.com".into(),
                name: None,
                tenant_id: String::nil(),
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
            id: String::nil(),
            name: "test".into(),
            key_prefix: "am_live_abc".into(),
            scopes: serde_json::json!(["*"]),
            last_used_at: None,
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&info).unwrap();
        assert!(json["last_used_at"].is_null());
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
    // Validate new password strength
    if body.new_password.len() < 12 {
        return Err(ApiError::BadRequest("Password must be at least 12 characters".into()));
    }

    // Verify current password
    let user_id_str = auth.user_id.as_ref().map(|id| id.to_string());
    let user = sqlx::query!(
        "SELECT id, password_hash FROM users WHERE id = $1",
        user_id_str,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("user not found".into()))?;

    let password_hash = user.password_hash.as_deref()
        .ok_or_else(|| ApiError::Unauthorized("No password set".into()))?;
    let valid = bcrypt::verify(&body.current_password, password_hash)
        .map_err(|_| ApiError::Unauthorized("Invalid current password".into()))?;

    if !valid {
        return Err(ApiError::Unauthorized("Invalid current password".into()));
    }

    // Hash and update
    let new_hash = bcrypt::hash(&body.new_password, 12)
        .map_err(|e| ApiError::Internal(format!("Password hashing failed: {e}")))?;

    let user_id_str = auth.user_id.as_ref().map(|id| id.to_string());
    sqlx::query!(
        "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2",
        new_hash,
        user_id_str,
    )
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
    let user_id_str = auth.user_id.map(|id| id.to_string());
    let affected = if let Some(session_id) = &body.session_id {
        // Revoke single session
        sqlx::query!(
            "DELETE FROM sessions WHERE id = $1 AND user_id = $2",
            session_id,
            user_id_str,
        )
        .execute(&state.db)
        .await?
        .rows_affected()
    } else {
        // Revoke all sessions except current - if no specific session provided,
        // revoke all other sessions (we don't have session_id in auth context)
        sqlx::query!(
            "DELETE FROM sessions WHERE user_id = $1",
            user_id_str,
        )
        .execute(&state.db)
        .await?
        .rows_affected()
    };

    Ok(Json(serde_json::json!({ "revoked": affected })))
}
