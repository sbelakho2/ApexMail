//! Authentication routes: login, logout, refresh, API key management.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, post};
use axum::{Json, Router};
use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{AuthUser, JwtClaims};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/login", post(login))
        .route("/api-keys", post(create_api_key).get(list_api_keys))
        .route("/api-keys/:id", delete(revoke_api_key))
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
    pub id: Uuid,
    pub email: String,
    pub name: Option<String>,
    pub tenant_id: Uuid,
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
    pub id: Uuid,
    pub key: String,
    pub key_prefix: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyInfo {
    pub id: Uuid,
    pub name: String,
    pub key_prefix: String,
    pub scopes: serde_json::Value,
    pub last_used_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub token: String,
}

// ─── Handlers ──────────────────────────────────────────────────

async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    if body.email.is_empty() || body.password.is_empty() {
        return Err(ApiError::Validation(vec![
            "email and password are required".into(),
        ]));
    }

    let user = sqlx::query_as::<_, UserRow>(
        "SELECT id, tenant_id, email, name, password_hash, role, status FROM users WHERE email = $1",
    )
    .bind(&body.email)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::Unauthorized("invalid credentials".into()))?;

    if user.status != "active" {
        return Err(ApiError::Forbidden("account is not active".into()));
    }

    let valid = apexmail_lib::crypto::verify_password(&body.password, &user.password_hash)
        .map_err(|_| ApiError::Internal("password verification error".into()))?;

    if !valid {
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }

    let expiry_secs = state.config.jwt_expiry.as_secs() as i64;
    let now = Utc::now();
    let exp = now + ChronoDuration::seconds(expiry_secs);

    let claims = JwtClaims {
        sub: user.id.to_string(),
        tenant_id: user.tenant_id.to_string(),
        scopes: vec!["*".into()],
        exp: exp.timestamp(),
        iat: now.timestamp(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
    )
    .map_err(|e| ApiError::Internal(format!("token generation failed: {e}")))?;

    Ok(Json(LoginResponse {
        token,
        expires_at: exp.to_rfc3339(),
        user: UserInfo {
            id: user.id,
            email: user.email,
            name: user.name,
            tenant_id: user.tenant_id,
            role: user.role,
        },
    }))
}

#[derive(sqlx::FromRow)]
struct UserRow {
    id: Uuid,
    tenant_id: Uuid,
    email: String,
    name: Option<String>,
    password_hash: String,
    role: String,
    status: String,
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
    let key_prefix = raw_key[..15.min(raw_key.len())].to_string();

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
) -> Result<Json<Vec<ApiKeyInfo>>, ApiError> {
    let rows = sqlx::query_as::<_, ApiKeyInfoRow>(
        "SELECT id, name, key_prefix, scopes, last_used_at, created_at
         FROM api_keys WHERE tenant_id = $1 ORDER BY created_at DESC",
    )
    .bind(auth.tenant_id)
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
    id: Uuid,
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
    _auth: AuthUser,
    Json(body): Json<RefreshRequest>,
) -> Result<StatusCode, ApiError> {
    // Blacklist the token in Redis
    let token_fragment = &body.token[..16.min(body.token.len())];
    let key = format!("apexmail:token_blacklist:{token_fragment}");
    if let Ok(mut conn) = state.redis.get().await {
        let ttl = state.config.jwt_expiry.as_secs();
        let _: Result<(), _> = deadpool_redis::redis::AsyncCommands::set_ex(
            &mut *conn, &key, "1", ttl,
        )
        .await;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn refresh_token(
    State(state): State<AppState>,
    Json(body): Json<RefreshRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    // Decode existing token to get claims
    let key = jsonwebtoken::DecodingKey::from_secret(state.config.jwt_secret.as_bytes());
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.set_required_spec_claims(&["exp", "sub", "tenant_id"]);

    let token_data = jsonwebtoken::decode::<JwtClaims>(&body.token, &key, &validation)?;
    let old_claims = token_data.claims;

    let user_id = Uuid::parse_str(&old_claims.sub)
        .map_err(|_| ApiError::BadRequest("invalid user ID".into()))?;
    let _tenant_id = Uuid::parse_str(&old_claims.tenant_id)
        .map_err(|_| ApiError::BadRequest("invalid tenant ID".into()))?;

    let user = sqlx::query_as::<_, UserRow>(
        "SELECT id, tenant_id, email, name, password_hash, role, status FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("user not found".into()))?;

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
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
    )
    .map_err(|e| ApiError::Internal(format!("token generation failed: {e}")))?;

    Ok(Json(LoginResponse {
        token,
        expires_at: exp.to_rfc3339(),
        user: UserInfo {
            id: user.id,
            email: user.email,
            name: user.name,
            tenant_id: user.tenant_id,
            role: user.role,
        },
    }))
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
                id: Uuid::nil(),
                email: "a@b.com".into(),
                name: None,
                tenant_id: Uuid::nil(),
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
            id: Uuid::nil(),
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
