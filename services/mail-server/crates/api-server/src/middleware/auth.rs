//! Authentication extractors for Axum.
//!
//! Supports two authentication methods:
//! 1. **API Key** — `X-API-Key` header, SHA-256 hashed, DB lookup (Redis-cached 60 s).
//! 2. **JWT Bearer** — `Authorization: Bearer <token>`, RS256, extracts claims.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use chrono::{DateTime, Utc};
use deadpool_redis::redis::AsyncCommands;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::AppState;

// ─── AuthUser ──────────────────────────────────────────────────

/// Authenticated identity extracted from the request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    pub tenant_id: Uuid,
    pub user_id: Option<Uuid>,
    pub api_key_id: Option<Uuid>,
    pub scopes: Vec<String>,
}

// ─── JWT claims ────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String,          // user_id
    pub tenant_id: String,
    pub scopes: Vec<String>,
    pub exp: i64,
    pub iat: i64,
}

// ─── Constants ─────────────────────────────────────────────────

// SEC-008 FIX: Reduced from 60s to 10s for better security/performance tradeoff
// Revoked API keys will be invalid within 10 seconds instead of 60
const API_KEY_CACHE_TTL: u64 = 10; // seconds
const TOKEN_BLACKLIST_PREFIX: &str = "apexmail:token_blacklist:";
const API_KEY_CACHE_PREFIX: &str = "apexmail:api_key_cache:";
// SEC-008: Prefix for marking revoked API keys (short TTL marker)
const API_KEY_REVOKED_PREFIX: &str = "apexmail:api_key_revoked:";

// ─── Extractor ─────────────────────────────────────────────────

#[axum::async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let headers = &parts.headers;

        // 1. Try X-API-Key header first
        if let Some(api_key) = headers
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
        {
            return authenticate_api_key(api_key, state).await;
        }

        // 2. Fall back to Bearer JWT
        if let Some(auth_header) = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
        {
            if let Some(token) = auth_header.strip_prefix("Bearer ") {
                return authenticate_jwt(token.trim(), state).await;
            }
        }

        Err(ApiError::Unauthorized(
            "missing authentication: provide X-API-Key or Authorization: Bearer <token>".into(),
        ))
    }
}

// ─── API Key authentication ────────────────────────────────────

async fn authenticate_api_key(key: &str, state: &AppState) -> Result<AuthUser, ApiError> {
    // Fix #10: Use HMAC-SHA256 with the configured secret instead of plain SHA-256.
    // This prevents offline brute-force if the database is compromised.
    let key_hash = apexmail_lib::hash_api_key_with_secret(key, &state.config.api_key_hash_secret);

    // Check Redis cache first
    if let Ok(cached) = lookup_cached_api_key(&key_hash, state).await {
        return Ok(cached);
    }

    // DB look-up (try HMAC hash first, fall back to legacy SHA-256 for migration)
    let row = sqlx::query_as::<_, ApiKeyRow>(
        "SELECT id, tenant_id, scopes, expires_at FROM api_keys WHERE key_hash = $1",
    )
    .bind(&key_hash)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "api key lookup failed");
        ApiError::Internal("authentication error".into())
    })?;

    // Fall back to legacy SHA-256 hash for keys created before migration
    let row = match row {
        Some(r) => r,
        None => {
            let legacy_hash = apexmail_lib::hash_api_key(key);
            sqlx::query_as::<_, ApiKeyRow>(
                "SELECT id, tenant_id, scopes, expires_at FROM api_keys WHERE key_hash = $1",
            )
            .bind(&legacy_hash)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "api key lookup failed (legacy)");
                ApiError::Internal("authentication error".into())
            })?
            .ok_or_else(|| ApiError::Unauthorized("invalid API key".into()))?
        }
    };

    // Check expiry
    if let Some(exp) = row.expires_at {
        if exp < Utc::now() {
            return Err(ApiError::Unauthorized("API key expired".into()));
        }
    }

    // Fix #13: Proper error for scope deserialization.
    let scopes: Vec<String> = serde_json::from_value(row.scopes.clone()).map_err(|e| {
        tracing::warn!(error = %e, api_key_id = %row.id, "malformed scopes in api_keys table");
        ApiError::Internal("invalid API key scopes configuration".into())
    })?;

    let auth_user = AuthUser {
        tenant_id: row.tenant_id,
        user_id: None,
        api_key_id: Some(row.id),
        scopes,
    };

    // Cache in Redis (fire-and-forget)
    cache_api_key(&key_hash, &auth_user, state).await;

    // Update last_used_at (fire-and-forget)
    let db = state.db.clone();
    let id = row.id;
    tokio::spawn(async move {
        let _ = sqlx::query("UPDATE api_keys SET last_used_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(&db)
            .await;
    });

    Ok(auth_user)
}

#[derive(Debug, sqlx::FromRow)]
struct ApiKeyRow {
    id: Uuid,
    tenant_id: Uuid,
    scopes: serde_json::Value,
    expires_at: Option<DateTime<Utc>>,
}

async fn lookup_cached_api_key(key_hash: &str, state: &AppState) -> Result<AuthUser, ()> {
    let cache_key = format!("{API_KEY_CACHE_PREFIX}{key_hash}");
    let mut conn = state.redis.get().await.map_err(|_| ())?;
    let cached: Option<String> = conn.get(&cache_key).await.map_err(|_| ())?;
    match cached {
        Some(json) => serde_json::from_str(&json).map_err(|_| ()),
        None => Err(()),
    }
}

async fn cache_api_key(key_hash: &str, user: &AuthUser, state: &AppState) {
    let cache_key = format!("{API_KEY_CACHE_PREFIX}{key_hash}");
    if let Ok(json) = serde_json::to_string(user) {
        if let Ok(mut conn) = state.redis.get().await {
            let _: Result<(), _> = conn.set_ex(&cache_key, &json, API_KEY_CACHE_TTL).await;
        }
    }
}

// ─── JWT authentication ────────────────────────────────────────

async fn authenticate_jwt(token: &str, state: &AppState) -> Result<AuthUser, ApiError> {
    // Check token blacklist
    // Fix #11: fail-closed — if Redis is down in production, reject the token.
    if is_token_blacklisted(token, state).await? {
        return Err(ApiError::Unauthorized("token has been revoked".into()));
    }

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_required_spec_claims(&["exp", "sub", "tenant_id"]);

    let key = DecodingKey::from_rsa_pem(state.config.jwt_public_key_pem.as_bytes())
        .map_err(|e| ApiError::Internal(format!("invalid JWT public key configuration: {e}")))?;
    let token_data = decode::<JwtClaims>(token, &key, &validation)?;

    let claims = token_data.claims;

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| ApiError::Unauthorized("invalid user ID in token".into()))?;
    let tenant_id = Uuid::parse_str(&claims.tenant_id)
        .map_err(|_| ApiError::Unauthorized("invalid tenant ID in token".into()))?;

    // Fix #12: Verify the user still exists and is active in the database.
    let user_active: Option<(String,)> = sqlx::query_as(
        "SELECT status FROM users WHERE id = $1 AND tenant_id = $2",
    )
    .bind(user_id)
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "user existence check failed");
        ApiError::Internal("authentication error".into())
    })?;

    match user_active {
        None => return Err(ApiError::Unauthorized("user no longer exists".into())),
        Some((status,)) if status != "active" => {
            return Err(ApiError::Unauthorized(
                format!("user account is {status}"),
            ));
        }
        _ => {}
    }

    Ok(AuthUser {
        tenant_id,
        user_id: Some(user_id),
        api_key_id: None,
        scopes: claims.scopes,
    })
}

/// Check if a JWT has been blacklisted (revoked).
///
/// Fix #11: Returns `Err` when Redis is unreachable so the caller can fail-closed.
async fn is_token_blacklisted(token: &str, state: &AppState) -> Result<bool, ApiError> {
    use sha2::{Sha256, Digest};
    let hash = hex::encode(Sha256::digest(token.as_bytes()));
    let key = format!("{TOKEN_BLACKLIST_PREFIX}{hash}");
    let mut conn = state.redis.get().await.map_err(|e| {
        tracing::error!(error = %e, "Redis unavailable for token blacklist check");
        ApiError::ServiceUnavailable("authentication service temporarily unavailable".into())
    })?;
    let exists: bool = conn.exists(&key).await.map_err(|e| {
        tracing::error!(error = %e, "Redis EXISTS failed for token blacklist");
        ApiError::ServiceUnavailable("authentication service temporarily unavailable".into())
    })?;
    Ok(exists)
}

// ─── Auth middleware (used by app.rs via from_fn_with_state) ───

/// Middleware that rejects unauthenticated requests before they hit the route handler.
///
/// Extracts `AuthUser` via the `FromRequestParts` impl above, then inserts
/// the identity into request extensions so downstream handlers can retrieve
/// it cheaply with `Extension<AuthUser>`.
pub async fn require_auth(
    axum::extract::State(state): axum::extract::State<AppState>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, ApiError> {
    // Extract the auth user from the request parts.
    let (mut parts, body) = req.into_parts();
    let auth_user = AuthUser::from_request_parts(&mut parts, &state).await?;

    // Insert the authenticated identity into extensions for downstream use.
    parts.extensions.insert(auth_user);

    req = axum::http::Request::from_parts(parts, body);
    Ok(next.run(req).await)
}

// ─── Scope guard extractor ─────────────────────────────────────

/// Helper to check scopes after extracting AuthUser manually.
pub fn require_scopes(user: &AuthUser, required: &[&str]) -> Result<(), ApiError> {
    // Wildcard scope
    if user.scopes.iter().any(|s| s == "*") {
        return Ok(());
    }
    for scope in required {
        if !user.scopes.iter().any(|s| s == scope) {
            return Err(ApiError::Forbidden(format!(
                "missing required scope: {scope}"
            )));
        }
    }
    Ok(())
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_hashing() {
        let hash = hex::encode(Sha256::digest(b"am_live_abc123"));
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_require_scopes_wildcard() {
        let user = AuthUser {
            tenant_id: Uuid::new_v4(),
            user_id: Some(Uuid::new_v4()),
            api_key_id: None,
            scopes: vec!["*".into()],
        };
        assert!(require_scopes(&user, &["messages:send", "domains:read"]).is_ok());
    }

    #[test]
    fn test_require_scopes_missing() {
        let user = AuthUser {
            tenant_id: Uuid::new_v4(),
            user_id: None,
            api_key_id: Some(Uuid::new_v4()),
            scopes: vec!["messages:read".into()],
        };
        assert!(require_scopes(&user, &["messages:send"]).is_err());
    }

    #[test]
    fn test_require_scopes_present() {
        let user = AuthUser {
            tenant_id: Uuid::new_v4(),
            user_id: None,
            api_key_id: Some(Uuid::new_v4()),
            scopes: vec!["messages:send".into(), "messages:read".into()],
        };
        assert!(require_scopes(&user, &["messages:send"]).is_ok());
    }

    #[test]
    fn test_jwt_claims_roundtrip() {
        let claims = JwtClaims {
            sub: Uuid::new_v4().to_string(),
            tenant_id: Uuid::new_v4().to_string(),
            scopes: vec!["messages:send".into()],
            exp: 9999999999,
            iat: 1000000000,
        };
        let json = serde_json::to_string(&claims).unwrap();
        let decoded: JwtClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.scopes, claims.scopes);
    }
}
