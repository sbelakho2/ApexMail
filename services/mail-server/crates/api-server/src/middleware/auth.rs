//! Authentication extractors for Axum.
//!
//! Supports three authentication methods:
//! 1. **API Key** — `X-API-Key` header, SHA-256 hashed, DB lookup (Redis-cached 60 s).
//! 2. **JWT Bearer** — `Authorization: Bearer <token>`, RS256, extracts claims.
//! 3. **Session Cookie** — `am_session` cookie, RS256, with CSRF checks on unsafe methods.

use axum::extract::FromRequestParts;
use axum::http::{HeaderMap, Method};
use axum::http::request::Parts;
use chrono::{DateTime, Utc};
use deadpool_redis::redis::{self, AsyncCommands};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::routes::{csrf::validate_csrf_token, helpers::extract_cookie};
use crate::state::AppState;

// ─── AuthUser ──────────────────────────────────────────────────

/// Authenticated identity extracted from the request.
/// IDs are stored as strings (VARCHAR(26) in the database).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    pub tenant_id: String,
    pub user_id: Option<String>,
    pub api_key_id: Option<String>,
    pub scopes: Vec<String>,
}

// ─── JWT claims ────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String, // user_id
    pub tenant_id: String,
    pub scopes: Vec<String>,
    pub exp: i64,
    pub iat: i64,
}

// ─── Constants ─────────────────────────────────────────────────

// Revoked API keys will be invalid within 10 seconds instead of 60
const API_KEY_CACHE_TTL: u64 = 10; // seconds
const TOKEN_BLACKLIST_PREFIX: &str = "apexmail:token_blacklist:";
const API_KEY_CACHE_PREFIX: &str = "apexmail:api_key_cache:";
const USER_STATUS_CACHE_TTL: u64 = 15; // seconds
const USER_STATUS_CACHE_PREFIX: &str = "apexmail:user_status:";
const USER_STATUS_CACHE_MISSING: &str = "__missing__";
const SESSION_COOKIE_NAME: &str = "am_session";
const CSRF_COOKIE_NAME: &str = "csrf_token";
const CSRF_HEADER_NAME: &str = "x-csrf-token";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthMechanism {
    ApiKey,
    BearerToken,
    SessionCookie,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CachedUserStatus {
    Missing,
    Present(String),
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

fn extract_auth_credential(headers: &HeaderMap) -> Option<(AuthMechanism, String)> {
    if let Some(api_key) = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some((AuthMechanism::ApiKey, api_key.to_string()));
    }

    if let Some(token) = extract_bearer_token(headers) {
        return Some((AuthMechanism::BearerToken, token));
    }

    extract_cookie(headers, SESSION_COOKIE_NAME)
        .filter(|token| !token.is_empty())
        .map(|token| (AuthMechanism::SessionCookie, token))
}

fn requires_csrf(method: &Method, mechanism: AuthMechanism) -> bool {
    mechanism == AuthMechanism::SessionCookie
        && !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE)
}

pub(crate) fn validate_session_csrf(headers: &HeaderMap, csrf_secret: &str) -> Result<(), ApiError> {
    let cookie_token = extract_cookie(headers, CSRF_COOKIE_NAME)
        .ok_or_else(|| ApiError::Forbidden("missing CSRF cookie".into()))?;
    let header_token = headers
        .get(CSRF_HEADER_NAME)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::Forbidden("missing X-CSRF-Token header".into()))?;

    if header_token != cookie_token {
        return Err(ApiError::Forbidden("CSRF token mismatch".into()));
    }

    validate_csrf_token(header_token, csrf_secret)
}

// ─── Extractor ─────────────────────────────────────────────────

#[axum::async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let headers = &parts.headers;
        let Some((mechanism, credential)) = extract_auth_credential(headers) else {
            return Err(ApiError::Unauthorized(
                "missing authentication: provide X-API-Key, Authorization: Bearer <token>, or an am_session cookie".into(),
            ));
        };

        if requires_csrf(&parts.method, mechanism) {
            validate_session_csrf(headers, &state.config.csrf_secret)?;
        }

        match mechanism {
            AuthMechanism::ApiKey => authenticate_api_key(&credential, state).await,
            AuthMechanism::BearerToken | AuthMechanism::SessionCookie => {
                authenticate_jwt(&credential, state).await
            }
        }
    }
}

// ─── API Key authentication ────────────────────────────────────

async fn authenticate_api_key(key: &str, state: &AppState) -> Result<AuthUser, ApiError> {
// ── Control-plane static key (no DB lookup) ────────────
    if let Some(ref cp_key) = state.config.control_plane_api_key {
        if apexmail_lib::timing_safe_compare(cp_key, key) {
            tracing::debug!("authenticated via control-plane static API key");
            return Ok(AuthUser {
                tenant_id: "system".into(), // sentinel:system-level admin
                user_id: None,
                api_key_id: None,
                scopes: vec!["*".into()],
            });
        }
    }

// This prevents offline brute-force if the database is compromised.
    let key_hash = apexmail_lib::hash_api_key_with_secret(key, &state.config.api_key_hash_secret);
    let legacy_hash = apexmail_lib::hash_api_key(key);

// Check Redis cache first
    if let Ok(cached) = lookup_cached_api_key(&key_hash, state).await {
        if let Some(api_key_id) = cached.api_key_id.as_deref() {
            touch_api_key_last_used(api_key_id, &key_hash, state).await?;
        }
        return Ok(cached);
    }

    if legacy_hash != key_hash {
        if let Ok(cached) = lookup_cached_api_key(&legacy_hash, state).await {
            if let Some(api_key_id) = cached.api_key_id.as_deref() {
                touch_api_key_last_used(api_key_id, &legacy_hash, state).await?;
            }
            return Ok(cached);
        }
    }

// DB look-up (try HMAC hash first, fall back to legacy SHA-256 for migration)
    let row = sqlx::query_as::<_, ApiKeyRow>(
        "SELECT id, tenant_id, key_hash, scopes, expires_at FROM api_keys WHERE key_hash = $1",
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
            sqlx::query_as::<_, ApiKeyRow>(
                "SELECT id, tenant_id, key_hash, scopes, expires_at FROM api_keys WHERE key_hash = $1",
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

    let scopes: Vec<String> = serde_json::from_value(row.scopes.clone()).map_err(|e| {
        tracing::warn!(error = %e, api_key_id = %row.id, "malformed scopes in api_keys table");
        ApiError::Internal("invalid API key scopes configuration".into())
    })?;

    let auth_user = AuthUser {
        tenant_id: row.tenant_id.clone(),
        user_id: None,
        api_key_id: Some(row.id.clone()),
        scopes,
    };

// Cache in Redis (fire-and-forget)
    cache_api_key(&row.key_hash, &auth_user, state).await;

    touch_api_key_last_used(&row.id, &row.key_hash, state).await?;

    Ok(auth_user)
}

#[derive(Debug, sqlx::FromRow)]
struct ApiKeyRow {
    id: String,
    tenant_id: String,
    key_hash: String,
    scopes: serde_json::Value,
    expires_at: Option<DateTime<Utc>>,
}

async fn touch_api_key_last_used(
    api_key_id: &str,
    key_hash: &str,
    state: &AppState,
) -> Result<(), ApiError> {
    let result = sqlx::query("UPDATE api_keys SET last_used_at = NOW() WHERE id = $1")
        .bind(api_key_id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, api_key_id, "failed to update API key last_used_at");
            ApiError::Internal("authentication error".into())
        })?;

    if result.rows_affected() == 0 {
        tracing::warn!(api_key_id, "api key disappeared during last_used_at update; evicting cache entry");
        invalidate_api_key_cache(key_hash, state).await;
        return Err(ApiError::Unauthorized("invalid API key".into()));
    }

    Ok(())
}

async fn lookup_cached_api_key(key_hash: &str, state: &AppState) -> Result<AuthUser, ()> {
    let cache_key = format!("{API_KEY_CACHE_PREFIX}{key_hash}");
    let mut conn = state.redis.get().await.map_err(|e| {
        tracing::warn!(error = %e, "redis pool error in API key cache lookup");
    })?;
    let cached: Option<String> = conn.get(&cache_key).await.map_err(|e| {
        tracing::warn!(error = %e, "redis GET error in API key cache lookup");
    })?;
    match cached {
        Some(json) => serde_json::from_str(&json).map_err(|e| {
            tracing::warn!(error = %e, cache_key, "corrupted JSON in API key cache — evicting");
// Best-effort eviction of poisoned cache entry
            tokio::spawn({
                let pool = state.redis.clone();
                let key = cache_key.clone();
                async move {
                    if let Ok(mut conn) = pool.get().await {
                        let _: Result<(), _> = redis::AsyncCommands::del(&mut *conn, &key).await;
                    }
                }
            });
        }),
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

pub(crate) async fn invalidate_api_key_cache(key_hash: &str, state: &AppState) {
    let cache_key = format!("{API_KEY_CACHE_PREFIX}{key_hash}");
    if let Ok(mut conn) = state.redis.get().await {
        let _: Result<(), _> = redis::AsyncCommands::del(&mut *conn, &cache_key).await;
    }
}

fn user_status_cache_key(tenant_id: &str, user_id: &str) -> String {
    format!("{USER_STATUS_CACHE_PREFIX}{tenant_id}:{user_id}")
}

fn parse_cached_user_status(value: &str) -> CachedUserStatus {
    if value == USER_STATUS_CACHE_MISSING {
        CachedUserStatus::Missing
    } else {
        CachedUserStatus::Present(value.to_owned())
    }
}

async fn lookup_cached_user_status(
    tenant_id: &str,
    user_id: &str,
    state: &AppState,
) -> Result<Option<CachedUserStatus>, ()> {
    let cache_key = user_status_cache_key(tenant_id, user_id);
    let mut conn = state.redis.get().await.map_err(|e| {
        tracing::warn!(error = %e, tenant_id, user_id, "redis pool error in user status cache lookup");
    })?;
    let cached: Option<String> = conn.get(&cache_key).await.map_err(|e| {
        tracing::warn!(error = %e, tenant_id, user_id, "redis GET error in user status cache lookup");
    })?;
    Ok(cached.as_deref().map(parse_cached_user_status))
}

async fn cache_user_status(
    tenant_id: &str,
    user_id: &str,
    status: Option<&str>,
    state: &AppState,
) {
    let cache_key = user_status_cache_key(tenant_id, user_id);
    let cached_value = status.unwrap_or(USER_STATUS_CACHE_MISSING);
    if let Ok(mut conn) = state.redis.get().await {
        let _: Result<(), _> = conn.set_ex(&cache_key, cached_value, USER_STATUS_CACHE_TTL).await;
    }
}

pub(crate) async fn invalidate_user_status_cache(user_id: &str, tenant_id: &str, state: &AppState) {
    let cache_key = user_status_cache_key(tenant_id, user_id);
    if let Ok(mut conn) = state.redis.get().await {
        let _: Result<(), _> = redis::AsyncCommands::del(&mut *conn, &cache_key).await;
    }
}

pub(crate) async fn invalidate_tenant_user_status_cache(tenant_id: &str, state: &AppState) {
    let pattern = format!("{USER_STATUS_CACHE_PREFIX}{tenant_id}:*");
    let Ok(mut conn) = state.redis.get().await else {
        return;
    };

    let mut cursor: u64 = 0;
    let mut cache_keys: Vec<String> = Vec::new();
    loop {
        let scan_result: Result<(u64, Vec<String>), _> = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(&pattern)
            .arg("COUNT")
            .arg(100u64)
            .query_async(&mut *conn)
            .await;

        let Ok((next_cursor, batch)) = scan_result else {
            break;
        };

        cache_keys.extend(batch);
        cursor = next_cursor;
        if cursor == 0 {
            break;
        }
    }

    if !cache_keys.is_empty() {
        let _: Result<u64, _> = redis::cmd("DEL").arg(&cache_keys).query_async(&mut *conn).await;
    }
}

// ─── JWT authentication ────────────────────────────────────────

async fn authenticate_jwt(token: &str, state: &AppState) -> Result<AuthUser, ApiError> {
// Check token blacklist
    if is_token_blacklisted(token, state).await? {
        return Err(ApiError::Unauthorized("token has been revoked".into()));
    }

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_required_spec_claims(&["exp", "sub", "tenant_id"]);

    let key = DecodingKey::from_rsa_pem(state.config.jwt_public_key_pem.as_bytes())
        .map_err(|e| ApiError::Internal(format!("invalid JWT public key configuration: {e}")))?;
    let token_data = decode::<JwtClaims>(token, &key, &validation)?;

    let claims = token_data.claims;

    let user_id = claims.sub.clone();
    let tenant_id = claims.tenant_id.clone();

    if user_id.is_empty() {
        return Err(ApiError::Unauthorized("missing user ID in token".into()));
    }
    if tenant_id.is_empty() {
        return Err(ApiError::Unauthorized("missing tenant ID in token".into()));
    }

    let user_status = match lookup_cached_user_status(&tenant_id, &user_id, state).await {
        Ok(Some(CachedUserStatus::Missing)) => {
            return Err(ApiError::Unauthorized("user no longer exists".into()));
        }
        Ok(Some(CachedUserStatus::Present(status))) => status,
        _ => {
            let user_status: Option<(String,)> = sqlx::query_as(
                "SELECT status FROM users WHERE id = $1 AND tenant_id = $2",
            )
            .bind(&user_id)
            .bind(&tenant_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "user existence check failed");
                ApiError::Internal("authentication error".into())
            })?;

            match user_status {
                None => {
                    cache_user_status(&tenant_id, &user_id, None, state).await;
                    return Err(ApiError::Unauthorized("user no longer exists".into()));
                }
                Some((status,)) => {
                    cache_user_status(&tenant_id, &user_id, Some(&status), state).await;
                    status
                }
            }
        }
    };

    if user_status != "active" {
        return Err(ApiError::Unauthorized(
            format!("user account is {user_status}"),
        ));
    }

    Ok(AuthUser {
        tenant_id,
        user_id: Some(user_id),
        api_key_id: None,
        scopes: claims.scopes,
    })
}

/// Check if a JWT has been blacklisted (revoked).
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
    use sha2::{Digest, Sha256};

    #[test]
    fn test_api_key_hashing() {
        let hash = hex::encode(Sha256::digest(b"am_live_abc123"));
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_require_scopes_wildcard() {
        let user = AuthUser {
            tenant_id: "ten_test_001".into(),
            user_id: Some("usr_test_001".into()),
            api_key_id: None,
            scopes: vec!["*".into()],
        };
        assert!(require_scopes(&user, &["messages:send", "domains:read"]).is_ok());
    }

    #[test]
    fn test_require_scopes_missing() {
        let user = AuthUser {
            tenant_id: "ten_test_001".into(),
            user_id: None,
            api_key_id: Some("key_test_001".into()),
            scopes: vec!["messages:read".into()],
        };
        assert!(require_scopes(&user, &["messages:send"]).is_err());
    }

    #[test]
    fn test_require_scopes_present() {
        let user = AuthUser {
            tenant_id: "ten_test_001".into(),
            user_id: None,
            api_key_id: Some("key_test_001".into()),
            scopes: vec!["messages:send".into(), "messages:read".into()],
        };
        assert!(require_scopes(&user, &["messages:send"]).is_ok());
    }

    #[test]
    fn test_jwt_claims_roundtrip() {
        let claims = JwtClaims {
            sub: "usr_test_roundtrip_001".into(),
            tenant_id: "ten_test_roundtrip_001".into(),
            scopes: vec!["messages:send".into()],
            exp: 9999999999,
            iat: 1000000000,
        };
        let json = serde_json::to_string(&claims).unwrap();
        let decoded: JwtClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.scopes, claims.scopes);
    }

    #[test]
    fn test_extract_auth_credential_prefers_api_key() {
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "key_123".parse().unwrap());
        headers.insert("authorization", "Bearer jwt.123".parse().unwrap());
        headers.insert("cookie", "am_session=session.jwt".parse().unwrap());

        assert_eq!(
            extract_auth_credential(&headers),
            Some((AuthMechanism::ApiKey, "key_123".into()))
        );
    }

    #[test]
    fn test_extract_auth_credential_accepts_session_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", "other=1; am_session=session.jwt".parse().unwrap());

        assert_eq!(
            extract_auth_credential(&headers),
            Some((AuthMechanism::SessionCookie, "session.jwt".into()))
        );
    }

    #[test]
    fn test_validate_session_csrf_requires_matching_cookie_and_header() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let secret = "test-csrf-secret-1234567890abcd";
        let nonce = format!("{}:{}", Utc::now().timestamp_millis(), uuid::Uuid::new_v4());
        let nonce_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            nonce.as_bytes(),
        );

        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(nonce.as_bytes());
        let sig = mac.finalize().into_bytes();
        let sig_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &sig,
        );
        let token = format!("{nonce_b64}.{sig_b64}");

        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            format!("am_session=session.jwt; csrf_token={token}").parse().unwrap(),
        );
        headers.insert(CSRF_HEADER_NAME, token.parse().unwrap());

        assert!(validate_session_csrf(&headers, secret).is_ok());

        headers.insert(CSRF_HEADER_NAME, "different-token".parse().unwrap());
        assert!(matches!(
            validate_session_csrf(&headers, secret),
            Err(ApiError::Forbidden(message)) if message == "CSRF token mismatch"
        ));
    }

// ── RBAC Security Regression Tests ─────────────────────────

    #[test]
    fn test_require_scopes_empty_scopes_denies_all() {
        let user = AuthUser {
            tenant_id: "ten_test_001".into(),
            user_id: Some("usr_test_001".into()),
            api_key_id: None,
            scopes: vec![],
        };
        assert!(require_scopes(&user, &["messages:read"]).is_err(),
            "empty scopes must deny access");
    }

    #[test]
    fn test_require_scopes_partial_match_denies() {
        let user = AuthUser {
            tenant_id: "ten_test_001".into(),
            user_id: None,
            api_key_id: Some("key_test_001".into()),
            scopes: vec!["messages:read".into()],
        };
// Requires both scopes, user only has one
        assert!(require_scopes(&user, &["messages:read", "messages:send"]).is_err(),
            "partial scope match must deny access");
    }

    #[test]
    fn test_require_scopes_similar_name_no_match() {
        let user = AuthUser {
            tenant_id: "ten_test_001".into(),
            user_id: None,
            api_key_id: Some("key_test_001".into()),
            scopes: vec!["messages:read_all".into()],
        };
// "messages:read_all" must NOT match "messages:read"
        assert!(require_scopes(&user, &["messages:read"]).is_err(),
            "similar scope name must not match");
    }

    #[test]
    fn test_require_scopes_wildcard_grants_everything() {
        let user = AuthUser {
            tenant_id: "ten_test_001".into(),
            user_id: Some("usr_test_001".into()),
            api_key_id: None,
            scopes: vec!["*".into()],
        };
// Wildcard should grant any scope
        assert!(require_scopes(&user, &["scim:write", "admin:delete", "billing:manage"]).is_ok());
    }

    #[test]
    fn test_require_scopes_no_requirements_passes() {
        let user = AuthUser {
            tenant_id: "ten_test_001".into(),
            user_id: Some("usr_test_001".into()),
            api_key_id: None,
            scopes: vec![],
        };
// Empty required scopes should pass
        assert!(require_scopes(&user, &[]).is_ok());
    }

    #[test]
    fn test_viewer_role_scopes_cannot_send_messages() {
// Viewer role should not have messages:send scope
        let viewer = AuthUser {
            tenant_id: "ten_test_001".into(),
            user_id: Some("usr_test_001".into()),
            api_key_id: None,
            scopes: vec![
                "messages:read".into(),
                "domains:read".into(),
                "templates:read".into(),
                "events:read".into(),
                "analytics:read".into(),
                "contacts:read".into(),
            ],
        };
        assert!(require_scopes(&viewer, &["messages:send"]).is_err(),
            "viewer must not be able to send messages");
        assert!(require_scopes(&viewer, &["domains:write"]).is_err(),
            "viewer must not be able to modify domains");
        assert!(require_scopes(&viewer, &["templates:write"]).is_err(),
            "viewer must not be able to modify templates");
    }

    #[test]
    fn test_developer_role_scopes_cannot_manage_webhooks() {
// Developer role should lack webhook/campaign/automation scopes
        let developer = AuthUser {
            tenant_id: "ten_test_001".into(),
            user_id: Some("usr_test_001".into()),
            api_key_id: None,
            scopes: vec![
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
        };
        assert!(require_scopes(&developer, &["webhooks:write"]).is_err(),
            "developer must not be able to manage webhooks");
        assert!(require_scopes(&developer, &["campaigns:write"]).is_err(),
            "developer must not be able to manage campaigns");
    }

    #[test]
    fn test_auth_user_serialization_roundtrip() {
        let user = AuthUser {
            tenant_id: "ten_test_001".into(),
            user_id: Some("usr_test_001".into()),
            api_key_id: None,
            scopes: vec!["messages:send".into(), "messages:read".into()],
        };
        let json = serde_json::to_string(&user).unwrap();
        let decoded: AuthUser = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.tenant_id, user.tenant_id);
        assert_eq!(decoded.scopes, user.scopes);
    }

    #[test]
    fn test_auth_user_api_key_has_no_user_id() {
        let user = AuthUser {
            tenant_id: "ten_test_001".into(),
            user_id: None,
            api_key_id: Some("key_test_001".into()),
            scopes: vec!["messages:send".into()],
        };
        assert!(user.user_id.is_none(), "API key auth must not have user_id");
        assert!(user.api_key_id.is_some(), "API key auth must have api_key_id");
    }

    #[test]
    fn test_user_status_cache_key_is_scoped_by_tenant_and_user() {
        assert_eq!(
            user_status_cache_key("ten_test_001", "usr_test_001"),
            "apexmail:user_status:ten_test_001:usr_test_001"
        );
    }

    #[test]
    fn test_parse_cached_user_status_handles_missing_sentinel() {
        assert_eq!(parse_cached_user_status(USER_STATUS_CACHE_MISSING), CachedUserStatus::Missing);
        assert_eq!(
            parse_cached_user_status("active"),
            CachedUserStatus::Present("active".into())
        );
    }
}
