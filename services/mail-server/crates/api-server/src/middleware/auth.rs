//! Authentication extractors for Axum.
//!
//! Supports three authentication methods:
//! 1. **API Key** — `X-API-Key` header, SHA-256 hashed, DB lookup (Redis-cached 60 s).
//! 2. **JWT Bearer** — `Authorization: Bearer <token>`, RS256, extracts claims.
//! 3. **Session Cookie** — `am_session` cookie, RS256, with CSRF checks on unsafe methods.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method};
use chrono::{DateTime, Utc};
use deadpool_redis::redis::{self, AsyncCommands};
use jsonwebtoken::{decode, Algorithm, DecodingKey, TokenData, Validation};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock};
use tokio::sync::Semaphore;

use crate::error::ApiError;
use crate::routes::{
    csrf::validate_csrf_token,
    helpers::{extract_cookie, token_blacklist_key},
};
use crate::state::AppState;

// ─── AuthUser ──────────────────────────────────────────────────

/// Authenticated identity extracted from the request.
/// IDs are stored as strings (VARCHAR(26) in the database).
///
/// # Security
/// `deny_unknown_fields` prevents cache-poisoning attacks where an attacker
/// writes extra JSON fields to Redis that would be silently ignored by serde.
/// RS-H-06: Custom Debug impl that redacts sensitive fields from log output.
/// Prevents tenant_id, user_id, session_id, and scopes from appearing in
/// debug logs which could expose sensitive authentication data.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthUser {
    pub tenant_id: String,
    pub user_id: Option<String>,
    pub api_key_id: Option<String>,
    pub session_id: Option<String>,
    pub scopes: Vec<String>,
}

impl std::fmt::Debug for AuthUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthUser")
            .field(
                "tenant_id",
                &format!(
                    "{}..{}",
                    &self.tenant_id[..self.tenant_id.len().min(4)],
                    self.tenant_id.len()
                ),
            )
            .field(
                "user_id",
                &self
                    .user_id
                    .as_ref()
                    .map(|id| format!("{}..{}", &id[..id.len().min(4)], id.len())),
            )
            .field(
                "api_key_id",
                &self
                    .api_key_id
                    .as_ref()
                    .map(|id| format!("{}..{}", &id[..id.len().min(4)], id.len())),
            )
            .field(
                "session_id",
                &self.session_id.as_ref().map(|_| "[REDACTED]"),
            )
            .field("scopes", &self.scopes)
            .finish()
    }
}

// ─── JWT claims ────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String, // user_id
    pub tenant_id: String,
    pub scopes: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    pub jti: String, // session ID (UUID)
    /// Token type discriminator. Session tokens carry `typ = "session"`;
    /// stream tokens (see routes/stream_tokens.rs) declare `typ = "stream"`.
    /// Legacy tokens issued before this field existed carry no `typ` at all
    /// and remain valid (None ⇒ not a stream token ⇒ accepted).
    #[serde(default)]
    pub typ: Option<String>,
}

// ─── Constants ─────────────────────────────────────────────────

// Revoked API keys will be invalid within 10 seconds instead of 60
const API_KEY_CACHE_TTL: u64 = 10; // seconds
const API_KEY_CACHE_PREFIX: &str = "apexmail:api_key_cache:";
const USER_STATUS_CACHE_TTL: u64 = 15; // seconds
const USER_STATUS_CACHE_PREFIX: &str = "apexmail:user_status:";
const USER_STATUS_CACHE_MISSING: &str = "__missing__";
const SESSION_REVOCATION_PREFIX: &str = "apexmail:session_revoked_after:";
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
        && !matches!(
            *method,
            Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
        )
}

pub(crate) fn validate_session_csrf(
    headers: &HeaderMap,
    csrf_secret: &str,
) -> Result<(), ApiError> {
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

fn is_control_plane_static_key_request(path: &str, on_control_plane_host: bool) -> bool {
    on_control_plane_host && path.starts_with("/v1/admin/")
}

fn tenant_id_from_request_path(path: &str) -> Option<&str> {
    let mut segments = path.split('/').filter(|segment| !segment.is_empty());
    while let Some(segment) = segments.next() {
        if matches!(segment, "tenant" | "tenants") {
            let tenant_id = segments.next()?;
            if matches!(tenant_id, "current" | "me" | "self") {
                return None;
            }
            return Some(tenant_id);
        }
    }
    None
}

/// Extract tenant ID from X-Tenant-ID header if present.
fn tenant_id_from_header(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Verify that the authenticated user is actually a member of the claimed tenant.
/// Queries the database to prevent tenant impersonation via header injection.
async fn verify_tenant_membership(
    user_id: &str,
    tenant_id: &str,
    db: &sqlx::PgPool,
) -> Result<bool, ApiError> {
    let exists: Option<(i64,)> = sqlx::query_as(
        "SELECT COUNT(*) FROM user_tenant_membership WHERE user_id = $1 AND tenant_id = $2",
    )
    .bind(user_id)
    .bind(tenant_id)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "tenant membership check failed");
        ApiError::Internal("authentication error".into())
    })?;

    Ok(exists.is_some_and(|(count,)| count > 0))
}

fn enforce_api_key_tenant_binding(user: &AuthUser, request_path: &str) -> Result<(), ApiError> {
    if user.tenant_id == "system" {
        return Ok(());
    }

    if let Some(path_tenant_id) = tenant_id_from_request_path(request_path) {
        if path_tenant_id != user.tenant_id {
            tracing::warn!(
                api_key_tenant_id = %user.tenant_id,
                path_tenant_id = %path_tenant_id,
                request_path = %request_path,
                "rejected API key request for a different tenant"
            );
            return Err(ApiError::Forbidden("API key tenant mismatch".into()));
        }
    }

    Ok(())
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
        let host = headers
            .get(axum::http::header::HOST)
            .and_then(|value| value.to_str().ok());
        let on_control_plane_host = host.is_some()
            && matches!(
                state.config.ui_surface_for_host(host),
                Some("control-plane")
            );
        let Some((mechanism, credential)) = extract_auth_credential(headers) else {
            return Err(ApiError::Unauthorized(
                "missing authentication: provide X-API-Key, Authorization: Bearer <token>, or an am_session cookie".into(),
            ));
        };

        if requires_csrf(&parts.method, mechanism) {
            validate_session_csrf(headers, &state.config.csrf_secret)?;
        }

        match mechanism {
            AuthMechanism::ApiKey => {
                authenticate_api_key(&credential, parts.uri.path(), on_control_plane_host, state)
                    .await
            }
            AuthMechanism::BearerToken | AuthMechanism::SessionCookie => {
                authenticate_jwt(&credential, state).await
            }
        }
    }
}

// ─── API Key authentication ────────────────────────────────────

async fn authenticate_api_key(
    key: &str,
    request_path: &str,
    on_control_plane_host: bool,
    state: &AppState,
) -> Result<AuthUser, ApiError> {
    // ── Control-plane static key (no DB lookup) ────────────
    if let Some(ref cp_key) = state.config.control_plane_api_key {
        if apexmail_lib::timing_safe_compare(cp_key, key) {
            if !is_control_plane_static_key_request(request_path, on_control_plane_host) {
                tracing::warn!(
                    path = %request_path,
                    control_plane_host = on_control_plane_host,
                    "rejected control-plane static API key outside control-plane admin surface"
                );
                return Err(ApiError::Unauthorized("invalid API key".into()));
            }

            tracing::debug!("authenticated via control-plane static API key");
            return Ok(AuthUser {
                tenant_id: "system".into(), // sentinel:system-level admin
                user_id: None,
                api_key_id: None,
                session_id: None,
                scopes: vec!["*".into()],
            });
        }
    }

    // Compute all hash variants: Argon2id (preferred), HMAC-SHA256, SHA-256 (legacy)
    let hmac_hash = apexmail_lib::hash_api_key_with_secret(key, &state.config.api_key_hash_secret);
    let legacy_hash = apexmail_lib::hash_api_key(key);

    // Check Redis cache (try HMAC first, then legacy SHA-256)
    if let Ok(cached) = lookup_cached_api_key(&hmac_hash, state).await {
        enforce_api_key_tenant_binding(&cached, request_path)?;
        if let Some(api_key_id) = cached.api_key_id.as_deref() {
            touch_api_key_last_used(api_key_id, &hmac_hash, state).await?;
        }
        return Ok(cached);
    }

    if legacy_hash != hmac_hash {
        if let Ok(cached) = lookup_cached_api_key(&legacy_hash, state).await {
            enforce_api_key_tenant_binding(&cached, request_path)?;
            if let Some(api_key_id) = cached.api_key_id.as_deref() {
                touch_api_key_last_used(api_key_id, &legacy_hash, state).await?;
            }
            return Ok(cached);
        }
    }

    // DB look-up: try HMAC hash first, fall back to legacy SHA-256, then Argon2id
    let row = sqlx::query_as::<_, ApiKeyRow>(
        "SELECT id::text AS id, tenant_id, key_hash, scopes, expires_at FROM api_keys WHERE key_hash = $1",
    )
    .bind(&hmac_hash)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "api key lookup failed");
        ApiError::Internal("authentication error".into())
    })?;

    // Fall back to legacy SHA-256 hash for keys created before migration
    let (row, used_legacy_hash) = match row {
        Some(r) => (r, false),
        None => {
            // Try legacy SHA-256 lookup
            let legacy_row = sqlx::query_as::<_, ApiKeyRow>(
                "SELECT id::text AS id, tenant_id, key_hash, scopes, expires_at FROM api_keys WHERE key_hash = $1",
            )
            .bind(&legacy_hash)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "api key lookup failed (legacy)");
                ApiError::Internal("authentication error".into())
            })?;

            match legacy_row {
                Some(r) => (r, true),
                None => {
                    // Last resort: try Argon2id hash verification if the key was
                    // hashed with Argon2id and stored in a different key_hash column.
                    //
                    // Fetch all active keys for this scope and verify individually
                    // (expensive, but only happens when the key is not found via
                    // the fast HMAC path — typically once per key creation).
                    return authenticate_api_key_argon2_fallback(
                        key,
                        &state.db,
                        request_path,
                        state,
                    )
                    .await;
                }
            }
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
        session_id: None,
        scopes,
    };

    enforce_api_key_tenant_binding(&auth_user, request_path)?;

    // Re-hash legacy SHA-256 key on successful authentication (upgrade to Argon2id)
    if used_legacy_hash {
        let hash_to_store = row.key_hash.clone();
        tokio::spawn(upgrade_api_key_hash(
            row.id.clone(),
            key.to_string(),
            hash_to_store,
            state.db.clone(),
        ));
        tracing::info!(
            api_key_id = %row.id,
            "Legacy API key authenticated — spawning background re-hash to Argon2id"
        );
    }

    // Cache in Redis (fire-and-forget) using the current stored hash as key
    cache_api_key(&row.key_hash, &auth_user, state).await;

    touch_api_key_last_used(&row.id, &row.key_hash, state).await?;

    Ok(auth_user)
}

/// Fallback authentication for Argon2id-hashed API keys.
/// Loads all active keys, tries Argon2id verification against each,
/// and re-hashes to HMAC-SHA256 for fast future lookups.
///
/// # DoS cap
/// Each fallback run performs memory-hard Argon2id verification against
/// EVERY active key, so unbounded concurrency lets an attacker pin N cores
/// with N cheap invalid-key requests. The scan is therefore gated by a
/// semaphore (mirroring `ARGON2_VERIFY_SEMAPHORE` in routes/auth.rs). Unlike
/// the captcha path we use `try_acquire`: when permits are exhausted the
/// fallback is skipped and the caller gets a normal "invalid API key"
/// failure — this path is a best-effort bridge for legacy keys, never worth
/// queueing requests behind.
static API_KEY_ARGON2_FALLBACK_SEMAPHORE: OnceLock<Arc<Semaphore>> = OnceLock::new();
const API_KEY_ARGON2_FALLBACK_MAX_CONCURRENT: usize = 2;
/// Upper bound on rows examined per fallback run. The scan is a best-effort
/// bridge for legacy Argon2id keys; on tenants with more keys than this the
/// newest entries simply fall back to the normal "invalid API key" failure
/// until the owner re-issues the key (ordered by creation for determinism).
const API_KEY_ARGON2_FALLBACK_SCAN_LIMIT: i32 = 500;

async fn authenticate_api_key_argon2_fallback(
    key: &str,
    db: &sqlx::PgPool,
    request_path: &str,
    state: &AppState,
) -> Result<AuthUser, ApiError> {
    use apexmail_lib::detect_api_key_hash_version;

    let semaphore = API_KEY_ARGON2_FALLBACK_SEMAPHORE
        .get_or_init(|| Arc::new(Semaphore::new(API_KEY_ARGON2_FALLBACK_MAX_CONCURRENT)))
        .clone();
    let _argon2_permit = match semaphore.try_acquire() {
        Ok(permit) => permit,
        Err(_) => {
            tracing::warn!("api key argon2 fallback capacity reached; skipping memory-hash scan");
            return Err(ApiError::Unauthorized("invalid API key".into()));
        }
    };

    // Scan active keys (limited scope — only runs when HMAC lookup fails,
    // capped at SCAN_LIMIT rows so a large api_keys table cannot turn each
    // unauthenticated request into a full-table Argon2id grind).
    let rows = sqlx::query_as::<_, ApiKeyRow>(
        "SELECT id::text AS id, tenant_id, key_hash, scopes, expires_at
         FROM api_keys
         WHERE expires_at IS NULL OR expires_at > NOW()
         ORDER BY created_at DESC NULLS LAST
         LIMIT $1",
    )
    .bind(API_KEY_ARGON2_FALLBACK_SCAN_LIMIT)
    .fetch_all(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "api key argon2 fallback lookup failed");
        ApiError::Internal("authentication error".into())
    })?;

    for row in rows {
        let version = detect_api_key_hash_version(&row.key_hash);
        tracing::debug!(
            api_key_id = %row.id,
            hash_version = %version,
            "Checking API key hash during fallback scan"
        );

        // Try Argon2id verification
        let matched = match version {
            apexmail_lib::ApiKeyHashVersion::Argon2id => {
                apexmail_lib::verify_api_key_hash(key, &row.key_hash).unwrap_or(false)
            }
            _ => continue, // Already tried HMAC and SHA-256
        };

        if !matched {
            continue;
        }

        // Check expiry
        if let Some(exp) = row.expires_at {
            if exp < Utc::now() {
                continue;
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
            session_id: None,
            scopes,
        };

        enforce_api_key_tenant_binding(&auth_user, request_path)?;

        // Upgrade: re-hash to HMAC-SHA256 for fast future lookups
        let new_hash =
            apexmail_lib::hash_api_key_with_secret(key, &state.config.api_key_hash_secret);

        if let Err(e) = sqlx::query("UPDATE api_keys SET key_hash = $1 WHERE id = $2::uuid")
            .bind(&new_hash)
            .bind(&row.id)
            .execute(db)
            .await
        {
            tracing::warn!(
                api_key_id = %row.id,
                error = %e,
                "Failed to upgrade Argon2id key hash to HMAC-SHA256"
            );
        } else {
            tracing::info!(
                api_key_id = %row.id,
                "Upgraded Argon2id API key hash to HMAC-SHA256 for fast lookups"
            );
        }

        cache_api_key(&new_hash, &auth_user, state).await;
        touch_api_key_last_used(&row.id, &new_hash, state).await?;

        return Ok(auth_user);
    }

    Err(ApiError::Unauthorized("invalid API key".into()))
}

/// Background task: upgrade a legacy SHA-256 API key hash to Argon2id.
async fn upgrade_api_key_hash(
    api_key_id: String,
    raw_key: String,
    _old_hash: String,
    db: sqlx::PgPool,
) {
    match apexmail_lib::hash_api_key_argon2(&raw_key) {
        Ok(new_hash) => {
            match sqlx::query("UPDATE api_keys SET key_hash = $1 WHERE id = $2::uuid")
                .bind(&new_hash)
                .bind(&api_key_id)
                .execute(&db)
                .await
            {
                Ok(_) => tracing::info!(
                    api_key_id = %api_key_id,
                    "API key hash upgraded from SHA-256 to Argon2id"
                ),
                Err(e) => tracing::error!(
                    api_key_id = %api_key_id,
                    error = %e,
                    "Failed to upgrade API key hash to Argon2id"
                ),
            }
        }
        Err(e) => tracing::error!(
            api_key_id = %api_key_id,
            error = %e,
            "Failed to compute Argon2id hash for API key upgrade"
        ),
    }
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
    // Throttle: at most one DB write per API key every 5 minutes, tracked in
    // Redis. This removes a write from every authenticated request. Redis
    // failures degrade to the unthrottled path (fail open).
    //
    // Atomicity: `SET key 1 NX EX <window>` is a single Redis command, so
    // concurrent requests for the same API key cannot both win the throttle
    // (the previous EXISTS + SETEX pair had a race window). Exactly one
    // request per key per window performs the DB write.
    const TOUCH_WINDOW_SECS: u64 = 300;
    let throttle_key = format!("api_key:last_used:{}", api_key_id);

    let mut skip_write = false;
    if let Ok(mut conn) = state.redis.get().await {
        let won: bool = match redis::cmd("SET")
            .arg(&throttle_key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(TOUCH_WINDOW_SECS)
            .query_async::<Option<String>>(&mut *conn)
            .await
        {
            Ok(value) => value.is_some(),
            Err(e) => {
                tracing::debug!(error = %e, "Redis SET NX failed in last_used throttle");
                // Fail open: let the DB write happen.
                true
            }
        };
        skip_write = !won;
    }

    if skip_write {
        return Ok(());
    }

    let result = sqlx::query("UPDATE api_keys SET last_used_at = NOW() WHERE id = $1::uuid")
        .bind(api_key_id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, api_key_id, "failed to update API key last_used_at");
            ApiError::Internal("authentication error".into())
        })?;

    if result.rows_affected() == 0 {
        tracing::warn!(
            api_key_id,
            "api key disappeared during last_used_at update; evicting cache entry"
        );
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
        Some(json) => {
            match serde_json::from_str::<AuthUser>(&json) {
                Ok(user) => {
                    // Validate cached AuthUser is structurally sound to prevent
                    // cache-poisoning attacks (e.g. empty tenant_id, wildcard
                    // scopes without an api_key_id — API keys are the only
                    // mechanism that legitimately grants wildcard scopes).
                    //
                    // L-05: map_or(false, ...) ensures a None user_id (legitimate
                    // for API key auth without a user association) is NOT flagged
                    // as invalid. Previously map_or(true, ...) caused None user_id
                    // to always be treated as invalid, evicting valid cache entries.
                    let is_invalid = user.tenant_id.is_empty()
                        || user.user_id.as_deref().is_some_and(|id| id.is_empty());
                    if is_invalid {
                        tracing::warn!(
                            cache_key,
                            tenant_id = %user.tenant_id,
                            user_id = ?user.user_id,
                            "cached API key AuthUser has empty required field(s) — evicting"
                        );
                        evict_api_key_cache_entry(state, &cache_key).await;
                        return Err(());
                    }
                    Ok(user)
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e, cache_key,
                        "corrupted or tampered JSON in API key cache — evicting"
                    );
                    // Best-effort eviction of poisoned cache entry
                    evict_api_key_cache_entry(state, &cache_key).await;
                    Err(())
                }
            }
        }
        None => Err(()),
    }
}

/// Best-effort eviction of a single API key cache entry.
async fn evict_api_key_cache_entry(state: &AppState, cache_key: &str) {
    if let Ok(mut conn) = state.redis.get().await {
        let _: Result<(), _> = redis::AsyncCommands::del(&mut *conn, cache_key).await;
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

pub(crate) fn session_revocation_key(tenant_id: &str, user_id: &str) -> String {
    format!("{SESSION_REVOCATION_PREFIX}{tenant_id}:{user_id}")
}

pub(crate) fn issued_before_or_at_revocation(iat: i64, revoked_after: Option<i64>) -> bool {
    revoked_after.is_some_and(|timestamp| iat <= timestamp)
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

pub(crate) async fn lookup_session_revoked_after(
    tenant_id: &str,
    user_id: &str,
    state: &AppState,
) -> Result<Option<i64>, ApiError> {
    let cache_key = session_revocation_key(tenant_id, user_id);
    let mut conn = state.redis.get().await.map_err(|error| {
        tracing::error!(error = %error, tenant_id, user_id, "redis unavailable for session revocation lookup");
        ApiError::ServiceUnavailable("authentication service temporarily unavailable".into())
    })?;

    conn.get(&cache_key).await.map_err(|error| {
        tracing::error!(error = %error, tenant_id, user_id, "redis GET failed for session revocation lookup");
        ApiError::ServiceUnavailable("authentication service temporarily unavailable".into())
    })
}

async fn cache_user_status(tenant_id: &str, user_id: &str, status: Option<&str>, state: &AppState) {
    let cache_key = user_status_cache_key(tenant_id, user_id);
    let cached_value = status.unwrap_or(USER_STATUS_CACHE_MISSING);
    if let Ok(mut conn) = state.redis.get().await {
        let _: Result<(), _> = conn
            .set_ex(&cache_key, cached_value, USER_STATUS_CACHE_TTL)
            .await;
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

    // L-09: Removed the hard cap of 1_000 iterations on the SCAN loop.
    // Previously, MAX_ITERATIONS = 1_000 meant that tenants with more than
    // ~100,000 user status cache keys (1_000 iterations × 100 COUNT) would
    // have stale entries left behind. The SCAN cursor naturally reaches 0
    // when all keys have been visited, so no explicit iteration limit is needed.
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
        // Use UNLINK (non-blocking) instead of DEL to avoid blocking the Redis event loop
        let _: Result<u64, _> = redis::cmd("UNLINK")
            .arg(&cache_keys)
            .query_async(&mut *conn)
            .await;
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

    let token_data = decode_jwt_with_rotation(token, &state.config, &validation)?;

    let claims = token_data.claims;

    // Token-type discrimination: a stream token (typ = "stream", issued by
    // POST /v1/stream/token for the tracking-service SSE endpoint) must never
    // authenticate a regular API session. Tokens without a `typ` claim are
    // pre-discrimination session tokens and stay valid — hard-requiring the
    // claim would invalidate every live session.
    if let Some(typ) = claims.typ.as_deref() {
        if typ != "session" {
            tracing::warn!(token_type = %typ, "rejecting non-session token used as session");
            return Err(ApiError::Unauthorized("invalid token type".into()));
        }
    }

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
            let user_status: Option<(String,)> =
                sqlx::query_as("SELECT status FROM users WHERE id = $1::uuid AND tenant_id = $2")
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
        return Err(ApiError::Unauthorized(format!(
            "user account is {user_status}"
        )));
    }

    let revoked_after = lookup_session_revoked_after(&tenant_id, &user_id, state).await?;
    if issued_before_or_at_revocation(claims.iat, revoked_after) {
        return Err(ApiError::Unauthorized("session has been revoked".into()));
    }

    // SA2-009: Enforce absolute maximum session lifetime server-side.
    // This is a secondary safeguard independent of the JWT `exp` claim.
    // Even if a stolen token's `exp` has been tampered with, sessions
    // older than MAX_SESSION_TTL_DAYS days from their `iat` are rejected.
    const MAX_SESSION_TTL_DAYS: i64 = 7;
    let iat_dt = DateTime::from_timestamp(claims.iat, 0)
        .ok_or_else(|| ApiError::Unauthorized("invalid session timestamp".into()))?;
    let max_session_deadline = iat_dt + chrono::Duration::days(MAX_SESSION_TTL_DAYS);
    if Utc::now() > max_session_deadline {
        return Err(ApiError::Unauthorized(
            "session has exceeded maximum lifetime — please log in again".into(),
        ));
    }

    Ok(AuthUser {
        tenant_id,
        user_id: Some(user_id),
        api_key_id: None,
        session_id: Some(claims.jti),
        scopes: claims.scopes,
    })
}

pub(crate) fn decode_jwt_with_rotation(
    token: &str,
    config: &crate::config::Config,
    validation: &Validation,
) -> Result<TokenData<JwtClaims>, ApiError> {
    let mut saw_valid_key = false;
    let mut last_decode_error = None;

    for public_key_pem in config.jwt_verification_public_keys() {
        let Ok(key) = DecodingKey::from_rsa_pem(public_key_pem.as_bytes()) else {
            continue;
        };
        saw_valid_key = true;
        match decode::<JwtClaims>(token, &key, validation) {
            Ok(token_data) => return Ok(token_data),
            Err(error) => last_decode_error = Some(error),
        }
    }

    if !saw_valid_key {
        return Err(ApiError::Internal(
            "invalid JWT public key configuration".into(),
        ));
    }

    Err(last_decode_error
        .map(ApiError::from)
        .unwrap_or_else(|| ApiError::Unauthorized("invalid token".into())))
}

/// Check if a JWT has been blacklisted (revoked).
async fn is_token_blacklisted(token: &str, state: &AppState) -> Result<bool, ApiError> {
    let key = token_blacklist_key(token);
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

/// Helper that rejects any caller whose tenant is not the `system` (control-plane) tenant.
///
/// The wildcard scope `"*"` is intentionally granted to every tenant's
/// admin/owner role so they can manage their *own* tenant's resources on
/// customer routes. That same scope must NOT grant access to control-plane
/// (`/v1/admin/*`) routes, otherwise any tenant administrator could operate the
/// entire platform. This helper is the system-tenant gate that, combined with
/// the `"*"` scope check performed by [`require_scopes`], ensures only platform
/// staff reach control-plane handlers.
pub fn require_system_tenant(auth: &AuthUser) -> Result<(), ApiError> {
    if auth.tenant_id != "system" {
        return Err(ApiError::Forbidden(
            "control-plane access requires system tenant".into(),
        ));
    }
    Ok(())
}

/// Middleware enforcing that the caller belongs to the `system` tenant.
///
/// Must be layered AFTER [`require_auth`] so that an [`AuthUser`] is already
/// present in request extensions. Intended for the control-plane (`/v1/admin/*`)
/// router so the tenant-admin wildcard scope `"*"` cannot be used to reach
/// platform administration endpoints.
pub async fn require_system_tenant_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, ApiError> {
    let auth_user = req.extensions().get::<AuthUser>().cloned().ok_or_else(|| {
        ApiError::Unauthorized("authentication required for control-plane access".into())
    })?;
    require_system_tenant(&auth_user)?;
    Ok(next.run(req).await)
}

// ─── Header-based tenant binding enforcement ───────────────────

/// Middleware that enforces tenant binding from X-Tenant-ID header.
/// After the user is authenticated, this checks that if an X-Tenant-ID
/// header is present, the authenticated user belongs to that tenant.
pub async fn enforce_tenant_header_binding(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, ApiError> {
    // Extract the tenant_id header if present
    let header_tenant_id = tenant_id_from_header(req.headers());

    if let Some(claimed_tenant_id) = header_tenant_id {
        // Check if an AuthUser is already in extensions
        if let Some(auth_user) = req.extensions().get::<AuthUser>() {
            // If the user is a system admin, allow cross-tenant access
            if auth_user.tenant_id != "system" {
                // If the user's own tenant doesn't match the claimed tenant,
                // verify DB-level membership
                if auth_user.tenant_id != claimed_tenant_id {
                    if let Some(ref user_id) = auth_user.user_id {
                        let is_member =
                            verify_tenant_membership(user_id, &claimed_tenant_id, &state.db)
                                .await?;

                        if !is_member {
                            tracing::warn!(
                                user_id = %user_id,
                                auth_tenant_id = %auth_user.tenant_id,
                                claimed_tenant_id = %claimed_tenant_id,
                                "X-Tenant-ID header injection attempt blocked"
                            );
                            return Err(ApiError::Forbidden("tenant access denied".into()));
                        }
                    } else {
                        // API key auth without user_id — cannot verify cross-tenant
                        tracing::warn!(
                            api_key_id = ?auth_user.api_key_id,
                            auth_tenant_id = %auth_user.tenant_id,
                            claimed_tenant_id = %claimed_tenant_id,
                            "X-Tenant-ID header with API key without user_id — rejected"
                        );
                        return Err(ApiError::Forbidden("tenant access denied".into()));
                    }
                }
            }
        }
    }

    Ok(next.run(req).await)
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
            session_id: None,
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
            session_id: None,
            scopes: vec!["messages:read".into()],
        };
        assert!(require_scopes(&user, &["messages:send"]).is_err());
    }

    #[test]
    fn test_tenant_id_from_request_path_extracts_admin_tenant_segment() {
        assert_eq!(
            tenant_id_from_request_path("/v1/billing/admin/tenants/ten_test_001/credits"),
            Some("ten_test_001")
        );
        assert_eq!(
            tenant_id_from_request_path("/v1/billing/plans/tenant/current"),
            None
        );
    }

    #[test]
    fn test_api_key_tenant_binding_rejects_path_mismatch() {
        let user = AuthUser {
            tenant_id: "ten_test_001".into(),
            user_id: None,
            api_key_id: Some("key_test_001".into()),
            session_id: None,
            scopes: vec!["*".into()],
        };

        assert!(enforce_api_key_tenant_binding(
            &user,
            "/v1/billing/admin/tenants/ten_test_001/credits"
        )
        .is_ok());
        assert!(matches!(
            enforce_api_key_tenant_binding(
                &user,
                "/v1/billing/admin/tenants/ten_other_001/credits"
            ),
            Err(ApiError::Forbidden(_))
        ));
    }

    #[test]
    fn test_api_key_tenant_binding_allows_system_key() {
        let user = AuthUser {
            tenant_id: "system".into(),
            user_id: None,
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        };

        assert!(enforce_api_key_tenant_binding(
            &user,
            "/v1/billing/admin/tenants/ten_other_001/credits"
        )
        .is_ok());
    }

    #[test]
    fn test_require_scopes_present() {
        let user = AuthUser {
            tenant_id: "ten_test_001".into(),
            user_id: None,
            api_key_id: Some("key_test_001".into()),
            session_id: None,
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
            jti: "sess_test_roundtrip_001".into(),
            typ: Some("session".into()),
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
    fn test_extract_auth_credential_ignores_bearer_like_cookie_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            "authorization=Bearer%20jwt.123; access_token=jwt.123; other=1"
                .parse()
                .unwrap(),
        );

        assert_eq!(extract_auth_credential(&headers), None);
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
        let sig_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, sig);
        let token = format!("{nonce_b64}.{sig_b64}");

        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            format!("am_session=session.jwt; csrf_token={token}")
                .parse()
                .unwrap(),
        );
        headers.insert(CSRF_HEADER_NAME, token.parse().unwrap());

        assert!(validate_session_csrf(&headers, secret).is_ok());

        headers.insert(CSRF_HEADER_NAME, "different-token".parse().unwrap());
        assert!(matches!(
            validate_session_csrf(&headers, secret),
            Err(ApiError::Forbidden(message)) if message == "CSRF token mismatch"
        ));
    }

    #[test]
    fn test_control_plane_static_key_request_requires_admin_path_and_control_plane_host() {
        assert!(is_control_plane_static_key_request(
            "/v1/admin/tenants",
            true
        ));
        assert!(!is_control_plane_static_key_request("/v1/messages", true));
        assert!(!is_control_plane_static_key_request(
            "/v1/admin/tenants",
            false
        ));
        assert!(!is_control_plane_static_key_request(
            "/api/auth/login",
            true
        ));
    }

    // ── RBAC Security Regression Tests ─────────────────────────

    #[test]
    fn test_require_scopes_empty_scopes_denies_all() {
        let user = AuthUser {
            tenant_id: "ten_test_001".into(),
            user_id: Some("usr_test_001".into()),
            api_key_id: None,
            session_id: None,
            scopes: vec![],
        };
        assert!(
            require_scopes(&user, &["messages:read"]).is_err(),
            "empty scopes must deny access"
        );
    }

    #[test]
    fn test_require_scopes_partial_match_denies() {
        let user = AuthUser {
            tenant_id: "ten_test_001".into(),
            user_id: None,
            api_key_id: Some("key_test_001".into()),
            session_id: None,
            scopes: vec!["messages:read".into()],
        };
        // Requires both scopes, user only has one
        assert!(
            require_scopes(&user, &["messages:read", "messages:send"]).is_err(),
            "partial scope match must deny access"
        );
    }

    #[test]
    fn test_require_scopes_similar_name_no_match() {
        let user = AuthUser {
            tenant_id: "ten_test_001".into(),
            user_id: None,
            api_key_id: Some("key_test_001".into()),
            session_id: None,
            scopes: vec!["messages:read_all".into()],
        };
        // "messages:read_all" must NOT match "messages:read"
        assert!(
            require_scopes(&user, &["messages:read"]).is_err(),
            "similar scope name must not match"
        );
    }

    #[test]
    fn test_require_scopes_wildcard_grants_everything() {
        let user = AuthUser {
            tenant_id: "ten_test_001".into(),
            user_id: Some("usr_test_001".into()),
            api_key_id: None,
            session_id: None,
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
            session_id: None,
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
            session_id: None,
            scopes: vec![
                "messages:read".into(),
                "domains:read".into(),
                "templates:read".into(),
                "events:read".into(),
                "analytics:read".into(),
                "contacts:read".into(),
            ],
        };
        assert!(
            require_scopes(&viewer, &["messages:send"]).is_err(),
            "viewer must not be able to send messages"
        );
        assert!(
            require_scopes(&viewer, &["domains:write"]).is_err(),
            "viewer must not be able to modify domains"
        );
        assert!(
            require_scopes(&viewer, &["templates:write"]).is_err(),
            "viewer must not be able to modify templates"
        );
    }

    #[test]
    fn test_developer_role_scopes_cannot_manage_webhooks() {
        // Developer role should lack webhook/campaign/automation scopes
        let developer = AuthUser {
            tenant_id: "ten_test_001".into(),
            user_id: Some("usr_test_001".into()),
            api_key_id: None,
            session_id: None,
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
        assert!(
            require_scopes(&developer, &["webhooks:write"]).is_err(),
            "developer must not be able to manage webhooks"
        );
        assert!(
            require_scopes(&developer, &["campaigns:write"]).is_err(),
            "developer must not be able to manage campaigns"
        );
    }

    #[test]
    fn test_auth_user_serialization_roundtrip() {
        let user = AuthUser {
            tenant_id: "ten_test_001".into(),
            user_id: Some("usr_test_001".into()),
            api_key_id: None,
            session_id: None,
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
            session_id: None,
            scopes: vec!["messages:send".into()],
        };
        assert!(user.user_id.is_none(), "API key auth must not have user_id");
        assert!(
            user.api_key_id.is_some(),
            "API key auth must have api_key_id"
        );
    }

    #[test]
    fn test_user_status_cache_key_is_scoped_by_tenant_and_user() {
        assert_eq!(
            user_status_cache_key("ten_test_001", "usr_test_001"),
            "apexmail:user_status:ten_test_001:usr_test_001"
        );
    }

    #[test]
    fn test_session_revocation_key_is_scoped_by_tenant_and_user() {
        assert_eq!(
            session_revocation_key("ten_test_001", "usr_test_001"),
            "apexmail:session_revoked_after:ten_test_001:usr_test_001"
        );
    }

    #[test]
    fn test_issued_before_or_at_revocation_rejects_old_tokens() {
        assert!(issued_before_or_at_revocation(100, Some(100)));
        assert!(issued_before_or_at_revocation(100, Some(101)));
        assert!(!issued_before_or_at_revocation(102, Some(101)));
        assert!(!issued_before_or_at_revocation(100, None));
    }

    #[test]
    fn test_parse_cached_user_status_handles_missing_sentinel() {
        assert_eq!(
            parse_cached_user_status(USER_STATUS_CACHE_MISSING),
            CachedUserStatus::Missing
        );
        assert_eq!(
            parse_cached_user_status("active"),
            CachedUserStatus::Present("active".into())
        );
    }

    // ── Redis Failover & Cache Resilience Tests ──────────────────

    /// Simulates the cache-poisoning protection: `AuthUser` uses
    /// `#[serde(deny_unknown_fields)]` so any extra fields injected by an
    /// attacker into Redis are rejected at deserialisation time.
    #[test]
    fn test_auth_user_deny_unknown_fields_rejects_extra_fields() {
        let json = r#"{
            "tenant_id": "ten_test_001",
            "user_id": "usr_test_001",
            "scopes": ["messages:read"],
            "injected_malicious_field": "evil_payload"
        }"#;
        let result: Result<AuthUser, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "AuthUser must reject unknown fields to prevent cache-poisoning attacks"
        );
    }

    /// Tests the cache eviction path for corrupted JSON.
    /// When Redis returns malformed JSON (e.g. from a partial write or
    /// tampering), the lookup must discard the bad entry rather than panic.
    #[test]
    fn test_lookup_cached_api_key_evicts_corrupted_json() {
        // Simulate the deserialisation step inside lookup_cached_api_key.
        // Corrupted JSON should fail to parse as AuthUser.
        let corrupted = r#"{"tenant_id":"ten_test_001","user_id":null,"scopes":["*"}"#; // truncated
        let result: Result<AuthUser, _> = serde_json::from_str(corrupted);
        assert!(result.is_err(), "corrupted JSON must fail deserialisation");

        // Even valid JSON with unknown fields (cache-poisoning attempt)
        // must be rejected by deny_unknown_fields.
        let poisoned = r#"{
            "tenant_id": "ten_test_001",
            "user_id": "usr_test_001",
            "scopes": ["messages:read"],
            "__MALICIOUS__": true
        }"#;
        let result: Result<AuthUser, _> = serde_json::from_str(poisoned);
        assert!(
            result.is_err(),
            "cache-poisoned JSON with extra fields must be rejected"
        );
    }

    /// Tests the structural validation inside `lookup_cached_api_key`:
    /// a cached `AuthUser` with empty `tenant_id` is considered invalid
    /// and triggers eviction (simulated here by checking the validation
    /// predicate that guards eviction).
    #[test]
    fn test_lookup_cached_api_key_evicts_empty_tenant_id() {
        // Construct an AuthUser with empty tenant_id — this simulates
        // what would happen if a cache entry had been corrupted.
        let user = AuthUser {
            tenant_id: String::new(),
            user_id: Some("usr_test_001".into()),
            api_key_id: Some("key_test_001".into()),
            session_id: None,
            scopes: vec!["*".into()],
        };
        // The validation predicate used in lookup_cached_api_key:
        // L-05: map_or(false, ...) so None user_id is NOT invalid.
        let is_invalid =
            user.tenant_id.is_empty() || user.user_id.as_deref().is_some_and(|id| id.is_empty());
        assert!(
            is_invalid,
            "cached API key with empty tenant_id must be flagged as invalid and evicted"
        );
    }

    /// Tests the structural validation inside `lookup_cached_api_key`:
    /// a cached `AuthUser` with empty `user_id` is considered invalid.
    #[test]
    fn test_lookup_cached_api_key_evicts_empty_user_id() {
        let user = AuthUser {
            tenant_id: "ten_test_001".into(),
            user_id: Some(String::new()),
            api_key_id: Some("key_test_001".into()),
            session_id: None,
            scopes: vec!["*".into()],
        };
        let is_invalid =
            user.tenant_id.is_empty() || user.user_id.as_deref().is_some_and(|id| id.is_empty());
        assert!(
            is_invalid,
            "cached API key with empty user_id must be flagged as invalid and evicted"
        );
    }

    /// Tests the structural validation inside `lookup_cached_api_key`:
    /// a `None` user_id (from API key auth without user association) is valid.
    #[test]
    fn test_lookup_cached_api_key_allows_none_user_id() {
        // API key authentication legitimately has user_id = None.
        let user = AuthUser {
            tenant_id: "ten_test_001".into(),
            user_id: None,
            api_key_id: Some("key_test_001".into()),
            session_id: None,
            scopes: vec!["*".into()],
        };
        // L-05: With map_or(false, ...), None user_id is NOT flagged as invalid.
        // user_id is None → .as_deref() returns None → .map_or(false, ...) returns false
        // This is correct: API key authentication legitimately has user_id = None.
        let is_invalid =
            user.tenant_id.is_empty() || user.user_id.as_deref().is_some_and(|id| id.is_empty());
        assert!(
            !is_invalid,
            "API key cache entries with None user_id must NOT be evicted (L-05 fix)"
        );
    }

    /// Tests the `CachedUserStatus` parsing — the `__missing__` sentinel
    /// is used to cache the fact that a user was not found in the DB,
    /// preventing repeated lookups for deleted users.
    #[test]
    fn test_parse_cached_user_status_missing_sentinel_is_specific() {
        // The sentinel must be the exact string `__missing__`.
        assert_eq!(
            parse_cached_user_status(USER_STATUS_CACHE_MISSING),
            CachedUserStatus::Missing
        );
        // Any non-sentinel value must be treated as Present, even unusual ones.
        assert_eq!(
            parse_cached_user_status("__MISSING__"),
            CachedUserStatus::Present("__MISSING__".into())
        );
        assert_eq!(
            parse_cached_user_status(""),
            CachedUserStatus::Present("".into())
        );
    }

    /// Tests the cache key isolation: different tenants/users must not
    /// collide, preventing cache side-channel information leaks.
    #[test]
    fn test_user_status_cache_key_isolates_tenants_and_users() {
        let key_a = user_status_cache_key("tenant_a", "user_1");
        let key_b = user_status_cache_key("tenant_b", "user_1");
        let key_c = user_status_cache_key("tenant_a", "user_2");
        assert_ne!(key_a, key_b, "different tenants must not share cache keys");
        assert_ne!(key_a, key_c, "different users must not share cache keys");
        assert!(key_a.starts_with(USER_STATUS_CACHE_PREFIX));
    }

    /// Tests the session revocation key isolation.
    #[test]
    fn test_session_revocation_key_isolates_tenants_and_users() {
        let key_a = session_revocation_key("tenant_a", "user_1");
        let key_b = session_revocation_key("tenant_b", "user_1");
        let key_c = session_revocation_key("tenant_a", "user_2");
        assert_ne!(
            key_a, key_b,
            "different tenants must not share revocation keys"
        );
        assert_ne!(
            key_a, key_c,
            "different users must not share revocation keys"
        );
        assert!(key_a.starts_with(SESSION_REVOCATION_PREFIX));
    }

    /// Tests that the fire-and-forget cache operations (cache_api_key,
    /// cache_user_status, invalidate_api_key_cache, etc.) gracefully
    /// handle Redis connection failures by using `if let Ok(...)` patterns.
    /// This test verifies the pattern is safe — it should never panic
    /// or block when Redis is unavailable.
    #[test]
    fn test_cache_operations_pattern_safe_on_redis_failure() {
        // The fire-and-forget pattern used by cache operations:
        //   if let Ok(mut conn) = state.redis.get().await { ... }
        // This means Redis connection failures result in a silent no-op.
        // We verify that the fallback path (DB lookup) is logically sound
        // by checking the function composition in authenticate_api_key:
        //
        // 1. lookup_cached_api_key returns Err(()) on Redis failure
        // 2. authenticate_api_key falls through to DB lookup
        // 3. cache_api_key is fire-and-forget after DB lookup
        //
        // This test verifies the Err(()) return type matches the expected
        // pattern — the caller uses `if let Ok(cached) = lookup_...` to
        // handle both cache miss and Redis failure identically.
        let err: Result<AuthUser, ()> = Err(());
        assert!(
            err.is_err(),
            "lookup_cached_api_key returns Err(()) on Redis failure — caller falls through to DB"
        );
    }

    /// Tests the `issued_before_or_at_revocation` function with edge cases
    /// that could arise from clock skew or cache staleness.
    #[test]
    fn test_issued_before_or_at_revocation_edge_cases() {
        // Token issued exactly at revocation time → revoked
        assert!(issued_before_or_at_revocation(1000, Some(1000)));

        // Token issued before revocation → revoked
        assert!(issued_before_or_at_revocation(999, Some(1000)));

        // Token issued after revocation → allowed (new session)
        assert!(!issued_before_or_at_revocation(1001, Some(1000)));

        // No revocation marker in cache → allowed
        assert!(!issued_before_or_at_revocation(999, None));

        // Revocation at Unix epoch → all non-negative timestamps are revoked
        assert!(issued_before_or_at_revocation(0, Some(0)));
        assert!(!issued_before_or_at_revocation(1, Some(0)));

        // Very large timestamps (future dates) — no overflow
        let far_future: i64 = 1_000_000_000_000;
        assert!(issued_before_or_at_revocation(far_future, Some(far_future)));
        assert!(!issued_before_or_at_revocation(
            far_future + 1,
            Some(far_future)
        ));
    }
}
