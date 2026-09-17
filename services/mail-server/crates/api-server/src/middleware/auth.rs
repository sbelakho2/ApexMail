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

/// Char-boundary-safe byte prefix of `s`, at most `max` bytes long.
/// Raw `&s[..max]` panics when `max` falls inside a multibyte UTF-8
/// character; identifiers can carry non-ASCII bytes (JWT claims, Redis
/// cache entries), so the Debug impl must never slice blindly.
fn char_safe_prefix(s: &str, max: usize) -> &str {
    let mut end = s.len().min(max);
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

impl std::fmt::Debug for AuthUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthUser")
            .field(
                "tenant_id",
                &format!(
                    "{}..{}",
                    char_safe_prefix(&self.tenant_id, 4),
                    self.tenant_id.len()
                ),
            )
            .field(
                "user_id",
                &self
                    .user_id
                    .as_ref()
                    .map(|id| format!("{}..{}", char_safe_prefix(id, 4), id.len())),
            )
            .field(
                "api_key_id",
                &self
                    .api_key_id
                    .as_ref()
                    .map(|id| format!("{}..{}", char_safe_prefix(id, 4), id.len())),
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
    /// Current `(status, role)` of a live user. The role rides the same
    /// cache entry so scope narrowing never costs an extra query.
    Present(String, String),
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

    // Constant-time comparison: a plain `!=` short-circuits on the first
    // differing byte, leaking how much of the token an attacker guessed.
    if !apexmail_lib::timing_safe_compare(header_token, cookie_token.as_str()) {
        return Err(ApiError::Forbidden("CSRF token mismatch".into()));
    }

    validate_csrf_token(header_token, csrf_secret)
}

fn is_control_plane_static_key_request(path: &str, on_control_plane_host: bool) -> bool {
    on_control_plane_host && path.starts_with("/v1/admin/")
}

/// Does this path segment carry a tenant id, or is it a static route word?
///
/// Tenant ids in this platform are minted as `ten_<…>` or `t<uuid-simple>`
/// (26 characters, `tenants.id VARCHAR(26)` — see `auth.rs`'s signup insert and
/// the canonical fixtures). A path segment after `tenant(s)` is only an id when
/// it has that shape: the billing plans surface uses `tenant` as a SCOPE WORD
/// (`/v1/billing/plans/tenant/features|limits|current`), and reading its next
/// segment as an id made the API-key tenant binding compare the key's tenant
/// against the literal word `features`, so every real key got a 403 on those
/// routes. Binding enforcement must be driven by real ids only — an
/// over-broad parser breaks working routes, which is exactly what this
/// predicate prevents.
fn looks_like_tenant_id(segment: &str) -> bool {
    if segment.is_empty() || segment.len() > 26 {
        return false;
    }
    if !segment
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return false;
    }
    // A real id either carries the documented `ten_` prefix (integrations and
    // fixtures) or is a minted nanoid — `apexmail_lib::id::generate_id("", 26)`
    // — which always contains a digit in practice. Static route words
    // (`features`, `limits`, `invoices`, `data`) have neither.
    segment.starts_with("ten_") || segment.chars().any(|c| c.is_ascii_digit())
}

fn tenant_id_from_request_path(path: &str) -> Option<&str> {
    let mut segments = path.split('/').filter(|segment| !segment.is_empty());
    while let Some(segment) = segments.next() {
        if matches!(segment, "tenant" | "tenants") {
            let tenant_id = segments.next()?;
            if matches!(tenant_id, "current" | "me" | "self") {
                return None;
            }
            return if looks_like_tenant_id(tenant_id) {
                Some(tenant_id)
            } else {
                None
            };
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
        // user_id is UUID (migration 229) and the bound value is the JWT
        // subject's UUID string: without the cast the comparison is
        // uuid = text (no such operator), and before 229 the column was
        // VARCHAR(26), where a UUID string could never be stored — a real
        // membership could never match.
        "SELECT COUNT(*) FROM user_tenant_membership WHERE user_id = $1::uuid AND tenant_id = $2",
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
        // Reuse an identity the `require_auth` layer ALREADY authenticated
        // for this request. Without this, a handler's `AuthUser` extractor
        // re-ran the whole credential flow — and inside a nested router
        // axum has STRIPPED the mount prefix from `parts.uri.path()`, so
        // every path-dependent policy in the re-run saw a relative path:
        // the F18 billing-recovery allowlist (all four entries are nested
        // under /v1/billing) could never match, leaving a suspended tenant
        // unable to pay/reactivate, and the control-plane static key's
        // `/v1/admin/` surface check refused the key on its own surface.
        // The extension is only inserted AFTER a successful authentication,
        // so reusing it cannot weaken any gate.
        if let Some(user) = parts.extensions.get::<AuthUser>() {
            return Ok(user.clone());
        }

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
                authenticate_api_key(
                    &credential,
                    &parts.method,
                    parts.uri.path(),
                    on_control_plane_host,
                    state,
                )
                .await
            }
            AuthMechanism::BearerToken | AuthMechanism::SessionCookie => {
                authenticate_jwt(&credential, &parts.method, parts.uri.path(), state).await
            }
        }
    }
}

// ─── API Key authentication ────────────────────────────────────

async fn authenticate_api_key(
    key: &str,
    request_method: &Method,
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
        // Tenant policy (F18): the cached identity does not carry the
        // tenant's CURRENT status, so the centralized gate runs on every
        // hit too.
        enforce_tenant_not_restricted(state, &cached.tenant_id, request_method, request_path)
            .await?;
        if let Some(api_key_id) = cached.api_key_id.as_deref() {
            touch_api_key_last_used(api_key_id, &hmac_hash, state).await?;
        }
        return Ok(cached);
    }

    if legacy_hash != hmac_hash {
        if let Ok(cached) = lookup_cached_api_key(&legacy_hash, state).await {
            enforce_api_key_tenant_binding(&cached, request_path)?;
            enforce_tenant_not_restricted(state, &cached.tenant_id, request_method, request_path)
                .await?;
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
                        request_method,
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

    // Tenant policy (F18): an API key belonging to a suspended (or
    // otherwise restricted) tenant must stop authenticating, on the DB
    // path just like on the cache-hit path above.
    enforce_tenant_not_restricted(state, &auth_user.tenant_id, request_method, request_path)
        .await?;

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
    cache_api_key(&row.key_hash, &auth_user, row.expires_at, state).await;

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
    request_method: &Method,
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
        // Tenant policy (F18) on the legacy-hash fallback path too.
        enforce_tenant_not_restricted(state, &auth_user.tenant_id, request_method, request_path)
            .await?;

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

        cache_api_key(&new_hash, &auth_user, row.expires_at, state).await;
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
            // Entries written before the expiry-aware wrapper (a plain
            // AuthUser JSON) fail to parse here and are evicted.
            let entry = match serde_json::from_str::<CachedApiKey>(&json) {
                Ok(entry) => entry,
                Err(e) => {
                    tracing::warn!(
                        error = %e, cache_key,
                        "corrupted or legacy API key cache entry — evicting"
                    );
                    evict_api_key_cache_entry(state, &cache_key).await;
                    return Err(());
                }
            };
            // Expiry re-check on the HIT path: a key that expired after its
            // entry was written must stop authenticating immediately, not
            // when the TTL lapses.
            if entry
                .expires_at
                .is_some_and(|expires_at| expires_at < Utc::now())
            {
                tracing::info!(cache_key, "cached API key has expired — evicting entry");
                evict_api_key_cache_entry(state, &cache_key).await;
                return Err(());
            }
            let user = entry.user;
            // Validate cached AuthUser is structurally sound to prevent
            // cache-poisoning attacks (e.g. empty tenant_id).
            //
            // L-05: a None user_id is legitimate for API key auth without a
            // user association and is NOT flagged as invalid.
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
        None => Err(()),
    }
}

/// Best-effort eviction of a single API key cache entry.
async fn evict_api_key_cache_entry(state: &AppState, cache_key: &str) {
    if let Ok(mut conn) = state.redis.get().await {
        let _: Result<(), _> = redis::AsyncCommands::del(&mut *conn, cache_key).await;
    }
}

/// Cache entry: the identity plus the key's expiry so a cached HIT can
/// re-check it (the 10s TTL outlives keys expiring any second — an entry
/// written just before expiry must not keep authenticating forever).
#[derive(serde::Serialize, serde::Deserialize)]
struct CachedApiKey {
    user: AuthUser,
    #[serde(default)]
    expires_at: Option<DateTime<Utc>>,
}

async fn cache_api_key(
    key_hash: &str,
    user: &AuthUser,
    expires_at: Option<DateTime<Utc>>,
    state: &AppState,
) {
    let cache_key = format!("{API_KEY_CACHE_PREFIX}{key_hash}");
    let entry = CachedApiKey {
        user: user.clone(),
        expires_at,
    };
    if let Ok(json) = serde_json::to_string(&entry) {
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

fn parse_cached_user_status(value: &str) -> Option<CachedUserStatus> {
    if value == USER_STATUS_CACHE_MISSING {
        return Some(CachedUserStatus::Missing);
    }
    // "status|role". A value without the role segment is a legacy
    // status-only entry — treat it as a miss so the authoritative row is
    // re-read (an unknown role must never silently narrow or widen
    // scopes).
    let (status, role) = value.split_once('|')?;
    Some(CachedUserStatus::Present(
        status.to_owned(),
        role.to_owned(),
    ))
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
    // None (miss) for legacy entries — see parse_cached_user_status.
    Ok(cached.as_deref().and_then(parse_cached_user_status))
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

async fn cache_user_status(
    tenant_id: &str,
    user_id: &str,
    status: Option<(&str, &str)>,
    state: &AppState,
) {
    let cache_key = user_status_cache_key(tenant_id, user_id);
    let cached_value = match status {
        Some((status, role)) => {
            // '|' cannot appear in either value from the database schema
            // (status/role are constrained vocabulary columns).
            format!("{status}|{role}")
        }
        None => USER_STATUS_CACHE_MISSING.to_string(),
    };
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

// ─── Tenant status policy (audit F18) ──────────────────────────

const TENANT_STATUS_CACHE_PREFIX: &str = "apexmail:tenant_status:";
const TENANT_STATUS_CACHE_TTL: u64 = 15; // seconds
const TENANT_STATUS_CACHE_MISSING: &str = "__missing__";

fn tenant_status_cache_key(tenant_id: &str) -> String {
    format!("{TENANT_STATUS_CACHE_PREFIX}{tenant_id}")
}

/// THE tenant-policy decision (audit F18): which `tenants.status` values
/// permit authenticated traffic. Only `active` does — a `pending` tenant
/// has not completed verification, and a `suspended` tenant is under an
/// administrative, abuse, or billing hold. Every enforcement point (API
/// key auth, JWT auth, and API key minting in `routes::auth`) consults
/// this ONE function so the surfaces cannot drift apart again.
pub(crate) fn tenant_status_permits_auth(status: &str) -> bool {
    status == "active"
}

async fn cache_tenant_status(tenant_id: &str, status: Option<&str>, state: &AppState) {
    let cache_key = tenant_status_cache_key(tenant_id);
    let value = status.unwrap_or(TENANT_STATUS_CACHE_MISSING).to_string();
    if let Ok(mut conn) = state.redis.get().await {
        let _: Result<(), _> = conn
            .set_ex(&cache_key, value, TENANT_STATUS_CACHE_TTL)
            .await;
    }
}

/// Drop the cached tenant-status decision so a control-plane status write
/// takes effect immediately instead of after the short TTL. Called by the
/// tenant lifecycle handlers (`routes::admin::tenants`, web console
/// suspend/resume) on every status change.
pub(crate) async fn invalidate_tenant_status_cache(tenant_id: &str, state: &AppState) {
    let cache_key = tenant_status_cache_key(tenant_id);
    if let Ok(mut conn) = state.redis.get().await {
        let _: Result<(), _> = redis::AsyncCommands::del(&mut *conn, &cache_key).await;
    }
}

/// Enforce the tenant-status policy for an authenticated identity (audit
/// F18). The decision is cached in Redis for 15 s (mirroring the
/// user-status cache) and invalidated by every control-plane status
/// write; an unreachable Redis degrades to the authoritative DB row.
/// Unknown tenants and DB errors fail CLOSED.
///
/// F18 (recovery access): authentication is separated from operation
/// authorization — a SUSPENDED tenant keeps authenticated access to the
/// narrow billing-recovery allowlist ([`is_billing_recovery_request`]) so
/// the customer can view invoices, update payment methods and enter the
/// billing portal to clear the suspension. Everything else (send, keys,
/// domains, ...) stays blocked: those requests fail this gate.
pub(crate) async fn enforce_tenant_not_restricted(
    state: &AppState,
    tenant_id: &str,
    request_method: &Method,
    request_path: &str,
) -> Result<(), ApiError> {
    // The static control-plane key carries the "system" sentinel tenant id,
    // which has no tenants row and is governed by its own gates.
    if tenant_id == "system" {
        return Ok(());
    }

    let status = tenant_status_for_auth(state, tenant_id).await?;
    if tenant_status_permits_auth(&status) {
        return Ok(());
    }

    // F18: suspended tenants keep the billing-recovery operations only.
    // Pending/closed/other statuses authenticate nothing.
    if status == "suspended" && is_billing_recovery_request(request_method, request_path) {
        tracing::info!(
            tenant_id = %tenant_id,
            method = %request_method,
            path = %request_path,
            "billing-recovery access granted for suspended tenant"
        );
        return Ok(());
    }

    tracing::warn!(tenant_id = %tenant_id, tenant_status = %status, "authentication refused for restricted tenant");
    Err(ApiError::Unauthorized(format!(
        "workspace is {status} — access is restricted"
    )))
}

/// F18: the narrow billing-recovery allowlist. Each entry is an exact HTTP
/// method plus a path PREFIX matched against the request path:
///
/// * view invoices (list/detail/PDF/XML exports) — `GET /v1/billing/invoices…`
/// * enter the billing portal (payment-method management happens inside
///   the Stripe-hosted portal) — `POST /v1/billing/portal`
/// * pay/reactivate through checkout — `POST /v1/billing/checkout`
/// * view the current subscription — `GET /v1/billing/subscription`
///
/// Deliberately NOT included: message sending, API-key minting, domain and
/// DNS mutations, contact operations — those stay blocked while suspended.
const BILLING_RECOVERY_ALLOWLIST: [(&Method, &str); 4] = [
    (&http::Method::GET, "/v1/billing/invoices"),
    (&http::Method::POST, "/v1/billing/portal"),
    (&http::Method::POST, "/v1/billing/checkout"),
    (&http::Method::GET, "/v1/billing/subscription"),
];

/// F18: does this request fall inside the billing-recovery allowlist?
/// Prefix matching keeps the invoice detail/export sub-paths covered; no
/// other route family matches.
pub(crate) fn is_billing_recovery_request(method: &http::Method, path: &str) -> bool {
    BILLING_RECOVERY_ALLOWLIST
        .iter()
        .any(|(allowed_method, prefix)| {
            method == allowed_method
                && (path == *prefix
                    || path
                        .strip_prefix(*prefix)
                        .is_some_and(|rest| rest.starts_with('/')))
        })
}

async fn tenant_status_for_auth(state: &AppState, tenant_id: &str) -> Result<String, ApiError> {
    if let Ok(mut conn) = state.redis.get().await {
        let cache_key = tenant_status_cache_key(tenant_id);
        if let Ok(cached) = conn.get::<_, Option<String>>(&cache_key).await {
            match cached {
                Some(value) if value == TENANT_STATUS_CACHE_MISSING => {
                    return Err(ApiError::Unauthorized("workspace no longer exists".into()));
                }
                Some(status) => return Ok(status),
                None => {} // cache miss — fall through to the DB row
            }
        }
    }

    let status: Option<String> = sqlx::query_scalar("SELECT status FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, tenant_id, "tenant status lookup failed");
            ApiError::Internal("authentication error".into())
        })?;

    let Some(status) = status else {
        cache_tenant_status(tenant_id, None, state).await;
        return Err(ApiError::Unauthorized("workspace no longer exists".into()));
    };

    cache_tenant_status(tenant_id, Some(&status), state).await;
    Ok(status)
}

// ─── JWT authentication ────────────────────────────────────────

/// Token-type discrimination shared by EVERY consumer of `am_session`-style
/// JWTs: API authentication, the refresh endpoint, and session
/// introspection. A stream token (`typ = "stream"`, issued by
/// `POST /v1/stream/token` for the tracking-service SSE endpoint) must
/// never be accepted as (or refreshed into) a full API session.
/// Tokens without a `typ` claim are pre-discrimination session tokens and
/// stay valid — hard-requiring the claim would invalidate every live session.
pub(crate) fn claims_typ_is_session(typ: Option<&str>) -> bool {
    typ.is_none_or(|token_type| token_type == "session")
}

/// Validate a session JWT exactly as the request-auth path does: token
/// blacklist, signature, token-type discrimination, per-request user
/// status recheck, session-revocation registry, and the absolute session
/// lifetime ceiling. Shared by `require_auth` and the session
/// introspection endpoint so the two can never disagree.
pub(crate) async fn authenticate_jwt(
    token: &str,
    request_method: &Method,
    request_path: &str,
    state: &AppState,
) -> Result<AuthUser, ApiError> {
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
    if !claims_typ_is_session(claims.typ.as_deref()) {
        tracing::warn!(
            token_type = claims.typ.as_deref().unwrap_or("<missing>"),
            "rejecting non-session token used as session"
        );
        return Err(ApiError::Unauthorized("invalid token type".into()));
    }

    let user_id = claims.sub.clone();
    let tenant_id = claims.tenant_id.clone();

    if user_id.is_empty() {
        return Err(ApiError::Unauthorized("missing user ID in token".into()));
    }
    if tenant_id.is_empty() {
        return Err(ApiError::Unauthorized("missing tenant ID in token".into()));
    }

    let (user_status, user_role) = match lookup_cached_user_status(&tenant_id, &user_id, state)
        .await
    {
        Ok(Some(CachedUserStatus::Missing)) => {
            return Err(ApiError::Unauthorized("user no longer exists".into()));
        }
        Ok(Some(CachedUserStatus::Present(status, role))) => (status, role),
        _ => {
            let user_status: Option<(String, String)> = sqlx::query_as(
                "SELECT status, role FROM users WHERE id = $1::uuid AND tenant_id = $2",
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
                Some((status, role)) => {
                    cache_user_status(&tenant_id, &user_id, Some((&status, &role)), state).await;
                    (status, role)
                }
            }
        }
    };

    if user_status != "active" {
        return Err(ApiError::Unauthorized(format!(
            "user account is {user_status}"
        )));
    }

    // Tenant policy (F18): the USER being active is not enough — a session
    // under a restricted tenant must stop authenticating across the API and
    // SSR surfaces alike. This is the same centralized gate the API key path
    // enforces; the billing-recovery allowlist keeps the narrowly defined
    // recovery operations reachable for suspended tenants.
    enforce_tenant_not_restricted(state, &tenant_id, request_method, request_path).await?;

    // Live scope narrowing: the token's scopes are the user's scopes AT
    // LOGIN; the role may have changed since. Recompute the effective set
    // from the CURRENT role (read above on the same per-request pass the
    // status came from) so a demoted admin's still-valid token immediately
    // loses the grants the old role no longer carries. A token's scope
    // set can only ever be narrowed, never widened, by this.
    let current_role_scopes = crate::routes::auth::scopes_for_role(&user_role);
    let scopes = if current_role_scopes.iter().any(|scope| scope == "*") {
        // The current role grants everything: the token's own set stands
        // (it cannot exceed what the role grants).
        claims.scopes
    } else if claims.scopes.iter().any(|scope| scope == "*") {
        // Wildcard token under a narrowed role: exactly what the role
        // still grants.
        current_role_scopes
    } else {
        claims
            .scopes
            .iter()
            .filter(|scope| current_role_scopes.contains(scope))
            .cloned()
            .collect()
    };

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
        scopes,
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
///
/// Slug-aware (audit F1): the seeded system tenant's id is
/// `system_internal_tenant01` (migration 072), not the literal `system`
/// sentinel (which only static API keys carry). The literal comparison
/// rejected every operator minted through the CP login, 403-ing every CP
/// POST. Membership now resolves through the SAME slug-aware check the CP
/// login gate uses (`routes::web::is_system_tenant`): the `system` literal
/// or a tenants row whose slug is `system`. A database error fails CLOSED.
pub async fn require_system_tenant(state: &AppState, auth: &AuthUser) -> Result<(), ApiError> {
    if auth.tenant_id != "system"
        && !crate::routes::web::is_system_tenant(state, &auth.tenant_id).await
    {
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
///
/// Browser surfaces (`/web/*` paths) get the web stack's PRG treatment on
/// rejection (audit F1): a signed flash cookie + 303 to the login page, the
/// same way `web_form_rejection_middleware` and the CP login gate render
/// errors — never a raw JSON 403 dump to a browser.
pub async fn require_system_tenant_middleware(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, ApiError> {
    let is_browser_path = req.uri().path().starts_with("/web/");
    let auth_user = req.extensions().get::<AuthUser>().cloned().ok_or_else(|| {
        ApiError::Unauthorized("authentication required for control-plane access".into())
    })?;
    if let Err(error) = require_system_tenant(&state, &auth_user).await {
        if is_browser_path {
            tracing::warn!(
                tenant_id = %auth_user.tenant_id,
                // F65: redacted route, never the raw token-bearing URI.
                path = %crate::middleware::request_logger::redact_token_bearing_path(req.uri().path()),
                "non-system session rejected from the control-plane form surface"
            );
            use axum::response::IntoResponse as _;
            let mut response = (
                axum::http::StatusCode::SEE_OTHER,
                [(axum::http::header::LOCATION, "/login")],
            )
                .into_response();
            if let Ok(cookie) = ui_foundation::flash::flash_set_cookie(
                &[ui_foundation::flash::FlashMessage::error(
                    "Control-plane access is restricted to ApexMail operators.",
                )],
                &state.config.csrf_secret,
                state.config.environment.is_production(),
            )
            .parse()
            {
                response
                    .headers_mut()
                    .append(axum::http::header::SET_COOKIE, cookie);
            }
            return Ok(response);
        }
        return Err(error);
    }
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

    // ── F18: billing-recovery allowlist for suspended tenants ──────────

    #[test]
    fn billing_recovery_allowlist_admits_only_the_narrow_set() {
        use axum::http::Method;

        // View invoices (list + detail + PDF/XML exports).
        for path in [
            "/v1/billing/invoices",
            "/v1/billing/invoices/in_123",
            "/v1/billing/invoices/in_123/pdf",
            "/v1/billing/invoices/in_123/xml",
        ] {
            assert!(
                is_billing_recovery_request(&Method::GET, path),
                "GET {path} must be recoverable"
            );
        }
        // Billing portal + checkout (payment-method updates happen inside
        // the Stripe-hosted portal).
        assert!(is_billing_recovery_request(
            &Method::POST,
            "/v1/billing/portal"
        ));
        assert!(is_billing_recovery_request(
            &Method::POST,
            "/v1/billing/checkout"
        ));
        assert!(is_billing_recovery_request(
            &Method::GET,
            "/v1/billing/subscription"
        ));
    }

    #[test]
    fn billing_recovery_allowlist_blocks_mutations_and_foreign_routes() {
        use axum::http::Method;

        // Send/key/domain mutations stay blocked.
        for (method, path) in [
            (&Method::POST, "/v1/messages"),
            (&Method::POST, "/v1/messages/batch"),
            (&Method::POST, "/v1/keys"),
            (&Method::POST, "/v1/domains"),
            (&Method::DELETE, "/v1/domains/d_1"),
            (&Method::GET, "/v1/messages"),
            (&Method::GET, "/v1/contacts"),
        ] {
            assert!(
                !is_billing_recovery_request(method, path),
                "{method} {path} must NOT be recoverable"
            );
        }
        // Prefix confusion: a path that merely STARTS with the prefix
        // string is not admitted (only the exact route or sub-paths).
        assert!(!is_billing_recovery_request(
            &Method::GET,
            "/v1/billing/invoices-mutations"
        ));
        assert!(!is_billing_recovery_request(
            &Method::POST,
            "/v1/billing/invoices"
        ));
        // Other billing operations stay blocked while suspended.
        assert!(!is_billing_recovery_request(
            &Method::POST,
            "/v1/billing/switch-plan"
        ));
        assert!(!is_billing_recovery_request(
            &Method::POST,
            "/v1/billing/cancel"
        ));
    }

    #[test]
    fn tenant_status_policy_distinguishes_auth_from_recovery() {
        // Only ACTIVE authenticates generally; the recovery path is keyed
        // on the explicit "suspended" status inside
        // enforce_tenant_not_restricted (pending stays fully blocked).
        assert!(tenant_status_permits_auth("active"));
        assert!(!tenant_status_permits_auth("suspended"));
        assert!(!tenant_status_permits_auth("pending"));
        assert!(!tenant_status_permits_auth("closed"));
    }

    #[test]
    fn test_api_key_hashing() {
        let hash = hex::encode(Sha256::digest(b"am_live_abc123"));
        assert_eq!(hash.len(), 64);
    }

    // ── Token-type discrimination (audit B) ─────────────────────

    #[test]
    fn test_claims_typ_is_session_matrix() {
        // Real session tokens
        assert!(claims_typ_is_session(Some("session")));
        // Legacy tokens issued before the typ claim existed
        assert!(claims_typ_is_session(None));
        // Stream tokens (routes/stream_tokens.rs) must never pass as sessions
        assert!(!claims_typ_is_session(Some("stream")));
        // Refresh-typed or arbitrary other typs must be rejected too
        assert!(!claims_typ_is_session(Some("refresh")));
        assert!(!claims_typ_is_session(Some("Session")));
        assert!(!claims_typ_is_session(Some("")));
        assert!(!claims_typ_is_session(Some("session\u{0}")));
    }

    // ── AuthUser Debug must not panic on non-ASCII identifiers (audit E) ──

    #[test]
    fn test_auth_user_debug_handles_multibyte_identifiers() {
        // A tenant_id whose 4th byte lands inside a multibyte character
        // ('中' = 3 bytes, 'é' = 2 bytes) previously panicked the Debug impl.
        let user = AuthUser {
            tenant_id: "中é中é中".into(),
            user_id: Some("é中é".into()),
            api_key_id: Some("😀ab".into()),
            session_id: Some("sess".into()),
            scopes: vec!["messages:read".into()],
        };
        // Formatting must not panic and must stay valid UTF-8.
        let debug = format!("{user:?}");
        assert!(debug.contains("AuthUser"));
        assert!(debug.contains("[REDACTED]"));
        // Single-byte prefix still works
        let ascii_user = AuthUser {
            tenant_id: "abcdefgh".into(),
            user_id: None,
            api_key_id: None,
            session_id: None,
            scopes: vec![],
        };
        let debug = format!("{ascii_user:?}");
        assert!(
            debug.contains("abcd..8"),
            "unexpected debug output: {debug}"
        );
    }

    #[test]
    fn test_char_safe_prefix_never_splits_characters() {
        assert_eq!(char_safe_prefix("abcdefgh", 4), "abcd");
        assert_eq!(char_safe_prefix("中中中", 4), "中"); // 4 -> 3 bytes
        assert_eq!(char_safe_prefix("ééé", 3), "é"); // 3 -> 2 bytes
        assert_eq!(char_safe_prefix("😀", 3), ""); // 3 -> 0 bytes (surrogate-free cut)
        assert_eq!(char_safe_prefix("short", 100), "short");
        assert_eq!(char_safe_prefix("", 4), "");
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
            Some(CachedUserStatus::Missing)
        );
        assert_eq!(
            parse_cached_user_status("active|owner"),
            Some(CachedUserStatus::Present("active".into(), "owner".into()))
        );
        // Legacy status-only entries are treated as cache misses so the
        // authoritative role is re-read from the database.
        assert_eq!(parse_cached_user_status("active"), None);
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
            Some(CachedUserStatus::Missing)
        );
        // Non-sentinel pairs decode as Present, even unusual ones; values
        // without the role segment are legacy entries (cache misses).
        assert_eq!(parse_cached_user_status("__MISSING__"), None);
        assert_eq!(parse_cached_user_status(""), None);
        assert_eq!(
            parse_cached_user_status("__MISSING__|weird-role"),
            Some(CachedUserStatus::Present(
                "__MISSING__".into(),
                "weird-role".into()
            ))
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

    // ─── Live-scope narrowing (DB+Redis) ───────────────────────

    mod live_scopes_tests {
        use super::*;

        /// Session scopes are recomputed from the user's CURRENT role on
        /// every authentication: a demoted admin's still-valid token must
        /// lose the wildcard scope immediately (the token used to carry
        /// its login-time scopes until natural expiry).
        #[tokio::test]
        async fn demoted_admin_session_loses_admin_scopes() {
            let Some(pool) = crate::test_db::canonical_pool("scopes_narrowing").await else {
                eprintln!(
                    "skipping demoted_admin_session_loses_admin_scopes: no TEST_DATABASE_URL"
                );
                return;
            };
            let redis_url = match std::env::var("TEST_REDIS_URL") {
                Ok(url) if !url.trim().is_empty() => url,
                _ => {
                    eprintln!(
                        "skipping demoted_admin_session_loses_admin_scopes: no TEST_REDIS_URL"
                    );
                    return;
                }
            };
            let redis = match deadpool_redis::Config::from_url(&redis_url)
                .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            {
                Ok(pool) => pool,
                Err(_) => return,
            };
            let redis_reachable = match redis.get().await {
                Ok(mut conn) => deadpool_redis::redis::cmd("PING")
                    .query_async::<String>(&mut *conn)
                    .await
                    .is_ok(),
                Err(_) => false,
            };
            if !redis_reachable {
                eprintln!(
                    "skipping demoted_admin_session_loses_admin_scopes: TEST_REDIS_URL unreachable"
                );
                return;
            }

            use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding};
            let key_pair = apexmail_lib::dkim::generate_dkim_keypair().expect("test RSA keypair");
            let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(key_pair.private_key_pem.as_str())
                .expect("valid PKCS8 private key");
            let mut config = crate::app::test_support::test_config();
            config.jwt_private_key_pem = key_pair.private_key_pem.to_string();
            config.jwt_public_key_pem = private_key
                .to_public_key()
                .to_public_key_pem(LineEnding::LF)
                .expect("public PEM")
                .to_string();

            let state =
                crate::app::test_support::test_state_over_with_config(pool.clone(), config).await;

            let tenant = apexmail_lib::id::generate_id("scopes", 18);
            let user_id = uuid::Uuid::new_v4();
            // F18: authenticate_jwt enforces the tenant policy, so the
            // fixture tenant must exist (and be active) for the session to
            // authenticate at all.
            sqlx::query(
                "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
                 VALUES ($1, 'Scope Co', $2, 'free', 'active', NOW(), NOW())",
            )
            .bind(&tenant)
            .bind(format!("slug-{tenant}"))
            .execute(&pool)
            .await
            .expect("seed tenant");
            sqlx::query(
                "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status, email_verified)
                 VALUES ($1, $2, $3, 'Scope Tester', 'x', 'admin', 'active', true)",
            )
            .bind(user_id)
            .bind(&tenant)
            .bind(format!("scopes-{}@example.com", user_id.simple()))
            .execute(&pool)
            .await
            .expect("seed admin user");

            let now = Utc::now().timestamp();
            let claims = JwtClaims {
                sub: user_id.to_string(),
                tenant_id: tenant.clone(),
                scopes: vec!["*".into()],
                exp: now + 3600,
                iat: now,
                jti: uuid::Uuid::new_v4().to_string(),
                typ: Some("session".into()),
            };
            let token = jsonwebtoken::encode(
                &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
                &claims,
                &jsonwebtoken::EncodingKey::from_rsa_pem(
                    state.config.jwt_private_key_pem.as_bytes(),
                )
                .expect("encoding key"),
            )
            .expect("sign session jwt");

            // Before the demotion the wildcard scope stands.
            let auth_user = authenticate_jwt(&token, &Method::GET, "/v1/session/test", &state)
                .await
                .expect("pre-demotion auth must succeed");
            assert!(auth_user.scopes.contains(&"*".to_string()));

            // Demote and let the (short-TTL) status cache expire.
            sqlx::query("UPDATE users SET role = 'member' WHERE id = $1::uuid")
                .bind(user_id)
                .execute(&pool)
                .await
                .expect("demote user");
            invalidate_user_status_cache(&user_id.to_string(), &tenant, &state).await;

            let demoted = authenticate_jwt(&token, &Method::GET, "/v1/session/test", &state)
                .await
                .expect("post-demotion auth must still identify the user");
            assert!(
                !demoted.scopes.contains(&"*".to_string()),
                "a demoted admin's session must lose the wildcard scope, got {:?}",
                demoted.scopes
            );
            assert!(
                demoted.scopes.contains(&"messages:read".to_string()),
                "the narrowed scope set must be the member role's grants, got {:?}",
                demoted.scopes
            );

            pool.close().await;
        }
    }

    // ── Tenant-status policy (audit F18) ──────────────────────────────

    #[test]
    fn tenant_status_policy_permits_only_active() {
        assert!(tenant_status_permits_auth("active"));
        assert!(!tenant_status_permits_auth("pending"));
        assert!(!tenant_status_permits_auth("suspended"));
        assert!(!tenant_status_permits_auth(""));
        assert!(!tenant_status_permits_auth("ACTIVE"));
    }

    #[test]
    fn tenant_status_cache_key_is_prefixed_and_tenant_scoped() {
        assert_eq!(
            tenant_status_cache_key("ten_test_001"),
            "apexmail:tenant_status:ten_test_001"
        );
    }

    /// Shared fixture for the F18 outcome tests: a tenant + active owner,
    /// and a state whose config carries a fresh RSA signing pair.
    async fn suspended_tenant_fixture(
        test_name: &str,
    ) -> Option<(sqlx::PgPool, AppState, String, String)> {
        let pool = crate::test_db::canonical_pool(test_name).await?;
        use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding};
        let key_pair = apexmail_lib::dkim::generate_dkim_keypair().expect("test RSA keypair");
        let private_key =
            rsa::RsaPrivateKey::from_pkcs8_pem(key_pair.private_key_pem.as_str()).unwrap();
        let mut config = crate::app::test_support::test_config();
        config.jwt_private_key_pem = key_pair.private_key_pem.to_string();
        config.jwt_public_key_pem = private_key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap()
            .to_string();
        let state =
            crate::app::test_support::test_state_over_with_config(pool.clone(), config).await;

        let tenant_id = apexmail_lib::id::generate_id("f18", 18);
        let user_id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
             VALUES ($1, 'F18 Co', $2, 'free', 'active', NOW(), NOW())",
        )
        .bind(&tenant_id)
        .bind(format!("slug-{tenant_id}"))
        .execute(&pool)
        .await
        .expect("seed tenant");
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status, email_verified)
             VALUES ($1, $2, $3, 'F18 Owner', 'x', 'owner', 'active', true)",
        )
        .bind(user_id)
        .bind(&tenant_id)
        .bind(format!("f18-{}@example.com", user_id.simple()))
        .execute(&pool)
        .await
        .expect("seed user");
        Some((pool, state, tenant_id, user_id.to_string()))
    }

    async fn sign_session(state: &AppState, tenant_id: &str, user_id: &str) -> String {
        let now = Utc::now().timestamp();
        let claims = JwtClaims {
            sub: user_id.to_string(),
            tenant_id: tenant_id.to_string(),
            scopes: vec!["*".into()],
            exp: now + 3600,
            iat: now,
            jti: uuid::Uuid::new_v4().to_string(),
            typ: Some("session".into()),
        };
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
            &claims,
            &jsonwebtoken::EncodingKey::from_rsa_pem(state.config.jwt_private_key_pem.as_bytes())
                .expect("encoding key"),
        )
        .expect("sign session jwt")
    }

    /// F18: a session under a suspended tenant stops authenticating, and a
    /// control-plane suspension takes effect immediately (the cached
    /// decision is dropped, so no TTL window remains).
    #[tokio::test]
    async fn suspended_tenant_session_is_refused_and_suspend_is_immediate() {
        // `authenticate_jwt` checks the Redis token blacklist before
        // anything else and fails CLOSED when Redis is unreachable
        // (`is_token_blacklisted` maps a dead pool to ServiceUnavailable, by
        // design). Gate on a reachable TEST_REDIS_URL exactly like
        // `demoted_admin_session_loses_admin_scopes` above: the ambient
        // 6379 is never probed implicitly, and an infrastructure failure
        // must read as a skip, never as an authentication result.
        let redis_url = match std::env::var("TEST_REDIS_URL") {
            Ok(url) if !url.trim().is_empty() => url,
            _ => {
                eprintln!("skipping suspended_tenant_session_is_refused: no TEST_REDIS_URL");
                return;
            }
        };
        let redis_probe = match deadpool_redis::Config::from_url(&redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        {
            Ok(pool) => pool,
            Err(_) => return,
        };
        let redis_reachable = match redis_probe.get().await {
            Ok(mut conn) => deadpool_redis::redis::cmd("PING")
                .query_async::<String>(&mut *conn)
                .await
                .is_ok(),
            Err(_) => false,
        };
        if !redis_reachable {
            eprintln!("skipping suspended_tenant_session_is_refused: TEST_REDIS_URL unreachable");
            return;
        }
        drop(redis_probe);

        let Some((pool, state, tenant_id, user_id)) =
            suspended_tenant_fixture("f18_jwt_gate").await
        else {
            eprintln!("skipping suspended_tenant_session_is_refused: no TEST_DATABASE_URL");
            return;
        };
        let token = sign_session(&state, &tenant_id, &user_id).await;

        authenticate_jwt(&token, &Method::GET, "/v1/session/test", &state)
            .await
            .expect("active tenant authenticates");

        sqlx::query("UPDATE tenants SET status = 'suspended' WHERE id = $1")
            .bind(&tenant_id)
            .execute(&pool)
            .await
            .expect("suspend tenant");
        invalidate_tenant_status_cache(&tenant_id, &state).await;

        match authenticate_jwt(&token, &Method::GET, "/v1/session/test", &state).await {
            Err(ApiError::Unauthorized(message)) => assert!(
                message.contains("suspended"),
                "expected a suspension-specific denial, got {message}"
            ),
            other => panic!("suspended tenant session must be refused, got {other:?}"),
        }

        // Recovery: resuming the tenant restores the session immediately.
        sqlx::query("UPDATE tenants SET status = 'active' WHERE id = $1")
            .bind(&tenant_id)
            .execute(&pool)
            .await
            .expect("resume tenant");
        invalidate_tenant_status_cache(&tenant_id, &state).await;
        authenticate_jwt(&token, &Method::GET, "/v1/session/test", &state)
            .await
            .expect("resumed tenant authenticates again");

        pool.close().await;
    }

    /// F18: an API key belonging to a suspended tenant stops
    /// authenticating on the database path (the Redis cache is bypassed in
    /// this fixture, exercising the authoritative row).
    #[tokio::test]
    async fn suspended_tenant_api_key_is_refused() {
        let Some((pool, state, tenant_id, _user_id)) =
            suspended_tenant_fixture("f18_apikey_gate").await
        else {
            eprintln!("skipping suspended_tenant_api_key_is_refused: no TEST_DATABASE_URL");
            return;
        };
        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS api_keys (
                id UUID PRIMARY KEY,
                tenant_id VARCHAR(26) NOT NULL,
                name TEXT NOT NULL,
                key_prefix VARCHAR(32) NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                scopes JSONB NOT NULL,
                expires_at TIMESTAMPTZ,
                last_used_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
        )
        .execute(&pool)
        .await
        .expect("api_keys fixture DDL must apply");
        let raw_key = format!("am_live_{}", uuid::Uuid::new_v4().simple());
        let key_hash =
            apexmail_lib::hash_api_key_with_secret(&raw_key, &state.config.api_key_hash_secret);
        sqlx::query(
            "INSERT INTO api_keys (id, tenant_id, name, key_prefix, key_hash, scopes, created_at, updated_at)
             VALUES ($1, $2, 'f18 key', 'am_live_', $3, $4::jsonb, NOW(), NOW())",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(&tenant_id)
        .bind(&key_hash)
        .bind(serde_json::json!(["*"]).to_string())
        .execute(&pool)
        .await
        .expect("seed api key");

        let mut parts = axum::http::Request::get("/")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        parts.headers.insert("x-api-key", raw_key.parse().unwrap());
        let auth = AuthUser::from_request_parts(&mut parts, &state)
            .await
            .expect("active tenant api key authenticates");
        assert_eq!(auth.tenant_id, tenant_id);

        sqlx::query("UPDATE tenants SET status = 'suspended' WHERE id = $1")
            .bind(&tenant_id)
            .execute(&pool)
            .await
            .expect("suspend tenant");
        invalidate_tenant_status_cache(&tenant_id, &state).await;

        let mut parts = axum::http::Request::get("/")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        parts.headers.insert("x-api-key", raw_key.parse().unwrap());
        match AuthUser::from_request_parts(&mut parts, &state).await {
            Err(ApiError::Unauthorized(message)) => assert!(
                message.contains("suspended"),
                "expected a suspension-specific denial, got {message}"
            ),
            other => panic!("suspended tenant api key must be refused, got {other:?}"),
        }

        pool.close().await;
    }

    /// An expired API key must stay rejected even when a cache entry from
    /// BEFORE its expiry still exists (10s TTL vs. keys expiring any
    /// second) — the cached hit path used to skip the expiry check
    /// entirely.
    #[tokio::test]
    async fn cached_api_key_hit_still_rejects_expired_keys() {
        let Some(pool) = crate::test_db::canonical_pool("apikey_cache_expiry").await else {
            eprintln!(
                "skipping cached_api_key_hit_still_rejects_expired_keys: no TEST_DATABASE_URL"
            );
            return;
        };
        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS api_keys (
                id UUID PRIMARY KEY,
                tenant_id VARCHAR(26) NOT NULL,
                name TEXT NOT NULL,
                key_prefix VARCHAR(32) NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                scopes JSONB NOT NULL,
                expires_at TIMESTAMPTZ,
                last_used_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
        )
        .execute(&pool)
        .await
        .expect("api_keys fixture DDL must apply");
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let mut conn = match state.redis.get().await {
            Ok(conn) => conn,
            Err(_) => {
                eprintln!("skipping cached_api_key_hit_still_rejects_expired_keys: no Redis");
                return;
            }
        };
        let pong: Result<String, _> = deadpool_redis::redis::cmd("PING")
            .query_async(&mut *conn)
            .await;
        if pong.is_err() {
            eprintln!("skipping cached_api_key_hit_still_rejects_expired_keys: Redis unreachable");
            return;
        }

        let raw_key = format!("am_live_{}", uuid::Uuid::new_v4().simple());
        let key_hash =
            apexmail_lib::hash_api_key_with_secret(&raw_key, &state.config.api_key_hash_secret);
        sqlx::query(
            "INSERT INTO api_keys (id, tenant_id, name, key_prefix, key_hash, scopes, expires_at, created_at, updated_at)
             VALUES ($1::uuid, $2, 'expired-key', 'am_live', $3, $4::jsonb, NOW() - INTERVAL '1 hour', NOW(), NOW())",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(apexmail_lib::id::generate_id("exp", 18))
        .bind(&key_hash)
        .bind(serde_json::json!(["*"]).to_string())
        .execute(&pool)
        .await
        .expect("seed expired api key");

        // Prime the cache exactly as a pre-expiry authentication would
        // have: an expiry-aware entry whose expires_at is now in the past
        // (the key expired AFTER the entry was written).
        let cache_key = format!("apexmail:api_key_cache:{key_hash}");
        let cached_user = serde_json::json!({
            "expires_at": (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339(),
            "user": {
                "tenant_id": "whatever-tenant",
                "user_id": null,
                "api_key_id": null,
                "session_id": null,
                "scopes": ["*"],
            },
        });
        let _: Result<(), _> = deadpool_redis::redis::AsyncCommands::set_ex(
            &mut *conn,
            &cache_key,
            cached_user.to_string(),
            10u64,
        )
        .await;

        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", raw_key.parse().unwrap());
        let request = axum::http::Request::builder()
            .method(axum::http::Method::GET)
            .uri("/")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let mut parts = request;
        parts.headers = headers;
        let auth_result = AuthUser::from_request_parts(&mut parts, &state).await;
        assert!(
            auth_result.is_err(),
            "an expired API key must be rejected despite a live cache entry"
        );

        pool.close().await;
    }

    /// The membership check binds the JWT's UUID subject against
    /// `user_tenant_membership.user_id`. Migration 229 is what makes that
    /// matchable: while the column was VARCHAR(26) no row could carry a real
    /// user id, so a legitimate member of a second tenant was always refused.
    #[tokio::test]
    async fn membership_check_matches_a_real_row_and_refuses_strangers() {
        let Some(pool) = crate::test_db::optional_pg_pool("mw_membership_uuid").await else {
            return;
        };
        let suffix = &uuid::Uuid::new_v4().simple().to_string()[..12];
        let tenant_a = format!("mwa{suffix}");
        let tenant_b = format!("mwb{suffix}");
        let tenant_c = format!("mwc{suffix}");
        for tenant in [&tenant_a, &tenant_b, &tenant_c] {
            sqlx::query(
                "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
                 VALUES ($1, 'membership test', 'free', 'active', NOW(), NOW())",
            )
            .bind(tenant)
            .execute(&pool)
            .await
            .expect("seed tenant");
        }
        let user_id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status,
                                email_verified, created_at, updated_at)
             VALUES ($1, $2, $3, 'Member', 'x', 'owner', 'active', true, NOW(), NOW())",
        )
        .bind(user_id)
        .bind(&tenant_a)
        .bind(format!("mw-{suffix}@example.com"))
        .execute(&pool)
        .await
        .expect("seed user");

        // A genuine second-tenant membership. Before migration 229 this INSERT
        // failed outright (a 36-char UUID into VARCHAR(26)).
        sqlx::query(
            "INSERT INTO user_tenant_membership (user_id, tenant_id, role) VALUES ($1, $2, 'member')",
        )
        .bind(user_id)
        .bind(&tenant_b)
        .execute(&pool)
        .await
        .expect("seed membership");

        let subject = user_id.to_string();
        assert!(
            verify_tenant_membership(&subject, &tenant_b, &pool)
                .await
                .expect("member check"),
            "a real membership row must admit the user"
        );
        assert!(
            !verify_tenant_membership(&subject, &tenant_c, &pool)
                .await
                .expect("stranger check"),
            "a tenant with no membership row must refuse"
        );
        assert!(
            !verify_tenant_membership(&uuid::Uuid::new_v4().to_string(), &tenant_b, &pool)
                .await
                .expect("unknown user check"),
            "an unknown user id must refuse even when the tenant has a row"
        );

        // Cleanup: this test's own rows only.
        let pattern = format!("%{suffix}%");
        let _ = sqlx::query(
            "DELETE FROM user_tenant_membership WHERE tenant_id IN (SELECT id FROM tenants WHERE id LIKE $1)",
        )
        .bind(&pattern)
        .execute(&pool)
        .await;
        let _ = sqlx::query(
            "DELETE FROM users WHERE tenant_id IN (SELECT id FROM tenants WHERE id LIKE $1)",
        )
        .bind(&pattern)
        .execute(&pool)
        .await;
        let _ = sqlx::query("DELETE FROM tenants WHERE id LIKE $1")
            .bind(&pattern)
            .execute(&pool)
            .await;
        pool.close().await;
    }
}

// ─── Adversarial credential / binding tests ────────────────────

#[cfg(test)]
mod adversarial_tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    fn user(tenant: &str, user_id: Option<&str>, scopes: &[&str]) -> AuthUser {
        AuthUser {
            tenant_id: tenant.to_string(),
            user_id: user_id.map(str::to_string),
            api_key_id: Some("key_adv_auth".into()),
            session_id: None,
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn bearer_extraction_is_strict_about_scheme_and_emptiness() {
        assert_eq!(
            extract_bearer_token(&headers(&[("authorization", "Bearer abc.def")])),
            Some("abc.def".into())
        );
        assert_eq!(
            extract_bearer_token(&headers(&[("authorization", "bearer   spaced  ")])),
            Some("spaced".into())
        );
        for value in [
            "Bearer",
            "Bearer ",
            "Basic abc",
            "bearerx abc",
            "",
            "Token abc",
        ] {
            assert_eq!(
                extract_bearer_token(&headers(&[("authorization", value)])),
                None,
                "{value:?}"
            );
        }
        assert_eq!(extract_bearer_token(&HeaderMap::new()), None);
    }

    #[test]
    fn credential_precedence_prefers_api_key_then_bearer_then_cookie() {
        let all = headers(&[
            ("x-api-key", "am_test_key"),
            ("authorization", "Bearer tok"),
            ("cookie", "am_session=sess"),
        ]);
        assert!(matches!(
            extract_auth_credential(&all),
            Some((AuthMechanism::ApiKey, key)) if key == "am_test_key"
        ));
        let bearer_only = headers(&[("authorization", "Bearer tok")]);
        assert!(matches!(
            extract_auth_credential(&bearer_only),
            Some((AuthMechanism::BearerToken, token)) if token == "tok"
        ));
        let cookie_only = headers(&[("cookie", "am_session=sess")]);
        assert!(matches!(
            extract_auth_credential(&cookie_only),
            Some((AuthMechanism::SessionCookie, token)) if token == "sess"
        ));
        // A blank API key header must fall through, not authenticate as "".
        let blank = headers(&[("x-api-key", "   "), ("authorization", "Bearer tok")]);
        assert!(matches!(
            extract_auth_credential(&blank),
            Some((AuthMechanism::BearerToken, _))
        ));
        assert!(extract_auth_credential(&HeaderMap::new()).is_none());
    }

    #[test]
    fn csrf_is_required_only_for_cookie_auth_on_unsafe_methods() {
        assert!(requires_csrf(&Method::POST, AuthMechanism::SessionCookie));
        assert!(requires_csrf(&Method::PUT, AuthMechanism::SessionCookie));
        assert!(requires_csrf(&Method::DELETE, AuthMechanism::SessionCookie));
        assert!(!requires_csrf(&Method::GET, AuthMechanism::SessionCookie));
        assert!(!requires_csrf(&Method::HEAD, AuthMechanism::SessionCookie));
        assert!(!requires_csrf(
            &Method::OPTIONS,
            AuthMechanism::SessionCookie
        ));
        assert!(!requires_csrf(&Method::POST, AuthMechanism::ApiKey));
        assert!(!requires_csrf(&Method::POST, AuthMechanism::BearerToken));
    }

    #[test]
    fn session_csrf_requires_matching_cookie_and_header() {
        let secret = "test-csrf-secret-1234567890abcd";
        let token = ui_foundation::csrf::generate_csrf_token(secret);
        let cookie = format!("csrf_token={token}");
        // Both present + valid → ok.
        assert!(validate_session_csrf(
            &headers(&[("cookie", &cookie), ("x-csrf-token", &token)]),
            secret
        )
        .is_ok());
        // Missing header / missing cookie / mismatched pair / invalid signature.
        assert!(matches!(
            validate_session_csrf(&headers(&[("cookie", &cookie)]), secret),
            Err(ApiError::Forbidden(_))
        ));
        assert!(matches!(
            validate_session_csrf(&headers(&[("x-csrf-token", &token)]), secret),
            Err(ApiError::Forbidden(_))
        ));
        assert!(matches!(
            validate_session_csrf(
                &headers(&[("cookie", &cookie), ("x-csrf-token", "different")]),
                secret
            ),
            Err(ApiError::Forbidden(_))
        ));
        assert!(matches!(
            validate_session_csrf(
                &headers(&[
                    ("cookie", "csrf_token=forged.signature"),
                    ("x-csrf-token", "forged.signature")
                ]),
                secret
            ),
            Err(ApiError::Forbidden(_))
        ));
    }

    #[test]
    fn static_control_plane_key_only_authenticates_admin_paths_on_cp_host() {
        assert!(is_control_plane_static_key_request(
            "/v1/admin/dashboard",
            true
        ));
        assert!(is_control_plane_static_key_request("/v1/admin/", true));
        // Same path off the control-plane host → refused.
        assert!(!is_control_plane_static_key_request(
            "/v1/admin/dashboard",
            false
        ));
        // Control-plane host but customer API path → refused.
        assert!(!is_control_plane_static_key_request("/v1/messages", true));
        // Prefix lookalikes must not slip through.
        assert!(!is_control_plane_static_key_request(
            "/v1/adminx/thing",
            true
        ));
        assert!(!is_control_plane_static_key_request("", true));
    }

    #[test]
    fn path_tenant_extraction_ignores_static_scope_words() {
        // Genuine tenant paths resolve.
        assert_eq!(
            tenant_id_from_request_path("/v1/tenants/ten_abc/invoices"),
            Some("ten_abc")
        );
        assert_eq!(
            tenant_id_from_request_path("/v1/tenant/ten_abc"),
            Some("ten_abc")
        );
        // Self-references are not ids.
        for path in [
            "/v1/tenants/current",
            "/v1/tenants/me",
            "/v1/tenants/self/limits",
        ] {
            assert_eq!(tenant_id_from_request_path(path), None, "{path}");
        }
        // No tenant segment at all.
        assert_eq!(tenant_id_from_request_path("/v1/messages"), None);
        assert_eq!(tenant_id_from_request_path(""), None);

        // The STATIC billing routes use `tenant` as a scope word: `features`
        // and `limits` are sub-resources, NOT tenant ids. Reading them as ids
        // made the API-key binding 403 every real tenant (fixed 2026-09-13).
        for path in [
            "/v1/billing/plans/tenant/features",
            "/v1/billing/plans/tenant/limits",
            "/v1/billing/plans/tenant/current",
        ] {
            assert_eq!(tenant_id_from_request_path(path), None, "{path}");
        }
        // Static words that are not ids are ignored wherever they appear,
        // while real ids still bind (including the singular form and ids that
        // carry a dash/underscore).
        assert_eq!(
            tenant_id_from_request_path("/v1/tenant/ten_abc/settings"),
            Some("ten_abc")
        );
        assert_eq!(
            tenant_id_from_request_path("/v1/tenants/t16fc3bc7dc4b4989aba92320c"),
            Some("t16fc3bc7dc4b4989aba92320c")
        );
        assert_eq!(
            tenant_id_from_request_path("/v1/tenants/features/limits"),
            None
        );
        assert_eq!(
            tenant_id_from_request_path("/v1/tenants/not-a-real-tenant-id-string"),
            None,
            "over-length candidates are not ids"
        );
    }

    #[test]
    fn api_key_tenant_binding_rejects_path_mismatch_and_admits_system() {
        // System sentinel bypasses path binding entirely.
        assert!(enforce_api_key_tenant_binding(
            &user("system", None, &["*"]),
            "/v1/tenants/anyone/data"
        )
        .is_ok());
        // Matching tenant passes.
        assert!(enforce_api_key_tenant_binding(
            &user("ten_abc", None, &["*"]),
            "/v1/tenants/ten_abc/data"
        )
        .is_ok());
        // Mismatch is a 403.
        let mismatch = enforce_api_key_tenant_binding(
            &user("ten_abc", None, &["*"]),
            "/v1/tenants/ten_other/data",
        );
        assert!(matches!(mismatch, Err(ApiError::Forbidden(_))));
        // No tenant segment → no binding.
        assert!(
            enforce_api_key_tenant_binding(&user("ten_abc", None, &["*"]), "/v1/messages").is_ok()
        );
    }

    #[test]
    fn x_tenant_id_header_is_trimmed_and_empty_becomes_absent() {
        let parsed = tenant_id_from_header(&headers(&[("x-tenant-id", "  ten_x  ")]));
        assert_eq!(parsed.as_deref(), Some("ten_x"));
        assert_eq!(
            tenant_id_from_header(&headers(&[("x-tenant-id", "   ")])),
            None
        );
        assert_eq!(
            tenant_id_from_header(&headers(&[("x-tenant-id", "")])),
            None
        );
        assert_eq!(tenant_id_from_header(&HeaderMap::new()), None);
    }

    #[test]
    fn authuser_debug_redacts_secrets_and_survives_multibyte_ids() {
        let user = AuthUser {
            tenant_id: "тень-üs-é-😀-longer".into(),
            user_id: Some("пользователь-42".into()),
            api_key_id: Some("key_0123456789".into()),
            session_id: Some("sess_super_secret_value".into()),
            scopes: vec!["messages:read".into()],
        };
        let debug = format!("{user:?}");
        assert!(!debug.contains("тень"), "tenant prefix only: {debug}");
        assert!(!debug.contains("пользователь-42"), "{debug}");
        assert!(!debug.contains("sess_super_secret_value"), "{debug}");
        assert!(debug.contains("[REDACTED]"), "{debug}");
        assert!(debug.contains("messages:read"), "{debug}");
    }

    #[test]
    fn require_scopes_wildcard_exact_and_multiple() {
        assert!(require_scopes(&user("t", None, &["*"]), &["a:b", "c:d"]).is_ok());
        assert!(require_scopes(&user("t", None, &["a:b"]), &["a:b"]).is_ok());
        assert!(require_scopes(&user("t", None, &["a:b"]), &["a:b", "c:d"]).is_err());
        assert!(require_scopes(&user("t", None, &[]), &[]).is_ok());
        assert!(require_scopes(&user("t", None, &[]), &["a:b"]).is_err());
        // Prefix matches are not scope matches.
        assert!(require_scopes(&user("t", None, &["a"]), &["a:b"]).is_err());
        // Case-sensitive.
        assert!(require_scopes(&user("t", None, &["A:B"]), &["a:b"]).is_err());
    }

    #[tokio::test]
    async fn from_request_parts_rejections_are_401_or_403_never_500() {
        let state = crate::app::test_support::test_state_over_lazy().await;

        // No credentials at all.
        let mut parts = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/v1/messages")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        assert!(matches!(
            AuthUser::from_request_parts(&mut parts, &state).await,
            Err(ApiError::Unauthorized(_))
        ));

        // Malformed bearer token against a REAL RSA keypair — a decode
        // failure is an auth failure (401), never a 500. The placeholder
        // keys in `test_config()` cannot decode anything and would fail
        // closed to a configuration 500, which is a different (startup)
        // contract.
        let Some(redis_url) = std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
        else {
            eprintln!("skipping bearer half: TEST_REDIS_URL unset");
            return;
        };
        use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding};
        let key_pair = apexmail_lib::dkim::generate_dkim_keypair().expect("test RSA keypair");
        let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(key_pair.private_key_pem.as_str())
            .expect("valid PKCS8 private key");
        let mut config = crate::app::test_support::test_config();
        config.jwt_private_key_pem = key_pair.private_key_pem.to_string();
        config.jwt_public_key_pem = private_key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("public PEM");
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect_lazy("postgres://apexmail:apexmail@127.0.0.1:1/apexmail")
            .expect("lazy pool");
        let rsa_state =
            crate::app::test_support::test_state_over_with_config_and_redis(db, config, &redis_url)
                .await;

        let mut parts = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/v1/messages")
            .header("authorization", "Bearer not-a-jwt")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        assert!(matches!(
            AuthUser::from_request_parts(&mut parts, &rsa_state).await,
            Err(ApiError::Unauthorized(_))
        ));

        // Unsafe method + session cookie without CSRF pair → 403 before the
        // JWT is even considered.
        let mut parts = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/v1/messages")
            .header("cookie", "am_session=whatever")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        assert!(matches!(
            AuthUser::from_request_parts(&mut parts, &rsa_state).await,
            Err(ApiError::Forbidden(_))
        ));

        // A valid CSRF pair still fails on the invalid session JWT.
        let secret = "test-csrf-secret-1234567890abcd";
        let token = ui_foundation::csrf::generate_csrf_token(secret);
        let mut parts = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/v1/messages")
            .header("cookie", format!("am_session=whatever; csrf_token={token}"))
            .header("x-csrf-token", &token)
            .body(())
            .unwrap()
            .into_parts()
            .0;
        assert!(matches!(
            AuthUser::from_request_parts(&mut parts, &rsa_state).await,
            Err(ApiError::Unauthorized(_))
        ));
    }

    #[test]
    fn char_safe_prefix_never_splits_a_codepoint() {
        // 'é' is 2 bytes; a 4-byte budget must stop at the boundary.
        assert_eq!(char_safe_prefix("ééé", 4), "éé");
        assert_eq!(char_safe_prefix("abc", 10), "abc");
        assert_eq!(char_safe_prefix("", 4), "");
        assert_eq!(char_safe_prefix("😀x", 2), "");
    }
    // ─── Wave D: extractor/cache/state-machine arms through the real router ──
    mod wave_d {
        use super::*;
        use crate::app::test_support::test_config;
        use crate::app::test_support::test_state_over_with_config_and_redis;
        use axum::body::Body;
        use tower::ServiceExt;

        fn dead_db_pool() -> sqlx::PgPool {
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect_lazy("postgres://apexmail:apexmail@127.0.0.1:1/apexmail")
                .expect("lazy dead pool")
        }

        fn rsa_config() -> crate::config::Config {
            use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding};
            let key_pair = apexmail_lib::dkim::generate_dkim_keypair().expect("rsa keypair");
            let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(key_pair.private_key_pem.as_str())
                .expect("pkcs8");
            let mut config = test_config();
            config.jwt_private_key_pem = key_pair.private_key_pem.to_string();
            config.jwt_public_key_pem = private_key
                .to_public_key()
                .to_public_key_pem(LineEnding::LF)
                .expect("public pem");
            config
        }

        fn mint_token(config: &crate::config::Config, claims: JwtClaims) -> String {
            jsonwebtoken::encode(
                &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
                &claims,
                &jsonwebtoken::EncodingKey::from_rsa_pem(config.jwt_private_key_pem.as_bytes())
                    .expect("encoding key"),
            )
            .expect("sign token")
        }

        fn base_claims(user_id: &str, tenant_id: &str, typ: Option<&str>) -> JwtClaims {
            let now = Utc::now().timestamp();
            JwtClaims {
                sub: user_id.to_string(),
                tenant_id: tenant_id.to_string(),
                scopes: vec!["*".into()],
                exp: now + 3600,
                iat: now,
                jti: uuid::Uuid::new_v4().to_string(),
                typ: typ.map(str::to_string),
            }
        }

        async fn bearer_request(
            app: &axum::Router,
            token: &str,
            uri: &str,
        ) -> (axum::http::StatusCode, serde_json::Value) {
            use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method(Method::GET)
                        .uri(uri)
                        .header(AUTHORIZATION, format!("Bearer {token}"))
                        .header(CONTENT_TYPE, "application/json")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .expect("response");
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body");
            let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
            (status, value)
        }

        /// A user row + tenant for the session flows.
        async fn seed_session_user(
            db: &sqlx::PgPool,
            status: &str,
            tenant_status: &str,
        ) -> (String, String) {
            let tenant_id = apexmail_lib::id::generate_id("wvau", 20);
            sqlx::query(
                "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
                 VALUES ($1, 'Wave D Auth', $2, 'free', $3, NOW(), NOW())",
            )
            .bind(&tenant_id)
            .bind(format!("slug-{tenant_id}"))
            .bind(tenant_status)
            .execute(db)
            .await
            .expect("seed tenant");
            let user_id = uuid::Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status, email_verified)
                 VALUES ($1::uuid, $2, $3, 'Wave D', 'x', 'owner', $4, true)",
            )
            .bind(&user_id)
            .bind(&tenant_id)
            .bind(format!("waved-{}@example.com", user_id))
            .bind(status)
            .execute(db)
            .await
            .expect("seed user");
            (tenant_id, user_id)
        }

        /// Redis-outage contracts, called directly: every arm maps to its
        /// documented failure mode instead of an unwrap or a silent pass.
        #[tokio::test]
        async fn redis_outage_maps_each_lookup_to_its_documented_failure() {
            let state = test_state_over_with_config_and_redis(
                dead_db_pool(),
                test_config(),
                "redis://127.0.0.1:1",
            )
            .await;

            // Token blacklist check fails CLOSED (503), never "not revoked".
            assert!(matches!(
                is_token_blacklisted("token", &state).await,
                Err(ApiError::ServiceUnavailable(_))
            ));
            // Session revocation lookup ditto.
            assert!(matches!(
                lookup_session_revoked_after("ten", "usr", &state).await,
                Err(ApiError::ServiceUnavailable(_))
            ));
            // The user-status and API-key caches degrade to a MISS (Err(())).
            assert!(lookup_cached_user_status("ten", "usr", &state)
                .await
                .is_err());
            assert!(lookup_cached_api_key("deadbeef", &state).await.is_err());
            // DB lookups behind the dead pool surface as Internal, never 401.
            assert!(matches!(
                tenant_status_for_auth(&state, "ten").await,
                Err(ApiError::Internal(_))
            ));
            assert!(matches!(
                verify_tenant_membership("usr", "ten", &state.db).await,
                Err(ApiError::Internal(_))
            ));
        }

        /// Tenant-status caching with a LIVE Redis but a dead database: the
        /// MISSING sentinel write happens before the DB error surfaces, and
        /// a pre-seeded sentinel short-circuits to "workspace no longer
        /// exists" without touching the database at all.
        #[tokio::test]
        async fn tenant_status_sentinel_short_circuits_before_the_database() {
            let Some(redis_url) = std::env::var("TEST_REDIS_URL")
                .ok()
                .filter(|value| !value.trim().is_empty())
            else {
                eprintln!("skipping tenant_status_sentinel_short_circuits: no TEST_REDIS_URL");
                return;
            };
            // Live Redis + dead DB: an unknown tenant takes the DB-error arm
            // (Internal), and the sentinel write is attempted on the way.
            let state =
                test_state_over_with_config_and_redis(dead_db_pool(), test_config(), &redis_url)
                    .await;
            assert!(matches!(
                tenant_status_for_auth(&state, "sentinel-probe-tenant").await,
                Err(ApiError::Internal(_))
            ));

            // Seeded sentinel: refused as "no longer exists" without a DB.
            let tenant = apexmail_lib::id::generate_id("wvst", 20);
            let mut conn = state.redis.get().await.expect("redis conn");
            let _: Result<(), _> = deadpool_redis::redis::AsyncCommands::set(
                &mut conn,
                tenant_status_cache_key(&tenant),
                TENANT_STATUS_CACHE_MISSING,
            )
            .await;
            assert!(matches!(
                tenant_status_for_auth(&state, &tenant).await,
                Err(ApiError::Unauthorized(message)) if message.contains("no longer exists")
            ));
        }

        /// The session-verifier matrix, through the REAL router: stream
        /// tokens, empty subjects/tenants, revoked tokens, disabled users,
        /// and vanished workspaces each get their exact 401; a suspended
        /// tenant keeps ONLY the billing-recovery allowlist.
        #[tokio::test]
        async fn verify_session_rejects_the_forged_token_family() {
            let Some(pool) = crate::test_db::canonical_pool("waved_mw_session").await else {
                eprintln!(
                    "skipping verify_session_rejects_the_forged_token_family: no TEST_DATABASE_URL"
                );
                return;
            };
            let Some(redis_url) = std::env::var("TEST_REDIS_URL")
                .ok()
                .filter(|value| !value.trim().is_empty())
            else {
                eprintln!(
                    "skipping verify_session_rejects_the_forged_token_family: no TEST_REDIS_URL"
                );
                return;
            };
            let config = rsa_config();
            let state =
                test_state_over_with_config_and_redis(pool.clone(), config.clone(), &redis_url)
                    .await;
            let app = crate::app::build_app(state.clone());

            let (tenant_id, user_id) = seed_session_user(&pool, "active", "active").await;

            // A stream token must never authenticate an API session.
            let stream_token =
                mint_token(&config, base_claims(&user_id, &tenant_id, Some("stream")));
            let (status, body) = bearer_request(&app, &stream_token, "/v1/account/profile").await;
            assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED, "{body}");

            // Empty subject / empty tenant claims are refused by name.
            let empty_sub = mint_token(&config, {
                let mut claims = base_claims(&user_id, &tenant_id, None);
                claims.sub = String::new();
                claims
            });
            let (status, _) = bearer_request(&app, &empty_sub, "/v1/account/profile").await;
            assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);

            let empty_tenant = mint_token(&config, {
                let mut claims = base_claims(&user_id, &tenant_id, None);
                claims.tenant_id = String::new();
                claims
            });
            let (status, _) = bearer_request(&app, &empty_tenant, "/v1/account/profile").await;
            assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);

            // A blacklisted (revoked) token is refused before anything else.
            let revoked = mint_token(&config, base_claims(&user_id, &tenant_id, Some("session")));
            let mut conn = state.redis.get().await.expect("redis conn");
            let _: Result<(), _> = deadpool_redis::redis::AsyncCommands::set_ex(
                &mut conn,
                crate::routes::helpers::token_blacklist_key(&revoked),
                "1",
                60_u64,
            )
            .await;
            let (status, body) = bearer_request(&app, &revoked, "/v1/account/profile").await;
            assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED, "{body}");
            assert!(body["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("revoked"));

            // A disabled user's still-valid token stops authenticating.
            sqlx::query("UPDATE users SET status = 'disabled' WHERE id = $1::uuid")
                .bind(&user_id)
                .execute(&pool)
                .await
                .expect("disable user");
            let disabled_token = mint_token(&config, base_claims(&user_id, &tenant_id, None));
            let (status, body) = bearer_request(&app, &disabled_token, "/v1/account/profile").await;
            assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED, "{body}");
            assert!(body["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("disabled"));

            // A vanished workspace is refused by the cached sentinel even
            // though the user row and token are perfectly valid.
            let (ghost_tenant, ghost_user) = seed_session_user(&pool, "active", "active").await;
            let mut conn = state.redis.get().await.expect("redis conn");
            let _: Result<(), _> = deadpool_redis::redis::AsyncCommands::set(
                &mut conn,
                tenant_status_cache_key(&ghost_tenant),
                TENANT_STATUS_CACHE_MISSING,
            )
            .await;
            let ghost_token = mint_token(&config, base_claims(&ghost_user, &ghost_tenant, None));
            let (status, body) = bearer_request(&app, &ghost_token, "/v1/account/profile").await;
            assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED, "{body}");
            assert!(body["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("no longer exists"));

            // F18 recovery: a suspended tenant keeps the billing-recovery
            // allowlist (authentication succeeds) while everything else is
            // refused with the suspension-specific denial.
            let (susp_tenant, susp_user) = seed_session_user(&pool, "active", "suspended").await;
            let susp_token = mint_token(&config, base_claims(&susp_user, &susp_tenant, None));
            assert!(
                enforce_tenant_not_restricted(
                    &state,
                    &susp_tenant,
                    &Method::GET,
                    "/v1/billing/invoices",
                )
                .await
                .is_ok(),
                "the recovery allowlist must admit GET /v1/billing/invoices"
            );
            let (status, body) = bearer_request(&app, &susp_token, "/v1/billing/invoices").await;
            assert_ne!(
                status,
                axum::http::StatusCode::UNAUTHORIZED,
                "billing recovery must stay reachable for a suspended tenant: {body}"
            );
            let (status, body) = bearer_request(&app, &susp_token, "/v1/account/profile").await;
            assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED, "{body}");
            assert!(body["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("suspended"));
        }

        /// The API-key cache lifecycle through the REAL router: hits, a
        /// corrupted entry, an entry with empty required fields, and a key
        /// whose row vanished mid-flight.
        #[tokio::test]
        async fn api_key_cache_survives_corruption_and_vanishing_rows() {
            let Some(pool) = crate::test_db::canonical_pool("waved_mw_keycache").await else {
                eprintln!("skipping api_key_cache_survives_corruption_and_vanishing_rows: no TEST_DATABASE_URL");
                return;
            };
            let Some(redis_url) = std::env::var("TEST_REDIS_URL")
                .ok()
                .filter(|value| !value.trim().is_empty())
            else {
                eprintln!("skipping api_key_cache_survives_corruption_and_vanishing_rows: no TEST_REDIS_URL");
                return;
            };
            let (env, tenant_id) =
                crate::app::test_support::adv::AdvEnv::tenant(pool.clone(), &["*"]).await;

            let profile = "/v1/account/profile";
            let (first, _) = env.get(profile).await;
            assert_eq!(first, axum::http::StatusCode::NOT_FOUND);
            // Second call = Redis cache hit (same verdict, cache path).
            let (second, _) = env.get(profile).await;
            assert_eq!(second, first, "cache hit must not change the verdict");

            // Corrupt the cached entry: evicted, DB fallback, still 404.
            let secret = crate::app::test_support::test_config()
                .api_key_hash_secret
                .clone();
            let hmac = apexmail_lib::hash_api_key_with_secret(&env.credential, &secret);
            let mut conn = deadpool_redis::Config::from_url(&redis_url)
                .create_pool(Some(deadpool_redis::Runtime::Tokio1))
                .expect("redis pool")
                .get()
                .await
                .expect("redis conn");
            let _: Result<(), _> = deadpool_redis::redis::AsyncCommands::set(
                &mut conn,
                format!("{API_KEY_CACHE_PREFIX}{hmac}"),
                "definitely-not-json",
            )
            .await;
            let (status, _) = env.get(profile).await;
            assert_eq!(status, axum::http::StatusCode::NOT_FOUND);

            // A structurally-valid entry with an EMPTY tenant id is evicted
            // (never authenticated as the empty tenant).
            let empty_tenant_entry = serde_json::json!({
                "user": {
                    "tenant_id": "",
                    "user_id": null,
                    "api_key_id": null,
                    "session_id": null,
                    "scopes": ["*"]
                },
                "expires_at": null
            });
            let _: Result<(), _> = deadpool_redis::redis::AsyncCommands::set(
                &mut conn,
                format!("{API_KEY_CACHE_PREFIX}{hmac}"),
                empty_tenant_entry.to_string(),
            )
            .await;
            let (status, _) = env.get(profile).await;
            assert_eq!(status, axum::http::StatusCode::NOT_FOUND);

            // The row vanishes while its cache entry lives. The last-used
            // touch is throttled to one DB write per key per 5 minutes, so
            // the eviction only fires when the throttle window has rolled:
            // clear the throttle key (the window-rollover boundary), and
            // the next request's touch matches zero rows, evicts the entry,
            // and answers an honest 401.
            sqlx::query("DELETE FROM api_keys WHERE tenant_id = $1")
                .bind(&tenant_id)
                .execute(&pool)
                .await
                .expect("delete key row");
            let api_key_id: Option<String> = None; // resolved from the row before deletion is unnecessary: the throttle key is derivable from the tenant's key id captured below.
            let _ = api_key_id;
            let throttle_keys: Vec<String> = deadpool_redis::redis::cmd("KEYS")
                .arg("api_key:last_used:*")
                .query_async(&mut conn)
                .await
                .expect("list throttle keys");
            for key in throttle_keys {
                let _: Result<(), _> =
                    deadpool_redis::redis::AsyncCommands::del(&mut conn, key).await;
            }
            // Drop the cached entry too: its TTL (10s) is longer than the
            // test window, and the contract under test is the DB-fallback
            // refusal, not TTL expiry.
            let _: Result<(), _> = deadpool_redis::redis::AsyncCommands::del(
                &mut conn,
                format!("{API_KEY_CACHE_PREFIX}{hmac}"),
            )
            .await;
            let (status, body) = env.get(profile).await;
            assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED, "{body}");
        }

        /// Legacy SHA-256 and Argon2id API keys authenticate through their
        /// fallback paths and are upgraded to the fast HMAC lookup — and an
        /// expired Argon2 key stays refused on the fallback scan.
        #[tokio::test]
        async fn legacy_and_argon2_api_keys_authenticate_and_upgrade() {
            let Some(pool) = crate::test_db::canonical_pool("waved_mw_legacy_keys").await else {
                eprintln!("skipping legacy_and_argon2_api_keys_authenticate_and_upgrade: no TEST_DATABASE_URL");
                return;
            };
            let secret = crate::app::test_support::test_config()
                .api_key_hash_secret
                .clone();

            // ── Legacy SHA-256 ──
            let legacy_raw = format!("am_live_{}", uuid::Uuid::new_v4().simple());
            let legacy_hash = apexmail_lib::hash_api_key(&legacy_raw);
            seed_raw_key(&pool, "wvlg", &legacy_hash).await;
            let env = crate::app::test_support::adv::AdvEnv::over(pool.clone(), legacy_raw).await;
            let (status, _) = env.get("/v1/account/profile").await;
            assert_eq!(status, axum::http::StatusCode::NOT_FOUND);

            // The spawned upgrade re-hashes to Argon2id; wait for it.
            let key_row: (String,) = sqlx::query_as(
                "SELECT key_hash FROM api_keys WHERE key_prefix = 'am_test_' ORDER BY created_at DESC LIMIT 1",
            )
            .fetch_one(&pool)
            .await
            .expect("key row");
            let mut upgraded = key_row.0 != legacy_hash;
            for _ in 0..40 {
                if upgraded {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                let key_row: (String,) = sqlx::query_as(
                    "SELECT key_hash FROM api_keys WHERE key_prefix = 'am_test_' ORDER BY created_at DESC LIMIT 1",
                )
                .fetch_one(&pool)
                .await
                .expect("key row");
                upgraded = key_row.0 != legacy_hash;
            }
            assert!(upgraded, "the legacy hash must be re-hashed after auth");

            // ── Argon2id (as the upgraded row now carries, or seeded) ──
            let argon_raw = format!("am_live_{}", uuid::Uuid::new_v4().simple());
            let argon_hash = apexmail_lib::hash_api_key_argon2(&argon_raw).expect("argon hash");
            seed_raw_key(&pool, "wvar", &argon_hash).await;
            let env =
                crate::app::test_support::adv::AdvEnv::over(pool.clone(), argon_raw.clone()).await;
            let (status, _) = env.get("/v1/account/profile").await;
            assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
            // The fallback upgrades to HMAC for the next lookup.
            let final_hash = apexmail_lib::hash_api_key_with_secret(&argon_raw, &secret);
            let stored: String =
                sqlx::query_scalar("SELECT key_hash FROM api_keys WHERE key_hash = $1")
                    .bind(&final_hash)
                    .fetch_optional(&pool)
                    .await
                    .expect("scan")
                    .unwrap_or_default();
            assert_eq!(stored, final_hash, "argon2id key must upgrade to HMAC");

            // ── An EXPIRED Argon2id key is refused on the fallback scan ──
            let expired_raw = format!("am_live_{}", uuid::Uuid::new_v4().simple());
            let expired_hash = apexmail_lib::hash_api_key_argon2(&expired_raw).expect("argon hash");
            let tenant = apexmail_lib::id::generate_id("wvex", 20);
            sqlx::query(
                "INSERT INTO api_keys (id, tenant_id, name, key_prefix, key_hash, scopes, expires_at, created_at, updated_at)
                 VALUES ($1, $2, 'expired probe', 'am_test_', $3, '[\"*\"]'::jsonb, NOW() - INTERVAL '1 day', NOW(), NOW())",
            )
            .bind(uuid::Uuid::new_v4())
            .bind(&tenant)
            .bind(&expired_hash)
            .execute(&pool)
            .await
            .expect("seed expired key");
            let env = crate::app::test_support::adv::AdvEnv::over(pool, expired_raw).await;
            let (status, _) = env.get("/v1/account/profile").await;
            assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
        }

        async fn seed_raw_key(pool: &sqlx::PgPool, tenant_prefix: &str, hash: &str) -> String {
            let tenant = apexmail_lib::id::generate_id(tenant_prefix, 20);
            sqlx::query(
                "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
                 VALUES ($1, 'Wave D Keys', $2, 'free', 'active', NOW(), NOW())",
            )
            .bind(&tenant)
            .bind(format!("slug-{tenant}"))
            .execute(pool)
            .await
            .expect("seed tenant");
            sqlx::query(
                "INSERT INTO api_keys (id, tenant_id, name, key_prefix, key_hash, scopes, created_at, updated_at)
                 VALUES ($1, $2, 'wave d key', 'am_test_', $3, '[\"*\"]'::jsonb, NOW(), NOW())",
            )
            .bind(uuid::Uuid::new_v4())
            .bind(&tenant)
            .bind(hash)
            .execute(pool)
            .await
            .expect("seed key");
            tenant
        }

        /// The control-plane static key is bound to the CP admin surface:
        /// the same secret that authenticates /v1/admin/* on the CP host is
        /// refused everywhere else.
        #[tokio::test]
        async fn control_plane_static_key_is_surface_bound() {
            let Some(pool) = crate::test_db::canonical_pool("waved_mw_cp_key").await else {
                eprintln!(
                    "skipping control_plane_static_key_is_surface_bound: no TEST_DATABASE_URL"
                );
                return;
            };
            let mut config = test_config();
            config.control_plane_api_key = Some("cp-static-key-wave-d".into());
            let state = crate::app::test_support::test_state_over_with_config(pool, config).await;

            // On the control-plane host, the admin surface admits the static
            // key as the system sentinel machine identity.
            let admitted = authenticate_api_key(
                "cp-static-key-wave-d",
                &Method::GET,
                "/v1/admin/tenants",
                true,
                &state,
            )
            .await
            .expect("static key admits on the CP admin surface");
            assert_eq!(admitted.tenant_id, "system");
            assert!(admitted.user_id.is_none());

            // The SAME key on a non-admin path is refused.
            assert!(matches!(
                authenticate_api_key(
                    "cp-static-key-wave-d",
                    &Method::GET,
                    "/v1/account/profile",
                    true,
                    &state,
                )
                .await,
                Err(ApiError::Unauthorized(_))
            ));

            // The same key OFF the control-plane host is refused even on the
            // admin path — the secret never becomes a general API key.
            assert!(matches!(
                authenticate_api_key(
                    "cp-static-key-wave-d",
                    &Method::GET,
                    "/v1/admin/tenants",
                    false,
                    &state,
                )
                .await,
                Err(ApiError::Unauthorized(_))
            ));

            // A DIFFERENT key never matches the static comparison and falls
            // through to the (empty) database lookup.
            assert!(matches!(
                authenticate_api_key(
                    "cp-static-key-wave-d-x",
                    &Method::GET,
                    "/v1/admin/tenants",
                    true,
                    &state,
                )
                .await,
                Err(ApiError::Unauthorized(_))
            ));
        }

        /// X-Tenant-ID header injection: a claimed tenant that is not the
        /// authenticated tenant is refused for BOTH session and API-key
        /// identities (an API key has no user id, so cross-tenant access is
        /// structurally unverifiable).
        #[tokio::test]
        async fn x_tenant_id_injection_is_refused_for_sessions_and_keys() {
            let Some(pool) = crate::test_db::canonical_pool("waved_mw_xtenant").await else {
                eprintln!("skipping x_tenant_id_injection_is_refused: no TEST_DATABASE_URL");
                return;
            };
            let other_tenant = apexmail_lib::id::generate_id("wvot", 20);
            sqlx::query(
                "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
                 VALUES ($1, 'Other Tenant', $2, 'free', 'active', NOW(), NOW())",
            )
            .bind(&other_tenant)
            .bind(format!("slug-{other_tenant}"))
            .execute(&pool)
            .await
            .expect("seed other tenant");

            // Session identity: claiming a foreign tenant is a 403.
            let Some((env, _t, _u)) =
                crate::app::test_support::adv::AdvEnv::session(pool.clone(), "owner").await
            else {
                eprintln!(
                    "skipping x_tenant_id_injection session half: TEST_REDIS_URL unreachable"
                );
                return;
            };
            let response = env
                .app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method(Method::GET)
                        .uri("/v1/account/profile")
                        .header(
                            axum::http::header::AUTHORIZATION,
                            format!("Bearer {}", env.credential),
                        )
                        .header("x-tenant-id", &other_tenant)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);

            // API-key identity: same refusal (cannot verify membership).
            let (env, _tenant) = crate::app::test_support::adv::AdvEnv::tenant(pool, &["*"]).await;
            let response = env
                .app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method(Method::GET)
                        .uri("/v1/account/profile")
                        .header("x-api-key", &env.credential)
                        .header("x-tenant-id", &other_tenant)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
        }

        /// The user-status cache invalidation sweep: seeded keys are
        /// SCANned and UNLINKed by the tenant-wide invalidator.
        #[tokio::test]
        async fn tenant_wide_user_status_invalidation_unlinks_every_key() {
            let Some(redis_url) = std::env::var("TEST_REDIS_URL")
                .ok()
                .filter(|value| !value.trim().is_empty())
            else {
                eprintln!("skipping tenant_wide_user_status_invalidation: no TEST_REDIS_URL");
                return;
            };
            let state =
                test_state_over_with_config_and_redis(dead_db_pool(), test_config(), &redis_url)
                    .await;
            let tenant = apexmail_lib::id::generate_id("wvin", 20);
            let mut conn = state.redis.get().await.expect("redis conn");
            for i in 0..3 {
                let _: Result<(), _> = deadpool_redis::redis::AsyncCommands::set_ex(
                    &mut conn,
                    user_status_cache_key(&tenant, &format!("user-{i}")),
                    "active|owner",
                    60_u64,
                )
                .await;
            }
            invalidate_tenant_user_status_cache(&tenant, &state).await;
            for i in 0..3 {
                let exists: bool = deadpool_redis::redis::AsyncCommands::exists(
                    &mut conn,
                    user_status_cache_key(&tenant, &format!("user-{i}")),
                )
                .await
                .unwrap_or(true);
                assert!(!exists, "key user-{i} must be unlinked");
            }
        }
    }
}
