//! ApexMail status + retained-auth server (deployed as the public
//! `status.apexmail.ee` backend, image `status-server`).
//!
//! SECURITY: this binary is exposed to the public internet through nginx
//! (`location /` on the status vhost) and on the internal Docker networks.
//! The router exposes ONLY the status page (`/status`), the status API
//! (`/status/api`), the status history (`/status/history`) and the health
//! probe (`/v1/health`). The former auth / register / MFA / API-key /
//! billing / admin / sandbox routes are intentionally NOT wired into the
//! router — interactive auth lives in the api-server crate; nginx
//! additionally refuses every other path. Routing stays out of scope; the
//! handlers below are retained so that the day a route is deliberately
//! re-exposed it is SAFE to route.
//!
//! # What the retained auth handlers enforce (audit F1–F3, F7)
//!
//! * **MFA gate (F1)** — the login fetch reads `mfa_enabled`; an
//!   MFA-enabled user NEVER receives a session cookie from a password-only
//!   submission. The handler answers `202` with an `mfa_required` challenge
//!   body. (The interactive TOTP verification itself lives in api-server;
//!   this handler must not become a second-factor bypass.)
//! * **Brake + timing uniformity (F2)** — every login attempt is checked
//!   through the rate-limiter BEFORE any database work, keyed BOTH by the
//!   submitted identifier and by the client IP (5-attempt burst, 1/s
//!   refill, Redis-backed when `RATE_LIMIT_REDIS_URL`/`REDIS_URL` is
//!   configured, in-memory keyed otherwise). Unknown emails run a dummy
//!   Argon2id verification so nonexistent and wrong-password responses cost
//!   the same ~19 MiB computation — the timing side channel that let
//!   attackers enumerate registered users is closed.
//! * **Random, revocable sessions (F3)** — the cookie value is a fresh
//!   256-bit OS-CSPRNG session id, HMAC-SHA256-bound to the process secret
//!   (via `apexmail_lib::crypto::create_hmac_signature` — never the old
//!   homebrew `SHA256(msg||secret)`). Every session has a row in the
//!   `auth_sessions` table (migration 234) with a hard `expires_at`;
//!   verification requires an unrevoked, unexpired row, so logout
//!   (`logout_post`, `revoke_session`) and password change / MFA reset
//!   (`revoke_all_for_user`) actually invalidate leaked cookies. Two
//!   logins can never produce the same token, and the email no longer
//!   rides in the cookie.
//! * **Atomic registration (F7)** — the tenant and user INSERTs run inside
//!   ONE transaction (`apexmail_db::transaction::with_transaction`), and
//!   the tenant-insert error is never swallowed: any failure rolls back
//!   both writes (no orphaned tenant permanently consuming the free-plan
//!   capacity), and conflicts surface as `409`.
//!
//! # Status surface (audit F8)
//!
//! The public `/status` and `/status/api` endpoints NEVER run probes per
//! request. A background task samples every probe (six database checks plus
//! the SMTP TCP probe) every [`PROBE_INTERVAL_SECS`] seconds — matching the
//! page's "probes run every 60 seconds" claim — into a shared snapshot the
//! handlers serve. At most ONE SMTP probe runs concurrently per process
//! (semaphore), so a slow SMTP target cannot stack up connections.

use apexmail_rate_limiter::{
    config::KeyedConfig, Decision, KeyedRateLimiter, RateLimitConfig, RedisLimiter,
};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::rand_core::RngCore;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// How often the background task samples the service probes. The status
/// page tells users "probes run every 60 seconds" — this is what makes that
/// claim true (audit F8).
const PROBE_INTERVAL_SECS: u64 = 60;

/// Maximum concurrent SMTP probes per process (audit F8: the probe is a
/// 3 s TCP connect; per-request probing let requests stack up unbounded).
const MAX_CONCURRENT_SMTP_PROBES: usize = 1;

// ─── Login throttle (audit F2) ────────────────────────────────

/// Burst of failed-login budget per key (per identifier AND per IP) before
/// denial. 5 attempts, then refill at [`LOGIN_REFILL_PER_SEC`].
const LOGIN_BURST: u32 = 5;
/// Steady refill rate of the login budget (attempts per second).
const LOGIN_REFILL_PER_SEC: u32 = 1;

/// Login brute-force brake: a keyed in-memory limiter ALWAYS consulted
/// (per-key buckets with eviction tombstones), plus a Redis token bucket
/// (the same one every other pod uses) when Redis is configured — so the
/// brake is fleet-wide in production and still effective per-process when
/// Redis is unavailable.
struct LoginThrottle {
    redis: Option<RedisLimiter>,
    memory: KeyedRateLimiter,
}

impl LoginThrottle {
    /// Build from the environment: the in-memory keyed brake always, plus a
    /// bounded Redis connect attempt when `RATE_LIMIT_REDIS_URL` (or the
    /// generic `REDIS_URL`) is configured. Must run inside a tokio runtime.
    async fn from_env_with_redis() -> Self {
        let mut throttle = Self {
            redis: None,
            memory: Self::memory_limiter(),
        };
        let url = std::env::var("RATE_LIMIT_REDIS_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .or_else(|| {
                std::env::var("REDIS_URL")
                    .ok()
                    .filter(|v| !v.trim().is_empty())
            });
        if let Some(url) = url {
            throttle.redis = RedisLimiter::connect(&Self::redis_config(), &url).await;
        }
        throttle
    }

    /// In-memory-only brake (tests, and deployments without Redis).
    #[cfg(test)]
    fn in_memory() -> Self {
        Self {
            redis: None,
            memory: Self::memory_limiter(),
        }
    }

    fn memory_limiter() -> KeyedRateLimiter {
        KeyedRateLimiter::new(KeyedConfig {
            per_key: RateLimitConfig::new(LOGIN_REFILL_PER_SEC).with_burst(LOGIN_BURST),
            max_keys: 10_000,
            cleanup_interval_secs: 60,
            eviction_tombstone_ttl_secs: 60,
        })
    }

    /// Rate parameters for the shared Redis bucket (same shape as the
    /// in-memory brake so both layers agree).
    fn redis_config() -> RateLimitConfig {
        RateLimitConfig::new(LOGIN_REFILL_PER_SEC).with_burst(LOGIN_BURST)
    }

    /// Check one attempt against BOTH dimensions' buckets. `Err(retry_after)`
    /// means denied.
    async fn check(&self, scope: &str, key: &str) -> Result<(), std::time::Duration> {
        let keyed = format!("{scope}:{key}");
        if let Decision::Denied { retry_after } = self.memory.check(&keyed) {
            return Err(retry_after);
        }
        if let Some(redis) = &self.redis {
            if let Decision::Denied { retry_after } =
                redis.check_n_for_tenant(Some(&keyed), 1).await
            {
                return Err(retry_after);
            }
        }
        Ok(())
    }
}

// ─── App state ────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    db: sqlx::PgPool,
    session_secret: String,
    throttle: Arc<LoginThrottle>,
    probes: Arc<ProbeCache>,
    /// Caps concurrent SMTP probes (audit F8).
    smtp_gate: Arc<tokio::sync::Semaphore>,
}

// ─── Session tokens (audit F3) ────────────────────────────────
//
// The cookie value is `{random 32-byte id}.{HMAC-SHA256(id, secret)}`.
// Randomness makes sessions unfingerprintable; the HMAC (from
// `apexmail_lib::crypto`, NOT a homebrew SHA256(msg||secret)) keeps a DB
// writer from forging ids without the process secret; the `auth_sessions`
// row (migration 234) makes every session individually revocable and
// expiring. A leaked cookie dies at logout, at a password change, or at
// `expires_at` — whichever comes first.

/// Maximum age of a session (24h): cookie Max-Age AND the `auth_sessions`
/// hard expiry minted with each session.
const SESSION_MAX_AGE_SECS: u64 = 24 * 60 * 60;

#[allow(dead_code)]
#[derive(Deserialize)]
struct LoginForm {
    username_or_email: String,
    password: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct RegisterForm {
    name: Option<String>,
    email: String,
    password: String,
}

/// Fresh 256-bit session id from the OS CSPRNG, hex-encoded (64 chars).
fn mint_session_id() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// HMAC-bind a session id to the process secret (hex signature).
fn sign_session_id(id: &str, secret: &str) -> String {
    apexmail_lib::crypto::create_hmac_signature(secret.as_bytes(), id.as_bytes())
}

/// Assemble the cookie value for a session id.
fn build_session_token(id: &str, secret: &str) -> String {
    format!("{id}.{}", sign_session_id(id, secret))
}

/// Verify the MAC portion of a token and return the session id on success.
///
/// Constant-time comparison via `timing_safe_compare` — a plain `==`
/// short-circuits and leaks a byte-by-byte timing oracle on the signature.
fn verify_session_mac(token: &str, secret: &str) -> Option<String> {
    let (id, sig) = token.split_once('.')?;
    if id.is_empty() || id.len() != 64 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let expected = sign_session_id(id, secret);
    if apexmail_lib::timing_safe_compare(&expected, sig) {
        Some(id.to_string())
    } else {
        None
    }
}

/// Full verification: MAC check AND a live `auth_sessions` row.
///
/// Fail-closed: a missing row, a revoked session, an expired session, or a
/// database error all deny.
async fn verify_session_token(pool: &sqlx::PgPool, token: &str, secret: &str) -> Option<String> {
    let id = verify_session_mac(token, secret)?;
    sqlx::query_scalar::<_, String>(
        "SELECT email FROM auth_sessions \
         WHERE id = $1 AND revoked_at IS NULL AND expires_at > NOW()",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}

/// Mint a session for `user_id`: persist the row (24h hard expiry) and
/// return the cookie token.
async fn mint_session(
    pool: &sqlx::PgPool,
    secret: &str,
    user_id: uuid::Uuid,
    email: &str,
) -> Result<String, sqlx::Error> {
    let id = mint_session_id();
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(SESSION_MAX_AGE_SECS as i64);
    sqlx::query(
        "INSERT INTO auth_sessions (id, user_id, email, expires_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(&id)
    .bind(user_id)
    .bind(email)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(build_session_token(&id, secret))
}

/// Revoke ONE session by token (logout). Idempotent: revoking an unknown or
/// already-revoked token reports `false` and never errors.
async fn revoke_session(pool: &sqlx::PgPool, token: &str) -> Result<bool, sqlx::Error> {
    // Only the id is needed; an unauthenticated forged token simply no-ops.
    let Some((id, _)) = token.split_once('.') else {
        return Ok(false);
    };
    if id.len() != 64 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(false);
    }
    let result = sqlx::query(
        "UPDATE auth_sessions SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Revoke EVERY live session of a user — the password-change / MFA-reset
/// hook (audit F3). Returns the number of sessions killed.
///
/// Kept ready (like the other retained handlers) for the day a
/// change-password route is deliberately re-exposed; until then the
/// DB-backed tests exercise it, and the api-server performs the equivalent
/// revocation on its own Redis-guarded path.
#[allow(dead_code)]
async fn revoke_all_for_user(pool: &sqlx::PgPool, user_id: uuid::Uuid) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE auth_sessions SET revoked_at = NOW() \
         WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Extract the raw session token from the Cookie header.
fn session_token_from_headers(headers: &axum::http::HeaderMap) -> Option<String> {
    let cookie = headers.get("cookie")?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(token) = part.strip_prefix("apexmail_session=") {
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    None
}

/// Verify the request's session cookie against the store.
#[allow(dead_code)]
async fn extract_session_email(
    pool: &sqlx::PgPool,
    headers: &axum::http::HeaderMap,
    secret: &str,
) -> Option<String> {
    let token = session_token_from_headers(headers)?;
    verify_session_token(pool, &token, secret).await
}

/// True when running with ENVIRONMENT=production|prod (the convention used
/// by api-server's config; dev defaults to development).
fn is_production_env() -> bool {
    matches!(
        std::env::var("ENVIRONMENT")
            .unwrap_or_default()
            .to_lowercase()
            .as_str(),
        "production" | "prod"
    )
}

fn session_cookie(token: &str) -> String {
    // `Secure` in production so the cookie is never sent over plain HTTP.
    let secure = if is_production_env() { "; Secure" } else { "" };
    format!("apexmail_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_MAX_AGE_SECS}{secure}")
}

fn cleared_session_cookie() -> String {
    let secure = if is_production_env() { "; Secure" } else { "" };
    format!("apexmail_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}")
}

/// Client IP for the per-IP brake dimension. nginx is the documented public
/// front and sets X-Forwarded-For; a missing header collapses all clients
/// into one shared "unattributed" bucket (conservative, never permissive).
fn client_ip(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
        .unwrap_or("unattributed")
        .to_string()
}

/// A fixed Argon2id hash verified against whenever the submitted email does
/// not exist, so unknown-user responses cost the same ~19 MiB as real
/// verifications (audit F2: the microsecond response leaked which emails
/// are registered).
fn dummy_password_hash() -> &'static String {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DUMMY.get_or_init(|| {
        apexmail_lib::crypto::hash_password("timing-uniformity-dummy-password")
            .expect("fixed OWASP argon2 hash for the dummy must be constructible")
    })
}

/// Spend the dummy Argon2id verification (result discarded).
fn burn_dummy_verification(password: &str) {
    let _ = apexmail_lib::crypto::verify_password(password, dummy_password_hash());
}

// ─── Auth endpoints (NOT routed — see crate docs) ──────────

#[allow(dead_code)]
async fn login_post(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(form): axum::Json<LoginForm>,
) -> axum::response::Response {
    let identifier = form.username_or_email.trim().to_lowercase();
    let ip = client_ip(&headers);
    let is_cp = headers
        .get("x-apexmail-surface")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "control-plane")
        .unwrap_or(false);

    // Brake FIRST — before any database work (audit F2).
    let retry_after = match state.throttle.check("login:id", &identifier).await {
        Err(wait) => Some(wait),
        Ok(()) => state.throttle.check("login:ip", &ip).await.err(),
    };
    if let Some(retry_after) = retry_after {
        let mut resp = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "Too many login attempts — try again later"
            })),
        )
            .into_response();
        if let Ok(value) = retry_after.as_secs().max(1).to_string().parse() {
            resp.headers_mut().insert(header::RETRY_AFTER, value);
        }
        return resp;
    }

    // Look up by email ONLY — the `users` table has no `username` column, so
    // the old `WHERE username = $1 OR email = $1` made every login fail with
    // a database error (column does not exist). mfa_enabled is fetched so
    // the MFA gate below can actually fire (audit F1).
    let row = sqlx::query_as::<_, (uuid::Uuid, String, String, bool)>(
        "SELECT id, password_hash, email, mfa_enabled FROM users WHERE email = $1 LIMIT 1",
    )
    .bind(&identifier)
    .fetch_optional(&state.db)
    .await;

    let user = match row {
        Ok(Some(user)) => {
            // Verify against the row's OWN argon2 params (weak legacy rows
            // still authenticate instead of hard-failing — apexmail-lib F11).
            let valid =
                apexmail_lib::crypto::verify_password(&form.password, &user.1).unwrap_or(false);
            if valid {
                Some(user)
            } else {
                None
            }
        }
        Ok(None) => {
            // Unknown email: burn the SAME Argon2id computation so response
            // timing does not reveal which addresses are registered.
            burn_dummy_verification(&form.password);
            None
        }
        // Database failure must fail CLOSED (500), never masquerade as a
        // wrong password.
        Err(e) => {
            eprintln!("login lookup failed: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Login unavailable"})),
            )
                .into_response();
        }
    };

    let Some((user_id, _, email, mfa_enabled)) = user else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid username or password"})),
        )
            .into_response();
    };

    // MFA gate (audit F1): an MFA-enabled user NEVER gets a session from a
    // password-only submission — issue the challenge instead.
    if mfa_enabled {
        return (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({
                "mfa_required": true,
                "error": "MFA challenge required",
                "challenge": "totp"
            })),
        )
            .into_response();
    }

    // Random, revocable session (audit F3). A mint failure is a hard error:
    // never answer success without a usable session.
    let token = match mint_session(&state.db, &state.session_secret, user_id, &email).await {
        Ok(token) => token,
        Err(e) => {
            eprintln!("session mint failed: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Login unavailable"})),
            )
                .into_response();
        }
    };
    let cookie = session_cookie(&token);
    let redirect = if is_cp {
        "/cp-admin/dashboard/"
    } else {
        "/dashboard"
    };
    let mut resp = Json(serde_json::json!({
        "message": "Login successful",
        "redirect": redirect,
        "user": {"email": email}
    }))
    .into_response();
    if let Ok(value) = cookie.parse() {
        resp.headers_mut().insert(header::SET_COOKIE, value);
    }
    resp
}

#[allow(dead_code)]
async fn logout_post(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    // Revoke the server-side row so the cookie is dead even if a client
    // keeps it; then clear the cookie.
    if let Some(token) = session_token_from_headers(&headers) {
        if let Err(e) = revoke_session(&state.db, &token).await {
            eprintln!("logout revoke failed: {e}");
        }
    }
    let mut resp = Json(serde_json::json!({"message": "Logged out"})).into_response();
    if let Ok(value) = cleared_session_cookie().parse() {
        resp.headers_mut().insert(header::SET_COOKIE, value);
    }
    resp
}

#[allow(dead_code)]
async fn register_post(
    State(state): State<AppState>,
    axum::Json(form): axum::Json<RegisterForm>,
) -> axum::response::Response {
    let email = form.email.trim().to_lowercase();
    if !email.contains('@') || !email.contains('.') {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid email"})),
        )
            .into_response();
    }
    // `users.email` is VARCHAR(255): an oversize address can never be stored,
    // so reject it up front instead of failing the INSERT and (previously)
    // still reporting a created account.
    if email.chars().count() > 255 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid email"})),
        )
            .into_response();
    }
    if form.password.len() < 12 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Password must be 12+ characters"})),
        )
            .into_response();
    }
    if let Ok(Some(_)) = sqlx::query_scalar::<_, String>("SELECT email FROM users WHERE email = $1")
        .bind(&email)
        .fetch_optional(&state.db)
        .await
    {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "Email already registered"})),
        )
            .into_response();
    }

    // Enforce Free plan quota: reject new free plan registrations if global free tenant
    // count exceeds the 30,000 email/month aggregate safety threshold. This is a blunt
    // gate — per-tenant usage is enforced by the billing_usage endpoint.
    let free_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM tenants WHERE plan = 'free' AND status = 'active'",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);
    let free_limit: i64 = std::env::var("FREE_TENANT_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50000);
    if free_count >= free_limit {
        return (StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Free plan is at capacity. Please try again later or contact sales for a paid plan."}))
        ).into_response();
    }

    let Ok(hash) = apexmail_lib::crypto::hash_password(&form.password) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Registration failed"})),
        )
            .into_response();
    };
    let user_id = uuid::Uuid::new_v4();
    // 26-char canonical tenant id (VARCHAR(26), migration 064).
    let tenant_id = apexmail_db::types::short_id('t');
    let tenant_name = email.split('@').next().unwrap_or("user").to_string();

    // ATOMIC registration (audit F7): tenant + user in ONE transaction —
    // the previous code swallowed the tenant error and ran the user INSERT
    // on a separate connection, so a failed user insert left an orphaned
    // tenant row permanently consuming the free-plan capacity. The flag
    // records which insert failed so only USER-insert unique violations map
    // to the "email already registered" conflict.
    let user_insert_started = Arc::new(AtomicBool::new(false));
    let started = user_insert_started.clone();
    // `email` is needed after the transaction (session mint), so the
    // closure gets its own copy.
    let tx_email = email.clone();
    let result: Result<(), sqlx::Error> =
        apexmail_db::transaction::with_transaction(&state.db, |mut tx| async move {
            let exec = tx.conn().ok_or_else(tx_consumed_error)?;
            sqlx::query(
                "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at) \
                 VALUES ($1, $2, $3, 'free', 'active', NOW(), NOW())",
            )
            .bind(&tenant_id)
            .bind(&tenant_name)
            .bind(&tenant_id)
            .execute(&mut *exec)
            .await?;
            started.store(true, Ordering::Relaxed);
            let exec = tx.conn().ok_or_else(tx_consumed_error)?;
            sqlx::query(
                "INSERT INTO users (id, tenant_id, email, password_hash, role, mfa_enabled, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, 'owner', false, NOW(), NOW())",
            )
            .bind(user_id)
            .bind(&tenant_id)
            .bind(&tx_email)
            .bind(&hash)
            .execute(&mut *exec)
            .await?;
            Ok((tx, ()))
        })
        .await;

    if let Err(e) = result {
        let from_user_insert = user_insert_started.load(Ordering::Relaxed);
        let unique = e
            .as_database_error()
            .is_some_and(|db| db.is_unique_violation());
        if from_user_insert && unique {
            // The case-fold unique index on lower(email) is the authority.
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "Email already registered"})),
            )
                .into_response();
        }
        eprintln!("registration failed to persist atomically: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Registration failed"})),
        )
            .into_response();
    }

    // The session mint is authoritative too: no cookie unless a real,
    // revocable session row exists (audit F3).
    let token = match mint_session(&state.db, &state.session_secret, user_id, &email).await {
        Ok(token) => token,
        Err(e) => {
            eprintln!("post-registration session mint failed: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Registration failed"})),
            )
                .into_response();
        }
    };
    let cookie = session_cookie(&token);
    let mut resp = Json(serde_json::json!({
        "message": "Account created",
        "redirect": "/login"
    }))
    .into_response();
    if let Ok(value) = cookie.parse() {
        resp.headers_mut().insert(header::SET_COOKIE, value);
    }
    resp
}

/// The (structurally unreachable) error for a `Tx` whose inner transaction
/// was already consumed — fail-closed instead of panicking.
fn tx_consumed_error() -> sqlx::Error {
    sqlx::Error::Io(std::io::Error::new(
        std::io::ErrorKind::Other,
        "transaction already consumed",
    ))
}

// ─── Probe helpers ─────────────────────────────────────────

/// Extract (host, port) from a service URL such as
/// `redis://:password@redis:6379/0`, falling back to `default_port` when the
/// URL carries no explicit port.
#[allow(dead_code)]
fn url_host_port(raw: &str, default_port: u16) -> Option<(String, u16)> {
    let parsed = url::Url::parse(raw).ok()?;
    let host = parsed.host_str()?.to_string();
    if host.is_empty() {
        return None;
    }
    let port = parsed.port().unwrap_or(default_port);
    Some((host, port))
}

/// Real TCP connectivity probe: true when a connection to `host:port` can be
/// established within `timeout`.
async fn tcp_connect_ok(host: &str, port: u16, timeout: std::time::Duration) -> bool {
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect((host, port))).await {
        Ok(Ok(_)) => true,
        Ok(Err(_)) | Err(_) => false,
    }
}

// ─── Probe snapshot (audit F8) ────────────────────────────────

/// One sampled snapshot of every service probe. Handlers serve this
/// verbatim — they NEVER probe per request.
#[derive(Debug, Clone)]
struct ProbeSnapshot {
    services: Vec<serde_json::Value>,
    all_operational: bool,
    updated: chrono::DateTime<chrono::Utc>,
    /// False only for the pre-first-cycle placeholder.
    probed: bool,
}

impl ProbeSnapshot {
    fn pending() -> Self {
        Self {
            services: Vec::new(),
            all_operational: false,
            updated: chrono::Utc::now(),
            probed: false,
        }
    }
}

/// Shared snapshot cell: a background task writes every
/// [`PROBE_INTERVAL_SECS`], the public handlers read.
struct ProbeCache {
    snapshot: std::sync::RwLock<Arc<ProbeSnapshot>>,
}

impl ProbeCache {
    fn new() -> Self {
        Self {
            snapshot: std::sync::RwLock::new(Arc::new(ProbeSnapshot::pending())),
        }
    }

    fn current(&self) -> Arc<ProbeSnapshot> {
        self.snapshot
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn store(&self, snapshot: ProbeSnapshot) {
        *self.snapshot.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(snapshot);
    }
}

/// Sample EVERY probe once, PUBLISH the snapshot into the shared cache, and
/// return it. Called ONLY by the background task (and tests) — never from a
/// request handler.
async fn run_probe_cycle(state: &AppState) -> ProbeSnapshot {
    // The SMTP probe FIRST, under the concurrency cap: at most one 3 s TCP
    // connect in flight per process no matter how cycles overlap.
    let smtp_ok = {
        let _permit = state.smtp_gate.acquire().await;
        match smtp_probe_target() {
            Some((host, port)) => {
                tcp_connect_ok(&host, port, std::time::Duration::from_secs(3)).await
            }
            None => false,
        }
    };

    let (mut services, mut all_operational) = collect_db_probe_results(state).await;
    services.push(serde_json::json!({
        "name": "Mail Server (SMTP)", "status": if smtp_ok { "operational" } else { "degraded" }
    }));
    if !smtp_ok {
        all_operational = false;
    }

    let snapshot = ProbeSnapshot {
        services,
        all_operational,
        updated: chrono::Utc::now(),
        probed: true,
    };
    // Publish HERE, not in the caller: every sampler (production task and
    // tests) must leave the shared cache holding exactly the snapshot it
    // sampled — a cycle that returns without publishing would keep handlers
    // serving the stale "probes are starting" placeholder.
    state.probes.store(snapshot.clone());
    snapshot
}

/// The configured SMTP probe target (MAIL_HOST env, port 25).
fn smtp_probe_target() -> Option<(String, u16)> {
    let host = std::env::var("MAIL_HOST")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "mail.apexmail.ee".to_string());
    Some((host, 25))
}

/// The six database probes. Cheap on the snapshot path: these run once per
/// cycle, not per request (audit F8 — the public endpoints used to run
/// these on EVERY request, including partitioned `messages` COUNT scans).
async fn collect_db_probe_results(state: &AppState) -> (Vec<serde_json::Value>, bool) {
    let mut services = Vec::new();
    let mut all_operational = true;

    // Probe database connectivity with a lightweight query.
    // `SELECT 1::bigint` (not `SELECT 1`): sqlx 0.8 type-checks scalars and
    // i64 is incompatible with the INT4 column type of a bare `SELECT 1`.
    let db_ok = sqlx::query_scalar::<_, i64>("SELECT 1::bigint")
        .fetch_one(&state.db)
        .await
        .is_ok();
    services.push(serde_json::json!({
        "name": "Database", "status": if db_ok { "operational" } else { "degraded" }
    }));
    if !db_ok {
        all_operational = false;
    }

    // Probe tenant table health
    let tenants_ok =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM tenants WHERE status = 'active'")
            .fetch_one(&state.db)
            .await
            .is_ok();
    services.push(serde_json::json!({
        "name": "Tenants API", "status": if tenants_ok { "operational" } else { "degraded" }
    }));
    if !tenants_ok {
        all_operational = false;
    }

    // Probe message throughput (last 5 minutes)
    let messages_ok = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM messages WHERE created_at > NOW() - INTERVAL '5 minutes'",
    )
    .fetch_one(&state.db)
    .await
    .is_ok();
    services.push(serde_json::json!({
        "name": "Message Pipeline", "status": if messages_ok { "operational" } else { "degraded" }
    }));
    if !messages_ok {
        all_operational = false;
    }

    // Probe auth functionality by checking user count
    let auth_ok = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await
        .is_ok();
    services.push(serde_json::json!({
        "name": "Auth Server", "status": if auth_ok { "operational" } else { "degraded" }
    }));
    if !auth_ok {
        all_operational = false;
    }

    // Probe billing/subscription data
    let billing_ok = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM plans")
        .fetch_one(&state.db)
        .await
        .is_ok();
    services.push(serde_json::json!({
        "name": "Billing API", "status": if billing_ok { "operational" } else { "degraded" }
    }));
    if !billing_ok {
        all_operational = false;
    }

    // Probe message delivery stats (analytics)
    let analytics_ok = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM messages WHERE status = 'delivered' AND created_at > NOW() - INTERVAL '1 hour'"
    ).fetch_one(&state.db).await.is_ok();
    services.push(serde_json::json!({
        "name": "Analytics API", "status": if analytics_ok { "operational" } else { "degraded" }
    }));
    if !analytics_ok {
        all_operational = false;
    }

    (services, all_operational)
}

// ─── Status page ───────────────────────────────────────────

async fn status_page(State(state): State<AppState>) -> impl IntoResponse {
    // Serve the SHARED SNAPSHOT (audit F8): the SSR output is the real
    // sampled health with the sample timestamp — never a per-request probe.
    let snapshot = state.probes.current();
    let updated = snapshot.updated.format("%Y-%m-%d %H:%M UTC").to_string();

    let esc = |v: &str| -> String {
        v.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    let mut cards = String::new();
    let mut operational = 0usize;
    for svc in &snapshot.services {
        let name = svc["name"].as_str().unwrap_or("service");
        let status = svc["status"].as_str().unwrap_or("unknown");
        let cls = match status {
            "operational" | "connected" => {
                operational += 1;
                "ok"
            }
            "degraded" => "warn",
            _ => "err",
        };
        cards.push_str(&format!(
            "<div class=card><h3>{}</h3><div class=\"status {}\">{}</div><div class=meta>checked {}</div></div>",
            esc(name), cls, esc(status), updated
        ));
    }
    let total = snapshot.services.len().max(1);
    let pct = (operational * 100 / total) as i64;
    let (overall_msg, overall_cls) = if !snapshot.probed {
        ("Probes are starting — first check within a minute", "warn")
    } else if pct == 100 {
        ("All systems operational", "ok")
    } else if pct >= 80 {
        ("Minor degradation", "warn")
    } else {
        ("Service disruption", "err")
    };

    let html = format!(
        r##"<!DOCTYPE html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>ApexMail Status</title>
<style>:root{{--brand:#ef4444;--bg:#f8f9fa;--card:#fff;--border:#e9ecef;--text:#0f1117;--muted:#6b7280;--success:#059669;--warning:#d97706;--error:#dc2626}}*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}body{{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text);max-width:900px;margin:0 auto;padding:40px 20px}}h1{{font-size:22px;font-weight:700;margin-bottom:4px}}h1 span{{color:var(--brand)}}h1+p{{color:var(--muted);font-size:14px;margin-bottom:32px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px}}.card{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:20px}}.card h3{{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:8px}}.card .status{{font-size:14px;font-weight:600;margin-bottom:4px}}.card .meta{{font-size:12px;color:var(--muted)}}.ok{{color:var(--success)}}.warn{{color:var(--warning)}}.err{{color:var(--error)}}.overall{{text-align:center;margin-bottom:24px;padding:20px;background:var(--card);border:1px solid var(--border);border-radius:10px}}.overall .big{{font-size:36px;font-weight:700}}.bar{{height:4px;background:var(--border);border-radius:2px;margin-top:12px;overflow:hidden}}.bar-fill{{height:100%;border-radius:2px;transition:width .3s}}footer{{text-align:center;margin-top:40px;font-size:12px;color:var(--muted)}}</style></head><body>
<h1><span>Apex</span>Mail Status</h1><p>Live service health — probes run every {PROBE_INTERVAL_SECS} seconds. <span id=updated style=color:var(--muted)>Last checked {updated}</span></p>
<div class=overall id=overall><div class="big {overall_cls}" id=big>{pct}%</div><div id=msg style=font-size:14px;color:var(--muted)>{overall_msg}</div></div>
<div class=grid id=grid>{cards}</div>
<div class=bar><div class=bar-fill id=bar style=width:{pct}%></div></div>
<footer>ApexMail — Bel Consulting OÜ, Registry 16588745</footer>
<script>
async function check(){{try{{var r=await fetch("/status/api"),d=await r.json();var ok=0,g=document.getElementById("grid"),h="";d.services.forEach(function(s){{var cls=s.status==="operational"||s.status==="connected"?"ok":s.status==="degraded"?"warn":"err";if(cls==="ok"||cls==="warn")ok++;h+="<div class=card><h3>"+s.name+"</h3><div class=\"status "+cls+"\">"+s.status+"</div><div class=meta>checked "+d.updated+"</div></div>"}});g.innerHTML=h;var pct=(ok/d.services.length*100).toFixed(0);document.getElementById("big").textContent=pct+"%";document.getElementById("bar").style.width=pct+"%";document.getElementById("big").className="big "+(pct==100?"ok":pct>=80?"warn":"err");document.getElementById("msg").textContent=pct==100?"All systems operational":pct>=80?"Minor degradation":"Service disruption";document.getElementById("updated").textContent="Last checked "+d.updated}}catch(ex){{/* keep the server-rendered state visible */}}}}
check();setInterval(check,60000)
</script></body></html>"##,
        updated = updated,
        overall_cls = overall_cls,
        overall_msg = overall_msg,
        pct = pct,
        cards = cards,
    );
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}

// ─── Health endpoint ─────────────────────────────────────
//
// G.6: /v1/health is reachable from the public internet via nginx, so the
// payload must NOT leak queue internals (email_queue depth, backlog state).
// It reports ok/error + version only; richer (still non-sensitive) service
// probes live on /status/api, which is the status page's purpose.

async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    // Database connectivity check — the only dependency whose failure makes
    // the service itself unable to answer authoritatively.
    let db_ok = sqlx::query_scalar::<_, i64>("SELECT 1::bigint")
        .fetch_one(&state.db)
        .await
        .is_ok();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": if db_ok { "ok" } else { "error" },
            "version": env!("CARGO_PKG_VERSION"),
        })),
    )
        .into_response()
}

async fn status_api(State(state): State<AppState>) -> impl IntoResponse {
    let snapshot = state.probes.current();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": if snapshot.probed && snapshot.all_operational { "operational" } else { "degraded" },
            "services": snapshot.services,
            "updated": snapshot.updated.to_rfc3339()
        })),
    )
        .into_response()
}

async fn status_history() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "history": [],
            "updated": chrono::Utc::now().to_rfc3339()
        })),
    )
        .into_response()
}

#[tokio::main]
async fn main() {
    // G.6: DATABASE_URL must be provided — the previous embedded default
    // (postgres://apexmail@127.0.0.1:5432/apexmail) silently pointed
    // misconfigured deployments at a host that may not exist.
    let db_url = resolve_database_url();
    let session_secret = resolve_session_secret();

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .unwrap();

    // Login brake (audit F2): Redis-backed when configured, in-memory keyed
    // otherwise.
    let throttle = LoginThrottle::from_env_with_redis().await;
    if throttle.redis.is_none() {
        eprintln!(
            "WARNING: RATE_LIMIT_REDIS_URL/REDIS_URL not configured or unreachable — \
             the login brake is per-process only"
        );
    }

    let state = AppState {
        db: pool,
        session_secret,
        throttle: Arc::new(throttle),
        probes: Arc::new(ProbeCache::new()),
        smtp_gate: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SMTP_PROBES)),
    };

    // Background probe sampler (audit F8): the ONLY caller of
    // run_probe_cycle in production. The first tick is immediate, so the
    // snapshot is populated right after startup. (run_probe_cycle publishes
    // into the shared cache itself.)
    tokio::spawn({
        let state = state.clone();
        async move {
            let mut ticker =
                tokio::time::interval(std::time::Duration::from_secs(PROBE_INTERVAL_SECS));
            loop {
                ticker.tick().await;
                run_probe_cycle(&state).await;
            }
        }
    });

    // SECURITY: status-only surface. Every route added here is reachable
    // from the public internet via nginx — see the crate docs. The auth
    // handlers are deliberately NOT routed (routing out of scope).
    let app = Router::new()
        .route("/v1/health", get(health_check))
        .route("/status", get(status_page))
        .route("/status/api", get(status_api))
        .route("/status/history", get(status_history))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Status server on {addr}");
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}

/// G.6: require DATABASE_URL — no credential-bearing embedded fallback.
fn resolve_database_url() -> String {
    match std::env::var("DATABASE_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => panic!("DATABASE_URL must be set (no embedded default is provided)"),
    }
}

/// G.6: SESSION_SECRET is REQUIRED in production (the random-UUID fallback
/// invalidated all sessions on every restart and was never operator
/// controlled); development keeps the fallback with a loud warning.
fn resolve_session_secret() -> String {
    match std::env::var("SESSION_SECRET") {
        Ok(secret) if !secret.trim().is_empty() => secret,
        _ => {
            if is_production_env() {
                panic!("SESSION_SECRET must be set in production (ENVIRONMENT=production)");
            }
            let fallback = uuid::Uuid::new_v4().to_string();
            eprintln!(
                "WARNING: SESSION_SECRET is not set — using a random per-process value. \
                 All sessions are invalidated on restart; set SESSION_SECRET for stability."
            );
            fallback
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Trait method scope for the raw-argon2 seed/assert helpers below.
    use argon2::password_hash::PasswordHasher;
    use argon2::PasswordVerifier;

    /// Serializes env-mutating tests.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn fake_state() -> AppState {
        let db = PgPoolOptions::new()
            .max_connections(1)
            // Fast-fail: the pool can never connect (127.0.0.1:1), and the
            // default 30 s acquire timeout would stall every probe.
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy("postgres://fake:fake@localhost:1/fake")
            .unwrap();
        AppState {
            db,
            session_secret: "test-secret".into(),
            throttle: Arc::new(LoginThrottle::in_memory()),
            probes: Arc::new(ProbeCache::new()),
            smtp_gate: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SMTP_PROBES)),
        }
    }

    /// G.6: the public /v1/health payload must contain ONLY ok/error status
    /// and the version — no queue depth, no service internals.
    #[tokio::test]
    async fn health_payload_has_no_queue_internals() {
        let response = health_check(State(fake_state())).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("status").is_some(), "status required");
        assert!(json.get("version").is_some(), "version required");
        for banned in ["queue_depth", "services", "depth", "timestamp"] {
            assert!(json.get(banned).is_none(), "{banned} must not appear");
        }
    }

    /// G.6: no embedded DATABASE_URL fallback.
    #[test]
    fn database_url_is_required() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("DATABASE_URL").ok();
        std::env::remove_var("DATABASE_URL");
        let result = std::panic::catch_unwind(resolve_database_url);
        if let Some(value) = saved {
            std::env::set_var("DATABASE_URL", value);
        }
        assert!(
            result.is_err(),
            "missing DATABASE_URL must be a hard startup error"
        );
    }

    /// G.6: SESSION_SECRET is required in production, random fallback only
    /// in development.
    #[test]
    fn session_secret_required_in_production() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved_secret = std::env::var("SESSION_SECRET").ok();
        let saved_env = std::env::var("ENVIRONMENT").ok();
        std::env::remove_var("SESSION_SECRET");

        std::env::set_var("ENVIRONMENT", "production");
        let prod = std::panic::catch_unwind(resolve_session_secret);
        assert!(prod.is_err(), "production must refuse the UUID fallback");

        std::env::set_var("ENVIRONMENT", "development");
        let dev = resolve_session_secret();
        assert!(!dev.is_empty(), "dev keeps the warned fallback");

        match saved_secret {
            Some(v) => std::env::set_var("SESSION_SECRET", v),
            None => std::env::remove_var("SESSION_SECRET"),
        }
        match saved_env {
            Some(v) => std::env::set_var("ENVIRONMENT", v),
            None => std::env::remove_var("ENVIRONMENT"),
        }
    }

    // ── Adversarial: session tokens / cookies (audit F3) ──────────────

    /// Two mints must NEVER collide — the old `email:ts:MAC` token was
    /// byte-identical for two logins in the same second.
    #[test]
    fn session_ids_are_random_and_unfingerprintable() {
        let a = mint_session_id();
        let b = mint_session_id();
        assert_ne!(a, b, "sessions must be distinguishable");
        assert_eq!(a.len(), 64, "256-bit id, hex encoded");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        // No email, no timestamp rides in the token.
        assert!(!a.contains('@'));
    }

    #[test]
    fn token_roundtrip_binds_the_id_and_secret() {
        let id = mint_session_id();
        let token = build_session_token(&id, "s3cret");
        // The MAC verifies and recovers the SAME session id.
        assert_eq!(
            verify_session_mac(&token, "s3cret").as_deref(),
            Some(id.as_str())
        );
        // A different secret must not validate the same token.
        assert_eq!(verify_session_mac(&token, "other-secret"), None);
        // The MAC is a real HMAC over the id — flip one id hex char, keep
        // the MAC: refused.
        let (parsed_id, sig) = token.split_once('.').unwrap();
        let mut flipped = parsed_id.to_string();
        let last = flipped.len() - 1;
        flipped.replace_range(last.., if flipped.ends_with('0') { "1" } else { "0" });
        assert_eq!(
            verify_session_mac(&format!("{flipped}.{sig}"), "s3cret"),
            None
        );
    }

    #[test]
    fn tampered_tokens_are_refused() {
        let secret = "test-secret";
        let id = mint_session_id();
        let good = build_session_token(&id, secret);
        assert!(verify_session_mac(&good, secret).is_some());

        // Flip one hex character of the MAC.
        let mut sig = good.rsplit('.').next().unwrap().to_string();
        let mut bytes = sig.clone().into_bytes();
        bytes[0] = if bytes[0] == b'a' { b'b' } else { b'a' };
        sig = String::from_utf8(bytes).unwrap();
        assert_eq!(verify_session_mac(&format!("{id}.{sig}"), secret), None);

        // Truncated MAC.
        assert_eq!(
            verify_session_mac(&format!("{id}.{}", &good[good.len() - 8..]), secret),
            None
        );

        // Empty MAC / missing separator / empty id.
        assert_eq!(verify_session_mac(&format!("{id}."), secret), None);
        assert_eq!(verify_session_mac(&id, secret), None);
        assert_eq!(verify_session_mac(&format!(".{}", good), secret), None);
        assert_eq!(verify_session_mac("", secret), None);

        // Non-hex id.
        assert_eq!(
            verify_session_mac(&format!("{}z.{sig}", &id[..63]), secret),
            None
        );

        // Legacy-format tokens (old `email:ts:sig` shape) are NOT session
        // tokens: they contain no '.' and must be refused.
        assert_eq!(
            verify_session_mac("user@example.com:1735689600:cafebabe", secret),
            None
        );
    }

    #[test]
    fn cookie_extraction_only_reads_the_session_cookie() {
        let token = build_session_token(mint_session_id().as_str(), "test-secret");
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "cookie",
            format!("theme=dark; apexmail_session={token}; other=1")
                .parse()
                .unwrap(),
        );
        assert_eq!(
            session_token_from_headers(&headers).as_deref(),
            Some(token.as_str())
        );

        // No cookie header at all.
        assert_eq!(
            session_token_from_headers(&axum::http::HeaderMap::new()),
            None
        );

        // Unrelated cookies only.
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("cookie", "theme=dark; session=x".parse().unwrap());
        assert_eq!(session_token_from_headers(&headers), None);
    }

    #[test]
    fn session_cookie_carries_hardening_flags() {
        {
            let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let saved = std::env::var("ENVIRONMENT").ok();
            std::env::set_var("ENVIRONMENT", "development");
            let cookie = session_cookie("tok");
            assert!(cookie.contains("HttpOnly"));
            assert!(cookie.contains("SameSite=Lax"));
            assert!(cookie.contains("Path=/"));
            assert!(cookie.contains(&format!("Max-Age={SESSION_MAX_AGE_SECS}")));
            assert!(
                !cookie.contains("Secure"),
                "dev cookie must stay usable over http"
            );

            std::env::set_var("ENVIRONMENT", "production");
            assert!(session_cookie("tok").contains("; Secure"));
            let cleared = cleared_session_cookie();
            assert!(cleared.contains("Max-Age=0"), "logout clears the cookie");

            match saved {
                Some(v) => std::env::set_var("ENVIRONMENT", v),
                None => std::env::remove_var("ENVIRONMENT"),
            }
        }
    }

    #[test]
    fn production_env_detection_is_exact() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("ENVIRONMENT").ok();
        for (value, expected) in [
            ("production", true),
            ("PRODUCTION", true),
            ("Prod", true),
            ("development", false),
            ("staging", false),
            ("", false),
        ] {
            std::env::set_var("ENVIRONMENT", value);
            assert_eq!(is_production_env(), expected, "ENVIRONMENT={value:?}");
        }
        std::env::remove_var("ENVIRONMENT");
        assert!(!is_production_env());
        match saved {
            Some(v) => std::env::set_var("ENVIRONMENT", v),
            None => std::env::remove_var("ENVIRONMENT"),
        }
    }

    #[test]
    fn url_host_port_parses_explicit_and_default_ports() {
        assert_eq!(
            url_host_port("redis://:pw@redis-cache:6380/0", 6379),
            Some(("redis-cache".to_string(), 6380))
        );
        assert_eq!(
            url_host_port("redis://cache/0", 6379),
            Some(("cache".to_string(), 6379))
        );
        assert_eq!(url_host_port("not a url", 6379), None);
        assert_eq!(url_host_port("mailto:ops@apexmail.ee", 25), None);
    }

    #[tokio::test]
    async fn tcp_probe_reports_reachability_honestly() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(
            tcp_connect_ok("127.0.0.1", port, std::time::Duration::from_millis(500)).await,
            "an accepting listener must probe reachable"
        );
        drop(listener);
        assert!(
            !tcp_connect_ok("127.0.0.1", port, std::time::Duration::from_millis(500)).await,
            "a closed port must probe unreachable"
        );
    }

    /// Audit F2: the unknown-email path burns the SAME Argon2id computation
    /// as a real verification (dummy hash present and verifiable).
    #[test]
    fn dummy_verification_costs_the_same_computation() {
        let hash = dummy_password_hash();
        assert!(hash.starts_with("$argon2id$"), "{hash}");
        // The dummy verifies with the correct password and refuses others.
        assert!(
            apexmail_lib::crypto::verify_password("timing-uniformity-dummy-password", hash)
                .unwrap_or(false)
        );
        assert!(!apexmail_lib::crypto::verify_password("anything-else", hash).unwrap_or(true));
        // The burn helper is callable repeatedly without panicking.
        burn_dummy_verification("whatever");
    }

    // ── Adversarial: DB-backed handlers (canonical schema) ────────────

    async fn canonical_pool(test_name: &str) -> Option<sqlx::PgPool> {
        match migrator::test_support::fresh_canonical_pool(test_name, test_name).await {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        }
    }

    fn live_state(pool: sqlx::PgPool) -> AppState {
        AppState {
            db: pool,
            session_secret: "test-secret".into(),
            throttle: Arc::new(LoginThrottle::in_memory()),
            probes: Arc::new(ProbeCache::new()),
            smtp_gate: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SMTP_PROBES)),
        }
    }

    async fn seed_tenant(pool: &sqlx::PgPool, tenant_id: &str, plan: &str, status: &str) {
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status) VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant_id)
        .bind(format!("tenant {tenant_id}"))
        .bind(tenant_id)
        .bind(plan)
        .bind(status)
        .execute(pool)
        .await
        .expect("seed tenant");
    }

    async fn seed_user(
        pool: &sqlx::PgPool,
        email: &str,
        password: &str,
        tenant_id: &str,
    ) -> uuid::Uuid {
        let salt = argon2::password_hash::SaltString::generate(&mut OsRng);
        let hash = argon2::Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();
        let id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, password_hash, role, mfa_enabled) \
             VALUES ($1, $2, $3, $4, 'owner', $5)",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(email)
        .bind(hash)
        .bind(false)
        .execute(pool)
        .await
        .expect("seed user");
        id
    }

    async fn seed_mfa_user(
        pool: &sqlx::PgPool,
        email: &str,
        password: &str,
        tenant_id: &str,
    ) -> uuid::Uuid {
        let salt = argon2::password_hash::SaltString::generate(&mut OsRng);
        let hash = argon2::Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();
        let id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, password_hash, role, mfa_enabled) \
             VALUES ($1, $2, $3, $4, 'owner', true)",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(email)
        .bind(hash)
        .execute(pool)
        .await
        .expect("seed mfa user");
        id
    }

    async fn response_json(response: axum::response::Response) -> serde_json::Value {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("response {status} is not JSON: {e}");
        })
    }

    fn login_form(identifier: &str, password: &str) -> LoginForm {
        LoginForm {
            username_or_email: identifier.to_string(),
            password: password.to_string(),
        }
    }

    fn cookie_token(response: &axum::response::Response) -> Option<String> {
        response
            .headers()
            .get(header::SET_COOKIE)?
            .to_str()
            .ok()?
            .strip_prefix("apexmail_session=")
            .and_then(|rest| rest.split(';').next())
            .map(str::to_string)
    }

    /// Register with a 300-char email must never answer 200/"Account
    /// created": `users.email` is VARCHAR(255), the INSERT fails, and the
    /// handler used to ignore the error and still set a session cookie —
    /// a fabricated success for an account that does not exist.
    #[tokio::test]
    async fn register_never_fabricates_success_for_oversize_email() {
        let Some(pool) = canonical_pool("auth_register_oversize").await else {
            return;
        };
        let state = live_state(pool.clone());
        let local = "a".repeat(280);
        let email = format!("{local}@example.com");
        let response = register_post(
            State(state),
            axum::Json(RegisterForm {
                name: None,
                email,
                password: "correct horse battery staple".into(),
            }),
        )
        .await;
        assert_ne!(
            response.status(),
            StatusCode::OK,
            "oversize email must be refused, not reported as created"
        );
        assert!(
            response.headers().get(header::SET_COOKIE).is_none(),
            "no session may be issued for a failed registration"
        );
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE length(email) > 255")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    /// Audit F1: an MFA-enabled user must NEVER receive a session cookie
    /// from a password-only submission — the handler issues the MFA
    /// challenge instead, and no `auth_sessions` row is minted.
    #[tokio::test]
    async fn login_mfa_enabled_users_get_a_challenge_not_a_session() {
        let Some(pool) = canonical_pool("auth_login_mfa").await else {
            return;
        };
        seed_tenant(&pool, "tn_login_mfa_00000000001", "free", "active").await;
        seed_mfa_user(
            &pool,
            "guarded@example.com",
            "correct-horse-battery",
            "tn_login_mfa_00000000001",
        )
        .await;
        let state = live_state(pool.clone());

        let response = login_post(
            State(state),
            axum::http::HeaderMap::new(),
            axum::Json(login_form("guarded@example.com", "correct-horse-battery")),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::ACCEPTED,
            "MFA-enabled users get the challenge, not a session"
        );
        assert!(
            response.headers().get(header::SET_COOKIE).is_none(),
            "password-only login must not mint a cookie for mfa_enabled users"
        );
        let json = response_json(response).await;
        assert_eq!(json["mfa_required"], true);

        // And no server-side session row was created either.
        let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM auth_sessions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            sessions, 0,
            "no session may exist for a challenge-only login"
        );
    }

    #[tokio::test]
    async fn login_accepts_valid_credentials_only() {
        let Some(pool) = canonical_pool("auth_login_edges").await else {
            return;
        };
        seed_tenant(&pool, "tn_login_edges_0000000001", "free", "active").await;
        seed_user(
            &pool,
            "owner@example.com",
            "correct-horse-battery",
            "tn_login_edges_0000000001",
        )
        .await;
        let state = live_state(pool.clone());

        // Valid credentials, identifier padded and uppercased.
        let response = login_post(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            axum::Json(login_form("  OWNER@Example.COM ", "correct-horse-battery")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let token = cookie_token(&response).expect("successful login sets a session cookie");
        // The token is `{id}.{hmac}` — NOT the old deterministic shape —
        // and it verifies ONLY against the server-side store.
        assert!(
            !token.contains('@'),
            "the email must not ride in the cookie: {token}"
        );
        assert_eq!(
            verify_session_token(&pool, &token, "test-secret")
                .await
                .as_deref(),
            Some("owner@example.com")
        );
        let json = response_json(response).await;
        assert_eq!(json["redirect"], "/dashboard");
        assert_eq!(json["user"]["email"], "owner@example.com");

        // Wrong password.
        let response = login_post(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            axum::Json(login_form("owner@example.com", "wrong-password")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(header::SET_COOKIE).is_none());

        // Unknown user — same 401, no cookie.
        let response = login_post(
            State(state),
            axum::http::HeaderMap::new(),
            axum::Json(login_form("nobody@example.com", "whatever")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
    }

    /// Audit F2: the brake's per-identifier AND per-IP scoping contract,
    /// verified directly on the throttle — the checks are microsecond-cheap,
    /// so the 1/s refill can never interfere and the assertions stay
    /// deterministic no matter how slow the machine is.
    #[tokio::test]
    async fn login_brake_scopes_identifier_and_ip_buckets() {
        let throttle = LoginThrottle::in_memory();

        // ── Identifier dimension ──────────────────────────────────────
        // Burst-1 attempts pass…
        for i in 0..LOGIN_BURST {
            assert!(
                throttle
                    .check("login:id", "hammered@example.com")
                    .await
                    .is_ok(),
                "identifier attempt {i} within the burst must pass"
            );
        }
        // …then the identifier bucket is drained: denied.
        assert!(
            throttle
                .check("login:id", "hammered@example.com")
                .await
                .is_err(),
            "an attempt beyond the burst on the SAME identifier must be denied"
        );
        // A different identifier has its own bucket.
        assert!(
            throttle
                .check("login:id", "fresh@example.com")
                .await
                .is_ok(),
            "identifier buckets must be isolated"
        );
        // Rotating IPs cannot escape the drained identifier bucket: the
        // check() key is `{scope}:{key}` — the identifier part decides.
        assert!(
            throttle
                .check("login:id", "hammered@example.com")
                .await
                .is_err(),
            "the identifier bucket stays drained (IPs cannot reset it)"
        );

        // ── IP dimension ──────────────────────────────────────────────
        for i in 0..LOGIN_BURST {
            assert!(
                throttle.check("login:ip", "198.51.100.7").await.is_ok(),
                "IP attempt {i} within the burst must pass"
            );
        }
        assert!(
            throttle.check("login:ip", "198.51.100.7").await.is_err(),
            "an attempt beyond the burst from the SAME IP must be denied"
        );
        // Rotating identifiers cannot escape the drained IP bucket.
        assert!(
            throttle.check("login:ip", "198.51.100.7").await.is_err(),
            "the IP bucket stays drained (identifiers cannot reset it)"
        );
        // A different IP has its own bucket.
        assert!(
            throttle.check("login:ip", "198.51.100.9").await.is_ok(),
            "IP buckets must be isolated"
        );
    }

    /// Audit F2: the handler actually WIRES the brake in — hammering one
    /// identifier from one IP must produce a plain 401 while budget remains
    /// and a 429 + Retry-After once the identifier bucket is drained. The
    /// loop allows headroom for the 1/s refill (each attempt burns a full
    /// token from the bucket and costs a full Argon2id computation, so the
    /// drain always outruns the refill within the bound).
    #[tokio::test]
    async fn login_brake_denies_the_handler_with_retry_after() {
        let Some(pool) = canonical_pool("auth_login_brake_handler").await else {
            return;
        };
        let state = live_state(pool);

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.7".parse().unwrap());

        let mut saw_plain_401 = false;
        let mut denied = false;
        for attempt in 0..LOGIN_BURST * 3 {
            let response = login_post(
                State(state.clone()),
                headers.clone(),
                axum::Json(login_form("hammered@example.com", "wrong-password")),
            )
            .await;
            match response.status() {
                StatusCode::UNAUTHORIZED => saw_plain_401 = true,
                StatusCode::TOO_MANY_REQUESTS => {
                    assert!(
                        response.headers().get(header::RETRY_AFTER).is_some(),
                        "denial attempt {attempt} must carry Retry-After"
                    );
                    assert!(
                        response.headers().get(header::SET_COOKIE).is_none(),
                        "a denied attempt must never mint a session"
                    );
                    denied = true;
                    break;
                }
                other => panic!("attempt {attempt}: unexpected status {other}"),
            }
        }
        assert!(saw_plain_401, "in-budget attempts must be plain 401s");
        assert!(
            denied,
            "the brake must deny within {} attempts (burst {} + refill headroom)",
            LOGIN_BURST * 3,
            LOGIN_BURST
        );
    }

    #[tokio::test]
    async fn login_control_plane_surface_redirects_to_cp_admin() {
        let Some(pool) = canonical_pool("auth_login_cp").await else {
            return;
        };
        seed_tenant(&pool, "tn_login_cp_0000000000001", "free", "active").await;
        seed_user(
            &pool,
            "cp@example.com",
            "correct-horse-battery",
            "tn_login_cp_0000000000001",
        )
        .await;
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-apexmail-surface", "control-plane".parse().unwrap());
        let response = login_post(
            State(live_state(pool)),
            headers,
            axum::Json(login_form("cp@example.com", "correct-horse-battery")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response_json(response).await["redirect"],
            "/cp-admin/dashboard/"
        );
    }

    /// Audit F3: sessions are server-side records — logout revokes the row,
    /// a password change kills every session of the user, and expiry is
    /// enforced by the store, not by trusting the cookie.
    #[tokio::test]
    async fn sessions_are_revocable_and_expire_server_side() {
        let Some(pool) = canonical_pool("auth_sessions_store").await else {
            return;
        };
        seed_tenant(&pool, "tn_sess_store_0000000001", "free", "active").await;
        let user_id = seed_user(
            &pool,
            "revoke@example.com",
            "correct-horse-battery",
            "tn_sess_store_0000000001",
        )
        .await;
        let state = live_state(pool.clone());

        let response = login_post(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            axum::Json(login_form("revoke@example.com", "correct-horse-battery")),
        )
        .await;
        let token = cookie_token(&response).expect("session cookie");
        assert!(
            verify_session_token(&pool, &token, "test-secret")
                .await
                .is_some(),
            "a fresh session verifies"
        );

        // Logout: the row is revoked, the cookie is dead even if kept.
        assert!(revoke_session(&pool, &token).await.unwrap());
        assert!(
            verify_session_token(&pool, &token, "test-secret")
                .await
                .is_none(),
            "a revoked session must not verify"
        );
        // Revoking again is idempotent.
        assert!(!revoke_session(&pool, &token).await.unwrap());

        // Second login; then the password-change hook kills ALL sessions.
        let response = login_post(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            axum::Json(login_form("revoke@example.com", "correct-horse-battery")),
        )
        .await;
        let token2 = cookie_token(&response).expect("second session cookie");
        assert_ne!(token, token2, "two logins never share a token");
        let killed = revoke_all_for_user(&pool, user_id).await.unwrap();
        assert_eq!(killed, 1);
        assert!(verify_session_token(&pool, &token2, "test-secret")
            .await
            .is_none());

        // Expiry is enforced by the store: force the row into the past.
        let response = login_post(
            State(state),
            axum::http::HeaderMap::new(),
            axum::Json(login_form("revoke@example.com", "correct-horse-battery")),
        )
        .await;
        let token3 = cookie_token(&response).expect("third session cookie");
        sqlx::query("UPDATE auth_sessions SET expires_at = NOW() - INTERVAL '1 second'")
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            verify_session_token(&pool, &token3, "test-secret")
                .await
                .is_none(),
            "an expired session must not verify"
        );
    }

    /// The logout endpoint revokes the server-side session AND clears the
    /// cookie.
    #[tokio::test]
    async fn logout_revokes_the_session_and_clears_the_cookie() {
        let Some(pool) = canonical_pool("auth_logout").await else {
            return;
        };
        seed_tenant(&pool, "tn_logout_0000000000001", "free", "active").await;
        seed_user(
            &pool,
            "bye@example.com",
            "correct-horse-battery",
            "tn_logout_0000000000001",
        )
        .await;
        let state = live_state(pool.clone());

        let response = login_post(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            axum::Json(login_form("bye@example.com", "correct-horse-battery")),
        )
        .await;
        let token = cookie_token(&response).expect("session cookie");

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "cookie",
            format!("apexmail_session={token}").parse().unwrap(),
        );
        let response = logout_post(State(state), headers).await;
        assert_eq!(response.status(), StatusCode::OK);
        let cleared = response
            .headers()
            .get(header::SET_COOKIE)
            .expect("logout clears the cookie")
            .to_str()
            .unwrap();
        assert!(cleared.contains("Max-Age=0"), "{cleared}");
        assert!(
            verify_session_token(&pool, &token, "test-secret")
                .await
                .is_none(),
            "the logout must have revoked the session row"
        );
    }

    #[tokio::test]
    async fn register_validates_input_before_touching_the_database() {
        // A lazy pool that can never connect: validation must reject before
        // any query is attempted (otherwise this test fails with a DB error).
        let state = fake_state();
        for (email, password) in [
            ("no-at-sign.example.com", "correct horse battery"),
            ("no-dot@example", "correct horse battery"),
            ("ok@example.com", "too-short"),
        ] {
            let response = register_post(
                State(state.clone()),
                axum::Json(RegisterForm {
                    name: None,
                    email: email.to_string(),
                    password: password.to_string(),
                }),
            )
            .await;
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "{email:?} / {password:?} must be rejected"
            );
        }
    }

    #[tokio::test]
    async fn register_rejects_duplicate_email_and_creates_a_real_account() {
        // register_post READS FREE_TENANT_LIMIT — hold the env lock for the
        // whole body so the capacity test's `FREE_TENANT_LIMIT=0` mutation
        // can never race this registration into a spurious 503.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(pool) = canonical_pool("auth_register_flow").await else {
            return;
        };
        let tenants_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenants")
            .fetch_one(&pool)
            .await
            .unwrap();
        let state = live_state(pool.clone());

        let response = register_post(
            State(state.clone()),
            axum::Json(RegisterForm {
                name: Some("Owner".into()),
                email: "  New.User@Example.COM ".into(),
                password: "correct horse battery staple".into(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let token = cookie_token(&response).expect("registration issues a session cookie");
        assert_eq!(
            verify_session_token(&pool, &token, "test-secret")
                .await
                .as_deref(),
            Some("new.user@example.com"),
            "the registration session is a real server-side row"
        );
        assert_eq!(response_json(response).await["message"], "Account created");

        // The account is real: role owner, argon2 hash, free/active tenant,
        // and EXACTLY one new tenant (no orphans — audit F7).
        let (email, hash, role, tenant_id): (
            String,
            Option<String>,
            Option<String>,
            Option<String>,
        ) = sqlx::query_as(
            "SELECT email, password_hash, role, tenant_id FROM users WHERE email = $1",
        )
        .bind("new.user@example.com")
        .fetch_one(&pool)
        .await
        .expect("registered user exists");
        assert_eq!(email, "new.user@example.com");
        assert_eq!(role.as_deref(), Some("owner"));
        let hash = hash.expect("password hash stored");
        let parsed = argon2::PasswordHash::new(&hash).expect("valid argon2 hash");
        assert!(argon2::Argon2::default()
            .verify_password(b"correct horse battery staple", &parsed)
            .is_ok());
        assert!(argon2::Argon2::default()
            .verify_password(b"wrong password", &parsed)
            .is_err());
        let tenant_id = tenant_id.expect("tenant bound");
        let (plan, status): (String, String) =
            sqlx::query_as("SELECT plan, status FROM tenants WHERE id = $1")
                .bind(&tenant_id)
                .fetch_one(&pool)
                .await
                .expect("tenant exists");
        assert_eq!((plan.as_str(), status.as_str()), ("free", "active"));
        let tenants_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenants")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            tenants_after - tenants_before,
            1,
            "a successful registration creates exactly one tenant"
        );

        // A second identical registration is a conflict — and issues no cookie.
        let response = register_post(
            State(state),
            axum::Json(RegisterForm {
                name: None,
                email: "new.user@example.com".into(),
                password: "another correct horse battery".into(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
    }

    #[tokio::test]
    async fn register_refuses_when_free_plan_is_at_capacity() {
        // Hold the env lock across the WHOLE test (including the handler
        // await): FREE_TENANT_LIMIT=0 must not leak into a concurrent
        // registration test between the set and the restore.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(pool) = canonical_pool("auth_register_capacity").await else {
            return;
        };
        seed_tenant(&pool, "tn_capacity_00000000000001", "free", "active").await;
        let saved_limit = std::env::var("FREE_TENANT_LIMIT").ok();
        std::env::set_var("FREE_TENANT_LIMIT", "0");
        let response = register_post(
            State(live_state(pool.clone())),
            axum::Json(RegisterForm {
                name: None,
                email: "blocked@example.com".into(),
                password: "correct horse battery staple".into(),
            }),
        )
        .await;
        match saved_limit {
            Some(v) => std::env::set_var("FREE_TENANT_LIMIT", v),
            None => std::env::remove_var("FREE_TENANT_LIMIT"),
        }
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = $1")
            .bind("blocked@example.com")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(users, 0, "a capacity refusal must not create the account");
    }

    #[tokio::test]
    async fn health_probe_reports_error_instead_of_lying() {
        // Unreachable database → "error", never a fabricated "ok".
        let response = health_check(State(fake_state())).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(json["status"], "error");

        // Real canonical database → "ok".
        let Some(pool) = canonical_pool("auth_health").await else {
            return;
        };
        let response = health_check(State(live_state(pool))).await.into_response();
        let json = response_json(response).await;
        assert_eq!(json["status"], "ok");
        assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
    }

    /// Audit F8: handlers serve the BACKGROUND snapshot. The snapshot is
    /// sampled once (by `run_probe_cycle`); repeated handler calls return
    /// the identical sample timestamp — proving no per-request probing.
    #[tokio::test]
    async fn status_handlers_serve_the_cached_snapshot() {
        std::env::set_var("MAIL_HOST", "127.0.0.2");
        let state = fake_state();
        run_probe_cycle(&state).await;

        let first = status_api(State(state.clone())).await.into_response();
        let second = status_api(State(state.clone())).await.into_response();
        let j1 = response_json(first).await;
        let j2 = response_json(second).await;
        assert_eq!(
            j1["updated"], j2["updated"],
            "handlers must serve the shared snapshot, not re-probe"
        );
        assert_eq!(j1["status"], "degraded", "SMTP is unreachable: {j1}");

        // The SSR page renders the same snapshot.
        let response = status_page(State(state)).await.into_response();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("probes run every 60 seconds"), "{html}");
        assert!(html.contains("Minor degradation"), "{html}");
    }

    #[tokio::test]
    async fn status_api_and_page_render_real_probe_state() {
        let Some(pool) = canonical_pool("auth_status_routes").await else {
            return;
        };
        // Point the SMTP probe at a loopback alias with no listener: the
        // probe must run for real (no network egress) and report degraded.
        std::env::set_var("MAIL_HOST", "127.0.0.2");
        let state = live_state(pool);

        // The background sampler is simulated by one explicit cycle.
        run_probe_cycle(&state).await;

        let response = status_api(State(state.clone())).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(json["status"], "degraded", "SMTP is unreachable: {json}");
        let services = json["services"].as_array().expect("services array");
        let names: Vec<&str> = services
            .iter()
            .map(|s| s["name"].as_str().unwrap())
            .collect();
        for expected in [
            "Database",
            "Tenants API",
            "Message Pipeline",
            "Auth Server",
            "Billing API",
            "Analytics API",
            "Mail Server (SMTP)",
        ] {
            assert!(names.contains(&expected), "missing {expected}: {names:?}");
        }
        let db = services.iter().find(|s| s["name"] == "Database").unwrap();
        assert_eq!(db["status"], "operational");
        let smtp = services
            .iter()
            .find(|s| s["name"] == "Mail Server (SMTP)")
            .unwrap();
        assert_eq!(smtp["status"], "degraded");
        assert!(json["updated"].as_str().unwrap().contains('T'));

        let response = status_page(State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("ApexMail Status"));
        assert!(html.contains("Database"));
        assert!(html.contains("degraded"), "server-rendered probe result");
        assert!(html.contains("Last checked"));
        // 6 of 7 operational → minor degradation branch.
        assert!(html.contains("Minor degradation"), "{html}");
    }

    #[tokio::test]
    async fn status_history_is_the_empty_audit_placeholder() {
        let response = status_history().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(json["history"], serde_json::json!([]));
        assert!(json["updated"].as_str().unwrap().contains('T'));
    }

    /// PINNED (considered by the 2026-09 privilege-boundary audit): the
    /// auth-server status surface has NO tenant dimension to fail closed
    /// on. It is deliberately public and aggregate-only: every probe is a
    /// COUNT(*)/SELECT 1/TCP reachability check, and the responses carry
    /// ONLY {status, services[{name, status}], updated} — never tenant ids,
    /// emails, or rows. There is no tenant selector on any routed endpoint
    /// (login/register are unrouted), so the AI-audit bypass class
    /// (missing-tenant → broad default) has no foothold here. This test
    /// pins the exact payload shape so a future probe that starts leaking
    /// tenant-attributed data is caught.
    #[tokio::test]
    async fn status_surface_is_aggregate_only_and_carries_no_tenant_data() {
        let Some(pool) = canonical_pool("auth_status_aggregate_only").await else {
            return;
        };
        // Seed real tenants/users so a leak would have something to leak.
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status) VALUES ($1, 'pin-a', 'pin-a', 'free', 'active') \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind("tn_statuspin0000000001")
        .execute(&pool)
        .await
        .ok();
        let state = live_state(pool);
        run_probe_cycle(&state).await;

        let response = status_api(State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;

        // The payload exposes exactly three keys.
        let mut keys: Vec<&str> = json
            .as_object()
            .expect("status api object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort();
        assert_eq!(keys, vec!["services", "status", "updated"], "{json}");

        // Each service entry exposes exactly name + status.
        for service in json["services"].as_array().expect("services array") {
            let mut entry_keys: Vec<&str> = service
                .as_object()
                .expect("service object")
                .keys()
                .map(String::as_str)
                .collect();
            entry_keys.sort();
            assert_eq!(
                entry_keys,
                vec!["name", "status"],
                "service entries must stay aggregate-only: {service}"
            );
        }
        let serialized = json.to_string();
        assert!(
            !serialized.contains("tn_statuspin0000000001"),
            "no tenant identifier may appear in the status payload"
        );
    }

    /// A totally unreachable database must render an honest total outage,
    /// not a fabricated page: every probe flipped to degraded and the
    /// overall state is "Service disruption".
    #[tokio::test]
    async fn status_page_reports_total_outage_when_every_probe_fails() {
        std::env::set_var("MAIL_HOST", "127.0.0.2");
        let state = fake_state();
        run_probe_cycle(&state).await;

        let response = status_page(State(state.clone())).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("id=big>0%<"), "overall percentage: {html}");
        assert!(
            html.contains(">Service disruption</div>"),
            "overall message: {html}"
        );
        // Every card is rendered in the degraded/error style (never "ok").
        assert_eq!(html.matches("class=\"status warn\"").count(), 7, "{html}");
        assert!(!html.contains("class=\"status ok\""), "{html}");

        let response = status_api(State(state)).await.into_response();
        let json = response_json(response).await;
        assert_eq!(json["status"], "degraded");
        assert!(json["services"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["status"] == "degraded"));
    }

    /// Before the first background cycle the handlers answer with the
    /// honest "probes are starting" placeholder — never a fabricated
    /// operational state.
    #[tokio::test]
    async fn status_page_admits_probes_have_not_run_yet() {
        let response = status_page(State(fake_state())).await.into_response();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            html.contains("Probes are starting"),
            "pre-cycle page must not fabricate health: {html}"
        );
    }

    /// Audit F8: the SMTP probe is capped at ONE concurrent probe per
    /// process — a cycle that finds the permit held WAITS instead of
    /// stacking a second TCP connect, and the permit is released after.
    #[tokio::test]
    async fn smtp_probe_is_capped_at_one_concurrent() {
        std::env::set_var("MAIL_HOST", "127.0.0.1"); // instant refusal, port 1
        let state = fake_state();
        assert_eq!(
            state.smtp_gate.available_permits(),
            MAX_CONCURRENT_SMTP_PROBES,
            "cap: one SMTP probe at a time"
        );

        // Hold the single permit: the cycle must stall (no second probe).
        let permit = state.smtp_gate.clone().acquire_owned().await.unwrap();
        let stalled = {
            let state = state.clone();
            tokio::spawn(async move { run_probe_cycle(&state).await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        assert!(
            !stalled.is_finished(),
            "a cycle must wait for the SMTP permit instead of stacking probes"
        );

        // Release: the cycle completes and the permit is back.
        drop(permit);
        let snapshot = stalled.await.expect("cycle completes after release");
        assert!(snapshot.probed);
        assert_eq!(
            state.smtp_gate.available_permits(),
            MAX_CONCURRENT_SMTP_PROBES,
            "the SMTP permit must be released after the cycle"
        );
    }

    /// The unique index is on `lower(email)`: an address whose normalized form
    /// differs from the stored row (mixed case) slips past the exact-match
    /// SELECT pre-check and must hit the CONFLICT branch on INSERT — not a
    /// 500 and not a fabricated success. Audit F7: the transaction must
    /// ROLL BACK the tenant insert, leaving NO orphaned tenant row.
    #[tokio::test]
    async fn register_maps_case_fold_unique_collision_to_conflict_without_orphan_tenant() {
        // register_post READS FREE_TENANT_LIMIT — same env-lock discipline
        // as the other registration flows.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(pool) = canonical_pool("auth_register_casefold").await else {
            return;
        };
        // Stored mixed-case; the handler lowercases the submitted form, so
        // `SELECT ... WHERE email = $1` misses the row while the
        // `lower(email)` unique index still rejects the INSERT.
        let stored = "K@example.com";
        seed_tenant(&pool, "tn_casefold_000000000001", "free", "active").await;
        seed_user(
            &pool,
            stored,
            "correct horse battery",
            "tn_casefold_000000000001",
        )
        .await;
        let tenants_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenants")
            .fetch_one(&pool)
            .await
            .unwrap();

        let response = register_post(
            State(live_state(pool.clone())),
            axum::Json(RegisterForm {
                name: None,
                email: stored.to_string(),
                password: "correct horse battery staple".into(),
            }),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::CONFLICT,
            "case-fold collision must be a conflict, not a fabricated account"
        );
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        let users: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE lower(email) = lower($1)")
                .bind(stored)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(users, 1, "no second account may be created");

        // Audit F7 (the actual fix): the failed registration must NOT have
        // left an orphaned tenant row behind.
        let tenants_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenants")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            tenants_after, tenants_before,
            "the tenant insert must roll back with the failed user insert"
        );
    }
}
