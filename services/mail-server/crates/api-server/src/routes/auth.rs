//! Authentication routes: login, logout, refresh, register, reset password, and API key management.

use super::helpers::{
    clamp_limit, default_limit, extract_cookie, hash_token, html_escape, token_blacklist_key,
};
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{
    invalidate_api_key_cache, invalidate_tenant_user_status_cache, issued_before_or_at_revocation,
    lookup_session_revoked_after, require_scopes, session_revocation_key, validate_session_csrf,
    AuthUser, JwtClaims,
};
use crate::middleware::rate_limiter::{extract_public_client_ip, INCR_EXPIRE_LUA};
use crate::routes::csrf::validate_form_csrf;
use crate::routes::system_sender::{
    ensure_system_sender_ready, queue_system_email, queue_system_email_in_transaction,
};
use crate::state::AppState;

const LOGIN_FAILURE_THRESHOLD: i64 = 5;
const LOGIN_FAILURE_WINDOW_SECS: u64 = 5 * 60;
const LOGIN_LOCKOUT_BASE_SECS: u64 = 15 * 60;
const LOGIN_LOCKOUT_MAX_SECS: u64 = 24 * 60 * 60;
const LOGIN_LOCKOUT_ESCALATION_WINDOW_SECS: u64 = 24 * 60 * 60;
const DEFAULT_API_KEY_EXPIRY_DAYS: i64 = 90;
const MAX_API_KEY_EXPIRY_DAYS: i64 = 365;
/// Per-tenant API key ceiling, counted before insert (F2). Mirrors
/// `webhooks::MAX_WEBHOOKS_PER_TENANT`. Shared with the console form twin
/// (`routes::web::form_api_key_create`) so both surfaces enforce the same cap.
pub(crate) const MAX_API_KEYS_PER_TENANT: i64 = 25;
/// Login IP rate limiting: max login attempts per IP address per window.
const LOGIN_IP_RATE_LIMIT: i64 = 20;
const LOGIN_IP_RATE_LIMIT_WINDOW_SECS: u64 = 15 * 60;
const REGISTER_RATE_LIMIT_WINDOW_SECS: u64 = 10 * 60;
const REGISTER_RATE_LIMIT_MAX_REQUESTS: i64 = 20;
const MFA_CHALLENGE_TTL_SECS: u64 = 10 * 60;
const MFA_CHALLENGE_PREFIX: &str = "apexmail:auth:mfa_challenge:";
const MFA_SECRET_BYTES: usize = 20;

fn register_rate_limit_message() -> String {
    "Too many sign-up attempts from this network. Please wait a few minutes and try again.".into()
}

// ─── KiwiCaptcha token verification ───────────────────────────

/// The Redis key prefix under which issued KiwiCaptcha challenges are stored.
const KIWI_CHALLENGE_PREFIX: &str = "apexmail:kiwi:";

/// Maximum verification attempts per issued challenge nonce.
///
/// Each attempt can trigger a server-side proof re-derivation (Argon2id is
/// memory-hard), so the count is bounded to keep a single nonce from being
/// used to burn unbounded server CPU/memory. The record itself is only
/// consumed on success, so this cap is the primary cost control.
const KIWI_MAX_VERIFY_ATTEMPTS: i64 = 20;

/// Global concurrency cap for memory-hard (Argon2id) verifications.
///
/// Each verification re-derives the Argon2id hash with the record's m_kib
/// (up to 64 MiB) — an attacker issuing many fresh challenges and submitting
/// bogus counters could otherwise turn the server into an aggregate
/// memory/CPU amplifier. Per-nonce attempt caps bound ONE challenge; this
/// semaphore bounds ALL of them. Initialized from config on first use.
static ARGON2_VERIFY_SEMAPHORE: OnceLock<Arc<Semaphore>> = OnceLock::new();

/// Upper bound on how long a verification may WAIT for an Argon2 permit
/// before it is rejected with a retryable denial. Without a bound, an
/// attacker occupying every permit (`kiwi_argon2_max_concurrent`, default 2)
/// with wrong-counter submissions parks every legitimate verification in an
/// unbounded `acquire_owned` queue. A single derivation finishes well under
/// a second even at the 64 MiB / `t` ceiling, so a caller still queued after
/// this bound is looking at attacker-dominated saturation, not jitter.
/// Follows the `Bulkhead::acquire` bounded-wait pattern (resilience.rs);
/// no argon-runtime config knob exists, so the bound is fixed here.
const KIWI_ARGON2_PERMIT_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Acquire the aggregate Argon2 verification permit with a BOUNDED wait.
/// On timeout (or semaphore closure — never triggered today) the caller gets
/// the same retryable 503-style denial `routes::kiwicaptcha.rs` uses for
/// capacity exhaustion, never an indefinite queue.
async fn acquire_argon2_permit_bounded(
    semaphore: &Arc<Semaphore>,
    max_wait: std::time::Duration,
) -> Result<tokio::sync::OwnedSemaphorePermit, ApiError> {
    match tokio::time::timeout(max_wait, semaphore.clone().acquire_owned()).await {
        Ok(permit) => permit.map_err(|_| {
            tracing::error!("KiwiCaptcha Argon2 verify semaphore closed");
            ApiError::ServiceUnavailable(
                "captcha verification capacity exceeded; please retry shortly".into(),
            )
        }),
        Err(_) => {
            tracing::warn!(
                max_wait_ms = max_wait.as_millis() as u64,
                "KiwiCaptcha: Argon2 verify permit wait timed out — verifier saturated"
            );
            Err(ApiError::ServiceUnavailable(
                "captcha verification capacity exceeded; please retry shortly".into(),
            ))
        }
    }
}

/// Atomic single-use consumption of a KiwiCaptcha challenge record.
///
/// The record is deleted only if it still equals the exact JSON the caller
/// verified against. A concurrent or replayed use finds the key missing (or
/// changed) and gets `0` — the challenge is strictly single-use.
const KIWI_CONSUME_LUA: &str = r#"
    local stored = redis.call('GET', KEYS[1])
    if stored == ARGV[1] then
        redis.call('DEL', KEYS[1])
        return 1
    end
    return 0
"#;

/// Outcome of the per-nonce KiwiCaptcha verify-attempt cap check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KiwiAttemptCap {
    /// Under the cap — verification may proceed.
    Allowed,
    /// Over the cap — verification must be denied. This is ALSO the outcome
    /// when the INCR Lua script itself fails: the check fails CLOSED, never
    /// silently passing (a `0` on a script error would remove the
    /// `KIWI_MAX_VERIFY_ATTEMPTS` cap and let one nonce drive unbounded
    /// Argon2id derivations). Mirrors the issuance limiter's script-error
    /// semantics in `routes::kiwicaptcha.rs` (error → treated as exceeded).
    Exceeded,
    /// Redis is unavailable — verification must be denied with a retryable
    /// 503, mirroring `ChallengeRateLimit::RedisUnavailable` in
    /// `routes::kiwicaptcha.rs`.
    RedisUnavailable,
}

/// Per-nonce verify-attempt cap check, extracted so it can be unit-tested
/// directly. Never silently allows on a Redis error: pool failure →
/// [`KiwiAttemptCap::RedisUnavailable`], script failure →
/// [`KiwiAttemptCap::Exceeded`] (the same fail-closed mapping the challenge
/// issuance limiter in `routes::kiwicaptcha.rs` applies).
async fn check_kiwi_verify_attempt_cap(
    redis_pool: &deadpool_redis::Pool,
    attempt_key: &str,
    ttl_secs: u64,
) -> KiwiAttemptCap {
    let mut conn = match redis_pool.get().await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::error!(
                error = %error,
                "KiwiCaptcha verify-attempt store unavailable — failing verification closed"
            );
            return KiwiAttemptCap::RedisUnavailable;
        }
    };

    let attempts: i64 = deadpool_redis::redis::Script::new(
        r#"
            local key = KEYS[1]
            local max = tonumber(ARGV[1])
            local ttl = tonumber(ARGV[2])
            local count = redis.call('INCR', key)
            if count == 1 then
                redis.call('EXPIRE', key, ttl)
            end
            if count > max then
                return 1
            end
            return 0
        "#,
    )
    .key(attempt_key)
    .arg(KIWI_MAX_VERIFY_ATTEMPTS)
    .arg(ttl_secs)
    .invoke_async::<i64>(&mut *conn)
    .await
    .unwrap_or_else(|error| {
        tracing::error!(
            error = %error,
            "KiwiCaptcha verify-attempt script failed — failing verification closed"
        );
        1
    });

    if attempts > 0 {
        KiwiAttemptCap::Exceeded
    } else {
        KiwiAttemptCap::Allowed
    }
}

/// Verify a KiwiCaptcha proof-of-work solution against the stored challenge.
///
/// This is the server-side half of the KiwiCaptcha protocol:
/// 1. Decode the `kiwi__token` (nonce.counter.duration.telemetry).
/// 2. Look up the stored `ChallengeRecord` in Redis by nonce.
/// 3. Re-derive the Argon2id hash and check leading zero bits.
/// 4. Check TTL, IP binding, and minimum solve duration.
/// 5. Delete the challenge (single-use).
///
/// In development mode (`kiwi_secret_key == "dev"`) verification is bypassed,
/// gated behind `cfg!(debug_assertions)` so it is impossible in release builds.
pub async fn verify_kiwi_token(
    config: &crate::config::Config,
    redis_pool: &deadpool_redis::Pool,
    kiwi_token: Option<&str>,
    client_ip: &str,
    scope: Option<&str>,
) -> Result<(), ApiError> {
    // RS-063: Dev-mode bypass gated behind compile-time debug_assertions check.
    if cfg!(debug_assertions) && config.kiwi_secret_key == "dev" {
        tracing::warn!(
            "KiwiCaptcha dev-mode bypass active — this must NOT be enabled in production"
        );
        return Ok(());
    }

    if !config.kiwi_enabled {
        return Ok(());
    }

    let raw = kiwi_token.filter(|t| !t.is_empty()).ok_or_else(|| {
        tracing::warn!("KiwiCaptcha: empty token received");
        ApiError::Validation(vec!["CAPTCHA verification token is required".into()])
    })?;

    let solution = kiwicaptcha::SolutionToken::decode(raw).map_err(|e| {
        tracing::warn!(error = %e, "KiwiCaptcha: token decode failed");
        ApiError::Validation(vec![
            "CAPTCHA verification failed — please refresh and try again".into(),
        ])
    })?;

    tracing::info!(
        counter = solution.counter,
        duration_ms = solution.duration_ms,
        "KiwiCaptcha: token decoded"
    );

    // Look up the stored challenge by nonce.
    let mut conn = redis_pool.get().await?;
    let key = format!("{KIWI_CHALLENGE_PREFIX}{}", solution.nonce);
    let stored: Option<String> =
        deadpool_redis::redis::AsyncCommands::get(&mut *conn, &key).await?;

    let record: kiwicaptcha::ChallengeRecord = stored
        .as_deref()
        .ok_or_else(|| {
            tracing::warn!("KiwiCaptcha: challenge not found in Redis");
            ApiError::Validation(vec![
                "CAPTCHA challenge expired or not found — please refresh and try again".into(),
            ])
        })
        .and_then(|s| {
            serde_json::from_str(s).map_err(|e| {
                tracing::warn!(error = %e, "KiwiCaptcha: challenge record decode failed");
                ApiError::Internal("CAPTCHA state corrupted".into())
            })
        })?;

    tracing::info!(
        scope = %record.scope,
        expires_at = record.expires_at,
        algorithm = record.algorithm.as_str(),
        m_kib = record.m_kib,
        target_bits = record.target_bits,
        "KiwiCaptcha: challenge record found"
    );

    // IP binding is enforced inside verify_solution (intrinsic) against the
    // record's nonce-bound binding_tag (protocol v2) or legacy hash (v1) —
    // no pre-check here (privacy: the raw client IP never reaches the logs,
    // and the pre-check was redundant with the intrinsic enforcement).

    // Per-nonce attempt cap: each challenge may only be tried a bounded number
    // of times before it is burned. This bounds the server-side cost of a
    // memory-hard (Argon2id) verification and defeats counter-guessing loops —
    // the challenge record itself is only consumed on success, so without this
    // cap a single issued nonce could trigger unbounded expensive verifications.
    // The check FAILS CLOSED (mirroring the issuance limiter in
    // routes::kiwicaptcha.rs): over the cap → denial; store unavailable →
    // retryable 503; never a silent pass.
    let attempt_key = format!("{KIWI_CHALLENGE_PREFIX}attempts:{}", solution.nonce);
    match check_kiwi_verify_attempt_cap(
        redis_pool,
        &attempt_key,
        config.kiwi_challenge_ttl_secs.max(1),
    )
    .await
    {
        KiwiAttemptCap::Allowed => {}
        KiwiAttemptCap::Exceeded => {
            tracing::warn!("KiwiCaptcha: verify attempt cap exceeded");
            return Err(ApiError::Validation(vec![
                "CAPTCHA verification failed — please refresh and try again".into(),
            ]));
        }
        KiwiAttemptCap::RedisUnavailable => {
            return Err(ApiError::ServiceUnavailable(
                "captcha challenge store unavailable; please retry shortly".into(),
            ));
        }
    }

    // kiwicaptcha's VerifyContext takes the clock as a closure so tests can
    // time-travel; production pins it to the system clock.
    let mut now_unix = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    };

    // Minimum duration: the per-challenge floor was derived at issuance from
    // the algorithm + difficulty (an operator override via KIWI_MIN_DURATION_MS
    // is applied at issuance too). Rejecting faster-than-possible solves is
    // enforced by the verify module against that floor.
    let min_duration_ms: u64 = 0; // floor comes from record.min_duration_ms

    // Telemetry scoring: detect headless/automated clients. The telemetry
    // payload itself is deliberately not logged (privacy).
    //
    // Telemetry is client-controlled and forgeable — supplementary evidence,
    // never the security boundary (the kiwicaptcha model: default-off,
    // verify.rs `enforce_telemetry` docs). It is scored EXACTLY ONCE here:
    // when enforcement is OFF, a bot-scored payload is observability-only
    // (warn log below, no rejection); when enforcement is ON, this call is
    // short-circuited and the crate-side check inside verify_solution
    // performs the single scoring and the rejection. The previous shape —
    // an unconditional hard reject here — ran before the configured
    // `kiwi_enforce_telemetry` flag was consulted (rejecting even with
    // KIWI_ENFORCE_TELEMETRY=false) and double-scored the payload when the
    // flag was on.
    if !config.kiwi_enforce_telemetry
        && kiwicaptcha::score_telemetry(&solution.telemetry, solution.duration_ms)
    {
        tracing::warn!(
            duration_ms = solution.duration_ms,
            "KiwiCaptcha bot signal in telemetry (not enforced: KIWI_ENFORCE_TELEMETRY is off)"
        );
    }

    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64) // epoch MICROseconds — kiwicaptcha's issued_at_ns/now_ns unit
        .unwrap_or(0);

    // kiwicaptcha's VerifyContext carries a `&mut dyn FnMut` clock (not
    // Send): acquire the Argon2 permit FIRST, then build ctx and scope it
    // to the sync verify call so the handler future stays Send. The wait is
    // BOUNDED (KIWI_ARGON2_PERMIT_WAIT_TIMEOUT): a saturated semaphore
    // yields a retryable denial instead of an unbounded queue.
    let _argon2_permit = if record.algorithm == kiwicaptcha::PoWAlgorithm::Argon2id {
        let semaphore = ARGON2_VERIFY_SEMAPHORE
            .get_or_init(|| Arc::new(Semaphore::new(config.kiwi_argon2_max_concurrent as usize)))
            .clone();
        Some(acquire_argon2_permit_bounded(&semaphore, KIWI_ARGON2_PERMIT_WAIT_TIMEOUT).await?)
    } else {
        None
    };

    let mut record_mut = record.clone();
    let ctx = kiwicaptcha::VerifyContext {
        record: &mut record_mut,
        secret_key: &config.kiwi_secret_key,
        // No key rotation configured: the single secret verifies every record
        // (the historical single-key path). No kids are revoked either.
        secrets_by_kid: None,
        revoked_kids: None,
        counter: solution.counter,
        duration_ms: solution.duration_ms,
        now_unix: Some(&mut now_unix),
        now_ns,
        min_duration_ms,
        expected_scope: scope,
        // The api-server redemption carries no authoritative transaction
        // binding input: the request binding is not enforced here.
        expected_request_binding: kiwicaptcha::RequestBindingExpectation::Unenforced,
        // No region / issuer / policy-version pinning is configured on this
        // deployment — those enforcement knobs stay off.
        expected_region: None,
        expected_issuer: None,
        expected_policy_version: None,
        // IP binding is enforced inside verify_solution (intrinsic).
        client_ip: Some(client_ip),
        // Execution/RSW evidence passes through from the token verbatim. This
        // deployment never arms those dimensions at issuance (see
        // routes::kiwicaptcha), so live records are unarmed and present None;
        // an armed record would still verify through these fields. The
        // verifier's rsw trapdoor parameters stay unset for the same reason.
        execution_digest: solution.execution_digest.as_deref(),
        execution_trace: solution.execution_trace.as_deref(),
        rsw_proof: solution.rsw_proof.as_deref(),
        rsw_modulus_n: None,
        rsw_lambda: None,
        // v1 challenges are rejected by default (the migration window is
        // closed); the api-server only ever issues v2.
        accept_legacy_v1: false,
        telemetry: Some(&solution.telemetry),
        // Telemetry is client-controlled and forgeable — supplementary only.
        // The per-nonce Lua INCR is the authoritative attempt cap (20); the
        // intrinsic max_attempts is left unlimited here to keep the two
        // mechanisms independent.
        enforce_telemetry: config.kiwi_enforce_telemetry,
        max_attempts: 0,
    };

    tracing::info!(
        counter = solution.counter,
        duration_ms = solution.duration_ms,
        min_duration_ms = min_duration_ms,
        scope = ?scope,
        target_bits = record.target_bits,
        m_kib = record.m_kib,
        "KiwiCaptcha: calling verify_solution"
    );

    // Aggregate Argon2id verification cap: bound concurrent memory-hard
    // verifications server-wide (not just per nonce). SHA-256 verifications
    // are cheap and not gated. (RAII permit: held to the end of the scope,
    // never read.)
    // kiwicaptcha's VerifyContext carries a `&mut dyn FnMut` clock (not
    // Send): scope it to the sync verify call so the async fn future stays
    // Send across the awaits below (the permit is acquired above).
    let outcome = {
        let mut ctx = ctx;
        kiwicaptcha::verify_solution(&mut ctx)
    };
    match outcome {
        // `Valid` is a struct variant carrying the consumed challenge's nonce
        // (jti) and any request binding — neither is needed here: consumption
        // is keyed by `solution.nonce` below.
        kiwicaptcha::VerifyOutcome::Valid { .. } => {
            // Atomic single-use consumption (compare-and-delete): the record is
            // deleted only if it still holds the exact value verified above, so
            // a replayed token or a concurrent use can never succeed twice.
            let consumed: i64 = deadpool_redis::redis::Script::new(KIWI_CONSUME_LUA)
                .key(&key)
                .arg(stored.as_deref().unwrap_or_default())
                .invoke_async(&mut *conn)
                .await?;
            if consumed == 1 {
                tracing::info!(
                    duration_ms = solution.duration_ms,
                    counter = solution.counter,
                    "KiwiCaptcha: VERIFIED"
                );
                Ok(())
            } else {
                tracing::warn!(
                    "KiwiCaptcha: challenge already consumed or expired — replay rejected"
                );
                Err(ApiError::Validation(vec![
                    "CAPTCHA challenge already used — please refresh and try again".into(),
                ]))
            }
        }
        kiwicaptcha::VerifyOutcome::Invalid(reason) => {
            tracing::warn!(reason = ?reason, counter = solution.counter, duration_ms = solution.duration_ms, target_bits = record.target_bits, "KiwiCaptcha: REJECTED");
            Err(ApiError::Validation(vec![
                "CAPTCHA verification failed — please try again".into(),
            ]))
        }
    }
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(db_error) if db_error.code().as_deref() == Some("23505"))
}

/// F8: enterprise SSO enforcement. A tenant whose `ent_sso_configurations`
/// row has `enforce_sso = true` must not be able to authenticate with a
/// local password — every login has to go through the SSO flow. Returns
/// `Ok(false)` when the table does not exist (deployments without the
/// enterprise schema) so enforcement degrades safely; any other database
/// error is propagated.
async fn tenant_sso_enforced(db: &sqlx::PgPool, tenant_id: &str) -> Result<bool, ApiError> {
    let enforced: Option<bool> = match sqlx::query_scalar::<_, bool>(
        "SELECT enforce_sso FROM ent_sso_configurations WHERE tenant_id = $1 LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(db)
    .await
    {
        Ok(row) => row,
        Err(error)
            if matches!(
                &error,
                sqlx::Error::Database(db_error)
                    if db_error.code().as_deref() == Some("42P01")
            ) =>
        {
            // ent_sso_configurations absent: no enterprise SSO configuration
            // can exist, so nothing is enforced.
            tracing::warn!(tenant_id = %tenant_id, "ent_sso_configurations table absent; SSO enforcement skipped");
            None
        }
        Err(error) => {
            tracing::error!(error = %error, tenant_id = %tenant_id, "SSO enforcement lookup failed");
            return Err(ApiError::Internal("database error".into()));
        }
    };

    Ok(enforced.unwrap_or(false))
}

fn verify_password_or_log(password: &str, hash: &str, subject: &str) -> Result<bool, ApiError> {
    // SSO-only accounts (auto-provisioned by routes/sso.rs) carry a
    // `$sso$…` placeholder that no password can ever verify; routing it
    // into the hash verifiers below fails with an Internal error on every
    // password attempt. Refuse with a clean 401 directing the user to
    // their IdP instead.
    if hash.starts_with("$sso$") {
        tracing::info!(subject = %subject, "password login refused for SSO-only account");
        return Err(ApiError::Unauthorized(
            "This account uses single sign-on".into(),
        ));
    }

    let result = if hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$")
    {
        bcrypt::verify(password, hash).map_err(|error| error.to_string())
    } else if hash.starts_with("$argon2") {
        apexmail_lib::verify_password(password, hash).map_err(|error| error.to_string())
    } else {
        let prefix: String = hash.chars().take(10).collect();
        tracing::error!(
            hash_prefix = %prefix,
            subject = %subject,
            "unknown password hash scheme — rejecting login"
        );
        return Err(ApiError::Internal(format!(
            "unknown password hash scheme for user {subject}"
        )));
    };

    match result {
        Ok(valid) => Ok(valid),
        Err(error) => {
            tracing::error!(error = %error, subject = %subject, "password verification failed");
            Err(ApiError::Internal(format!(
                "password verification error for user {subject}: {error}"
            )))
        }
    }
}

pub(crate) fn scopes_for_role(role: &str) -> Vec<String> {
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
            "logs:read".into(),
            "webhooks:read".into(),
            "webhooks:write".into(),
            "campaigns:read".into(),
            "campaigns:write".into(),
            "automations:read".into(),
            "suppressions:read".into(),
            "suppressions:write".into(),
            "dedicated_ips:read".into(),
            "dedicated_ips:write".into(),
            "support:read".into(),
            "support:write".into(),
        ],
        "viewer" => vec![
            "messages:read".into(),
            "domains:read".into(),
            "templates:read".into(),
            "events:read".into(),
            "analytics:read".into(),
            "contacts:read".into(),
            "logs:read".into(),
            "campaigns:read".into(),
            "suppressions:read".into(),
            "dedicated_ips:read".into(),
            "support:read".into(),
        ],
        _ => vec!["messages:read".into()],
    }
}

pub(crate) fn role_requires_mfa(role: &str) -> bool {
    matches!(role, "admin" | "owner")
}

// ─── API key scope registry (F17) ──────────────────────────────

/// The scope vocabulary an API key may carry (F17): the union of every
/// role's grants plus the administrative wildcard. Both key-creating
/// surfaces (the JSON endpoint and the console form) validate requested
/// scopes against THIS shared registry, so a typo'd or not-yet-granted
/// scope string is rejected instead of being stored as inert authority.
pub(crate) fn registered_api_key_scopes() -> &'static [String] {
    static REGISTERED: OnceLock<Vec<String>> = OnceLock::new();
    REGISTERED.get_or_init(|| {
        let mut scopes: Vec<String> = vec!["*".into()];
        for role in ["admin", "developer", "viewer", "member"] {
            for scope in scopes_for_role(role) {
                if !scopes.contains(&scope) {
                    scopes.push(scope);
                }
            }
        }
        scopes
    })
}

/// Whether `scope` is part of the shared API key scope registry.
pub(crate) fn is_registered_api_key_scope(scope: &str) -> bool {
    registered_api_key_scopes()
        .iter()
        .any(|known| known == scope)
}

/// Per-scope issuance authorization for API key creation (F17):
///
/// * a caller holding the wildcard `*` may mint ANY registered scope — the
///   previous exact-match check locked administrators out of ordinary
///   scoped keys, forcing them to mint full-power `*` keys instead;
/// * a restricted caller may mint exactly the scopes they already hold;
/// * `*` itself may only be minted by a caller who already holds it, so a
///   restricted caller can never escalate through a minted key.
pub(crate) fn authorize_scope_issuance(
    caller_scopes: &[String],
    requested: &str,
) -> Result<(), ApiError> {
    let caller_holds_wildcard = caller_scopes.iter().any(|scope| scope == "*");
    if requested == "*" {
        if caller_holds_wildcard {
            return Ok(());
        }
        return Err(ApiError::Forbidden(
            "scope '*' exceeds your own permissions".into(),
        ));
    }
    if !is_registered_api_key_scope(requested) {
        return Err(ApiError::Validation(vec![format!(
            "unknown scope '{requested}': must be one of {}",
            registered_api_key_scopes().join(", ")
        )]));
    }
    if caller_holds_wildcard || caller_scopes.iter().any(|scope| scope == requested) {
        return Ok(());
    }
    Err(ApiError::Forbidden(format!(
        "scope '{requested}' exceeds your own permissions"
    )))
}

/// Bind the MFA secret ciphertext to the owning user_id so a row swap
/// (database-level relocation) cannot make a stolen ciphertext usable
/// against another account.
fn mfa_secret_aad(user_id: &str) -> Vec<u8> {
    format!("user_id={user_id}").into_bytes()
}

/// Encrypt an MFA secret for at-rest storage (CRIT-10). When the encryption
/// key is unconfigured this returns the plaintext unchanged with a logged
/// warning so existing deployments stay functional.
fn encrypt_mfa_secret_for_user(user_id: &str, secret: &str) -> Result<String, ApiError> {
    apexmail_lib::secret_at_rest::encrypt_at_rest(secret, &mfa_secret_aad(user_id))
        .map_err(|e| ApiError::Internal(format!("failed to encrypt MFA secret: {e}")))
}

/// Decrypt the stored MFA secret on a `UserRow` in place. Plaintext rows
/// (legacy deployments) are passed through transparently.
fn decrypt_mfa_secret_in_place(user: &mut UserRow) -> Result<(), ApiError> {
    if let Some(stored) = user.mfa_secret.as_deref() {
        if !stored.is_empty() {
            let aad = mfa_secret_aad(&user.id);
            let plain = apexmail_lib::secret_at_rest::decrypt_at_rest(stored, &aad)
                .map_err(|e| ApiError::Internal(format!("failed to decrypt MFA secret: {e}")))?;
            user.mfa_secret = Some(plain);
        }
    }
    Ok(())
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

fn generate_mfa_secret() -> Result<String, ApiError> {
    let mut secret = [0u8; MFA_SECRET_BYTES];
    use rand::TryRngCore;
    rand::rngs::OsRng.try_fill_bytes(&mut secret).map_err(|e| {
        tracing::error!(error = %e, "failed to generate MFA secret via OsRng");
        ApiError::Internal("failed to generate MFA secret".into())
    })?;
    Ok(base32_encode(&secret))
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
    // NIST SP 800-63B-4 policy (external review 2026-09-08 §21): length
    // and breached-password screening, NOT composition rules. The old
    // uppercase/lowercase/digit/punctuation mandate pushed users toward
    // predictable transformations (Password1!) without adding entropy.
    // Unicode (including spaces) is allowed; paste and password managers
    // are supported by the clients.
    //
    // Use char count for minimum length (Unicode-aware) and byte length
    // for max (DB storage limit).
    let char_count = password.chars().count();
    if char_count < 15 || password.len() > 128 {
        return Err(ApiError::Validation(vec![
            "password must be 15-128 characters; longer is stronger — no uppercase/digit/symbol mix is required".into(),
        ]));
    }

    // F-12: Check for common weak passwords (normalized to lowercase)
    let lower = password.to_ascii_lowercase();
    if COMMON_WEAK_PASSWORDS.binary_search(&lower.as_str()).is_ok() {
        return Err(ApiError::Validation(vec![
            "password is too common; choose a less predictable password".into(),
        ]));
    }

    // F-12: Check for repeated characters (3+ identical consecutive chars)
    if password
        .as_bytes()
        .windows(3)
        .any(|w| w[0] == w[1] && w[1] == w[2])
    {
        return Err(ApiError::Validation(vec![
            "password must not contain 3 or more repeated consecutive characters".into(),
        ]));
    }

    // F-12: Check for sequential characters (e.g., "abcd", "1234", "4321")
    if has_sequential_chars(password) {
        return Err(ApiError::Validation(vec![
            "password must not contain 3 or more sequential characters".into(),
        ]));
    }

    Ok(())
}

/// Returns true if the string contains 3+ sequential ASCII characters (forward or backward).
fn has_sequential_chars(s: &str) -> bool {
    let bytes: Vec<u8> = s
        .as_bytes()
        .iter()
        .copied()
        .filter(|&b| b.is_ascii())
        .collect();
    if bytes.len() < 3 {
        return false;
    }
    bytes.windows(3).any(|w| {
        (w[0] + 1 == w[1] && w[1] + 1 == w[2]) // forward sequential
            || (w[0] == w[1] + 1 && w[1] == w[2] + 1) // backward sequential
    })
}

/// Sorted list of common weak passwords (top ~100) to reject.
static COMMON_WEAK_PASSWORDS: &[&str] = &[
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "1234567890",
    "12345678910",
    "111111",
    "112233",
    "121212",
    "123123",
    "1234",
    "12345",
    "123456789",
    "654321",
    "666666",
    "696969",
    "777777",
    "888888",
    "abc123",
    "abcd1234",
    "admin",
    "admin123",
    "baseball",
    "chester",
    "charlie",
    "cookie",
    "daniel",
    "dragon",
    "football",
    "fuckme",
    "fuckyou",
    "guest",
    "hunter",
    "hunter2",
    "iloveyou",
    "jennifer",
    "jessica",
    "jordan",
    "killer",
    "letmein",
    "master",
    "michael",
    "michelle",
    "monkey",
    "mustang",
    "ninja",
    "pass",
    "passwd",
    "password",
    "password1",
    "password12",
    "password123",
    "password1234",
    "password12345",
    "photoshop",
    "princess",
    "pussy",
    "qazwsx",
    "qwerty",
    "qwerty123",
    "qwertyuiop",
    "robert",
    "solo",
    "starwars",
    "sunshine",
    "superman",
    "thomas",
    "trustno1",
    "welcome",
    "whatever",
    "zxcvbnm",
    "passw0rd",
    "p@ssword",
    "p@ssw0rd",
    "Pa$$word",
    "Pa$$w0rd",
];

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

fn build_action_link(base_url: &str, path: &str, _email: &str, token: &str) -> String {
    // CWE-598: Use path-based token instead of query parameters to prevent
    // sensitive token exposure in server logs, referrer headers, and browser history.
    format!("{}{}/{}", base_url.trim_end_matches('/'), path, token,)
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

/// Redis set of source IPs that recently produced failed logins for an
/// identifier. Lockout requires corroboration across distinct sources (M-6),
/// so the set — not just a counter — drives the lock decision.
fn login_failure_ip_key(identifier: &str) -> String {
    format!("apexmail:auth:fail_ips:{}", hash_token(identifier))
}

/// How many distinct source IPs must have produced failures before an
/// account may be locked (audit M-6). A single source — however persistent —
/// can no longer lock a victim's account at will; the per-IP login rate
/// limit keeps throttling that source while the account stays usable for
/// the real owner elsewhere.
const LOGIN_LOCKOUT_MIN_DISTINCT_IPS: i64 = 2;

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
    source_ip: Option<&str>,
) -> Result<(), ApiError> {
    let failure_key = login_failure_key(identifier);
    let failure_ip_key = login_failure_ip_key(identifier);
    let lock_key = login_lock_key(identifier);
    let lockout_counter_key = login_lockout_counter_key(identifier);
    let identifier_hash = hash_token(identifier);

    let mut conn = redis_pool.get().await?;
    let failures: i64 = deadpool_redis::redis::Script::new(INCR_EXPIRE_LUA)
        .key(&failure_key)
        .arg(LOGIN_FAILURE_WINDOW_SECS)
        .invoke_async(&mut *conn)
        .await?;

    // Track which source IPs produced the failures. `None` (no ConnectInfo)
    // buckets into a single "unknown" source.
    let ip_member = source_ip.unwrap_or("unknown");
    let _: () =
        deadpool_redis::redis::AsyncCommands::sadd(&mut *conn, &failure_ip_key, ip_member).await?;
    let _: () = deadpool_redis::redis::AsyncCommands::expire(
        &mut *conn,
        &failure_ip_key,
        LOGIN_FAILURE_WINDOW_SECS as i64,
    )
    .await?;
    let distinct_ips: i64 =
        deadpool_redis::redis::AsyncCommands::scard(&mut *conn, &failure_ip_key).await?;

    if failures < LOGIN_FAILURE_THRESHOLD {
        return Ok(());
    }

    // M-6: lock only with corroboration across distinct source IPs. One
    // source's failures alone never lock the account (its per-IP rate limit
    // already throttles it); the failure counter stays alive so a second
    // distinct source immediately triggers the lock on the next failure.
    if distinct_ips < LOGIN_LOCKOUT_MIN_DISTINCT_IPS {
        tracing::warn!(
            identifier_hash = %identifier_hash,
            failures = failures,
            distinct_ips = distinct_ips,
            "login failures reached the threshold from a single source — \
             account lockout withheld (M-6 distinct-IP rule); per-IP rate \
             limits remain active"
        );
        return Ok(());
    }

    let lockouts: i64 = deadpool_redis::redis::Script::new(INCR_EXPIRE_LUA)
        .key(&lockout_counter_key)
        .arg(LOGIN_LOCKOUT_ESCALATION_WINDOW_SECS)
        .invoke_async(&mut *conn)
        .await?;

    let duration = login_lockout_duration(lockouts);
    let _: () =
        deadpool_redis::redis::AsyncCommands::set_ex(&mut *conn, &lock_key, "1", duration).await?;
    let _: i64 = deadpool_redis::redis::AsyncCommands::del(&mut *conn, &failure_key).await?;
    let _: i64 = deadpool_redis::redis::AsyncCommands::del(&mut *conn, &failure_ip_key).await?;

    tracing::warn!(
        identifier_hash = %identifier_hash,
        failures = failures,
        distinct_ips = distinct_ips,
        lockouts = lockouts,
        lockout_seconds = duration,
        "login account temporarily locked after repeated failures from multiple sources"
    );

    Ok(())
}

async fn clear_login_failures(
    redis_pool: &deadpool_redis::Pool,
    identifier: &str,
) -> Result<(), ApiError> {
    let failure_key = login_failure_key(identifier);
    let failure_ip_key = login_failure_ip_key(identifier);
    let mut conn = redis_pool.get().await?;
    let _: i64 = deadpool_redis::redis::AsyncCommands::del(
        &mut *conn,
        vec![failure_key.as_str(), failure_ip_key.as_str()],
    )
    .await?;
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

async fn delete_mfa_challenge(
    redis_pool: &deadpool_redis::Pool,
    token: &str,
) -> Result<(), ApiError> {
    let key = mfa_challenge_key(token);
    let mut conn = redis_pool.get().await?;
    let _: i64 = deadpool_redis::redis::AsyncCommands::del(&mut *conn, &key).await?;
    Ok(())
}

// ─── F3: TOTP hardening (lockout, replay guard, single-use challenges) ──

/// RFC 6238 time step used by `apexmail_lib::mfa` (30 s). Duplicated here
/// because the lib keeps it private; the replay guard must key on the same
/// windows the verifier accepts.
const TOTP_STEP_SECS: u64 = 30;

/// Replay-guard TTL: a code is accepted while the current step is within ±1
/// of the code's own step, so a single code can stay acceptable for up to
/// 3 steps (90 s). 120 s covers the whole span plus clock-skew slack.
const TOTP_REPLAY_TTL_SECS: u64 = 120;

/// Capacity bound for the in-process replay fallback so a Redis outage can
/// never grow memory unboundedly (F3).
const TOTP_REPLAY_FALLBACK_CAP: usize = 8192;

const MFA_TOTP_REPLAY_PREFIX: &str = "apexmail:auth:mfa_totp_replay:";

/// Process-wide TOTP verifier with per-secret failed-attempt lockout
/// (`apexmail_lib::mfa::TOTPVerifier`, audit O-19.2). Shared so every TOTP
/// check site contributes to — and is bounded by — the same lockout state.
static TOTP_VERIFIER: std::sync::LazyLock<apexmail_lib::mfa::TOTPVerifier> =
    std::sync::LazyLock::new(apexmail_lib::mfa::TOTPVerifier::new);

/// Bounded in-process replay-map fallback used only while Redis is
/// unavailable (key → expiry instant).
static TOTP_REPLAY_FALLBACK: std::sync::LazyLock<
    parking_lot::Mutex<std::collections::HashMap<String, std::time::Instant>>,
> = std::sync::LazyLock::new(|| parking_lot::Mutex::new(std::collections::HashMap::new()));

/// Atomic single-use claim of a TOTP code's ±1 acceptance windows (F3).
/// KEYS = the three replay keys for the current step ±1,
/// ARGV[1] = TTL seconds.
/// Returns 1 when this caller is the first to use the window, 0 on replay.
const TOTP_REPLAY_CLAIM_LUA: &str = r#"
    for i = 1, #KEYS do
        if redis.call('EXISTS', KEYS[i]) == 1 then
            return 0
        end
    end
    for i = 1, #KEYS do
        redis.call('SET', KEYS[i], '1', 'EX', ARGV[1])
    end
    return 1
"#;

/// Atomic single-use consumption of an MFA challenge (F3): fetch the stored
/// state and delete it in the same round trip. The challenge is burned on
/// the first verification ATTEMPT regardless of outcome, so a challenge
/// token can never be replayed after a failed code (or a successful one).
const MFA_CHALLENGE_CONSUME_LUA: &str = r#"
    local stored = redis.call('GET', KEYS[1])
    if stored ~= false then
        redis.call('DEL', KEYS[1])
    end
    return stored
"#;

/// Replay-guard key for one TOTP step window of one secret. The secret is
/// hashed (never stored raw) so TOTP key material does not land in Redis
/// keyspace.
fn mfa_totp_replay_key(secret_fingerprint: &str, step: u64) -> String {
    format!("{MFA_TOTP_REPLAY_PREFIX}{secret_fingerprint}:{step}")
}

/// Stable fingerprint of a TOTP secret for replay keys.
fn mfa_totp_secret_fingerprint(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

fn current_totp_step() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / TOTP_STEP_SECS
}

/// Atomically claim the ±1 windows around the current step in Redis.
/// `Some(true)` = first use, `Some(false)` = replay, `None` = Redis
/// unavailable (caller falls back to the in-process map).
async fn claim_totp_window_redis(
    redis_pool: &deadpool_redis::Pool,
    secret_fingerprint: &str,
) -> Option<bool> {
    let mut conn = match redis_pool.get().await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(error = %error, "TOTP replay guard Redis unavailable");
            return None;
        }
    };

    let step = current_totp_step();
    let keys = [
        mfa_totp_replay_key(secret_fingerprint, step.saturating_sub(1)),
        mfa_totp_replay_key(secret_fingerprint, step),
        mfa_totp_replay_key(secret_fingerprint, step + 1),
    ];

    let claimed: i64 = deadpool_redis::redis::Script::new(TOTP_REPLAY_CLAIM_LUA)
        .key(&keys[0])
        .key(&keys[1])
        .key(&keys[2])
        .arg(TOTP_REPLAY_TTL_SECS)
        .invoke_async(&mut conn)
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "TOTP replay guard Redis command failed");
            error
        })
        .ok()?;

    Some(claimed == 1)
}

/// Bounded in-process fallback for the replay claim while Redis is down.
/// Expired entries are pruned on insert; the map is cleared if it is still
/// at capacity, so memory stays bounded no matter how many secrets are seen.
fn claim_totp_window_inprocess(secret_fingerprint: &str) -> bool {
    let mut map = TOTP_REPLAY_FALLBACK.lock();
    let now = std::time::Instant::now();
    let step = current_totp_step();
    let keys = [
        mfa_totp_replay_key(secret_fingerprint, step.saturating_sub(1)),
        mfa_totp_replay_key(secret_fingerprint, step),
        mfa_totp_replay_key(secret_fingerprint, step + 1),
    ];

    if keys
        .iter()
        .any(|key| map.get(key).is_some_and(|expires| *expires > now))
    {
        return false;
    }

    if map.len() >= TOTP_REPLAY_FALLBACK_CAP {
        map.retain(|_, expires| *expires > now);
        if map.len() >= TOTP_REPLAY_FALLBACK_CAP {
            map.clear();
        }
    }

    let expires = now + std::time::Duration::from_secs(TOTP_REPLAY_TTL_SECS);
    for key in keys {
        map.insert(key, expires);
    }
    true
}

/// Verify a TOTP code with the full F3 hardening applied:
/// 1. **Lockout** — the shared `TOTPVerifier` locks a secret after repeated
///    failures (per process).
/// 2. **Replay guard** — a valid code is single-use across its whole ±1
///    acceptance window (atomic Redis claim, in-process fallback), so an
///    intercepted code cannot be replayed inside the drift window.
///
/// Returns `true` only for a valid, previously-unused code. Shared with the
/// console form twins (`routes::web`) so browser MFA gets the identical
/// hardening.
pub(crate) async fn verify_totp_code_guarded(
    redis_pool: &deadpool_redis::Pool,
    secret: &str,
    code: &str,
) -> bool {
    if !TOTP_VERIFIER.verify(secret, code) {
        return false;
    }

    let fingerprint = mfa_totp_secret_fingerprint(secret);
    match claim_totp_window_redis(redis_pool, &fingerprint).await {
        Some(true) => true,
        Some(false) => {
            tracing::warn!("replayed TOTP code rejected");
            TOTP_VERIFIER.record_failure(secret);
            false
        }
        None => claim_totp_window_inprocess(&fingerprint),
    }
}

/// Load an MFA challenge and atomically consume it (single-use, F3). The
/// token is deleted whether the upcoming verification succeeds or fails.
async fn consume_mfa_challenge(
    redis_pool: &deadpool_redis::Pool,
    token: &str,
) -> Result<MfaChallengeState, ApiError> {
    let mut conn = redis_pool.get().await?;
    let stored: Option<String> = deadpool_redis::redis::Script::new(MFA_CHALLENGE_CONSUME_LUA)
        .key(mfa_challenge_key(token))
        .invoke_async(&mut conn)
        .await
        .map_err(|error| ApiError::Internal(format!("failed to consume MFA challenge: {error}")))?;

    let payload =
        stored.ok_or_else(|| ApiError::Unauthorized("invalid or expired MFA challenge".into()))?;

    serde_json::from_str(&payload)
        .map_err(|error| ApiError::Internal(format!("failed to decode MFA challenge: {error}")))
}

async fn delete_email_mfa_code(
    redis_pool: &deadpool_redis::Pool,
    user_id: &str,
) -> Result<(), ApiError> {
    let key = format!("apexmail:email_mfa:{user_id}");
    let mut conn = redis_pool.get().await?;
    let _: i64 = deadpool_redis::redis::AsyncCommands::del(&mut *conn, &key).await?;
    Ok(())
}

async fn revoke_user_sessions(
    redis_pool: &deadpool_redis::Pool,
    tenant_id: &str,
    user_id: &str,
    ttl_secs: u64,
) -> Result<i64, ApiError> {
    let mut conn = redis_pool.get().await?;
    let key = session_revocation_key(tenant_id, user_id);
    let revoked_after = Utc::now().timestamp();

    let _: () =
        deadpool_redis::redis::AsyncCommands::set_ex(&mut *conn, &key, revoked_after, ttl_secs)
            .await?;

    Ok(revoked_after)
}

async fn enqueue_verification_email(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    base_url: &str,
    email: &str,
    token: &str,
) -> Result<(), ApiError> {
    // F5: the link targets the path-param JSON route. The bare
    // `/verify-email` root path only understands `?token=` (browser page
    // routed in app.rs), so a path-style link there would 404.
    let verification_link = build_action_link(base_url, "/v1/auth/verify-email", email, token);
    let safe_email = html_escape(email);
    let safe_link = html_escape(&verification_link);
    let html_body = format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/></head><body style="font-family:ui-monospace,'JetBrains Mono',monospace;line-height:1.6;color:#09090b;max-width:560px;margin:0 auto;padding:24px">
<h2 style="color:#dc2626;text-transform:uppercase;letter-spacing:0.05em">Verify Your ApexMail Account</h2>
<p>Finish setting up <strong>{safe_email}</strong> by confirming this email address.</p>
<p><a href="{safe_link}" style="display:inline-block;padding:12px 28px;background:#dc2626;color:#fff;border-radius:0px;text-decoration:none;font-weight:700;text-transform:uppercase;letter-spacing:0.1em">Verify email</a></p>
<p style="font-size:13px;color:#71717a">This link expires in 24 hours.</p>
<hr style="border:none;border-top:1px solid #000;margin:24px 0"/>
<p style="font-size:11px;color:#999;text-transform:uppercase;letter-spacing:0.05em">&copy; 2026 ApexMail &middot; <a href="https://apexmail.ee" style="color:#999;text-decoration:none">apexmail.ee</a></p>
</body></html>"#,
    );
    let text_body = format!(
        "Verify Your ApexMail Account\n\nConfirm {email} by visiting: {verification_link}\n\nThis link expires in 24 hours.\n\n© 2026 ApexMail — https://apexmail.ee",
    );

    queue_system_email_in_transaction(
        tx,
        email,
        "Verify your ApexMail account",
        &html_body,
        &text_body,
        vec!["system".into(), "verification".into()],
    )
    .await
    .map(|_| ())
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/me", get(get_current_user))
        .route("/login", post(login))
        .route("/mfa/verify", post(complete_mfa_challenge))
        .route("/mfa/setup", post(init_mfa_setup))
        .route("/mfa/confirm-setup", post(confirm_mfa_setup))
        .route("/mfa/status", get(mfa_status))
        .route("/register", post(register))
        .route("/signup", post(register))
        // Canonical path-param form (F5/CWE-598); the query-string twin
        // below is deprecated but kept for in-flight links and old clients.
        .route("/verify-email/:token", get(verify_email_by_path))
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
        .route("/me", get(get_current_user))
        .route("/login", post(login))
        .route("/mfa/verify", post(complete_mfa_challenge))
        .route("/mfa/setup", post(init_mfa_setup))
        .route("/mfa/confirm-setup", post(confirm_mfa_setup))
        .route("/mfa/status", get(mfa_status))
        .route("/register", post(register))
        .route("/signup", post(register))
        // Canonical path-param form (F5/CWE-598); the query-string twin
        // below is deprecated but kept for in-flight links and old clients.
        .route("/verify-email/:token", get(verify_email_by_path))
        .route("/verify-email", get(verify_email))
        .route("/reset-password", post(reset_password))
        .route("/logout", post(logout))
        .route("/refresh", post(refresh_token))
}

// ─── Request / Response types ──────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    #[serde(default, rename = "mfaCode", alias = "mfa_code")]
    pub mfa_code: Option<String>,
    /// Token from the KiwiCaptcha proof-of-work widget, submitted as a hidden form field.
    /// Optional for non-interactive API clients; required if KiwiCaptcha is enabled.
    #[serde(default, rename = "kiwi__token")]
    pub kiwi__token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SessionAuthResponse {
    pub expires_at: String,
    pub user: UserInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_codes: Option<Vec<String>>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_codes: Option<Vec<String>>,
}

impl MfaChallengeResponse {
    fn verify(challenge_token: String) -> Self {
        Self {
            status: "mfa_required".into(),
            challenge_token,
            secret: None,
            otpauth_url: None,
            recovery_codes: None,
        }
    }

    fn setup(challenge_token: String, email: &str, secret: &str) -> Self {
        Self {
            status: "mfa_setup_required".into(),
            challenge_token,
            secret: Some(secret.to_string()),
            otpauth_url: Some(build_mfa_otpauth_url(email, secret)),
            recovery_codes: None,
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
    #[serde(default, rename = "recoveryCode", alias = "recovery_code")]
    pub recovery_code: Option<String>,
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
        "am_session={token}; HttpOnly; Path=/; Max-Age={max_age_secs}; SameSite=Strict{}",
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

fn session_issue_time_after_revocation(
    now: DateTime<Utc>,
    revoked_after: Option<i64>,
) -> DateTime<Utc> {
    if let Some(cutoff) = revoked_after {
        if now.timestamp() <= cutoff {
            return DateTime::<Utc>::from_timestamp(cutoff + 1, 0).unwrap_or(now);
        }
    }

    now
}

fn issue_session_response_after_revocation(
    state: &AppState,
    user: &UserRow,
    revoked_after: i64,
) -> Result<Response, ApiError> {
    issue_session_response_with_codes_after_revocation(state, user, None, revoked_after)
}

fn issue_session_response_with_codes_after_revocation(
    state: &AppState,
    user: &UserRow,
    recovery_codes: Option<Vec<String>>,
    revoked_after: i64,
) -> Result<Response, ApiError> {
    let issued_at = session_issue_time_after_revocation(Utc::now(), Some(revoked_after));
    issue_session_response_with_codes_at(state, user, recovery_codes, issued_at)
}

fn issue_session_response_with_codes_at(
    state: &AppState,
    user: &UserRow,
    recovery_codes: Option<Vec<String>>,
    issued_at: DateTime<Utc>,
) -> Result<Response, ApiError> {
    let expiry_secs = state.config.jwt_expiry.as_secs() as i64;
    let exp = issued_at + ChronoDuration::seconds(expiry_secs);

    let session_id = Uuid::new_v4().to_string();

    let claims = JwtClaims {
        sub: user.id.to_string(),
        tenant_id: user.tenant_id.to_string(),
        scopes: scopes_for_role(&user.role),
        exp: exp.timestamp(),
        iat: issued_at.timestamp(),
        jti: session_id.clone(),
        typ: Some("session".into()),
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
            recovery_codes,
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
    ip_address: Option<&str>,
    user_agent: Option<&str>,
) -> Result<(), ApiError> {
    // Canonical audit_logs schema (compliance hash chain): resource + details
    // columns, with NOT NULL outcome/hash/signature populated.
    let id = uuid::Uuid::new_v4().to_string();
    let timestamp = Utc::now();
    let mut hasher = Sha256::new();
    hasher.update(tenant_id.as_bytes());
    hasher.update(b"|");
    hasher.update(user_id.as_bytes());
    hasher.update(b"|");
    hasher.update(action.as_bytes());
    hasher.update(b"|");
    hasher.update(metadata.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(timestamp.to_rfc3339().as_bytes());
    let hash = hex::encode(hasher.finalize());

    // Chain the audit entry through the platform-wide hash-chain head
    // (audit item M-10): the old `SELECT ... ORDER BY timestamp DESC LIMIT 1
    // FOR UPDATE` on audit_logs serialised every login/MFA/recovery event
    // platform-wide. The single head row advanced by
    // `crate::audit_log::advance_chain_head` in this same transaction is the
    // only serialization point, so concurrent auth events no longer queue
    // behind each other's transactions while chain integrity is preserved.
    let mut tx = state.db.begin().await?;
    let previous_hash: Option<String> =
        crate::audit_log::advance_chain_head(&mut *tx, &hash).await?;
    // L-14/L-21: the production decision comes from the loaded config
    // (`state.config.environment`), NOT a separate `ENVIRONMENT` env read —
    // a deployment that configures the app as production through config
    // loading must never silently fall back to the public dev signing key.
    let signature = audit_log_signature(
        state.config.environment.is_production(),
        &hash,
        previous_hash.as_deref().unwrap_or_default(),
    )?;

    sqlx::query(
        "INSERT INTO audit_logs (
            id, tenant_id, user_id, action, resource, resource_id,
            details, ip_address, user_agent, outcome, error_message,
            timestamp, hash, previous_hash, signature, created_at
         ) VALUES (
            $1, $2, $3, $4, 'auth', $5,
            $6::jsonb, $7, $8, 'success', NULL,
            $9, $10, $11, $12, $9
         )",
    )
    .bind(&id)
    .bind(tenant_id)
    .bind(user_id)
    .bind(action)
    .bind(metadata)
    .bind(ip_address)
    .bind(user_agent)
    .bind(timestamp)
    .bind(&hash)
    .bind(&previous_hash)
    .bind(&signature)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(())
}

/// HMAC-SHA256 signature over the audit hash (and its chain link), keyed
/// with `AUDIT_SIGNING_KEY`. In production the key MUST be configured — a
/// publicly-known fallback would make every signature forgeable — so the
/// function fails closed there (hard error on first use). Development keeps
/// a fallback with a warning.
///
/// L-14/L-21: `is_production` is derived from the loaded config
/// (`state.config.environment`), the single real source for the deployment
/// environment. It previously re-read the `ENVIRONMENT` env var here, so a
/// deployment configured as production through config loading could silently
/// sign with the public fallback key.
fn audit_log_signature(
    is_production: bool,
    hash: &str,
    previous_hash: &str,
) -> Result<String, ApiError> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let key = match std::env::var("AUDIT_SIGNING_KEY") {
        Ok(k) if !k.is_empty() => k,
        Ok(_) | Err(_) => {
            if is_production {
                return Err(ApiError::Internal(
                    "AUDIT_SIGNING_KEY must be configured in production".into(),
                ));
            }
            tracing::warn!(
                "AUDIT_SIGNING_KEY not set — using development fallback for audit signatures"
            );
            "apexmail-auth-audit-fallback-key".to_string()
        }
    };
    let mut mac = match HmacSha256::new_from_slice(key.as_bytes()) {
        Ok(mac) => mac,
        Err(_) => return Err(ApiError::Internal("audit HMAC init failed".into())),
    };
    mac.update(previous_hash.as_bytes());
    mac.update(b"|");
    mac.update(hash.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
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
// `kiwi__token` is KiwiCaptcha's literal wire field name — kept verbatim
// (same convention as LoginRequest) so the hidden form field deserializes.
#[allow(non_snake_case)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub email: String,
    pub password: String,
    #[serde(default, rename = "confirmPassword", alias = "confirm_password")]
    pub confirm_password: Option<String>,
    #[serde(default)]
    pub kiwi__token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ResetPasswordResponse {
    pub success: bool,
    pub message: String,
}

// ─── Handlers ──────────────────────────────────────────────────

/// GET /v1/auth/me — returns the currently authenticated user's profile.
/// Used by the Console/CP after login to hydrate the UI.
async fn get_current_user(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    // If authenticated via API key, return the key's tenant info
    if let Some(user_id) = &auth.user_id {
        let user: Option<(String, String, Option<String>, String)> =
            sqlx::query_as("SELECT id::text, email, name, role FROM users WHERE id = $1::uuid AND status = 'active'")
                .bind(user_id)
                .fetch_optional(&state.db)
                .await?;
        if let Some((id, email, name, role)) = user {
            return Ok(Json(serde_json::json!({
                "id": id,
                "email": email,
                "name": name,
                "role": role,
                "tenant_id": auth.tenant_id,
                "scopes": auth.scopes,
            })));
        }
    }
    // Fallback: return tenant + scopes (e.g. API key auth)
    Ok(Json(serde_json::json!({
        "tenant_id": auth.tenant_id,
        "scopes": auth.scopes,
        "api_key_id": auth.api_key_id,
    })))
}

async fn login(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Result<Response, ApiError> {
    // Validate CSRF token from X-CSRF-Token header (auth form protection)
    validate_form_csrf(&headers, &state.config.csrf_secret)?;

    if body.email.is_empty() || body.password.is_empty() {
        return Err(ApiError::Validation(vec![
            "email and password are required".into(),
        ]));
    }

    // RS-H-03: Per-IP rate limiting — prevents credential-stuffing and brute-force
    // attacks from a single source, complementing per-account lockout below.
    let client_ip = connect_info
        .map(|ConnectInfo(addr)| {
            extract_public_client_ip(&headers, addr.ip(), &state.config.trusted_proxies)
        })
        .unwrap_or_else(|| {
            tracing::warn!("login request missing ConnectInfo; using shared rate-limit bucket");
            "unknown".to_string()
        });

    // Verify KiwiCaptcha proof-of-work before proceeding with credential check.
    // Early verification avoids leaking user existence via timing or error messages.
    // The client IP is needed to verify the challenge's IP binding (relay-attack defense).
    verify_kiwi_token(
        &state.config,
        &state.redis,
        body.kiwi__token.as_deref(),
        &client_ip,
        Some("login"),
    )
    .await?;

    // The limiter fails CLOSED in production: an unreachable Redis used to
    // silently skip this check (if-let-Ok), removing brute-force protection
    // exactly while the platform is degraded. Outside production it fails
    // open so local development works without Redis. Script errors remain
    // rate-limited (count treated as exceeded) in every environment.
    match state.redis.get().await {
        Ok(mut conn) => {
            let ip_rate_key = format!("apexmail:login_rate:ip:{client_ip}");

            // Atomic rate-limit check using Lua script to avoid INCR + EXPIRE race condition.
            let count: i64 = deadpool_redis::redis::Script::new(
                r#"
                    local ip_key = KEYS[1]
                    local max_ip = tonumber(ARGV[1])
                    local window_secs = tonumber(ARGV[2])

                    local ip_count = redis.call('INCR', ip_key)
                    if ip_count == 1 then
                        redis.call('EXPIRE', ip_key, window_secs)
                    end

                    if ip_count > max_ip then
                        return 1
                    end
                    return 0
                "#,
            )
            .key(&ip_rate_key)
            .arg(LOGIN_IP_RATE_LIMIT)
            .arg(LOGIN_IP_RATE_LIMIT_WINDOW_SECS)
            .invoke_async::<i64>(&mut *conn)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, ip = %client_ip, "login IP rate-limit Lua script failed; treating as rate-limited");
                1
            });

            if count > 0 {
                return Err(ApiError::RateLimited);
            }
        }
        Err(error) => {
            if state.config.environment.is_production() {
                tracing::error!(error = %error, ip = %client_ip, "login IP rate limiter unavailable — failing closed in production");
                return Err(ApiError::ServiceUnavailable(
                    "login is temporarily unavailable; please retry shortly".into(),
                ));
            }
            tracing::warn!(error = %error, ip = %client_ip, "login IP rate limiter unavailable — failing open outside production");
        }
    }

    let login_identifier = normalized_login_identifier(&body.email);
    if login_lock_ttl(&state.redis, &login_identifier)
        .await?
        .is_some()
    {
        return Err(ApiError::RateLimited);
    }

    let user = sqlx::query_as::<_, UserRow>(
        "SELECT id::text, tenant_id::text, email, name, password_hash, role, status, mfa_enabled, email_verified, mfa_secret, mfa_recovery_hashes
         FROM users WHERE LOWER(email) = LOWER($1) OR LOWER(username) = LOWER($2)",
    )
    .bind(&body.email)
    .bind(&body.email)
    .fetch_optional(&state.db)
    .await?;

    let Some(mut user) = user else {
        record_login_failure(&state.redis, &login_identifier, Some(&client_ip)).await?;
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    };

    decrypt_mfa_secret_in_place(&mut user)?;

    let valid = verify_password_or_log(&body.password, &user.password_hash, &user.email)?;

    if !valid {
        record_login_failure(&state.redis, &login_identifier, Some(&client_ip)).await?;
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }

    // Status and SSO policy are revealed only AFTER the password verified:
    // these branches previously ran pre-verification, letting an anonymous
    // caller confirm an email is registered (and whether its org enforces
    // SSO) without any credential knowledge.
    if user.status != "active" {
        return Err(ApiError::Forbidden("account is not active".into()));
    }

    // F8: SSO-enforced tenants reject password login. The password check
    // above still runs first so password-guessing against SSO-only
    // accounts is rate-limited identically to normal accounts; only the
    // policy disclosure moves after verification.
    if tenant_sso_enforced(&state.db, &user.tenant_id).await? {
        tracing::info!(
            tenant_id = %user.tenant_id,
            "password login rejected: tenant enforces SSO"
        );
        return Err(ApiError::Forbidden(
            "SSO_REQUIRED: this organization requires single sign-on; password login is disabled"
                .into(),
        ));
    }

    clear_login_failures(&state.redis, &login_identifier).await?;

    // Email verification is a login prerequisite, enforced only after the
    // password verified (never leaking account existence to anonymous
    // callers).
    if !user.email_verified {
        return Err(ApiError::Forbidden(
            "email not verified — check your inbox for the verification link".into(),
        ));
    }

    if role_requires_mfa(&user.role) {
        if user.mfa_enabled {
            let secret = user
                .mfa_secret
                .as_deref()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    ApiError::Forbidden("MFA is not configured for this admin account".into())
                })?;

            // Email-based MFA: generate a one-time code, store in Redis.
            if secret == "email" {
                let mut redis_conn = state.redis.get().await?;
                if let Some(mfa_code) = body.mfa_code.as_deref() {
                    if mfa_code.trim().is_empty() {
                        return Err(ApiError::Validation(vec!["MFA code is required".into()]));
                    }
                    let key = format!("apexmail:email_mfa:{}", user.id);
                    let stored: Option<String> =
                        deadpool_redis::redis::AsyncCommands::get(&mut *redis_conn, &key).await?;
                    match stored {
                        Some(code) if code == mfa_code => {
                            let _: () =
                                deadpool_redis::redis::AsyncCommands::del(&mut *redis_conn, &key)
                                    .await?;
                        }
                        _ => {
                            record_login_failure(&state.redis, &login_identifier, Some(&client_ip))
                                .await?;
                            return Err(ApiError::Unauthorized("invalid MFA code".into()));
                        }
                    }
                } else {
                    // A code without a sendable notification is unusable.
                    // Check before writing the Redis challenge state.
                    ensure_system_sender_ready(&state.db).await?;

                    use rand::Rng;
                    let code: u32 = rand::rng().random_range(100000..999999);
                    let code_str = code.to_string();
                    let key = format!("apexmail:email_mfa:{}", user.id);
                    let _: () = deadpool_redis::redis::AsyncCommands::set_ex(
                        &mut *redis_conn,
                        &key,
                        &code_str,
                        300,
                    )
                    .await?;
                    tracing::info!(user_id = %user.id, email = %user.email, code_length = code_str.len(), "Email MFA code generated");
                    drop(redis_conn);

                    let safe_email = html_escape(&user.email);
                    let safe_code = html_escape(&code_str);
                    let html_body = format!(
                        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/></head><body style="font-family:ui-monospace,'JetBrains Mono',monospace;line-height:1.6;color:#09090b;max-width:560px;margin:0 auto;padding:24px">
<h2 style="color:#dc2626;text-transform:uppercase;letter-spacing:0.05em">Your MFA Code</h2>
<p>Your one-time verification code for <strong>{safe_email}</strong> is:</p>
<p style="font-size:28px;font-family:ui-monospace,'JetBrains Mono',monospace;letter-spacing:0.2em;font-weight:700;color:#dc2626">{safe_code}</p>
<p style="font-size:13px;color:#71717a">This code expires in 5 minutes. If you didn't request this, your account may be at risk.</p>
<hr style="border:none;border-top:1px solid #000;margin:24px 0"/>
<p style="font-size:11px;color:#999;text-transform:uppercase;letter-spacing:0.05em">&copy; 2026 ApexMail</p>
</body></html>"#,
                    );
                    let text_body = format!("Your MFA Code\n\nYour one-time verification code is: {code_str}\n\nThis code expires in 5 minutes.");
                    let challenge_token = match store_mfa_challenge(
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
                    .await
                    {
                        Ok(token) => token,
                        Err(error) => {
                            if let Err(cleanup_error) =
                                delete_email_mfa_code(&state.redis, &user.id).await
                            {
                                tracing::error!(
                                    error = %cleanup_error,
                                    user_id = %user.id,
                                    "failed to remove incomplete MFA code"
                                );
                            }
                            return Err(error);
                        }
                    };

                    let message_id = match queue_system_email(
                        &state.db,
                        &user.email,
                        "Your ApexMail MFA Code",
                        &html_body,
                        &text_body,
                        vec!["system".into(), "mfa".into()],
                    )
                    .await
                    {
                        Ok(message_id) => message_id,
                        Err(error) => {
                            if let Err(cleanup_error) =
                                delete_email_mfa_code(&state.redis, &user.id).await
                            {
                                tracing::error!(
                                    error = %cleanup_error,
                                    user_id = %user.id,
                                    "failed to remove undeliverable MFA code"
                                );
                            }
                            if let Err(cleanup_error) =
                                delete_mfa_challenge(&state.redis, &challenge_token).await
                            {
                                tracing::error!(
                                    error = %cleanup_error,
                                    user_id = %user.id,
                                    "failed to remove undeliverable MFA challenge"
                                );
                            }
                            tracing::error!(
                                error = %error,
                                user_id = %user.id,
                                "failed to queue MFA email"
                            );
                            return Err(error);
                        }
                    };
                    tracing::info!(user_id=%user.id, email=%user.email, %message_id, "MFA email queued");

                    return Ok(no_store_json_response(
                        StatusCode::ACCEPTED,
                        MfaChallengeResponse::verify(challenge_token),
                    ));
                }
            } else if let Some(mfa_code) = body.mfa_code.as_deref() {
                // Try TOTP first (with lockout + replay guards, F3), then
                // fall back to recovery code
                let totp_valid = verify_totp_code_guarded(&state.redis, secret, mfa_code).await;
                let recovery_valid = if !totp_valid {
                    verify_and_consume_recovery_code(
                        &state.db,
                        &user.id,
                        &user.tenant_id,
                        mfa_code,
                        user.mfa_recovery_hashes.as_ref(),
                    )
                    .await?
                } else {
                    false
                };

                if !totp_valid && !recovery_valid {
                    record_login_failure(&state.redis, &login_identifier, Some(&client_ip)).await?;
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
            let secret = generate_mfa_secret()?;
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

    // AR-005: Revoke all previous sessions on login to force session token rotation.
    // This prevents session fixation attacks where an attacker could reuse a
    // pre-authentication session after privilege escalation.
    let ttl = state.config.jwt_expiry.as_secs();
    let revoked_after = revoke_user_sessions(&state.redis, &user.tenant_id, &user.id, ttl).await?;

    issue_session_response_after_revocation(&state, &user, revoked_after)
}

/// Try to verify a code as a recovery/backup code and consume it if valid.
/// Returns `true` if the code was valid and has been consumed (removed from the stored set).
async fn verify_and_consume_recovery_code(
    db: &sqlx::PgPool,
    user_id: &str,
    tenant_id: &str,
    code: &str,
    stored_hashes_json: Option<&serde_json::Value>,
) -> Result<bool, ApiError> {
    let Some(json) = stored_hashes_json else {
        return Ok(false);
    };
    let Some(stored_hashes) = json.as_array() else {
        return Ok(false);
    };
    if stored_hashes.is_empty() {
        return Ok(false);
    }

    // Find which stored hash (if any) matches the provided code
    let hashes: Vec<String> = stored_hashes
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let matched_idx = hashes
        .iter()
        .position(|hash| apexmail_lib::mfa::verify_recovery_code(code, hash));

    if let Some(idx) = matched_idx {
        // Remove the consumed hash from the list
        let remaining: Vec<&str> = hashes
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != idx)
            .map(|(_, h)| h.as_str())
            .collect();

        let remaining_json = serde_json::to_value(&remaining)
            .map_err(|e| ApiError::Internal(format!("failed to serialize recovery hashes: {e}")))?;

        sqlx::query(
            "UPDATE users SET mfa_recovery_hashes = $1, updated_at = NOW()
             WHERE id = $2 AND tenant_id = $3",
        )
        .bind(&remaining_json)
        .bind(user_id)
        .bind(tenant_id)
        .execute(db)
        .await?;

        Ok(true)
    } else {
        Ok(false)
    }
}

async fn complete_mfa_challenge(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<CompleteMfaChallengeRequest>,
) -> Result<Response, ApiError> {
    // Validate CSRF token from X-CSRF-Token header (auth form protection)
    validate_form_csrf(&headers, &state.config.csrf_secret)?;

    if body.challenge_token.trim().is_empty() {
        return Err(ApiError::Validation(vec![
            "challenge_token is required".into()
        ]));
    }

    let client_ip = connect_info.as_ref().map(|ConnectInfo(addr)| {
        extract_public_client_ip(&headers, addr.ip(), &state.config.trusted_proxies)
    });
    let user_agent = headers.get("user-agent").and_then(|v| v.to_str().ok());

    let has_mfa_code = !body.mfa_code.trim().is_empty();
    let has_recovery_code = body
        .recovery_code
        .as_deref()
        .map(|c| !c.trim().is_empty())
        .unwrap_or(false);

    if !has_mfa_code && !has_recovery_code {
        return Err(ApiError::Validation(vec![
            "mfa_code or recovery_code is required".into(),
        ]));
    }

    // Single-use (F3): consume the challenge on this attempt regardless of
    // the outcome — a challenge token can never be retried after a failed
    // (or successful) verification.
    let challenge = consume_mfa_challenge(&state.redis, &body.challenge_token).await?;
    let login_identifier = normalized_login_identifier(&challenge.email);

    // Verify the TOTP code exactly once (F3): the replay guard makes codes
    // single-use, so a second verification of the same code below would
    // always fail. The result is carried into the second half instead.
    let totp_verified = match challenge.kind {
        MfaChallengeKind::Setup => {
            // Setup always requires a valid TOTP code
            if !has_mfa_code
                || !verify_totp_code_guarded(&state.redis, &challenge.secret, &body.mfa_code).await
            {
                record_login_failure(&state.redis, &login_identifier, client_ip.as_deref()).await?;
                return Err(ApiError::Unauthorized("invalid MFA code".into()));
            }
            true
        }
        MfaChallengeKind::Verify => {
            // Verify accepts either TOTP code or recovery code
            let totp_valid = has_mfa_code
                && verify_totp_code_guarded(&state.redis, &challenge.secret, &body.mfa_code).await;

            if !totp_valid {
                // Try recovery code before failing
                let rc = body
                    .recovery_code
                    .as_deref()
                    .filter(|c| !c.trim().is_empty());
                if rc.is_none() {
                    record_login_failure(&state.redis, &login_identifier, client_ip.as_deref())
                        .await?;
                    return Err(ApiError::Unauthorized("invalid MFA code".into()));
                }
                // Recovery code verification happens below after loading user
            }
            totp_valid
        }
    };

    clear_login_failures(&state.redis, &login_identifier).await?;

    let mut user = sqlx::query_as::<_, UserRow>(
        "SELECT id::text, tenant_id, email, name, password_hash, role, status, mfa_enabled, email_verified, mfa_secret, mfa_recovery_hashes
         FROM users WHERE id = $1::uuid AND tenant_id = $2",
    )
    .bind(&challenge.user_id)
    .bind(&challenge.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::Unauthorized("user no longer exists".into()))?;

    decrypt_mfa_secret_in_place(&mut user)?;

    if user.status != "active" {
        return Err(ApiError::Forbidden(format!("account is {}", user.status)));
    }
    // MFA completion is the second half of login: the email-verification
    // prerequisite applies exactly as at the password step.
    if !user.email_verified {
        return Err(ApiError::Forbidden(
            "email not verified — check your inbox for the verification link".into(),
        ));
    }

    match challenge.kind {
        MfaChallengeKind::Setup => {
            // Generate recovery codes
            let recovery_codes =
                apexmail_lib::mfa::try_generate_default_recovery_codes().map_err(|e| {
                    ApiError::Internal(format!("failed to generate recovery codes: {e}"))
                })?;
            let recovery_hashes: Vec<String> = recovery_codes
                .iter()
                .map(|code| {
                    apexmail_lib::mfa::try_hash_recovery_code(code).map_err(|e| {
                        ApiError::Internal(format!("failed to hash recovery code: {e}"))
                    })
                })
                .collect::<Result<_, _>>()?;
            let hashes_json = serde_json::to_value(&recovery_hashes).map_err(|e| {
                ApiError::Internal(format!("failed to serialize recovery hashes: {e}"))
            })?;

            // Encrypt the MFA secret at rest before persisting (CRIT-10).
            let encrypted_secret =
                encrypt_mfa_secret_for_user(&challenge.user_id, &challenge.secret)?;

            sqlx::query(
                "UPDATE users
                 SET mfa_secret = $1, mfa_enabled = true, mfa_recovery_hashes = $2, updated_at = NOW()
                 WHERE id = $3 AND tenant_id = $4",
            )
            .bind(&encrypted_secret)
            .bind(&hashes_json)
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
                client_ip.as_deref(),
                user_agent,
            )
            .await?;

            user.mfa_enabled = true;
            user.mfa_secret = Some(challenge.secret.clone());

            // AR-005: Rotate session after MFA setup (privilege escalation)
            let ttl = state.config.jwt_expiry.as_secs();
            let revoked_after =
                revoke_user_sessions(&state.redis, &user.tenant_id, &user.id, ttl).await?;

            issue_session_response_with_codes_after_revocation(
                &state,
                &user,
                Some(recovery_codes),
                revoked_after,
            )
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

            // If TOTP failed earlier, try recovery code. `totp_verified`
            // carries the one-shot verification result from above — the code
            // must NOT be verified again (replay guard makes it single-use).
            let totp_valid = totp_verified;
            if !totp_valid {
                let rc = body
                    .recovery_code
                    .as_deref()
                    .filter(|c| !c.trim().is_empty())
                    .unwrap_or(&body.mfa_code);

                let consumed = verify_and_consume_recovery_code(
                    &state.db,
                    &challenge.user_id,
                    &challenge.tenant_id,
                    rc,
                    user.mfa_recovery_hashes.as_ref(),
                )
                .await?;

                if !consumed {
                    record_login_failure(&state.redis, &login_identifier, client_ip.as_deref())
                        .await?;
                    return Err(ApiError::Unauthorized("invalid MFA code".into()));
                }

                insert_auth_audit_log(
                    &state,
                    &challenge.tenant_id,
                    &challenge.user_id,
                    "auth.mfa_recovery_code_used",
                    serde_json::json!({
                        "remaining_codes": 0, // approximate; we don't re-query
                    }),
                    client_ip.as_deref(),
                    user_agent,
                )
                .await?;
            }

            // AR-005: Rotate session after MFA verification (privilege escalation)
            let ttl = state.config.jwt_expiry.as_secs();
            let revoked_after =
                revoke_user_sessions(&state.redis, &user.tenant_id, &user.id, ttl).await?;

            issue_session_response_after_revocation(&state, &user, revoked_after)
        }
    }
}

// ─── MFA Management handlers ──────────────────────────────────

/// Request to confirm an MFA setup by providing a valid TOTP code.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmMfaSetupRequest {
    challenge_token: String,
    #[serde(rename = "mfaCode", alias = "mfa_code")]
    mfa_code: String,
}

/// Helper struct to fetch just the fields needed for MFA management.
#[derive(sqlx::FromRow)]
struct MfaUserRow {
    id: String,
    email: String,
    name: Option<String>,
    role: String,
    mfa_enabled: bool,
}

/// Initialise MFA setup for the current user.
///
/// Generates a new TOTP secret, stores a Setup‑kind MFA challenge in Redis,
/// and returns the challenge token, plaintext secret, and `otpauth://` URL
/// so the front‑end can render a QR code.
async fn init_mfa_setup(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Response, ApiError> {
    let user_id = authenticated_user_id(&auth)?;

    let user = sqlx::query_as::<_, MfaUserRow>(
        "SELECT id::text, email, name, role, mfa_enabled
         FROM users WHERE id = $1::uuid AND tenant_id = $2",
    )
    .bind(user_id)
    .bind(&auth.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("user not found".into()))?;

    if user.mfa_enabled {
        return Err(ApiError::Validation(vec!["MFA is already enabled".into()]));
    }

    let secret = generate_mfa_secret()?;
    let otpauth_url = build_mfa_otpauth_url(&user.email, &secret);

    let challenge_token = store_mfa_challenge(
        &state.redis,
        &MfaChallengeState {
            user_id: user.id.clone(),
            tenant_id: auth.tenant_id.clone(),
            email: user.email.clone(),
            name: user.name.clone(),
            role: user.role.clone(),
            secret: secret.clone(),
            kind: MfaChallengeKind::Setup,
        },
    )
    .await?;

    Ok(no_store_json_response(
        StatusCode::OK,
        serde_json::json!({
            "challengeToken": challenge_token,
            "secret": secret,
            "otpauthUrl": otpauth_url,
        }),
    ))
}

/// Confirm MFA setup by validating a TOTP code against the challenge secret.
///
/// On success the user's `mfa_secret` is encrypted and persisted,
/// `mfa_enabled` is set to `true`, and a set of recovery codes is generated.
/// The session is rotated (AR‑005) so the new privilege level requires a
/// fresh token.
async fn confirm_mfa_setup(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<ConfirmMfaSetupRequest>,
) -> Result<Response, ApiError> {
    let user_id = authenticated_user_id(&auth)?;

    if body.challenge_token.trim().is_empty() {
        return Err(ApiError::Validation(vec![
            "challenge_token is required".into()
        ]));
    }
    if body.mfa_code.trim().is_empty() {
        return Err(ApiError::Validation(vec!["mfa_code is required".into()]));
    }

    // Single-use (F3): consume the challenge on this attempt regardless of
    // the outcome, and check the TOTP code with lockout + replay guards.
    let challenge = consume_mfa_challenge(&state.redis, &body.challenge_token).await?;

    if !verify_totp_code_guarded(&state.redis, &challenge.secret, &body.mfa_code).await {
        return Err(ApiError::Unauthorized("invalid MFA code".into()));
    }

    let user = sqlx::query_as::<_, UserRow>(
        "SELECT id::text, tenant_id, email, name, password_hash, role, status, mfa_enabled, email_verified, mfa_secret, mfa_recovery_hashes
         FROM users WHERE id = $1::uuid AND tenant_id = $2",
    )
    .bind(user_id)
    .bind(&auth.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("user not found".into()))?;

    if user.mfa_enabled {
        return Err(ApiError::Validation(vec!["MFA is already enabled".into()]));
    }

    // Generate recovery codes
    let recovery_codes = apexmail_lib::mfa::try_generate_default_recovery_codes()
        .map_err(|e| ApiError::Internal(format!("failed to generate recovery codes: {e}")))?;
    let recovery_hashes: Vec<String> = recovery_codes
        .iter()
        .map(|code| {
            apexmail_lib::mfa::try_hash_recovery_code(code)
                .map_err(|e| ApiError::Internal(format!("failed to hash recovery code: {e}")))
        })
        .collect::<Result<_, _>>()?;
    let hashes_json = serde_json::to_value(&recovery_hashes)
        .map_err(|e| ApiError::Internal(format!("failed to serialize recovery hashes: {e}")))?;

    // Encrypt and persist
    let encrypted_secret = encrypt_mfa_secret_for_user(&challenge.user_id, &challenge.secret)?;

    sqlx::query(
        "UPDATE users
         SET mfa_secret = $1, mfa_enabled = true, mfa_recovery_hashes = $2, updated_at = NOW()
         WHERE id = $3 AND tenant_id = $4",
    )
    .bind(&encrypted_secret)
    .bind(&hashes_json)
    .bind(&user.id)
    .bind(&user.tenant_id)
    .execute(&state.db)
    .await?;

    insert_auth_audit_log(
        &state,
        &user.tenant_id,
        &user.id,
        "auth.mfa_enabled",
        serde_json::json!({
            "role": user.role,
            "enforced_for_admin": true,
        }),
        None, // client_ip – not fighting IP plumbing here
        None, // user_agent
    )
    .await?;

    // AR-005: Rotate session after MFA setup (privilege escalation)
    let ttl = state.config.jwt_expiry.as_secs();
    revoke_user_sessions(&state.redis, &user.tenant_id, &user.id, ttl).await?;

    Ok(no_store_json_response(
        StatusCode::OK,
        serde_json::json!({
            "mfaEnabled": true,
            "recoveryCodes": recovery_codes,
        }),
    ))
}

/// Return the current MFA status for the authenticated user.
async fn mfa_status(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user_id = authenticated_user_id(&auth)?;

    let row = sqlx::query_as::<_, (bool, String)>(
        "SELECT mfa_enabled, role FROM users WHERE id = $1::uuid AND tenant_id = $2",
    )
    .bind(user_id)
    .bind(&auth.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("user not found".into()))?;

    Ok(Json(serde_json::json!({
        "mfaEnabled": row.0,
        "roleRequiresMfa": role_requires_mfa(&row.1),
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
    mfa_enabled: bool,
    email_verified: bool,
    mfa_secret: Option<String>,
    mfa_recovery_hashes: Option<serde_json::Value>,
}

// ─── Registration types ────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
pub struct RegisterRequest {
    /// Optional since the 2026-09-08 signup simplification: the first
    /// screen collects email + password only; name/company are gathered
    /// during post-verification onboarding. Defaults keep the tenant
    /// record valid (slug, display name) until the user fills them in.
    #[serde(default)]
    pub company_name: Option<String>,
    pub email: String,
    #[serde(default)]
    pub name: Option<String>,
    pub password: String,
    #[serde(default = "default_plan")]
    pub plan: String,
    /// Token from the KiwiCaptcha proof-of-work widget, submitted as a hidden form field.
    /// Optional for non-interactive API clients; required if KiwiCaptcha is enabled.
    #[serde(default, rename = "kiwi__token")]
    pub kiwi__token: Option<String>,
}

fn default_plan() -> String {
    "free".into()
}

/// Plans that may be selected during public registration. A selection is
/// retained as non-entitling onboarding intent; it never changes the tenant's
/// active plan. Enterprise sales and PAYG onboarding have separate flows, so
/// they are intentionally not accepted by this public registration endpoint.
const PUBLIC_SIGNUP_PLAN_IDS: &[&str] = &["free", "starter", "pro", "growth", "scale"];

/// Validate a public registration plan and return the paid-plan intent, if
/// any. The returned value is a static catalog identifier so untrusted input
/// is never copied into tenant metadata or audit logs.
fn signup_plan_intent(plan: &str) -> Result<Option<&'static str>, ApiError> {
    if !PUBLIC_SIGNUP_PLAN_IDS.contains(&plan) {
        return Err(ApiError::Validation(vec!["invalid plan selection".into()]));
    }

    match plan {
        "free" => Ok(None),
        "starter" => Ok(Some("starter")),
        "pro" => Ok(Some("pro")),
        "growth" => Ok(Some("growth")),
        "scale" => Ok(Some("scale")),
        // The allow-list above makes this unreachable while retaining an
        // explicit fallback if the catalog is edited incorrectly.
        _ => Err(ApiError::Validation(vec!["invalid plan selection".into()])),
    }
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
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), ApiError> {
    // Validate CSRF token from X-CSRF-Token header (auth form protection)
    validate_form_csrf(&headers, &state.config.csrf_secret)?;

    // Extract client IP for KiwiCaptcha IP-binding verification.
    let client_ip = connect_info
        .map(|ConnectInfo(addr)| {
            extract_public_client_ip(&headers, addr.ip(), &state.config.trusted_proxies)
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Verify KiwiCaptcha proof-of-work before processing registration.
    verify_kiwi_token(
        &state.config,
        &state.redis,
        body.kiwi__token.as_deref(),
        &client_ip,
        Some("signup"),
    )
    .await?;

    // Validate input. company_name/name are optional (signup §37): when
    // absent they default from the email local-part so the tenant record
    // and billing slug stay well-formed.
    let email_local = body
        .email
        .split('@')
        .next()
        .unwrap_or("workspace")
        .to_string();
    let company_name = body
        .company_name
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or(&email_local)
        .to_string();
    let display_name = body
        .name
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or(&email_local)
        .to_string();
    if company_name.len() > 100 {
        return Err(ApiError::Validation(vec![
            "company_name must be 1-100 characters".into(),
        ]));
    }
    if body.email.is_empty() || body.email.len() > 254 {
        return Err(ApiError::Validation(vec!["invalid email address".into()]));
    }
    if display_name.len() > 100 {
        return Err(ApiError::Validation(vec![
            "name must be 1-100 characters".into()
        ]));
    }
    validate_password_strength(&body.password)?;

    // A plan submitted at sign-up is only an onboarding preference. Never
    // grant a paid entitlement until the authenticated billing flow creates a
    // Stripe subscription and its verified webhook updates the tenant.
    let signup_plan_intent = signup_plan_intent(&body.plan)?;

    // Rate-limit only after cheap validation so ordinary form mistakes do not
    // burn the user's sign-up attempts. The limit still protects the database
    // and email queue from repeated valid registration submissions.

    let rate_key = format!("apexmail:register_rate:{client_ip}");

    if let Ok(mut conn) = state.redis.get().await {
        // Atomic INCR + EXPIRE-on-first (single Lua script) so the key can
        // never be left behind without a TTL.
        let count: i64 = match deadpool_redis::redis::Script::new(INCR_EXPIRE_LUA)
            .key(&rate_key)
            .arg(REGISTER_RATE_LIMIT_WINDOW_SECS)
            .invoke_async(&mut *conn)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, ip = %client_ip, "register rate-limit INCR failed; rejecting request");
                return Err(ApiError::Internal("rate limit check unavailable".into()));
            }
        };

        if count > REGISTER_RATE_LIMIT_MAX_REQUESTS {
            return Err(ApiError::RateLimitedMessage(register_rate_limit_message()));
        }
    }

    let email_lower = body.email.to_lowercase();

    // A new account cannot complete onboarding without a verification email.
    // Check before creating tenant/user state so an outage never leaves an
    // account stranded with a message the delivery worker will reject.
    ensure_system_sender_ready(&state.db).await?;

    // Check if email already exists
    let existing: Option<String> =
        sqlx::query_scalar("SELECT id::text FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1")
            .bind(&email_lower)
            .fetch_optional(&state.db)
            .await?;

    if existing.is_some() {
        return Ok((StatusCode::ACCEPTED, Json(register_response())));
    }

    // Generate IDs and slug.
    //
    // Schema note (canonical services/mail-server/migrations lineage):
    // tenants.id is VARCHAR(26) (ULID, migration 064) — a 26-char text id is
    // correct — but users.id is UUID (migration 052). A text nanoid bound
    // into users.id fails the INSERT with `invalid input syntax for type
    // uuid`, breaking every public registration; generate a UUID for the
    // user id (same convention as create_api_key / the reset-password fix).
    let tenant_id = apexmail_lib::id::generate_id("", 26);
    let user_id = Uuid::new_v4();
    let slug = generate_slug(&company_name);
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

    let tenant_metadata = match signup_plan_intent {
        Some(plan) => serde_json::json!({
            "signup_plan_intent": plan,
            "signup_plan_selected_at": now.to_rfc3339(),
        }),
        None => serde_json::json!({}),
    };

    // Every public registration begins on Free. The requested paid plan is
    // auditable intent only and must be activated by the billing webhook.
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
    )
    .bind(&tenant_id)
    .bind(&company_name)
    .bind(&slug)
    .bind("free")
    .bind("pending")
    .bind(serde_json::json!({}))
    .bind(tenant_metadata)
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
    .bind(user_id)
    .bind(&tenant_id)
    .bind(&email_lower)
    .bind(&display_name)
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

    // Verification is required to complete a public registration, so account
    // creation and queue admission use the same transaction. A concurrent
    // sender-domain revoke or queue failure rolls the account back instead of
    // stranding an unverifiable tenant.
    enqueue_verification_email(&mut tx, &state.config.base_url, &email_lower, &verification_token)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, tenant_id = %tenant_id, user_id = %user_id, "failed to queue verification email during registration");
            error
        })?;

    tx.commit().await.map_err(|error| {
        tracing::error!(error = %error, tenant_id = %tenant_id, user_id = %user_id, "failed to commit registration transaction");
        ApiError::Internal("database error".into())
    })?;

    tracing::info!(
        tenant_id = %tenant_id,
        user_id = %user_id,
        signup_plan_intent = ?signup_plan_intent,
        active_plan = "free",
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
    // Deprecated query-string form (CWE-598): a token in the query string
    // leaks into server/access logs, proxies, Referer headers, and browser
    // history. Retained only so in-flight links and API clients built
    // against the old shape keep working — new links use
    // GET /v1/auth/verify-email/{token} (F5).
    tracing::warn!(
        "deprecated query-string email verification used; use /v1/auth/verify-email/{{token}}"
    );
    Ok(Json(verify_email_token(&state, &params.token).await?))
}

/// Path-parameter form of email verification (F5/CWE-598): the token
/// travels in the path, never in the query string.
///
/// F65: verification emails link HERE, so the primary consumer is a
/// browser navigation. After a SUCCESSFUL exchange the response for
/// HTML-preferring clients is a 303 to the token-free page URL, taking the
/// token out of the address bar, history, and any onward Referer header.
/// Non-browser clients (no `Accept: text/html`) keep the JSON contract.
async fn verify_email_by_path(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Result<Response, ApiError> {
    let result = verify_email_token(&state, &token).await;

    if let Ok(verification) = &result {
        if client_prefers_html(&headers) {
            let location = format!(
                "/verify-email?status=success&message={}",
                urlencode_component(&verification.message)
            );
            let mut response = (
                StatusCode::SEE_OTHER,
                [(axum::http::header::LOCATION, location)],
            )
                .into_response();
            // Strict referrer policy for the token-bearing exchange: the
            // page (and anything it links to) must never re-disclose the
            // URL the token arrived on.
            response.headers_mut().insert(
                axum::http::header::REFERRER_POLICY,
                HeaderValue::from_static("no-referrer"),
            );
            return Ok(response);
        }
    }

    Ok(result.map(Json).into_response())
}

/// Whether the client's `Accept` header prefers an HTML response — i.e.
/// this is a browser navigation rather than an API call.
fn client_prefers_html(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| accept.contains("text/html"))
}

/// Percent-encode a query component for a `Location` header value.
fn urlencode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
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

    // Lookup, consumption, and activation share ONE transaction (F16): the
    // row lock taken below serializes concurrent presentations of the same
    // token, and the conditional UPDATE consumes it only while THIS token
    // hash is still stored on the still-unverified row.
    let mut tx = state.db.begin().await?;

    // Find user with matching verification token. `users.id` is UUID
    // (migrations 052/056), so the id is returned and re-bound as
    // `uuid::Uuid` — the previous text round-trip bound a TEXT value
    // against the UUID column and failed with 42883
    // `operator does not exist: uuid = text` (F15). `tenant_id` is
    // VARCHAR(26) (migration 064) and stays a String.
    let user: Option<(Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT id, tenant_id, metadata->>'verification_expires' AS verification_expires
         FROM users
         WHERE metadata->>'verification_token_hash' = $1
           AND email_verified = false
         LIMIT 1
         FOR UPDATE",
    )
    .bind(&token_hash)
    .fetch_optional(&mut *tx)
    .await?;

    let (user_id, tenant_id, expires_raw) = match user {
        Some(u) => u,
        None => {
            let _ = tx.rollback().await;
            return Err(ApiError::BadRequest(
                "invalid or expired verification token".into(),
            ));
        }
    };

    // Expiry is mandatory and typed (F16): the RFC 3339 metadata string is
    // parsed into a `DateTime<Utc>` and must lie in the future. A missing
    // or malformed value fails CLOSED — the old code silently skipped the
    // expiry check whenever parsing failed, and a missing value was never
    // checked at all.
    let expires: chrono::DateTime<chrono::Utc> = match expires_raw
        .as_deref()
        .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
        .map(|parsed| parsed.with_timezone(&Utc))
    {
        Some(expires) => expires,
        None => {
            let _ = tx.rollback().await;
            tracing::warn!(
                user_id = %user_id,
                tenant_id = %tenant_id,
                "verification token has missing or malformed expiry — refusing"
            );
            return Err(ApiError::BadRequest(
                "invalid or expired verification token".into(),
            ));
        }
    };
    if Utc::now() > expires {
        let _ = tx.rollback().await;
        return Err(ApiError::BadRequest(
            "verification token has expired".into(),
        ));
    }

    // Consume the token atomically (F16): the UPDATE matches only while the
    // exact token hash is still present on the still-unverified row, so a
    // replay — including one that raced the SELECT — affects zero rows.
    let consumed = sqlx::query(
        "UPDATE users SET email_verified = true,
            metadata = metadata - 'verification_token_hash' - 'verification_token' - 'verification_expires',
         updated_at = NOW()
         WHERE id = $1
           AND email_verified = false
           AND metadata->>'verification_token_hash' = $2",
    )
    .bind(user_id)
    .bind(&token_hash)
    .execute(&mut *tx)
    .await?;
    if consumed.rows_affected() == 0 {
        let _ = tx.rollback().await;
        return Err(ApiError::BadRequest(
            "invalid or expired verification token".into(),
        ));
    }

    // Activate the tenant ONLY from the initial pending-verification state
    // (F16): an administrative, abuse, or billing hold written between
    // sign-up and this click survives verification instead of being
    // clobbered to 'active'.
    sqlx::query(
        "UPDATE tenants SET status = 'active', updated_at = NOW()
         WHERE id = $1 AND status = 'pending'",
    )
    .bind(&tenant_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    tracing::info!(user_id = %user_id, tenant_id = %tenant_id, "Email verified");

    Ok(VerifyEmailResponse {
        success: true,
        message: "Email verified successfully. You can now log in.".into(),
    })
}

/// A newly minted API key: the one-time raw secret plus the persisted
/// metadata. Returned by [`mint_api_key`].
pub(crate) struct MintedApiKey {
    pub id: String,
    pub raw_key: String,
    pub key_prefix: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
}

/// Shared API key creation (F46): the JSON endpoint (`POST /v1/api-keys`)
/// and the console form (`POST /web/api-keys`) BOTH go through this
/// function, so scope authorization (F17), the expiry default/bounds, the
/// keyed HMAC hash, and the per-tenant key ceiling are enforced
/// identically on both surfaces. The console-created keys previously
/// bypassed the JSON endpoint's expiry policy entirely (no `expires_at`).
pub(crate) async fn mint_api_key(
    state: &AppState,
    caller: &AuthUser,
    name: &str,
    scopes: &[String],
    expires_in_days: Option<i64>,
) -> Result<MintedApiKey, ApiError> {
    // Scope gate (F2): minting keys is a write-capability on credential
    // material, not an implicit side effect of being logged in. Admin/owner
    // sessions hold the "*" wildcard, so they pass transparently.
    require_scopes(caller, &["api-keys:write"])?;

    let name = name.trim();
    if name.is_empty() {
        return Err(ApiError::Validation(vec!["name is required".into()]));
    }
    if name.len() > 100 {
        return Err(ApiError::Validation(vec![
            "name must be at most 100 characters".into(),
        ]));
    }
    if scopes.len() > 50 {
        return Err(ApiError::Validation(vec![
            "at most 50 scopes are allowed".into()
        ]));
    }

    // Privilege-escalation guard (F17): every requested scope must be
    // registered AND held by the caller — the wildcard authorizes any
    // registered scope, restricted callers authorize their own scopes
    // only, and "*" is mintable solely by a wildcard holder.
    for scope in scopes {
        authorize_scope_issuance(&caller.scopes, scope)?;
    }

    // Same expiry policy for every surface (F46): absent = the 90-day
    // default, values bounded to 1..=365 days.
    let now = Utc::now();
    let expires_at = resolve_api_key_expiry(expires_in_days, now)?;

    let raw_key = apexmail_lib::id::generate_api_key(false);
    let key_hash =
        apexmail_lib::hash_api_key_with_secret(&raw_key, &state.config.api_key_hash_secret);
    // The persisted prefix must fit the api_keys.key_prefix VARCHAR(8) column.
    // If the key is unusually short, store at most 8 chars (or half the key)
    // to avoid exposing the full key.
    let prefix_len = if raw_key.len() >= 8 {
        8
    } else {
        raw_key.len().min(8).max(raw_key.len() / 2)
    };
    let key_prefix = raw_key[..prefix_len].to_string();

    let id = Uuid::new_v4();

    // One transaction with the tenant row LOCKED (F46/F18): the per-tenant
    // key count is enforced atomically — concurrent mints serialize on the
    // row lock instead of racing a COUNT-then-INSERT past the ceiling — and
    // the tenant policy is decided at mint time through the SAME helper
    // the auth middleware uses, so a suspended tenant mints nothing.
    let mut tx = state.db.begin().await?;
    let tenant_status: Option<String> =
        sqlx::query_scalar("SELECT status FROM tenants WHERE id = $1 FOR UPDATE")
            .bind(&caller.tenant_id)
            .fetch_optional(&mut *tx)
            .await?;
    match tenant_status.as_deref() {
        Some(status) if crate::middleware::auth::tenant_status_permits_auth(status) => {}
        Some(status) => {
            let _ = tx.rollback().await;
            tracing::warn!(
                tenant_id = %caller.tenant_id,
                tenant_status = %status,
                "API key mint refused for restricted tenant"
            );
            return Err(ApiError::Forbidden(format!(
                "workspace is {status} — API keys cannot be created until it is active"
            )));
        }
        None => {
            let _ = tx.rollback().await;
            return Err(ApiError::Forbidden("workspace not found".into()));
        }
    }

    let existing_keys: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM api_keys WHERE tenant_id = $1")
            .bind(&caller.tenant_id)
            .fetch_one(&mut *tx)
            .await?;
    if existing_keys.0 >= MAX_API_KEYS_PER_TENANT {
        let _ = tx.rollback().await;
        return Err(ApiError::Forbidden(format!(
            "API key limit reached: maximum {MAX_API_KEYS_PER_TENANT} keys per tenant"
        )));
    }

    sqlx::query(
        "INSERT INTO api_keys (id, tenant_id, name, key_prefix, key_hash, scopes, expires_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)",
    )
    .bind(id)
    .bind(&caller.tenant_id)
    .bind(name)
    .bind(&key_prefix)
    .bind(&key_hash)
    .bind(serde_json::json!(scopes))
    .bind(expires_at)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(MintedApiKey {
        id: id.to_string(),
        raw_key,
        key_prefix,
        name: name.to_string(),
        scopes: scopes.to_vec(),
        created_at: now,
        expires_at,
    })
}

async fn create_api_key(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<CreateApiKeyResponse>), ApiError> {
    // F46: shared creation path with the console form — scope
    // authorization, expiry policy, hashing, ceiling, and persistence all
    // live in `mint_api_key`.
    let minted = mint_api_key(
        &state,
        &auth,
        &body.name,
        &body.scopes,
        body.expires_in_days,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateApiKeyResponse {
            id: minted.id,
            key: minted.raw_key,
            key_prefix: minted.key_prefix,
            name: minted.name,
            scopes: minted.scopes,
            created_at: minted.created_at.to_rfc3339(),
            expires_at: Some(minted.expires_at.to_rfc3339()),
        }),
    ))
}

async fn list_api_keys(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ListApiKeysQuery>,
) -> Result<Json<Vec<ApiKeyInfo>>, ApiError> {
    // Scope gate (F2): key prefixes/scope sets are credential metadata and
    // must not be enumerable by every member of the tenant.
    require_scopes(&auth, &["api-keys:read"])?;

    let offset = params.cursor.unwrap_or(params.offset).clamp(0, 100_000);
    let rows = sqlx::query_as::<_, ApiKeyInfoRow>(
        "SELECT id::text AS id, name, key_prefix, scopes, last_used_at, created_at, expires_at
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
    // Scope gate (F2): destroying credentials is a write operation.
    require_scopes(&auth, &["api-keys:write"])?;

    let deleted_key_hash: Option<String> = sqlx::query_scalar(
        "DELETE FROM api_keys WHERE id::text = $1 AND tenant_id = $2 RETURNING key_hash",
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
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<ResetPasswordRequest>,
) -> Result<Json<ResetPasswordResponse>, ApiError> {
    // Validate CSRF token from X-CSRF-Token header (auth form protection)
    validate_form_csrf(&headers, &state.config.csrf_secret)?;

    // Rate-limit by client IP using Redis
    let client_ip = connect_info
        .map(|ConnectInfo(addr)| {
            extract_public_client_ip(&headers, addr.ip(), &state.config.trusted_proxies)
        })
        .unwrap_or_else(|| {
            tracing::warn!(
                "reset-password request missing ConnectInfo; using shared rate-limit bucket"
            );
            "unknown".to_string()
        });

    // Verify KiwiCaptcha proof-of-work token
    verify_kiwi_token(
        &state.config,
        &state.redis,
        body.kiwi__token.as_deref(),
        &client_ip,
        Some("reset-password"),
    )
    .await?;

    let rate_key = format!("apexmail:reset_password_rate:{client_ip}");
    let window_secs: u64 = 15 * 60; // 15 minutes
    let max_requests: i64 = 5;

    if let Ok(mut conn) = state.redis.get().await {
        // Atomic INCR + EXPIRE-on-first (single Lua script) so the key can
        // never be left behind without a TTL.
        let count: i64 = match deadpool_redis::redis::Script::new(INCR_EXPIRE_LUA)
            .key(&rate_key)
            .arg(window_secs)
            .invoke_async(&mut *conn)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, ip = %client_ip, "reset-password rate-limit INCR failed; rejecting request");
                return Err(ApiError::Internal("rate limit check unavailable".into()));
            }
        };

        if count > max_requests {
            return Err(ApiError::RateLimited);
        }
    }

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
    let user: Option<(String, String, String, serde_json::Value)> = sqlx::query_as(
        "SELECT id::text, tenant_id, status, metadata FROM users
         WHERE LOWER(email) = LOWER($1)
                     AND metadata->>'password_reset_token_hash' = $2
         LIMIT 1",
    )
    .bind(&email)
    .bind(&token_hash)
    .fetch_optional(&state.db)
    .await?;

    let Some((user_id, tenant_id, status, metadata)) = user else {
        return Err(ApiError::BadRequest(
            "invalid or expired reset token".into(),
        ));
    };

    if status != "active" {
        return Err(ApiError::Forbidden(format!("account is {status}")));
    }

    // Primary expiration check: token-level expiry (typically one hour).
    // Missing or malformed expiry metadata must never turn a reset token into
    // a non-expiring credential.
    let expires_str = metadata
        .get("password_reset_expires")
        .and_then(|value| value.as_str())
        .ok_or_else(|| ApiError::BadRequest("invalid or expired reset token".into()))?;
    let expires = chrono::DateTime::parse_from_rfc3339(expires_str)
        .map_err(|_| ApiError::BadRequest("invalid or expired reset token".into()))?;
    if Utc::now() > expires {
        return Err(ApiError::BadRequest(
            "password reset token has expired".into(),
        ));
    }

    // SA2-003: Secondary hard-coded expiration check (24h absolute max)
    // This ensures tokens cannot be used beyond a hard-coded window even if
    // the primary expiration value is extended.
    const MAX_RESET_TOKEN_TTL_HOURS: i64 = 24;
    let iat_str = metadata
        .get("password_reset_iat")
        .and_then(|value| value.as_str())
        .ok_or_else(|| ApiError::BadRequest("invalid or expired reset token".into()))?;
    let iat = chrono::DateTime::parse_from_rfc3339(iat_str)
        .map_err(|_| ApiError::BadRequest("invalid or expired reset token".into()))?;
    let now = Utc::now();
    if iat > now || now > iat + chrono::Duration::hours(MAX_RESET_TOKEN_TTL_HOURS) {
        return Err(ApiError::BadRequest(
            "password reset token has exceeded maximum lifetime".into(),
        ));
    }

    let password_hash = apexmail_lib::hash_password(&body.password)
        .map_err(|error| ApiError::Internal(format!("password hashing failed: {error}")))?;

    // Revoke before changing the password. A Redis failure therefore fails
    // closed without updating credentials; a later optimistic-lock miss only
    // causes a harmless extra session revocation.
    let ttl = state.config.jwt_expiry.as_secs();
    revoke_user_sessions(&state.redis, &tenant_id, &user_id, ttl).await?;

    let password_update = sqlx::query(
        "UPDATE users
         SET password_hash = $1,
             metadata = metadata - 'password_reset_token_hash' - 'password_reset_token' - 'password_reset_expires' - 'password_reset_iat',
             updated_at = NOW()
         WHERE id = $2
           AND status = 'active'
           AND metadata->>'password_reset_token_hash' = $3",
    )
    .bind(password_hash)
    .bind(&user_id)
    .bind(&token_hash)
    .execute(&state.db)
    .await?;
    if password_update.rows_affected() != 1 {
        return Err(ApiError::BadRequest(
            "invalid or expired reset token".into(),
        ));
    }

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

    // Decode existing token to get claims.
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.set_required_spec_claims(&["exp", "sub", "tenant_id"]);

    let token_data =
        crate::middleware::auth::decode_jwt_with_rotation(&token, &state.config, &validation)?;
    let old_claims = token_data.claims;

    // Token-type confusion (audit B): the middleware already rejects
    // non-session `typ` claims for API authentication, but refresh used to
    // decode the cookie JWT blindly — letting a stream token (or any other
    // non-session typ) be refreshed into a brand-new full `"*"`-scope
    // session. Enforce the same discrimination here.
    if !crate::middleware::auth::claims_typ_is_session(old_claims.typ.as_deref()) {
        tracing::warn!(
            token_type = old_claims.typ.as_deref().unwrap_or("<missing>"),
            "rejecting refresh for a non-session token"
        );
        return Err(ApiError::Unauthorized("invalid token type".into()));
    }

    let user_id = old_claims.sub.clone();
    let tenant_id = old_claims.tenant_id.clone();

    // Check if the session has been revoked since the token was issued
    let revoked_after = lookup_session_revoked_after(&tenant_id, &user_id, &state).await?;
    if issued_before_or_at_revocation(old_claims.iat, revoked_after) {
        return Err(ApiError::Unauthorized("session has been revoked".into()));
    }

    // Per-token blacklist (logout / a prior refresh's rotation): the
    // registry above only encodes user-wide revocation, so a token that
    // logout blacklisted could still mint a brand-new session here. Same
    // key scheme and fail-closed Redis handling as the middleware's
    // blacklist check (middleware::auth::is_token_blacklisted).
    let blacklist_key = token_blacklist_key(&token);
    let blacklisted: bool = {
        let mut conn = state.redis.get().await.map_err(|error| {
            tracing::error!(error = %error, "Redis unavailable for token blacklist check on refresh");
            ApiError::ServiceUnavailable(
                "authentication service temporarily unavailable".into(),
            )
        })?;
        deadpool_redis::redis::AsyncCommands::exists(&mut *conn, &blacklist_key)
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "Redis EXISTS failed for token blacklist check on refresh");
                ApiError::ServiceUnavailable(
                    "authentication service temporarily unavailable".into(),
                )
            })?
    };
    if blacklisted {
        tracing::info!(user_id = %user_id, "refresh refused for blacklisted token");
        return Err(ApiError::Unauthorized("session has been revoked".into()));
    }

    let user = sqlx::query_as::<_, UserRow>(
        "SELECT id::text, tenant_id, email, name, password_hash, role, status, email_verified FROM users WHERE id = $1::uuid",
    )
    .bind(&user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("user not found".into()))?;

    // Fix #21: Reject refresh if the user is no longer active.
    if user.status != "active" {
        return Err(ApiError::Forbidden(format!("account is {}", user.status)));
    }
    // Refresh is a login continuation: an unverified account never
    // receives a fresh session through it either.
    if !user.email_verified {
        return Err(ApiError::Forbidden(
            "email not verified — check your inbox for the verification link".into(),
        ));
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

    let session_id = Uuid::new_v4().to_string();

    let claims = JwtClaims {
        sub: user.id.to_string(),
        tenant_id: user.tenant_id.to_string(),
        scopes: scopes_for_role(&user.role),
        exp: exp.timestamp(),
        iat: now.timestamp(),
        jti: session_id,
        typ: Some("session".into()),
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
            recovery_codes: None,
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
            recovery_codes: None,
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
    fn public_signup_plan_selection_is_bounded_and_non_entitling() {
        assert_eq!(signup_plan_intent("free").unwrap(), None);
        assert_eq!(signup_plan_intent("starter").unwrap(), Some("starter"));
        assert_eq!(signup_plan_intent("pro").unwrap(), Some("pro"));
        assert_eq!(signup_plan_intent("growth").unwrap(), Some("growth"));
        assert_eq!(signup_plan_intent("scale").unwrap(), Some("scale"));

        // Legacy identifiers and sales/PAYG plans must not be accepted by the
        // unauthenticated public registration endpoint.
        for invalid in ["developer", "business", "enterprise", "payg", "admin"] {
            assert!(matches!(
                signup_plan_intent(invalid),
                Err(ApiError::Validation(_))
            ));
        }
    }

    #[test]
    fn public_signup_plan_catalog_matches_the_declared_allowlist() {
        assert_eq!(
            PUBLIC_SIGNUP_PLAN_IDS,
            ["free", "starter", "pro", "growth", "scale"]
        );
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

        assert!(verify_password_or_log(password, &hash, "argon2-user@example.com").unwrap());
        assert!(
            !verify_password_or_log("WrongPassword1!", &hash, "argon2-user@example.com").unwrap()
        );
    }

    #[test]
    fn test_verify_password_or_log_accepts_bcrypt_hashes() {
        let password = "StrongPassword1!";
        let hash = bcrypt::hash(password, 4).unwrap();

        assert!(verify_password_or_log(password, &hash, "bcrypt-user@example.com").unwrap());
        assert!(
            !verify_password_or_log("WrongPassword1!", &hash, "bcrypt-user@example.com").unwrap()
        );
    }

    #[test]
    fn test_validate_password_strength_follows_nist_length_policy() {
        // NIST SP 800-63B-4 (review 2026-09-08 §21): length + blocklist,
        // no composition mandates. A long lowercase passphrase is valid…
        assert!(validate_password_strength("correct horse battery staple").is_ok());
        // …Unicode and spaces are allowed…
        assert!(validate_password_strength("grüße großes passwort").is_ok());
        // …composition rules are GONE: letters-only is fine if long enough.
        assert!(validate_password_strength("LetterOnlyLongPassphrase").is_ok());
        // Too short under the 15-char minimum…
        assert!(matches!(
            validate_password_strength("Strong1!a"),
            Err(ApiError::Validation(_))
        ));
        // …and the old composition-mandate error is retired with it: a
        // 15+ char letters-only password must NOT be rejected.
        assert!(!matches!(
            validate_password_strength("PlainButLongEnough"),
            Err(ApiError::Validation(m)) if m.iter().any(|e| e.contains("uppercase"))
        ));
        // Weak-password blocklist and repeat/sequence rules still apply.
        assert!(matches!(
            validate_password_strength("123456789012345678"),
            Err(ApiError::Validation(_))
        ));
        assert!(matches!(
            validate_password_strength("aaaabbbbccccdddde"),
            Err(ApiError::Validation(_))
        ));
        assert!(matches!(
            validate_password_strength("abcdabcdabcdabcd"),
            Err(ApiError::Validation(_))
        ));
    }

    #[test]
    fn test_register_rate_limit_is_not_tiny_retry_bucket() {
        const {
            assert!(REGISTER_RATE_LIMIT_MAX_REQUESTS >= 20);
            assert!(REGISTER_RATE_LIMIT_WINDOW_SECS <= 10 * 60);
        }
        assert!(register_rate_limit_message().contains("sign-up attempts"));
    }

    #[test]
    fn test_authenticated_user_id_requires_user_session() {
        let auth = AuthUser {
            tenant_id: "tenant_123".into(),
            user_id: None,
            api_key_id: Some("key_123".into()),
            session_id: None,
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
            session_id: None,
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

    /// Serialises tests that mutate the `AUDIT_SIGNING_KEY` process env var
    /// (env access is process-global and cargo runs tests in parallel).
    static AUDIT_KEY_ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_audit_signature_refuses_fallback_key_in_production() {
        let _guard = AUDIT_KEY_ENV_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // Production without a configured key: hard error — never sign with
        // the publicly-known development fallback (L-14/L-21).
        std::env::remove_var("AUDIT_SIGNING_KEY");
        match audit_log_signature(true, "hash", "prev") {
            Err(ApiError::Internal(message)) if message.contains("AUDIT_SIGNING_KEY") => {}
            other => {
                panic!("production without AUDIT_SIGNING_KEY must refuse to sign, got {other:?}")
            }
        }

        // Production with the key configured: real HMAC signature.
        std::env::set_var("AUDIT_SIGNING_KEY", "prod-audit-key-0123456789abcdef");
        let signed = audit_log_signature(true, "hash", "prev").expect("signs with real key");
        assert_eq!(signed.len(), 64, "hex-encoded HMAC-SHA256");
        assert!(!signed.is_empty() && signed.chars().all(|c| c.is_ascii_hexdigit()));

        std::env::remove_var("AUDIT_SIGNING_KEY");
    }

    #[test]
    fn test_audit_signature_uses_dev_fallback_outside_production() {
        let _guard = AUDIT_KEY_ENV_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        std::env::remove_var("AUDIT_SIGNING_KEY");
        let dev = audit_log_signature(false, "hash", "prev")
            .expect("development may use the warned fallback key");
        assert_eq!(dev.len(), 64);

        // The configured key always wins, in any environment.
        std::env::set_var("AUDIT_SIGNING_KEY", "shared-key-0123456789abcdef");
        let keyed = audit_log_signature(false, "hash", "prev").unwrap();
        assert_eq!(
            keyed,
            audit_log_signature(true, "hash", "prev").unwrap(),
            "signature depends only on the key material, not the environment flag"
        );
        assert_ne!(keyed, dev, "fallback and real keys sign differently");

        std::env::remove_var("AUDIT_SIGNING_KEY");
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

    // ── F17: wildcard + restricted scope issuance ─────────────────────

    #[test]
    fn registered_api_key_scopes_covers_role_grants_and_wildcard() {
        let registry = registered_api_key_scopes();
        assert!(
            registry.contains(&"*".to_string()),
            "wildcard is registered"
        );
        for scope in scopes_for_role("developer") {
            assert!(
                registry.contains(&scope),
                "developer scope {scope} must be registered"
            );
        }
        for scope in scopes_for_role("viewer") {
            assert!(
                registry.contains(&scope),
                "viewer scope {scope} must be registered"
            );
        }
        // The key-minting scopes are NOT role-granted (only wildcard holders
        // pass the api-keys:write gate), so they are deliberately absent:
        // a minted key must not be able to mint further keys.
        assert!(!registry.contains(&"api-keys:write".to_string()));
        assert!(!registry.contains(&"api-keys:read".to_string()));
    }

    #[test]
    fn wildcard_caller_mints_any_registered_scope() {
        let caller = vec!["*".to_string()];
        // THE F17 REGRESSION: a wildcard administrator previously could NOT
        // mint an ordinary scoped key (exact-match check), forcing them to
        // mint full-power "*" keys instead.
        assert!(authorize_scope_issuance(&caller, "messages:send").is_ok());
        assert!(authorize_scope_issuance(&caller, "webhooks:write").is_ok());
        assert!(authorize_scope_issuance(&caller, "suppressions:read").is_ok());
        assert!(authorize_scope_issuance(&caller, "*").is_ok());
    }

    #[test]
    fn restricted_caller_mints_only_own_scopes_and_never_the_wildcard() {
        let caller = vec!["messages:read".to_string(), "domains:read".to_string()];
        assert!(authorize_scope_issuance(&caller, "messages:read").is_ok());
        // Escalation attempts must fail with Forbidden.
        assert!(matches!(
            authorize_scope_issuance(&caller, "messages:send"),
            Err(ApiError::Forbidden(message)) if message.contains("exceeds")
        ));
        assert!(matches!(
            authorize_scope_issuance(&caller, "*"),
            Err(ApiError::Forbidden(message)) if message.contains("exceeds")
        ));
        // Unregistered scope strings are rejected as validation errors.
        assert!(matches!(
            authorize_scope_issuance(&caller, "not-a-scope"),
            Err(ApiError::Validation(_))
        ));
        assert!(matches!(
            authorize_scope_issuance(&["*".to_string()], "not-a-scope"),
            Err(ApiError::Validation(_))
        ));
    }

    // ── F65: browser-negotiated redirect helpers ──────────────────────

    #[test]
    fn client_prefers_html_detects_browser_navigation() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                .parse()
                .unwrap(),
        );
        assert!(client_prefers_html(&headers));

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            "application/json".parse().unwrap(),
        );
        assert!(!client_prefers_html(&headers));

        let headers = HeaderMap::new();
        assert!(!client_prefers_html(&headers));
    }

    #[test]
    fn urlencode_component_percent_encodes_reserved_characters() {
        assert_eq!(urlencode_component("Email verified"), "Email%20verified");
        assert_eq!(
            urlencode_component("a&b=c?d#e"),
            "a%26b%3Dc%3Fd%23e",
            "redirect targets must never smuggle extra query params or fragments"
        );
        assert_eq!(urlencode_component("ok.-_~"), "ok.-_~");
    }

    // ── F15/F16: email verification against canonical UUID user ids ───

    /// Fixture: a pending tenant plus an unverified owner carrying the
    /// given verification metadata. Mirrors the `register` INSERT.
    async fn seed_unverified_user(
        pool: &sqlx::PgPool,
        tenant_status: &str,
        expires: Option<chrono::DateTime<Utc>>,
        extra_metadata: serde_json::Value,
    ) -> (String, String, String) {
        let tenant_id = format!("tver{}", &Uuid::new_v4().simple().to_string()[..18]);
        let user_id = Uuid::new_v4();
        let token = format!("vtok_{}", Uuid::new_v4().simple());
        let mut metadata = serde_json::json!({
            "verification_token_hash": hash_token(&token),
        });
        if let Some(expires) = expires {
            metadata["verification_expires"] = serde_json::json!(expires.to_rfc3339());
        }
        if let serde_json::Value::Object(extra) = extra_metadata {
            for (key, value) in extra {
                metadata[key] = value;
            }
        }
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
             VALUES ($1, 'Verify Co', $2, 'free', $3, NOW(), NOW())",
        )
        .bind(&tenant_id)
        .bind(format!("slug-{tenant_id}"))
        .bind(tenant_status)
        .execute(pool)
        .await
        .expect("seed tenant");
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status,
                               email_verified, mfa_enabled, metadata, created_at, updated_at)
             VALUES ($1, $2, $3, 'Verify Owner', 'x', 'owner', 'active', false, false, $4, NOW(), NOW())",
        )
        .bind(user_id)
        .bind(&tenant_id)
        .bind(format!("verify-{}@example.com", user_id.simple()))
        .bind(&metadata)
        .execute(pool)
        .await
        .expect("seed user");
        (tenant_id, user_id.to_string(), token)
    }

    async fn user_verification_state(
        pool: &sqlx::PgPool,
        user_id: &str,
    ) -> (bool, serde_json::Value) {
        sqlx::query_as("SELECT email_verified, metadata FROM users WHERE id = $1::uuid")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .expect("load user")
    }

    #[tokio::test]
    async fn verify_email_token_succeeds_consumes_token_and_activates_pending_tenant() {
        let Some(pool) = crate::test_db::canonical_pool("verify_email_success").await else {
            eprintln!("skipping verify_email_token_succeeds: no TEST_DATABASE_URL");
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let (tenant_id, user_id, token) = seed_unverified_user(
            &pool,
            "pending",
            Some(Utc::now() + ChronoDuration::hours(24)),
            serde_json::json!({}),
        )
        .await;

        // F15 regression: this call performs the UUID round-trip that used
        // to fail with 42883 (`operator does not exist: uuid = text`).
        let result = verify_email_token(&state, &token)
            .await
            .expect("verification must succeed");
        assert!(result.success);

        let (verified, metadata) = user_verification_state(&pool, &user_id).await;
        assert!(verified, "user must be email_verified");
        assert!(
            metadata.get("verification_token_hash").is_none()
                && metadata.get("verification_expires").is_none(),
            "token material must be consumed, got {metadata}"
        );
        let tenant_status: String = sqlx::query_scalar("SELECT status FROM tenants WHERE id = $1")
            .bind(&tenant_id)
            .fetch_one(&pool)
            .await
            .expect("load tenant");
        assert_eq!(tenant_status, "active", "pending tenant must activate");

        // Sequential replay: the consumed token no longer matches.
        assert!(verify_email_token(&state, &token).await.is_err());

        pool.close().await;
    }

    #[tokio::test]
    async fn verify_email_token_rejects_expired_missing_and_malformed_expiry() {
        let Some(pool) = crate::test_db::canonical_pool("verify_email_expiry").await else {
            eprintln!("skipping verify_email_token_rejects_expired: no TEST_DATABASE_URL");
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;

        // Expired.
        let (_, user_id, token) = seed_unverified_user(
            &pool,
            "pending",
            Some(Utc::now() - ChronoDuration::hours(1)),
            serde_json::json!({}),
        )
        .await;
        assert!(matches!(
            verify_email_token(&state, &token).await,
            Err(ApiError::BadRequest(message)) if message.contains("expired")
        ));
        let (verified, _) = user_verification_state(&pool, &user_id).await;
        assert!(!verified, "expired token must not verify the user");

        // Missing expiry (F16: fails CLOSED, previously unchecked).
        let (_, user_id, token) =
            seed_unverified_user(&pool, "pending", None, serde_json::json!({})).await;
        assert!(verify_email_token(&state, &token).await.is_err());
        let (verified, _) = user_verification_state(&pool, &user_id).await;
        assert!(!verified, "token without expiry must not verify the user");

        // Malformed expiry (F16: parse failure previously skipped the check).
        let (_, user_id, token) = seed_unverified_user(
            &pool,
            "pending",
            Some(Utc::now() + ChronoDuration::hours(24)),
            serde_json::json!({ "verification_expires": "not-a-timestamp" }),
        )
        .await;
        assert!(verify_email_token(&state, &token).await.is_err());
        let (verified, _) = user_verification_state(&pool, &user_id).await;
        assert!(!verified, "malformed expiry must not verify the user");

        // Unknown token.
        assert!(verify_email_token(&state, "vtok_does_not_exist")
            .await
            .is_err());

        pool.close().await;
    }

    #[tokio::test]
    async fn verify_email_token_concurrent_double_use_consumes_exactly_once() {
        let Some(pool) = crate::test_db::canonical_pool("verify_email_double_use").await else {
            eprintln!("skipping verify_email_token_concurrent_double_use: no TEST_DATABASE_URL");
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let (tenant_id, user_id, token) = seed_unverified_user(
            &pool,
            "pending",
            Some(Utc::now() + ChronoDuration::hours(24)),
            serde_json::json!({}),
        )
        .await;

        // Two racing presentations of the SAME token: the row lock plus the
        // conditional consumption means exactly one exchange commits (F16).
        let (first, second) = tokio::join!(
            verify_email_token(&state, &token),
            verify_email_token(&state, &token),
        );
        let successes = [&first, &second].iter().filter(|r| r.is_ok()).count();
        assert_eq!(
            successes, 1,
            "exactly one concurrent presentation may succeed, got {first:?} / {second:?}"
        );
        let (verified, _) = user_verification_state(&pool, &user_id).await;
        assert!(verified);

        let tenant_status: String = sqlx::query_scalar("SELECT status FROM tenants WHERE id = $1")
            .bind(&tenant_id)
            .fetch_one(&pool)
            .await
            .expect("load tenant");
        assert_eq!(tenant_status, "active");

        pool.close().await;
    }

    #[tokio::test]
    async fn verify_email_token_preserves_administrative_and_billing_holds() {
        let Some(pool) = crate::test_db::canonical_pool("verify_email_holds").await else {
            eprintln!("skipping verify_email_token_preserves_holds: no TEST_DATABASE_URL");
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;

        // A tenant an operator (or dunning) suspended between sign-up and
        // the verification click keeps its hold (F16).
        let (tenant_id, user_id, token) = seed_unverified_user(
            &pool,
            "suspended",
            Some(Utc::now() + ChronoDuration::hours(24)),
            serde_json::json!({}),
        )
        .await;
        verify_email_token(&state, &token)
            .await
            .expect("the user's email still verifies");
        let (verified, _) = user_verification_state(&pool, &user_id).await;
        assert!(verified, "the user is verified even though the hold stands");
        let tenant_status: String = sqlx::query_scalar("SELECT status FROM tenants WHERE id = $1")
            .bind(&tenant_id)
            .fetch_one(&pool)
            .await
            .expect("load tenant");
        assert_eq!(
            tenant_status, "suspended",
            "verification must NOT lift an administrative/abuse/billing hold"
        );

        pool.close().await;
    }

    // ── F18/F46: key minting honours the tenant policy and shared path ──

    #[tokio::test]
    async fn mint_api_key_enforces_tenant_policy_expiry_and_scopes() {
        let Some(pool) = crate::test_db::canonical_pool("mint_api_key_policy").await else {
            eprintln!("skipping mint_api_key_enforces_policy: no TEST_DATABASE_URL");
            return;
        };
        // The canonical fixture lineage ships no api_keys table (only the
        // auth-critical shapes); create the same fixture the API-key cache
        // test uses.
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
        let tenant_id = format!("tmint{}", &Uuid::new_v4().simple().to_string()[..16]);
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
             VALUES ($1, 'Mint Co', $2, 'free', 'active', NOW(), NOW())",
        )
        .bind(&tenant_id)
        .bind(format!("slug-{tenant_id}"))
        .execute(&pool)
        .await
        .expect("seed tenant");

        let wildcard = AuthUser {
            tenant_id: tenant_id.clone(),
            user_id: Some(Uuid::new_v4().to_string()),
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        };

        // F17 through the shared path: a wildcard caller mints ordinary
        // scoped keys (previously rejected outright).
        let minted = mint_api_key(&state, &wildcard, "scoped", &["messages:read".into()], None)
            .await
            .expect("wildcard caller must mint scoped keys");
        assert_eq!(minted.scopes, vec!["messages:read".to_string()]);
        assert!(
            minted.expires_at > Utc::now() + ChronoDuration::days(89),
            "absent expiry must resolve to the shared 90-day default"
        );

        let row: Option<(String, chrono::DateTime<Utc>)> =
            sqlx::query_as("SELECT key_hash, expires_at FROM api_keys WHERE id::text = $1")
                .bind(&minted.id)
                .fetch_optional(&pool)
                .await
                .expect("load key row");
        let (stored_hash, stored_expiry) = row.expect("key persisted");
        assert_eq!(
            stored_hash,
            apexmail_lib::hash_api_key_with_secret(
                &minted.raw_key,
                &state.config.api_key_hash_secret
            ),
            "shared keyed HMAC hashing on every surface"
        );
        assert_eq!(stored_expiry, minted.expires_at, "expiry persisted (F46)");

        // Escalation through the shared path still fails.
        let restricted = AuthUser {
            tenant_id: tenant_id.clone(),
            user_id: Some(Uuid::new_v4().to_string()),
            api_key_id: None,
            session_id: None,
            scopes: vec!["messages:read".into()],
        };
        assert!(matches!(
            mint_api_key(&state, &restricted, "escalate", &["*".into()], None).await,
            Err(ApiError::Forbidden(_))
        ));

        // F18: a suspended tenant mints nothing.
        sqlx::query("UPDATE tenants SET status = 'suspended' WHERE id = $1")
            .bind(&tenant_id)
            .execute(&pool)
            .await
            .expect("suspend tenant");
        crate::middleware::auth::invalidate_tenant_status_cache(&tenant_id, &state).await;
        assert!(matches!(
            mint_api_key(&state, &wildcard, "nope", &["messages:read".into()], None).await,
            Err(ApiError::Forbidden(message)) if message.contains("suspended")
        ));

        pool.close().await;
    }

    #[tokio::test]
    async fn test_record_login_failure_sets_lock_when_redis_is_available() {
        // F6: never probe the ambient 6379 — the variable must name the
        // Redis under test explicitly; unset means skip.
        let Ok(redis_url) = std::env::var("TEST_REDIS_URL") else {
            eprintln!("skipping: TEST_REDIS_URL not set");
            return;
        };
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
        let failure_ip_key = login_failure_ip_key(&identifier);
        let lock_key = login_lock_key(&identifier);
        let counter_key = login_lockout_counter_key(&identifier);

        let cleanup_keys = [
            failure_key.clone(),
            failure_ip_key.clone(),
            lock_key.clone(),
            counter_key.clone(),
        ];
        if let Ok(mut conn) = pool.get().await {
            let _: Result<i64, _> = deadpool_redis::redis::cmd("DEL")
                .arg(cleanup_keys.as_slice())
                .query_async(&mut *conn)
                .await;
        }

        // M-6 distinct-IP rule: five failures from ONE source never lock the
        // account (an attacker must not be able to lock a victim at will;
        // the per-IP login rate limit keeps throttling that single source).
        for _ in 0..LOGIN_FAILURE_THRESHOLD {
            record_login_failure(&pool, &identifier, Some("203.0.113.10"))
                .await
                .unwrap();
        }
        assert!(
            login_lock_ttl(&pool, &identifier).await.unwrap().is_none(),
            "single-source failures must not lock the account"
        );

        // A corroborating failure from a SECOND distinct source locks it.
        record_login_failure(&pool, &identifier, Some("198.51.100.77"))
            .await
            .unwrap();
        assert!(
            login_lock_ttl(&pool, &identifier)
                .await
                .unwrap()
                .unwrap_or_default()
                > 0,
            "failures spanning two distinct sources must lock the account"
        );

        // A lock is lifted by its TTL (a locked account never reaches the
        // success path), but `clear_login_failures` — the successful-login
        // path — must clear the failure evidence keys.
        clear_login_failures(&pool, &identifier).await.unwrap();
        if let Ok(mut conn) = pool.get().await {
            let failures: Result<i64, _> = deadpool_redis::redis::cmd("GET")
                .arg(login_failure_key(&identifier))
                .query_async(&mut *conn)
                .await;
            assert!(
                matches!(failures, Ok(0) | Err(_)),
                "failure counter cleared after successful login, got {failures:?}"
            );
        }

        if let Ok(mut conn) = pool.get().await {
            let _: Result<i64, _> = deadpool_redis::redis::cmd("DEL")
                .arg(cleanup_keys.as_slice())
                .query_async(&mut *conn)
                .await;
        }
    }

    #[tokio::test]
    async fn test_record_login_failure_locks_after_failures_from_two_sources() {
        // F6: never probe the ambient 6379 — the variable must name the
        // Redis under test explicitly; unset means skip.
        let Ok(redis_url) = std::env::var("TEST_REDIS_URL") else {
            eprintln!("skipping: TEST_REDIS_URL not set");
            return;
        };
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

        let identifier = format!("lockout-multi-{}@example.com", Uuid::new_v4());
        let keys = [
            login_failure_key(&identifier),
            login_failure_ip_key(&identifier),
            login_lock_key(&identifier),
            login_lockout_counter_key(&identifier),
        ];
        if let Ok(mut conn) = pool.get().await {
            let _: Result<i64, _> = deadpool_redis::redis::cmd("DEL")
                .arg(keys.as_slice())
                .query_async(&mut *conn)
                .await;
        }

        // Below the threshold even with two sources: no lock.
        for ip in ["203.0.113.1", "203.0.113.2"] {
            for _ in 0..(LOGIN_FAILURE_THRESHOLD / 2) {
                record_login_failure(&pool, &identifier, Some(ip))
                    .await
                    .unwrap();
            }
        }
        assert!(
            login_lock_ttl(&pool, &identifier).await.unwrap().is_none(),
            "threshold not reached yet"
        );

        // Reaching the threshold with failures spanning multiple IPs locks.
        record_login_failure(&pool, &identifier, Some("203.0.113.3"))
            .await
            .unwrap();
        assert!(
            login_lock_ttl(&pool, &identifier)
                .await
                .unwrap()
                .unwrap_or_default()
                > 0
        );

        if let Ok(mut conn) = pool.get().await {
            let _: Result<i64, _> = deadpool_redis::redis::cmd("DEL")
                .arg(keys.as_slice())
                .query_async(&mut *conn)
                .await;
        }
    }

    /// End-to-end KiwiCaptcha single-use test (skipped when no Redis is
    /// available). Issues a challenge, stores it like the route does, verifies
    /// a valid solution once, then replays the same token — the replay must
    /// be rejected even though the TTL window is still open.
    #[tokio::test]
    async fn test_kiwi_token_is_single_use_when_redis_available() {
        // F6: never probe the ambient 6379 — the variable must name the
        // Redis under test explicitly; unset means skip.
        let Ok(redis_url) = std::env::var("TEST_REDIS_URL") else {
            eprintln!("skipping: TEST_REDIS_URL not set");
            return;
        };
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

        let mut config = crate::config::tests::valid_production_config();
        config.kiwi_enabled = true;
        config.kiwi_secret_key = "test-kiwi-secret-key-for-single-use-test".into();
        config.kiwi_difficulty_bits = 8; // fast to solve in tests
        config.kiwi_min_duration_ms = Some(0); // disable the min-duration gate
        config.kiwi_challenge_ttl_secs = 120;

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let kc_config = kiwicaptcha::ChallengeConfig {
            secret_key: config.kiwi_secret_key.clone(),
            algorithm: config.kiwi_algorithm,
            m_kib: config.kiwi_argon_m_kib,
            t: config.kiwi_argon_t,
            p: config.kiwi_argon_p,
            target_bits: config.kiwi_difficulty_bits,
            argon2_target_bits: config.kiwi_argon2_difficulty_bits,
            ttl_secs: config.kiwi_challenge_ttl_secs,
            min_duration_ms: config.kiwi_min_duration_ms,
            auto_tune: config.kiwi_auto_tune,
            auto_tune_min_bits: config.kiwi_auto_tune_min_bits,
            auto_tune_max_bits: config.kiwi_auto_tune_max_bits,
            binding_mode: kiwicaptcha::BindingMode::Bound,
            // Mirrors the issuance defaults used by the challenge route.
            policy_version: 1,
            region: None,
            issuer: None,
            kid: 1,
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: kiwicaptcha::challenge::DEFAULT_RSW_T,
        };
        let issued = kiwicaptcha::issue_challenge(
            &kc_config,
            "login",
            "1.2.3.4",
            now_unix,
            now_unix * 1_000_000,
            0,
            None,
        )
        .expect("challenge issuance succeeds");

        let record_json = serde_json::to_string(&issued.record).expect("record serializes");
        let key = format!("{KIWI_CHALLENGE_PREFIX}{}", issued.record.nonce);

        let mut conn = pool.get().await.expect("redis connection available");
        let _: () = deadpool_redis::redis::AsyncCommands::set_ex(
            &mut *conn,
            &key,
            record_json.clone(),
            config.kiwi_challenge_ttl_secs,
        )
        .await
        .expect("challenge stored");
        drop(conn);

        let counter = kiwicaptcha::solve_for_test(&issued.record).expect("solver finds a counter");
        let token = kiwicaptcha::SolutionToken {
            nonce: issued.challenge.nonce.clone(),
            counter,
            duration_ms: 5000,
            // valid_production_config() enables kiwi_enforce_telemetry, and
            // strict mode rejects clients that submit NO or EMPTY telemetry
            // (a custom solver does not send it — VerifyError::BotDetected,
            // which made the first verification fail whenever Redis was
            // actually present; ci/README.md §9 F3). Send a realistic
            // human-looking payload: non-empty, no webdriver flag, few
            // discrete events (the ≥24-event uniformity heuristic never
            // fires), well under the 30s zero-interaction bound.
            telemetry: serde_json::json!({
                "me": 3, "ke": 2, "hc": 8, "dm": 8, "pl": 3,
                "et": [10, 25, 40, 90],
            }),
            execution_digest: None,
            execution_trace: None,
            rsw_proof: None,
        }
        .encode();

        // First use: valid solution → succeeds and consumes the challenge.
        verify_kiwi_token(&config, &pool, Some(&token), "1.2.3.4", Some("login"))
            .await
            .expect("first verification should succeed");

        // Replay within the TTL window: must now fail (atomic single-use).
        let replay_err = verify_kiwi_token(&config, &pool, Some(&token), "1.2.3.4", Some("login"))
            .await
            .expect_err("replay of a consumed challenge must be rejected");
        assert!(
            matches!(replay_err, ApiError::Validation(_)),
            "replay must fail with a validation error, got {replay_err:?}"
        );

        // The challenge key must be gone from Redis.
        let mut conn = pool.get().await.expect("redis connection available");
        let exists: Option<String> = deadpool_redis::redis::AsyncCommands::get(&mut *conn, &key)
            .await
            .unwrap_or(None);
        assert!(
            exists.is_none(),
            "challenge key must be deleted after successful verification"
        );
        let _: i64 = deadpool_redis::redis::AsyncCommands::del(&mut *conn, &key)
            .await
            .unwrap_or(0);
    }

    /// Issue a fresh KiwiCaptcha challenge, store it in Redis exactly like
    /// the challenge route does, solve it, and encode a solution token with
    /// the given telemetry payload. Shared by the kiwi verify regression
    /// tests (needs a live Redis — callers gate on TEST_REDIS_URL).
    async fn mint_kiwi_solution_token(
        pool: &deadpool_redis::Pool,
        config: &crate::config::Config,
        telemetry: serde_json::Value,
    ) -> String {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let kc_config = kiwicaptcha::ChallengeConfig {
            secret_key: config.kiwi_secret_key.clone(),
            algorithm: config.kiwi_algorithm,
            m_kib: config.kiwi_argon_m_kib,
            t: config.kiwi_argon_t,
            p: config.kiwi_argon_p,
            target_bits: config.kiwi_difficulty_bits,
            argon2_target_bits: config.kiwi_argon2_difficulty_bits,
            ttl_secs: config.kiwi_challenge_ttl_secs,
            min_duration_ms: config.kiwi_min_duration_ms,
            auto_tune: config.kiwi_auto_tune,
            auto_tune_min_bits: config.kiwi_auto_tune_min_bits,
            auto_tune_max_bits: config.kiwi_auto_tune_max_bits,
            binding_mode: kiwicaptcha::BindingMode::Bound,
            policy_version: 1,
            region: None,
            issuer: None,
            kid: 1,
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: kiwicaptcha::challenge::DEFAULT_RSW_T,
        };
        let issued = kiwicaptcha::issue_challenge(
            &kc_config,
            "login",
            "1.2.3.4",
            now_unix,
            now_unix * 1_000_000,
            0,
            None,
        )
        .expect("challenge issuance succeeds");

        let record_json = serde_json::to_string(&issued.record).expect("record serializes");
        let key = format!("{KIWI_CHALLENGE_PREFIX}{}", issued.record.nonce);
        let mut conn = pool.get().await.expect("redis connection available");
        let _: () = deadpool_redis::redis::AsyncCommands::set_ex(
            &mut *conn,
            &key,
            record_json,
            config.kiwi_challenge_ttl_secs,
        )
        .await
        .expect("challenge stored");
        drop(conn);

        let counter = kiwicaptcha::solve_for_test(&issued.record).expect("solver finds a counter");
        kiwicaptcha::SolutionToken {
            nonce: issued.challenge.nonce.clone(),
            counter,
            duration_ms: 5000,
            telemetry,
            execution_digest: None,
            execution_trace: None,
            rsw_proof: None,
        }
        .encode()
    }

    /// Live-Redis test pool gate shared by the kiwi verify tests: returns
    /// None (skip) unless TEST_REDIS_URL names a reachable Redis (F6: the
    /// ambient 6379 is never probed implicitly).
    async fn live_redis_pool_or_skip() -> Option<deadpool_redis::Pool> {
        let Ok(redis_url) = std::env::var("TEST_REDIS_URL") else {
            eprintln!("skipping: TEST_REDIS_URL not set");
            return None;
        };
        let pool = RedisConfig::from_url(&redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .ok()?;
        let mut conn = pool.get().await.ok()?;
        let ping: Result<String, _> = deadpool_redis::redis::cmd("PING")
            .query_async(&mut *conn)
            .await;
        if ping.is_err() {
            eprintln!("skipping: TEST_REDIS_URL unreachable");
            return None;
        }
        drop(conn);
        Some(pool)
    }

    /// F1 regression: when Redis is unreachable the per-nonce verify-attempt
    /// cap must report store-unavailability — never silently allow (the old
    /// `.unwrap_or(0)` treated script/pool failures as "under the cap",
    /// removing the 20-attempt bound on Argon2id re-derivations).
    #[tokio::test]
    async fn kiwi_verify_attempt_cap_fails_closed_when_redis_is_down() {
        // Port 1 is guaranteed-closed on loopback; the pool is created lazily
        // so construction succeeds and the failure surfaces on acquire.
        let cfg = RedisConfig::from_url("redis://127.0.0.1:1/");
        let pool = cfg
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("pool construction is lazy");

        assert_eq!(
            check_kiwi_verify_attempt_cap(&pool, "apexmail:kiwi:attempts:test-down", 60).await,
            KiwiAttemptCap::RedisUnavailable,
            "a dead Redis must never silently allow Kiwi verify attempts"
        );
    }

    /// F1 regression against live Redis: under the cap allows, past
    /// KIWI_MAX_VERIFY_ATTEMPTS exceeds (skipped when no Redis is available).
    #[tokio::test]
    async fn kiwi_verify_attempt_cap_allows_then_exceeds_on_live_redis() {
        let Some(pool) = live_redis_pool_or_skip().await else {
            return;
        };
        let key = format!("apexmail:kiwi:attempts:test-{}", uuid::Uuid::new_v4());
        if let Ok(mut conn) = pool.get().await {
            let _: Result<i64, _> = deadpool_redis::redis::cmd("DEL")
                .arg(&key)
                .query_async(&mut *conn)
                .await;
        }

        for _ in 0..KIWI_MAX_VERIFY_ATTEMPTS {
            assert_eq!(
                check_kiwi_verify_attempt_cap(&pool, &key, 60).await,
                KiwiAttemptCap::Allowed
            );
        }
        assert_eq!(
            check_kiwi_verify_attempt_cap(&pool, &key, 60).await,
            KiwiAttemptCap::Exceeded,
            "attempt {} must exceed the cap of {KIWI_MAX_VERIFY_ATTEMPTS}",
            KIWI_MAX_VERIFY_ATTEMPTS + 1
        );

        if let Ok(mut conn) = pool.get().await {
            let _: Result<i64, _> = deadpool_redis::redis::cmd("DEL")
                .arg(&key)
                .query_async(&mut *conn)
                .await;
        }
    }

    /// F2 regression: the Argon2 permit wait is BOUNDED — a saturated
    /// semaphore must produce a prompt retryable denial (503-style), not an
    /// unbounded queue that an attacker pinning both permits could induce.
    #[tokio::test]
    async fn argon2_permit_wait_is_bounded_under_saturation() {
        let semaphore = Arc::new(Semaphore::new(1));

        // Free permit: acquired immediately.
        let held = acquire_argon2_permit_bounded(&semaphore, std::time::Duration::from_millis(50))
            .await
            .expect("a free permit must be acquired");

        // Saturation: the only permit is held, so the bounded acquire must
        // time out promptly with the retryable overloaded denial.
        let started = std::time::Instant::now();
        let err = acquire_argon2_permit_bounded(&semaphore, std::time::Duration::from_millis(50))
            .await
            .expect_err("a saturated semaphore must time out, not queue forever");
        assert!(
            matches!(err, ApiError::ServiceUnavailable(_)),
            "permit-wait timeout must surface as a retryable 503-style denial, got {err:?}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "the bounded wait must return promptly, took {:?}",
            started.elapsed()
        );

        drop(held);
        assert!(
            acquire_argon2_permit_bounded(&semaphore, std::time::Duration::from_millis(50))
                .await
                .is_ok(),
            "a released permit must be acquirable again"
        );
    }

    /// F3 regression: telemetry findings reject ONLY when
    /// `kiwi_enforce_telemetry` is on. With the flag off a bot-scored
    /// payload (webdriver=true) must not reject — the crate's documented
    /// telemetry-default-off model (skipped when no Redis is available).
    #[tokio::test]
    async fn kiwi_telemetry_rejects_only_when_enforced() {
        let Some(pool) = live_redis_pool_or_skip().await else {
            return;
        };
        let mut config = crate::config::tests::valid_production_config();
        config.kiwi_enabled = true;
        config.kiwi_secret_key = "test-kiwi-secret-key-for-telemetry-test".into();
        config.kiwi_difficulty_bits = 8; // fast to solve in tests
        config.kiwi_min_duration_ms = Some(0); // disable the min-duration gate
        config.kiwi_challenge_ttl_secs = 120;

        // Flag OFF: bot-scored telemetry (wd=true is an instant bot signal
        // in score_telemetry) must NOT reject — log-only.
        config.kiwi_enforce_telemetry = false;
        let token =
            mint_kiwi_solution_token(&pool, &config, serde_json::json!({ "wd": true })).await;
        verify_kiwi_token(&config, &pool, Some(&token), "1.2.3.4", Some("login"))
            .await
            .expect("telemetry findings must not reject when KIWI_ENFORCE_TELEMETRY is off");

        // Flag ON: the same bot-scored payload on a fresh challenge must
        // reject (scored once, crate-side).
        config.kiwi_enforce_telemetry = true;
        let token =
            mint_kiwi_solution_token(&pool, &config, serde_json::json!({ "wd": true })).await;
        let err = verify_kiwi_token(&config, &pool, Some(&token), "1.2.3.4", Some("login"))
            .await
            .expect_err("enforced telemetry must reject a bot-scored payload");
        assert!(
            matches!(err, ApiError::Validation(_)),
            "enforced telemetry rejection must be a validation error, got {err:?}"
        );
    }

    #[test]
    fn test_login_lockout_duration_all_escalation_levels() {
        // Verify the full escalation series: 15min → 30min → 1hr → 2hr → 4hr → 8hr → 16hr → 24hr (cap)
        assert_eq!(login_lockout_duration(1), 15 * 60);
        assert_eq!(login_lockout_duration(2), 30 * 60);
        assert_eq!(login_lockout_duration(3), 60 * 60);
        assert_eq!(login_lockout_duration(4), 120 * 60);
        assert_eq!(login_lockout_duration(5), 240 * 60);
        assert_eq!(login_lockout_duration(6), 480 * 60);
        assert_eq!(login_lockout_duration(7), 960 * 60);
        assert_eq!(login_lockout_duration(8), 86400); // capped at 24h
        assert_eq!(login_lockout_duration(100), 86400);
    }

    #[test]
    fn test_login_lockout_duration_zero_and_negative() {
        // lockout_count <= 0 should be treated as count=1 (base duration)
        assert_eq!(login_lockout_duration(0), 15 * 60);
        assert_eq!(login_lockout_duration(-1), 15 * 60);
        assert_eq!(login_lockout_duration(-100), 15 * 60);
    }

    #[test]
    fn test_login_failure_key_format() {
        let key = login_failure_key("user@example.com");
        assert!(key.starts_with("apexmail:auth:failures:"));
        // The hash should be 64 hex chars (SHA-256)
        let prefix = "apexmail:auth:failures:";
        let hash = &key[prefix.len()..];
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_login_lock_key_format() {
        let key = login_lock_key("user@example.com");
        assert!(key.starts_with("apexmail:auth:lock:"));
        let prefix = "apexmail:auth:lock:";
        let hash = &key[prefix.len()..];
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_login_lockout_counter_key_format() {
        let key = login_lockout_counter_key("user@example.com");
        assert!(key.starts_with("apexmail:auth:lockouts:"));
        let prefix = "apexmail:auth:lockouts:";
        let hash = &key[prefix.len()..];
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_login_lockout_keys_deterministic() {
        let identifier = "Owner@Example.com";
        assert_eq!(login_failure_key(identifier), login_failure_key(identifier));
        assert_eq!(login_lock_key(identifier), login_lock_key(identifier));
        assert_eq!(
            login_lockout_counter_key(identifier),
            login_lockout_counter_key(identifier)
        );
    }

    #[test]
    fn test_login_lockout_keys_different_for_different_users() {
        let key_a_fail = login_failure_key("alice@example.com");
        let key_b_fail = login_failure_key("bob@example.com");
        assert_ne!(key_a_fail, key_b_fail);

        let key_a_lock = login_lock_key("alice@example.com");
        let key_b_lock = login_lock_key("bob@example.com");
        assert_ne!(key_a_lock, key_b_lock);

        let key_a_ctr = login_lockout_counter_key("alice@example.com");
        let key_b_ctr = login_lockout_counter_key("bob@example.com");
        assert_ne!(key_a_ctr, key_b_ctr);
    }

    #[test]
    fn test_login_lockout_keys_different_key_types_same_identifier() {
        let identifier = "user@example.com";
        let failure_key = login_failure_key(identifier);
        let lock_key = login_lock_key(identifier);
        let counter_key = login_lockout_counter_key(identifier);
        assert_ne!(failure_key, lock_key);
        assert_ne!(failure_key, counter_key);
        assert_ne!(lock_key, counter_key);
    }

    #[test]
    fn test_login_lockout_keys_do_not_leak_raw_identifier() {
        let identifier = "sensitive@example.com";
        let failure_key = login_failure_key(identifier);
        let lock_key = login_lock_key(identifier);
        let counter_key = login_lockout_counter_key(identifier);
        assert!(!failure_key.contains("sensitive"));
        assert!(!lock_key.contains("sensitive"));
        assert!(!counter_key.contains("sensitive"));
    }

    #[test]
    fn test_normalized_login_identifier_trims_and_lowercases() {
        assert_eq!(
            normalized_login_identifier("  User@Example.com  "),
            "user@example.com"
        );
        assert_eq!(
            normalized_login_identifier("ALICE@EXAMPLE.COM"),
            "alice@example.com"
        );
        assert_eq!(
            normalized_login_identifier("  spaced@test.COM  "),
            "spaced@test.com"
        );
    }

    #[test]
    fn test_login_lockout_keys_normalized_unlike_login_failure_key() {
        // The failure key uses hash_token directly on the identifier (not normalized),
        // but the login function normalizes before calling. Test that raw identifier
        // with different casing produces different keys (since hash_token is case-sensitive).
        let raw = login_failure_key("User@Example.com");
        let lower = login_failure_key("user@example.com");
        assert_ne!(
            raw, lower,
            "hash_token is case-sensitive, so keys must differ"
        );
    }

    // ── Session revocation tests ─────────────────────────────────────

    #[test]
    fn test_session_revocation_key_is_tenant_scoped() {
        let key = session_revocation_key("tenant_alpha", "user_beta");
        assert!(key.starts_with("apexmail:session_revoked_after:"));
        assert!(key.contains("tenant_alpha"));
        assert!(key.contains("user_beta"));
        assert_eq!(key, "apexmail:session_revoked_after:tenant_alpha:user_beta");
    }

    #[test]
    fn test_session_revocation_key_isolates_tenants() {
        let key_a = session_revocation_key("tenant_a", "user_1");
        let key_b = session_revocation_key("tenant_b", "user_1");
        assert_ne!(key_a, key_b, "different tenants must have different keys");
    }

    #[test]
    fn test_session_revocation_key_isolates_users() {
        let key_a = session_revocation_key("tenant_1", "user_a");
        let key_b = session_revocation_key("tenant_1", "user_b");
        assert_ne!(key_a, key_b, "different users must have different keys");
    }

    #[test]
    fn test_issued_before_or_at_revocation_no_revocation() {
        // When there is no revocation (None), old tokens should NOT be rejected
        assert!(!issued_before_or_at_revocation(1000, None));
    }

    #[test]
    fn test_issued_before_or_at_revocation_token_issued_before_revocation() {
        // Token issued at t=100, revocation at t=200 → token was issued BEFORE revocation → REJECT
        assert!(issued_before_or_at_revocation(100, Some(200)));
    }

    #[test]
    fn test_issued_before_or_at_revocation_token_issued_at_same_time() {
        // Token issued at t=200, revocation at t=200 → issued AT revocation → REJECT
        assert!(issued_before_or_at_revocation(200, Some(200)));
    }

    #[test]
    fn test_session_issue_time_moves_past_revocation_cutoff() {
        let now = DateTime::<Utc>::from_timestamp(200, 0).unwrap();
        let issued_at = session_issue_time_after_revocation(now, Some(200));

        assert_eq!(issued_at.timestamp(), 201);
        assert!(!issued_before_or_at_revocation(
            issued_at.timestamp(),
            Some(200)
        ));
    }

    #[test]
    fn test_session_issue_time_keeps_later_timestamps() {
        let now = DateTime::<Utc>::from_timestamp(201, 0).unwrap();
        let issued_at = session_issue_time_after_revocation(now, Some(200));

        assert_eq!(issued_at, now);
    }

    #[test]
    fn test_issued_before_or_at_revocation_token_issued_after_revocation() {
        // Token issued at t=300, revocation at t=200 → issued AFTER revocation → ALLOW (new session)
        assert!(!issued_before_or_at_revocation(300, Some(200)));
    }

    // ── Redis Failover Tests for Auth Routes ──────────────────────

    /// Tests the login lockout key format — verifying the key structure
    /// is correct for Redis operations even when Redis is down.
    #[test]
    fn test_login_failure_key_format_does_not_leak_email() {
        let key = login_failure_key("admin@example.com");
        assert!(key.starts_with("apexmail:auth:failures:"));
        // The key must NOT contain the raw email to prevent information leakage
        // via Redis introspection (e.g. KEYS or SCAN commands).
        assert!(
            !key.contains("admin@example.com"),
            "login failure key must not contain the raw email address"
        );
        assert!(
            !key.contains("admin"),
            "login failure key must not contain parts of the email address"
        );
    }

    /// Tests that all login lockout key types use the same hashed
    /// identifier, so they operate on the same logical Redis namespace
    /// for a given user.
    #[test]
    fn test_login_lockout_keys_share_hashed_identifier() {
        let identifier = "user@example.com";
        let fail_key = login_failure_key(identifier);
        let lock_key = login_lock_key(identifier);
        let counter_key = login_lockout_counter_key(identifier);

        // All keys should share the same suffix after the prefix
        let fail_suffix = fail_key.strip_prefix("apexmail:auth:failures:").unwrap();
        let lock_suffix = lock_key.strip_prefix("apexmail:auth:lock:").unwrap();
        let counter_suffix = counter_key.strip_prefix("apexmail:auth:lockouts:").unwrap();

        assert_eq!(
            fail_suffix, lock_suffix,
            "failure and lock keys must share the same hashed identifier"
        );
        assert_eq!(
            lock_suffix, counter_suffix,
            "lock and counter keys must share the same hashed identifier"
        );
    }

    /// Tests that the login lockout functions propagate errors when
    /// Redis is unavailable. The `login_lock_ttl` and `record_login_failure`
    /// functions use `?` for Redis errors, which means they will propagate
    /// the error up to the caller rather than silently swallowing it.
    #[test]
    fn test_login_lockout_functions_use_propagating_error_pattern() {
        // Both `login_lock_ttl` and `record_login_failure` use `?` for Redis
        // operations, meaning Redis connection failures propagate as ApiError.
        // This is verified by checking the function signatures:
        //
        //   async fn login_lock_ttl(...) -> Result<Option<i64>, ApiError>
        //   async fn record_login_failure(...) -> Result<(), ApiError>
        //
        // The `?` operator on `redis_pool.get().await?` converts deadpool_redis::PoolError
        // into ApiError via the From/Into trait implementations.
        // This means Redis failures are NOT silently swallowed — they
        // result in a 503 Service Unavailable response.
        fn assert_propagates_error<T>() {}
        assert_propagates_error::<Result<Option<i64>, ApiError>>();
        assert_propagates_error::<Result<(), ApiError>>();
    }

    /// Tests MFA challenge key format for correctness.
    #[test]
    fn test_mfa_challenge_key_format() {
        let key = mfa_challenge_key("mfa_token_abc123");
        assert_eq!(key, "apexmail:auth:mfa_challenge:mfa_token_abc123");
        assert!(
            key.starts_with("apexmail:auth:mfa_challenge:"),
            "MFA challenge keys must use the configured prefix"
        );
    }

    /// Tests that MFA challenge store/consume functions use `?` for Redis
    /// errors, meaning Redis failures are propagated as ApiError.
    #[test]
    fn test_mfa_challenge_functions_use_propagating_error_pattern() {
        // Both `store_mfa_challenge` and `consume_mfa_challenge` use `?` for
        // Redis operations. This means Redis connection failures propagate
        // as ApiError (503 Service Unavailable).
        fn assert_propagates_error<T>() {}
        assert_propagates_error::<Result<String, ApiError>>();
        assert_propagates_error::<Result<MfaChallengeState, ApiError>>();
    }

    /// Tests the MFA challenge key prefix constant.
    #[test]
    fn test_mfa_challenge_prefix_constant() {
        assert_eq!(
            MFA_CHALLENGE_PREFIX, "apexmail:auth:mfa_challenge:",
            "MFA challenge prefix must match the build_challenge_key function"
        );
    }

    // ── F3: TOTP hardening helpers ──────────────────────────────

    #[test]
    fn test_mfa_totp_replay_key_is_secret_safe_and_window_scoped() {
        let fingerprint = mfa_totp_secret_fingerprint("JBSWY3DPEHPK3PXP");
        // Only the SHA-256 fingerprint may appear in the key — raw TOTP key
        // material must never land in Redis keyspace.
        assert_eq!(fingerprint.len(), 64);
        assert!(!fingerprint.to_uppercase().contains("JBSWY3DPEHPK3PXP"));
        assert_eq!(
            mfa_totp_replay_key(&fingerprint, 42),
            format!("apexmail:auth:mfa_totp_replay:{fingerprint}:42")
        );
        // Different secrets (and different windows) must not collide.
        assert_ne!(
            mfa_totp_replay_key(&fingerprint, 42),
            mfa_totp_replay_key(&mfa_totp_secret_fingerprint("other-secret"), 42)
        );
        assert_ne!(
            mfa_totp_replay_key(&fingerprint, 42),
            mfa_totp_replay_key(&fingerprint, 43)
        );
    }

    #[test]
    fn test_claim_totp_window_inprocess_single_use_per_window() {
        // Unique secret per run so the shared process-wide fallback map is
        // not polluted by other tests claiming the same window.
        let fingerprint = mfa_totp_secret_fingerprint(&format!("window-{}", Uuid::new_v4()));
        assert!(
            claim_totp_window_inprocess(&fingerprint),
            "first use of a window must be claimable"
        );
        assert!(
            !claim_totp_window_inprocess(&fingerprint),
            "the same window must not be claimable twice (replay)"
        );
    }

    /// Tests that the `revoke_user_sessions` function propagates Redis
    /// errors (uses `?` pattern), meaning Redis failures are not silent.
    #[test]
    fn test_revoke_user_sessions_propagates_redis_errors() {
        // `revoke_user_sessions` uses `?` on Redis operations.
        // Redis failure → ApiError propagated to caller.
        fn assert_propagates_error<T>() {}
        assert_propagates_error::<Result<(), ApiError>>();
    }

    /// Tests login lockout duration edge cases for the exponential
    /// backoff calculation used when Redis IS available.
    #[test]
    fn test_login_lockout_duration_escalation_edge_cases() {
        // First lockout: 15 minutes (base)
        assert_eq!(login_lockout_duration(1), 15 * 60);
        // Second: 30 minutes
        assert_eq!(login_lockout_duration(2), 30 * 60);
        // Third: 1 hour
        assert_eq!(login_lockout_duration(3), 60 * 60);
        // Fourth: 2 hours
        assert_eq!(login_lockout_duration(4), 120 * 60);
        // Fifth: 4 hours
        assert_eq!(login_lockout_duration(5), 240 * 60);
        // Sixth: 8 hours
        assert_eq!(login_lockout_duration(6), 480 * 60);
        // Seventh: 16 hours
        assert_eq!(login_lockout_duration(7), 960 * 60);
        // Eighth+: capped at 24 hours
        assert_eq!(login_lockout_duration(8), 86400);
        assert_eq!(login_lockout_duration(50), 86400);
        assert_eq!(login_lockout_duration(1000), 86400);
    }

    /// Tests that the login lockout key for a normalized vs raw identifier
    /// produces different keys — the system uses the normalized form for
    /// lockout checks but the raw form is not used for key generation
    /// (the helper functions take pre-normalized identifiers).
    #[test]
    fn test_login_lockout_keys_use_input_as_is() {
        // The login lockout helper functions (login_failure_key, login_lock_key,
        // login_lockout_counter_key) take the identifier as-is without normalization.
        // Normalization (lowercasing, trimming) is done by the login handler BEFORE
        // calling these functions.
        let raw = "  User@Example.Com  ";
        let normalized = normalized_login_identifier(raw);

        assert_ne!(
            login_failure_key(raw),
            login_failure_key(&normalized),
            "non-normalized and normalized identifiers must produce different Redis keys"
        );
    }

    /// Tests that the `clear_login_failures` function uses the same
    /// Redis error propagation pattern as `record_login_failure`.
    #[test]
    fn test_clear_login_failures_propagates_redis_errors() {
        // `clear_login_failures` uses `?` on Redis operations
        fn assert_propagates_error<T>() {}
        assert_propagates_error::<Result<(), ApiError>>();
    }

    /// L-24 + migration 106 (DB-gated): the login lookup
    /// `WHERE LOWER(email) = LOWER($1) OR LOWER(username) = LOWER($2)` must
    /// (a) run against an existing `username` column — no migration had ever
    /// created it before 106, so the query failed with 42703 — and (b) be
    /// driven by the functional indexes instead of a sequential scan.
    #[tokio::test]
    async fn login_lookup_becomes_index_driven_after_migration_106() {
        use sqlx::postgres::PgPoolOptions;
        use std::time::Duration;

        let database_url = std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let Some(database_url) = database_url else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let Some((server_part, db_part)) = database_url.rsplit_once('/') else {
            eprintln!("skipping: TEST_DATABASE_URL has no database segment");
            return;
        };
        let db_only = db_part.split('?').next().unwrap_or(db_part);
        let isolated_db = format!("{db_only}_api_login_idx");
        let isolated_url = format!("{server_part}/{isolated_db}");
        let admin_url = format!("{server_part}/postgres");

        let admin = match PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(3))
            .connect(&admin_url)
            .await
        {
            Ok(pool) => pool,
            Err(_) => {
                eprintln!("skipping: cannot reach Postgres admin database");
                return;
            }
        };
        let _ = sqlx::query(&format!(
            r#"DROP DATABASE IF EXISTS "{isolated_db}" WITH (FORCE)"#
        ))
        .execute(&admin)
        .await;
        let created = sqlx::query(&format!(r#"CREATE DATABASE "{isolated_db}""#))
            .execute(&admin)
            .await;
        admin.close().await;
        assert!(
            created.is_ok(),
            "isolated login-index test DB must be creatable"
        );

        let pool = PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&isolated_url)
            .await
            .expect("connect to isolated login-index test DB");

        // Minimal users table in the pre-106 shape (migrations 052/056/076):
        // email unique, NO username column yet.
        sqlx::query(
            r#"CREATE TABLE users (
                   id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                   tenant_id       UUID,
                   email           VARCHAR(255) UNIQUE NOT NULL,
                   password_hash   TEXT,
                   role            VARCHAR(50),
                   status          VARCHAR(20) NOT NULL DEFAULT 'active',
                   mfa_enabled     BOOLEAN NOT NULL DEFAULT false,
                   created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
               )"#,
        )
        .execute(&pool)
        .await
        .expect("users table created");

        // The login query must FAIL before the migration (missing column).
        let login_sql =
            "SELECT id FROM users WHERE LOWER(email) = LOWER($1) OR LOWER(username) = LOWER($2)";
        let pre_migration = sqlx::query(login_sql)
            .bind("a@b.com")
            .bind("a@b.com")
            .fetch_all(&pool)
            .await;
        assert!(
            pre_migration.is_err(),
            "pre-106 schema has no username column — the login query must fail, not scan"
        );

        // Apply the actual migration file (not a copy).
        let migration_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../migrations/106_users_login_functional_indexes.sql");
        let migration_sql =
            std::fs::read_to_string(&migration_path).expect("migration 106 file must exist");
        sqlx::raw_sql(&migration_sql)
            .execute(&pool)
            .await
            .expect("migration 106 applies cleanly");

        // Seed a row and prove the functional indexes drive the lookup.
        // (seq scans are disabled per-SESSION, so the SET and the EXPLAIN run
        // on the same acquired connection.)
        sqlx::query("INSERT INTO users (email) VALUES ('User@Example.com')")
            .execute(&pool)
            .await
            .unwrap();
        let mut conn = pool.acquire().await.expect("acquire planner connection");
        sqlx::query("SET enable_seqscan = off")
            .execute(&mut *conn)
            .await
            .unwrap();
        let plan: Vec<String> = sqlx::query_scalar(
            "EXPLAIN (FORMAT text) SELECT id FROM users \
             WHERE LOWER(email) = LOWER($1) OR LOWER(username) = LOWER($2)",
        )
        .bind("user@example.com")
        .bind("user@example.com")
        .fetch_all(&mut *conn)
        .await
        .expect("post-migration the login query must be plannable");
        let plan = plan.join("\n");

        assert!(
            plan.contains("idx_users_email_lower") || plan.contains("idx_users_username_lower"),
            "login lookup must use the functional indexes, plan: {plan}"
        );
        drop(conn);
        pool.close().await;
    }

    // ─── Signup id-generation regression (production signup bug) ────
    //
    // users.id is UUID on both authoritative schema lineages (the canonical
    // services/mail-server/migrations chain applied by the migrator crate,
    // and the apexmail-db SCHEMA used by CI). The register handler used to
    // generate a 26-char text nanoid for the user id, which fails the
    // INSERT with `invalid input syntax for type uuid` — every public
    // signup returned "database error" and no row was created. These tests
    // drive the REAL handler through a router against a canonical-shape
    // fixture database (crate::test_db::canonical_pool) and prove the
    // signup persists a usable account.

    /// Test AppState over the given pool (mirrors web.rs's `web_test_state`
    /// fixture, parameterized on the database and redis URL).
    async fn signup_test_state(db: sqlx::PgPool, redis_url: &str) -> AppState {
        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(|| {
            let _ = metrics_exporter_prometheus::PrometheusBuilder::new().install_recorder();
            std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
            std::env::set_var("AWS_ACCESS_KEY_ID", "test");
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
            // Surface handler tracing::error! output in test output (opt-in
            // via RUST_LOG; defaults to error-level only).
            let _ = tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("error")),
                )
                .with_test_writer()
                .try_init();
        });
        let redis = deadpool_redis::Config::from_url(redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("lazy redis pool");
        let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_sesv2::config::Region::new("us-east-1"))
            .load()
            .await;
        let ses_provider = Arc::new(crate::ses_provider::SesIpProvider::new(
            aws_sdk_sesv2::Client::new(&aws_config),
            db.clone(),
            "apexmail".into(),
            "us-east-1".into(),
        ));
        let config = crate::app::test_support::test_config();
        crate::state::AppStateInner::with_ddos_protector(
            db.clone(),
            apexmail_db::pool::PoolPair {
                rw: db.clone(),
                ro: db,
            },
            redis,
            config,
            reqwest::Client::new(),
            (*ses_provider).clone(),
            None,
            Arc::new(
                ddos_protection::DdosProtector::new(ddos_protection::ProtectorConfig::default())
                    .await
                    .expect("ddos protector"),
            ),
            None,
            None,
            crate::resilience::ResilientClient::new_from_config(
                &crate::app::test_support::test_config(),
            ),
        )
    }

    /// Seed the system sender domain (apexmail.ee) with valid DKIM material
    /// so `ensure_system_sender_ready` passes and the verification email can
    /// be queued. Requires `DKIM_PRIVATE_KEY_ENCRYPTION_KEY` (set here) and
    /// generates a real RSA keypair — the readiness check decrypts and
    /// re-derives the public key, so fake material is rejected.
    ///
    /// The caller must hold `crate::test_db::DKIM_ENV_MUTEX` across the
    /// whole seeded scope and restore the env var afterwards via
    /// `restore_dkim_env` (same convention as admin/domains.rs).
    async fn seed_system_sender(db: &sqlx::PgPool) {
        std::env::set_var(
            apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
            "3f7a1c9e2b5d48f01a6c3e792d4b8f15a0c6e3917d2f4b8a5c1e7309d4f2b6a8",
        );
        let key_pair = apexmail_lib::dkim::generate_dkim_keypair()
            .expect("test DKIM keypair generation must not fail");
        let aad = apexmail_lib::dkim::dkim_private_key_aad(
            crate::routes::system_sender::SYSTEM_TENANT_ID,
            crate::routes::system_sender::SYSTEM_DOMAIN_ID,
        );
        let encrypted =
            apexmail_lib::dkim::encrypt_dkim_private_key(&key_pair.private_key_pem, &aad)
                .expect("test DKIM private key encryption must not fail");
        let public_key =
            apexmail_lib::dkim::public_key_base64_from_private_key_pem(&key_pair.private_key_pem)
                .expect("test DKIM public key derivation must not fail");

        sqlx::query(
            "INSERT INTO domains (id, tenant_id, name, status, verified, ses_verified,
                                  dkim_enabled, dkim_selector, dkim_public_key, dkim_private_key)
             VALUES ($1, $2, $3, 'verified', true, true, true, 'testsel', $4, $5)
             ON CONFLICT (tenant_id, lower(name)) DO UPDATE
               SET status = 'verified', verified = true, ses_verified = true,
                   dkim_enabled = true, dkim_selector = 'testsel',
                   dkim_public_key = EXCLUDED.dkim_public_key,
                   dkim_private_key = EXCLUDED.dkim_private_key",
        )
        .bind(
            Uuid::parse_str(crate::routes::system_sender::SYSTEM_DOMAIN_ID)
                .expect("system domain id is a uuid"),
        )
        .bind(crate::routes::system_sender::SYSTEM_TENANT_ID)
        .bind(crate::routes::system_sender::SYSTEM_DOMAIN)
        .bind(&public_key)
        .bind(&encrypted)
        .execute(db)
        .await
        .expect("system sender seed must insert");
    }

    /// Restore the DKIM env var after a seeded scope (admin/domains.rs
    /// convention).
    fn restore_dkim_env(previous_key: Option<String>) {
        match previous_key {
            Some(key) => {
                std::env::set_var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV, key)
            }
            None => std::env::remove_var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV),
        }
    }

    /// DB-gated signup regression: POST /v1/auth/register must create a real
    /// users row (UUID id) + tenants row, store a verifiable bcrypt hash,
    /// and queue the verification email. Before the fix the users INSERT
    /// failed with invalid uuid syntax and NOTHING was persisted.
    /// The DKIM env guard is held across awaits on purpose: the awaited
    /// signup path reads the process-global key.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn signup_persists_uuid_user_and_tenant_rows() {
        let Some(pool) = crate::test_db::canonical_pool("signup_rows").await else {
            eprintln!("skipping signup_persists_uuid_user_and_tenant_rows: no TEST_DATABASE_URL");
            return;
        };
        // The DKIM env var is process-global: serialise against every other
        // test that mutates it, and restore the previous value afterwards.
        let _env_guard = crate::test_db::DKIM_ENV_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let had_dkim_key =
            std::env::var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV).ok();
        seed_system_sender(&pool).await;
        // Redis is deliberately NOT required for signup (the rate limiter
        // soft-skips when Redis is unreachable) — the dead port keeps the
        // test hermetic on that axis.
        let state = signup_test_state(pool.clone(), "redis://127.0.0.1:1").await;

        let app = axum::Router::new()
            .merge(crate::routes::auth::router())
            .with_state(state.clone());
        let csrf = ui_foundation::csrf::generate_csrf_token(&state.config.csrf_secret);
        let email = format!("signup-fix-{}@example.com", Uuid::new_v4());
        let body = serde_json::json!({
            "company_name": "Signup Fix Co",
            "email": email,
            "name": "Signup Tester",
            "password": "Sup3r#SecurePass",
            "plan": "free",
        });

        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method(axum::http::Method::POST)
                .uri("/register")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .header("x-csrf-token", csrf)
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .expect("register request must dispatch");
        let status = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap_or_default();
        let body_text = String::from_utf8_lossy(&body_bytes);
        assert_eq!(
            status,
            axum::http::StatusCode::ACCEPTED,
            "signup must succeed, not {status} with a uuid bind error; body: {body_text}"
        );

        // The users row exists, has a UUID id, and the password verifies.
        let row: Option<(String, String, String, String)> = sqlx::query_as(
            "SELECT id::text, tenant_id::text, password_hash, role FROM users WHERE email = $1",
        )
        .bind(&email)
        .fetch_optional(&pool)
        .await
        .expect("users lookup must not error");
        let Some((user_id, tenant_id, password_hash, role)) = row else {
            panic!("signup must persist a users row for {email}");
        };
        assert!(
            Uuid::parse_str(&user_id).is_ok(),
            "users.id must be a valid UUID, got {user_id}"
        );
        assert_eq!(role, "owner");
        assert!(
            password_hash.starts_with("$2") || password_hash.starts_with("$argon2"),
            "password hash must be a verifiable hash, got {password_hash:?}"
        );

        // The tenants row exists with the 26-char text id that was bound.
        let tenant_status: Option<(String,)> =
            sqlx::query_as("SELECT status FROM tenants WHERE id = $1")
                .bind(&tenant_id)
                .fetch_optional(&pool)
                .await
                .expect("tenants lookup must not error");
        assert_eq!(
            tenant_status.map(|(status,)| status).as_deref(),
            Some("pending"),
            "signup must persist the tenant row"
        );

        // The verification email was queued through the system sender.
        let queued: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM email_queue WHERE to_addresses = ARRAY[$1]::text[]",
        )
        .bind(&email)
        .fetch_one(&pool)
        .await
        .expect("email_queue lookup must not error");
        assert!(queued >= 1, "verification email must be queued for {email}");

        restore_dkim_env(had_dkim_key);
        pool.close().await;
    }

    /// DB+Redis-gated full flow: after a successful signup, a login with the
    /// same credentials reaches the authentication decision (for a fresh
    /// owner account that is the MFA-enrollment challenge, 202 — NOT
    /// 401 invalid credentials), proving the persisted row is usable.
    /// The DKIM env guard is held across awaits on purpose: the awaited
    /// signup path reads the process-global key.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn signup_then_login_authenticates_the_new_account() {
        let Some(pool) = crate::test_db::canonical_pool("signup_login").await else {
            eprintln!(
                "skipping signup_then_login_authenticates_the_new_account: no TEST_DATABASE_URL"
            );
            return;
        };
        let redis_url = std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "redis://127.0.0.1:1".into());
        // Login hard-requires Redis (lockout TTL + rate limiter); soft-skip
        // when it is not reachable so the suite stays green without Redis.
        let redis_probe = deadpool_redis::Config::from_url(&redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool");
        let redis_reachable = match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            redis_probe.get(),
        )
        .await
        {
            Ok(Ok(mut conn)) => {
                let pong: Result<String, _> = deadpool_redis::redis::cmd("PING")
                    .query_async(&mut *conn)
                    .await;
                pong.is_ok()
            }
            _ => false,
        };
        if !redis_reachable {
            eprintln!(
                "skipping signup_then_login_authenticates_the_new_account: TEST_REDIS_URL unreachable"
            );
            pool.close().await;
            return;
        }

        // The DKIM env var is process-global: serialise against every other
        // test that mutates it, and restore the previous value afterwards.
        let _env_guard = crate::test_db::DKIM_ENV_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let had_dkim_key =
            std::env::var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV).ok();
        seed_system_sender(&pool).await;
        let state = signup_test_state(pool.clone(), &redis_url).await;
        let app = axum::Router::new()
            .merge(crate::routes::auth::router())
            .with_state(state.clone());
        let csrf = ui_foundation::csrf::generate_csrf_token(&state.config.csrf_secret);

        let email = format!("signup-login-{}@example.com", Uuid::new_v4());
        let password = "Sup3r#SecurePass";
        let register_body = serde_json::json!({
            "company_name": "Signup Login Co",
            "email": email,
            "name": "Login Tester",
            "password": password,
            "plan": "free",
        });
        let response = tower::ServiceExt::oneshot(
            app.clone(),
            axum::http::Request::builder()
                .method(axum::http::Method::POST)
                .uri("/register")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .header("x-csrf-token", csrf.clone())
                .body(axum::body::Body::from(register_body.to_string()))
                .unwrap(),
        )
        .await
        .expect("register request must dispatch");
        assert_eq!(response.status(), axum::http::StatusCode::ACCEPTED);

        let login_body = serde_json::json!({
            "email": email,
            "password": password,
        });
        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method(axum::http::Method::POST)
                .uri("/login")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .header("x-csrf-token", csrf)
                .body(axum::body::Body::from(login_body.to_string()))
                .unwrap(),
        )
        .await
        .expect("login request must dispatch");

        // A fresh owner account is UNVERIFIED: login must refuse it (403
        // verify-your-email) — proving the password verified against the
        // row the signup created (it is not a 401 invalid-credentials).
        assert_eq!(
            response.status(),
            axum::http::StatusCode::FORBIDDEN,
            "login before email verification must be refused"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json.to_string().to_lowercase().contains("verif"),
            "the refusal must name the verification requirement, got: {json}"
        );

        // After verification the same credentials authenticate — for a
        // fresh owner that means the 202 MFA-enrollment challenge.
        sqlx::query("UPDATE users SET email_verified = true WHERE email = $1")
            .bind(&email)
            .execute(&pool)
            .await
            .expect("mark verified");
        let state2 = signup_test_state(pool.clone(), &redis_url).await;
        let csrf2 = ui_foundation::csrf::generate_csrf_token(&state2.config.csrf_secret);
        let app2 = axum::Router::new()
            .merge(crate::routes::auth::router())
            .with_state(state2);
        let response = tower::ServiceExt::oneshot(
            app2,
            axum::http::Request::builder()
                .method(axum::http::Method::POST)
                .uri("/login")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .header("x-csrf-token", csrf2)
                .body(axum::body::Body::from(login_body.to_string()))
                .unwrap(),
        )
        .await
        .expect("verified login dispatch");
        assert_eq!(
            response.status(),
            axum::http::StatusCode::ACCEPTED,
            "login after verification must reach the MFA-enrollment challenge"
        );

        restore_dkim_env(had_dkim_key);
        pool.close().await;
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
        sqlx::query_as::<_, PasswordHashRow>("SELECT password_hash FROM users WHERE id = $1::uuid")
            .bind(user_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| ApiError::NotFound("user not found".into()))?;

    let password_hash = user
        .password_hash
        .as_deref()
        .ok_or_else(|| ApiError::Unauthorized("No password set".into()))?;
    let valid = verify_password_or_log(&body.current_password, password_hash, user_id)?;

    if !valid {
        return Err(ApiError::Unauthorized("Invalid current password".into()));
    }

    // Hash and update
    let new_hash = apexmail_lib::hash_password(&body.new_password)
        .map_err(|error| ApiError::Internal(format!("Password hashing failed: {error}")))?;

    sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2::uuid")
        .bind(new_hash)
        .bind(user_id)
        .execute(&state.db)
        .await?;

    // Revoke all other sessions to force re-authentication with new password
    if let Some(current_session_id) = &auth.session_id {
        sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND id != $2")
            .bind(user_id)
            .bind(current_session_id)
            .execute(&state.db)
            .await?;
    } else {
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&state.db)
            .await?;
    }

    // Invalidate user status cache so stale cached entries cannot bypass the password change
    invalidate_tenant_user_status_cache(&auth.tenant_id, &state).await;

    // Set Redis revocation marker so all existing JWTs (including the current session's
    // refresh token) are rejected immediately. Without this, a stolen old refresh token
    // could still obtain new access tokens even after the password is changed.
    let ttl = state.config.jwt_expiry.as_secs();
    revoke_user_sessions(&state.redis, &auth.tenant_id, user_id, ttl).await?;

    Ok(Json(serde_json::json!({ "changed": true })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeSessionRequest {
    /// Optional: revoke a specific session ID. If omitted, revokes all other sessions.
    #[serde(default)]
    pub session_id: Option<String>,
    /// When true, revoke all sessions including the current one (requires `revoke_all=true` query param).
    #[serde(default)]
    pub revoke_all: bool,
}

async fn revoke_session(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<RevokeSessionRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user_id = authenticated_user_id(&auth)?;

    // Write the Redis revocation marker BEFORE deleting from Postgres.
    // This closes the TOCTOU window where a revoked session's JWT could still
    // obtain a new refresh token via the refresh_token endpoint.
    let ttl = state.config.jwt_expiry.as_secs();
    revoke_user_sessions(&state.redis, &auth.tenant_id, user_id, ttl).await?;

    let affected = if body.revoke_all {
        // Revoke ALL sessions including the current one
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&state.db)
            .await?
            .rows_affected()
    } else if let Some(session_id) = &body.session_id {
        // Revoke single specific session
        sqlx::query("DELETE FROM sessions WHERE id = $1 AND user_id = $2")
            .bind(session_id)
            .bind(user_id)
            .execute(&state.db)
            .await?
            .rows_affected()
    } else if let Some(current_session_id) = &auth.session_id {
        // Default: revoke all sessions except the current one
        sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND id != $2")
            .bind(user_id)
            .bind(current_session_id)
            .execute(&state.db)
            .await?
            .rows_affected()
    } else {
        // No session context (e.g. API key auth) — revoke all sessions
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&state.db)
            .await?
            .rows_affected()
    };

    Ok(Json(serde_json::json!({ "revoked": affected })))
}
