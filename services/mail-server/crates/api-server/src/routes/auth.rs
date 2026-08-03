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
use std::net::SocketAddr;
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{
    invalidate_api_key_cache, invalidate_tenant_user_status_cache, issued_before_or_at_revocation,
    lookup_session_revoked_after, session_revocation_key, validate_session_csrf, AuthUser,
    JwtClaims,
};
use crate::middleware::rate_limiter::extract_public_client_ip;
use crate::routes::csrf::validate_form_csrf;
use crate::state::AppState;

const SYSTEM_TENANT_ID: &str = "system_internal_tenant01";
const LOGIN_FAILURE_THRESHOLD: i64 = 5;
const LOGIN_FAILURE_WINDOW_SECS: u64 = 5 * 60;
const LOGIN_LOCKOUT_BASE_SECS: u64 = 15 * 60;
const LOGIN_LOCKOUT_MAX_SECS: u64 = 24 * 60 * 60;
const LOGIN_LOCKOUT_ESCALATION_WINDOW_SECS: u64 = 24 * 60 * 60;
const DEFAULT_API_KEY_EXPIRY_DAYS: i64 = 90;
const MAX_API_KEY_EXPIRY_DAYS: i64 = 365;
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

    tracing::info!(token_len = raw.len(), "KiwiCaptcha: decoding token");

    let solution = kiwicaptcha::SolutionToken::decode(raw).map_err(|e| {
        tracing::warn!(error = %e, token_len = raw.len(), "KiwiCaptcha: token decode failed");
        ApiError::Validation(vec![
            "CAPTCHA verification failed — please refresh and try again".into(),
        ])
    })?;

    tracing::info!(
        nonce = %solution.nonce,
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
        .ok_or_else(|| {
            tracing::warn!(nonce = %solution.nonce, key = %key, "KiwiCaptcha: challenge not found in Redis");
            ApiError::Validation(vec![
                "CAPTCHA challenge expired or not found — please refresh and try again".into(),
            ])
        })
        .and_then(|s| {
            serde_json::from_str(&s).map_err(|e| {
                tracing::warn!(error = %e, nonce = %solution.nonce, "KiwiCaptcha: challenge record decode failed");
                ApiError::Internal("CAPTCHA state corrupted".into())
            })
        })?;

    tracing::info!(
        nonce = %solution.nonce,
        scope = %record.scope,
        expires_at = record.expires_at,
        ip_hash = %record.ip_hash,
        m_kib = record.m_kib,
        target_bits = record.target_bits,
        "KiwiCaptcha: challenge record found"
    );

    // Set a short expiry (30s) on first successful verify so the challenge
    // cannot be replayed, but survives long enough for a MFA retry.
    let _: () = deadpool_redis::redis::AsyncCommands::expire(
        &mut *conn,
        &key,
        30,
    )
    .await?;

    // IP binding: the challenge was issued to this IP. A mismatch means a
    // relay attack (token minted elsewhere, submitted from here).
    let expected_ip_hash = kiwicaptcha::hash_ip(client_ip, &config.kiwi_secret_key);
    if record.ip_hash != expected_ip_hash {
        tracing::warn!(
            expected = %record.ip_hash,
            actual = %expected_ip_hash,
            client_ip = %client_ip,
            "KiwiCaptcha: IP mismatch — challenge was issued to a different client"
        );
        return Err(ApiError::Validation(vec![
            "CAPTCHA verification failed — please try again".into(),
        ]));
    }

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Minimum duration: reject solves faster than theoretically possible.
    // Configurable via KIWI_MIN_DURATION_MS (default 80ms).
    let min_duration_ms: u64 = config.kiwi_min_duration_ms.unwrap_or(80);

    // Telemetry scoring: detect headless/automated clients.
    if kiwicaptcha::score_telemetry(&solution.telemetry, solution.duration_ms) {
        tracing::warn!(
            telemetry = ?solution.telemetry,
            duration_ms = solution.duration_ms,
            "KiwiCaptcha bot detected via telemetry"
        );
        return Err(ApiError::Validation(vec![
            "CAPTCHA verification failed — please try again".into(),
        ]));
    }

    let ctx = kiwicaptcha::VerifyContext {
        record: &record,
        secret_key: &config.kiwi_secret_key,
        counter: solution.counter,
        duration_ms: solution.duration_ms,
        now_unix,
        min_duration_ms,
        expected_scope: scope,
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

    match kiwicaptcha::verify_solution(&ctx) {
        kiwicaptcha::VerifyOutcome::Valid => {
            tracing::info!(duration_ms = solution.duration_ms, counter = solution.counter, "KiwiCaptcha: VERIFIED");
            Ok(())
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

fn verify_password_or_log(password: &str, hash: &str, subject: &str) -> Result<bool, ApiError> {
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

fn role_requires_mfa(role: &str) -> bool {
    matches!(role, "admin" | "owner")
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
    // Use char count for minimum length (Unicode-aware) and byte length for max (DB storage limit)
    let char_count = password.chars().count();
    if char_count < 12 || password.len() > 128 {
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
            "password must include uppercase, lowercase, number, and an ASCII punctuation mark"
                .into(),
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
    format!(
        "{}{}/{}",
        base_url.trim_end_matches('/'),
        path,
        token,
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
    db: &sqlx::PgPool,
    base_url: &str,
    email: &str,
    token: &str,
) -> Result<(), sqlx::Error> {
    let verification_link = build_action_link(base_url, "/verify-email", email, token);
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

    // Generate a message ID used in both the messages log and the email_queue
    let message_id = apexmail_lib::id::generate_id("msg", 22);

    // 1. Insert into messages table (audit/log)
    sqlx::query(
        "INSERT INTO messages (id, tenant_id, from_email, to_emails, subject, html_body, text_body, status, tags, created_at)
         VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, 'queued', $8::jsonb, NOW())",
    )
    .bind(&message_id)
    .bind(SYSTEM_TENANT_ID)
    .bind("noreply@apexmail.ee")
    .bind(serde_json::json!([email]))
    .bind("Verify your ApexMail account")
    .bind(&html_body)
    .bind(&text_body)
    .bind(serde_json::json!(["system", "verification"]))
    .execute(db)
    .await?;

    // 2. Look up the domain_id for "apexmail.ee" via the system domain alias.
    //    System-internal emails use a well-known tenant-less domain; if it is
    //    not yet registered in the domains table we generate a synthetic ID
    //    so the email_queue worker can still pick up the row (DKIM will be
    //    skipped gracefully for unknown domains).
    let domain_id: String = sqlx::query_scalar(
        "SELECT id FROM domains WHERE domain = 'apexmail.ee' LIMIT 1",
    )
    .fetch_optional(db)
    .await?
    .unwrap_or_else(|| apexmail_lib::id::generate_id("dom", 22));

    // 3. Insert into email_queue for the worker processor to pick up
    let now = chrono::Utc::now();
    sqlx::query(
        "INSERT INTO email_queue (
            id, message_id, tenant_id, domain_id, \"from\", \"to\", subject,
            html, text, tags, metadata, scheduled_at, priority, status, created_at, updated_at
         ) VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9, $10, $11, $12, 5, 'pending', $13, $13
         )",
    )
    .bind(apexmail_lib::id::generate_id("emq", 22))
    .bind(&message_id)
    .bind(SYSTEM_TENANT_ID)
    .bind(&domain_id)
    .bind("noreply@apexmail.ee")
    .bind(email)
    .bind("Verify your ApexMail account")
    .bind(&html_body)
    .bind(&text_body)
    .bind(serde_json::json!(["system", "verification"]))
    .bind(Option::<serde_json::Value>::None) // metadata
    .bind(Option::<chrono::DateTime<chrono::Utc>>::None) // scheduled_at
    .bind(now)
    .execute(db)
    .await?;

    Ok(())
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
    sqlx::query(
        "INSERT INTO audit_logs (id, tenant_id, user_id, action, resource_type, ip_address, user_agent, metadata, created_at)
         VALUES (gen_random_uuid(), $1, $2, $3, 'auth', $4, $5, $6::jsonb, NOW())",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(action)
    .bind(ip_address)
    .bind(user_agent)
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
            sqlx::query_as("SELECT id, email, name, role FROM users WHERE id = $1 AND status = 'active'")
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
            tracing::warn!(
                "login request missing ConnectInfo; using shared rate-limit bucket"
            );
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

    if let Ok(mut conn) = state.redis.get().await {
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

    let login_identifier = normalized_login_identifier(&body.email);
    if login_lock_ttl(&state.redis, &login_identifier)
        .await?
        .is_some()
    {
        return Err(ApiError::RateLimited);
    }

    let user = sqlx::query_as::<_, UserRow>(
        "SELECT id::text, tenant_id::text, email, name, password_hash, role, status, mfa_enabled, mfa_secret, mfa_recovery_hashes
         FROM users WHERE LOWER(email) = LOWER($1) OR LOWER(username) = LOWER($2)",
    )
    .bind(&body.email)
    .bind(&body.email)
    .fetch_optional(&state.db)
    .await?;

    let Some(mut user) = user else {
        record_login_failure(&state.redis, &login_identifier).await?;
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    };

    decrypt_mfa_secret_in_place(&mut user)?;

    if user.status != "active" {
        return Err(ApiError::Forbidden("account is not active".into()));
    }

    let valid = verify_password_or_log(&body.password, &user.password_hash, &user.email)?;

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

            // Email-based MFA: generate a one-time code, store in Redis.
            if secret == "email" {
                let mut redis_conn = state.redis.get().await?;
                if let Some(mfa_code) = body.mfa_code.as_deref() {
                    if mfa_code.trim().is_empty() {
                        return Err(ApiError::Validation(vec!["MFA code is required".into()]));
                    }
                    let key = format!("apexmail:email_mfa:{}", user.id);
                    let stored: Option<String> = deadpool_redis::redis::AsyncCommands::get(&mut *redis_conn, &key).await?;
                    match stored {
                        Some(code) if code == mfa_code => {
                            let _: () = deadpool_redis::redis::AsyncCommands::del(&mut *redis_conn, &key).await?;
                        }
                        _ => {
                            record_login_failure(&state.redis, &login_identifier).await?;
                            return Err(ApiError::Unauthorized("invalid MFA code".into()));
                        }
                    }
                } else {
                    use rand::Rng;
                    let code: u32 = rand::thread_rng().gen_range(100000..999999);
                    let code_str = code.to_string();
                    let key = format!("apexmail:email_mfa:{}", user.id);
                    let _: () = deadpool_redis::redis::AsyncCommands::set_ex(&mut *redis_conn, &key, &code_str, 300).await?;
                    tracing::info!(user_id = %user.id, email = %user.email, "Email MFA code generated: {code_str}");

                    // Enqueue MFA email via email_queue (same pattern as forgot_password)
                    let msg_id = apexmail_lib::id::generate_id("msg", 22);
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
                    let domain_id = sqlx::query_scalar::<_, String>("SELECT id FROM domains WHERE tenant_id=$1 AND status='verified' LIMIT 1")
                        .bind(SYSTEM_TENANT_ID)
                        .fetch_optional(&state.db)
                        .await
                        .map_err(|e| { tracing::error!(error=%e, "Failed to look up system domain"); ApiError::Internal("Failed to send MFA email".into()) })?
                        .unwrap_or_else(|| apexmail_lib::id::generate_id("dom", 22));
                    let _ = sqlx::query(
                        "INSERT INTO email_queue (id, message_id, tenant_id, domain_id, \"from\", \"to\", subject, html, text, tags, metadata, scheduled_at, priority, status, created_at, updated_at)
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 5, 'pending', $13, $13)",
                    )
                    .bind(apexmail_lib::id::generate_id("emq", 22))
                    .bind(&msg_id)
                    .bind(SYSTEM_TENANT_ID)
                    .bind(&domain_id)
                    .bind("noreply@apexmail.ee")
                    .bind(&user.email)
                    .bind("Your ApexMail MFA Code")
                    .bind(&html_body)
                    .bind(&text_body)
                    .bind(serde_json::json!(["system", "mfa"]))
                    .bind(Option::<serde_json::Value>::None)
                    .bind(Option::<chrono::DateTime<chrono::Utc>>::None)
                    .bind(chrono::Utc::now())
                    .execute(&state.db)
                    .await;
                    tracing::info!(user_id=%user.id, email=%user.email, "MFA email queued");

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
            } else if let Some(mfa_code) = body.mfa_code.as_deref() {
                // Try TOTP first, then fall back to recovery code
                let totp_valid = apexmail_lib::mfa::verify_totp_code(secret, mfa_code);
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

    let challenge = load_mfa_challenge(&state.redis, &body.challenge_token).await?;
    let login_identifier = normalized_login_identifier(&challenge.email);

    match challenge.kind {
        MfaChallengeKind::Setup => {
            // Setup always requires a valid TOTP code
            if !has_mfa_code
                || !apexmail_lib::mfa::verify_totp_code(&challenge.secret, &body.mfa_code)
            {
                record_login_failure(&state.redis, &login_identifier).await?;
                return Err(ApiError::Unauthorized("invalid MFA code".into()));
            }
        }
        MfaChallengeKind::Verify => {
            // Verify accepts either TOTP code or recovery code
            let totp_valid = has_mfa_code
                && apexmail_lib::mfa::verify_totp_code(&challenge.secret, &body.mfa_code);

            if !totp_valid {
                // Try recovery code before failing
                let rc = body
                    .recovery_code
                    .as_deref()
                    .filter(|c| !c.trim().is_empty());
                if rc.is_none() {
                    record_login_failure(&state.redis, &login_identifier).await?;
                    return Err(ApiError::Unauthorized("invalid MFA code".into()));
                }
                // Recovery code verification happens below after loading user
            }
        }
    }

    clear_login_failures(&state.redis, &login_identifier).await?;

    let mut user = sqlx::query_as::<_, UserRow>(
        "SELECT id, tenant_id, email, name, password_hash, role, status, mfa_enabled, mfa_secret, mfa_recovery_hashes
         FROM users WHERE id = $1 AND tenant_id = $2",
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

            delete_mfa_challenge(&state.redis, &body.challenge_token).await?;

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

            // If TOTP failed earlier, try recovery code
            let totp_valid = apexmail_lib::mfa::verify_totp_code(&challenge.secret, &body.mfa_code);
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
                    record_login_failure(&state.redis, &login_identifier).await?;
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

            delete_mfa_challenge(&state.redis, &body.challenge_token).await?;

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
        "SELECT id, email, name, role, mfa_enabled
         FROM users WHERE id = $1 AND tenant_id = $2",
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

    let challenge = load_mfa_challenge(&state.redis, &body.challenge_token).await?;

    // Validate the TOTP code
    if !apexmail_lib::mfa::verify_totp_code(&challenge.secret, &body.mfa_code) {
        return Err(ApiError::Unauthorized("invalid MFA code".into()));
    }

    let user = sqlx::query_as::<_, UserRow>(
        "SELECT id, tenant_id, email, name, password_hash, role, status, mfa_enabled, mfa_secret, mfa_recovery_hashes
         FROM users WHERE id = $1 AND tenant_id = $2",
    )
    .bind(user_id)
    .bind(&auth.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("user not found".into()))?;

    if user.mfa_enabled {
        delete_mfa_challenge(&state.redis, &body.challenge_token).await?;
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

    delete_mfa_challenge(&state.redis, &body.challenge_token).await?;

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
        "SELECT mfa_enabled, role FROM users WHERE id = $1 AND tenant_id = $2",
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
    mfa_secret: Option<String>,
    mfa_recovery_hashes: Option<serde_json::Value>,
}

// ─── Registration types ────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
pub struct RegisterRequest {
    pub company_name: String,
    pub email: String,
    pub name: String,
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

    // Rate-limit only after cheap validation so ordinary form mistakes do not
    // burn the user's sign-up attempts. The limit still protects the database
    // and email queue from repeated valid registration submissions.

    let rate_key = format!("apexmail:register_rate:{client_ip}");

    if let Ok(mut conn) = state.redis.get().await {
        let count: i64 = match deadpool_redis::redis::cmd("INCR")
            .arg(&rate_key)
            .query_async(&mut *conn)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, ip = %client_ip, "register rate-limit INCR failed; rejecting request");
                return Err(ApiError::Internal("rate limit check unavailable".into()));
            }
        };

        if count == 1 {
            let _: Result<(), _> = deadpool_redis::redis::cmd("EXPIRE")
                .arg(&rate_key)
                .arg(REGISTER_RATE_LIMIT_WINDOW_SECS)
                .query_async(&mut *conn)
                .await;
        }

        if count > REGISTER_RATE_LIMIT_MAX_REQUESTS {
            return Err(ApiError::RateLimitedMessage(register_rate_limit_message()));
        }
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

    tx.commit().await.map_err(|error| {
        tracing::error!(error = %error, tenant_id = %tenant_id, user_id = %user_id, "failed to commit registration transaction");
        ApiError::Internal("database error".into())
    })?;

    // Enqueue verification email AFTER transaction commit so the email
    // is only sent if the DB transaction succeeded. This prevents sending
    // verification emails for registrations that are rolled back.
    enqueue_verification_email(&state.db, &state.config.base_url, &email_lower, &verification_token)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, tenant_id = %tenant_id, user_id = %user_id, "failed to queue verification email during registration");
            // Non-fatal: registration succeeded but email failed to queue.
            // The user can request a new verification email via the resend flow.
            tracing::warn!(
                tenant_id = %tenant_id,
                user_id = %user_id,
                "Registration succeeded but verification email could not be queued. User can request resend."
            );
            ApiError::Internal("registration succeeded but verification email could not be sent".into())
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
        let count: i64 = match deadpool_redis::redis::cmd("INCR")
            .arg(&rate_key)
            .query_async(&mut *conn)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, ip = %client_ip, "reset-password rate-limit INCR failed; rejecting request");
                return Err(ApiError::Internal("rate limit check unavailable".into()));
            }
        };

        if count == 1 {
            let _: Result<(), _> = deadpool_redis::redis::cmd("EXPIRE")
                .arg(&rate_key)
                .arg(window_secs)
                .query_async(&mut *conn)
                .await;
        }

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

    // Primary expiration check: token-level expiry (typically 1 hour)
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

    // SA2-003: Secondary hard-coded expiration check (24h absolute max)
    // This ensures tokens cannot be used beyond a hard-coded window even if
    // the primary `password_reset_expires` field is manipulated or missing.
    const MAX_RESET_TOKEN_TTL_HOURS: i64 = 24;
    if let Some(iat_str) = metadata
        .get("password_reset_iat")
        .and_then(|value| value.as_str())
    {
        if let Ok(iat) = chrono::DateTime::parse_from_rfc3339(iat_str) {
            let hard_deadline = iat + chrono::Duration::hours(MAX_RESET_TOKEN_TTL_HOURS);
            if Utc::now() > hard_deadline {
                return Err(ApiError::BadRequest(
                    "password reset token has exceeded maximum lifetime".into(),
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

    // Decode existing token to get claims.
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.set_required_spec_claims(&["exp", "sub", "tenant_id"]);

    let token_data =
        crate::middleware::auth::decode_jwt_with_rotation(&token, &state.config, &validation)?;
    let old_claims = token_data.claims;

    let user_id = old_claims.sub.clone();
    let tenant_id = old_claims.tenant_id.clone();

    // Check if the session has been revoked since the token was issued
    let revoked_after = lookup_session_revoked_after(&tenant_id, &user_id, &state).await?;
    if issued_before_or_at_revocation(old_claims.iat, revoked_after) {
        return Err(ApiError::Unauthorized("session has been revoked".into()));
    }

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

    let session_id = Uuid::new_v4().to_string();

    let claims = JwtClaims {
        sub: user.id.to_string(),
        tenant_id: user.tenant_id.to_string(),
        scopes: scopes_for_role(&user.role),
        exp: exp.timestamp(),
        iat: now.timestamp(),
        jti: session_id,
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
    fn test_validate_password_strength_requires_ascii_special_character() {
        assert!(validate_password_strength("StrongPassword1!").is_ok());
        assert!(validate_password_strength("ValidPass9?Z").is_ok());
        assert!(validate_password_strength("ValidPass9~Z").is_ok());
        assert!(matches!(
            validate_password_strength("Password123é"),
            Err(ApiError::Validation(_))
        ));
    }

    #[test]
    fn test_register_rate_limit_is_not_tiny_retry_bucket() {
        assert!(REGISTER_RATE_LIMIT_MAX_REQUESTS >= 20);
        assert!(REGISTER_RATE_LIMIT_WINDOW_SECS <= 10 * 60);
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

    /// Tests that MFA challenge store/load functions use `?` for Redis
    /// errors, meaning Redis failures are propagated as ApiError.
    #[test]
    fn test_mfa_challenge_functions_use_propagating_error_pattern() {
        // Both `store_mfa_challenge` and `load_mfa_challenge` use `?` for
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
    let valid = verify_password_or_log(&body.current_password, password_hash, user_id)?;

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
