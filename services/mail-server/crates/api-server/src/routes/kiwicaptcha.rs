//! KiwiCaptcha challenge issuance endpoint.
//!
//! `POST /api/kcaptcha/challenge` (and `/v1/kcaptcha/challenge`) mints a new
//! memory-hard proof-of-work challenge, stores it in Redis (single-use, TTL'd,
//! IP-bound), and returns the challenge parameters to the inline widget script.

use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::OnceLock;

use crate::error::ApiError;
use crate::middleware::rate_limiter::extract_public_client_ip;
use crate::state::AppState;

/// The Redis key prefix under which issued KiwiCaptcha challenges are stored.
/// (Mirrors the constant in `routes::auth` — kept here so this module is standalone.)
const KIWI_CHALLENGE_PREFIX: &str = "apexmail:kiwi:";

/// Per-IP rate limit for challenge issuance, preventing a bot from requesting
/// thousands of challenges to DoS Redis or pre-compute solutions.
const CHALLENGE_IP_RATE_LIMIT: i64 = 30;
const CHALLENGE_IP_RATE_LIMIT_WINDOW_SECS: u64 = 15 * 60;

/// Process-wide in-memory challenge cache (per IP hash + scope, 1s TTL).
///
/// A page load (or a double-fetch from the widget) often issues 2+ challenge
/// requests for the same client within a second. The cache serves those
/// repeats from memory instead of re-issuing a nonce and re-writing Redis.
/// Entries are pruned lazily inside `ChallengeCache` (on `get`/`put`).
static CHALLENGE_CACHE: OnceLock<Mutex<kiwicaptcha::ChallengeCache>> = OnceLock::new();

fn challenge_cache() -> &'static Mutex<kiwicaptcha::ChallengeCache> {
    CHALLENGE_CACHE.get_or_init(|| Mutex::new(kiwicaptcha::ChallengeCache::new()))
}

pub fn router() -> Router<AppState> {
    Router::new().route("/challenge", post(issue_challenge_handler))
}

// ─── Request / Response ────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeRequest {
    /// The auth scope this challenge is for (e.g. "login", "signup").
    /// The verifier will reject a solution submitted to a different scope.
    pub scope: String,
}

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub nonce: String,
    pub challenge: String,
    pub salt: String,
    /// The proof-of-work algorithm ("sha256" | "argon2id"). The widget
    /// dispatches on this field; it must never infer the mode from a number.
    pub algorithm: String,
    #[serde(rename = "mKib")]
    pub m_kib: u32,
    #[serde(rename = "t")]
    pub t: u32,
    #[serde(rename = "p")]
    pub p: u32,
    #[serde(rename = "targetBits")]
    pub target_bits: u32,
    #[serde(rename = "ttlSecs")]
    pub ttl_secs: u64,
    #[serde(rename = "minDurationMs")]
    pub min_duration_ms: u64,
    pub prefix: String,
}

// ─── Handler ───────────────────────────────────────────────────

async fn issue_challenge_handler(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, ApiError> {
    // Dev-mode bypass: if the secret key is "dev" in a debug build, return a
    // trivially-solvable challenge so local development works without a real
    // solve. (Mirrors the bypass in verify_kiwi_token.)
    if cfg!(debug_assertions) && state.config.kiwi_secret_key == "dev" {
        return Ok(Json(ChallengeResponse {
            nonce: "dev".into(),
            challenge: "dev".into(),
            salt: "dev".into(),
            algorithm: "sha256".into(),
            m_kib: 0,
            t: 1,
            p: 1,
            target_bits: 1,
            ttl_secs: 120,
            min_duration_ms: 0,
            prefix: "dev|dev|".into(),
        }));
    }

    if !state.config.kiwi_enabled {
        return Err(ApiError::ServiceUnavailable(
            "KiwiCaptcha is not enabled".into(),
        ));
    }

    // Validate scope against an allowlist to prevent abuse.
    let scope = body.scope.as_str();
    if !matches!(scope, "login" | "signup" | "forgot-password" | "reset-password") {
        return Err(ApiError::Validation(vec![
            "invalid captcha scope".into(),
        ]));
    }

    let client_ip = connect_info
        .map(|ConnectInfo(addr)| {
            extract_public_client_ip(&headers, addr.ip(), &state.config.trusted_proxies)
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Per-IP rate limiting: prevent bots from requesting thousands of challenges.
    let ip_rate_key = format!("apexmail:kiwi_challenge_rate:ip:{client_ip}");
    if let Ok(mut conn) = state.redis.get().await {
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
        .arg(CHALLENGE_IP_RATE_LIMIT)
        .arg(CHALLENGE_IP_RATE_LIMIT_WINDOW_SECS)
        .invoke_async::<i64>(&mut *conn)
        .await
        .unwrap_or(0);

        if count > 0 {
            tracing::warn!(client_ip = %client_ip, "KiwiCaptcha challenge rate limit exceeded");
            return Err(ApiError::RateLimited);
        }
    }

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let kc_config = kiwicaptcha::ChallengeConfig {
        secret_key: state.config.kiwi_secret_key.clone(),
        algorithm: state.config.kiwi_algorithm,
        m_kib: state.config.kiwi_argon_m_kib,
        t: state.config.kiwi_argon_t,
        p: state.config.kiwi_argon_p,
        target_bits: state.config.kiwi_difficulty_bits,
        argon2_target_bits: state.config.kiwi_argon2_difficulty_bits,
        ttl_secs: state.config.kiwi_challenge_ttl_secs,
        min_duration_ms: state.config.kiwi_min_duration_ms,
        auto_tune: state.config.kiwi_auto_tune,
        auto_tune_min_bits: state.config.kiwi_auto_tune_min_bits,
        auto_tune_max_bits: state.config.kiwi_auto_tune_max_bits,
    };

    // Serve repeat requests from the same client (IP hash + scope) within the
    // cache window from memory — the challenge record is already in Redis from
    // the first issuance, so no extra Redis write happens per page load.
    let ip_hash = kiwicaptcha::hash_ip(&client_ip, &state.config.kiwi_secret_key);
    if let Some(issued) = challenge_cache().lock().get(&ip_hash, scope) {
        return Ok(Json(challenge_response(issued)));
    }

    let issued = kiwicaptcha::issue_challenge(&kc_config, scope, &client_ip, now_unix, 0)
        .map_err(|_| ApiError::Internal("failed to issue KiwiCaptcha challenge".into()))?;

    // Store the challenge record in Redis, keyed by nonce, with TTL.
    let record_json = serde_json::to_string(&issued.record)
        .map_err(|_| ApiError::Internal("failed to serialize KiwiCaptcha challenge".into()))?;

    let mut conn = state.redis.get().await?;
    let key = format!("{KIWI_CHALLENGE_PREFIX}{}", issued.record.nonce);
    let _: () = deadpool_redis::redis::AsyncCommands::set_ex(
        &mut *conn,
        &key,
        record_json,
        state.config.kiwi_challenge_ttl_secs,
    )
    .await?;

    challenge_cache().lock().put(&ip_hash, scope, issued.clone());

    tracing::debug!(
        scope = scope,
        ttl_secs = state.config.kiwi_challenge_ttl_secs,
        "KiwiCaptcha challenge issued"
    );

    Ok(Json(challenge_response(&issued)))
}

fn challenge_response(issued: &kiwicaptcha::Issued) -> ChallengeResponse {
    ChallengeResponse {
        nonce: issued.challenge.nonce.clone(),
        challenge: issued.challenge.challenge.clone(),
        salt: issued.challenge.salt.clone(),
        algorithm: issued.challenge.algorithm.as_str().to_string(),
        m_kib: issued.challenge.m_kib,
        t: issued.challenge.t,
        p: issued.challenge.p,
        target_bits: issued.challenge.target_bits,
        ttl_secs: issued.challenge.ttl_secs,
        min_duration_ms: issued.challenge.min_duration_ms,
        prefix: issued.challenge.prefix.clone(),
    }
}
