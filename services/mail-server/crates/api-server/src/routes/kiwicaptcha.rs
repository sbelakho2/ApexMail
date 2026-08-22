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

/// Outcome of the per-IP challenge-issuance rate-limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeRateLimit {
    /// Under the limit — issuance may proceed.
    Allowed,
    /// Over the limit — issuance must be rejected with 429.
    Exceeded,
    /// Redis is unavailable (L-26). Issuance must FAIL CLOSED (503):
    /// silently skipping the rate limit would let a bot mint unbounded
    /// single-use challenges while the store is degraded.
    RedisUnavailable,
}

/// The per-IP challenge issuance rate-limit check, extracted so it can be
/// unit-tested directly. Never silently allows on a Redis error.
async fn check_challenge_rate_limit(
    redis_pool: &deadpool_redis::Pool,
    ip_rate_key: &str,
) -> ChallengeRateLimit {
    let mut conn = match redis_pool.get().await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::error!(
                error = %error,
                "KiwiCaptcha rate-limit store unavailable — failing challenge issuance closed"
            );
            return ChallengeRateLimit::RedisUnavailable;
        }
    };

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
    .key(ip_rate_key)
    .arg(CHALLENGE_IP_RATE_LIMIT)
    .arg(CHALLENGE_IP_RATE_LIMIT_WINDOW_SECS)
    .invoke_async::<i64>(&mut *conn)
    .await
    .unwrap_or_else(|error| {
        tracing::error!(
            error = %error,
            "KiwiCaptcha rate-limit script failed — failing challenge issuance closed"
        );
        1
    });

    if count > 0 {
        ChallengeRateLimit::Exceeded
    } else {
        ChallengeRateLimit::Allowed
    }
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

    // Per-IP rate limiting: prevent bots from requesting thousands of
    // challenges. PRIVACY: the key is a keyed digest of the IP
    // (kiwicaptcha::hash_ip = sha256(secret||ip) with the kiwi secret as
    // pepper) — the raw client IP never appears in the Redis key.
    let ip_rate_key = format!(
        "apexmail:kiwi_challenge_rate:hmac:{}",
        kiwicaptcha::hash_ip(&client_ip, &state.config.kiwi_secret_key)
    );
    // L-26: fail CLOSED on Redis errors. The old `if let Ok(...)` silently
    // skipped the rate limit whenever the pool errored, letting bots mint
    // unbounded challenges exactly when the platform is degraded.
    match check_challenge_rate_limit(&state.redis, &ip_rate_key).await {
        ChallengeRateLimit::Allowed => {}
        ChallengeRateLimit::Exceeded => {
            tracing::warn!("KiwiCaptcha challenge rate limit exceeded");
            return Err(ApiError::RateLimited);
        }
        ChallengeRateLimit::RedisUnavailable => {
            return Err(ApiError::ServiceUnavailable(
                "captcha challenge store unavailable; please retry shortly".into(),
            ));
        }
    }

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64) // epoch MICROseconds — kiwicaptcha's issued_at_ns/now_ns unit
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
        binding_mode: kiwicaptcha::BindingMode::Bound,
        // Policy epoch 1: stamped into every issued record so outstanding
        // challenges can be invalidated wholesale on a future policy change
        // (verification currently does not pin an expected version).
        policy_version: 1,
        // Single-region, single-key deployment: no region/issuer binding and
        // kid 1 (the primary key) signs every challenge.
        region: None,
        issuer: None,
        kid: 1,
    };

    // Serve repeat requests from the same client (IP hash + scope) within the
    // cache window from memory — the challenge record is already in Redis from
    // the first issuance, so no extra Redis write happens per page load.
    let ip_hash = kiwicaptcha::hash_ip(&client_ip, &state.config.kiwi_secret_key);
    if let Some(issued) = challenge_cache().lock().get(&ip_hash, scope) {
        return Ok(Json(challenge_response(issued)));
    }

    // active_solves = 0: no solver-load accounting is wired up here, so
    // auto-tuning (when enabled via config) always sees an idle deployment.
    // request_binding = None: no application transaction is correlated with
    // the challenge at issuance.
    let issued = kiwicaptcha::issue_challenge(&kc_config, scope, &client_ip, now_unix, now_ns, 0, None)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// L-26 regression: when Redis is unreachable the issuance rate-limit
    /// check must report unavailability — never silently allow.
    #[tokio::test]
    async fn challenge_rate_limit_fails_closed_when_redis_is_down() {
        // Port 1 is guaranteed-closed on loopback; the pool is created lazily
        // so construction succeeds and the failure surfaces on acquire.
        let cfg = deadpool_redis::Config::from_url("redis://127.0.0.1:1/");
        let pool = cfg
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("pool construction is lazy");

        assert_eq!(
            check_challenge_rate_limit(&pool, "apexmail:kiwi_challenge_rate:hmac:test")
                .await,
            ChallengeRateLimit::RedisUnavailable,
            "a dead Redis must never silently allow challenge issuance"
        );
    }

    /// Against live Redis the check allows under the limit and rejects over
    /// it (skipped when no local Redis is available).
    #[tokio::test]
    async fn challenge_rate_limit_allows_then_exceeds_on_live_redis() {
        // F6: never probe the ambient 6379 — the variable must name the
        // Redis under test explicitly; unset means skip.
        let Ok(redis_url) = std::env::var("TEST_REDIS_URL") else {
            eprintln!("skipping: TEST_REDIS_URL not set");
            return;
        };
        let pool = match deadpool_redis::Config::from_url(&redis_url)
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

        let key = format!(
            "apexmail:kiwi_challenge_rate:hmac:test-{}",
            uuid::Uuid::new_v4()
        );
        if let Ok(mut conn) = pool.get().await {
            let _: Result<i64, _> = deadpool_redis::redis::cmd("DEL")
                .arg(&key)
                .query_async(&mut *conn)
                .await;
        }

        assert_eq!(
            check_challenge_rate_limit(&pool, &key).await,
            ChallengeRateLimit::Allowed
        );

        // Burn the rest of the allowance (already used one above), then one
        // more must exceed.
        for _ in 0..(CHALLENGE_IP_RATE_LIMIT - 1) {
            assert_eq!(
                check_challenge_rate_limit(&pool, &key).await,
                ChallengeRateLimit::Allowed
            );
        }
        assert_eq!(
            check_challenge_rate_limit(&pool, &key).await,
            ChallengeRateLimit::Exceeded
        );

        if let Ok(mut conn) = pool.get().await {
            let _: Result<i64, _> = deadpool_redis::redis::cmd("DEL")
                .arg(&key)
                .query_async(&mut *conn)
                .await;
        }
    }
}
