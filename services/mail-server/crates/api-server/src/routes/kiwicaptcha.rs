//! KiwiCaptcha challenge issuance endpoint.
//!
//! `POST /api/kcaptcha/challenge` (and `/v1/kcaptcha/challenge`) mints a new
//! memory-hard proof-of-work challenge, stores it in Redis (single-use, TTL'd,
//! IP-bound), and returns the challenge parameters to the inline widget script.

use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::error::ApiError;
use crate::middleware::rate_limiter::extract_public_client_ip;
use crate::state::AppState;

/// The Redis key prefix under which issued KiwiCaptcha challenges are stored.
/// (Mirrors the constant in `routes::auth` — kept here so this module is standalone.)
const KIWI_CHALLENGE_PREFIX: &str = "apexmail:kiwi:";

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
    #[serde(rename = "mKib")]
    pub m_kib: u32,
    #[serde(rename = "t")]
    pub t: u32,
    #[serde(rename = "p")]
    pub p: u32,
    #[serde(rename = "targetBits")]
    pub target_bits: u32,
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
            m_kib: 8,
            t: 1,
            p: 1,
            target_bits: 1,
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

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let kc_config = kiwicaptcha::ChallengeConfig {
        secret_key: state.config.kiwi_secret_key.clone(),
        m_kib: state.config.kiwi_pbkdf2_iterations,
        t: state.config.kiwi_argon_t,
        p: state.config.kiwi_argon_p,
        target_bits: state.config.kiwi_difficulty_bits,
        ttl_secs: state.config.kiwi_challenge_ttl_secs,
    };

    let issued = kiwicaptcha::issue_challenge(&kc_config, scope, &client_ip, now_unix)
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

    tracing::debug!(
        scope = scope,
        ttl_secs = state.config.kiwi_challenge_ttl_secs,
        "KiwiCaptcha challenge issued"
    );

    Ok(Json(ChallengeResponse {
        nonce: issued.challenge.nonce,
        challenge: issued.challenge.challenge,
        salt: issued.challenge.salt,
        m_kib: issued.challenge.m_kib,
        t: issued.challenge.t,
        p: issued.challenge.p,
        target_bits: issued.challenge.target_bits,
        prefix: issued.challenge.prefix,
    }))
}
