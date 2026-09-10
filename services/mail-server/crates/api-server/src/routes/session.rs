//! Session introspection endpoint.
//!
//! Provides current session state including impersonation status.

use super::helpers::extract_cookie;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::error::ApiError;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(get_session))
}

// ─── Response types ────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub authenticated: bool,
    pub impersonation: Option<ImpersonationInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<serde_json::Value>,
    /// Why a presented credential was refused (revoked, expired,
    /// over-age, unknown user, …). Absent for authenticated callers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ImpersonationInfo {
    pub tenant_id: String,
    pub operator_id: String,
    pub operator_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

fn e2e_bypass_enabled(
    debug_build: bool,
    environment: crate::config::Environment,
    e2e_mode: Option<&str>,
    bypass_key: Option<&str>,
) -> bool {
    debug_build
        && !environment.is_production()
        && matches!(e2e_mode, Some("true"))
        && matches!(bypass_key, Some(key) if !key.is_empty())
}

// ─── Handler ───────────────────────────────────────────────────

async fn get_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SessionResponse>, ApiError> {
    // Check for E2E bypass (debug builds only, non-production only)
    let e2e_mode = std::env::var("E2E_TEST_MODE").ok();
    let expected_bypass_key = std::env::var("E2E_BYPASS_KEY").ok();
    if e2e_bypass_enabled(
        cfg!(debug_assertions),
        state.config.environment,
        e2e_mode.as_deref(),
        expected_bypass_key.as_deref(),
    ) {
        if let Some(provided) = headers.get("x-e2e-bypass-key") {
            if let (Ok(provided_str), Some(expected)) =
                (provided.to_str(), expected_bypass_key.as_deref())
            {
                if constant_time_eq(provided_str.as_bytes(), expected.as_bytes()) {
                    return Ok(Json(SessionResponse {
                        authenticated: true,
                        impersonation: None,
                        session_type: Some("e2e".into()),
                        user: None,
                        reason: None,
                    }));
                }
            }
        }
    }

    let mut response = SessionResponse {
        authenticated: false,
        impersonation: None,
        session_type: None,
        user: None,
        reason: None,
    };

    // Check for impersonation session cookie. HMAC + expiry alone vouch
    // nothing about server state, so every presentation is revalidated
    // against the stores routes/impersonate.rs wrote at exchange time
    // (jti tombstone, absolute lifetime cap, operator status). Failures
    // surface as authenticated:false plus a reason — the endpoint's
    // contract is a state report, not an error status.
    let impersonation_token = extract_cookie(&headers, "impersonation_session");
    if let Some(token) = impersonation_token {
        match verify_session_token(&token, &state.config.session_secret) {
            Ok(payload) if payload.token_type.as_deref() == Some("impersonation") => {
                match revalidate_impersonation_session(&state, &payload).await {
                    Ok(()) => {
                        response.authenticated = true;
                        response.impersonation = Some(ImpersonationInfo {
                            tenant_id: payload.tenant_id.unwrap_or_default(),
                            operator_id: payload.operator_id.unwrap_or_default(),
                            operator_name: payload
                                .operator_name
                                .unwrap_or_else(|| "Operator".into()),
                            exp: payload.exp,
                            expires_at: payload.exp,
                        });
                        response.session_type = Some("impersonation".into());
                    }
                    Err(reason) => {
                        tracing::warn!(reason = %reason, "impersonation session refused on revalidation");
                        response.reason = Some(reason);
                    }
                }
            }
            // A correctly signed but non-impersonation token in this
            // cookie authenticates nothing.
            Ok(_) => {}
            Err(error) => {
                response.reason = Some(error.to_string());
            }
        }
    }

    // Check regular user session if no impersonation
    if !response.authenticated {
        let user_token = extract_cookie(&headers, "am_session").or_else(|| {
            headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .map(|s| s.to_string())
        });

        if let Some(token) = user_token {
            // Route the SAME validation require_auth performs — blacklist,
            // revocation registry, per-request status recheck, absolute
            // lifetime — so introspection can never vouch for a token the
            // API surface would refuse. Failures surface as
            // authenticated:false plus a human-readable reason (the
            // endpoint's contract is a state report, not an error status).
            // Introspection is not bound to one route; the tenant gate runs
            // with the session endpoint's own method/path (introspection
            // stays reachable for suspended tenants as a state report).
            match crate::middleware::auth::authenticate_jwt(
                &token,
                &axum::http::Method::GET,
                "/v1/session/introspect",
                &state,
            )
            .await
            {
                Ok(auth_user) => {
                    let profile: Option<(String, String, Option<String>, String)> = sqlx::query_as(
                        "SELECT id::text, email, name, role FROM users
                             WHERE id = $1::uuid AND tenant_id = $2 AND status = 'active'",
                    )
                    .bind(auth_user.user_id.clone().unwrap_or_default())
                    .bind(&auth_user.tenant_id)
                    .fetch_optional(&state.db)
                    .await
                    .ok()
                    .flatten();
                    if let Some((id, email, name, role)) = profile {
                        response.authenticated = true;
                        response.session_type = Some("user".into());
                        response.user = Some(serde_json::json!({
                            "id": id,
                            "email": email,
                            "name": name,
                            "role": role,
                        }));
                    } else {
                        response.reason = Some("user account is no longer active".into());
                    }
                }
                Err(error) => {
                    tracing::debug!(error = %error, "session introspection rejected a token");
                    response.reason = Some(error.to_string());
                }
            }
        }
    }

    Ok(Json(response))
}

// ─── Helpers ───────────────────────────────────────────────────

/// RS-064: Constant-time comparison that does NOT leak length through timing.
/// Uses a dummy comparison loop when lengths differ to avoid short-circuiting.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let len_matches = a.len() == b.len();
    // Always iterate over the longer of the two to avoid timing leaks.
    // When lengths differ, compare against self (result is discarded).
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter().chain(a.iter().cycle())) {
        diff |= x ^ y;
    }
    // If lengths don't match, ensure result is false regardless of XOR outcome
    len_matches && diff == 0
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionPayload {
    #[serde(rename = "type")]
    token_type: Option<String>,
    /// The wire format is camelCase (see routes/impersonate.rs's mint):
    /// `deny_unknown_fields` makes a missing rename a hard deserialize
    /// failure, not a silently-null field.
    #[serde(rename = "tenantId")]
    tenant_id: Option<String>,
    #[serde(rename = "operatorId")]
    operator_id: Option<String>,
    #[serde(rename = "operatorName")]
    operator_name: Option<String>,
    /// `jti` of the single-use impersonation token the session was minted
    /// from (routes/impersonate.rs mints it as `tokenId`). Mandatory for
    /// revalidation.
    #[serde(rename = "tokenId")]
    token_id: Option<String>,
    exp: Option<i64>,
}

fn verify_session_token(token: &str, secret: &str) -> Result<SessionPayload, ApiError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    // Token format:base64url(payload).base64url(signature)
    let parts: Vec<&str> = token.rsplitn(2, '.').collect();
    if parts.len() != 2 {
        return Err(ApiError::Unauthorized(
            "invalid session token format".into(),
        ));
    }
    let (sig_part, payload_part) = (parts[0], parts[1]);

    // Verify HMAC
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| ApiError::Internal("HMAC key error".into()))?;
    mac.update(payload_part.as_bytes());

    let sig_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, sig_part)
            .map_err(|_| {
                ApiError::Unauthorized("invalid session token signature encoding".into())
            })?;

    mac.verify_slice(&sig_bytes)
        .map_err(|_| ApiError::Unauthorized("invalid session token signature".into()))?;

    // Decode payload
    let payload_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        payload_part,
    )
    .map_err(|_| ApiError::Unauthorized("invalid session token payload".into()))?;

    let payload: SessionPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|_| ApiError::Unauthorized("invalid session token payload".into()))?;

    // Expiry is MANDATORY: an optional check let a correctly signed token
    // without `exp` authenticate forever (the same audit-D class fixed for
    // impersonation tokens in routes/impersonate.rs).
    let exp = payload
        .exp
        .ok_or_else(|| ApiError::Unauthorized("session token missing expiry".into()))?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    if now_ms > exp {
        return Err(ApiError::Unauthorized("session token expired".into()));
    }

    Ok(payload)
}

/// Server-side maximum impersonation-SESSION lifetime. The session payload
/// carries no `iat`, so the absolute cap is enforced as "exp must not
/// promise more than one hour of validity from the evaluation point" —
/// the same 1-hour ceiling `MAX_IMPERSONATION_TOKEN_TTL_MS` imposed on
/// the token at exchange time in routes/impersonate.rs.
const MAX_IMPERSONATION_SESSION_TTL_MS: i64 = 60 * 60 * 1000;

/// True when `exp_ms` stays within the one-hour absolute cap relative to
/// `now_ms`. Separated for unit testing.
fn impersonation_lifetime_within_cap(exp_ms: i64, now_ms: i64) -> bool {
    exp_ms - now_ms <= MAX_IMPERSONATION_SESSION_TTL_MS
}

/// Revalidate an impersonation session against server-side state.
///
/// Every introspection re-derives liveness from the same stores the token
/// exchange wrote:
///
///   * jti tombstone — `apexmail:impersonation_used:{jti}` is `SET NX`'d
///     at exchange with a TTL ≥ the session's remaining life, so its
///     existence proves the session was minted by a single-use exchange
///     that has not outlived its recorded validity. A missing tombstone
///     means forged jti, Redis flush, or a stale cookie — all refused,
///     failing closed exactly like the exchange itself does on Redis
///     unavailability.
///   * absolute lifetime cap — [`MAX_IMPERSONATION_SESSION_TTL_MS`].
///   * operator status — a deactivated operator's live cookies must stop
///     vouching immediately; the operator resolves by user id or email
///     against the users table the control plane manages.
async fn revalidate_impersonation_session(
    state: &AppState,
    payload: &SessionPayload,
) -> Result<(), String> {
    let now_ms = chrono::Utc::now().timestamp_millis();

    let exp = payload
        .exp
        .ok_or_else(|| "impersonation session missing expiry".to_string())?;
    if !impersonation_lifetime_within_cap(exp, now_ms) {
        return Err("impersonation session exceeds the maximum lifetime".into());
    }

    let jti = payload
        .token_id
        .as_deref()
        .filter(|jti| !jti.is_empty())
        .ok_or_else(|| "impersonation session missing token ID".to_string())?;

    let tombstone_key = format!("apexmail:impersonation_used:{jti}");
    // Both the command error and a pool-acquisition failure land in the
    // same error arm below: fail closed either way.
    let tombstone_exists: Result<bool, String> = match state.redis.get().await {
        Ok(mut conn) => {
            deadpool_redis::redis::AsyncCommands::exists::<_, bool>(&mut *conn, &tombstone_key)
                .await
                .map_err(|error| error.to_string())
        }
        Err(error) => Err(format!("redis pool acquisition failed: {error}")),
    };
    match tombstone_exists {
        Ok(true) => {}
        Ok(false) => return Err("impersonation session is no longer active".into()),
        Err(error) => {
            tracing::error!(error = %error, "Redis unavailable revalidating impersonation session");
            return Err("impersonation session could not be revalidated".into());
        }
    }

    let operator_id = payload
        .operator_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .ok_or_else(|| "impersonation session missing operator".to_string())?;
    let operator_status: Option<String> = sqlx::query_scalar(
        "SELECT status FROM users WHERE id::text = $1 OR LOWER(email) = LOWER($1) LIMIT 1",
    )
    .bind(operator_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| {
        tracing::error!(error = %error, "operator status recheck failed for impersonation session");
        "impersonation session could not be revalidated".to_string()
    })?;
    match operator_status.as_deref() {
        Some("active") => Ok(()),
        // A missing row is a deleted operator — treated exactly like a
        // deactivated one: the session stops vouching.
        _ => Err("impersonation operator is no longer active".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            "am_session=abc123; impersonation_session=xyz789"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            extract_cookie(&headers, "am_session"),
            Some("abc123".into())
        );
        assert_eq!(
            extract_cookie(&headers, "impersonation_session"),
            Some("xyz789".into())
        );
        assert_eq!(extract_cookie(&headers, "nonexistent"), None);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }

    // ── Impersonation-session revalidation (pure parts) ──────────

    /// Mint a session cookie with the exact payload shape
    /// routes/impersonate.rs emits (`payload.signature`, HMAC-SHA256,
    /// base64url). Local signer so these tests do not depend on another
    /// module's private helper.
    fn mint_impersonation_session(payload: &serde_json::Value, secret: &str) -> String {
        use base64::Engine;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(payload).unwrap());
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(payload_b64.as_bytes());
        let sig_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{payload_b64}.{sig_b64}")
    }

    fn impersonation_session_payload(exp: i64) -> serde_json::Value {
        serde_json::json!({
            "type": "impersonation",
            "tenantId": "ten_demo",
            "operatorId": "op_1",
            "operatorName": "Op",
            "tokenId": "jti-1",
            "exp": exp,
        })
    }

    #[test]
    fn session_payload_with_token_id_deserializes() {
        // Regression: SessionPayload carries deny_unknown_fields and used
        // to lack `tokenId` — every cookie minted by routes/impersonate.rs
        // FAILED to deserialize, so the impersonation branch silently
        // reported unauthenticated for all real sessions.
        let now_ms = chrono::Utc::now().timestamp_millis();
        let token =
            mint_impersonation_session(&impersonation_session_payload(now_ms + 60_000), "secret");
        let payload = verify_session_token(&token, "secret").expect("minted shape must verify");
        assert_eq!(payload.token_type.as_deref(), Some("impersonation"));
        assert_eq!(payload.token_id.as_deref(), Some("jti-1"));
        assert_eq!(payload.tenant_id.as_deref(), Some("ten_demo"));
    }

    #[test]
    fn session_token_without_expiry_is_rejected() {
        // Expiry used to be optional — a signed token with no `exp` was
        // valid forever.
        let mut payload = impersonation_session_payload(0);
        payload.as_object_mut().unwrap().remove("exp");
        let token = mint_impersonation_session(&payload, "secret");
        assert!(verify_session_token(&token, "secret").is_err());
    }

    #[test]
    fn session_token_expired_is_rejected() {
        let expired = chrono::Utc::now().timestamp_millis() - 1_000;
        let token = mint_impersonation_session(&impersonation_session_payload(expired), "secret");
        assert!(verify_session_token(&token, "secret").is_err());
    }

    #[test]
    fn session_token_wrong_signature_is_rejected() {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let token = mint_impersonation_session(
            &impersonation_session_payload(now_ms + 60_000),
            "right-secret",
        );
        assert!(verify_session_token(&token, "wrong-secret").is_err());
    }

    #[test]
    fn impersonation_lifetime_cap_arithmetic() {
        let now_ms = 1_000_000_000i64;
        // Freshly minted 30-minute session: within the 1-hour cap.
        assert!(impersonation_lifetime_within_cap(
            now_ms + 30 * 60 * 1000,
            now_ms
        ));
        // Exactly one hour: still within (cap is inclusive).
        assert!(impersonation_lifetime_within_cap(
            now_ms + MAX_IMPERSONATION_SESSION_TTL_MS,
            now_ms
        ));
        // Two hours: over the cap — a cookie whose signature promised more
        // than the exchange could ever have granted must be refused.
        assert!(!impersonation_lifetime_within_cap(
            now_ms + 2 * 60 * 60 * 1000,
            now_ms
        ));
    }

    #[test]
    fn test_e2e_bypass_enabled_only_for_debug_non_production() {
        assert!(e2e_bypass_enabled(
            true,
            crate::config::Environment::Development,
            Some("true"),
            Some("secret"),
        ));
        assert!(e2e_bypass_enabled(
            true,
            crate::config::Environment::Staging,
            Some("true"),
            Some("secret"),
        ));
        assert!(!e2e_bypass_enabled(
            false,
            crate::config::Environment::Development,
            Some("true"),
            Some("secret"),
        ));
        assert!(!e2e_bypass_enabled(
            true,
            crate::config::Environment::Production,
            Some("true"),
            Some("secret"),
        ));
        assert!(!e2e_bypass_enabled(
            true,
            crate::config::Environment::Development,
            Some("false"),
            Some("secret"),
        ));
        assert!(!e2e_bypass_enabled(
            true,
            crate::config::Environment::Development,
            Some("true"),
            Some(""),
        ));
    }

    // ─── Revocation/expiry parity with authenticate_jwt (DB+Redis) ───

    mod introspection_tests {
        use super::*;
        use axum::body::Body;
        use std::sync::Arc;
        use tower::ServiceExt;

        /// Router + pool over a canonical fixture database with a real RSA
        /// signing pair and reachable Redis (the token blacklist + session
        /// revocation lookups require it). Soft-skips without infra.
        async fn introspection_app(
            test_name: &str,
        ) -> Option<(axum::Router, sqlx::PgPool, crate::config::Config)> {
            let pool = crate::test_db::canonical_pool(test_name).await?;
            let redis_url = std::env::var("TEST_REDIS_URL").ok()?;
            let redis = deadpool_redis::Config::from_url(&redis_url)
                .create_pool(Some(deadpool_redis::Runtime::Tokio1))
                .ok()?;
            let mut conn = redis.get().await.ok()?;
            let ping: Result<String, _> = deadpool_redis::redis::cmd("PING")
                .query_async(&mut *conn)
                .await;
            if ping.is_err() {
                eprintln!("skipping {test_name}: TEST_REDIS_URL unreachable");
                return None;
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

            let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(aws_sdk_sesv2::config::Region::new("us-east-1"))
                .load()
                .await;
            let ses_provider = Arc::new(crate::ses_provider::SesIpProvider::new(
                aws_sdk_sesv2::Client::new(&aws_config),
                pool.clone(),
                "apexmail".into(),
                "us-east-1".into(),
            ));
            let state =
                crate::state::AppStateInner::with_ddos_protector(
                    pool.clone(),
                    apexmail_db::pool::PoolPair {
                        rw: pool.clone(),
                        ro: pool.clone(),
                    },
                    redis,
                    config.clone(),
                    reqwest::Client::new(),
                    (*ses_provider).clone(),
                    None,
                    Arc::new(
                        ddos_protection::DdosProtector::new(
                            ddos_protection::ProtectorConfig::default(),
                        )
                        .await
                        .expect("ddos protector"),
                    ),
                    None,
                    None,
                    crate::resilience::ResilientClient::new_from_config(&config),
                );
            Some((
                axum::Router::new().merge(router()).with_state(state),
                pool,
                config,
            ))
        }

        async fn seed_active_user(db: &sqlx::PgPool) -> (String, String) {
            let tenant = apexmail_lib::id::generate_id("intro", 18);
            let user_id = uuid::Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO tenants (id, name, slug, status) VALUES ($1, 'Intro Co', $2, 'active')",
            )
            .bind(&tenant)
            .bind(format!("intro-{tenant}"))
            .execute(db)
            .await
            .expect("seed tenant");
            sqlx::query(
                "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status, email_verified)
                 VALUES ($1::uuid, $2, $3, 'Intro User', 'x', 'owner', 'active', true)",
            )
            .bind(&user_id)
            .bind(&tenant)
            .bind(format!("intro-{}@example.com", user_id))
            .execute(db)
            .await
            .expect("seed user");
            (tenant, user_id)
        }

        fn mint_session_jwt(
            config: &crate::config::Config,
            tenant_id: &str,
            user_id: &str,
            iat: i64,
            ttl_secs: i64,
        ) -> String {
            let claims = crate::middleware::auth::JwtClaims {
                sub: user_id.to_string(),
                tenant_id: tenant_id.to_string(),
                scopes: vec!["*".into()],
                exp: iat + ttl_secs,
                iat,
                jti: uuid::Uuid::new_v4().to_string(),
                typ: Some("session".into()),
            };
            let key =
                jsonwebtoken::EncodingKey::from_rsa_pem(config.jwt_private_key_pem.as_bytes())
                    .expect("encoding key");
            jsonwebtoken::encode(
                &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
                &claims,
                &key,
            )
            .expect("sign session jwt")
        }

        async fn introspect(app: &axum::Router, token: &str) -> serde_json::Value {
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::get("/")
                        .header("cookie", format!("am_session={token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .expect("introspection dispatch");
            assert_eq!(response.status(), axum::http::StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice(&body).expect("json body")
        }

        /// A session revoked by a password reset must introspect as
        /// unauthenticated WITH a reason — the endpoint previously decoded
        /// the JWT and never consulted the revocation registry.
        #[tokio::test]
        async fn introspection_reports_revoked_sessions_as_unauthenticated() {
            let Some((app, db, config)) = introspection_app("intro_revoked").await else {
                return;
            };
            let (tenant, user) = seed_active_user(&db).await;
            let token = mint_session_jwt(
                &config,
                &tenant,
                &user,
                chrono::Utc::now().timestamp(),
                3600,
            );

            // Simulate the password-reset revocation marker.
            let revocation_key = format!("apexmail:session_revoked_after:{tenant}:{user}");
            let mut conn = {
                let url = std::env::var("TEST_REDIS_URL").unwrap();
                deadpool_redis::Config::from_url(&url)
                    .create_pool(Some(deadpool_redis::Runtime::Tokio1))
                    .unwrap()
                    .get()
                    .await
                    .unwrap()
            };
            let _: Result<(), _> = deadpool_redis::redis::AsyncCommands::set_ex(
                &mut *conn,
                &revocation_key,
                chrono::Utc::now().timestamp() + 1,
                300u64,
            )
            .await;

            let body = introspect(&app, &token).await;
            assert_eq!(
                body["authenticated"], false,
                "a revoked session must not introspect as authenticated: {body}"
            );
            let reason = body["reason"].as_str().unwrap_or_default();
            assert!(
                reason.to_lowercase().contains("revok"),
                "the reason must say the session was revoked, got: {reason}"
            );
        }

        /// Sessions older than the 7-day absolute lifetime ceiling must be
        /// refused even when their exp claim is still in the future.
        #[tokio::test]
        async fn introspection_enforces_the_absolute_session_lifetime() {
            let Some((app, db, config)) = introspection_app("intro_absolute_ttl").await else {
                return;
            };
            let (tenant, user) = seed_active_user(&db).await;
            // Issued 8 days ago, exp 30 days out: cryptographically valid,
            // beyond the absolute ceiling.
            let token = mint_session_jwt(
                &config,
                &tenant,
                &user,
                chrono::Utc::now().timestamp() - 8 * 24 * 3600,
                30 * 24 * 3600,
            );

            let body = introspect(&app, &token).await;
            assert_eq!(
                body["authenticated"], false,
                "an over-age session must not introspect as authenticated: {body}"
            );
        }

        /// A healthy, current session still introspects fully.
        #[tokio::test]
        async fn introspection_admits_current_sessions() {
            let Some((app, db, config)) = introspection_app("intro_current").await else {
                return;
            };
            let (tenant, user) = seed_active_user(&db).await;
            let token = mint_session_jwt(
                &config,
                &tenant,
                &user,
                chrono::Utc::now().timestamp(),
                3600,
            );

            let body = introspect(&app, &token).await;
            assert_eq!(body["authenticated"], true, "body: {body}");
            assert_eq!(body["session_type"], "user");
            assert!(body["user"]["id"].as_str() == Some(user.as_str()));
        }
    }
}
