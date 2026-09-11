use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::net::{IpAddr, SocketAddr};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::routes::helpers::extract_cookie;
use crate::state::AppState;
use ipnetwork::IpNetwork;

const CP_SESSION_COOKIE_NAME: &str = "apexmail_cp_session";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpSessionClaims {
    pub sub: String,
    pub tenant_id: String,
    pub email: String,
    pub role: String,
    pub mfa_enabled: bool,
    pub iat: i64,
    pub last_active: i64,
    pub exp: i64,
}

#[derive(Debug, Clone)]
pub struct CpAuthUser {
    pub user_id: String,
    pub tenant_id: String,
    pub email: String,
    pub role: String,
}

fn validate_cidr_allowed(client_ip: IpAddr, allowed_ips: &[String]) -> bool {
    // An EMPTY allowlist is the explicit "every network" policy: the MFA and
    // admin/owner-role session requirements below are enforced regardless,
    // so the gate never silently degrades to fully-open by misconfiguration.
    if allowed_ips.is_empty() {
        return true;
    }

    allowed_ips.iter().any(|cidr| {
        cidr.trim()
            .parse::<IpNetwork>()
            .ok()
            .is_some_and(|net| net.contains(client_ip))
    })
}

pub fn create_cp_session_token(claims: &CpSessionClaims, secret: &str) -> String {
    let payload =
        serde_json::to_string(claims).expect("CpSessionClaims serialization should not fail");
    let payload_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        payload.as_bytes(),
    );

    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC-SHA256 key should be valid");
    mac.update(payload_b64.as_bytes());
    let sig = mac.finalize().into_bytes();
    let sig_b64 = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, sig);

    format!("{payload_b64}.{sig_b64}")
}

fn verify_cp_session_token(token: &str, secret: &str) -> Result<CpSessionClaims, ApiError> {
    let parts: Vec<&str> = token.rsplitn(2, '.').collect();
    if parts.len() != 2 {
        return Err(ApiError::Unauthorized(
            "invalid CP session token format".into(),
        ));
    }
    let (sig_str, payload_str) = (parts[0], parts[1]);

    let sig_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, sig_str)
            .map_err(|_| ApiError::Unauthorized("invalid CP session signature encoding".into()))?;

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| ApiError::Internal("HMAC key error".into()))?;
    mac.update(payload_str.as_bytes());

    mac.verify_slice(&sig_bytes)
        .map_err(|_| ApiError::Unauthorized("invalid CP session signature".into()))?;

    let payload_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        payload_str,
    )
    .map_err(|_| ApiError::Unauthorized("invalid CP session payload encoding".into()))?;

    serde_json::from_slice::<CpSessionClaims>(&payload_bytes)
        .map_err(|_| ApiError::Unauthorized("invalid CP session payload".into()))
}

pub(crate) fn build_cp_session_cookie(token: &str, max_age_secs: i64, secure: bool) -> String {
    format!(
        "{CP_SESSION_COOKIE_NAME}={token}; HttpOnly; Path=/; Max-Age={max_age_secs}; SameSite=Strict{}",
        if secure { "; Secure" } else { "" }
    )
}

/// Test-visible alias for the private verifier (app-level CP gate tests
/// confirm login-minted tokens verify against the configured secret).
#[cfg(test)]
pub(crate) fn verify_cp_session_token_for_tests(
    token: &str,
    secret: &str,
) -> Result<CpSessionClaims, ApiError> {
    verify_cp_session_token(token, secret)
}

/// Mint a fresh `apexmail_cp_session` cookie for an operator (the exact
/// claims shape [`require_cp_auth`] validates). The operator's REAL
/// `mfa_enabled` state is baked into the signed payload: a non-MFA
/// operator receives a structurally valid cookie the gate then refuses —
/// enforcement lives server-side, never in the login form.
pub(crate) fn issue_cp_session_cookie(
    cp_config: &crate::config::CpAuthConfig,
    user_id: &str,
    tenant_id: &str,
    email: &str,
    role: &str,
    mfa_enabled: bool,
    secure: bool,
) -> String {
    let now = Utc::now().timestamp();
    let claims = CpSessionClaims {
        sub: user_id.to_string(),
        tenant_id: tenant_id.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        mfa_enabled,
        iat: now,
        last_active: now,
        exp: now + cp_config.session_absolute_timeout_secs as i64,
    };
    let token = create_cp_session_token(&claims, &cp_config.session_secret);
    build_cp_session_cookie(
        &token,
        cp_config.session_absolute_timeout_secs as i64,
        secure,
    )
}

pub(crate) fn build_clear_cp_session_cookie(secure: bool) -> String {
    format!(
        "{CP_SESSION_COOKIE_NAME}=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict{}",
        if secure { "; Secure" } else { "" }
    )
}

pub async fn refresh_cp_session_activity(
    state: &AppState,
    existing: &CpSessionClaims,
) -> Result<(String, CpSessionClaims), ApiError> {
    let now = Utc::now().timestamp();
    let absolute_expiry = existing.iat + state.config.cp_auth.session_absolute_timeout_secs as i64;

    if now >= absolute_expiry || now >= existing.exp {
        return Err(ApiError::Unauthorized("CP session expired".into()));
    }

    let idle_deadline =
        existing.last_active + state.config.cp_auth.session_idle_timeout_secs as i64;
    if now > idle_deadline {
        return Err(ApiError::Unauthorized("CP session idle timeout".into()));
    }

    let updated = CpSessionClaims {
        sub: existing.sub.clone(),
        tenant_id: existing.tenant_id.clone(),
        email: existing.email.clone(),
        role: existing.role.clone(),
        mfa_enabled: existing.mfa_enabled,
        iat: existing.iat,
        last_active: now,
        exp: absolute_expiry,
    };

    let token = create_cp_session_token(&updated, &state.config.cp_auth.session_secret);
    Ok((token, updated))
}

/// Outcome of the shared CP-session verification ([`verify_cp_session`]).
pub(crate) enum CpAuthOutcome {
    /// Printed machine credentials pass without a CP session: the static
    /// control-plane key and system-tenant API keys authenticate as
    /// NON-user identities (no user_id). They are deliberately issued
    /// operator credentials for automation, not browser sessions, so the
    /// CP-session regime — which exists to keep human operator sessions
    /// MFA-backed and time-bounded — does not apply.
    MachineCredential,
    /// A verified human operator CP session.
    Verified(CpSessionVerification),
}

/// The verified session material the middleware inserts into the request
/// and replays as a refreshed cookie.
#[derive(Debug, Clone)]
pub(crate) struct CpSessionVerification {
    pub user: CpAuthUser,
    pub refreshed_token: String,
    pub refreshed_claims: CpSessionClaims,
}

/// Verify a CP session exactly the way the admin API gate does — one shared
/// implementation so the browser GET render path can never drift weaker than
/// the mutation path.
///
/// `bearer` is the request's ORDINARY authenticated identity
/// ([`AuthUser`]): the signed CP claims must name that same user and tenant,
/// so a CP cookie cannot be paired with somebody else's session. The live
/// row in `users` is then re-read on every call and must still be active
/// with an admin/owner role and MFA enabled — role demotions, MFA removal,
/// and deactivation take effect immediately instead of at session expiry.
/// The refreshed claims carry the LIVE role/MFA values.
pub(crate) async fn verify_cp_session(
    state: &AppState,
    headers: &HeaderMap,
    connect_info: Option<SocketAddr>,
    bearer: &AuthUser,
    path: &str,
) -> Result<CpAuthOutcome, ApiError> {
    // ── IP allowlist enforcement (fail closed) ──────────────
    // An EMPTY allowlist is the explicit "every network" policy. A
    // configured allowlist with an unresolvable peer address is a DENY:
    // missing client identity must never be treated as allowlisted.
    if !state.config.cp_auth.allowed_ips.is_empty() {
        match connect_info {
            Some(addr) if validate_cidr_allowed(addr.ip(), &state.config.cp_auth.allowed_ips) => {}
            Some(_) => {
                log_cp_access(
                    state,
                    None,
                    path,
                    StatusCode::FORBIDDEN.as_u16(),
                    "cp_ip_denied",
                )
                .await;
                return Err(ApiError::Forbidden(
                    "access denied from this network".into(),
                ));
            }
            None => {
                log_cp_access(
                    state,
                    None,
                    path,
                    StatusCode::FORBIDDEN.as_u16(),
                    "cp_ip_unavailable",
                )
                .await;
                return Err(ApiError::Forbidden(
                    "client address unavailable for the configured network allowlist".into(),
                ));
            }
        }
    }

    // ── Machine credentials pass without a CP session ───────
    if bearer.user_id.is_none() && bearer.tenant_id == "system" {
        log_cp_access(
            state,
            bearer.api_key_id.as_deref(),
            path,
            StatusCode::OK.as_u16(),
            "cp_machine_key",
        )
        .await;
        return Ok(CpAuthOutcome::MachineCredential);
    }

    // ── Extract CP session cookie ───────────────────────────
    let token = match extract_cookie(headers, CP_SESSION_COOKIE_NAME) {
        Some(t) if !t.is_empty() => t,
        _ => {
            log_cp_access(
                state,
                None,
                path,
                StatusCode::UNAUTHORIZED.as_u16(),
                "cp_missing_session",
            )
            .await;
            return Err(ApiError::Unauthorized(
                "control-plane authentication required".into(),
            ));
        }
    };

    // ── Verify token ────────────────────────────────────────
    let claims = match verify_cp_session_token(&token, &state.config.cp_auth.session_secret) {
        Ok(c) => c,
        Err(e) => {
            log_cp_access(
                state,
                None,
                path,
                StatusCode::UNAUTHORIZED.as_u16(),
                "cp_invalid_token",
            )
            .await;
            return Err(e);
        }
    };

    // ── Bind the claims to the ordinary authenticated identity ──
    // A structurally valid CP cookie for user A must not authorize a
    // request authenticated as user B (or another tenant).
    if bearer.user_id.as_deref() != Some(claims.sub.as_str())
        || bearer.tenant_id != claims.tenant_id
    {
        log_cp_access(
            state,
            Some(&claims.email),
            path,
            StatusCode::FORBIDDEN.as_u16(),
            "cp_identity_mismatch",
        )
        .await;
        return Err(ApiError::Forbidden(
            "CP session does not belong to the authenticated user".into(),
        ));
    }

    // ── Validate role ───────────────────────────────────────
    if !matches!(claims.role.as_str(), "admin" | "owner") {
        log_cp_access(
            state,
            Some(&claims.email),
            path,
            StatusCode::FORBIDDEN.as_u16(),
            "cp_insufficient_role",
        )
        .await;
        return Err(ApiError::Forbidden(
            "admin or owner role required for control plane".into(),
        ));
    }

    // ── Enforce MFA ─────────────────────────────────────────
    if !claims.mfa_enabled {
        log_cp_access(
            state,
            Some(&claims.email),
            path,
            StatusCode::FORBIDDEN.as_u16(),
            "cp_mfa_required",
        )
        .await;
        return Err(ApiError::Forbidden(
            "MFA is required for control-plane access".into(),
        ));
    }

    // ── Validate timeouts ───────────────────────────────────
    let now = Utc::now().timestamp();
    if now >= claims.exp {
        log_cp_access(
            state,
            Some(&claims.email),
            path,
            StatusCode::UNAUTHORIZED.as_u16(),
            "cp_session_expired",
        )
        .await;
        return Err(ApiError::Unauthorized("CP session expired".into()));
    }

    let idle_deadline = claims.last_active + state.config.cp_auth.session_idle_timeout_secs as i64;
    if now > idle_deadline {
        log_cp_access(
            state,
            Some(&claims.email),
            path,
            StatusCode::UNAUTHORIZED.as_u16(),
            "cp_session_idle",
        )
        .await;
        return Err(ApiError::Unauthorized(
            "CP session idle timeout — please log in again".into(),
        ));
    }

    // ── Re-read the LIVE role/MFA/status from the database ──
    // Signed claims are a snapshot from login time; authority must not
    // outlive a demotion or an MFA removal, so the current row is the only
    // source of truth for the authorization decision.
    let live: Option<(String, String, Option<bool>)> = sqlx::query_as(
        "SELECT status, role, mfa_enabled FROM users WHERE id = $1::uuid AND tenant_id = $2",
    )
    .bind(&claims.sub)
    .bind(&claims.tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "CP auth user recheck failed");
        ApiError::Internal("authentication error".into())
    })?;

    let (status, live_role, live_mfa) = match live {
        None => {
            log_cp_access(
                state,
                Some(&claims.email),
                path,
                StatusCode::UNAUTHORIZED.as_u16(),
                "cp_user_missing",
            )
            .await;
            return Err(ApiError::Unauthorized("user no longer exists".into()));
        }
        Some(row) => row,
    };

    if status != "active" {
        log_cp_access(
            state,
            Some(&claims.email),
            path,
            StatusCode::FORBIDDEN.as_u16(),
            "cp_user_inactive",
        )
        .await;
        return Err(ApiError::Forbidden(format!("account is {status}")));
    }

    if !matches!(live_role.as_str(), "admin" | "owner") {
        log_cp_access(
            state,
            Some(&claims.email),
            path,
            StatusCode::FORBIDDEN.as_u16(),
            "cp_role_revoked",
        )
        .await;
        return Err(ApiError::Forbidden(
            "admin or owner role required for control plane".into(),
        ));
    }

    if !live_mfa.unwrap_or(false) {
        log_cp_access(
            state,
            Some(&claims.email),
            path,
            StatusCode::FORBIDDEN.as_u16(),
            "cp_mfa_revoked",
        )
        .await;
        return Err(ApiError::Forbidden(
            "MFA is required for control-plane access".into(),
        ));
    }

    // ── Refresh session active timestamp with the LIVE values ───
    let live_claims = CpSessionClaims {
        role: live_role.clone(),
        mfa_enabled: true,
        ..claims.clone()
    };
    let (new_token, updated_claims) = refresh_cp_session_activity(state, &live_claims).await?;

    let cp_user = CpAuthUser {
        user_id: claims.sub.clone(),
        tenant_id: claims.tenant_id.clone(),
        email: claims.email.clone(),
        role: live_role,
    };

    log_cp_access(
        state,
        Some(&cp_user.email),
        path,
        StatusCode::OK.as_u16(),
        "cp_access",
    )
    .await;

    Ok(CpAuthOutcome::Verified(CpSessionVerification {
        user: cp_user,
        refreshed_token: new_token,
        refreshed_claims: updated_claims,
    }))
}

/// Build the `Set-Cookie` value that replays a refreshed CP session.
pub(crate) fn refreshed_cp_cookie(
    state: &AppState,
    verification: &CpSessionVerification,
) -> String {
    build_cp_session_cookie(
        &verification.refreshed_token,
        state.config.cp_auth.session_absolute_timeout_secs as i64,
        state.config.environment.is_production(),
    )
}

pub async fn require_cp_auth(
    axum::extract::State(state): axum::extract::State<AppState>,
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, ApiError> {
    let path = req.uri().path().to_string();

    // `require_auth` runs before this gate on the admin router and always
    // populates the ordinary identity; without it there is nothing to bind
    // the CP claims to, so fail closed rather than trust bare claims.
    let bearer = req.extensions().get::<AuthUser>().cloned().ok_or_else(|| {
        ApiError::Unauthorized("authentication required for control-plane access".into())
    })?;

    match verify_cp_session(
        &state,
        req.headers(),
        connect_info.map(|ci| ci.0),
        &bearer,
        &path,
    )
    .await?
    {
        CpAuthOutcome::MachineCredential => Ok(next.run(req).await),
        CpAuthOutcome::Verified(verification) => {
            let (mut parts, body) = req.into_parts();
            parts.extensions.insert(verification.user.clone());
            parts
                .extensions
                .insert(verification.refreshed_claims.clone());
            req = axum::http::Request::from_parts(parts, body);

            let mut response = next.run(req).await;

            let cookie = refreshed_cp_cookie(&state, &verification);
            // APPEND, never insert: `insert` replaces every existing
            // Set-Cookie value on the response — including the signed flash
            // cookie every CP form handler sets — so "Tenant suspended /
            // Operator invited" feedback never reached the browser.
            response
                .headers_mut()
                .append("Set-Cookie", cookie.parse().expect("valid cookie header"));

            Ok(response)
        }
    }
}

async fn log_cp_access(
    state: &AppState,
    email: Option<&str>,
    path: &str,
    status_code: u16,
    outcome: &str,
) {
    let redacted = email.map(|e| {
        if e.contains('@') {
            mail_common::pii::redact_email(e).to_string()
        } else {
            format!("id#{}", e.chars().take(8).collect::<String>())
        }
    });

    tracing::info!(
        target: "cp_access",
        email = ?redacted,
        path = %path,
        status = status_code,
        outcome = %outcome,
        "CP access event"
    );

    let status_ok = status_code < 400;
    let _ = sqlx::query(
        "INSERT INTO cp_access_log (id, email, path, status_code, outcome, created_at)
         VALUES (gen_random_uuid(), $1, $2, $3, $4, NOW())",
    )
    .bind(redacted)
    .bind(path)
    .bind(status_code as i32)
    .bind(if status_ok { "allowed" } else { outcome })
    .execute(&state.db)
    .await;
}

#[axum::async_trait]
impl FromRequestParts<AppState> for CpAuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<CpAuthUser>()
            .cloned()
            .ok_or_else(|| ApiError::Unauthorized("control-plane authentication required".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> String {
        "test-cp-session-secret-1234567890ab".into()
    }

    #[test]
    fn test_cp_session_token_roundtrip() {
        let claims = CpSessionClaims {
            sub: "usr_test_001".into(),
            tenant_id: "ten_test_001".into(),
            email: "admin@apexmail.ee".into(),
            role: "admin".into(),
            mfa_enabled: true,
            iat: 1000000,
            last_active: 1000000,
            exp: 2000000,
        };

        let token = create_cp_session_token(&claims, &test_secret());
        let decoded = verify_cp_session_token(&token, &test_secret()).unwrap();

        assert_eq!(decoded.sub, claims.sub);
        assert_eq!(decoded.role, claims.role);
        assert_eq!(decoded.mfa_enabled, claims.mfa_enabled);
        assert_eq!(decoded.iat, claims.iat);
    }

    #[test]
    fn test_cp_session_token_tamper_detection() {
        let claims = CpSessionClaims {
            sub: "usr_test_001".into(),
            tenant_id: "ten_test_001".into(),
            email: "admin@apexmail.ee".into(),
            role: "admin".into(),
            mfa_enabled: true,
            iat: 1000000,
            last_active: 1000000,
            exp: 2000000,
        };

        let token = create_cp_session_token(&claims, &test_secret());
        // Flip a byte in the signature to simulate tampering
        let mut tampered = token.clone();
        let last_char = tampered.pop().unwrap();
        tampered.push(if last_char == 'A' { 'B' } else { 'A' });

        assert!(verify_cp_session_token(&tampered, &test_secret()).is_err());
    }

    #[test]
    fn test_cp_session_token_wrong_secret() {
        let claims = CpSessionClaims {
            sub: "usr_test_001".into(),
            tenant_id: "ten_test_001".into(),
            email: "admin@apexmail.ee".into(),
            role: "admin".into(),
            mfa_enabled: true,
            iat: 1000000,
            last_active: 1000000,
            exp: 2000000,
        };

        let token = create_cp_session_token(&claims, &test_secret());
        assert!(verify_cp_session_token(&token, "different-secret-key-here-xxxx").is_err());
    }

    #[test]
    fn test_cidr_validation() {
        let allowed = vec!["10.0.0.0/8".into(), "127.0.0.1/32".into()];

        assert!(validate_cidr_allowed(
            "127.0.0.1".parse().unwrap(),
            &allowed
        ));
        assert!(validate_cidr_allowed("10.5.5.5".parse().unwrap(), &allowed));
        assert!(!validate_cidr_allowed(
            "192.168.1.1".parse().unwrap(),
            &allowed
        ));
        // Empty allowlist is the explicit allow-every-network policy (MFA +
        // role enforcement is independent of it).
        assert!(validate_cidr_allowed("192.168.1.1".parse().unwrap(), &[]));
    }

    // ─── Middleware behaviour (DB-gated; soft-skip without infra) ───

    mod middleware_tests {
        use super::*;
        use axum::body::Body;
        use axum::http::Request;
        use std::sync::Arc;
        use tower::ServiceExt;

        /// AppState over a canonical fixture pool with the CP knobs the
        /// individual test needs. Returns None (soft skip) without
        /// TEST_DATABASE_URL or an reachable TEST_REDIS_URL — the gate's
        /// per-request user recheck and audit insert need both.
        async fn gate_state(
            test_name: &str,
            allowed_ips: Vec<String>,
        ) -> Option<(AppState, sqlx::PgPool)> {
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

            sqlx::raw_sql(
                "CREATE TABLE IF NOT EXISTS cp_access_log (
                     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                     email VARCHAR(320),
                     path VARCHAR(1024) NOT NULL,
                     status_code INTEGER NOT NULL,
                     outcome VARCHAR(64) NOT NULL,
                     created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                 )",
            )
            .execute(&pool)
            .await
            .expect("cp_access_log fixture DDL must apply");

            let mut config = crate::app::test_support::test_config();
            config.cp_auth.allowed_ips = allowed_ips;
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
                    config,
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
                    crate::resilience::ResilientClient::new_from_config(
                        &crate::app::test_support::test_config(),
                    ),
                );
            Some((state, pool))
        }

        /// Minimal router carrying ONLY the gate + a probe handler.
        fn gate_router(state: AppState) -> axum::Router {
            axum::Router::new()
                .route("/v1/admin/probe", axum::routing::get(|| async { "ok" }))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    require_cp_auth,
                ))
                .with_state(state)
        }

        async fn seed_operator(db: &sqlx::PgPool, mfa_enabled: bool) -> (String, String) {
            let email = format!("cp-mw-{}@apexmail.ee", uuid::Uuid::new_v4().simple());
            let user_id = uuid::Uuid::new_v4();
            // Canonical users.tenant_id FKs to tenants(id): the real chain has
            // no bare 'system' tenant, so seed it before the operator.
            sqlx::query(
                "INSERT INTO tenants (id, name, slug, plan, status)
                 VALUES ('system', 'System', 'system-cp-mw', 'enterprise', 'active')
                 ON CONFLICT (id) DO NOTHING",
            )
            .execute(db)
            .await
            .expect("seed system tenant");
            sqlx::query(
                "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status,
                                    email_verified, mfa_enabled, metadata, created_at, updated_at)
                 VALUES ($1, 'system', $2, 'Op', 'x', 'admin', 'active', true, $3, '{}'::jsonb, NOW(), NOW())",
            )
            .bind(user_id)
            .bind(&email)
            .bind(mfa_enabled)
            .execute(db)
            .await
            .expect("seed operator");
            (user_id.to_string(), email)
        }

        fn cp_cookie_header(
            state: &AppState,
            user_id: &str,
            email: &str,
            mfa_enabled: bool,
        ) -> String {
            cp_cookie_header_with_role(state, user_id, email, "admin", mfa_enabled)
        }

        fn cp_cookie_header_with_role(
            state: &AppState,
            user_id: &str,
            email: &str,
            role: &str,
            mfa_enabled: bool,
        ) -> String {
            let now = Utc::now().timestamp();
            let claims = CpSessionClaims {
                sub: user_id.to_string(),
                tenant_id: "system".into(),
                email: email.to_string(),
                role: role.into(),
                mfa_enabled,
                iat: now,
                last_active: now,
                exp: now + 3600,
            };
            let token = create_cp_session_token(&claims, &state.config.cp_auth.session_secret);
            format!("{CP_SESSION_COOKIE_NAME}={token}")
        }

        /// The ordinary authenticated identity the gate binds CP claims to
        /// (require_auth populates this before require_cp_auth runs).
        fn cp_auth_user(user_id: &str) -> crate::middleware::auth::AuthUser {
            crate::middleware::auth::AuthUser {
                tenant_id: "system".into(),
                user_id: Some(user_id.to_string()),
                api_key_id: None,
                session_id: None,
                scopes: vec!["*".into()],
            }
        }

        #[tokio::test]
        async fn ip_outside_allowlist_is_forbidden_even_with_valid_session() {
            let Some((state, db)) =
                gate_state("cp_ip_outside_allowlist", vec!["10.0.0.0/8".to_string()]).await
            else {
                return;
            };
            let (user_id, email) = seed_operator(&db, true).await;
            let cookie = cp_cookie_header(&state, &user_id, &email, true);
            let app = gate_router(state.clone());

            let request = Request::get("/v1/admin/probe")
                .header("cookie", &cookie)
                // The gate reads the peer address from ConnectInfo (inserted
                // by into_make_service_with_connect_info in production).
                .extension(axum::extract::ConnectInfo(
                    "192.168.1.50:40000"
                        .parse::<std::net::SocketAddr>()
                        .unwrap(),
                ))
                .extension(cp_auth_user(&user_id))
                .body(Body::empty())
                .unwrap();
            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);

            // The denial is auditable.
            let outcome: Option<String> = sqlx::query_scalar(
                "SELECT outcome FROM cp_access_log WHERE path = '/v1/admin/probe' LIMIT 1",
            )
            .fetch_optional(&db)
            .await
            .unwrap()
            .flatten();
            assert_eq!(outcome.as_deref(), Some("cp_ip_denied"));
        }

        /// Fix 2: a configured allowlist must FAIL CLOSED when the peer
        /// address cannot be established — a missing ConnectInfo is a deny,
        /// never an implicit allowlist pass.
        #[tokio::test]
        async fn missing_connect_info_with_allowlist_is_denied() {
            let Some((state, db)) =
                gate_state("cp_ip_missing_connect_info", vec!["10.0.0.0/8".to_string()]).await
            else {
                return;
            };
            let (user_id, email) = seed_operator(&db, true).await;
            let cookie = cp_cookie_header(&state, &user_id, &email, true);
            let app = gate_router(state.clone());

            // No ConnectInfo extension: the old conditional skipped the
            // allowlist entirely and admitted the session.
            let response = app
                .oneshot(
                    Request::get("/v1/admin/probe")
                        .header("cookie", &cookie)
                        .extension(cp_auth_user(&user_id))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "an unresolvable client address must not satisfy a configured allowlist"
            );

            let outcome: Option<String> = sqlx::query_scalar(
                "SELECT outcome FROM cp_access_log
                 WHERE path = '/v1/admin/probe' AND outcome = 'cp_ip_unavailable' LIMIT 1",
            )
            .fetch_optional(&db)
            .await
            .unwrap()
            .flatten();
            assert_eq!(outcome.as_deref(), Some("cp_ip_unavailable"));
        }

        #[tokio::test]
        async fn machine_credentials_bypass_the_session_requirement() {
            let Some((state, _db)) = gate_state("cp_machine_bypass", vec![]).await else {
                return;
            };
            let app = gate_router(state.clone());

            let mut request = Request::get("/v1/admin/probe").body(Body::empty()).unwrap();
            request
                .extensions_mut()
                .insert(crate::middleware::auth::AuthUser {
                    tenant_id: "system".into(),
                    user_id: None,
                    api_key_id: Some("static-cp-key".into()),
                    session_id: None,
                    scopes: vec!["*".into()],
                });
            let response = app.oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "static-key/system API-key identities are deliberate machine \
                 credentials, not browser sessions"
            );
        }

        #[tokio::test]
        async fn idle_timeout_rejects_stale_cp_sessions() {
            let Some((state, db)) = gate_state("cp_idle_timeout", vec![]).await else {
                return;
            };
            let (user_id, email) = seed_operator(&db, true).await;
            // last_active far in the past: beyond the 900s idle window.
            let stale = Utc::now().timestamp() - 10_000;
            let claims = CpSessionClaims {
                sub: user_id.clone(),
                tenant_id: "system".into(),
                email,
                role: "admin".into(),
                mfa_enabled: true,
                iat: stale,
                last_active: stale,
                exp: Utc::now().timestamp() + 3600,
            };
            let token = create_cp_session_token(&claims, &state.config.cp_auth.session_secret);
            let app = gate_router(state);

            let response = app
                .oneshot(
                    Request::get("/v1/admin/probe")
                        .header("cookie", format!("{CP_SESSION_COOKIE_NAME}={token}"))
                        .extension(cp_auth_user(&user_id))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn inactive_operator_session_is_rejected_on_recheck() {
            let Some((state, db)) = gate_state("cp_inactive_recheck", vec![]).await else {
                return;
            };
            let (user_id, email) = seed_operator(&db, true).await;
            // Deactivate AFTER minting: the per-request recheck must catch it.
            sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1::uuid")
                .bind(&user_id)
                .execute(&db)
                .await
                .expect("suspend operator");
            let cookie = cp_cookie_header(&state, &user_id, &email, true);
            let app = gate_router(state);

            let response = app
                .oneshot(
                    Request::get("/v1/admin/probe")
                        .header("cookie", &cookie)
                        .extension(cp_auth_user(&user_id))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }

        /// Fix 3: a role demotion AFTER login (the signed claims still say
        /// admin) must be caught by the live DB recheck on the next request.
        #[tokio::test]
        async fn demoted_role_is_rejected_on_live_recheck() {
            let Some((state, db)) = gate_state("cp_role_demoted", vec![]).await else {
                return;
            };
            let (user_id, email) = seed_operator(&db, true).await;
            // The cookie was minted while the user was an admin.
            let cookie = cp_cookie_header(&state, &user_id, &email, true);
            sqlx::query("UPDATE users SET role = 'viewer' WHERE id = $1::uuid")
                .bind(&user_id)
                .execute(&db)
                .await
                .expect("demote operator");
            let app = gate_router(state);

            let response = app
                .oneshot(
                    Request::get("/v1/admin/probe")
                        .header("cookie", &cookie)
                        .extension(cp_auth_user(&user_id))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "a live role demotion must revoke CP authority immediately"
            );
        }

        /// Fix 3: MFA removal AFTER login must be caught by the live DB
        /// recheck even though the signed claims still say mfa_enabled=true.
        #[tokio::test]
        async fn mfa_disabled_after_login_is_rejected_on_live_recheck() {
            let Some((state, db)) = gate_state("cp_mfa_revoked", vec![]).await else {
                return;
            };
            let (user_id, email) = seed_operator(&db, true).await;
            let cookie = cp_cookie_header(&state, &user_id, &email, true);
            sqlx::query("UPDATE users SET mfa_enabled = false WHERE id = $1::uuid")
                .bind(&user_id)
                .execute(&db)
                .await
                .expect("disable operator MFA");
            let app = gate_router(state);

            let response = app
                .oneshot(
                    Request::get("/v1/admin/probe")
                        .header("cookie", &cookie)
                        .extension(cp_auth_user(&user_id))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "removing MFA must revoke CP authority immediately"
            );
        }

        /// Fix 3: CP claims are bound to the ordinary authenticated
        /// identity — a valid CP cookie for user A cannot authorize a
        /// request authenticated as user B.
        #[tokio::test]
        async fn cp_session_for_a_different_user_is_rejected() {
            let Some((state, db)) = gate_state("cp_identity_mismatch", vec![]).await else {
                return;
            };
            let (user_id, email) = seed_operator(&db, true).await;
            let (other_user_id, _other_email) = seed_operator(&db, true).await;
            let cookie = cp_cookie_header(&state, &user_id, &email, true);
            let app = gate_router(state);

            let response = app
                .oneshot(
                    Request::get("/v1/admin/probe")
                        .header("cookie", &cookie)
                        .extension(cp_auth_user(&other_user_id))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
    }
}
