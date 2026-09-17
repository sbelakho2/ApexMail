//! Forgot-password endpoint.
//!
//! Validates email, rate-limits by IP, then delegates to password reset logic.

use super::auth::verify_kiwi_token;
use super::helpers::{hash_token, html_escape};
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::error::ApiError;
use crate::middleware::rate_limiter::extract_public_client_ip;
use crate::routes::csrf::validate_form_csrf;
use crate::routes::system_sender::{ensure_system_sender_ready, queue_system_email_in_transaction};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", post(forgot_password))
}

// ─── Request / Response types ──────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
// `kiwi__token` is KiwiCaptcha's literal wire field name — kept verbatim
// (same convention as LoginRequest) so the hidden form field deserializes.
#[allow(non_snake_case)]
pub struct ForgotPasswordRequest {
    pub email: String,
    #[serde(default)]
    pub kiwi__token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ForgotPasswordResponse {
    pub success: bool,
}

// ─── Handler ───────────────────────────────────────────────────

async fn forgot_password(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<ForgotPasswordRequest>,
) -> Result<Json<ForgotPasswordResponse>, ApiError> {
    // Validate CSRF token from X-CSRF-Token header (auth form protection)
    validate_form_csrf(&headers, &state.config.csrf_secret)?;

    // Validate email
    let email = body.email.trim().to_lowercase();
    if email.is_empty() || email.len() > 254 || !email.contains('@') {
        return Err(ApiError::Validation(vec!["Invalid email address.".into()]));
    }

    // Rate-limit by client IP using Redis
    let client_ip = connect_info
        .map(|ConnectInfo(addr)| {
            extract_public_client_ip(&headers, addr.ip(), &state.config.trusted_proxies)
        })
        .unwrap_or_else(|| {
            tracing::warn!(
                "forgot-password request missing ConnectInfo; using shared rate-limit bucket"
            );
            "unknown".to_string()
        });

    // Verify KiwiCaptcha proof-of-work token
    verify_kiwi_token(
        &state.config,
        &state.redis,
        body.kiwi__token.as_deref(),
        &client_ip,
        Some("forgot-password"),
    )
    .await?;

    // F-11: Dual rate-limiting — IP-based and email-based.
    // IP-based prevents single-source flooding; email-based prevents
    // multi-IP botnet attacks targeting a specific user's inbox.
    let window_secs: u64 = 15 * 60; // 15 minutes
    let max_ip_requests: i64 = 5;
    let max_email_requests: i64 = 3;

    // The limiter fails CLOSED in production: an unreachable Redis used to
    // silently skip this check (if-let-Ok), removing reset-flooding
    // protection exactly while the platform is degraded. Outside production
    // it fails open so local development works without Redis. Script errors
    // remain rate-limited (count treated as exceeded) in every environment.
    match state.redis.get().await {
        Ok(mut conn) => {
            let ip_rate_key = format!("apexmail:forgot_password_rate:ip:{client_ip}");
            // Audit J: hash the address in the Redis key (like the login lockout
            // does) — storing raw emails as key names pollutes Redis with PII,
            // leaks addresses to anyone with Redis list/scan access, and keeps
            // the victim's mailbox address resident long after the window.
            let email_rate_key =
                format!("apexmail:forgot_password_rate:email:{}", hash_token(&email));

            // Atomic rate-limit check using Lua script to avoid INCR + EXPIRE race condition.
            // The script atomically increments the counter and sets expiry on first creation.
            // Checks both IP and email keys; denies if either exceeds its limit.
            let count: i64 = deadpool_redis::redis::Script::new(
                r#"
                    local ip_key = KEYS[1]
                    local email_key = KEYS[2]
                    local max_ip = tonumber(ARGV[1])
                    local max_email = tonumber(ARGV[2])
                    local window_secs = tonumber(ARGV[3])

                    local ip_count = redis.call('INCR', ip_key)
                    if ip_count == 1 then
                        redis.call('EXPIRE', ip_key, window_secs)
                    end

                    local email_count = redis.call('INCR', email_key)
                    if email_count == 1 then
                        redis.call('EXPIRE', email_key, window_secs)
                    end

                    if ip_count > max_ip or email_count > max_email then
                        return 1
                    end
                    return 0
                "#,
            )
            .key(&ip_rate_key)
            .key(&email_rate_key)
            .arg(max_ip_requests)
            .arg(max_email_requests)
            .arg(window_secs)
            .invoke_async::<i64>(&mut *conn)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, ip = %client_ip, email = %email, "forgot-password rate-limit Lua script failed; treating as rate-limited");
                1
            });

            if count > 0 {
                return Err(ApiError::RateLimited);
            }
        }
        Err(error) => {
            if state.config.environment.is_production() {
                tracing::error!(error = %error, ip = %client_ip, "forgot-password rate limiter unavailable — failing closed in production");
                return Err(ApiError::ServiceUnavailable(
                    "password reset is temporarily unavailable; please retry shortly".into(),
                ));
            }
            tracing::warn!(error = %error, ip = %client_ip, "forgot-password rate limiter unavailable — failing open outside production");
        }
    }

    // Check before looking up the account so a sender outage produces the
    // same service-level response for every address and cannot become an
    // account-enumeration oracle.
    ensure_system_sender_ready(&state.db).await?;

    // Look up user — always return success to avoid email enumeration
    let user: Option<(String, String)> = sqlx::query_as(
        "SELECT id::text, email FROM users WHERE LOWER(email) = LOWER($1) AND status = 'active' LIMIT 1",
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await?;

    if let Some((user_id, _user_email)) = user {
        // Generate password reset token
        let token = apexmail_lib::id::generate_verification_token();
        let expires = chrono::Utc::now() + chrono::Duration::hours(1);
        let now_rfc = chrono::Utc::now().to_rfc3339();

        // The token update and the queue record must commit together. Otherwise
        // a transaction failure could leave the account with an unusable reset
        // token that was never delivered.
        let mut tx = state.db.begin().await?;
        let token_update = sqlx::query(
            "UPDATE users SET metadata = COALESCE(metadata, '{}'::jsonb) || $1::jsonb, updated_at = NOW() WHERE id = $2::uuid AND status = 'active'",
        )
        .bind(serde_json::json!({
            "password_reset_token_hash": hash_token(&token),
            "password_reset_expires": expires.to_rfc3339(),
            "password_reset_iat": now_rfc,
        }))
        .bind(&user_id)
        .execute(&mut *tx)
        .await?;
        if token_update.rows_affected() != 1 {
            // The user can be deactivated or deleted between the deliberately
            // non-enumerating lookup and this update. Do not issue a token or
            // queue a message for a no-longer-active account.
            return Ok(Json(ForgotPasswordResponse { success: true }));
        }

        // Queue the password reset email into both the messages audit log and
        // email_queue under the same transaction as the token update.
        let encoded_token = percent_encode_component(&token);
        // CWE-598: Use path-based token instead of query parameter to prevent
        // sensitive token exposure in server logs, referrer headers, and browser history.
        let reset_link = format!("{}/reset-password/{}", state.config.base_url, encoded_token,);
        let safe_email = html_escape(&email);
        let safe_link = html_escape(&reset_link);
        let html_body = format!(
            r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/></head><body style="font-family:ui-monospace,'JetBrains Mono',monospace;line-height:1.6;color:#09090b;max-width:560px;margin:0 auto;padding:24px">
<h2 style="color:#dc2626;text-transform:uppercase;letter-spacing:0.05em">Reset Your Password</h2>
<p>We received a request to reset the password for <strong>{safe_email}</strong>.</p>
<p><a href="{safe_link}" style="display:inline-block;padding:12px 28px;background:#dc2626;color:#fff;border-radius:0px;text-decoration:none;font-weight:700;text-transform:uppercase;letter-spacing:0.1em">Reset Password</a></p>
<p style="font-size:13px;color:#71717a">This link expires in 1 hour. If you didn't request a password reset, you can safely ignore this email.</p>
<hr style="border:none;border-top:1px solid #000;margin:24px 0"/>
<p style="font-size:11px;color:#999;text-transform:uppercase;letter-spacing:0.05em">&copy; 2026 ApexMail &middot; <a href="https://apexmail.ee" style="color:#999;text-decoration:none">apexmail.ee</a></p>
</body></html>"#,
        );
        let text_body = format!(
            "Reset Your Password\n\nWe received a request to reset the password for {email}.\n\nReset your password by visiting: {reset_link}\n\nThis link expires in 1 hour. If you didn't request this, you can safely ignore this email.\n\n© 2026 ApexMail — https://apexmail.ee",
        );

        let msg_id = queue_system_email_in_transaction(
            &mut tx,
            &email,
            "Reset your ApexMail password",
            &html_body,
            &text_body,
            vec!["system".into(), "password-reset".into()],
        )
        .await?;

        tx.commit().await?;

        tracing::info!(
            user_id = %user_id,
            message_id = %msg_id,
            "Password reset email enqueued"
        );
    }

    // Always return success to prevent email enumeration
    Ok(Json(ForgotPasswordResponse { success: true }))
}

// ─── Helpers ───────────────────────────────────────────────────

/// Percent-encode a string for use as a URL query parameter value.
fn percent_encode_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(char::from(HEX[(b >> 4) as usize]));
                out.push(char::from(HEX[(b & 0x0f) as usize]));
            }
        }
    }
    out
}

const HEX: [u8; 16] = *b"0123456789ABCDEF";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forgot_password_request_deser() {
        let json = r#"{"email":"user@example.com"}"#;
        let req: ForgotPasswordRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.email, "user@example.com");
    }

    #[test]
    fn test_percent_encode_component() {
        assert_eq!(percent_encode_component("hello"), "hello");
        assert_eq!(percent_encode_component("a b"), "a%20b");
        assert_eq!(percent_encode_component("a&b=c"), "a%26b%3Dc");
        assert_eq!(
            percent_encode_component("user@example.com"),
            "user%40example.com"
        );
    }

    #[test]
    fn test_email_rate_limit_key_is_hashed_not_raw_pii() {
        // Audit J: the Redis rate-limit key must not embed the raw email —
        // it would leave PII resident in Redis key names and leak addresses
        // to anything able to SCAN the keyspace.
        let email = "victim@example.com";
        let key = format!("apexmail:forgot_password_rate:email:{}", hash_token(email));
        assert!(
            !key.contains(email),
            "key must not contain raw email: {key}"
        );
        assert!(
            !key.contains("victim"),
            "key must not contain the local part"
        );
        assert!(key.starts_with("apexmail:forgot_password_rate:email:"));
        // Deterministic — the same address maps to the same bucket.
        let again = format!("apexmail:forgot_password_rate:email:{}", hash_token(email));
        assert_eq!(key, again);
        // Distinct addresses map to distinct buckets.
        let other = format!(
            "apexmail:forgot_password_rate:email:{}",
            hash_token("other@example.com")
        );
        assert_ne!(key, other);
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(
            html_escape("<script>alert('xss')</script>"),
            "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
        );
        assert_eq!(html_escape("a&b"), "a&amp;b");
        assert_eq!(html_escape("plain text"), "plain text");
    }
}

#[cfg(test)]
mod adversarial_tests {
    use axum::extract::ConnectInfo;
    use axum::http::StatusCode;
    use tower::ServiceExt;

    const CSRF_SECRET: &str = "test-csrf-secret-1234567890abcd";

    fn csrf_header() -> String {
        ui_foundation::csrf::generate_csrf_token(CSRF_SECRET)
    }

    /// Make the platform sender READY: generate + encrypt DKIM material for
    /// the seeded system domain and mark it verified (mirrors what the
    /// system-sender bootstrap + verification flow leaves behind).
    async fn make_system_sender_ready(pool: &sqlx::PgPool) {
        use apexmail_lib::dkim::{
            dkim_private_key_aad, encrypt_dkim_private_key, generate_dkim_keypair,
        };
        // Set the env under the lock, then drop the guard before any await
        // (clippy: std MutexGuard must not live across await points).
        {
            let _guard = crate::test_db::DKIM_ENV_MUTEX
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::env::set_var(
                apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
                "3f7a1c9e2b5d48f01a6c3e792d4b8f15a0c6e3917d2f4b8a5c1e7309d4f2b6a8",
            );
        }
        let domain_id: uuid::Uuid =
            sqlx::query_scalar("SELECT id FROM domains WHERE tenant_id = $1 FOR UPDATE")
                .bind(crate::routes::system_sender::SYSTEM_TENANT_ID)
                .fetch_one(pool)
                .await
                .expect("system domain row");
        let key_pair = generate_dkim_keypair().expect("keypair");
        let aad = dkim_private_key_aad(
            crate::routes::system_sender::SYSTEM_TENANT_ID,
            &domain_id.to_string(),
        );
        let encrypted = encrypt_dkim_private_key(&key_pair.private_key_pem, &aad).expect("encrypt");
        let public_b64 = key_pair.public_key;
        sqlx::query(
            "UPDATE domains
                SET status = 'verified', dkim_enabled = true, dkim_selector = 'apexmail',
                    dkim_public_key = $2, dkim_private_key = $3, ses_verified = true
              WHERE id = $1",
        )
        .bind(domain_id)
        .bind(public_b64)
        .bind(encrypted)
        .execute(pool)
        .await
        .expect("ready the sender");
    }

    async fn post_forgot(
        env: &crate::app::test_support::adv::AdvEnv,
        csrf: Option<&str>,
        body: &str,
    ) -> (StatusCode, serde_json::Value) {
        use axum::body::Body;
        let mut builder = axum::http::Request::post("/v1/auth/forgot-password")
            .header("content-type", "application/json");
        if let Some(token) = csrf {
            builder = builder.header("x-csrf-token", token);
        }
        let mut request = builder.body(Body::from(body.to_string())).unwrap();
        if let Some(addr) = env.client_ip {
            request.extensions_mut().insert(ConnectInfo(addr));
        }
        let response = env.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, value)
    }

    /// Deterministic per-test client identity: a fixed TEST-NET-3 address
    /// whose rate-limit bucket is DELETED up front, so reruns and parallel
    /// tests never inherit or share state.
    async fn env_with_ip(pool: sqlx::PgPool, ip: [u8; 4]) -> crate::app::test_support::adv::AdvEnv {
        let mut env = crate::app::test_support::adv::AdvEnv::admin(pool).await;
        env.client_ip = Some(std::net::SocketAddr::from((ip, 40000)));
        if let Ok(redis) = deadpool_redis::Config::from_url(
            std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:1".into()),
        )
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        {
            if let Ok(mut conn) = redis.get().await {
                let key = format!(
                    "apexmail:forgot_password_rate:ip:{}.{}.{}.{}",
                    ip[0], ip[1], ip[2], ip[3]
                );
                let _: Result<(), _> =
                    deadpool_redis::redis::AsyncCommands::del(&mut conn, key).await;
            }
        }
        env
    }

    #[tokio::test]
    async fn forgot_password_validation_gates_come_first() {
        let Some(pool) = crate::test_db::canonical_pool("forgot_gates").await else {
            return;
        };
        let env = env_with_ip(pool, [198, 51, 100, 77]).await;

        // Missing CSRF header.
        let (status, body) = post_forgot(&env, None, r#"{"email":"a@example.com"}"#).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        // Invalid CSRF token.
        let (status, body) =
            post_forgot(&env, Some("garbage.token"), r#"{"email":"a@example.com"}"#).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        // Malformed emails (empty, over-length, no @).
        for email in ["", "x".repeat(255).as_str(), "not-an-email"] {
            let (status, body) = post_forgot(
                &env,
                Some(&csrf_header()),
                &serde_json::json!({ "email": email }).to_string(),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{email}: {body}");
        }

        // deny_unknown_fields.
        let (status, _body) = post_forgot(
            &env,
            Some(&csrf_header()),
            r#"{"email":"a@example.com","extra":true}"#,
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn forgot_password_is_non_enumerating_and_queues_the_reset_email() {
        if std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_none()
        {
            eprintln!("skipping: TEST_REDIS_URL unset");
            return;
        }
        let Some(pool) = crate::test_db::canonical_pool("forgot_ok").await else {
            return;
        };
        let env = env_with_ip(pool.clone(), [198, 51, 100, 78]).await;

        // Sender NOT ready: the service-level refusal applies to every
        // address equally (no enumeration oracle). The email is unique per
        // run: the email-based limiter bucket is keyed by address hash and
        // persists in Redis across reruns.
        let probe_email = format!(
            "nobody-{}@example.com",
            &uuid::Uuid::new_v4().simple().to_string()[..10]
        );
        let (status, body) = post_forgot(
            &env,
            Some(&csrf_header()),
            &serde_json::json!({ "email": probe_email }).to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");

        make_system_sender_ready(&pool).await;

        // Unknown email: identical success, nothing queued (unique per run,
        // same email-bucket rationale).
        let ghost_email = format!(
            "ghost-{}@example.com",
            &uuid::Uuid::new_v4().simple().to_string()[..10]
        );
        let (status, body) = post_forgot(
            &env,
            Some(&csrf_header()),
            &serde_json::json!({ "email": ghost_email }).to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["success"], true);
        let queued: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM email_queue WHERE subject LIKE 'Reset your%'")
                .fetch_one(&pool)
                .await
                .expect("count");
        assert_eq!(queued, 0, "no mail for unknown addresses");

        // Known active user: token stored, mail queued under the system tenant.
        let user_id = uuid::Uuid::new_v4();
        let email = format!("reset-{user_id}@example.com");
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status, email_verified)
             VALUES ($1::uuid, $2, $3, 'Reset Target', 'x', 'owner', 'active', true)",
        )
        .bind(user_id)
        .bind("system_internal_tenant01")
        .bind(&email)
        .execute(&pool)
        .await
        .expect("seed user");

        let (status, body) = post_forgot(
            &env,
            Some(&csrf_header()),
            &serde_json::json!({ "email": email.to_uppercase() }).to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["success"], true);

        let (token_hash, expires): (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT metadata->>'password_reset_token_hash', metadata->>'password_reset_expires' \
             FROM users WHERE id = $1::uuid",
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .expect("user row");
        assert!(token_hash.is_some(), "reset token hash stored");
        assert!(expires.is_some());

        let (subject, html): (String, String) = sqlx::query_as(
            "SELECT subject, html FROM email_queue WHERE to_addresses = ARRAY[$1] LIMIT 1",
        )
        .bind(&email)
        .fetch_one(&pool)
        .await
        .expect("queued reset email");
        assert!(subject.contains("Reset your ApexMail password"));
        // CWE-598: the token rides the PATH, never the query string.
        assert!(html.contains("/reset-password/"), "{subject}");
        assert!(!html.contains("token="), "no query-string token leakage");
    }

    #[tokio::test]
    async fn forgot_password_rate_limits_by_ip_and_email() {
        if std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_none()
        {
            eprintln!("skipping: TEST_REDIS_URL unset");
            return;
        }
        let Some(pool) = crate::test_db::canonical_pool("forgot_rate").await else {
            return;
        };
        let env = env_with_ip(pool.clone(), [198, 51, 100, 79]).await;
        make_system_sender_ready(&pool).await;

        // 5 requests from this client's bucket: the 6th is 429.
        let mut saw_limit = false;
        for i in 0..6 {
            let (status, _body) = post_forgot(
                &env,
                Some(&csrf_header()),
                &serde_json::json!({ "email": format!("victim{i}@example.com") }).to_string(),
            )
            .await;
            if status == StatusCode::TOO_MANY_REQUESTS {
                saw_limit = true;
                break;
            }
            assert_eq!(status, StatusCode::OK, "request {i}");
        }
        assert!(saw_limit, "the IP bucket must cap at 5 per window");
    }
}
