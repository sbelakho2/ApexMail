//! Forgot-password endpoint.
//!
//! Validates email, rate-limits by IP, then delegates to password reset logic.

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
use crate::state::AppState;

const SYSTEM_TENANT_ID: &str = "system_internal_tenant01";

pub fn router() -> Router<AppState> {
    Router::new().route("/", post(forgot_password))
}

// ─── Request / Response types ──────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForgotPasswordRequest {
    pub email: String,
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

    // F-11: Dual rate-limiting — IP-based and email-based.
    // IP-based prevents single-source flooding; email-based prevents
    // multi-IP botnet attacks targeting a specific user's inbox.
    let window_secs: u64 = 15 * 60; // 15 minutes
    let max_ip_requests: i64 = 5;
    let max_email_requests: i64 = 3;

    if let Ok(mut conn) = state.redis.get().await {
        let ip_rate_key = format!("apexmail:forgot_password_rate:ip:{client_ip}");
        let email_rate_key = format!("apexmail:forgot_password_rate:email:{}", &email);

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
        .unwrap_or(0);

        if count > 0 {
            return Err(ApiError::RateLimited);
        }
    }

    // Look up user — always return success to avoid email enumeration
    let user: Option<(String, String)> = sqlx::query_as(
        "SELECT id, email FROM users WHERE LOWER(email) = LOWER($1) AND status = 'active' LIMIT 1",
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await?;

    if let Some((user_id, _user_email)) = user {
        // Generate password reset token
        let token = apexmail_lib::id::generate_verification_token();
        let expires = chrono::Utc::now() + chrono::Duration::hours(1);
        let now_rfc = chrono::Utc::now().to_rfc3339();

        // Store reset token in user metadata
        sqlx::query(
            "UPDATE users SET metadata = metadata || $1::jsonb, updated_at = NOW() WHERE id = $2",
        )
        .bind(serde_json::json!({
            "password_reset_token_hash": hash_token(&token),
            "password_reset_expires": expires.to_rfc3339(),
            "password_reset_iat": now_rfc,
        }))
        .bind(&user_id)
        .execute(&state.db)
        .await?;

        tracing::info!(
            user_id = %user_id,
            "Password reset token generated"
        );

        // Enqueue the password reset email into both the messages audit log
        // and the email_queue so the worker processor delivers it.
        let encoded_token = percent_encode_component(&token);
        let encoded_email_param = percent_encode_component(&email);
        let reset_link = format!(
            "{}/reset-password?token={}&email={}",
            state.config.base_url, encoded_token, encoded_email_param,
        );
        let msg_id = apexmail_lib::id::generate_id("msg", 22);
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

        // 1. Insert into messages table (audit/log)
        sqlx::query(
            "INSERT INTO messages (id, tenant_id, from_email, to_emails, subject, html_body, text_body, status, tags, created_at)
             VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, 'queued', $8::jsonb, NOW())",
        )
        .bind(&msg_id)
        .bind(SYSTEM_TENANT_ID)
        .bind("noreply@apexmail.ee")
        .bind(serde_json::json!([email]))
        .bind("Reset your ApexMail password")
        .bind(&html_body)
        .bind(&text_body)
        .bind(serde_json::json!(["system", "password-reset"]))
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to enqueue password reset email");
            ApiError::Internal("Failed to send reset email".into())
        })?;

        // 2. Look up the domain_id for "apexmail.ee" (system domain).
        //    Falls back to a synthetic ID if the domain is not yet registered.
        let domain_id: String = sqlx::query_scalar(
            "SELECT id FROM domains WHERE domain = 'apexmail.ee' LIMIT 1",
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to look up system domain");
            ApiError::Internal("Failed to send reset email".into())
        })?
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
        .bind(&msg_id)
        .bind(SYSTEM_TENANT_ID)
        .bind(&domain_id)
        .bind("noreply@apexmail.ee")
        .bind(&email)
        .bind("Reset your ApexMail password")
        .bind(&html_body)
        .bind(&text_body)
        .bind(serde_json::json!(["system", "password-reset"]))
        .bind(Option::<serde_json::Value>::None) // metadata
        .bind(Option::<chrono::DateTime<chrono::Utc>>::None) // scheduled_at
        .bind(now)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to enqueue password reset email to worker queue");
            ApiError::Internal("Failed to send reset email".into())
        })?;

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
    fn test_html_escape() {
        assert_eq!(
            html_escape("<script>alert('xss')</script>"),
            "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
        );
        assert_eq!(html_escape("a&b"), "a&amp;b");
        assert_eq!(html_escape("plain text"), "plain text");
    }
}
