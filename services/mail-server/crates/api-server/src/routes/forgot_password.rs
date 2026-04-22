//! Forgot-password endpoint.
//!
//! Migrated from apps/web/src/app/api/auth/forgot-password/route.ts.
//! Validates email, rate-limits by IP, then delegates to password reset logic.

use super::helpers::{hash_token, html_escape};
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::state::AppState;

const SYSTEM_TENANT_ID: &str = "system_internal_tenant01";

pub fn router() -> Router<AppState> {
    Router::new().route("/", post(forgot_password))
}

// ─── Request / Response types ──────────────────────────────────

#[derive(Debug, Deserialize)]
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
    headers: HeaderMap,
    Json(body): Json<ForgotPasswordRequest>,
) -> Result<Json<ForgotPasswordResponse>, ApiError> {
// Validate email
    let email = body.email.trim().to_lowercase();
    if email.is_empty() || email.len() > 254 || !email.contains('@') {
        return Err(ApiError::Validation(vec!["Invalid email address.".into()]));
    }

// Rate-limit by client IP using Redis
    let client_ip = extract_client_ip(&headers)
        .unwrap_or_else(|| "unknown".into());

    let rate_key = format!("apexmail:forgot_password_rate:{client_ip}");
    let window_secs: u64 = 15 * 60; // 15 minutes
    let max_requests: i64 = 5;

    if let Ok(mut conn) = state.redis.get().await {
        let count: i64 = deadpool_redis::redis::cmd("INCR")
            .arg(&rate_key)
            .query_async(&mut *conn)
            .await
            .unwrap_or(1);

        if count == 1 {
// Set expiry on first request in window
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

// Store reset token in user metadata
        sqlx::query(
            "UPDATE users SET metadata = metadata || $1::jsonb, updated_at = NOW() WHERE id = $2",
        )
        .bind(serde_json::json!({
            "password_reset_token_hash": hash_token(&token),
            "password_reset_expires": expires.to_rfc3339(),
        }))
        .bind(&user_id)
        .execute(&state.db)
        .await?;

        tracing::info!(
            user_id = %user_id,
            "Password reset token generated"
        );

// Enqueue the password reset email into the messages table so the
// MTA worker picks it up for delivery.
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
<html lang="en"><head><meta charset="utf-8"/></head><body style="font-family:sans-serif;line-height:1.6;color:#1a1a1a;max-width:560px;margin:0 auto;padding:24px">
<h2 style="color:#2563EB">Reset Your Password</h2>
<p>We received a request to reset the password for <strong>{safe_email}</strong>.</p>
<p><a href="{safe_link}" style="display:inline-block;padding:12px 28px;background:#2563EB;color:#fff;border-radius:8px;text-decoration:none;font-weight:600">Reset Password</a></p>
<p style="font-size:13px;color:#666">This link expires in 1 hour. If you didn't request a password reset, you can safely ignore this email.</p>
<hr style="border:none;border-top:1px solid #e5e5e5;margin:24px 0"/>
<p style="font-size:12px;color:#999">&copy; 2026 ApexMail &middot; <a href="https://apexmail.ee" style="color:#999">apexmail.ee</a></p>
</body></html>"#,
        );
        let text_body = format!(
            "Reset Your Password\n\nWe received a request to reset the password for {email}.\n\nReset your password by visiting: {reset_link}\n\nThis link expires in 1 hour. If you didn't request this, you can safely ignore this email.\n\n© 2026 ApexMail — https://apexmail.ee",
        );

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

fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
// Check X-Forwarded-For first
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(val) = xff.to_str() {
            if let Some(first) = val.split(',').next() {
                let ip = first.trim();
                if !ip.is_empty() {
                    return Some(ip.to_string());
                }
            }
        }
    }

// Check X-Real-IP
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(val) = real_ip.to_str() {
            let ip = val.trim();
            if !ip.is_empty() {
                return Some(ip.to_string());
            }
        }
    }

    None
}

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
    fn test_extract_client_ip_xff() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "10.0.0.1, 192.168.1.1".parse().unwrap());
        assert_eq!(extract_client_ip(&headers), Some("10.0.0.1".into()));
    }

    #[test]
    fn test_extract_client_ip_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "10.0.0.2".parse().unwrap());
        assert_eq!(extract_client_ip(&headers), Some("10.0.0.2".into()));
    }

    #[test]
    fn test_percent_encode_component() {
        assert_eq!(percent_encode_component("hello"), "hello");
        assert_eq!(percent_encode_component("a b"), "a%20b");
        assert_eq!(percent_encode_component("a&b=c"), "a%26b%3Dc");
        assert_eq!(percent_encode_component("user@example.com"), "user%40example.com");
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>alert('xss')</script>"),
                   "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;");
        assert_eq!(html_escape("a&b"), "a&amp;b");
        assert_eq!(html_escape("plain text"), "plain text");
    }
}
