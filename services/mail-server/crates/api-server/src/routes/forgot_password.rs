//! Forgot-password endpoint.
//!
//! Migrated from: apps/web/src/app/api/auth/forgot-password/route.ts
//! Validates email, rate-limits by IP, then delegates to password reset logic.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::state::AppState;

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
    let user: Option<(uuid::Uuid, String)> = sqlx::query_as(
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
            "password_reset_token": token,
            "password_reset_expires": expires.to_rfc3339(),
        }))
        .bind(user_id)
        .execute(&state.db)
        .await?;

        tracing::info!(
            user_id = %user_id,
            "Password reset token generated"
        );

        // TODO: Send password reset email via the MTA crate
        // For now, the token is stored and can be used via a reset endpoint.
    }

    // Always return success to prevent email enumeration
    Ok(Json(ForgotPasswordResponse { success: true }))
}

// ─── Helpers ───────────────────────────────────────────────────

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
}
