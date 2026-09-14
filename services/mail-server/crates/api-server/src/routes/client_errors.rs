//! Client-side error reporting route.
//!
//! POST / → log a client-side error from the console SPA

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", post(report_client_error))
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientErrorReport {
    /// Error message
    pub message: String,
    /// Optional stack trace
    #[serde(default)]
    pub stack: Option<String>,
    /// Page URL where the error occurred
    #[serde(default)]
    pub url: Option<String>,
    /// Source file/line information
    #[serde(default)]
    pub source: Option<String>,
    /// Browser/OS info
    #[serde(default)]
    pub user_agent: Option<String>,
    /// Severity:"error" | "warning" | "info"
    #[serde(default = "default_severity")]
    pub severity: String,
    /// Optional additional context
    #[serde(default)]
    pub context: Option<serde_json::Value>,
}

fn default_severity() -> String {
    "error".into()
}

#[derive(Debug, Serialize)]
pub struct ClientErrorAck {
    pub accepted: bool,
}

// ─── Handler ───────────────────────────────────────────────────

async fn report_client_error(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<ClientErrorReport>,
) -> Result<(StatusCode, Json<ClientErrorAck>), ApiError> {
    // Sanitize:truncate overly long fields to prevent abuse
    let message = truncate(&body.message, 2048);
    let stack = body.stack.as_deref().map(|s| truncate(s, 8192));
    let url = body.url.as_deref().map(|s| truncate(s, 2048));
    let source = body.source.as_deref().map(|s| truncate(s, 512));

    // Log with structured fields for observability pipeline
    warn!(
        tenant_id = %auth.tenant_id,
        severity = %body.severity,
        message = %message,
        url = ?url,
        source = ?source,
        stack_len = stack.as_ref().map(|s| s.len()).unwrap_or(0),
        "client-side error reported"
    );

    // Persist to database for analysis. user_id is UUID (migration 229): the
    // JWT subject is a UUID string, and binding it without the cast made every
    // authenticated report fail with "value too long for character varying(26)".
    sqlx::query(
        "INSERT INTO client_errors (id, tenant_id, user_id, error_message, stack_trace, url, user_agent, created_at)
         VALUES (gen_random_uuid(), $1, $2::uuid, $3, $4, $5, $6, NOW())",
    )
    .bind(auth.tenant_id.to_string())
    .bind(auth.user_id.as_deref())
    .bind(message)
    .bind(stack)
    .bind(url)
    .bind(body.user_agent.as_deref().map(|s| truncate(s, 512)))
    .execute(&state.db)
    .await?;

    Ok((
        StatusCode::ACCEPTED,
        Json(ClientErrorAck { accepted: true }),
    ))
}

/// Truncate a string to at most `max` bytes without panicking on multibyte
/// UTF-8: `&s[..max]` slices at a raw byte offset and panics when `max`
/// lands inside a multibyte character (an authenticated remote crash — a
/// client only needs to send a long CJK/emoji payload). This helper walks
/// back to the nearest char boundary instead.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…[truncated]", &s[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_short_strings_untouched() {
        assert_eq!(truncate("hello", 2048), "hello");
        assert_eq!(truncate("", 2048), "");
    }

    #[test]
    fn truncate_ascii_long_strings_cut_at_exact_boundary() {
        let input = "a".repeat(5000);
        let output = truncate(&input, 2048);
        assert!(output.starts_with(&"a".repeat(2040)));
        assert!(output.ends_with("…[truncated]"));
        assert!(output.len() < input.len());
    }

    #[test]
    fn truncate_multibyte_payload_does_not_panic_at_mid_char_boundary() {
        // '中' is 3 bytes; byte offset 2048 lands in the middle of the 683rd
        // character (683 * 3 = 2049), which previously panicked the handler.
        let input = "中".repeat(1000);
        assert_eq!(input.len(), 3000);
        let output = truncate(&input, 2048);
        // Must cut back to a char boundary (2048 -> 2046, a multiple of 3)
        // and never panic.
        assert!(output.len() < input.len());
        assert!(output.ends_with("…[truncated]"));
        let truncated_part = output.trim_end_matches("…[truncated]");
        assert!(truncated_part.chars().all(|c| c == '中'));
    }

    #[test]
    fn truncate_two_byte_payload_does_not_panic() {
        // 'é' is 2 bytes; 2049 % 2 = 1 offsets would be invalid — probe
        // several odd/even limits around multibyte content.
        let input = "é".repeat(2000);
        for max in [2047usize, 2048, 2049] {
            let output = truncate(&input, max);
            assert!(std::str::from_utf8(output.as_bytes()).is_ok());
        }
    }

    #[test]
    fn truncate_emoji_four_byte_characters() {
        let input = "😀".repeat(1000); // 4 bytes each
        let output = truncate(&input, 2048);
        assert!(std::str::from_utf8(output.as_bytes()).is_ok());
        assert!(output.contains("😀"));
    }

    /// The authenticated report path persists the reporter's UUID subject.
    /// Before migration 229 `client_errors.user_id` was VARCHAR(26) while the
    /// JWT subject is a 36-character UUID, so every authenticated report
    /// failed with "value too long" and the endpoint 500'd.
    #[tokio::test]
    async fn authenticated_report_persists_the_uuid_subject() {
        let Some(pool) = crate::test_db::optional_pg_pool("client_errors_uuid_subject").await
        else {
            return;
        };
        let suffix = &uuid::Uuid::new_v4().simple().to_string()[..12];
        let tenant = format!("cerr{suffix}");
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
             VALUES ($1, 'client error test', 'free', 'active', NOW(), NOW())",
        )
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed tenant");
        let user_id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status,
                                email_verified, created_at, updated_at)
             VALUES ($1, $2, $3, 'Reporter', 'x', 'owner', 'active', true, NOW(), NOW())",
        )
        .bind(user_id)
        .bind(&tenant)
        .bind(format!("cerr-{suffix}@example.com"))
        .execute(&pool)
        .await
        .expect("seed user");

        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let auth = AuthUser {
            tenant_id: tenant.clone(),
            user_id: Some(user_id.to_string()),
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        };
        let (status, Json(ack)) = report_client_error(
            State(state),
            auth,
            Json(ClientErrorReport {
                message: "boom".into(),
                stack: None,
                url: Some("https://cp.example/".into()),
                source: None,
                user_agent: Some("probe".into()),
                severity: "error".into(),
                context: None,
            }),
        )
        .await
        .expect("an authenticated report must be accepted");
        assert_eq!(status, StatusCode::ACCEPTED);
        assert!(ack.accepted);

        let stored: (Option<uuid::Uuid>,) = sqlx::query_as(
            "SELECT user_id FROM client_errors WHERE tenant_id = $1
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("read the stored report");
        assert_eq!(
            stored.0,
            Some(user_id),
            "the stored report must carry the UUID subject"
        );

        // Cleanup.
        let _ = sqlx::query("DELETE FROM client_errors WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await;
        pool.close().await;
    }
}
