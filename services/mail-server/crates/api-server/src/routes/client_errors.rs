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

    // Persist to database for analysis
    sqlx::query(
        "INSERT INTO client_errors (id, tenant_id, user_id, error_message, stack_trace, url, user_agent, created_at)
         VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, NOW())",
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

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…[truncated]", &s[..max])
    }
}
