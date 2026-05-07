//! Auth telemetry endpoint.
//!
//! Receives client-side auth telemetry events for observability.

use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", post(auth_telemetry))
}

// ─── Request / Response types ──────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryPayload {
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub status: Option<serde_json::Value>,
    #[serde(default)]
    pub network_class: Option<String>,
    #[serde(default)]
    pub at: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct TelemetryResponse {
    pub success: bool,
}

// ─── Handler ───────────────────────────────────────────────────

async fn auth_telemetry(
    body: Result<Json<TelemetryPayload>, axum::extract::rejection::JsonRejection>,
) -> Json<TelemetryResponse> {
    // Telemetry endpoint is non-blocking:never fail
    match body {
        Ok(Json(payload)) => {
            let reason = sanitize_log_string(payload.reason.as_deref(), "unknown", 64);
            let status = sanitize_status(&payload.status);
            let network_class =
                sanitize_log_string(payload.network_class.as_deref(), "unknown", 32);
            let at = payload
                .at
                .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());

            tracing::info!(
                reason = %reason,
                status = ?status,
                network_class = %network_class,
                at = at,
                "[auth-telemetry]"
            );
        }
        Err(_) => {
            // Non-blocking:silently ignore parse errors
        }
    }

    Json(TelemetryResponse { success: true })
}

// ─── Sanitization helpers ──────────────────────────────────────

fn sanitize_log_string(value: Option<&str>, fallback: &str, max_len: usize) -> String {
    match value {
        Some(v) => {
            let cleaned: String = v
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect::<String>()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            if cleaned.is_empty() {
                fallback.into()
            } else if cleaned.len() > max_len {
                cleaned[..max_len].to_string()
            } else {
                cleaned
            }
        }
        None => fallback.into(),
    }
}

fn sanitize_status(value: &Option<serde_json::Value>) -> Option<i64> {
    match value {
        Some(serde_json::Value::Number(n)) => {
            let status = n.as_i64()?;
            if (100..=599).contains(&status) {
                Some(status)
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_log_string() {
        assert_eq!(
            sanitize_log_string(Some("hello world"), "default", 64),
            "hello world"
        );
        assert_eq!(
            sanitize_log_string(Some("hello\r\nworld\ttab"), "default", 64),
            "hello world tab"
        );
        assert_eq!(sanitize_log_string(None, "default", 64), "default");
        assert_eq!(sanitize_log_string(Some(""), "default", 64), "default");
        assert_eq!(sanitize_log_string(Some("abcdefgh"), "default", 5), "abcde");
    }

    #[test]
    fn test_sanitize_status() {
        assert_eq!(sanitize_status(&Some(serde_json::json!(200))), Some(200));
        assert_eq!(sanitize_status(&Some(serde_json::json!(599))), Some(599));
        assert_eq!(sanitize_status(&Some(serde_json::json!(600))), None);
        assert_eq!(sanitize_status(&Some(serde_json::json!(99))), None);
        assert_eq!(sanitize_status(&None), None);
        assert_eq!(
            sanitize_status(&Some(serde_json::json!("not a number"))),
            None
        );
    }
}
