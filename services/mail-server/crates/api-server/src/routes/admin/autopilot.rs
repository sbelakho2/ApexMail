//! Autopilot AI proxy endpoints.
//!
//! Migrated from: apps/control-plane/src/app/api/autopilot/route.ts
//! Proxies to the Sales Autopilot backend (port 3010).

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(get_autopilot).post(post_autopilot))
}

const AUTOPILOT_BASE: &str = "http://localhost:3010/api/v1/operator";

#[derive(Debug, Deserialize)]
pub struct AutopilotQuery {
    pub section: Option<String>,
}

async fn get_autopilot(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<AutopilotQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let section = params.section.as_deref().unwrap_or("overview");
    let allowed = ["overview", "metrics", "baseline", "candidates", "outcomes", "pending", "actions", "safety"];
    if !allowed.contains(&section) {
        return Err(ApiError::Validation(vec!["Invalid section".into()]));
    }

    let url = format!("{AUTOPILOT_BASE}/{section}");
    let response = state
        .http_client
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Autopilot GET error: {e}");
            ApiError::Internal("Autopilot service unavailable".into())
        })?;

    if !response.status().is_success() {
        return Err(ApiError::Internal("Autopilot service error".into()));
    }

    let body: serde_json::Value = response.json().await.map_err(|e| {
        tracing::error!("Autopilot response parse error: {e}");
        ApiError::Internal("Invalid autopilot response".into())
    })?;

    Ok(Json(body))
}

#[derive(Debug, Deserialize)]
pub struct AutopilotAction {
    pub action: String,
    #[serde(default)]
    pub candidate_id: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

async fn post_autopilot(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<AutopilotAction>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let allowed = ["start", "stop", "approve", "reject", "approve-all", "exit-safe-mode"];
    if !allowed.contains(&body.action.as_str()) {
        return Err(ApiError::Validation(vec!["Invalid action".into()]));
    }

    let url = format!("{AUTOPILOT_BASE}/{}", body.action);
    let response = state
        .http_client
        .post(&url)
        .json(&body.extra)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Autopilot POST error: {e}");
            ApiError::Internal("Autopilot service unavailable".into())
        })?;

    if !response.status().is_success() {
        return Err(ApiError::Internal("Autopilot action failed".into()));
    }

    let result: serde_json::Value = response.json().await.unwrap_or(serde_json::json!({ "success": true }));
    Ok(Json(result))
}
