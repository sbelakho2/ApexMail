//! Automation / workflow routes.

use super::helpers::{clamp_limit, default_limit};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(create_automation).get(list_automations))
        .route(
            "/:id",
            get(get_automation)
                .put(update_automation)
                .delete(delete_automation),
        )
        .route("/:id/enable", post(enable_automation))
        .route("/:id/disable", post(disable_automation))
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAutomationRequest {
    pub name: String,
    pub trigger: serde_json::Value,
    pub actions: Vec<serde_json::Value>,
    #[serde(default)]
    pub conditions: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateAutomationRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub trigger: Option<serde_json::Value>,
    #[serde(default)]
    pub actions: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub conditions: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct AutomationResponse {
    pub id: String,
    pub name: String,
    pub trigger: serde_json::Value,
    pub actions: serde_json::Value,
    pub conditions: Option<serde_json::Value>,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
pub struct ListAutomationsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub cursor: Option<i64>,
}

// ─── Handlers ──────────────────────────────────────────────────

async fn create_automation(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateAutomationRequest>,
) -> Result<(StatusCode, Json<AutomationResponse>), ApiError> {
    require_scopes(&auth, &["automations:write"])?;

    if body.name.is_empty() || body.actions.is_empty() {
        return Err(ApiError::Validation(vec![
            "name and at least one action are required".into(),
        ]));
    }

    let id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query(
        "INSERT INTO automations (id, tenant_id, name, trigger_config, actions, conditions, status, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,'disabled',$7,$7)",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .bind(&body.name)
    .bind(&body.trigger)
    .bind(serde_json::json!(body.actions))
    .bind(&body.conditions)
    .bind(now)
    .execute(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(AutomationResponse {
            id: id.to_string(),
            name: body.name,
            trigger: body.trigger,
            actions: serde_json::json!(body.actions),
            conditions: body.conditions,
            status: "disabled".into(),
            created_at: now.to_rfc3339(),
            updated_at: now.to_rfc3339(),
        }),
    ))
}

async fn list_automations(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ListAutomationsQuery>,
) -> Result<Json<Vec<AutomationResponse>>, ApiError> {
    require_scopes(&auth, &["automations:read"])?;

    let offset = params.cursor.unwrap_or(params.offset).clamp(0, 100_000);
    let rows = sqlx::query_as::<_, AutomationRow>(
        "SELECT id, name, trigger_config, actions, conditions, status, created_at, updated_at
         FROM automations WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(&auth.tenant_id)
    .bind(clamp_limit(params.limit, 100))
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn get_automation(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<AutomationResponse>, ApiError> {
    require_scopes(&auth, &["automations:read"])?;
    let row = fetch_automation(&state, &auth.tenant_id, id).await?;
    Ok(Json(row.into()))
}

async fn update_automation(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<UpdateAutomationRequest>,
) -> Result<Json<AutomationResponse>, ApiError> {
    require_scopes(&auth, &["automations:write"])?;

    let existing = fetch_automation(&state, &auth.tenant_id, id.clone()).await?;

    let name = body.name.unwrap_or(existing.name);
    let trigger = body.trigger.unwrap_or(existing.trigger_config);
    let actions = body
        .actions
        .map(|a| serde_json::json!(a))
        .unwrap_or(existing.actions);
    let conditions = body.conditions.or(existing.conditions);

    sqlx::query(
        "UPDATE automations SET name=$1, trigger_config=$2, actions=$3, conditions=$4, updated_at=NOW()
         WHERE id=$5 AND tenant_id=$6",
    )
    .bind(&name)
    .bind(&trigger)
    .bind(&actions)
    .bind(&conditions)
    .bind(&id)
    .bind(&auth.tenant_id)
    .execute(&state.db)
    .await?;

    Ok(Json(AutomationResponse {
        id,
        name,
        trigger,
        actions,
        conditions,
        status: existing.status,
        created_at: existing.created_at.to_rfc3339(),
        updated_at: Utc::now().to_rfc3339(),
    }))
}

async fn delete_automation(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["automations:write"])?;

    let result = sqlx::query("DELETE FROM automations WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(&auth.tenant_id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("automation not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn enable_automation(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<AutomationResponse>, ApiError> {
    require_scopes(&auth, &["automations:write"])?;
    set_automation_status(&state, &auth.tenant_id, id, "enabled").await
}

async fn disable_automation(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<AutomationResponse>, ApiError> {
    require_scopes(&auth, &["automations:write"])?;
    set_automation_status(&state, &auth.tenant_id, id, "disabled").await
}

async fn set_automation_status(
    state: &AppState,
    tenant_id: &str,
    id: String,
    new_status: &str,
) -> Result<Json<AutomationResponse>, ApiError> {
    let result = sqlx::query(
        "UPDATE automations SET status = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3",
    )
    .bind(new_status)
    .bind(&id)
    .bind(tenant_id)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("automation not found".into()));
    }

    let row = fetch_automation(state, tenant_id, id).await?;
    Ok(Json(row.into()))
}

// ─── Row types ─────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct AutomationRow {
    id: String,
    name: String,
    trigger_config: serde_json::Value,
    actions: serde_json::Value,
    conditions: Option<serde_json::Value>,
    status: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<AutomationRow> for AutomationResponse {
    fn from(r: AutomationRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            trigger: r.trigger_config,
            actions: r.actions,
            conditions: r.conditions,
            status: r.status,
            created_at: r.created_at.to_rfc3339(),
            updated_at: r.updated_at.to_rfc3339(),
        }
    }
}

async fn fetch_automation(
    state: &AppState,
    tenant_id: &str,
    id: String,
) -> Result<AutomationRow, ApiError> {
    sqlx::query_as::<_, AutomationRow>(
        "SELECT id, name, trigger_config, actions, conditions, status, created_at, updated_at
         FROM automations WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("automation not found".into()))
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_automation_deser() {
        let json = r#"{
            "name": "Welcome Series",
            "trigger": {"type": "contact_created"},
            "actions": [{"type": "send_email", "template_id": "abc"}]
        }"#;
        let req: CreateAutomationRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "Welcome Series");
        assert_eq!(req.actions.len(), 1);
    }

    #[test]
    fn test_automation_response_serialisation() {
        let resp = AutomationResponse {
            id: String::new(),
            name: "Follow-up".into(),
            trigger: serde_json::json!({"type": "event"}),
            actions: serde_json::json!([]),
            conditions: None,
            status: "enabled".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "enabled");
    }
}
