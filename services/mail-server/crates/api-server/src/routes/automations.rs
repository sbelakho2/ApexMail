//! Automation / workflow routes.

use super::helpers::{clamp_limit, decode_cursor, encode_cursor, has_more};
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

// ─── Keyset cursor helpers ─────────────────────────────────────
//
// The list cursor encodes the `(created_at, id)` pair of the last row of the
// previous page (automations.id is UUID, migration 075). The previous
// implementation returned a numeric OFFSET as "nextCursor" while calling it
// a cursor — rows were skipped or duplicated whenever rows shared a
// created_at value, and the "cursor" restarted the scan on every page.

/// Separator between the RFC3339 timestamp and the row id inside the
/// hex-encoded cursor payload (RFC3339 and UUID ids never contain it).
const KEYSET_CURSOR_SEP: char = '\n';

/// Encode a `(created_at, id)` keyset cursor as an opaque hex string.
fn encode_keyset_cursor(created_at: &DateTime<Utc>, id: &str) -> String {
    encode_cursor(&format!("{created_at}{KEYSET_CURSOR_SEP}{id}"))
}

/// Decode and validate a `(created_at, id)` keyset cursor. Malformed input
/// is a client error (400), never a database 500.
fn decode_keyset_cursor(encoded: &str) -> Result<(DateTime<Utc>, String), ApiError> {
    let Some(decoded) = decode_cursor(encoded) else {
        return Err(ApiError::BadRequest(
            "invalid cursor: malformed encoding".into(),
        ));
    };
    let Some((timestamp, id)) = decoded.split_once(KEYSET_CURSOR_SEP) else {
        return Err(ApiError::BadRequest(
            "invalid cursor: must encode a created_at timestamp and row id".into(),
        ));
    };
    let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp)
        .map_err(|_| {
            ApiError::BadRequest("invalid cursor: must be an encoded created_at timestamp".into())
        })?
        .with_timezone(&Utc);
    if id.is_empty() || id.len() > 64 || id.bytes().any(|b| b.is_ascii_control()) {
        return Err(ApiError::BadRequest(
            "invalid cursor: malformed row id".into(),
        ));
    }
    Ok((timestamp, id.to_string()))
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
#[serde(deny_unknown_fields)]
pub struct ListAutomationsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    /// Cursor for cursor-based pagination — hex-encoded `created_at` + row id
    /// pair of the last item from the previous page. When provided, overrides
    /// `offset`.
    #[serde(default)]
    pub cursor: Option<String>,
}

fn default_limit() -> i64 {
    50
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
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["automations:read"])?;

    let limit = clamp_limit(params.limit, 100);

    // Real keyset pagination on (created_at, id): decode and validate the
    // cursor BEFORE binding, and page with a total-ordering tuple
    // comparison instead of the numeric offset this endpoint used to
    // return under the "nextCursor" name.
    let cursor_value = match params.cursor.as_deref() {
        Some(encoded) => Some(decode_keyset_cursor(encoded)?),
        None => None,
    };

    let total: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM automations WHERE tenant_id = $1",
    )
    .bind(&auth.tenant_id)
    .fetch_one(&state.db)
    .await?;

    // Fetch limit + 1 rows so we can detect whether another page exists.
    let rows = if let Some((ref cursor_ts, ref cursor_id)) = cursor_value {
        sqlx::query_as::<_, AutomationRow>(
            "SELECT id, name, trigger_config, actions, conditions, status, created_at, updated_at
             FROM automations WHERE tenant_id = $1
               AND (created_at < $2::timestamp OR (created_at = $2::timestamp AND id < $3::uuid))
             ORDER BY created_at DESC, id DESC LIMIT $4",
        )
        .bind(&auth.tenant_id)
        .bind(cursor_ts)
        .bind(cursor_id)
        .bind(limit + 1)
        .fetch_all(&state.db)
        .await?
    } else {
        let offset = params.offset.clamp(0, 100_000);
        sqlx::query_as::<_, AutomationRow>(
            "SELECT id, name, trigger_config, actions, conditions, status, created_at, updated_at
             FROM automations WHERE tenant_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3",
        )
        .bind(&auth.tenant_id)
        .bind(limit + 1)
        .bind(offset)
        .fetch_all(&state.db)
        .await?
    };

    let mut details: Vec<AutomationResponse> = rows.into_iter().map(Into::into).collect();
    let has_more = has_more(&mut details, limit as usize);

    // Next (created_at, id) keyset cursor — a genuine cursor, not an offset.
    let next_cursor = details.last().and_then(|r| {
        chrono::DateTime::parse_from_rfc3339(&r.created_at)
            .ok()
            .map(|ts| encode_keyset_cursor(&ts.with_timezone(&Utc), &r.id))
    });

    // Wrap in the standard {data, error, meta} envelope with pagination meta.
    Ok(Json(serde_json::json!({
        "data": details,
        "error": null,
        "meta": {
            "total": total,
            "hasMore": has_more,
            "nextCursor": next_cursor,
        },
    })))
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
