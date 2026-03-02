//! GDPR request management endpoints.
//!
//! Migrated from: apps/control-plane/src/app/api/gdpr/route.ts

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(list_gdpr_requests).patch(update_gdpr_request))
}

#[derive(Debug, Deserialize)]
pub struct GdprListQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct GdprRequestRow {
    id: String,
    #[sqlx(rename = "type")]
    request_type: String,
    status: String,
    email: String,
    tenant_id: String,
    tenant_name: String,
    created_at: chrono::DateTime<chrono::Utc>,
    verified_at: Option<chrono::DateTime<chrono::Utc>>,
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
    sla_deadline: chrono::DateTime<chrono::Utc>,
    notes: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GdprRequestResponse {
    pub id: String,
    #[serde(rename = "type")]
    pub request_type: String,
    pub status: String,
    pub email: String,
    pub tenant_id: String,
    pub tenant_name: String,
    pub created_at: String,
    pub verified_at: Option<String>,
    pub completed_at: Option<String>,
    pub sla_deadline: String,
    pub notes: Option<String>,
}

async fn list_gdpr_requests(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<GdprListQuery>,
) -> Result<Json<Vec<GdprRequestResponse>>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);

    // Check if table exists
    let exists: (bool,) = sqlx::query_as(
        "SELECT to_regclass('public.gdpr_requests') IS NOT NULL",
    )
    .fetch_one(&state.db)
    .await?;

    if !exists.0 {
        return Ok(Json(vec![]));
    }

    let rows = sqlx::query_as::<_, GdprRequestRow>(
        "SELECT g.id, g.type, g.status, g.email, g.tenant_id,
                COALESCE(t.name, g.tenant_id) as tenant_name,
                g.created_at, g.verified_at, g.completed_at,
                g.sla_deadline, g.notes
         FROM gdpr_requests g
         LEFT JOIN tenants t ON t.id = g.tenant_id
         ORDER BY g.created_at DESC
         LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let response: Vec<GdprRequestResponse> = rows
        .into_iter()
        .map(|r| GdprRequestResponse {
            id: r.id,
            request_type: r.request_type,
            status: r.status,
            email: r.email,
            tenant_id: r.tenant_id,
            tenant_name: r.tenant_name,
            created_at: r.created_at.to_rfc3339(),
            verified_at: r.verified_at.map(|t| t.to_rfc3339()),
            completed_at: r.completed_at.map(|t| t.to_rfc3339()),
            sla_deadline: r.sla_deadline.to_rfc3339(),
            notes: r.notes,
        })
        .collect();

    Ok(Json(response))
}

#[derive(Debug, Deserialize)]
pub struct UpdateGdprRequest {
    pub id: String,
    pub status: String,
}

async fn update_gdpr_request(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<UpdateGdprRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let allowed = ["pending", "verified", "processing", "completed", "rejected"];
    if !allowed.contains(&body.status.as_str()) {
        return Err(ApiError::Validation(vec!["Invalid status".into()]));
    }

    sqlx::query(
        "UPDATE gdpr_requests
         SET status = $2,
             verified_at = CASE WHEN $2 = 'verified' THEN NOW() ELSE verified_at END,
             completed_at = CASE WHEN $2 = 'completed' THEN NOW() ELSE completed_at END
         WHERE id = $1",
    )
    .bind(&body.id)
    .bind(&body.status)
    .execute(&state.db)
    .await?;

    Ok(Json(serde_json::json!({ "success": true })))
}
