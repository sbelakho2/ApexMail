//! GDPR request management endpoints.
//!

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(list_gdpr_requests).patch(update_gdpr_request))
}

fn build_gdpr_audit_metadata(body: &UpdateGdprRequest) -> serde_json::Value {
    json!({ "status": body.status })
}

async fn log_gdpr_audit(db: &sqlx::PgPool, request_id: &str, metadata: serde_json::Value) {
    crate::audit_log::insert_audit_log_best_effort(
        db,
        None,
        None,
        "control_plane.gdpr.request_updated",
        "gdpr_request",
        Some(request_id),
        metadata,
        None,
        None,
    )
    .await;
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
    request_type: String,
    status: String,
    email: String,
    tenant_id: String,
    tenant_name: String,
    created_at: chrono::DateTime<chrono::Utc>,
    fulfilled_at: Option<chrono::DateTime<chrono::Utc>>,
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
    pub completed_at: Option<String>,
}

async fn list_gdpr_requests(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<GdprListQuery>,
) -> Result<Json<Vec<GdprRequestResponse>>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);
    let tenant_scoped = auth.tenant_id != "system";

    // Check if table exists
    let exists: (bool,) = sqlx::query_as("SELECT to_regclass('public.gdpr_requests') IS NOT NULL")
        .fetch_one(&state.db)
        .await?;

    if !exists.0 {
        return Ok(Json(vec![]));
    }

    let rows = if tenant_scoped {
        sqlx::query_as::<_, GdprRequestRow>(
            "SELECT g.id, g.request_type, g.status, g.email, g.tenant_id,
                COALESCE(t.name, g.tenant_id) as tenant_name,
                g.created_at, g.fulfilled_at
         FROM gdpr_requests g
         LEFT JOIN tenants t ON t.id = g.tenant_id
         WHERE g.tenant_id = $3
         ORDER BY g.created_at DESC
         LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .bind(&auth.tenant_id)
        .fetch_all(&state.db)
        .await?
    } else {
        sqlx::query_as::<_, GdprRequestRow>(
            "SELECT g.id, g.request_type, g.status, g.email, g.tenant_id,
                COALESCE(t.name, g.tenant_id) as tenant_name,
                g.created_at, g.fulfilled_at
         FROM gdpr_requests g
         LEFT JOIN tenants t ON t.id = g.tenant_id
         ORDER BY g.created_at DESC
         LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await?
    };

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
            completed_at: r.fulfilled_at.map(|t| t.to_rfc3339()),
        })
        .collect();

    Ok(Json(response))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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

    let tenant_scoped = auth.tenant_id != "system";
    let result = if tenant_scoped {
        sqlx::query(
            "UPDATE gdpr_requests
         SET status = $2,
             fulfilled_at = CASE WHEN $2 = 'completed' THEN NOW() ELSE fulfilled_at END
         WHERE id = $1 AND tenant_id = $3",
        )
        .bind(&body.id)
        .bind(&body.status)
        .bind(&auth.tenant_id)
        .execute(&state.db)
        .await?
    } else {
        sqlx::query(
            "UPDATE gdpr_requests
         SET status = $2,
             fulfilled_at = CASE WHEN $2 = 'completed' THEN NOW() ELSE fulfilled_at END
         WHERE id = $1",
        )
        .bind(&body.id)
        .bind(&body.status)
        .execute(&state.db)
        .await?
    };

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("gdpr request not found".into()));
    }

    log_gdpr_audit(&state.db, &body.id, build_gdpr_audit_metadata(&body)).await;

    Ok(Json(serde_json::json!({ "success": true })))
}
