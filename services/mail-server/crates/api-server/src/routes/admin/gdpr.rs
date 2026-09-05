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
    json!({
        "status": body.status,
        "evidenceProvided": body.evidence.as_deref().is_some_and(|e| !e.trim().is_empty()),
    })
}

/// Audit with full actor attribution (P2-2): the operator's tenant AND user
/// id must land in the entry — an unattributed GDPR status change is
/// unverifiable the moment it matters legally.
async fn log_gdpr_audit(state: &AppState, auth: &AuthUser, request_id: &str, metadata: serde_json::Value) {
    crate::audit_log::insert_audit_log_best_effort_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
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
    // Slug-aware system-tenant resolution (audit F1): human operators belong
    // to `system_internal_tenant01`, not the literal `system` sentinel — the
    // literal comparison silently scoped this console to an empty tenant.
    let tenant_scoped = !crate::routes::web::is_system_tenant(&state, &auth.tenant_id).await;

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
    /// Operator-supplied proof of execution. Required to complete an
    /// erasure request (e.g. erasure job reference, verifier note); export
    /// requests additionally require a materialized `gdpr_exports` artifact.
    #[serde(default)]
    pub evidence: Option<String>,
}

/// A completed GDPR request must point at executed work, never an
/// operator's say-so (P1-5): an export needs a materialized artifact row
/// (`gdpr_exports.request_id`, migration 038 — the download the data
/// subject receives), an erasure needs a non-empty evidence note tying the
/// completion to the compliance erasure path. Returns Ok(()) only when the
/// request may legally transition to `completed`.
async fn ensure_completion_is_evidenced(
    state: &AppState,
    request: &GdprRequestRow,
    evidence: Option<&str>,
) -> Result<(), ApiError> {
    let has_evidence = evidence.is_some_and(|e| !e.trim().is_empty());
    match request.request_type.as_str() {
        "export" | "access" => {
            let has_artifact: Option<bool> = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM gdpr_exports WHERE request_id = $1)",
            )
            .bind(&request.id)
            .fetch_optional(&state.db)
            .await?
            .flatten();
            if !has_artifact.unwrap_or(false) {
                return Err(ApiError::Validation(vec![
                    "export requests can only be completed after the export artifact has been generated (gdpr_exports row missing)".into(),
                ]));
            }
            // An artifact without any operator evidence still leaves the
            // completion unattributed — require both.
            if !has_evidence {
                return Err(ApiError::Validation(vec![
                    "completing a request requires non-empty evidence".into(),
                ]));
            }
        }
        // Erasure and any unrecognized type: fail safe — demand evidence.
        _ => {
            if !has_evidence {
                return Err(ApiError::Validation(vec![
                    "completing an erasure request requires non-empty evidence (erasure job reference or compliance note)".into(),
                ]));
            }
        }
    }
    Ok(())
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

    let tenant_scoped = !crate::routes::web::is_system_tenant(&state, &auth.tenant_id).await;

    // Fetch the request first: completion gating needs its type, and a
    // tenant-scoped operator must not learn anything about foreign requests.
    let request: Option<GdprRequestRow> = if tenant_scoped {
        sqlx::query_as::<_, GdprRequestRow>(
            "SELECT g.id, g.request_type, g.status, g.email, g.tenant_id,
                COALESCE(t.name, g.tenant_id) as tenant_name,
                g.created_at, g.fulfilled_at
         FROM gdpr_requests g
         LEFT JOIN tenants t ON t.id = g.tenant_id
         WHERE g.id = $1 AND g.tenant_id = $2",
        )
        .bind(&body.id)
        .bind(&auth.tenant_id)
        .fetch_optional(&state.db)
        .await?
    } else {
        sqlx::query_as::<_, GdprRequestRow>(
            "SELECT g.id, g.request_type, g.status, g.email, g.tenant_id,
                COALESCE(t.name, g.tenant_id) as tenant_name,
                g.created_at, g.fulfilled_at
         FROM gdpr_requests g
         LEFT JOIN tenants t ON t.id = g.tenant_id
         WHERE g.id = $1",
        )
        .bind(&body.id)
        .fetch_optional(&state.db)
        .await?
    };
    let request = request.ok_or_else(|| ApiError::NotFound("gdpr request not found".into()))?;

    // P1-5: `fulfilled_at` is legal evidence of execution. It is written
    // ONLY after the completion gates below pass — never on the operator's
    // say-so.
    if body.status == "completed" {
        ensure_completion_is_evidenced(&state, &request, body.evidence.as_deref()).await?;
    }

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

    log_gdpr_audit(&state, &auth, &body.id, build_gdpr_audit_metadata(&body)).await;

    Ok(Json(serde_json::json!({ "success": true })))
}
