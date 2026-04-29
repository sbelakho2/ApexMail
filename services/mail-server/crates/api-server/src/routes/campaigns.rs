//! Campaign management routes.

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
        .route("/", post(create_campaign).get(list_campaigns))
        .route("/:id", get(get_campaign).delete(delete_campaign))
        .route("/:id/resume", post(resume_campaign))
        .route("/:id/pause", post(pause_campaign))
        .route("/:id/resend", post(resend_campaign))
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCampaignRequest {
    pub name: String,
    pub subject: String,
    #[serde(default)]
    pub template_id: Option<String>,
    #[serde(default)]
    pub scheduled_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct CampaignResponse {
    pub id: String,
    pub name: String,
    pub subject: String,
    pub template_id: Option<String>,
    pub status: String,
    pub scheduled_at: Option<String>,
    pub sent_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
pub struct ListCampaignsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub cursor: Option<i64>,
}

// ─── Handlers ──────────────────────────────────────────────────

async fn create_campaign(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateCampaignRequest>,
) -> Result<(StatusCode, Json<CampaignResponse>), ApiError> {
    require_scopes(&auth, &["campaigns:write"])?;

    if body.name.is_empty() || body.subject.is_empty() {
        return Err(ApiError::Validation(vec![
            "name and subject are required".into(),
        ]));
    }

    let id = Uuid::new_v4();
    let now = Utc::now();
    let status = if body.scheduled_at.is_some() { "scheduled" } else { "draft" };
    let template_id = body.template_id.clone();

    sqlx::query(
        "INSERT INTO campaigns (id, tenant_id, name, subject, template_id, status, scheduled_at, sent_count, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,0,$8,$8)",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .bind(&body.name)
    .bind(&body.subject)
    .bind(&template_id)
    .bind(status)
    .bind(body.scheduled_at)
    .bind(now)
    .execute(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(CampaignResponse {
            id: id.to_string(),
            name: body.name,
            subject: body.subject,
            template_id,
            status: status.into(),
            scheduled_at: body.scheduled_at.map(|t| t.to_rfc3339()),
            sent_count: 0,
            created_at: now.to_rfc3339(),
            updated_at: now.to_rfc3339(),
        }),
    ))
}

async fn list_campaigns(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ListCampaignsQuery>,
) -> Result<Json<Vec<CampaignResponse>>, ApiError> {
    require_scopes(&auth, &["campaigns:read"])?;

    let offset = params.cursor.unwrap_or(params.offset).clamp(0, 100_000);
    let rows = sqlx::query_as::<_, CampaignRow>(
        "SELECT id, name, subject, template_id, status, scheduled_at, sent_count, created_at, updated_at
         FROM campaigns WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(&auth.tenant_id)
    .bind(clamp_limit(params.limit, 100))
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn get_campaign(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<CampaignResponse>, ApiError> {
    require_scopes(&auth, &["campaigns:read"])?;
    let row = fetch_campaign(&state, &auth.tenant_id, id).await?;
    Ok(Json(row.into()))
}

async fn delete_campaign(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["campaigns:write"])?;

    let result = sqlx::query("DELETE FROM campaigns WHERE id = $1 AND tenant_id = $2")
        .bind(&id)
        .bind(&auth.tenant_id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("campaign not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn resume_campaign(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<CampaignResponse>, ApiError> {
    require_scopes(&auth, &["campaigns:write"])?;
    update_campaign_status_validated(&state, &auth.tenant_id, id, "sending", &["paused", "draft"]).await
}

async fn pause_campaign(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<CampaignResponse>, ApiError> {
    require_scopes(&auth, &["campaigns:write"])?;
    update_campaign_status_validated(&state, &auth.tenant_id, id, "paused", &["sending", "scheduled"]).await
}

async fn update_campaign_status_validated(
    state: &AppState,
    tenant_id: &str,
    id: String,
    new_status: &str,
    valid_current_states: &[&str],
) -> Result<Json<CampaignResponse>, ApiError> {
// Fetch current campaign to validate state transition.
    let current = fetch_campaign(state, tenant_id, id.clone()).await?;
    
    if !valid_current_states.contains(&current.status.as_str()) {
        return Err(ApiError::Validation(vec![
            format!("cannot transition from '{}' to '{}'", current.status, new_status)
        ]));
    }

    let result = sqlx::query(
        "UPDATE campaigns SET status = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3",
    )
    .bind(new_status)
    .bind(&id)
    .bind(tenant_id)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("campaign not found".into()));
    }

    let row = fetch_campaign(state, tenant_id, id).await?;
    Ok(Json(row.into()))
}

// ─── Row types ─────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct CampaignRow {
    id: String,
    name: String,
    subject: String,
    template_id: Option<String>,
    status: String,
    scheduled_at: Option<DateTime<Utc>>,
    sent_count: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<CampaignRow> for CampaignResponse {
    fn from(r: CampaignRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            subject: r.subject,
            template_id: r.template_id,
            status: r.status,
            scheduled_at: r.scheduled_at.map(|t| t.to_rfc3339()),
            sent_count: r.sent_count,
            created_at: r.created_at.to_rfc3339(),
            updated_at: r.updated_at.to_rfc3339(),
        }
    }
}

async fn fetch_campaign(state: &AppState, tenant_id: &str, id: String) -> Result<CampaignRow, ApiError> {
    sqlx::query_as::<_, CampaignRow>(
        "SELECT id, name, subject, template_id, status, scheduled_at, sent_count, created_at, updated_at
         FROM campaigns WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("campaign not found".into()))
}

// ─── Resend Handler ────────────────────────────────────────────

async fn resend_campaign(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["campaigns:write"])?;

// Verify campaign exists and belongs to tenant, and is in a resendable state
    let campaign_status = sqlx::query_scalar::<_, String>(
        "SELECT status FROM campaigns WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(auth.tenant_id.to_string())
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("campaign not found".into()))?;

    if campaign_status != "sent" && campaign_status != "partial" {
        return Err(ApiError::BadRequest(format!(
            "Campaign status '{}' is not resendable. Must be 'sent' or 'partial'.",
            campaign_status
        )));
    }

// Create a new send job for failed/unsent recipients
    let new_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO campaign_jobs (id, campaign_id, tenant_id, status, created_at)
         VALUES ($1, $2, $3, 'queued', NOW())",
    )
    .bind(new_id)
    .bind(id)
    .bind(auth.tenant_id.to_string())
    .execute(&state.db)
    .await?;

// Update campaign status
    sqlx::query(
        "UPDATE campaigns SET status = 'resending', updated_at = NOW() WHERE id = $1",
    )
    .bind(id)
    .execute(&state.db)
    .await?;

    Ok(Json(serde_json::json!({
        "job_id": new_id,
        "campaign_id": id,
        "status": "queued",
    })))
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_campaign_deser() {
        let json = r#"{"name":"Summer Sale","subject":"50% Off!"}"#;
        let req: CreateCampaignRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "Summer Sale");
        assert!(req.template_id.is_none());
    }

    #[test]
    fn test_campaign_response_serialisation() {
        let resp = CampaignResponse {
            id: String::new(),
            name: "Test".into(),
            subject: "Sub".into(),
            template_id: None,
            status: "draft".into(),
            scheduled_at: None,
            sent_count: 0,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["sent_count"], 0);
    }
}
