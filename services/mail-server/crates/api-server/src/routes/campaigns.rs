//! Campaign management routes.

use super::helpers::{
    clamp_limit, compute_etag, decode_cursor, default_limit, encode_cursor, has_more,
    is_not_modified, pagination_meta,
};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
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

// ─── Keyset cursor helpers ─────────────────────────────────────
//
// The list cursor encodes the `(created_at, id)` pair of the last row of the
// previous page. A timestamp alone skips or duplicates rows that share a
// `created_at` value; the tie-break `created_at = $ts AND id < $id` makes
// the ordering total.

/// Separator between the RFC3339 timestamp and the row id inside the
/// hex-encoded cursor payload (RFC3339 and UUID ids never contain it).
const KEYSET_CURSOR_SEP: char = '\n';

/// Encode a `(created_at, id)` keyset cursor as an opaque hex string.
fn encode_keyset_cursor(created_at: &DateTime<Utc>, id: &str) -> String {
    encode_cursor(&format!("{created_at}{KEYSET_CURSOR_SEP}{id}"))
}

/// Decode and validate a `(created_at, id)` keyset cursor. Malformed
/// encodings, unparsable timestamps, or bogus ids are client errors (400) —
/// an unvalidated cursor used to reach the database and surface as a 500.
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
#[serde(deny_unknown_fields)]
pub struct ListCampaignsQuery {
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

// ─── Handlers ──────────────────────────────────────────────────

async fn create_campaign(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateCampaignRequest>,
) -> Result<(StatusCode, Json<CampaignResponse>), ApiError> {
    require_scopes(&auth, &["campaigns:write"])?;

    if body.name.is_empty() || body.name.len() > 200 {
        return Err(ApiError::Validation(vec![
            "name is required and must be 200 characters or fewer".into(),
        ]));
    }
    if body.subject.is_empty() || body.subject.len() > 500 {
        return Err(ApiError::Validation(vec![
            "subject is required and must be 500 characters or fewer".into(),
        ]));
    }

    let id = Uuid::new_v4();
    let now = Utc::now();
    let status = if body.scheduled_at.is_some() {
        "scheduled"
    } else {
        "draft"
    };
    let template_id = body.template_id.clone();

    // Verify the referenced template exists and belongs to this tenant before
    // creating the campaign (prevents cross-tenant template_id references).
    if let Some(ref tid) = template_id {
        let exists: Option<bool> = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM templates WHERE id = $1 AND tenant_id = $2)",
        )
        .bind(tid)
        .bind(&auth.tenant_id)
        .fetch_one(&state.db)
        .await?;
        if !exists.unwrap_or(false) {
            return Err(ApiError::NotFound("template not found".into()));
        }
    }

    sqlx::query(
        "INSERT INTO campaigns (id, tenant_id, name, subject, template_id, status, scheduled_at, sent_count, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5::uuid,$6,$7,0,$8,$8)",
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
    headers: HeaderMap,
    Query(params): Query<ListCampaignsQuery>,
) -> Result<Response, ApiError> {
    require_scopes(&auth, &["campaigns:read"])?;

    let limit = clamp_limit(params.limit, 100);

    // Cursor-based pagination: decode and validate the hex-encoded
    // `created_at\nid` pair BEFORE binding — a bogus cursor used to reach
    // the `::timestamp` cast and surface as a database 500 instead of a
    // client 400.
    let cursor_value = match params.cursor.as_deref() {
        Some(encoded) => Some(decode_keyset_cursor(encoded)?),
        None => None,
    };

    let fetch_limit = limit + 1; // fetch one extra to detect has_more

    let rows = if let Some((ref cursor_ts, ref cursor_id)) = cursor_value {
        // campaigns.id is UUID — the VALUE is cast once, never the column,
        // so the primary-key index remains usable for the tie-break.
        sqlx::query_as::<_, CampaignRow>(
            "SELECT id, name, subject, template_id, status, scheduled_at, sent_count, created_at, updated_at
             FROM campaigns WHERE tenant_id = $1
               AND (created_at < $2::timestamp OR (created_at = $2::timestamp AND id < $3::uuid))
             ORDER BY created_at DESC, id DESC LIMIT $4",
        )
        .bind(&auth.tenant_id)
        .bind(cursor_ts)
        .bind(cursor_id)
        .bind(fetch_limit)
        .fetch_all(&state.db)
        .await?
    } else {
        // Fallback to offset-based pagination for backward compatibility
        let offset = params.offset.clamp(0, 100_000);
        sqlx::query_as::<_, CampaignRow>(
            "SELECT id, name, subject, template_id, status, scheduled_at, sent_count, created_at, updated_at
             FROM campaigns WHERE tenant_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3",
        )
        .bind(&auth.tenant_id)
        .bind(fetch_limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await?
    };

    // Build the response rows and detect has_more
    let mut details: Vec<CampaignResponse> = rows.into_iter().map(Into::into).collect();
    let more = has_more(&mut details, limit as usize);

    // Compute the next cursor from the last row's (created_at, id) pair.
    let next_cursor = details.last().and_then(|r| {
        chrono::DateTime::parse_from_rfc3339(&r.created_at)
            .ok()
            .map(|ts| encode_keyset_cursor(&ts.with_timezone(&Utc), &r.id))
    });
    let meta = pagination_meta(more, next_cursor);

    // Build the response body and compute ETag
    let body = serde_json::json!({
        "data": details,
        "error": null,
        "meta": meta,
    });
    let body_bytes = serde_json::to_vec(&body)?;
    let etag = compute_etag(&body_bytes);

    // Check If-None-Match for 304
    if is_not_modified(&headers, &etag) {
        return Ok(axum::response::Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header("ETag", &etag)
            .body(axum::body::Body::empty())
            .expect("invariant: Response builder with valid status/headers should not fail"));
    }

    Ok(axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("ETag", &etag)
        .header("Cache-Control", "private, max-age=0, must-revalidate")
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(body_bytes))
        .expect("invariant: Response builder with valid status/headers/body should not fail"))
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

    let result = sqlx::query("DELETE FROM campaigns WHERE id = $1::uuid AND tenant_id = $2")
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
    update_campaign_status_validated(&state, &auth.tenant_id, id, "sending", &["paused", "draft"])
        .await
}

async fn pause_campaign(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<CampaignResponse>, ApiError> {
    require_scopes(&auth, &["campaigns:write"])?;
    update_campaign_status_validated(
        &state,
        &auth.tenant_id,
        id,
        "paused",
        &["sending", "scheduled"],
    )
    .await
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
        return Err(ApiError::Validation(vec![format!(
            "cannot transition from '{}' to '{}'",
            current.status, new_status
        )]));
    }

    // Atomically guard the transition against TOCTOU races: the UPDATE only
    // fires if the status is still one of the allowed values. If 0 rows are
    // affected, the status changed between the SELECT and the UPDATE.
    let allowed: Vec<&str> = valid_current_states.to_vec();
    let result = sqlx::query(
        "UPDATE campaigns SET status = $1, updated_at = NOW()
         WHERE id = $2::uuid AND tenant_id = $3 AND status = ANY($4)",
    )
    .bind(new_status)
    .bind(&id)
    .bind(tenant_id)
    .bind(&allowed)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::Conflict(format!(
            "campaign '{}' status changed before update; cannot transition to '{}'",
            id, new_status
        )));
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

async fn fetch_campaign(
    state: &AppState,
    tenant_id: &str,
    id: String,
) -> Result<CampaignRow, ApiError> {
    sqlx::query_as::<_, CampaignRow>(
        "SELECT id, name, subject, template_id, status, scheduled_at, sent_count, created_at, updated_at
         FROM campaigns WHERE id = $1::uuid AND tenant_id = $2",
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
        "SELECT status FROM campaigns WHERE id = $1::uuid AND tenant_id = $2",
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
    // job_type is NOT NULL with no default, so it must be supplied explicitly.
    let new_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO campaign_jobs (id, campaign_id, tenant_id, job_type, status, created_at)
         VALUES ($1, $2, $3, 'resend', 'queued', NOW())",
    )
    .bind(new_id)
    .bind(id)
    .bind(auth.tenant_id.to_string())
    .execute(&state.db)
    .await?;

    // Update campaign status
    sqlx::query("UPDATE campaigns SET status = 'resending', updated_at = NOW() WHERE id = $1::uuid AND tenant_id = $2")
        .bind(id)
        .bind(auth.tenant_id.to_string())
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
