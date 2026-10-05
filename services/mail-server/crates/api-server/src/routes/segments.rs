//! Segments API — named saved audiences.
//!
//! A segment is a reusable audience definition: subscriber lists plus
//! tag/status match rules (`{"tags_all": [...], "tags_any": [...],
//! "statuses": [...]}`). Campaigns target one via `segmentId`; the audience
//! resolver (api-server + worker, same semantics) unions the segment's lists
//! and excludes with the campaign's own and applies the match rules.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::FromRow;
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::require_scopes;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

/// Upper bound of list references per segment (same bound as campaigns).
const MAX_LISTS_PER_SEGMENT: usize = 50;
/// Upper bound of tag rules, per list.
const MAX_TAGS_PER_RULE: usize = 50;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(create_segment).get(list_segments))
        .route(
            "/:id",
            get(get_segment)
                .patch(update_segment)
                .delete(delete_segment),
        )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SegmentWriteRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default, alias = "listIds")]
    pub list_ids: Option<Vec<String>>,
    #[serde(default, alias = "excludeListIds")]
    pub exclude_list_ids: Option<Vec<String>>,
    /// Match rules: `{"tags_all": [...], "tags_any": [...], "statuses": [...]}`.
    #[serde(default)]
    pub r#match: Option<Value>,
}

#[derive(Debug, Serialize, FromRow)]
pub struct SegmentResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub list_ids: Value,
    pub exclude_list_ids: Value,
    pub r#match: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Parse + bound + dedupe one list-id array (identical policy to campaigns:
/// malformed ids are a clean 400, never a database cast 500).
fn parse_list_ids(raw: &[String], field: &str) -> Result<Vec<Uuid>, ApiError> {
    if raw.len() > MAX_LISTS_PER_SEGMENT {
        return Err(ApiError::Validation(vec![format!(
            "{field} must contain at most {MAX_LISTS_PER_SEGMENT} list ids"
        )]));
    }
    let mut out: Vec<Uuid> = Vec::with_capacity(raw.len());
    for id in raw {
        let uuid = Uuid::parse_str(id).map_err(|_| {
            ApiError::Validation(vec![format!("{field} contains a malformed list id")])
        })?;
        if !out.contains(&uuid) {
            out.push(uuid);
        }
    }
    Ok(out)
}

async fn validate_lists_exist(
    state: &AppState,
    tenant_id: &str,
    list_ids: &[Uuid],
) -> Result<(), ApiError> {
    if list_ids.is_empty() {
        return Ok(());
    }
    let found: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM lists WHERE tenant_id = $1 AND id = ANY($2)")
            .bind(tenant_id)
            .bind(list_ids)
            .fetch_one(&state.db)
            .await?;
    if found != list_ids.len() as i64 {
        return Err(ApiError::NotFound("list not found".into()));
    }
    Ok(())
}

/// Validate the match rules and normalize them to the canonical shape
/// (`{"tags_all": [...], "tags_any": [...], "statuses": [...]}` with absent
/// rules omitted).
fn validate_match(raw: Option<&Value>) -> Result<Value, ApiError> {
    let Some(value) = raw else {
        return Ok(json!({}));
    };
    let Some(object) = value.as_object() else {
        return Err(ApiError::Validation(vec![
            "match must be an object with tags_all / tags_any / statuses".into(),
        ]));
    };
    let mut out = serde_json::Map::new();
    for (key, value) in object {
        match key.as_str() {
            "tags_all" | "tags_any" => {
                let Some(items) = value.as_array() else {
                    return Err(ApiError::Validation(vec![format!(
                        "match.{key} must be an array of tag names"
                    )]));
                };
                if items.len() > MAX_TAGS_PER_RULE {
                    return Err(ApiError::Validation(vec![format!(
                        "match.{key} must contain at most {MAX_TAGS_PER_RULE} tags"
                    )]));
                }
                let mut tags: Vec<String> = Vec::new();
                for item in items {
                    let Some(tag) = item.as_str() else {
                        return Err(ApiError::Validation(vec![format!(
                            "match.{key} entries must be strings"
                        )]));
                    };
                    if tag.is_empty() || tag.chars().count() > 64 {
                        return Err(ApiError::Validation(vec![format!(
                            "match.{key} tags must be 1-64 characters"
                        )]));
                    }
                    if !tags.contains(&tag.to_string()) {
                        tags.push(tag.to_string());
                    }
                }
                out.insert(key.clone(), json!(tags));
            }
            "statuses" => {
                let Some(items) = value.as_array() else {
                    return Err(ApiError::Validation(vec![
                        "match.statuses must be an array of contact statuses".into(),
                    ]));
                };
                const VALID: [&str; 5] = [
                    "active",
                    "subscribed",
                    "unsubscribed",
                    "bounced",
                    "complained",
                ];
                let mut statuses: Vec<String> = Vec::new();
                for item in items {
                    let Some(status) = item.as_str() else {
                        return Err(ApiError::Validation(vec![
                            "match.statuses entries must be strings".into(),
                        ]));
                    };
                    if !VALID.contains(&status) {
                        return Err(ApiError::Validation(vec![format!(
                            "match.statuses must be drawn from: {}",
                            VALID.join(", ")
                        )]));
                    }
                    if !statuses.contains(&status.to_string()) {
                        statuses.push(status.to_string());
                    }
                }
                if statuses.is_empty() {
                    return Err(ApiError::Validation(vec![
                        "match.statuses must not be empty when present".into(),
                    ]));
                }
                out.insert(key.clone(), json!(statuses));
            }
            other => {
                return Err(ApiError::Validation(vec![format!(
                    "match.{other} is not a segment rule (allowed: tags_all, tags_any, statuses)"
                )]));
            }
        }
    }
    Ok(Value::Object(out))
}

/// Duplicate names are an honest 409 (unique `(tenant_id, name)`).
fn map_segment_write_error(error: sqlx::Error) -> ApiError {
    if let sqlx::Error::Database(ref db_error) = error {
        if db_error.code().as_deref() == Some("23505") {
            return ApiError::Conflict("a segment with this name already exists".into());
        }
    }
    ApiError::from(error)
}

async fn create_segment(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<SegmentWriteRequest>,
) -> Result<(StatusCode, Json<SegmentResponse>), ApiError> {
    require_scopes(&auth, &["campaigns:write"])?;
    if body.name.is_empty() || body.name.chars().count() > 200 {
        return Err(ApiError::Validation(vec![
            "name is required and must be 200 characters or fewer".into(),
        ]));
    }
    let include = parse_list_ids(body.list_ids.as_deref().unwrap_or_default(), "listIds")?;
    let exclude = parse_list_ids(
        body.exclude_list_ids.as_deref().unwrap_or_default(),
        "excludeListIds",
    )?;
    validate_lists_exist(&state, &auth.tenant_id, &include).await?;
    validate_lists_exist(&state, &auth.tenant_id, &exclude).await?;
    let match_rules = validate_match(body.r#match.as_ref())?;

    let id = Uuid::new_v4();
    let ids_json = |ids: &[Uuid]| json!(ids.iter().map(Uuid::to_string).collect::<Vec<_>>());
    let row: SegmentResponse = sqlx::query_as(
        "INSERT INTO segments (id, tenant_id, name, description, list_ids, exclude_list_ids, match) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         RETURNING id::text, name, description, list_ids, exclude_list_ids, match, created_at, updated_at",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .bind(&body.name)
    .bind(&body.description)
    .bind(ids_json(&include))
    .bind(ids_json(&exclude))
    .bind(&match_rules)
    .fetch_one(&state.db)
    .await
    .map_err(map_segment_write_error)?;

    Ok((StatusCode::CREATED, Json(row)))
}

async fn list_segments(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Value>, ApiError> {
    require_scopes(&auth, &["campaigns:read"])?;
    let rows: Vec<SegmentResponse> = sqlx::query_as(
        "SELECT id::text, name, description, list_ids, exclude_list_ids, match, created_at, updated_at \
         FROM segments WHERE tenant_id = $1 ORDER BY created_at DESC",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({ "data": rows, "error": null })))
}

async fn get_segment(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<SegmentResponse>, ApiError> {
    require_scopes(&auth, &["campaigns:read"])?;
    fetch_segment(&state, &auth.tenant_id, &id).await.map(Json)
}

async fn fetch_segment(
    state: &AppState,
    tenant_id: &str,
    id: &str,
) -> Result<SegmentResponse, ApiError> {
    let uuid = Uuid::parse_str(id).map_err(|_| ApiError::NotFound("segment not found".into()))?;
    sqlx::query_as(
        "SELECT id::text, name, description, list_ids, exclude_list_ids, match, created_at, updated_at \
         FROM segments WHERE id = $1 AND tenant_id = $2",
    )
    .bind(uuid)
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("segment not found".into()))
}

async fn update_segment(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<SegmentWriteRequest>,
) -> Result<Json<SegmentResponse>, ApiError> {
    require_scopes(&auth, &["campaigns:write"])?;
    if body.name.is_empty() || body.name.chars().count() > 200 {
        return Err(ApiError::Validation(vec![
            "name is required and must be 200 characters or fewer".into(),
        ]));
    }
    let include = parse_list_ids(body.list_ids.as_deref().unwrap_or_default(), "listIds")?;
    let exclude = parse_list_ids(
        body.exclude_list_ids.as_deref().unwrap_or_default(),
        "excludeListIds",
    )?;
    validate_lists_exist(&state, &auth.tenant_id, &include).await?;
    validate_lists_exist(&state, &auth.tenant_id, &exclude).await?;
    let match_rules = validate_match(body.r#match.as_ref())?;
    let uuid = Uuid::parse_str(&id).map_err(|_| ApiError::NotFound("segment not found".into()))?;
    let ids_json = |ids: &[Uuid]| json!(ids.iter().map(Uuid::to_string).collect::<Vec<_>>());

    sqlx::query_as::<_, SegmentResponse>(
        "UPDATE segments SET name = $3, description = $4, list_ids = $5, exclude_list_ids = $6, \
             match = $7, updated_at = NOW() \
         WHERE id = $1 AND tenant_id = $2 \
         RETURNING id::text, name, description, list_ids, exclude_list_ids, match, created_at, updated_at",
    )
    .bind(uuid)
    .bind(&auth.tenant_id)
    .bind(&body.name)
    .bind(&body.description)
    .bind(ids_json(&include))
    .bind(ids_json(&exclude))
    .bind(&match_rules)
    .fetch_optional(&state.db)
    .await
    .map_err(map_segment_write_error)?
    .map(Json)
    .ok_or_else(|| ApiError::NotFound("segment not found".into()))
}

async fn delete_segment(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["campaigns:write"])?;
    let uuid = Uuid::parse_str(&id).map_err(|_| ApiError::NotFound("segment not found".into()))?;
    let result = sqlx::query("DELETE FROM segments WHERE id = $1 AND tenant_id = $2")
        .bind(uuid)
        .bind(&auth.tenant_id)
        .execute(&state.db)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("segment not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}
