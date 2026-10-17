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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::auth::AuthUser;

    async fn fixture(name: &str) -> Option<(AppState, sqlx::PgPool, String, String, Uuid)> {
        let pool = crate::test_db::canonical_pool(name).await?;
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let tenant = apexmail_lib::id::generate_id("", 26);
        let other = apexmail_lib::id::generate_id("", 26);
        for id in [&tenant, &other] {
            sqlx::query(
                "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at) \
                 VALUES ($1, 'Segment Co', $1, 'free', 'active', NOW(), NOW())",
            )
            .bind(id)
            .execute(&pool)
            .await
            .expect("seed tenant");
        }
        let list = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO lists (id, tenant_id, name, opt_in_mode) \
             VALUES ($1, $2, 'Audience', 'single_opt_in')",
        )
        .bind(list)
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed list");
        Some((state, pool, tenant, other, list))
    }

    fn auth(tenant: &str, scopes: &[&str]) -> AuthUser {
        AuthUser {
            tenant_id: tenant.to_string(),
            user_id: Some(Uuid::new_v4().to_string()),
            api_key_id: None,
            session_id: None,
            scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
        }
    }

    /// Use-all audit (P0): segments had ZERO tests. Pin CRUD, bounds, tenant
    /// isolation and the unique-name contract.
    #[tokio::test]
    async fn segment_crud_validates_bounds_and_tenant_scope() {
        let Some((state, pool, tenant, other, list)) = fixture("segments_crud").await else {
            return;
        };
        let writer = auth(&tenant, &["campaigns:write"]);
        let reader = auth(&tenant, &["campaigns:read"]);

        let body = || SegmentWriteRequest {
            name: "High intent".into(),
            description: Some("opens and status".into()),
            list_ids: Some(vec![list.to_string()]),
            exclude_list_ids: Some(vec![]),
            r#match: Some(serde_json::json!({
                "tags_all": ["vip"],
                "tags_any": ["trial", "paid"],
                "statuses": ["active"]
            })),
        };
        let (status, Json(created)) =
            create_segment(State(state.clone()), writer.clone(), Json(body()))
                .await
                .expect("create segment");
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(created.name, "High intent");
        assert_eq!(created.list_ids, serde_json::json!([list.to_string()]));
        assert_eq!(created.r#match["tags_all"], serde_json::json!(["vip"]));

        // Duplicate name → 409, not a database 500.
        assert!(matches!(
            create_segment(State(state.clone()), writer.clone(), Json(body())).await,
            Err(ApiError::Conflict(_))
        ));

        // Bounds and malformed inputs.
        let mut too_many = SegmentWriteRequest {
            list_ids: Some(vec![list.to_string(); MAX_LISTS_PER_SEGMENT + 1]),
            ..body()
        };
        too_many.name = "Too many".into();
        assert!(matches!(
            create_segment(State(state.clone()), writer.clone(), Json(too_many)).await,
            Err(ApiError::Validation(_))
        ));
        let mut malformed = SegmentWriteRequest {
            list_ids: Some(vec!["not-a-uuid".into()]),
            ..body()
        };
        malformed.name = "Malformed".into();
        assert!(matches!(
            create_segment(State(state.clone()), writer.clone(), Json(malformed)).await,
            Err(ApiError::Validation(_))
        ));
        let mut foreign_list = SegmentWriteRequest {
            list_ids: Some(vec![Uuid::new_v4().to_string()]),
            ..body()
        };
        foreign_list.name = "Foreign list".into();
        assert!(matches!(
            create_segment(State(state.clone()), writer.clone(), Json(foreign_list)).await,
            Err(ApiError::NotFound(_))
        ));

        // Read + tenant isolation (the other tenant cannot get/update/delete).
        let Json(fetched) = get_segment(
            State(state.clone()),
            reader.clone(),
            Path(created.id.clone()),
        )
        .await
        .expect("get own segment");
        assert_eq!(fetched.id, created.id);
        let other_writer = auth(&other, &["campaigns:write"]);
        assert!(matches!(
            get_segment(
                State(state.clone()),
                auth(&other, &["campaigns:read"]),
                Path(created.id.clone())
            )
            .await,
            Err(ApiError::NotFound(_))
        ));
        assert!(matches!(
            update_segment(
                State(state.clone()),
                other_writer.clone(),
                Path(created.id.clone()),
                Json(SegmentWriteRequest {
                    name: "Hijacked".into(),
                    description: None,
                    list_ids: None,
                    exclude_list_ids: None,
                    r#match: None,
                })
            )
            .await,
            Err(ApiError::NotFound(_))
        ));
        assert!(matches!(
            delete_segment(State(state.clone()), other_writer, Path(created.id.clone())).await,
            Err(ApiError::NotFound(_))
        ));

        // Update + delete by the owner.
        let Json(updated) = update_segment(
            State(state.clone()),
            writer.clone(),
            Path(created.id.clone()),
            Json(SegmentWriteRequest {
                name: "High intent v2".into(),
                description: None,
                list_ids: Some(vec![]),
                exclude_list_ids: None,
                r#match: Some(serde_json::json!({"statuses": ["active"]})),
            }),
        )
        .await
        .expect("update segment");
        assert_eq!(updated.name, "High intent v2");
        assert_eq!(updated.list_ids, serde_json::json!([]));
        assert_eq!(
            delete_segment(State(state.clone()), writer, Path(created.id.clone()))
                .await
                .expect("delete"),
            StatusCode::NO_CONTENT
        );
        assert!(matches!(
            get_segment(State(state.clone()), reader, Path(created.id)).await,
            Err(ApiError::NotFound(_))
        ));

        sqlx::query("DELETE FROM lists WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .ok();
        for id in [&tenant, &other] {
            sqlx::query("DELETE FROM tenants WHERE id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .ok();
        }
        pool.close().await;
    }

    /// The FK contract the audit named: deleting a segment nulls the
    /// campaign's reference instead of deleting the campaign or failing.
    #[tokio::test]
    async fn segment_delete_nulls_the_campaign_reference() {
        let Some((state, pool, tenant, _other, list)) = fixture("segments_cascade").await else {
            return;
        };
        let writer = auth(&tenant, &["campaigns:write"]);
        let (_, Json(segment)) = create_segment(
            State(state.clone()),
            writer.clone(),
            Json(SegmentWriteRequest {
                name: "Cascade".into(),
                description: None,
                list_ids: Some(vec![list.to_string()]),
                exclude_list_ids: None,
                r#match: None,
            }),
        )
        .await
        .expect("create segment");
        let campaign = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO campaigns (id, tenant_id, name, status, segment_id, created_at, updated_at) \
             VALUES ($1, $2, 'Segmented', 'draft', $3, NOW(), NOW())",
        )
        .bind(campaign)
        .bind(&tenant)
        .bind(Uuid::parse_str(&segment.id).expect("segment id"))
        .execute(&pool)
        .await
        .expect("seed campaign");

        delete_segment(State(state.clone()), writer, Path(segment.id))
            .await
            .expect("delete segment");
        let segment_id: Option<Uuid> =
            sqlx::query_scalar("SELECT segment_id FROM campaigns WHERE id = $1")
                .bind(campaign)
                .fetch_one(&pool)
                .await
                .expect("campaign after delete");
        assert!(
            segment_id.is_none(),
            "ON DELETE SET NULL must clear the campaign reference"
        );

        sqlx::query("DELETE FROM campaigns WHERE id = $1")
            .bind(campaign)
            .execute(&pool)
            .await
            .ok();
        sqlx::query("DELETE FROM lists WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .ok();
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .ok();
        pool.close().await;
    }
}
