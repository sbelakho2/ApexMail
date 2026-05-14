//! Contact list / audience management routes.
//!
//! Routes://! GET / → list all lists for tenant
//! POST / → create a new list
//! GET /:id → get a single list
//! PUT /:id → update a list
//! DELETE /:id → delete a list
//! GET /:id/subscribers → list subscribers in a list
//! POST /:id/subscribers → add subscriber(s) to a list
//! DELETE /:id/subscribers → remove subscriber(s) from a list

use super::helpers::default_limit;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_lists).post(create_list))
        .route("/:id", get(get_list).put(update_list).delete(delete_list))
        .route(
            "/:id/subscribers",
            get(list_subscribers)
                .post(add_subscribers)
                .delete(remove_subscribers),
        )
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateListRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// "single_opt_in" | "double_opt_in"
    #[serde(default = "default_opt_in")]
    pub opt_in_mode: String,
}

fn default_opt_in() -> String {
    "double_opt_in".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateListRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub opt_in_mode: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub opt_in_mode: String,
    pub subscriber_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub search: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListsPageResponse {
    pub data: Vec<ListResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Serialize)]
pub struct SubscriberResponse {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub status: String,
    pub subscribed_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddSubscribersRequest {
    pub contact_ids: Vec<Uuid>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoveSubscribersRequest {
    pub contact_ids: Vec<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct BulkResult {
    pub affected: i64,
}

// ─── Handlers ──────────────────────────────────────────────────

async fn list_lists(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<ListQuery>,
) -> Result<Json<ListsPageResponse>, ApiError> {
    require_scopes(&auth, &["lists:read"])?;
    let limit = q.limit.clamp(1, 200);
    let offset = q.offset.max(0);

    let rows = sqlx::query_as::<_, ListRow>(
        r#"SELECT l.id, l.name, l.description, l.opt_in_mode,
                  COUNT(ls.contact_id)::bigint AS subscriber_count,
                  l.created_at, l.updated_at
           FROM lists l
           LEFT JOIN list_subscribers ls ON ls.list_id = l.id
           WHERE l.tenant_id = $1
             AND ($4::text IS NULL OR l.name ILIKE '%' || $4 || '%')
           GROUP BY l.id
           ORDER BY l.created_at DESC
           LIMIT $2 OFFSET $3"#,
    )
    .bind(auth.tenant_id.to_string())
    .bind(limit)
    .bind(offset)
    .bind(q.search.as_deref())
    .fetch_all(&state.db)
    .await?;

    let total =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM lists WHERE tenant_id = $1")
            .bind(auth.tenant_id.to_string())
            .fetch_one(&state.db)
            .await?;

    let data = rows
        .into_iter()
        .map(|r| ListResponse {
            id: r.id,
            name: r.name,
            description: r.description,
            opt_in_mode: r.opt_in_mode,
            subscriber_count: r.subscriber_count,
            created_at: r.created_at.to_rfc3339(),
            updated_at: r.updated_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(ListsPageResponse {
        data,
        total,
        limit,
        offset,
    }))
}

#[derive(sqlx::FromRow)]
struct ListRow {
    id: String,
    name: String,
    description: Option<String>,
    opt_in_mode: String,
    subscriber_count: i64,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

async fn create_list(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateListRequest>,
) -> Result<(StatusCode, Json<ListResponse>), ApiError> {
    require_scopes(&auth, &["lists:write"])?;

    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now();

    sqlx::query(
        "INSERT INTO lists (id, tenant_id, name, description, opt_in_mode, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $6)",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .bind(&body.name)
    .bind(&body.description)
    .bind(&body.opt_in_mode)
    .bind(now)
    .execute(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(ListResponse {
            id,
            name: body.name,
            description: body.description,
            opt_in_mode: body.opt_in_mode,
            subscriber_count: 0,
            created_at: now.to_rfc3339(),
            updated_at: now.to_rfc3339(),
        }),
    ))
}

async fn get_list(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<ListResponse>, ApiError> {
    require_scopes(&auth, &["lists:read"])?;

    let row = sqlx::query_as::<_, ListRow>(
        r#"SELECT l.id, l.name, l.description, l.opt_in_mode,
                  COUNT(ls.contact_id)::bigint AS subscriber_count,
                  l.created_at, l.updated_at
           FROM lists l
           LEFT JOIN list_subscribers ls ON ls.list_id = l.id
           WHERE l.id = $1 AND l.tenant_id = $2
           GROUP BY l.id"#,
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound("list not found".into()))?;

    Ok(Json(ListResponse {
        id: row.id,
        name: row.name,
        description: row.description,
        opt_in_mode: row.opt_in_mode,
        subscriber_count: row.subscriber_count,
        created_at: row.created_at.to_rfc3339(),
        updated_at: row.updated_at.to_rfc3339(),
    }))
}

async fn update_list(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<UpdateListRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["lists:write"])?;

    let result = sqlx::query(
        "UPDATE lists SET
            name = COALESCE($3, name),
            description = COALESCE($4, description),
            opt_in_mode = COALESCE($5, opt_in_mode),
            updated_at = NOW()
         WHERE id = $1 AND tenant_id = $2",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .bind(&body.name)
    .bind(&body.description)
    .bind(&body.opt_in_mode)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("list not found".into()));
    }

    Ok(Json(serde_json::json!({ "updated": true })))
}

async fn delete_list(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["lists:write"])?;

    let result = sqlx::query("DELETE FROM lists WHERE id = $1 AND tenant_id = $2")
        .bind(&id)
        .bind(&auth.tenant_id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("list not found".into()));
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn list_subscribers(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(list_id): Path<String>,
    Query(q): Query<ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["lists:read"])?;
    let limit = q.limit.clamp(1, 200);
    let offset = q.offset.max(0);

    // Verify list belongs to tenant
    let exists: Option<bool> =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM lists WHERE id = $1 AND tenant_id = $2)")
            .bind(&list_id)
            .bind(&auth.tenant_id)
            .fetch_one(&state.db)
            .await?;

    if !exists.unwrap_or(false) {
        return Err(ApiError::NotFound("list not found".into()));
    }

    #[derive(sqlx::FromRow)]
    struct SubscriberRow {
        id: String,
        email: String,
        name: Option<String>,
        status: String,
        subscribed_at: chrono::DateTime<chrono::Utc>,
    }

    let rows = sqlx::query_as::<_, SubscriberRow>(
        r#"SELECT c.id, c.email, c.name, ls.status,
                  ls.created_at AS subscribed_at
           FROM list_subscribers ls
           JOIN contacts c ON c.id = ls.contact_id
           WHERE ls.list_id = $1 AND c.tenant_id = $2
           ORDER BY ls.created_at DESC
           LIMIT $3 OFFSET $4"#,
    )
    .bind(&list_id)
    .bind(&auth.tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    let total: i64 = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT COUNT(*)::bigint
         FROM list_subscribers ls
         JOIN contacts c ON c.id = ls.contact_id
         WHERE ls.list_id = $1 AND c.tenant_id = $2",
    )
    .bind(&list_id)
    .bind(&auth.tenant_id)
    .fetch_one(&state.db)
    .await?
    .unwrap_or(0);

    let subscribers: Vec<SubscriberResponse> = rows
        .into_iter()
        .map(|r| SubscriberResponse {
            id: r.id,
            email: r.email,
            name: r.name,
            status: r.status,
            subscribed_at: r.subscribed_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(serde_json::json!({
        "data": subscribers,
        "total": total,
        "limit": limit,
        "offset": offset,
    })))
}

async fn add_subscribers(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(list_id): Path<String>,
    Json(body): Json<AddSubscribersRequest>,
) -> Result<Json<BulkResult>, ApiError> {
    require_scopes(&auth, &["lists:write"])?;

    // Verify list belongs to tenant
    let exists: Option<bool> =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM lists WHERE id = $1 AND tenant_id = $2)")
            .bind(&list_id)
            .bind(&auth.tenant_id)
            .fetch_one(&state.db)
            .await?;

    if !exists.unwrap_or(false) {
        return Err(ApiError::NotFound("list not found".into()));
    }

    let mut affected = 0i64;
    for contact_id in &body.contact_ids {
        let result = sqlx::query(
            "INSERT INTO list_subscribers (list_id, contact_id, status, created_at)
             SELECT $1, c.id, 'active', NOW()
             FROM contacts c
             WHERE c.id = $2 AND c.tenant_id = $3
             ON CONFLICT (list_id, contact_id) DO NOTHING",
        )
        .bind(&list_id)
        .bind(contact_id.to_string())
        .bind(&auth.tenant_id)
        .execute(&state.db)
        .await?;
        affected += result.rows_affected() as i64;
    }

    Ok(Json(BulkResult { affected }))
}

async fn remove_subscribers(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(list_id): Path<String>,
    Json(body): Json<RemoveSubscribersRequest>,
) -> Result<Json<BulkResult>, ApiError> {
    require_scopes(&auth, &["lists:write"])?;

    let contact_ids: Vec<String> = body.contact_ids.iter().map(|id| id.to_string()).collect();
    let affected = sqlx::query(
        "DELETE FROM list_subscribers ls
                 USING contacts c
                 WHERE ls.list_id = $1
                     AND ls.contact_id = ANY($2)
                     AND c.id = ls.contact_id
                     AND c.tenant_id = $3",
    )
    .bind(&list_id)
    .bind(&contact_ids)
    .bind(&auth.tenant_id)
    .execute(&state.db)
    .await?
    .rows_affected() as i64;

    Ok(Json(BulkResult { affected }))
}
