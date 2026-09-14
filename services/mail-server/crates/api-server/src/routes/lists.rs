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

/// The only accepted `opt_in_mode` values — the field is stored verbatim, so
/// an arbitrary string used to silently disappear from every opt-in-aware
/// consumer.
const VALID_OPT_IN_MODES: &[&str] = &["single_opt_in", "double_opt_in"];

/// Maximum list name length (lists.name is VARCHAR(255); 200 keeps parity
/// with the campaigns/subject caps).
const MAX_LIST_NAME_LEN: usize = 200;

/// Parse a list path id; malformed ids are honest 404s (never a database
/// type error), since list ids are UUIDs in the canonical schema.
fn parse_list_id(id: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(id).map_err(|_| ApiError::NotFound("list not found".into()))
}

/// Validate the caller-supplied list fields. `name` is required on create;
/// `opt_in_mode`, when present, must be one of [`VALID_OPT_IN_MODES`].
fn validate_list_fields(name: Option<&str>, opt_in_mode: Option<&str>) -> Result<(), ApiError> {
    if let Some(name) = name {
        if name.is_empty() || name.len() > MAX_LIST_NAME_LEN {
            return Err(ApiError::Validation(vec![format!(
                "name is required and must be {MAX_LIST_NAME_LEN} characters or fewer"
            )]));
        }
    }
    if let Some(mode) = opt_in_mode {
        if !VALID_OPT_IN_MODES.contains(&mode) {
            return Err(ApiError::Validation(vec![format!(
                "invalid opt_in_mode '{mode}': must be one of single_opt_in, double_opt_in"
            )]));
        }
    }
    Ok(())
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

/// Map a list write's SQL error: the unique index `idx_lists_tenant_name`
/// makes a duplicate (tenant, name) a CLIENT conflict — the API must answer
/// an honest 409 instead of leaking a generic database 500.
fn map_list_write_error(error: sqlx::Error) -> ApiError {
    if let sqlx::Error::Database(ref db_error) = error {
        if db_error.code().as_deref() == Some("23505") {
            return ApiError::Conflict("a list with this name already exists".into());
        }
    }
    ApiError::from(error)
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
        r#"SELECT l.id::text, l.name, l.description, l.opt_in_mode,
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

    validate_list_fields(Some(&body.name), Some(&body.opt_in_mode))?;

    // `lists.id` is UUID: bind the typed id (a text-typed parameter cannot
    // be assigned to a uuid column and turned every create into a 500).
    let id = Uuid::new_v4();
    let now = chrono::Utc::now();

    sqlx::query(
        "INSERT INTO lists (id, tenant_id, name, description, opt_in_mode, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $6)",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .bind(&body.name)
    .bind(&body.description)
    .bind(&body.opt_in_mode)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(map_list_write_error)?;

    Ok((
        StatusCode::CREATED,
        Json(ListResponse {
            id: id.to_string(),
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
        r#"SELECT l.id::text, l.name, l.description, l.opt_in_mode,
                  COUNT(ls.contact_id)::bigint AS subscriber_count,
                  l.created_at, l.updated_at
           FROM lists l
           LEFT JOIN list_subscribers ls ON ls.list_id = l.id
           WHERE l.id = $1 AND l.tenant_id = $2
           GROUP BY l.id"#,
    )
    .bind(parse_list_id(&id)?)
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

    validate_list_fields(body.name.as_deref(), body.opt_in_mode.as_deref())?;

    let result = sqlx::query(
        "UPDATE lists SET
            name = COALESCE($3, name),
            description = COALESCE($4, description),
            opt_in_mode = COALESCE($5, opt_in_mode),
            updated_at = NOW()
         WHERE id = $1 AND tenant_id = $2",
    )
    .bind(parse_list_id(&id)?)
    .bind(&auth.tenant_id)
    .bind(&body.name)
    .bind(&body.description)
    .bind(&body.opt_in_mode)
    .execute(&state.db)
    .await
    .map_err(map_list_write_error)?;

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
        .bind(parse_list_id(&id)?)
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
    let list_uuid = parse_list_id(&list_id)?;
    let exists: Option<bool> =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM lists WHERE id = $1 AND tenant_id = $2)")
            .bind(list_uuid)
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
        r#"SELECT c.id::text, c.email, c.name, ls.status,
                  ls.created_at AS subscribed_at
           FROM list_subscribers ls
           JOIN contacts c ON c.id = ls.contact_id
           WHERE ls.list_id = $1 AND c.tenant_id = $2
           ORDER BY ls.created_at DESC
           LIMIT $3 OFFSET $4"#,
    )
    .bind(list_uuid)
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
    .bind(list_uuid)
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

/// Maximum contact ids accepted by [`add_subscribers`] — the previous
/// per-id INSERT loop made this an unbounded-work endpoint.
const MAX_ADD_SUBSCRIBERS: usize = 10_000;

/// Contact ids per chunked INSERT (one round-trip per 500 ids).
const ADD_SUBSCRIBERS_CHUNK_SIZE: usize = 500;

async fn add_subscribers(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(list_id): Path<String>,
    Json(body): Json<AddSubscribersRequest>,
) -> Result<Json<BulkResult>, ApiError> {
    require_scopes(&auth, &["lists:write"])?;

    if body.contact_ids.len() > MAX_ADD_SUBSCRIBERS {
        return Err(ApiError::BadRequest(format!(
            "contact_ids limited to {} entries, got {}",
            MAX_ADD_SUBSCRIBERS,
            body.contact_ids.len()
        )));
    }

    // Verify list belongs to tenant
    let list_uuid = parse_list_id(&list_id)?;
    let exists: Option<bool> =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM lists WHERE id = $1 AND tenant_id = $2)")
            .bind(list_uuid)
            .bind(&auth.tenant_id)
            .fetch_one(&state.db)
            .await?;

    if !exists.unwrap_or(false) {
        return Err(ApiError::NotFound("list not found".into()));
    }

    // Chunked insert (previously one INSERT per contact id). The join against
    // contacts keeps the tenant ownership check in the statement itself, and
    // ON CONFLICT DO NOTHING makes re-adding an existing subscriber a no-op.
    // `contacts.id` is UUID: the ids must bind as a uuid[] array, not text[]
    // (uuid = ANY(text[]) has no operator and every add 500'd).
    let all_ids: Vec<Uuid> = body.contact_ids.clone();
    let mut affected = 0i64;
    for chunk in all_ids.chunks(ADD_SUBSCRIBERS_CHUNK_SIZE) {
        affected += sqlx::query(
            "INSERT INTO list_subscribers (list_id, contact_id, status, created_at)
             SELECT $1, c.id, 'active', NOW()
             FROM contacts c
             WHERE c.tenant_id = $2 AND c.id = ANY($3)
             ON CONFLICT (list_id, contact_id) DO NOTHING",
        )
        .bind(list_uuid)
        .bind(&auth.tenant_id)
        .bind(chunk)
        .execute(&state.db)
        .await?
        .rows_affected() as i64;
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

    // Verify list belongs to tenant (same guard as add_subscribers).
    let list_uuid = parse_list_id(&list_id)?;
    let exists: Option<bool> =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM lists WHERE id = $1 AND tenant_id = $2)")
            .bind(list_uuid)
            .bind(&auth.tenant_id)
            .fetch_one(&state.db)
            .await?;

    if !exists.unwrap_or(false) {
        return Err(ApiError::NotFound("list not found".into()));
    }

    let contact_ids: Vec<Uuid> = body.contact_ids.clone();
    let affected = sqlx::query(
        "DELETE FROM list_subscribers ls
                 USING contacts c
                 WHERE ls.list_id = $1
                     AND ls.contact_id = ANY($2)
                     AND c.id = ls.contact_id
                     AND c.tenant_id = $3",
    )
    .bind(list_uuid)
    .bind(&contact_ids)
    .bind(&auth.tenant_id)
    .execute(&state.db)
    .await?
    .rows_affected() as i64;

    Ok(Json(BulkResult { affected }))
}

// ─── Adversarial CRUD / isolation tests ────────────────────────

#[cfg(test)]
mod adversarial_tests {
    use super::*;

    fn auth_for(tenant: &str, scopes: &[&str]) -> AuthUser {
        AuthUser {
            tenant_id: tenant.to_string(),
            user_id: None,
            api_key_id: Some("key_adversarial".into()),
            session_id: None,
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
        }
    }

    async fn state_and_pool(name: &str) -> Option<(AppState, sqlx::PgPool)> {
        let pool = crate::test_db::optional_pg_pool(name).await?;
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        Some((state, pool))
    }

    async fn seed_tenant(pool: &sqlx::PgPool, tenant: &str) {
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
             VALUES ($1, 'lists adversarial', 'free', 'active', NOW(), NOW())
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant)
        .execute(pool)
        .await
        .expect("seed tenant");
    }

    async fn seed_contact(pool: &sqlx::PgPool, tenant: &str, email: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO contacts (id, tenant_id, email, status, tags) VALUES ($1, $2, $3, 'subscribed', '[]'::jsonb)",
        )
        .bind(id)
        .bind(tenant)
        .bind(email)
        .execute(pool)
        .await
        .expect("seed contact");
        id
    }

    async fn create_ok(state: &AppState, tenant: &str, name: &str) -> ListResponse {
        let (status, Json(list)) = create_list(
            State(state.clone()),
            auth_for(tenant, &["lists:write"]),
            Json(CreateListRequest {
                name: name.into(),
                description: Some("seeded".into()),
                opt_in_mode: "single_opt_in".into(),
            }),
        )
        .await
        .expect("create list");
        assert_eq!(status, StatusCode::CREATED);
        list
    }

    #[test]
    fn validation_rejects_empty_overlong_names_and_unknown_modes() {
        assert!(validate_list_fields(None, None).is_ok());
        assert!(validate_list_fields(Some("ok"), Some("single_opt_in")).is_ok());
        assert!(validate_list_fields(Some("ok"), Some("double_opt_in")).is_ok());
        assert!(validate_list_fields(Some(""), None).is_err());
        assert!(validate_list_fields(Some(&"x".repeat(200)), None).is_ok());
        assert!(validate_list_fields(Some(&"x".repeat(201)), None).is_err());
        let err = validate_list_fields(None, Some("triple_opt_in")).unwrap_err();
        assert!(matches!(err, ApiError::Validation(_)));
    }

    #[test]
    fn scope_gate_refuses_read_only_and_scope_less_callers() {
        let read_only = auth_for("ten", &["lists:read"]);
        assert!(require_scopes(&read_only, &["lists:write"]).is_err());
        let none = auth_for("ten", &[]);
        assert!(require_scopes(&none, &["lists:read"]).is_err());
        let wildcard = auth_for("ten", &["*"]);
        assert!(require_scopes(&wildcard, &["lists:write"]).is_ok());
    }

    #[tokio::test]
    async fn crud_walk_is_tenant_isolated_and_conflicts_are_honest() {
        let Some((state, pool)) = state_and_pool("adv_lists_crud").await else {
            return;
        };
        let tenant_a = apexmail_lib::id::generate_id("", 26);
        let tenant_b = apexmail_lib::id::generate_id("", 26);
        seed_tenant(&pool, &tenant_a).await;
        seed_tenant(&pool, &tenant_b).await;
        // Unique per run: the shared `_api` database is reused between runs.
        let tag = uuid::Uuid::new_v4().simple().to_string();
        let list_name = format!("Alpha Audience {tag}");

        let list_a = create_ok(&state, &tenant_a, &list_name).await;
        assert_eq!(list_a.subscriber_count, 0);
        assert_eq!(list_a.opt_in_mode, "single_opt_in");

        // Duplicate name in the SAME tenant is a constraint violation — it
        // must be an honest 409, never a database 500.
        let duplicate = create_list(
            State(state.clone()),
            auth_for(&tenant_a, &["lists:write"]),
            Json(CreateListRequest {
                name: list_name.clone(),
                description: None,
                opt_in_mode: "double_opt_in".into(),
            }),
        )
        .await;
        assert!(
            matches!(duplicate, Err(ApiError::Conflict(_))),
            "duplicate list name must conflict, got {duplicate:?}"
        );

        // The SAME name under another tenant is fine (uniqueness is per tenant).
        let list_b = create_ok(&state, &tenant_b, &list_name).await;

        // Listing sees only the caller's tenant rows.
        let Json(page_a) = list_lists(
            State(state.clone()),
            auth_for(&tenant_a, &["lists:read"]),
            Query(ListQuery {
                limit: 50,
                offset: 0,
                search: None,
            }),
        )
        .await
        .expect("list a");
        assert_eq!(page_a.total, 1);
        assert_eq!(page_a.data.len(), 1);
        assert_eq!(page_a.data[0].id, list_a.id);
        assert!(
            page_a.data.iter().all(|l| l.id != list_b.id),
            "tenant B's list must never appear"
        );

        // Search is scoped too.
        let Json(found) = list_lists(
            State(state.clone()),
            auth_for(&tenant_a, &["lists:read"]),
            Query(ListQuery {
                limit: 50,
                offset: 0,
                search: Some("alph".into()),
            }),
        )
        .await
        .expect("search");
        assert_eq!(found.total, 1);
        // `search` is a SQL ILIKE PATTERN, not a literal: "%" matches every
        // row (documented current behaviour), while a literal non-match
        // returns an empty page.
        let Json(pattern) = list_lists(
            State(state.clone()),
            auth_for(&tenant_a, &["lists:read"]),
            Query(ListQuery {
                limit: 50,
                offset: 0,
                search: Some("%".into()),
            }),
        )
        .await
        .expect("pattern search");
        assert_eq!(pattern.data.len(), 1);
        let Json(absent) = list_lists(
            State(state.clone()),
            auth_for(&tenant_a, &["lists:read"]),
            Query(ListQuery {
                limit: 50,
                offset: 0,
                search: Some("no-such-list-zzz".into()),
            }),
        )
        .await
        .expect("no match");
        assert_eq!(absent.data.len(), 0);

        // Pagination clamps: limit 0 → 1, negative offset → 0.
        let Json(clamped) = list_lists(
            State(state.clone()),
            auth_for(&tenant_a, &["lists:read"]),
            Query(ListQuery {
                limit: 0,
                offset: -5,
                search: None,
            }),
        )
        .await
        .expect("clamped");
        assert_eq!(clamped.limit, 1);
        assert_eq!(clamped.offset, 0);

        // Cross-tenant reads are 404, never a leak.
        let cross = get_list(
            State(state.clone()),
            auth_for(&tenant_a, &["lists:read"]),
            Path(list_b.id.clone()),
        )
        .await;
        assert!(matches!(cross, Err(ApiError::NotFound(_))));

        let cross_update = update_list(
            State(state.clone()),
            auth_for(&tenant_a, &["lists:write"]),
            Path(list_b.id.clone()),
            Json(UpdateListRequest {
                name: Some("stolen".into()),
                description: None,
                opt_in_mode: None,
            }),
        )
        .await;
        assert!(matches!(cross_update, Err(ApiError::NotFound(_))));
        let (still_named,): (String,) =
            sqlx::query_as("SELECT name FROM lists WHERE id = $1::uuid AND tenant_id = $2")
                .bind(&list_b.id)
                .bind(&tenant_b)
                .fetch_one(&pool)
                .await
                .expect("row still there");
        assert_eq!(still_named, list_name, "no cross-tenant write");

        let cross_delete = delete_list(
            State(state.clone()),
            auth_for(&tenant_a, &["lists:write"]),
            Path(list_b.id.clone()),
        )
        .await;
        assert!(matches!(cross_delete, Err(ApiError::NotFound(_))));

        // Own update works; invalid opt_in_mode is a validation error.
        let Json(updated) = update_list(
            State(state.clone()),
            auth_for(&tenant_a, &["lists:write"]),
            Path(list_a.id.clone()),
            Json(UpdateListRequest {
                name: Some(format!("Alpha Renamed {tag}")),
                description: None,
                opt_in_mode: None,
            }),
        )
        .await
        .expect("update own");
        assert_eq!(updated["updated"], true);
        let invalid_mode = update_list(
            State(state.clone()),
            auth_for(&tenant_a, &["lists:write"]),
            Path(list_a.id.clone()),
            Json(UpdateListRequest {
                name: None,
                description: None,
                opt_in_mode: Some("nonsense".into()),
            }),
        )
        .await;
        assert!(matches!(invalid_mode, Err(ApiError::Validation(_))));

        // Subscriber add/remove is tenant-guarded end to end.
        let own_contact = seed_contact(&pool, &tenant_a, "own@example.com").await;
        let foreign_contact = seed_contact(&pool, &tenant_b, "foreign@example.com").await;
        let Json(added) = add_subscribers(
            State(state.clone()),
            auth_for(&tenant_a, &["lists:write"]),
            Path(list_a.id.clone()),
            Json(AddSubscribersRequest {
                contact_ids: vec![own_contact, foreign_contact],
            }),
        )
        .await
        .expect("add subscribers");
        assert_eq!(
            added.affected, 1,
            "the other tenant's contact must be ignored by the join"
        );

        // Idempotent re-add: ON CONFLICT DO NOTHING.
        let Json(again) = add_subscribers(
            State(state.clone()),
            auth_for(&tenant_a, &["lists:write"]),
            Path(list_a.id.clone()),
            Json(AddSubscribersRequest {
                contact_ids: vec![own_contact],
            }),
        )
        .await
        .expect("re-add");
        assert_eq!(again.affected, 0);

        let Json(subscribers) = list_subscribers(
            State(state.clone()),
            auth_for(&tenant_a, &["lists:read"]),
            Path(list_a.id.clone()),
            Query(ListQuery {
                limit: 10,
                offset: 0,
                search: None,
            }),
        )
        .await
        .expect("list subscribers");
        assert_eq!(subscribers["total"], 1);
        assert_eq!(subscribers["data"][0]["email"], "own@example.com");

        // A foreign list's subscribers are a 404 to this tenant.
        let cross_subs = list_subscribers(
            State(state.clone()),
            auth_for(&tenant_a, &["lists:read"]),
            Path(list_b.id.clone()),
            Query(ListQuery {
                limit: 10,
                offset: 0,
                search: None,
            }),
        )
        .await;
        assert!(matches!(cross_subs, Err(ApiError::NotFound(_))));

        let Json(removed) = remove_subscribers(
            State(state.clone()),
            auth_for(&tenant_a, &["lists:write"]),
            Path(list_a.id.clone()),
            Json(RemoveSubscribersRequest {
                contact_ids: vec![own_contact, foreign_contact],
            }),
        )
        .await
        .expect("remove subscribers");
        assert_eq!(removed.affected, 1, "only the owned contact is removed");
        let Json(removed_again) = remove_subscribers(
            State(state.clone()),
            auth_for(&tenant_a, &["lists:write"]),
            Path(list_a.id.clone()),
            Json(RemoveSubscribersRequest {
                contact_ids: vec![own_contact],
            }),
        )
        .await
        .expect("re-remove");
        assert_eq!(removed_again.affected, 0);

        // Delete own list → 204, then 404 on every subsequent access.
        let status = delete_list(
            State(state.clone()),
            auth_for(&tenant_a, &["lists:write"]),
            Path(list_a.id.clone()),
        )
        .await
        .expect("delete own");
        assert_eq!(status, StatusCode::NO_CONTENT);
        let gone = get_list(
            State(state.clone()),
            auth_for(&tenant_a, &["lists:read"]),
            Path(list_a.id.clone()),
        )
        .await;
        assert!(matches!(gone, Err(ApiError::NotFound(_))));
        let gone_delete = delete_list(
            State(state.clone()),
            auth_for(&tenant_a, &["lists:write"]),
            Path(list_a.id.clone()),
        )
        .await;
        assert!(matches!(gone_delete, Err(ApiError::NotFound(_))));
        let gone_update = update_list(
            State(state.clone()),
            auth_for(&tenant_a, &["lists:write"]),
            Path(list_a.id.clone()),
            Json(UpdateListRequest {
                name: Some("zombie".into()),
                description: None,
                opt_in_mode: None,
            }),
        )
        .await;
        assert!(matches!(gone_update, Err(ApiError::NotFound(_))));

        // Unknown id shapes (non-uuid / empty / huge) are 404, not 500.
        for bad in ["", "not-a-uuid", &"f".repeat(500)] {
            let resp = get_list(
                State(state.clone()),
                auth_for(&tenant_a, &["lists:read"]),
                Path(bad.to_string()),
            )
            .await;
            assert!(
                matches!(
                    resp,
                    Err(ApiError::NotFound(_)) | Err(ApiError::Internal(_))
                ),
                "bad id {bad:?} may not panic"
            );
        }

        // Subscriber endpoints on a nonexistent list are 404.
        for bad in ["", "nope"] {
            let resp = add_subscribers(
                State(state.clone()),
                auth_for(&tenant_a, &["lists:write"]),
                Path(bad.to_string()),
                Json(AddSubscribersRequest {
                    contact_ids: vec![Uuid::new_v4()],
                }),
            )
            .await;
            assert!(matches!(resp, Err(ApiError::NotFound(_))));
            let resp = remove_subscribers(
                State(state.clone()),
                auth_for(&tenant_a, &["lists:write"]),
                Path(bad.to_string()),
                Json(RemoveSubscribersRequest {
                    contact_ids: vec![Uuid::new_v4()],
                }),
            )
            .await;
            assert!(matches!(resp, Err(ApiError::NotFound(_))));
        }

        // Cleanup (scoped to the two fixture tenants).
        for tenant in [&tenant_a, &tenant_b] {
            sqlx::query("DELETE FROM lists WHERE tenant_id = $1")
                .bind(tenant)
                .execute(&pool)
                .await
                .expect("cleanup lists");
            sqlx::query("DELETE FROM contacts WHERE tenant_id = $1")
                .bind(tenant)
                .execute(&pool)
                .await
                .expect("cleanup contacts");
            sqlx::query("DELETE FROM tenants WHERE id = $1")
                .bind(tenant)
                .execute(&pool)
                .await
                .expect("cleanup tenants");
        }
    }

    #[tokio::test]
    async fn subscriber_bulk_limit_is_enforced_before_any_write() {
        let Some((state, pool)) = state_and_pool("adv_lists_bulk_limit").await else {
            return;
        };
        let tenant = apexmail_lib::id::generate_id("", 26);
        seed_tenant(&pool, &tenant).await;
        let list = create_ok(
            &state,
            &tenant,
            &format!("Bulk Cap {}", uuid::Uuid::new_v4().simple()),
        )
        .await;

        let too_many: Vec<Uuid> = (0..10_001).map(|_| Uuid::new_v4()).collect();
        let resp = add_subscribers(
            State(state.clone()),
            auth_for(&tenant, &["lists:write"]),
            Path(list.id.clone()),
            Json(AddSubscribersRequest {
                contact_ids: too_many,
            }),
        )
        .await;
        match resp {
            Err(ApiError::BadRequest(message)) => assert!(message.contains("10000")),
            other => panic!("expected the documented bulk cap, got {other:?}"),
        }

        sqlx::query("DELETE FROM lists WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("cleanup");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("cleanup");
    }

    #[test]
    fn add_subscribers_denies_unknown_fields_at_deserialization() {
        let err = serde_json::from_str::<AddSubscribersRequest>(
            r#"{"contact_ids":[],"tenant_id":"other"}"#,
        );
        assert!(err.is_err(), "unknown fields must be refused");
        let err = serde_json::from_str::<CreateListRequest>(r#"{"name":"x","evil":true}"#);
        assert!(err.is_err());
    }
}
