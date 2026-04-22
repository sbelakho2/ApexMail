//! SCIM 2.0 provisioning routes for enterprise SSO.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{invalidate_user_status_cache, require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/Users", get(list_users).post(create_user))
        .route("/Users/:id", get(get_user).put(update_user).delete(delete_user))
        .route("/Groups", get(list_groups).post(create_group))
        .route("/Groups/:id", get(get_group).put(update_group).patch(patch_group).delete(delete_group))
}

// ─── SCIM Types ────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ScimListResponse<T: Serialize> {
    pub schemas: Vec<String>,
    #[serde(rename = "totalResults")]
    pub total_results: i64,
    #[serde(rename = "startIndex")]
    pub start_index: i64,
    #[serde(rename = "itemsPerPage")]
    pub items_per_page: i64,
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScimUser {
    pub schemas: Vec<String>,
    pub id: String,
    #[serde(rename = "userName")]
    pub user_name: String,
    pub name: Option<ScimName>,
    pub emails: Vec<ScimEmail>,
    pub active: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScimName {
    #[serde(rename = "givenName")]
    pub given_name: Option<String>,
    #[serde(rename = "familyName")]
    pub family_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScimEmail {
    pub value: String,
    pub primary: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScimGroup {
    pub schemas: Vec<String>,
    pub id: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub members: Vec<ScimMember>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScimMember {
    pub value: String,
    pub display: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ScimListQuery {
    #[serde(default = "default_start")]
    #[serde(rename = "startIndex")]
    pub start_index: i64,
    #[serde(default = "default_count")]
    pub count: i64,
    #[serde(default)]
    pub cursor: Option<i64>,
}

fn default_start() -> i64 {
    1
}
fn default_count() -> i64 {
    100
}

const SCIM_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const SCIM_GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const SCIM_LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

/// Maximum allowed count parameter for list operations.
const MAX_SCIM_COUNT: i64 = 200;

/// SCIM placeholder hash that can never be valid Argon2.
/// Users with this hash must authenticate via SSO.
const SCIM_DISABLED_HASH: &str = "!scim:disabled";

// ─── Handlers ──────────────────────────────────────────────────

async fn list_users(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ScimListQuery>,
) -> Result<Json<ScimListResponse<ScimUser>>, ApiError> {
    require_scopes(&auth, &["scim:read"])?;

    let start_index = params.cursor.unwrap_or(params.start_index);
    let offset = (start_index - 1).max(0);
    let count = params.count.min(MAX_SCIM_COUNT);
    let total = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM users WHERE tenant_id = $1",
    )
    .bind(&auth.tenant_id)
    .fetch_one(&state.db)
    .await?;

    let rows = sqlx::query_as::<_, UserScimRow>(
        "SELECT id, email, name, status FROM users WHERE tenant_id = $1 ORDER BY email LIMIT $2 OFFSET $3",
    )
    .bind(&auth.tenant_id)
    .bind(count)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    let resources: Vec<ScimUser> = rows.into_iter().map(|r| ScimUser {
        schemas: vec![SCIM_USER_SCHEMA.into()],
        id: r.id.to_string(),
        user_name: r.email.clone(),
        name: r.name.map(|n| ScimName {
            given_name: Some(n),
            family_name: None,
        }),
        emails: vec![ScimEmail { value: r.email, primary: true }],
        active: r.status == "active",
    }).collect();

    Ok(Json(ScimListResponse {
        schemas: vec![SCIM_LIST_SCHEMA.into()],
        total_results: total,
        start_index: params.start_index,
        items_per_page: params.count,
        resources,
    }))
}

async fn create_user(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<ScimUser>,
) -> Result<(StatusCode, Json<ScimUser>), ApiError> {
    require_scopes(&auth, &["scim:write"])?;

    let email = body.emails.first()
        .map(|e| e.value.clone())
        .unwrap_or(body.user_name.clone());

    let name = body.name.as_ref().and_then(|n| n.given_name.clone());
    let id = Uuid::new_v4();
    let now = Utc::now();

// SCIM users must authenticate via SSO; direct password login is blocked.
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,'member','active',$6,$6)",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .bind(&email)
    .bind(&name)
    .bind(SCIM_DISABLED_HASH)
    .bind(now)
    .execute(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(ScimUser {
            schemas: vec![SCIM_USER_SCHEMA.into()],
            id: id.to_string(),
            user_name: email.clone(),
            name: name.map(|n| ScimName { given_name: Some(n), family_name: None }),
            emails: vec![ScimEmail { value: email, primary: true }],
            active: true,
        }),
    ))
}

async fn get_user(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ScimUser>, ApiError> {
    require_scopes(&auth, &["scim:read"])?;

    let row = sqlx::query_as::<_, UserScimRow>(
        "SELECT id, email, name, status FROM users WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("user not found".into()))?;

    Ok(Json(ScimUser {
        schemas: vec![SCIM_USER_SCHEMA.into()],
        id: row.id.to_string(),
        user_name: row.email.clone(),
        name: row.name.map(|n| ScimName { given_name: Some(n), family_name: None }),
        emails: vec![ScimEmail { value: row.email, primary: true }],
        active: row.status == "active",
    }))
}

async fn update_user(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<ScimUser>,
) -> Result<Json<ScimUser>, ApiError> {
    require_scopes(&auth, &["scim:write"])?;

    let email = body.emails.first().map(|e| e.value.clone()).unwrap_or(body.user_name.clone());
    let name = body.name.as_ref().and_then(|n| n.given_name.clone());
    let status = if body.active { "active" } else { "deactivated" };

    let result = sqlx::query(
        "UPDATE users SET email=$1, name=$2, status=$3, updated_at=NOW() WHERE id=$4 AND tenant_id=$5",
    )
    .bind(&email)
    .bind(&name)
    .bind(status)
    .bind(id)
    .bind(&auth.tenant_id)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("user not found".into()));
    }

    invalidate_user_status_cache(&id.to_string(), &auth.tenant_id, &state).await;

    Ok(Json(ScimUser {
        schemas: vec![SCIM_USER_SCHEMA.into()],
        id: id.to_string(),
        user_name: email.clone(),
        name: name.map(|n| ScimName { given_name: Some(n), family_name: None }),
        emails: vec![ScimEmail { value: email, primary: true }],
        active: body.active,
    }))
}

async fn delete_user(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["scim:write"])?;

    let result = sqlx::query(
        "UPDATE users SET status = 'deactivated', updated_at = NOW() WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("user not found".into()));
    }

    invalidate_user_status_cache(&id.to_string(), &auth.tenant_id, &state).await;

    Ok(StatusCode::NO_CONTENT)
}

async fn list_groups(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ScimListQuery>,
) -> Result<Json<ScimListResponse<ScimGroup>>, ApiError> {
    require_scopes(&auth, &["scim:read"])?;

    let start_index = params.cursor.unwrap_or(params.start_index);
    let offset = (start_index - 1).max(0);
    let count = params.count.min(MAX_SCIM_COUNT);
    let total = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM scim_groups WHERE tenant_id = $1",
    )
    .bind(&auth.tenant_id)
    .fetch_one(&state.db)
    .await?;

    let group_rows = sqlx::query_as::<_, GroupScimRow>(
        "SELECT id, scim_id, display_name, created_at FROM scim_groups 
         WHERE tenant_id = $1 ORDER BY display_name LIMIT $2 OFFSET $3",
    )
    .bind(&auth.tenant_id)
    .bind(count)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    let group_ids: Vec<String> = group_rows.iter().map(|r| r.id.clone()).collect();
    let all_members = if group_ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query_as::<_, GroupMemberWithGroupRow>(
            "SELECT m.group_id, m.user_id, m.display, u.email 
             FROM scim_group_members m
             LEFT JOIN users u ON u.id = m.user_id
             WHERE m.group_id = ANY($1) AND m.tenant_id = $2",
        )
        .bind(&group_ids)
        .bind(auth.tenant_id.to_string())
        .fetch_all(&state.db)
        .await?
    };

// Group members by group_id for efficient lookup.
    let mut members_by_group: std::collections::HashMap<String, Vec<ScimMember>> = 
        std::collections::HashMap::new();
    for m in all_members {
        members_by_group
            .entry(m.group_id.clone())
            .or_default()
            .push(ScimMember {
                value: m.user_id.to_string(),
                display: m.display.or(m.email),
            });
    }

    let resources: Vec<ScimGroup> = group_rows
        .into_iter()
        .map(|row| ScimGroup {
            schemas: vec![SCIM_GROUP_SCHEMA.into()],
            id: row.scim_id,
            display_name: row.display_name,
            members: members_by_group.remove(&row.id).unwrap_or_default(),
        })
        .collect();

    Ok(Json(ScimListResponse {
        schemas: vec![SCIM_LIST_SCHEMA.into()],
        total_results: total,
        start_index: params.start_index,
        items_per_page: params.count,
        resources,
    }))
}

async fn create_group(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<ScimGroup>,
) -> Result<(StatusCode, Json<ScimGroup>), ApiError> {
    require_scopes(&auth, &["scim:write"])?;

    let id = Uuid::new_v4();
    let scim_id = id.to_string();
    let now = Utc::now();

    sqlx::query(
        "INSERT INTO scim_groups (id, tenant_id, display_name, scim_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $5)",
    )
    .bind(id)
    .bind(auth.tenant_id.to_string())
    .bind(&body.display_name)
    .bind(&scim_id)
    .bind(now)
    .execute(&state.db)
    .await?;

// Add members if provided
    for member in &body.members {
        if let Ok(user_id) = Uuid::parse_str(&member.value) {
            sqlx::query(
                "INSERT INTO scim_group_members (group_id, user_id, tenant_id, display, created_at)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (group_id, user_id) DO NOTHING",
            )
            .bind(id)
            .bind(user_id)
            .bind(auth.tenant_id.to_string())
            .bind(&member.display)
            .bind(now)
            .execute(&state.db)
            .await?;
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(ScimGroup {
            schemas: vec![SCIM_GROUP_SCHEMA.into()],
            id: scim_id,
            display_name: body.display_name,
            members: body.members,
        }),
    ))
}

async fn get_group(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(scim_id): Path<String>,
) -> Result<Json<ScimGroup>, ApiError> {
    require_scopes(&auth, &["scim:read"])?;

    let row = sqlx::query_as::<_, GroupScimRow>(
        "SELECT id, scim_id, display_name, created_at FROM scim_groups 
         WHERE scim_id = $1 AND tenant_id = $2",
    )
    .bind(&scim_id)
    .bind(auth.tenant_id.to_string())
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("group not found".into()))?;

    let members = sqlx::query_as::<_, GroupMemberRow>(
        "SELECT m.user_id, m.display, u.email 
         FROM scim_group_members m
         LEFT JOIN users u ON u.id = m.user_id
            WHERE m.group_id = $1 AND m.tenant_id = $2",
    )
    .bind(row.id)
        .bind(auth.tenant_id.to_string())
    .fetch_all(&state.db)
    .await?;

    Ok(Json(ScimGroup {
        schemas: vec![SCIM_GROUP_SCHEMA.into()],
        id: row.scim_id,
        display_name: row.display_name,
        members: members.into_iter().map(|m| ScimMember {
            value: m.user_id.to_string(),
            display: m.display.or(m.email),
        }).collect(),
    }))
}

async fn update_group(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(scim_id): Path<String>,
    Json(body): Json<ScimGroup>,
) -> Result<Json<ScimGroup>, ApiError> {
    require_scopes(&auth, &["scim:write"])?;

    let row = sqlx::query_as::<_, GroupScimRow>(
        "SELECT id, scim_id, display_name, created_at FROM scim_groups 
         WHERE scim_id = $1 AND tenant_id = $2",
    )
    .bind(&scim_id)
    .bind(auth.tenant_id.to_string())
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("group not found".into()))?;

    sqlx::query(
        "UPDATE scim_groups SET display_name = $1, updated_at = NOW() WHERE id = $2",
    )
    .bind(&body.display_name)
    .bind(&row.id)
    .execute(&state.db)
    .await?;

// Replace members entirely
    sqlx::query("DELETE FROM scim_group_members WHERE group_id = $1 AND tenant_id = $2")
        .bind(&row.id)
        .bind(auth.tenant_id.to_string())
        .execute(&state.db)
        .await?;

    let now = Utc::now();
    for member in &body.members {
        if let Ok(user_id) = Uuid::parse_str(&member.value) {
            sqlx::query(
                "INSERT INTO scim_group_members (group_id, user_id, tenant_id, display, created_at)
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(&row.id)
            .bind(user_id)
            .bind(auth.tenant_id.to_string())
            .bind(&member.display)
            .bind(now)
            .execute(&state.db)
            .await?;
        }
    }

    Ok(Json(ScimGroup {
        schemas: vec![SCIM_GROUP_SCHEMA.into()],
        id: scim_id,
        display_name: body.display_name,
        members: body.members,
    }))
}

#[derive(Debug, Deserialize)]
struct ScimPatchOp {
    op: String,
    path: Option<String>,
    value: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ScimPatchRequest {
    #[serde(rename = "Operations")]
    operations: Vec<ScimPatchOp>,
}

async fn patch_group(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(scim_id): Path<String>,
    Json(body): Json<ScimPatchRequest>,
) -> Result<Json<ScimGroup>, ApiError> {
    require_scopes(&auth, &["scim:write"])?;

    let row = sqlx::query_as::<_, GroupScimRow>(
        "SELECT id, scim_id, display_name, created_at FROM scim_groups 
         WHERE scim_id = $1 AND tenant_id = $2",
    )
    .bind(&scim_id)
    .bind(auth.tenant_id.to_string())
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("group not found".into()))?;

    let mut display_name = row.display_name.clone();
    let now = Utc::now();

    for op in body.operations {
        match op.op.to_lowercase().as_str() {
            "replace" => {
                if op.path.as_deref() == Some("displayName") {
                    if let Some(serde_json::Value::String(val)) = op.value {
                        display_name = val;
                        sqlx::query("UPDATE scim_groups SET display_name = $1, updated_at = NOW() WHERE id = $2")
                            .bind(&display_name)
                            .bind(&row.id)
                            .execute(&state.db)
                            .await?;
                    }
                }
            }
            "add" => {
                if op.path.as_deref() == Some("members") {
                    if let Some(serde_json::Value::Array(members)) = op.value {
                        for member in members {
                            if let Some(value) = member.get("value").and_then(|v| v.as_str()) {
                                if let Ok(user_id) = Uuid::parse_str(value) {
                                    let display = member.get("display").and_then(|v| v.as_str()).map(|s| s.to_string());
                                    sqlx::query(
                                        "INSERT INTO scim_group_members (group_id, user_id, tenant_id, display, created_at)
                                         VALUES ($1, $2, $3, $4, $5) ON CONFLICT (group_id, user_id) DO NOTHING",
                                    )
                                    .bind(&row.id)
                                    .bind(user_id)
                                    .bind(auth.tenant_id.to_string())
                                    .bind(&display)
                                    .bind(now)
                                    .execute(&state.db)
                                    .await?;
                                }
                            }
                        }
                    }
                }
            }
            "remove" => {
                if let Some(path) = &op.path {
// Path like:members[value eq "user-uuid"]
                    if path.starts_with("members[value eq \"") {
                        let user_id_str = path.trim_start_matches("members[value eq \"").trim_end_matches("\"]");
                        if let Ok(user_id) = Uuid::parse_str(user_id_str) {
                            sqlx::query(
                                "DELETE FROM scim_group_members WHERE group_id = $1 AND user_id = $2 AND tenant_id = $3",
                            )
                                .bind(&row.id)
                                .bind(user_id)
                                .bind(auth.tenant_id.to_string())
                                .execute(&state.db)
                                .await?;
                        }
                    }
                }
            }
            _ => {}
        }
    }

// Fetch updated members
    let members = sqlx::query_as::<_, GroupMemberRow>(
        "SELECT m.user_id, m.display, u.email 
         FROM scim_group_members m
         LEFT JOIN users u ON u.id = m.user_id
            WHERE m.group_id = $1 AND m.tenant_id = $2",
    )
    .bind(&row.id)
        .bind(auth.tenant_id.to_string())
    .fetch_all(&state.db)
    .await?;

    Ok(Json(ScimGroup {
        schemas: vec![SCIM_GROUP_SCHEMA.into()],
        id: scim_id,
        display_name,
        members: members.into_iter().map(|m| ScimMember {
            value: m.user_id.to_string(),
            display: m.display.or(m.email),
        }).collect(),
    }))
}

async fn delete_group(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(scim_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["scim:write"])?;

    let result = sqlx::query(
        "DELETE FROM scim_groups WHERE scim_id = $1 AND tenant_id = $2",
    )
    .bind(&scim_id)
    .bind(auth.tenant_id.to_string())
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("group not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

// ─── Row types ─────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct UserScimRow {
    id: String,
    email: String,
    name: Option<String>,
    status: String,
}

#[derive(sqlx::FromRow)]
struct GroupScimRow {
    id: String,
    scim_id: String,
    display_name: String,
    #[allow(unused)]
    created_at: chrono::DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct GroupMemberRow {
    user_id: String,
    display: Option<String>,
    email: Option<String>,
}

#[derive(sqlx::FromRow)]
struct GroupMemberWithGroupRow {
    group_id: String,
    user_id: String,
    display: Option<String>,
    email: Option<String>,
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scim_user_serialisation() {
        let user = ScimUser {
            schemas: vec![SCIM_USER_SCHEMA.into()],
            id: String::new(),
            user_name: "alice@example.com".into(),
            name: Some(ScimName { given_name: Some("Alice".into()), family_name: None }),
            emails: vec![ScimEmail { value: "alice@example.com".into(), primary: true }],
            active: true,
        };
        let json = serde_json::to_value(&user).unwrap();
        assert_eq!(json["userName"], "alice@example.com");
    }

    #[test]
    fn test_scim_list_response() {
        let resp: ScimListResponse<ScimUser> = ScimListResponse {
            schemas: vec![SCIM_LIST_SCHEMA.into()],
            total_results: 0,
            start_index: 1,
            items_per_page: 100,
            resources: vec![],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["totalResults"], 0);
    }
}
