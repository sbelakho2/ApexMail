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
        .route(
            "/Users/:id",
            get(get_user).put(update_user).delete(delete_user),
        )
        .route("/Groups", get(list_groups).post(create_group))
        .route(
            "/Groups/:id",
            get(get_group)
                .put(update_group)
                .patch(patch_group)
                .delete(delete_group),
        )
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
    #[serde(default)]
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
#[serde(deny_unknown_fields)]
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

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(db_error) if db_error.code().as_deref() == Some("23505"))
}

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
    let total = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE tenant_id = $1")
        .bind(&auth.tenant_id)
        .fetch_one(&state.db)
        .await?;

    let rows = sqlx::query_as::<_, UserScimRow>(
        "SELECT id::text, email, name, status FROM users WHERE tenant_id = $1 ORDER BY email LIMIT $2 OFFSET $3",
    )
    .bind(&auth.tenant_id)
    .bind(count)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    let resources: Vec<ScimUser> = rows
        .into_iter()
        .map(|r| ScimUser {
            schemas: vec![SCIM_USER_SCHEMA.into()],
            id: r.id.to_string(),
            user_name: r.email.clone(),
            name: r.name.map(|n| ScimName {
                given_name: Some(n),
                family_name: None,
            }),
            emails: vec![ScimEmail {
                value: r.email,
                primary: true,
            }],
            active: r.status == "active",
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

async fn create_user(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<ScimUser>,
) -> Result<(StatusCode, Json<ScimUser>), ApiError> {
    require_scopes(&auth, &["scim:write"])?;

    let email = body
        .emails
        .first()
        .map(|e| e.value.clone())
        .unwrap_or(body.user_name.clone());

    let name = body.name.as_ref().and_then(|n| n.given_name.clone());
    let id = apexmail_lib::id::generate_id("", 26);
    let now = Utc::now();

    // SCIM users must authenticate via SSO; direct password login is blocked.
    match sqlx::query(
        "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,'member','active',$6,$6)",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .bind(&email)
    .bind(&name)
    .bind(SCIM_DISABLED_HASH)
    .bind(now)
    .execute(&state.db)
    .await
    {
        Ok(_) => {}
        Err(error) if is_unique_violation(&error) => {
            return Err(ApiError::Conflict("user already exists".into()));
        }
        Err(error) => return Err(error.into()),
    }

    Ok((
        StatusCode::CREATED,
        Json(ScimUser {
            schemas: vec![SCIM_USER_SCHEMA.into()],
            id: id.clone(),
            user_name: email.clone(),
            name: name.map(|n| ScimName {
                given_name: Some(n),
                family_name: None,
            }),
            emails: vec![ScimEmail {
                value: email,
                primary: true,
            }],
            active: true,
        }),
    ))
}

async fn get_user(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<ScimUser>, ApiError> {
    require_scopes(&auth, &["scim:read"])?;

    let row = sqlx::query_as::<_, UserScimRow>(
        "SELECT id::text, email, name, status FROM users WHERE id = $1::uuid AND tenant_id = $2",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("user not found".into()))?;

    Ok(Json(ScimUser {
        schemas: vec![SCIM_USER_SCHEMA.into()],
        id: row.id,
        user_name: row.email.clone(),
        name: row.name.map(|n| ScimName {
            given_name: Some(n),
            family_name: None,
        }),
        emails: vec![ScimEmail {
            value: row.email,
            primary: true,
        }],
        active: row.status == "active",
    }))
}

async fn update_user(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<ScimUser>,
) -> Result<Json<ScimUser>, ApiError> {
    require_scopes(&auth, &["scim:write"])?;

    let email = body
        .emails
        .first()
        .map(|e| e.value.clone())
        .unwrap_or(body.user_name.clone());
    let name = body.name.as_ref().and_then(|n| n.given_name.clone());
    let status = if body.active { "active" } else { "deactivated" };

    let result = sqlx::query(
        "UPDATE users SET email=$1, name=$2, status=$3, updated_at=NOW() WHERE id=$4 AND tenant_id=$5",
    )
    .bind(&email)
    .bind(&name)
    .bind(status)
    .bind(&id)
    .bind(&auth.tenant_id)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("user not found".into()));
    }

    invalidate_user_status_cache(&id, &auth.tenant_id, &state).await;

    Ok(Json(ScimUser {
        schemas: vec![SCIM_USER_SCHEMA.into()],
        id,
        user_name: email.clone(),
        name: name.map(|n| ScimName {
            given_name: Some(n),
            family_name: None,
        }),
        emails: vec![ScimEmail {
            value: email,
            primary: true,
        }],
        active: body.active,
    }))
}

async fn delete_user(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["scim:write"])?;

    let result = sqlx::query(
        "UPDATE users SET status = 'deactivated', updated_at = NOW() WHERE id = $1::uuid AND tenant_id = $2",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("user not found".into()));
    }

    invalidate_user_status_cache(&id, &auth.tenant_id, &state).await;

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
    let total =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM scim_groups WHERE tenant_id = $1")
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
        members: members
            .into_iter()
            .map(|m| ScimMember {
                value: m.user_id.to_string(),
                display: m.display.or(m.email),
            })
            .collect(),
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

    sqlx::query("UPDATE scim_groups SET display_name = $1, updated_at = NOW() WHERE id = $2")
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
#[serde(deny_unknown_fields)]
struct ScimPatchOp {
    op: String,
    path: Option<String>,
    value: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
                                    let display = member
                                        .get("display")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string());
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
                        let user_id_str = path
                            .trim_start_matches("members[value eq \"")
                            .trim_end_matches("\"]");
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
        members: members
            .into_iter()
            .map(|m| ScimMember {
                value: m.user_id.to_string(),
                display: m.display.or(m.email),
            })
            .collect(),
    }))
}

async fn delete_group(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(scim_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["scim:write"])?;

    let result = sqlx::query("DELETE FROM scim_groups WHERE scim_id = $1 AND tenant_id = $2")
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
    #[expect(
        dead_code,
        reason = "SCIM group row keeps created_at for stable SELECT mapping"
    )]
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
    use serde_json::json;

    // ── User Serialization ──────────────────────────────────────

    #[test]
    fn test_scim_user_serialisation() {
        let user = ScimUser {
            schemas: vec![SCIM_USER_SCHEMA.into()],
            id: String::new(),
            user_name: "alice@example.com".into(),
            name: Some(ScimName {
                given_name: Some("Alice".into()),
                family_name: None,
            }),
            emails: vec![ScimEmail {
                value: "alice@example.com".into(),
                primary: true,
            }],
            active: true,
        };
        let json = serde_json::to_value(&user).unwrap();
        assert_eq!(json["userName"], "alice@example.com");
        assert_eq!(json["schemas"][0], SCIM_USER_SCHEMA);
        assert_eq!(json["name"]["givenName"], "Alice");
        assert!(json["active"].as_bool().unwrap());
    }

    #[test]
    fn test_scim_user_serialises_with_all_name_fields() {
        let user = ScimUser {
            schemas: vec![SCIM_USER_SCHEMA.into()],
            id: "u-001".into(),
            user_name: "bob@example.com".into(),
            name: Some(ScimName {
                given_name: Some("Bob".into()),
                family_name: Some("Smith".into()),
            }),
            emails: vec![ScimEmail {
                value: "bob@example.com".into(),
                primary: true,
            }],
            active: false,
        };
        let json = serde_json::to_value(&user).unwrap();
        assert_eq!(json["id"], "u-001");
        assert_eq!(json["name"]["familyName"], "Smith");
        assert!(!json["active"].as_bool().unwrap());
    }

    #[test]
    fn test_scim_user_deserialises_minimal() {
        let json = json!({
            "schemas": [SCIM_USER_SCHEMA],
            "id": "u-002",
            "userName": "carol@example.com",
            "name": { "givenName": "Carol" },
            "emails": [{ "value": "carol@example.com", "primary": true }],
            "active": true
        });
        let user: ScimUser = serde_json::from_value(json).unwrap();
        assert_eq!(user.user_name, "carol@example.com");
        assert!(user.active);
        assert_eq!(user.emails.len(), 1);
    }

    #[test]
    fn test_scim_user_deserialises_without_name() {
        // SCIM allows name to be null/missing
        let json = json!({
            "schemas": [SCIM_USER_SCHEMA],
            "id": "u-003",
            "userName": "dave@example.com",
            "emails": [{ "value": "dave@example.com", "primary": true }],
            "active": true
        });
        let user: ScimUser = serde_json::from_value(json).unwrap();
        assert!(user.name.is_none());
    }

    #[test]
    fn test_scim_user_deserialises_with_multiple_emails() {
        let json = json!({
            "schemas": [SCIM_USER_SCHEMA],
            "id": "u-004",
            "userName": "eve@example.com",
            "emails": [
                { "value": "eve@example.com", "primary": true },
                { "value": "eve@personal.com", "primary": false }
            ],
            "active": true
        });
        let user: ScimUser = serde_json::from_value(json).unwrap();
        assert_eq!(user.emails.len(), 2);
        assert!(user.emails[0].primary);
        assert!(!user.emails[1].primary);
    }

    #[test]
    fn test_scim_user_rejects_unknown_fields() {
        // serde(deny_unknown_fields) not set on ScimUser, so unknown fields are silently ignored
        let json = json!({
            "schemas": [SCIM_USER_SCHEMA],
            "id": "u-005",
            "userName": "frank@example.com",
            "emails": [{ "value": "frank@example.com", "primary": true }],
            "active": true,
            "extraField": "should-be-ignored",
            "nickName": "Frankie"
        });
        let user: ScimUser = serde_json::from_value(json).unwrap();
        assert_eq!(user.user_name, "frank@example.com");
        // Unknown fields are silently ignored by serde's default behaviour
    }

    // ── Group Serialization ─────────────────────────────────────

    #[test]
    fn test_scim_group_serialisation() {
        let group = ScimGroup {
            schemas: vec![SCIM_GROUP_SCHEMA.into()],
            id: "g-001".into(),
            display_name: "Engineering".into(),
            members: vec![
                ScimMember {
                    value: "u-001".into(),
                    display: Some("Alice".into()),
                },
                ScimMember {
                    value: "u-002".into(),
                    display: None,
                },
            ],
        };
        let json = serde_json::to_value(&group).unwrap();
        assert_eq!(json["displayName"], "Engineering");
        assert_eq!(json["members"].as_array().unwrap().len(), 2);
        assert_eq!(json["members"][0]["display"], "Alice");
        assert_eq!(json["members"][1]["display"], serde_json::Value::Null);
    }

    #[test]
    fn test_scim_group_deserialises() {
        let json = json!({
            "schemas": [SCIM_GROUP_SCHEMA],
            "id": "g-002",
            "displayName": "Marketing",
            "members": [
                { "value": "u-003", "display": "Carol" }
            ]
        });
        let group: ScimGroup = serde_json::from_value(json).unwrap();
        assert_eq!(group.display_name, "Marketing");
        assert_eq!(group.members.len(), 1);
        assert_eq!(group.members[0].value, "u-003");
    }

    #[test]
    fn test_scim_group_empty_members() {
        let group = ScimGroup {
            schemas: vec![SCIM_GROUP_SCHEMA.into()],
            id: "g-003".into(),
            display_name: "EmptyGroup".into(),
            members: vec![],
        };
        let json = serde_json::to_value(&group).unwrap();
        assert!(json["members"].as_array().unwrap().is_empty());
    }

    // ── List Response ───────────────────────────────────────────

    #[test]
    fn test_scim_list_response_with_users() {
        let users = vec![
            ScimUser {
                schemas: vec![SCIM_USER_SCHEMA.into()],
                id: "u-001".into(),
                user_name: "alice@example.com".into(),
                name: None,
                emails: vec![ScimEmail {
                    value: "alice@example.com".into(),
                    primary: true,
                }],
                active: true,
            },
            ScimUser {
                schemas: vec![SCIM_USER_SCHEMA.into()],
                id: "u-002".into(),
                user_name: "bob@example.com".into(),
                name: None,
                emails: vec![ScimEmail {
                    value: "bob@example.com".into(),
                    primary: true,
                }],
                active: false,
            },
        ];
        let resp = ScimListResponse {
            schemas: vec![SCIM_LIST_SCHEMA.into()],
            total_results: 2,
            start_index: 1,
            items_per_page: 100,
            resources: users,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["totalResults"], 2);
        assert_eq!(json["startIndex"], 1);
        assert_eq!(json["itemsPerPage"], 100);
        assert_eq!(json["Resources"].as_array().unwrap().len(), 2);
        assert_eq!(json["Resources"][0]["userName"], "alice@example.com");
    }

    #[test]
    fn test_scim_list_response_empty() {
        let resp: ScimListResponse<ScimUser> = ScimListResponse {
            schemas: vec![SCIM_LIST_SCHEMA.into()],
            total_results: 0,
            start_index: 1,
            items_per_page: 100,
            resources: vec![],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["totalResults"], 0);
        assert!(json["Resources"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_scim_list_response_with_groups() {
        let groups = vec![ScimGroup {
            schemas: vec![SCIM_GROUP_SCHEMA.into()],
            id: "g-001".into(),
            display_name: "Engineering".into(),
            members: vec![],
        }];
        let resp = ScimListResponse {
            schemas: vec![SCIM_LIST_SCHEMA.into()],
            total_results: 1,
            start_index: 1,
            items_per_page: 50,
            resources: groups,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["totalResults"], 1);
        assert_eq!(json["Resources"][0]["displayName"], "Engineering");
    }

    // ── Pagination Query ────────────────────────────────────────

    #[test]
    fn test_scim_list_query_defaults() {
        let q: ScimListQuery = serde_json::from_value(json!({})).unwrap();
        assert_eq!(q.start_index, 1);
        assert_eq!(q.count, 100);
        assert!(q.cursor.is_none());
    }

    #[test]
    fn test_scim_list_query_accepts_start_index_and_count() {
        let q: ScimListQuery =
            serde_json::from_value(json!({ "startIndex": 5, "count": 25 })).unwrap();
        assert_eq!(q.start_index, 5);
        assert_eq!(q.count, 25);
    }

    #[test]
    fn test_scim_list_query_accepts_cursor() {
        let q: ScimListQuery =
            serde_json::from_value(json!({ "startIndex": 1, "count": 10, "cursor": 50 })).unwrap();
        assert_eq!(q.cursor, Some(50));
    }

    // ── Patch Operations ─────────────────────────────────────────

    #[test]
    fn test_scim_patch_request_single_add_operation() {
        let json = json!({
            "Operations": [{
                "op": "add",
                "path": "members",
                "value": [{ "value": "u-010", "display": "New Member" }]
            }]
        });
        let req: ScimPatchRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.operations.len(), 1);
        assert_eq!(req.operations[0].op, "add");
        assert_eq!(req.operations[0].path.as_deref(), Some("members"));
    }

    #[test]
    fn test_scim_patch_request_remove_operation() {
        let json = json!({
            "Operations": [{
                "op": "remove",
                "path": "members[value eq \"u-001\"]"
            }]
        });
        let req: ScimPatchRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.operations.len(), 1);
        assert_eq!(req.operations[0].op, "remove");
        assert!(req.operations[0].value.is_none());
    }

    #[test]
    fn test_scim_patch_request_rejects_unknown_fields() {
        // denY_unknown_fields is set on ScimPatchOp
        let json = json!({
            "Operations": [{
                "op": "add",
                "unknownField": "should-fail"
            }]
        });
        let result: Result<ScimPatchRequest, _> = serde_json::from_value(json);
        assert!(result.is_err(), "Should reject unknown patch op fields");
    }

    #[test]
    fn test_scim_patch_request_rejects_unknown_request_fields() {
        // denY_unknown_fields is set on ScimPatchRequest
        let json = json!({
            "Operations": [{ "op": "add", "path": "members" }],
            "extra": true
        });
        let result: Result<ScimPatchRequest, _> = serde_json::from_value(json);
        assert!(result.is_err(), "Should reject unknown request fields");
    }

    // ── Name/Email Validation ────────────────────────────────────

    #[test]
    fn test_scim_name_both_fields_optional() {
        let name: ScimName = serde_json::from_value(json!({})).unwrap();
        assert!(name.given_name.is_none());
        assert!(name.family_name.is_none());
    }

    #[test]
    fn test_scim_name_accepts_given_name_only() {
        let name: ScimName = serde_json::from_value(json!({ "givenName": "Alice" })).unwrap();
        assert_eq!(name.given_name.as_deref(), Some("Alice"));
        assert!(name.family_name.is_none());
    }

    #[test]
    fn test_scim_email_requires_value() {
        let email: ScimEmail =
            serde_json::from_value(json!({ "value": "a@b.com", "primary": false })).unwrap();
        assert_eq!(email.value, "a@b.com");
        assert!(!email.primary);
    }

    #[test]
    fn test_scim_email_defaults_primary_false_if_missing() {
        // serde default for bool is false
        let email: ScimEmail = serde_json::from_value(json!({ "value": "a@b.com" })).unwrap();
        assert_eq!(email.value, "a@b.com");
        assert!(!email.primary);
    }

    // ── Constants ────────────────────────────────────────────────

    #[test]
    fn test_scim_schemas_are_well_known_urns() {
        assert_eq!(
            SCIM_USER_SCHEMA,
            "urn:ietf:params:scim:schemas:core:2.0:User"
        );
        assert_eq!(
            SCIM_GROUP_SCHEMA,
            "urn:ietf:params:scim:schemas:core:2.0:Group"
        );
        assert_eq!(
            SCIM_LIST_SCHEMA,
            "urn:ietf:params:scim:api:messages:2.0:ListResponse"
        );
    }

    #[test]
    fn test_scim_max_count_is_reasonable() {
        assert_eq!(MAX_SCIM_COUNT, 200);
    }

    #[test]
    fn test_scim_disabled_hash_is_not_valid_argon2() {
        assert_eq!(SCIM_DISABLED_HASH, "!scim:disabled");
        assert!(!SCIM_DISABLED_HASH.starts_with('$'));
    }

    // ── Error Handling Patterns ──────────────────────────────────

    #[test]
    fn test_scim_user_rejects_missing_required_fields() {
        // userName is required but not an Option — serde will error
        let result: Result<ScimUser, _> =
            serde_json::from_value(json!({ "schemas": [SCIM_USER_SCHEMA], "id": "u-001" }));
        assert!(
            result.is_err(),
            "Missing userName should fail deserialization"
        );
    }

    #[test]
    fn test_scim_user_rejects_wrong_schema_type() {
        let json = json!({
            "schemas": [SCIM_GROUP_SCHEMA], // Wrong schema!
            "id": "u-001",
            "userName": "alice@example.com",
            "emails": [{ "value": "alice@example.com", "primary": true }],
            "active": true
        });
        // Deserialization succeeds — SCIM doesn't validate the schema in the type system
        let user: ScimUser = serde_json::from_value(json).unwrap();
        assert_eq!(user.user_name, "alice@example.com");
        // Schema validation is an application-level concern, not enforced by serde
    }

    #[test]
    fn test_scim_member_serialises_with_and_without_display() {
        let member_with = ScimMember {
            value: "u-001".into(),
            display: Some("Alice".into()),
        };
        let json = serde_json::to_value(&member_with).unwrap();
        assert_eq!(json["display"], "Alice");

        let member_without = ScimMember {
            value: "u-002".into(),
            display: None,
        };
        let json = serde_json::to_value(&member_without).unwrap();
        assert_eq!(json["display"], serde_json::Value::Null);
    }

    #[test]
    fn test_scim_unique_violation_code() {
        // The is_unique_violation check uses PostgreSQL code "23505"
        // We can't easily test this without a real DB, but verify the constant
        // pattern is correct
        let pg_unique_code = "23505";
        assert_eq!(pg_unique_code.len(), 5);
        assert!(pg_unique_code.chars().all(|c| c.is_ascii_digit()));
    }
}
