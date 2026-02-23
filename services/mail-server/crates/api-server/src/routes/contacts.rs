//! Contact management routes.

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
        .route("/", post(create_contact).get(list_contacts))
        .route("/:id", get(get_contact).put(update_contact).delete(delete_contact))
        .route("/bulk", post(bulk_import))
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateContactRequest {
    pub email: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateContactRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ContactResponse {
    pub id: Uuid,
    pub email: String,
    pub name: Option<String>,
    pub tags: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
pub struct ListContactsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub tag: Option<String>,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Deserialize)]
pub struct BulkImportRequest {
    pub contacts: Vec<CreateContactRequest>,
}

#[derive(Debug, Serialize)]
pub struct BulkImportResponse {
    pub created: usize,
    pub updated: usize,
    pub failed: usize,
}

// ─── Handlers ──────────────────────────────────────────────────

async fn create_contact(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateContactRequest>,
) -> Result<(StatusCode, Json<ContactResponse>), ApiError> {
    require_scopes(&auth, &["contacts:write"])?;

    if !apexmail_lib::validation::is_valid_email(&body.email) {
        return Err(ApiError::Validation(vec!["invalid email address".into()]));
    }

    let id = Uuid::new_v4();
    let now = Utc::now();
    let tags = body.tags.as_ref().map(|t| serde_json::json!(t));

    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, email, name, tags, metadata, status, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,'active',$7,$7)",
    )
    .bind(id)
    .bind(auth.tenant_id)
    .bind(&body.email)
    .bind(&body.name)
    .bind(&tags)
    .bind(&body.metadata)
    .bind(now)
    .execute(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(ContactResponse {
            id,
            email: body.email,
            name: body.name,
            tags,
            metadata: body.metadata,
            status: "active".into(),
            created_at: now.to_rfc3339(),
            updated_at: now.to_rfc3339(),
        }),
    ))
}

async fn list_contacts(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ListContactsQuery>,
) -> Result<Json<Vec<ContactResponse>>, ApiError> {
    require_scopes(&auth, &["contacts:read"])?;

    let rows = sqlx::query_as::<_, ContactRow>(
        "SELECT id, email, name, tags, metadata, status, created_at, updated_at
         FROM contacts WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(auth.tenant_id)
    .bind(params.limit.min(200))
    .bind(params.offset)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn get_contact(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ContactResponse>, ApiError> {
    require_scopes(&auth, &["contacts:read"])?;
    let row = fetch_contact(&state, auth.tenant_id, id).await?;
    Ok(Json(row.into()))
}

async fn update_contact(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateContactRequest>,
) -> Result<Json<ContactResponse>, ApiError> {
    require_scopes(&auth, &["contacts:write"])?;

    let existing = fetch_contact(&state, auth.tenant_id, id).await?;

    let name = body.name.or(existing.name);
    let tags = body.tags.map(|t| serde_json::json!(t)).or(existing.tags);
    let metadata = body.metadata.or(existing.metadata);
    let status = body.status.unwrap_or(existing.status);

    sqlx::query(
        "UPDATE contacts SET name=$1, tags=$2, metadata=$3, status=$4, updated_at=NOW()
         WHERE id=$5 AND tenant_id=$6",
    )
    .bind(&name)
    .bind(&tags)
    .bind(&metadata)
    .bind(&status)
    .bind(id)
    .bind(auth.tenant_id)
    .execute(&state.db)
    .await?;

    Ok(Json(ContactResponse {
        id,
        email: existing.email,
        name,
        tags,
        metadata,
        status,
        created_at: existing.created_at.to_rfc3339(),
        updated_at: Utc::now().to_rfc3339(),
    }))
}

async fn delete_contact(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["contacts:write"])?;

    let result = sqlx::query("DELETE FROM contacts WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(auth.tenant_id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("contact not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn bulk_import(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<BulkImportRequest>,
) -> Result<Json<BulkImportResponse>, ApiError> {
    require_scopes(&auth, &["contacts:write"])?;

    let mut created = 0usize;
    let mut updated = 0usize;
    let mut failed = 0usize;

    for contact in &body.contacts {
        if !apexmail_lib::validation::is_valid_email(&contact.email) {
            failed += 1;
            continue;
        }

        let existing = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM contacts WHERE tenant_id = $1 AND email = $2",
        )
        .bind(auth.tenant_id)
        .bind(&contact.email)
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

        if existing > 0 {
            // Update existing contact
            let tags = contact.tags.as_ref().map(|t| serde_json::json!(t));
            let _ = sqlx::query(
                "UPDATE contacts SET name=COALESCE($1, name), tags=COALESCE($2, tags), metadata=COALESCE($3, metadata), updated_at=NOW()
                 WHERE tenant_id=$4 AND email=$5",
            )
            .bind(&contact.name)
            .bind(&tags)
            .bind(&contact.metadata)
            .bind(auth.tenant_id)
            .bind(&contact.email)
            .execute(&state.db)
            .await;
            updated += 1;
        } else {
            let tags = contact.tags.as_ref().map(|t| serde_json::json!(t));
            let res = sqlx::query(
                "INSERT INTO contacts (id, tenant_id, email, name, tags, metadata, status, created_at, updated_at)
                 VALUES ($1,$2,$3,$4,$5,$6,'active',NOW(),NOW())",
            )
            .bind(Uuid::new_v4())
            .bind(auth.tenant_id)
            .bind(&contact.email)
            .bind(&contact.name)
            .bind(&tags)
            .bind(&contact.metadata)
            .execute(&state.db)
            .await;

            match res {
                Ok(_) => created += 1,
                Err(_) => failed += 1,
            }
        }
    }

    Ok(Json(BulkImportResponse {
        created,
        updated,
        failed,
    }))
}

// ─── Row types ─────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct ContactRow {
    id: Uuid,
    email: String,
    name: Option<String>,
    tags: Option<serde_json::Value>,
    metadata: Option<serde_json::Value>,
    status: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<ContactRow> for ContactResponse {
    fn from(r: ContactRow) -> Self {
        Self {
            id: r.id,
            email: r.email,
            name: r.name,
            tags: r.tags,
            metadata: r.metadata,
            status: r.status,
            created_at: r.created_at.to_rfc3339(),
            updated_at: r.updated_at.to_rfc3339(),
        }
    }
}

async fn fetch_contact(state: &AppState, tenant_id: Uuid, id: Uuid) -> Result<ContactRow, ApiError> {
    sqlx::query_as::<_, ContactRow>(
        "SELECT id, email, name, tags, metadata, status, created_at, updated_at
         FROM contacts WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("contact not found".into()))
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_contact_deser() {
        let json = r#"{"email":"alice@example.com","name":"Alice"}"#;
        let req: CreateContactRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.email, "alice@example.com");
    }

    #[test]
    fn test_bulk_import_response() {
        let resp = BulkImportResponse {
            created: 10,
            updated: 3,
            failed: 1,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["created"], 10);
    }

    #[test]
    fn test_contact_response_serialisation() {
        let resp = ContactResponse {
            id: Uuid::nil(),
            email: "a@b.com".into(),
            name: Some("A".into()),
            tags: Some(serde_json::json!(["vip"])),
            metadata: None,
            status: "active".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "active");
    }
}
