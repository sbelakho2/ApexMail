//! Suppression list management routes.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(create_suppression).get(list_suppressions))
        .route("/:id", delete(delete_suppression))
        .route("/check/:email", get(check_suppression))
        .route("/bulk", post(bulk_suppress))
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateSuppressionRequest {
    pub email: String,
    pub reason: String,
    #[serde(default = "default_source")]
    pub source: String,
}

fn default_source() -> String {
    "manual".into()
}

#[derive(Debug, Serialize)]
pub struct SuppressionResponse {
    pub id: Uuid,
    pub email: String,
    pub reason: String,
    pub source: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct ListSuppressionsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub reason: Option<String>,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Serialize)]
pub struct CheckResponse {
    pub email: String,
    pub suppressed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BulkSuppressRequest {
    pub entries: Vec<BulkEntry>,
}

#[derive(Debug, Deserialize)]
pub struct BulkEntry {
    pub email: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct BulkSuppressResponse {
    pub created: usize,
    pub duplicates: usize,
}

// ─── Handlers ──────────────────────────────────────────────────

async fn create_suppression(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateSuppressionRequest>,
) -> Result<(StatusCode, Json<SuppressionResponse>), ApiError> {
    require_scopes(&auth, &["suppressions:write"])?;

    if !apexmail_lib::validation::is_valid_email(&body.email) {
        return Err(ApiError::Validation(vec!["invalid email address".into()]));
    }

    // Check duplicate
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM suppressions WHERE tenant_id = $1 AND email = $2",
    )
    .bind(auth.tenant_id)
    .bind(&body.email)
    .fetch_one(&state.db)
    .await?;

    if exists > 0 {
        return Err(ApiError::Conflict("email already suppressed".into()));
    }

    let id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query(
        "INSERT INTO suppressions (id, tenant_id, email, reason, source, created_at)
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(id)
    .bind(auth.tenant_id)
    .bind(&body.email)
    .bind(&body.reason)
    .bind(&body.source)
    .bind(now)
    .execute(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(SuppressionResponse {
            id,
            email: body.email,
            reason: body.reason,
            source: body.source,
            created_at: now.to_rfc3339(),
        }),
    ))
}

async fn list_suppressions(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ListSuppressionsQuery>,
) -> Result<Json<Vec<SuppressionResponse>>, ApiError> {
    require_scopes(&auth, &["suppressions:read"])?;

    let rows = sqlx::query_as::<_, SuppressionRow>(
        "SELECT id, email, reason, source, created_at
         FROM suppressions WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(auth.tenant_id)
    .bind(params.limit.min(100))
    .bind(params.offset)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn delete_suppression(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["suppressions:write"])?;

    let result = sqlx::query("DELETE FROM suppressions WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(auth.tenant_id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("suppression not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn check_suppression(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(email): Path<String>,
) -> Result<Json<CheckResponse>, ApiError> {
    require_scopes(&auth, &["suppressions:read"])?;

    let row = sqlx::query_as::<_, SuppressionReasonRow>(
        "SELECT reason FROM suppressions WHERE tenant_id = $1 AND email = $2",
    )
    .bind(auth.tenant_id)
    .bind(&email)
    .fetch_optional(&state.db)
    .await?;

    Ok(Json(CheckResponse {
        email,
        suppressed: row.is_some(),
        reason: row.map(|r| r.reason),
    }))
}

async fn bulk_suppress(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<BulkSuppressRequest>,
) -> Result<Json<BulkSuppressResponse>, ApiError> {
    require_scopes(&auth, &["suppressions:write"])?;

    let mut created = 0usize;
    let mut duplicates = 0usize;

    for entry in &body.entries {
        let exists = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM suppressions WHERE tenant_id = $1 AND email = $2",
        )
        .bind(auth.tenant_id)
        .bind(&entry.email)
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

        if exists > 0 {
            duplicates += 1;
            continue;
        }

        let _ = sqlx::query(
            "INSERT INTO suppressions (id, tenant_id, email, reason, source, created_at)
             VALUES ($1,$2,$3,$4,'bulk',$5)",
        )
        .bind(Uuid::new_v4())
        .bind(auth.tenant_id)
        .bind(&entry.email)
        .bind(&entry.reason)
        .bind(Utc::now())
        .execute(&state.db)
        .await;

        created += 1;
    }

    Ok(Json(BulkSuppressResponse { created, duplicates }))
}

// ─── Row types ─────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct SuppressionRow {
    id: Uuid,
    email: String,
    reason: String,
    source: String,
    created_at: DateTime<Utc>,
}

impl From<SuppressionRow> for SuppressionResponse {
    fn from(r: SuppressionRow) -> Self {
        Self {
            id: r.id,
            email: r.email,
            reason: r.reason,
            source: r.source,
            created_at: r.created_at.to_rfc3339(),
        }
    }
}

#[derive(sqlx::FromRow)]
struct SuppressionReasonRow {
    reason: String,
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_response_suppressed() {
        let resp = CheckResponse {
            email: "bad@example.com".into(),
            suppressed: true,
            reason: Some("hard_bounce".into()),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["suppressed"], true);
    }

    #[test]
    fn test_check_response_not_suppressed() {
        let resp = CheckResponse {
            email: "good@example.com".into(),
            suppressed: false,
            reason: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("reason").is_none()); // skip_serializing_if omits None
    }

    #[test]
    fn test_bulk_response_serialisation() {
        let resp = BulkSuppressResponse {
            created: 5,
            duplicates: 2,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["created"], 5);
    }
}
