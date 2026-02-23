//! Support ticket routes.

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
        .route("/tickets", post(create_ticket).get(list_tickets))
        .route("/tickets/:id", get(get_ticket).put(update_ticket))
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateTicketRequest {
    pub subject: String,
    pub description: String,
    #[serde(default = "default_priority")]
    pub priority: String,
}

fn default_priority() -> String {
    "normal".into()
}

#[derive(Debug, Deserialize)]
pub struct UpdateTicketRequest {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub priority: Option<String>,
    #[serde(default)]
    pub assigned_to: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct TicketResponse {
    pub id: Uuid,
    pub subject: String,
    pub description: String,
    pub priority: String,
    pub status: String,
    pub assigned_to: Option<Uuid>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
pub struct ListTicketsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub status: Option<String>,
}

fn default_limit() -> i64 {
    50
}

// ─── Handlers ──────────────────────────────────────────────────

async fn create_ticket(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateTicketRequest>,
) -> Result<(StatusCode, Json<TicketResponse>), ApiError> {
    require_scopes(&auth, &["support:write"])?;

    if body.subject.is_empty() || body.description.is_empty() {
        return Err(ApiError::Validation(vec![
            "subject and description are required".into(),
        ]));
    }

    let id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query(
        "INSERT INTO support_tickets (id, tenant_id, subject, description, priority, status, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,'open',$6,$6)",
    )
    .bind(id)
    .bind(auth.tenant_id)
    .bind(&body.subject)
    .bind(&body.description)
    .bind(&body.priority)
    .bind(now)
    .execute(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(TicketResponse {
            id,
            subject: body.subject,
            description: body.description,
            priority: body.priority,
            status: "open".into(),
            assigned_to: None,
            created_at: now.to_rfc3339(),
            updated_at: now.to_rfc3339(),
        }),
    ))
}

async fn list_tickets(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ListTicketsQuery>,
) -> Result<Json<Vec<TicketResponse>>, ApiError> {
    require_scopes(&auth, &["support:read"])?;

    let rows = sqlx::query_as::<_, TicketRow>(
        "SELECT id, subject, description, priority, status, assigned_to, created_at, updated_at
         FROM support_tickets WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(auth.tenant_id)
    .bind(params.limit.min(100))
    .bind(params.offset)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn get_ticket(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<TicketResponse>, ApiError> {
    require_scopes(&auth, &["support:read"])?;

    let row = sqlx::query_as::<_, TicketRow>(
        "SELECT id, subject, description, priority, status, assigned_to, created_at, updated_at
         FROM support_tickets WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(auth.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("ticket not found".into()))?;

    Ok(Json(row.into()))
}

async fn update_ticket(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateTicketRequest>,
) -> Result<Json<TicketResponse>, ApiError> {
    require_scopes(&auth, &["support:write"])?;

    let existing = sqlx::query_as::<_, TicketRow>(
        "SELECT id, subject, description, priority, status, assigned_to, created_at, updated_at
         FROM support_tickets WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(auth.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("ticket not found".into()))?;

    let status = body.status.unwrap_or(existing.status);
    let priority = body.priority.unwrap_or(existing.priority);
    let assigned_to = body.assigned_to.or(existing.assigned_to);

    sqlx::query(
        "UPDATE support_tickets SET status=$1, priority=$2, assigned_to=$3, updated_at=NOW()
         WHERE id=$4 AND tenant_id=$5",
    )
    .bind(&status)
    .bind(&priority)
    .bind(assigned_to)
    .bind(id)
    .bind(auth.tenant_id)
    .execute(&state.db)
    .await?;

    Ok(Json(TicketResponse {
        id,
        subject: existing.subject,
        description: existing.description,
        priority,
        status,
        assigned_to,
        created_at: existing.created_at.to_rfc3339(),
        updated_at: Utc::now().to_rfc3339(),
    }))
}

// ─── Row types ─────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct TicketRow {
    id: Uuid,
    subject: String,
    description: String,
    priority: String,
    status: String,
    assigned_to: Option<Uuid>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<TicketRow> for TicketResponse {
    fn from(r: TicketRow) -> Self {
        Self {
            id: r.id,
            subject: r.subject,
            description: r.description,
            priority: r.priority,
            status: r.status,
            assigned_to: r.assigned_to,
            created_at: r.created_at.to_rfc3339(),
            updated_at: r.updated_at.to_rfc3339(),
        }
    }
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_ticket_request_deser() {
        let json = r#"{"subject":"Help","description":"Need assistance"}"#;
        let req: CreateTicketRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.priority, "normal");
    }

    #[test]
    fn test_ticket_response_serialisation() {
        let resp = TicketResponse {
            id: Uuid::nil(),
            subject: "Test".into(),
            description: "desc".into(),
            priority: "high".into(),
            status: "open".into(),
            assigned_to: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["priority"], "high");
    }
}
