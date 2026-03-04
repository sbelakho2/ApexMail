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
        .route("/tickets/:id/messages", get(list_ticket_messages).post(create_ticket_message))
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
    pub cursor: Option<i64>,
    #[serde(default)]
    pub status: Option<String>,
}

fn default_limit() -> i64 {
    50
}

fn clamp_limit(limit: i64, max: i64) -> i64 {
    limit.clamp(1, max)
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

    let offset = params.cursor.unwrap_or(params.offset).clamp(0, 100_000);
    let rows = sqlx::query_as::<_, TicketRow>(
        "SELECT id, subject, description, priority, status, assigned_to, created_at, updated_at
         FROM support_tickets WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(auth.tenant_id)
    .bind(clamp_limit(params.limit, 100))
    // Fix #58: Clamp offset to valid range.
    .bind(offset)
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

// ─── Ticket Message Handlers ───────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateMessageRequest {
    pub body: String,
}

#[derive(Debug, Serialize)]
pub struct TicketMessageResponse {
    pub id: Uuid,
    pub ticket_id: Uuid,
    pub sender_id: Uuid,
    pub sender_type: String,
    pub body: String,
    pub created_at: String,
}

async fn list_ticket_messages(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(ticket_id): Path<Uuid>,
    Query(q): Query<ListTicketsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["support:read"])?;
    let limit = q.limit.min(200).max(1);
    let offset = q.offset.max(0);

    // Verify ticket belongs to tenant
    let exists = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM support_tickets WHERE id = $1 AND tenant_id = $2)",
        ticket_id,
        auth.tenant_id,
    )
    .fetch_one(&*state.db)
    .await?
    .unwrap_or(false);

    if !exists {
        return Err(ApiError::NotFound);
    }

    let rows = sqlx::query!(
        r#"SELECT id, ticket_id, sender_id, sender_type AS "sender_type!", body, created_at
           FROM ticket_messages
           WHERE ticket_id = $1
           ORDER BY created_at ASC
           LIMIT $2 OFFSET $3"#,
        ticket_id,
        limit,
        offset,
    )
    .fetch_all(&*state.db)
    .await?;

    let messages: Vec<TicketMessageResponse> = rows
        .into_iter()
        .map(|r| TicketMessageResponse {
            id: r.id,
            ticket_id: r.ticket_id,
            sender_id: r.sender_id,
            sender_type: r.sender_type,
            body: r.body,
            created_at: r.created_at.to_rfc3339(),
        })
        .collect();

    let total = sqlx::query_scalar!(
        "SELECT COUNT(*)::bigint FROM ticket_messages WHERE ticket_id = $1",
        ticket_id,
    )
    .fetch_one(&*state.db)
    .await?
    .unwrap_or(0);

    Ok(Json(serde_json::json!({
        "data": messages,
        "total": total,
    })))
}

async fn create_ticket_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(ticket_id): Path<Uuid>,
    Json(body): Json<CreateMessageRequest>,
) -> Result<(StatusCode, Json<TicketMessageResponse>), ApiError> {
    require_scopes(&auth, &["support:write"])?;

    // Verify ticket belongs to tenant
    let exists = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM support_tickets WHERE id = $1 AND tenant_id = $2)",
        ticket_id,
        auth.tenant_id,
    )
    .fetch_one(&*state.db)
    .await?
    .unwrap_or(false);

    if !exists {
        return Err(ApiError::NotFound);
    }

    let id = Uuid::now_v7();
    let now = chrono::Utc::now();

    sqlx::query!(
        "INSERT INTO ticket_messages (id, ticket_id, sender_id, sender_type, body, created_at)
         VALUES ($1, $2, $3, 'user', $4, $5)",
        id,
        ticket_id,
        auth.user_id,
        body.body,
        now,
    )
    .execute(&*state.db)
    .await?;

    // Update ticket updated_at
    sqlx::query!(
        "UPDATE support_tickets SET updated_at = NOW() WHERE id = $1",
        ticket_id,
    )
    .execute(&*state.db)
    .await?;

    Ok((StatusCode::CREATED, Json(TicketMessageResponse {
        id,
        ticket_id,
        sender_id: auth.user_id,
        sender_type: "user".into(),
        body: body.body,
        created_at: now.to_rfc3339(),
    })))
}
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
