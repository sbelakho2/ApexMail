//! Support ticket management endpoints.
//!

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(list_tickets).post(add_reply).put(update_ticket))
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct TicketsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    pub status: Option<String>,
}

fn default_limit() -> i64 { 50 }

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Ticket {
    pub id: String,
    pub subject: String,
    pub description: Option<String>,
    pub tenant_id: Option<String>,
    pub tenant_name: Option<String>,
    pub tenant_email: Option<String>,
    pub status: String,
    pub priority: String,
    pub category: Option<String>,
    pub assignee: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub messages: Vec<TicketMessage>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TicketMessage {
    pub id: String,
    pub content: String,
    pub author: String,
    pub author_type: String,
    pub attachments: serde_json::Value,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddReplyRequest {
    pub ticket_id: String,
    pub content: String,
    #[serde(default = "default_author")]
    pub author: String,
    #[serde(default = "default_author_type")]
    pub author_type: String,
    pub new_status: Option<String>,
}

fn default_author() -> String { "System".into() }
fn default_author_type() -> String { "agent".into() }

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTicketRequest {
    pub id: String,
    pub status: Option<String>,
    pub priority: Option<String>,
    pub assignee: Option<String>,
}

// ─── Handlers ──────────────────────────────────────────────────

const VALID_STATUSES: &[&str] = &["open", "in_progress", "pending_customer", "resolved", "closed"];
const VALID_PRIORITIES: &[&str] = &["low", "medium", "high", "urgent"];

async fn list_tickets(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<TicketsQuery>,
) -> Result<Json<Vec<Ticket>>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    let (where_clause, bind_status) = if let Some(ref s) = params.status {
        ("WHERE st.status = $3".to_string(), Some(s.clone()))
    } else {
        (String::new(), None)
    };

    let sql = format!(
        "SELECT st.id::text, st.subject, st.description, st.tenant_id::text,
                st.tenant_name, st.tenant_email, st.status, st.priority,
                st.category, st.assignee, st.created_at, st.updated_at
         FROM support_tickets st {where_clause}
         ORDER BY st.created_at DESC LIMIT $1 OFFSET $2"
    );

    let mut query = sqlx::query_as::<_, (
        String, String, Option<String>, Option<String>, Option<String>, Option<String>,
        String, String, Option<String>, Option<String>,
        chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>,
    )>(&sql)
    .bind(limit)
    .bind(offset);

    if let Some(s) = &bind_status {
        query = query.bind(s);
    }

    let ticket_rows = query.fetch_all(&state.db).await?;

    let mut tickets: Vec<Ticket> = Vec::with_capacity(ticket_rows.len());
    for (id, subj, desc, tid, tname, temail, status, priority, cat, assignee, ca, ua) in ticket_rows {
// Load messages for this ticket
        let msgs = sqlx::query_as::<_, (
            String, String, String, String, serde_json::Value, chrono::DateTime<chrono::Utc>,
        )>(
            "SELECT id::text, content, author, author_type, COALESCE(attachments, '[]'::jsonb), created_at
             FROM support_ticket_messages WHERE ticket_id::text = $1
             ORDER BY created_at ASC LIMIT 50",
        )
        .bind(&id)
        .fetch_all(&state.db)
        .await
        ?;

        let messages: Vec<TicketMessage> = msgs
            .into_iter()
            .map(|(mid, content, author, at, attachments, mca)| TicketMessage {
                id: mid, content, author, author_type: at, attachments,
                created_at: mca.to_rfc3339(),
            })
            .collect();

        tickets.push(Ticket {
            id, subject: subj, description: desc, tenant_id: tid,
            tenant_name: tname, tenant_email: temail, status, priority,
            category: cat, assignee,
            created_at: ca.to_rfc3339(), updated_at: ua.to_rfc3339(),
            messages,
        });
    }

    Ok(Json(tickets))
}

async fn add_reply(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<AddReplyRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    if body.content.is_empty() {
        return Err(ApiError::Validation(vec!["content is required".into()]));
    }

    let msg_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO support_ticket_messages (id, ticket_id, content, author, author_type, created_at)
         VALUES ($1, $2::uuid, $3, $4, $5, NOW())",
    )
    .bind(msg_id)
    .bind(&body.ticket_id)
    .bind(&body.content)
    .bind(&body.author)
    .bind(&body.author_type)
    .execute(&state.db)
    .await?;

// Optionally update ticket status
    if let Some(ref new_status) = body.new_status {
        if VALID_STATUSES.contains(&new_status.as_str()) {
            sqlx::query("UPDATE support_tickets SET status = $1, updated_at = NOW() WHERE id::text = $2")
                .bind(new_status)
                .bind(&body.ticket_id)
                .execute(&state.db)
                .await?;
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": msg_id.to_string(),
            "ticketId": body.ticket_id,
            "content": body.content,
            "author": body.author,
            "authorType": body.author_type,
            "createdAt": chrono::Utc::now().to_rfc3339(),
        })),
    ))
}

async fn update_ticket(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<UpdateTicketRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    if let Some(ref s) = body.status {
        if !VALID_STATUSES.contains(&s.as_str()) {
            return Err(ApiError::Validation(vec![format!("invalid status: {s}")]));
        }
    }
    if let Some(ref p) = body.priority {
        if !VALID_PRIORITIES.contains(&p.as_str()) {
            return Err(ApiError::Validation(vec![format!("invalid priority: {p}")]));
        }
    }

    if let Some(ref s) = body.status {
        sqlx::query("UPDATE support_tickets SET status = $1, updated_at = NOW() WHERE id::text = $2")
            .bind(s).bind(&body.id).execute(&state.db).await?;
    }
    if let Some(ref p) = body.priority {
        sqlx::query("UPDATE support_tickets SET priority = $1, updated_at = NOW() WHERE id::text = $2")
            .bind(p).bind(&body.id).execute(&state.db).await?;
    }
    if let Some(ref a) = body.assignee {
        sqlx::query("UPDATE support_tickets SET assignee = $1, updated_at = NOW() WHERE id::text = $2")
            .bind(a).bind(&body.id).execute(&state.db).await?;
    }

    Ok(Json(serde_json::json!({
        "id": body.id,
        "status": body.status,
        "priority": body.priority,
        "assignee": body.assignee,
        "updatedAt": chrono::Utc::now().to_rfc3339(),
    })))
}
