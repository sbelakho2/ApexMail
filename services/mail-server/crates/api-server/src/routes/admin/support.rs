//! Support ticket management endpoints.
//!

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_tickets).post(post_support).put(update_ticket))
        .route("/reply", post(add_reply))
}

fn default_ticket_priority() -> String {
    "medium".into()
}

fn normalize_optional_text(value: Option<&String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn build_support_create_audit_metadata(
    body: &CreateTicketRequest,
    ticket_id: &str,
) -> serde_json::Value {
    json!({
        "ticketId": ticket_id,
        "tenantId": body.tenant_id,
        "tenantName": body.tenant_name,
        "tenantEmail": body.tenant_email,
        "priority": body.priority,
        "category": body.category,
        "assignee": body.assignee,
    })
}

fn build_support_reply_audit_metadata(
    body: &AddReplyRequest,
    message_id: &str,
) -> serde_json::Value {
    json!({
        "messageId": message_id,
        "author": body.author,
        "authorType": body.author_type,
        "newStatus": body.new_status,
    })
}

fn build_support_update_audit_metadata(body: &UpdateTicketRequest) -> serde_json::Value {
    json!({
        "status": body.status,
        "priority": body.priority,
        "assignee": body.assignee,
    })
}

async fn log_support_audit(
    db: &sqlx::PgPool,
    action: &str,
    ticket_id: &str,
    metadata: serde_json::Value,
) {
    crate::audit_log::insert_audit_log_best_effort(
        db,
        None,
        None,
        action,
        "support_ticket",
        Some(ticket_id),
        metadata,
        None,
        None,
    )
    .await;
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct CreateTicketRequest {
    pub subject: String,
    pub description: String,
    pub tenant_id: Option<String>,
    pub tenant_name: Option<String>,
    pub tenant_email: Option<String>,
    #[serde(default = "default_ticket_priority")]
    pub priority: String,
    pub category: Option<String>,
    pub assignee: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TicketsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    pub status: Option<String>,
}

fn default_limit() -> i64 {
    50
}

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
#[serde(deny_unknown_fields)]
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

fn default_author() -> String {
    "System".into()
}
fn default_author_type() -> String {
    "agent".into()
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SupportPostRequest {
    Create(CreateTicketRequest),
    Reply(AddReplyRequest),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTicketRequest {
    pub id: String,
    pub status: Option<String>,
    pub priority: Option<String>,
    pub assignee: Option<String>,
}

// ─── Handlers ──────────────────────────────────────────────────

const VALID_STATUSES: &[&str] = &[
    "open",
    "in_progress",
    "pending_customer",
    "resolved",
    "closed",
];
const VALID_PRIORITIES: &[&str] = &["low", "medium", "high", "urgent"];

struct ReplyInsertResult {
    id: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

async fn insert_support_ticket(
    db: &sqlx::PgPool,
    body: &CreateTicketRequest,
) -> Result<Ticket, ApiError> {
    let subject = body.subject.trim().to_string();
    let description = body.description.trim().to_string();
    let tenant_id = normalize_optional_text(body.tenant_id.as_ref());
    let tenant_name = normalize_optional_text(body.tenant_name.as_ref());
    let tenant_email = normalize_optional_text(body.tenant_email.as_ref());
    let priority = body.priority.trim().to_lowercase();
    let category = normalize_optional_text(body.category.as_ref());
    let assignee = normalize_optional_text(body.assignee.as_ref());

    let row: (
        String,
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
    ) = sqlx::query_as(
        "INSERT INTO support_tickets (
            subject, description, tenant_id, tenant_name, tenant_email,
            status, priority, category, assignee, created_at, updated_at
         )
         VALUES ($1, $2, $3, $4, $5, 'open', $6, $7, $8, NOW(), NOW())
         RETURNING id::text, created_at, updated_at",
    )
    .bind(&subject)
    .bind(&description)
    .bind(&tenant_id)
    .bind(&tenant_name)
    .bind(&tenant_email)
    .bind(&priority)
    .bind(&category)
    .bind(&assignee)
    .fetch_one(db)
    .await?;

    Ok(Ticket {
        id: row.0,
        subject,
        description: Some(description),
        tenant_id,
        tenant_name,
        tenant_email,
        status: "open".into(),
        priority,
        category,
        assignee,
        created_at: row.1.to_rfc3339(),
        updated_at: row.2.to_rfc3339(),
        messages: Vec::new(),
    })
}

async fn insert_support_reply_message(
    db: &sqlx::PgPool,
    body: &AddReplyRequest,
) -> Result<ReplyInsertResult, ApiError> {
    let row: (String, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
        "INSERT INTO support_ticket_messages (ticket_id, content, author, author_type, created_at)
         VALUES ($1, $2, $3, $4, NOW())
         RETURNING id::text, created_at",
    )
    .bind(&body.ticket_id)
    .bind(body.content.trim())
    .bind(&body.author)
    .bind(&body.author_type)
    .fetch_one(db)
    .await?;

    Ok(ReplyInsertResult {
        id: row.0,
        created_at: row.1,
    })
}

async fn post_support(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<SupportPostRequest>,
) -> Result<Response, ApiError> {
    match body {
        SupportPostRequest::Create(body) => create_ticket(State(state), auth, Json(body))
            .await
            .map(IntoResponse::into_response),
        SupportPostRequest::Reply(body) => add_reply(State(state), auth, Json(body))
            .await
            .map(IntoResponse::into_response),
    }
}

async fn create_ticket(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateTicketRequest>,
) -> Result<(StatusCode, Json<Ticket>), ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    if body.subject.trim().is_empty() || body.description.trim().is_empty() {
        return Err(ApiError::Validation(vec![
            "subject and description are required".into(),
        ]));
    }

    if !VALID_PRIORITIES.contains(&body.priority.trim().to_lowercase().as_str()) {
        return Err(ApiError::Validation(vec![format!(
            "invalid priority: {}",
            body.priority
        )]));
    }

    let ticket = insert_support_ticket(&state.db, &body).await?;

    log_support_audit(
        &state.db,
        "control_plane.support.ticket_created",
        &ticket.id,
        build_support_create_audit_metadata(&body, &ticket.id),
    )
    .await;

    Ok((StatusCode::CREATED, Json(ticket)))
}

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

    let mut query = sqlx::query_as::<
        _,
        (
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            String,
            String,
            Option<String>,
            Option<String>,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        ),
    >(&sql)
    .bind(limit)
    .bind(offset);

    if let Some(s) = &bind_status {
        query = query.bind(s);
    }

    let ticket_rows = query.fetch_all(&state.db).await?;

    let mut tickets: Vec<Ticket> = Vec::with_capacity(ticket_rows.len());
    for (id, subj, desc, tid, tname, temail, status, priority, cat, assignee, ca, ua) in ticket_rows
    {
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
            .map(
                |(mid, content, author, at, attachments, mca)| TicketMessage {
                    id: mid,
                    content,
                    author,
                    author_type: at,
                    attachments,
                    created_at: mca.to_rfc3339(),
                },
            )
            .collect();

        tickets.push(Ticket {
            id,
            subject: subj,
            description: desc,
            tenant_id: tid,
            tenant_name: tname,
            tenant_email: temail,
            status,
            priority,
            category: cat,
            assignee,
            created_at: ca.to_rfc3339(),
            updated_at: ua.to_rfc3339(),
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

    if body.content.trim().is_empty() {
        return Err(ApiError::Validation(vec!["content is required".into()]));
    }

    let inserted_reply = insert_support_reply_message(&state.db, &body).await?;

    // Optionally update ticket status
    if let Some(ref new_status) = body.new_status {
        if VALID_STATUSES.contains(&new_status.as_str()) {
            sqlx::query(
                "UPDATE support_tickets SET status = $1, updated_at = NOW() WHERE id::text = $2",
            )
            .bind(new_status)
            .bind(&body.ticket_id)
            .execute(&state.db)
            .await?;
        }
    }

    log_support_audit(
        &state.db,
        "control_plane.support.reply_added",
        &body.ticket_id,
        build_support_reply_audit_metadata(&body, &inserted_reply.id),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": inserted_reply.id,
            "ticketId": body.ticket_id,
            "content": body.content.trim(),
            "author": body.author,
            "authorType": body.author_type,
            "createdAt": inserted_reply.created_at.to_rfc3339(),
        })),
    ))
}

async fn update_ticket(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<UpdateTicketRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    if body.status.is_none() && body.priority.is_none() && body.assignee.is_none() {
        return Err(ApiError::Validation(vec!["No fields to update".into()]));
    }

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

    let mut rows_affected: u64 = 0;

    if let Some(ref s) = body.status {
        rows_affected += sqlx::query(
            "UPDATE support_tickets SET status = $1, updated_at = NOW() WHERE id::text = $2",
        )
        .bind(s)
        .bind(&body.id)
        .execute(&state.db)
        .await?
        .rows_affected();
    }
    if let Some(ref p) = body.priority {
        rows_affected += sqlx::query(
            "UPDATE support_tickets SET priority = $1, updated_at = NOW() WHERE id::text = $2",
        )
        .bind(p)
        .bind(&body.id)
        .execute(&state.db)
        .await?
        .rows_affected();
    }
    if let Some(ref a) = body.assignee {
        rows_affected += sqlx::query(
            "UPDATE support_tickets SET assignee = $1, updated_at = NOW() WHERE id::text = $2",
        )
        .bind(a)
        .bind(&body.id)
        .execute(&state.db)
        .await?
        .rows_affected();
    }

    if rows_affected == 0 {
        return Err(ApiError::NotFound("ticket not found".into()));
    }

    log_support_audit(
        &state.db,
        "control_plane.support.ticket_updated",
        &body.id,
        build_support_update_audit_metadata(&body),
    )
    .await;

    Ok(Json(serde_json::json!({
        "id": body.id,
        "status": body.status,
        "priority": body.priority,
        "assignee": body.assignee,
        "updatedAt": chrono::Utc::now().to_rfc3339(),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    use sqlx::{migrate::Migrator, PgPool};
    use uuid::Uuid;

    fn tool_migrations_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../tools/migrations")
    }

    async fn apply_tool_migrations(pool: &PgPool) {
        let source_dir = tool_migrations_dir();
        let temp_dir = std::env::temp_dir().join(format!(
            "apexmail-api-support-up-migrations-{}",
            Uuid::new_v4()
        ));

        fs::create_dir_all(&temp_dir).expect("failed to create temp sqlx migration directory");

        let mut entries: Vec<PathBuf> = fs::read_dir(&source_dir)
            .expect("failed to read tools/migrations")
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("sql"))
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| {
                        !name.ends_with("_down.sql") && !name.contains("performance_indexes")
                    })
                    .unwrap_or(false)
            })
            .collect();
        entries.sort();

        for path in entries {
            let file_name = path.file_name().expect("migration path missing filename");
            let raw = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("failed to read migration {:?}: {error}", path));
            let normalized = raw
                .replace("CREATE UNIQUE INDEX CONCURRENTLY", "CREATE UNIQUE INDEX")
                .replace("CREATE INDEX CONCURRENTLY", "CREATE INDEX");
            fs::write(temp_dir.join(file_name), normalized).unwrap_or_else(|error| {
                panic!("failed to write copied migration {:?}: {error}", path)
            });
        }

        let migrator = Migrator::new(temp_dir.clone())
            .await
            .expect("failed to load copied up migrations");
        migrator
            .run(pool)
            .await
            .expect("failed to apply copied up migrations");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn support_post_request_deserializes_create_shape() {
        let body = serde_json::json!({
            "subject": "Escalated deliverability issue",
            "description": "Customer reports blocked sends",
            "priority": "high"
        });

        let request: SupportPostRequest = serde_json::from_value(body).unwrap();
        assert!(matches!(request, SupportPostRequest::Create(_)));
    }

    #[test]
    fn support_post_request_deserializes_reply_shape() {
        let body = serde_json::json!({
            "ticketId": "sup_test_ticket",
            "content": "We are investigating now",
            "author": "System",
            "authorType": "agent"
        });

        let request: SupportPostRequest = serde_json::from_value(body).unwrap();
        assert!(matches!(request, SupportPostRequest::Reply(_)));
    }

    #[tokio::test]
    async fn create_support_ticket_persists_ticket() {
        let Some(pool) =
            crate::test_db::optional_pg_pool("create_support_ticket_persists_ticket").await
        else {
            return;
        };
        apply_tool_migrations(&pool).await;

        let ticket = insert_support_ticket(
            &pool,
            &CreateTicketRequest {
                subject: "Escalated deliverability issue".into(),
                description: "Customer reports blocked sends".into(),
                tenant_id: Some("ten_support_a".into()),
                tenant_name: Some("Tenant A".into()),
                tenant_email: Some("ops@tenant-a.test".into()),
                priority: "high".into(),
                category: Some("technical".into()),
                assignee: Some("alice@apexmail.test".into()),
            },
        )
        .await
        .expect("support ticket creation should succeed");

        let row: (String, String, Option<String>, Option<String>, Option<String>, String, Option<String>, Option<String>) =
            sqlx::query_as(
                "SELECT subject, description, tenant_id, tenant_name, tenant_email, priority, category, assignee
                 FROM support_tickets WHERE id = $1",
            )
            .bind(&ticket.id)
            .fetch_one(&pool)
            .await
            .expect("failed to fetch created support ticket");

        assert_eq!(row.0, "Escalated deliverability issue");
        assert_eq!(row.1, "Customer reports blocked sends");
        assert_eq!(row.2.as_deref(), Some("ten_support_a"));
        assert_eq!(row.3.as_deref(), Some("Tenant A"));
        assert_eq!(row.4.as_deref(), Some("ops@tenant-a.test"));
        assert_eq!(row.5, "high");
        assert_eq!(row.6.as_deref(), Some("technical"));
        assert_eq!(row.7.as_deref(), Some("alice@apexmail.test"));
        assert!(ticket.messages.is_empty());
        assert_eq!(ticket.status, "open");
    }

    #[tokio::test]
    async fn add_reply_persists_message_with_database_generated_id() {
        let Some(pool) = crate::test_db::optional_pg_pool(
            "add_reply_persists_message_with_database_generated_id",
        )
        .await
        else {
            return;
        };
        apply_tool_migrations(&pool).await;

        let ticket = insert_support_ticket(
            &pool,
            &CreateTicketRequest {
                subject: "Reply test".into(),
                description: "Seed ticket".into(),
                tenant_id: Some("ten_support_b".into()),
                tenant_name: None,
                tenant_email: None,
                priority: "medium".into(),
                category: None,
                assignee: None,
            },
        )
        .await
        .expect("support ticket seed should succeed");

        let reply = insert_support_reply_message(
            &pool,
            &AddReplyRequest {
                ticket_id: ticket.id.clone(),
                content: "We are investigating now".into(),
                author: "System".into(),
                author_type: "agent".into(),
                new_status: Some("in_progress".into()),
            },
        )
        .await
        .expect("support reply insertion should succeed");

        let row: (String, String, String) = sqlx::query_as(
            "SELECT content, author, author_type FROM support_ticket_messages WHERE id = $1",
        )
        .bind(&reply.id)
        .fetch_one(&pool)
        .await
        .expect("failed to fetch support reply row");

        assert_eq!(row.0, "We are investigating now");
        assert_eq!(row.1, "System");
        assert_eq!(row.2, "agent");
        assert!(
            reply.id.len() <= 26,
            "database-generated ids should fit the support schema"
        );
    }
}
