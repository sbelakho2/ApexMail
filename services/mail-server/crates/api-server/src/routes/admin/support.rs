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

/// Actor-attributed support audit (P2-2): ticket mutations record the
/// acting operator's tenant AND user id — `None, None` left every support
/// action anonymous in the compliance trail.
async fn log_support_audit(
    state: &AppState,
    auth: &AuthUser,
    action: &str,
    ticket_id: &str,
    metadata: serde_json::Value,
) {
    crate::audit_log::insert_audit_log_best_effort_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
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

/// Author types that an authenticated operator may legitimately claim when
/// replying to a support ticket. Anything else (e.g. "customer") is rejected
/// so a staff member cannot forge messages that look like they came from a
/// customer or a different staff role.
const VALID_STAFF_AUTHOR_TYPES: &[&str] = &["agent", "system", "admin", "owner", "staff"];

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
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

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

    // Derive tenant identity from the authenticated operator; never trust
    // client-supplied tenant fields (prevents forging another tenant's
    // identity in support tickets or audit logs).
    let mut body = body;
    body.tenant_id = Some(auth.tenant_id.clone());
    body.tenant_name = None;
    body.tenant_email = None;

    let ticket = insert_support_ticket(&state.db, &body).await?;

    log_support_audit(
        &state,
        &auth,
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
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

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

    // One batched messages fetch (P2 N+1): the per-ticket loop issued
    // limit+1 queries per page (101 at the cap). The global window bounds
    // memory; the per-ticket cap is re-applied while grouping.
    let ticket_ids: Vec<String> = ticket_rows.iter().map(|row| row.0.clone()).collect();
    let msg_rows: Vec<(
        String,
        String,
        String,
        String,
        String,
        serde_json::Value,
        chrono::DateTime<chrono::Utc>,
    )> = if ticket_ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query_as(
            "SELECT ticket_id::text, id::text, content, author, author_type, \
             COALESCE(attachments, '[]'::jsonb), created_at \
             FROM support_ticket_messages WHERE ticket_id::text = ANY($1) \
             ORDER BY created_at ASC LIMIT 5000",
        )
        .bind(&ticket_ids)
        .fetch_all(&state.db)
        .await?
    };

    // ORDER BY created_at ASC keeps each ticket's slice chronological; the
    // per-ticket truncation preserves the old per-ticket LIMIT 50 contract.
    let mut messages_by_ticket: std::collections::HashMap<String, Vec<TicketMessage>> =
        std::collections::HashMap::new();
    for (tid, mid, content, author, author_type, attachments, mca) in msg_rows {
        messages_by_ticket
            .entry(tid)
            .or_default()
            .push(TicketMessage {
                id: mid,
                content,
                author,
                author_type,
                attachments,
                created_at: mca.to_rfc3339(),
            });
    }
    for messages in messages_by_ticket.values_mut() {
        messages.truncate(50);
    }

    let mut tickets: Vec<Ticket> = Vec::with_capacity(ticket_rows.len());
    for (id, subj, desc, tid, tname, temail, status, priority, cat, assignee, ca, ua) in ticket_rows
    {
        tickets.push(Ticket {
            messages: messages_by_ticket.remove(&id).unwrap_or_default(),
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
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    if body.content.trim().is_empty() {
        return Err(ApiError::Validation(vec!["content is required".into()]));
    }

    // Author identity is derived server-side from the authenticated operator;
    // client-supplied author is never trusted (prevents impersonating a
    // customer or another staff member). author_type is restricted to staff
    // roles so a caller cannot forge "customer" authorship.
    let mut body = body;
    body.author = auth.user_id.clone().unwrap_or_else(|| "System".to_string());
    if !VALID_STAFF_AUTHOR_TYPES.contains(&body.author_type.as_str()) {
        body.author_type = "agent".to_string();
    }

    // Reject unknown tickets and invalid transitions BEFORE writing: the
    // FK used to swallow the former into a driver error and the latter was
    // silently ignored (status stays stale while the reply suggests action).
    let ticket_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM support_tickets WHERE id::text = $1)")
            .bind(&body.ticket_id)
            .fetch_one(&state.db)
            .await
            .unwrap_or(false);
    if !ticket_exists {
        return Err(ApiError::NotFound("ticket not found".into()));
    }
    if let Some(ref new_status) = body.new_status {
        if !VALID_STATUSES.contains(&new_status.as_str()) {
            return Err(ApiError::Validation(vec![format!(
                "invalid newStatus: {new_status}"
            )]));
        }
    }

    let inserted_reply = insert_support_reply_message(&state.db, &body).await?;

    // Optionally update ticket status (validated above)
    if let Some(ref new_status) = body.new_status {
        sqlx::query(
            "UPDATE support_tickets SET status = $1, updated_at = NOW() WHERE id::text = $2",
        )
        .bind(new_status)
        .bind(&body.ticket_id)
        .execute(&state.db)
        .await?;
    }

    log_support_audit(
        &state,
        &auth,
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
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

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

    // All three UPDATEs share one transaction: a status flip landing while
    // the priority flip fails must not leave a half-applied edit (the old
    // shape could set status, then 500 on priority, then re-run to a
    // second status write).
    let mut tx = state.db.begin().await?;
    let mut rows_affected: u64 = 0;

    if let Some(ref s) = body.status {
        rows_affected += sqlx::query(
            "UPDATE support_tickets SET status = $1, updated_at = NOW() WHERE id::text = $2",
        )
        .bind(s)
        .bind(&body.id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    }
    if let Some(ref p) = body.priority {
        rows_affected += sqlx::query(
            "UPDATE support_tickets SET priority = $1, updated_at = NOW() WHERE id::text = $2",
        )
        .bind(p)
        .bind(&body.id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    }
    if let Some(ref a) = body.assignee {
        rows_affected += sqlx::query(
            "UPDATE support_tickets SET assignee = $1, updated_at = NOW() WHERE id::text = $2",
        )
        .bind(a)
        .bind(&body.id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    }

    if rows_affected == 0 {
        tx.rollback().await?;
        return Err(ApiError::NotFound("ticket not found".into()));
    }
    tx.commit().await?;

    log_support_audit(
        &state,
        &auth,
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
    use uuid::Uuid;

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
            "SELECT content, author, author_type FROM support_ticket_messages WHERE id = $1::uuid",
        )
        .bind(&reply.id)
        .fetch_one(&pool)
        .await
        .expect("failed to fetch support reply row");

        assert_eq!(row.0, "We are investigating now");
        assert_eq!(row.1, "System");
        assert_eq!(row.2, "agent");
        // Canonical support_ticket_messages ids are database-generated UUIDs
        // (migration 093); the tools lineage's VARCHAR(26) bound is gone.
        assert!(
            Uuid::parse_str(&reply.id).is_ok(),
            "database-generated reply id must be a UUID, got {}",
            reply.id
        );
    }
}

// ─── Adversarial control-plane support tests ───────────────────

#[cfg(test)]
mod adversarial_tests {
    use super::*;

    fn admin_auth() -> AuthUser {
        AuthUser {
            tenant_id: "system".into(),
            user_id: Some("usr_adv_support_000001".into()),
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        }
    }

    async fn state_and_pool(name: &str) -> Option<(AppState, sqlx::PgPool)> {
        let pool = crate::test_db::optional_pg_pool(name).await?;
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        Some((state, pool))
    }

    fn create_body(subject: &str) -> CreateTicketRequest {
        CreateTicketRequest {
            subject: subject.into(),
            description: "  needs help  ".into(),
            tenant_id: None,
            tenant_name: Some("forged name".into()),
            tenant_email: Some("forged@evil.example".into()),
            priority: "HIGH".into(),
            category: Some("billing".into()),
            assignee: Some("operator-1".into()),
        }
    }

    async fn cleanup(pool: &sqlx::PgPool, ticket_ids: &[String]) {
        for id in ticket_ids {
            sqlx::query("DELETE FROM support_ticket_messages WHERE ticket_id = $1")
                .bind(id)
                .execute(pool)
                .await
                .expect("cleanup messages");
            sqlx::query("DELETE FROM support_tickets WHERE id = $1")
                .bind(id)
                .execute(pool)
                .await
                .expect("cleanup ticket");
        }
    }

    #[test]
    fn optional_text_normalization_trims_and_drops_empty() {
        let empty = String::new();
        let blank = "   ".to_string();
        let value = "  x  ".to_string();
        assert_eq!(normalize_optional_text(None), None);
        assert_eq!(normalize_optional_text(Some(&empty)), None);
        assert_eq!(normalize_optional_text(Some(&blank)), None);
        assert_eq!(normalize_optional_text(Some(&value)), Some("x".into()));
    }

    #[tokio::test]
    async fn ticket_create_derives_tenant_and_lowercases_priority() {
        let Some((state, pool)) = state_and_pool("adv_admin_support_create").await else {
            return;
        };
        let (status, Json(ticket)) = create_ticket(
            State(state.clone()),
            admin_auth(),
            Json(create_body("Cannot export data")),
        )
        .await
        .expect("create ticket");
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(ticket.status, "open");
        assert_eq!(ticket.priority, "high", "priority normalized to lowercase");
        assert_eq!(ticket.subject, "Cannot export data");
        assert_eq!(ticket.description.as_deref(), Some("needs help"));
        // Client-supplied tenant fields must never be trusted.
        assert_eq!(ticket.tenant_id.as_deref(), Some("system"));
        assert!(ticket.tenant_name.is_none());
        assert!(ticket.tenant_email.is_none());
        assert!(ticket.messages.is_empty());

        // Validation: blank fields and unknown priority.
        let mut blank = create_body("   ");
        blank.description = "d".into();
        assert!(matches!(
            create_ticket(State(state.clone()), admin_auth(), Json(blank)).await,
            Err(ApiError::Validation(_))
        ));
        let mut blank_desc = create_body("subject");
        blank_desc.description = "   ".into();
        assert!(matches!(
            create_ticket(State(state.clone()), admin_auth(), Json(blank_desc)).await,
            Err(ApiError::Validation(_))
        ));
        let mut bad_priority = create_body("subject");
        bad_priority.priority = "impossible".into();
        assert!(matches!(
            create_ticket(State(state.clone()), admin_auth(), Json(bad_priority)).await,
            Err(ApiError::Validation(_))
        ));

        cleanup(&pool, &[ticket.id]).await;
    }

    #[tokio::test]
    async fn list_reply_and_update_flow_with_forgery_guards() {
        let Some((state, pool)) = state_and_pool("adv_admin_support_flow").await else {
            return;
        };
        let (_, Json(ticket)) = create_ticket(
            State(state.clone()),
            admin_auth(),
            Json(create_body(&format!(
                "Thread {}",
                uuid::Uuid::new_v4().simple()
            ))),
        )
        .await
        .expect("create ticket");

        // List with clamps and a status filter.
        let Json(list) = list_tickets(
            State(state.clone()),
            admin_auth(),
            Query(TicketsQuery {
                limit: i64::MAX,
                offset: -1,
                status: Some("open".into()),
            }),
        )
        .await
        .expect("list");
        assert!(list.iter().any(|t| t.id == ticket.id));
        assert!(list.iter().all(|t| t.status == "open"));
        let Json(no_match) = list_tickets(
            State(state.clone()),
            admin_auth(),
            Query(TicketsQuery {
                limit: 1,
                offset: 0,
                status: Some("closed".into()),
            }),
        )
        .await
        .expect("filtered list");
        assert!(no_match.iter().all(|t| t.status == "closed"));

        // Reply: content required, unknown ticket 404, invalid status refused.
        assert!(matches!(
            add_reply(
                State(state.clone()),
                admin_auth(),
                Json(AddReplyRequest {
                    ticket_id: ticket.id.clone(),
                    content: "   ".into(),
                    author: "attacker".into(),
                    author_type: "customer".into(),
                    new_status: None,
                })
            )
            .await,
            Err(ApiError::Validation(_))
        ));
        assert!(matches!(
            add_reply(
                State(state.clone()),
                admin_auth(),
                Json(AddReplyRequest {
                    ticket_id: "no-such-ticket".into(),
                    content: "hi".into(),
                    author: "attacker".into(),
                    author_type: "agent".into(),
                    new_status: None,
                })
            )
            .await,
            Err(ApiError::NotFound(_))
        ));
        assert!(matches!(
            add_reply(
                State(state.clone()),
                admin_auth(),
                Json(AddReplyRequest {
                    ticket_id: ticket.id.clone(),
                    content: "hi".into(),
                    author: "attacker".into(),
                    author_type: "agent".into(),
                    new_status: Some("banana".into()),
                })
            )
            .await,
            Err(ApiError::Validation(_))
        ));

        // A valid reply overrides the client author/author_type and moves
        // the ticket status.
        let (status, Json(reply)) = add_reply(
            State(state.clone()),
            admin_auth(),
            Json(AddReplyRequest {
                ticket_id: ticket.id.clone(),
                content: "  investigating  ".into(),
                author: "forged-customer".into(),
                author_type: "customer".into(),
                new_status: Some("in_progress".into()),
            }),
        )
        .await
        .expect("reply");
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(reply["author"], "usr_adv_support_000001");
        assert_eq!(reply["authorType"], "agent", "customer forgery coerced");
        assert_eq!(reply["content"], "investigating");

        let Json(listed) = list_tickets(
            State(state.clone()),
            admin_auth(),
            Query(TicketsQuery {
                limit: 100,
                offset: 0,
                status: None,
            }),
        )
        .await
        .expect("list with messages");
        let fetched = listed
            .iter()
            .find(|t| t.id == ticket.id)
            .expect("ticket present");
        assert_eq!(fetched.status, "in_progress");
        assert_eq!(fetched.messages.len(), 1);
        assert_eq!(fetched.messages[0].content, "investigating");

        // Update: no-op refused, bad enums refused, unknown id 404.
        assert!(matches!(
            update_ticket(
                State(state.clone()),
                admin_auth(),
                Json(UpdateTicketRequest {
                    id: ticket.id.clone(),
                    status: None,
                    priority: None,
                    assignee: None,
                })
            )
            .await,
            Err(ApiError::Validation(_))
        ));
        for (status, priority) in [(Some("nope"), None), (None, Some("nope"))] {
            assert!(matches!(
                update_ticket(
                    State(state.clone()),
                    admin_auth(),
                    Json(UpdateTicketRequest {
                        id: ticket.id.clone(),
                        status: status.map(str::to_string),
                        priority: priority.map(str::to_string),
                        assignee: None,
                    })
                )
                .await,
                Err(ApiError::Validation(_))
            ));
        }
        assert!(matches!(
            update_ticket(
                State(state.clone()),
                admin_auth(),
                Json(UpdateTicketRequest {
                    id: "missing".into(),
                    status: Some("closed".into()),
                    priority: None,
                    assignee: None,
                })
            )
            .await,
            Err(ApiError::NotFound(_))
        ));
        let Json(updated) = update_ticket(
            State(state.clone()),
            admin_auth(),
            Json(UpdateTicketRequest {
                id: ticket.id.clone(),
                status: Some("resolved".into()),
                priority: Some("low".into()),
                assignee: Some("operator-9".into()),
            }),
        )
        .await
        .expect("update");
        assert_eq!(updated["status"], "resolved");
        assert_eq!(updated["priority"], "low");

        // Access gates.
        let mut customer = admin_auth();
        customer.tenant_id = "ten_customer_adv".into();
        assert!(matches!(
            list_tickets(
                State(state.clone()),
                customer.clone(),
                Query(TicketsQuery {
                    limit: 1,
                    offset: 0,
                    status: None
                })
            )
            .await,
            Err(ApiError::Forbidden(_))
        ));
        let mut no_scope = admin_auth();
        no_scope.scopes = vec![];
        assert!(matches!(
            post_support(
                State(state.clone()),
                no_scope,
                Json(SupportPostRequest::Create(create_body("nope")))
            )
            .await,
            Err(ApiError::Forbidden(_))
        ));

        cleanup(&pool, &[ticket.id]).await;
    }

    #[test]
    fn support_post_request_disambiguates_create_and_reply() {
        let create: SupportPostRequest =
            serde_json::from_str(r#"{"subject":"s","description":"d","priority":"high"}"#)
                .expect("create shape");
        assert!(matches!(create, SupportPostRequest::Create(_)));
        let reply: SupportPostRequest =
            serde_json::from_str(r#"{"ticketId":"t","content":"c"}"#).expect("reply shape");
        assert!(matches!(reply, SupportPostRequest::Reply(_)));
        // Unknown fields remain refused on both shapes.
        assert!(serde_json::from_str::<CreateTicketRequest>(
            r#"{"subject":"s","description":"d","evil":1}"#
        )
        .is_err());
        assert!(serde_json::from_str::<AddReplyRequest>(
            r#"{"ticketId":"t","content":"c","evil":1}"#
        )
        .is_err());
    }
}
