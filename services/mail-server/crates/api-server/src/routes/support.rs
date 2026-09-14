//! Support ticket routes.

use super::helpers::{clamp_limit, default_limit};
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
        .route(
            "/tickets/:id/messages",
            get(list_ticket_messages).post(create_ticket_message),
        )
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct UpdateTicketRequest {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub priority: Option<String>,
    #[serde(default)]
    pub assigned_to: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TicketResponse {
    pub id: String,
    pub subject: String,
    pub description: String,
    pub priority: String,
    pub status: String,
    pub assigned_to: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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

// ─── Handlers ──────────────────────────────────────────────────

async fn create_ticket(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateTicketRequest>,
) -> Result<(StatusCode, Json<TicketResponse>), ApiError> {
    require_scopes(&auth, &["support:write"])?;

    if body.subject.is_empty() || body.subject.len() > 500 {
        return Err(ApiError::Validation(vec![
            "subject is required and must be 500 characters or fewer".into(),
        ]));
    }
    if body.description.is_empty() || body.description.len() > 10000 {
        return Err(ApiError::Validation(vec![
            "description is required and must be 10,000 characters or fewer".into(),
        ]));
    }
    const VALID_PRIORITIES: &[&str] = &["low", "normal", "high", "urgent"];
    if !VALID_PRIORITIES.contains(&body.priority.as_str()) {
        return Err(ApiError::Validation(vec![format!(
            "invalid priority '{}'; expected one of: low, normal, high, urgent",
            body.priority
        )]));
    }

    // support_tickets.id is VARCHAR(26) (canonical migration chain): a
    // 36-char hyphenated UUID overflows the column and turned every ticket
    // creation into a database 500.
    let id = apexmail_lib::id::generate_id("", 26);
    let now = Utc::now();

    sqlx::query(
        "INSERT INTO support_tickets (id, tenant_id, subject, description, priority, status, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,'open',$6,$6)",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
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
    .bind(&auth.tenant_id)
    .bind(clamp_limit(params.limit, 100))
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn get_ticket(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<TicketResponse>, ApiError> {
    require_scopes(&auth, &["support:read"])?;

    // The id column is VARCHAR(26), not UUID: bind the raw string so
    // malformed ids resolve to an honest 404 instead of a router-level
    // rejection or a database type error.
    let row = sqlx::query_as::<_, TicketRow>(
        "SELECT id, subject, description, priority, status, assigned_to, created_at, updated_at
         FROM support_tickets WHERE id = $1 AND tenant_id = $2",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("ticket not found".into()))?;

    Ok(Json(row.into()))
}

async fn update_ticket(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<UpdateTicketRequest>,
) -> Result<Json<TicketResponse>, ApiError> {
    require_scopes(&auth, &["support:write"])?;

    let existing = sqlx::query_as::<_, TicketRow>(
        "SELECT id, subject, description, priority, status, assigned_to, created_at, updated_at
         FROM support_tickets WHERE id = $1 AND tenant_id = $2",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("ticket not found".into()))?;

    const VALID_STATUSES: &[&str] = &[
        "open",
        "in_progress",
        "pending_customer",
        "resolved",
        "closed",
    ];
    const VALID_PRIORITIES: &[&str] = &["low", "normal", "high", "urgent"];

    let status = body.status.unwrap_or(existing.status);
    if !VALID_STATUSES.contains(&status.as_str()) {
        return Err(ApiError::Validation(vec![format!(
            "invalid status '{}'; expected one of: open, in_progress, pending_customer, resolved, closed",
            status
        )]));
    }
    let priority = body.priority.unwrap_or(existing.priority);
    if !VALID_PRIORITIES.contains(&priority.as_str()) {
        return Err(ApiError::Validation(vec![format!(
            "invalid priority '{}'; expected one of: low, normal, high, urgent",
            priority
        )]));
    }
    let assigned_to = body.assigned_to.or(existing.assigned_to);
    if let Some(ref assignee) = assigned_to {
        // support_tickets.assigned_to is VARCHAR(26) — validating against
        // 255 let an over-long assignee reach the column and 500.
        if assignee.len() > 26 {
            return Err(ApiError::Validation(vec![
                "assigned_to must be 26 characters or fewer".into(),
            ]));
        }
    }

    sqlx::query(
        "UPDATE support_tickets SET status=$1, priority=$2, assigned_to=$3, updated_at=NOW()
         WHERE id=$4 AND tenant_id=$5",
    )
    .bind(&status)
    .bind(&priority)
    .bind(assigned_to.clone())
    .bind(&id)
    .bind(&auth.tenant_id)
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
    id: String,
    subject: String,
    description: String,
    priority: String,
    status: String,
    assigned_to: Option<String>,
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
#[serde(deny_unknown_fields)]
pub struct CreateMessageRequest {
    pub body: String,
}

#[derive(Debug, Serialize)]
pub struct TicketMessageResponse {
    pub id: String,
    pub ticket_id: String,
    pub sender_id: String,
    pub sender_type: String,
    pub body: String,
    pub created_at: String,
}

#[derive(sqlx::FromRow)]
struct TicketMessageRow {
    id: String,
    ticket_id: String,
    sender_id: Option<String>,
    sender_type: String,
    body: String,
    created_at: DateTime<Utc>,
}

async fn list_ticket_messages(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(ticket_id): Path<String>,
    Query(q): Query<ListTicketsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["support:read"])?;
    let limit = q.limit.clamp(1, 200);
    let offset = q.offset.max(0);

    // Verify ticket belongs to tenant
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM support_tickets WHERE id = $1 AND tenant_id = $2)",
    )
    .bind(&ticket_id)
    .bind(auth.tenant_id.to_string())
    .fetch_one(&state.db)
    .await?;

    if !exists {
        return Err(ApiError::NotFound("ticket not found".into()));
    }

    let rows: Vec<TicketMessageRow> = sqlx::query_as(
        r#"SELECT id::text, ticket_id, author_id AS sender_id, '' AS sender_type, body, created_at
           FROM ticket_messages
           WHERE ticket_id = $1
           ORDER BY created_at ASC
           LIMIT $2 OFFSET $3"#,
    )
    .bind(&ticket_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    let messages: Vec<TicketMessageResponse> = rows
        .into_iter()
        .map(|r| TicketMessageResponse {
            id: r.id,
            ticket_id: r.ticket_id,
            sender_id: r.sender_id.unwrap_or_default(),
            sender_type: r.sender_type,
            body: r.body,
            created_at: r.created_at.to_rfc3339(),
        })
        .collect();

    let total: i64 = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT COUNT(*)::bigint FROM ticket_messages WHERE ticket_id = $1",
    )
    .bind(&ticket_id)
    .fetch_one(&state.db)
    .await?
    .unwrap_or(0);

    Ok(Json(serde_json::json!({
        "data": messages,
        "total": total,
    })))
}

/// Maximum ticket-message body length (64 KiB) — an unbounded body would
/// be stored verbatim in ticket_messages and echoed back in list views.
const MAX_MESSAGE_BODY_BYTES: usize = 64 * 1024;

async fn create_ticket_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(ticket_id): Path<String>,
    Json(body): Json<CreateMessageRequest>,
) -> Result<(StatusCode, Json<TicketMessageResponse>), ApiError> {
    require_scopes(&auth, &["support:write"])?;

    if body.body.trim().is_empty() {
        return Err(ApiError::Validation(vec!["body is required".into()]));
    }
    if body.body.len() > MAX_MESSAGE_BODY_BYTES {
        return Err(ApiError::BadRequest(format!(
            "message body must be {MAX_MESSAGE_BODY_BYTES} bytes or fewer"
        )));
    }

    // Verify ticket belongs to tenant
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM support_tickets WHERE id = $1 AND tenant_id = $2)",
    )
    .bind(&ticket_id)
    .bind(auth.tenant_id.to_string())
    .fetch_one(&state.db)
    .await?;

    if !exists {
        return Err(ApiError::NotFound("ticket not found".into()));
    }

    let id = Uuid::new_v4();
    let now = chrono::Utc::now();
    let user_id_str = auth.user_id.as_ref().map(|id| id.to_string());

    // Bind the generated id so the 201 response returns the id that was
    // actually persisted — the previous statement used gen_random_uuid()
    // and discarded this one, so responses named a row that did not exist.
    sqlx::query(
        "INSERT INTO ticket_messages (id, ticket_id, author_id, body, is_internal, created_at)
         VALUES ($1, $2, $3, $4, false, $5)",
    )
    .bind(id)
    .bind(&ticket_id)
    .bind(&user_id_str)
    .bind(&body.body)
    .bind(now)
    .execute(&state.db)
    .await?;

    // Update ticket updated_at
    sqlx::query("UPDATE support_tickets SET updated_at = NOW() WHERE id = $1 AND tenant_id = $2")
        .bind(&ticket_id)
        .bind(auth.tenant_id.to_string())
        .execute(&state.db)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(TicketMessageResponse {
            id: id.to_string(),
            ticket_id,
            sender_id: auth.user_id.unwrap_or_default(),
            sender_type: "user".into(),
            body: body.body,
            created_at: now.to_rfc3339(),
        }),
    ))
}

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
            id: String::new(),
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

// ─── Adversarial ticket CRUD tests ─────────────────────────────

#[cfg(test)]
mod adversarial_tests {
    use super::*;

    fn auth_for(tenant: &str, scopes: &[&str]) -> AuthUser {
        AuthUser {
            tenant_id: tenant.to_string(),
            user_id: Some("usr_adv_0000000000000001".into()),
            api_key_id: None,
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
             VALUES ($1, 'support adversarial', 'free', 'active', NOW(), NOW())
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant)
        .execute(pool)
        .await
        .expect("seed tenant");
    }

    async fn create_ok(state: &AppState, tenant: &str, subject: &str) -> TicketResponse {
        let (status, Json(ticket)) = create_ticket(
            State(state.clone()),
            auth_for(tenant, &["support:write"]),
            Json(CreateTicketRequest {
                subject: subject.into(),
                description: "please help".into(),
                priority: "high".into(),
            }),
        )
        .await
        .expect("create ticket");
        assert_eq!(status, StatusCode::CREATED);
        ticket
    }

    #[tokio::test]
    async fn ticket_crud_is_tenant_scoped_and_ids_are_canonical_length() {
        let Some((state, pool)) = state_and_pool("adv_support_tickets").await else {
            return;
        };
        let tenant_a = apexmail_lib::id::generate_id("", 26);
        let tenant_b = apexmail_lib::id::generate_id("", 26);
        seed_tenant(&pool, &tenant_a).await;
        seed_tenant(&pool, &tenant_b).await;

        let ticket = create_ok(&state, &tenant_a, "Cannot send").await;
        // support_tickets.id is VARCHAR(26): a 36-char hyphenated UUID would
        // overflow the column and turn every create into a 500.
        assert_eq!(
            ticket.id.len(),
            26,
            "the persisted id must fit support_tickets.id: {}",
            ticket.id
        );
        assert_eq!(ticket.status, "open");
        assert_eq!(ticket.priority, "high");

        // Validation edges.
        for (subject, description, priority) in [
            ("", "d", "normal"),
            (&"s".repeat(501), "d", "normal"),
            ("s", "", "normal"),
            ("s", &"d".repeat(10_001), "normal"),
            ("s", "d", "impossible"),
            ("s", "d", ""),
        ] {
            let resp = create_ticket(
                State(state.clone()),
                auth_for(&tenant_a, &["support:write"]),
                Json(CreateTicketRequest {
                    subject: subject.to_string(),
                    description: description.to_string(),
                    priority: priority.to_string(),
                }),
            )
            .await;
            assert!(
                matches!(resp, Err(ApiError::Validation(_))),
                "({subject:?},{priority:?}) must be refused"
            );
        }

        // Own reads; other-tenant reads are 404 and leak nothing.
        let Json(fetched) = get_ticket(
            State(state.clone()),
            auth_for(&tenant_a, &["support:read"]),
            Path(ticket.id.clone()),
        )
        .await
        .expect("own read");
        assert_eq!(fetched.subject, "Cannot send");

        let foreign = create_ok(&state, &tenant_b, "Tenant B secret").await;
        let cross = get_ticket(
            State(state.clone()),
            auth_for(&tenant_a, &["support:read"]),
            Path(foreign.id.clone()),
        )
        .await;
        assert!(matches!(cross, Err(ApiError::NotFound(_))));

        // Malformed / unknown / over-long ids are 404, never database 500s.
        for bad in [
            "",
            "not-a-ticket-id",
            &"z".repeat(400),
            "00000000000000000000000000",
        ] {
            let resp = get_ticket(
                State(state.clone()),
                auth_for(&tenant_a, &["support:read"]),
                Path(bad.to_string()),
            )
            .await;
            assert!(
                matches!(resp, Err(ApiError::NotFound(_))),
                "GET {bad:?} must be 404, got {resp:?}"
            );
            let resp = update_ticket(
                State(state.clone()),
                auth_for(&tenant_a, &["support:write"]),
                Path(bad.to_string()),
                Json(UpdateTicketRequest {
                    status: None,
                    priority: None,
                    assigned_to: None,
                }),
            )
            .await;
            assert!(
                matches!(resp, Err(ApiError::NotFound(_))),
                "PUT {bad:?} must be 404, got {resp:?}"
            );
        }

        // Listing is scoped and paginated.
        let Json(list) = list_tickets(
            State(state.clone()),
            auth_for(&tenant_a, &["support:read"]),
            Query(ListTicketsQuery {
                limit: 1,
                offset: 0,
                cursor: None,
                status: None,
            }),
        )
        .await
        .expect("list");
        assert_eq!(list.len(), 1);
        assert!(list.iter().all(|t| t.id != foreign.id));
        let Json(clamped) = list_tickets(
            State(state.clone()),
            auth_for(&tenant_a, &["support:read"]),
            Query(ListTicketsQuery {
                limit: -1,
                offset: -9,
                cursor: Some(-4),
                status: Some("open".into()),
            }),
        )
        .await
        .expect("clamped");
        assert_eq!(clamped.len(), 1);

        // Valid transition; invalid enum values refused without touching the row.
        let Json(updated) = update_ticket(
            State(state.clone()),
            auth_for(&tenant_a, &["support:write"]),
            Path(ticket.id.clone()),
            Json(UpdateTicketRequest {
                status: Some("in_progress".into()),
                priority: Some("urgent".into()),
                assigned_to: Some("operator-1".into()),
            }),
        )
        .await
        .expect("update");
        assert_eq!(updated.status, "in_progress");
        assert_eq!(updated.priority, "urgent");
        assert_eq!(updated.assigned_to.as_deref(), Some("operator-1"));

        for (status, priority) in [
            (Some("banana"), None),
            (None, Some("banana")),
            (Some("OPEN"), None),
        ] {
            let resp = update_ticket(
                State(state.clone()),
                auth_for(&tenant_a, &["support:write"]),
                Path(ticket.id.clone()),
                Json(UpdateTicketRequest {
                    status: status.map(str::to_string),
                    priority: priority.map(str::to_string),
                    assigned_to: None,
                }),
            )
            .await;
            assert!(matches!(resp, Err(ApiError::Validation(_))));
        }
        // Over-long assignee is a validation error, not a column overflow 500.
        let long_assignee = update_ticket(
            State(state.clone()),
            auth_for(&tenant_a, &["support:write"]),
            Path(ticket.id.clone()),
            Json(UpdateTicketRequest {
                status: None,
                priority: None,
                assigned_to: Some("a".repeat(255)),
            }),
        )
        .await;
        assert!(matches!(long_assignee, Err(ApiError::Validation(_))));

        // Cross-tenant update is a 404 and leaves the row untouched.
        let cross_update = update_ticket(
            State(state.clone()),
            auth_for(&tenant_a, &["support:write"]),
            Path(foreign.id.clone()),
            Json(UpdateTicketRequest {
                status: Some("closed".into()),
                priority: None,
                assigned_to: None,
            }),
        )
        .await;
        assert!(matches!(cross_update, Err(ApiError::NotFound(_))));
        let (foreign_status,): (String,) =
            sqlx::query_as("SELECT status FROM support_tickets WHERE id = $1 AND tenant_id = $2")
                .bind(&foreign.id)
                .bind(&tenant_b)
                .fetch_one(&pool)
                .await
                .expect("foreign row");
        assert_eq!(foreign_status, "open");

        // Scope gates.
        assert!(matches!(
            create_ticket(
                State(state.clone()),
                auth_for(&tenant_a, &["support:read"]),
                Json(CreateTicketRequest {
                    subject: "s".into(),
                    description: "d".into(),
                    priority: "normal".into(),
                })
            )
            .await,
            Err(ApiError::Forbidden(_))
        ));
        assert!(matches!(
            get_ticket(
                State(state.clone()),
                auth_for(&tenant_a, &[]),
                Path(ticket.id.clone())
            )
            .await,
            Err(ApiError::Forbidden(_))
        ));

        for tenant in [&tenant_a, &tenant_b] {
            sqlx::query("DELETE FROM ticket_messages WHERE ticket_id IN (SELECT id FROM support_tickets WHERE tenant_id = $1)")
                .bind(tenant)
                .execute(&pool)
                .await
                .expect("cleanup messages");
            sqlx::query("DELETE FROM support_tickets WHERE tenant_id = $1")
                .bind(tenant)
                .execute(&pool)
                .await
                .expect("cleanup tickets");
            sqlx::query("DELETE FROM tenants WHERE id = $1")
                .bind(tenant)
                .execute(&pool)
                .await
                .expect("cleanup tenant");
        }
    }

    #[tokio::test]
    async fn ticket_messages_bound_bodies_and_tenant_guard() {
        let Some((state, pool)) = state_and_pool("adv_support_messages").await else {
            return;
        };
        let tenant_a = apexmail_lib::id::generate_id("", 26);
        let tenant_b = apexmail_lib::id::generate_id("", 26);
        seed_tenant(&pool, &tenant_a).await;
        seed_tenant(&pool, &tenant_b).await;
        let ticket = create_ok(&state, &tenant_a, "Thread").await;
        let foreign = create_ok(&state, &tenant_b, "Foreign thread").await;

        let (status, Json(message)) = create_ticket_message(
            State(state.clone()),
            auth_for(&tenant_a, &["support:write"]),
            Path(ticket.id.clone()),
            Json(CreateMessageRequest {
                body: "first reply".into(),
            }),
        )
        .await
        .expect("create message");
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(message.ticket_id, ticket.id);
        assert_eq!(message.sender_type, "user");

        // Empty / whitespace-only bodies and oversize bodies are refused.
        for body in ["", "   ", "\n\t"] {
            let resp = create_ticket_message(
                State(state.clone()),
                auth_for(&tenant_a, &["support:write"]),
                Path(ticket.id.clone()),
                Json(CreateMessageRequest { body: body.into() }),
            )
            .await;
            assert!(matches!(resp, Err(ApiError::Validation(_))), "{body:?}");
        }
        let oversized = create_ticket_message(
            State(state.clone()),
            auth_for(&tenant_a, &["support:write"]),
            Path(ticket.id.clone()),
            Json(CreateMessageRequest {
                body: "x".repeat(MAX_MESSAGE_BODY_BYTES + 1),
            }),
        )
        .await;
        assert!(matches!(oversized, Err(ApiError::BadRequest(_))));

        // Cross-tenant and unknown tickets are 404 for both list and create.
        for bad in [foreign.id.clone(), "unknown-ticket".into()] {
            let resp = create_ticket_message(
                State(state.clone()),
                auth_for(&tenant_a, &["support:write"]),
                Path(bad.clone()),
                Json(CreateMessageRequest {
                    body: "sneaky".into(),
                }),
            )
            .await;
            assert!(matches!(resp, Err(ApiError::NotFound(_))), "{bad:?}");
            let resp = list_ticket_messages(
                State(state.clone()),
                auth_for(&tenant_a, &["support:read"]),
                Path(bad.clone()),
                Query(ListTicketsQuery {
                    limit: 10,
                    offset: 0,
                    cursor: None,
                    status: None,
                }),
            )
            .await;
            assert!(matches!(resp, Err(ApiError::NotFound(_))), "{bad:?}");
        }

        let Json(messages) = list_ticket_messages(
            State(state.clone()),
            auth_for(&tenant_a, &["support:read"]),
            Path(ticket.id.clone()),
            Query(ListTicketsQuery {
                limit: 50,
                offset: 0,
                cursor: None,
                status: None,
            }),
        )
        .await
        .expect("list messages");
        assert_eq!(messages["total"], 1);
        assert_eq!(messages["data"][0]["body"], "first reply");
        // The 201 id must be the persisted row id.
        assert_eq!(messages["data"][0]["id"], message.id);

        // Scope gates on both message routes.
        assert!(matches!(
            create_ticket_message(
                State(state.clone()),
                auth_for(&tenant_a, &["support:read"]),
                Path(ticket.id.clone()),
                Json(CreateMessageRequest { body: "x".into() })
            )
            .await,
            Err(ApiError::Forbidden(_))
        ));
        assert!(matches!(
            list_ticket_messages(
                State(state.clone()),
                auth_for(&tenant_a, &[]),
                Path(ticket.id.clone()),
                Query(ListTicketsQuery {
                    limit: 1,
                    offset: 0,
                    cursor: None,
                    status: None
                })
            )
            .await,
            Err(ApiError::Forbidden(_))
        ));

        for tenant in [&tenant_a, &tenant_b] {
            sqlx::query("DELETE FROM ticket_messages WHERE ticket_id IN (SELECT id FROM support_tickets WHERE tenant_id = $1)")
                .bind(tenant)
                .execute(&pool)
                .await
                .expect("cleanup messages");
            sqlx::query("DELETE FROM support_tickets WHERE tenant_id = $1")
                .bind(tenant)
                .execute(&pool)
                .await
                .expect("cleanup tickets");
            sqlx::query("DELETE FROM tenants WHERE id = $1")
                .bind(tenant)
                .execute(&pool)
                .await
                .expect("cleanup tenant");
        }
    }

    #[test]
    fn unknown_fields_and_default_priority_deserialize() {
        assert!(serde_json::from_str::<CreateTicketRequest>(
            r#"{"subject":"s","description":"d","tenant_id":"other"}"#
        )
        .is_err());
        let req: CreateTicketRequest =
            serde_json::from_str(r#"{"subject":"s","description":"d"}"#).unwrap();
        assert_eq!(req.priority, "normal");
    }
}
