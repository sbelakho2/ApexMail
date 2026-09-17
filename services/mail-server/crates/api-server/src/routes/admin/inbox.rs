//! Inbox / autopilot message management endpoints.
//!

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(list_inbox).patch(update_message))
}

fn build_inbox_audit_metadata(body: &UpdateInboxMessage) -> serde_json::Value {
    json!({
        "isRead": body.is_read,
        "isArchived": body.is_archived,
        "actionTaken": body.action_taken,
    })
}

async fn log_inbox_audit(
    db: &sqlx::PgPool,
    auth: &AuthUser,
    message_id: &str,
    metadata: serde_json::Value,
) {
    crate::audit_log::insert_audit_log_best_effort(
        db,
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        "control_plane.inbox.updated",
        "autopilot_inbox_message",
        Some(message_id),
        metadata,
        None,
        None,
    )
    .await;
}

#[derive(Debug, Deserialize)]
pub struct InboxQuery {
    pub classification: Option<String>,
    pub archived: Option<bool>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

fn build_list_inbox_sql(params: &InboxQuery, tenant_scoped: bool) -> String {
    let mut conditions: Vec<String> = Vec::new();
    let mut idx = 1u32;

    if tenant_scoped {
        conditions.push(format!("tenant_id = ${idx}"));
        idx += 1;
    }
    if params.classification.is_some() {
        conditions.push(format!("classification = ${idx}"));
        idx += 1;
    }
    if params.archived.is_some() {
        conditions.push(format!("is_archived = ${idx}"));
        idx += 1;
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    format!(
        "SELECT id::text AS id, classification, subject, from_address, to_address,
                summary, is_read, is_archived, action_taken, created_at
         FROM autopilot_inbox_messages
         {where_clause}
         ORDER BY created_at DESC
         LIMIT ${idx} OFFSET ${}",
        idx + 1
    )
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InboxMessage {
    pub id: String,
    pub classification: String,
    pub subject: String,
    pub from_address: String,
    pub to_address: String,
    pub summary: Option<String>,
    pub is_read: bool,
    pub is_archived: bool,
    pub action_taken: Option<String>,
    pub created_at: String,
}

async fn list_inbox(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<InboxQuery>,
) -> Result<Json<Vec<InboxMessage>>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);
    // Slug-aware system-tenant resolution (audit F1): the literal `system`
    // sentinel never matches human operators (`system_internal_tenant01`).
    let tenant_scoped = !crate::routes::web::is_system_tenant(&state, &auth.tenant_id).await;
    let sql = build_list_inbox_sql(&params, tenant_scoped);

    let mut query = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            bool,
            bool,
            Option<String>,
            chrono::DateTime<chrono::Utc>,
        ),
    >(&sql);

    if tenant_scoped {
        query = query.bind(&auth.tenant_id);
    }
    if let Some(ref classification) = params.classification {
        query = query.bind(classification);
    }
    if let Some(archived) = params.archived {
        query = query.bind(archived);
    }
    query = query.bind(limit).bind(offset);

    let rows = query.fetch_all(&state.db).await?;

    let messages: Vec<InboxMessage> = rows
        .into_iter()
        .map(
            |(
                id,
                classification,
                subject,
                from_addr,
                to_addr,
                summary,
                is_read,
                is_archived,
                action_taken,
                created_at,
            )| {
                InboxMessage {
                    id,
                    classification,
                    subject,
                    from_address: from_addr,
                    to_address: to_addr,
                    summary,
                    is_read,
                    is_archived,
                    action_taken,
                    created_at: created_at.to_rfc3339(),
                }
            },
        )
        .collect();

    Ok(Json(messages))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInboxMessage {
    pub id: String,
    #[serde(default)]
    pub is_read: Option<bool>,
    #[serde(default)]
    pub is_archived: Option<bool>,
    #[serde(default)]
    pub action_taken: Option<String>,
}

fn build_update_inbox_sql(
    body: &UpdateInboxMessage,
    tenant_scoped: bool,
) -> Result<String, ApiError> {
    let mut sets: Vec<String> = Vec::new();
    let mut idx = if tenant_scoped { 3u32 } else { 2u32 };

    if body.is_read.is_some() {
        sets.push(format!("is_read = ${idx}"));
        idx += 1;
    }
    if body.is_archived.is_some() {
        sets.push(format!("is_archived = ${idx}"));
        idx += 1;
    }
    if body.action_taken.is_some() {
        sets.push(format!("action_taken = ${idx}"));
        idx += 1;
    }
    let _ = idx;

    if sets.is_empty() {
        return Err(ApiError::Validation(vec!["No fields to update".into()]));
    }

    sets.push("updated_at = NOW()".into());

    Ok(format!(
        "UPDATE autopilot_inbox_messages SET {} WHERE id = $1{}",
        sets.join(", "),
        if tenant_scoped {
            " AND tenant_id = $2"
        } else {
            ""
        }
    ))
}

async fn update_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<UpdateInboxMessage>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    // autopilot_inbox_messages.id is a UUID: parse the client-supplied id
    // here so a malformed value is a 400 (validation) and the WHERE bind is
    // typed — the previous text bind against a uuid column errored with
    // 42883 on EVERY update, and malformed ids surfaced as 500s.
    let id = uuid::Uuid::parse_str(body.id.trim())
        .map_err(|_| ApiError::Validation(vec!["id must be a UUID".into()]))?;
    // Slug-aware system-tenant resolution (audit F1) — see list_inbox.
    let tenant_scoped = !crate::routes::web::is_system_tenant(&state, &auth.tenant_id).await;
    let sql = build_update_inbox_sql(&body, tenant_scoped)?;

    let mut query = sqlx::query(&sql).bind(id);

    if tenant_scoped {
        query = query.bind(&auth.tenant_id);
    }

    if let Some(is_read) = body.is_read {
        query = query.bind(is_read);
    }
    if let Some(is_archived) = body.is_archived {
        query = query.bind(is_archived);
    }
    if let Some(ref action_taken) = body.action_taken {
        query = query.bind(action_taken);
    }

    let result = query.execute(&state.db).await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("message not found".into()));
    }

    log_inbox_audit(
        &state.db,
        &auth,
        &body.id,
        build_inbox_audit_metadata(&body),
    )
    .await;

    Ok(Json(serde_json::json!({ "success": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_list_inbox_sql_scopes_non_system_tenants() {
        let params = InboxQuery {
            classification: Some("sales".into()),
            archived: Some(false),
            limit: 50,
            offset: 0,
        };

        let sql = build_list_inbox_sql(&params, true);

        assert!(sql.contains("WHERE tenant_id = $1 AND classification = $2 AND is_archived = $3"));
        assert!(sql.contains("LIMIT $4 OFFSET $5"));
    }

    #[test]
    fn build_list_inbox_sql_allows_system_admins() {
        let params = InboxQuery {
            classification: Some("sales".into()),
            archived: None,
            limit: 50,
            offset: 0,
        };

        let sql = build_list_inbox_sql(&params, false);

        assert!(!sql.contains("tenant_id = $1"));
        assert!(sql.contains("WHERE classification = $1"));
        assert!(sql.contains("LIMIT $2 OFFSET $3"));
    }

    #[test]
    fn build_inbox_audit_metadata_only_contains_mutated_fields() {
        let metadata = build_inbox_audit_metadata(&UpdateInboxMessage {
            id: "msg_123".into(),
            is_read: Some(true),
            is_archived: None,
            action_taken: Some("triaged".into()),
        });

        assert_eq!(metadata["isRead"], true);
        assert!(metadata["isArchived"].is_null());
        assert_eq!(metadata["actionTaken"], "triaged");
    }

    #[test]
    fn build_update_inbox_sql_scopes_non_system_tenants() {
        let body = UpdateInboxMessage {
            id: "msg_123".into(),
            is_read: Some(true),
            is_archived: None,
            action_taken: Some("triaged".into()),
        };

        let sql = build_update_inbox_sql(&body, true).expect("sql should build");

        assert!(sql.contains("WHERE id = $1 AND tenant_id = $2"));
        assert!(sql.contains("is_read = $3"));
        assert!(sql.contains("action_taken = $4"));
    }
}

#[cfg(test)]
mod adversarial_tests {
    use axum::http::StatusCode;

    use crate::app::test_support::adv::AdvEnv;

    async fn seed_inbox_message(
        pool: &sqlx::PgPool,
        tenant: Option<&str>,
        classification: &str,
        subject: &str,
        read: bool,
        archived: bool,
    ) -> uuid::Uuid {
        seed_inbox_message_aged(pool, tenant, classification, subject, read, archived, 0).await
    }

    async fn seed_inbox_message_aged(
        pool: &sqlx::PgPool,
        tenant: Option<&str>,
        classification: &str,
        subject: &str,
        read: bool,
        archived: bool,
        minutes_ago: i32,
    ) -> uuid::Uuid {
        let id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO autopilot_inbox_messages
                (id, tenant_id, classification, subject, from_address, to_address,
                 summary, is_read, is_archived, action_taken, created_at)
             VALUES ($1, $2, $3, $4, 'ops@example.com', 'cp@example.com',
                     'inbox probe', $5, $6, NULL,
                     NOW() - ($7 || ' minutes')::interval)",
        )
        .bind(id)
        .bind(tenant)
        .bind(classification)
        .bind(subject)
        .bind(read)
        .bind(archived)
        .bind(minutes_ago.to_string())
        .execute(pool)
        .await
        .expect("seed inbox message");
        id
    }

    #[tokio::test]
    async fn inbox_lists_and_filters_for_the_system_operator() {
        let Some(pool) = crate::test_db::canonical_pool("inbox_admin_list").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;
        let customer_tenant = format!("inbx{}", &uuid::Uuid::new_v4().simple().to_string()[..18]);
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status) VALUES ($1, 'inbox customer', $2, 'free', 'active')",
        )
        .bind(&customer_tenant)
        .bind(format!("slug-{customer_tenant}"))
        .execute(&pool)
        .await
        .expect("seed customer tenant");

        // System-tenant row (operator view), customer rows, and filters.
        // Explicit ages make the DESC ordering deterministic.
        let sys_id = seed_inbox_message_aged(
            &pool,
            Some("system"),
            "security",
            "sys alert",
            false,
            false,
            0,
        )
        .await;
        seed_inbox_message_aged(
            &pool,
            Some(&customer_tenant),
            "sales",
            "customer lead",
            true,
            false,
            5,
        )
        .await;
        seed_inbox_message_aged(
            &pool,
            Some(&customer_tenant),
            "billing",
            "archived invoice",
            false,
            true,
            10,
        )
        .await;

        let (status, body) = env.get("/v1/admin/inbox").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let items = body.as_array().expect("array");
        // System caller sees everything (unscoped).
        assert_eq!(items.len(), 3);
        assert_eq!(items[0]["id"], sys_id.to_string());
        assert_eq!(items[0]["classification"], "security");
        assert_eq!(items[0]["isRead"], false);
        assert_eq!(items[0]["summary"], "inbox probe");

        // classification + archived filters compose.
        let (status, body) = env
            .get("/v1/admin/inbox?classification=sales&archived=false")
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let items = body.as_array().expect("array");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["subject"], "customer lead");

        let (status, body) = env.get("/v1/admin/inbox?archived=true").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let items = body.as_array().expect("array");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["subject"], "archived invoice");

        // Pagination clamps: zero limit floors to one row; negative offset to 0.
        let (status, body) = env.get("/v1/admin/inbox?limit=0").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body.as_array().map(Vec::len), Some(1));
        let (status, body) = env.get("/v1/admin/inbox?limit=200&offset=-5").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body.as_array().map(Vec::len), Some(3));
    }

    #[tokio::test]
    async fn inbox_customer_sessions_are_scoped_to_their_tenant() {
        // A customer SESSION (non-system tenant) with wildcard scope lists
        // ONLY its own tenant's messages — the slug-aware scoping arm.
        let Some(pool) = crate::test_db::canonical_pool("inbox_tenant_scope").await else {
            return;
        };
        let Some((env, tenant, _user)) = AdvEnv::session(pool.clone(), "owner").await else {
            return;
        };
        seed_inbox_message(
            &pool,
            Some(&tenant),
            "security",
            "own tenant alert",
            false,
            false,
        )
        .await;
        seed_inbox_message(
            &pool,
            Some("system"),
            "security",
            "foreign sys alert",
            false,
            false,
        )
        .await;

        let (status, body) = env.get("/v1/admin/inbox").await;
        // The admin router's system-tenant gate rejects the customer first.
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }

    #[tokio::test]
    async fn inbox_update_mutates_only_the_named_fields_and_audits() {
        let Some(pool) = crate::test_db::canonical_pool("inbox_update").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;
        let id =
            seed_inbox_message(&pool, Some("system"), "sales", "to triage", false, false).await;

        let (status, body) = env
            .patch(
                "/v1/admin/inbox",
                &serde_json::json!({ "id": id.to_string(), "isRead": true, "actionTaken": "triaged" })
                    .to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["success"], true);

        let (is_read, action_taken, archived): (bool, Option<String>, bool) = sqlx::query_as(
            "SELECT is_read, action_taken, is_archived FROM autopilot_inbox_messages WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("row");
        assert!(is_read);
        assert_eq!(action_taken.as_deref(), Some("triaged"));
        assert!(!archived, "untouched field must not change");

        let (action, resource): (String, Option<String>) = sqlx::query_as(
            "SELECT action, resource_id FROM audit_logs WHERE action = 'control_plane.inbox.updated' AND resource_id = $1",
        )
        .bind(id.to_string())
        .fetch_one(&pool)
        .await
        .expect("audit row");
        assert_eq!(action, "control_plane.inbox.updated");
        assert_eq!(resource.as_deref(), Some(id.to_string().as_str()));

        // Archiving alone works; combined flags map to the right binds.
        let (status, body) = env
            .patch(
                "/v1/admin/inbox",
                &serde_json::json!({ "id": id.to_string(), "isArchived": true }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let archived: bool =
            sqlx::query_scalar("SELECT is_archived FROM autopilot_inbox_messages WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("archived");
        assert!(archived);
    }

    #[tokio::test]
    async fn inbox_update_refuses_empty_and_unknown_and_missing_bodies() {
        let Some(pool) = crate::test_db::canonical_pool("inbox_update_refusals").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;
        let id = seed_inbox_message(&pool, Some("system"), "sales", "refusals", false, false).await;

        // No fields to update.
        let (status, body) = env
            .patch(
                "/v1/admin/inbox",
                &serde_json::json!({ "id": id.to_string() }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        // Unknown id is a 404, indistinguishable per-row.
        let (status, body) = env
            .patch(
                "/v1/admin/inbox",
                &serde_json::json!({ "id": uuid::Uuid::new_v4().to_string(), "isRead": true })
                    .to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

        // Malformed (non-UUID) ids are rejected as validation errors before
        // the database sees them (previously a 500 from the uuid/text bind).
        let (status, body) = env
            .patch(
                "/v1/admin/inbox",
                &serde_json::json!({ "id": "not-a-uuid", "isRead": true }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        // deny_unknown_fields.
        let (status, _body) = env
            .patch(
                "/v1/admin/inbox",
                &serde_json::json!({ "id": id.to_string(), "isRead": true, "surprise": 1 })
                    .to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn inbox_requires_the_wildcard_scope() {
        let Some(pool) = crate::test_db::canonical_pool("inbox_scope").await else {
            return;
        };
        let key =
            crate::app::test_support::seed_api_key_for(&pool, "system", &["inbox:read"]).await;
        let env = AdvEnv::over(pool, key).await;
        let (status, body) = env.get("/v1/admin/inbox").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }
}
