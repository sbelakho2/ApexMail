//! Inbox / autopilot message management endpoints.
//!
//! Migrated from: apps/control-plane/src/app/api/inbox/route.ts

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(list_inbox).patch(update_message))
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

    let mut conditions: Vec<String> = Vec::new();
    let mut bind_values: Vec<String> = Vec::new();
    let mut archived_val: Option<bool> = None;
    let mut idx = 1u32;

    if let Some(ref classification) = params.classification {
        conditions.push(format!("classification = ${idx}"));
        idx += 1;
        bind_values.push(classification.clone());
    }
    if let Some(archived) = params.archived {
        conditions.push(format!("is_archived = ${idx}"));
        idx += 1;
        archived_val = Some(archived);
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let sql = format!(
        "SELECT id, classification, subject, from_address, to_address,
                summary, is_read, is_archived, action_taken, created_at
         FROM autopilot_inbox_messages
         {where_clause}
         ORDER BY created_at DESC
         LIMIT ${idx} OFFSET ${}",
        idx + 1
    );

    let mut query = sqlx::query_as::<_, (
        String, String, String, String, String,
        Option<String>, bool, bool, Option<String>, chrono::DateTime<chrono::Utc>,
    )>(&sql);

    for val in &bind_values {
        query = query.bind(val);
    }
    if let Some(archived) = archived_val {
        query = query.bind(archived);
    }
    query = query.bind(limit).bind(offset);

    let rows = query.fetch_all(&state.db).await?;

    let messages: Vec<InboxMessage> = rows
        .into_iter()
        .map(|(id, classification, subject, from_addr, to_addr, summary, is_read, is_archived, action_taken, created_at)| {
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
        })
        .collect();

    Ok(Json(messages))
}

#[derive(Debug, Deserialize)]
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

async fn update_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<UpdateInboxMessage>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let mut sets: Vec<String> = Vec::new();
    let mut idx = 2u32; // $1 is id

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

    let sql = format!(
        "UPDATE autopilot_inbox_messages SET {} WHERE id = $1",
        sets.join(", ")
    );

    let mut query = sqlx::query(&sql).bind(&body.id);

    if let Some(is_read) = body.is_read {
        query = query.bind(is_read);
    }
    if let Some(is_archived) = body.is_archived {
        query = query.bind(is_archived);
    }
    if let Some(ref action_taken) = body.action_taken {
        query = query.bind(action_taken);
    }

    query.execute(&state.db).await?;

    Ok(Json(serde_json::json!({ "success": true })))
}
