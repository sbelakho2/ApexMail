//! Content management endpoints.
//!
//! Migrated from: apps/control-plane/src/app/api/content/route.ts

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(list_content))
}

#[derive(Debug, Deserialize)]
pub struct ContentQuery {
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
pub struct ContentItem {
    pub id: String,
    pub title: String,
    pub slug: String,
    pub content_type: String,
    pub status: String,
    pub author: Option<String>,
    pub tags: Vec<String>,
    pub view_count: i64,
    pub published_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

async fn list_content(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ContentQuery>,
) -> Result<Json<Vec<ContentItem>>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);

    let rows: Vec<(
        String, String, String, String, String,
        Option<String>, Option<Vec<String>>, i64,
        Option<chrono::DateTime<chrono::Utc>>,
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
    )> = sqlx::query_as(
        "SELECT id, title, slug, content_type, status,
                author, tags, COALESCE(view_count, 0),
                published_at, created_at, updated_at
         FROM content_items
         ORDER BY COALESCE(published_at, created_at) DESC
         LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let items: Vec<ContentItem> = rows
        .into_iter()
        .map(|(id, title, slug, content_type, status, author, tags, view_count, published_at, created_at, updated_at)| {
            ContentItem {
                id,
                title,
                slug,
                content_type,
                status,
                author,
                tags: tags.unwrap_or_default(),
                view_count,
                published_at: published_at.map(|t| t.to_rfc3339()),
                created_at: created_at.to_rfc3339(),
                updated_at: updated_at.to_rfc3339(),
            }
        })
        .collect();

    Ok(Json(items))
}
