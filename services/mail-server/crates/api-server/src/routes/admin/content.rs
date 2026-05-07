//! Content management endpoints.
//!

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::routes::helpers::column_exists;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(list_content))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContentQuery {
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default, alias = "type")]
    pub content_type: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

fn normalize_filter(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn build_list_content_sql(
    has_author: bool,
    has_content_type: bool,
    type_col: &str,
    view_col: &str,
) -> String {
    let mut conditions = Vec::new();
    let mut idx = 1u32;

    if has_author {
        conditions.push(format!("author = ${idx}"));
        idx += 1;
    }
    if has_content_type {
        conditions.push(format!("{type_col} = ${idx}"));
        idx += 1;
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    format!(
        "SELECT id, title, slug, {type_col}, status,
                author, tags, COALESCE({view_col}, 0),
                published_at, created_at, updated_at
         FROM content_items
         {where_clause}
         ORDER BY COALESCE(published_at, created_at) DESC
         LIMIT ${idx} OFFSET ${}",
        idx + 1
    )
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
    let author = normalize_filter(params.author.as_deref());
    let content_type = normalize_filter(params.content_type.as_deref());
    let type_col = if column_exists(&state.db, "content_items", "content_type").await {
        "content_type"
    } else {
        "type"
    };
    let view_col = if column_exists(&state.db, "content_items", "view_count").await {
        "view_count"
    } else {
        "views"
    };
    let sql = build_list_content_sql(author.is_some(), content_type.is_some(), type_col, view_col);

    let rows: Vec<(
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<Vec<String>>,
        i64,
        Option<chrono::DateTime<chrono::Utc>>,
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
    )> = {
        let mut query = sqlx::query_as(&sql);
        if let Some(author) = author.as_deref() {
            query = query.bind(author);
        }
        if let Some(content_type) = content_type.as_deref() {
            query = query.bind(content_type);
        }
        query.bind(limit).bind(offset).fetch_all(&state.db).await
    }?;

    let items: Vec<ContentItem> = rows
        .into_iter()
        .map(
            |(
                id,
                title,
                slug,
                content_type,
                status,
                author,
                tags,
                view_count,
                published_at,
                created_at,
                updated_at,
            )| {
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
            },
        )
        .collect();

    Ok(Json(items))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_list_content_sql_filters_by_author_and_type() {
        let sql = build_list_content_sql(true, true, "content_type", "view_count");

        assert!(sql.contains("WHERE author = $1 AND content_type = $2"));
        assert!(sql.contains("LIMIT $3 OFFSET $4"));
    }

    #[test]
    fn normalize_filter_discards_blank_values() {
        assert_eq!(normalize_filter(Some("   ")), None);
        assert_eq!(normalize_filter(Some(" blog ")), Some("blog".into()));
    }
}
