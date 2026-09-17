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
    slug_expr: &str,
    status_expr: &str,
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
        "SELECT id::text AS id, title, {slug_expr}, {type_col}, {status_expr},
                author, tags, COALESCE({view_col}, 0) AS view_count,
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
    /// Absent (null) on schemas whose content_items carries no slug column
    /// (the canonical table does not).
    pub slug: Option<String>,
    pub content_type: String,
    /// Absent (null) on schemas without a status column.
    pub status: Option<String>,
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
    // `slug` and `status` are NOT part of the canonical content_items table:
    // probe them so the route answers (with null fields) instead of 500-ing
    // with an undefined-column error on every canonical deployment.
    // The fallback expressions are ALIASED: sqlx maps row columns by name,
    // and a bare NULL would surface as Postgres' anonymous "?column?".
    let slug_expr = if column_exists(&state.db, "content_items", "slug").await {
        "slug"
    } else {
        "NULL AS slug"
    };
    let status_expr = if column_exists(&state.db, "content_items", "status").await {
        "status"
    } else {
        "NULL AS status"
    };
    let sql = build_list_content_sql(
        author.is_some(),
        content_type.is_some(),
        type_col,
        view_col,
        slug_expr,
        status_expr,
    );

    let rows: Vec<(
        String,
        String,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
        Option<sqlx::types::Json<Vec<String>>>,
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
                    tags: tags
                        .map(|sqlx::types::Json(value)| value)
                        .unwrap_or_default(),
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
        let sql =
            build_list_content_sql(true, true, "content_type", "view_count", "slug", "status");

        assert!(sql.contains("WHERE author = $1 AND content_type = $2"));
        assert!(sql.contains("LIMIT $3 OFFSET $4"));
        assert!(sql.contains("SELECT id::text AS id, title, slug, content_type, status"));
        // Canonical schema probes degrade to NULL, never to an error.
        let canonical = build_list_content_sql(
            false,
            false,
            "content_type",
            "view_count",
            "NULL AS slug",
            "NULL AS status",
        );
        assert!(canonical
            .contains("SELECT id::text AS id, title, NULL AS slug, content_type, NULL AS status"));
    }

    #[test]
    fn normalize_filter_discards_blank_values() {
        assert_eq!(normalize_filter(Some("   ")), None);
        assert_eq!(normalize_filter(Some(" blog ")), Some("blog".into()));
    }

    mod adversarial_tests {
        use axum::http::StatusCode;

        use crate::app::test_support::adv::AdvEnv;

        async fn seed_content(
            pool: &sqlx::PgPool,
            title: &str,
            content_type: &str,
            status: &str,
            author: Option<&str>,
            published_days_ago: i64,
        ) {
            let _ = status;
            sqlx::query(
                "INSERT INTO content_items (id, title, content_type, author, tags, view_count, published_at)
                 VALUES ($1, $2, $3, $4, '[\"probe\",\"apex\"]'::jsonb, 7,
                         NOW() - ($5 || ' days')::interval)",
            )
            .bind(uuid::Uuid::new_v4())
            .bind(title)
            .bind(content_type)
            .bind(author)
            .bind(published_days_ago.to_string())
            .execute(pool)
            .await
            .expect("seed content item");
        }

        #[tokio::test]
        async fn content_lists_rows_with_filters_and_pagination() {
            let Some(pool) = crate::test_db::canonical_pool("content_list").await else {
                return;
            };
            let env = AdvEnv::admin(pool.clone()).await;
            seed_content(&pool, "First post", "blog", "published", Some("alice"), 3).await;
            seed_content(&pool, "Docs page", "docs", "published", Some("bob"), 2).await;
            seed_content(&pool, "Draft thing", "blog", "draft", None, 1).await;

            // Unfiltered: ordered by most recent publish date first.
            let (status, body) = env.get("/v1/admin/content").await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let items = body.as_array().expect("array");
            assert_eq!(items.len(), 3);
            assert_eq!(items[0]["title"], "Draft thing");
            assert_eq!(items[0]["contentType"], "blog");
            // Canonical content_items carries no slug/status columns: the
            // route must answer with null fields, not a 500 (the bug this
            // wave's failing test exposed).
            assert_eq!(items[0]["slug"], serde_json::Value::Null);
            assert_eq!(items[0]["status"], serde_json::Value::Null);
            assert_eq!(items[0]["tags"], serde_json::json!(["probe", "apex"]));
            assert_eq!(items[0]["viewCount"], 7);
            assert_eq!(items[0]["author"], serde_json::Value::Null);

            // author filter (exact match).
            let (status, body) = env.get("/v1/admin/content?author=alice").await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let items = body.as_array().expect("array");
            assert_eq!(items.len(), 1);
            assert_eq!(items[0]["title"], "First post");
            assert_eq!(items[0]["author"], "alice");

            // type filter — via the camelCase name and the `type` alias.
            for uri in [
                "/v1/admin/content?contentType=docs",
                "/v1/admin/content?type=docs",
            ] {
                let (status, body) = env.get(uri).await;
                assert_eq!(status, StatusCode::OK, "{uri}: {body}");
                let items = body.as_array().expect("array");
                assert_eq!(items.len(), 1, "{uri}");
                assert_eq!(items[0]["title"], "Docs page", "{uri}");
            }

            // Combined filters.
            let (status, body) = env
                .get("/v1/admin/content?author=alice&contentType=blog")
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body.as_array().map(Vec::len), Some(1));

            // Blank filters are normalized away (never `author = ''`).
            let (status, body) = env.get("/v1/admin/content?author=%20%20&type=").await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body.as_array().map(Vec::len), Some(3));

            // Pagination: limit clamps the page, offset skips.
            let (status, body) = env.get("/v1/admin/content?limit=1").await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body.as_array().map(Vec::len), Some(1));
            let (status, body) = env.get("/v1/admin/content?limit=5&offset=2").await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let items = body.as_array().expect("array");
            assert_eq!(items.len(), 1);
            assert_eq!(items[0]["title"], "First post");

            // Hostile params: negative offset floors to 0; absurd limit
            // clamps to 200 (still a valid page size).
            let (status, body) = env.get("/v1/admin/content?offset=-50&limit=999999").await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body.as_array().map(Vec::len), Some(3));
        }

        #[tokio::test]
        async fn content_rejects_unknown_query_fields() {
            let Some(pool) = crate::test_db::canonical_pool("content_unknown").await else {
                return;
            };
            let env = AdvEnv::admin(pool).await;
            let (status, _body) = env.get("/v1/admin/content?surprise=1").await;
            // axum's Query extractor rejects unknown fields with 400.
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn content_requires_the_wildcard_scope() {
            let Some(pool) = crate::test_db::canonical_pool("content_scope").await else {
                return;
            };
            let key =
                crate::app::test_support::seed_api_key_for(&pool, "system", &["content:read"])
                    .await;
            let env = AdvEnv::over(pool, key).await;
            let (status, body) = env.get("/v1/admin/content").await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        }

        #[tokio::test]
        async fn content_rejects_customer_tenants() {
            let Some(pool) = crate::test_db::canonical_pool("content_tenant").await else {
                return;
            };
            let (env, _tenant) = AdvEnv::tenant(pool, &["*"]).await;
            let (status, body) = env.get("/v1/admin/content").await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        }
    }
}

#[cfg(test)]
mod debug_probe {
    use super::*;

    /// Schema-honesty probe: the exact SQL build_list_content_sql emits must
    /// decode against the CANONICAL content_items shape (UUID ids, no
    /// slug/status columns, view_count present) — the adversarial route test
    /// depends on it and this pins the column mapping at the unit level.
    #[tokio::test]
    async fn probe_list_content_error() {
        let Some(pool) = crate::test_db::canonical_pool("content_probe").await else {
            return;
        };
        sqlx::query(
            "INSERT INTO content_items (id, title, content_type, author) VALUES ($1, 'probe', 'blog', 'alice')",
        )
        .bind(uuid::Uuid::new_v4())
        .execute(&pool)
        .await
        .expect("seed");
        let sql = build_list_content_sql(
            false,
            false,
            "content_type",
            "view_count",
            "NULL AS slug",
            "NULL AS status",
        );
        let rows: Vec<(
            String,
            String,
            Option<String>,
            String,
            Option<String>,
            Option<String>,
            Option<sqlx::types::Json<Vec<String>>>,
            i64,
            Option<chrono::DateTime<chrono::Utc>>,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        )> = sqlx::query_as(&sql)
            .bind(50i64)
            .bind(0i64)
            .fetch_all(&pool)
            .await
            .unwrap_or_else(|error| panic!("probe sqlx error: {error}"));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, "probe");
        assert_eq!(rows[0].3, "blog");
        assert_eq!(rows[0].5.as_deref(), Some("alice"));
    }
}
