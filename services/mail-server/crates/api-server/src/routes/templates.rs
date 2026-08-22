//! Email template CRUD routes.

use super::helpers::{clamp_limit, default_limit, html_escape};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(create_template).get(list_templates))
        .route(
            "/:id",
            get(get_template)
                .put(update_template)
                .delete(delete_template),
        )
        .route("/:id/render", post(render_template))
        .route("/:id/duplicate", post(duplicate_template))
        .route("/:id/rollback", post(rollback_template))
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTemplateRequest {
    pub name: String,
    pub subject: String,
    pub html_body: String,
    #[serde(default)]
    pub text_body: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateTemplateRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub html_body: Option<String>,
    #[serde(default)]
    pub text_body: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TemplateResponse {
    pub id: String,
    pub name: String,
    pub subject: String,
    pub html_body: String,
    pub text_body: Option<String>,
    pub version: i32,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenderRequest {
    pub variables: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct RenderResponse {
    pub subject: String,
    pub html: String,
    pub text: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListTemplatesQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub cursor: Option<i64>,
}

// ─── Handlers ──────────────────────────────────────────────────

async fn create_template(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateTemplateRequest>,
) -> Result<(StatusCode, Json<TemplateResponse>), ApiError> {
    require_scopes(&auth, &["templates:write"])?;

    if body.name.is_empty() || body.subject.is_empty() || body.html_body.is_empty() {
        return Err(ApiError::Validation(vec![
            "name, subject, and html_body are required".into(),
        ]));
    }

    // templates.id is VARCHAR(26) — generate a 26-char text id (not a UUID,
    // whose 36-char hyphenated form overflows the column).
    let id = apexmail_lib::id::generate_id("", 26);
    let now = Utc::now();

    // L-1: the templates row and its v1 snapshot land in one transaction so
    // a template can never exist without rollback history.
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO templates (id, tenant_id, name, subject, html_body, text_body, version, status, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,1,'active',$7,$7)",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .bind(&body.name)
    .bind(&body.subject)
    .bind(&body.html_body)
    .bind(&body.text_body)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    snapshot_template_version(
        &mut tx,
        &id,
        &auth.tenant_id,
        1,
        &body.name,
        &body.subject,
        &body.html_body,
        body.text_body.as_deref(),
    )
    .await?;
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(TemplateResponse {
            id,
            name: body.name,
            subject: body.subject,
            html_body: body.html_body,
            text_body: body.text_body,
            version: 1,
            status: "active".into(),
            created_at: now.to_rfc3339(),
            updated_at: now.to_rfc3339(),
        }),
    ))
}

async fn list_templates(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ListTemplatesQuery>,
) -> Result<Json<Vec<TemplateResponse>>, ApiError> {
    require_scopes(&auth, &["templates:read"])?;

    let offset = params.cursor.unwrap_or(params.offset).clamp(0, 100_000);
    let rows = sqlx::query_as::<_, TemplateRow>(
        "SELECT id, name, subject, html_body, text_body, version, status, created_at, updated_at
         FROM templates WHERE tenant_id = $1 ORDER BY updated_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(&auth.tenant_id)
    .bind(clamp_limit(params.limit, 200))
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn get_template(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<TemplateResponse>, ApiError> {
    require_scopes(&auth, &["templates:read"])?;
    let row = fetch_template(&state, &auth.tenant_id, id).await?;
    Ok(Json(row.into()))
}

async fn update_template(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<UpdateTemplateRequest>,
) -> Result<Json<TemplateResponse>, ApiError> {
    require_scopes(&auth, &["templates:write"])?;

    let existing = fetch_template(&state, &auth.tenant_id, id.clone()).await?;

    let name = body.name.unwrap_or(existing.name);
    let subject = body.subject.unwrap_or(existing.subject);
    let html_body = body.html_body.unwrap_or(existing.html_body);
    let text_body = body.text_body.or(existing.text_body);
    let new_version = existing.version + 1;

    // L-1: snapshot every saved state atomically with the templates write,
    // so POST /:id/rollback always has the history it restores from.
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "UPDATE templates SET name=$1, subject=$2, html_body=$3, text_body=$4, version=$5, updated_at=NOW()
         WHERE id=$6 AND tenant_id=$7",
    )
    .bind(&name)
    .bind(&subject)
    .bind(&html_body)
    .bind(&text_body)
    .bind(new_version)
    .bind(&id)
    .bind(&auth.tenant_id)
    .execute(&mut *tx)
    .await?;
    snapshot_template_version(
        &mut tx,
        &id,
        &auth.tenant_id,
        new_version,
        &name,
        &subject,
        &html_body,
        text_body.as_deref(),
    )
    .await?;
    tx.commit().await?;

    Ok(Json(TemplateResponse {
        id,
        name,
        subject,
        html_body,
        text_body,
        version: new_version,
        status: existing.status,
        created_at: existing.created_at.to_rfc3339(),
        updated_at: Utc::now().to_rfc3339(),
    }))
}

async fn delete_template(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["templates:write"])?;

    let result = sqlx::query("DELETE FROM templates WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(&auth.tenant_id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("template not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn render_template(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<RenderRequest>,
) -> Result<Json<RenderResponse>, ApiError> {
    require_scopes(&auth, &["templates:read"])?;

    let tpl = fetch_template(&state, &auth.tenant_id, id).await?;

    // Simple Handlebars-style variable substitution:{{var_name}}
    let vars = body
        .variables
        .as_object()
        .unwrap_or(&serde_json::Map::new())
        .clone();
    let html = substitute(&tpl.html_body, &vars);
    let subject = substitute(&tpl.subject, &vars);
    let text = tpl.text_body.as_ref().map(|t| substitute(t, &vars));

    Ok(Json(RenderResponse {
        subject,
        html,
        text,
    }))
}

fn substitute(template: &str, vars: &serde_json::Map<String, serde_json::Value>) -> String {
    use std::borrow::Cow;

    // Build a lookup map for O(1) variable access
    let lookup: std::collections::HashMap<&str, Cow<str>> = vars
        .iter()
        .map(|(k, v)| {
            let escaped = match v {
                serde_json::Value::String(s) => Cow::Owned(html_escape(s)),
                other => Cow::Owned(html_escape(&other.to_string())),
            };
            (k.as_str(), escaped)
        })
        .collect();

    // Single pass through template
    let mut result = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '{' && chars.peek() == Some(&'{') {
            chars.next(); // consume second '{'
                          // Read variable name until '}}'
            let mut var_name = String::new();
            while let Some(&ch) = chars.peek() {
                if ch == '}' {
                    chars.next();
                    if chars.peek() == Some(&'}') {
                        chars.next();
                        break;
                    } else {
                        var_name.push('}');
                    }
                } else if let Some(next_ch) = chars.next() {
                    var_name.push(next_ch);
                } else {
                    break;
                }
            }
            // Look up and substitute
            if let Some(replacement) = lookup.get(var_name.as_str()) {
                result.push_str(replacement);
            } else {
                // Keep original placeholder if variable not found
                result.push_str("{{");
                result.push_str(&var_name);
                result.push_str("}}");
            }
        } else {
            result.push(c);
        }
    }

    result
}

// ─── Row types ─────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct TemplateRow {
    id: String,
    name: String,
    subject: String,
    html_body: String,
    text_body: Option<String>,
    version: i32,
    status: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<TemplateRow> for TemplateResponse {
    fn from(r: TemplateRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            subject: r.subject,
            html_body: r.html_body,
            text_body: r.text_body,
            version: r.version,
            status: r.status,
            created_at: r.created_at.to_rfc3339(),
            updated_at: r.updated_at.to_rfc3339(),
        }
    }
}

async fn fetch_template(
    state: &AppState,
    tenant_id: &str,
    id: String,
) -> Result<TemplateRow, ApiError> {
    sqlx::query_as::<_, TemplateRow>(
        "SELECT id, name, subject, html_body, text_body, version, status, created_at, updated_at
         FROM templates WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("template not found".into()))
}

/// L-1: persist a rollback snapshot for one saved template state. The upsert
/// keeps history linear: after rolling back to v1, the next save rewrites
/// the v2 snapshot instead of colliding with the stale one.
/// `pub(crate)` so the SSR template editor snapshots versions through the
/// exact same writer the JSON update path uses.
pub(crate) async fn snapshot_template_version(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    template_id: &str,
    tenant_id: &str,
    version: i32,
    name: &str,
    subject: &str,
    html_body: &str,
    text_body: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO template_versions
            (template_id, tenant_id, version, name, subject, html_body, text_body)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (template_id, version) DO UPDATE SET
            tenant_id  = EXCLUDED.tenant_id,
            name       = EXCLUDED.name,
            subject    = EXCLUDED.subject,
            html_body  = EXCLUDED.html_body,
            text_body  = EXCLUDED.text_body,
            created_at = NOW()",
    )
    .bind(template_id)
    .bind(tenant_id)
    .bind(version)
    .bind(name)
    .bind(subject)
    .bind(html_body)
    .bind(text_body)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

// ─── Duplicate / Rollback Handlers ─────────────────────────────

async fn duplicate_template(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<TemplateResponse>), ApiError> {
    require_scopes(&auth, &["templates:write"])?;

    // Fetch original
    let original = fetch_template(&state, &auth.tenant_id, id.clone()).await?;

    let new_id = apexmail_lib::id::generate_id("", 26);
    let now = chrono::Utc::now();
    let new_name = format!("{} (copy)", original.name);

    sqlx::query(
        "INSERT INTO templates (id, tenant_id, name, subject, html_body, text_body, version, status, created_at, updated_at)
         SELECT $1, tenant_id, $3, subject, html_body, text_body, 1, 'draft', $4, $4
         FROM templates WHERE id = $2 AND tenant_id = $5",
    )
    .bind(&new_id)
    .bind(id)
    .bind(new_name)
    .bind(now)
    .bind(auth.tenant_id.to_string())
    .execute(&state.db)
    .await?;

    let row = fetch_template(&state, &auth.tenant_id, new_id).await?;
    Ok((StatusCode::CREATED, Json(row.into())))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackRequest {
    pub version: i32,
}

async fn rollback_template(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<RollbackRequest>,
) -> Result<Json<TemplateResponse>, ApiError> {
    require_scopes(&auth, &["templates:write"])?;

    // Restore from template_versions (snapshots are written on every save —
    // see snapshot_template_version; L-1).
    let restored = restore_template_version(&state.db, &auth.tenant_id, &id, body.version).await?;
    if !restored {
        return Err(ApiError::NotFound("template or version not found".into()));
    }

    let row = fetch_template(&state, &auth.tenant_id, id).await?;
    Ok(Json(row.into()))
}

/// Restore a template's content from its version snapshot. Returns `false`
/// when the template or the requested version does not exist.
async fn restore_template_version(
    db: &sqlx::PgPool,
    tenant_id: &str,
    template_id: &str,
    version: i32,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE templates SET
            html_body = tv.html_body,
            text_body = tv.text_body,
            subject = tv.subject,
            name = tv.name,
            version = tv.version,
            updated_at = NOW()
         FROM template_versions tv
         WHERE templates.id = $1 AND templates.tenant_id = $2
           AND tv.template_id = $1 AND tv.tenant_id = $2 AND tv.version = $3",
    )
    .bind(template_id)
    .bind(tenant_id)
    .bind(version)
    .execute(db)
    .await?;

    Ok(result.rows_affected() > 0)
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_substitute_simple() {
        let mut vars = serde_json::Map::new();
        vars.insert("name".into(), serde_json::Value::String("Alice".into()));
        let result = substitute("Hello {{name}}!", &vars);
        assert_eq!(result, "Hello Alice!");
    }

    #[test]
    fn test_substitute_multiple() {
        let mut vars = serde_json::Map::new();
        vars.insert("first".into(), serde_json::json!("A"));
        vars.insert("last".into(), serde_json::json!("B"));
        let result = substitute("{{first}} {{last}}", &vars);
        assert_eq!(result, "A B");
    }

    #[test]
    fn test_template_response_serialisation() {
        let resp = TemplateResponse {
            id: String::new(),
            name: "welcome".into(),
            subject: "Welcome!".into(),
            html_body: "<p>Hi</p>".into(),
            text_body: None,
            version: 1,
            status: "active".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["version"], 1);
    }

    // ── L-1: version snapshots + rollback (skipped without TEST_DATABASE_URL) ──

    /// Minimal schema for the template versioning flow in a dedicated
    /// per-test database (same convention as `self_hosted_bounces.rs`).
    async fn template_test_pool(db_suffix: &str) -> Option<sqlx::PgPool> {
        use sqlx::postgres::PgPoolOptions;
        use std::time::Duration;

        let database_url = std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())?;
        let (server_part, db_part) = database_url.rsplit_once('/')?;
        let db_only = db_part.split('?').next().unwrap_or(db_part);
        let isolated_db = format!("{db_only}_api_templates_{db_suffix}");
        let isolated_url = format!("{server_part}/{isolated_db}");
        let admin_url = format!("{server_part}/postgres");

        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(3))
            .connect(&admin_url)
            .await
            .ok()?;
        let _ = sqlx::query(&format!(
            r#"DROP DATABASE IF EXISTS "{isolated_db}" WITH (FORCE)"#
        ))
        .execute(&admin)
        .await;
        let created = sqlx::query(&format!(r#"CREATE DATABASE "{isolated_db}""#))
            .execute(&admin)
            .await;
        admin.close().await;
        created.ok()?;

        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&isolated_url)
            .await
            .ok()?;
        sqlx::query(
            r#"
            CREATE TABLE templates (
                id          VARCHAR(26) PRIMARY KEY,
                tenant_id   VARCHAR(26) NOT NULL,
                name        VARCHAR(255) NOT NULL,
                slug        VARCHAR(100),
                subject     VARCHAR(255) NOT NULL,
                html_body   TEXT NOT NULL,
                text_body   TEXT,
                version     INTEGER NOT NULL DEFAULT 1,
                status      VARCHAR(20) NOT NULL DEFAULT 'active',
                created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE TABLE template_versions (
                template_id VARCHAR(26)  NOT NULL,
                tenant_id   VARCHAR(26)  NOT NULL,
                version     INTEGER      NOT NULL,
                name        VARCHAR(255) NOT NULL,
                subject     VARCHAR(255) NOT NULL,
                html_body   TEXT         NOT NULL,
                text_body   TEXT,
                created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
                PRIMARY KEY (template_id, version)
            );
            "#,
        )
        .execute(&pool)
        .await
        .ok()?;
        Some(pool)
    }

    /// The create-template DB path: templates row + v1 snapshot atomically.
    async fn insert_template_v1(
        pool: &sqlx::PgPool,
        tenant_id: &str,
        id: &str,
        subject: &str,
        html_body: &str,
    ) -> bool {
        let mut tx = match pool.begin().await {
            Ok(tx) => tx,
            Err(_) => return false,
        };
        if sqlx::query(
            "INSERT INTO templates (id, tenant_id, name, subject, html_body, version, status)
             VALUES ($1, $2, 'welcome', $3, $4, 1, 'active')",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(subject)
        .bind(html_body)
        .execute(&mut *tx)
        .await
        .is_err()
        {
            return false;
        }
        snapshot_template_version(
            &mut tx, id, tenant_id, 1, "welcome", subject, html_body, None,
        )
        .await
        .is_ok()
            && tx.commit().await.is_ok()
    }

    #[tokio::test]
    async fn save_twice_then_rollback_to_v1_returns_v1_content() {
        let Some(pool) = template_test_pool("rollback").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };

        let tenant = "ten_tpl_rollback_001";
        let id = apexmail_lib::id::generate_id("", 26);

        // Save #1 — create (v1 content).
        assert!(insert_template_v1(&pool, tenant, &id, "Welcome v1", "<p>v1</p>").await);

        // Save #2 — update to v2 (mirrors update_template's DB path).
        let mut tx = pool.begin().await.unwrap();
        sqlx::query(
            "UPDATE templates SET subject=$1, html_body=$2, version=2, updated_at=NOW()
             WHERE id=$3 AND tenant_id=$4",
        )
        .bind("Welcome v2")
        .bind("<p>v2</p>")
        .bind(&id)
        .bind(tenant)
        .execute(&mut *tx)
        .await
        .unwrap();
        snapshot_template_version(
            &mut tx,
            &id,
            tenant,
            2,
            "welcome",
            "Welcome v2",
            "<p>v2</p>",
            None,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let (subject, html, version): (String, String, i32) = sqlx::query_as(
            "SELECT subject, html_body, version FROM templates WHERE id = $1 AND tenant_id = $2",
        )
        .bind(&id)
        .bind(tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            (subject.as_str(), html.as_str(), version),
            ("Welcome v2", "<p>v2</p>", 2)
        );

        // Rollback to v1 — must restore the v1 snapshot.
        assert!(
            restore_template_version(&pool, tenant, &id, 1)
                .await
                .unwrap(),
            "rollback must find the v1 snapshot"
        );
        let (subject, html, version): (String, String, i32) = sqlx::query_as(
            "SELECT subject, html_body, version FROM templates WHERE id = $1 AND tenant_id = $2",
        )
        .bind(&id)
        .bind(tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(subject, "Welcome v1");
        assert_eq!(html, "<p>v1</p>");
        assert_eq!(version, 1);

        // Unknown versions report not-found instead of silently succeeding.
        assert!(!restore_template_version(&pool, tenant, &id, 99)
            .await
            .unwrap());

        pool.close().await;
    }
}
