//! Email template CRUD routes.

use super::helpers::{clamp_limit, default_limit, html_escape};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use billing_entitlements::FeatureKey;
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

/// Template customization requires the `custom_templates` entitlement
/// (403 Forbidden otherwise). Applied to every mutating template handler so
/// create/update/duplicate/rollback cannot be used to bypass the gate.
async fn require_template_write(state: &AppState, tenant_id: &str) -> Result<(), ApiError> {
    crate::entitlements::require_feature(state, tenant_id, FeatureKey::CustomTemplates)
        .await
        .map(|_| ())
}

async fn create_template(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateTemplateRequest>,
) -> Result<(StatusCode, Json<TemplateResponse>), ApiError> {
    require_scopes(&auth, &["templates:write"])?;

    require_template_write(&state, &auth.tenant_id).await?;

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

    require_template_write(&state, &auth.tenant_id).await?;

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

    require_template_write(&state, &auth.tenant_id).await?;

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

    require_template_write(&state, &auth.tenant_id).await?;

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

// ─── Adversarial template CRUD / substitution tests ────────────

#[cfg(test)]
mod adversarial_tests {
    use super::*;

    fn auth_for(tenant: &str, scopes: &[&str]) -> AuthUser {
        AuthUser {
            tenant_id: tenant.to_string(),
            user_id: None,
            api_key_id: Some("key_adversarial".into()),
            session_id: None,
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
        }
    }

    async fn state_and_pool(name: &str) -> Option<(AppState, sqlx::PgPool)> {
        let pool = crate::test_db::optional_pg_pool(name).await?;
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        Some((state, pool))
    }

    async fn seed_tenant(pool: &sqlx::PgPool, tenant: &str, plan: &str) {
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
             VALUES ($1, 'templates adversarial', $2, 'active', NOW(), NOW())
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant)
        .bind(plan)
        .execute(pool)
        .await
        .expect("seed tenant");
    }

    async fn cleanup(pool: &sqlx::PgPool, tenants: &[&str]) {
        for tenant in tenants {
            sqlx::query("DELETE FROM template_versions WHERE tenant_id = $1")
                .bind(tenant)
                .execute(pool)
                .await
                .expect("cleanup versions");
            sqlx::query("DELETE FROM templates WHERE tenant_id = $1")
                .bind(tenant)
                .execute(pool)
                .await
                .expect("cleanup templates");
            sqlx::query("DELETE FROM tenants WHERE id = $1")
                .bind(tenant)
                .execute(pool)
                .await
                .expect("cleanup tenant");
        }
    }

    async fn create_ok(state: &AppState, tenant: &str, name: &str) -> TemplateResponse {
        let (status, Json(tpl)) = create_template(
            State(state.clone()),
            auth_for(tenant, &["templates:write"]),
            Json(CreateTemplateRequest {
                name: name.into(),
                subject: "Hello {{name}}".into(),
                html_body: "<p>{{name}}</p>".into(),
                text_body: Some("Hi {{name}}".into()),
            }),
        )
        .await
        .expect("create template");
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(tpl.version, 1);
        tpl
    }

    #[test]
    fn substitution_escapes_values_and_preserves_unknown_placeholders() {
        let mut vars = serde_json::Map::new();
        vars.insert(
            "name".into(),
            serde_json::json!("<script>alert('x')</script>"),
        );
        vars.insert("count".into(), serde_json::json!(7));
        vars.insert("flag".into(), serde_json::json!(true));
        vars.insert("nil".into(), serde_json::Value::Null);
        vars.insert("obj".into(), serde_json::json!({"a":"<b>"}));

        let out = substitute(
            "<b>{{name}}</b> {{count}} {{flag}} {{nil}} {{obj}} {{missing}}",
            &vars,
        );
        assert!(!out.contains("<script>"), "script payload escaped: {out}");
        assert!(out.contains("&lt;script&gt;"), "{out}");
        assert!(out.contains("7"));
        assert!(out.contains("true"));
        assert!(out.contains("null"));
        assert!(out.contains("{{missing}}"), "unknown vars stay literal");
        // Malformed braces must never panic; a dangling opener round-trips
        // through the placeholder-render path verbatim.
        assert_eq!(substitute("{{", &vars), "{{}}");
        assert_eq!(substitute("no vars here", &vars), "no vars here");
        assert_eq!(substitute("", &vars), "");
        let mut only_name = serde_json::Map::new();
        only_name.insert("name".into(), serde_json::json!("N"));
        assert_eq!(substitute("{{{name}}}", &only_name), "{{{name}}}");
    }

    #[tokio::test]
    async fn crud_flow_versions_rollback_and_tenant_isolation() {
        let Some((state, pool)) = state_and_pool("adv_templates_flow").await else {
            return;
        };
        let tenant_a = apexmail_lib::id::generate_id("", 26);
        let tenant_b = apexmail_lib::id::generate_id("", 26);
        seed_tenant(&pool, &tenant_a, "starter").await;
        seed_tenant(&pool, &tenant_b, "starter").await;
        let read = auth_for(&tenant_a, &["templates:read"]);
        let write = auth_for(&tenant_a, &["templates:write"]);
        let tag = uuid::Uuid::new_v4().simple().to_string();
        let template_name = format!("Welcome {tag}");

        let tpl = create_ok(&state, &tenant_a, &template_name).await;
        let (snap_count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM template_versions WHERE template_id = $1 AND version = 1",
        )
        .bind(&tpl.id)
        .fetch_one(&pool)
        .await
        .expect("v1 snapshot exists");
        assert_eq!(snap_count, 1);

        // Template names are NOT unique in the canonical schema
        // (idx_templates_tenant_name is a plain index) — a same-name create
        // succeeds and is a distinct resource; that is the current contract.
        let (dup_status, Json(duplicate)) = create_template(
            State(state.clone()),
            write.clone(),
            Json(CreateTemplateRequest {
                name: template_name.clone(),
                subject: "s".into(),
                html_body: "<p>x</p>".into(),
                text_body: None,
            }),
        )
        .await
        .expect("duplicate names are allowed on the canonical schema");
        assert_eq!(dup_status, StatusCode::CREATED);
        assert_ne!(duplicate.id, tpl.id);

        // Empty required fields are validation errors.
        for (name, subject, html) in [("", "s", "<p/>"), ("n", "", "<p/>"), ("n", "s", "")] {
            let resp = create_template(
                State(state.clone()),
                write.clone(),
                Json(CreateTemplateRequest {
                    name: name.into(),
                    subject: subject.into(),
                    html_body: html.into(),
                    text_body: None,
                }),
            )
            .await;
            assert!(matches!(resp, Err(ApiError::Validation(_))));
        }

        // Reads are tenant-scoped.
        let Json(fetched) = get_template(State(state.clone()), read.clone(), Path(tpl.id.clone()))
            .await
            .expect("own read");
        assert_eq!(fetched.name, template_name);
        let cross = get_template(
            State(state.clone()),
            read.clone(),
            Path("unknown-tpl".into()),
        )
        .await;
        assert!(matches!(cross, Err(ApiError::NotFound(_))));

        // Update bumps version and snapshots v2; render substitutes + escapes.
        let Json(updated) = update_template(
            State(state.clone()),
            write.clone(),
            Path(tpl.id.clone()),
            Json(UpdateTemplateRequest {
                name: Some(format!("Welcome v2 {tag}")),
                subject: None,
                html_body: Some("<h1>{{name}}</h1>".into()),
                text_body: None,
            }),
        )
        .await
        .expect("update");
        assert_eq!(updated.version, 2);
        let (v2,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM template_versions WHERE template_id = $1 AND version = 2",
        )
        .bind(&tpl.id)
        .fetch_one(&pool)
        .await
        .expect("v2 snapshot");
        assert_eq!(v2, 1);

        let Json(rendered) = render_template(
            State(state.clone()),
            read.clone(),
            Path(tpl.id.clone()),
            Json(RenderRequest {
                variables: serde_json::json!({"name": "<script>x</script>"}),
            }),
        )
        .await
        .expect("render");
        assert!(!rendered.html.contains("<script>"), "{}", rendered.html);
        assert!(rendered.html.contains("&lt;script&gt;"));
        assert!(rendered.text.as_deref().unwrap_or_default().contains("Hi"));

        // Non-object `variables` degrade to an empty map without an error.
        let Json(rendered_scalar) = render_template(
            State(state.clone()),
            read.clone(),
            Path(tpl.id.clone()),
            Json(RenderRequest {
                variables: serde_json::json!("not-an-object"),
            }),
        )
        .await
        .expect("render scalar vars");
        assert!(rendered_scalar.html.contains("{{name}}"));

        // Rollback restores v1 content and version.
        let Json(rolled) = rollback_template(
            State(state.clone()),
            write.clone(),
            Path(tpl.id.clone()),
            Json(RollbackRequest { version: 1 }),
        )
        .await
        .expect("rollback v1");
        assert_eq!(rolled.version, 1);
        assert_eq!(rolled.name, template_name);
        assert_eq!(rolled.html_body, "<p>{{name}}</p>");
        let missing_version = rollback_template(
            State(state.clone()),
            write.clone(),
            Path(tpl.id.clone()),
            Json(RollbackRequest { version: 99 }),
        )
        .await;
        assert!(matches!(missing_version, Err(ApiError::NotFound(_))));
        let cross_rollback = rollback_template(
            State(state.clone()),
            write.clone(),
            Path("not-our-template".into()),
            Json(RollbackRequest { version: 1 }),
        )
        .await;
        assert!(matches!(cross_rollback, Err(ApiError::NotFound(_))));

        // Duplicate copies content as a draft with a "(copy)" name.
        let (status, Json(copy)) =
            duplicate_template(State(state.clone()), write.clone(), Path(tpl.id.clone()))
                .await
                .expect("duplicate");
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(copy.name, format!("{template_name} (copy)"));
        assert_eq!(copy.status, "draft");
        assert_eq!(copy.version, 1);

        // Listing is paginated and tenant-scoped.
        let Json(list) = list_templates(
            State(state.clone()),
            read.clone(),
            Query(ListTemplatesQuery {
                limit: 1,
                offset: 0,
                cursor: None,
            }),
        )
        .await
        .expect("list");
        assert_eq!(list.len(), 1, "limit honoured");
        let Json(all) = list_templates(
            State(state.clone()),
            read.clone(),
            Query(ListTemplatesQuery {
                limit: i64::MAX,
                offset: -5,
                cursor: Some(-3),
            }),
        )
        .await
        .expect("clamped list");
        // original + same-name duplicate + "(copy)" duplicate
        assert_eq!(all.len(), 3);
        assert!(all.iter().all(|t| t.id != "unknown"));

        // Cross-tenant delete is a 404 and leaves the row.
        let foreign = create_ok_foreign(&state, &tenant_b, &format!("Foreign {tag}")).await;
        let cross_delete =
            delete_template(State(state.clone()), write.clone(), Path(foreign.clone())).await;
        assert!(matches!(cross_delete, Err(ApiError::NotFound(_))));
        let (foreign_exists,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM templates WHERE id = $1 AND tenant_id = $2")
                .bind(&foreign)
                .bind(&tenant_b)
                .fetch_one(&pool)
                .await
                .expect("foreign row survives");
        assert_eq!(foreign_exists, 1);

        // Own delete → 204, then 404s.
        let deleted = delete_template(State(state.clone()), write.clone(), Path(tpl.id.clone()))
            .await
            .expect("delete own");
        assert_eq!(deleted, StatusCode::NO_CONTENT);
        for _ in 0..2 {
            let gone =
                delete_template(State(state.clone()), write.clone(), Path(tpl.id.clone())).await;
            assert!(matches!(gone, Err(ApiError::NotFound(_))));
        }
        let gone_read =
            get_template(State(state.clone()), read.clone(), Path(tpl.id.clone())).await;
        assert!(matches!(gone_read, Err(ApiError::NotFound(_))));
        let gone_update = update_template(
            State(state.clone()),
            write.clone(),
            Path(tpl.id.clone()),
            Json(UpdateTemplateRequest {
                name: Some("zombie".into()),
                subject: None,
                html_body: None,
                text_body: None,
            }),
        )
        .await;
        assert!(matches!(gone_update, Err(ApiError::NotFound(_))));

        // Scope gates: read scope cannot write; no scope cannot read.
        let forbidden = create_template(
            State(state.clone()),
            read.clone(),
            Json(CreateTemplateRequest {
                name: "nope".into(),
                subject: "s".into(),
                html_body: "<p/>".into(),
                text_body: None,
            }),
        )
        .await;
        assert!(matches!(forbidden, Err(ApiError::Forbidden(_))));
        let no_scope = get_template(
            State(state.clone()),
            auth_for(&tenant_a, &[]),
            Path("anything".into()),
        )
        .await;
        assert!(matches!(no_scope, Err(ApiError::Forbidden(_))));

        cleanup(&pool, &[&tenant_a, &tenant_b]).await;
    }

    async fn create_ok_foreign(state: &AppState, tenant: &str, name: &str) -> String {
        let (_, Json(tpl)) = create_template(
            State(state.clone()),
            auth_for(tenant, &["templates:write"]),
            Json(CreateTemplateRequest {
                name: name.into(),
                subject: "Foreign".into(),
                html_body: "<p>f</p>".into(),
                text_body: None,
            }),
        )
        .await
        .expect("create foreign template");
        tpl.id
    }

    #[tokio::test]
    async fn free_plan_write_is_403_and_unknown_tenant_is_404() {
        let Some((state, pool)) = state_and_pool("adv_templates_entitlement").await else {
            return;
        };
        let free_tenant = apexmail_lib::id::generate_id("", 26);
        seed_tenant(&pool, &free_tenant, "free").await;
        let write = auth_for(&free_tenant, &["templates:write"]);

        let denied = create_template(
            State(state.clone()),
            write.clone(),
            Json(CreateTemplateRequest {
                name: "gated".into(),
                subject: "s".into(),
                html_body: "<p/>".into(),
                text_body: None,
            }),
        )
        .await;
        assert!(
            matches!(denied, Err(ApiError::Forbidden(_))),
            "the custom_templates entitlement must gate writes, got {denied:?}"
        );

        // Reads are allowed on the free plan.
        let Json(read) = list_templates(
            State(state.clone()),
            auth_for(&free_tenant, &["templates:read"]),
            Query(ListTemplatesQuery {
                limit: 10,
                offset: 0,
                cursor: None,
            }),
        )
        .await
        .expect("free plan can list");
        assert!(read.is_empty());

        // A tenant that does not exist resolves to 404, not a silent grant.
        let ghost = apexmail_lib::id::generate_id("", 26);
        let ghost_write = create_template(
            State(state.clone()),
            auth_for(&ghost, &["templates:write"]),
            Json(CreateTemplateRequest {
                name: "ghost".into(),
                subject: "s".into(),
                html_body: "<p/>".into(),
                text_body: None,
            }),
        )
        .await;
        assert!(matches!(ghost_write, Err(ApiError::NotFound(_))));

        cleanup(&pool, &[&free_tenant]).await;
    }
}
