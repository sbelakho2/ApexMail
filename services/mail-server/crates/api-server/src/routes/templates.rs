//! Email template CRUD routes.

use super::helpers::{html_escape, clamp_limit, default_limit};
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
        .route("/", post(create_template).get(list_templates))
        .route("/:id", get(get_template).put(update_template).delete(delete_template))
        .route("/:id/render", post(render_template))
        .route("/:id/duplicate", post(duplicate_template))
        .route("/:id/rollback", post(rollback_template))
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateTemplateRequest {
    pub name: String,
    pub subject: String,
    pub html_body: String,
    #[serde(default)]
    pub text_body: Option<String>,
}

#[derive(Debug, Deserialize)]
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

    let id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query(
        "INSERT INTO templates (id, tenant_id, name, subject, html_body, text_body, version, status, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,1,'active',$7,$7)",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .bind(&body.name)
    .bind(&body.subject)
    .bind(&body.html_body)
    .bind(&body.text_body)
    .bind(now)
    .execute(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(TemplateResponse {
            id: id.to_string(),
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

    let existing = fetch_template(&state, &auth.tenant_id, id.clone()).await?;;

    let name = body.name.unwrap_or(existing.name);
    let subject = body.subject.unwrap_or(existing.subject);
    let html_body = body.html_body.unwrap_or(existing.html_body);
    let text_body = body.text_body.or(existing.text_body);
    let new_version = existing.version + 1;

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
    .execute(&state.db)
    .await?;

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

    let tpl = fetch_template(&state, &auth.tenant_id, id).await?;;

    // Simple Handlebars-style variable substitution: {{var_name}}
    let vars = body.variables.as_object().unwrap_or(&serde_json::Map::new()).clone();
    let html = substitute(&tpl.html_body, &vars);
    let subject = substitute(&tpl.subject, &vars);
    let text = tpl.text_body.as_ref().map(|t| substitute(t, &vars));

    Ok(Json(RenderResponse {
        subject,
        html,
        text,
    }))
}

/// Fix #37: HTML-escape variable values to prevent stored XSS.
/// Fix #38: Build output in single pass instead of O(n×m) replacements.
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
                } else {
                    if let Some(next_ch) = chars.next() {
                        var_name.push(next_ch);
                    } else {
                        break;
                    }
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

async fn fetch_template(state: &AppState, tenant_id: &str, id: String) -> Result<TemplateRow, ApiError> {
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

// ─── Duplicate / Rollback Handlers ─────────────────────────────

async fn duplicate_template(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<TemplateResponse>), ApiError> {
    require_scopes(&auth, &["templates:write"])?;

    // Fetch original
    let original = fetch_template(&state, &auth.tenant_id, id.clone()).await?;

    let new_id = Uuid::new_v4();
    let now = chrono::Utc::now();
    let new_name = format!("{} (copy)", original.name);

    sqlx::query!(
        "INSERT INTO templates (id, tenant_id, name, subject, html_body, text_body, version, status, created_at, updated_at)
         SELECT $1, tenant_id, $3, subject, html_body, text_body, 1, 'draft', $4, $4
         FROM templates WHERE id = $2 AND tenant_id = $5",
        new_id.to_string(),
        id,
        new_name,
        now,
        auth.tenant_id.to_string(),
    )
    .execute(&state.db)
    .await?;

    let row = fetch_template(&state, &auth.tenant_id, new_id.to_string()).await?;
    Ok((StatusCode::CREATED, Json(row.into())))
}

#[derive(Debug, Deserialize)]
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

    // Restore from template_versions table
    let result = sqlx::query!(
        "UPDATE templates SET
            html_body = tv.html_body,
            text_body = tv.text_body,
            subject = tv.subject,
            version = tv.version,
            updated_at = NOW()
         FROM template_versions tv
         WHERE templates.id = $1 AND templates.tenant_id = $2
           AND tv.template_id = $1 AND tv.version = $3",
        id,
        auth.tenant_id.to_string(),
        body.version,
    )
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("template or version not found".into()));
    }

    let row = fetch_template(&state, &auth.tenant_id, id).await?;
    Ok(Json(row.into()))
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
            id: String::nil(),
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
}
