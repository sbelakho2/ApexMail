//! Email template CRUD routes.

use axum::extract::{Path, State};
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
    pub id: Uuid,
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
    .bind(auth.tenant_id)
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
) -> Result<Json<Vec<TemplateResponse>>, ApiError> {
    require_scopes(&auth, &["templates:read"])?;

    let rows = sqlx::query_as::<_, TemplateRow>(
        "SELECT id, name, subject, html_body, text_body, version, status, created_at, updated_at
         FROM templates WHERE tenant_id = $1 ORDER BY updated_at DESC",
    )
    .bind(auth.tenant_id)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn get_template(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<TemplateResponse>, ApiError> {
    require_scopes(&auth, &["templates:read"])?;
    let row = fetch_template(&state, auth.tenant_id, id).await?;
    Ok(Json(row.into()))
}

async fn update_template(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateTemplateRequest>,
) -> Result<Json<TemplateResponse>, ApiError> {
    require_scopes(&auth, &["templates:write"])?;

    let existing = fetch_template(&state, auth.tenant_id, id).await?;

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
    .bind(id)
    .bind(auth.tenant_id)
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
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["templates:write"])?;

    let result = sqlx::query("DELETE FROM templates WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(auth.tenant_id)
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
    Path(id): Path<Uuid>,
    Json(body): Json<RenderRequest>,
) -> Result<Json<RenderResponse>, ApiError> {
    require_scopes(&auth, &["templates:read"])?;

    let tpl = fetch_template(&state, auth.tenant_id, id).await?;

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

fn substitute(template: &str, vars: &serde_json::Map<String, serde_json::Value>) -> String {
    let mut result = template.to_string();
    for (key, val) in vars {
        let placeholder = format!("{{{{{key}}}}}");
        let replacement = match val {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        result = result.replace(&placeholder, &replacement);
    }
    result
}

// ─── Row types ─────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct TemplateRow {
    id: Uuid,
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

async fn fetch_template(state: &AppState, tenant_id: Uuid, id: Uuid) -> Result<TemplateRow, ApiError> {
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
            id: Uuid::nil(),
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
