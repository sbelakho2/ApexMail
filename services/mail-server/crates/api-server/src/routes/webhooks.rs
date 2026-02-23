//! Webhook management routes.

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
        .route("/", post(create_webhook).get(list_webhooks))
        .route("/:id", get(get_webhook).put(update_webhook).delete(delete_webhook))
        .route("/:id/test", post(test_webhook))
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateWebhookRequest {
    pub url: String,
    pub events: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateWebhookRequest {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub events: Option<Vec<String>>,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WebhookResponse {
    pub id: Uuid,
    pub url: String,
    pub events: serde_json::Value,
    pub secret: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
pub struct TestWebhookResponse {
    pub success: bool,
    pub status_code: Option<u16>,
    pub response_time_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ─── Handlers ──────────────────────────────────────────────────

async fn create_webhook(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateWebhookRequest>,
) -> Result<(StatusCode, Json<WebhookResponse>), ApiError> {
    require_scopes(&auth, &["webhooks:write"])?;

    if body.url.is_empty() || body.events.is_empty() {
        return Err(ApiError::Validation(vec![
            "url and events are required".into(),
        ]));
    }

    let id = Uuid::new_v4();
    let now = Utc::now();
    let secret = apexmail_lib::id::generate_webhook_secret();

    sqlx::query(
        "INSERT INTO webhooks (id, tenant_id, url, events, secret, status, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,'active',$6,$6)",
    )
    .bind(id)
    .bind(auth.tenant_id)
    .bind(&body.url)
    .bind(serde_json::json!(body.events))
    .bind(&secret)
    .bind(now)
    .execute(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(WebhookResponse {
            id,
            url: body.url,
            events: serde_json::json!(body.events),
            secret,
            status: "active".into(),
            created_at: now.to_rfc3339(),
            updated_at: now.to_rfc3339(),
        }),
    ))
}

async fn list_webhooks(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<WebhookResponse>>, ApiError> {
    require_scopes(&auth, &["webhooks:read"])?;

    let rows = sqlx::query_as::<_, WebhookRow>(
        "SELECT id, url, events, secret, status, created_at, updated_at
         FROM webhooks WHERE tenant_id = $1 ORDER BY created_at DESC",
    )
    .bind(auth.tenant_id)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn get_webhook(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<WebhookResponse>, ApiError> {
    require_scopes(&auth, &["webhooks:read"])?;
    let row = fetch_webhook(&state, auth.tenant_id, id).await?;
    Ok(Json(row.into()))
}

async fn update_webhook(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateWebhookRequest>,
) -> Result<Json<WebhookResponse>, ApiError> {
    require_scopes(&auth, &["webhooks:write"])?;

    let existing = fetch_webhook(&state, auth.tenant_id, id).await?;
    let url = body.url.unwrap_or(existing.url);
    let events = body.events.map(|e| serde_json::json!(e)).unwrap_or(existing.events);
    let status = body.status.unwrap_or(existing.status);

    sqlx::query(
        "UPDATE webhooks SET url=$1, events=$2, status=$3, updated_at=NOW()
         WHERE id=$4 AND tenant_id=$5",
    )
    .bind(&url)
    .bind(&events)
    .bind(&status)
    .bind(id)
    .bind(auth.tenant_id)
    .execute(&state.db)
    .await?;

    Ok(Json(WebhookResponse {
        id,
        url,
        events,
        secret: existing.secret,
        status,
        created_at: existing.created_at.to_rfc3339(),
        updated_at: Utc::now().to_rfc3339(),
    }))
}

async fn delete_webhook(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["webhooks:write"])?;

    let result = sqlx::query("DELETE FROM webhooks WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(auth.tenant_id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("webhook not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn test_webhook(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<TestWebhookResponse>, ApiError> {
    require_scopes(&auth, &["webhooks:write"])?;

    let wh = fetch_webhook(&state, auth.tenant_id, id).await?;
    let timeout = std::time::Duration::from_millis(state.config.webhook_timeout_ms);

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| ApiError::Internal(format!("http client error: {e}")))?;

    let payload = serde_json::json!({
        "type": "test",
        "timestamp": Utc::now().to_rfc3339(),
    });

    let signature = apexmail_lib::crypto::create_hmac_signature(
        wh.secret.as_bytes(),
        &serde_json::to_vec(&payload).unwrap_or_default(),
    );

    let start = std::time::Instant::now();
    let result = client
        .post(&wh.url)
        .header("Content-Type", "application/json")
        .header("X-Webhook-Signature", &signature)
        .json(&payload)
        .send()
        .await;
    let elapsed = start.elapsed().as_millis() as u64;

    match result {
        Ok(resp) => Ok(Json(TestWebhookResponse {
            success: resp.status().is_success(),
            status_code: Some(resp.status().as_u16()),
            response_time_ms: elapsed,
            error: None,
        })),
        Err(e) => Ok(Json(TestWebhookResponse {
            success: false,
            status_code: None,
            response_time_ms: elapsed,
            error: Some(e.to_string()),
        })),
    }
}

// ─── Row types ─────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct WebhookRow {
    id: Uuid,
    url: String,
    events: serde_json::Value,
    secret: String,
    status: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<WebhookRow> for WebhookResponse {
    fn from(r: WebhookRow) -> Self {
        Self {
            id: r.id,
            url: r.url,
            events: r.events,
            secret: r.secret,
            status: r.status,
            created_at: r.created_at.to_rfc3339(),
            updated_at: r.updated_at.to_rfc3339(),
        }
    }
}

async fn fetch_webhook(state: &AppState, tenant_id: Uuid, id: Uuid) -> Result<WebhookRow, ApiError> {
    sqlx::query_as::<_, WebhookRow>(
        "SELECT id, url, events, secret, status, created_at, updated_at
         FROM webhooks WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("webhook not found".into()))
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_webhook_request_deser() {
        let json = r#"{"url":"https://example.com/hook","events":["delivered","bounced"]}"#;
        let req: CreateWebhookRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.events.len(), 2);
    }

    #[test]
    fn test_webhook_response_serialisation() {
        let resp = WebhookResponse {
            id: Uuid::nil(),
            url: "https://example.com".into(),
            events: serde_json::json!(["delivered"]),
            secret: "whsec_abc".into(),
            status: "active".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "active");
    }

    #[test]
    fn test_test_webhook_response_success() {
        let resp = TestWebhookResponse {
            success: true,
            status_code: Some(200),
            response_time_ms: 150,
            error: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["success"], true);
        assert!(json.get("error").is_none());
    }
}
