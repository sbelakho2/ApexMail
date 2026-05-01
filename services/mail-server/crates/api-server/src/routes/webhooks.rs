//! Webhook management routes.

use super::helpers::{clamp_limit, default_limit};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use mail_common::{is_localhost, is_private_or_reserved_host};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(create_webhook).get(list_webhooks))
        .route(
            "/:id",
            get(get_webhook).put(update_webhook).delete(delete_webhook),
        )
        .route("/:id/test", post(test_webhook))
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateWebhookRequest {
    pub url: String,
    pub events: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
    pub id: String,
    pub url: String,
    pub events: serde_json::Value,
    // Secret is only returned at creation time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
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

#[derive(Debug, Deserialize)]
pub struct ListWebhooksQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub cursor: Option<i64>,
}

// ─── Validation ────────────────────────────────────────────────

/// Validate webhook URL format and security requirements.
/// Requires HTTPS (or HTTP for localhost in development).
fn validate_webhook_url(url_str: &str) -> Result<(), String> {
    let url = Url::parse(url_str).map_err(|e| format!("invalid URL: {}", e))?;

    let scheme = url.scheme();
    let host = url.host_str().ok_or("URL must have a host")?;

    // Require HTTPS for production URLs
    if scheme == "http" {
        // Allow HTTP only for localhost/development
        if host != "localhost" && host != "127.0.0.1" && host != "::1" {
            return Err("webhook URL must use HTTPS for non-local hosts".into());
        }
    } else if scheme != "https" {
        return Err(format!("invalid URL scheme: {}, must be https", scheme));
    }

    if !is_localhost(host) && is_private_or_reserved_host(host) {
        return Err("webhook URL cannot point to private or reserved addresses".into());
    }

    Ok(())
}

// ─── Handlers ──────────────────────────────────────────────────

async fn create_webhook(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateWebhookRequest>,
) -> Result<(StatusCode, Json<WebhookResponse>), ApiError> {
    require_scopes(&auth, &["webhooks:write"])?;

    let mut errors = Vec::new();

    if body.url.is_empty() {
        errors.push("url is required".into());
    } else if let Err(e) = validate_webhook_url(&body.url) {
        errors.push(e);
    }

    if body.events.is_empty() {
        errors.push("events are required".into());
    }

    if !errors.is_empty() {
        return Err(ApiError::Validation(errors));
    }

    // Enforce per-tenant webhook count limit (default:25)
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM webhooks WHERE tenant_id = $1")
        .bind(&auth.tenant_id)
        .fetch_one(&state.db)
        .await?;

    const MAX_WEBHOOKS_PER_TENANT: i64 = 25;
    if count.0 >= MAX_WEBHOOKS_PER_TENANT {
        return Err(ApiError::Forbidden(format!(
            "webhook limit reached: maximum {} webhooks per tenant",
            MAX_WEBHOOKS_PER_TENANT,
        )));
    }

    let id = Uuid::new_v4();
    let now = Utc::now();
    let secret = apexmail_lib::id::generate_webhook_secret();

    sqlx::query(
        "INSERT INTO webhooks (id, tenant_id, url, events, secret, status, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,'active',$6,$6)",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .bind(&body.url)
    .bind(serde_json::json!(body.events))
    .bind(&secret)
    .bind(now)
    .execute(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(WebhookResponse {
            id: id.to_string(),
            url: body.url,
            events: serde_json::json!(body.events),
            // Only return secret at creation time
            secret: Some(secret),
            status: "active".into(),
            created_at: now.to_rfc3339(),
            updated_at: now.to_rfc3339(),
        }),
    ))
}

async fn list_webhooks(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ListWebhooksQuery>,
) -> Result<Json<Vec<WebhookResponse>>, ApiError> {
    require_scopes(&auth, &["webhooks:read"])?;

    let offset = params.cursor.unwrap_or(params.offset).clamp(0, 100_000);
    let rows = sqlx::query_as::<_, WebhookRow>(
        "SELECT id, url, events, secret, status, created_at, updated_at
         FROM webhooks WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(&auth.tenant_id)
    .bind(clamp_limit(params.limit, 200))
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn get_webhook(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<WebhookResponse>, ApiError> {
    require_scopes(&auth, &["webhooks:read"])?;
    let row = fetch_webhook(&state, &auth.tenant_id, id).await?;
    Ok(Json(row.into()))
}

async fn update_webhook(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<UpdateWebhookRequest>,
) -> Result<Json<WebhookResponse>, ApiError> {
    require_scopes(&auth, &["webhooks:write"])?;

    // Validate new URL if provided
    if let Some(ref new_url) = body.url {
        if let Err(e) = validate_webhook_url(new_url) {
            return Err(ApiError::Validation(vec![e]));
        }
    }

    let existing = fetch_webhook(&state, &auth.tenant_id, id.clone()).await?;
    let url = body.url.unwrap_or(existing.url);
    let events = body
        .events
        .map(|e| serde_json::json!(e))
        .unwrap_or(existing.events);

    let status = match body.status.as_deref() {
        Some(s) if s == "active" || s == "paused" || s == "disabled" => s.to_string(),
        Some(s) => {
            return Err(ApiError::Validation(vec![format!(
                "invalid status '{}': must be 'active', 'paused', or 'disabled'",
                s
            )]))
        }
        None => existing.status,
    };

    sqlx::query(
        "UPDATE webhooks SET url=$1, events=$2, status=$3, updated_at=NOW()
         WHERE id=$4 AND tenant_id=$5",
    )
    .bind(&url)
    .bind(&events)
    .bind(&status)
    .bind(&id)
    .bind(&auth.tenant_id)
    .execute(&state.db)
    .await?;

    Ok(Json(WebhookResponse {
        id,
        url,
        events,
        secret: None, // Don't expose secret in update response
        status,
        created_at: existing.created_at.to_rfc3339(),
        updated_at: Utc::now().to_rfc3339(),
    }))
}

async fn delete_webhook(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["webhooks:write"])?;

    let result = sqlx::query("DELETE FROM webhooks WHERE id = $1 AND tenant_id = $2")
        .bind(&id)
        .bind(&auth.tenant_id)
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
    Path(id): Path<String>,
) -> Result<Json<TestWebhookResponse>, ApiError> {
    require_scopes(&auth, &["webhooks:write"])?;

    let wh = fetch_webhook(&state, &auth.tenant_id, id).await?;

    if let Err(e) = validate_webhook_url(&wh.url) {
        return Err(ApiError::BadRequest(format!(
            "webhook URL validation failed: {e}"
        )));
    }

    // Additional DNS rebinding protection:resolve and check IP before request.
    let url = Url::parse(&wh.url).map_err(|e| ApiError::BadRequest(format!("invalid URL: {e}")))?;
    if let Some(host) = url.host_str() {
        // Skip DNS check for localhost in dev
        if host != "localhost" && host != "127.0.0.1" && host != "::1" {
            // Try to resolve and verify the IP isn't private
            if let Ok(addrs) = tokio::net::lookup_host(format!(
                "{}:{}",
                host,
                url.port_or_known_default().unwrap_or(443)
            ))
            .await
            {
                for addr in addrs {
                    let ip_str = addr.ip().to_string();
                    if is_private_or_reserved_host(&ip_str) {
                        return Err(ApiError::BadRequest(
                            "webhook URL resolves to a private IP address (possible DNS rebinding)"
                                .into(),
                        ));
                    }
                }
            }
        }
    }

    let timeout = std::time::Duration::from_millis(state.config.webhook_timeout_ms);

    let client = state.http_client.clone();

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
        .timeout(timeout)
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
    id: String,
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
            secret: None,
            status: r.status,
            created_at: r.created_at.to_rfc3339(),
            updated_at: r.updated_at.to_rfc3339(),
        }
    }
}

async fn fetch_webhook(
    state: &AppState,
    tenant_id: &str,
    id: String,
) -> Result<WebhookRow, ApiError> {
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
            id: String::new(),
            url: "https://example.com".into(),
            events: serde_json::json!(["delivered"]),
            secret: Some("whsec_abc".into()),
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

    #[test]
    fn test_validate_webhook_url_allows_explicit_localhost_http() {
        assert!(validate_webhook_url("http://localhost:3000/hook").is_ok());
        assert!(validate_webhook_url("http://127.0.0.1:3000/hook").is_ok());
    }

    #[test]
    fn test_validate_webhook_url_blocks_ipv6_link_local_targets() {
        let error = validate_webhook_url("https://[fe80::1]/hook").unwrap_err();
        assert!(error.contains("private or reserved addresses"));
    }
}
