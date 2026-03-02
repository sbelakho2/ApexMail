//! SSRF-safe proxy endpoint.
//!
//! Migrated from: apps/control-plane/src/app/api/proxy/route.ts

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", post(proxy_request).get(proxy_disabled))
}

#[derive(Debug, Deserialize)]
pub struct ProxyRequest {
    pub url: String,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub headers: Option<serde_json::Value>,
    #[serde(default)]
    pub body: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ProxyResponse {
    pub status: u16,
    pub headers: serde_json::Value,
    pub body: serde_json::Value,
}

/// Allowed headers to forward (security allowlist).
const HEADER_ALLOWLIST: &[&str] = &[
    "content-type",
    "accept",
    "authorization",
    "x-api-key",
    "x-request-id",
];

async fn proxy_disabled() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(serde_json::json!({ "error": "GET not supported on proxy endpoint" })),
    )
}

async fn proxy_request(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<ProxyRequest>,
) -> Result<Json<ProxyResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    // Validate URL
    let parsed = url::Url::parse(&body.url)
        .map_err(|_| ApiError::Validation(vec!["Invalid URL".into()]))?;

    // Enforce HTTPS in production
    if state.config.environment.is_production() && parsed.scheme() != "https" {
        return Err(ApiError::Validation(vec!["Only HTTPS URLs are allowed in production".into()]));
    }

    // Check allowlist
    let allowlist_str = std::env::var("CONTROL_PLANE_PROXY_ALLOWLIST").unwrap_or_default();
    let allowlist: Vec<&str> = allowlist_str.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();

    if !allowlist.is_empty() {
        let host = parsed.host_str().unwrap_or("");
        if !allowlist.iter().any(|allowed| host == *allowed || host.ends_with(&format!(".{allowed}"))) {
            return Err(ApiError::Validation(vec!["URL host not in proxy allowlist".into()]));
        }
    }

    // SSRF: Block private/RFC1918 IPs
    if let Some(host) = parsed.host_str() {
        let blocked = ["localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]"];
        if blocked.contains(&host) || host.starts_with("10.") || host.starts_with("172.") || host.starts_with("192.168.") {
            return Err(ApiError::Validation(vec!["Private/internal URLs are not allowed".into()]));
        }
    }

    let method = body.method.as_deref().unwrap_or("GET");

    let mut request = match method.to_uppercase().as_str() {
        "GET" => state.http_client.get(&body.url),
        "POST" => state.http_client.post(&body.url),
        "PUT" => state.http_client.put(&body.url),
        "PATCH" => state.http_client.patch(&body.url),
        "DELETE" => state.http_client.delete(&body.url),
        _ => return Err(ApiError::Validation(vec!["Unsupported HTTP method".into()])),
    };

    // Forward only allowed headers
    if let Some(headers) = &body.headers {
        if let Some(obj) = headers.as_object() {
            for (key, value) in obj {
                if HEADER_ALLOWLIST.contains(&key.to_lowercase().as_str()) {
                    if let Some(val) = value.as_str() {
                        request = request.header(key.as_str(), val);
                    }
                }
            }
        }
    }

    // Forward body for mutation methods
    if let Some(body_data) = &body.body {
        request = request.json(body_data);
    }

    let response = request
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Proxy request failed: {e}");
            ApiError::Internal("Proxy request failed".into())
        })?;

    let status = response.status().as_u16();
    let resp_headers = serde_json::json!({
        "content-type": response.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("")
    });

    let resp_body: serde_json::Value = response
        .json()
        .await
        .unwrap_or(serde_json::json!(null));

    Ok(Json(ProxyResponse {
        status,
        headers: resp_headers,
        body: resp_body,
    }))
}
