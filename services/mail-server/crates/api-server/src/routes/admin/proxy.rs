//! SSRF-safe proxy endpoint.
//!

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", post(proxy_request).get(proxy_disabled))
}

fn build_proxy_audit_metadata(
    body: &ProxyRequest,
    method: &str,
    host: &str,
    status: u16,
) -> serde_json::Value {
    let forwarded_headers: Vec<String> = body
        .headers
        .as_ref()
        .and_then(|headers| headers.as_object())
        .map(|headers| headers.keys().cloned().collect())
        .unwrap_or_default();

    json!({
        "url": body.url,
        "host": host,
        "method": method,
        "forwardedHeaders": forwarded_headers,
        "hasBody": body.body.is_some(),
        "responseStatus": status,
    })
}

async fn log_proxy_audit(db: &sqlx::PgPool, host: &str, metadata: serde_json::Value) {
    crate::audit_log::insert_audit_log_best_effort(
        db,
        None,
        None,
        "control_plane.proxy.requested",
        "proxy_request",
        Some(host),
        metadata,
        None,
        None,
    )
    .await;
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
    let parsed =
        url::Url::parse(&body.url).map_err(|_| ApiError::Validation(vec!["Invalid URL".into()]))?;

    // Enforce HTTPS in production
    if state.config.environment.is_production() && parsed.scheme() != "https" {
        return Err(ApiError::Validation(vec![
            "Only HTTPS URLs are allowed in production".into(),
        ]));
    }

    // Check allowlist — in production, an empty allowlist means NO proxying
    // is permitted.
    let allowlist_str = std::env::var("CONTROL_PLANE_PROXY_ALLOWLIST").unwrap_or_default();
    let allowlist: Vec<&str> = allowlist_str
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    if allowlist.is_empty() {
        if state.config.environment.is_production() {
            return Err(ApiError::Validation(vec![
                "Proxy not configured — set CONTROL_PLANE_PROXY_ALLOWLIST".into(),
            ]));
        }
    } else {
        let host = parsed.host_str().unwrap_or("");
        if !allowlist
            .iter()
            .any(|allowed| host == *allowed || host.ends_with(&format!(".{allowed}")))
        {
            return Err(ApiError::Validation(vec![
                "URL host not in proxy allowlist".into(),
            ]));
        }
    }

    // SSRF:Block private/RFC1918/link-local/cloud-metadata IPs and hostnames.
    if let Some(host) = parsed.host_str() {
        let host_lower = host.to_lowercase();
        // Strip brackets from IPv6 for matching.
        let bare = host_lower.trim_start_matches('[').trim_end_matches(']');

        // Blocked hostnames and literal IP addresses.
        let blocked_hosts = ["localhost", "127.0.0.1", "0.0.0.0", "::1", "0", "0.0.0.0"];
        // Cloud metadata endpoints.
        let blocked_prefixes = [
            "169.254.",        // AWS/GCP metadata + link-local
            "10.",             // RFC1918
            "192.168.",        // RFC1918
            "fc00:",           // IPv6 ULA
            "fd",              // IPv6 ULA
            "fe80:",           // IPv6 link-local
            "::ffff:127.",     // IPv4-mapped loopback
            "::ffff:10.",      // IPv4-mapped RFC1918
            "::ffff:192.168.", // IPv4-mapped RFC1918
            "::ffff:169.254.", // IPv4-mapped link-local
            "100.64.",         // Carrier-grade NAT (RFC6598)
        ];
        let is_blocked = blocked_hosts.contains(&bare)
            || blocked_prefixes.iter().any(|p| bare.starts_with(p))
// RFC1918 172.16.0.0/12
            || (bare.starts_with("172.")
                && bare
                    .split('.')
                    .nth(1)
                    .and_then(|s| s.parse::<u8>().ok())
                    .is_some_and(|second| (16..=31).contains(&second)))
// Cloud metadata exact IPs
            || bare == "169.254.169.254"
            || bare == "metadata.google.internal"
// Decimal/octal IP tricks (reject any all-digit hostnames)
            || bare.chars().all(|c| c.is_ascii_digit());
        if is_blocked {
            return Err(ApiError::Validation(vec![
                "Private/internal URLs are not allowed".into(),
            ]));
        }
    }

    let method = body.method.as_deref().unwrap_or("GET").to_uppercase();
    let host = parsed.host_str().unwrap_or("").to_string();

    let mut request = match method.as_str() {
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
    log_proxy_audit(
        &state.db,
        &host,
        build_proxy_audit_metadata(&body, &method, &host, status),
    )
    .await;

    let resp_headers = serde_json::json!({
        "content-type": response.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("")
    });

    let resp_body: serde_json::Value = response.json().await.unwrap_or(serde_json::json!(null));

    Ok(Json(ProxyResponse {
        status,
        headers: resp_headers,
        body: resp_body,
    }))
}
