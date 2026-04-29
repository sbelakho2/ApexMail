//! Click-tracking redirect handler.
//!
//! GET `{click_path}/:tracking_id`
//!
//! Security properties://! - Prefers `originalUrl` from inside the encrypted token over `?r=` query
//! param (-041) — query params can be tampered with, token content cannot.
//! - Only allows redirects to http/https URLs whose hostname is explicitly
//! authorised for the tenant (blocks open-redirect attacks).
//! - Adds `Content-Security-Policy:frame-ancestors 'none'` to prevent
//! click-jacking (-500-455).

use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Deserialize;
use tracing::{debug, error, warn};

use crate::processor::ClickData;
use crate::routes::extract_client_ip;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct ClickQuery {
/// Optional override URL (used when originalUrl was not baked into the token).
    r: Option<String>,
}

pub async fn handle_click(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(tracking_id): Path<String>,
    Query(q): Query<ClickQuery>,
) -> Response {
    let fallback = state.config.tracking.fallback_url.clone();
    let redirect_status = state.config.tracking.redirect_status;

// E-148:Length guard
    if tracking_id.len() < 10 || tracking_id.len() > 4096 {
        warn!(len = tracking_id.len(), "Click: invalid trackingId length");
        return csp_redirect(&fallback, redirect_status);
    }

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let ip = extract_client_ip(&headers, addr.ip(), &state);

    debug!(
        id_prefix = &tracking_id[..tracking_id.len().min(20)],
        has_r = q.r.is_some(),
        "Click tracking request"
    );

    let data = state.codec.decode(&tracking_id);

    let redirect_url = determine_redirect_url(&data, q.r.as_deref(), &fallback);

// Validate protocol and domain
    let redirect_url = match validate_redirect_url(&redirect_url, data.as_ref(), &state).await {
        Ok(url) => url,
        Err(_) => fallback.clone(),
    };

// Record click asynchronously (fire-and-forget)
    if let Some(d) = &data {
        let processor = state.processor.clone();
        let click_data = ClickData {
            tenant_id: d.tenant_id.clone(),
            message_id: d.message_id.clone(),
            recipient: d.recipient.clone(),
            link_id: d.link_id.clone().unwrap_or_else(|| "unknown".into()),
            link_url: redirect_url.clone(),
            user_agent: user_agent.clone(),
            ip_address: Some(ip.clone()),
        };

// Store link URL in Redis for analytics (F-213, 90 day TTL)
        if let Some(link_id) = &d.link_id {
            let redis = state.redis.clone();
            let link_key = format!("links:{}:{}", d.tenant_id, d.message_id);
            let lid = link_id.clone();
            let url2 = redirect_url.clone();
            tokio::spawn(async move {
                if let Ok(mut conn) = redis.get().await {
                    if let Err(error) = redis::pipe()
                        .hset(&link_key, &lid, &url2)
                        .expire(&link_key, 86400 * 90)
                        .query_async::<()>(&mut *conn)
                        .await
                    {
                        warn!(link_key = %link_key, link_id = %lid, error = %error, "Failed to cache click-tracking link metadata");
                    }
                }
            });
        }

        tokio::spawn(async move {
            if let Err(e) = processor.record_click(click_data).await {
                error!(error = %e, "Failed to record click event");
            }
        });
    } else {
        warn!(
            id_prefix = &tracking_id[..tracking_id.len().min(20)],
            "Click: invalid tracking token"
        );
    }

    csp_redirect(&redirect_url, redirect_status)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn determine_redirect_url(
    data: &Option<crate::codec::TrackingData>,
    r_param: Option<&str>,
    fallback: &str,
) -> String {
    if let Some(d) = data {
        if let Some(url) = &d.original_url {
            return url.clone();
        }
        if let Some(r) = r_param {
// F-211:decodeURIComponent equivalent — percent-decode only
            return percent_decode(r).unwrap_or_else(|| fallback.to_owned());
        }
    }
    fallback.to_owned()
}

fn percent_decode(s: &str) -> Option<String> {
// Use a simple approach:percent-decode once
    let decoded = urlencoding::decode(s).ok()?;
    Some(decoded.into_owned())
}

async fn validate_redirect_url(
    url: &str,
    data: Option<&crate::codec::TrackingData>,
    state: &AppState,
) -> Result<String, ()> {
    let parsed = parse_allowed_redirect_url(url)?;

    if let Some(d) = data {
        let domain = parsed.host_str().unwrap_or("").to_owned();
        let allowed = verify_redirect_domain(state, &d.tenant_id, &domain).await;
        if !allowed {
            warn!(
                domain = %domain,
                tenant_id = %d.tenant_id,
                "Click: blocked unauthorized redirect domain"
            );
            return Err(());
        }
    }

    Ok(url.to_owned())
}

fn parse_allowed_redirect_url(url: &str) -> Result<url::Url, ()> {
    let parsed = url.parse::<url::Url>().map_err(|_| ())?;

    match parsed.scheme() {
        "http" | "https" => Ok(parsed),
        scheme => {
            warn!(scheme, "Click: blocked non-http redirect");
            Err(())
        }
    }
}

/// Check if `domain` is authorised for `tenant_id`.
/// Cache hierarchy:/// 1. moka in-memory cache (60 s TTL, 10 000 entries)
/// 2. Redis (300 s TTL)
/// 3. Postgres (domains + tenant_settings tables)
async fn verify_redirect_domain(state: &AppState, tenant_id: &str, domain: &str) -> bool {
    let cache_key = format!("{tenant_id}:{domain}");

// 1. moka
    if let Some(r) = state.domain_cache.get(&cache_key).await {
        return r;
    }

// Allow fallback domain without DB round-trip
    if let Ok(fallback) = state.config.tracking.fallback_url.parse::<url::Url>() {
        if fallback.host_str() == Some(domain) {
            state.domain_cache.insert(cache_key.clone(), true).await;
            return true;
        }
    }

// 2. Redis
    let redis_key = format!("redirect_domain:{cache_key}");
    if let Ok(mut conn) = state.redis.get().await {
        if let Ok(cached) = redis::cmd("GET")
            .arg(&redis_key)
            .query_async::<Option<String>>(&mut *conn)
            .await
        {
            let result = cached.as_deref() == Some("1");
            state.domain_cache.insert(cache_key.clone(), result).await;
            return result;
        }
    }

// 3. Postgres:owned domains
    let result: bool = async {
        let row = sqlx::query_as::<_, (i64,)>(
            "SELECT 1 FROM domains WHERE tenant_id = $1 AND domain = $2 LIMIT 1",
        )
        .bind(tenant_id)
        .bind(domain)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

        if row.is_some() {
            return true;
        }

// 4. Postgres:allowed_redirect_domains wildcard patterns
        let row = sqlx::query_as::<_, (Vec<String>,)>(
            "SELECT allowed_redirect_domains FROM tenant_settings WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

        if let Some((patterns,)) = row {
            for pattern in &patterns {
                if match_domain_pattern(domain, pattern) {
                    return true;
                }
            }
        }
        false
    }
    .await;

// Cache result in both Redis and moka
    if let Ok(mut conn) = state.redis.get().await {
        let val = if result { "1" } else { "0" };
        let _ = redis::cmd("SETEX")
            .arg(&redis_key)
            .arg(300u64)
            .arg(val)
            .query_async::<()>(&mut *conn)
            .await;
    }
    state.domain_cache.insert(cache_key, result).await;
    result
}

/// Match a domain against a pattern (supports `*.example.com` wildcard prefix).
/// Case-insensitive per RFC 4343 (F-212).
fn match_domain_pattern(domain: &str, pattern: &str) -> bool {
    let d = domain.to_lowercase();
    let p = pattern.to_lowercase();
    if p == d {
        return true;
    }
    if let Some(suffix) = p.strip_prefix("*.") {
        let dot_suffix = format!(".{suffix}");
        return d.ends_with(&dot_suffix) && d.len() > dot_suffix.len();
    }
    false
}

/// Return a redirect response with `Content-Security-Policy:frame-ancestors 'none'`
/// and the exact status code from config (typically 302).
fn csp_redirect(url: &str, status: u16) -> Response {
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::FOUND);
    axum::http::Response::builder()
        .status(code)
        .header("location", url)
        .header("content-security-policy", "frame-ancestors 'none'")
        .body(axum::body::Body::empty())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::TrackingData;

    #[test]
    fn determine_redirect_url_prefers_token_original_url() {
        let data = Some(TrackingData {
            tenant_id: "tenant_1".into(),
            message_id: "msg_1".into(),
            recipient: "user@example.com".into(),
            link_id: Some("link_1".into()),
            original_url: Some("https://safe.example.com/path".into()),
        });

        let redirect = determine_redirect_url(
            &data,
            Some("https%3A%2F%2Fevil.example.com"),
            "https://fallback.example.com",
        );

        assert_eq!(redirect, "https://safe.example.com/path");
    }

    #[test]
    fn determine_redirect_url_decodes_query_only_once() {
        let data = Some(TrackingData {
            tenant_id: "tenant_1".into(),
            message_id: "msg_1".into(),
            recipient: "user@example.com".into(),
            link_id: Some("link_1".into()),
            original_url: None,
        });

        let redirect = determine_redirect_url(
            &data,
            Some("https%253A%252F%252Fevil.example.com%252Flanding"),
            "https://fallback.example.com",
        );

        assert_eq!(redirect, "https%3A%2F%2Fevil.example.com%2Flanding");
        assert!(parse_allowed_redirect_url(&redirect).is_err());
    }

    #[test]
    fn parse_allowed_redirect_url_rejects_javascript_scheme() {
        assert!(parse_allowed_redirect_url("javascript:alert(1)").is_err());
    }

    #[test]
    fn parse_allowed_redirect_url_accepts_https_scheme() {
        let parsed = parse_allowed_redirect_url("https://app.example.com/path").unwrap();

        assert_eq!(parsed.scheme(), "https");
        assert_eq!(parsed.host_str(), Some("app.example.com"));
    }
}
