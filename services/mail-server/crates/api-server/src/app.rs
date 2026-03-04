//! Application builder — assembles all middleware and routes into an Axum `Router`.

use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, Method, StatusCode};
use axum::response::IntoResponse;
use axum::{Json, Router};
use std::time::Duration;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::middleware::{auth, idempotency, rate_limiter, request_logger};
use crate::routes;
use crate::state::AppState;

/// Build the complete Axum application with all middleware and routes.
pub fn build_app(state: AppState) -> Router {
    // ── CORS ────────────────────────────────────────────────
    let cors = if state.config.cors_origins.iter().any(|o| o == "*") {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::PATCH,
                Method::OPTIONS,
            ])
            .allow_headers(Any)
            .max_age(Duration::from_secs(86400))
    } else {
        let origins: Vec<HeaderValue> = state
            .config
            .cors_origins
            .iter()
            .filter_map(|o| o.parse::<HeaderValue>().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(origins)
            .allow_credentials(true)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::PATCH,
                Method::OPTIONS,
            ])
            .allow_headers(Any)
            .max_age(Duration::from_secs(86400))
    };

    // ── Public routes (no auth) ─────────────────────────────
    let public = Router::new()
        .nest("/health", routes::health::router())
        .nest("/v1/auth", routes::auth::router())
        .nest("/v1/auth/session", routes::session::router())
        .nest("/v1/auth/forgot-password", routes::forgot_password::router())
        .nest("/v1/auth/sso", routes::sso::router())
        .nest("/v1/auth/csrf", routes::csrf::router())
        .nest("/v1/ses", routes::ses_notifications::router());

    // ── Authenticated v1 routes ─────────────────────────────
    //  Fix #6: Wrap with auth middleware so every route requires authentication.
    //  Fix #7: Wire rate limiting and idempotency middleware.
    let authenticated = Router::new()
        .nest("/v1/messages", routes::messages::router())
        .nest("/v1/domains", routes::domains::router())
        .nest("/v1/templates", routes::templates::router())
        .nest("/v1/suppressions", routes::suppressions::router())
        .nest("/v1/events", routes::events::router())
        .nest("/v1/webhooks", routes::webhooks::router())
        .nest("/v1/analytics", routes::analytics::router())
        .nest("/v1/support", routes::support::router())
        .nest("/v1/scim", routes::scim::router())
        .nest("/v1/campaigns", routes::campaigns::router())
        .nest("/v1/contacts", routes::contacts::router())
        .nest("/v1/lists", routes::lists::router())
        .nest("/v1/dashboard", routes::dashboard::router())
        .nest("/v1/client-errors", routes::client_errors::router())
        .nest("/v1/automations", routes::automations::router())
        .nest("/v1/ai", routes::ai_insights::router())
        .nest("/v1/dedicated-ips", routes::dedicated_ips::router())
        .nest("/v1/account", routes::account::router())
        // Migrated auth routes (require session/auth)
        .nest("/v1/auth/impersonate", routes::impersonate::router())
        .nest("/v1/auth/telemetry", routes::telemetry::router())
        // Control-plane admin routes
        .nest("/v1/admin/tenants", routes::admin::tenants::router())
        .nest("/v1/admin/features", routes::admin::features::router())
        .nest("/v1/admin/gdpr", routes::admin::gdpr::router())
        .nest("/v1/admin/secrets", routes::admin::secrets::router())
        .nest("/v1/admin/audit", routes::admin::audit::router())
        .nest("/v1/admin/dashboard", routes::admin::dashboard::router())
        .nest("/v1/admin/compliance", routes::admin::compliance_overview::router())
        .nest("/v1/admin/risk", routes::admin::risk::router())
        .nest("/v1/admin/revenue", routes::admin::revenue::router())
        .nest("/v1/admin/inbox", routes::admin::inbox::router())
        .nest("/v1/admin/calendar", routes::admin::calendar::router())
        .nest("/v1/admin/warmup", routes::admin::warmup::router())
        .nest("/v1/admin/content", routes::admin::content::router())
        .nest("/v1/admin/autopilot", routes::admin::autopilot::router())
        .nest("/v1/admin/proxy", routes::admin::proxy::router())
        .nest("/v1/admin/sales", routes::admin::sales::router())
        .nest("/v1/admin/analytics", routes::admin::analytics::router())
        .nest("/v1/admin/analytics/export", routes::admin::analytics_export::router())
        .nest("/v1/admin/campaigns", routes::admin::campaigns::router())
        .nest("/v1/admin/crm/leads", routes::admin::crm_leads::router())
        .nest("/v1/admin/leads/discovery", routes::admin::leads_discovery::router())
        .nest("/v1/admin/support", routes::admin::support::router())
        .nest("/v1/admin/support/analytics", routes::admin::support_analytics::router())
        .nest("/v1/admin/system/health", routes::admin::system_health::router())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            idempotency::idempotency_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            rate_limiter::rate_limit_middleware,
        ));

    // ── Assemble ────────────────────────────────────────────
    Router::new()
        .merge(public)
        .merge(authenticated)
        .fallback(fallback_handler)
        .layer(axum::middleware::from_fn(null_byte_check))
        .layer(axum::middleware::from_fn(security_headers))
        .layer(axum::middleware::from_fn(request_logger::request_logger))
        .layer(CompressionLayer::new())
        // Fix #8: Limit request body to 10 MiB to prevent memory exhaustion.
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024))
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

// ─── Security headers (Fix #9: use from_static, no runtime panics) ─────────

static HDR_API_VERSION: HeaderValue = HeaderValue::from_static("v1");
static HDR_HSTS: HeaderValue =
    HeaderValue::from_static("max-age=31536000; includeSubDomains");
static HDR_FRAME_OPTIONS: HeaderValue = HeaderValue::from_static("DENY");
static HDR_CONTENT_TYPE_OPTIONS: HeaderValue = HeaderValue::from_static("nosniff");
static HDR_XSS_PROTECTION: HeaderValue = HeaderValue::from_static("0");
static HDR_REFERRER_POLICY: HeaderValue =
    HeaderValue::from_static("strict-origin-when-cross-origin");
static HDR_CACHE_CONTROL: HeaderValue =
    HeaderValue::from_static("no-store, no-cache, must-revalidate");

async fn security_headers(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert("X-API-Version", HDR_API_VERSION.clone());
    headers.insert("Strict-Transport-Security", HDR_HSTS.clone());
    headers.insert("X-Frame-Options", HDR_FRAME_OPTIONS.clone());
    headers.insert("X-Content-Type-Options", HDR_CONTENT_TYPE_OPTIONS.clone());
    headers.insert("X-XSS-Protection", HDR_XSS_PROTECTION.clone());
    headers.insert("Referrer-Policy", HDR_REFERRER_POLICY.clone());
    headers.insert("Cache-Control", HDR_CACHE_CONTROL.clone());
    resp
}

// ─── Null byte check ───────────────────────────────────────────

async fn null_byte_check(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, axum::response::Response> {
    let path = req.uri().path();
    if apexmail_lib::validation::has_null_bytes(path) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": {
                    "code": "NULL_BYTE_DETECTED",
                    "message": "null bytes are not allowed in request paths"
                }
            })),
        )
            .into_response());
    }

    if let Some(query) = req.uri().query() {
        if apexmail_lib::validation::has_null_bytes(query) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": {
                        "code": "NULL_BYTE_DETECTED",
                        "message": "null bytes are not allowed in query parameters"
                    }
                })),
            )
                .into_response());
        }
    }

    Ok(next.run(req).await)
}

// ─── Fallback ──────────────────────────────────────────────────

async fn fallback_handler() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": {
                "code": "NOT_FOUND",
                "message": "the requested endpoint does not exist"
            }
        })),
    )
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fallback_handler() {
        let resp = fallback_handler().await.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_null_byte_detection() {
        assert!(apexmail_lib::validation::has_null_bytes("hello\0world"));
        assert!(!apexmail_lib::validation::has_null_bytes("hello_world"));
    }
}
