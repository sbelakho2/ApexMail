//! Application builder — assembles all middleware and routes into an Axum `Router`.

use base64::Engine;
use axum::error_handling::HandleErrorLayer;
use axum::extract::{DefaultBodyLimit, Query};
use axum::http::{header::{self, ACCEPT, AUTHORIZATION, CONTENT_TYPE, HOST}, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Response};
use rand::RngCore;
use axum::routing::get;
use axum::{BoxError, Json, Router};
use serde::Deserialize;
use std::time::Duration;
use tower::limit::GlobalConcurrencyLimitLayer;
use tower::load_shed::{error::Overloaded, LoadShedLayer};
use tower::ServiceBuilder;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use ui_foundation::axum_router as ui_router;

use crate::config::Config;
use crate::middleware::{auth, ddos, idempotency, metrics, rate_limiter, request_logger};
use crate::routes;
use crate::state::AppState;

async fn handle_backpressure_error(error: BoxError) -> Response {
    if error.is::<Overloaded>() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": {
                    "code": "SERVICE_OVERLOADED",
                    "message": "too many concurrent requests"
                }
            })),
        )
            .into_response();
    }

    tracing::error!(error = %error, "unexpected backpressure middleware error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "request middleware failed"
            }
        })),
    )
        .into_response()
}

/// Build the complete Axum application with all middleware and routes.
pub fn build_app(state: AppState) -> Router {
// ── CORS ────────────────────────────────────────────────
    let allowed_headers = [
        ACCEPT,
        AUTHORIZATION,
        CONTENT_TYPE,
        header::HeaderName::from_static("x-api-key"),
        header::HeaderName::from_static("x-csrf-token"),
    ];
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
            .allow_headers(allowed_headers.clone())
            .max_age(Duration::from_secs(86400))
    } else {
        let origins: Vec<HeaderValue> = state
            .config
            .cors_origins
            .iter()
            .filter_map(|o| o.parse::<HeaderValue>().ok())
            .collect();
        let cors = CorsLayer::new()
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::PATCH,
                Method::OPTIONS,
            ])
            .allow_headers(allowed_headers)
            .max_age(Duration::from_secs(86400));

        if origins.is_empty() {
            cors
        } else {
            cors.allow_origin(origins).allow_credentials(true)
        }
    };

// ── Public routes (no auth) ─────────────────────────────
// credential stuffing and registration spam.
    let rate_limited_public = Router::new()
        .nest("/v1/auth", routes::auth::router())
        .nest("/v1/auth/session", routes::session::router())
        .nest("/v1/auth/forgot-password", routes::forgot_password::router())
        .nest("/v1/auth/sso", routes::sso::router())
        .nest("/v1/auth/csrf", routes::csrf::router())
        .nest("/api/auth", routes::auth::control_plane_alias_router())
        .nest("/api/auth/session", routes::session::router())
        .nest("/api/csrf", routes::csrf::router())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            rate_limiter::public_rate_limit_middleware,
        ));

    let public = Router::<AppState>::new()
        .route("/assets/globals.css", get(browser_globals_css))
        .route("/verify-email", get(browser_verify_email_page))
        .nest("/health", routes::health::router())
        .nest("/v1/ses", routes::ses_notifications::router())
        .merge(rate_limited_public)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            ddos::ddos_protection_middleware,
        ));

// ── Authenticated v1 routes ─────────────────────────────
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
        .nest("/v1/billing", routes::billing::router())
        .nest("/v1/campaigns", routes::campaigns::router())
        .nest("/v1/contacts", routes::contacts::router())
        .nest("/v1/lists", routes::lists::router())
        .nest("/v1/dashboard", routes::dashboard::router())
        .nest("/v1/client-errors", routes::client_errors::router())
        .nest("/v1/automations", routes::automations::router())
        .nest("/v1/ai", routes::ai_insights::router())
        .nest("/v1/dedicated-ips", routes::dedicated_ips::router())
        .nest("/v1/account", routes::account::router())
        .nest("/v1/stream", routes::stream_tokens::router())
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
            ddos::ddos_protection_middleware,
        ))
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
    let overload_protection = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(handle_backpressure_error))
        .layer(LoadShedLayer::new())
        .layer(GlobalConcurrencyLimitLayer::new(
            state.config.max_inflight_requests,
        ));

    Router::new()
        .merge(public)
        .merge(authenticated)
        .fallback(fallback_handler)
        .layer(axum::middleware::from_fn(null_byte_check))
        .layer(axum::middleware::from_fn(security_headers))
        .layer(axum::middleware::from_fn(request_logger::request_logger))
        .layer(overload_protection)
// Prometheus request metrics — placed after the router so MatchedPath is
// available from extensions, but before compression/timeout so the
// recorded duration is accurate end-to-end.
        .layer(axum::middleware::from_fn(metrics::metrics_middleware))
        .layer(CompressionLayer::new())
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024))
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

// ─── Security headers ──────────────────────────────────────────

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
static HDR_CSP: HeaderValue =
    HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'");
static HDR_PERMISSIONS_POLICY: HeaderValue =
    HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()");

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
    if !headers.contains_key("Content-Security-Policy") {
        headers.insert("Content-Security-Policy", HDR_CSP.clone());
    }
    headers.insert("Permissions-Policy", HDR_PERMISSIONS_POLICY.clone());
    resp
}

fn generate_csp_nonce() -> String {
    let mut nonce_bytes = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes)
}

fn browser_csp_header(nonce: &str) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "default-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'; img-src 'self' data: https://plausible.apexmail.ee; font-src 'self' data:; manifest-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'nonce-{nonce}'; object-src 'none'"
    ))
    .expect("browser CSP should be valid")
}

fn inject_script_nonce(html: &str, nonce: &str) -> String {
    let lower = html.to_ascii_lowercase();
    let mut output = String::with_capacity(html.len() + (nonce.len() + 9) * 4);
    let mut cursor = 0;

    while let Some(relative_start) = lower[cursor..].find("<script") {
        let start = cursor + relative_start;
        output.push_str(&html[cursor..start]);

        let Some(relative_end) = lower[start..].find('>') else {
            output.push_str(&html[start..]);
            return output;
        };

        let end = start + relative_end;
        let tag = &html[start..=end];
        let lower_tag = &lower[start..=end];

        if lower_tag.starts_with("</script") || lower_tag.contains(" nonce=") {
            output.push_str(tag);
        } else {
            output.push_str(&html[start..end]);
            output.push_str(" nonce=\"");
            output.push_str(nonce);
            output.push_str("\">");
        }

        cursor = end + 1;
    }

    output.push_str(&html[cursor..]);
    output
}

fn browser_html_response(html: String) -> Response {
    let nonce = generate_csp_nonce();
    let html = inject_script_nonce(&html, &nonce);
    let mut response = Html(html).into_response();
    response
        .headers_mut()
        .insert("Content-Security-Policy", browser_csp_header(&nonce));
    response
}

async fn browser_globals_css() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, HeaderValue::from_static("text/css; charset=utf-8"))],
        ui_foundation::GLOBALS_CSS,
    )
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

#[derive(Debug, Deserialize)]
struct BrowserVerifyEmailQuery {
    token: Option<String>,
    email: Option<String>,
}

fn auth_page_error_message(error: &crate::error::ApiError) -> String {
    match error {
        crate::error::ApiError::BadRequest(message)
        | crate::error::ApiError::Unauthorized(message)
        | crate::error::ApiError::Forbidden(message)
        | crate::error::ApiError::NotFound(message)
        | crate::error::ApiError::Conflict(message)
        | crate::error::ApiError::PayloadTooLarge(message)
        | crate::error::ApiError::ServiceUnavailable(message) => message.clone(),
        crate::error::ApiError::Validation(details) => details.join(" "),
        crate::error::ApiError::RateLimited => {
            "Too many verification attempts. Please wait and try again.".into()
        }
        crate::error::ApiError::Timeout => "The verification request timed out. Please try again.".into(),
        crate::error::ApiError::Internal(_) => {
            "We could not verify your email right now. Please try again.".into()
        }
    }
}

async fn browser_verify_email_page(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    Query(params): Query<BrowserVerifyEmailQuery>,
) -> Response {
    let host = headers.get(HOST).and_then(|value| value.to_str().ok());
    if !state.config.is_explicit_web_host(host) {
        return not_found_response();
    }
    let surface = "web";

    let mut query_params: Vec<(&str, String)> = Vec::new();
    if let Some(email) = params.email.as_deref() {
        query_params.push(("email", email.to_owned()));
    }

    if let Some(token) = params.token.as_deref() {
        match routes::auth::verify_email_token(&state, token).await {
            Ok(result) => {
                query_params.push(("status", "success".into()));
                query_params.push(("message", result.message));
            }
            Err(error) => {
                query_params.push(("status", "error".into()));
                query_params.push(("message", auth_page_error_message(&error)));
            }
        }
    }

    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in query_params {
        serializer.append_pair(key, &value);
    }
    let query = serializer.finish();
    let html = ui_router::render_route_with_query(
        surface,
        "/verify-email",
        if query.is_empty() {
            None
        } else {
            Some(query.as_str())
        },
    );

    match html {
        Some(html) => browser_html_response(html),
        None => not_found_response(),
    }
}

fn render_ui_response(config: &Config, headers: &HeaderMap, uri: &Uri, method: &Method) -> Option<Response> {
    if !matches!(method, &Method::GET | &Method::HEAD) {
        return None;
    }

    if uri.path() == "/v1" || uri.path().starts_with("/v1/") {
        return None;
    }

    let host = headers.get(HOST).and_then(|value| value.to_str().ok());
    let surface = config.ui_surface_for_host(host)?;
    let html = ui_router::render_route_with_query(surface, uri.path(), uri.query())?;
    Some(browser_html_response(html))
}

fn not_found_response() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": {
                "code": "NOT_FOUND",
                "message": "the requested endpoint does not exist"
            }
        })),
    )
        .into_response()
}

async fn fallback_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    request: axum::extract::Request,
) -> Response {
    if let Some(response) = render_ui_response(
        &state.config,
        request.headers(),
        request.uri(),
        request.method(),
    ) {
        return response;
    }

    not_found_response()
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{HeaderMap, HeaderValue, Request};
    use deadpool_redis::Config as RedisConfig;
    use ddos_protection::{DdosProtector, ProtectorConfig};
    use sqlx::postgres::PgPoolOptions;
    use std::sync::Arc;
    use std::sync::Once;
    use tokio::sync::Notify;
    use tower::ServiceExt;

    use crate::ses_provider::SesIpProvider;
    use crate::state::AppStateInner;

    async fn response_body_string(resp: Response) -> String {
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(body.to_vec()).unwrap()
    }

    async fn response_json(resp: Response) -> serde_json::Value {
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    fn install_test_metrics_recorder() {
        static INSTALL: Once = Once::new();
        INSTALL.call_once(|| {
            let _ = metrics_exporter_prometheus::PrometheusBuilder::new().install_recorder();
            std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
            std::env::set_var("AWS_ACCESS_KEY_ID", "test");
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        });
    }

    async fn test_app() -> Router {
        let ddos_protector = Arc::new(
            DdosProtector::new(ProtectorConfig::default())
                .await
                .expect("failed to create default ddos protector"),
        );
        test_app_with_ddos(ddos_protector).await
    }

    async fn test_app_with_ddos(ddos_protector: Arc<DdosProtector>) -> Router {
        install_test_metrics_recorder();

        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://apexmail:apexmail@127.0.0.1:5433/apexmail".to_string());
        let db = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy(&database_url)
            .expect("failed to create lazy test database pool");

        let redis_url =
            std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let redis = RedisConfig::from_url(&redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("failed to create lazy test redis pool");

        let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_sesv2::config::Region::new("us-east-1"))
            .load()
            .await;
        let ses_provider = SesIpProvider::new(
            aws_sdk_sesv2::Client::new(&aws_config),
            db.clone(),
            "apexmail".into(),
            "us-east-1".into(),
        );

        build_app(AppStateInner::with_ddos_protector(
            db,
            redis,
            test_config(),
            reqwest::Client::new(),
            ses_provider,
            None,
            ddos_protector,
        ))
    }

    #[test]
    fn test_not_found_response() {
        let resp = not_found_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    fn test_config() -> Config {
        Config {
            port: 3000,
            host: "0.0.0.0".into(),
            base_url: "http://localhost:3000".into(),
            environment: crate::config::Environment::Development,
            db_host: "localhost".into(),
            db_port: 5432,
            db_name: "apexmail".into(),
            db_user: "apexmail".into(),
            db_password: "password".into(),
            db_max_connections: 20,
            redis_host: "localhost".into(),
            redis_port: 6379,
            redis_password: None,
            redis_db: 0,
            redis_pool_max_size: 40,
            jwt_private_key_pem: "BEGIN TEST".into(),
            jwt_public_key_pem: "BEGIN TEST".into(),
            jwt_expiry: Duration::from_secs(86400),
            api_key_hash_secret: "test-api-key-secret-12345678901234567890".into(),
            rate_limit_window_ms: 60000,
            rate_limit_max_requests: 1000,
            max_inflight_requests: 80,
            cors_origins: vec!["*".into()],
            trusted_proxies: vec![],
            ui_web_hosts: vec!["app.apexmail.ee".into(), "127.0.0.1".into()],
            ui_control_plane_hosts: vec!["admin.apexmail.ee".into(), "localhost".into()],
            ui_marketing_hosts: vec!["apexmail.ee".into()],
            ui_marketing_surface: "marketing-zola".into(),
            ui_default_surface: Some("web".into()),
            webhook_signing_secret: "test-webhook-signing-secret-1234567890".into(),
            webhook_timeout_ms: 5000,
            webhook_max_retries: 3,
            idempotency_ttl_seconds: 86400,
            aws_region: "us-east-1".into(),
            ses_ip_pool_prefix: "apexmail".into(),
            ses_default_warmup_days: 14,
            ses_configuration_set: None,
            google_client_id: None,
            google_client_secret: None,
            github_client_id: None,
            github_client_secret: None,
            oauth_redirect_base_url: "http://localhost:3000".into(),
            session_secret: "test-session-secret-1234567890ab".into(),
            impersonation_secret: "test-impersonation-secret-12345".into(),
            csrf_secret: "test-csrf-secret-1234567890abcd".into(),
            control_plane_api_key: None,
            sales_autopilot_base_url: "http://localhost:3010".into(),
            internal_service_token: None,
            tracking_secret_key: "test-tracking-secret-123456789012".into(),
            billing_company_iban: "EE381010220123456789".into(),
            billing_company_phone: "+3721234567".into(),
            metrics_port: 9090,
        }
    }

    #[tokio::test]
    async fn test_public_routes_run_through_ddos_protection() {
        let ddos_protector = Arc::new(
            DdosProtector::new(ProtectorConfig {
                system_cost_capacity: 1020,
                ..ProtectorConfig::default()
            })
                .await
                .expect("failed to create constrained ddos protector"),
        );
        let app = test_app_with_ddos(ddos_protector).await;

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health/live")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let second = app
            .oneshot(
                Request::builder()
                    .uri("/health/live")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[derive(Clone)]
    struct SlowRouteState {
        entered: Arc<Notify>,
        release: Arc<Notify>,
    }

    async fn slow_route_handler(
        axum::extract::State(state): axum::extract::State<SlowRouteState>,
    ) -> &'static str {
        state.entered.notify_one();
        state.release.notified().await;
        "ok"
    }

    #[tokio::test]
    async fn overload_protection_rejects_excess_inflight_requests() {
        let state = SlowRouteState {
            entered: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
        };
        let app = Router::new()
            .route("/slow", get(slow_route_handler))
            .with_state(state.clone())
            .layer(
                ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(handle_backpressure_error))
                    .layer(LoadShedLayer::new())
                    .layer(GlobalConcurrencyLimitLayer::new(1)),
            );

        let first_app = app.clone();
        let first_state = state.clone();
        let first_response = tokio::spawn(async move {
            first_app
                .oneshot(Request::builder().uri("/slow").body(Body::empty()).unwrap())
                .await
                .unwrap()
        });

        first_state.entered.notified().await;

        let overload_response = app
            .oneshot(Request::builder().uri("/slow").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(overload_response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response_json(overload_response).await["error"]["code"], "SERVICE_OVERLOADED");

        state.release.notify_waiters();

        let first_response = first_response.await.unwrap();
        assert_eq!(first_response.status(), StatusCode::OK);
    }

    #[test]
    fn renders_rust_ui_for_known_host_and_route() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("app.apexmail.ee"));
        let uri: Uri = "/login".parse().unwrap();

        let response = render_ui_response(&test_config(), &headers, &uri, &Method::GET)
            .expect("expected ui response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("content-type").unwrap(), "text/html; charset=utf-8");
    }

    #[tokio::test]
    async fn renders_control_plane_sales_for_localhost() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("localhost"));
        let uri: Uri = "/sales".parse().unwrap();

        let response = render_ui_response(&test_config(), &headers, &uri, &Method::GET)
            .expect("expected control-plane sales ui response");
        let body = response_body_string(response).await;

        assert!(body.contains("Operator console for discovery, outreach, and autopilot approvals."));
        assert!(body.contains("Admin API session"));
    }

    #[tokio::test]
    async fn serves_globals_css_asset() {
        let response = test_app()
            .await
            .oneshot(
                Request::builder()
                    .uri("/assets/globals.css")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "text/css; charset=utf-8"
        );

        let body = response_body_string(response).await;
        assert!(body.contains(":root {"));
        assert!(body.contains("font-family: var(--font-sans);"));
    }

    #[test]
    fn unknown_host_without_matching_route_falls_back_to_not_found() {
        let mut config = test_config();
        config.ui_default_surface = None;

        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("api.apexmail.ee"));
        let uri: Uri = "/".parse().unwrap();

        assert!(render_ui_response(&config, &headers, &uri, &Method::GET).is_none());
    }

    #[test]
    fn api_prefixed_paths_never_render_ui_fallback() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("app.apexmail.ee"));
        let uri: Uri = "/v1/missing-route".parse().unwrap();

        assert!(render_ui_response(&test_config(), &headers, &uri, &Method::GET).is_none());
    }

    #[tokio::test]
    async fn render_ui_response_preserves_auth_query_state() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("app.apexmail.ee"));
        let uri: Uri = "/reset-password?token=reset-token-123&email=owner%40apexmail.ee"
            .parse()
            .unwrap();

        let response = render_ui_response(&test_config(), &headers, &uri, &Method::GET)
            .expect("expected reset-password ui response");
        let body = response_body_string(response).await;

        assert!(body.contains("name=\"token\" value=\"reset-token-123\""));
        assert!(body.contains("name=\"email\" value=\"owner@apexmail.ee\""));
    }

    #[test]
    fn test_null_byte_detection() {
        assert!(apexmail_lib::validation::has_null_bytes("hello\0world"));
        assert!(!apexmail_lib::validation::has_null_bytes("hello_world"));
    }

    #[test]
    fn inject_script_nonce_only_touches_opening_script_tags() {
        let html = r#"<html><head><script type="application/ld+json">{}</script><script nonce="keep">ok</script></head></html>"#;

        let updated = inject_script_nonce(html, "nonce-123");

        assert!(updated.contains(r#"<script type="application/ld+json" nonce="nonce-123">"#));
        assert!(updated.contains(r#"<script nonce="keep">ok</script>"#));
        assert_eq!(updated.matches("nonce=").count(), 2);
    }

    #[tokio::test]
    async fn migrated_ui_route_inventory_renders_for_exposed_surfaces() {
        let app = test_app().await;
        let surfaces = [
            ("web", "app.apexmail.ee"),
            ("control-plane", "admin.apexmail.ee"),
            ("marketing-zola", "apexmail.ee"),
        ];

        for (surface, host) in surfaces {
            let routes = ui_foundation::routing::surface_routes(surface);
            assert!(
                !routes.is_empty(),
                "{surface} route inventory unexpectedly empty"
            );

            for route in routes {
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method(Method::GET)
                            .uri(route.path)
                            .header(HOST, host)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();

                assert_eq!(
                    response.status(),
                    StatusCode::OK,
                    "{surface} route {} did not render through the app router",
                    route.path,
                );
                assert_eq!(
                    response.headers().get("content-type").unwrap(),
                    "text/html; charset=utf-8",
                    "{surface} route {} did not return HTML",
                    route.path,
                );
            }
        }
    }

    #[tokio::test]
    async fn auth_session_and_csrf_aliases_return_expected_public_contracts() {
        let app = test_app().await;

        for path in ["/v1/auth/session", "/api/auth/session"] {
            let response = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path} should be reachable");

            let json = response_json(response).await;
            assert_eq!(json["authenticated"], false, "{path} should default to logged-out state");
            assert!(json["impersonation"].is_null(), "{path} should not report impersonation");
        }

        for path in ["/v1/auth/csrf", "/api/csrf"] {
            let response = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path} should issue a CSRF token");

            let set_cookie = response
                .headers()
                .get("set-cookie")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let json = response_json(response).await;

            assert!(set_cookie.contains("csrf_token="), "{path} should set the CSRF cookie");
            assert!(json["token"].as_str().unwrap_or_default().contains('.'));
        }
    }

    #[tokio::test]
    async fn auth_public_routes_validate_inputs_and_render_browser_verify_page() {
        let app = test_app().await;

        let login_response = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"email":"","password":""}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login_response.status(), StatusCode::BAD_REQUEST);
        let login_json = response_json(login_response).await;
        assert_eq!(login_json["error"]["code"], "VALIDATION_ERROR");

        for path in ["/v1/auth/register", "/v1/auth/signup"] {
            let response = app
                .clone()
                .oneshot(
                    Request::post(path)
                        .header("content-type", "application/json")
                        .body(Body::from(
                            r#"{"company_name":"","email":"","name":"","password":"short","plan":"free"}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path} should fail fast on invalid input");
            let json = response_json(response).await;
            assert_eq!(json["error"]["code"], "VALIDATION_ERROR");
        }

        let forgot_response = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/forgot-password")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"email":"invalid"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forgot_response.status(), StatusCode::BAD_REQUEST);
        let forgot_json = response_json(forgot_response).await;
        assert_eq!(forgot_json["error"]["code"], "VALIDATION_ERROR");

        let reset_response = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/reset-password")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"token":"tok_123","email":"owner@example.com","password":"StrongPass123!","confirmPassword":"MismatchPass123!"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reset_response.status(), StatusCode::BAD_REQUEST);
        let reset_json = response_json(reset_response).await;
        assert_eq!(reset_json["error"]["code"], "VALIDATION_ERROR");

        let verify_response = app
            .clone()
            .oneshot(
                Request::get("/verify-email")
                    .header(HOST, "app.apexmail.ee")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verify_response.status(), StatusCode::OK);
        let verify_csp = verify_response
            .headers()
            .get("Content-Security-Policy")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(verify_csp.contains("script-src 'self' 'nonce-"));
        assert!(verify_csp.contains("style-src 'self' 'unsafe-inline'"));
        let verify_body = response_body_string(verify_response).await;
        assert!(verify_body.contains("Check your email"));
        assert!(verify_body.contains("Back to sign in"));

        let verify_unknown_host = app
            .clone()
            .oneshot(
                Request::get("/verify-email")
                    .header(HOST, "unexpected.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verify_unknown_host.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn marketing_fallback_pages_receive_nonce_backed_browser_csp() {
        let app = test_app().await;

        let response = app
            .clone()
            .oneshot(
                Request::get("/")
                    .header(HOST, "apexmail.ee")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let csp = response
            .headers()
            .get("Content-Security-Policy")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(csp.contains("script-src 'self' 'nonce-"));
        assert!(csp.contains("img-src 'self' data: https://plausible.apexmail.ee"));

        let body = response_body_string(response).await;
        assert!(body.contains("<script type=application/ld+json nonce=\""));
        assert!(!body.contains("<script type=application/ld+json>"));
    }

    #[tokio::test]
    async fn api_json_routes_keep_the_default_locked_down_csp() {
        let app = test_app().await;

        let response = app
            .clone()
            .oneshot(Request::get("/v1/auth/session").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("Content-Security-Policy").unwrap(),
            "default-src 'none'; frame-ancestors 'none'"
        );
    }

    #[tokio::test]
    async fn logout_and_post_only_auth_aliases_remain_wired() {
        let app = test_app().await;

        for path in ["/v1/auth/logout", "/api/auth/logout"] {
            let response = app
                .clone()
                .oneshot(Request::post(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT, "{path} should clear the session even without an active cookie");
            let set_cookie = response
                .headers()
                .get("set-cookie")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            assert!(set_cookie.contains("am_session=;"), "{path} should clear the session cookie");
        }

        for path in ["/v1/auth/refresh", "/api/auth/refresh"] {
            let response = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED, "{path} should stay registered as POST-only");
        }
    }

    #[tokio::test]
    async fn cookie_backed_auth_flows_require_csrf_on_unsafe_requests() {
        let app = test_app().await;

        for path in ["/v1/auth/logout", "/api/auth/logout"] {
            let response = app
                .clone()
                .oneshot(
                    Request::post(path)
                        .header("cookie", "am_session=session.jwt")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path} should reject cookie logout without CSRF");
        }

        for path in ["/v1/auth/refresh", "/api/auth/refresh"] {
            let response = app
                .clone()
                .oneshot(
                    Request::post(path)
                        .header("cookie", "am_session=session.jwt")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path} should reject cookie refresh without CSRF");
        }

        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/change-password")
                    .header("cookie", "am_session=session.jwt")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"current_password":"old","new_password":"NewPassword123!"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "/v1/auth/change-password should reject cookie-authenticated writes without CSRF");
    }
}
