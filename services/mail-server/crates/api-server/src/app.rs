//! Application builder — assembles all middleware and routes into an Axum `Router`.

use axum::error_handling::HandleErrorLayer;
use axum::extract::FromRequestParts;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{
    header::{self, ACCEPT, AUTHORIZATION, CONTENT_TYPE, HOST},
    HeaderMap, HeaderValue, Method, StatusCode, Uri,
};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::routing::post;
use axum::{BoxError, Json, Router};
use serde::Deserialize;
use std::path::PathBuf;
use std::time::Duration;
use tower::limit::GlobalConcurrencyLimitLayer;
use tower::load_shed::{error::Overloaded, LoadShedLayer};
use tower::ServiceBuilder;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use ui_foundation::axum_router as ui_router;

use crate::config::Config;
use crate::middleware::{
    auth, ddos, idempotency, metrics, rate_limiter, request_logger, versioning,
};
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

    // Timeouts and transient overload degrade to 503 with a retry hint —
    // never a raw error string or stack trace.
    let timed_out = error.to_string().to_lowercase().contains("timeout")
        || error.to_string().to_lowercase().contains("elapsed");
    if timed_out {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": {
                    "code": "SERVICE_TIMEOUT",
                    "message": "the request timed out — please retry in a moment"
                }
            })),
        )
            .into_response();
    }

    tracing::error!(error = %error, "unexpected backpressure middleware error");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": {
                "code": "SERVICE_OVERLOADED",
                "message": "the service is busy — please retry in a moment"
            }
        })),
    )
        .into_response()
}

// ── Grader route wrapper handlers ──────────────────────────────
// These extract GraderState from AppState and delegate to the
// email-grader crate's transport-agnostic handlers, propagating tenant
// authentication context and the resolved client IP.

async fn grader_check_domain(
    State(state): State<AppState>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<email_grader::DomainCheckRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let gs = match state.grader_state.clone() {
        Some(s) => s,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": { "code": "GRADER_DISABLED", "message": "Email Grader is disabled" }
                })),
            )
        }
    };
    let client_ip_str = crate::middleware::rate_limiter::extract_public_client_ip(
        &headers,
        addr.ip(),
        &state.config.trusted_proxies,
    );
    let client_ip: std::net::IpAddr = client_ip_str.parse().unwrap_or(addr.ip());
    email_grader::routes::check_domain(gs, client_ip, body).await
}

async fn grader_submit_email(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<auth::AuthUser>,
    headers: axum::http::HeaderMap,
    Json(body): Json<email_grader::EmailSubmitRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let gs = match state.grader_state.clone() {
        Some(s) => s,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": { "code": "GRADER_DISABLED", "message": "Email Grader is disabled" }
                })),
            )
        }
    };
    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let auth_ctx = email_grader::GraderAuthContext {
        tenant_id: user.tenant_id.clone(),
        scopes: user.scopes.clone(),
        idempotency_key,
    };
    email_grader::routes::submit_email(gs, auth_ctx, body).await
}

async fn grader_get_result(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<auth::AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> (StatusCode, Json<serde_json::Value>) {
    let gs = match state.grader_state.clone() {
        Some(s) => s,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": { "code": "GRADER_DISABLED", "message": "Email Grader is disabled" }
                })),
            )
        }
    };
    let auth_ctx = email_grader::GraderAuthContext {
        tenant_id: user.tenant_id.clone(),
        scopes: user.scopes.clone(),
        idempotency_key: None,
    };
    email_grader::routes::get_result(gs, auth_ctx, id).await
}

async fn grader_list_results(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<auth::AuthUser>,
    Query(params): Query<email_grader::PaginationParams>,
) -> (StatusCode, Json<serde_json::Value>) {
    let gs = match state.grader_state.clone() {
        Some(s) => s,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": { "code": "GRADER_DISABLED", "message": "Email Grader is disabled" }
                })),
            )
        }
    };
    let auth_ctx = email_grader::GraderAuthContext {
        tenant_id: user.tenant_id.clone(),
        scopes: user.scopes.clone(),
        idempotency_key: None,
    };
    email_grader::routes::list_results(gs, auth_ctx, params).await
}

// ── Inbox Placement route wrapper handlers ─────────────────────
// These extract PlacementState from AppState and delegate to the
// inbox-placement crate's transport-agnostic handlers.

async fn placement_create_test(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<auth::AuthUser>,
    Json(body): Json<inbox_placement::CreateTestRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let ps = match state.placement_state.clone() {
        Some(s) => s,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": { "code": "PLACEMENT_DISABLED", "message": "Inbox Placement is disabled" }
                })),
            )
        }
    };
    inbox_placement::routes::create_placement_test(ps, user.tenant_id, body).await
}

async fn placement_list_tests(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<auth::AuthUser>,
    Query(params): Query<inbox_placement::TestListQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    let ps = match state.placement_state.clone() {
        Some(s) => s,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": { "code": "PLACEMENT_DISABLED", "message": "Inbox Placement is disabled" }
                })),
            )
        }
    };
    inbox_placement::routes::list_placement_tests(
        ps,
        user.tenant_id,
        params.page,
        params.per_page,
        params.status,
    )
    .await
}

async fn placement_get_test(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<auth::AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> (StatusCode, Json<serde_json::Value>) {
    let ps = match state.placement_state.clone() {
        Some(s) => s,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": { "code": "PLACEMENT_DISABLED", "message": "Inbox Placement is disabled" }
                })),
            )
        }
    };
    inbox_placement::routes::get_placement_test(ps, user.tenant_id, id).await
}

async fn placement_get_trends(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<auth::AuthUser>,
    Query(params): Query<inbox_placement::TrendsQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    let ps = match state.placement_state.clone() {
        Some(s) => s,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": { "code": "PLACEMENT_DISABLED", "message": "Inbox Placement is disabled" }
                })),
            )
        }
    };
    inbox_placement::routes::get_placement_trends(ps, user.tenant_id, params.days, params.provider)
        .await
}

async fn placement_list_providers(
    State(state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    let ps = match state.placement_state.clone() {
        Some(s) => s,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": { "code": "PLACEMENT_DISABLED", "message": "Inbox Placement is disabled" }
                })),
            )
        }
    };
    inbox_placement::routes::list_seed_providers(ps).await
}

/// Helper to produce an error JSON tuple (legacy non-grader call sites).
#[expect(
    dead_code,
    reason = "legacy route adapters still use this shape in downstream branches"
)]
fn err_tuple(status: StatusCode, msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({"error": msg})))
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
    let has_wildcard_origin = state.config.cors_origins.iter().any(|origin| origin == "*");
    let origins: Vec<HeaderValue> = state
        .config
        .cors_origins
        .iter()
        .filter(|origin| origin.as_str() != "*")
        .filter_map(|origin| origin.parse::<HeaderValue>().ok())
        .collect();
    let cors = if origins.is_empty() {
        let layer = CorsLayer::new()
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

        if has_wildcard_origin {
            // SECURITY: A wildcard ("*") origin is fundamentally incompatible
            // with credentialed requests. Reflecting any incoming `Origin` while
            // also sending `Access-Control-Allow-Credentials: true` would let
            // *every* site issue authenticated cross-origin calls (session
            // cookies included) against the API. We therefore reflect the
            // origin for unauthenticated/public reads but explicitly DISABLE
            // credentials in this mode. Credentialed cross-origin access is only
            // available when origins are configured explicitly (see below).
            layer
                .allow_origin(AllowOrigin::mirror_request())
                .allow_credentials(false)
        } else {
            // No configured origins: deny all cross-origin requests
            layer
        }
    } else {
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::PATCH,
                Method::OPTIONS,
            ])
            .allow_headers(allowed_headers)
            .allow_credentials(true)
            .max_age(Duration::from_secs(86400))
    };

    // ── Public routes (no auth) ─────────────────────────────
    // credential stuffing and registration spam.
    let rate_limited_public = Router::new()
        .nest("/v1/auth", routes::auth::router())
        .nest("/v1/contact", routes::contact::router())
        .nest("/v1/auth/session", routes::session::router())
        .nest(
            "/v1/auth/forgot-password",
            routes::forgot_password::router(),
        )
        .nest("/v1/auth/sso", routes::sso::router())
        .nest("/v1/auth/csrf", routes::csrf::router())
        .nest("/api/auth", routes::auth::control_plane_alias_router())
        .nest("/api/auth/csrf", routes::csrf::router())
        .nest("/api/auth/session", routes::session::router())
        .nest("/api/csrf", routes::csrf::router())
        .nest("/api/kcaptcha", routes::kiwicaptcha::router())
        .nest("/v1/kcaptcha", routes::kiwicaptcha::router())
        // Zero-JS console form routes (PRG twins). Public auth forms ride
        // the same rate-limited stack as the JSON auth surface.
        .merge(routes::web::public_router(state.clone()))
        // No-JS cookie consent endpoint (marketing banner links here).
        // Same public rate-limit stack = the light per-IP bucketing.
        .merge(routes::web::consent_router())
        // Data-backed SSR detail pages (/domains/{id}, /campaigns/{id}).
        // Browser pages: the handlers resolve the session and redirect
        // anonymous visitors to /login?next=… (same contract as the SSR
        // fallback's auth gate), so they ride the public rate-limit stack.
        .merge(routes::web::detail_router())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            rate_limiter::public_rate_limit_middleware,
        ));

    // ── Marketing static assets ──────────────────────────────
    // Serve the Zola-built marketing public directory (CSS, fonts, images, JS,
    // manifests, sitemap) for hosts that map to the marketing surface. The
    // base directory is overridable via MARKETING_PUBLIC_DIR; the default is
    // resolved relative to the working directory when the api-server binary
    // is launched from the workspace root.
    // Resolve the marketing site's generated public/ directory. The env var
    // wins; otherwise probe candidate paths relative to the CWD and the crate,
    // so the font/favicon/css assets resolve no matter where the binary runs
    // from (dev runs from services/mail-server/, prod from /opt/apexmail).
    let marketing_public = std::env::var("MARKETING_PUBLIC_DIR")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            [
                "apps/marketing-zola/public",
                "../../apps/marketing-zola/public",
                "../../../apps/marketing-zola/public",
                "../../../../apps/marketing-zola/public",
                "/opt/apexmail/apps/marketing-zola/public",
            ]
            .iter()
            .map(PathBuf::from)
            .find(|p| p.join("icon.svg").exists())
        })
        .unwrap_or_else(|| PathBuf::from("apps/marketing-zola/public"));
    let marketing_public = marketing_public.to_string_lossy().to_string();
    let marketing_assets = Router::<AppState>::new()
        .nest_service("/css", ServeDir::new(format!("{marketing_public}/css")))
        .nest_service("/fonts", ServeDir::new(format!("{marketing_public}/fonts")))
        .nest_service(
            "/images",
            ServeDir::new(format!("{marketing_public}/images")),
        )
        .nest_service("/js", ServeDir::new(format!("{marketing_public}/js")))
        .route_service(
            "/manifest.json",
            ServeFile::new(format!("{marketing_public}/manifest.json")),
        )
        .route_service(
            "/icon.svg",
            ServeFile::new(format!("{marketing_public}/icon.svg")),
        )
        .route_service(
            "/favicon.ico",
            ServeFile::new(format!("{marketing_public}/icon.svg")),
        )
        .route_service(
            "/robots.txt",
            ServeFile::new(format!("{marketing_public}/robots.txt")),
        )
        .route_service(
            "/sitemap.xml",
            ServeFile::new(format!("{marketing_public}/sitemap.xml")),
        )
        // Thunderbird / Apple Mail autoconfig — served at the well-known path so
        // clients auto-discover IMAPS (993) + SMTP submission (587) on mail.apexmail.ee
        // without requiring a separate autoconfig.apexmail.ee DNS record.
        .nest_service(
            "/.well-known/autoconfig",
            ServeDir::new(format!("{marketing_public}/.well-known/autoconfig")),
        )
        .route_service(
            "/mail/config-v1.1.xml",
            ServeFile::new(format!(
                "{marketing_public}/.well-known/autoconfig/mail/config-v1.1.xml"
            )),
        );

    let public = Router::<AppState>::new()
        .route("/assets/globals.css", get(browser_globals_css))
        .route("/verify-email", get(browser_verify_email_page))
        // Path-param twin (F5/CWE-598): verification emails link to the
        // root-relative `/verify-email/{token}` so the token never rides
        // the query string. The `?token=` variant above keeps working for
        // already-sent links.
        .route(
            "/verify-email/:token",
            get(browser_verify_email_page_by_path),
        )
        // Permanent redirects for the legacy /legal/* paths (previously
        // interim HTML meta-refresh pages served by ui-foundation).
        .route("/legal/terms", get(legal_terms_redirect))
        .route("/legal/privacy", get(legal_privacy_redirect))
        .nest("/health", routes::health::router())
        .nest("/v1/ses", routes::ses_notifications::router())
        .merge(marketing_assets)
        .merge(rate_limited_public)
        // ── Grader public routes (conditionally added) ──────────
        .merge(if state.grader_state.is_some() {
            Router::<AppState>::new().route("/v1/grader/check", post(grader_check_domain))
        } else {
            Router::<AppState>::new()
        })
        // ── Placement public routes (conditionally added) ───────
        .merge(if state.placement_state.is_some() {
            Router::<AppState>::new().route(
                "/v1/inbox-placement/providers",
                get(placement_list_providers),
            )
        } else {
            Router::<AppState>::new()
        })
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            ddos::ddos_protection_middleware,
        ));

    // ── Control-plane (`/v1/admin/*`) routes ─────────────────
    // The wildcard scope "*" is granted to every tenant's admin/owner so they
    // can manage their OWN tenant's resources on customer routes. That scope
    // must NOT grant control-plane access — otherwise any tenant administrator
    // could operate the entire platform. `require_system_tenant_middleware`
    // rejects any caller whose `tenant_id` is not `system`. It is layered on
    // this dedicated router, which is then merged into `authenticated`, so for
    // an admin request the full stack runs:
    //   ddos → require_auth → rate_limit → idempotency → system_tenant → handler
    // i.e. the gate always runs AFTER `require_auth` has populated `AuthUser`.
    let admin = Router::new()
        .nest("/v1/admin/tenants", routes::admin::tenants::router())
        .nest("/v1/admin/features", routes::admin::features::router())
        .nest("/v1/admin/gdpr", routes::admin::gdpr::router())
        .nest("/v1/admin/secrets", routes::admin::secrets::router())
        .nest("/v1/admin/audit", routes::admin::audit::router())
        .nest("/v1/admin/dashboard", routes::admin::dashboard::router())
        .nest(
            "/v1/admin/compliance",
            routes::admin::compliance_overview::router(),
        )
        .nest("/v1/admin/risk", routes::admin::risk::router())
        .nest("/v1/admin/revenue", routes::admin::revenue::router())
        .nest("/v1/admin/inbox", routes::admin::inbox::router())
        .nest("/v1/admin/calendar", routes::admin::calendar::router())
        .nest("/v1/admin/warmup", routes::admin::warmup::router())
        .nest("/v1/admin/content", routes::admin::content::router())
        .nest("/v1/admin/autopilot", routes::admin::autopilot::router())
        .nest("/v1/admin/operators", routes::admin::operators::router())
        .nest("/v1/admin/proxy", routes::admin::proxy::router())
        .nest("/v1/admin/sales", routes::admin::sales::router())
        .nest("/v1/admin/analytics", routes::admin::analytics::router())
        .nest(
            "/v1/admin/analytics/export",
            routes::admin::analytics_export::router(),
        )
        .nest("/v1/admin/campaigns", routes::admin::campaigns::router())
        .nest("/v1/admin/crm/leads", routes::admin::crm_leads::router())
        .nest(
            "/v1/admin/leads/discovery",
            routes::admin::leads_discovery::router(),
        )
        .nest("/v1/admin/support", routes::admin::support::router())
        .nest(
            "/v1/admin/support/analytics",
            routes::admin::support_analytics::router(),
        )
        .nest(
            "/v1/admin/system/health",
            routes::admin::system_health::router(),
        )
        .nest(
            "/v1/admin/system-sender",
            routes::admin::system_sender::router(),
        )
        .nest("/v1/admin/vat", routes::admin::vat::router())
        // Zero-JS control-plane form routes (/web/admin/*) ride the SAME
        // system-tenant gate as the JSON admin surface: a customer session
        // (any non-system tenant) is rejected before the handler runs.
        .merge(routes::web::admin_router(state.clone()))
        // CP session gate (CRITICAL): human operator sessions must present
        // the dedicated `apexmail_cp_session` cookie (admin/owner role +
        // MFA enabled, idle + absolute timeouts, per-request status
        // recheck, cp_access_log audit trail) on EVERY control-plane
        // route. Layered INSIDE `require_system_tenant_middleware` so the
        // tenant gate stays the first, cheapest rejection; machine
        // credentials (static CP key / system API keys) pass through the
        // gate as non-user identities.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::cp_auth::require_cp_auth,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::require_system_tenant_middleware,
        ));

    // ── Authenticated v1 routes ─────────────────────────────
    let authenticated = Router::new()
        // ── Grader authenticated routes (conditionally added) ──
        .merge(if state.grader_state.is_some() {
            Router::<AppState>::new()
                .route("/v1/grader/submit", post(grader_submit_email))
                .route("/v1/grader/results/:id", get(grader_get_result))
                .route("/v1/grader/history", get(grader_list_results))
        } else {
            Router::<AppState>::new()
        })
        // ── Placement authenticated routes (conditionally added) ─
        .merge(if state.placement_state.is_some() {
            Router::<AppState>::new()
                .route("/v1/inbox-placement/tests", post(placement_create_test))
                .route("/v1/inbox-placement/tests", get(placement_list_tests))
                .route("/v1/inbox-placement/tests/:id", get(placement_get_test))
                .route("/v1/inbox-placement/trends", get(placement_get_trends))
        } else {
            Router::<AppState>::new()
        })
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
        // ── Zero-JS console form routes that require a session ──────
        .merge(routes::web::authenticated_router(state.clone()))
        // Migrated auth routes (require session/auth)
        .nest("/v1/auth/impersonate", routes::impersonate::router())
        .nest("/v1/auth/telemetry", routes::telemetry::router())
        // Control-plane admin routes ride the SAME auth stack so that
        // `require_auth` populates `AuthUser` before the system-tenant gate
        // runs (previously merging `admin` at the top level skipped
        // `require_auth` entirely and 401'd every admin request).
        .merge(admin)
        // Layer order in axum 0.7: the LAST `.layer()` added wraps everything
        // before it, so it is the OUTERMOST layer (runs FIRST on the request
        // path). The required execution order for an authenticated request is:
        //
        //   ddos → require_auth → rate_limit → tenant_binding → idempotency → handler
        //
        //   * ddos first   — cheap load-shedding before expensive auth work.
        //   * require_auth before rate_limit/idempotency — both of those read
        //     `AuthUser` (tenant_id) from request extensions and MUST run only
        //     after auth populates it. Running them before auth (the previous
        //     order) caused every authenticated request to be rate-bucketed as
        //     "anonymous" and allowed cross-tenant `Idempotency-Key` response
        //     leaks.
        //   * tenant_binding after require_auth — it validates the optional
        //     X-Tenant-ID header against the authenticated identity (and DB
        //     membership on mismatch), so it needs `AuthUser` populated. It
        //     no-ops when the header is absent.
        //
        // To get execution order [ddos, require_auth, rate_limit,
        // tenant_binding, idempotency] we add the layers in REVERSE here.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            idempotency::idempotency_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::enforce_tenant_header_binding,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            rate_limiter::rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            ddos::ddos_protection_middleware,
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
        .merge(routes::explorer::router())
        .merge(authenticated)
        .fallback(fallback_handler)
        .layer(axum::middleware::from_fn(null_byte_check))
        .layer(axum::middleware::from_fn(content_type_check))
        .layer(axum::middleware::from_fn(security_headers))
        .layer(axum::middleware::from_fn(request_logger::request_logger))
        // Accept-header API version negotiation (RS-M-10)
        .layer(axum::middleware::from_fn(
            versioning::api_versioning_middleware,
        ))
        .layer(overload_protection)
        // Prometheus request metrics — placed after the router so MatchedPath is
        // available from extensions, but before compression/timeout so the
        // recorded duration is accurate end-to-end.
        .layer(axum::middleware::from_fn(metrics::metrics_middleware))
        .layer(CompressionLayer::new())
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024))
        .layer(RequestBodyLimitLayer::new(
            10 * 1024 * 1024, /* 10 MB general limit */
        ))
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

// ─── Security headers ──────────────────────────────────────────

static HDR_API_VERSION: HeaderValue = HeaderValue::from_static("v1");
static HDR_HSTS: HeaderValue =
    HeaderValue::from_static("max-age=63072000; includeSubDomains; preload");
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
    let path = req.uri().path().to_string();
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert("X-API-Version", HDR_API_VERSION.clone());
    headers.insert("Strict-Transport-Security", HDR_HSTS.clone());
    // Respect a pre-set X-Frame-Options so that embedded widgets can be
    // framed instead of always forcing DENY.
    if !headers.contains_key("X-Frame-Options") {
        headers.insert("X-Frame-Options", HDR_FRAME_OPTIONS.clone());
    }
    headers.insert("X-Content-Type-Options", HDR_CONTENT_TYPE_OPTIONS.clone());
    headers.insert("X-XSS-Protection", HDR_XSS_PROTECTION.clone());
    headers.insert("Referrer-Policy", HDR_REFERRER_POLICY.clone());
    headers.insert("Cache-Control", static_asset_cache_control(&path));
    if !headers.contains_key("Content-Security-Policy") {
        headers.insert("Content-Security-Policy", HDR_CSP.clone());
    }
    headers.insert("Permissions-Policy", HDR_PERMISSIONS_POLICY.clone());
    resp
}

/// Cache policy per request path.
///
/// Everything the api-server serves is either a private console page (never
/// cacheable: `no-store`) or one of the marketing site's static assets.
/// The static assets live at content-hashed or build-stamped URLs and MUST
/// be cacheable — forcing `no-store` onto them made every page load
/// re-download every stylesheet, font, and image. Two tiers:
///
/// - immutable build artifacts (`/css`, `/js`, `/fonts`, `/images`):
///   `public, max-age=31536000, immutable`;
/// - site-level files that change per build but must still be cacheable
///   (`/manifest.json`, `/sitemap.xml`, `/robots.txt`, icons, the SSR
///   pages' `/assets/globals.css`, autoconfig): `public, max-age=3600`
///   (revalidated hourly).
fn static_asset_cache_control(path: &str) -> HeaderValue {
    let immutable = path.starts_with("/css/")
        || path.starts_with("/js/")
        || path.starts_with("/fonts/")
        || path.starts_with("/images/");
    let cacheable_file = matches!(
        path,
        "/manifest.json"
            | "/sitemap.xml"
            | "/robots.txt"
            | "/icon.svg"
            | "/favicon.ico"
            | "/assets/globals.css"
    ) || path.starts_with("/.well-known/")
        || path == "/mail/config-v1.1.xml";
    if immutable {
        HeaderValue::from_static("public, max-age=31536000, immutable")
    } else if cacheable_file {
        HeaderValue::from_static("public, max-age=3600")
    } else {
        HDR_CACHE_CONTROL.clone()
    }
}

fn browser_csp_header() -> HeaderValue {
    let analytics_img_src = std::env::var("ANALYTICS_IMAGE_SRC").ok();
    browser_csp_header_with_sources(analytics_img_src.as_deref())
}

#[allow(dead_code)]
fn browser_csp_header_with_analytics(analytics_img_src: Option<&str>) -> HeaderValue {
    browser_csp_header_with_sources(analytics_img_src)
}

/// The browser surfaces ship ZERO JavaScript: `script-src 'none'` is the
/// strongest possible script policy. Only stylesheet + image + font loads
/// from same-origin (plus an optional HTTPS analytics image source) remain.
fn browser_csp_header_with_sources(analytics_img_src: Option<&str>) -> HeaderValue {
    let analytics_img_src = analytics_img_src
        .map(str::trim)
        .filter(|src| !src.is_empty())
        .filter(|src| src.starts_with("https://"))
        .map(|src| format!(" {src}"))
        .unwrap_or_default();

    HeaderValue::from_str(&format!(
        "default-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'; img-src 'self' data:{analytics_img_src}; font-src 'self' data:; manifest-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; script-src 'none'; frame-src 'none'; object-src 'none'"
    ))
    .expect("browser CSP should be valid")
}

fn browser_html_response(html: String) -> Response {
    // Zero-JS policy: the served document carries NO executable scripts.
    // ui_foundation's render pass strips them for marketing static docs and
    // this final defensive pass guarantees it even for hand-written HTML.
    // The CSP pins `script-src 'none'` so nothing could execute regardless.
    html_response_with_csp(html, browser_csp_header())
}

/// Browser HTML response for campaign/template PREVIEWS (audit F5): the
/// previewed body is user-authored email HTML whose inline `style=`
/// attributes and remote images are the point of the preview, so the page
/// CSP allows inline styles and https/data images — while keeping the
/// zero-JS posture (`script-src 'none'`, scripts stripped) and denying
/// everything else `default-src 'none'` leaves.
pub(crate) fn preview_html_response(html: String) -> Response {
    html_response_with_csp(html, preview_csp_header())
}

fn preview_csp_header() -> HeaderValue {
    HeaderValue::from_static(
        "default-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; img-src https: data:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; style-src-attr 'unsafe-inline'; script-src 'none'; frame-src 'none'; object-src 'none'",
    )
}

fn html_response_with_csp(html: String, csp: HeaderValue) -> Response {
    let html = ui_foundation::axum_router::strip_executable_scripts(&html);
    let mut response = Html(html).into_response();
    response
        .headers_mut()
        .insert("Content-Security-Policy", csp);
    response
}

/// No-JS cookie banner state: when the apexmail_consent cookie (set by
/// GET/POST /consent with Domain=.apexmail.ee) is present, flip the
/// banner's marker attribute to "recorded" so the stylesheet collapses
/// it. This mirrors the marketing container's nginx sub_filter variant
/// (map on $cookie_apexmail_consent) — same cookie, same attribute,
/// same CSS rule — so the banner behaves identically on both serving
/// paths. Non-marketing documents simply do not contain the marker and
/// pass through unchanged.
fn apply_recorded_consent_state(html: String, headers: &HeaderMap) -> String {
    let has_consent = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(routes::web::cookie_header_has_consent)
        .unwrap_or(false);
    if !has_consent {
        return html;
    }
    html.replace(
        "data-consent-state=\"pending\"",
        "data-consent-state=\"recorded\"",
    )
    .replace("data-consent-state=pending", "data-consent-state=recorded")
}

async fn browser_globals_css() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/css; charset=utf-8"),
        )],
        ui_foundation::GLOBALS_CSS,
    )
}

// ─── Legacy /legal/* permanent redirects ───────────────────────

async fn legal_terms_redirect() -> impl IntoResponse {
    (
        StatusCode::MOVED_PERMANENTLY,
        [(header::LOCATION, "/terms")],
    )
}

async fn legal_privacy_redirect() -> impl IntoResponse {
    (
        StatusCode::MOVED_PERMANENTLY,
        [(header::LOCATION, "/privacy")],
    )
}

// ─── Content-Type validation ──────────────────────────────────────

/// Reject POST/PUT/PATCH requests without a valid Content-Type header.
/// This prevents unexpected behavior where Axum's `Json` extractor accepts
/// arbitrary content types and deserializes them as JSON.
async fn content_type_check(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, axum::response::Response> {
    let method = req.method();
    let content_type = req
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Only validate methods that carry a body
    if method == Method::POST || method == Method::PUT || method == Method::PATCH {
        let has_valid_content_type = content_type.starts_with("application/json")
            || content_type.starts_with("multipart/form-data")
            || content_type.starts_with("application/x-www-form-urlencoded")
            || content_type.starts_with("text/plain")
            || content_type.is_empty();

        if !has_valid_content_type {
            return Err((
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                Json(serde_json::json!({
                    "error": {
                        "code": "UNSUPPORTED_MEDIA_TYPE",
                        "message": format!(
                            "Content-Type '{}' is not supported. Use application/json, multipart/form-data, or application/x-www-form-urlencoded",
                            content_type
                        )
                    }
                })),
            )
                .into_response());
        }
    }

    Ok(next.run(req).await)
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
#[serde(deny_unknown_fields)]
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
        crate::error::ApiError::RateLimitedMessage(message) => message.clone(),
        crate::error::ApiError::Timeout => {
            "The verification request timed out. Please try again.".into()
        }
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
    render_browser_verify_email(&state, &headers, params.token, params.email).await
}

/// `GET /verify-email/{token}` — path-param variant of the branded
/// verify-email page. Only the token moves into the path; an optional
/// `?email=` still rides the query for display context.
async fn browser_verify_email_page_by_path(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Query(params): Query<BrowserVerifyEmailQuery>,
) -> Response {
    // The path token wins; a stray `?token=` from an old link is ignored.
    render_browser_verify_email(&state, &headers, Some(token), params.email).await
}

async fn render_browser_verify_email(
    state: &AppState,
    headers: &HeaderMap,
    token: Option<String>,
    email: Option<String>,
) -> Response {
    let host = headers.get(HOST).and_then(|value| value.to_str().ok());
    if !state.config.is_explicit_web_host(host) {
        return branded_not_found(&state.config, host);
    }
    let surface = "web";

    let mut query_params: Vec<(&str, String)> = Vec::new();
    if let Some(email) = email.as_deref() {
        query_params.push(("email", email.to_owned()));
    }

    if let Some(token) = token.as_deref() {
        match routes::auth::verify_email_token(state, token).await {
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
        None,
    );

    match html {
        Some(html) => browser_html_response(html),
        None => not_found_response(),
    }
}

fn render_ui_response(
    config: &Config,
    headers: &HeaderMap,
    uri: &Uri,
    method: &Method,
) -> Option<Response> {
    if !matches!(method, &Method::GET | &Method::HEAD) {
        return None;
    }

    if uri.path() == "/v1" || uri.path().starts_with("/v1/") {
        return None;
    }

    let host = headers.get(HOST).and_then(|value| value.to_str().ok());
    let surface = config.ui_surface_for_host(host)?;
    // Pass CSRF secret so the render pass can sign confirm links and embed
    // hidden _csrf inputs in every POST /web form.
    let csrf_secret = Some(config.csrf_secret.as_str());
    // PRG flash: the signed cookie from the previous POST renders as a
    // banner (then the response clears it).
    let flash = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|cookies| routes::web::decode_flash_from_cookie_header(cookies, &config.csrf_secret))
        .unwrap_or_default();
    // Failed-POST field map (values / per-field errors / reveal-once
    // secrets) decodes here so the re-rendered form is repopulated.
    let field_map = routes::web::decode_form_fields_from_headers(headers, &config.csrf_secret);
    let field_data = field_map.as_ref().map(|map| map.clone().into_view_data());
    // Double-submit CSRF (audit F4): reuse the request's still-valid token
    // so open tabs keep working, else mint one and set the cookie below.
    let form_csrf = routes::web::form_csrf_for_render(headers, config);
    let (html, _embedded_token) = ui_router::render_route_with_form_fields_and_csrf(
        surface,
        uri.path(),
        uri.query(),
        csrf_secret,
        &flash,
        None,
        field_data.as_ref(),
        Some(form_csrf.token.as_str()),
    )?;
    let html = apply_recorded_consent_state(html, headers);
    let mut response = browser_html_response(html);
    append_render_cookies(
        &mut response,
        &form_csrf,
        !flash.is_empty(),
        field_map.is_some(),
        config,
    );
    Some(response)
}

/// Data-aware render: the authenticated browser surfaces load their page
/// data (rows/KPIs) from the database before rendering, so list pages show
/// real records instead of static demo markup. Anonymous requests (and the
/// marketing surface) render exactly as before.
async fn render_ui_response_with_state(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    method: &Method,
) -> Option<Response> {
    if !matches!(method, &Method::GET | &Method::HEAD) {
        return None;
    }

    if uri.path() == "/v1" || uri.path().starts_with("/v1/") {
        return None;
    }

    let host = headers.get(HOST).and_then(|value| value.to_str().ok());
    let surface = state.config.ui_surface_for_host(host)?;
    let csrf_secret = Some(state.config.csrf_secret.as_str());
    let flash = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|cookies| {
            routes::web::decode_flash_from_cookie_header(cookies, &state.config.csrf_secret)
        })
        .unwrap_or_default();
    // Failed-POST field map (values / per-field errors / reveal-once
    // secrets) decodes here so the re-rendered form is repopulated.
    let field_map =
        routes::web::decode_form_fields_from_headers(headers, &state.config.csrf_secret);
    let field_data = field_map.as_ref().map(|map| map.clone().into_view_data());
    // Double-submit CSRF (audit F4): reuse the request's still-valid token
    // so open tabs keep working, else mint one and set the cookie below.
    let form_csrf = routes::web::form_csrf_for_render(headers, &state.config);

    // Control-plane pages (other than the login) are operator-only: a
    // customer session is bounced to the CP login, mirroring the
    // /web/admin/* form gate and require_system_tenant on the JSON side.
    if surface == "control-plane" && !is_cp_public_path(uri.path()) {
        // Fail closed: no resolvable identity ⇒ login redirect, never the
        // static CP page.
        let auth_user = match browser_auth_user(state, headers, uri, method).await {
            Some(user) => user,
            None => return Some(login_redirect_response(uri)),
        };
        if !routes::web::is_system_tenant(state, &auth_user.tenant_id).await {
            tracing::warn!(
                tenant_id = %auth_user.tenant_id,
                path = %uri.path(),
                "non-system session bounced from the control plane"
            );
            return Some(login_redirect_response(uri));
        }
    }

    let route_data = match surface {
        "web" | "control-plane" => {
            let auth_user = browser_auth_user(state, headers, uri, method).await;
            let mut data = routes::web::load_page_data(
                state,
                surface,
                uri.path(),
                uri.query(),
                auth_user.as_ref(),
            )
            .await;
            // Pending MFA setup rides along on the CP security page via its
            // signed cookie (set by POST /web/auth/mfa/setup).
            if surface == "control-plane"
                && matches!(uri.path(), "/cp/security" | "/settings/security")
            {
                if let Some(user_id) = auth_user.as_ref().and_then(|user| user.user_id.clone()) {
                    data.mfa_setup =
                        routes::web::decode_mfa_setup_cookie(headers, &state.config, &user_id);
                }
            }
            Some(data)
        }
        _ => None,
    };

    let (html, _embedded_token) = ui_router::render_route_with_form_fields_and_csrf(
        surface,
        uri.path(),
        uri.query(),
        csrf_secret,
        &flash,
        route_data.as_ref(),
        field_data.as_ref(),
        Some(form_csrf.token.as_str()),
    )?;
    let html = apply_recorded_consent_state(html, headers);
    let mut response = browser_html_response(html);
    append_render_cookies(
        &mut response,
        &form_csrf,
        !flash.is_empty(),
        field_map.is_some(),
        &state.config,
    );
    Some(response)
}

/// Set the response cookies every browser GET render owes:
///
/// - the double-submit `csrf_token` cookie when this render minted a fresh
///   token (reused tokens already have their cookie on the browser);
/// - the flash clear cookie when a flash banner was just rendered;
/// - the form field-map clear cookie when the failed-POST field map was
///   just consumed into the re-rendered form (one PRG round trip).
fn append_render_cookies(
    response: &mut Response,
    form_csrf: &routes::web::FormCsrfToken,
    clear_flash: bool,
    clear_fields: bool,
    config: &Config,
) {
    if form_csrf.minted {
        if let Ok(value) = routes::web::form_csrf_set_cookie(&form_csrf.token, config).parse() {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    if clear_flash {
        if let Ok(value) =
            ui_foundation::flash::flash_clear_cookie(config.environment.is_production()).parse()
        {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    if clear_fields {
        if let Ok(value) =
            routes::web::form_fields_clear_cookie(config.environment.is_production()).parse()
        {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
}

/// CP paths reachable without a system-tenant session.
fn is_cp_public_path(path: &str) -> bool {
    path == "/login" || path == "/login/" || path == "/not-found"
}

/// Resolve the browser request's `AuthUser` (session cookie/API key), if
/// authenticated — the data loader needs the tenant id and user id.
async fn browser_auth_user(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    method: &Method,
) -> Option<auth::AuthUser> {
    let mut request_builder = axum::http::Request::builder()
        .method(method.clone())
        .uri(uri.clone());
    for (name, value) in headers {
        request_builder = request_builder.header(name, value);
    }
    let request = request_builder.body(axum::body::Body::empty()).ok()?;
    let (mut parts, _) = request.into_parts();
    auth::AuthUser::from_request_parts(&mut parts, state)
        .await
        .ok()
}

fn ui_route_requires_auth(surface: &str, path: &str) -> bool {
    if let Some(auth_required) = ui_foundation::routing::auth_required(surface, path) {
        return auth_required;
    }

    let matches_manifest_pattern = ui_foundation::routing::surface_routes(surface)
        .into_iter()
        .filter(|route| route.auth_required)
        .filter_map(|route| route.canonical_pattern)
        .any(|pattern| ui_route_pattern_matches(pattern, path));
    if matches_manifest_pattern {
        return true;
    }

    // Default-protect authenticated areas: any control-plane `/cp*` path or
    // web `/inbox-placement*` path that is missing from the manifest must
    // still redirect unauthenticated visitors to login. Failing OPEN here
    // would let new (or forgotten) operator/placement routes render for
    // anonymous users. The same holds for the web console's dynamic detail
    // and editor routes (`/lists/{id}`, `/templates/{id}/edit`) that the
    // fallback renders directly but the manifest does not enumerate — an
    // anonymous GET there previously fell through to the static demo page
    // (audit F3) instead of the documented 303 `/login?next=…` contract.
    match surface {
        "control-plane" => path == "/cp" || path.starts_with("/cp/"),
        "web" => {
            path == "/inbox-placement"
                || path.starts_with("/inbox-placement/")
                || path.starts_with("/lists/")
                || path.starts_with("/templates/")
        }
        _ => false,
    }
}

fn ui_route_pattern_matches(pattern: &str, path: &str) -> bool {
    let pattern_segments: Vec<&str> = pattern
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let path_segments: Vec<&str> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();

    pattern_segments.len() == path_segments.len()
        && pattern_segments.iter().zip(path_segments.iter()).all(
            |(pattern_segment, path_segment)| {
                (pattern_segment.starts_with('[') && pattern_segment.ends_with(']'))
                    || pattern_segment == path_segment
            },
        )
}

async fn browser_request_is_authenticated(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    method: &Method,
) -> bool {
    let mut request_builder = axum::http::Request::builder()
        .method(method.clone())
        .uri(uri.clone());

    for (name, value) in headers {
        request_builder = request_builder.header(name, value);
    }

    let Ok(request) = request_builder.body(axum::body::Body::empty()) else {
        return false;
    };
    let (mut parts, _) = request.into_parts();
    auth::AuthUser::from_request_parts(&mut parts, state)
        .await
        .is_ok()
}

fn login_redirect_response(uri: &Uri) -> Response {
    let next_path = uri
        .path_and_query()
        .map(|path_and_query| path_and_query.as_str())
        .unwrap_or(uri.path());
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("next", next_path);
    let location = format!("/login?{}", serializer.finish());

    (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response()
}

async fn ui_auth_redirect_if_required(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    method: &Method,
) -> Option<Response> {
    if !matches!(method, &Method::GET | &Method::HEAD) {
        return None;
    }

    if uri.path() == "/v1" || uri.path().starts_with("/v1/") {
        return None;
    }

    let host = headers.get(HOST).and_then(|value| value.to_str().ok());
    let surface = state.config.ui_surface_for_host(host)?;
    if !ui_route_requires_auth(surface, uri.path()) {
        return None;
    }

    if browser_request_is_authenticated(state, headers, uri, method).await {
        None
    } else {
        Some(login_redirect_response(uri))
    }
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
    let path = request.uri().path();
    let method = request.method().clone();

    // Serve static assets that the SSR pages reference
    if method == axum::http::Method::GET {
        // Favicon and apple-icon requests — return empty 204 to avoid JSON NOT_FOUND
        if path.starts_with("/favicon")
            || path.starts_with("/apple-icon")
            || path.starts_with("/android-icon")
            || path == "/favicon.ico"
        {
            return StatusCode::NO_CONTENT.into_response();
        }
        // ms-application TileImage requests
        if path.starts_with("/assets/img/") || path.ends_with(".png") || path.ends_with(".ico") {
            return StatusCode::NO_CONTENT.into_response();
        }
    }

    if let Some(response) =
        ui_auth_redirect_if_required(&state, request.headers(), request.uri(), request.method())
            .await
    {
        return response;
    }

    // Data-aware render first (authenticated pages load real rows); the
    // sync, database-free render remains the fallback.
    if let Some(response) =
        render_ui_response_with_state(&state, request.headers(), request.uri(), request.method())
            .await
    {
        return response;
    }
    if let Some(response) = render_ui_response(
        &state.config,
        request.headers(),
        request.uri(),
        request.method(),
    ) {
        return response;
    }

    // For API paths (starting with /v1/ or /api/), return JSON NOT_FOUND
    if path.starts_with("/v1/") || path.starts_with("/api/") {
        return not_found_response();
    }

    // Browser surfaces get the branded, script-free 404 page.
    branded_not_found(
        &state.config,
        request.headers().get(HOST).and_then(|v| v.to_str().ok()),
    )
}

/// Branded, zero-JS 404 page: ui-foundation's not-found contract for the
/// matching surface, with navigation back to safety.
fn branded_not_found(config: &Config, host: Option<&str>) -> Response {
    let surface = config
        .ui_surface_for_host(host)
        .or(config.ui_default_surface.as_deref())
        .unwrap_or("web");
    let inner = match surface {
        "control-plane" => ui_foundation::leptos_views::control_plane_not_found_page(),
        "marketing" | "marketing-zola" => ui_foundation::leptos_views::marketing_home_page(),
        _ => ui_foundation::leptos_views::web_not_found_page(),
    };
    let page = format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Page Not Found — ApexMail</title><link rel=\"stylesheet\" href=\"/assets/globals.css\"></head><body class=\"antialiased bg-background text-surface-950\">{}</body></html>",
        inner,
    );
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8".to_string())],
        page,
    )
        .into_response()
}

// ─── Tests ─────────────────────────────────────────────────────

/// Shared test fixtures (cfg(test)): one Config constructor for every
/// in-crate test module.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::state::AppStateInner;
    use std::sync::Arc;

    pub(crate) fn test_config() -> Config {
        crate::app::tests::test_config_impl()
    }

    /// A real AppState over a caller-provided pool (per-test fixture DBs),
    /// with Redis from TEST_REDIS_URL when reachable and a dead-port pool
    /// otherwise — handlers that hard-require Redis gate themselves in
    /// their tests. Shared by handler-level tests across route modules.
    pub(crate) async fn test_state_over(db: sqlx::PgPool) -> AppState {
        test_state_over_with_config(db, test_config()).await
    }

    /// [`test_state_over`] with a caller-supplied Config (e.g. a real RSA
    /// signing pair for JWT round-trips).
    pub(crate) async fn test_state_over_with_config(db: sqlx::PgPool, config: Config) -> AppState {
        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(|| {
            let _ = metrics_exporter_prometheus::PrometheusBuilder::new().install_recorder();
            std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
            std::env::set_var("AWS_ACCESS_KEY_ID", "test");
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        });
        let redis_url = std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "redis://127.0.0.1:1".into());
        let redis = deadpool_redis::Config::from_url(&redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("lazy redis pool");
        let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_sesv2::config::Region::new("us-east-1"))
            .load()
            .await;
        let ses_provider = Arc::new(crate::ses_provider::SesIpProvider::new(
            aws_sdk_sesv2::Client::new(&aws_config),
            db.clone(),
            "apexmail".into(),
            "us-east-1".into(),
        ));
        AppStateInner::with_ddos_protector(
            db.clone(),
            apexmail_db::pool::PoolPair {
                rw: db.clone(),
                ro: db,
            },
            redis,
            config,
            reqwest::Client::new(),
            (*ses_provider).clone(),
            None,
            Arc::new(
                ddos_protection::DdosProtector::new(ddos_protection::ProtectorConfig::default())
                    .await
                    .expect("ddos protector"),
            ),
            None,
            None,
            crate::resilience::ResilientClient::new_from_config(&test_config()),
        )
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{HeaderMap, HeaderValue, Request};
    use ddos_protection::{DdosProtector, ProtectorConfig};
    use deadpool_redis::Config as RedisConfig;
    use sqlx::postgres::PgPoolOptions;
    use std::sync::Arc;
    use std::sync::Once;
    use tokio::sync::Notify;
    use tower::ServiceExt;

    use crate::resilience::ResilientClient;

    #[allow(dead_code)]
    fn test_config() -> Config {
        test_config_impl()
    }

    use crate::ses_provider::SesIpProvider;
    use crate::state::AppStateInner;

    /// CSRF secret used by `test_config()` — must match the value in that function.
    const TEST_CSRF_SECRET: &str = "test-csrf-secret-1234567890abcd";

    /// Generate a valid CSRF token for integration tests using the test secret.
    fn test_csrf_token() -> String {
        ui_foundation::csrf::generate_csrf_token(TEST_CSRF_SECRET)
    }

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
        let state = test_state().await;
        build_app(AppStateInner::with_ddos_protector(
            state.db.clone(),
            apexmail_db::pool::PoolPair {
                rw: state.db.clone(),
                ro: state.db.clone(),
            },
            state.redis.clone(),
            test_config(),
            reqwest::Client::new(),
            (*state.ses_provider).clone(),
            None,
            ddos_protector,
            None, // grader_state
            None, // placement_state
            ResilientClient::new_from_config(&test_config()),
        ))
    }

    /// Minimal AppState for calling state-driven helpers (the SSR data
    /// loader) directly in tests.
    struct TestState {
        db: sqlx::PgPool,
        redis: deadpool_redis::Pool,
        ses_provider: Arc<SesIpProvider>,
        // Fixture holder only: the config is never read through TestState,
        // but constructing it validates the Config wiring.
        #[allow(dead_code)]
        config: Config,
    }

    impl std::ops::Deref for TestState {
        type Target = AppStateInner;

        fn deref(&self) -> &Self::Target {
            unreachable!("TestState is a fixture holder, not an AppState")
        }
    }

    async fn test_state() -> TestState {
        install_test_metrics_recorder();

        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://apexmail:apexmail@127.0.0.1:5433/apexmail".to_string());
        let db = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy(&database_url)
            .expect("failed to create lazy test database pool");

        // F6: never default to the ambient 6379 — a brew Redis there must
        // not be probed by tests that did not opt in via TEST_REDIS_URL.
        // Port 1 is the same deterministic dead-end the CI pipeline pins.
        let redis_url =
            std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:1".into());
        let redis = RedisConfig::from_url(&redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("failed to create lazy test redis pool");

        let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_sesv2::config::Region::new("us-east-1"))
            .load()
            .await;
        let ses_provider = Arc::new(SesIpProvider::new(
            aws_sdk_sesv2::Client::new(&aws_config),
            db.clone(),
            "apexmail".into(),
            "us-east-1".into(),
        ));

        TestState {
            db,
            redis,
            ses_provider,
            config: test_config(),
        }
    }

    /// DB presence probe for conditional tests: the suite must stay green
    /// on machines without a local Postgres, while still exercising the
    /// SQL paths where one exists (TEST_DATABASE_URL or the dev default).
    async fn test_db_reachable(db: &sqlx::PgPool) -> bool {
        matches!(
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(db),
            )
            .await,
            Ok(Ok(1))
        )
    }

    /// A real AppState (the same shape test_app builds) for calling the
    /// SSR data loader directly.
    async fn test_state_app() -> AppState {
        let fixture = test_state().await;
        AppStateInner::with_ddos_protector(
            fixture.db.clone(),
            apexmail_db::pool::PoolPair {
                rw: fixture.db.clone(),
                ro: fixture.db.clone(),
            },
            fixture.redis.clone(),
            test_config(),
            reqwest::Client::new(),
            (*fixture.ses_provider).clone(),
            None,
            Arc::new(
                DdosProtector::new(ProtectorConfig::default())
                    .await
                    .expect("failed to create default ddos protector"),
            ),
            None,
            None,
            ResilientClient::new_from_config(&test_config()),
        )
    }

    #[test]
    fn test_not_found_response() {
        let resp = not_found_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    pub(crate) fn test_config_impl() -> Config {
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
            api_replica_count: 1,
            db_cluster_connection_budget: None,
            expected_replica_count: 3,
            statement_cache_capacity: 500,
            query_timeout_seconds: 30,
            database_replica_url: None,
            redis_host: "localhost".into(),
            redis_port: 6379,
            redis_password: None,
            redis_db: 0,
            redis_pool_max_size: 40,
            jwt_private_key_pem: "BEGIN TEST".into(),
            jwt_public_key_pem: "BEGIN TEST".into(),
            jwt_previous_public_keys_pem: vec![],
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
            public_rate_limit_enabled: false,
            control_plane_api_key: None,
            sales_autopilot_base_url: "http://localhost:3010".into(),
            internal_service_token: None,
            cp_auth: crate::config::CpAuthConfig {
                allowed_ips: vec![],
                session_secret: "test-cp-session-secret-1234567890".into(),
                session_idle_timeout_secs: 900,
                session_absolute_timeout_secs: 14400,
            },
            tracking_secret_key: "test-tracking-secret-123456789012".into(),
            billing_company_iban: "EE381010220123456789".into(),
            billing_company_phone: "+3721234567".into(),
            metrics_port: 9090,
            grader_enabled: false,
            grader_rate_limit: 10,
            grader_rate_window_seconds: 60,
            grader_cache_ttl_seconds: 300,
            grader_max_body_size: 1048576,

            placement_enabled: false,
            placement_polling_interval_secs: 60,
            placement_max_polling_attempts: 10,
            placement_max_seeds_per_test: 50,
            placement_max_tests_per_hour: 5,
            placement_imap_timeout_secs: 30,
            placement_encrypt_passwords: true,
            placement_encryption_secret: "test-placement-encryption-secret".into(),

            kiwi_enabled: false,
            kiwi_secret_key: "dev".into(),
            kiwi_algorithm: kiwicaptcha::PoWAlgorithm::Sha256,
            kiwi_argon_m_kib: 0,
            kiwi_argon2_difficulty_bits: 8,
            kiwi_argon_t: 2,
            kiwi_argon_p: 1,
            kiwi_difficulty_bits: 16,
            kiwi_challenge_ttl_secs: 120,
            kiwi_min_duration_ms: None,
            kiwi_enforce_telemetry: true,
            kiwi_argon2_max_concurrent: 2,
            kiwi_auto_tune: false,
            kiwi_auto_tune_min_bits: 10,
            kiwi_auto_tune_max_bits: 20,
            http_client_timeout_secs: 30,
            internal_tls_enabled: false,
            internal_tls_ca_cert_path: None,
            internal_tls_client_cert_path: None,
            internal_tls_client_key_path: None,
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
        assert_eq!(
            response_json(overload_response).await["error"]["code"],
            "SERVICE_OVERLOADED"
        );

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
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/html; charset=utf-8"
        );
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
        assert!(body.contains("Same-origin operator session"));
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
        let compact_body = body.replace(' ', "");
        assert!(compact_body.contains(":root{"));
        assert!(compact_body.contains("font-family:var(--font-sans)"));
    }

    #[tokio::test]
    async fn console_js_asset_is_gone_and_csp_is_script_src_none() {
        let app = test_app().await;

        // The zero-JS console deleted /assets/console.js entirely.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/assets/console.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Every browser-served HTML response pins script-src 'none'.
        let page = app
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .header(HOST, "app.apexmail.ee")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let csp = page
            .headers()
            .get("Content-Security-Policy")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(csp.contains("script-src 'none'"), "CSP was: {csp}");
        let body = response_body_string(page).await;
        assert!(
            !body.contains("<script"),
            "rendered page must contain no scripts"
        );
    }

    #[tokio::test]
    async fn branded_html_404_for_unknown_browser_routes() {
        let app = test_app().await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/definitely-not-a-page")
                    .header(HOST, "app.apexmail.ee")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/html; charset=utf-8"
        );
        let body = response_body_string(response).await;
        assert!(body.contains("404"));
        assert!(body.contains("Go Home"));
        assert!(!body.contains("<script"));
    }

    #[tokio::test]
    async fn web_form_login_rejects_bad_csrf_with_flash_redirect() {
        let app = test_app().await;
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/web/auth/login")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header(HOST, "app.apexmail.ee")
                    .body(Body::from("email=ops@apexmail.ee&password=x&_csrf=bad"))
                    .unwrap(),
            )
            .await
            .unwrap();
        // PRG: 303 back to the login page, never a 403 JSON dump.
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/login");
        let set_cookie = response
            .headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            set_cookie.contains("apexmail_flash="),
            "flash cookie missing"
        );
        // The flash payload is signed and decodes to a friendly message.
        let flash =
            routes::web::decode_flash_from_cookie_header(&set_cookie, &test_config().csrf_secret);
        assert!(!flash.is_empty());
        assert_eq!(flash[0].kind, ui_foundation::flash::FlashKind::Error);
        assert!(flash[0].text.contains("expired"));
    }

    #[tokio::test]
    async fn consent_endpoint_records_choice_and_redirects_safely() {
        let app = test_app().await;

        // GET with the banner's exact link shape (percent-encoded return_to).
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/consent?choice=all&return_to=https%3A%2F%2Fapexmail.ee%2Fpricing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "https://apexmail.ee/pricing"
        );
        let set_cookie = response
            .headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            set_cookie.starts_with("apexmail_consent=all;"),
            "{set_cookie}"
        );
        assert!(set_cookie.contains("Domain=.apexmail.ee"));
        assert!(set_cookie.contains("Max-Age=31536000"));
        assert!(set_cookie.contains("HttpOnly"));

        // Open redirect: off-family return_to falls back to "/" (consent is
        // still recorded — the redirect target is what must be safe).
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/consent?choice=all&return_to=https%3A%2F%2Fevil.example%2Ftrap")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/");

        // POST form twin: necessary-only records the distinct value.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/consent")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("choice=necessary&return_to=/pricing"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/pricing"
        );
        let set_cookie = response
            .headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            set_cookie.starts_with("apexmail_consent=necessary;"),
            "{set_cookie}"
        );

        // Unknown choice: redirect WITHOUT writing any cookie (the banner
        // stays pending instead of silently downgrading recorded consent).
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/consent?choice=everything&return_to=/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        assert!(response.headers().get("set-cookie").is_none());
    }

    #[tokio::test]
    async fn marketing_page_hides_banner_when_consent_cookie_present() {
        if !ui_foundation::MARKETING_PUBLIC_BUILT {
            // F5: bare checkouts embed placeholder pages (no consent banner
            // markup); the assertion needs the real Zola build output.
            eprintln!("skipping: marketing site not built (placeholder pages embedded)");
            return;
        }
        let app = test_app().await;

        // Fresh visitor: banner pending (visible).
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(HOST, "apexmail.ee")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_body_string(response).await;
        assert!(
            body.contains("data-consent-state=pending")
                || body.contains("data-consent-state=\"pending\""),
            "fresh visitor must see the pending banner"
        );

        // Consent recorded: the api-server flips the same attribute the
        // marketing container's nginx sub_filter variant flips.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(HOST, "apexmail.ee")
                    .header(header::COOKIE, "apexmail_consent=necessary")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_body_string(response).await;
        assert!(
            body.contains("data-consent-state=recorded")
                || body.contains("data-consent-state=\"recorded\""),
            "recorded consent must flip the banner state server-side"
        );
        assert!(!body.contains("data-consent-state=pending"));

        // An unrelated cookie must NOT flip the state.
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(HOST, "apexmail.ee")
                    .header(header::COOKIE, "session=abc")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = response_body_string(response).await;
        assert!(
            body.contains("data-consent-state=pending")
                || body.contains("data-consent-state=\"pending\""),
            "unrelated cookies must leave the banner pending"
        );
    }

    #[tokio::test]
    async fn legacy_legal_paths_redirect_permanently() {
        for (legacy, canonical) in [("/legal/terms", "/terms"), ("/legal/privacy", "/privacy")] {
            let response = test_app()
                .await
                .oneshot(Request::builder().uri(legacy).body(Body::empty()).unwrap())
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
            assert_eq!(response.headers().get(header::LOCATION).unwrap(), canonical);
        }
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
    async fn unauthenticated_protected_ui_routes_redirect_to_login() {
        let app = test_app().await;
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/campaigns?status=draft")
                    .header(HOST, "app.apexmail.ee")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/login?next=%2Fcampaigns%3Fstatus%3Ddraft"
        );
    }

    #[test]
    fn dynamic_ui_routes_match_auth_manifest_patterns() {
        assert!(ui_route_requires_auth("web", "/campaigns/real-campaign-id"));
        assert!(ui_route_requires_auth(
            "web",
            "/campaigns/real-campaign-id/edit"
        ));
        assert!(!ui_route_requires_auth("web", "/login"));
    }

    #[test]
    fn inbox_placement_and_cp_routes_require_auth_by_default() {
        // Manifest entries for the known routes...
        for path in [
            "/inbox-placement",
            "/inbox-placement/new",
            "/inbox-placement/t_1",
        ] {
            assert!(
                ui_route_requires_auth("web", path),
                "web {path} must require auth"
            );
        }
        for path in [
            "/cp",
            "/cp/tenants",
            "/cp/audit",
            "/cp/sales",
            "/cp/infrastructure",
            "/cp/security",
        ] {
            assert!(
                ui_route_requires_auth("control-plane", path),
                "control-plane {path} must require auth"
            );
        }
        // ...and the default-protect fallback for paths NOT in the manifest
        // (new/forgotten operator or placement routes must never fail open).
        assert!(ui_route_requires_auth(
            "web",
            "/inbox-placement/t_not-in-manifest"
        ));
        assert!(ui_route_requires_auth(
            "control-plane",
            "/cp/some-future-page"
        ));
        // Audit F3: the fallback-rendered dynamic console routes (list
        // detail/edit, template editor) are authenticated pages the
        // manifest does not enumerate — anonymous GETs previously fell
        // through to the static demo data instead of the 303 login
        // contract.
        assert!(ui_route_requires_auth("web", "/lists/l_vip"));
        assert!(ui_route_requires_auth("web", "/lists/l_vip/edit"));
        assert!(ui_route_requires_auth("web", "/templates/t_1/edit"));
        // Unrelated unknown web routes still render anonymously (404/public).
        assert!(!ui_route_requires_auth("web", "/definitely-not-protected"));
        // The marketing-zola /inbox-placement marketing page stays public.
        assert!(!ui_route_requires_auth(
            "marketing-zola",
            "/inbox-placement"
        ));
    }

    #[tokio::test]
    async fn anonymous_dynamic_console_pages_redirect_to_login() {
        // Audit F3 (end to end): every fallback-rendered authenticated web
        // page bounces anonymous visitors with the documented 303
        // `/login?next=…` — never the static demo page.
        let app = test_app().await;
        for path in ["/lists/l_vip", "/lists/l_vip/edit", "/templates/t_1/edit"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri(path)
                        .header(HOST, "app.apexmail.ee")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::SEE_OTHER,
                "{path} must redirect anonymous visitors to login"
            );
            let location = response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            assert!(
                location.starts_with("/login?next="),
                "{path} redirected to {location} instead of /login?next=…"
            );
        }
    }

    #[test]
    fn preview_csp_allows_styles_and_images_but_no_scripts() {
        // Audit F5: previews must render their inline styles and remote
        // images, while keeping the zero-JS posture.
        let csp_value = preview_csp_header();
        let csp = csp_value.to_str().unwrap();
        assert!(csp.contains("style-src 'self' 'unsafe-inline'"));
        assert!(csp.contains("img-src https: data:"));
        assert!(csp.contains("script-src 'none'"));
        assert!(csp.contains("default-src 'none'"));
    }

    #[tokio::test]
    async fn browser_render_mints_the_double_submit_csrf_pair() {
        // Audit F4: the rendered page's hidden `_csrf` input must match the
        // `csrf_token` cookie minted on the same response.
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("app.apexmail.ee"));
        let uri: Uri = "/login".parse().unwrap();

        let response =
            render_ui_response(&test_config(), &headers, &uri, &Method::GET).expect("renders");
        let set_cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let cookie_token = set_cookie
            .split(';')
            .next()
            .and_then(|pair| pair.strip_prefix("csrf_token="))
            .expect("the render mints the csrf_token cookie")
            .to_string();
        assert!(set_cookie.contains("HttpOnly"));

        let body = response_body_string(response).await;
        assert!(
            body.contains("_csrf") && body.contains(&format!("value=\"{cookie_token}\"")),
            "the hidden _csrf input must carry the cookie-matching token"
        );

        // A still-valid cookie on the NEXT request is reused (open tabs keep
        // working) instead of being rotated.
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("app.apexmail.ee"));
        headers.insert(
            header::COOKIE,
            format!("csrf_token={cookie_token}").parse().unwrap(),
        );
        let response =
            render_ui_response(&test_config(), &headers, &uri, &Method::GET).expect("renders");
        assert!(
            response.headers().get(header::SET_COOKIE).is_none(),
            "a reused token must not re-set the cookie"
        );
        let body = response_body_string(response).await;
        assert!(
            body.contains("_csrf") && body.contains(&format!("value=\"{cookie_token}\"")),
            "the reused token is the one embedded in the page"
        );
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

    /// The nonce/signature script machinery was removed with the zero-JS
    /// migration: nothing in the app should reference it again.
    #[test]
    fn no_script_nonce_machinery_remains() {
        let source = include_str!("app.rs");
        // Tokens are concatenated so this test's own source does not
        // contain the names it guards against.
        for forbidden in [
            ["inject_script", "_nonce"].concat(),
            ["inject_style", "_nonce"].concat(),
            ["KNOWN_SCRIPT", "_SIGNATURES"].concat(),
            ["KNOWN_SCRIPT", "_SRCS"].concat(),
            ["generate_csp", "_nonce"].concat(),
        ] {
            assert!(
                !source.contains(forbidden.as_str()),
                "dead JS machinery re-introduced: {forbidden}"
            );
        }
    }

    #[test]
    fn test_null_byte_detection() {
        assert!(apexmail_lib::validation::has_null_bytes("hello\0world"));
        assert!(!apexmail_lib::validation::has_null_bytes("hello_world"));
    }

    /// Unit-level pin of the cache tiers: immutable build artifacts get a
    /// one-year immutable cache; per-build site files get an hour; every
    /// other path (console pages, API responses) stays `no-store`.
    #[test]
    fn static_asset_cache_control_tiers() {
        for immutable in [
            "/css/styles.css",
            "/js/none.js",
            "/fonts/Inter.woff2",
            "/images/logo.svg",
        ] {
            assert_eq!(
                static_asset_cache_control(immutable),
                "public, max-age=31536000, immutable",
                "{immutable} must be immutably cacheable"
            );
        }
        for cacheable in [
            "/manifest.json",
            "/sitemap.xml",
            "/robots.txt",
            "/icon.svg",
            "/favicon.ico",
            "/.well-known/autoconfig/mail/config-v1.1.xml",
            "/mail/config-v1.1.xml",
        ] {
            assert_eq!(
                static_asset_cache_control(cacheable),
                "public, max-age=3600",
                "{cacheable} must be cacheable"
            );
        }
        for private in [
            "/login",
            "/dashboard",
            "/v1/messages",
            "/api/csrf/token",
            "/",
        ] {
            assert_eq!(
                static_asset_cache_control(private),
                "no-store, no-cache, must-revalidate",
                "{private} must stay no-store"
            );
        }
    }

    /// End-to-end: the security middleware must NOT force `no-store` onto
    /// the marketing static assets, while console pages keep it.
    #[tokio::test]
    async fn marketing_static_assets_are_cacheable_but_pages_are_not() {
        let app = test_app().await;

        let asset = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/css/styles.css")
                    .header(HOST, "apexmail.ee")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let cache = asset
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert_eq!(cache, "public, max-age=31536000, immutable");

        let sitemap = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/sitemap.xml")
                    .header(HOST, "apexmail.ee")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let cache = sitemap
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert_eq!(cache, "public, max-age=3600");

        let page = app
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .header(HOST, "app.apexmail.ee")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let cache = page
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert_eq!(cache, "no-store, no-cache, must-revalidate");
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

                if route.auth_required {
                    assert_eq!(
                        response.status(),
                        StatusCode::SEE_OTHER,
                        "{surface} route {} should require a browser session",
                        route.path,
                    );
                    assert!(
                        response
                            .headers()
                            .get(header::LOCATION)
                            .and_then(|value| value.to_str().ok())
                            .is_some_and(|location| location.starts_with("/login?next=")),
                        "{surface} route {} did not redirect to login",
                        route.path,
                    );
                } else {
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
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "{path} should be reachable"
            );

            let json = response_json(response).await;
            assert_eq!(
                json["authenticated"], false,
                "{path} should default to logged-out state"
            );
            assert!(
                json["impersonation"].is_null(),
                "{path} should not report impersonation"
            );
        }

        for path in ["/v1/auth/csrf", "/api/csrf"] {
            let response = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "{path} should issue a CSRF token"
            );

            let set_cookie = response
                .headers()
                .get("set-cookie")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let json = response_json(response).await;

            assert!(
                set_cookie.contains("csrf_token="),
                "{path} should set the CSRF cookie"
            );
            assert!(json["token"].as_str().unwrap_or_default().contains('.'));
        }
    }

    #[tokio::test]
    async fn auth_public_routes_validate_inputs_and_render_browser_verify_page() {
        let app = test_app().await;
        let csrf = test_csrf_token();

        let login_response = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/login")
                    .header("content-type", "application/json")
                    .header("x-csrf-token", &csrf)
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
                        .header("x-csrf-token", &csrf)
                        .body(Body::from(
                            r#"{"company_name":"","email":"","name":"","password":"short","plan":"free"}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "{path} should fail fast on invalid input"
            );
            let json = response_json(response).await;
            assert_eq!(json["error"]["code"], "VALIDATION_ERROR");
        }

        let forgot_response = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/forgot-password")
                    .header("content-type", "application/json")
                    .header("x-csrf-token", &csrf)
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
                    .header("x-csrf-token", &csrf)
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
        assert!(verify_csp.contains("script-src 'none'"));
        assert!(verify_csp.contains("style-src 'self';"));
        let verify_body = response_body_string(verify_response).await;
        assert!(verify_body.contains("Verify your email"));
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

        // Path-param twin (F5/CWE-598): the token rides the path, not the
        // query string. An over-length token is rejected by
        // `verify_email_token` BEFORE any database access, so asserting its
        // rendered message proves the path token reaches the verifier —
        // without needing an external database — and the branded page still
        // renders. An unknown host stays a branded 404.
        let oversized_token = "t".repeat(129);
        let verify_path_response = app
            .clone()
            .oneshot(
                Request::get(format!("/verify-email/{oversized_token}"))
                    .header(HOST, "app.apexmail.ee")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verify_path_response.status(), StatusCode::OK);
        let verify_path_body = response_body_string(verify_path_response).await;
        assert!(verify_path_body.contains("invalid verification token"));

        let verify_path_unknown_host = app
            .clone()
            .oneshot(
                Request::get(format!("/verify-email/{oversized_token}"))
                    .header(HOST, "unexpected.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verify_path_unknown_host.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn marketing_fallback_pages_receive_nonce_backed_browser_csp() {
        if !ui_foundation::MARKETING_PUBLIC_BUILT {
            // F5: bare checkouts embed placeholder pages (no JSON-LD block);
            // the assertion needs the real Zola build output.
            eprintln!("skipping: marketing site not built (placeholder pages embedded)");
            return;
        }
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
        assert!(csp.contains("script-src 'none'"));
        assert!(csp.contains("img-src 'self' data:"));
        assert!(!csp.contains("plausible.apexmail.ee"));

        let body = response_body_string(response).await;
        // JSON-LD (non-executable SEO data) survives the zero-JS strip;
        // nothing else does.
        assert!(body.contains("<script type=application/ld+json"));
        assert!(!body.contains("apexmail-site.js"));
        assert!(!body.contains("api-explorer.js"));
        assert!(!body.contains("pricing-calculator.js"));
    }

    #[test]
    fn browser_csp_accepts_configured_https_analytics_image_source() {
        let csp = browser_csp_header_with_analytics(Some("https://analytics.example.com"));
        let csp = csp.to_str().expect("csp header should be utf-8");

        assert!(csp.contains("img-src 'self' data: https://analytics.example.com"));
        assert!(csp.contains("script-src 'none'"));
    }

    #[test]
    fn browser_csp_rejects_non_https_analytics_image_source() {
        let csp = browser_csp_header_with_analytics(Some("http://analytics.example.com"));
        let csp = csp.to_str().expect("csp header should be utf-8");

        assert!(csp.contains("img-src 'self' data:"));
        assert!(!csp.contains("http://analytics.example.com"));
    }

    #[test]
    fn browser_csp_has_no_external_kiwi_sources() {
        // KiwiCaptcha is fully same-origin: the inline nonce'd script and the
        // /api/kcaptcha/challenge endpoint are both covered by 'self'. The CSP
        // must NOT contain any external connect/script/frame sources for it.
        let csp = browser_csp_header_with_sources(None);
        let csp = csp.to_str().expect("csp header should be utf-8");

        assert!(csp.contains("connect-src 'self';"));
        assert!(csp.contains("script-src 'none'"));
        assert!(csp.contains("style-src 'self';"));
        assert!(csp.contains("frame-src 'none'"));
        // No external hosts leaked into the CSP.
        assert!(!csp.contains("captcha.apexmail"));
    }

    #[test]
    fn browser_csp_allows_inline_style_attributes() {
        // SSR primitives (Slider, Progress, chart frames) set per-element
        // style="..." attributes. Style attributes cannot carry nonces, and
        // they are far lower risk than script, so the CSP relaxes only the
        // style-src-attr directive while style-src stays nonce-gated.
        let csp = browser_csp_header_with_sources(None);
        let csp = csp.to_str().expect("csp header should be utf-8");

        assert!(csp.contains("style-src-attr 'unsafe-inline'"));
        // The element style-src directive must remain nonce-only (the
        // 'unsafe-inline' must not have leaked into style-src itself).
        assert!(csp.contains("style-src 'self';"));
    }

    #[tokio::test]
    async fn api_json_routes_keep_the_default_locked_down_csp() {
        let app = test_app().await;

        let response = app
            .clone()
            .oneshot(
                Request::get("/v1/auth/session")
                    .body(Body::empty())
                    .unwrap(),
            )
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
            assert_eq!(
                response.status(),
                StatusCode::NO_CONTENT,
                "{path} should clear the session even without an active cookie"
            );
            let set_cookie = response
                .headers()
                .get("set-cookie")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            assert!(
                set_cookie.contains("am_session=;"),
                "{path} should clear the session cookie"
            );
        }

        for path in ["/v1/auth/refresh", "/api/auth/refresh"] {
            let response = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{path} should stay registered as POST-only"
            );
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
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{path} should reject cookie logout without CSRF"
            );
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
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{path} should reject cookie refresh without CSRF"
            );
        }

        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/change-password")
                    .header("cookie", "am_session=session.jwt")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"current_password":"old","new_password":"NewPassword123!"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "/v1/auth/change-password should reject cookie-authenticated writes without CSRF"
        );
    }

    #[tokio::test]
    async fn web_admin_form_routes_reject_customer_sessions() {
        // P0 security fix: /web/admin/* used to sit on the plain
        // authenticated router — any customer session could create tenants
        // and operators. The branch now rides require_system_tenant_middleware
        // exactly like /v1/admin/*: a customer-tenant AuthUser (even with
        // the wildcard scope every tenant admin holds) is rejected.
        let state = test_state_app().await;
        let gated = Router::new()
            .route("/web/admin/tenants", post(|| async { "created" }))
            .route("/v1/admin/tenants", post(|| async { "created" }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::middleware::auth::require_system_tenant_middleware,
            ));

        // Browser surface (audit F1): a customer session posting a CP form
        // gets the web stack's PRG treatment — 303 to /login with a signed
        // flash cookie, never a raw JSON 403 dump.
        let mut request = Request::post("/web/admin/tenants")
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(crate::middleware::auth::AuthUser {
                tenant_id: "01HCUSTOMERTENANT0abcdefgh".into(),
                user_id: Some("00000000-0000-0000-0000-000000000001".into()),
                api_key_id: None,
                session_id: None,
                scopes: vec!["*".into()],
            });
        let response = gated.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::SEE_OTHER,
            "a customer session must be PRG-bounced from /web/admin/*"
        );
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/login",
            "the bounce target is the CP login"
        );
        let set_cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert!(
            set_cookie.contains("apexmail_flash="),
            "the rejection carries a friendly flash, got: {set_cookie}"
        );
        let flash =
            routes::web::decode_flash_from_cookie_header(set_cookie, &state.config.csrf_secret);
        assert!(
            flash
                .iter()
                .any(|message| message.text.contains("restricted to ApexMail operators")),
            "the flash names the privilege boundary, got: {flash:?}"
        );

        // JSON surface: the same rejection stays a 403 ApiError.
        let mut request = Request::post("/v1/admin/tenants")
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(crate::middleware::auth::AuthUser {
                tenant_id: "01HCUSTOMERTENANT0abcdefgh".into(),
                user_id: Some("00000000-0000-0000-0000-000000000001".into()),
                api_key_id: None,
                session_id: None,
                scopes: vec!["*".into()],
            });
        let response = gated.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a customer session must be forbidden from /v1/admin/*"
        );

        // System-tenant operators pass the gate: the literal `system`
        // sentinel (static API keys)…
        let mut request = Request::post("/web/admin/tenants")
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(crate::middleware::auth::AuthUser {
                tenant_id: "system".into(),
                user_id: None,
                api_key_id: None,
                session_id: None,
                scopes: vec!["*".into()],
            });
        let response = gated.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // …and the SEEDED system tenant id (audit F1): a slug-aware
        // membership lookup must admit the operator the CP login actually
        // mints. The lookup needs a reachable database (with the seeded
        // tenants row) — without one the gate must fail CLOSED (reject),
        // never silently admit an unresolvable tenant.
        if test_db_reachable(&state.db).await {
            sqlx::query(
                "INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at)
                 VALUES ('system_internal_tenant01', 'ApexMail', 'system', 'free', 'active', '{}'::jsonb, '{}'::jsonb, NOW(), NOW())
                 ON CONFLICT (id) DO NOTHING",
            )
            .execute(&state.db)
            .await
            .expect("seed system tenant");
        }
        let mut request = Request::post("/web/admin/tenants")
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(crate::middleware::auth::AuthUser {
                tenant_id: "system_internal_tenant01".into(),
                user_id: Some("00000000-0000-0000-0000-000000000002".into()),
                api_key_id: None,
                session_id: None,
                scopes: vec!["*".into()],
            });
        let response = gated.oneshot(request).await.unwrap();
        if test_db_reachable(&state.db).await {
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "the seeded system tenant must pass the slug-aware gate"
            );
        } else {
            assert_eq!(
                response.status(),
                StatusCode::SEE_OTHER,
                "without a database the gate fails closed, not open"
            );
        }
    }

    #[tokio::test]
    async fn web_admin_form_routes_require_authentication() {
        // The gated branch also runs after require_auth: unauthenticated
        // (or garbage-session) posts never reach the handler.
        let app = test_app().await;
        for path in [
            "/web/admin/tenants",
            "/web/admin/operators",
            "/web/admin/sales/leads/update",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::post(path)
                        .header("cookie", "am_session=not.a.jwt")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(
                response.status(),
                StatusCode::SEE_OTHER,
                "{path} must be rejected by the auth stack, not PRG-handled"
            );
            assert!(
                matches!(
                    response.status(),
                    StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
                ),
                "{path} unauthenticated posts must be rejected by auth, got {}",
                response.status()
            );
        }
    }

    #[tokio::test]
    async fn malformed_form_posts_get_friendly_redirects_not_plain_400() {
        // The rejection middleware converts extractor 400s on POST /web/*
        // into the console's PRG contract: 303 redirect (Referer or the
        // dashboard fallback) + a signed friendly flash cookie. Anything
        // else passes through untouched.
        let state = test_state_app().await;
        let app = Router::new()
            .route(
                "/web/auth/login",
                post(|| async { StatusCode::BAD_REQUEST }),
            )
            .route("/web/campaigns", post(|| async { StatusCode::BAD_REQUEST }))
            .route("/v1/other", post(|| async { StatusCode::BAD_REQUEST }))
            .route("/web/ok", post(|| async { "handled" }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                routes::web::web_form_rejection_middleware_for_tests,
            ));

        // POST /web/* + 400 → 303 + flash, back to the Referer.
        let response = app
            .clone()
            .oneshot(
                Request::post("/web/auth/login")
                    .header("referer", "http://app.apexmail.ee/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/login",
            "the referer's path becomes the redirect target"
        );
        let set_cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert!(set_cookie.contains("apexmail_flash="), "got: {set_cookie}");
        let decoded =
            routes::web::decode_flash_from_cookie_header(set_cookie, &state.config.csrf_secret);
        assert!(decoded
            .iter()
            .any(|message| message.text.contains("The form could not be read")));

        // No Referer → the dashboard fallback.
        let response = app
            .clone()
            .oneshot(Request::post("/web/campaigns").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/dashboard"
        );

        // Non-/web paths and non-400 statuses are untouched.
        let response = app
            .clone()
            .oneshot(Request::post("/v1/other").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = app
            .clone()
            .oneshot(Request::post("/web/ok").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn reset_password_validates_before_flashing_anything() {
        // The handler used to be a no-op that flashed success. Validation
        // failures now flash errors — without touching the database.
        let app = test_app().await;
        let csrf = test_csrf_token();

        // Missing token → error, not success.
        let body = format!(
            "_csrf={csrf}&token=&email=owner%40apexmail.ee&password=Valid123!Password&confirmPassword=Valid123!Password"
        );
        let response = app
            .clone()
            .oneshot(
                Request::post("/web/auth/reset-password")
                    .header("content-type", "application/x-www-form-urlencoded")
                    // Double-submit CSRF (audit F4): the form token must be
                    // backed by the matching csrf_token cookie.
                    .header("cookie", format!("csrf_token={csrf}"))
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let decoded = flash_from_response(&response);
        assert!(decoded
            .iter()
            .any(|message| matches!(message.kind, ui_foundation::flash::FlashKind::Error)));
        assert!(!decoded
            .iter()
            .any(|message| matches!(message.kind, ui_foundation::flash::FlashKind::Success)));

        // Mismatched passwords → error.
        let body = format!(
            "_csrf={csrf}&token=abc&email=owner%40apexmail.ee&password=Valid123!Password&confirmPassword=Different123!Pass"
        );
        let response = app
            .clone()
            .oneshot(
                Request::post("/web/auth/reset-password")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("cookie", format!("csrf_token={csrf}"))
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let decoded = flash_from_response(&response);
        assert!(
            decoded
                .iter()
                .any(|message| message.text.contains("do not match")),
            "expected a mismatch error, got {decoded:?}"
        );
    }

    fn flash_from_response(response: &Response) -> Vec<ui_foundation::flash::FlashMessage> {
        let set_cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        routes::web::decode_flash_from_cookie_header(set_cookie, &test_config().csrf_secret)
    }

    /// Full bad/good-token roundtrip against a real database: skipped when
    /// no local Postgres is reachable so the suite stays green everywhere.
    #[tokio::test]
    async fn reset_password_token_roundtrip_against_db() {
        let state = test_state_app().await;
        if !test_db_reachable(&state.db).await {
            eprintln!("skipping reset_password_token_roundtrip_against_db: no database");
            return;
        }

        let email = format!(
            "web-reset-{}@test.apexmail.ee",
            uuid::Uuid::new_v4().simple()
        );
        let tenant_id = apexmail_lib::id::generate_id("", 26);
        // users.id is a UUID column in both the migration chain and the
        // canonical apexmail-db SCHEMA — a 26-char text id fails with
        // "column id is of type uuid but expression is of type text"
        // (ci/README.md §9 F4). tenants.id is VARCHAR(26), so the text
        // tenant id is correct.
        let user_id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at)
             VALUES ($1, 'Reset Test', $2, 'free', 'active', '{}'::jsonb, '{}'::jsonb, NOW(), NOW())
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&tenant_id)
        .bind(format!("reset-test-{}", &tenant_id[..8]))
        .execute(&state.db)
        .await
        .expect("seed tenant");
        let password_hash = bcrypt::hash("OldValid123!Password", 4).expect("hash old password");
        let token = format!("vfy_{}", &uuid::Uuid::new_v4().simple().to_string()[..24]);
        let token_hash = crate::routes::helpers::hash_token(&token);
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status, email_verified, mfa_enabled, metadata, created_at, updated_at)
             VALUES ($1, $2, $3, 'Reset Test', $4, 'owner', 'active', true, false, $5::jsonb, NOW(), NOW())",
        )
        .bind(user_id)
        .bind(&tenant_id)
        .bind(&email)
        .bind(&password_hash)
        .bind(serde_json::json!({
            "password_reset_token_hash": token_hash,
            "password_reset_expires": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            "password_reset_iat": chrono::Utc::now().to_rfc3339(),
        }))
        .execute(&state.db)
        .await
        .expect("seed user");

        // Drive the handler through the real router.
        let app = build_app(state.clone());
        let csrf = test_csrf_token();

        // Bad token: rejected, password unchanged.
        let body = format!(
            "_csrf={csrf}&token=not-the-token&email={}&password=NewValid123!Pass&confirmPassword=NewValid123!Pass",
            email.replace('@', "%40"),
        );
        let response = app
            .clone()
            .oneshot(
                Request::post("/web/auth/reset-password")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("cookie", format!("csrf_token={csrf}"))
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let decoded = flash_from_response(&response);
        assert!(
            !decoded
                .iter()
                .any(|message| matches!(message.kind, ui_foundation::flash::FlashKind::Success)),
            "bad token must not flash success: {decoded:?}"
        );
        let stored: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert!(bcrypt::verify("OldValid123!Password", &stored).unwrap());

        // Good token: password rotated, token consumed, success flash.
        let body = format!(
            "_csrf={csrf}&token={}&email={}&password=NewValid123!Pass&confirmPassword=NewValid123!Pass",
            token,
            email.replace('@', "%40"),
        );
        let response = app
            .clone()
            .oneshot(
                Request::post("/web/auth/reset-password")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("cookie", format!("csrf_token={csrf}"))
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let decoded = flash_from_response(&response);
        assert!(
            decoded
                .iter()
                .any(|message| matches!(message.kind, ui_foundation::flash::FlashKind::Success)),
            "good token must flash success: {decoded:?}"
        );
        let stored: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert!(bcrypt::verify("NewValid123!Pass", &stored).unwrap());
        let metadata: serde_json::Value =
            sqlx::query_scalar("SELECT metadata FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert!(metadata.get("password_reset_token_hash").is_none());

        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&state.db)
            .await
            .expect("cleanup user");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant_id)
            .execute(&state.db)
            .await
            .expect("cleanup tenant");
    }

    /// Read-wiring smoke test: the SSR data layer renders DB-seeded rows
    /// and applies search/filter/pagination server-side. Skipped without
    /// a reachable database.
    #[tokio::test]
    async fn ssr_data_layer_renders_seeded_rows_with_filters_and_paging() {
        let state = test_state_app().await;
        if !test_db_reachable(&state.db).await {
            eprintln!(
                "skipping ssr_data_layer_renders_seeded_rows_with_filters_and_paging: no database"
            );
            return;
        }

        let tenant_id = apexmail_lib::id::generate_id("", 26);
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at)
             VALUES ($1, 'SSR Data Test', $2, 'free', 'active', '{}'::jsonb, '{}'::jsonb, NOW(), NOW())
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&tenant_id)
        .bind(format!("ssr-data-{}", &tenant_id[..8]))
        .execute(&state.db)
        .await
        .expect("seed tenant");
        // 25 campaigns: 20 named "Alpha Row N" (draft) + 5 "Beta Row N"
        // (completed — the live status CHECK has no 'sent').
        // campaigns.id is a UUID column (both schema lineages) — the text
        // nanoid ids previously failed the bind (ci/README.md §9 F4);
        // campaigns.tenant_id is VARCHAR, matching the text tenant id.
        for index in 0..20 {
            sqlx::query(
                "INSERT INTO campaigns (id, tenant_id, name, subject, status, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, 'draft', NOW(), NOW())",
            )
            .bind(uuid::Uuid::new_v4())
            .bind(&tenant_id)
            .bind(format!("Alpha Row {index:02}"))
            .bind("alpha subject")
            .execute(&state.db)
            .await
            .expect("seed campaign");
        }
        for index in 0..5 {
            sqlx::query(
                "INSERT INTO campaigns (id, tenant_id, name, subject, status, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, 'completed', NOW(), NOW())",
            )
            .bind(uuid::Uuid::new_v4())
            .bind(&tenant_id)
            .bind(format!("Beta Row {index:02}"))
            .bind("beta subject")
            .execute(&state.db)
            .await
            .expect("seed campaign");
        }

        let user = crate::middleware::auth::AuthUser {
            tenant_id: tenant_id.clone(),
            user_id: None,
            api_key_id: None,
            session_id: None,
            scopes: vec![],
        };

        // Unfiltered: 25 campaigns, first page of 20.
        let data =
            routes::web::load_page_data(&state, "web", "/campaigns", None, Some(&user)).await;
        let list = data.list.expect("campaigns list data");
        assert_eq!(list.total_count, 25);
        assert_eq!(list.total_pages, 2);
        assert_eq!(list.page, 1);
        let table = list.table.as_ref().expect("table");
        assert_eq!(table.rows.len(), 20);

        // Status filter: only the 5 completed campaigns.
        let data = routes::web::load_page_data(
            &state,
            "web",
            "/campaigns",
            Some("status=completed"),
            Some(&user),
        )
        .await;
        let list = data.list.expect("filtered list");
        assert_eq!(list.total_count, 5);
        assert!(list
            .table
            .as_ref()
            .unwrap()
            .rows
            .iter()
            .all(|row| row.cells.iter().any(|cell| matches!(
                cell,
                ui_foundation::view_data::DataCell::Status(ref status) if status == "completed"
            ))));

        // Search filter: "Beta" matches the 5 beta rows.
        let data = routes::web::load_page_data(
            &state,
            "web",
            "/campaigns",
            Some("query=Beta"),
            Some(&user),
        )
        .await;
        assert_eq!(data.list.unwrap().total_count, 5);

        // Pagination: page 2 has the remaining 5 rows.
        let data =
            routes::web::load_page_data(&state, "web", "/campaigns", Some("page=2"), Some(&user))
                .await;
        let list = data.list.expect("paged list");
        assert_eq!(list.page, 2);
        assert_eq!(list.table.as_ref().unwrap().rows.len(), 5);

        // The render pipeline shows the seeded row names.
        let data =
            routes::web::load_page_data(&state, "web", "/campaigns", None, Some(&user)).await;
        let html = ui_foundation::axum_router::render_route_with_data(
            "web",
            "/campaigns",
            None,
            None,
            &[],
            Some(&data),
        )
        .expect("render with data");
        assert!(html.contains("Alpha Row 0"));
        assert!(html.contains("Showing 1–20 of 25 campaigns"));

        // Honest empty state: a tenant with no campaigns.
        let empty_tenant = apexmail_lib::id::generate_id("", 26);
        let user = crate::middleware::auth::AuthUser {
            tenant_id: empty_tenant.clone(),
            user_id: None,
            api_key_id: None,
            session_id: None,
            scopes: vec![],
        };
        let data =
            routes::web::load_page_data(&state, "web", "/campaigns", None, Some(&user)).await;
        let html = ui_foundation::axum_router::render_route_with_data(
            "web",
            "/campaigns",
            None,
            None,
            &[],
            Some(&data),
        )
        .expect("render empty");
        assert!(html.contains("No campaigns yet"));

        sqlx::query("DELETE FROM campaigns WHERE tenant_id = $1")
            .bind(&tenant_id)
            .execute(&state.db)
            .await
            .expect("cleanup campaigns");
        sqlx::query("DELETE FROM tenants WHERE id = ANY($1)")
            .bind(vec![tenant_id, empty_tenant])
            .execute(&state.db)
            .await
            .expect("cleanup tenants");
    }

    #[tokio::test]
    async fn admin_routes_run_through_require_auth_not_the_gate() {
        // Regression test: the control-plane router was previously merged at
        // the TOP level, outside the `authenticated` stack, so `require_auth`
        // never executed for `/v1/admin/*`. With no AuthUser in the request
        // extensions, `require_system_tenant_middleware` 401'd EVERY admin
        // request — including fully valid ones — with "authentication
        // required for control-plane access".
        //
        // Now the admin router is merged into `authenticated` BEFORE the
        // layer stack, so a bad bearer token on an admin route is rejected
        // by `require_auth` itself (token decode failure, or a 503 when the
        // token-blacklist Redis is unavailable in unit tests) — proving the
        // auth middleware, which populates AuthUser, runs before the gate.
        let app = test_app().await;

        let response = app
            .clone()
            .oneshot(
                Request::get("/v1/admin/system/health")
                    .header("authorization", "Bearer not-a-real-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let status = response.status();
        let body = response_body_string(response).await;
        assert_ne!(status, StatusCode::OK);
        assert!(
            !(status == StatusCode::UNAUTHORIZED && body.contains("control-plane")),
            "admin request must be rejected by require_auth (which populates \
             AuthUser), not by the system-tenant gate — got {status} with body: {body}"
        );
    }

    // ─── Control-plane session gate (middleware::cp_auth) ──────

    /// Full-app fixture for CP-gate tests: canonical-shape DB, a real RSA
    /// signing keypair (require_auth must actually decode the minted
    /// am_session), reachable Redis (token blacklist), and the cp_access_log
    /// table the gate audits into. Soft-skips without TEST_DATABASE_URL or
    /// an reachable TEST_REDIS_URL (workspace convention).
    async fn cp_gate_app(
        test_name: &str,
    ) -> Option<(Router, sqlx::PgPool, Config, deadpool_redis::Pool)> {
        let pool = crate::test_db::canonical_pool(test_name).await?;
        let redis_url = std::env::var("TEST_REDIS_URL").ok()?;
        let redis = deadpool_redis::Config::from_url(&redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .ok()?;
        let mut conn = redis.get().await.ok()?;
        let ping: Result<String, _> = redis::cmd("PING").query_async(&mut *conn).await;
        if ping.is_err() {
            eprintln!("skipping {test_name}: TEST_REDIS_URL unreachable");
            return None;
        }

        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS cp_access_log (
                 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                 email VARCHAR(320),
                 path VARCHAR(1024) NOT NULL,
                 status_code INTEGER NOT NULL,
                 outcome VARCHAR(64) NOT NULL,
                 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
             )",
        )
        .execute(&pool)
        .await
        .expect("cp_access_log fixture DDL must apply");

        // Real RSA keypair so the login form can sign an am_session that
        // require_auth actually decodes. The DKIM keygen is this crate's
        // existing test RSA source; the public half is re-derived as an
        // SPKI PEM for jsonwebtoken (avoiding the rand 0.9 / rsa 0.9 RNG
        // trait mismatch on direct keygen).
        use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding};
        let key_pair = apexmail_lib::dkim::generate_dkim_keypair().expect("test RSA keypair");
        let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(key_pair.private_key_pem.as_str())
            .expect("valid PKCS8 private key");
        let jwt_private_key_pem = key_pair.private_key_pem.to_string();
        let jwt_public_key_pem = private_key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("public PEM")
            .to_string();

        let mut config = test_config_impl();
        config.jwt_private_key_pem = jwt_private_key_pem;
        config.jwt_public_key_pem = jwt_public_key_pem;

        let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_sesv2::config::Region::new("us-east-1"))
            .load()
            .await;
        let ses_provider = Arc::new(crate::ses_provider::SesIpProvider::new(
            aws_sdk_sesv2::Client::new(&aws_config),
            pool.clone(),
            "apexmail".into(),
            "us-east-1".into(),
        ));
        let state = AppStateInner::with_ddos_protector(
            pool.clone(),
            apexmail_db::pool::PoolPair {
                rw: pool.clone(),
                ro: pool.clone(),
            },
            redis.clone(),
            config.clone(),
            reqwest::Client::new(),
            (*ses_provider).clone(),
            None,
            Arc::new(
                DdosProtector::new(ProtectorConfig::default())
                    .await
                    .expect("ddos protector"),
            ),
            None,
            None,
            ResilientClient::new_from_config(&config),
        );
        Some((build_app(state), pool, config, redis))
    }

    /// Seed a system-tenant operator and return (user_id, email, password).
    ///
    /// The tenant id is the SEEDED system tenant (`system_internal_tenant01`,
    /// migration 072) — not the literal `system` sentinel — so every gate on
    /// this fixture exercises the slug-aware membership check (audit F1)
    /// the CP login uses. A tenants row with slug `system` backs the
    /// membership.
    async fn cp_gate_seed_operator(
        db: &sqlx::PgPool,
        mfa_enabled: bool,
    ) -> (String, String, String) {
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at)
             VALUES ('system_internal_tenant01', 'ApexMail', 'system', 'free', 'active', '{}'::jsonb, '{}'::jsonb, NOW(), NOW())
             ON CONFLICT (id) DO NOTHING",
        )
        .execute(db)
        .await
        .expect("seed system tenant");

        let email = format!("cp-gate-{}@apexmail.ee", uuid::Uuid::new_v4().simple());
        let password = "Sup3r#SecurePass".to_string();
        let hash = bcrypt::hash(&password, bcrypt::DEFAULT_COST).expect("bcrypt hash");
        let user_id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status,
                                email_verified, mfa_enabled, metadata, created_at, updated_at)
             VALUES ($1, 'system_internal_tenant01', $2, 'CP Op', $3, 'owner', 'active', true, $4, '{}'::jsonb, NOW(), NOW())",
        )
        .bind(user_id)
        .bind(&email)
        .bind(&hash)
        .bind(mfa_enabled)
        .execute(db)
        .await
        .expect("seed cp operator");
        (user_id.to_string(), email, password)
    }

    /// Collect every Set-Cookie value from a response (login returns several).
    fn all_set_cookies(response: &Response) -> Vec<String> {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok().map(str::to_string))
            .collect()
    }

    fn cookie_value<'a>(cookies: &'a [String], name: &str) -> Option<&'a str> {
        cookies.iter().find_map(|cookie| {
            cookie
                .split(';')
                .next()?
                .strip_prefix(&format!("{name}="))
                .filter(|value| !value.is_empty())
        })
    }

    /// A CP session cookie minted out-of-band (the same shape form_cp_login
    /// issues after the fix).
    fn mint_cp_cookie(config: &Config, user_id: &str, email: &str, mfa_enabled: bool) -> String {
        let now = chrono::Utc::now().timestamp();
        let claims = crate::middleware::cp_auth::CpSessionClaims {
            sub: user_id.to_string(),
            tenant_id: "system".into(),
            email: email.to_string(),
            role: "owner".into(),
            mfa_enabled,
            iat: now,
            last_active: now,
            exp: now + 3600,
        };
        let token = crate::middleware::cp_auth::create_cp_session_token(
            &claims,
            &config.cp_auth.session_secret,
        );
        format!("apexmail_cp_session={token}")
    }

    /// CP login through the real form endpoint; returns the response's
    /// Set-Cookie header values.
    async fn cp_gate_login(
        app: &Router,
        config: &Config,
        email: &str,
        password: &str,
    ) -> Vec<String> {
        let csrf = ui_foundation::csrf::generate_csrf_token(&config.csrf_secret);
        let response = app
            .clone()
            .oneshot(
                Request::post("/web/cp/login")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header(HOST, "admin.apexmail.ee")
                    .header("cookie", format!("csrf_token={csrf}"))
                    .body(Body::from(format!(
                        "email={}&password={}&_csrf={csrf}",
                        urlencode(email),
                        urlencode(password),
                    )))
                    .unwrap(),
            )
            .await
            .expect("cp login dispatch");
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        all_set_cookies(&response)
    }

    fn urlencode(value: &str) -> String {
        url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
    }

    /// CRITICAL gate regression: an operator WITHOUT MFA must not be able to
    /// drive control-plane routes with the plain am_session the CP login
    /// form mints — the session gate (role + MFA enforcement) must reject
    /// them even though the tenant is `system`.
    #[tokio::test]
    async fn cp_gate_blocks_non_mfa_operator_sessions_from_admin_routes() {
        let Some((app, db, config, _redis)) = cp_gate_app("cp_gate_blocks_non_mfa").await else {
            return;
        };
        let (_user_id, email, password) = cp_gate_seed_operator(&db, false).await;
        let cookies = cp_gate_login(&app, &config, &email, &password).await;
        let am_session = cookie_value(&cookies, "am_session")
            .expect("cp login must still mint the am_session cookie")
            .to_string();

        // Session-cookie writes need the double-submit CSRF pair.
        let csrf = ui_foundation::csrf::generate_csrf_token(&config.csrf_secret);
        let response = app
            .clone()
            .oneshot(
                Request::post("/web/admin/tenants")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header(
                        "cookie",
                        format!("am_session={am_session}; csrf_token={csrf}"),
                    )
                    .header("x-csrf-token", &csrf)
                    .body(Body::from(format!(
                        "_csrf={csrf}&name=Evil+Co&domain=evil.example&plan=free"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            matches!(
                response.status(),
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
            ),
            "a non-MFA operator session must be blocked by the CP gate, got {}",
            response.status()
        );
    }

    /// The CP login form must mint the dedicated CP session cookie with the
    /// operator's MFA state baked into the signed claims (not just the
    /// generic am_session JWT).
    #[tokio::test]
    async fn cp_login_mints_mfa_backed_cp_session_cookie() {
        let Some((app, db, config, _redis)) = cp_gate_app("cp_login_cp_cookie").await else {
            return;
        };
        let (user_id, email, password) = cp_gate_seed_operator(&db, false).await;
        let cookies = cp_gate_login(&app, &config, &email, &password).await;

        let token = cookie_value(&cookies, "apexmail_cp_session")
            .expect("cp login must set apexmail_cp_session")
            .to_string();
        let parts: Vec<&str> = token.splitn(2, '.').collect();
        assert_eq!(parts.len(), 2, "CP session token is payload.signature");
        // The signed payload carries the user id and their REAL mfa state.
        let payload = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            parts[0].as_bytes(),
        )
        .expect("payload base64");
        let claims: serde_json::Value = serde_json::from_slice(&payload).expect("payload json");
        assert_eq!(claims["sub"].as_str(), Some(user_id.as_str()));
        assert_eq!(claims["role"].as_str(), Some("owner"));
        assert_eq!(
            claims["mfa_enabled"].as_bool(),
            Some(false),
            "non-MFA operator's CP cookie must carry mfa_enabled=false so the \
             gate rejects it"
        );

        // And the token verifies against the configured CP secret.
        let verify = crate::middleware::cp_auth::verify_cp_session_token_for_tests(
            &token,
            &config.cp_auth.session_secret,
        );
        assert!(verify.is_ok(), "cp session token must be HMAC-verifiable");
    }

    /// Every CP gate decision lands in cp_access_log (separate, append-only
    /// audit trail for control-plane access).
    #[tokio::test]
    async fn cp_access_attempts_are_audited() {
        let Some((app, db, config, _redis)) = cp_gate_app("cp_access_audit").await else {
            return;
        };
        let (_user_id, email, password) = cp_gate_seed_operator(&db, false).await;
        let cookies = cp_gate_login(&app, &config, &email, &password).await;
        let am_session = cookie_value(&cookies, "am_session").unwrap().to_string();

        let csrf = ui_foundation::csrf::generate_csrf_token(&config.csrf_secret);
        let _ = app
            .clone()
            .oneshot(
                Request::post("/web/admin/tenants")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header(
                        "cookie",
                        format!("am_session={am_session}; csrf_token={csrf}"),
                    )
                    .header("x-csrf-token", &csrf)
                    .body(Body::from(format!("_csrf={csrf}&name=X&domain=x.example")))
                    .unwrap(),
            )
            .await
            .unwrap();

        let logged: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM cp_access_log WHERE path = '/web/admin/tenants'",
        )
        .fetch_one(&db)
        .await
        .expect("cp_access_log readable");
        assert!(
            logged >= 1,
            "the gate decision must be written to cp_access_log"
        );
    }

    /// An MFA-enabled operator holding a valid CP session passes the gate
    /// and receives the refreshed session cookie (sliding idle window).
    #[tokio::test]
    async fn cp_gate_admits_mfa_operator_with_valid_cp_session() {
        let Some((app, db, config, _redis)) = cp_gate_app("cp_gate_admits_mfa").await else {
            return;
        };
        let (user_id, email, _password) = cp_gate_seed_operator(&db, true).await;
        // The MFA operator is mid-flow (their password step redirects to
        // the TOTP challenge), so sign the am_session directly — the same
        // claims shape session_cookie_for_user produces.
        let now = chrono::Utc::now().timestamp();
        let claims = crate::middleware::auth::JwtClaims {
            sub: user_id.clone(),
            // The seeded system tenant id (slug-aware gate, audit F1) — the
            // literal `system` sentinel is only for static API keys.
            tenant_id: "system_internal_tenant01".into(),
            scopes: vec!["*".into()],
            exp: now + 3600,
            iat: now,
            jti: uuid::Uuid::new_v4().to_string(),
            typ: Some("session".into()),
        };
        let encoding_key =
            jsonwebtoken::EncodingKey::from_rsa_pem(config.jwt_private_key_pem.as_bytes())
                .expect("encoding key");
        let am_session = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
            &claims,
            &encoding_key,
        )
        .expect("sign am_session");
        let cp_cookie = mint_cp_cookie(&config, &user_id, &email, true);

        let csrf = ui_foundation::csrf::generate_csrf_token(&config.csrf_secret);
        let response = app
            .clone()
            .oneshot(
                Request::post("/web/admin/tenants")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header(
                        "cookie",
                        format!("am_session={am_session}; csrf_token={csrf}; {cp_cookie}"),
                    )
                    .header("x-csrf-token", &csrf)
                    .body(Body::from(format!("_csrf={csrf}&name=X&domain=x.example")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::SEE_OTHER,
            "an MFA'd operator with a valid CP session must reach the handler"
        );
        let refreshed = all_set_cookies(&response);
        assert!(
            cookie_value(&refreshed, "apexmail_cp_session").is_some(),
            "the gate must slide the CP session cookie on activity"
        );
    }
    /// A cursor that decodes to something OTHER than a timestamp must be
    /// a 400 — the messages list used to bind the decoded string into a
    /// `::timestamp` cast and surface the database's parse failure as a
    /// 500.
    #[tokio::test]
    async fn malformed_message_cursor_returns_400_not_500() {
        let Some((app, db, config, _redis)) = cp_gate_app("cursor_400").await else {
            return;
        };
        let (user_id, _email, _password) = cp_gate_seed_operator(&db, true).await;
        sqlx::query(
            "INSERT INTO messages (id, tenant_id, from_email, to_emails, subject, created_at)
             VALUES ($1, 'system', 'a@apexmail.ee', '[\"b@example.com\"]'::jsonb, 's', NOW())",
        )
        .bind(uuid::Uuid::new_v4())
        .execute(&db)
        .await
        .expect("seed message");

        let now = chrono::Utc::now().timestamp();
        let claims = crate::middleware::auth::JwtClaims {
            sub: user_id,
            tenant_id: "system".into(),
            scopes: vec!["messages:read".into()],
            exp: now + 3600,
            iat: now,
            jti: uuid::Uuid::new_v4().to_string(),
            typ: Some("session".into()),
        };
        let am_session = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
            &claims,
            &jsonwebtoken::EncodingKey::from_rsa_pem(config.jwt_private_key_pem.as_bytes())
                .expect("encoding key"),
        )
        .expect("sign am_session");

        use base64::Engine;
        let garbage_cursor = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode("definitely-not-a-timestamp".as_bytes());
        let response = app
            .oneshot(
                Request::get(format!("/v1/messages?cursor={garbage_cursor}"))
                    .header("cookie", format!("am_session={am_session}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "a malformed cursor is a client error, not a database 500"
        );
    }
}
// Build cache invalidation: 1785670948
