//! HTTP routes for the template renderer service.

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Json, State},
    http::{header::AUTHORIZATION, Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tower_http::timeout::TimeoutLayer;

use crate::auth::ServiceAuth;
use crate::cache::{source_render_cache_key, TemplateCache};
use crate::config::RendererConfig;
use crate::plaintext::html_to_plaintext;
use crate::sandbox::Sandbox;
use crate::transpiler;
use crate::types::{RenderMetadata, RenderOptions, RenderResult, TemplateError, STARTER_TEMPLATE};

// ─── App State ─────────────────────────────────────────────────

pub struct AppState {
    pub db: sqlx::PgPool,
    pub sandbox: Sandbox,
    pub cache: TemplateCache,
    pub config: RendererConfig,
    /// P1 #6: per-workload credentials — the dedicated
    /// `TEMPLATE_RENDERER_AUTH_TOKEN` is the only accepted secret when
    /// configured; the universal token is legacy fallback (non-production).
    pub service_auth: ServiceAuth,
}

/// Routes that stay public for orchestrator probes (no service token).
/// `/health` is liveness; `/ready` reports dependency honesty (P1 #12).
fn is_public_probe_path(path: &str) -> bool {
    path == "/health" || path == "/ready"
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/render", post(render_handler))
        .route("/validate", post(validate_handler))
        .route("/starter", get(starter_handler))
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_service_token,
        ))
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024)) // 2 MB
        // HTTP-level cap. The sandbox work itself runs on a blocking thread
        // (see `render_handler`), so this layer can actually fire and release
        // the async worker instead of being stuck behind CPU-bound code.
        .layer(TimeoutLayer::new(Duration::from_secs(
            state.config.server.request_timeout_secs,
        )))
        .with_state(state)
}

async fn require_service_token(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if is_public_probe_path(req.uri().path()) {
        return Ok(next.run(req).await);
    }
    let provided = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok().map(String::from))
        .or_else(|| {
            req.headers()
                .get(AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|raw| raw.trim().strip_prefix("Bearer ").map(String::from))
        })
        .unwrap_or_default();
    if state.service_auth.authorize(&provided) {
        return Ok(next.run(req).await);
    }
    // P1 #6: a configured dedicated token means the universal
    // INTERNAL_SERVICE_TOKEN no longer authorizes anything here — call out
    // unmigrated callers loudly (they get 401 either way).
    if state.service_auth.is_refused_universal_attempt(&provided) {
        tracing::warn!(
            "request refused: the universal INTERNAL_SERVICE_TOKEN was presented but \
             TEMPLATE_RENDERER_AUTH_TOKEN is configured — the caller must migrate to the \
             dedicated per-workload token"
        );
    }
    Err(StatusCode::UNAUTHORIZED)
}

// ─── Request / Response types ──────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenderRequest {
    source: String,
    #[serde(default)]
    props: serde_json::Value,
    #[serde(default = "default_true")]
    generate_plaintext: bool,
    #[serde(default)]
    minify: bool,
    subject: Option<String>,
    /// Fallback substituted for missing merge fields (default: empty string).
    #[serde(default)]
    missing_field_fallback: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidateRequest {
    source: String,
}

// ─── Handlers ──────────────────────────────────────────────────

async fn render_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RenderRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let opts = RenderOptions {
        props: req.props,
        generate_plaintext: req.generate_plaintext,
        minify: req.minify,
        subject: req.subject,
        missing_field_fallback: req.missing_field_fallback.clone(),
    };

    // P1 #11: the render cache is consulted on the HTTP path. The key is a
    // SHA-256 over the template SOURCE (never an id alone — the request
    // carries inline source), the canonicalized props, every output-affecting
    // option and the renderer semantics version, so any content or option
    // change rotates the key.
    let cache_key = source_render_cache_key(&req.source, &opts);
        if let Some(mut cached) = state.cache.get(&cache_key) {
            cached.metadata.cached = true;
            return (
                StatusCode::OK,
                // coverage: justified — RenderResult is plain strings/numbers,
                // so serde_json::to_value cannot fail; the fallback guards
                // future field types only.
                Json(serde_json::to_value(&cached).unwrap_or_else(|e| {
                    serde_json::json!({"error": "serialization_failed", "message": e.to_string()})
                })),
            );
        }

    // The sandbox execute is CPU-bound (regex scans, html5ever parse,
    // minify). Running it inline on the async worker starves the runtime:
    // the TimeoutLayer cannot fire while a future is stuck inside a poll,
    // so one slow render used to hang the whole request (and worker) until
    // the sandbox finished. `spawn_blocking` moves it off the worker — the
    // future yields Pending, the 30s HTTP timeout can fire (408), and the
    // worker keeps serving other requests.
    let sandbox = state.sandbox.clone();
    let blocking_source = req.source.clone();
    let blocking_opts = opts.clone();
    let result = match tokio::task::spawn_blocking(move || {
        sandbox.execute(&blocking_source, &blocking_opts)
    })
    .await
    {
        Ok(result) => result,
        Err(join_err) => {
            // coverage: justified — panic containment for the blocking render
            // task; the sandbox is panic-free by its own test contract, so no
            // input deterministically reaches this arm.
            tracing::error!(error = %join_err, "render blocking task panicked");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "RENDER_TASK_FAILED",
                    "message": "render task failed unexpectedly",
                })),
            );
        }
    };

    match result {
        Ok(result) => {
            let plaintext = if opts.generate_plaintext {
                Some(html_to_plaintext(&result.html))
            } else {
                None
            };

            // Subject-bound resolution also strips CR/LF/NUL (header
            // injection hardening — see the transpiler's subject variant).
            let subject = opts.subject.as_ref().map(|s| {
                transpiler::resolve_placeholders_subject_reported(
                    s,
                    &opts.props,
                    opts.missing_field_fallback.as_deref().unwrap_or(""),
                )
                .html
            });

            let render_result = RenderResult {
                html: result.html.clone(),
                plaintext: plaintext.clone(),
                subject,
                metadata: RenderMetadata {
                    render_time_ms: result.execution_time.as_millis() as u64,
                    html_size_bytes: result.html.len(),
                    plaintext_size_bytes: plaintext.as_ref().map(|p| p.len()),
                    cached: false,
                },
                warnings: result.warnings,
            };

            // Cache the successful render (bounded by `CacheConfig`): the
            // next identical (source, props, options) request is served from
            // the cache with `cached: true`.
            state.cache.insert(cache_key, render_result.clone());

            (
                StatusCode::OK,
                // coverage: justified — RenderResult is plain strings/numbers,
                // so serde_json::to_value cannot fail; the fallback guards
                // future field types only.
                Json(serde_json::to_value(&render_result).unwrap_or_else(|e| {
                    serde_json::json!({"error": "serialization_failed", "message": e.to_string()})
                })),
            )
        }
        Err(e) => {
            let status = match &e {
                TemplateError::SourceTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
                TemplateError::OutputTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
                TemplateError::Timeout { .. } => StatusCode::GATEWAY_TIMEOUT,
                TemplateError::ForbiddenModule { .. } => StatusCode::FORBIDDEN,
                // coverage: justified — NotFound is produced by the
                // stored-template renderer only; the HTTP path renders inline
                // source and can never produce it (arm kept for totality).
                TemplateError::NotFound { .. } => StatusCode::NOT_FOUND,
                _ => StatusCode::BAD_REQUEST,
            };
            (
                status,
                Json(serde_json::json!({
                    "error": e.code().to_string(),
                    "message": e.to_string(),
                })),
            )
        }
    }
}

async fn validate_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ValidateRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let result = transpiler::validate_source(&req.source, state.config.sandbox.max_source_length);
    (
        StatusCode::OK,
        // coverage: justified — ValidationResult is plain strings/bools, so
        // serde_json::to_value cannot fail; the fallback guards future field
        // types only.
        Json(serde_json::to_value(&result).unwrap_or_else(
            |e| serde_json::json!({"error": "serialization_failed", "message": e.to_string()}),
        )),
    )
}

async fn starter_handler() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "template": STARTER_TEMPLATE,
        })),
    )
}

/// Liveness probe: the process is up. It deliberately says NOTHING about
/// dependencies (P1 #12) — restart loops driven by a blind "healthy" answer
/// are exactly what the readiness probe below exists to prevent.
async fn health_handler() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::OK,
        Json(serde_json::json!({ "status": "healthy" })),
    )
}

/// Upper bound on the readiness probe's DB check so orchestrator polls
/// cannot pile up behind a hung pool acquisition.
const READY_CHECK_TIMEOUT: Duration = Duration::from_secs(2);

/// Readiness probe (P1 #12): honestly reports whether the service can serve
/// traffic. `/health` used to answer "healthy" regardless of the DB pool;
/// `/ready` runs a bounded `SELECT 1` against it and reports
/// `{"status":"ready"}` (200) or `{"status":"degraded", ...}` (503) with the
/// failing dependency named.
async fn ready_handler(State(state): State<Arc<AppState>>) -> (StatusCode, Json<serde_json::Value>) {
    let check = sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&state.db);
    match tokio::time::timeout(READY_CHECK_TIMEOUT, check).await {
        Ok(Ok(_)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "ready",
                "dependencies": { "database": "up" },
            })),
        ),
        Ok(Err(error)) => {
            tracing::warn!(error = %error, "readiness check: database not reachable");
            degraded("down", &error.to_string())
        }
        Err(_) => {
            tracing::warn!(
                "readiness check: database did not answer within {READY_CHECK_TIMEOUT:?}"
            );
            degraded("timeout", &format!("no answer within {READY_CHECK_TIMEOUT:?}"))
        }
    }
}

fn degraded(detail: &str, message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "status": "degraded",
            "dependencies": { "database": detail },
            "detail": message,
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::ServiceAuth;
    use crate::config::*;

    fn test_config() -> RendererConfig {
        RendererConfig {
            db: DatabaseConfig {
                url: "postgres://localhost/test".to_string(),
                max_connections: 5,
            },
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 9080,
                request_timeout_secs: 30,
            },
            sandbox: SandboxConfig {
                timeout_ms: 5000,
                max_memory_bytes: 64 * 1024 * 1024,
                max_source_length: 512 * 1024,
                max_output_length: 2 * 1024 * 1024,
                trusted_html_props: Vec::new(),
            },
            cache: CacheConfig {
                max_entries: 100,
                ttl_secs: 60,
            },
        }
    }

    /// P1 #6: state construction uses the per-workload `ServiceAuth`
    /// resolver (a single accepted token, no universal credential).
    fn auth_with_token(token: &str) -> ServiceAuth {
        ServiceAuth::resolve(Some(token), None, false).expect("test auth resolves")
    }

    #[tokio::test]
    async fn test_router_creation() {
        // Just verifies router builds without panic
        let config = test_config();
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let state = Arc::new(AppState {
            db: pool,
            sandbox: Sandbox::new(config.sandbox.clone()),
            cache: TemplateCache::new(config.cache.max_entries, config.cache.ttl_secs),
            config,
            service_auth: auth_with_token("test-key"),
        });
        let _router = router(state);
    }

    #[test]
    fn test_render_request_deserialization() {
        let json = r#"{
            "source": "<p>Hello</p>",
            "props": {"name": "World"},
            "minify": true
        }"#;
        let req: RenderRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.source, "<p>Hello</p>");
        assert!(req.generate_plaintext); // default
        assert!(req.minify);
    }

    #[test]
    fn test_error_status_codes() {
        let err = TemplateError::SourceTooLarge {
            size: 1000,
            max: 100,
        };
        assert_eq!(err.code().to_string(), "SOURCE_TOO_LARGE");

        let err = TemplateError::Timeout { ms: 5000 };
        assert_eq!(err.code().to_string(), "SANDBOX_TIMEOUT");

        let err = TemplateError::ForbiddenModule {
            module: "fs".into(),
        };
        assert_eq!(err.code().to_string(), "FORBIDDEN_MODULE");
    }

    /// A CPU-bound render that outruns the HTTP timeout must produce a 408
    /// (tower-http 0.5 `TimeoutLayer`) instead of hanging the request on a
    /// blocked async worker, and the runtime must stay responsive while the
    /// render is stuck.
    ///
    /// The sandbox's own 60s timeout deliberately cannot fire here (it only
    /// checks between phases), so the only thing that can bound this request
    /// is the HTTP layer — which requires the sandbox work to run off the
    /// async worker (`spawn_blocking`).
    #[tokio::test]
    async fn render_handler_slow_render_times_out_and_runtime_stays_responsive() {
        use tower::ServiceExt;

        let config = RendererConfig {
            db: DatabaseConfig {
                url: "postgres://localhost/test".to_string(),
                max_connections: 5,
            },
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 9080,
                request_timeout_secs: 1,
            },
            sandbox: SandboxConfig {
                timeout_ms: 60_000, // sandbox's own checks must NOT fire first
                max_memory_bytes: 64 * 1024 * 1024,
                max_source_length: 512 * 1024,
                max_output_length: 2 * 1024 * 1024,
                trusted_html_props: Vec::new(),
            },
            cache: CacheConfig {
                max_entries: 100,
                ttl_secs: 60,
            },
        };
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let state = Arc::new(AppState {
            db: pool,
            sandbox: Sandbox::new(config.sandbox.clone()),
            cache: TemplateCache::new(config.cache.max_entries, config.cache.ttl_secs),
            config,
            service_auth: auth_with_token("test-key"),
        });
        let app = router(state);

        // ~120KB of alternating <pre> regions (12 bytes each): minification's
        // per-region scan is quadratic, so this legitimately burns CPU well
        // past the 1s HTTP cap while staying a perfectly legal template.
        let source = "<pre>a</pre>".repeat(10_000);
        assert!(source.len() < 512 * 1024);

        let body = serde_json::json!({ "source": source, "minify": true });
        let render_req = Request::builder()
            .method("POST")
            .uri("/render")
            .header("x-api-key", "test-key")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let health_req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let (render_outcome, health_outcome) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(5), app.clone().oneshot(render_req)),
            tokio::time::timeout(Duration::from_millis(2_000), app.oneshot(health_req)),
        );

        let health_resp = health_outcome
            .expect("/health must stay responsive while a render is stuck")
            .unwrap(); // Router's error type is Infallible
        assert_eq!(health_resp.status(), StatusCode::OK);

        let resp = render_outcome
            .expect("render request must resolve via the HTTP timeout, not hang")
            .expect("render oneshot must not error");
        assert_eq!(
            resp.status(),
            StatusCode::REQUEST_TIMEOUT,
            "slow render must be cut off by the HTTP timeout layer"
        );
    }

    // ── Adversarial: auth matrix + handler contracts ────────────────────

    fn state_with_token(token: &str) -> Arc<AppState> {
        let config = test_config();
        Arc::new(AppState {
            db: sqlx::PgPool::connect_lazy("postgres://localhost/test").expect("lazy pool"),
            sandbox: Sandbox::new(config.sandbox.clone()),
            cache: TemplateCache::new(config.cache.max_entries, config.cache.ttl_secs),
            config,
            // P1 #6: per-workload ServiceAuth replaces the bare token field.
            service_auth: auth_with_token(token),
        })
    }

    #[tokio::test]
    async fn auth_matrix_and_public_health() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = router(state_with_token("test-key"));
        // /health is public.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Everything else requires the token.
        for uri in ["/starter"] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }
        // Bearer token accepted.
        let mut request = Request::builder()
            .uri("/starter")
            .body(Body::empty())
            .unwrap();
        request.headers_mut().insert(
            axum::http::header::AUTHORIZATION,
            "Bearer test-key".parse().unwrap(),
        );
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!body.is_empty());

        // An unconfigured token locks everything but /health.
        let locked = router(state_with_token(""));
        let response = locked
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = locked
            .oneshot(
                Request::builder()
                    .uri("/starter")
                    .header("x-api-key", "anything")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn render_and_validate_handlers_answer_with_json() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = router(state_with_token("test-key"));
        let post = |uri: &'static str, body: serde_json::Value| {
            let app = app.clone();
            async move {
                app.oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(uri)
                        .header("x-api-key", "test-key")
                        .header("content-type", "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap()
            }
        };

        let response = post(
            "/render",
            serde_json::json!({
                "source": "<h1>{{ title }}</h1>",
                "props": { "title": "Hello" },
                "subject": "T: {{ title }}"
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["html"].as_str().unwrap().contains("Hello"), "{json}");

        let response = post("/validate", serde_json::json!({ "source": "<p>ok</p>" })).await;
        assert_eq!(response.status(), StatusCode::OK);

        // Oversized source is refused by the sandbox length cap.
        let huge = "a".repeat(600_000);
        let response = post("/validate", serde_json::json!({ "source": huge })).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["valid"], false, "{json}");
    }

    /// PINNED (considered by the 2026-09 privilege-boundary audit): the
    /// template renderer has NO tenant dimension to fail closed on. It never
    /// fetches tenant rows: templates arrive as `source` in the token-gated
    /// request body (the callers — api-server/enterprise — select the tenant
    /// row and pass its compiled source), the handlers touch neither the
    /// `db` pool nor the response cache, and no route accepts a tenant
    /// selector. Identical inputs render identical output for any caller,
    /// so there is no cross-tenant fetch to probe and no default bucket to
    /// exploit. This test pins the statelessness and the isolation between
    /// two callers' renders.
    #[tokio::test]
    async fn renders_are_stateless_and_never_leak_between_callers() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = router(state_with_token("test-key"));
        let render = |source: &'static str| {
            let app = app.clone();
            async move {
                app.oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/render")
                        .header("x-api-key", "test-key")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::json!({
                                "source": source,
                                "props": { "marker": "x" },
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap()
            }
        };

        // Caller "A" and caller "B" render distinct sources; each output
        // carries only its own content.
        let response_a = render("<p>A {{ marker }}</p>").await;
        assert_eq!(response_a.status(), StatusCode::OK);
        let body_a = axum::body::to_bytes(response_a.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_a: serde_json::Value = serde_json::from_slice(&body_a).unwrap();
        assert!(
            json_a["html"].as_str().unwrap().contains(">A x<"),
            "{json_a}"
        );

        let response_b = render("<p>B {{ marker }}</p>").await;
        assert_eq!(response_b.status(), StatusCode::OK);
        let body_b = axum::body::to_bytes(response_b.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_b: serde_json::Value = serde_json::from_slice(&body_b).unwrap();
        assert!(
            json_b["html"].as_str().unwrap().contains(">B x<"),
            "{json_b}"
        );
        assert!(
            !json_b["html"].as_str().unwrap().contains(">A"),
            "caller B's render must not contain caller A's content"
        );
        // P1 #11: the two callers render DISTINCT sources, so both remain
        // cache misses (the comment below previously said the HTTP path was
        // uncached entirely — the wired cache is content-addressed, so only
        // byte-identical (source, props, options) requests share an entry).
        assert_eq!(
            json_b["metadata"]["cached"], false,
            "distinct sources are distinct cache keys: no shared entry"
        );
    }

    // ── P1 #6: per-workload token semantics over HTTP ────────────────────

    /// When `TEMPLATE_RENDERER_AUTH_TOKEN` is configured it is the ONLY
    /// accepted credential: the universal `INTERNAL_SERVICE_TOKEN` gets 401
    /// (and is detected for loud logging) instead of authorizing requests.
    #[tokio::test]
    async fn dedicated_token_authorizes_and_universal_token_is_refused() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let config = test_config();
        let state = Arc::new(AppState {
            db: sqlx::PgPool::connect_lazy("postgres://localhost/test").expect("lazy pool"),
            sandbox: Sandbox::new(config.sandbox.clone()),
            cache: TemplateCache::new(config.cache.max_entries, config.cache.ttl_secs),
            config,
            // Dedicated token configured; universal retained only for
            // refusal detection.
            service_auth: ServiceAuth::resolve(
                Some("dedicated-secret"),
                Some("universal-legacy"),
                false,
            )
            .expect("dedicated auth resolves"),
        });
        let app = router(state);
        let probe = |app: axum::Router, key: &'static str| async move {
            let mut builder = Request::builder().uri("/starter");
            if !key.is_empty() {
                builder = builder.header("x-api-key", key);
            }
            app.oneshot(builder.body(Body::empty()).unwrap())
                .await
                .unwrap()
        };

        let response = probe(app.clone(), "dedicated-secret").await;
        assert_eq!(response.status(), StatusCode::OK, "dedicated token passes");
        let response = probe(app.clone(), "universal-legacy").await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "the universal token must be refused once the dedicated one is set"
        );
        let response = probe(app.clone(), "").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = probe(app, "wrong").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Legacy fallback (dedicated env unset): the universal token still
    /// authenticates outside production — migration-safe behavior.
    #[tokio::test]
    async fn unset_dedicated_token_keeps_universal_token_working() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let config = test_config();
        let state = Arc::new(AppState {
            db: sqlx::PgPool::connect_lazy("postgres://localhost/test").expect("lazy pool"),
            sandbox: Sandbox::new(config.sandbox.clone()),
            cache: TemplateCache::new(config.cache.max_entries, config.cache.ttl_secs),
            config,
            service_auth: ServiceAuth::resolve(None, Some("universal-legacy"), false)
                .expect("legacy auth resolves"),
        });
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/starter")
                    .header("x-api-key", "universal-legacy")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "legacy token still works");
    }

    // ── P1 #11: the HTTP /render path actually uses the cache ────────────

    async fn post_render(
        app: axum::Router,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        use tower::ServiceExt;
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/render")
                    .header("x-api-key", "test-key")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (status, json)
    }

    /// Same (source, props) twice: the second answer is `cached: true` and
    /// byte-identical in every output field.
    #[tokio::test]
    async fn render_cache_second_identical_request_is_hit_and_byte_identical() {
        let app = router(state_with_token("test-key"));
        let body = serde_json::json!({
            "source": "<p>Hi {{ name }}</p>",
            "props": { "name": "Ada" },
            "subject": "S: {{ name }}"
        });

        let (status_a, json_a) = post_render(app.clone(), body.clone()).await;
        assert_eq!(status_a, StatusCode::OK);
        assert_eq!(json_a["metadata"]["cached"], false, "first is a miss");

        let (status_b, json_b) = post_render(app.clone(), body).await;
        assert_eq!(status_b, StatusCode::OK);
        assert_eq!(json_b["metadata"]["cached"], true, "second must be a hit");
        assert_eq!(json_a["html"], json_b["html"], "byte-identical html");
        assert_eq!(json_a["plaintext"], json_b["plaintext"]);
        assert_eq!(json_a["subject"], json_b["subject"]);
        assert_eq!(json_a["warnings"], json_b["warnings"]);
    }

    /// Different props → different cache entry: the second render is still a
    /// miss and produces the OTHER props' output.
    #[tokio::test]
    async fn render_cache_distinguishes_props() {
        let app = router(state_with_token("test-key"));
        let first = serde_json::json!({
            "source": "<p>Hi {{ name }}</p>",
            "props": { "name": "Ada" },
        });
        let second = serde_json::json!({
            "source": "<p>Hi {{ name }}</p>",
            "props": { "name": "Grace" },
        });

        let (status_a, json_a) = post_render(app.clone(), first).await;
        assert_eq!(status_a, StatusCode::OK);
        let (status_b, json_b) = post_render(app.clone(), second).await;
        assert_eq!(status_b, StatusCode::OK);
        assert_eq!(
            json_b["metadata"]["cached"], false,
            "different props must be a different cache entry"
        );
        assert!(json_a["html"].as_str().unwrap().contains("Ada"));
        assert!(json_b["html"].as_str().unwrap().contains("Grace"));

        // Re-rendering the first props hits its (still valid) entry.
        let (_, json_again) = post_render(
            app,
            serde_json::json!({
                "source": "<p>Hi {{ name }}</p>",
                "props": { "name": "Ada" },
            }),
        )
        .await;
        assert_eq!(json_again["metadata"]["cached"], true);
        assert!(json_again["html"].as_str().unwrap().contains("Ada"));
    }

    /// Render options participate in the identity: flipping `minify` changes
    /// the key, so the minified variant is rendered and cached separately.
    #[tokio::test]
    async fn render_cache_distinguishes_options() {
        let app = router(state_with_token("test-key"));
        let plain = serde_json::json!({
            "source": "<div>  <p>hello</p>  </div>",
            "props": {},
            "generate_plaintext": false,
            "minify": false
        });
        let minified = serde_json::json!({
            "source": "<div>  <p>hello</p>  </div>",
            "props": {},
            "generate_plaintext": false,
            "minify": true
        });

        let (_, json_a) = post_render(app.clone(), plain).await;
        let (_, json_b) = post_render(app.clone(), minified).await;
        assert_eq!(json_b["metadata"]["cached"], false, "options change = new key");
        assert_ne!(json_a["html"], json_b["html"]);
    }

    // ── P1 #12: /health (liveness) vs /ready (dependency honesty) ────────

    /// `/health` must stay a pure liveness answer: 200 even when the DB pool
    /// is unreachable (it must not consult dependencies).
    #[tokio::test]
    async fn health_stays_liveness_when_database_is_down() {
        use tower::ServiceExt;

        let config = test_config();
        let state = Arc::new(AppState {
            // Port 1 on loopback: nothing listens there — deterministically down.
            db: sqlx::PgPool::connect_lazy("postgres://127.0.0.1:1/none").expect("lazy pool"),
            sandbox: Sandbox::new(config.sandbox.clone()),
            cache: TemplateCache::new(config.cache.max_entries, config.cache.ttl_secs),
            config,
            service_auth: auth_with_token("test-key"),
        });
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "healthy");
    }

    /// `/ready` with the DB pool unreachable: 503 with `status: "degraded"`
    /// and the failing dependency NAMED.
    #[tokio::test]
    async fn ready_reports_degraded_with_named_dependency_when_database_is_down() {
        use tower::ServiceExt;

        let config = test_config();
        let state = Arc::new(AppState {
            db: sqlx::PgPool::connect_lazy("postgres://127.0.0.1:1/none").expect("lazy pool"),
            sandbox: Sandbox::new(config.sandbox.clone()),
            cache: TemplateCache::new(config.cache.max_entries, config.cache.ttl_secs),
            config,
            service_auth: auth_with_token("test-key"),
        });
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "degraded", "{json}");
        assert_ne!(
            json["dependencies"]["database"], "up",
            "the failing dependency must be named honestly: {json}"
        );
    }

    /// `/ready` with a live database (same TEST_DATABASE_URL convention as
    /// the F62 stored-template tests — skipped when unset).
    #[tokio::test]
    async fn ready_reports_ready_when_database_is_up() {
        use tower::ServiceExt;

        let Some(database_url) = std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
        else {
            // coverage: justified — env-gated soft-skip; this branch runs when
            // the suite executes WITHOUT TEST_DATABASE_URL (the coverage run
            // sets it and exercises the DB-backed assertions below instead).
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let pool = sqlx::PgPool::connect(&database_url).await.expect("live pool");

        let config = test_config();
        let state = Arc::new(AppState {
            db: pool,
            sandbox: Sandbox::new(config.sandbox.clone()),
            cache: TemplateCache::new(config.cache.max_entries, config.cache.ttl_secs),
            config,
            service_auth: auth_with_token("test-key"),
        });
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ready", "{json}");
        assert_eq!(json["dependencies"]["database"], "up", "{json}");
    }

    /// `/ready` when the DB check FAILS (not times out): a closed pool errors
    /// the query immediately, so the handler must answer 503 degraded with
    /// `database: "down"` — the honest failure arm, distinct from the
    /// timeout arm.
    #[tokio::test]
    async fn ready_names_the_database_down_when_the_check_errors_without_timing_out() {
        use tower::ServiceExt;

        let config = test_config();
        let pool = sqlx::PgPool::connect_lazy("postgres://127.0.0.1:1/none").expect("lazy pool");
        // A closed pool fails `SELECT 1` immediately with PoolClosed — no
        // acquire timeout, so the handler's error arm (not the timeout arm)
        // runs.
        pool.close().await;
        let state = Arc::new(AppState {
            db: pool,
            sandbox: Sandbox::new(config.sandbox.clone()),
            cache: TemplateCache::new(config.cache.max_entries, config.cache.ttl_secs),
            config,
            service_auth: auth_with_token("test-key"),
        });
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "degraded", "{json}");
        assert_eq!(
            json["dependencies"]["database"], "down",
            "an errored check must be named down, not timeout: {json}"
        );
    }

    /// Every sandbox failure mode maps to its honest HTTP status through the
    /// render handler's error arm: oversized source (413), oversized output
    /// (413), zero-budget timeout (504), forbidden module (403) and a
    /// dangerous-pattern syntax error (400).
    #[tokio::test]
    async fn render_failure_modes_map_to_honest_status_codes() {
        use tower::ServiceExt;

        let render = |app: axum::Router, source: serde_json::Value| async move {
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/render")
                    .header("x-api-key", "test-key")
                    .header("content-type", "application/json")
                    .body(Body::from(source.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
        };

        // SourceTooLarge: 600 KB source against a 512 KB cap → 413.
        let app = router(state_with_token("test-key"));
        let huge = serde_json::json!({ "source": "a".repeat(600_000) });
        let response = render(app.clone(), huge).await;
        assert_eq!(
            response.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "oversized source must be 413"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "SOURCE_TOO_LARGE", "{json}");

        // ForbiddenModule → 403.
        let response = render(
            app.clone(),
            serde_json::json!({ "source": "import fs from 'fs'; <div>evil</div>" }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "fs import is 403");

        // InvalidSyntax (dangerous pattern) → 400.
        let response = render(
            app.clone(),
            serde_json::json!({ "source": "<p>{{ process }}</p>" }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "eval-ish is 400");

        // Timeout: a state whose sandbox budget is already spent → 504.
        let mut config = test_config();
        config.sandbox.timeout_ms = 0;
        let expired = Arc::new(AppState {
            db: sqlx::PgPool::connect_lazy("postgres://localhost/test").expect("lazy pool"),
            sandbox: Sandbox::new(config.sandbox.clone()),
            cache: TemplateCache::new(config.cache.max_entries, config.cache.ttl_secs),
            config,
            service_auth: auth_with_token("test-key"),
        });
        let response = render(
            router(expired),
            serde_json::json!({ "source": "<p>hello</p>" }),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::GATEWAY_TIMEOUT,
            "an exhausted sandbox budget must be 504"
        );

        // OutputTooLarge: a 10-byte output cap → 413 with OUTPUT_TOO_LARGE.
        let mut config = test_config();
        config.sandbox.max_output_length = 10;
        let tiny_output = Arc::new(AppState {
            db: sqlx::PgPool::connect_lazy("postgres://localhost/test").expect("lazy pool"),
            sandbox: Sandbox::new(config.sandbox.clone()),
            cache: TemplateCache::new(config.cache.max_entries, config.cache.ttl_secs),
            config,
            service_auth: auth_with_token("test-key"),
        });
        let response = render(
            router(tiny_output),
            serde_json::json!({ "source": "<p>hello</p>" }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "OUTPUT_TOO_LARGE", "{json}");
    }
}
