//! Health-check endpoints.
//!
//! - `GET /health` and `GET /health/`, liveness alias (always 200)
//! - `GET /health/live`, liveness probe (always 200)
//! - `GET /health/ready`, readiness: DB + Redis (uses circuit breaker for
//!   the DB check) + required-schema probe
//! - `GET /health/deep`, comprehensive with response times
//!
//! # Public vs privileged callers (third external audit)
//!
//! `/health/ready` and `/health/deep` sit on the externally routed api
//! vhosts (nginx proxies every unmatched path to api-server), and their
//! dependency detail ("db: connected", per-dependency state, response
//! times) is an attacker reconnaissance gift. The EXTERNAL contract for
//! anonymous callers is therefore ONLY:
//!
//! * healthy → `200 {"status":"ok"}`
//! * unhealthy → `503 {"status":"unavailable"}`
//!
//! The full dependency detail is served when the caller is loopback
//! (Kubernetes/docker/monitoring probes, `127.0.0.1` / `::1`) or presents
//! the internal monitoring token. The token mechanism MIRRORS the
//! enterprise metrics handler (crates/enterprise/src/routes.rs, fix H-3):
//! the SAME `METRICS_TOKEN` environment variable, read as a `Bearer`
//! credential, compared in constant time.

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::time::Instant;

use crate::resilience::CircuitBreakerError;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(liveness))
        .route("/live", get(liveness))
        .route("/ready", get(readiness))
        .route("/deep", get(deep_check))
}

// ─── Liveness ──────────────────────────────────────────────────

async fn liveness() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok"}))
}

// ─── Caller classification ─────────────────────────────────────

/// The external (anonymous) health body: healthy answers exactly
/// `{"status":"ok"}` with 200, unhealthy answers exactly
/// `{"status":"unavailable"}` with 503, NOTHING else (no dependency
/// names, no states, no timing).
fn external_health_response(healthy: bool) -> (StatusCode, Json<serde_json::Value>) {
    if healthy {
        (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"status": "unavailable"})),
        )
    }
}

/// Constant-time string comparison (the enterprise metrics handler's
/// pattern): hash both values and compare the digests, so the comparison
/// time does not leak the expected token's length or prefix.
fn constant_time_eq(provided: &str, expected: &str) -> bool {
    let digest = |value: &str| {
        let mut hasher = Sha256::new();
        hasher.update(value.as_bytes());
        hasher.finalize()
    };
    digest(provided) == digest(expected)
}

/// May this caller see the detailed (dependency-by-dependency) health
/// view? Loopback peers (in-container orchestrator probes, the monitoring
/// sidecar) and bearers of the internal `METRICS_TOKEN` may; everyone
/// else gets the minimal external body only. A missing `ConnectInfo`
/// (unit-test harnesses, a server not built with
/// `into_make_service_with_connect_info`) is treated as NON-loopback:
/// the detailed view fails closed.
fn caller_may_see_detail(peer: Option<SocketAddr>, headers: &HeaderMap) -> bool {
    let peer_is_loopback = peer.map(|addr| addr.ip().is_loopback()).unwrap_or(false);

    let token_ok = std::env::var("METRICS_TOKEN")
        .ok()
        .map(|expected| expected.trim().to_string())
        .filter(|expected| !expected.is_empty())
        .and_then(|expected| {
            headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("Bearer "))
                .map(|provided| constant_time_eq(provided.trim(), &expected))
        })
        .unwrap_or(false);

    peer_is_loopback || token_ok
}

// ─── Readiness ─────────────────────────────────────────────────

/// How long the readiness probe may take before it reports the service
/// degraded.
///
/// A health endpoint that can hang is a health endpoint that causes restart
/// loops: the orchestrator's probe never gets an answer, so it kills the
/// instance and tries again, forever. The bound makes the endpoint ALWAYS
/// answer within this window, degraded is a valid, actionable answer;
/// silence is not.
const READINESS_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

async fn readiness(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    match tokio::time::timeout(READINESS_DEADLINE, readiness_inner(&state)).await {
        Ok((status, body)) => {
            if caller_may_see_detail(connect_info.map(|ci| ci.0), &headers) {
                (status, body)
            } else {
                external_health_response(status == StatusCode::OK)
            }
        }
        Err(_) => {
            tracing::warn!(
                deadline_secs = READINESS_DEADLINE.as_secs(),
                "readiness: dependency checks exceeded the deadline; reporting degraded"
            );
            if caller_may_see_detail(connect_info.map(|ci| ci.0), &headers) {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "status": "degraded",
                        "db": "unknown",
                        "redis": "unknown",
                        "schema": "unknown",
                        "error": "dependency checks exceeded the readiness deadline",
                    })),
                )
            } else {
                external_health_response(false)
            }
        }
    }
}

async fn readiness_inner(state: &AppState) -> (StatusCode, Json<serde_json::Value>) {
    // Use circuit breaker for DB check, if the circuit is open, we fail fast
    // instead of waiting for a connection timeout.
    let db_result = state
        .resilient
        .db
        .call(|| async {
            sqlx::query_scalar::<_, i32>("SELECT 1")
                .fetch_one(&state.db)
                .await
                .map_err(|e| anyhow::anyhow!("DB query failed: {e}"))
        })
        .await;

    let db_ok = match &db_result {
        Ok(_) => true,
        Err(CircuitBreakerError::CircuitOpen { name }) => {
            tracing::warn!(dependency = %name, "readiness: DB circuit breaker is open");
            false
        }
        Err(CircuitBreakerError::Inner(e)) => {
            tracing::warn!(error = %e, "readiness: DB check failed");
            false
        }
    };

    let redis_ok = async {
        let mut conn = state.redis.get().await?;
        let pong: String = redis::cmd("PING").query_async(&mut conn).await?;
        Ok::<bool, anyhow::Error>(pong == "PONG")
    }
    .await
    .unwrap_or_else(|e| {
        tracing::warn!(error = %e, "Redis readiness check failed");
        false
    });

    // F14: required-schema readiness. A misdeployed schema (missing console
    // table/column, SQLSTATE 42P01/42703) used to pass readiness and then
    // render empty pages / zero KPIs. The probe fails readiness FIRST, so a
    // rollout with a missing column never serves fabricated empty data.
    let schema_missing: Vec<String> = if db_ok {
        match crate::routes::web::data::missing_required_console_schema(&state.db).await {
            Ok(missing) => missing,
            Err(error) => {
                tracing::warn!(error = %error, "readiness: required-schema probe failed");
                vec!["schema probe unavailable".to_string()]
            }
        }
    } else {
        Vec::new() // DB already degraded; the db flag reports it.
    };
    let schema_ok = db_ok && schema_missing.is_empty();

    if db_ok && redis_ok && schema_ok {
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "ok",
                "db": "connected",
                "redis": "connected",
                "schema": "complete",
            })),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "degraded",
                "db": if db_ok { "connected" } else { "disconnected" },
                "redis": if redis_ok { "connected" } else { "disconnected" },
                "schema": if schema_ok {
                    serde_json::json!("complete")
                } else {
                    serde_json::json!(schema_missing)
                },
            })),
        )
    }
}

// ─── Deep check ────────────────────────────────────────────────

#[derive(Serialize)]
struct DeepCheck {
    status: &'static str,
    db: ComponentCheck,
    redis: ComponentCheck,
}

#[derive(Serialize)]
struct ComponentCheck {
    status: &'static str,
    response_time_ms: u64,
}

async fn deep_check(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let db_start = Instant::now();
    let db_ok = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.db)
        .await
        .is_ok();
    let db_ms = db_start.elapsed().as_millis() as u64;

    let redis_start = Instant::now();
    let redis_ok = async {
        let mut conn = state.redis.get().await?;
        let _: String = redis::cmd("PING").query_async(&mut conn).await?;
        Ok::<_, anyhow::Error>(())
    }
    .await
    .is_ok();
    let redis_ms = redis_start.elapsed().as_millis() as u64;

    let all_ok = db_ok && redis_ok;

    let status = if all_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    // The per-dependency detail (states, response times) is internal
    // reconnaissance data: loopback peers and METRICS_TOKEN bearers only.
    if !caller_may_see_detail(connect_info.map(|ci| ci.0), &headers) {
        return external_health_response(all_ok);
    }

    let body = DeepCheck {
        status: if all_ok { "ok" } else { "degraded" },
        db: ComponentCheck {
            status: if db_ok { "connected" } else { "disconnected" },
            response_time_ms: db_ms,
        },
        redis: ComponentCheck {
            status: if redis_ok {
                "connected"
            } else {
                "disconnected"
            },
            response_time_ms: redis_ms,
        },
    };

    let detail =
        serde_json::to_value(&body).unwrap_or_else(|_| serde_json::json!({"status": "degraded"}));
    (status, Json(detail))
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::response::IntoResponse;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_liveness_returns_ok() {
        let resp = liveness().await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// A dead lazy pool + a dead Redis URL: every dependency check fails
    /// fast, exactly the fixture the degraded branches need.
    async fn dead_state() -> AppState {
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(200))
            .connect_lazy("postgres://apexmail:apexmail@127.0.0.1:1/absent")
            .expect("lazy dead pool");
        crate::app::test_support::test_state_over(db).await
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        serde_json::from_slice(&bytes).expect("JSON body")
    }

    fn loopback() -> Option<ConnectInfo<SocketAddr>> {
        Some(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 50000))))
    }

    fn remote() -> Option<ConnectInfo<SocketAddr>> {
        Some(ConnectInfo(SocketAddr::from(([203, 0, 113, 9], 50000))))
    }

    fn bearer_headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        headers
    }

    /// Use-all audit (health): with an unreachable database the endpoints
    /// must answer 503 with the named component states for PRIVILEGED
    /// (loopback) callers, never a fabricated "ok".
    #[tokio::test]
    async fn readiness_and_deep_check_report_a_disconnected_database_to_loopback() {
        let state = dead_state().await;

        let response = readiness(State(state.clone()), loopback(), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let json = body_json(response).await;
        assert_eq!(json["status"], "degraded");
        assert_eq!(json["db"], "disconnected");

        let response = deep_check(State(state), loopback(), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let json = body_json(response).await;
        assert_eq!(json["db"]["status"], "disconnected");
    }

    /// Third external audit: an ANONYMOUS caller gets the minimal external
    /// contract only. Healthy or not, the body is exactly
    /// {"status":"ok"} / {"status":"unavailable"}: no dependency names, no
    /// states, no schema detail, no timing.
    #[tokio::test]
    async fn anonymous_callers_get_the_minimal_body_only() {
        let state = dead_state().await;

        // No ConnectInfo at all (a caller whose peer address is unknown
        // fails CLOSED to the minimal view).
        let response = readiness(State(state.clone()), None, HeaderMap::new())
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let json = body_json(response).await;
        assert_eq!(json, serde_json::json!({"status": "unavailable"}));

        // A remote peer without the monitoring token: same minimal body.
        let response = readiness(State(state.clone()), remote(), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let json = body_json(response).await;
        assert_eq!(json, serde_json::json!({"status": "unavailable"}));

        let response = deep_check(State(state.clone()), remote(), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let json = body_json(response).await;
        assert_eq!(json, serde_json::json!({"status": "unavailable"}));

        // The healthy external shape is the exact minimal ok body too.
        let (status, body) = external_health_response(true);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.0, serde_json::json!({"status": "ok"}));
    }

    /// The METRICS_TOKEN bearer path mirrors the enterprise metrics
    /// handler: a remote peer WITH the token sees the dependency detail, a
    /// remote peer with a wrong token does not.
    #[tokio::test]
    async fn remote_callers_with_the_metrics_token_see_the_detail() {
        struct ScopedMetricsToken;
        impl ScopedMetricsToken {
            fn install(value: &str) -> Self {
                std::env::set_var("METRICS_TOKEN", value);
                ScopedMetricsToken
            }
        }
        impl Drop for ScopedMetricsToken {
            fn drop(&mut self) {
                std::env::remove_var("METRICS_TOKEN");
            }
        }

        let state = dead_state().await;
        let _token = ScopedMetricsToken::install("health-test-monitoring-token");

        // Right token, remote peer: the detailed degraded body.
        let response = readiness(
            State(state.clone()),
            remote(),
            bearer_headers("health-test-monitoring-token"),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let json = body_json(response).await;
        assert_eq!(json["status"], "degraded");
        assert_eq!(json["db"], "disconnected");

        // Wrong token, remote peer: back to the minimal external body.
        let response = readiness(
            State(state.clone()),
            remote(),
            bearer_headers("not-the-token"),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let json = body_json(response).await;
        assert_eq!(json, serde_json::json!({"status": "unavailable"}));

        // Deep check, same split.
        let response = deep_check(
            State(state.clone()),
            remote(),
            bearer_headers("health-test-monitoring-token"),
        )
        .await
        .into_response();
        let json = body_json(response).await;
        assert_eq!(json["db"]["status"], "disconnected");

        let response = deep_check(
            State(state.clone()),
            remote(),
            bearer_headers("not-the-token"),
        )
        .await
        .into_response();
        let json = body_json(response).await;
        assert_eq!(json, serde_json::json!({"status": "unavailable"}));
    }

    /// Loopback is 127.0.0.1 AND ::1 (IPv6 containers); anything else,
    /// including the v4-mapped form, is judged by the bearer token only.
    #[test]
    fn caller_classification_is_loopback_or_token() {
        assert!(caller_may_see_detail(
            Some(SocketAddr::from(([127, 0, 0, 1], 443))),
            &HeaderMap::new()
        ));
        assert!(caller_may_see_detail(
            Some(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 443))),
            &HeaderMap::new()
        ));
        assert!(!caller_may_see_detail(
            Some(SocketAddr::from(([203, 0, 113, 9], 443))),
            &HeaderMap::new()
        ));
        assert!(!caller_may_see_detail(None, &HeaderMap::new()));
        // A bearer-shaped header without a configured token grants nothing.
        assert!(!caller_may_see_detail(
            Some(SocketAddr::from(([203, 0, 113, 9], 443))),
            &bearer_headers("anything")
        ));
    }

    /// Endpoint-level wiring: through the real router, an anonymous
    /// request (no ConnectInfo) answers the minimal body and a loopback
    /// request answers the detailed one.
    #[tokio::test]
    async fn health_router_splits_anonymous_and_loopback_callers() {
        use axum::extract::ConnectInfo as CI;
        let state = dead_state().await;
        let app = router().with_state(state);

        let response = app
            .clone()
            .oneshot(Request::get("/ready").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let json = body_json(response).await;
        assert_eq!(json, serde_json::json!({"status": "unavailable"}));

        let mut request = Request::get("/deep").body(Body::empty()).unwrap();
        request
            .extensions_mut()
            .insert(CI(SocketAddr::from(([127, 0, 0, 1], 50000))));
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let json = body_json(response).await;
        assert_eq!(json["db"]["status"], "disconnected");
    }

    #[test]
    fn test_deep_check_serialisation() {
        let dc = DeepCheck {
            status: "ok",
            db: ComponentCheck {
                status: "connected",
                response_time_ms: 3,
            },
            redis: ComponentCheck {
                status: "connected",
                response_time_ms: 1,
            },
        };
        let json = serde_json::to_value(&dc).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["db"]["response_time_ms"], 3);
    }

    #[test]
    fn test_component_check_fields() {
        let c = ComponentCheck {
            status: "disconnected",
            response_time_ms: 999,
        };
        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(json["status"], "disconnected");
    }
}
