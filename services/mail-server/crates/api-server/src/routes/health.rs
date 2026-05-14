//! Health-check endpoints.
//!
//! - `GET /health/live` — liveness probe (always 200)
//! - `GET /health/ready` — readiness:DB + Redis (uses circuit breaker for DB check)
//! - `GET /health/deep` — comprehensive with response times

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use std::time::Instant;

use crate::resilience::CircuitBreakerError;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/live", get(liveness))
        .route("/ready", get(readiness))
        .route("/deep", get(deep_check))
}

// ─── Liveness ──────────────────────────────────────────────────

async fn liveness() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok"}))
}

// ─── Readiness ─────────────────────────────────────────────────

async fn readiness(State(state): State<AppState>) -> impl IntoResponse {
    // Use circuit breaker for DB check — if the circuit is open, we fail fast
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

    if db_ok && redis_ok {
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "ok",
                "db": "connected",
                "redis": "connected",
            })),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "degraded",
                "db": if db_ok { "connected" } else { "disconnected" },
                "redis": if redis_ok { "connected" } else { "disconnected" },
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

async fn deep_check(State(state): State<AppState>) -> impl IntoResponse {
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

    let status = if all_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status, Json(body))
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_liveness_returns_ok() {
        let resp = liveness().await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
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
