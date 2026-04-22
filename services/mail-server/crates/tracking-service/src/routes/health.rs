//! Health-check and readiness-probe endpoints.
//!
//! GET `/health` — liveness probe; returns 200 normally, 503 when shutting down.
//! GET `/ready` — readiness probe; checks DB + Redis connectivity in parallel.

use std::sync::atomic::{AtomicBool, Ordering};

use axum::{
    extract::State,
    response::{IntoResponse, Json, Response},
    http::StatusCode,
};
use serde_json::json;
use tracing::error;

use crate::state::AppState;

/// Set to `true` when SIGTERM/SIGINT is received. The `/health` endpoint
/// returns 503 once this flag is set, signalling to the load-balancer that
/// the pod should no longer receive new connections (-500-354).
pub static SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);

pub async fn handle_health() -> Response {
    if SHUTTING_DOWN.load(Ordering::Relaxed) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "shutting_down", "service": "tracking" })),
        )
            .into_response();
    }
    Json(json!({ "status": "healthy", "service": "tracking" })).into_response()
}

pub async fn handle_ready(State(state): State<AppState>) -> Response {
    let db_check = sqlx::query("SELECT 1").execute(&state.db);
    let redis_check = ping_redis(state.redis.clone());

    let (db_res, redis_res) = tokio::join!(db_check, redis_check);

    if let Err(e) = db_res {
        error!(error = %e, "Readiness check: DB failure");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "not ready" })),
        )
            .into_response();
    }

    if let Err(e) = redis_res {
        error!(error = %e, "Readiness check: Redis failure");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "not ready" })),
        )
            .into_response();
    }

    Json(json!({ "status": "ready" })).into_response()
}

async fn ping_redis(pool: deadpool_redis::Pool) -> anyhow::Result<()> {
    let mut conn = pool.get().await?;
    let _: String = redis::cmd("PING").query_async(&mut *conn).await?;
    Ok(())
}
