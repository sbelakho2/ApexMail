//! IP warmup schedule management endpoints.
//!

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(list_warmup).post(warmup_action))
}

async fn update_pool_status(
    db: &sqlx::PgPool,
    pool_id: &str,
    new_status: &str,
) -> Result<(), ApiError> {
    let result = sqlx::query("UPDATE ip_pools SET status = $1, updated_at = NOW() WHERE id = $2")
        .bind(new_status)
        .bind(pool_id)
        .execute(db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("ip pool not found".into()));
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmupQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpAddress {
    pub id: String,
    pub ip_address: String,
    pub status: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WarmupSchedule {
    pub id: String,
    pub day: i32,
    pub target_volume: i64,
    pub actual_volume: Option<i64>,
    pub status: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpPool {
    pub id: String,
    pub name: String,
    pub status: String,
    pub created_at: String,
    pub addresses: Vec<IpAddress>,
    pub schedules: Vec<WarmupSchedule>,
}

async fn list_warmup(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<WarmupQuery>,
) -> Result<Json<Vec<IpPool>>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let db = &state.db;
    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);

    // Fetch pools
    let pool_rows: Vec<(String, String, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT id, name, status, created_at FROM ip_pools ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await?;

    let pool_ids: Vec<String> = pool_rows.iter().map(|(id, ..)| id.clone()).collect();

    if pool_ids.is_empty() {
        return Ok(Json(vec![]));
    }

    // Fetch addresses for all pools
    let addr_rows: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT id, pool_id, ip_address, status FROM ip_pool_addresses WHERE pool_id = ANY($1)",
    )
    .bind(&pool_ids)
    .fetch_all(db)
    .await?;

    // Fetch schedules for all pools
    let schedule_rows: Vec<(String, String, i32, i64, Option<i64>, String)> = sqlx::query_as(
        "SELECT id, pool_id, day, target_volume, actual_volume, status FROM isp_warmup_schedules WHERE pool_id = ANY($1) ORDER BY day ASC",
    )
    .bind(&pool_ids)
    .fetch_all(db)
    .await?;

    let pools: Vec<IpPool> = pool_rows
        .into_iter()
        .map(|(id, name, status, created_at)| {
            let addresses: Vec<IpAddress> = addr_rows
                .iter()
                .filter(|(_, pool_id, ..)| pool_id == &id)
                .map(|(aid, _, ip, astatus)| IpAddress {
                    id: aid.clone(),
                    ip_address: ip.clone(),
                    status: astatus.clone(),
                })
                .collect();

            let schedules: Vec<WarmupSchedule> = schedule_rows
                .iter()
                .filter(|(_, pool_id, ..)| pool_id == &id)
                .map(|(sid, _, day, target, actual, sstatus)| WarmupSchedule {
                    id: sid.clone(),
                    day: *day,
                    target_volume: *target,
                    actual_volume: *actual,
                    status: sstatus.clone(),
                })
                .collect();

            IpPool {
                id,
                name,
                status,
                created_at: created_at.to_rfc3339(),
                addresses,
                schedules,
            }
        })
        .collect();

    Ok(Json(pools))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct WarmupAction {
    pub pool_id: String,
    pub action: String,
}

async fn warmup_action(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: HeaderMap,
    Json(body): Json<WarmupAction>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let allowed = ["start", "pause", "reset"];
    if !allowed.contains(&body.action.as_str()) {
        return Err(ApiError::Validation(vec![
            "Invalid action. Use start, pause, or reset.".into(),
        ]));
    }

    let new_status = match body.action.as_str() {
        "start" => "active",
        "pause" => "paused",
        "reset" => "pending",
        // Pre-validated above - unreachable if reached, but needed for exhaustiveness
        _ => return Err(ApiError::Internal("unreachable warmup action".into())),
    };

    update_pool_status(&state.db, &body.pool_id, new_status).await?;

    if body.action == "reset" {
        sqlx::query(
            "UPDATE isp_warmup_schedules SET status = 'pending', actual_volume = NULL WHERE pool_id = $1",
        )
        .bind(&body.pool_id)
        .execute(&state.db)
        .await?;
    }

    // Audit log
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");
    let ua = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    if let Err(e) = sqlx::query(
        "INSERT INTO audit_logs (timestamp, action, resource_type, resource_id, ip_address, user_agent, metadata)
         VALUES (NOW(), $1, 'ip_pool', $2, $3, $4, $5::jsonb)",
    )
    .bind(format!("warmup.{}", body.action))
    .bind(&body.pool_id)
    .bind(ip)
    .bind(ua)
    .bind(serde_json::json!({ "action": body.action, "newStatus": new_status }))
    .execute(&state.db)
    .await
    {
        tracing::warn!(pool_id = %body.pool_id, error = %e, "Failed to write warmup audit log");
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "status": new_status,
        "message": format!("Pool {} {}", body.pool_id, body.action)
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    use sqlx::{migrate::Migrator, PgPool};
    use uuid::Uuid;

    fn tool_migrations_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../tools/migrations")
    }

    async fn apply_tool_migrations(pool: &PgPool) {
        let source_dir = tool_migrations_dir();
        let temp_dir = std::env::temp_dir().join(format!(
            "apexmail-api-warmup-up-migrations-{}",
            Uuid::new_v4()
        ));

        fs::create_dir_all(&temp_dir).expect("failed to create temp sqlx migration directory");

        let mut entries: Vec<PathBuf> = fs::read_dir(&source_dir)
            .expect("failed to read tools/migrations")
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("sql"))
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| {
                        !name.ends_with("_down.sql") && !name.contains("performance_indexes")
                    })
                    .unwrap_or(false)
            })
            .collect();
        entries.sort();

        for path in entries {
            let file_name = path.file_name().expect("migration path missing filename");
            let raw = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("failed to read migration {:?}: {error}", path));
            let normalized = raw
                .replace("CREATE UNIQUE INDEX CONCURRENTLY", "CREATE UNIQUE INDEX")
                .replace("CREATE INDEX CONCURRENTLY", "CREATE INDEX");
            fs::write(temp_dir.join(file_name), normalized).unwrap_or_else(|error| {
                panic!("failed to write copied migration {:?}: {error}", path)
            });
        }

        let migrator = Migrator::new(temp_dir.clone())
            .await
            .expect("failed to load copied up migrations");
        migrator
            .run(pool)
            .await
            .expect("failed to apply copied up migrations");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn warmup_action_returns_not_found_for_missing_pool() {
        let Some(pool) =
            crate::test_db::optional_pg_pool("warmup_action_returns_not_found_for_missing_pool")
                .await
        else {
            return;
        };
        apply_tool_migrations(&pool).await;

        let error = update_pool_status(&pool, "pool_missing", "active")
            .await
            .expect_err("missing pools should be rejected");

        assert!(matches!(error, ApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn warmup_action_updates_existing_pool_status() {
        let Some(pool) =
            crate::test_db::optional_pg_pool("warmup_action_updates_existing_pool_status").await
        else {
            return;
        };
        apply_tool_migrations(&pool).await;

        let pool_id = apexmail_lib::id::generate_id("ipp", 22);
        sqlx::query("INSERT INTO ip_pools (id, name, status) VALUES ($1, $2, 'pending')")
            .bind(&pool_id)
            .bind("Primary Pool")
            .execute(&pool)
            .await
            .expect("failed to insert test ip pool");

        update_pool_status(&pool, &pool_id, "active")
            .await
            .expect("existing pools should update cleanly");

        let row: (String,) = sqlx::query_as("SELECT status FROM ip_pools WHERE id = $1")
            .bind(&pool_id)
            .fetch_one(&pool)
            .await
            .expect("failed to fetch updated pool status");
        assert_eq!(row.0, "active");
    }
}
