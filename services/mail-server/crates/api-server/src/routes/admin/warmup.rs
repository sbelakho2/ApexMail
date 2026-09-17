//! Advisory IP warmup CATALOG management endpoints.
//!
//! # These endpoints are NOT an admission control
//!
//! This router manages advisory data only: the per-pool warmup PLAN rows in
//! `isp_warmup_schedules` and the `ip_pools.status` flag. Neither is read by
//! the send path. Warmup admission is enforced per SOURCE IP in
//! `worker-processors`:
//!
//! * the daily cap is the canonical
//!   `mail_common::warmup::WarmupSchedule::limit_for_day`, derived from
//!   `dedicated_ips.warmup_started_at`;
//! * the reservation is the Redis key
//!   `apexmail:warmup:ip:{ip_address}:{utc_day}`, taken atomically before
//!   the transport.
//!
//! `start` / `pause` / `reset` here canNOT start, pause, raise, or lower that
//! admission. Responses carry `"advisory": true` (and the action response
//! `"admissionControl": false`) so API consumers cannot mistake the plan for
//! a live control.
//!
//! The ISP-specific schedule targets (`isp_warmup_templates`) are advisory
//! for the same reason: no live path resolves the recipient's provider/MX at
//! admission time (the SMTP relay performs MX resolution and does not report
//! it; SES does not report it either), so a `min(canonical, ISP target)` rule
//! cannot be computed in the send path.

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

/// Update a pool's ADVISORY status flag. `ip_pools.status` is not consulted
/// by the send path (warmup admission keys on `dedicated_ips` + Redis), so
/// this cannot start or pause enforcement.
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

/// One ADVISORY plan day for a pool (`isp_warmup_schedules`). Nothing in the
/// send path reads this row; `actual_volume` has no runtime writer anymore
/// (the execution runner was removed with the inert ISP execution model), so
/// it is legacy display data only.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvisoryWarmupDay {
    pub id: String,
    pub day: i32,
    pub target_volume: i64,
    pub actual_volume: Option<i64>,
    pub status: String,
}

/// Advisory pool view. `advisory` is always `true`: this payload describes a
/// plan, not an admission control (see the module docs).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpPool {
    pub id: String,
    pub name: String,
    pub status: String,
    pub created_at: String,
    pub addresses: Vec<IpAddress>,
    pub schedules: Vec<AdvisoryWarmupDay>,
    /// Always `true`. Present so API consumers cannot mistake the warmup plan
    /// for the live per-source-IP admission in `worker-processors`.
    pub advisory: bool,
}

/// List the advisory warmup plan for the platform's IP pools. Read-only with
/// respect to admission: the canonical per-source-IP warmup control lives in
/// `worker-processors` and is not represented here (see the module docs).
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

    // Fetch addresses for all pools. Canonical ip_pool_addresses ids are
    // UUIDs and ip_address is INET — both cast to text at the boundary so
    // the String row decode matches the canonical schema.
    let addr_rows: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT id::text AS id, pool_id, ip_address::text AS ip_address, status \
         FROM ip_pool_addresses WHERE pool_id = ANY($1)",
    )
    .bind(&pool_ids)
    .fetch_all(db)
    .await?;

    // Fetch schedules for all pools (canonical ids are UUIDs — cast to text).
    let schedule_rows: Vec<(String, String, i32, i64, Option<i64>, String)> = sqlx::query_as(
        "SELECT id::text AS id, pool_id, day, target_volume, actual_volume, status \
         FROM isp_warmup_schedules WHERE pool_id = ANY($1) ORDER BY day ASC",
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

            let schedules: Vec<AdvisoryWarmupDay> = schedule_rows
                .iter()
                .filter(|(_, pool_id, ..)| pool_id == &id)
                .map(|(sid, _, day, target, actual, sstatus)| AdvisoryWarmupDay {
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
                advisory: true,
            }
        })
        .collect();

    Ok(Json(pools))
}

/// Advisory plan action. `start` / `pause` / `reset` toggle the ADVISORY
/// per-pool plan (`ip_pools.status` + `isp_warmup_schedules` rows) only;
/// they do not touch the live per-source-IP admission in `worker-processors`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct WarmupAction {
    pub pool_id: String,
    pub action: String,
}

/// Apply an advisory plan action to a pool. The response states
/// `"advisory": true` / `"admissionControl": false` explicitly: the live
/// warmup cap is the canonical per-IP schedule in the send path, not this
/// row (see the module docs).
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

    crate::audit_log::insert_audit_log_best_effort(
        &state.db,
        Some(&auth.tenant_id),
        None,
        &format!("warmup.{}", body.action),
        "ip_pool",
        Some(&body.pool_id),
        serde_json::json!({ "action": body.action, "newStatus": new_status }),
        Some(ip),
        Some(ua),
    )
    .await;

    Ok(Json(serde_json::json!({
        "success": true,
        "advisory": true,
        "admissionControl": false,
        "status": new_status,
        "message": format!(
            "Advisory warmup plan for pool {} set to {} — this does not control send admission",
            body.pool_id, new_status
        )
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn warmup_action_returns_not_found_for_missing_pool() {
        let Some(pool) =
            crate::test_db::optional_pg_pool("warmup_action_returns_not_found_for_missing_pool")
                .await
        else {
            return;
        };

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

    /// Source lock: the admin surface must keep SAYING it is advisory, and
    /// must keep naming the canonical live path, so the route can never
    /// silently imply it controls admission. Needles are assembled so this
    /// test's own text cannot satisfy them.
    #[test]
    fn warmup_routes_document_advisory_only_semantics() {
        let source = include_str!("warmup.rs");
        for needle in [
            concat!("NOT an admission", " control"),
            concat!("does not control", " send admission"),
            concat!("\"advisory\": ", "true"),
            concat!("\"admissionControl\": ", "false"),
            concat!("apexmail:warmup:ip:", "{ip_address}:{utc_day}"),
            concat!("mail_common::warmup::WarmupSchedule", "::limit_for_day"),
        ] {
            assert!(
                source.contains(needle),
                "admin warmup routes must state {needle:?}: the endpoint is \
                 advisory and the live control is the canonical per-IP path"
            );
        }
    }
}

#[cfg(test)]
mod adversarial_tests {
    use axum::http::StatusCode;

    use crate::app::test_support::adv::AdvEnv;

    async fn seed_pool_with_plan(pool: &sqlx::PgPool, name: &str, status: &str) -> String {
        let pool_id = apexmail_lib::id::generate_id("ipp", 22);
        let ip = format!("192.0.2.{}", uuid::Uuid::new_v4().as_bytes()[0]);
        sqlx::query("INSERT INTO ip_pools (id, name, status) VALUES ($1, $2, $3)")
            .bind(&pool_id)
            .bind(name)
            .bind(status)
            .execute(pool)
            .await
            .expect("seed ip pool");
        sqlx::query(
            "INSERT INTO ip_pool_addresses (id, pool_id, ip_address, status)
             VALUES ($1, $2, $3::inet, 'active')",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(&pool_id)
        .bind(&ip)
        .execute(pool)
        .await
        .expect("seed pool address");
        for day in 1..=2i32 {
            sqlx::query(
                "INSERT INTO isp_warmup_schedules (id, pool_id, day, target_volume, actual_volume, status)
                 VALUES ($1, $2, $3, $4, $5, 'active')",
            )
            .bind(uuid::Uuid::new_v4())
            .bind(&pool_id)
            .bind(day)
            .bind((day as i64) * 500)
            .bind(Option::<i64>::Some(120))
            .execute(pool)
            .await
            .expect("seed warmup schedule");
        }
        pool_id
    }

    #[tokio::test]
    async fn warmup_lists_the_advisory_plan_with_addresses_and_schedules() {
        let Some(pool) = crate::test_db::canonical_pool("warmup_list").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;
        seed_pool_with_plan(&pool, "Primary", "active").await;

        let (status, body) = env.get("/v1/admin/warmup").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let pools = body.as_array().expect("array");
        assert_eq!(pools.len(), 1);
        assert_eq!(pools[0]["name"], "Primary");
        assert_eq!(pools[0]["status"], "active");
        assert_eq!(pools[0]["advisory"], true);
        let addresses = pools[0]["addresses"].as_array().expect("addresses");
        assert_eq!(addresses.len(), 1);
        // INET::text renders in CIDR form (192.0.2.x/32).
        assert!(addresses[0]["ipAddress"]
            .as_str()
            .is_some_and(|ip| ip.starts_with("192.0.2.")));
        let schedules = pools[0]["schedules"].as_array().expect("schedules");
        assert_eq!(schedules.len(), 2);
        assert_eq!(schedules[0]["day"], 1);
        assert_eq!(schedules[0]["targetVolume"], 500);
        assert_eq!(schedules[0]["actualVolume"], 120);
        assert_eq!(schedules[0]["status"], "active");
    }

    #[tokio::test]
    async fn warmup_empty_state_and_pagination_clamps() {
        let Some(pool) = crate::test_db::canonical_pool("warmup_empty").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;
        seed_pool_with_plan(&pool, "Pool-A", "pending").await;
        seed_pool_with_plan(&pool, "Pool-B", "paused").await;

        let (status, body) = env.get("/v1/admin/warmup?limit=1").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body.as_array().map(Vec::len), Some(1));
        let (status, body) = env.get("/v1/admin/warmup?limit=0&offset=-4").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body.as_array().map(Vec::len), Some(1), "limit clamps to 1");
    }

    #[tokio::test]
    async fn warmup_actions_toggle_status_reset_clears_and_audit() {
        let Some(pool) = crate::test_db::canonical_pool("warmup_actions").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;
        let pool_id = seed_pool_with_plan(&pool, "Actionable", "active").await;

        // pause → paused, advisory flags explicit.
        let (status, headers, bytes) = env
            .post_raw(
                "/v1/admin/warmup",
                &serde_json::json!({ "poolId": pool_id, "action": "pause" }).to_string(),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&bytes)
        );
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(body["advisory"], true);
        assert_eq!(body["admissionControl"], false);
        assert_eq!(body["status"], "paused");
        assert!(headers.contains_key("content-type"));

        // start → active again.
        let (status, body) = env
            .post(
                "/v1/admin/warmup",
                &serde_json::json!({ "poolId": pool_id, "action": "start" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "active");

        // reset → pending AND the plan rows reset.
        let (status, body) = env
            .post(
                "/v1/admin/warmup",
                &serde_json::json!({ "poolId": pool_id, "action": "reset" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "pending");
        let (sched_status, actual): (String, Option<i64>) = sqlx::query_as(
            "SELECT status, actual_volume FROM isp_warmup_schedules WHERE pool_id = $1 AND day = 1",
        )
        .bind(&pool_id)
        .fetch_one(&pool)
        .await
        .expect("schedule row");
        assert_eq!(sched_status, "pending");
        assert!(actual.is_none(), "reset clears actual_volume");

        // The audit trail carries actor-attributed entries per action.
        let actions: Vec<String> = sqlx::query_scalar(
            "SELECT action FROM audit_logs WHERE resource_id = $1 ORDER BY action",
        )
        .bind(&pool_id)
        .fetch_all(&pool)
        .await
        .expect("audit rows");
        assert!(actions.contains(&"warmup.start".to_string()));
        assert!(actions.contains(&"warmup.pause".to_string()));
        assert!(actions.contains(&"warmup.reset".to_string()));
    }

    #[tokio::test]
    async fn warmup_action_refusals() {
        let Some(pool) = crate::test_db::canonical_pool("warmup_refusals").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;
        let pool_id = seed_pool_with_plan(&pool, "Refusal", "pending").await;

        // Unknown action.
        let (status, body) = env
            .post(
                "/v1/admin/warmup",
                &serde_json::json!({ "poolId": pool_id, "action": "detonate" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        // Unknown pool id.
        let (status, body) = env
            .post(
                "/v1/admin/warmup",
                &serde_json::json!({ "poolId": "ipp_missing", "action": "start" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

        // Unknown body fields.
        let (status, _body) = env
            .post(
                "/v1/admin/warmup",
                &serde_json::json!({ "poolId": pool_id, "action": "start", "force": true })
                    .to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // Scope gate.
        let key =
            crate::app::test_support::seed_api_key_for(&pool, "system", &["warmup:read"]).await;
        let scoped = AdvEnv::over(pool, key).await;
        let (status, body) = scoped.get("/v1/admin/warmup").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }
}
