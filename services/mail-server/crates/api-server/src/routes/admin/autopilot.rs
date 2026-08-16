//! Autopilot control endpoints backed by the sales data model.
//!
//! The original control-plane autopilot route was migrated as a proxy to a
//! downstream operator API that no longer exists in the current workspace.
//! This module restores the control surface against the data that the admin
//! sales routes actually manage today.

use super::super::helpers::table_exists;
use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::task::JoinHandle;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

const PENDING_APPROVAL_SCORE: i32 = 80;
const AUTOPILOT_POLL_INTERVAL_SECS: u64 = 30;

static AUTOPILOT_WORKER: OnceLock<tokio::sync::Mutex<Option<JoinHandle<()>>>> = OnceLock::new();

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(get_autopilot).post(post_autopilot))
}

async fn log_autopilot_audit(
    db: &sqlx::PgPool,
    tenant_id: Option<&str>,
    user_id: Option<&str>,
    action: &str,
    metadata: serde_json::Value,
) {
    crate::audit_log::insert_audit_log_best_effort(
        db,
        tenant_id,
        user_id,
        action,
        "sales_autopilot",
        Some("default"),
        metadata,
        None,
        None,
    )
    .await;
}

#[derive(Debug, Deserialize)]
pub struct AutopilotQuery {
    pub section: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutopilotAction {
    pub action: String,
    #[serde(default)]
    pub candidate_id: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

#[derive(Debug, Clone)]
struct AutopilotStateRow {
    status: String,
    safe_mode: bool,
    last_action: Option<String>,
    last_action_at: Option<DateTime<Utc>>,
    rules: serde_json::Value,
}

/// API-114/115: Track whether the autopilot state table has been ensured
/// to avoid running DDL on every request (causes latency and lock contention).
static AUTOPILOT_TABLE_ENSURE: OnceLock<()> = OnceLock::new();

async fn ensure_autopilot_state_table(db: &sqlx::PgPool) -> Result<(), ApiError> {
    // Only run DDL once per process lifetime; tables should be created via migrations.
    if AUTOPILOT_TABLE_ENSURE.get().is_some() {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO sales_autopilot_state (tenant_id, status, safe_mode, rules, updated_at)
         VALUES ('system', 'stopped', false, '[]'::jsonb, NOW())
         ON CONFLICT (tenant_id) DO NOTHING",
    )
    .execute(db)
    .await?;

    // Mark as ensured so subsequent calls skip the DDL entirely.
    let _ = AUTOPILOT_TABLE_ENSURE.set(());
    Ok(())
}

async fn load_autopilot_state(db: &sqlx::PgPool) -> Result<AutopilotStateRow, ApiError> {
    ensure_autopilot_state_table(db).await?;

    let row: (
        String,
        bool,
        Option<String>,
        Option<DateTime<Utc>>,
        serde_json::Value,
    ) = sqlx::query_as(
        "SELECT status, safe_mode, last_action, last_action_at, rules
         FROM sales_autopilot_state
         WHERE tenant_id = 'system'",
    )
    .fetch_one(db)
    .await?;

    Ok(AutopilotStateRow {
        status: row.0,
        safe_mode: row.1,
        last_action: row.2,
        last_action_at: row.3,
        rules: row.4,
    })
}

async fn persist_autopilot_state(
    db: &sqlx::PgPool,
    current: &AutopilotStateRow,
    action: &str,
    next_status: Option<&str>,
    next_safe_mode: Option<bool>,
    next_rules: Option<serde_json::Value>,
) -> Result<AutopilotStateRow, ApiError> {
    ensure_autopilot_state_table(db).await?;

    let row: (
        String,
        bool,
        Option<String>,
        Option<DateTime<Utc>>,
        serde_json::Value,
    ) = sqlx::query_as(
        "UPDATE sales_autopilot_state
         SET status = $1,
             safe_mode = $2,
             last_action = $3,
             last_action_at = NOW(),
             rules = $4,
             updated_at = NOW()
         WHERE tenant_id = 'system'
         RETURNING status, safe_mode, last_action, last_action_at, rules",
    )
    .bind(next_status.unwrap_or(&current.status))
    .bind(next_safe_mode.unwrap_or(current.safe_mode))
    .bind(action)
    .bind(next_rules.unwrap_or_else(|| current.rules.clone()))
    .fetch_one(db)
    .await?;

    Ok(AutopilotStateRow {
        status: row.0,
        safe_mode: row.1,
        last_action: row.2,
        last_action_at: row.3,
        rules: row.4,
    })
}

fn worker_handle() -> &'static tokio::sync::Mutex<Option<JoinHandle<()>>> {
    AUTOPILOT_WORKER.get_or_init(|| tokio::sync::Mutex::new(None))
}

fn max_approvals_per_cycle(rules: &serde_json::Value) -> i64 {
    rules
        .get("maxApprovalsPerCycle")
        .and_then(|value| value.as_i64())
        .unwrap_or(5)
        .clamp(1, 25)
}

/// Process one autopilot cycle, scoped to a specific tenant.
/// API-102: Background autopilot worker now filters by tenant_id.
async fn process_autopilot_cycle(
    state: &AppState,
    tenant_id: &str,
    rules: &serde_json::Value,
) -> Result<usize, ApiError> {
    if !table_exists(&state.db, "sales_leads").await {
        return Ok(0);
    }

    let approved_ids: Vec<String> = sqlx::query_scalar(
        "UPDATE sales_leads
         SET status = 'qualified', updated_at = NOW()
         WHERE id IN (
             SELECT id
             FROM sales_leads
             WHERE status IN ('new', 'prospect')
               AND COALESCE(score, 0) >= $1
               AND tenant_id = $3
             ORDER BY COALESCE(score, 0) DESC, created_at ASC
             LIMIT $2
         )
         RETURNING id",
    )
    .bind(PENDING_APPROVAL_SCORE)
    .bind(max_approvals_per_cycle(rules))
    .bind(tenant_id)
    .fetch_all(&state.db)
    .await?;

    if !approved_ids.is_empty() {
        log_autopilot_audit(
            &state.db,
            Some(tenant_id),
            None,
            "control_plane.autopilot.cycle_applied",
            json!({
                "approved": approved_ids.len(),
                "leadIds": approved_ids,
            }),
        )
        .await;
    }

    Ok(approved_ids.len())
}

/// API-105: Per-tenant autopilot worker state key.
fn autopilot_tenant_worker_key(tenant_id: &str) -> String {
    format!("apexmail:autopilot:worker:{tenant_id}")
}

async fn run_autopilot_worker(state: AppState, tenant_id: String) {
    loop {
        let current = match load_autopilot_state(&state.db).await {
            Ok(current) => current,
            Err(error) => {
                tracing::warn!(error = %error, tenant_id = %tenant_id, "autopilot worker failed to load state");
                break;
            }
        };

        if current.status != "running" {
            break;
        }

        if !current.safe_mode {
            // API-102: Process only leads for this specific tenant.
            if let Err(error) = process_autopilot_cycle(&state, &tenant_id, &current.rules).await {
                tracing::warn!(error = %error, tenant_id = %tenant_id, "autopilot worker cycle failed");
            }
        }

        tokio::time::sleep(Duration::from_secs(AUTOPILOT_POLL_INTERVAL_SECS)).await;
    }
}

/// API-105: Spawn autopilot worker scoped to a specific tenant.
async fn ensure_autopilot_worker_running(state: AppState, tenant_id: String) {
    let mut guard = worker_handle().lock().await;
    if guard
        .as_ref()
        .map(|handle| !handle.is_finished())
        .unwrap_or(false)
    {
        return;
    }

    let tid = tenant_id.clone();
    *guard = Some(tokio::spawn(async move {
        run_autopilot_worker(state, tid).await;
    }));
}

async fn stop_autopilot_worker() {
    let mut guard = worker_handle().lock().await;
    if let Some(handle) = guard.take() {
        handle.abort();
    }
}

/// Pending approval candidates, scoped to `tenant_id` so that what the CP
/// shows matches what the approve/reject mutations can actually act on.
async fn pending_candidates(
    db: &sqlx::PgPool,
    tenant_id: &str,
) -> Result<Vec<serde_json::Value>, ApiError> {
    if !table_exists(db, "sales_leads").await {
        return Ok(Vec::new());
    }

    let rows: Vec<(
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<i32>,
        Option<String>,
        DateTime<Utc>,
    )> = sqlx::query_as(build_pending_candidates_sql(true))
        .bind(tenant_id)
        .bind(PENDING_APPROVAL_SCORE)
        .fetch_all(db)
        .await?;

    Ok(map_pending_candidates(rows))
}

fn build_pending_candidates_sql(tenant_scoped: bool) -> &'static str {
    if tenant_scoped {
        "SELECT id, company_name, domain, contact_email, score, source, created_at
         FROM sales_leads
         WHERE tenant_id = $1
           AND status IN ('new', 'prospect')
           AND COALESCE(score, 0) >= $2
         ORDER BY COALESCE(score, 0) DESC, created_at DESC
         LIMIT 25"
    } else {
        "SELECT id, company_name, domain, contact_email, score, source, created_at
         FROM sales_leads
         WHERE status IN ('new', 'prospect')
           AND COALESCE(score, 0) >= $1
         ORDER BY COALESCE(score, 0) DESC, created_at DESC
         LIMIT 25"
    }
}

fn map_pending_candidates(
    rows: Vec<(
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<i32>,
        Option<String>,
        DateTime<Utc>,
    )>,
) -> Vec<serde_json::Value> {
    rows.into_iter()
        .map(
            |(id, company_name, domain, contact_email, score, source, created_at)| {
                serde_json::json!({
                    "id": id,
                    "companyName": company_name,
                    "domain": domain,
                    "contactEmail": contact_email,
                    "score": score.unwrap_or(0),
                    "source": source,
                    "createdAt": created_at.to_rfc3339(),
                })
            },
        )
        .collect()
}

async fn load_sales_settings(db: &sqlx::PgPool) -> Result<serde_json::Value, ApiError> {
    let row: Option<(serde_json::Value, serde_json::Value, serde_json::Value)> = sqlx::query_as(
        "SELECT scoring_weights, schedule, notifications FROM sales_settings LIMIT 1",
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten();

    Ok(match row {
        Some((scoring_weights, schedule, notifications)) => serde_json::json!({
            "scoringWeights": scoring_weights,
            "schedule": schedule,
            "notifications": notifications,
        }),
        None => serde_json::json!({
            "scoringWeights": {},
            "schedule": {},
            "notifications": {},
        }),
    })
}

async fn metrics_payload(
    db: &sqlx::PgPool,
    autopilot: &AutopilotStateRow,
    pending_count: usize,
) -> Result<serde_json::Value, ApiError> {
    let has_sales_leads = table_exists(db, "sales_leads").await;
    let has_drip_campaigns = table_exists(db, "drip_campaigns").await;
    let has_campaign_recipients = table_exists(db, "campaign_recipients").await;

    let total_leads: i64 = if has_sales_leads {
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM sales_leads")
            .fetch_one(db)
            .await
            .unwrap_or(0)
    } else {
        0
    };
    let active_leads: i64 = if has_sales_leads {
        sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_leads WHERE status NOT IN ('converted', 'lost', 'unqualified')",
        )
        .fetch_one(db)
        .await
        .unwrap_or(0)
    } else {
        0
    };
    let converted_leads: i64 = if has_sales_leads {
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM sales_leads WHERE status = 'converted'")
            .fetch_one(db)
            .await
            .unwrap_or(0)
    } else {
        0
    };
    let average_score: f64 = if has_sales_leads {
        sqlx::query_scalar::<_, Option<f64>>("SELECT AVG(score)::float8 FROM sales_leads")
            .fetch_one(db)
            .await
            .ok()
            .flatten()
            .unwrap_or(0.0)
    } else {
        0.0
    };
    let active_campaigns: i64 = if has_drip_campaigns {
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM drip_campaigns WHERE status = 'active'")
            .fetch_one(db)
            .await
            .unwrap_or(0)
    } else {
        0
    };
    let queued_recipients: i64 = if has_campaign_recipients {
        sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM campaign_recipients WHERE status = 'queued'",
        )
        .fetch_one(db)
        .await
        .unwrap_or(0)
    } else {
        0
    };
    let replied_recipients: i64 = if has_campaign_recipients {
        sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM campaign_recipients WHERE replied_at IS NOT NULL",
        )
        .fetch_one(db)
        .await
        .unwrap_or(0)
    } else {
        0
    };

    let conversion_rate = if active_leads + converted_leads == 0 {
        0.0
    } else {
        converted_leads as f64 / (active_leads + converted_leads) as f64
    };

    Ok(serde_json::json!({
        "status": autopilot.status,
        "safeMode": autopilot.safe_mode,
        "pipeline": {
            "totalLeads": total_leads,
            "activeLeads": active_leads,
            "convertedLeads": converted_leads,
            "conversionRate": conversion_rate,
            "averageScore": average_score,
            "pendingApprovals": pending_count,
        },
        "campaigns": {
            "active": active_campaigns,
            "queuedRecipients": queued_recipients,
            "repliedRecipients": replied_recipients,
        },
        "lastAction": autopilot.last_action,
        "lastActionAt": autopilot.last_action_at.map(|ts| ts.to_rfc3339()),
    }))
}

async fn outcomes_payload(db: &sqlx::PgPool) -> Result<serde_json::Value, ApiError> {
    let recent_campaigns = if table_exists(db, "drip_campaigns").await {
        let rows: Vec<(String, String, String, DateTime<Utc>)> = sqlx::query_as(
            "SELECT id, name, status, created_at FROM drip_campaigns ORDER BY created_at DESC LIMIT 10",
        )
        .fetch_all(db)
        .await?;

        rows.into_iter()
            .map(|(id, name, status, created_at)| {
                serde_json::json!({
                    "id": id,
                    "name": name,
                    "status": status,
                    "createdAt": created_at.to_rfc3339(),
                })
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    let converted_leads = if table_exists(db, "sales_leads").await {
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM sales_leads WHERE status = 'converted'")
            .fetch_one(db)
            .await
            .unwrap_or(0)
    } else {
        0
    };

    Ok(serde_json::json!({
        "recentCampaigns": recent_campaigns,
        "convertedLeads": converted_leads,
    }))
}

async fn get_autopilot(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<AutopilotQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&auth)?;

    let section = params.section.as_deref().unwrap_or("overview");
    let allowed = [
        "overview",
        "metrics",
        "baseline",
        "candidates",
        "outcomes",
        "pending",
        "actions",
        "safety",
    ];
    if !allowed.contains(&section) {
        return Err(ApiError::Validation(vec!["Invalid section".into()]));
    }

    let autopilot = load_autopilot_state(&state.db).await?;

    // If the DB says autopilot is running but this process has no live worker
    // (e.g. after a process restart), re-spawn it so cycles actually resume.
    if autopilot.status == "running" {
        ensure_autopilot_worker_running(state.clone(), auth.tenant_id.clone()).await;
    }

    // Pending candidates are scoped to the caller's tenant so they match the
    // tenant-scoped approve/reject mutations.
    let pending = pending_candidates(&state.db, &auth.tenant_id).await?;

    let payload = match section {
        "overview" => {
            let metrics = metrics_payload(&state.db, &autopilot, pending.len()).await?;
            serde_json::json!({
                "status": autopilot.status,
                "safeMode": autopilot.safe_mode,
                "rules": autopilot.rules,
                "metrics": metrics,
                "recentCandidates": pending.iter().take(5).cloned().collect::<Vec<_>>(),
                "lastAction": autopilot.last_action,
                "lastActionAt": autopilot.last_action_at.map(|ts| ts.to_rfc3339()),
            })
        }
        "metrics" => metrics_payload(&state.db, &autopilot, pending.len()).await?,
        "baseline" => serde_json::json!({
            "status": autopilot.status,
            "safeMode": autopilot.safe_mode,
            "rules": autopilot.rules,
            "settings": load_sales_settings(&state.db).await?,
        }),
        "candidates" => serde_json::json!({
            "status": autopilot.status,
            "threshold": PENDING_APPROVAL_SCORE,
            "candidates": pending,
        }),
        "outcomes" => outcomes_payload(&state.db).await?,
        "pending" => serde_json::json!({
            "status": autopilot.status,
            "approvals": pending,
        }),
        "actions" => serde_json::json!({
            "status": autopilot.status,
            "safeMode": autopilot.safe_mode,
            "available": ["start", "stop", "approve", "reject", "approve-all", "exit-safe-mode"],
            "lastAction": autopilot.last_action,
            "lastActionAt": autopilot.last_action_at.map(|ts| ts.to_rfc3339()),
        }),
        "safety" => serde_json::json!({
            "status": autopilot.status,
            "safeMode": autopilot.safe_mode,
            "pendingApprovals": pending.len(),
            "lastAction": autopilot.last_action,
            "lastActionAt": autopilot.last_action_at.map(|ts| ts.to_rfc3339()),
        }),
        unknown => {
            return Err(ApiError::BadRequest(format!(
                "unknown autopilot section '{}'. Valid: overview, metrics, baseline, candidates, outcomes, pending, actions, safety",
                unknown
            )));
        }
    };

    Ok(Json(payload))
}

fn extract_candidate_id(body: &AutopilotAction) -> Option<String> {
    body.candidate_id
        .clone()
        .or_else(|| {
            body.extra
                .get("candidateId")
                .and_then(|value| value.as_str())
                .map(String::from)
        })
        .or_else(|| {
            body.extra
                .get("id")
                .and_then(|value| value.as_str())
                .map(String::from)
        })
}

async fn post_autopilot(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<AutopilotAction>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&auth)?;

    let allowed = [
        "start",
        "stop",
        "approve",
        "reject",
        "approve-all",
        "exit-safe-mode",
    ];
    if !allowed.contains(&body.action.as_str()) {
        return Err(ApiError::Validation(vec!["Invalid action".into()]));
    }

    let current = load_autopilot_state(&state.db).await?;

    let payload = match body.action.as_str() {
        "start" => {
            let next_rules = body.extra.get("rules").cloned();
            let next_safe_mode = body.extra.get("safeMode").and_then(|value| value.as_bool());
            let updated = persist_autopilot_state(
                &state.db,
                &current,
                "start",
                Some("running"),
                next_safe_mode,
                next_rules,
            )
            .await?;

            // API-105: Pass tenant_id to scope the autopilot worker.
            ensure_autopilot_worker_running(state.clone(), auth.tenant_id.clone()).await;

            log_autopilot_audit(
                &state.db,
                Some(auth.tenant_id.as_str()),
                auth.user_id.as_deref(),
                "control_plane.autopilot.started",
                json!({
                    "safeMode": updated.safe_mode,
                    "rules": updated.rules,
                }),
            )
            .await;

            serde_json::json!({
                "success": true,
                "status": updated.status,
                "safeMode": updated.safe_mode,
                "rules": updated.rules,
            })
        }
        "stop" => {
            let updated =
                persist_autopilot_state(&state.db, &current, "stop", Some("stopped"), None, None)
                    .await?;

            stop_autopilot_worker().await;

            log_autopilot_audit(
                &state.db,
                Some(auth.tenant_id.as_str()),
                auth.user_id.as_deref(),
                "control_plane.autopilot.stopped",
                json!({ "previousStatus": current.status }),
            )
            .await;

            serde_json::json!({
                "success": true,
                "status": updated.status,
                "safeMode": updated.safe_mode,
            })
        }
        "approve" => {
            if current.safe_mode {
                return Err(ApiError::Conflict("autopilot is in safe mode".into()));
            }

            let candidate_id = extract_candidate_id(&body)
                .ok_or_else(|| ApiError::Validation(vec!["candidateId is required".into()]))?;
            // API-101: Scope approve by tenant_id to prevent IDOR.
            let result = sqlx::query(
                "UPDATE sales_leads
                 SET status = 'qualified', updated_at = NOW()
                 WHERE id = $1 AND tenant_id = $3 AND status IN ('new', 'prospect') AND COALESCE(score, 0) >= $2",
            )
            .bind(&candidate_id)
            .bind(PENDING_APPROVAL_SCORE)
            .bind(&auth.tenant_id)
            .execute(&state.db)
            .await?;

            if result.rows_affected() == 0 {
                return Err(ApiError::NotFound("candidate not found".into()));
            }

            persist_autopilot_state(&state.db, &current, "approve", None, None, None).await?;
            log_autopilot_audit(
                &state.db,
                Some(auth.tenant_id.as_str()),
                auth.user_id.as_deref(),
                "control_plane.autopilot.approved",
                json!({ "candidateId": candidate_id }),
            )
            .await;
            serde_json::json!({
                "success": true,
                "candidateId": candidate_id,
                "status": "qualified",
            })
        }
        "reject" => {
            let candidate_id = extract_candidate_id(&body)
                .ok_or_else(|| ApiError::Validation(vec!["candidateId is required".into()]))?;
            // API-101: Scope reject by tenant_id to prevent IDOR.
            let result = sqlx::query(
                "UPDATE sales_leads
                 SET status = 'unqualified', updated_at = NOW()
                 WHERE id = $1 AND tenant_id = $3 AND status IN ('new', 'prospect') AND COALESCE(score, 0) >= $2",
            )
            .bind(&candidate_id)
            .bind(PENDING_APPROVAL_SCORE)
            .bind(&auth.tenant_id)
            .execute(&state.db)
            .await?;

            if result.rows_affected() == 0 {
                return Err(ApiError::NotFound("candidate not found".into()));
            }

            persist_autopilot_state(&state.db, &current, "reject", None, None, None).await?;
            log_autopilot_audit(
                &state.db,
                Some(auth.tenant_id.as_str()),
                auth.user_id.as_deref(),
                "control_plane.autopilot.rejected",
                json!({ "candidateId": candidate_id }),
            )
            .await;
            serde_json::json!({
                "success": true,
                "candidateId": candidate_id,
                "status": "unqualified",
            })
        }
        "approve-all" => {
            if current.safe_mode {
                return Err(ApiError::Conflict("autopilot is in safe mode".into()));
            }

            // API-100: Scope approve-all by tenant_id to prevent cross-tenant modification.
            let result = sqlx::query(
                "UPDATE sales_leads
                 SET status = 'qualified', updated_at = NOW()
                 WHERE tenant_id = $2 AND status IN ('new', 'prospect') AND COALESCE(score, 0) >= $1",
            )
            .bind(PENDING_APPROVAL_SCORE)
            .bind(&auth.tenant_id)
            .execute(&state.db)
            .await?;

            persist_autopilot_state(&state.db, &current, "approve-all", None, None, None).await?;
            log_autopilot_audit(
                &state.db,
                Some(auth.tenant_id.as_str()),
                auth.user_id.as_deref(),
                "control_plane.autopilot.approved_all",
                json!({ "approved": result.rows_affected() }),
            )
            .await;
            serde_json::json!({
                "success": true,
                "approved": result.rows_affected(),
            })
        }
        "exit-safe-mode" => {
            let updated = persist_autopilot_state(
                &state.db,
                &current,
                "exit-safe-mode",
                None,
                Some(false),
                None,
            )
            .await?;

            log_autopilot_audit(
                &state.db,
                Some(auth.tenant_id.as_str()),
                auth.user_id.as_deref(),
                "control_plane.autopilot.exited_safe_mode",
                json!({ "status": updated.status }),
            )
            .await;

            serde_json::json!({
                "success": true,
                "status": updated.status,
                "safeMode": updated.safe_mode,
            })
        }
        // All actions are validated by pre-check above, this is unreachable
        _ => return Err(ApiError::Internal("unreachable action".into())),
    };

    Ok(Json(payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_candidate_id_from_legacy_payload() {
        let body = AutopilotAction {
            action: "approve".into(),
            candidate_id: None,
            extra: serde_json::json!({ "id": "lead_123" }),
        };

        assert_eq!(extract_candidate_id(&body).as_deref(), Some("lead_123"));
    }

    #[test]
    fn build_pending_candidates_sql_scopes_non_system_tenants() {
        let sql = build_pending_candidates_sql(true);

        assert!(sql.contains("WHERE tenant_id = $1"));
        assert!(sql.contains("COALESCE(score, 0) >= $2"));
    }

    #[test]
    fn max_approvals_per_cycle_honors_rules_override() {
        let rules = serde_json::json!({ "maxApprovalsPerCycle": 12 });

        assert_eq!(max_approvals_per_cycle(&rules), 12);
        assert_eq!(max_approvals_per_cycle(&serde_json::json!({})), 5);
        assert_eq!(
            max_approvals_per_cycle(&serde_json::json!({ "maxApprovalsPerCycle": 100 })),
            25
        );
    }
}
