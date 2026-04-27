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

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

const PENDING_APPROVAL_SCORE: i32 = 80;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(get_autopilot).post(post_autopilot))
}

#[derive(Debug, Deserialize)]
pub struct AutopilotQuery {
    pub section: Option<String>,
}

#[derive(Debug, Deserialize)]
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

async fn ensure_autopilot_state_table(db: &sqlx::PgPool) -> Result<(), ApiError> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sales_autopilot_state (
            id INTEGER PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'stopped',
            safe_mode BOOLEAN NOT NULL DEFAULT false,
            last_action TEXT,
            last_action_at TIMESTAMPTZ,
            rules JSONB NOT NULL DEFAULT '[]'::jsonb,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    )
    .execute(db)
    .await?;

    sqlx::query(
        "INSERT INTO sales_autopilot_state (id, status, safe_mode, rules, updated_at)
         VALUES (1, 'stopped', false, '[]'::jsonb, NOW())
         ON CONFLICT (id) DO NOTHING",
    )
    .execute(db)
    .await?;

    Ok(())
}

async fn load_autopilot_state(db: &sqlx::PgPool) -> Result<AutopilotStateRow, ApiError> {
    ensure_autopilot_state_table(db).await?;

    let row: (String, bool, Option<String>, Option<DateTime<Utc>>, serde_json::Value) = sqlx::query_as(
        "SELECT status, safe_mode, last_action, last_action_at, rules
         FROM sales_autopilot_state
         WHERE id = 1",
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

    let row: (String, bool, Option<String>, Option<DateTime<Utc>>, serde_json::Value) = sqlx::query_as(
        "UPDATE sales_autopilot_state
         SET status = $1,
             safe_mode = $2,
             last_action = $3,
             last_action_at = NOW(),
             rules = $4,
             updated_at = NOW()
         WHERE id = 1
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

async fn pending_candidates(db: &sqlx::PgPool) -> Result<Vec<serde_json::Value>, ApiError> {
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
    )> = sqlx::query_as(
        "SELECT id, company_name, domain, contact_email, score, source, created_at
         FROM sales_leads
         WHERE status IN ('new', 'prospect')
           AND COALESCE(score, 0) >= $1
         ORDER BY COALESCE(score, 0) DESC, created_at DESC
         LIMIT 25",
    )
    .bind(PENDING_APPROVAL_SCORE)
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(id, company_name, domain, contact_email, score, source, created_at)| {
            serde_json::json!({
                "id": id,
                "companyName": company_name,
                "domain": domain,
                "contactEmail": contact_email,
                "score": score.unwrap_or(0),
                "source": source,
                "createdAt": created_at.to_rfc3339(),
            })
        })
        .collect())
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
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM campaign_recipients WHERE status = 'queued'")
            .fetch_one(db)
            .await
            .unwrap_or(0)
    } else {
        0
    };
    let replied_recipients: i64 = if has_campaign_recipients {
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM campaign_recipients WHERE replied_at IS NOT NULL")
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
    let pending = pending_candidates(&state.db).await?;

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

    let allowed = ["start", "stop", "approve", "reject", "approve-all", "exit-safe-mode"];
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

            serde_json::json!({
                "success": true,
                "status": updated.status,
                "safeMode": updated.safe_mode,
                "rules": updated.rules,
            })
        }
        "stop" => {
            let updated = persist_autopilot_state(
                &state.db,
                &current,
                "stop",
                Some("stopped"),
                None,
                None,
            )
            .await?;

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
            let result = sqlx::query(
                "UPDATE sales_leads
                 SET status = 'qualified', updated_at = NOW()
                 WHERE id = $1 AND status IN ('new', 'prospect') AND COALESCE(score, 0) >= $2",
            )
            .bind(&candidate_id)
            .bind(PENDING_APPROVAL_SCORE)
            .execute(&state.db)
            .await?;

            if result.rows_affected() == 0 {
                return Err(ApiError::NotFound("candidate not found".into()));
            }

            persist_autopilot_state(&state.db, &current, "approve", None, None, None).await?;
            serde_json::json!({
                "success": true,
                "candidateId": candidate_id,
                "status": "qualified",
            })
        }
        "reject" => {
            let candidate_id = extract_candidate_id(&body)
                .ok_or_else(|| ApiError::Validation(vec!["candidateId is required".into()]))?;
            let result = sqlx::query(
                "UPDATE sales_leads
                 SET status = 'unqualified', updated_at = NOW()
                 WHERE id = $1 AND status IN ('new', 'prospect') AND COALESCE(score, 0) >= $2",
            )
            .bind(&candidate_id)
            .bind(PENDING_APPROVAL_SCORE)
            .execute(&state.db)
            .await?;

            if result.rows_affected() == 0 {
                return Err(ApiError::NotFound("candidate not found".into()));
            }

            persist_autopilot_state(&state.db, &current, "reject", None, None, None).await?;
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

            let result = sqlx::query(
                "UPDATE sales_leads
                 SET status = 'qualified', updated_at = NOW()
                 WHERE status IN ('new', 'prospect') AND COALESCE(score, 0) >= $1",
            )
            .bind(PENDING_APPROVAL_SCORE)
            .execute(&state.db)
            .await?;

            persist_autopilot_state(&state.db, &current, "approve-all", None, None, None).await?;
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
}
