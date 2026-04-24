//! Dashboard stats endpoint.
//!

use super::super::helpers::table_exists;
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use std::sync::Mutex;
use std::time::Instant;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/stats", get(get_dashboard_stats))
}

static CACHE: Mutex<Option<(Instant, DashboardStats)>> = Mutex::new(None);
const CACHE_TTL_SECS: u64 = 30;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SalesStats {
    pub active_leads: i64,
    pub leads_this_week: i64,
    pub campaigns_running: i64,
    pub demos_scheduled: i64,
    pub conversion_rate: f64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceStats {
    pub risk_alerts: i64,
    pub critical_tenants: i64,
    pub gdpr_pending: i64,
    pub audit_events_today: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformStats {
    pub active_tenants: i64,
    pub total_emails: i64,
    pub mrr: f64,
    pub health_status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActivityEntry {
    pub id: String,
    #[serde(rename = "type")]
    pub entry_type: String,
    pub message: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PipelineStats {
    pub prospect: i64,
    pub outreach: i64,
    pub engaged: i64,
    pub demo: i64,
    pub closed: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardStats {
    pub sales: SalesStats,
    pub compliance: ComplianceStats,
    pub platform: PlatformStats,
    pub recent_activity: Vec<ActivityEntry>,
    pub pipeline: PipelineStats,
}

fn parse_count(val: Option<String>) -> i64 {
    val.and_then(|s| s.parse().ok()).unwrap_or(0)
}

async fn get_dashboard_stats(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<DashboardStats>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

// Check cache
    {
        if let Ok(guard) = CACHE.lock() {
            if let Some((ts, ref cached)) = *guard {
                if ts.elapsed().as_secs() < CACHE_TTL_SECS {
                    return Ok(Json(cached.clone()));
                }
            }
        }
    }

    let db = &state.db;

    let has_sales_leads = table_exists(db, "sales_leads").await;
    let has_drip_campaigns = table_exists(db, "drip_campaigns").await;
    let has_gdpr_requests = table_exists(db, "gdpr_requests").await;
    let has_system_alerts = table_exists(db, "system_alerts").await;
    let has_stripe_subs = table_exists(db, "stripe_subscriptions").await;

// Aggregate counts
    let active_leads = if has_sales_leads {
        parse_count(
            sqlx::query_scalar("SELECT COUNT(*)::text FROM sales_leads WHERE status NOT IN ('converted', 'lost', 'unqualified')")
                .fetch_one(db).await.ok(),
        )
    } else { 0 };

    let leads_this_week = if has_sales_leads {
        parse_count(
            sqlx::query_scalar("SELECT COUNT(*)::text FROM sales_leads WHERE created_at >= NOW() - INTERVAL '7 days'")
                .fetch_one(db).await.ok(),
        )
    } else { 0 };

    let campaigns_running = if has_drip_campaigns {
        parse_count(
            sqlx::query_scalar("SELECT COUNT(*)::text FROM drip_campaigns WHERE status = 'active'")
                .fetch_one(db).await.ok(),
        )
    } else { 0 };

    let demos_scheduled = if has_sales_leads {
        parse_count(
            sqlx::query_scalar("SELECT COUNT(*)::text FROM sales_leads WHERE status IN ('demo_scheduled', 'demo_booked', 'demo')")
                .fetch_one(db).await.ok(),
        )
    } else { 0 };

    let conversion_rate: f64 = if has_sales_leads {
        sqlx::query_scalar::<_, String>(
            "SELECT CASE
                WHEN COUNT(*) FILTER (WHERE status IN ('contacted', 'qualified', 'converted')) = 0 THEN '0'
                ELSE (COUNT(*) FILTER (WHERE status = 'converted')::float /
                      COUNT(*) FILTER (WHERE status IN ('contacted', 'qualified', 'converted')))::text
             END FROM sales_leads",
        )
        .fetch_one(db)
        .await
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0)
    } else { 0.0 };

    let audit_events_today = parse_count(
        sqlx::query_scalar("SELECT COUNT(*)::text FROM audit_logs WHERE timestamp >= CURRENT_DATE")
            .fetch_one(db).await.ok(),
    );

    let active_tenants = parse_count(
        sqlx::query_scalar("SELECT COUNT(*)::text FROM tenants WHERE status = 'active'")
            .fetch_one(db).await.ok(),
    );

    let total_emails = parse_count(
        sqlx::query_scalar("SELECT COUNT(*)::text FROM messages WHERE status IN ('sent', 'delivered')")
            .fetch_one(db).await.ok(),
    );

    let mrr: f64 = if has_stripe_subs {
        sqlx::query_scalar::<_, String>(
            "SELECT COALESCE(SUM(CASE WHEN billing_interval = 'year' THEN amount / 12.0 WHEN billing_interval = 'month' THEN amount ELSE 0 END) / 100.0, 0)::text
             FROM stripe_subscriptions WHERE status IN ('active', 'trialing', 'past_due') AND canceled_at IS NULL",
        )
        .fetch_one(db).await.ok().and_then(|s| s.parse().ok()).unwrap_or(0.0)
    } else { 0.0 };

// Risk / health
    let (mut risk_alerts, mut critical_tenants) = (0i64, 0i64);
    let mut critical_alert_count = 0i64;
    let mut high_alert_count = 0i64;

    if has_system_alerts {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT severity, COUNT(*)::text FROM system_alerts WHERE acknowledged = false AND severity IN ('high', 'critical') GROUP BY severity",
        ).fetch_all(db).await?;

        for (severity, count_str) in &rows {
            let count: i64 = count_str.parse().unwrap_or(0);
            risk_alerts += count;
            if severity == "critical" {
                critical_alert_count += count;
                critical_tenants += count;
            } else if severity == "high" {
                high_alert_count += count;
            }
        }
    }

    let health_status = if critical_alert_count >= 5 {
        "down"
    } else if critical_alert_count > 0 || high_alert_count > 0 {
        "degraded"
    } else {
        "healthy"
    };

    let gdpr_pending = if has_gdpr_requests {
        parse_count(
            sqlx::query_scalar("SELECT COUNT(*)::text FROM gdpr_requests WHERE status = 'pending'")
                .fetch_one(db).await.ok(),
        )
    } else { 0 };

// Pipeline
    let mut pipeline = PipelineStats { prospect: 0, outreach: 0, engaged: 0, demo: 0, closed: 0 };

    if has_sales_leads {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT status, COUNT(*)::text FROM sales_leads GROUP BY status",
        ).fetch_all(db).await?;

        for (status, count_str) in &rows {
            let count: i64 = count_str.parse().unwrap_or(0);
            match status.as_str() {
                "new" | "prospect" | "identified" => pipeline.prospect += count,
                "contacted" | "outreach" | "attempted" => pipeline.outreach += count,
                "engaged" | "qualified" | "responded" => pipeline.engaged += count,
                "demo_scheduled" | "demo_booked" | "demo" => pipeline.demo += count,
                "converted" | "closed_won" => pipeline.closed += count,
                _ => {}
            }
        }
    }

// Recent activity (simple — latest leads)
    let mut recent_activity: Vec<ActivityEntry> = Vec::new();

    if has_sales_leads {
        let leads: Vec<(String, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
            "SELECT id, company_name, created_at FROM sales_leads ORDER BY created_at DESC LIMIT 5",
        ).fetch_all(db).await?;

        for (id, name, ts) in leads {
            recent_activity.push(ActivityEntry {
                id,
                entry_type: "lead".into(),
                message: format!("New lead: {name}"),
                timestamp: ts.to_rfc3339(),
            });
        }
    }

    recent_activity.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    recent_activity.truncate(10);

    let stats = DashboardStats {
        sales: SalesStats {
            active_leads,
            leads_this_week,
            campaigns_running,
            demos_scheduled,
            conversion_rate,
        },
        compliance: ComplianceStats {
            risk_alerts,
            critical_tenants,
            gdpr_pending,
            audit_events_today,
        },
        platform: PlatformStats {
            active_tenants,
            total_emails,
            mrr,
            health_status: health_status.into(),
        },
        recent_activity,
        pipeline,
    };

// Update cache
    if let Ok(mut guard) = CACHE.lock() {
        *guard = Some((Instant::now(), stats.clone()));
    }

    Ok(Json(stats))
}
