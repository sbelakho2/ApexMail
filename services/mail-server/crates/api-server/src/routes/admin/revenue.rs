//! Revenue analytics endpoint.
//!
//! Migrated from: apps/control-plane/src/app/api/revenue/route.ts

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(get_revenue))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevenueStats {
    pub mrr: f64,
    pub mrr_growth: f64,
    pub arr: f64,
    pub arr_growth: f64,
    pub ltv: f64,
    pub cac: f64,
    pub churn_rate: f64,
    pub expansion_revenue: f64,
    pub new_customers: i64,
    pub upgrades: i64,
    pub downgrades: i64,
    pub churned: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MonthlyData {
    pub month: String,
    pub mrr: f64,
    pub new_mrr: f64,
    pub expansion_mrr: f64,
    pub churned_mrr: f64,
}

#[derive(Debug, Serialize)]
pub struct PlanRevenue {
    pub plan: String,
    pub customers: i64,
    pub mrr: f64,
    pub percentage: f64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevenueResponse {
    pub stats: RevenueStats,
    pub monthly_data: Vec<MonthlyData>,
    pub revenue_by_plan: Vec<PlanRevenue>,
}

async fn get_revenue(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<RevenueResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let db = &state.db;

    // Current MRR
    let current_mrr: f64 = sqlx::query_scalar::<_, String>(
        "SELECT COALESCE(SUM(
            CASE WHEN billing_interval = 'year' THEN amount / 12.0 ELSE 0 END
         ) / 100.0, 0)::text
         FROM stripe_subscriptions
         WHERE status IN ('active', 'trialing', 'past_due') AND canceled_at IS NULL",
    )
    .fetch_one(db)
    .await
    .ok()
    .and_then(|s| s.parse().ok())
    .unwrap_or(0.0);

    // Previous MRR (30 days ago snapshot)
    let previous_mrr: f64 = sqlx::query_scalar::<_, String>(
        "SELECT COALESCE(SUM(
            CASE WHEN billing_interval = 'year' THEN amount / 12.0
                 WHEN billing_interval = 'month' THEN amount
                 ELSE 0 END
         ) / 100.0, 0)::text
         FROM stripe_subscriptions
         WHERE status IN ('active', 'trialing', 'past_due')
           AND created_at < NOW() - INTERVAL '30 days'
           AND (canceled_at IS NULL OR canceled_at >= NOW() - INTERVAL '30 days')",
    )
    .fetch_one(db)
    .await
    .ok()
    .and_then(|s| s.parse().ok())
    .unwrap_or(0.0);

    let mrr_growth = if previous_mrr > 0.0 { (current_mrr - previous_mrr) / previous_mrr } else { 0.0 };
    let arr = current_mrr * 12.0;
    let previous_arr = previous_mrr * 12.0;
    let arr_growth = if previous_arr > 0.0 { (arr - previous_arr) / previous_arr } else { 0.0 };

    // Revenue by plan
    let plan_rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT t.plan,
                COUNT(DISTINCT t.id)::text,
                COALESCE(SUM(
                    CASE WHEN s.billing_interval = 'year' THEN s.amount / 12.0
                         WHEN s.billing_interval = 'month' THEN s.amount
                         ELSE 0 END
                ) / 100.0, 0)::text
         FROM tenants t
         LEFT JOIN stripe_subscriptions s
           ON s.tenant_id = t.id
          AND s.status IN ('active', 'trialing', 'past_due')
          AND s.canceled_at IS NULL
         GROUP BY t.plan
         ORDER BY 3 DESC",
    )
    .fetch_all(db)
    .await
    ?;

    let total_mrr_by_plan: f64 = plan_rows
        .iter()
        .map(|(_, _, mrr)| mrr.parse::<f64>().unwrap_or(0.0))
        .sum();

    let revenue_by_plan: Vec<PlanRevenue> = plan_rows
        .into_iter()
        .map(|(plan, customers, mrr)| {
            let plan_mrr: f64 = mrr.parse().unwrap_or(0.0);
            PlanRevenue {
                plan: if plan.is_empty() { "free".into() } else { plan },
                customers: customers.parse().unwrap_or(0),
                mrr: plan_mrr,
                percentage: if total_mrr_by_plan > 0.0 { plan_mrr / total_mrr_by_plan } else { 0.0 },
            }
        })
        .collect();

    // Monthly data (last 6 months)
    let monthly_rows: Vec<(String, String)> = sqlx::query_as(
        "WITH months AS (
            SELECT generate_series(
                date_trunc('month', NOW()) - INTERVAL '5 months',
                date_trunc('month', NOW()),
                INTERVAL '1 month'
            ) AS month_start
         )
         SELECT to_char(month_start, 'Mon'),
                COALESCE(SUM(i.total) / 100.0, 0)::text
         FROM months m
         LEFT JOIN invoices i
           ON date_trunc('month', COALESCE(i.issued_at, i.created_at)) = m.month_start
          AND i.status IN ('paid', 'open')
         GROUP BY month_start
         ORDER BY month_start",
    )
    .fetch_all(db)
    .await
    ?;

    let monthly_data: Vec<MonthlyData> = monthly_rows
        .into_iter()
        .map(|(month, mrr)| MonthlyData {
            month,
            mrr: mrr.parse().unwrap_or(0.0),
            new_mrr: 0.0,
            expansion_mrr: 0.0,
            churned_mrr: 0.0,
        })
        .collect();

    // Customer counts
    let new_customers: i64 = sqlx::query_scalar::<_, String>(
        "SELECT COUNT(*)::text FROM tenants WHERE created_at >= NOW() - INTERVAL '30 days'",
    )
    .fetch_one(db)
    .await
    .ok()
    .and_then(|s| s.parse().ok())
    .unwrap_or(0);

    let movement: (String, String) = sqlx::query_as(
        "SELECT COUNT(*) FILTER (WHERE canceled_at >= NOW() - INTERVAL '30 days')::text,
                COUNT(*) FILTER (WHERE status IN ('active', 'trialing', 'past_due') AND canceled_at IS NULL)::text
         FROM stripe_subscriptions",
    )
    .fetch_one(db)
    .await
    .unwrap_or(("0".into(), "0".into()));

    let churned: i64 = movement.0.parse().unwrap_or(0);
    let active: i64 = movement.1.parse().unwrap_or(0);
    let churn_rate = if active > 0 { churned as f64 / active as f64 } else { 0.0 };

    Ok(Json(RevenueResponse {
        stats: RevenueStats {
            mrr: current_mrr,
            mrr_growth,
            arr,
            arr_growth,
            ltv: 0.0,
            cac: 0.0,
            churn_rate,
            expansion_revenue: 0.0,
            new_customers,
            upgrades: 0,
            downgrades: 0,
            churned,
        },
        monthly_data,
        revenue_by_plan,
    }))
}
