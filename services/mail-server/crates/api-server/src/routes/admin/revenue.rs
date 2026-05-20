//! Revenue analytics endpoint.
//!

use std::collections::{HashMap, HashSet};

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Datelike, Duration, Months, NaiveTime, Utc};
use serde::Serialize;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::routes::helpers::{column_exists, table_exists};
use crate::state::AppState;

/// Allowlist of known-safe column names for use in dynamic SQL identifiers.
/// Prevents SQL injection via format!() interpolation.
const ALLOWED_COLUMNS: &[&str] = &[
    "amount_cents",
    "cost_cents",
    "spend_cents",
    "spent_at",
    "date",
    "created_at",
    "timestamp",
    "canceled_at",
    "s.canceled_at",
    "s.created_at",
];

/// Validate that a column name is in the allowlist before using it in SQL.
/// Returns the column name on success, or an error on invalid input.
/// RS-055: Uses proper error return instead of assert!() to prevent DoS via panic.
fn validated_column(col: &str) -> Result<&str, ApiError> {
    if ALLOWED_COLUMNS.contains(&col) {
        Ok(col)
    } else {
        tracing::warn!(column = %col, "rejected unknown column name for dynamic SQL construction");
        Err(ApiError::Internal(format!(
            "column '{col}' is not in the allowlist for dynamic SQL construction"
        )))
    }
}

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

#[derive(Debug, sqlx::FromRow)]
struct SubscriptionRevenueRow {
    tenant_id: String,
    plan_name: String,
    billing_interval: String,
    status: String,
    created_at: DateTime<Utc>,
    canceled_at: Option<DateTime<Utc>>,
    price_monthly: i64,
    price_yearly: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct PlanChangeRevenueRow {
    logged_at: DateTime<Utc>,
    change_type: Option<String>,
    billing_interval: Option<String>,
    previous_price_monthly: i64,
    previous_price_yearly: i64,
    new_price_monthly: i64,
    new_price_yearly: i64,
    net_amount: Option<i64>,
}

fn is_active_subscription_status(status: &str) -> bool {
    matches!(status, "active" | "trialing" | "past_due")
}

fn is_yearly_interval(interval: &str) -> bool {
    interval.eq_ignore_ascii_case("yearly") || interval.eq_ignore_ascii_case("year")
}

fn monthly_price_cents(interval: &str, price_monthly: i64, price_yearly: i64) -> i64 {
    if is_yearly_interval(interval) {
        price_yearly / 12
    } else {
        price_monthly
    }
}

fn cents_to_dollars(cents: i64) -> f64 {
    cents as f64 / 100.0
}

fn calculate_ltv(mrr_cents: i64, active_customers: i64, churn_rate: f64) -> f64 {
    if active_customers <= 0 || churn_rate <= f64::EPSILON {
        0.0
    } else {
        cents_to_dollars(mrr_cents) / active_customers as f64 / churn_rate
    }
}

fn month_start(timestamp: DateTime<Utc>) -> DateTime<Utc> {
    timestamp
        .date_naive()
        .with_day(1)
        .unwrap_or(timestamp.date_naive())
        .and_time(NaiveTime::MIN)
        .and_utc()
}

fn next_month_start(timestamp: DateTime<Utc>) -> DateTime<Utc> {
    let start = month_start(timestamp).date_naive();
    start
        .checked_add_months(Months::new(1))
        .unwrap_or(start)
        .and_time(NaiveTime::MIN)
        .and_utc()
}

fn recent_month_starts(now: DateTime<Utc>, count: u32) -> Vec<DateTime<Utc>> {
    let anchor = month_start(now).date_naive();

    (0..count)
        .rev()
        .map(|offset| {
            anchor
                .checked_sub_months(Months::new(offset))
                .unwrap_or(anchor)
                .and_time(NaiveTime::MIN)
                .and_utc()
        })
        .collect()
}

fn plan_change_delta_cents(change: &PlanChangeRevenueRow) -> i64 {
    let interval = change.billing_interval.as_deref().unwrap_or("monthly");

    monthly_price_cents(interval, change.new_price_monthly, change.new_price_yearly)
        - monthly_price_cents(
            interval,
            change.previous_price_monthly,
            change.previous_price_yearly,
        )
}

fn build_subscription_revenue_sql(has_billing_interval: bool, cancel_expr: &str) -> String {
    // cancel_expr is validated at the call site to be either a known column ref or a safe CASE expression
    let billing_interval_expr = if has_billing_interval {
        "COALESCE(NULLIF(s.billing_interval, ''), 'monthly')"
    } else {
        "'monthly'"
    };

    format!(
        "SELECT s.tenant_id::text as tenant_id,
                COALESCE(NULLIF(s.plan_name, ''), 'free') as plan_name,
                {billing_interval_expr} as billing_interval,
                s.status,
                s.created_at,
                {cancel_expr} as canceled_at,
                COALESCE(p.price_monthly, 0) as price_monthly,
                COALESCE(p.price_yearly, 0) as price_yearly
         FROM subscriptions s
         LEFT JOIN plans p ON p.name = s.plan_name"
    )
}

fn build_plan_change_sql(audit_time_col: &str) -> Result<String, ApiError> {
    let audit_time_col = validated_column(audit_time_col)?;
    Ok(format!(
        "SELECT a.{audit_time_col} as logged_at,
                a.metadata->>'changeType' as change_type,
                a.metadata->>'billingInterval' as billing_interval,
                COALESCE(previous_plan.price_monthly, 0) as previous_price_monthly,
                COALESCE(previous_plan.price_yearly, 0) as previous_price_yearly,
                COALESCE(new_plan.price_monthly, 0) as new_price_monthly,
                COALESCE(new_plan.price_yearly, 0) as new_price_yearly,
                CASE
                    WHEN jsonb_typeof(a.metadata->'proration'->'netAmount') = 'number'
                    THEN (a.metadata->'proration'->>'netAmount')::bigint
                    ELSE NULL
                END as net_amount
         FROM audit_logs a
         LEFT JOIN plans previous_plan ON previous_plan.name = a.metadata->>'previousPlan'
         LEFT JOIN plans new_plan ON new_plan.name = a.metadata->>'newPlan'
         WHERE a.action = 'plan.changed'
           AND a.metadata IS NOT NULL
           AND a.{audit_time_col} >= $1"
    ))
}

fn audit_log_spend_sql(audit_time_col: &str) -> Result<String, ApiError> {
    let audit_time_col = validated_column(audit_time_col)?;
    Ok(format!(
        "SELECT COALESCE(SUM(
            CASE
                WHEN jsonb_typeof(metadata->'spendCents') = 'number'
                THEN (metadata->>'spendCents')::bigint
                WHEN jsonb_typeof(metadata->'acquisitionCostCents') = 'number'
                THEN (metadata->>'acquisitionCostCents')::bigint
                WHEN jsonb_typeof(metadata->'marketingSpendCents') = 'number'
                THEN (metadata->>'marketingSpendCents')::bigint
                ELSE 0
            END
        ), 0)::bigint
         FROM audit_logs
         WHERE action IN (
            'marketing.spend.recorded',
            'marketing.acquisition_spend.recorded',
            'growth.spend.recorded'
         )
           AND metadata IS NOT NULL
           AND {audit_time_col} >= $1"
    ))
}

async fn marketing_spend_cents_since(
    db: &sqlx::PgPool,
    cutoff: DateTime<Utc>,
) -> Result<i64, ApiError> {
    if table_exists(db, "marketing_spend").await {
        let time_col = if column_exists(db, "marketing_spend", "spent_at").await {
            Some(validated_column("spent_at")?)
        } else if column_exists(db, "marketing_spend", "date").await {
            Some(validated_column("date")?)
        } else if column_exists(db, "marketing_spend", "created_at").await {
            Some(validated_column("created_at")?)
        } else {
            None
        };

        let mut amount_col = None;
        for column in ["amount_cents", "cost_cents", "spend_cents"] {
            if column_exists(db, "marketing_spend", column).await {
                amount_col = Some(validated_column(column)?);
                break;
            }
        }

        if let Some(amount_col) = amount_col {
            let sql = if let Some(time_col) = time_col {
                format!(
                    "SELECT COALESCE(SUM({amount_col}), 0)::bigint
                     FROM marketing_spend
                     WHERE {time_col} >= $1"
                )
            } else {
                format!("SELECT COALESCE(SUM({amount_col}), 0)::bigint FROM marketing_spend")
            };
            let mut query = sqlx::query_scalar::<_, i64>(&sql);
            if time_col.is_some() {
                query = query.bind(cutoff);
            }
            return Ok(query.fetch_one(db).await?);
        }
    }

    if table_exists(db, "audit_logs").await {
        let audit_time_col = if column_exists(db, "audit_logs", "timestamp").await {
            validated_column("timestamp")?
        } else {
            validated_column("created_at")?
        };
        let sql = audit_log_spend_sql(audit_time_col)?;
        return Ok(sqlx::query_scalar::<_, i64>(&sql)
            .bind(cutoff)
            .fetch_one(db)
            .await?);
    }

    Ok(0)
}

fn calculate_cac(marketing_spend_cents: i64, new_customers: i64) -> f64 {
    if new_customers <= 0 {
        0.0
    } else {
        cents_to_dollars(marketing_spend_cents) / new_customers as f64
    }
}

async fn get_revenue(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<RevenueResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let db = &state.db;
    let now = Utc::now();
    let cutoff_30 = now - Duration::days(30);
    let month_starts = recent_month_starts(now, 6);
    let earliest_month = month_starts
        .first()
        .copied()
        .unwrap_or_else(|| month_start(now));

    let subscriptions =
        if table_exists(db, "subscriptions").await && table_exists(db, "plans").await {
            let has_billing_interval = column_exists(db, "subscriptions", "billing_interval").await;
            let cancel_expr = if column_exists(db, "subscriptions", "canceled_at").await {
                validated_column("s.canceled_at")?
            } else {
                // Hardcoded CASE expression - not from user input, safe from injection
                "CASE WHEN s.status = 'canceled' THEN s.updated_at ELSE NULL END"
            };
            let sql = build_subscription_revenue_sql(has_billing_interval, cancel_expr);

            sqlx::query_as::<_, SubscriptionRevenueRow>(&sql)
                .fetch_all(db)
                .await?
        } else {
            Vec::new()
        };

    let tenant_plan_counts: HashMap<String, i64> = if table_exists(db, "tenants").await {
        sqlx::query_as::<_, (String, i64)>(
            "SELECT COALESCE(NULLIF(plan, ''), 'free') as plan,
                    COUNT(*)::bigint as customers
             FROM tenants
             GROUP BY 1",
        )
        .fetch_all(db)
        .await?
        .into_iter()
        .collect()
    } else {
        HashMap::new()
    };

    let plan_changes = if table_exists(db, "audit_logs").await && table_exists(db, "plans").await {
        let audit_time_col = if column_exists(db, "audit_logs", "timestamp").await {
            validated_column("timestamp")?
        } else {
            validated_column("created_at")?
        };
        let sql = build_plan_change_sql(audit_time_col)?;

        sqlx::query_as::<_, PlanChangeRevenueRow>(&sql)
            .bind(earliest_month)
            .fetch_all(db)
            .await?
    } else {
        Vec::new()
    };

    let current_mrr_cents: i64 = subscriptions
        .iter()
        .filter(|row| is_active_subscription_status(&row.status))
        .map(|row| monthly_price_cents(&row.billing_interval, row.price_monthly, row.price_yearly))
        .sum();

    let active_customers: i64 = subscriptions
        .iter()
        .filter(|row| is_active_subscription_status(&row.status))
        .map(|row| row.tenant_id.as_str())
        .collect::<HashSet<_>>()
        .len() as i64;

    let previous_mrr_cents: i64 = subscriptions
        .iter()
        .filter(|row| {
            row.created_at < cutoff_30
                && (is_active_subscription_status(&row.status)
                    || row
                        .canceled_at
                        .map(|timestamp| timestamp >= cutoff_30)
                        .unwrap_or(false))
        })
        .map(|row| monthly_price_cents(&row.billing_interval, row.price_monthly, row.price_yearly))
        .sum();

    let starting_customers: i64 = subscriptions
        .iter()
        .filter(|row| {
            row.created_at < cutoff_30
                && (is_active_subscription_status(&row.status)
                    || row
                        .canceled_at
                        .map(|timestamp| timestamp >= cutoff_30)
                        .unwrap_or(false))
        })
        .map(|row| row.tenant_id.as_str())
        .collect::<HashSet<_>>()
        .len() as i64;

    let churned: i64 = subscriptions
        .iter()
        .filter(|row| {
            row.canceled_at
                .map(|timestamp| timestamp >= cutoff_30)
                .unwrap_or(false)
        })
        .map(|row| row.tenant_id.as_str())
        .collect::<HashSet<_>>()
        .len() as i64;

    let churn_rate = if starting_customers > 0 {
        churned as f64 / starting_customers as f64
    } else {
        0.0
    };

    let current_mrr = cents_to_dollars(current_mrr_cents);
    let previous_mrr = cents_to_dollars(previous_mrr_cents);
    let mrr_growth = if previous_mrr > 0.0 {
        (current_mrr - previous_mrr) / previous_mrr
    } else {
        0.0
    };
    let arr = current_mrr * 12.0;
    let previous_arr = previous_mrr * 12.0;
    let arr_growth = if previous_arr > 0.0 {
        (arr - previous_arr) / previous_arr
    } else {
        0.0
    };

    let new_customers = if table_exists(db, "tenants").await {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM tenants WHERE created_at >= $1")
            .bind(cutoff_30)
            .fetch_one(db)
            .await
            .unwrap_or(0)
    } else {
        0
    };
    let marketing_spend_cents = marketing_spend_cents_since(db, cutoff_30).await?;

    let mut revenue_by_plan_cents = HashMap::<String, i64>::new();
    for row in subscriptions
        .iter()
        .filter(|row| is_active_subscription_status(&row.status))
    {
        let plan = if row.plan_name.trim().is_empty() {
            "free".to_string()
        } else {
            row.plan_name.clone()
        };

        *revenue_by_plan_cents.entry(plan).or_default() +=
            monthly_price_cents(&row.billing_interval, row.price_monthly, row.price_yearly);
    }

    let total_mrr_by_plan_cents: i64 = revenue_by_plan_cents.values().sum();
    let mut all_plans = tenant_plan_counts.keys().cloned().collect::<HashSet<_>>();
    all_plans.extend(revenue_by_plan_cents.keys().cloned());

    let mut revenue_by_plan: Vec<PlanRevenue> = all_plans
        .into_iter()
        .map(|plan| {
            let plan_mrr_cents = *revenue_by_plan_cents.get(&plan).unwrap_or(&0);
            let customers = *tenant_plan_counts.get(&plan).unwrap_or(&0);

            PlanRevenue {
                plan,
                customers,
                mrr: cents_to_dollars(plan_mrr_cents),
                percentage: if total_mrr_by_plan_cents > 0 {
                    plan_mrr_cents as f64 / total_mrr_by_plan_cents as f64
                } else {
                    0.0
                },
            }
        })
        .collect();
    revenue_by_plan.sort_by(|left, right| {
        right
            .mrr
            .partial_cmp(&left.mrr)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.plan.cmp(&right.plan))
    });

    let mut expansion_by_month = HashMap::<DateTime<Utc>, i64>::new();
    let mut upgrades = 0i64;
    let mut downgrades = 0i64;
    let mut expansion_revenue_cents = 0i64;

    for change in &plan_changes {
        let delta_cents = plan_change_delta_cents(change);
        let positive_delta = if delta_cents > 0 {
            delta_cents
        } else if delta_cents == 0 {
            change.net_amount.unwrap_or(0).max(0)
        } else {
            0
        };
        let is_upgrade = matches!(change.change_type.as_deref(), Some("upgrade"))
            || (change.change_type.is_none() && delta_cents > 0);
        let is_downgrade = matches!(change.change_type.as_deref(), Some("downgrade"))
            || (change.change_type.is_none() && delta_cents < 0);

        if change.logged_at >= cutoff_30 {
            if is_upgrade {
                upgrades += 1;
            }
            if is_downgrade {
                downgrades += 1;
            }
            expansion_revenue_cents += positive_delta;
        }

        if positive_delta > 0 {
            *expansion_by_month
                .entry(month_start(change.logged_at))
                .or_default() += positive_delta;
        }
    }

    let monthly_data: Vec<MonthlyData> = month_starts
        .into_iter()
        .map(|month_start| {
            let month_end = next_month_start(month_start);
            let mrr_cents: i64 = subscriptions
                .iter()
                .filter(|row| {
                    row.created_at < month_end
                        && (is_active_subscription_status(&row.status)
                            || row
                                .canceled_at
                                .map(|timestamp| timestamp >= month_end)
                                .unwrap_or(false))
                })
                .map(|row| {
                    monthly_price_cents(&row.billing_interval, row.price_monthly, row.price_yearly)
                })
                .sum();
            let new_mrr_cents: i64 = subscriptions
                .iter()
                .filter(|row| row.created_at >= month_start && row.created_at < month_end)
                .map(|row| {
                    monthly_price_cents(&row.billing_interval, row.price_monthly, row.price_yearly)
                })
                .sum();
            let churned_mrr_cents: i64 = subscriptions
                .iter()
                .filter(|row| {
                    row.canceled_at
                        .map(|timestamp| timestamp >= month_start && timestamp < month_end)
                        .unwrap_or(false)
                })
                .map(|row| {
                    monthly_price_cents(&row.billing_interval, row.price_monthly, row.price_yearly)
                })
                .sum();

            MonthlyData {
                month: month_start.format("%b").to_string(),
                mrr: cents_to_dollars(mrr_cents),
                new_mrr: cents_to_dollars(new_mrr_cents),
                expansion_mrr: cents_to_dollars(
                    *expansion_by_month.get(&month_start).unwrap_or(&0),
                ),
                churned_mrr: cents_to_dollars(churned_mrr_cents),
            }
        })
        .collect();

    let ltv = calculate_ltv(current_mrr_cents, active_customers, churn_rate);
    let cac = calculate_cac(marketing_spend_cents, new_customers);

    Ok(Json(RevenueResponse {
        stats: RevenueStats {
            mrr: current_mrr,
            mrr_growth,
            arr,
            arr_growth,
            ltv,
            cac,
            churn_rate,
            expansion_revenue: cents_to_dollars(expansion_revenue_cents),
            new_customers,
            upgrades,
            downgrades,
            churned,
        },
        monthly_data,
        revenue_by_plan,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revenue_monthly_price_cents_supports_interval_aliases() {
        assert_eq!(monthly_price_cents("monthly", 2_500, 25_000), 2_500);
        assert_eq!(monthly_price_cents("month", 2_500, 25_000), 2_500);
        assert_eq!(monthly_price_cents("yearly", 2_500, 24_000), 2_000);
        assert_eq!(monthly_price_cents("year", 2_500, 24_000), 2_000);
    }

    #[test]
    fn revenue_plan_change_delta_cents_uses_recurring_delta() {
        let change = PlanChangeRevenueRow {
            logged_at: Utc::now(),
            change_type: Some("upgrade".into()),
            billing_interval: Some("yearly".into()),
            previous_price_monthly: 2_500,
            previous_price_yearly: 25_000,
            new_price_monthly: 6_500,
            new_price_yearly: 65_000,
            net_amount: Some(5_000),
        };

        assert_eq!(plan_change_delta_cents(&change), 3_333);
    }

    #[test]
    fn revenue_calculate_ltv_uses_arpa_over_churn() {
        assert_eq!(calculate_ltv(10_000, 10, 0.1), 100.0);
    }

    #[test]
    fn revenue_calculate_cac_uses_marketing_spend_per_new_customer() {
        assert_eq!(calculate_cac(12_500, 5), 25.0);
        assert_eq!(calculate_cac(12_500, 0), 0.0);
    }

    #[test]
    fn revenue_audit_log_spend_sql_reads_known_spend_metadata_keys() {
        let sql = audit_log_spend_sql("timestamp");

        assert!(sql.contains("spendCents"));
        assert!(sql.contains("acquisitionCostCents"));
        assert!(sql.contains("marketingSpendCents"));
        assert!(sql.contains("timestamp >= $1"));
    }
}
