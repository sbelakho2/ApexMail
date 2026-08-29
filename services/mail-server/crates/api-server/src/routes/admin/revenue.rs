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
    /// Customer acquisition cost. Omitted (not zero) when no marketing-spend
    /// data has been recorded — a zero would be a fabricated metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cac: Option<f64>,
    pub churn_rate: f64,
    /// Expansion revenue from plan changes. Omitted when no plan-change
    /// history source exists (the `plan.changed` audit action is never
    /// emitted and stripe webhook events store no plan payload).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expansion_revenue: Option<f64>,
    pub new_customers: i64,
    /// Plan-change upgrade count. Omitted for the same reason as
    /// `expansion_revenue`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upgrades: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downgrades: Option<i64>,
    pub churned: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MonthlyData {
    pub month: String,
    pub mrr: f64,
    pub new_mrr: f64,
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
    /// Honest data-omission notes surfaced to the caller.
    pub notes: Vec<String>,
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

fn is_active_subscription_status(status: &str) -> bool {
    matches!(status, "active" | "trialing" | "past_due")
}

fn is_yearly_interval(interval: &str) -> bool {
    interval.eq_ignore_ascii_case("yearly") || interval.eq_ignore_ascii_case("year")
}

/// Monthly-normalized price with round-half-up yearly math, mirroring
/// billing-service's `yearly_price_to_monthly_mrr` (a yearly €25 000 plan
/// counts as 2 083 cents/month instead of truncating to 2 082).
fn monthly_price_cents(interval: &str, price_monthly: i64, price_yearly: i64) -> i64 {
    if is_yearly_interval(interval) {
        (price_yearly + 6) / 12
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

/// Subscriptions are read from `stripe_subscriptions` — the table the
/// billing-service webhook writers populate (the legacy `subscriptions`
/// table has no writer) — joined via `tenants.plan` to `plans` pricing,
/// mirroring billing-service's `get_mrr_report` pattern. `cancel_expr` is
/// validated at the call site to be a known column ref or a safe CASE
/// expression.
fn build_subscription_revenue_sql(has_billing_interval: bool, cancel_expr: &str) -> String {
    let billing_interval_expr = if has_billing_interval {
        "COALESCE(NULLIF(s.billing_interval, ''), 'monthly')"
    } else {
        "'monthly'"
    };

    format!(
        "SELECT s.tenant_id::text as tenant_id,
                COALESCE(NULLIF(s.plan, ''), NULLIF(t.plan, ''), 'free') as plan_name,
                {billing_interval_expr} as billing_interval,
                s.status,
                s.created_at,
                {cancel_expr} as canceled_at,
                COALESCE(p.price_monthly, 0) as price_monthly,
                COALESCE(p.price_yearly, 0) as price_yearly
         FROM stripe_subscriptions s
         JOIN tenants t ON t.id = s.tenant_id
         LEFT JOIN plans p ON p.name = t.plan"
    )
}

fn audit_log_spend_sql(audit_time_col: &str) -> Result<String, ApiError> {
    let audit_time_col = validated_column(audit_time_col)?;
    Ok(format!(
        "SELECT
            COUNT(*)::bigint as rows,
            COALESCE(SUM(
                CASE
                    WHEN jsonb_typeof(details->'spendCents') = 'number'
                    THEN (details->>'spendCents')::bigint
                    WHEN jsonb_typeof(details->'acquisitionCostCents') = 'number'
                    THEN (details->>'acquisitionCostCents')::bigint
                    WHEN jsonb_typeof(details->'marketingSpendCents') = 'number'
                    THEN (details->>'marketingSpendCents')::bigint
                    ELSE 0
                END
            ), 0)::bigint as cents
         FROM audit_logs
         WHERE action IN (
            'marketing.spend.recorded',
            'marketing.acquisition_spend.recorded',
            'growth.spend.recorded'
         )
           AND details IS NOT NULL
           AND {audit_time_col} >= $1"
    ))
}

/// Marketing spend since `cutoff`. Returns `Ok(None)` when no spend source
/// has any rows — the CAC block is then omitted from the response instead
/// of reporting a fabricated zero.
async fn marketing_spend_cents_since(
    db: &sqlx::PgPool,
    cutoff: DateTime<Utc>,
) -> Result<Option<i64>, ApiError> {
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
                    "SELECT COUNT(*)::bigint as rows,
                            COALESCE(SUM({amount_col}), 0)::bigint as cents
                     FROM marketing_spend
                     WHERE {time_col} >= $1"
                )
            } else {
                format!(
                    "SELECT COUNT(*)::bigint as rows,
                            COALESCE(SUM({amount_col}), 0)::bigint as cents
                     FROM marketing_spend"
                )
            };
            let mut query = sqlx::query_as::<_, (i64, i64)>(&sql);
            if time_col.is_some() {
                query = query.bind(cutoff);
            }
            let (rows, cents) = query.fetch_one(db).await?;
            return Ok((rows > 0).then_some(cents));
        }
    }

    if table_exists(db, "audit_logs").await {
        let audit_time_col = if column_exists(db, "audit_logs", "timestamp").await {
            validated_column("timestamp")?
        } else {
            validated_column("created_at")?
        };
        let sql = audit_log_spend_sql(audit_time_col)?;
        let (rows, cents): (i64, i64) = sqlx::query_as(&sql).bind(cutoff).fetch_one(db).await?;
        return Ok((rows > 0).then_some(cents));
    }

    Ok(None)
}

/// CAC from real spend data. `None` when spend data is absent (omitted, not
/// zero) or when there are no new customers to attribute the spend to.
fn calculate_cac(marketing_spend_cents: Option<i64>, new_customers: i64) -> Option<f64> {
    match (marketing_spend_cents, new_customers) {
        (Some(cents), n) if n > 0 => Some(cents_to_dollars(cents) / n as f64),
        _ => None,
    }
}

async fn get_revenue(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<RevenueResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    let db = &state.db;
    let now = Utc::now();
    let cutoff_30 = now - Duration::days(30);
    let month_starts = recent_month_starts(now, 6);
    let mut notes: Vec<String> = Vec::new();

    let subscriptions =
        if table_exists(db, "stripe_subscriptions").await && table_exists(db, "plans").await {
            let has_billing_interval =
                column_exists(db, "stripe_subscriptions", "billing_interval").await;
            let cancel_expr = if column_exists(db, "stripe_subscriptions", "canceled_at").await {
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

    // Plan-change velocity (upgrades/downgrades/expansion MRR) is omitted:
    // the `plan.changed` audit action it was derived from is never emitted
    // by any writer, and stripe_webhook_events stores only event ids/types
    // (no plan payload) — there is no honest data source to derive from.
    notes.push(
        "plan-change velocity (upgrades, downgrades, expansion revenue) omitted: no writer \
         records plan-change history"
            .into(),
    );

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
    if marketing_spend_cents.is_none() {
        notes.push(
            "CAC omitted: no marketing-spend rows recorded (a zero CAC would be fabricated)".into(),
        );
    }

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
            // No plan-change history source exists (see note above) — these
            // are omitted rather than reported as zero.
            expansion_revenue: None,
            upgrades: None,
            downgrades: None,
            new_customers,
            churned,
        },
        monthly_data,
        revenue_by_plan,
        notes,
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
    fn revenue_yearly_rounding_is_round_half_up() {
        // Mirrors billing-service's yearly_price_to_monthly_mrr: a yearly
        // €25 000 plan is 2 083 cents/month, not a truncated 2 082.
        assert_eq!(monthly_price_cents("yearly", 0, 25_000), 2_083);
        assert_eq!(monthly_price_cents("year", 0, 24_000), 2_000);
    }

    #[test]
    fn revenue_subscription_sql_reads_stripe_subscriptions() {
        let sql = build_subscription_revenue_sql(
            true,
            "CASE WHEN s.status = 'canceled' THEN s.updated_at ELSE NULL END",
        );

        assert!(sql.contains("FROM stripe_subscriptions s"));
        assert!(sql.contains("JOIN tenants t ON t.id = s.tenant_id"));
        assert!(sql.contains("LEFT JOIN plans p ON p.name = t.plan"));
        assert!(sql.contains("COALESCE(NULLIF(s.plan, ''), NULLIF(t.plan, ''), 'free')"));
        assert!(!sql.contains("FROM subscriptions\n"));
    }

    #[test]
    fn revenue_calculate_ltv_uses_arpa_over_churn() {
        assert_eq!(calculate_ltv(10_000, 10, 0.1), 100.0);
    }

    #[test]
    fn revenue_calculate_cac_requires_real_spend_data() {
        // With recorded spend: real division.
        assert_eq!(calculate_cac(Some(12_500), 5), Some(25.0));
        // Without spend data the metric is omitted, never a fabricated zero.
        assert_eq!(calculate_cac(None, 5), None);
        // Spend but no new customers: not attributable.
        assert_eq!(calculate_cac(Some(12_500), 0), None);
    }

    #[test]
    fn revenue_audit_log_spend_sql_reads_known_spend_metadata_keys() {
        let sql = audit_log_spend_sql("timestamp").expect("audit_log_spend_sql should succeed");

        assert!(sql.contains("spendCents"));
        assert!(sql.contains("acquisitionCostCents"));
        assert!(sql.contains("marketingSpendCents"));
        assert!(sql.contains("timestamp >= $1"));
    }
}
