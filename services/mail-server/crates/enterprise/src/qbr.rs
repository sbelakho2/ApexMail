use chrono::{Datelike, Utc};
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::types::*;

/// Quarterly Business Review Service:scheduling, data gathering, insights, benchmarks
pub struct QBRService {
    db: PgPool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct QuarterlyBusinessReviewDbRow {
    id: Uuid,
    tenant_id: String,
    quarter: i32,
    year: i32,
    status: String,
    scheduled_date: Option<chrono::NaiveDate>,
    delivered_date: Option<chrono::DateTime<Utc>>,
    attendees: Option<serde_json::Value>,
    metrics: Option<serde_json::Value>,
    insights: Option<serde_json::Value>,
    recommendations: Option<serde_json::Value>,
    highlights: Option<serde_json::Value>,
    concerns: Option<serde_json::Value>,
    goals: Option<serde_json::Value>,
    previous_qbr_id: Option<Uuid>,
    quarter_over_quarter_change: Option<serde_json::Value>,
    presentation_url: Option<String>,
    report_url: Option<String>,
    recording_url: Option<String>,
    feedback: Option<serde_json::Value>,
    action_items: Option<serde_json::Value>,
    created_at: Option<chrono::DateTime<Utc>>,
    updated_at: Option<chrono::DateTime<Utc>>,
}

impl From<QuarterlyBusinessReviewDbRow> for QuarterlyBusinessReview {
    fn from(row: QuarterlyBusinessReviewDbRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            quarter: row.quarter,
            year: row.year,
            status: row.status,
            scheduled_date: row.scheduled_date,
            delivered_date: row.delivered_date,
            attendees: row.attendees,
            metrics: row.metrics,
            insights: row.insights,
            recommendations: row.recommendations,
            highlights: row.highlights,
            concerns: row.concerns,
            goals: row.goals,
            previous_qbr_id: row.previous_qbr_id,
            quarter_over_quarter_change: row.quarter_over_quarter_change,
            presentation_url: row.presentation_url,
            report_url: row.report_url,
            recording_url: row.recording_url,
            feedback: row.feedback,
            action_items: row.action_items,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

impl QBRService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Schedule a new QBR
    pub async fn schedule(
        &self,
        tenant_id: String,
        quarter: i32,
        year: i32,
        scheduled_date: Option<chrono::NaiveDate>,
        attendees: Option<serde_json::Value>,
    ) -> Result<ApiResult<QuarterlyBusinessReview>, String> {
        let id = Uuid::new_v4();
        let row = sqlx::query_as::<_, QuarterlyBusinessReviewDbRow>(
            "INSERT INTO ent_qbrs (id, tenant_id, quarter, year, status, scheduled_date, attendees, created_at, updated_at)
             VALUES ($1,$2,$3,$4,'scheduled',$5,$6,NOW(),NOW())
             RETURNING *"
        )
        .bind(id).bind(&tenant_id).bind(quarter).bind(year)
        .bind(scheduled_date).bind(&attendees)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Schedule QBR: {e}"))?;

        info!(qbr_id = %id, quarter, year, "QBR scheduled");
        Ok(ApiResult::ok(row.into()))
    }

    /// Get a QBR by ID
    pub async fn get(&self, id: Uuid) -> Result<ApiResult<QuarterlyBusinessReview>, String> {
        let row = sqlx::query_as::<_, QuarterlyBusinessReviewDbRow>(
            "SELECT * FROM ent_qbrs WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get QBR: {e}"))?;

        match row {
            Some(r) => Ok(ApiResult::ok(r.into())),
            None => Ok(ApiResult::err("QBR not found", "NOT_FOUND")),
        }
    }

    /// List QBRs for a tenant
    pub async fn list(
        &self,
        tenant_id: String,
        limit: i64,
        offset: i64,
    ) -> Result<ApiResult<Vec<QuarterlyBusinessReview>>, String> {
        let rows = sqlx::query_as::<_, QuarterlyBusinessReviewDbRow>(
            "SELECT * FROM ent_qbrs WHERE tenant_id = $1 ORDER BY year DESC, quarter DESC LIMIT $2 OFFSET $3"
        )
        .bind(&tenant_id).bind(limit).bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("List QBRs: {e}"))?;

        Ok(ApiResult::ok(rows.into_iter().map(Into::into).collect()))
    }

    /// Generate QBR data (gather metrics + insights)
    pub async fn generate(&self, id: Uuid) -> Result<ApiResult<serde_json::Value>, String> {
        let qbr = sqlx::query_as::<_, QuarterlyBusinessReviewDbRow>(
            "SELECT * FROM ent_qbrs WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get QBR: {e}"))?;

        let qbr = match qbr {
            Some(q) => q,
            None => return Ok(ApiResult::err("QBR not found", "NOT_FOUND")),
        };

        // Gather quarter metrics
        let (q_start, q_end) = quarter_date_range(qbr.quarter, qbr.year);
        let metrics = self
            .gather_quarter_metrics(qbr.tenant_id, q_start, q_end)
            .await?;
        let insights = generate_insights(&metrics);

        // Update QBR with generated data
        let metrics_json = serde_json::to_value(&metrics)
            .map_err(|e| format!("failed to serialize QBR metrics: {e}"))?;
        let insights_json = serde_json::to_value(&insights)
            .map_err(|e| format!("failed to serialize QBR insights: {e}"))?;

        let _updated = sqlx::query(
            "UPDATE ent_qbrs SET status = 'generating', metrics = $2, insights = $3, updated_at = NOW() WHERE id = $1"
        )
        .bind(id).bind(&metrics_json).bind(&insights_json)
        .execute(&self.db)
        .await
        .map_err(|e| format!("Update QBR data: {e}"))?;

        Ok(ApiResult::ok(serde_json::json!({
            "id": id,
            "metrics": metrics_json,
            "insights": insights_json,
            "status": "generating",
        })))
    }

    /// Mark QBR as delivered
    pub async fn mark_delivered(
        &self,
        id: Uuid,
    ) -> Result<ApiResult<QuarterlyBusinessReview>, String> {
        let row = sqlx::query_as::<_, QuarterlyBusinessReviewDbRow>(
            "UPDATE ent_qbrs SET status = 'delivered', delivered_date = NOW(), updated_at = NOW() WHERE id = $1 RETURNING *"
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Mark delivered: {e}"))?;

        match row {
            Some(r) => Ok(ApiResult::ok(r.into())),
            None => Ok(ApiResult::err("QBR not found", "NOT_FOUND")),
        }
    }

    /// Submit feedback on a QBR
    pub async fn submit_feedback(
        &self,
        id: Uuid,
        rating: i32,
        feedback_text: Option<&str>,
    ) -> Result<ApiResult<QuarterlyBusinessReview>, String> {
        let feedback_val = serde_json::json!({
            "rating": rating,
            "text": feedback_text,
        });
        let row = sqlx::query_as::<_, QuarterlyBusinessReviewDbRow>(
            "UPDATE ent_qbrs SET feedback = $2, status = 'feedback_received', updated_at = NOW() WHERE id = $1 RETURNING *"
        )
        .bind(id).bind(&feedback_val)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Submit feedback: {e}"))?;

        match row {
            Some(r) => Ok(ApiResult::ok(r.into())),
            None => Ok(ApiResult::err("QBR not found", "NOT_FOUND")),
        }
    }

    /// Update a QBR goal
    pub async fn update_goal(
        &self,
        id: Uuid,
        goal_id: Uuid,
        current_value: f64,
    ) -> Result<ApiResult<QBRGoal>, String> {
        let goal_row = sqlx::query_as::<_, QBRGoal>(
            "SELECT * FROM ent_qbr_goals WHERE id = $1 AND qbr_id = $2",
        )
        .bind(goal_id)
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get goal: {e}"))?;

        let goal = match goal_row {
            Some(g) => g,
            None => return Ok(ApiResult::err("Goal not found", "NOT_FOUND")),
        };

        let baseline = goal.baseline_value.unwrap_or(0.0);
        let target = goal.target_value.unwrap_or(100.0);
        let progress = calculate_goal_progress(baseline, target, current_value);
        let status = if progress >= 100.0 {
            "completed"
        } else {
            "in_progress"
        };

        let updated = sqlx::query_as::<_, QBRGoal>(
            "UPDATE ent_qbr_goals SET current_value = $3, progress_percent = $4, status = $5
             WHERE id = $1 AND qbr_id = $2 RETURNING *",
        )
        .bind(goal_id)
        .bind(id)
        .bind(current_value)
        .bind(progress)
        .bind(status)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Update goal: {e}"))?;

        Ok(ApiResult::ok(updated))
    }

    /// Get industry benchmarks
    pub async fn get_benchmarks(
        &self,
        industry: &str,
    ) -> Result<ApiResult<Vec<IndustryBenchmark>>, String> {
        let rows = sqlx::query_as::<_, IndustryBenchmark>(
            "SELECT * FROM ent_industry_benchmarks WHERE industry = $1 ORDER BY metric_name",
        )
        .bind(industry)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("Get benchmarks: {e}"))?;

        Ok(ApiResult::ok(rows))
    }

    /// Gather metrics for a quarter (internal)
    async fn gather_quarter_metrics(
        &self,
        tenant_id: String,
        start: chrono::DateTime<Utc>,
        end: chrono::DateTime<Utc>,
    ) -> Result<serde_json::Value, String> {
        let row: (i64, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT
             COALESCE(SUM(sent), 0)::bigint,
             COALESCE(SUM(delivered), 0)::bigint,
             COALESCE(SUM(bounced), 0)::bigint,
             COALESCE(SUM(opened), 0)::bigint,
             COALESCE(SUM(clicked), 0)::bigint
             FROM ent_sending_metrics
             WHERE account_id = $1 AND period_start >= $2 AND period_start < $3",
        )
        .bind(tenant_id)
        .bind(start)
        .bind(end)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Gather metrics: {e}"))?;

        let sent = row.0;
        let delivered = row.1;
        let bounced = row.2;
        let opened = row.3;
        let clicked = row.4;

        let delivery_rate = if sent > 0 {
            (delivered as f64 / sent as f64) * 100.0
        } else {
            0.0
        };
        let bounce_rate = if sent > 0 {
            (bounced as f64 / sent as f64) * 100.0
        } else {
            0.0
        };
        let open_rate = if delivered > 0 {
            (opened as f64 / delivered as f64) * 100.0
        } else {
            0.0
        };
        let click_rate = if delivered > 0 {
            (clicked as f64 / delivered as f64) * 100.0
        } else {
            0.0
        };

        Ok(serde_json::json!({
            "sent": sent,
            "delivered": delivered,
            "bounced": bounced,
            "opened": opened,
            "clicked": clicked,
            "delivery_rate": delivery_rate,
            "bounce_rate": bounce_rate,
            "open_rate": open_rate,
            "click_rate": click_rate,
        }))
    }
}

// ── Pure Functions ──────────────────────────────────────────────────────

/// Calculate goal progress:((current - baseline) / (target - baseline)) * 100
pub fn calculate_goal_progress(baseline: f64, target: f64, current: f64) -> f64 {
    let range = target - baseline;
    if range.abs() < f64::EPSILON {
        return if (current - target).abs() < f64::EPSILON {
            100.0
        } else {
            0.0
        };
    }
    let progress = ((current - baseline) / range) * 100.0;
    progress.clamp(0.0, 200.0) // Cap at 200% (over-achievement)
}

/// Get start/end dates for a quarter (quarter as int:1-4)
/// #267-268:Added validation for quarter range and safe date construction
pub fn quarter_date_range(
    quarter: i32,
    year: i32,
) -> (chrono::DateTime<Utc>, chrono::DateTime<Utc>) {
    // #268:Validate quarter is 1-4, default to Q1 for invalid values with warning
    let valid_quarter = if !(1..=4).contains(&quarter) {
        tracing::warn!(quarter = quarter, "Invalid quarter value, defaulting to Q1");
        1
    } else {
        quarter
    };

    // #268: Pre-validated above (line 324), but keep for exhaustiveness
    debug_assert!((1..=4).contains(&valid_quarter));
    let (start_month, end_month) = match valid_quarter {
        1 => (1u32, 4u32),
        2 => (4, 7),
        3 => (7, 10),
        4 => (10, 1),
        // Pre-validated above (line 324), unreachable if reached
        _ => return (chrono::Utc::now(), chrono::Utc::now()),
    };

    // #267: Use checked construction to avoid potential panics
    let start = chrono::NaiveDate::from_ymd_opt(year, start_month, 1)
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .unwrap_or_else(|| {
            // Fallback:January 1st of the year at midnight
            chrono::NaiveDate::from_ymd_opt(year, 1, 1)
                .unwrap_or(chrono::NaiveDate::MIN)
                .and_hms_opt(0, 0, 0)
                .unwrap_or_else(|| chrono::NaiveDate::MIN.and_time(chrono::NaiveTime::MIN))
        });

    let end_year = if valid_quarter == 4 { year + 1 } else { year };
    let end = chrono::NaiveDate::from_ymd_opt(end_year, end_month, 1)
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .unwrap_or_else(|| {
            chrono::NaiveDate::from_ymd_opt(end_year, 1, 1)
                .unwrap_or(chrono::NaiveDate::MIN)
                .and_hms_opt(0, 0, 0)
                .unwrap_or_else(|| chrono::NaiveDate::MIN.and_time(chrono::NaiveTime::MIN))
        });

    (start.and_utc(), end.and_utc())
}

/// Generate insights from quarter metrics
pub fn generate_insights(metrics: &serde_json::Value) -> Vec<QBRInsight> {
    let mut insights = Vec::new();

    let delivery_rate = metrics["delivery_rate"].as_f64().unwrap_or(100.0);
    let bounce_rate = metrics["bounce_rate"].as_f64().unwrap_or(0.0);
    let open_rate = metrics["open_rate"].as_f64().unwrap_or(0.0);
    let click_rate = metrics["click_rate"].as_f64().unwrap_or(0.0);

    // Insight:Low delivery rate
    if delivery_rate < 95.0 {
        insights.push(QBRInsight {
            category: "deliverability".into(),
            severity: if delivery_rate < 90.0 { "critical".into() } else { "warning".into() },
            message: format!("Delivery rate is {:.1}% (target: 95%+). Review bounce reasons and sender authentication.", delivery_rate),
            metric_name: Some("delivery_rate".into()),
            metric_value: Some(delivery_rate),
            threshold: Some(95.0),
        });
    }

    // Insight:High bounce rate
    if bounce_rate > 5.0 {
        insights.push(QBRInsight {
            category: "list_hygiene".into(),
            severity: if bounce_rate > 10.0 {
                "critical".into()
            } else {
                "warning".into()
            },
            message: format!(
                "Bounce rate is {:.1}% (target: <5%). Consider list cleaning.",
                bounce_rate
            ),
            metric_name: Some("bounce_rate".into()),
            metric_value: Some(bounce_rate),
            threshold: Some(5.0),
        });
    }

    // Insight:Low open rate
    if open_rate < 15.0 {
        insights.push(QBRInsight {
            category: "engagement".into(),
            severity: "info".into(),
            message: format!(
                "Open rate is {:.1}% (industry avg: 20-25%). Review subject lines and send times.",
                open_rate
            ),
            metric_name: Some("open_rate".into()),
            metric_value: Some(open_rate),
            threshold: Some(15.0),
        });
    }

    // Insight:Low click rate
    if click_rate < 2.0 {
        insights.push(QBRInsight {
            category: "engagement".into(),
            severity: "info".into(),
            message: format!(
                "Click rate is {:.1}% (industry avg: 2-5%). Review email content and CTAs.",
                click_rate
            ),
            metric_name: Some("click_rate".into()),
            metric_value: Some(click_rate),
            threshold: Some(2.0),
        });
    }

    // Positive insight:Good performance
    if delivery_rate >= 99.0 && bounce_rate < 1.0 {
        insights.push(QBRInsight {
            category: "deliverability".into(),
            severity: "positive".into(),
            message: format!(
                "Delivery rate {:.1}% with {:.1}% bounce rate. Outstanding performance!",
                delivery_rate, bounce_rate
            ),
            metric_name: Some("delivery_rate".into()),
            metric_value: Some(delivery_rate),
            threshold: None,
        });
    }

    insights
}

/// Compare account metrics against industry benchmarks
pub fn compare_with_benchmarks(
    metrics: &serde_json::Value,
    benchmarks: &[IndustryBenchmark],
) -> Vec<BenchmarkComparison> {
    let mut comparisons = Vec::new();

    for benchmark in benchmarks {
        let account_value = match benchmark.metric_name.as_str() {
            "delivery_rate" => metrics["delivery_rate"].as_f64(),
            "bounce_rate" => metrics["bounce_rate"].as_f64(),
            "open_rate" => metrics["open_rate"].as_f64(),
            "click_rate" => metrics["click_rate"].as_f64(),
            _ => None,
        };

        if let Some(value) = account_value {
            let p25 = benchmark.percentile_25.unwrap_or(0.0);
            let p50 = benchmark.percentile_50.unwrap_or(benchmark.metric_value);
            let p75 = benchmark.percentile_75.unwrap_or(100.0);
            let p90 = benchmark.percentile_90.unwrap_or(100.0);

            let percentile = estimate_percentile(value, p25, p50, p75, p90);
            let ranking = if percentile >= 90.0 {
                format!("Top 10% performer ({:.0}th percentile)", percentile)
            } else if percentile >= 75.0 {
                format!("Above average ({:.0}th percentile)", percentile)
            } else if percentile >= 50.0 {
                format!("Average ({:.0}th percentile)", percentile)
            } else if percentile >= 25.0 {
                format!("Below average ({:.0}th percentile)", percentile)
            } else {
                format!("Bottom quartile ({:.0}th percentile)", percentile)
            };

            comparisons.push(BenchmarkComparison {
                metric_name: benchmark.metric_name.clone(),
                account_value: value,
                industry_avg: p50,
                percentile_ranking: ranking,
                unit: benchmark.unit.clone().unwrap_or_else(|| "percent".into()),
            });
        }
    }

    comparisons
}

/// Estimate percentile ranking based on known quartile values
///
/// Fix J-9: the result is clamped to 0..=100 — extrapolating past the p90
/// anchor (e.g. a value twice the p90) previously produced "137th percentile"
/// rankings.
pub fn estimate_percentile(value: f64, p25: f64, median: f64, p75: f64, p90: f64) -> f64 {
    let raw = if value <= p25 {
        let ratio = if p25 > 0.0 { value / p25 } else { 0.0 };
        ratio * 25.0
    } else if value <= median {
        25.0 + ((value - p25) / (median - p25).max(0.001)) * 25.0
    } else if value <= p75 {
        50.0 + ((value - median) / (p75 - median).max(0.001)) * 25.0
    } else if value <= p90 {
        75.0 + ((value - p75) / (p90 - p75).max(0.001)) * 15.0
    } else {
        90.0 + ((value - p90) / p90.max(0.001)) * 10.0
    };
    raw.clamp(0.0, 100.0)
}

/// Calculate quarter-over-quarter change
pub fn qoq_change(current: f64, previous: f64) -> f64 {
    if previous.abs() < f64::EPSILON {
        return if current.abs() < f64::EPSILON {
            0.0
        } else {
            100.0
        };
    }
    ((current - previous) / previous) * 100.0
}

/// Determine the current quarter label
pub fn current_quarter() -> (String, i32) {
    let now = Utc::now();
    let q = match now.month() {
        1..=3 => "Q1",
        4..=6 => "Q2",
        7..=9 => "Q3",
        _ => "Q4",
    };
    (q.into(), now.year())
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_goal_progress_midway() {
        let progress = calculate_goal_progress(100.0, 200.0, 150.0);
        assert!((progress - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_goal_progress_achieved() {
        let progress = calculate_goal_progress(100.0, 200.0, 200.0);
        assert!((progress - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_goal_progress_over_achieved() {
        let progress = calculate_goal_progress(100.0, 200.0, 300.0);
        assert!((progress - 200.0).abs() < 0.01); // Capped at 200%
    }

    #[test]
    fn test_goal_progress_no_progress() {
        let progress = calculate_goal_progress(100.0, 200.0, 100.0);
        assert!((progress - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_goal_progress_same_baseline_target() {
        let progress = calculate_goal_progress(100.0, 100.0, 100.0);
        assert!((progress - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_quarter_date_range_q1() {
        let (start, end) = quarter_date_range(1, 2024);
        assert_eq!(start.month(), 1);
        assert_eq!(end.month(), 4);
        assert_eq!(start.year(), 2024);
    }

    #[test]
    fn test_quarter_date_range_q4() {
        let (start, end) = quarter_date_range(4, 2024);
        assert_eq!(start.month(), 10);
        assert_eq!(start.year(), 2024);
        assert_eq!(end.month(), 1);
        assert_eq!(end.year(), 2025);
    }

    #[test]
    fn test_insights_low_delivery() {
        let metrics = serde_json::json!({
            "delivery_rate": 85.0,
            "bounce_rate": 15.0,
            "open_rate": 25.0,
            "click_rate": 5.0,
        });
        let insights = generate_insights(&metrics);
        assert!(insights
            .iter()
            .any(|i| i.category == "deliverability" && i.severity == "critical"));
        assert!(insights.iter().any(|i| i.category == "list_hygiene"));
    }

    #[test]
    fn test_insights_excellent_performance() {
        let metrics = serde_json::json!({
            "delivery_rate": 99.5,
            "bounce_rate": 0.5,
            "open_rate": 30.0,
            "click_rate": 5.0,
        });
        let insights = generate_insights(&metrics);
        assert!(insights.iter().any(|i| i.severity == "positive"));
    }

    #[test]
    fn test_insights_low_engagement() {
        let metrics = serde_json::json!({
            "delivery_rate": 98.0,
            "bounce_rate": 2.0,
            "open_rate": 10.0,
            "click_rate": 1.0,
        });
        let insights = generate_insights(&metrics);
        assert!(insights.iter().any(|i| i.message.contains("Open rate")));
        assert!(insights.iter().any(|i| i.message.contains("Click rate")));
    }

    #[test]
    fn test_qoq_change_increase() {
        let change = qoq_change(120.0, 100.0);
        assert!((change - 20.0).abs() < 0.01);
    }

    #[test]
    fn test_qoq_change_decrease() {
        let change = qoq_change(80.0, 100.0);
        assert!((change - (-20.0)).abs() < 0.01);
    }

    #[test]
    fn test_qoq_change_from_zero() {
        assert_eq!(qoq_change(50.0, 0.0), 100.0);
        assert_eq!(qoq_change(0.0, 0.0), 0.0);
    }

    #[test]
    fn test_estimate_percentile_below_median() {
        let p = estimate_percentile(30.0, 20.0, 40.0, 60.0, 80.0);
        assert!((25.0..=50.0).contains(&p), "Expected 25-50, got {}", p);
    }

    #[test]
    fn test_estimate_percentile_above_p90() {
        let p = estimate_percentile(100.0, 20.0, 40.0, 60.0, 80.0);
        assert!(p > 90.0, "Expected >90, got {}", p);
    }

    #[test]
    fn test_benchmark_comparison() {
        let metrics = serde_json::json!({
            "delivery_rate": 97.0,
            "bounce_rate": 3.0,
            "open_rate": 22.0,
            "click_rate": 3.5,
        });
        let benchmarks = vec![IndustryBenchmark {
            id: Uuid::new_v4(),
            industry: "saas".into(),
            metric_name: "delivery_rate".into(),
            metric_value: 95.0,
            percentile_25: Some(92.0),
            percentile_50: Some(95.0),
            percentile_75: Some(97.5),
            percentile_90: Some(99.0),
            unit: Some("percent".into()),
            period: Some("Q1 2024".into()),
            source: Some("industry_report".into()),
            valid_from: None,
            valid_until: None,
        }];
        let comparisons = compare_with_benchmarks(&metrics, &benchmarks);
        assert_eq!(comparisons.len(), 1);
        assert!((comparisons[0].account_value - 97.0).abs() < 0.01);
        assert!(comparisons[0].percentile_ranking.contains("percentile"));
    }

    #[test]
    fn test_current_quarter() {
        let (q, y) = current_quarter();
        assert!(q.starts_with('Q'));
        assert!(y >= 2024);
    }

    #[test]
    fn test_qbr_insight_serialization() {
        let insight = QBRInsight {
            category: "deliverability".into(),
            severity: "warning".into(),
            message: "Delivery rate is 93% (target: 95%+)".into(),
            metric_name: Some("delivery_rate".into()),
            metric_value: Some(93.0),
            threshold: Some(95.0),
        };
        let json = serde_json::to_value(&insight).unwrap();
        assert_eq!(json["category"], "deliverability");
    }

    #[test]
    fn test_benchmark_comparison_serialization() {
        let bc = BenchmarkComparison {
            metric_name: "delivery_rate".into(),
            account_value: 97.0,
            industry_avg: 95.0,
            percentile_ranking: "Above average (65th percentile)".into(),
            unit: "percent".into(),
        };
        let json = serde_json::to_value(&bc).unwrap();
        assert_eq!(json["account_value"], 97.0);
    }
}
