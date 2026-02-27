//! Query engine – time-series, aggregations, funnel analysis, deliverability.

use sqlx::PgPool;

use crate::types::*;

pub struct QueryEngine {
    pool: PgPool,
}

impl QueryEngine {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Time-series data grouped by period.
    pub async fn get_time_series(&self, query: &AnalyticsQuery) -> anyhow::Result<Vec<TimeSeriesPoint>> {
        let group_by = query.group_by.as_deref().unwrap_or("day");
        let trunc = time_trunc_expression(group_by);
        let limit = query.limit.unwrap_or(1000);

        let mut conditions = vec![
            "tenant_id = $1".to_string(),
            "timestamp >= $2".to_string(),
            "timestamp < $3".to_string(),
        ];
        let has_event_filter = query.event_types.as_ref().map_or(false, |t| !t.is_empty());
        if has_event_filter {
            conditions.push("event_type = ANY($5::text[])".to_string());
        }
        let where_clause = conditions.join(" AND ");

        let sql = format!(
            "SELECT {trunc} as period, COUNT(*) as value FROM events WHERE {where_clause} GROUP BY period ORDER BY period LIMIT $4"
        );

        let mut q = sqlx::query_as::<_, (String, i64)>(&sql)
            .bind(&query.tenant_id)
            .bind(query.start_date)
            .bind(query.end_date)
            .bind(limit);
        if let Some(ref types) = query.event_types {
            if !types.is_empty() {
                q = q.bind(types);
            }
        }
        let rows = q.fetch_all(&self.pool).await?;

        Ok(rows
            .into_iter()
            .map(|(ts, val)| TimeSeriesPoint {
                timestamp: ts,
                value: val,
            })
            .collect())
    }

    /// Aggregation by dimension.
    pub async fn get_aggregation(
        &self,
        query: &AnalyticsQuery,
        dimension: &str,
    ) -> anyhow::Result<Vec<AggregationResult>> {
        let allowed_dims = ["event_type", "recipient_domain", "bounce_type", "link_id"];
        let dim_col = if allowed_dims.contains(&dimension) {
            dimension
        } else {
            "event_type"
        };

        let sql = format!(
            "SELECT {dim_col} as dim, COUNT(*) as cnt FROM events WHERE tenant_id = $1 AND timestamp >= $2 AND timestamp < $3 GROUP BY {dim_col} ORDER BY cnt DESC LIMIT 100"
        );

        let rows = sqlx::query_as::<_, (String, i64)>(&sql)
            .bind(&query.tenant_id)
            .bind(query.start_date)
            .bind(query.end_date)
            .fetch_all(&self.pool)
            .await?;

        let total: i64 = rows.iter().map(|(_, c)| c).sum();
        Ok(rows
            .into_iter()
            .map(|(dim, count)| AggregationResult {
                dimension: dim,
                count,
                percentage: if total > 0 {
                    Some(count as f64 / total as f64 * 100.0)
                } else {
                    None
                },
            })
            .collect())
    }

    /// Funnel analysis: queued → sent → delivered → opened → clicked.
    pub async fn get_funnel_analysis(
        &self,
        query: &AnalyticsQuery,
    ) -> anyhow::Result<Vec<FunnelStage>> {
        let rows = sqlx::query_as::<_, (String, i64)>(
            "SELECT event_type, COUNT(DISTINCT message_id) as cnt FROM events \
             WHERE tenant_id = $1 AND timestamp >= $2 AND timestamp < $3 \
             GROUP BY event_type"
        )
        .bind(&query.tenant_id)
        .bind(query.start_date)
        .bind(query.end_date)
        .fetch_all(&self.pool)
        .await?;

        let counts: std::collections::HashMap<String, i64> =
            rows.into_iter().collect();

        let stages = ["queued", "sent", "delivered", "opened", "clicked"];
        let mut result: Vec<FunnelStage> = Vec::with_capacity(stages.len());
        let mut prev_count: Option<i64> = None;

        for stage in &stages {
            let count = counts.get(*stage).copied().unwrap_or(0);
            let first_count = if result.is_empty() { count.max(1) } else { result[0].count.max(1) };
            let dropoff = match prev_count {
                Some(prev) if prev > 0 => ((1.0 - count as f64 / prev as f64) * 100.0).round(),
                _ => 0.0,
            };
            result.push(FunnelStage {
                stage: stage.to_string(),
                count,
                dropoff,
                percentage: (count as f64 / first_count as f64 * 100.0).round(),
            });
            prev_count = Some(count);
        }

        Ok(result)
    }

    /// Deliverability metrics.
    pub async fn get_deliverability_metrics(
        &self,
        query: &AnalyticsQuery,
    ) -> anyhow::Result<DeliverabilityMetrics> {
        let rows = sqlx::query_as::<_, (String, i64)>(
            "SELECT event_type, COUNT(*) as cnt FROM events \
             WHERE tenant_id = $1 AND timestamp >= $2 AND timestamp < $3 \
             GROUP BY event_type"
        )
        .bind(&query.tenant_id)
        .bind(query.start_date)
        .bind(query.end_date)
        .fetch_all(&self.pool)
        .await?;

        let counts: std::collections::HashMap<String, i64> =
            rows.into_iter().collect();

        let sent = *counts.get("sent").unwrap_or(&0) as f64;
        let delivered = *counts.get("delivered").unwrap_or(&0) as f64;
        let bounced = *counts.get("bounced").unwrap_or(&0) as f64;
        let complained = *counts.get("complained").unwrap_or(&0) as f64;
        let opened = *counts.get("opened").unwrap_or(&0) as f64;
        let clicked = *counts.get("clicked").unwrap_or(&0) as f64;
        let unsubscribed = *counts.get("unsubscribed").unwrap_or(&0) as f64;

        let safe_div = |num: f64, den: f64| if den > 0.0 { num / den } else { 0.0 };

        Ok(DeliverabilityMetrics {
            delivery_rate: safe_div(delivered, sent),
            bounce_rate: safe_div(bounced, sent),
            complaint_rate: safe_div(complained, sent),
            open_rate: safe_div(opened, delivered),
            click_rate: safe_div(clicked, delivered),
            unsubscribe_rate: safe_div(unsubscribed, delivered),
        })
    }

    /// Engagement histogram.
    pub async fn get_engagement_histogram(
        &self,
        query: &AnalyticsQuery,
    ) -> anyhow::Result<Vec<EngagementBucket>> {
        let rows = sqlx::query_as::<_, (String, i64)>(
            r#"
            WITH recipient_stats AS (
                SELECT recipient,
                    COUNT(*) FILTER (WHERE event_type = 'clicked') as clicks,
                    COUNT(*) FILTER (WHERE event_type = 'opened') as opens,
                    COUNT(*) FILTER (WHERE event_type = 'unsubscribed') as unsubs
                FROM events
                WHERE tenant_id = $1 AND timestamp >= $2 AND timestamp < $3
                GROUP BY recipient
            )
            SELECT
                CASE
                    WHEN clicks > 2 THEN 'highly_engaged'
                    WHEN opens > 2 THEN 'engaged'
                    WHEN opens > 0 THEN 'somewhat_engaged'
                    WHEN unsubs > 0 THEN 'unsubscribed'
                    ELSE 'not_engaged'
                END as bucket,
                COUNT(*) as cnt
            FROM recipient_stats
            GROUP BY bucket
            "#,
        )
        .bind(&query.tenant_id)
        .bind(query.start_date)
        .bind(query.end_date)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(range, count)| EngagementBucket { range, count })
            .collect())
    }

    /// Real-time stats from Redis.
    pub async fn get_realtime_stats(
        &self,
        redis: &deadpool_redis::Pool,
        tenant_id: &str,
    ) -> anyhow::Result<serde_json::Value> {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let hour = chrono::Utc::now().format("%H").to_string();
        let event_types = ["sent", "delivered", "bounced", "opened", "clicked", "complained"];

        let mut conn = redis.get().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut today_stats = serde_json::Map::new();
        let mut hour_stats = serde_json::Map::new();

        for et in &event_types {
            let day_key = format!("stats:{tenant_id}:day:{today}:{et}");
            let hour_key = format!("stats:{tenant_id}:hour:{today}:{hour}:{et}");

            let day_val: Option<i64> = redis::cmd("GET")
                .arg(&day_key)
                .query_async(&mut *conn)
                .await
                .unwrap_or(None);

            let hour_val: Option<i64> = redis::cmd("GET")
                .arg(&hour_key)
                .query_async(&mut *conn)
                .await
                .unwrap_or(None);

            today_stats.insert(et.to_string(), serde_json::json!(day_val.unwrap_or(0)));
            hour_stats.insert(et.to_string(), serde_json::json!(hour_val.unwrap_or(0)));
        }

        Ok(serde_json::json!({
            "today": today_stats,
            "this_hour": hour_stats,
        }))
    }
}

fn time_trunc_expression(group_by: &str) -> String {
    match group_by {
        "hour" => "DATE_TRUNC('hour', timestamp)::text".into(),
        "day" => "DATE_TRUNC('day', timestamp)::text".into(),
        "week" => "DATE_TRUNC('week', timestamp)::text".into(),
        "month" => "DATE_TRUNC('month', timestamp)::text".into(),
        _ => "DATE_TRUNC('day', timestamp)::text".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_trunc_expression() {
        assert!(time_trunc_expression("hour").contains("hour"));
        assert!(time_trunc_expression("day").contains("day"));
        assert!(time_trunc_expression("invalid").contains("day"));
    }

    #[test]
    fn test_funnel_stage_creation() {
        let stage = FunnelStage {
            stage: "sent".into(),
            count: 1000,
            dropoff: 0.0,
            percentage: 100.0,
        };
        assert_eq!(stage.count, 1000);
    }
}
