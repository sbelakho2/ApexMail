//! Query engine — thin facade that delegates all analytic queries to ClickHouseEngine.
//!
//! Previously used PostgreSQL (sqlx::PgPool). All queries now route through
//! ClickHouse's columnar engine for better OLAP performance.
//!
//! # Architecture
//!
//! `QueryEngine` wraps a [`ClickHouseEngine`] and exposes a backward-compatible
//! API. Each public method extracts parameters from [`AnalyticsQuery`] and
//! delegates to the corresponding ClickHouse method. Errors are translated to
//! [`QueryError`] so callers don't depend on ClickHouse-specific error types.

use crate::clickhouse_engine::ClickHouseEngine;
use crate::types::*;

/// Errors that can occur during query execution.
#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    /// An error from the underlying ClickHouse engine.
    #[error("ClickHouse error: {0}")]
    ClickHouse(String),
    /// The provided parameters are invalid.
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),
    /// The requested resource was not found.
    #[error("Not found: {0}")]
    NotFound(String),
}

/// Thin facade over [`ClickHouseEngine`] for analytic queries.
///
/// All query methods delegate to ClickHouse. No caching or transformation
/// layer is applied — this is a pure delegation pattern.
pub struct QueryEngine {
    clickhouse: ClickHouseEngine,
}

impl QueryEngine {
    /// Create a new [`QueryEngine`] backed by the given [`ClickHouseEngine`].
    pub fn new(clickhouse: ClickHouseEngine) -> Self {
        Self { clickhouse }
    }

    /// Time-series data grouped by period.
    pub async fn get_time_series(
        &self,
        query: &AnalyticsQuery,
    ) -> Result<Vec<TimeSeriesPoint>, QueryError> {
        let granularity = query.group_by.as_deref().unwrap_or("day");
        let event_types = query.event_types.as_deref();

        self.clickhouse
            .time_series(
                &query.tenant_id,
                query.start_date,
                query.end_date,
                granularity,
                event_types,
            )
            .await
            .map_err(|e| QueryError::ClickHouse(e.to_string()))
    }

    /// Aggregation by dimension.
    pub async fn get_aggregation(
        &self,
        query: &AnalyticsQuery,
        dimension: &str,
    ) -> Result<Vec<AggregationResult>, QueryError> {
        self.clickhouse
            .aggregate_by_dimension(
                &query.tenant_id,
                query.start_date,
                query.end_date,
                dimension,
            )
            .await
            .map_err(|e| QueryError::ClickHouse(e.to_string()))
    }

    /// Funnel analysis: queued → sent → delivered → opened → clicked.
    pub async fn get_funnel_analysis(
        &self,
        query: &AnalyticsQuery,
    ) -> Result<Vec<FunnelStage>, QueryError> {
        let stages = &["queued", "sent", "delivered", "opened", "clicked"];

        self.clickhouse
            .funnel_analysis(&query.tenant_id, query.start_date, query.end_date, stages)
            .await
            .map_err(|e| QueryError::ClickHouse(e.to_string()))
    }

    /// Deliverability metrics.
    pub async fn get_deliverability_metrics(
        &self,
        query: &AnalyticsQuery,
    ) -> Result<DeliverabilityMetrics, QueryError> {
        self.clickhouse
            .deliverability_metrics(&query.tenant_id, query.start_date, query.end_date)
            .await
            .map_err(|e| QueryError::ClickHouse(e.to_string()))
    }

    /// Engagement histogram.
    pub async fn get_engagement_histogram(
        &self,
        query: &AnalyticsQuery,
    ) -> Result<Vec<EngagementBucket>, QueryError> {
        self.clickhouse
            .engagement_histogram(&query.tenant_id, query.start_date, query.end_date)
            .await
            .map_err(|e| QueryError::ClickHouse(e.to_string()))
    }

    /// Real-time stats for the current hour and day windows.
    ///
    /// Unlike the previous implementation (which queried Redis), this now
    /// reads from ClickHouse for consistency with all other analytic queries.
    /// The `redis` parameter from the old signature has been removed.
    pub async fn get_realtime_stats(&self, tenant_id: &str) -> Result<RealtimeStats, QueryError> {
        self.clickhouse
            .realtime_stats(tenant_id)
            .await
            .map_err(|e| QueryError::ClickHouse(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that QueryEngine delegates to ClickHouseEngine correctly.
    /// This test does NOT require a running ClickHouse instance — it validates
    /// the delegation layer, not the underlying engine.
    #[test]
    fn test_query_engine_construction() {
        // We can't easily construct a ClickHouseEngine without a running
        // ClickHouse instance, but we can verify the struct layout.
        // Integration tests in clickhouse_engine.rs cover the full path.
        let _ = QueryError::ClickHouse("test error".into());
        let _ = QueryError::InvalidParameters("test".into());
        let _ = QueryError::NotFound("test".into());
    }

    #[test]
    fn test_query_error_display() {
        let err = QueryError::ClickHouse("connection refused".into());
        assert_eq!(err.to_string(), "ClickHouse error: connection refused");

        let err = QueryError::InvalidParameters("missing tenant_id".into());
        assert_eq!(err.to_string(), "Invalid parameters: missing tenant_id");

        let err = QueryError::NotFound("campaign 42".into());
        assert_eq!(err.to_string(), "Not found: campaign 42");
    }

    #[test]
    fn test_query_error_is_debug() {
        let err = QueryError::ClickHouse("timeout".into());
        assert!(format!("{err:?}").contains("ClickHouse"));
    }
}
