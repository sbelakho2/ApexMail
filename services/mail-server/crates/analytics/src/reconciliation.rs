//! Reconciliation worker – exact-once event verification, health checks.

use chrono::{Duration, TimeDelta, Utc};
use sqlx::PgPool;
use tracing::warn;

use crate::types::*;

/// Expected event chain for a successfully delivered message.
const EXPECTED_CHAIN: &[&str] = &["queued", "sent", "delivered"];

pub struct ReconciliationWorker {
    pool: PgPool,
    redis: deadpool_redis::Pool,
}

impl ReconciliationWorker {
    pub fn new(pool: PgPool, redis: deadpool_redis::Pool) -> Self {
        Self { pool, redis }
    }

/// Run full reconciliation cycle.
    pub async fn run(&self) -> anyhow::Result<ReconciliationResult> {
        let since = Utc::now() - TimeDelta::try_hours(24).unwrap_or(TimeDelta::zero());
        let discrepancies = self.find_discrepancies(since).await?;
        let health = self.check_health().await?;

        if !discrepancies.is_empty() {
            self.publish_alert(&discrepancies).await?;
        }

        Ok(ReconciliationResult {
            discrepancies_found: discrepancies.len() as i64,
            discrepancies,
            health_check: health,
            run_at: Utc::now(),
        })
    }

/// Find messages with incomplete event chains.
    async fn find_discrepancies(
        &self,
        since: chrono::DateTime<Utc>,
    ) -> anyhow::Result<Vec<DiscrepancyDetail>> {
// Find messages that were queued but not delivered
        let rows = sqlx::query_as::<_, (String, String, Vec<String>)>(
            r#"
            SELECT message_id, tenant_id, array_agg(DISTINCT event_type ORDER BY event_type) as events
            FROM events
            WHERE timestamp >= $1
            GROUP BY message_id, tenant_id
            HAVING 'queued' = ANY(array_agg(event_type))
               AND NOT ('delivered' = ANY(array_agg(event_type)))
               AND NOT ('bounced' = ANY(array_agg(event_type)))
            LIMIT 1000
            "#,
        )
        .bind(since)
        .fetch_all(&self.pool)
        .await?;

        let mut discrepancies = Vec::new();
        for (message_id, tenant_id, events) in rows {
            let missing: Vec<String> = EXPECTED_CHAIN
                .iter()
                .filter(|&&stage| !events.iter().any(|e| e == stage))
                .map(|s| s.to_string())
                .collect();

            if !missing.is_empty() {
                discrepancies.push(DiscrepancyDetail {
                    message_id,
                    tenant_id,
                    expected_events: EXPECTED_CHAIN.iter().map(|s| s.to_string()).collect(),
                    actual_events: events,
                    missing_events: missing,
                });
            }
        }

        Ok(discrepancies)
    }

/// Health checks:orphaned messages, event lag, queue backlog.
    async fn check_health(&self) -> anyhow::Result<serde_json::Value> {
        let now = Utc::now();

// Orphaned messages:sent but no events in 5+ min
// #189:Use NOT EXISTS instead of NOT IN (SELECT DISTINCT ...) for O(n) instead of O(n×m)
        let five_min_ago = now - Duration::minutes(5);
        let orphaned_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(DISTINCT m.message_id) FROM messages m \
             WHERE m.status = 'sent' AND m.created_at < $1 \
             AND NOT EXISTS (SELECT 1 FROM events e WHERE e.message_id = m.message_id AND e.timestamp >= $1)",
        )
        .bind(five_min_ago)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| anyhow::anyhow!("reconciliation orphaned_count query failed: {e}"))?;

// Event lag:average time between events
        let event_lag: (Option<f64>,) = sqlx::query_as(
            "SELECT AVG(EXTRACT(EPOCH FROM (NOW() - timestamp))) as avg_lag \
             FROM events WHERE timestamp >= NOW() - INTERVAL '1 hour'",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| anyhow::anyhow!("reconciliation event_lag query failed: {e}"))?;

// Queue backlog
        let queue_backlog: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM messages WHERE status = 'queued'",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| anyhow::anyhow!("reconciliation queue_backlog query failed: {e}"))?;

        let healthy = orphaned_count.0 < 100
            && event_lag.0.unwrap_or(0.0) < 300.0
            && queue_backlog.0 < 1000;

        Ok(serde_json::json!({
            "healthy": healthy,
            "orphaned_messages": orphaned_count.0,
            "avg_event_lag_seconds": event_lag.0.unwrap_or(0.0),
            "queue_backlog": queue_backlog.0,
            "checked_at": now.to_rfc3339(),
        }))
    }

/// Publish reconciliation alert via Redis pub/sub.
    async fn publish_alert(&self, discrepancies: &[DiscrepancyDetail]) -> anyhow::Result<()> {
        let mut conn = self.redis.get().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        let payload = serde_json::json!({
            "type": "reconciliation_alert",
            "count": discrepancies.len(),
            "sample": discrepancies.iter().take(10).collect::<Vec<_>>(),
            "timestamp": Utc::now().to_rfc3339(),
        });

        redis::cmd("PUBLISH")
            .arg("alerts:reconciliation")
            .arg(payload.to_string())
            .query_async::<()>(&mut *conn)
            .await?;

        warn!(
            "Published reconciliation alert for {} discrepancies",
            discrepancies.len()
        );
        Ok(())
    }
}

/// Check if an event chain is complete.
pub fn is_chain_complete(events: &[String]) -> bool {
    EXPECTED_CHAIN
        .iter()
        .all(|stage| events.iter().any(|e| e == stage))
}

/// Find missing events in a chain.
pub fn find_missing_events(events: &[String]) -> Vec<String> {
    EXPECTED_CHAIN
        .iter()
        .filter(|&&stage| !events.iter().any(|e| e == stage))
        .map(|s| s.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_chain_complete() {
        let events = vec!["queued".into(), "sent".into(), "delivered".into()];
        assert!(is_chain_complete(&events));
    }

    #[test]
    fn test_is_chain_incomplete() {
        let events = vec!["queued".into(), "sent".into()];
        assert!(!is_chain_complete(&events));
    }

    #[test]
    fn test_find_missing_events() {
        let events = vec!["queued".into()];
        let missing = find_missing_events(&events);
        assert_eq!(missing, vec!["sent", "delivered"]);
    }

    #[test]
    fn test_find_missing_events_none() {
        let events = vec!["queued".into(), "sent".into(), "delivered".into()];
        let missing = find_missing_events(&events);
        assert!(missing.is_empty());
    }

    #[test]
    fn test_extra_events_still_complete() {
        let events = vec![
            "queued".into(),
            "sent".into(),
            "delivered".into(),
            "opened".into(),
            "clicked".into(),
        ];
        assert!(is_chain_complete(&events));
    }

    #[test]
    fn test_expected_chain_order() {
        assert_eq!(EXPECTED_CHAIN, &["queued", "sent", "delivered"]);
    }
}
