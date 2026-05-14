//! Events repository.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::Event;

/// Aggregate row for event-type counts.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EventTypeCount {
    pub event_type: String,
    pub count: i64,
}

/// Repository for event operations.
pub struct EventsRepo;

impl EventsRepo {
    /// Create a new event.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        message_id: Option<Uuid>,
        event_type: &str,
        recipient: Option<&str>,
        metadata: Option<serde_json::Value>,
    ) -> Result<Event, sqlx::Error> {
        sqlx::query_as::<_, Event>(
            "INSERT INTO events (id, tenant_id, message_id, event_type, recipient, metadata, timestamp) \
             VALUES ($1, $2, $3, $4, $5, $6, NOW()) \
             RETURNING id, tenant_id, message_id, event_type, recipient, metadata, timestamp"
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(message_id)
        .bind(event_type)
        .bind(recipient)
        .bind(metadata)
        .fetch_one(pool)
        .await
    }

    /// List events for a specific message.
    pub async fn list_by_message(
        pool: &PgPool,
        tenant_id: Uuid,
        message_id: Uuid,
    ) -> Result<Vec<Event>, sqlx::Error> {
        sqlx::query_as::<_, Event>(
            "SELECT id, tenant_id, message_id, event_type, recipient, metadata, timestamp \
             FROM events WHERE tenant_id = $1 AND message_id = $2 ORDER BY timestamp ASC",
        )
        .bind(tenant_id)
        .bind(message_id)
        .fetch_all(pool)
        .await
    }

    /// List events for a tenant with pagination.
    pub async fn list_by_tenant(
        pool: &PgPool,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Event>, sqlx::Error> {
        let limit = limit.clamp(1, 200);
        let offset = offset.clamp(0, 100_000);
        sqlx::query_as::<_, Event>(
            "SELECT id, tenant_id, message_id, event_type, recipient, metadata, timestamp \
             FROM events WHERE tenant_id = $1 ORDER BY timestamp DESC LIMIT $2 OFFSET $3",
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// List events for a tenant using keyset (cursor-based) pagination.
    /// Uses `(timestamp, id)` tuple comparison since the events table uses `timestamp` (not `created_at`).
    pub async fn list_keyset_by_tenant(
        pool: &PgPool,
        tenant_id: Uuid,
        limit: i64,
        cursor_timestamp: Option<DateTime<Utc>>,
        cursor_id: Option<Uuid>,
    ) -> Result<Vec<Event>, sqlx::Error> {
        let limit = limit.clamp(1, 200);
        let fetch_limit = limit + 1;
        match (cursor_timestamp, cursor_id) {
            (Some(ts), Some(id)) => {
                sqlx::query_as::<_, Event>(
                    "SELECT id, tenant_id, message_id, event_type, recipient, metadata, timestamp \
                     FROM events WHERE tenant_id = $1 AND (timestamp, id) < ($2, $3) \
                     ORDER BY timestamp DESC, id DESC LIMIT $4",
                )
                .bind(tenant_id)
                .bind(ts)
                .bind(id)
                .bind(fetch_limit)
                .fetch_all(pool)
                .await
            }
            _ => {
                // First page — no cursor
                sqlx::query_as::<_, Event>(
                    "SELECT id, tenant_id, message_id, event_type, recipient, metadata, timestamp \
                     FROM events WHERE tenant_id = $1 \
                     ORDER BY timestamp DESC, id DESC LIMIT $2",
                )
                .bind(tenant_id)
                .bind(fetch_limit)
                .fetch_all(pool)
                .await
            }
        }
    }

    /// Count events by type for a tenant within a time window.
    /// #222:Added time bound to prevent expensive full table scans
    pub async fn count_by_type(
        pool: &PgPool,
        tenant_id: Uuid,
        since_hours: i32,
    ) -> Result<Vec<EventTypeCount>, sqlx::Error> {
        let since_hours = since_hours.clamp(1, 8760); // Max 1 year
        sqlx::query_as::<_, EventTypeCount>(
            "SELECT event_type, COUNT(*) as count \
             FROM events WHERE tenant_id = $1 AND timestamp > NOW() - make_interval(hours => $2) \
             GROUP BY event_type ORDER BY count DESC",
        )
        .bind(tenant_id)
        .bind(since_hours)
        .fetch_all(pool)
        .await
    }

    /// Event type stats with time window.
    pub async fn stats_by_type(
        pool: &PgPool,
        tenant_id: Uuid,
        since_hours: i32,
    ) -> Result<Vec<EventTypeCount>, sqlx::Error> {
        sqlx::query_as::<_, EventTypeCount>(
            "SELECT event_type, COUNT(*) as count \
             FROM events WHERE tenant_id = $1 AND timestamp > NOW() - make_interval(hours => $2) \
             GROUP BY event_type ORDER BY count DESC",
        )
        .bind(tenant_id)
        .bind(since_hours)
        .fetch_all(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use crate::types::Event;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_event_mock() {
        let e = Event {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            message_id: Some(Uuid::new_v4()),
            event_type: "delivered".into(),
            recipient: Some("user@example.com".into()),
            metadata: Some(serde_json::json!({"smtp_code": 250})),
            timestamp: Utc::now(),
        };
        assert_eq!(e.event_type, "delivered");
        assert!(e.recipient.is_some());
    }

    #[test]
    fn test_event_type_count() {
        let c = super::EventTypeCount {
            event_type: "opened".into(),
            count: 42,
        };
        assert_eq!(c.count, 42);
    }

    #[test]
    fn test_event_without_message() {
        let e = Event {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            message_id: None,
            event_type: "complaint".into(),
            recipient: Some("spam@test.com".into()),
            metadata: None,
            timestamp: Utc::now(),
        };
        assert!(e.message_id.is_none());
    }
}
