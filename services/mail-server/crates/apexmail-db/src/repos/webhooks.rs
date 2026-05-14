//! Webhooks repository.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::Webhook;

/// Repository for webhook operations.
pub struct WebhooksRepo;

impl WebhooksRepo {
    /// Create a new webhook.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        url: &str,
        events: serde_json::Value,
        secret: &str,
    ) -> Result<Webhook, sqlx::Error> {
        sqlx::query_as::<_, Webhook>(
            "INSERT INTO webhooks (id, tenant_id, url, events, secret, status, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, 'active', NOW(), NOW()) \
             RETURNING id, tenant_id, url, events, secret, status, created_at, updated_at"
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(url)
        .bind(events)
        .bind(secret)
        .fetch_one(pool)
        .await
    }

    /// Find a webhook by ID.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Webhook>, sqlx::Error> {
        sqlx::query_as::<_, Webhook>(
            "SELECT id, tenant_id, url, events, secret, status, created_at, updated_at \
             FROM webhooks WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List webhooks for a tenant with pagination.
    /// #225:Added limit/offset parameters
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Webhook>, sqlx::Error> {
        let limit = limit.clamp(1, 100);
        let offset = offset.max(0);
        sqlx::query_as::<_, Webhook>(
            "SELECT id, tenant_id, url, events, secret, status, created_at, updated_at \
             FROM webhooks WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// List webhooks for a tenant using keyset (cursor-based) pagination.
    /// Uses `(created_at, id)` tuple comparison for stable, efficient pagination.
    pub async fn list_keyset(
        pool: &PgPool,
        tenant_id: Uuid,
        limit: i64,
        cursor_created_at: Option<DateTime<Utc>>,
        cursor_id: Option<Uuid>,
    ) -> Result<Vec<Webhook>, sqlx::Error> {
        let limit = limit.clamp(1, 200);
        let fetch_limit = limit + 1;
        match (cursor_created_at, cursor_id) {
            (Some(created_at), Some(id)) => {
                sqlx::query_as::<_, Webhook>(
                    "SELECT id, tenant_id, url, events, secret, status, created_at, updated_at \
                     FROM webhooks WHERE tenant_id = $1 AND (created_at, id) < ($2, $3) \
                     ORDER BY created_at DESC, id DESC LIMIT $4",
                )
                .bind(tenant_id)
                .bind(created_at)
                .bind(id)
                .bind(fetch_limit)
                .fetch_all(pool)
                .await
            }
            _ => {
                // First page — no cursor
                sqlx::query_as::<_, Webhook>(
                    "SELECT id, tenant_id, url, events, secret, status, created_at, updated_at \
                     FROM webhooks WHERE tenant_id = $1 \
                     ORDER BY created_at DESC, id DESC LIMIT $2",
                )
                .bind(tenant_id)
                .bind(fetch_limit)
                .fetch_all(pool)
                .await
            }
        }
    }

    /// Update a webhook.
    pub async fn update(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        url: &str,
        events: serde_json::Value,
        status: &str,
    ) -> Result<Option<Webhook>, sqlx::Error> {
        sqlx::query_as::<_, Webhook>(
            "UPDATE webhooks SET url = $1, events = $2, status = $3, updated_at = NOW() \
             WHERE id = $4 AND tenant_id = $5 RETURNING id, tenant_id, url, events, secret, status, created_at, updated_at",
        )
        .bind(url)
        .bind(events)
        .bind(status)
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Delete a webhook.
    pub async fn delete(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM webhooks WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .execute(pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// List all webhooks subscribed to a specific event type.
    pub async fn list_by_event_type(
        pool: &PgPool,
        tenant_id: Uuid,
        event_type: &str,
    ) -> Result<Vec<Webhook>, sqlx::Error> {
        sqlx::query_as::<_, Webhook>(
            "SELECT id, tenant_id, url, events, secret, status, created_at, updated_at \
             FROM webhooks WHERE tenant_id = $1 AND status = 'active' \
             AND events @> $2::jsonb ORDER BY created_at ASC",
        )
        .bind(tenant_id)
        .bind(serde_json::json!([event_type]))
        .fetch_all(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use crate::types::Webhook;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_webhook_mock() {
        let w = Webhook {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            url: "https://example.com/hooks".into(),
            events: serde_json::json!(["delivered", "bounced"]),
            secret: "whsec_abc123".into(),
            status: "active".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(w.status, "active");
        assert_eq!(w.events.as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_webhook_event_contains() {
        let events = serde_json::json!(["delivered", "bounced", "opened"]);
        let arr = events.as_array().unwrap();
        assert!(arr.iter().any(|v| v == "delivered"));
    }

    #[test]
    fn test_webhooks_repo_is_stateless() {
        let _repo = super::WebhooksRepo;
    }
}
