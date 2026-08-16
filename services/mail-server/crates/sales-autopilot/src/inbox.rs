use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::{InboxMessage, MessageCategory, SalesError};

/// Inbox monitoring / sentinel service backed by PostgreSQL.
/// Categorises inbound messages into Lead / Customer / Support / Spam / Other
/// using simple keyword heuristics (production would use an ML classifier).
#[derive(Debug, Clone)]
pub struct InboxManager {
    db: PgPool,
}

impl InboxManager {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Classify a message without persisting it.
    pub fn classify_message(tenant_id: String, from: String, subject: String) -> InboxMessage {
        let category = Self::classify(&subject, &from);
        InboxMessage {
            id: Uuid::new_v4(),
            tenant_id,
            from,
            subject,
            received_at: Utc::now(),
            category,
            replied: false,
        }
    }

    /// Classify and store a message, returning the assigned category.
    pub async fn categorize_message(
        &self,
        tenant_id: &str,
        from: String,
        subject: String,
    ) -> InboxMessage {
        let msg = Self::classify_message(tenant_id.to_string(), from, subject);

        let _ = sqlx::query(
            "INSERT INTO sales_inbox_messages (id, tenant_id, sender, subject, received_at, category, replied) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(msg.id)
        .bind(&msg.tenant_id)
        .bind(&msg.from)
        .bind(&msg.subject)
        .bind(msg.received_at)
        .bind(msg.category.to_string())
        .bind(msg.replied)
        .execute(&self.db)
        .await
        .inspect_err(|e| tracing::warn!(error = %e, "failed to persist inbox message"));

        msg
    }

    /// Heuristic classification.
    fn classify(subject: &str, from: &str) -> MessageCategory {
        let s = subject.to_lowercase();
        let f = from.to_lowercase();

        if s.contains("unsubscribe")
            || s.contains("viagra")
            || s.contains("lottery")
            || f.contains("noreply")
        {
            return MessageCategory::Spam;
        }
        if s.contains("support")
            || s.contains("help")
            || s.contains("ticket")
            || s.contains("issue")
        {
            return MessageCategory::Support;
        }
        if s.contains("invoice")
            || s.contains("payment")
            || s.contains("subscription")
            || s.contains("renewal")
        {
            return MessageCategory::Customer;
        }
        if s.contains("demo")
            || s.contains("pricing")
            || s.contains("interested")
            || s.contains("trial")
        {
            return MessageCategory::Lead;
        }
        MessageCategory::Other
    }

    /// List messages belonging to a given category, scoped to tenant.
    ///
    /// Returns `Err` on database failure — previously errors were logged and
    /// silently converted into an empty list.
    pub async fn list_by_category(
        &self,
        tenant_id: &str,
        cat: MessageCategory,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<InboxMessage>, SalesError> {
        let rows = sqlx::query_as::<_, InboxMessageRow>(
            "SELECT id, tenant_id, sender, subject, received_at, category, replied FROM sales_inbox_messages WHERE tenant_id = $1 AND category = $2 ORDER BY received_at DESC LIMIT $3 OFFSET $4",
        )
        .bind(tenant_id)
        .bind(cat.to_string())
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.into_message()).collect())
    }

    /// List all messages regardless of category, scoped to tenant.
    ///
    /// Returns `Err` on database failure — previously errors were logged and
    /// silently converted into an empty list.
    pub async fn list_all(
        &self,
        tenant_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<InboxMessage>, SalesError> {
        let rows = sqlx::query_as::<_, InboxMessageRow>(
            "SELECT id, tenant_id, sender, subject, received_at, category, replied FROM sales_inbox_messages WHERE tenant_id = $1 ORDER BY received_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.into_message()).collect())
    }

    /// Mark a message as replied (scoped to tenant).
    ///
    /// Returns `Err(SalesError::MessageNotFound)` when no matching message
    /// exists for this tenant, and `Err(SalesError::Database(..))` on
    /// database failure — previously both cases collapsed into a bare
    /// `false` that callers could not distinguish.
    pub async fn mark_replied(&self, tenant_id: &str, id: Uuid) -> Result<(), SalesError> {
        let result = sqlx::query(
            "UPDATE sales_inbox_messages SET replied = true WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .execute(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SalesError::MessageNotFound(id));
        }
        Ok(())
    }

    /// Return the reply rate (0.0–1.0) scoped to a tenant.
    pub async fn get_reply_rate(&self, tenant_id: &str) -> f64 {
        let counts: Result<(i64, i64), _> = sqlx::query_as::<_, (i64, i64)>(
            "SELECT COUNT(*), COALESCE(SUM(CASE WHEN replied THEN 1 ELSE 0 END), 0) FROM sales_inbox_messages WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_one(&self.db)
        .await;

        match counts {
            Ok((total, replied)) if total > 0 => replied as f64 / total as f64,
            _ => 0.0,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal row type for sqlx mapping
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct InboxMessageRow {
    id: Uuid,
    tenant_id: String,
    sender: String,
    subject: String,
    received_at: chrono::DateTime<chrono::Utc>,
    category: String,
    replied: bool,
}

impl InboxMessageRow {
    fn into_message(self) -> InboxMessage {
        InboxMessage {
            id: self.id,
            tenant_id: self.tenant_id,
            from: self.sender,
            subject: self.subject,
            received_at: self.received_at,
            category: MessageCategory::from_str(&self.category),
            replied: self.replied,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    async fn make_mgr() -> InboxManager {
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        InboxManager::new(db)
    }

    /// Integration test requiring local Postgres. Run with infrastructure.
    #[ignore]
    #[tokio::test]
    async fn test_categorization() {
        let mgr = make_mgr().await;
        let m1 = mgr
            .categorize_message(
                "tenant-1",
                "alice@x.com".into(),
                "Interested in a demo".into(),
            )
            .await;
        assert_eq!(m1.category, MessageCategory::Lead);

        let m2 = mgr
            .categorize_message(
                "tenant-1",
                "noreply@spam.biz".into(),
                "You won the lottery!".into(),
            )
            .await;
        assert_eq!(m2.category, MessageCategory::Spam);

        let m3 = mgr
            .categorize_message(
                "tenant-1",
                "bob@y.com".into(),
                "Support ticket #1234".into(),
            )
            .await;
        assert_eq!(m3.category, MessageCategory::Support);

        let m4 = mgr
            .categorize_message(
                "tenant-1",
                "billing@co.com".into(),
                "Invoice for subscription".into(),
            )
            .await;
        assert_eq!(m4.category, MessageCategory::Customer);
    }

    /// Integration test requiring local Postgres. Run with infrastructure.
    #[ignore]
    #[tokio::test]
    async fn test_list_by_category_and_mark_replied() {
        let mgr = make_mgr().await;
        let m = mgr
            .categorize_message("tenant-1", "a@b.com".into(), "Pricing inquiry".into())
            .await;
        assert_eq!(m.category, MessageCategory::Lead);

        let leads = mgr
            .list_by_category("tenant-1", MessageCategory::Lead, 100, 0)
            .await
            .unwrap();
        assert_eq!(leads.len(), 1);

        mgr.mark_replied("tenant-1", m.id).await.unwrap();
        assert!(mgr.mark_replied("tenant-1", Uuid::new_v4()).await.is_err()); // non-existent
    }

    /// Integration test requiring local Postgres. Run with infrastructure.
    #[ignore]
    #[tokio::test]
    async fn test_reply_rate() {
        let mgr = make_mgr().await;
        assert_eq!(mgr.get_reply_rate("tenant-1").await, 0.0);

        let m1 = mgr
            .categorize_message("tenant-1", "a@b.com".into(), "Hello".into())
            .await;
        let _m2 = mgr
            .categorize_message("tenant-1", "c@d.com".into(), "World".into())
            .await;
        mgr.mark_replied("tenant-1", m1.id).await.unwrap();

        let rate = mgr.get_reply_rate("tenant-1").await;
        assert!((rate - 0.5).abs() < f64::EPSILON);
    }
}
