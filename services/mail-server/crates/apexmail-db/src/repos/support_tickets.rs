//! Support tickets repository.

use sqlx::PgPool;
use uuid::Uuid;

use crate::types::SupportTicket;

/// Repository for support ticket operations.
pub struct SupportTicketsRepo;

impl SupportTicketsRepo {
/// Create a new support ticket.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        subject: &str,
        description: &str,
        priority: &str,
    ) -> Result<SupportTicket, sqlx::Error> {
        sqlx::query_as::<_, SupportTicket>(
            "INSERT INTO support_tickets \
             (id, tenant_id, subject, description, priority, status, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, 'open', NOW(), NOW()) \
             RETURNING *"
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(subject)
        .bind(description)
        .bind(priority)
        .fetch_one(pool)
        .await
    }

/// Find a support ticket by ID.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<SupportTicket>, sqlx::Error> {
        sqlx::query_as::<_, SupportTicket>(
            "SELECT * FROM support_tickets WHERE id = $1 AND tenant_id = $2"
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

/// List support tickets for a tenant.
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SupportTicket>, sqlx::Error> {
        sqlx::query_as::<_, SupportTicket>(
            "SELECT * FROM support_tickets WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

/// Update support ticket status.
    pub async fn update_status(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        status: &str,
        assigned_to: Option<Uuid>,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE support_tickets SET status = $1, assigned_to = $2, updated_at = NOW() \
             WHERE id = $3 AND tenant_id = $4"
        )
        .bind(status)
        .bind(assigned_to)
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use crate::types::SupportTicket;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_ticket_mock() {
        let t = SupportTicket {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            subject: "Cannot send emails".into(),
            description: "Getting 403 errors on send endpoint".into(),
            priority: "high".into(),
            status: "open".into(),
            assigned_to: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(t.priority, "high");
        assert_eq!(t.status, "open");
    }

    #[test]
    fn test_ticket_assigned() {
        let agent = Uuid::new_v4();
        let t = SupportTicket {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            subject: "Billing question".into(),
            description: "Need invoice".into(),
            priority: "low".into(),
            status: "in_progress".into(),
            assigned_to: Some(agent),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(t.assigned_to.unwrap(), agent);
    }

    #[test]
    fn test_support_tickets_repo_is_stateless() {
        let _repo = super::SupportTicketsRepo;
    }
}
