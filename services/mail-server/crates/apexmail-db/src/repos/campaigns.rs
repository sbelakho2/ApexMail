//! Campaigns repository.

use sqlx::PgPool;
use uuid::Uuid;

use crate::types::Campaign;

/// Repository for campaign operations.
pub struct CampaignsRepo;

impl CampaignsRepo {
/// Create a new campaign.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        name: &str,
        subject: &str,
        template_id: Option<Uuid>,
        scheduled_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Campaign, sqlx::Error> {
        sqlx::query_as::<_, Campaign>(
            "INSERT INTO campaigns \
             (id, tenant_id, name, subject, template_id, status, scheduled_at, sent_count, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, 'draft', $6, 0, NOW(), NOW()) \
             RETURNING *"
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(name)
        .bind(subject)
        .bind(template_id)
        .bind(scheduled_at)
        .fetch_one(pool)
        .await
    }

/// Find a campaign by ID.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Campaign>, sqlx::Error> {
        sqlx::query_as::<_, Campaign>(
            "SELECT * FROM campaigns WHERE id = $1 AND tenant_id = $2"
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

/// List campaigns for a tenant.
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Campaign>, sqlx::Error> {
        sqlx::query_as::<_, Campaign>(
            "SELECT * FROM campaigns WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

/// Update campaign status (draft → sending → sent, etc.).
    pub async fn update_status(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        status: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE campaigns SET status = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3"
        )
        .bind(status)
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

/// Delete a campaign (only allowed in draft status).
    pub async fn delete(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM campaigns WHERE id = $1 AND tenant_id = $2 AND status = 'draft'"
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use crate::types::Campaign;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_campaign_mock() {
        let c = Campaign {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Black Friday Sale".into(),
            subject: "50% off everything!".into(),
            template_id: Some(Uuid::new_v4()),
            status: "draft".into(),
            scheduled_at: None,
            sent_count: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(c.status, "draft");
        assert_eq!(c.sent_count, 0);
    }

    #[test]
    fn test_campaign_sent() {
        let c = Campaign {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Newsletter".into(),
            subject: "Weekly digest".into(),
            template_id: None,
            status: "sent".into(),
            scheduled_at: Some(Utc::now()),
            sent_count: 1500,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(c.status, "sent");
        assert!(c.sent_count > 0);
    }

    #[test]
    fn test_campaigns_repo_is_stateless() {
        let _repo = super::CampaignsRepo;
    }
}
