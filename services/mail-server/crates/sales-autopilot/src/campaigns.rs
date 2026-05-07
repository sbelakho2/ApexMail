use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::{Campaign, CampaignStatus, SalesError};

/// PostgreSQL-backed campaign manager.
/// Campaigns and recipients are persisted across restarts.
#[derive(Debug, Clone)]
pub struct CampaignManager {
    db: PgPool,
    max_campaigns: usize,
}

impl CampaignManager {
    pub fn new(max_campaigns: usize, db: PgPool) -> Self {
        Self { db, max_campaigns }
    }

    /// Create a campaign in Draft status.
    pub async fn create_campaign(
        &self,
        tenant_id: String,
        name: String,
        template_id: String,
        audience: String,
    ) -> Result<Campaign, SalesError> {
        let active_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_campaigns WHERE tenant_id = $1 AND status = 'active'",
        )
        .bind(&tenant_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        if active_count >= self.max_campaigns as i64 {
            return Err(SalesError::MaxCampaignsReached(self.max_campaigns));
        }

        let campaign = Campaign {
            id: Uuid::new_v4(),
            tenant_id,
            name,
            template_id,
            audience,
            status: CampaignStatus::Draft,
            sent: 0,
            opened: 0,
            clicked: 0,
            created_at: Utc::now(),
        };

        sqlx::query(
            "INSERT INTO sales_campaigns (id, tenant_id, name, template_id, audience, status, sent, opened, clicked, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(campaign.id)
        .bind(&campaign.tenant_id)
        .bind(&campaign.name)
        .bind(&campaign.template_id)
        .bind(&campaign.audience)
        .bind(campaign.status.to_string())
        .bind(campaign.sent as i64)
        .bind(campaign.opened as i64)
        .bind(campaign.clicked as i64)
        .bind(campaign.created_at)
        .execute(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        Ok(campaign)
    }

    /// List all campaigns for a tenant.
    pub async fn list_campaigns(&self, tenant_id: &str, limit: i64, offset: i64) -> Vec<Campaign> {
        let rows = sqlx::query_as::<_, CampaignRow>(
            "SELECT id, tenant_id, name, template_id, audience, status, sent, opened, clicked, created_at FROM sales_campaigns WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await;

        match rows {
            Ok(rows) => rows
                .into_iter()
                .filter_map(|r| r.into_campaign().ok())
                .collect(),
            Err(e) => {
                tracing::warn!(error = %e, "failed to list campaigns");
                Vec::new()
            }
        }
    }

    /// Transition a draft/paused campaign to Active.
    pub async fn start_campaign(&self, tenant_id: &str, id: Uuid) -> Result<Campaign, SalesError> {
        let row: Option<CampaignRow> = sqlx::query_as(
            "SELECT id, tenant_id, name, template_id, audience, status, sent, opened, clicked, created_at FROM sales_campaigns WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        let campaign = row
            .and_then(|r| r.into_campaign().ok())
            .ok_or(SalesError::CampaignNotFound(id))?;

        match campaign.status {
            CampaignStatus::Draft | CampaignStatus::Paused => {
                sqlx::query("UPDATE sales_campaigns SET status = 'active' WHERE id = $1")
                    .bind(id)
                    .execute(&self.db)
                    .await
                    .map_err(|e| SalesError::Database(e.to_string()))?;
                let mut updated = campaign;
                updated.status = CampaignStatus::Active;
                Ok(updated)
            }
            _ => Err(SalesError::InvalidInput(format!(
                "cannot start campaign in status {}",
                campaign.status
            ))),
        }
    }

    /// Pause an active campaign.
    pub async fn pause_campaign(&self, tenant_id: &str, id: Uuid) -> Result<Campaign, SalesError> {
        let row: Option<CampaignRow> = sqlx::query_as(
            "SELECT id, tenant_id, name, template_id, audience, status, sent, opened, clicked, created_at FROM sales_campaigns WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        let campaign = row
            .and_then(|r| r.into_campaign().ok())
            .ok_or(SalesError::CampaignNotFound(id))?;

        if campaign.status != CampaignStatus::Active {
            return Err(SalesError::InvalidInput("campaign is not active".into()));
        }

        sqlx::query("UPDATE sales_campaigns SET status = 'paused' WHERE id = $1")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        let mut updated = campaign;
        updated.status = CampaignStatus::Paused;
        Ok(updated)
    }

    /// Return stats for a campaign (sent / opened / clicked / recipients).
    /// Requires `tenant_id` to enforce tenant isolation — returns
    /// `CampaignNotFound` if the campaign does not belong to this tenant.
    pub async fn get_stats(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<serde_json::Value, SalesError> {
        let row: Option<CampaignRow> = sqlx::query_as(
            "SELECT id, tenant_id, name, template_id, audience, status, sent, opened, clicked, created_at FROM sales_campaigns WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        let c = row
            .and_then(|r| r.into_campaign().ok())
            .ok_or(SalesError::CampaignNotFound(id))?;

        let recipient_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_campaign_recipients r \
             JOIN sales_campaigns c ON r.campaign_id = c.id \
             WHERE r.campaign_id = $1 AND c.tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        Ok(serde_json::json!({
            "campaign_id": c.id,
            "tenant_id": c.tenant_id,
            "status": c.status,
            "sent": c.sent,
            "opened": c.opened,
            "clicked": c.clicked,
            "recipients": recipient_count,
        }))
    }

    /// Add recipient emails to a campaign. Deduplicates against existing entries.
    pub async fn add_recipients(
        &self,
        tenant_id: &str,
        id: Uuid,
        emails: Vec<String>,
    ) -> Result<usize, SalesError> {
        // Verify campaign exists and belongs to tenant
        let exists: bool = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sales_campaigns WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?
            > 0;

        if !exists {
            return Err(SalesError::CampaignNotFound(id));
        }

        let mut added = 0usize;
        for email in emails {
            let normalized = email.trim().to_ascii_lowercase();
            if normalized.is_empty() {
                continue;
            }
            let result = sqlx::query(
                "INSERT INTO sales_campaign_recipients (campaign_id, email) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            )
            .bind(id)
            .bind(&normalized)
            .execute(&self.db)
            .await;

            if let Ok(res) = result {
                if res.rows_affected() > 0 {
                    added += 1;
                }
            }
        }

        Ok(added)
    }
}

// ---------------------------------------------------------------------------
// Internal row type for sqlx mapping
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct CampaignRow {
    id: Uuid,
    tenant_id: String,
    name: String,
    template_id: String,
    audience: String,
    status: String,
    sent: i64,
    opened: i64,
    clicked: i64,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl CampaignRow {
    fn into_campaign(self) -> Result<Campaign, SalesError> {
        let status = match self.status.as_str() {
            "draft" => CampaignStatus::Draft,
            "active" => CampaignStatus::Active,
            "paused" => CampaignStatus::Paused,
            "completed" => CampaignStatus::Completed,
            other => {
                return Err(SalesError::Internal(anyhow::anyhow!(
                    "unknown campaign status: {other}"
                )));
            }
        };
        Ok(Campaign {
            id: self.id,
            tenant_id: self.tenant_id,
            name: self.name,
            template_id: self.template_id,
            audience: self.audience,
            status,
            sent: self.sent as u64,
            opened: self.opened as u64,
            clicked: self.clicked as u64,
            created_at: self.created_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create an in-memory SQLite-like manager backed by a
    /// `connect_lazy` pool. Tests using this will not persist data
    /// between test functions.
    async fn make_mgr() -> CampaignManager {
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        CampaignManager::new(10, db)
    }

    /// Integration test requiring local Postgres. Run with infrastructure.
    #[ignore]
    #[tokio::test]
    async fn test_create_and_list() {
        let mgr = make_mgr().await;
        let c = mgr
            .create_campaign(
                "tenant-a".into(),
                "Welcome".into(),
                "tmpl_1".into(),
                "all_leads".into(),
            )
            .await
            .unwrap();
        assert_eq!(c.status, CampaignStatus::Draft);
        let list = mgr.list_campaigns("tenant-a", 100, 0).await;
        assert!(!list.is_empty());
        assert!(mgr.list_campaigns("tenant-b", 100, 0).await.is_empty());
    }

    /// Integration test requiring local Postgres. Run with infrastructure.
    #[ignore]
    #[tokio::test]
    async fn test_start_pause_lifecycle() {
        let mgr = make_mgr().await;
        let c = mgr
            .create_campaign(
                "tenant-a".into(),
                "Drip".into(),
                "tmpl_2".into(),
                "new_leads".into(),
            )
            .await
            .unwrap();
        let started = mgr.start_campaign("tenant-a", c.id).await.unwrap();
        assert_eq!(started.status, CampaignStatus::Active);

        let paused = mgr.pause_campaign("tenant-a", c.id).await.unwrap();
        assert_eq!(paused.status, CampaignStatus::Paused);

        // re-start after pause
        let restarted = mgr.start_campaign("tenant-a", c.id).await.unwrap();
        assert_eq!(restarted.status, CampaignStatus::Active);
    }

    /// Integration test requiring local Postgres. Run with infrastructure.
    #[ignore]
    #[tokio::test]
    async fn test_max_campaigns_enforced() {
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let mgr = CampaignManager::new(1, db);
        let c = mgr
            .create_campaign("tenant-a".into(), "C1".into(), "t".into(), "a".into())
            .await
            .unwrap();
        mgr.start_campaign("tenant-a", c.id).await.unwrap();

        // second active campaign should be rejected
        let c2 = mgr
            .create_campaign("tenant-a".into(), "C2".into(), "t".into(), "a".into())
            .await;
        assert!(c2.is_err());
    }

    /// Integration test requiring local Postgres. Run with infrastructure.
    #[ignore]
    #[tokio::test]
    async fn test_recipients_and_stats() {
        let mgr = make_mgr().await;
        let c = mgr
            .create_campaign(
                "tenant-a".into(),
                "Outreach".into(),
                "tmpl".into(),
                "saas".into(),
            )
            .await
            .unwrap();
        let added = mgr
            .add_recipients("tenant-a", c.id, vec!["a@x.com".into(), "b@x.com".into()])
            .await
            .unwrap();
        assert_eq!(added, 2);

        let stats = mgr.get_stats("tenant-a", c.id).await.unwrap();
        assert_eq!(stats["recipients"], 2);
        assert_eq!(stats["sent"], 0);
    }

    /// Integration test requiring local Postgres. Run with infrastructure.
    #[ignore]
    #[tokio::test]
    async fn test_campaign_operations_are_tenant_scoped() {
        let mgr = make_mgr().await;
        let campaign = mgr
            .create_campaign(
                "tenant-a".into(),
                "Scoped".into(),
                "tmpl".into(),
                "all".into(),
            )
            .await
            .unwrap();

        assert!(matches!(
            mgr.start_campaign("tenant-b", campaign.id).await,
            Err(SalesError::CampaignNotFound(id)) if id == campaign.id
        ));
        assert!(matches!(
            mgr.add_recipients("tenant-b", campaign.id, vec!["user@example.com".into()]).await,
            Err(SalesError::CampaignNotFound(id)) if id == campaign.id
        ));
    }

    /// Integration test requiring local Postgres. Run with infrastructure.
    #[ignore]
    #[tokio::test]
    async fn test_add_recipients_deduplicates_addresses() {
        let mgr = make_mgr().await;
        let campaign = mgr
            .create_campaign(
                "tenant-a".into(),
                "Scoped".into(),
                "tmpl".into(),
                "all".into(),
            )
            .await
            .unwrap();

        let added = mgr
            .add_recipients(
                "tenant-a",
                campaign.id,
                vec![
                    "alice@example.com".into(),
                    " ALICE@example.com ".into(),
                    "bob@example.com".into(),
                ],
            )
            .await
            .unwrap();

        assert_eq!(added, 2);
        let stats = mgr.get_stats("tenant-a", campaign.id).await.unwrap();
        assert_eq!(stats["recipients"], 2);
    }
}
