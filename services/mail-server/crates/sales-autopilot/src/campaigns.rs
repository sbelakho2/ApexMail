use chrono::Utc;
use parking_lot::RwLock;
use std::sync::Arc;
use uuid::Uuid;

use crate::types::{Campaign, CampaignStatus, SalesError};

/// In-memory campaign manager.
///
/// Mirrors the TypeScript drip-engine / campaign subsystem, exposing CRUD +
/// lifecycle operations. Recipients are tracked as a simple Vec of email
/// addresses per campaign for now.
#[derive(Debug, Clone)]
pub struct CampaignManager {
    campaigns: Arc<RwLock<Vec<Campaign>>>,
    /// campaign_id → list of recipient emails
    recipients: Arc<RwLock<std::collections::HashMap<Uuid, Vec<String>>>>,
    max_campaigns: usize,
}

impl CampaignManager {
    pub fn new(max_campaigns: usize) -> Self {
        Self {
            campaigns: Arc::new(RwLock::new(Vec::new())),
            recipients: Arc::new(RwLock::new(std::collections::HashMap::new())),
            max_campaigns,
        }
    }

    /// Create a campaign in Draft status.
    pub fn create_campaign(
        &self,
        name: String,
        template_id: String,
        audience: String,
    ) -> Result<Campaign, SalesError> {
        let store = self.campaigns.read();
        let active = store.iter().filter(|c| c.status == CampaignStatus::Active).count();
        if active >= self.max_campaigns {
            return Err(SalesError::MaxCampaignsReached(self.max_campaigns));
        }
        drop(store);

        let campaign = Campaign {
            id: Uuid::new_v4(),
            name,
            template_id,
            audience,
            status: CampaignStatus::Draft,
            sent: 0,
            opened: 0,
            clicked: 0,
            created_at: Utc::now(),
        };

        self.campaigns.write().push(campaign.clone());
        self.recipients.write().insert(campaign.id, Vec::new());
        Ok(campaign)
    }

    /// List all campaigns.
    pub fn list_campaigns(&self) -> Vec<Campaign> {
        self.campaigns.read().clone()
    }

    /// Transition a draft/paused campaign to Active.
    pub fn start_campaign(&self, id: Uuid) -> Result<Campaign, SalesError> {
        let mut store = self.campaigns.write();
        let c = store
            .iter_mut()
            .find(|c| c.id == id)
            .ok_or(SalesError::CampaignNotFound(id))?;
        match c.status {
            CampaignStatus::Draft | CampaignStatus::Paused => {
                c.status = CampaignStatus::Active;
                Ok(c.clone())
            }
            _ => Err(SalesError::InvalidInput(format!(
                "cannot start campaign in status {}",
                c.status
            ))),
        }
    }

    /// Pause an active campaign.
    pub fn pause_campaign(&self, id: Uuid) -> Result<Campaign, SalesError> {
        let mut store = self.campaigns.write();
        let c = store
            .iter_mut()
            .find(|c| c.id == id)
            .ok_or(SalesError::CampaignNotFound(id))?;
        if c.status != CampaignStatus::Active {
            return Err(SalesError::InvalidInput("campaign is not active".into()));
        }
        c.status = CampaignStatus::Paused;
        Ok(c.clone())
    }

    /// Return stats for a campaign (sent / opened / clicked / recipients).
    pub fn get_stats(&self, id: Uuid) -> Result<serde_json::Value, SalesError> {
        let store = self.campaigns.read();
        let c = store
            .iter()
            .find(|c| c.id == id)
            .ok_or(SalesError::CampaignNotFound(id))?;
        let recipient_count = self
            .recipients
            .read()
            .get(&id)
            .map_or(0, |r| r.len());
        Ok(serde_json::json!({
            "campaign_id": c.id,
            "status": c.status,
            "sent": c.sent,
            "opened": c.opened,
            "clicked": c.clicked,
            "recipients": recipient_count,
        }))
    }

    /// Add recipient emails to a campaign.
    pub fn add_recipients(
        &self,
        id: Uuid,
        emails: Vec<String>,
    ) -> Result<usize, SalesError> {
        // verify campaign exists
        if !self.campaigns.read().iter().any(|c| c.id == id) {
            return Err(SalesError::CampaignNotFound(id));
        }
        let mut map = self.recipients.write();
        let list = map.entry(id).or_default();
        let before = list.len();
        list.extend(emails);
        Ok(list.len() - before)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mgr() -> CampaignManager {
        CampaignManager::new(10)
    }

    #[test]
    fn test_create_and_list() {
        let mgr = make_mgr();
        let c = mgr
            .create_campaign("Welcome".into(), "tmpl_1".into(), "all_leads".into())
            .unwrap();
        assert_eq!(c.status, CampaignStatus::Draft);
        assert_eq!(mgr.list_campaigns().len(), 1);
    }

    #[test]
    fn test_start_pause_lifecycle() {
        let mgr = make_mgr();
        let c = mgr
            .create_campaign("Drip".into(), "tmpl_2".into(), "new_leads".into())
            .unwrap();
        let started = mgr.start_campaign(c.id).unwrap();
        assert_eq!(started.status, CampaignStatus::Active);

        let paused = mgr.pause_campaign(c.id).unwrap();
        assert_eq!(paused.status, CampaignStatus::Paused);

        // re-start after pause
        let restarted = mgr.start_campaign(c.id).unwrap();
        assert_eq!(restarted.status, CampaignStatus::Active);
    }

    #[test]
    fn test_max_campaigns_enforced() {
        let mgr = CampaignManager::new(1);
        let c = mgr
            .create_campaign("C1".into(), "t".into(), "a".into())
            .unwrap();
        mgr.start_campaign(c.id).unwrap();

        // second active campaign should be rejected
        let c2 = mgr.create_campaign("C2".into(), "t".into(), "a".into());
        assert!(c2.is_err());
    }

    #[test]
    fn test_recipients_and_stats() {
        let mgr = make_mgr();
        let c = mgr
            .create_campaign("Outreach".into(), "tmpl".into(), "saas".into())
            .unwrap();
        let added = mgr
            .add_recipients(c.id, vec!["a@x.com".into(), "b@x.com".into()])
            .unwrap();
        assert_eq!(added, 2);

        let stats = mgr.get_stats(c.id).unwrap();
        assert_eq!(stats["recipients"], 2);
        assert_eq!(stats["sent"], 0);
    }
}
