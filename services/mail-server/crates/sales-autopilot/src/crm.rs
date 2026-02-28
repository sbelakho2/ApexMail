use chrono::Utc;
use parking_lot::RwLock;
use std::sync::Arc;
use uuid::Uuid;

use crate::types::{Lead, LeadStatus, SalesError};

/// In-memory CRM service backed by an `RwLock<Vec<Lead>>`.
///
/// Production workloads persist to Postgres (via `sqlx`); this in-memory
/// implementation keeps the crate self-contained for testing.
#[derive(Debug, Clone)]
pub struct CrmService {
    leads: Arc<RwLock<Vec<Lead>>>,
}

impl Default for CrmService {
    fn default() -> Self {
        Self::new()
    }
}

impl CrmService {
    pub fn new() -> Self {
        Self {
            leads: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Insert a new lead and return its assigned id.
    pub fn create_lead(
        &self,
        email: String,
        name: String,
        company: String,
        title: String,
        source: String,
    ) -> Lead {
        let lead = Lead {
            id: Uuid::new_v4(),
            email,
            name,
            company,
            title,
            score: 0,
            source,
            status: LeadStatus::New,
            created_at: Utc::now(),
        };
        self.leads.write().push(lead.clone());
        lead
    }

    /// Retrieve a lead by id.
    pub fn get_lead(&self, id: Uuid) -> Result<Lead, SalesError> {
        self.leads
            .read()
            .iter()
            .find(|l| l.id == id)
            .cloned()
            .ok_or(SalesError::LeadNotFound(id))
    }

    /// List leads, optionally filtering by status and/or source.
    pub fn list_leads(
        &self,
        status: Option<LeadStatus>,
        source: Option<&str>,
    ) -> Vec<Lead> {
        self.leads
            .read()
            .iter()
            .filter(|l| status.map_or(true, |s| l.status == s))
            .filter(|l| source.map_or(true, |src| l.source == src))
            .cloned()
            .collect()
    }

    /// Transition a lead to a new status.
    pub fn update_lead_status(
        &self,
        id: Uuid,
        new_status: LeadStatus,
    ) -> Result<Lead, SalesError> {
        let mut store = self.leads.write();
        let lead = store
            .iter_mut()
            .find(|l| l.id == id)
            .ok_or(SalesError::LeadNotFound(id))?;
        lead.status = new_status;
        Ok(lead.clone())
    }

    /// Compute a deterministic lead score (0–100) from three normalised
    /// dimensions: email engagement, company size tier, and recency.
    ///
    /// Each input should be in `0.0..=1.0`.
    pub fn score_lead(
        email_engagement: f64,
        company_size: f64,
        recency: f64,
    ) -> u8 {
        let raw =
            email_engagement.clamp(0.0, 1.0) * 40.0
            + company_size.clamp(0.0, 1.0) * 30.0
            + recency.clamp(0.0, 1.0) * 30.0;
        (raw.round() as u8).min(100)
    }

    /// Full-text search over lead name, email, and company.
    pub fn search_leads(&self, query: &str) -> Vec<Lead> {
        let q = query.to_lowercase();
        self.leads
            .read()
            .iter()
            .filter(|l| {
                l.name.to_lowercase().contains(&q)
                    || l.email.to_lowercase().contains(&q)
                    || l.company.to_lowercase().contains(&q)
            })
            .cloned()
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_svc() -> CrmService {
        let svc = CrmService::new();
        svc.create_lead(
            "alice@acme.com".into(),
            "Alice".into(),
            "Acme".into(),
            "CTO".into(),
            "product_hunt".into(),
        );
        svc.create_lead(
            "bob@beta.io".into(),
            "Bob".into(),
            "Beta".into(),
            "CEO".into(),
            "manual".into(),
        );
        svc
    }

    #[test]
    fn test_create_and_get_lead() {
        let svc = make_svc();
        let leads = svc.list_leads(None, None);
        assert_eq!(leads.len(), 2);
        let first = &leads[0];
        let fetched = svc.get_lead(first.id).unwrap();
        assert_eq!(fetched.email, first.email);
    }

    #[test]
    fn test_update_lead_status() {
        let svc = make_svc();
        let leads = svc.list_leads(None, None);
        let id = leads[0].id;
        let updated = svc.update_lead_status(id, LeadStatus::Contacted).unwrap();
        assert_eq!(updated.status, LeadStatus::Contacted);

        // missing lead
        let res = svc.update_lead_status(Uuid::new_v4(), LeadStatus::Lost);
        assert!(res.is_err());
    }

    #[test]
    fn test_score_lead() {
        assert_eq!(CrmService::score_lead(1.0, 1.0, 1.0), 100);
        assert_eq!(CrmService::score_lead(0.0, 0.0, 0.0), 0);
        assert_eq!(CrmService::score_lead(0.5, 0.5, 0.5), 50);
        // clamping
        assert_eq!(CrmService::score_lead(2.0, 2.0, 2.0), 100);
    }

    #[test]
    fn test_search_and_filter() {
        let svc = make_svc();

        // search
        let results = svc.search_leads("alice");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Alice");

        // filter by source
        let manual = svc.list_leads(None, Some("manual"));
        assert_eq!(manual.len(), 1);
        assert_eq!(manual[0].name, "Bob");

        // filter by status — both are New
        let new_leads = svc.list_leads(Some(LeadStatus::New), None);
        assert_eq!(new_leads.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Additional comprehensive tests for all code paths
    // -----------------------------------------------------------------------

    #[test]
    fn default_creates_empty_service() {
        let svc = CrmService::default();
        assert!(svc.list_leads(None, None).is_empty());
    }

    #[test]
    fn create_lead_returns_new_status_and_zero_score() {
        let svc = CrmService::new();
        let lead = svc.create_lead(
            "t@t.com".into(), "T".into(), "C".into(), "E".into(), "src".into(),
        );
        assert_eq!(lead.status, LeadStatus::New);
        assert_eq!(lead.score, 0);
    }

    #[test]
    fn create_lead_unique_ids() {
        let svc = CrmService::new();
        let a = svc.create_lead("a@a.com".into(), "A".into(), "".into(), "".into(), "".into());
        let b = svc.create_lead("b@b.com".into(), "B".into(), "".into(), "".into(), "".into());
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn get_lead_missing_returns_error() {
        let svc = CrmService::new();
        match svc.get_lead(Uuid::new_v4()) {
            Err(SalesError::LeadNotFound(_)) => {}
            other => panic!("Expected LeadNotFound, got {:?}", other),
        }
    }

    #[test]
    fn update_status_all_transitions() {
        let svc = CrmService::new();
        let lead = svc.create_lead("x@x.com".into(), "X".into(), "".into(), "".into(), "".into());
        let id = lead.id;

        for status in [
            LeadStatus::Contacted,
            LeadStatus::Qualified,
            LeadStatus::Converted,
            LeadStatus::Lost,
            LeadStatus::New, // back to New
        ] {
            let updated = svc.update_lead_status(id, status).unwrap();
            assert_eq!(updated.status, status);
        }
    }

    #[test]
    fn search_is_case_insensitive() {
        let svc = CrmService::new();
        svc.create_lead("UPPER@TEST.COM".into(), "LOUD".into(), "BIG".into(), "".into(), "".into());
        assert_eq!(svc.search_leads("upper").len(), 1);
        assert_eq!(svc.search_leads("UPPER").len(), 1);
        assert_eq!(svc.search_leads("loud").len(), 1);
        assert_eq!(svc.search_leads("big").len(), 1);
    }

    #[test]
    fn search_empty_query_returns_all() {
        let svc = make_svc();
        assert_eq!(svc.search_leads("").len(), 2);
    }

    #[test]
    fn search_no_match_returns_empty() {
        let svc = make_svc();
        assert!(svc.search_leads("zzz_nonexistent").is_empty());
    }

    #[test]
    fn filter_by_status_and_source_combined() {
        let svc = make_svc();
        let leads = svc.list_leads(Some(LeadStatus::New), Some("product_hunt"));
        assert_eq!(leads.len(), 1);
        assert_eq!(leads[0].name, "Alice");
    }

    #[test]
    fn filter_by_nonexistent_source() {
        let svc = make_svc();
        assert!(svc.list_leads(None, Some("zzz")).is_empty());
    }

    #[test]
    fn filter_by_status_after_update() {
        let svc = make_svc();
        let id = svc.list_leads(None, None)[0].id;
        svc.update_lead_status(id, LeadStatus::Qualified).unwrap();
        let qualified = svc.list_leads(Some(LeadStatus::Qualified), None);
        assert_eq!(qualified.len(), 1);
        let still_new = svc.list_leads(Some(LeadStatus::New), None);
        assert_eq!(still_new.len(), 1); // only Bob
    }

    #[test]
    fn score_lead_boundary_values() {
        // Exact boundaries
        assert_eq!(CrmService::score_lead(0.0, 0.0, 0.0), 0);
        assert_eq!(CrmService::score_lead(1.0, 1.0, 1.0), 100);
        
        // Negative inputs clamped to 0
        assert_eq!(CrmService::score_lead(-1.0, -1.0, -1.0), 0);
        
        // Only engagement
        assert_eq!(CrmService::score_lead(1.0, 0.0, 0.0), 40);
        
        // Only company size
        assert_eq!(CrmService::score_lead(0.0, 1.0, 0.0), 30);
        
        // Only recency
        assert_eq!(CrmService::score_lead(0.0, 0.0, 1.0), 30);
    }

    #[test]
    fn score_lead_fractional() {
        // 0.25 * 40 + 0.75 * 30 + 0.5 * 30 = 10 + 22.5 + 15 = 47.5 → 48
        assert_eq!(CrmService::score_lead(0.25, 0.75, 0.5), 48);
    }

    #[test]
    fn clone_service_shares_state() {
        let svc = CrmService::new();
        let svc2 = svc.clone();
        svc.create_lead("a@a.com".into(), "A".into(), "".into(), "".into(), "".into());
        assert_eq!(svc2.list_leads(None, None).len(), 1);
    }

    #[test]
    fn search_matches_company_field() {
        let svc = CrmService::new();
        svc.create_lead("x@x.com".into(), "X".into(), "Unique Corp".into(), "".into(), "".into());
        assert_eq!(svc.search_leads("unique corp").len(), 1);
    }

    #[test]
    fn search_matches_email_field() {
        let svc = CrmService::new();
        svc.create_lead("special@domain.com".into(), "N".into(), "C".into(), "".into(), "".into());
        assert_eq!(svc.search_leads("special@domain").len(), 1);
    }
}
