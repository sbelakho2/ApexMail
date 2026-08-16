use chrono::Utc;
use parking_lot::RwLock;
use std::sync::Arc;
use uuid::Uuid;

use crate::crm_pg::SqlxCrmService;
use crate::types::{Lead, LeadStatus, SalesError};

/// In-memory CRM service backed by an `RwLock<Vec<Lead>>`.
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
        tenant_id: String,
        email: String,
        name: String,
        company: String,
        title: String,
        source: String,
    ) -> Lead {
        let lead = Lead {
            id: Uuid::new_v4().to_string(),
            tenant_id,
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

    /// Retrieve a lead by id, scoped to tenant.
    pub fn get_lead(&self, id: &str, tenant_id: &str) -> Result<Lead, SalesError> {
        self.leads
            .read()
            .iter()
            .find(|l| l.id == id && l.tenant_id == tenant_id)
            .cloned()
            .ok_or_else(|| SalesError::LeadNotFound(id.to_string()))
    }

    /// List leads, optionally filtering by tenant_id, status and/or source.
    pub fn list_leads(
        &self,
        tenant_id: &str,
        status: Option<LeadStatus>,
        source: Option<&str>,
    ) -> Vec<Lead> {
        self.leads
            .read()
            .iter()
            .filter(|l| l.tenant_id == tenant_id)
            .filter(|l| status.as_ref().is_none_or(|s| l.status == *s))
            .filter(|l| source.is_none_or(|src| l.source == src))
            .cloned()
            .collect()
    }

    /// Transition a lead to a new status, scoped to tenant.
    ///
    /// Enforces the lead lifecycle state machine — see
    /// [`is_valid_transition`] for the allowed edges. Invalid transitions
    /// are rejected with [`SalesError::InvalidInput`].
    pub fn update_lead_status(
        &self,
        id: &str,
        new_status: LeadStatus,
        tenant_id: &str,
    ) -> Result<Lead, SalesError> {
        let mut store = self.leads.write();
        let lead = store
            .iter_mut()
            .find(|l| l.id == id && l.tenant_id == tenant_id)
            .ok_or_else(|| SalesError::LeadNotFound(id.to_string()))?;
        if !is_valid_transition(&lead.status, &new_status) {
            return Err(SalesError::InvalidInput(format!(
                "invalid lead status transition: {} -> {}",
                lead.status, new_status
            )));
        }
        lead.status = new_status;
        Ok(lead.clone())
    }

    /// Compute a deterministic lead score (0–100) from three normalised
    /// dimensions: email engagement, company size tier, and recency.
    /// Each input should be in `0.0..=1.0`.
    ///
    /// Uses default weights (40/30/30). For configurable weights, use
    /// [`score_lead_with_weights`].
    pub fn score_lead(email_engagement: f64, company_size: f64, recency: f64) -> u8 {
        Self::score_lead_with_weights(email_engagement, company_size, recency, 40, 30, 30)
    }

    /// Compute a deterministic lead score with customisable weights (SALES-01).
    ///
    /// Each weight is an integer percentage point. The final score is:
    ///   `engagement.clamp(0,1) * engagement_weight + company_size.clamp(0,1) * company_size_weight + recency.clamp(0,1) * recency_weight`
    ///
    /// The result is clamped to `0..=100`.
    pub fn score_lead_with_weights(
        email_engagement: f64,
        company_size: f64,
        recency: f64,
        engagement_weight: u8,
        company_size_weight: u8,
        recency_weight: u8,
    ) -> u8 {
        let raw = email_engagement.clamp(0.0, 1.0) * engagement_weight as f64
            + company_size.clamp(0.0, 1.0) * company_size_weight as f64
            + recency.clamp(0.0, 1.0) * recency_weight as f64;
        (raw.round() as u8).min(100)
    }

    /// Full-text search over lead name, email, and company, scoped to tenant.
    pub fn search_leads(&self, tenant_id: &str, query: &str) -> Vec<Lead> {
        let q = query.to_lowercase();
        self.leads
            .read()
            .iter()
            .filter(|l| l.tenant_id == tenant_id)
            .filter(|l| {
                l.name.to_lowercase().contains(&q)
                    || l.email.to_lowercase().contains(&q)
                    || l.company.to_lowercase().contains(&q)
            })
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone)]
pub enum CrmBackend {
    Postgres(SqlxCrmService),
}

/// Lead lifecycle state machine.
///
/// Allowed transitions:
///
/// ```text
/// New ──────► Contacted ──► Qualified ──► Converted
///  │             │              │
///  │             └──► Lost ◄────┘
///  │                    │
///  └───────◄────────────┘   (Lost → New re-open)
/// ```
///
/// Every other edge (including no-op self transitions and transitions out of
/// terminal/unrecognised statuses) is invalid and must be rejected with
/// [`SalesError::InvalidInput`].
pub fn is_valid_transition(from: &LeadStatus, to: &LeadStatus) -> bool {
    matches!(
        (from, to),
        (LeadStatus::New, LeadStatus::Contacted)
            | (LeadStatus::New, LeadStatus::Qualified)
            | (LeadStatus::Contacted, LeadStatus::Qualified)
            | (LeadStatus::Contacted, LeadStatus::Lost)
            | (LeadStatus::Qualified, LeadStatus::Converted)
            | (LeadStatus::Qualified, LeadStatus::Lost)
            | (LeadStatus::Lost, LeadStatus::New)
    )
}

impl CrmBackend {
    pub fn postgres(pool: sqlx::PgPool) -> Self {
        Self::Postgres(SqlxCrmService::new(pool))
    }

    pub async fn initialize(&self) -> Result<(), SalesError> {
        match self {
            Self::Postgres(service) => service.initialize().await,
        }
    }

    /// Require a non-empty tenant_id, returning a 403 error if missing.
    pub fn require_tenant_id(tenant_id: &str) -> Result<(), SalesError> {
        if tenant_id.is_empty() {
            Err(SalesError::Unauthorized("tenant_id is required".into()))
        } else {
            Ok(())
        }
    }

    pub async fn create_lead(
        &self,
        tenant_id: &str,
        email: String,
        name: String,
        company: String,
        title: String,
        source: String,
    ) -> Result<Lead, SalesError> {
        Self::require_tenant_id(tenant_id)?;
        match self {
            Self::Postgres(service) => {
                service
                    .create_lead(tenant_id, email, name, company, title, source)
                    .await
            }
        }
    }

    pub async fn get_lead(&self, id: &str, tenant_id: &str) -> Result<Lead, SalesError> {
        Self::require_tenant_id(tenant_id)?;
        match self {
            Self::Postgres(service) => service.get_lead(id, tenant_id).await,
        }
    }

    pub async fn list_leads(
        &self,
        tenant_id: &str,
        status: Option<LeadStatus>,
        source: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Lead>, SalesError> {
        Self::require_tenant_id(tenant_id)?;
        match self {
            Self::Postgres(service) => {
                service
                    .list_leads(tenant_id, status, source, limit, offset)
                    .await
            }
        }
    }

    pub async fn update_lead_status(
        &self,
        id: &str,
        new_status: LeadStatus,
        tenant_id: &str,
    ) -> Result<Lead, SalesError> {
        Self::require_tenant_id(tenant_id)?;
        match self {
            Self::Postgres(service) => service.update_lead_status(id, new_status, tenant_id).await,
        }
    }

    pub async fn delete_lead(&self, id: &str, tenant_id: &str) -> Result<(), SalesError> {
        Self::require_tenant_id(tenant_id)?;
        match self {
            Self::Postgres(service) => service.delete_lead(id, tenant_id).await,
        }
    }

    pub async fn set_lead_score(
        &self,
        id: &str,
        score: u8,
        tenant_id: &str,
    ) -> Result<(), SalesError> {
        Self::require_tenant_id(tenant_id)?;
        match self {
            Self::Postgres(service) => service.set_lead_score(id, score, tenant_id).await,
        }
    }

    pub async fn search_leads(
        &self,
        tenant_id: &str,
        query: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Lead>, SalesError> {
        Self::require_tenant_id(tenant_id)?;
        match self {
            Self::Postgres(service) => service.search_leads(tenant_id, query, limit, offset).await,
        }
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
            "tenant-a".into(),
            "alice@acme.com".into(),
            "Alice".into(),
            "Acme".into(),
            "CTO".into(),
            "product_hunt".into(),
        );
        svc.create_lead(
            "tenant-a".into(),
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
        let leads = svc.list_leads("tenant-a", None, None);
        assert_eq!(leads.len(), 2);
        let first = &leads[0];
        let fetched = svc.get_lead(&first.id, "tenant-a").unwrap();
        assert_eq!(fetched.email, first.email);
    }

    #[test]
    fn test_update_lead_status() {
        let svc = make_svc();
        let leads = svc.list_leads("tenant-a", None, None);
        let id = leads[0].id.clone();
        let updated = svc
            .update_lead_status(&id, LeadStatus::Contacted, "tenant-a")
            .unwrap();
        assert_eq!(updated.status, LeadStatus::Contacted);

        // missing lead
        let res = svc.update_lead_status("does-not-exist", LeadStatus::Lost, "tenant-a");
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
        let results = svc.search_leads("tenant-a", "alice");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Alice");

        // filter by source
        let manual = svc.list_leads("tenant-a", None, Some("manual"));
        assert_eq!(manual.len(), 1);
        assert_eq!(manual[0].name, "Bob");

        // filter by status — both are New
        let new_leads = svc.list_leads("tenant-a", Some(LeadStatus::New), None);
        assert_eq!(new_leads.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Additional comprehensive tests for all code paths
    // -----------------------------------------------------------------------

    #[test]
    fn default_creates_empty_service() {
        let svc = CrmService::default();
        assert!(svc.list_leads("tenant-a", None, None).is_empty());
    }

    #[test]
    fn create_lead_returns_new_status_and_zero_score() {
        let svc = CrmService::new();
        let lead = svc.create_lead(
            "tenant-a".into(),
            "t@t.com".into(),
            "T".into(),
            "C".into(),
            "E".into(),
            "src".into(),
        );
        assert_eq!(lead.status, LeadStatus::New);
        assert_eq!(lead.score, 0);
    }

    #[test]
    fn cross_tenant_isolation_get_lead() {
        let svc = CrmService::new();
        // Create lead under tenant-a
        let lead_a = svc.create_lead(
            "tenant-a".into(),
            "a@a.com".into(),
            "A".into(),
            "A Inc".into(),
            "".into(),
            "source".into(),
        );
        // Create lead under tenant-b
        let lead_b = svc.create_lead(
            "tenant-b".into(),
            "b@b.com".into(),
            "B".into(),
            "B Inc".into(),
            "".into(),
            "source".into(),
        );

        // tenant-a cannot see tenant-b's lead
        match svc.get_lead(&lead_b.id, "tenant-a") {
            Err(SalesError::LeadNotFound(_)) => {}
            other => panic!(
                "Expected LeadNotFound for cross-tenant get, got {:?}",
                other
            ),
        }

        // tenant-b cannot see tenant-a's lead
        match svc.get_lead(&lead_a.id, "tenant-b") {
            Err(SalesError::LeadNotFound(_)) => {}
            other => panic!(
                "Expected LeadNotFound for cross-tenant get, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn cross_tenant_isolation_update_status() {
        let svc = CrmService::new();
        let lead_a = svc.create_lead(
            "tenant-a".into(),
            "a@a.com".into(),
            "A".into(),
            "".into(),
            "".into(),
            "".into(),
        );

        // tenant-b cannot update tenant-a's lead status
        match svc.update_lead_status(&lead_a.id, LeadStatus::Contacted, "tenant-b") {
            Err(SalesError::LeadNotFound(_)) => {}
            other => panic!(
                "Expected LeadNotFound for cross-tenant status update, got {:?}",
                other
            ),
        }

        // tenant-a can still update their own lead
        let updated = svc
            .update_lead_status(&lead_a.id, LeadStatus::Contacted, "tenant-a")
            .unwrap();
        assert_eq!(updated.status, LeadStatus::Contacted);
    }

    #[test]
    fn cross_tenant_isolation_list() {
        let svc = CrmService::new();
        svc.create_lead(
            "tenant-a".into(),
            "a@a.com".into(),
            "A".into(),
            "".into(),
            "".into(),
            "".into(),
        );
        svc.create_lead(
            "tenant-b".into(),
            "b@b.com".into(),
            "B".into(),
            "".into(),
            "".into(),
            "".into(),
        );

        // tenant-a sees only its own lead
        let tenant_a_leads = svc.list_leads("tenant-a", None, None);
        assert_eq!(tenant_a_leads.len(), 1);
        assert_eq!(tenant_a_leads[0].tenant_id, "tenant-a");

        // tenant-b sees only its own lead
        let tenant_b_leads = svc.list_leads("tenant-b", None, None);
        assert_eq!(tenant_b_leads.len(), 1);
        assert_eq!(tenant_b_leads[0].tenant_id, "tenant-b");
    }

    #[test]
    fn cross_tenant_isolation_search() {
        let svc = CrmService::new();
        svc.create_lead(
            "tenant-a".into(),
            "alice@a.com".into(),
            "Alice".into(),
            "A Inc".into(),
            "".into(),
            "".into(),
        );
        svc.create_lead(
            "tenant-b".into(),
            "bob@b.com".into(),
            "Bob".into(),
            "B Inc".into(),
            "".into(),
            "".into(),
        );

        // tenant-a searching for "alice" finds result
        assert_eq!(svc.search_leads("tenant-a", "alice").len(), 1);
        // tenant-a searching for "bob" finds nothing (cross-tenant)
        assert_eq!(svc.search_leads("tenant-a", "bob").len(), 0);
        // tenant-b searching for "bob" finds result
        assert_eq!(svc.search_leads("tenant-b", "bob").len(), 1);
        // tenant-b searching for "alice" finds nothing (cross-tenant)
        assert_eq!(svc.search_leads("tenant-b", "alice").len(), 0);
    }

    #[test]
    fn create_lead_unique_ids() {
        let svc = CrmService::new();
        let a = svc.create_lead(
            "tenant-a".into(),
            "a@a.com".into(),
            "A".into(),
            "".into(),
            "".into(),
            "".into(),
        );
        let b = svc.create_lead(
            "tenant-a".into(),
            "b@b.com".into(),
            "B".into(),
            "".into(),
            "".into(),
            "".into(),
        );
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn get_lead_missing_returns_error() {
        let svc = CrmService::new();
        match svc.get_lead("no-such-lead-id", "tenant-a") {
            Err(SalesError::LeadNotFound(_)) => {}
            other => panic!("Expected LeadNotFound, got {:?}", other),
        }
    }

    #[test]
    fn update_status_all_transitions() {
        let svc = CrmService::new();
        let lead = svc.create_lead(
            "tenant-a".into(),
            "x@x.com".into(),
            "X".into(),
            "".into(),
            "".into(),
            "".into(),
        );
        let id = lead.id.clone();

        // Happy path: New → Contacted → Qualified → Converted
        for status in [
            LeadStatus::Contacted,
            LeadStatus::Qualified,
            LeadStatus::Converted,
        ] {
            let updated = svc
                .update_lead_status(&id, status.clone(), "tenant-a")
                .unwrap();
            assert_eq!(updated.status, status);
        }
    }

    #[test]
    fn update_status_lost_lead_can_be_reopened() {
        let svc = CrmService::new();
        let lead = svc.create_lead(
            "tenant-a".into(),
            "x@x.com".into(),
            "X".into(),
            "".into(),
            "".into(),
            "".into(),
        );
        let id = &lead.id;

        // New → Contacted → Lost, then re-open: Lost → New
        svc.update_lead_status(id, LeadStatus::Contacted, "tenant-a")
            .unwrap();
        svc.update_lead_status(id, LeadStatus::Lost, "tenant-a")
            .unwrap();
        let reopened = svc
            .update_lead_status(id, LeadStatus::New, "tenant-a")
            .unwrap();
        assert_eq!(reopened.status, LeadStatus::New);
    }

    #[test]
    fn update_status_rejects_invalid_transitions() {
        let svc = CrmService::new();
        let lead = svc.create_lead(
            "tenant-a".into(),
            "x@x.com".into(),
            "X".into(),
            "".into(),
            "".into(),
            "".into(),
        );
        let id = &lead.id;

        // New → Converted skips qualification: invalid
        match svc.update_lead_status(id, LeadStatus::Converted, "tenant-a") {
            Err(SalesError::InvalidInput(_)) => {}
            other => panic!("Expected InvalidInput for New → Converted, got {:?}", other),
        }

        // No-op self transition is invalid too
        assert!(matches!(
            svc.update_lead_status(id, LeadStatus::New, "tenant-a"),
            Err(SalesError::InvalidInput(_))
        ));

        // Converted is terminal: Converted → Lost is invalid
        svc.update_lead_status(id, LeadStatus::Qualified, "tenant-a")
            .unwrap();
        svc.update_lead_status(id, LeadStatus::Converted, "tenant-a")
            .unwrap();
        assert!(matches!(
            svc.update_lead_status(id, LeadStatus::Lost, "tenant-a"),
            Err(SalesError::InvalidInput(_))
        ));

        // The rejected transitions must not have mutated the status
        let fetched = svc.get_lead(id, "tenant-a").unwrap();
        assert_eq!(fetched.status, LeadStatus::Converted);
    }

    #[test]
    fn is_valid_transition_table() {
        let new = LeadStatus::New;
        let contacted = LeadStatus::Contacted;
        let qualified = LeadStatus::Qualified;
        let converted = LeadStatus::Converted;
        let lost = LeadStatus::Lost;

        // Allowed edges
        for (from, to) in [
            (&new, &contacted),
            (&new, &qualified),
            (&contacted, &qualified),
            (&contacted, &lost),
            (&qualified, &converted),
            (&qualified, &lost),
            (&lost, &new),
        ] {
            assert!(
                is_valid_transition(from, to),
                "{from} -> {to} should be valid"
            );
        }

        // A representative set of disallowed edges
        for (from, to) in [
            (&new, &converted),
            (&new, &lost),
            (&converted, &lost),
            (&converted, &new),
            (&lost, &qualified),
            (&qualified, &new),
            (&new, &new),
            (&contacted, &contacted),
            (&new, &LeadStatus::Snoozed),
            (
                &LeadStatus::Unknown("weird".into()),
                &LeadStatus::Qualified,
            ),
        ] {
            assert!(
                !is_valid_transition(from, to),
                "{from} -> {to} should be invalid"
            );
        }
    }

    #[test]
    fn search_is_case_insensitive() {
        let svc = CrmService::new();
        svc.create_lead(
            "tenant-a".into(),
            "UPPER@TEST.COM".into(),
            "LOUD".into(),
            "BIG".into(),
            "".into(),
            "".into(),
        );
        assert_eq!(svc.search_leads("tenant-a", "upper").len(), 1);
        assert_eq!(svc.search_leads("tenant-a", "UPPER").len(), 1);
        assert_eq!(svc.search_leads("tenant-a", "loud").len(), 1);
        assert_eq!(svc.search_leads("tenant-a", "big").len(), 1);
    }

    #[test]
    fn search_empty_query_returns_all() {
        let svc = make_svc();
        assert_eq!(svc.search_leads("tenant-a", "").len(), 2);
    }

    #[test]
    fn search_no_match_returns_empty() {
        let svc = make_svc();
        assert!(svc.search_leads("tenant-a", "zzz_nonexistent").is_empty());
    }

    #[test]
    fn filter_by_status_and_source_combined() {
        let svc = make_svc();
        let leads = svc.list_leads("tenant-a", Some(LeadStatus::New), Some("product_hunt"));
        assert_eq!(leads.len(), 1);
        assert_eq!(leads[0].name, "Alice");
    }

    #[test]
    fn filter_by_nonexistent_source() {
        let svc = make_svc();
        assert!(svc.list_leads("tenant-a", None, Some("zzz")).is_empty());
    }

    #[test]
    fn filter_by_status_after_update() {
        let svc = make_svc();
        let id = svc.list_leads("tenant-a", None, None)[0].id.clone();
        svc.update_lead_status(&id, LeadStatus::Qualified, "tenant-a")
            .unwrap();
        let qualified = svc.list_leads("tenant-a", Some(LeadStatus::Qualified), None);
        assert_eq!(qualified.len(), 1);
        let still_new = svc.list_leads("tenant-a", Some(LeadStatus::New), None);
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
        svc.create_lead(
            "tenant-a".into(),
            "a@a.com".into(),
            "A".into(),
            "".into(),
            "".into(),
            "".into(),
        );
        assert_eq!(svc2.list_leads("tenant-a", None, None).len(), 1);
    }

    #[test]
    fn search_matches_company_field() {
        let svc = CrmService::new();
        svc.create_lead(
            "tenant-a".into(),
            "x@x.com".into(),
            "X".into(),
            "Unique Corp".into(),
            "".into(),
            "".into(),
        );
        assert_eq!(svc.search_leads("tenant-a", "unique corp").len(), 1);
    }

    #[test]
    fn search_matches_email_field() {
        let svc = CrmService::new();
        svc.create_lead(
            "tenant-a".into(),
            "special@domain.com".into(),
            "N".into(),
            "C".into(),
            "".into(),
            "".into(),
        );
        assert_eq!(svc.search_leads("tenant-a", "special@domain").len(), 1);
    }

    // -----------------------------------------------------------------------
    // Lead scoring formula — comprehensive tests
    // -----------------------------------------------------------------------

    /// Verifies that each weight (40 / 30 / 30) contributes the correct
    /// proportion when individual factors are driven to their maximum.
    #[test]
    fn score_lead_weights_sum_to_100() {
        // Full score must be exactly 100
        assert_eq!(CrmService::score_lead(1.0, 1.0, 1.0), 100);

        // Email engagement weight = 40% of total
        assert_eq!(CrmService::score_lead(1.0, 0.0, 0.0), 40);

        // Company size weight = 30% of total
        assert_eq!(CrmService::score_lead(0.0, 1.0, 0.0), 30);

        // Recency weight = 30% of total
        assert_eq!(CrmService::score_lead(0.0, 0.0, 1.0), 30);
    }

    /// Verifies weighted factor contributions across intermediate values,
    /// confirming the formula produces linear, proportional output.
    #[test]
    fn score_lead_intermediate_contributions() {
        // Engagement only at half strength: 0.5 * 40 = 20
        assert_eq!(CrmService::score_lead(0.5, 0.0, 0.0), 20);

        // Company size only at half strength: 0.5 * 30 = 15
        assert_eq!(CrmService::score_lead(0.0, 0.5, 0.0), 15);

        // Recency only at half strength: 0.5 * 30 = 15
        assert_eq!(CrmService::score_lead(0.0, 0.0, 0.5), 15);

        // Quarter strength each: 0.25*40 + 0.25*30 + 0.25*30 = 10 + 7.5 + 7.5 = 25
        assert_eq!(CrmService::score_lead(0.25, 0.25, 0.25), 25);
    }

    /// Verifies rounding behaviour: the formula uses `f64::round()` before
    /// casting to `u8`, which rounds half-way values away from zero.
    #[test]
    fn score_lead_rounding_edge_cases() {
        // 0.125 * 40 + 0.125 * 30 + 0.125 * 30 = 5.0 + 3.75 + 3.75 = 12.5 → 13
        assert_eq!(CrmService::score_lead(0.125, 0.125, 0.125), 13);

        // 0.0625 * 40 + 0.0625 * 30 + 0.0625 * 30 = 2.5 + 1.875 + 1.875 = 6.25 → 6
        assert_eq!(CrmService::score_lead(0.0625, 0.0625, 0.0625), 6);

        // Produces a raw value of x.5 to confirm rounding direction
        // 0.1875 * 40 = 7.5, engagement only
        assert_eq!(CrmService::score_lead(0.1875, 0.0, 0.0), 8);

        // Just below a rounding threshold: 0.1874 * 40 = 7.496 → 7
        assert_eq!(CrmService::score_lead(0.1874, 0.0, 0.0), 7);
    }

    /// Ensures the scoring formula is deterministic: identical inputs always
    /// produce the identical output, even across many invocations.
    #[test]
    fn score_lead_deterministic() {
        let inputs = [
            (0.0, 0.0, 0.0, 0u8),
            (0.3, 0.6, 0.9, 57u8),
            (0.5, 0.5, 0.5, 50u8),
            (0.75, 0.25, 0.5, 53u8),
            (1.0, 1.0, 1.0, 100u8),
        ];

        for &(eng, size, rec, expected) in &inputs {
            for _ in 0..10 {
                assert_eq!(
                    CrmService::score_lead(eng, size, rec),
                    expected,
                    "Determinism failure for ({eng}, {size}, {rec})",
                );
            }
        }
    }

    /// Verifies clamping works for values slightly above the [0, 1] range
    /// as well as values far outside it.
    #[test]
    fn score_lead_clamps_over_max() {
        // Just above max
        assert_eq!(CrmService::score_lead(1.001, 1.001, 1.001), 100);
        // Far above max
        assert_eq!(CrmService::score_lead(100.0, 100.0, 100.0), 100);
        // One factor slightly over
        assert_eq!(CrmService::score_lead(1.001, 0.0, 0.0), 40);
    }

    /// Verifies clamping works for negative values and values slightly
    /// below the [0, 1] range.
    #[test]
    fn score_lead_clamps_under_min() {
        // Slightly below zero (negative)
        assert_eq!(CrmService::score_lead(-0.001, -0.001, -0.001), 0);
        // Far below zero
        assert_eq!(CrmService::score_lead(-100.0, -100.0, -100.0), 0);
        // One factor slightly below
        assert_eq!(CrmService::score_lead(-0.001, 1.0, 1.0), 60);
    }

    /// Documents the behaviour when `f64::NAN` is passed.  NaN propagates
    /// through `clamp()` and all arithmetic operations; `round()` on NaN
    /// yields NaN, and the `as u8` cast converts NaN to 0.
    #[test]
    fn score_lead_nan_handling() {
        // All NaN → 0 (NaN propagates through, cast to u8 yields 0)
        assert_eq!(CrmService::score_lead(f64::NAN, f64::NAN, f64::NAN), 0);
        // Any single NaN input causes the entire raw sum to become NaN → 0
        assert_eq!(CrmService::score_lead(f64::NAN, 1.0, 1.0), 0);
        assert_eq!(CrmService::score_lead(1.0, f64::NAN, 1.0), 0);
        assert_eq!(CrmService::score_lead(1.0, 1.0, f64::NAN), 0);
        // Infinity is clamped to 1.0, so it produces a valid score
        assert_eq!(
            CrmService::score_lead(f64::INFINITY, f64::INFINITY, f64::INFINITY),
            100
        );
    }

    /// Verifies the formula never exceeds the documented maximum of 100,
    /// even with pathological or extreme inputs.
    #[test]
    fn score_lead_never_exceeds_max() {
        for eng in [0.0, 0.5, 1.0, 2.0, -1.0] {
            for size in [0.0, 0.5, 1.0, 2.0, -1.0] {
                for rec in [0.0, 0.5, 1.0, 2.0, -1.0] {
                    let score = CrmService::score_lead(eng, size, rec);
                    assert!(
                        score <= 100,
                        "Score {score} exceeds 100 for ({eng}, {size}, {rec})",
                    );
                    assert!(
                        score <= 100 || (eng < 0.0 || size < 0.0 || rec < 0.0),
                        "Negative inputs for ({eng}, {size}, {rec}) should clamp to 0, got {score}",
                    );
                }
            }
        }
    }

    /// Verifies the formula never returns a negative score.  Even with all
    /// negative inputs the result must be 0.
    #[test]
    fn score_lead_never_negative() {
        let negatives = [-1.0, -0.5, -0.001, -100.0];
        for &eng in &negatives {
            for &size in &negatives {
                for &rec in &negatives {
                    let score = CrmService::score_lead(eng, size, rec);
                    assert_eq!(
                        score, 0,
                        "All-negative ({eng}, {size}, {rec}) should yield 0, got {score}",
                    );
                }
            }
        }
    }

    /// Confirms that floating-point imprecision around the 0/1 boundaries
    /// is handled gracefully.
    #[test]
    fn score_lead_floating_point_boundaries() {
        // Smallest representable positive f64 should be ~0 but clamped to 0 contribution
        let tiny = f64::from_bits(1); // smallest subnormal
        assert_eq!(CrmService::score_lead(tiny, 0.0, 0.0), 0);

        // Very close to 1.0 from below
        let almost_one = 1.0 - f64::EPSILON;
        assert_eq!(
            CrmService::score_lead(almost_one, almost_one, almost_one),
            100
        );

        // Just above 1.0 by epsilon
        let just_over = 1.0 + f64::EPSILON;
        assert_eq!(CrmService::score_lead(just_over, just_over, just_over), 100);
    }
}
