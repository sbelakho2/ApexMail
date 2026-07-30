use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::dedicated_ip::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EligibilityStep {
    AssessMonthlyVolume,
    AssessDailyConsistency,
    AssessProviderDistribution,
    SeparateTraffic,
    ReviewDomainHistory,
    ReviewComplaintsAndBounces,
    ApproveOrReject,
}

impl EligibilityStep {
    pub fn label(&self) -> &str {
        match self {
            EligibilityStep::AssessMonthlyVolume => "Assess monthly volume",
            EligibilityStep::AssessDailyConsistency => "Assess daily consistency",
            EligibilityStep::AssessProviderDistribution => "Assess provider distribution",
            EligibilityStep::SeparateTraffic => "Separate transactional and broadcast traffic",
            EligibilityStep::ReviewDomainHistory => "Review domain history",
            EligibilityStep::ReviewComplaintsAndBounces => "Review complaints and bounces",
            EligibilityStep::ApproveOrReject => "Approve or reject dedicated-IP assignment",
        }
    }

    pub fn order() -> Vec<EligibilityStep> {
        vec![
            EligibilityStep::AssessMonthlyVolume,
            EligibilityStep::AssessDailyConsistency,
            EligibilityStep::AssessProviderDistribution,
            EligibilityStep::SeparateTraffic,
            EligibilityStep::ReviewDomainHistory,
            EligibilityStep::ReviewComplaintsAndBounces,
            EligibilityStep::ApproveOrReject,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepResult {
    Passed,
    Failed,
    ReviewNeeded,
    NotStarted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EligibilityProcess {
    pub tenant_id: String,
    pub steps: HashMap<EligibilityStep, StepResult>,
    pub notes: HashMap<EligibilityStep, String>,
    pub final_decision: Option<bool>,
    pub ip_count_approved: Option<u32>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub reviewer: Option<String>,
}

impl EligibilityProcess {
    pub fn new(tenant_id: &str) -> Self {
        let mut steps = HashMap::new();
        for step in EligibilityStep::order() {
            steps.insert(step, StepResult::NotStarted);
        }
        Self {
            tenant_id: tenant_id.to_string(),
            steps,
            notes: HashMap::new(),
            final_decision: None,
            ip_count_approved: None,
            started_at: Utc::now(),
            completed_at: None,
            reviewer: None,
        }
    }

    pub fn assess_step(&mut self, step: EligibilityStep, passed: bool, note: &str) {
        if let Some(result) = self.steps.get_mut(&step) {
            *result = if passed {
                StepResult::Passed
            } else {
                StepResult::Failed
            };
        }
        self.notes.insert(step, note.to_string());
    }

    pub fn mark_review_needed(&mut self, step: EligibilityStep, note: &str) {
        if let Some(result) = self.steps.get_mut(&step) {
            *result = StepResult::ReviewNeeded;
        }
        self.notes.insert(step, note.to_string());
    }

    pub fn finalize(&mut self, approved: bool, ip_count: u32, reviewer: &str) {
        if let Some(result) = self.steps.get_mut(&EligibilityStep::ApproveOrReject) {
            *result = if approved {
                StepResult::Passed
            } else {
                StepResult::Failed
            };
        }
        self.final_decision = Some(approved);
        self.ip_count_approved = Some(ip_count);
        self.completed_at = Some(Utc::now());
        self.reviewer = Some(reviewer.to_string());
    }

    pub fn all_steps_passed(&self) -> bool {
        EligibilityStep::order()
            .iter()
            .filter(|s| **s != EligibilityStep::ApproveOrReject)
            .all(|s| self.steps.get(s) == Some(&StepResult::Passed))
    }

    pub fn any_step_failed(&self) -> bool {
        self.steps.values().any(|r| *r == StepResult::Failed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarmupScheduler {
    pub plans: HashMap<String, WarmupPlan>,
}

impl WarmupScheduler {
    pub fn new() -> Self {
        Self {
            plans: HashMap::new(),
        }
    }

    pub fn create_plan(
        &mut self,
        ip: &str,
        total_days: u32,
        starting_volume: u64,
        providers: Vec<String>,
    ) -> &WarmupPlan {
        let plan = WarmupPlan::new(ip, total_days, starting_volume, providers);
        self.plans.insert(ip.to_string(), plan);
        self.plans.get(ip).unwrap()
    }

    pub fn get_plan(&self, ip: &str) -> Option<&WarmupPlan> {
        self.plans.get(ip)
    }

    pub fn get_plan_mut(&mut self, ip: &str) -> Option<&mut WarmupPlan> {
        self.plans.get_mut(ip)
    }

    pub fn list_active_plans(&self) -> Vec<&WarmupPlan> {
        self.plans
            .values()
            .filter(|p| !p.is_warmup_complete() && !p.paused)
            .collect()
    }

    pub fn list_paused_plans(&self) -> Vec<&WarmupPlan> {
        self.plans.values().filter(|p| p.paused).collect()
    }

    pub fn list_completed_plans(&self) -> Vec<&WarmupPlan> {
        self.plans.values().filter(|p| p.is_warmup_complete()).collect()
    }

    pub fn daily_targets_for(&self, ip: &str) -> Option<u64> {
        self.plans.get(ip).and_then(|p| p.current_target())
    }
}

impl Default for WarmupScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpDashboardTracker {
    pub dashboards: HashMap<String, IpDashboard>,
    pub warnings: Vec<IpWarning>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpWarning {
    pub ip_address: String,
    pub warning_type: WarningType,
    pub message: String,
    pub created_at: DateTime<Utc>,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningType {
    Underused,
    BlocklistListing,
    HighComplaintRate,
    HighBounceRate,
    WarmupStalled,
    Inactive,
}

impl IpDashboardTracker {
    pub fn new() -> Self {
        Self {
            dashboards: HashMap::new(),
            warnings: Vec::new(),
        }
    }

    pub fn register_dashboard(&mut self, dashboard: IpDashboard) {
        self.dashboards.insert(dashboard.ip_address.clone(), dashboard);
    }

    pub fn get_dashboard(&self, ip: &str) -> Option<&IpDashboard> {
        self.dashboards.get(ip)
    }

    pub fn update_status(
        &mut self,
        ip: &str,
        warmup_status: IpStatus,
        warmup_day: Option<u32>,
        warmup_total_days: Option<u32>,
    ) {
        if let Some(dashboard) = self.dashboards.get_mut(ip) {
            dashboard.warmup_status = warmup_status;
            dashboard.warmup_day = warmup_day;
            dashboard.warmup_total_days = warmup_total_days;
        }
    }

    pub fn add_warning(&mut self, ip: &str, warning_type: WarningType, message: &str) {
        self.warnings.push(IpWarning {
            ip_address: ip.to_string(),
            warning_type,
            message: message.to_string(),
            created_at: Utc::now(),
            acknowledged: false,
        });
    }

    pub fn acknowledge_warning(&mut self, ip: &str, warning_type: WarningType) {
        for w in &mut self.warnings {
            if w.ip_address == ip && w.warning_type == warning_type {
                w.acknowledged = true;
            }
        }
    }

    pub fn check_for_issues(&mut self) {
        let mut pending_warnings: Vec<(String, WarningType, String)> = Vec::new();
        for (ip, dashboard) in &self.dashboards {
            if dashboard.blocks > 0 {
                pending_warnings.push((
                    ip.clone(),
                    WarningType::BlocklistListing,
                    format!("{} blocks detected on IP {}.", dashboard.blocks, ip),
                ));
            }
            if dashboard.complaint_rate_pct > 0.1 {
                pending_warnings.push((
                    ip.clone(),
                    WarningType::HighComplaintRate,
                    format!(
                        "Complaint rate {:.2}% exceeds threshold on IP {}.",
                        dashboard.complaint_rate_pct, ip
                    ),
                ));
            }
            if dashboard.warmup_status != IpStatus::Active
                && dashboard.warmup_status != IpStatus::Warming
                && dashboard.warmup_status != IpStatus::Provisioning
            {
                pending_warnings.push((
                    ip.clone(),
                    WarningType::Inactive,
                    format!(
                        "IP {} is in {} status.",
                        ip,
                        serde_json::to_string(&dashboard.warmup_status).unwrap_or_default()
                    ),
                ));
            }
        }
        for (ip, warning_type, message) in pending_warnings {
            self.add_warning(&ip, warning_type, &message);
        }
    }

    pub fn unacknowledged_warnings(&self) -> Vec<&IpWarning> {
        self.warnings.iter().filter(|w| !w.acknowledged).collect()
    }
}

impl Default for IpDashboardTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplacementPolicy {
    Immediate,
    Within24Hours,
    Within72Hours,
    OnNextBillingCycle,
    ManualOnly,
}

impl ReplacementPolicy {
    pub fn sla_hours(&self) -> Option<u32> {
        match self {
            ReplacementPolicy::Immediate => Some(1),
            ReplacementPolicy::Within24Hours => Some(24),
            ReplacementPolicy::Within72Hours => Some(72),
            ReplacementPolicy::OnNextBillingCycle => None,
            ReplacementPolicy::ManualOnly => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelistingSupport {
    FullService,
    Assisted,
    SelfService,
    NotSupported,
}

impl DelistingSupport {
    pub fn description(&self) -> &str {
        match self {
            DelistingSupport::FullService => "ApexMail handles all delisting requests on behalf of the customer.",
            DelistingSupport::Assisted => "ApexMail provides templates and guidance; customer submits requests.",
            DelistingSupport::SelfService => "Customer is responsible for all delisting; ApexMail provides documentation.",
            DelistingSupport::NotSupported => "Delisting support is not available for this IP or deployment type.",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplacementRequest {
    pub ip_address: String,
    pub reason: String,
    pub policy: ReplacementPolicy,
    pub replacement_ip: Option<String>,
    pub requested_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelistingRequest {
    pub ip_address: String,
    pub blocklist: String,
    pub support_level: DelistingSupport,
    pub status: DelistingStatus,
    pub requested_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelistingStatus {
    Pending,
    InProgress,
    Delisted,
    Rejected,
    Failed,
}

#[derive(Debug, Clone, Default)]
pub struct IpOperationsManager {
    pub eligibility_processes: HashMap<String, EligibilityProcess>,
    pub warmup_scheduler: WarmupScheduler,
    pub dashboard_tracker: IpDashboardTracker,
    pub replacement_requests: Vec<ReplacementRequest>,
    pub delisting_requests: Vec<DelistingRequest>,
}

impl IpOperationsManager {
    pub fn new() -> Self {
        Self {
            eligibility_processes: HashMap::new(),
            warmup_scheduler: WarmupScheduler::new(),
            dashboard_tracker: IpDashboardTracker::new(),
            replacement_requests: Vec::new(),
            delisting_requests: Vec::new(),
        }
    }

    pub fn start_eligibility(&mut self, tenant_id: &str) -> &EligibilityProcess {
        let process = EligibilityProcess::new(tenant_id);
        self.eligibility_processes
            .insert(tenant_id.to_string(), process);
        self.eligibility_processes.get(tenant_id).unwrap()
    }

    pub fn request_replacement(&mut self, ip: &str, reason: &str, policy: ReplacementPolicy) {
        self.replacement_requests.push(ReplacementRequest {
            ip_address: ip.to_string(),
            reason: reason.to_string(),
            policy,
            replacement_ip: None,
            requested_at: Utc::now(),
            completed_at: None,
        });
    }

    pub fn request_delisting(&mut self, ip: &str, blocklist: &str, support: DelistingSupport) {
        self.delisting_requests.push(DelistingRequest {
            ip_address: ip.to_string(),
            blocklist: blocklist.to_string(),
            support_level: support,
            status: DelistingStatus::Pending,
            requested_at: Utc::now(),
            completed_at: None,
        });
    }

    pub fn complete_replacement(&mut self, ip: &str, replacement_ip: &str) -> bool {
        if let Some(req) = self
            .replacement_requests
            .iter_mut()
            .rev()
            .find(|r| r.ip_address == ip && r.completed_at.is_none())
        {
            req.replacement_ip = Some(replacement_ip.to_string());
            req.completed_at = Some(Utc::now());
            true
        } else {
            false
        }
    }

    pub fn complete_delisting(&mut self, ip: &str, blocklist: &str, successful: bool) -> bool {
        if let Some(req) = self
            .delisting_requests
            .iter_mut()
            .rev()
            .find(|r| r.ip_address == ip && r.blocklist == blocklist && r.completed_at.is_none())
        {
            req.status = if successful {
                DelistingStatus::Delisted
            } else {
                DelistingStatus::Failed
            };
            req.completed_at = Some(Utc::now());
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eligibility_process_all_steps_present() {
        let process = EligibilityProcess::new("tenant-1");
        let steps = EligibilityStep::order();
        assert_eq!(steps.len(), 7);
        for step in &steps {
            assert_eq!(process.steps.get(step), Some(&StepResult::NotStarted));
        }
    }

    #[test]
    fn test_eligibility_process_passes_all_steps() {
        let mut process = EligibilityProcess::new("tenant-1");
        for step in EligibilityStep::order() {
            if step != EligibilityStep::ApproveOrReject {
                process.assess_step(step, true, "OK");
            }
        }
        assert!(process.all_steps_passed());
        assert!(!process.any_step_failed());
    }

    #[test]
    fn test_eligibility_process_failure_detected() {
        let mut process = EligibilityProcess::new("tenant-1");
        process.assess_step(EligibilityStep::AssessMonthlyVolume, true, "OK");
        process.assess_step(EligibilityStep::AssessDailyConsistency, false, "Volume too volatile");
        assert!(!process.all_steps_passed());
        assert!(process.any_step_failed());
    }

    #[test]
    fn test_warmup_scheduler_create_and_retrieve() {
        let mut scheduler = WarmupScheduler::new();
        scheduler.create_plan("192.0.2.100", 14, 200, vec!["gmail".into()]);
        let plan = scheduler.get_plan("192.0.2.100");
        assert!(plan.is_some());
        assert_eq!(plan.unwrap().total_days, 14);
    }

    #[test]
    fn test_warmup_scheduler_lists_active_paused_completed() {
        let mut scheduler = WarmupScheduler::new();
        scheduler.create_plan("192.0.2.101", 5, 100, vec!["gmail".into()]);
        scheduler.create_plan("192.0.2.102", 3, 50, vec!["outlook".into()]);

        if let Some(plan) = scheduler.get_plan_mut("192.0.2.102") {
            plan.pause();
        }

        assert_eq!(scheduler.list_active_plans().len(), 1);
        assert_eq!(scheduler.list_paused_plans().len(), 1);

        if let Some(plan) = scheduler.get_plan_mut("192.0.2.101") {
            for _ in 0..6 {
                plan.advance_day();
            }
        }
        assert_eq!(scheduler.list_completed_plans().len(), 1);
    }

    #[test]
    fn test_dashboard_tracker_warnings() {
        let mut tracker = IpDashboardTracker::new();
        let dashboard = IpDashboard {
            ip_address: "203.0.113.99".to_string(),
            pool: "eu-west-1".to_string(),
            reverse_dns: None,
            assigned_domains: vec!["example.com".to_string()],
            current_stream: None,
            warmup_status: IpStatus::Active,
            warmup_day: None,
            warmup_total_days: None,
            provider_distribution: vec![],
            blocks: 3,
            deferrals: 0,
            complaint_rate_pct: 0.05,
            blocklist_status: vec![],
            feedback_loop_status: true,
            recommended_action: None,
            last_checked_at: Utc::now(),
        };
        tracker.register_dashboard(dashboard);
        tracker.check_for_issues();

        let unacked = tracker.unacknowledged_warnings();
        assert!(unacked.len() >= 1);
        assert!(unacked.iter().any(|w| matches!(w.warning_type, WarningType::BlocklistListing)));
    }

    #[test]
    fn test_replacement_request_and_completion() {
        let mut manager = IpOperationsManager::new();
        manager.request_replacement("192.0.2.200", "Reputation damaged", ReplacementPolicy::Within24Hours);
        assert_eq!(manager.replacement_requests.len(), 1);
        assert_eq!(manager.replacement_requests[0].policy, ReplacementPolicy::Within24Hours);
        assert_eq!(manager.replacement_requests[0].policy.sla_hours(), Some(24));

        let completed = manager.complete_replacement("192.0.2.200", "192.0.2.201");
        assert!(completed);
        assert_eq!(manager.replacement_requests[0].replacement_ip, Some("192.0.2.201".to_string()));
        assert!(manager.replacement_requests[0].completed_at.is_some());
    }

    #[test]
    fn test_delisting_request_and_completion() {
        let mut manager = IpOperationsManager::new();
        manager.request_delisting("192.0.2.300", "Spamhaus", DelistingSupport::FullService);
        assert_eq!(manager.delisting_requests.len(), 1);
        assert_eq!(manager.delisting_requests[0].status, DelistingStatus::Pending);
        assert_eq!(manager.delisting_requests[0].support_level, DelistingSupport::FullService);

        let completed = manager.complete_delisting("192.0.2.300", "Spamhaus", true);
        assert!(completed);
        assert_eq!(manager.delisting_requests[0].status, DelistingStatus::Delisted);
    }

    #[test]
    fn test_delisting_support_descriptions() {
        assert!(!DelistingSupport::FullService.description().is_empty());
        assert!(!DelistingSupport::Assisted.description().is_empty());
        assert!(!DelistingSupport::SelfService.description().is_empty());
        assert!(!DelistingSupport::NotSupported.description().is_empty());
    }

    #[test]
    fn test_replacement_policy_sla() {
        assert_eq!(ReplacementPolicy::Immediate.sla_hours(), Some(1));
        assert_eq!(ReplacementPolicy::Within24Hours.sla_hours(), Some(24));
        assert_eq!(ReplacementPolicy::Within72Hours.sla_hours(), Some(72));
        assert_eq!(ReplacementPolicy::OnNextBillingCycle.sla_hours(), None);
        assert_eq!(ReplacementPolicy::ManualOnly.sla_hours(), None);
    }
}
