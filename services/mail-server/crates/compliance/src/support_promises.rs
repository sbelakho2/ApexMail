use chrono::{DateTime, Datelike, Utc, Weekday};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportPlan {
    Free,
    Developer,
    Pro,
    Growth,
    Business,
    Enterprise,
    DedicatedTenant,
}

impl SupportPlan {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Developer => "developer",
            Self::Pro => "pro",
            Self::Growth => "growth",
            Self::Business => "business",
            Self::Enterprise => "enterprise",
            Self::DedicatedTenant => "dedicated_tenant",
        }
    }

    pub fn response_target_hours(&self) -> f64 {
        match self {
            Self::Free => f64::INFINITY,
            Self::Developer => 48.0,
            Self::Pro => 24.0,
            Self::Growth => 8.0,
            Self::Business => 4.0,
            Self::Enterprise => 2.0,
            Self::DedicatedTenant => 1.0,
        }
    }

    pub fn response_target_display(&self) -> &'static str {
        match self {
            Self::Free => "Community and documentation only",
            Self::Developer => "2 business days",
            Self::Pro => "1 business day",
            Self::Growth => "8 business hours",
            Self::Business => "4 business hours",
            Self::Enterprise => "Negotiated per contract",
            Self::DedicatedTenant => "Premium — negotiated per contract",
        }
    }

    pub fn eligible_channels(&self) -> Vec<SupportChannel> {
        match self {
            Self::Free => vec![SupportChannel::Documentation, SupportChannel::Community],
            Self::Developer => vec![SupportChannel::Email, SupportChannel::Documentation, SupportChannel::Community],
            Self::Pro => vec![SupportChannel::Email, SupportChannel::Documentation, SupportChannel::Community],
            Self::Growth => vec![SupportChannel::Email, SupportChannel::Portal, SupportChannel::Documentation],
            Self::Business => vec![SupportChannel::Email, SupportChannel::Portal, SupportChannel::Documentation, SupportChannel::Slack],
            Self::Enterprise => vec![SupportChannel::Email, SupportChannel::Portal, SupportChannel::Slack, SupportChannel::Phone, SupportChannel::DedicatedCSM],
            Self::DedicatedTenant => vec![SupportChannel::Email, SupportChannel::Portal, SupportChannel::Slack, SupportChannel::Phone, SupportChannel::DedicatedCSM, SupportChannel::PrivateSlack],
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "free" => Some(Self::Free),
            "developer" => Some(Self::Developer),
            "pro" => Some(Self::Pro),
            "growth" => Some(Self::Growth),
            "business" => Some(Self::Business),
            "enterprise" => Some(Self::Enterprise),
            "dedicated_tenant" => Some(Self::DedicatedTenant),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportChannel {
    Email,
    Portal,
    Slack,
    Phone,
    Documentation,
    Community,
    DedicatedCSM,
    PrivateSlack,
}

impl SupportChannel {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Email => "Email support",
            Self::Portal => "Support portal",
            Self::Slack => "Shared Slack channel",
            Self::Phone => "Phone support",
            Self::Documentation => "Documentation",
            Self::Community => "Community forum",
            Self::DedicatedCSM => "Dedicated CSM",
            Self::PrivateSlack => "Private Slack channel",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "critical" => Some(Self::Critical),
            "high" => Some(Self::High),
            "medium" => Some(Self::Medium),
            "low" => Some(Self::Low),
            _ => None,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Critical => "Service unavailable or data loss. Affects all customers.",
            Self::High => "Major feature degraded. Affects majority of customers.",
            Self::Medium => "Partial impairment. Affects subset of customers.",
            Self::Low => "Minor issue. No customer impact.",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SupportHours {
    pub timezone: &'static str,
    pub weekday_start_hour: u32,
    pub weekday_end_hour: u32,
    pub saturday_start_hour: Option<u32>,
    pub saturday_end_hour: Option<u32>,
    pub sunday: bool,
}

impl Default for SupportHours {
    fn default() -> Self {
        Self {
            timezone: "Europe/Tallinn",
            weekday_start_hour: 9,
            weekday_end_hour: 18,
            saturday_start_hour: Some(10),
            saturday_end_hour: Some(16),
            sunday: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SupportTiers {
    tiers: HashMap<SupportPlan, TierDefinition>,
}

#[derive(Debug, Clone)]
pub struct TierDefinition {
    pub plan: SupportPlan,
    pub response_target_hours: f64,
    pub channels: Vec<SupportChannel>,
    pub severity_support: Vec<Severity>,
    pub dedicated_csm: bool,
    pub private_slack: bool,
    pub phone_support: bool,
    pub migration_support: bool,
    pub deliverability_consulting: bool,
    pub security_questionnaire_support: bool,
    pub architecture_review: bool,
}

impl Default for TierDefinition {
    fn default() -> Self {
        Self {
            plan: SupportPlan::Free,
            response_target_hours: f64::INFINITY,
            channels: vec![SupportChannel::Documentation, SupportChannel::Community],
            severity_support: vec![Severity::Low],
            dedicated_csm: false,
            private_slack: false,
            phone_support: false,
            migration_support: false,
            deliverability_consulting: false,
            security_questionnaire_support: false,
            architecture_review: false,
        }
    }
}

impl SupportTiers {
    pub fn new() -> Self {
        let mut tiers = Self {
            tiers: HashMap::new(),
        };
        tiers.register_default_tiers();
        tiers
    }

    fn register_default_tiers(&mut self) {
        self.tiers.insert(SupportPlan::Free, TierDefinition {
            plan: SupportPlan::Free,
            response_target_hours: f64::INFINITY,
            channels: vec![SupportChannel::Documentation, SupportChannel::Community],
            severity_support: vec![Severity::Low],
            dedicated_csm: false,
            private_slack: false,
            phone_support: false,
            migration_support: false,
            deliverability_consulting: false,
            security_questionnaire_support: false,
            architecture_review: false,
        });

        self.tiers.insert(SupportPlan::Developer, TierDefinition {
            plan: SupportPlan::Developer,
            response_target_hours: 48.0,
            channels: vec![SupportChannel::Email, SupportChannel::Documentation, SupportChannel::Community],
            severity_support: vec![Severity::Medium, Severity::Low],
            dedicated_csm: false,
            private_slack: false,
            phone_support: false,
            migration_support: false,
            deliverability_consulting: false,
            security_questionnaire_support: false,
            architecture_review: false,
        });

        self.tiers.insert(SupportPlan::Pro, TierDefinition {
            plan: SupportPlan::Pro,
            response_target_hours: 24.0,
            channels: vec![SupportChannel::Email, SupportChannel::Documentation, SupportChannel::Community],
            severity_support: vec![Severity::High, Severity::Medium, Severity::Low],
            dedicated_csm: false,
            private_slack: false,
            phone_support: false,
            migration_support: false,
            deliverability_consulting: false,
            security_questionnaire_support: false,
            architecture_review: false,
        });

        self.tiers.insert(SupportPlan::Growth, TierDefinition {
            plan: SupportPlan::Growth,
            response_target_hours: 8.0,
            channels: vec![SupportChannel::Email, SupportChannel::Portal, SupportChannel::Documentation],
            severity_support: vec![Severity::High, Severity::Medium, Severity::Low],
            dedicated_csm: false,
            private_slack: false,
            phone_support: false,
            migration_support: true,
            deliverability_consulting: false,
            security_questionnaire_support: false,
            architecture_review: false,
        });

        self.tiers.insert(SupportPlan::Business, TierDefinition {
            plan: SupportPlan::Business,
            response_target_hours: 4.0,
            channels: vec![SupportChannel::Email, SupportChannel::Portal, SupportChannel::Documentation, SupportChannel::Slack],
            severity_support: vec![Severity::Critical, Severity::High, Severity::Medium, Severity::Low],
            dedicated_csm: false,
            private_slack: false,
            phone_support: false,
            migration_support: true,
            deliverability_consulting: true,
            security_questionnaire_support: true,
            architecture_review: false,
        });

        self.tiers.insert(SupportPlan::Enterprise, TierDefinition {
            plan: SupportPlan::Enterprise,
            response_target_hours: 2.0,
            channels: vec![SupportChannel::Email, SupportChannel::Portal, SupportChannel::Slack, SupportChannel::Phone, SupportChannel::DedicatedCSM],
            severity_support: vec![Severity::Critical, Severity::High, Severity::Medium, Severity::Low],
            dedicated_csm: true,
            private_slack: false,
            phone_support: true,
            migration_support: true,
            deliverability_consulting: true,
            security_questionnaire_support: true,
            architecture_review: true,
        });

        self.tiers.insert(SupportPlan::DedicatedTenant, TierDefinition {
            plan: SupportPlan::DedicatedTenant,
            response_target_hours: 1.0,
            channels: vec![SupportChannel::Email, SupportChannel::Portal, SupportChannel::Slack, SupportChannel::Phone, SupportChannel::DedicatedCSM, SupportChannel::PrivateSlack],
            severity_support: vec![Severity::Critical, Severity::High, Severity::Medium, Severity::Low],
            dedicated_csm: true,
            private_slack: true,
            phone_support: true,
            migration_support: true,
            deliverability_consulting: true,
            security_questionnaire_support: true,
            architecture_review: true,
        });
    }

    pub fn get_tier(&self, plan: SupportPlan) -> Option<&TierDefinition> {
        self.tiers.get(&plan)
    }

    pub fn response_target_for(&self, plan: SupportPlan) -> f64 {
        self.tiers
            .get(&plan)
            .map(|t| t.response_target_hours)
            .unwrap_or(f64::INFINITY)
    }

    pub fn channels_for(&self, plan: SupportPlan) -> Vec<SupportChannel> {
        self.tiers
            .get(&plan)
            .map(|t| t.channels.clone())
            .unwrap_or_default()
    }
}

pub fn validate_support_target(
    plan: SupportPlan,
    severity: Severity,
    opened_at: DateTime<Utc>,
    first_response_at: Option<DateTime<Utc>>,
    hours: &SupportHours,
) -> Result<SupportTargetResult, SupportTargetError> {
    let tiers = SupportTiers::new();
    let tier = tiers
        .get_tier(plan)
        .ok_or(SupportTargetError::UnknownPlan)?;

    let target_hours = tier.response_target_hours;
    if target_hours == f64::INFINITY {
        return Ok(SupportTargetResult {
            met: true,
            target_hours,
            actual_hours: None,
            within_target: true,
            plan,
            severity,
            note: "Free plan has no response target obligation".into(),
        });
    }

    let Some(response_at) = first_response_at else {
        let now = Utc::now();
        let elapsed = (now - opened_at).num_minutes() as f64 / 60.0;
        return Ok(SupportTargetResult {
            met: elapsed <= target_hours,
            target_hours,
            actual_hours: Some(elapsed),
            within_target: elapsed <= target_hours,
            plan,
            severity,
            note: if elapsed <= target_hours {
                "Awaiting first response; currently within target".into()
            } else {
                format!(
                    "Target exceeded: {}h elapsed without response (target: {}h)",
                    elapsed.round(),
                    target_hours
                )
            },
        });
    };

    let elapsed_business_hours = compute_business_hours(opened_at, response_at, hours);
    let met = elapsed_business_hours <= target_hours;

    Ok(SupportTargetResult {
        met,
        target_hours,
        actual_hours: Some(elapsed_business_hours),
        within_target: elapsed_business_hours <= target_hours,
        plan,
        severity,
        note: if met {
            format!(
                "Response within {}h target ({}h elapsed business hours)",
                target_hours,
                (elapsed_business_hours * 10.0).round() / 10.0
            )
        } else {
            format!(
                "Response exceeded {}h target ({}h elapsed business hours)",
                target_hours,
                (elapsed_business_hours * 10.0).round() / 10.0
            )
        },
    })
}

fn compute_business_hours(
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    hours: &SupportHours,
) -> f64 {
    let mut total: f64 = 0.0;
    let mut cursor = start;

    while cursor < end {
        let weekday = cursor.date_naive().weekday();
        let is_sunday = weekday == Weekday::Sun;

        let (day_start_hour, day_end_hour) = if is_sunday && !hours.sunday {
            cursor = cursor.date_naive().succ_opt()
                .map(|d| d.and_hms_opt(0, 0, 0).unwrap())
                .map(|d| DateTime::from_naive_utc_and_offset(d, *cursor.offset()))
                .unwrap_or(end);
            continue;
        } else if weekday == Weekday::Sat {
            match (hours.saturday_start_hour, hours.saturday_end_hour) {
                (Some(s), Some(e)) => (s, e),
                _ => {
                    cursor = cursor.date_naive().succ_opt()
                        .map(|d| d.and_hms_opt(0, 0, 0).unwrap())
                        .map(|d| DateTime::from_naive_utc_and_offset(d, *cursor.offset()))
                        .unwrap_or(end);
                    continue;
                }
            }
        } else {
            (hours.weekday_start_hour, hours.weekday_end_hour)
        };

        let day_start = cursor.date_naive()
            .and_hms_opt(day_start_hour, 0, 0)
            .map(|ndt| DateTime::from_naive_utc_and_offset(ndt, *cursor.offset()))
            .unwrap_or(cursor);

        let day_end = cursor.date_naive()
            .and_hms_opt(day_end_hour, 0, 0)
            .map(|ndt| DateTime::from_naive_utc_and_offset(ndt, *cursor.offset()))
            .unwrap_or(cursor);

        let effective_start = if cursor < day_start { day_start } else { cursor };
        let effective_end = if end < day_end { end } else { day_end };

        if effective_start < effective_end {
            total += (effective_end - effective_start).num_seconds() as f64 / 3600.0;
        }

        cursor = day_end + chrono::Duration::seconds(1);
    }

    total
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportTargetResult {
    pub met: bool,
    pub target_hours: f64,
    pub actual_hours: Option<f64>,
    pub within_target: bool,
    pub plan: SupportPlan,
    pub severity: Severity,
    pub note: String,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum SupportTargetError {
    #[error("Unknown support plan")]
    UnknownPlan,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationPath {
    pub level: u32,
    pub title: String,
    pub trigger_hours: f64,
    pub contacts: Vec<String>,
}

pub fn escalation_path(plan: SupportPlan) -> Vec<EscalationPath> {
    let mut path = Vec::new();

    path.push(EscalationPath {
        level: 1,
        title: "Support Engineer".into(),
        trigger_hours: 0.0,
        contacts: vec!["support@apexmail.ee".into()],
    });

    match plan {
        SupportPlan::Free | SupportPlan::Developer => {
            path.push(EscalationPath {
                level: 2,
                title: "Support Lead".into(),
                trigger_hours: 48.0,
                contacts: vec!["support-lead@apexmail.ee".into()],
            });
        }
        SupportPlan::Pro | SupportPlan::Growth => {
            path.push(EscalationPath {
                level: 2,
                title: "Support Lead".into(),
                trigger_hours: 24.0,
                contacts: vec!["support-lead@apexmail.ee".into()],
            });
            path.push(EscalationPath {
                level: 3,
                title: "Engineering Manager".into(),
                trigger_hours: 48.0,
                contacts: vec!["eng-manager@apexmail.ee".into()],
            });
        }
        _ => {
            path.push(EscalationPath {
                level: 2,
                title: "Support Lead".into(),
                trigger_hours: 4.0,
                contacts: vec!["support-lead@apexmail.ee".into()],
            });
            path.push(EscalationPath {
                level: 3,
                title: "Engineering Manager".into(),
                trigger_hours: 8.0,
                contacts: vec!["eng-manager@apexmail.ee".into()],
            });
            path.push(EscalationPath {
                level: 4,
                title: "CTO".into(),
                trigger_hours: 12.0,
                contacts: vec!["cto@apexmail.ee".into()],
            });
        }
    }

    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_plans_have_tier_definitions() {
        let tiers = SupportTiers::new();
        for plan in [
            SupportPlan::Free,
            SupportPlan::Developer,
            SupportPlan::Pro,
            SupportPlan::Growth,
            SupportPlan::Business,
            SupportPlan::Enterprise,
            SupportPlan::DedicatedTenant,
        ] {
            assert!(tiers.get_tier(plan).is_some(), "Missing tier for {:?}", plan);
        }
    }

    #[test]
    fn test_response_targets_match_requirements() {
        assert_eq!(SupportPlan::Free.response_target_hours(), f64::INFINITY);
        assert_eq!(SupportPlan::Developer.response_target_hours(), 48.0);
        assert_eq!(SupportPlan::Pro.response_target_hours(), 24.0);
        assert_eq!(SupportPlan::Growth.response_target_hours(), 8.0);
        assert_eq!(SupportPlan::Business.response_target_hours(), 4.0);
        assert!(SupportPlan::Enterprise.response_target_hours() <= 2.0);
        assert!(SupportPlan::DedicatedTenant.response_target_hours() <= 1.0);
    }

    #[test]
    fn test_enterprise_has_dedicated_csm() {
        let tiers = SupportTiers::new();
        let enterprise = tiers.get_tier(SupportPlan::Enterprise).unwrap();
        assert!(enterprise.dedicated_csm);
        assert!(enterprise.phone_support);
        assert!(!enterprise.private_slack);
    }

    #[test]
    fn test_dedicated_tenant_has_private_slack() {
        let tiers = SupportTiers::new();
        let dt = tiers.get_tier(SupportPlan::DedicatedTenant).unwrap();
        assert!(dt.private_slack);
        assert!(dt.architecture_review);
    }

    #[test]
    fn test_free_plan_no_phone_or_csm() {
        let tiers = SupportTiers::new();
        let free = tiers.get_tier(SupportPlan::Free).unwrap();
        assert!(!free.dedicated_csm);
        assert!(!free.phone_support);
        assert!(!free.private_slack);
    }

    #[test]
    fn test_validate_support_target_free_plan() {
        let hours = SupportHours::default();
        let now = Utc::now();
        let result = validate_support_target(
            SupportPlan::Free,
            Severity::Low,
            now,
            None,
            &hours,
        )
        .unwrap();
        assert!(result.met);
        assert!(result.note.contains("Free plan"));
    }

    #[test]
    fn test_escalation_path_hierarchy() {
        let path = escalation_path(SupportPlan::Enterprise);
        assert_eq!(path.len(), 4);
        assert_eq!(path[0].level, 1);
        assert_eq!(path[3].level, 4);
        assert_eq!(path[3].title, "CTO");
    }

    #[test]
    fn test_developer_plan_no_csm_no_private_slack() {
        let tiers = SupportTiers::new();
        let dev = tiers.get_tier(SupportPlan::Developer).unwrap();
        assert!(!dev.dedicated_csm);
        assert!(!dev.private_slack);
        assert!(!dev.deliverability_consulting);
    }
}
