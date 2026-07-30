use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

pub const FIRST_DEDICATED_IP_MONTHLY_EUR: u32 = 49;
pub const ADDITIONAL_DEDICATED_IP_MONTHLY_EUR: u32 = 69;
pub const ELIGIBILITY_MIN_MONTHLY_VOLUME: u64 = 100_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedicatedIpBilling {
    pub ip_count: u32,
    pub first_ip_monthly_eur: u32,
    pub additional_ip_monthly_eur: u32,
    pub total_monthly_eur: u32,
    pub assigned_ips: Vec<IpAssignment>,
    pub billing_start_date: Option<NaiveDate>,
}

impl DedicatedIpBilling {
    pub fn new() -> Self {
        Self {
            ip_count: 0,
            first_ip_monthly_eur: FIRST_DEDICATED_IP_MONTHLY_EUR,
            additional_ip_monthly_eur: ADDITIONAL_DEDICATED_IP_MONTHLY_EUR,
            total_monthly_eur: 0,
            assigned_ips: Vec::new(),
            billing_start_date: None,
        }
    }

    pub fn calculate_fee(&self) -> u32 {
        if self.ip_count == 0 {
            0
        } else {
            FIRST_DEDICATED_IP_MONTHLY_EUR
                + (self.ip_count.saturating_sub(1) * ADDITIONAL_DEDICATED_IP_MONTHLY_EUR)
        }
    }

    pub fn assign_ip(&mut self, ip: IpAssignment) {
        self.assigned_ips.push(ip);
        self.ip_count = self.assigned_ips.len() as u32;
        self.total_monthly_eur = self.calculate_fee();
    }

    pub fn fee_for_count(count: u32) -> u32 {
        if count == 0 {
            0
        } else {
            FIRST_DEDICATED_IP_MONTHLY_EUR + (count.saturating_sub(1) * ADDITIONAL_DEDICATED_IP_MONTHLY_EUR)
        }
    }
}

impl Default for DedicatedIpBilling {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpAssignment {
    pub ip_address: String,
    pub pool: String,
    pub assigned_at: DateTime<Utc>,
    pub reverse_dns: Option<String>,
    pub status: IpStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpStatus {
    Provisioning,
    Warming,
    Active,
    Paused,
    Deprovisioning,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EligibilityInput {
    pub monthly_volume: u64,
    pub daily_consistency_score: f64,
    pub transactional_volume_pct: f64,
    pub broadcast_volume_pct: f64,
    pub domain_age_days: i64,
    pub bounce_rate_pct: f64,
    pub complaint_rate_pct: f64,
    pub warmup_capacity_confirmed: bool,
    pub provider_distribution: Vec<String>,
    pub needs_multiple_pools: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EligibilityResult {
    pub eligible: bool,
    pub score: f64,
    pub reasons: Vec<String>,
    pub recommended_ip_count: u32,
    pub estimated_monthly_fee_eur: u32,
}

pub fn check_eligibility(input: &EligibilityInput) -> EligibilityResult {
    let mut reasons = Vec::new();
    let mut passed = 0;
    let total_checks = 8;

    if input.monthly_volume >= ELIGIBILITY_MIN_MONTHLY_VOLUME {
        passed += 1;
    } else {
        reasons.push(format!(
            "Monthly volume ({}) below minimum ({}).",
            input.monthly_volume, ELIGIBILITY_MIN_MONTHLY_VOLUME
        ));
    }

    if input.daily_consistency_score >= 0.7 {
        passed += 1;
    } else {
        reasons.push(format!(
            "Daily consistency score ({:.2}) below threshold 0.70.",
            input.daily_consistency_score
        ));
    }

    if input.transactional_volume_pct >= 50.0 || input.broadcast_volume_pct >= 50.0 {
        passed += 1;
    } else {
        reasons.push("Neither transactional nor broadcast traffic exceeds 50% threshold.".into());
    }

    if input.domain_age_days >= 90 {
        passed += 1;
    } else {
        reasons.push(format!(
            "Domain age ({} days) below minimum 90 days.",
            input.domain_age_days
        ));
    }

    if input.bounce_rate_pct <= 5.0 {
        passed += 1;
    } else {
        reasons.push(format!(
            "Bounce rate ({:.1}%) exceeds 5.0% maximum.",
            input.bounce_rate_pct
        ));
    }

    if input.complaint_rate_pct <= 0.1 {
        passed += 1;
    } else {
        reasons.push(format!(
            "Complaint rate ({:.2}%) exceeds 0.10% maximum.",
            input.complaint_rate_pct
        ));
    }

    if input.warmup_capacity_confirmed {
        passed += 1;
    } else {
        reasons.push("Customer warm-up capacity not confirmed.".into());
    }

    if !input.provider_distribution.is_empty() {
        passed += 1;
    } else {
        reasons.push("No provider distribution data available.".into());
    }

    let score = (passed as f64) / (total_checks as f64);
    let eligible = score >= 1.0;

    let recommended = if input.needs_multiple_pools { 2 } else { 1 };

    EligibilityResult {
        eligible,
        score,
        reasons,
        recommended_ip_count: recommended,
        estimated_monthly_fee_eur: DedicatedIpBilling::fee_for_count(recommended),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarmupPlan {
    pub ip_address: String,
    pub total_days: u32,
    pub current_day: u32,
    pub paused: bool,
    pub rollback_day: Option<u32>,
    pub daily_targets: Vec<WarmupDay>,
    pub throttle_by_provider: bool,
    pub fallback_to_shared_pool: bool,
    pub alerts_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarmupDay {
    pub day: u32,
    pub target_volume: u64,
    pub actual_volume: Option<u64>,
    pub provider_throttles: Vec<ProviderThrottle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderThrottle {
    pub provider: String,
    pub max_daily: u64,
}

impl WarmupPlan {
    pub fn new(ip_address: &str, total_days: u32, starting_daily_volume: u64, providers: Vec<String>) -> Self {
        let daily_targets: Vec<WarmupDay> = (1..=total_days)
            .map(|day| {
                let target = if day <= 7 {
                    starting_daily_volume
                } else if day <= 14 {
                    starting_daily_volume * 2
                } else if day <= 21 {
                    starting_daily_volume * 4
                } else {
                    starting_daily_volume * 8
                };
                let throttles = providers
                    .iter()
                    .map(|p| ProviderThrottle {
                        provider: p.clone(),
                        max_daily: target / providers.len().max(1) as u64,
                    })
                    .collect();
                WarmupDay {
                    day,
                    target_volume: target,
                    actual_volume: None,
                    provider_throttles: throttles,
                }
            })
            .collect();

        Self {
            ip_address: ip_address.to_string(),
            total_days,
            current_day: 0,
            paused: false,
            rollback_day: None,
            daily_targets,
            throttle_by_provider: true,
            fallback_to_shared_pool: true,
            alerts_enabled: true,
        }
    }

    pub fn advance_day(&mut self) -> bool {
        if self.paused || self.current_day >= self.total_days {
            return false;
        }
        self.current_day += 1;
        true
    }

    pub fn pause(&mut self) {
        self.paused = true;
    }

    pub fn resume(&mut self) {
        self.paused = false;
    }

    pub fn rollback(&mut self, to_day: u32) {
        if to_day < self.current_day {
            self.rollback_day = Some(to_day);
            self.current_day = to_day;
            for d in &mut self.daily_targets {
                if d.day > to_day {
                    d.actual_volume = None;
                }
            }
        }
    }

    pub fn record_actual(&mut self, day: u32, volume: u64) {
        if let Some(target) = self.daily_targets.iter_mut().find(|d| d.day == day) {
            target.actual_volume = Some(volume);
        }
    }

    pub fn current_target(&self) -> Option<u64> {
        self.daily_targets
            .get(self.current_day as usize)
            .map(|d| d.target_volume)
    }

    pub fn is_warmup_complete(&self) -> bool {
        self.current_day >= self.total_days
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpDashboard {
    pub ip_address: String,
    pub pool: String,
    pub reverse_dns: Option<String>,
    pub assigned_domains: Vec<String>,
    pub current_stream: Option<String>,
    pub warmup_status: IpStatus,
    pub warmup_day: Option<u32>,
    pub warmup_total_days: Option<u32>,
    pub provider_distribution: Vec<ProviderMetrics>,
    pub blocks: u64,
    pub deferrals: u64,
    pub complaint_rate_pct: f64,
    pub blocklist_status: Vec<BlocklistEntry>,
    pub feedback_loop_status: bool,
    pub recommended_action: Option<String>,
    pub last_checked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderMetrics {
    pub provider: String,
    pub messages_sent: u64,
    pub delivered: u64,
    pub opens: u64,
    pub clicks: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistEntry {
    pub list_name: String,
    pub listed: bool,
    pub listed_since: Option<DateTime<Utc>>,
    pub delist_url: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pricing_first_ip_49_eur() {
        assert_eq!(DedicatedIpBilling::fee_for_count(1), 49);
    }

    #[test]
    fn test_pricing_two_ips_118_eur() {
        assert_eq!(DedicatedIpBilling::fee_for_count(2), 49 + 69);
    }

    #[test]
    fn test_pricing_three_ips_187_eur() {
        assert_eq!(DedicatedIpBilling::fee_for_count(3), 49 + 69 + 69);
    }

    #[test]
    fn test_pricing_zero_ips() {
        assert_eq!(DedicatedIpBilling::fee_for_count(0), 0);
    }

    #[test]
    fn test_assign_ip_updates_count_and_fee() {
        let mut billing = DedicatedIpBilling::new();
        billing.assign_ip(IpAssignment {
            ip_address: "192.0.2.1".to_string(),
            pool: "dedicated-pool-1".to_string(),
            assigned_at: Utc::now(),
            reverse_dns: Some("mail.example.com".to_string()),
            status: IpStatus::Provisioning,
        });
        assert_eq!(billing.ip_count, 1);
        assert_eq!(billing.total_monthly_eur, 49);

        billing.assign_ip(IpAssignment {
            ip_address: "192.0.2.2".to_string(),
            pool: "dedicated-pool-2".to_string(),
            assigned_at: Utc::now(),
            reverse_dns: Some("mail2.example.com".to_string()),
            status: IpStatus::Provisioning,
        });
        assert_eq!(billing.ip_count, 2);
        assert_eq!(billing.total_monthly_eur, 49 + 69);
    }

    #[test]
    fn test_eligibility_passes_when_all_checks_met() {
        let input = EligibilityInput {
            monthly_volume: 150_000,
            daily_consistency_score: 0.85,
            transactional_volume_pct: 60.0,
            broadcast_volume_pct: 40.0,
            domain_age_days: 180,
            bounce_rate_pct: 2.0,
            complaint_rate_pct: 0.05,
            warmup_capacity_confirmed: true,
            provider_distribution: vec!["gmail".into(), "outlook".into()],
            needs_multiple_pools: false,
        };
        let result = check_eligibility(&input);
        assert!(result.eligible);
        assert_eq!(result.recommended_ip_count, 1);
        assert_eq!(result.estimated_monthly_fee_eur, 49);
        assert!(result.reasons.is_empty());
    }

    #[test]
    fn test_eligibility_fails_low_volume() {
        let input = EligibilityInput {
            monthly_volume: 10_000,
            daily_consistency_score: 0.85,
            transactional_volume_pct: 60.0,
            broadcast_volume_pct: 40.0,
            domain_age_days: 180,
            bounce_rate_pct: 2.0,
            complaint_rate_pct: 0.05,
            warmup_capacity_confirmed: true,
            provider_distribution: vec!["gmail".into()],
            needs_multiple_pools: false,
        };
        let result = check_eligibility(&input);
        assert!(!result.eligible);
        assert!(!result.reasons.is_empty());
    }

    #[test]
    fn test_warmup_plan_advance_and_complete() {
        let plan = WarmupPlan::new("192.0.2.10", 28, 500, vec!["gmail".into(), "outlook".into()]);
        assert_eq!(plan.total_days, 28);
        assert_eq!(plan.current_day, 0);
        assert!(!plan.is_warmup_complete());
        assert_eq!(plan.daily_targets.len(), 28);
    }

    #[test]
    fn test_warmup_pause_and_resume() {
        let mut plan = WarmupPlan::new("192.0.2.10", 5, 100, vec!["gmail".into()]);
        plan.pause();
        assert!(plan.paused);
        let advanced = plan.advance_day();
        assert!(!advanced);
        plan.resume();
        assert!(!plan.paused);
        let advanced = plan.advance_day();
        assert!(advanced);
        assert_eq!(plan.current_day, 1);
    }

    #[test]
    fn test_warmup_rollback() {
        let mut plan = WarmupPlan::new("192.0.2.10", 10, 100, vec!["gmail".into()]);
        for _ in 0..5 {
            plan.advance_day();
        }
        assert_eq!(plan.current_day, 5);
        plan.rollback(2);
        assert_eq!(plan.current_day, 2);
        assert_eq!(plan.rollback_day, Some(2));
    }

    #[test]
    fn test_ip_dashboard_creation() {
        let dashboard = IpDashboard {
            ip_address: "203.0.113.1".to_string(),
            pool: "eu-west-1".to_string(),
            reverse_dns: Some("mail.apexmail.ee".to_string()),
            assigned_domains: vec!["example.com".to_string()],
            current_stream: Some("transactional".to_string()),
            warmup_status: IpStatus::Warming,
            warmup_day: Some(7),
            warmup_total_days: Some(28),
            provider_distribution: vec![ProviderMetrics {
                provider: "gmail".to_string(),
                messages_sent: 5_000,
                delivered: 4_950,
                opens: 1_200,
                clicks: 300,
            }],
            blocks: 0,
            deferrals: 10,
            complaint_rate_pct: 0.02,
            blocklist_status: vec![BlocklistEntry {
                list_name: "Spamhaus".to_string(),
                listed: false,
                listed_since: None,
                delist_url: None,
            }],
            feedback_loop_status: true,
            recommended_action: None,
            last_checked_at: Utc::now(),
        };
        assert_eq!(dashboard.blocks, 0);
        assert_eq!(dashboard.complaint_rate_pct, 0.02);
        assert_eq!(dashboard.warmup_day, Some(7));
    }
}
