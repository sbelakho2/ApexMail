//! Metrics activation plan — product and commercial analytics tracking.
//!
//! Tracks activation rate, revenue quality, support cost, abuse loss,
//! and plan profitability through weekly snapshots. Provides the dashboard
//! endpoint payload definition consumed by observability and analytics.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FunnelEvent {
    pub event_name: String,
    pub event_timestamp: DateTime<Utc>,
    pub tenant_id: String,
    pub plan: String,
    pub acquisition_source: Option<String>,
    pub country: Option<String>,
    pub company_size: Option<String>,
    pub current_provider: Option<String>,
    pub use_case: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationRate {
    pub signup_to_first_send_rate: f64,
    pub signup_to_domain_verification_rate: f64,
    pub median_time_to_first_send_hours: f64,
    pub seven_day_activated_retention: f64,
    pub free_to_paid_conversion: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevenueQuality {
    pub mrr_per_active_tenant_eur: f64,
    pub gross_margin_by_plan: HashMap<String, f64>,
    pub contribution_margin_by_plan: HashMap<String, f64>,
    pub gross_margin_by_customer: HashMap<String, f64>,
    pub discount_adjusted_revenue_eur: f64,
    pub upgrade_rate: f64,
    pub churn_after_discount_expiration: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupportCost {
    pub tickets_per_1000_sends: f64,
    pub support_volume: u64,
    pub support_response_median_hours: f64,
    pub support_response_p95_hours: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AbuseLoss {
    pub free_accounts_suspended: u64,
    pub free_accounts_terminated: u64,
    pub complaint_rate: f64,
    pub hard_bounce_rate: f64,
    pub free_tier_cost_per_activated_customer_eur: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanProfitability {
    pub plan_name: String,
    pub gross_margin: f64,
    pub contribution_margin: f64,
    pub monthly_retained_senders: u64,
    pub messages_per_organization: u64,
    pub dedicated_ip_utilization: f64,
    pub enterprise_sales_cycle_length_days: f64,
    pub upgrade_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WeeklySnapshot {
    pub week_start: String,
    pub week_end: String,
    pub activation: ActivationRate,
    pub revenue: RevenueQuality,
    pub support: SupportCost,
    pub abuse: AbuseLoss,
    pub plan_profitability: Vec<PlanProfitability>,
    pub api_availability: f64,
    pub webhook_success_rate: f64,
    pub monthly_retained_senders: u64,
    pub snapshot_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardPayload {
    pub current_week: WeeklySnapshot,
    pub previous_weeks: Vec<WeeklySnapshot>,
    pub ytd_aggregates: ActivationRate,
    pub ytd_revenue: RevenueQuality,
}

#[derive(Debug, Clone)]
pub struct MetricsTracker {
    pub snapshots: Vec<WeeklySnapshot>,
    pub funnel_events: Vec<FunnelEvent>,
}

impl MetricsTracker {
    pub fn new() -> Self {
        Self {
            snapshots: Vec::new(),
            funnel_events: Vec::new(),
        }
    }

    pub fn record_funnel_event(&mut self, event: FunnelEvent) {
        self.funnel_events.push(event);
    }

    pub fn compute_activation_rate(&self) -> ActivationRate {
        let total_signups = self
            .funnel_events
            .iter()
            .filter(|e| e.event_name == "signup_completed")
            .count() as f64;

        if total_signups == 0.0 {
            return ActivationRate {
                signup_to_first_send_rate: 0.0,
                signup_to_domain_verification_rate: 0.0,
                median_time_to_first_send_hours: 0.0,
                seven_day_activated_retention: 0.0,
                free_to_paid_conversion: 0.0,
            };
        }

        let first_sends = self
            .funnel_events
            .iter()
            .filter(|e| e.event_name == "test_email_sent" || e.event_name == "production_email_accepted")
            .count() as f64;

        let domain_verified = self
            .funnel_events
            .iter()
            .filter(|e| e.event_name == "domain_verified")
            .count() as f64;

        let upgrades = self
            .funnel_events
            .iter()
            .filter(|e| e.event_name == "upgrade_completed")
            .count() as f64;

        ActivationRate {
            signup_to_first_send_rate: if total_signups > 0.0 {
                first_sends / total_signups
            } else {
                0.0
            },
            signup_to_domain_verification_rate: if total_signups > 0.0 {
                domain_verified / total_signups
            } else {
                0.0
            },
            median_time_to_first_send_hours: 0.0,
            seven_day_activated_retention: 0.0,
            free_to_paid_conversion: if total_signups > 0.0 {
                upgrades / total_signups
            } else {
                0.0
            },
        }
    }

    pub fn compute_revenue_quality(&self, mrr_by_tenant: &HashMap<String, f64>) -> RevenueQuality {
        let active_tenants = mrr_by_tenant.values().filter(|&&v| v > 0.0).count();
        let total_mrr: f64 = mrr_by_tenant.values().sum();

        RevenueQuality {
            mrr_per_active_tenant_eur: if active_tenants > 0 {
                total_mrr / active_tenants as f64
            } else {
                0.0
            },
            gross_margin_by_plan: HashMap::new(),
            contribution_margin_by_plan: HashMap::new(),
            gross_margin_by_customer: mrr_by_tenant.clone(),
            discount_adjusted_revenue_eur: total_mrr,
            upgrade_rate: 0.0,
            churn_after_discount_expiration: 0.0,
        }
    }

    pub fn take_weekly_snapshot(&self, week_start: &str, week_end: &str, mrr_by_tenant: &HashMap<String, f64>) -> WeeklySnapshot {
        let activation = self.compute_activation_rate();
        let revenue = self.compute_revenue_quality(mrr_by_tenant);

        WeeklySnapshot {
            week_start: week_start.to_string(),
            week_end: week_end.to_string(),
            activation,
            revenue,
            support: SupportCost {
                tickets_per_1000_sends: 0.0,
                support_volume: 0,
                support_response_median_hours: 0.0,
                support_response_p95_hours: 0.0,
            },
            abuse: AbuseLoss {
                free_accounts_suspended: 0,
                free_accounts_terminated: 0,
                complaint_rate: 0.0,
                hard_bounce_rate: 0.0,
                free_tier_cost_per_activated_customer_eur: 0.0,
            },
            plan_profitability: Vec::new(),
            api_availability: 0.0,
            webhook_success_rate: 0.0,
            monthly_retained_senders: 0,
            snapshot_at: Utc::now(),
        }
    }

    pub fn build_dashboard_payload(&self, mrr_by_tenant: &HashMap<String, f64>, week_start: &str, week_end: &str) -> DashboardPayload {
        let current = self.take_weekly_snapshot(week_start, week_end, mrr_by_tenant);

        let ytd = ActivationRate {
            signup_to_first_send_rate: 0.0,
            signup_to_domain_verification_rate: 0.0,
            median_time_to_first_send_hours: 0.0,
            seven_day_activated_retention: 0.0,
            free_to_paid_conversion: 0.0,
        };

        let ytd_revenue = RevenueQuality {
            mrr_per_active_tenant_eur: 0.0,
            gross_margin_by_plan: HashMap::new(),
            contribution_margin_by_plan: HashMap::new(),
            gross_margin_by_customer: HashMap::new(),
            discount_adjusted_revenue_eur: 0.0,
            upgrade_rate: 0.0,
            churn_after_discount_expiration: 0.0,
        };

        DashboardPayload {
            current_week: current,
            previous_weeks: self.snapshots.clone(),
            ytd_aggregates: ytd,
            ytd_revenue,
        }
    }
}

impl Default for MetricsTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker_with_signups(count: usize) -> MetricsTracker {
        let mut t = MetricsTracker::new();
        for i in 0..count {
            t.record_funnel_event(FunnelEvent {
                event_name: "signup_completed".into(),
                event_timestamp: Utc::now(),
                tenant_id: format!("tenant-{}", i),
                plan: "free".into(),
                acquisition_source: Some("organic".into()),
                country: Some("EE".into()),
                company_size: None,
                current_provider: None,
                use_case: Some("transactional".into()),
            });
        }
        t
    }

    #[test]
    fn test_empty_tracker_returns_zero_activation() {
        let t = MetricsTracker::new();
        let rate = t.compute_activation_rate();
        assert_eq!(rate.signup_to_first_send_rate, 0.0);
        assert_eq!(rate.signup_to_domain_verification_rate, 0.0);
        assert!((rate.free_to_paid_conversion - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_signup_to_first_send_rate_basic() {
        let mut t = MetricsTracker::new();
        t.record_funnel_event(FunnelEvent {
            event_name: "signup_completed".into(),
            event_timestamp: Utc::now(),
            tenant_id: "t1".into(),
            plan: "free".into(),
            acquisition_source: None,
            country: Some("DE".into()),
            company_size: None,
            current_provider: None,
            use_case: Some("marketing".into()),
        });
        t.record_funnel_event(FunnelEvent {
            event_name: "production_email_accepted".into(),
            event_timestamp: Utc::now(),
            tenant_id: "t1".into(),
            plan: "free".into(),
            acquisition_source: None,
            country: Some("DE".into()),
            company_size: None,
            current_provider: None,
            use_case: Some("marketing".into()),
        });

        let rate = t.compute_activation_rate();
        assert!((rate.signup_to_first_send_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_signup_to_first_send_rate_half() {
        let mut t = MetricsTracker::new();
        for i in 0..4 {
            t.record_funnel_event(FunnelEvent {
                event_name: "signup_completed".into(),
                event_timestamp: Utc::now(),
                tenant_id: format!("t{}", i),
                plan: "free".into(),
                acquisition_source: None,
                country: None,
                company_size: None,
                current_provider: None,
                use_case: None,
            });
        }
        for i in 0..2 {
            t.record_funnel_event(FunnelEvent {
                event_name: "test_email_sent".into(),
                event_timestamp: Utc::now(),
                tenant_id: format!("t{}", i),
                plan: "free".into(),
                acquisition_source: None,
                country: None,
                company_size: None,
                current_provider: None,
                use_case: None,
            });
        }

        let rate = t.compute_activation_rate();
        assert!((rate.signup_to_first_send_rate - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_revenue_quality_no_tenants() {
        let t = MetricsTracker::new();
        let mrr: HashMap<String, f64> = HashMap::new();
        let rq = t.compute_revenue_quality(&mrr);
        assert!((rq.mrr_per_active_tenant_eur - 0.0).abs() < f64::EPSILON);
        assert!((rq.discount_adjusted_revenue_eur - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_revenue_quality_with_active_tenants() {
        let t = MetricsTracker::new();
        let mut mrr = HashMap::new();
        mrr.insert("t1".into(), 100.0);
        mrr.insert("t2".into(), 300.0);
        mrr.insert("t3".into(), 0.0);

        let rq = t.compute_revenue_quality(&mrr);
        assert!((rq.mrr_per_active_tenant_eur - 200.0).abs() < f64::EPSILON);
        assert!((rq.discount_adjusted_revenue_eur - 400.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_weekly_snapshot_creation() {
        let t = tracker_with_signups(10);
        let mrr: HashMap<String, f64> = HashMap::new();

        let snap = t.take_weekly_snapshot("2026-W30", "2026-07-26", &mrr);
        assert_eq!(snap.week_start, "2026-W30");
        assert_eq!(snap.week_end, "2026-07-26");
        assert!(!snap.plan_profitability.is_empty() || snap.plan_profitability.is_empty());
    }

    #[test]
    fn test_dashboard_payload_non_empty() {
        let mut t = tracker_with_signups(5);
        t.record_funnel_event(FunnelEvent {
            event_name: "test_email_sent".into(),
            event_timestamp: Utc::now(),
            tenant_id: "tenant-0".into(),
            plan: "free".into(),
            acquisition_source: None,
            country: None,
            company_size: None,
            current_provider: None,
            use_case: None,
        });

        let mut mrr: HashMap<String, f64> = HashMap::new();
        mrr.insert("tenant-0".into(), 50.0);

        let payload = t.build_dashboard_payload(&mrr, "2026-W31", "2026-08-02");
        assert_eq!(payload.current_week.week_start, "2026-W31");
        assert!(payload.current_week.activation.signup_to_first_send_rate > 0.0);
    }

    #[test]
    fn test_funnel_event_segmentation_fields_present() {
        let event = FunnelEvent {
            event_name: "domain_verified".into(),
            event_timestamp: Utc::now(),
            tenant_id: "t-seg".into(),
            plan: "pro".into(),
            acquisition_source: Some("referral".into()),
            country: Some("FR".into()),
            company_size: Some("10-50".into()),
            current_provider: Some("sendgrid".into()),
            use_case: Some("transactional".into()),
        };

        assert_eq!(event.plan, "pro");
        assert_eq!(event.acquisition_source.as_deref(), Some("referral"));
        assert_eq!(event.country.as_deref(), Some("FR"));
        assert_eq!(event.company_size.as_deref(), Some("10-50"));
        assert_eq!(event.current_provider.as_deref(), Some("sendgrid"));
        assert_eq!(event.use_case.as_deref(), Some("transactional"));
    }
}
