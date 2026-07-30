use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingControlsConfig {
    pub alert_at_50_pct: bool,
    pub alert_at_80_pct: bool,
    pub alert_at_100_pct: bool,
    pub alert_at_projected_125_pct: bool,
    pub hard_spending_limit: Option<SpendingLimit>,
    pub hard_sending_limit: Option<HardSendingLimit>,
    pub auto_upgrade: AutoUpgradeConfig,
    pub email_notifications: bool,
    pub webhook_notifications: bool,
    pub notify_billing_contacts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingLimit {
    pub enabled: bool,
    pub monthly_limit_eur_cents: i64,
    pub action_on_limit: SpendingLimitAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendingLimitAction {
    BlockNewMessages,
    AllowInFlight,
    NotifyOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardSendingLimit {
    pub enabled: bool,
    pub daily_limit: Option<i64>,
    pub monthly_limit: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoUpgradeConfig {
    pub enabled: bool,
    pub target_plan: Option<String>,
    pub max_upgrade_plan: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingStatus {
    pub current_usage: SpendingUsage,
    pub alerts: Vec<SpendingAlert>,
    pub estimated_invoice: EstimatedInvoice,
    pub projected_month_end: ProjectedInvoice,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingUsage {
    pub included_recipients: i64,
    pub current_recipients: i64,
    pub overage_recipients: i64,
    pub overage_rate_cents_per_1000: i64,
    pub overage_cost_eur_cents: i64,
    pub base_plan_cost_eur_cents: i64,
    pub dedicated_ip_cost_eur_cents: i64,
    pub active_discount_pct: f64,
    pub active_discount_amount_eur_cents: i64,
    pub credits_eur_cents: i64,
    pub tax_estimate_eur_cents: i64,
    pub total_estimated_eur_cents: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EstimatedInvoice {
    pub base_plan_eur_cents: i64,
    pub overage_eur_cents: i64,
    pub add_ons_eur_cents: i64,
    pub discounts_eur_cents: i64,
    pub credits_applied_eur_cents: i64,
    pub subtotal_eur_cents: i64,
    pub tax_eur_cents: i64,
    pub total_eur_cents: i64,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectedInvoice {
    pub projected_recipients: i64,
    pub projected_overage_eur_cents: i64,
    pub projected_total_eur_cents: i64,
    pub confidence: ProjectionConfidence,
    pub projection_basis: String,
    pub projected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingAlert {
    pub alert_type: SpendingAlertType,
    pub threshold_pct: f64,
    pub current_usage_pct: f64,
    pub message: String,
    pub triggered_at: DateTime<Utc>,
    pub acknowledged: bool,
    pub notification_channels: Vec<NotificationChannel>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendingAlertType {
    Usage50Pct,
    Usage80Pct,
    Usage100Pct,
    Projected125Pct,
    SpendingLimitReached,
    SendingLimitReached,
    AutoUpgradeTriggered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationChannel {
    Email,
    Dashboard,
    Webhook,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverageRate {
    pub plan: String,
    pub rate_cents_per_1000: i64,
    pub automatic_overage: bool,
}

pub struct SpendingController {
    configs: HashMap<String, SpendingControlsConfig>,
    overage_rates: HashMap<String, OverageRate>,
}

impl SpendingController {
    pub fn new() -> Self {
        Self {
            configs: HashMap::new(),
            overage_rates: HashMap::new(),
        }
    }

    pub fn set_config(&mut self, customer_id: &str, config: SpendingControlsConfig) {
        self.configs.insert(customer_id.into(), config);
    }

    pub fn get_config(&self, customer_id: &str) -> Option<&SpendingControlsConfig> {
        self.configs.get(customer_id)
    }

    pub fn evaluate_alerts(
        &self,
        customer_id: &str,
        usage: &SpendingUsage,
    ) -> Vec<SpendingAlert> {
        let config = match self.configs.get(customer_id) {
            Some(c) => c,
            None => return vec![],
        };

        let mut alerts = Vec::new();
        let now = Utc::now();

        let total_before_credits = usage.base_plan_cost_eur_cents
            + usage.overage_cost_eur_cents
            + usage.dedicated_ip_cost_eur_cents;
        let effective_total = (total_before_credits - usage.credits_eur_cents).max(0);

        if let Some(ref limit) = config.hard_spending_limit {
            if limit.enabled && effective_total >= limit.monthly_limit_eur_cents {
                alerts.push(SpendingAlert {
                    alert_type: SpendingAlertType::SpendingLimitReached,
                    threshold_pct: 100.0,
                    current_usage_pct: (effective_total as f64 / limit.monthly_limit_eur_cents as f64) * 100.0,
                    message: format!(
                        "Hard spending limit of €{:.2} reached. Current spend: €{:.2}.",
                        limit.monthly_limit_eur_cents as f64 / 100.0,
                        effective_total as f64 / 100.0
                    ),
                    triggered_at: now,
                    acknowledged: false,
                    notification_channels: vec![NotificationChannel::Email, NotificationChannel::Dashboard],
                });
            }
        }

        if config.alert_at_100_pct && usage.included_recipients > 0 {
            let pct = usage.current_recipients as f64 / usage.included_recipients as f64 * 100.0;
            if pct >= 100.0 {
                alerts.push(SpendingAlert {
                    alert_type: SpendingAlertType::Usage100Pct,
                    threshold_pct: 100.0,
                    current_usage_pct: pct,
                    message: format!(
                        "Usage has reached {:.0}% of included {} recipients. Overage charges now apply.",
                        pct, usage.included_recipients
                    ),
                    triggered_at: now,
                    acknowledged: false,
                    notification_channels: vec![
                        NotificationChannel::Email,
                        NotificationChannel::Dashboard,
                        NotificationChannel::Webhook,
                    ],
                });
            }
        }

        if config.alert_at_80_pct && usage.included_recipients > 0 {
            let pct = usage.current_recipients as f64 / usage.included_recipients as f64 * 100.0;
            if pct >= 80.0 && pct < 100.0 {
                alerts.push(SpendingAlert {
                    alert_type: SpendingAlertType::Usage80Pct,
                    threshold_pct: 80.0,
                    current_usage_pct: pct,
                    message: format!(
                        "Usage at {:.0}% of included {} recipients. Consider adjusting limits.",
                        pct, usage.included_recipients
                    ),
                    triggered_at: now,
                    acknowledged: false,
                    notification_channels: vec![
                        NotificationChannel::Email,
                        NotificationChannel::Dashboard,
                    ],
                });
            }
        }

        if config.alert_at_50_pct && usage.included_recipients > 0 {
            let pct = usage.current_recipients as f64 / usage.included_recipients as f64 * 100.0;
            if pct >= 50.0 && pct < 80.0 {
                alerts.push(SpendingAlert {
                    alert_type: SpendingAlertType::Usage50Pct,
                    threshold_pct: 50.0,
                    current_usage_pct: pct,
                    message: format!(
                        "Usage at {:.0}% of included {} recipients.",
                        pct, usage.included_recipients
                    ),
                    triggered_at: now,
                    acknowledged: false,
                    notification_channels: vec![NotificationChannel::Dashboard],
                });
            }
        }

        alerts
    }

    pub fn evaluate_projected_alert(
        &self,
        customer_id: &str,
        usage: &SpendingUsage,
        projected: &ProjectedInvoice,
    ) -> Option<SpendingAlert> {
        let config = self.configs.get(customer_id)?;

        if config.alert_at_projected_125_pct && usage.included_recipients > 0 {
            let proj_pct = projected.projected_recipients as f64 / usage.included_recipients as f64 * 100.0;
            if proj_pct >= 125.0 {
                return Some(SpendingAlert {
                    alert_type: SpendingAlertType::Projected125Pct,
                    threshold_pct: 125.0,
                    current_usage_pct: usage.current_recipients as f64 / usage.included_recipients as f64 * 100.0,
                    message: format!(
                        "Projected month-end usage at {:.0}% of included {} recipients. Estimated overage: €{:.2}.",
                        proj_pct,
                        usage.included_recipients,
                        projected.projected_overage_eur_cents as f64 / 100.0
                    ),
                    triggered_at: Utc::now(),
                    acknowledged: false,
                    notification_channels: vec![
                        NotificationChannel::Email,
                        NotificationChannel::Dashboard,
                        NotificationChannel::Webhook,
                    ],
                });
            }
        }

        None
    }

    pub fn check_sending_limit(
        &self,
        customer_id: &str,
        current_daily: i64,
        current_monthly: i64,
    ) -> Result<(), SendingLimitBlock> {
        let config = match self.configs.get(customer_id) {
            Some(c) => c,
            None => return Ok(()),
        };

        if let Some(ref send_limit) = config.hard_sending_limit {
            if send_limit.enabled {
                if let Some(daily) = send_limit.daily_limit {
                    if current_daily >= daily {
                        return Err(SendingLimitBlock {
                            limit_type: "daily".into(),
                            current: current_daily,
                            limit: daily,
                            message: format!(
                                "Daily sending limit of {} reached. Current: {}.",
                                daily, current_daily
                            ),
                        });
                    }
                }
                if let Some(monthly) = send_limit.monthly_limit {
                    if current_monthly >= monthly {
                        return Err(SendingLimitBlock {
                            limit_type: "monthly".into(),
                            current: current_monthly,
                            limit: monthly,
                            message: format!(
                                "Monthly sending limit of {} reached. Current: {}.",
                                monthly, current_monthly
                            ),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    pub fn check_spending_before_accept(
        &self,
        customer_id: &str,
        plan: &str,
        usage: &SpendingUsage,
    ) -> Result<(), SpendingBlock> {
        let config = match self.configs.get(customer_id) {
            Some(c) => c,
            None => return Ok(()),
        };

        let overage_rate = self.get_overage_rate(plan);

        if let Some(rate) = overage_rate {
            if !rate.automatic_overage && usage.overage_recipients > 0 {
                return Err(SpendingBlock {
                    reason: SpendingBlockReason::OverageNotAllowed,
                    message: format!(
                        "Plan {} does not permit automatic overage. Please upgrade or contact support.",
                        rate.plan
                    ),
                    required_action: Some("Upgrade plan or add spending limit".into()),
                });
            }
        }

        if let Some(ref limit) = config.hard_spending_limit {
            if limit.enabled {
                let total = usage.total_estimated_eur_cents;
                if total >= limit.monthly_limit_eur_cents {
                    return match limit.action_on_limit {
                        SpendingLimitAction::BlockNewMessages => Err(SpendingBlock {
                            reason: SpendingBlockReason::SpendingLimitExceeded,
                            message: format!(
                                "Hard spending limit of €{:.2} reached. New messages are blocked.",
                                limit.monthly_limit_eur_cents as f64 / 100.0
                            ),
                            required_action: Some("Increase spending limit or wait until next billing period".into()),
                        }),
                        SpendingLimitAction::NotifyOnly | SpendingLimitAction::AllowInFlight => Ok(()),
                    };
                }
            }
        }

        Ok(())
    }

    pub fn should_auto_upgrade(&self, customer_id: &str, usage: &SpendingUsage) -> Option<String> {
        let config = self.configs.get(customer_id)?;
        if !config.auto_upgrade.enabled {
            return None;
        }
        if let Some(ref target) = config.auto_upgrade.target_plan {
            if usage.current_recipients > usage.included_recipients {
                return Some(target.clone());
            }
        }
        None
    }

    pub fn get_overage_rate(&self, plan: &str) -> Option<&OverageRate> {
        self.overage_rates.get(plan)
    }

    pub fn calculate_invoice(
        &self,
        usage: &SpendingUsage,
        plan_base_cost_cents: i64,
    ) -> EstimatedInvoice {
        let now = Utc::now();
        let subtotal = plan_base_cost_cents + usage.overage_cost_eur_cents + usage.dedicated_ip_cost_eur_cents;
        let after_discounts = subtotal - usage.active_discount_amount_eur_cents;
        let after_credits = (after_discounts - usage.credits_eur_cents).max(0);
        let tax = ((after_credits as f64) * 0.22) as i64;

        EstimatedInvoice {
            base_plan_eur_cents: plan_base_cost_cents,
            overage_eur_cents: usage.overage_cost_eur_cents,
            add_ons_eur_cents: usage.dedicated_ip_cost_eur_cents,
            discounts_eur_cents: usage.active_discount_amount_eur_cents,
            credits_applied_eur_cents: usage.credits_eur_cents.min(after_discounts),
            subtotal_eur_cents: after_credits,
            tax_eur_cents: tax,
            total_eur_cents: after_credits + tax,
            period_start: now,
            period_end: now,
            generated_at: now,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendingLimitBlock {
    pub limit_type: String,
    pub current: i64,
    pub limit: i64,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingBlock {
    pub reason: SpendingBlockReason,
    pub message: String,
    pub required_action: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendingBlockReason {
    SpendingLimitExceeded,
    OverageNotAllowed,
    AbuseReviewRequired,
    AccountSuspended,
}

pub fn seed_spending_controller() -> SpendingController {
    let mut controller = SpendingController::new();

    controller.overage_rates.insert("free".into(), OverageRate {
        plan: "free".into(),
        rate_cents_per_1000: 0,
        automatic_overage: false,
    });
    controller.overage_rates.insert("developer".into(), OverageRate {
        plan: "developer".into(),
        rate_cents_per_1000: 80,
        automatic_overage: true,
    });
    controller.overage_rates.insert("pro".into(), OverageRate {
        plan: "pro".into(),
        rate_cents_per_1000: 60,
        automatic_overage: true,
    });
    controller.overage_rates.insert("growth".into(), OverageRate {
        plan: "growth".into(),
        rate_cents_per_1000: 35,
        automatic_overage: true,
    });
    controller.overage_rates.insert("business".into(), OverageRate {
        plan: "business".into(),
        rate_cents_per_1000: 35,
        automatic_overage: true,
    });
    controller.overage_rates.insert("enterprise".into(), OverageRate {
        plan: "enterprise".into(),
        rate_cents_per_1000: 35,
        automatic_overage: true,
    });

    controller
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> SpendingControlsConfig {
        SpendingControlsConfig {
            alert_at_50_pct: true,
            alert_at_80_pct: true,
            alert_at_100_pct: true,
            alert_at_projected_125_pct: true,
            hard_spending_limit: None,
            hard_sending_limit: None,
            auto_upgrade: AutoUpgradeConfig {
                enabled: false,
                target_plan: None,
                max_upgrade_plan: None,
            },
            email_notifications: true,
            webhook_notifications: true,
            notify_billing_contacts: vec![],
        }
    }

    fn low_usage() -> SpendingUsage {
        SpendingUsage {
            included_recipients: 50_000,
            current_recipients: 5_000,
            overage_recipients: 0,
            overage_rate_cents_per_1000: 80,
            overage_cost_eur_cents: 0,
            base_plan_cost_eur_cents: 2900,
            dedicated_ip_cost_eur_cents: 0,
            active_discount_pct: 0.0,
            active_discount_amount_eur_cents: 0,
            credits_eur_cents: 0,
            tax_estimate_eur_cents: 0,
            total_estimated_eur_cents: 2900,
        }
    }

    fn at_80_pct_usage() -> SpendingUsage {
        SpendingUsage {
            included_recipients: 50_000,
            current_recipients: 40_000,
            overage_recipients: 0,
            overage_rate_cents_per_1000: 80,
            overage_cost_eur_cents: 0,
            base_plan_cost_eur_cents: 2900,
            dedicated_ip_cost_eur_cents: 0,
            active_discount_pct: 0.0,
            active_discount_amount_eur_cents: 0,
            credits_eur_cents: 0,
            tax_estimate_eur_cents: 0,
            total_estimated_eur_cents: 2900,
        }
    }

    fn over_100_pct_usage() -> SpendingUsage {
        SpendingUsage {
            included_recipients: 50_000,
            current_recipients: 60_000,
            overage_recipients: 10_000,
            overage_rate_cents_per_1000: 80,
            overage_cost_eur_cents: 800,
            base_plan_cost_eur_cents: 2900,
            dedicated_ip_cost_eur_cents: 0,
            active_discount_pct: 0.0,
            active_discount_amount_eur_cents: 0,
            credits_eur_cents: 0,
            tax_estimate_eur_cents: 0,
            total_estimated_eur_cents: 3700,
        }
    }

    #[test]
    fn test_no_alerts_low_usage() {
        let controller = seed_spending_controller();
        let mut ctrl = controller;
        ctrl.set_config("cust_1", default_config());
        let alerts = ctrl.evaluate_alerts("cust_1", &low_usage());
        assert!(alerts.is_empty(), "No alerts at 10% usage");
    }

    #[test]
    fn test_80_pct_alert() {
        let mut controller = seed_spending_controller();
        controller.set_config("cust_1", default_config());
        let alerts = controller.evaluate_alerts("cust_1", &at_80_pct_usage());
        assert!(!alerts.is_empty(), "Should have alert at 80%");
        assert!(
            alerts.iter().any(|a| matches!(a.alert_type, SpendingAlertType::Usage80Pct)),
            "Should have 80% alert"
        );
    }

    #[test]
    fn test_100_pct_alert() {
        let mut controller = seed_spending_controller();
        controller.set_config("cust_1", default_config());
        let alerts = controller.evaluate_alerts("cust_1", &over_100_pct_usage());
        assert!(
            alerts.iter().any(|a| matches!(a.alert_type, SpendingAlertType::Usage100Pct)),
            "Should have 100% alert"
        );
    }

    #[test]
    fn test_free_plan_no_overage_allowed() {
        let controller = seed_spending_controller();
        let free_usage = SpendingUsage {
            included_recipients: 3_000,
            current_recipients: 3_500,
            overage_recipients: 500,
            overage_rate_cents_per_1000: 0,
            overage_cost_eur_cents: 0,
            base_plan_cost_eur_cents: 0,
            dedicated_ip_cost_eur_cents: 0,
            active_discount_pct: 0.0,
            active_discount_amount_eur_cents: 0,
            credits_eur_cents: 0,
            tax_estimate_eur_cents: 0,
            total_estimated_eur_cents: 0,
        };

        let mut ctrl = controller;
        ctrl.set_config("free_cust", SpendingControlsConfig {
            hard_spending_limit: None,
            ..default_config()
        });

        let result = ctrl.check_spending_before_accept("free_cust", "free", &free_usage);
        assert!(result.is_err(), "Free plan should block overage");
    }

    #[test]
    fn test_hard_spending_limit_blocks() {
        let mut controller = seed_spending_controller();
        controller.set_config("cust_1", SpendingControlsConfig {
            hard_spending_limit: Some(SpendingLimit {
                enabled: true,
                monthly_limit_eur_cents: 5000,
                action_on_limit: SpendingLimitAction::BlockNewMessages,
            }),
            ..default_config()
        });

        let high_spend = SpendingUsage {
            included_recipients: 50_000,
            current_recipients: 60_000,
            overage_recipients: 10_000,
            overage_rate_cents_per_1000: 80,
            overage_cost_eur_cents: 800,
            base_plan_cost_eur_cents: 5000,
            dedicated_ip_cost_eur_cents: 4900,
            active_discount_pct: 0.0,
            active_discount_amount_eur_cents: 0,
            credits_eur_cents: 0,
            tax_estimate_eur_cents: 0,
            total_estimated_eur_cents: 10700,
        };

        let result = controller.check_spending_before_accept("cust_1", "developer", &high_spend);
        assert!(result.is_err(), "Should block when spending limit exceeded");
    }

    #[test]
    fn test_auto_upgrade_triggered() {
        let mut controller = seed_spending_controller();
        controller.set_config("cust_1", SpendingControlsConfig {
            auto_upgrade: AutoUpgradeConfig {
                enabled: true,
                target_plan: Some("pro".into()),
                max_upgrade_plan: Some("growth".into()),
            },
            ..default_config()
        });

        let result = controller.should_auto_upgrade("cust_1", &over_100_pct_usage());
        assert_eq!(result, Some("pro".into()));
    }

    #[test]
    fn test_sending_limit_enforced() {
        let mut controller = seed_spending_controller();
        controller.set_config("cust_1", SpendingControlsConfig {
            hard_sending_limit: Some(HardSendingLimit {
                enabled: true,
                daily_limit: Some(1000),
                monthly_limit: Some(10000),
            }),
            ..default_config()
        });

        let result = controller.check_sending_limit("cust_1", 1000, 5000);
        assert!(result.is_err(), "Should block when daily limit reached");
    }

    #[test]
    fn test_invoice_calculation() {
        let controller = seed_spending_controller();
        let usage = SpendingUsage {
            included_recipients: 150_000,
            current_recipients: 200_000,
            overage_recipients: 50_000,
            overage_rate_cents_per_1000: 60,
            overage_cost_eur_cents: 3000,
            base_plan_cost_eur_cents: 8900,
            dedicated_ip_cost_eur_cents: 4900,
            active_discount_pct: 10.0,
            active_discount_amount_eur_cents: 890,
            credits_eur_cents: 500,
            tax_estimate_eur_cents: 0,
            total_estimated_eur_cents: 16410,
        };

        let invoice = controller.calculate_invoice(&usage, 8900);
        assert!(invoice.total_eur_cents > 0, "Invoice total should be positive");
        assert_eq!(invoice.base_plan_eur_cents, 8900);
        assert_eq!(invoice.overage_eur_cents, 3000);
        assert_eq!(invoice.add_ons_eur_cents, 4900);

        let subtotal = 8900 + 3000 + 4900 - 890 - 500;
        assert_eq!(invoice.subtotal_eur_cents, subtotal);
    }

    #[test]
    fn test_50_pct_alert() {
        let mut controller = seed_spending_controller();
        controller.set_config("cust_1", default_config());
        let mid = SpendingUsage {
            included_recipients: 50_000,
            current_recipients: 25_000,
            overage_recipients: 0,
            overage_rate_cents_per_1000: 80,
            overage_cost_eur_cents: 0,
            base_plan_cost_eur_cents: 2900,
            dedicated_ip_cost_eur_cents: 0,
            active_discount_pct: 0.0,
            active_discount_amount_eur_cents: 0,
            credits_eur_cents: 0,
            tax_estimate_eur_cents: 0,
            total_estimated_eur_cents: 2900,
        };

        let alerts = controller.evaluate_alerts("cust_1", &mid);
        assert!(
            alerts.iter().any(|a| matches!(a.alert_type, SpendingAlertType::Usage50Pct)),
            "Should have 50% alert at exactly 50%"
        );
    }

    #[test]
    fn test_projected_125_alert() {
        let mut controller = seed_spending_controller();
        controller.set_config("cust_1", default_config());

        let usage = SpendingUsage {
            included_recipients: 50_000,
            current_recipients: 30_000,
            overage_recipients: 0,
            overage_rate_cents_per_1000: 80,
            overage_cost_eur_cents: 0,
            base_plan_cost_eur_cents: 2900,
            dedicated_ip_cost_eur_cents: 0,
            active_discount_pct: 0.0,
            active_discount_amount_eur_cents: 0,
            credits_eur_cents: 0,
            tax_estimate_eur_cents: 0,
            total_estimated_eur_cents: 2900,
        };

        let projected = ProjectedInvoice {
            projected_recipients: 70_000,
            projected_overage_eur_cents: 1600,
            projected_total_eur_cents: 4500,
            confidence: ProjectionConfidence::High,
            projection_basis: "Current daily rate extrapolated to month end".into(),
            projected_at: Utc::now(),
        };

        let alert = controller.evaluate_projected_alert("cust_1", &usage, &projected);
        assert!(alert.is_some(), "Should alert at projected 140%");
        assert!(matches!(alert.unwrap().alert_type, SpendingAlertType::Projected125Pct));
    }

    #[test]
    fn test_overage_rates_seeded() {
        let controller = seed_spending_controller();
        assert_eq!(controller.get_overage_rate("free").unwrap().rate_cents_per_1000, 0);
        assert_eq!(controller.get_overage_rate("developer").unwrap().rate_cents_per_1000, 80);
        assert_eq!(controller.get_overage_rate("pro").unwrap().rate_cents_per_1000, 60);
        assert_eq!(controller.get_overage_rate("growth").unwrap().rate_cents_per_1000, 35);
        assert_eq!(controller.get_overage_rate("business").unwrap().rate_cents_per_1000, 35);
        assert!(!controller.get_overage_rate("free").unwrap().automatic_overage);
        assert!(controller.get_overage_rate("developer").unwrap().automatic_overage);
    }
}
