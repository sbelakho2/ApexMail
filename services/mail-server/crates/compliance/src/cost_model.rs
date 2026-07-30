use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostLineItem {
    pub item_id: String,
    pub item_name: String,
    pub category: CostCategory,
    pub monthly_estimate_eur: f64,
    pub unit: CostUnit,
    pub unit_cost_eur: f64,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostCategory {
    Compute,
    Storage,
    Network,
    Monitoring,
    Deliverability,
    Labor,
    PaymentProcessing,
    Risk,
    SalesAndMarketing,
    ComplianceOverhead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostUnit {
    Per1000Recipients,
    PerGbMonth,
    PerMillionWebhookAttempts,
    PerManagedIp,
    PerSupportHour,
    PerDeliverabilityHour,
    PerAbuseCase,
    PerSecurityQuestionnaire,
    PerDedicatedDeployment,
    PerByocDeployment,
    FlatMonthly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductCategory {
    SharedSelfService,
    ManagedHighVolume,
    DedicatedTenant,
    BYOCPrivate,
    ImplementationServices,
    PremiumSupport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarginTarget {
    pub category: ProductCategory,
    pub minimum_pct: f64,
    pub maximum_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomerEconomics {
    pub customer_id: String,
    pub plan: String,
    pub monthly_revenue_eur: f64,
    pub monthly_recipients: i64,
    pub content_storage_gb: f64,
    pub event_storage_gb: f64,
    pub webhook_attempts: i64,
    pub dedicated_ips: i32,
    pub support_hours: f64,
    pub deliverability_hours: f64,
    pub abuse_cases: i32,
    pub security_questionnaires: i32,
}

#[derive(Debug, Clone)]
pub struct CostModel {
    line_items: HashMap<String, CostLineItem>,
    margin_targets: HashMap<ProductCategory, MarginTarget>,
}

impl CostModel {
    pub fn new() -> Self {
        Self {
            line_items: HashMap::new(),
            margin_targets: HashMap::new(),
        }
    }

    pub fn add_line_item(&mut self, item: CostLineItem) {
        self.line_items.insert(item.item_id.clone(), item);
    }

    pub fn add_margin_target(&mut self, target: MarginTarget) {
        self.margin_targets.insert(target.category, target);
    }

    pub fn cost_per_1000_recipients(&self) -> f64 {
        self.line_items
            .values()
            .filter(|i| i.unit == CostUnit::Per1000Recipients)
            .map(|i| i.unit_cost_eur)
            .sum()
    }

    pub fn cost_per_gb_month(&self) -> f64 {
        self.line_items
            .values()
            .filter(|i| i.unit == CostUnit::PerGbMonth)
            .map(|i| i.unit_cost_eur)
            .sum()
    }

    pub fn cost_per_managed_ip(&self) -> f64 {
        self.line_items
            .values()
            .filter(|i| i.unit == CostUnit::PerManagedIp)
            .map(|i| i.unit_cost_eur)
            .sum()
    }

    pub fn cost_per_support_hour(&self) -> f64 {
        self.line_items
            .values()
            .filter(|i| i.unit == CostUnit::PerSupportHour)
            .map(|i| i.unit_cost_eur)
            .sum()
    }

    pub fn total_monthly_fixed_cost(&self) -> f64 {
        self.line_items
            .values()
            .filter(|i| i.unit == CostUnit::FlatMonthly)
            .map(|i| i.unit_cost_eur)
            .sum()
    }

    pub fn total_monthly_variable_cost(&self) -> f64 {
        self.line_items
            .values()
            .filter(|i| i.unit != CostUnit::FlatMonthly)
            .map(|i| i.unit_cost_eur)
            .sum()
    }

    pub fn estimate_customer_cost(&self, customer: &CustomerEconomics) -> f64 {
        let per_recipient = self.cost_per_1000_recipients() * (customer.monthly_recipients as f64 / 1000.0);
        let storage = self.cost_per_gb_month() * (customer.content_storage_gb + customer.event_storage_gb);
        let ip_cost = self.cost_per_managed_ip() * customer.dedicated_ips as f64;
        let support = self.cost_per_support_hour() * customer.support_hours;
        let deliverability = self.line_items.values()
            .filter(|i| i.unit == CostUnit::PerDeliverabilityHour)
            .map(|i| i.unit_cost_eur)
            .sum::<f64>() * customer.deliverability_hours;
        let abuse = self.line_items.values()
            .filter(|i| i.unit == CostUnit::PerAbuseCase)
            .map(|i| i.unit_cost_eur)
            .sum::<f64>() * customer.abuse_cases as f64;
        let questionnaires = self.line_items.values()
            .filter(|i| i.unit == CostUnit::PerSecurityQuestionnaire)
            .map(|i| i.unit_cost_eur)
            .sum::<f64>() * customer.security_questionnaires as f64;

        per_recipient + storage + ip_cost + support + deliverability + abuse + questionnaires
    }

    pub fn calculate_gross_margin(&self, customer: &CustomerEconomics) -> f64 {
        let cost = self.estimate_customer_cost(customer);
        if customer.monthly_revenue_eur == 0.0 {
            return 0.0;
        }
        (customer.monthly_revenue_eur - cost) / customer.monthly_revenue_eur * 100.0
    }

    pub fn check_margin_alert(&self, customer: &CustomerEconomics) -> Option<MarginAlert> {
        let margin = self.calculate_gross_margin(customer);
        let category = self.product_category_for_plan(&customer.plan);

        if let Some(target) = self.margin_targets.get(&category) {
            if margin < target.minimum_pct {
                return Some(MarginAlert {
                    customer_id: customer.customer_id.clone(),
                    plan: customer.plan.clone(),
                    current_margin_pct: margin,
                    minimum_target_pct: target.minimum_pct,
                    category,
                    severity: AlertSeverity::Critical,
                    message: format!(
                        "Customer {} on {} plan: gross margin {:.1}% below minimum target of {:.0}%",
                        customer.customer_id, customer.plan, margin, target.minimum_pct
                    ),
                    generated_at: Utc::now(),
                });
            }

            if margin < target.minimum_pct + 5.0 {
                return Some(MarginAlert {
                    customer_id: customer.customer_id.clone(),
                    plan: customer.plan.clone(),
                    current_margin_pct: margin,
                    minimum_target_pct: target.minimum_pct,
                    category,
                    severity: AlertSeverity::Warning,
                    message: format!(
                        "Customer {} on {} plan: gross margin {:.1}% approaching minimum target of {:.0}%",
                        customer.customer_id, customer.plan, margin, target.minimum_pct
                    ),
                    generated_at: Utc::now(),
                });
            }
        }

        None
    }

    pub fn check_cohort_margin(
        &self,
        customers: &[CustomerEconomics],
        category: ProductCategory,
    ) -> Option<MarginAlert> {
        let cohort: Vec<&CustomerEconomics> = customers
            .iter()
            .filter(|c| self.product_category_for_plan(&c.plan) == category)
            .collect();

        if cohort.is_empty() {
            return None;
        }

        let total_revenue: f64 = cohort.iter().map(|c| c.monthly_revenue_eur).sum();
        let total_cost: f64 = cohort.iter().map(|c| self.estimate_customer_cost(c)).sum();

        if total_revenue == 0.0 {
            return None;
        }

        let cohort_margin = (total_revenue - total_cost) / total_revenue * 100.0;

        if let Some(target) = self.margin_targets.get(&category) {
            if cohort_margin < target.minimum_pct {
                return Some(MarginAlert {
                    customer_id: format!("cohort:{:?}", category),
                    plan: format!("cohort-{:?}", category),
                    current_margin_pct: cohort_margin,
                    minimum_target_pct: target.minimum_pct,
                    category,
                    severity: AlertSeverity::Critical,
                    message: format!(
                        "Cohort {:?}: aggregate gross margin {:.1}% below minimum {:.0}% across {} customers",
                        category, cohort_margin, target.minimum_pct, cohort.len()
                    ),
                    generated_at: Utc::now(),
                });
            }
        }

        None
    }

    fn product_category_for_plan(&self, plan: &str) -> ProductCategory {
        match plan {
            "free" | "developer" | "pro" => ProductCategory::SharedSelfService,
            "growth" | "business" | "enterprise" => ProductCategory::ManagedHighVolume,
            "dedicated_tenant" => ProductCategory::DedicatedTenant,
            "byoc" => ProductCategory::BYOCPrivate,
            _ => ProductCategory::SharedSelfService,
        }
    }

    pub fn get_margin_target(&self, category: ProductCategory) -> Option<&MarginTarget> {
        self.margin_targets.get(&category)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarginAlert {
    pub customer_id: String,
    pub plan: String,
    pub current_margin_pct: f64,
    pub minimum_target_pct: f64,
    pub category: ProductCategory,
    pub severity: AlertSeverity,
    pub message: String,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Warning,
    Critical,
}

pub fn seed_cost_model() -> CostModel {
    let mut model = CostModel::new();

    model.add_margin_target(MarginTarget {
        category: ProductCategory::SharedSelfService,
        minimum_pct: 75.0,
        maximum_pct: 85.0,
    });
    model.add_margin_target(MarginTarget {
        category: ProductCategory::ManagedHighVolume,
        minimum_pct: 65.0,
        maximum_pct: 80.0,
    });
    model.add_margin_target(MarginTarget {
        category: ProductCategory::DedicatedTenant,
        minimum_pct: 60.0,
        maximum_pct: 75.0,
    });
    model.add_margin_target(MarginTarget {
        category: ProductCategory::BYOCPrivate,
        minimum_pct: 50.0,
        maximum_pct: 70.0,
    });
    model.add_margin_target(MarginTarget {
        category: ProductCategory::ImplementationServices,
        minimum_pct: 40.0,
        maximum_pct: 60.0,
    });
    model.add_margin_target(MarginTarget {
        category: ProductCategory::PremiumSupport,
        minimum_pct: 60.0,
        maximum_pct: 75.0,
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-001".into(),
        item_name: "SMTP Compute".into(),
        category: CostCategory::Compute,
        monthly_estimate_eur: 200.0,
        unit: CostUnit::Per1000Recipients,
        unit_cost_eur: 0.002,
        notes: None,
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-002".into(),
        item_name: "Queue Compute".into(),
        category: CostCategory::Compute,
        monthly_estimate_eur: 150.0,
        unit: CostUnit::Per1000Recipients,
        unit_cost_eur: 0.0015,
        notes: None,
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-003".into(),
        item_name: "API Compute".into(),
        category: CostCategory::Compute,
        monthly_estimate_eur: 300.0,
        unit: CostUnit::Per1000Recipients,
        unit_cost_eur: 0.003,
        notes: None,
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-004".into(),
        item_name: "Database Cost".into(),
        category: CostCategory::Compute,
        monthly_estimate_eur: 250.0,
        unit: CostUnit::Per1000Recipients,
        unit_cost_eur: 0.0025,
        notes: None,
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-005".into(),
        item_name: "Event Storage".into(),
        category: CostCategory::Storage,
        monthly_estimate_eur: 100.0,
        unit: CostUnit::PerGbMonth,
        unit_cost_eur: 0.50,
        notes: None,
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-006".into(),
        item_name: "Message Content Storage".into(),
        category: CostCategory::Storage,
        monthly_estimate_eur: 80.0,
        unit: CostUnit::PerGbMonth,
        unit_cost_eur: 0.40,
        notes: Some("Variable with content retention settings".into()),
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-007".into(),
        item_name: "Backup Storage".into(),
        category: CostCategory::Storage,
        monthly_estimate_eur: 60.0,
        unit: CostUnit::PerGbMonth,
        unit_cost_eur: 0.15,
        notes: None,
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-008".into(),
        item_name: "Network Transfer".into(),
        category: CostCategory::Network,
        monthly_estimate_eur: 120.0,
        unit: CostUnit::PerGbMonth,
        unit_cost_eur: 0.08,
        notes: Some("Includes egress for API, SMTP, and webhook traffic".into()),
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-009".into(),
        item_name: "Attachment Transfer".into(),
        category: CostCategory::Network,
        monthly_estimate_eur: 50.0,
        unit: CostUnit::PerGbMonth,
        unit_cost_eur: 0.06,
        notes: None,
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-010".into(),
        item_name: "Monitoring".into(),
        category: CostCategory::Monitoring,
        monthly_estimate_eur: 200.0,
        unit: CostUnit::FlatMonthly,
        unit_cost_eur: 200.0,
        notes: Some("Prometheus, Grafana, alerting infrastructure".into()),
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-011".into(),
        item_name: "Logging".into(),
        category: CostCategory::Monitoring,
        monthly_estimate_eur: 150.0,
        unit: CostUnit::PerGbMonth,
        unit_cost_eur: 0.30,
        notes: Some("Log ingestion, storage, and search".into()),
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-012".into(),
        item_name: "Error Reporting".into(),
        category: CostCategory::Monitoring,
        monthly_estimate_eur: 80.0,
        unit: CostUnit::FlatMonthly,
        unit_cost_eur: 80.0,
        notes: None,
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-013".into(),
        item_name: "Blocklist Monitoring".into(),
        category: CostCategory::Deliverability,
        monthly_estimate_eur: 150.0,
        unit: CostUnit::PerManagedIp,
        unit_cost_eur: 15.0,
        notes: Some("Third-party blocklist monitoring service".into()),
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-014".into(),
        item_name: "Postmaster Integrations".into(),
        category: CostCategory::Deliverability,
        monthly_estimate_eur: 100.0,
        unit: CostUnit::FlatMonthly,
        unit_cost_eur: 100.0,
        notes: Some("Google Postmaster Tools, Microsoft SNDS integration".into()),
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-015".into(),
        item_name: "Inbox-Placement Seed Services".into(),
        category: CostCategory::Deliverability,
        monthly_estimate_eur: 200.0,
        unit: CostUnit::Per1000Recipients,
        unit_cost_eur: 0.01,
        notes: Some("Seed address subscriptions and test infrastructure".into()),
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-016".into(),
        item_name: "Dedicated IP Rental".into(),
        category: CostCategory::Deliverability,
        monthly_estimate_eur: 100.0,
        unit: CostUnit::PerManagedIp,
        unit_cost_eur: 25.0,
        notes: Some("Provider IP rental fee".into()),
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-017".into(),
        item_name: "Reverse DNS and IP Administration".into(),
        category: CostCategory::Deliverability,
        monthly_estimate_eur: 50.0,
        unit: CostUnit::PerManagedIp,
        unit_cost_eur: 5.0,
        notes: None,
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-018".into(),
        item_name: "Support Labor".into(),
        category: CostCategory::Labor,
        monthly_estimate_eur: 3000.0,
        unit: CostUnit::PerSupportHour,
        unit_cost_eur: 45.0,
        notes: Some("Loaded cost per support hour".into()),
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-019".into(),
        item_name: "Deliverability Labor".into(),
        category: CostCategory::Labor,
        monthly_estimate_eur: 2000.0,
        unit: CostUnit::PerDeliverabilityHour,
        unit_cost_eur: 65.0,
        notes: None,
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-020".into(),
        item_name: "Abuse Review Labor".into(),
        category: CostCategory::Labor,
        monthly_estimate_eur: 1000.0,
        unit: CostUnit::PerAbuseCase,
        unit_cost_eur: 25.0,
        notes: Some("Average loaded cost per abuse case review".into()),
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-021".into(),
        item_name: "Security Review Labor".into(),
        category: CostCategory::Labor,
        monthly_estimate_eur: 1500.0,
        unit: CostUnit::PerSecurityQuestionnaire,
        unit_cost_eur: 150.0,
        notes: Some("Average loaded cost per security questionnaire response".into()),
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-022".into(),
        item_name: "Payment Processing Fees".into(),
        category: CostCategory::PaymentProcessing,
        monthly_estimate_eur: 200.0,
        unit: CostUnit::Per1000Recipients,
        unit_cost_eur: 0.005,
        notes: Some("Stripe fees ~1.5% + €0.25 per transaction".into()),
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-023".into(),
        item_name: "Refunds".into(),
        category: CostCategory::Risk,
        monthly_estimate_eur: 50.0,
        unit: CostUnit::Per1000Recipients,
        unit_cost_eur: 0.001,
        notes: Some("Assumed 0.5% refund rate".into()),
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-024".into(),
        item_name: "Chargebacks".into(),
        category: CostCategory::Risk,
        monthly_estimate_eur: 25.0,
        unit: CostUnit::Per1000Recipients,
        unit_cost_eur: 0.0005,
        notes: Some("Assumed 0.1% chargeback rate".into()),
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-025".into(),
        item_name: "Fraud Losses".into(),
        category: CostCategory::Risk,
        monthly_estimate_eur: 30.0,
        unit: CostUnit::Per1000Recipients,
        unit_cost_eur: 0.0005,
        notes: None,
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-026".into(),
        item_name: "Free-Account Abuse".into(),
        category: CostCategory::Risk,
        monthly_estimate_eur: 50.0,
        unit: CostUnit::Per1000Recipients,
        unit_cost_eur: 0.001,
        notes: Some("Cost of abused free tier accounts".into()),
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-027".into(),
        item_name: "Sales Commission".into(),
        category: CostCategory::SalesAndMarketing,
        monthly_estimate_eur: 500.0,
        unit: CostUnit::Per1000Recipients,
        unit_cost_eur: 0.01,
        notes: Some("Assumed 10% commission on first-year revenue, amortized".into()),
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-028".into(),
        item_name: "Customer-Success Labor".into(),
        category: CostCategory::Labor,
        monthly_estimate_eur: 2500.0,
        unit: CostUnit::PerSupportHour,
        unit_cost_eur: 55.0,
        notes: None,
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-029".into(),
        item_name: "Audit and Compliance Overhead".into(),
        category: CostCategory::ComplianceOverhead,
        monthly_estimate_eur: 500.0,
        unit: CostUnit::FlatMonthly,
        unit_cost_eur: 500.0,
        notes: Some("External audit prep, certification maintenance, legal review".into()),
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-030".into(),
        item_name: "Dedicated Deployment Infrastructure".into(),
        category: CostCategory::Compute,
        monthly_estimate_eur: 1500.0,
        unit: CostUnit::PerDedicatedDeployment,
        unit_cost_eur: 1500.0,
        notes: Some("Baseline infrastructure for dedicated tenant".into()),
    });

    model.add_line_item(CostLineItem {
        item_id: "COST-031".into(),
        item_name: "BYOC Infrastructure Management".into(),
        category: CostCategory::Compute,
        monthly_estimate_eur: 3000.0,
        unit: CostUnit::PerByocDeployment,
        unit_cost_eur: 3000.0,
        notes: Some("Deployment automation, monitoring, upgrade management".into()),
    });

    model
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> CostModel {
        seed_cost_model()
    }

    #[test]
    fn test_all_line_items_unique() {
        let m = model();
        let mut ids: Vec<&str> = m.line_items.keys().map(|s| s.as_str()).collect();
        ids.sort();
        let mut deduped = ids.clone();
        deduped.dedup();
        assert_eq!(ids.len(), deduped.len(), "Duplicate line item IDs");
    }

    #[test]
    fn test_cost_per_1000_recipients_positive() {
        let m = model();
        let cost = m.cost_per_1000_recipients();
        assert!(cost > 0.0, "Cost per 1000 recipients should be positive");
        assert!(cost < 0.10, "Cost per 1000 recipients should be under €0.10");
    }

    #[test]
    fn test_cost_per_gb_month_positive() {
        let m = model();
        let cost = m.cost_per_gb_month();
        assert!(cost > 0.0, "Cost per GB-month should be positive");
    }

    #[test]
    fn test_margin_targets_all_set() {
        let m = model();
        assert!(m.get_margin_target(ProductCategory::SharedSelfService).is_some());
        assert!(m.get_margin_target(ProductCategory::ManagedHighVolume).is_some());
        assert!(m.get_margin_target(ProductCategory::DedicatedTenant).is_some());
        assert!(m.get_margin_target(ProductCategory::BYOCPrivate).is_some());
        assert!(m.get_margin_target(ProductCategory::ImplementationServices).is_some());
        assert!(m.get_margin_target(ProductCategory::PremiumSupport).is_some());
    }

    #[test]
    fn test_margin_alert_below_minimum() {
        let m = model();
        let customer = CustomerEconomics {
            customer_id: "cust_test_001".into(),
            plan: "developer".into(),
            monthly_revenue_eur: 29.0,
            monthly_recipients: 100_000,
            content_storage_gb: 1.0,
            event_storage_gb: 2.0,
            webhook_attempts: 10_000,
            dedicated_ips: 0,
            support_hours: 0.5,
            deliverability_hours: 0.0,
            abuse_cases: 0,
            security_questionnaires: 0,
        };

        let alert = m.check_margin_alert(&customer);
        assert!(alert.is_some(), "Should alert when margin is below target");
        assert!(matches!(alert.unwrap().severity, AlertSeverity::Critical));
    }

    #[test]
    fn test_margin_alert_near_minimum() {
        let m = model();
        let target = m.get_margin_target(ProductCategory::SharedSelfService).unwrap();
        let revenue = 500.0;
        let cost_at_target = revenue * (1.0 - (target.minimum_pct + 2.0) / 100.0);

        let recipients = (cost_at_target / m.cost_per_1000_recipients() * 1000.0) as i64;

        let customer = CustomerEconomics {
            customer_id: "cust_test_002".into(),
            plan: "pro".into(),
            monthly_revenue_eur: revenue,
            monthly_recipients: recipients.max(1),
            content_storage_gb: 0.0,
            event_storage_gb: 0.0,
            webhook_attempts: 0,
            dedicated_ips: 0,
            support_hours: 0.0,
            deliverability_hours: 0.0,
            abuse_cases: 0,
            security_questionnaires: 0,
        };

        let alert = m.check_margin_alert(&customer);
        assert!(alert.is_some(), "Should alert when margin is near minimum");
        if let Some(a) = alert {
            assert!(matches!(a.severity, AlertSeverity::Warning));
        }
    }

    #[test]
    fn test_healthy_customer_no_alert() {
        let m = model();
        let customer = CustomerEconomics {
            customer_id: "cust_test_003".into(),
            plan: "pro".into(),
            monthly_revenue_eur: 890.0,
            monthly_recipients: 200_000,
            content_storage_gb: 1.0,
            event_storage_gb: 2.0,
            webhook_attempts: 20_000,
            dedicated_ips: 0,
            support_hours: 0.1,
            deliverability_hours: 0.0,
            abuse_cases: 0,
            security_questionnaires: 0,
        };

        let alert = m.check_margin_alert(&customer);
        assert!(alert.is_none(), "Healthy customer should not trigger alert");
    }

    #[test]
    fn test_cohort_margin_alert() {
        let m = model();
        let customers = vec![
            CustomerEconomics {
                customer_id: "cohort_1".into(),
                plan: "enterprise".into(),
                monthly_revenue_eur: 1750.0,
                monthly_recipients: 10_000_000,
                content_storage_gb: 50.0,
                event_storage_gb: 100.0,
                webhook_attempts: 500_000,
                dedicated_ips: 3,
                support_hours: 10.0,
                deliverability_hours: 5.0,
                abuse_cases: 2,
                security_questionnaires: 1,
            },
            CustomerEconomics {
                customer_id: "cohort_2".into(),
                plan: "business".into(),
                monthly_revenue_eur: 699.0,
                monthly_recipients: 5_000_000,
                content_storage_gb: 30.0,
                event_storage_gb: 60.0,
                webhook_attempts: 200_000,
                dedicated_ips: 2,
                support_hours: 5.0,
                deliverability_hours: 3.0,
                abuse_cases: 1,
                security_questionnaires: 0,
            },
        ];

        let alert = m.check_cohort_margin(&customers, ProductCategory::ManagedHighVolume);
        assert!(alert.is_some(), "Low-margin cohort should generate alert");
    }
}
