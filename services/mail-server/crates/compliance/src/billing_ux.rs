use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingDisplay {
    pub active_plan: String,
    pub billing_period: BillingPeriod,
    pub included_volume: i64,
    pub current_accepted_recipients: i64,
    pub overage_recipients: i64,
    pub estimated_current_invoice: f64,
    pub projected_invoice: f64,
    pub dedicated_ip_fees: f64,
    pub retention_add_ons: f64,
    pub active_discount: Option<DiscountInfo>,
    pub credits: f64,
    pub tax_status: TaxStatus,
    pub annual_commitment: Option<AnnualCommitment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BillingPeriod {
    Monthly,
    Annual,
}

impl std::fmt::Display for BillingPeriod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Monthly => f.write_str("monthly"),
            Self::Annual => f.write_str("annual"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscountInfo {
    pub name: String,
    pub percentage: f64,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaxStatus {
    None,
    ReverseCharge,
    TaxExempt,
    Standard,
}

impl std::fmt::Display for TaxStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::None => "none",
            Self::ReverseCharge => "reverse_charge",
            Self::TaxExempt => "tax_exempt",
            Self::Standard => "standard",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnualCommitment {
    pub months_committed: i32,
    pub discount_rate: f64,
    pub start_date: DateTime<Utc>,
    pub end_date: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingControls {
    pub spending_alert_threshold: Option<f64>,
    pub hard_spending_limit: Option<f64>,
    pub hard_send_limit: Option<i64>,
    pub auto_upgrade_enabled: bool,
    pub usage_webhook_url: Option<String>,
    pub billing_contact_email: Option<String>,
    pub payment_method: Option<PaymentMethod>,
    pub invoice_downloads: Vec<InvoiceRecord>,
    pub credit_history: Vec<CreditTransaction>,
    pub plan_change_history: Vec<PlanChange>,
    pub cancellation_requested: bool,
    pub data_export_warning_sent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentMethod {
    pub id: String,
    pub method_type: PaymentMethodType,
    pub last_four: Option<String>,
    pub expiry_month: Option<u32>,
    pub expiry_year: Option<u32>,
    pub is_default: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentMethodType {
    Card,
    Sepa,
    WireTransfer,
}

impl std::fmt::Display for PaymentMethodType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Card => f.write_str("card"),
            Self::Sepa => f.write_str("sepa"),
            Self::WireTransfer => f.write_str("wire_transfer"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvoiceRecord {
    pub invoice_id: String,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub total_eur: f64,
    pub status: InvoiceStatus,
    pub download_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InvoiceStatus {
    Draft,
    Open,
    Paid,
    Void,
    Overdue,
}

impl std::fmt::Display for InvoiceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Draft => f.write_str("draft"),
            Self::Open => f.write_str("open"),
            Self::Paid => f.write_str("paid"),
            Self::Void => f.write_str("void"),
            Self::Overdue => f.write_str("overdue"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditTransaction {
    pub transaction_id: String,
    pub amount: f64,
    pub reason: String,
    pub applied_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanChange {
    pub from_plan: String,
    pub to_plan: String,
    pub changed_at: DateTime<Utc>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingCalculatorInput {
    pub monthly_volume: i64,
    pub transactional_percentage: f64,
    pub broadcast_percentage: f64,
    pub domains: i32,
    pub users: i32,
    pub retention_days: Option<i32>,
    pub dedicated_ip: bool,
    pub sso: bool,
    pub inbound_email: bool,
    pub private_deployment: bool,
    pub billing_period: BillingPeriod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingCalculatorOutput {
    pub recommended_plan: String,
    pub base_fee_eur: f64,
    pub overage_eur: f64,
    pub add_ons_eur: f64,
    pub effective_price_per_1k: f64,
    pub annual_total_eur: f64,
    pub recommendation_reason: String,
    pub upgrade_point: Option<i64>,
    pub lower_cost_alternative: Option<String>,
    pub sales_review_required: bool,
}

pub fn calculate_pricing(input: &PricingCalculatorInput) -> PricingCalculatorOutput {
    let volume = input.monthly_volume as f64;

    let (recommended_plan, base_fee, included_emails, overage_rate_per_1k) =
        if volume <= 10_000.0 {
            ("Free", 0.0, 10_000.0, 0.0)
        } else if volume <= 50_000.0 {
            ("Starter", 25.0, 25_000.0, 0.80)
        } else if volume <= 200_000.0 {
            ("Growth", 90.0, 100_000.0, 0.55)
        } else if volume <= 500_000.0 {
            ("Business", 250.0, 300_000.0, 0.45)
        } else if volume <= 1_000_000.0 {
            ("Scale", 500.0, 600_000.0, 0.35)
        } else {
            ("Enterprise", 1_200.0, 1_000_000.0, 0.30)
        };

    let overage = if volume > included_emails {
        ((volume - included_emails) / 1_000.0) * overage_rate_per_1k
    } else {
        0.0
    };

    let mut add_ons = 0.0;

    if input.dedicated_ip {
        add_ons += 30.0 * input.domains.max(1) as f64;
    }
    if let Some(retention_days) = input.retention_days {
        if retention_days > 30 {
            add_ons += ((retention_days - 30) as f64 / 30.0).ceil() * 10.0;
        }
    }
    if input.sso {
        add_ons += 50.0;
    }
    if input.inbound_email {
        add_ons += 20.0;
    }
    if input.private_deployment {
        add_ons += 500.0;
    }

    let monthly = base_fee + overage + add_ons;
    let effective_per_1k = if volume > 0.0 { (monthly / volume) * 1_000.0 } else { 0.0 };

    let annual = match input.billing_period {
        BillingPeriod::Annual => monthly * 12.0 * 0.9,
        BillingPeriod::Monthly => monthly * 12.0,
    };

    let upgrade_point = match recommended_plan {
        "Free" => Some(10_001),
        "Starter" => Some(50_001),
        "Growth" => Some(200_001),
        "Business" => Some(500_001),
        "Scale" => Some(1_000_001),
        _ => None,
    };

    let lower_cost = match recommended_plan {
        "Free" => None,
        "Starter" => Some("Free".to_string()),
        "Growth" => Some("Starter".to_string()),
        "Business" => Some("Growth".to_string()),
        "Scale" => Some("Business".to_string()),
        _ => Some("Scale".to_string()),
    };

    let mut reason = format!(
        "{} emails/month fits the {} plan (up to {} included).",
        volume as i64, recommended_plan, included_emails as i64
    );
    if overage > 0.0 {
        reason.push_str(&format!(
            " Overage at EUR {:.2}/1K for {} emails above included volume.",
            overage_rate_per_1k, (volume - included_emails) as i64
        ));
    }

    PricingCalculatorOutput {
        recommended_plan: recommended_plan.to_string(),
        base_fee_eur: monthly,
        overage_eur: overage,
        add_ons_eur: add_ons,
        effective_price_per_1k: effective_per_1k,
        annual_total_eur: annual,
        recommendation_reason: reason,
        upgrade_point,
        lower_cost_alternative: lower_cost,
        sales_review_required: recommended_plan == "Enterprise",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_input(volume: i64) -> PricingCalculatorInput {
        PricingCalculatorInput {
            monthly_volume: volume,
            transactional_percentage: 80.0,
            broadcast_percentage: 20.0,
            domains: 1,
            users: 2,
            retention_days: None,
            dedicated_ip: false,
            sso: false,
            inbound_email: false,
            private_deployment: false,
            billing_period: BillingPeriod::Monthly,
        }
    }

    #[test]
    fn test_pricing_free_tier() {
        let output = calculate_pricing(&base_input(5_000));
        assert_eq!(output.recommended_plan, "Free");
        assert_eq!(output.base_fee_eur, 0.0);
        assert!(!output.sales_review_required);
    }

    #[test]
    fn test_pricing_growth_with_overage() {
        let output = calculate_pricing(&base_input(150_000));
        assert_eq!(output.recommended_plan, "Growth");
        assert!(output.overage_eur > 0.0);
        assert!(output.base_fee_eur > 90.0);
    }

    #[test]
    fn test_pricing_annual_discount() {
        let mut input = base_input(100_000);
        input.billing_period = BillingPeriod::Annual;
        let output = calculate_pricing(&input);
        assert_eq!(output.recommended_plan, "Growth");
        let monthly = base_input(100_000);
        let monthly_output = calculate_pricing(&monthly);
        assert!(output.annual_total_eur < monthly_output.annual_total_eur);
    }

    #[test]
    fn test_pricing_with_add_ons() {
        let mut input = base_input(100_000);
        input.dedicated_ip = true;
        input.domains = 3;
        input.sso = true;
        input.inbound_email = true;
        input.retention_days = Some(90);

        let output = calculate_pricing(&input);
        assert!(output.add_ons_eur > 0.0);
        assert!(output.base_fee_eur > 90.0);
    }

    #[test]
    fn test_pricing_enterprise_triggers_sales_review() {
        let output = calculate_pricing(&base_input(2_000_000));
        assert_eq!(output.recommended_plan, "Enterprise");
        assert!(output.sales_review_required);
        assert!(output.lower_cost_alternative.is_some());
    }

    #[test]
    fn test_billing_display_fields_present() {
        let display = BillingDisplay {
            active_plan: "Growth".to_string(),
            billing_period: BillingPeriod::Monthly,
            included_volume: 200_000,
            current_accepted_recipients: 150_000,
            overage_recipients: 0,
            estimated_current_invoice: 90.0,
            projected_invoice: 90.0,
            dedicated_ip_fees: 0.0,
            retention_add_ons: 0.0,
            active_discount: None,
            credits: 0.0,
            tax_status: TaxStatus::ReverseCharge,
            annual_commitment: None,
        };
        assert_eq!(display.active_plan, "Growth");
        assert_eq!(display.tax_status, TaxStatus::ReverseCharge);
    }

    #[test]
    fn test_billing_controls_defaults() {
        let controls = BillingControls {
            spending_alert_threshold: None,
            hard_spending_limit: None,
            hard_send_limit: None,
            auto_upgrade_enabled: false,
            usage_webhook_url: None,
            billing_contact_email: None,
            payment_method: None,
            invoice_downloads: vec![],
            credit_history: vec![],
            plan_change_history: vec![],
            cancellation_requested: false,
            data_export_warning_sent: false,
        };
        assert!(!controls.auto_upgrade_enabled);
        assert!(controls.spending_alert_threshold.is_none());
    }
}
