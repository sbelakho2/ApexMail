//! Core billing domain types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

/// Pricing plan stored in the `plans` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub id: Uuid,
    pub name: String,
    pub display_name: String,
    pub description: String,
    /// Monthly price in **cents**.
    pub price_monthly: i64,
    /// Yearly price in **cents** (discounted).
    pub price_yearly: i64,
    /// Monthly email sending limit (−1 = unlimited).
    pub email_limit: i64,
    /// Monthly API-call limit (−1 = unlimited).
    pub api_call_limit: i64,
    /// JSON-encoded feature flags.
    pub features: PlanFeatures,
    pub stripe_price_id_monthly: Option<String>,
    pub stripe_price_id_yearly: Option<String>,
    pub is_active: bool,
    pub sort_order: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Feature flags attached to a plan.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlanFeatures {
    // Infrastructure
    pub dedicated_ip: bool,
    pub dedicated_ip_count: i32,
    pub max_sending_domains: i32,

    // Auth & Security
    pub sso_enabled: bool,
    pub audit_logs: bool,

    // API & Integrations
    pub api_access: bool,
    pub webhooks_enabled: bool,
    pub inbound_email: bool,

    // Analytics
    pub advanced_analytics: bool,
    pub send_time_optimization: bool,
    pub ab_testing: bool,
    pub time_travel_debugging: bool,
    pub data_export: bool,

    // Customization
    pub custom_tracking_domain: bool,
    pub custom_templates: bool,
    pub template_approval_workflow: bool,
    pub white_label: bool,
    pub powered_by_footer: bool,

    // Retention
    pub custom_retention: bool,
    pub max_retention_days: i32,

    // Team
    pub max_team_members: i32,
    pub subaccounts: bool,
    pub max_subaccounts: i32,

    // Support
    pub support_level: SupportLevel,
    pub dedicated_csm: bool,
    pub priority_onboarding: bool,

    // Enterprise
    pub byoip: bool,
    pub sla_guarantee: bool,
    pub sla_credit_percentage: i32,
    pub hipaa_compliance: bool,
    pub soc2_compliance: bool,
    pub private_cloud: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SupportLevel {
    #[default]
    Community,
    Email,
    Priority,
    Phone,
    Dedicated,
}

// ---------------------------------------------------------------------------
// Subscription
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "subscription_status", rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Active,
    PastDue,
    Canceled,
    Trialing,
    Paused,
    Incomplete,
}

/// Subscription record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub plan_name: String,
    pub status: SubscriptionStatus,
    pub billing_interval: BillingInterval,
    pub current_period_start: DateTime<Utc>,
    pub current_period_end: DateTime<Utc>,
    pub stripe_subscription_id: Option<String>,
    pub stripe_customer_id: Option<String>,
    pub cancel_at_period_end: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "billing_interval", rename_all = "snake_case")]
pub enum BillingInterval {
    Monthly,
    Yearly,
}

// ---------------------------------------------------------------------------
// Usage / Metering
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "meter_event_type", rename_all = "snake_case")]
pub enum MeterEventType {
    EmailsSent,
    EmailsDelivered,
    ApiCalls,
    WebhooksDelivered,
    DedicatedIpHours,
    StorageGbHours,
    BandwidthGb,
}

/// A single metering event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub event_type: MeterEventType,
    pub quantity: i64,
    pub timestamp: DateTime<Utc>,
    pub metadata: serde_json::Value,
}

/// Aggregated usage for a billing period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageSummary {
    pub tenant_id: Uuid,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub emails_sent: i64,
    pub emails_limit: i64,
    pub api_calls: i64,
    pub api_calls_limit: i64,
    pub percent_used: f64,
    pub metrics: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Invoice
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "invoice_status", rename_all = "snake_case")]
pub enum InvoiceStatus {
    Draft,
    Pending,
    Paid,
    Void,
    Uncollectible,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvoiceLineItem {
    pub description: String,
    pub quantity: i64,
    /// Unit price in cents.
    pub unit_price: i64,
    /// Line total in cents.
    pub amount: i64,
    pub vat_rate: i32,
    pub vat_amount: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invoice {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub stripe_invoice_id: Option<String>,
    pub invoice_number: String,
    pub status: InvoiceStatus,
    pub currency: String,
    /// Subtotal in cents.
    pub subtotal: i64,
    pub vat_total: i64,
    pub total: i64,
    pub line_items: Vec<InvoiceLineItem>,
    pub issued_at: DateTime<Utc>,
    pub due_at: DateTime<Utc>,
    pub paid_at: Option<DateTime<Utc>>,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Billing Event
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BillingEventKind {
    SubscriptionCreated,
    SubscriptionUpdated,
    SubscriptionCanceled,
    InvoicePaid,
    InvoiceFailed,
    UsageThresholdReached,
    PlanChanged,
    QuotaExceeded,
}

/// An audit-style record of billing-relevant events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingEvent {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub kind: BillingEventKind,
    pub payload: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Quota / Rate-limit tier
// ---------------------------------------------------------------------------

/// Quota limits derived from a plan, used for enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaLimit {
    pub tenant_id: Uuid,
    pub plan_name: String,
    pub emails_per_month: i64,
    pub api_calls_per_month: i64,
    pub max_sending_domains: i32,
    pub max_team_members: i32,
    pub max_subaccounts: i32,
    pub rate_limit_tier: RateLimitTier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitTier {
    /// Free tier – strict limits.
    Free,
    /// Starter / Pro.
    Standard,
    /// Growth / Scale.
    High,
    /// Enterprise – highest throughput.
    Unlimited,
}

impl RateLimitTier {
    /// Requests per second for the API.
    pub fn rps(&self) -> u32 {
        match self {
            Self::Free => 10,
            Self::Standard => 100,
            Self::High => 500,
            Self::Unlimited => 5_000,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn support_level_serde_roundtrip() {
        let level = SupportLevel::Dedicated;
        let json = serde_json::to_string(&level).unwrap();
        assert_eq!(json, "\"dedicated\"");
        let back: SupportLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(back, level);
    }

    #[test]
    fn rate_limit_tier_rps() {
        assert_eq!(RateLimitTier::Free.rps(), 10);
        assert_eq!(RateLimitTier::Standard.rps(), 100);
        assert_eq!(RateLimitTier::High.rps(), 500);
        assert_eq!(RateLimitTier::Unlimited.rps(), 5_000);
    }

    #[test]
    fn plan_features_default_is_restrictive() {
        let f = PlanFeatures::default();
        assert!(!f.dedicated_ip);
        assert!(!f.sso_enabled);
        assert!(matches!(f.support_level, SupportLevel::Community));
    }

    #[test]
    fn billing_event_kind_roundtrip() {
        let kind = BillingEventKind::QuotaExceeded;
        let json = serde_json::to_string(&kind).unwrap();
        let back: BillingEventKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, kind);
    }

    #[test]
    fn invoice_status_roundtrip() {
        for status in [
            InvoiceStatus::Draft,
            InvoiceStatus::Pending,
            InvoiceStatus::Paid,
            InvoiceStatus::Void,
            InvoiceStatus::Uncollectible,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: InvoiceStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }
}
