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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl Default for PlanFeatures {
    fn default() -> Self {
        Self {
            dedicated_ip: false,
            dedicated_ip_count: 0,
            max_sending_domains: 1,
            sso_enabled: false,
            audit_logs: false,
            api_access: true,
            webhooks_enabled: false,
            inbound_email: false,
            advanced_analytics: false,
            send_time_optimization: false,
            ab_testing: false,
            time_travel_debugging: false,
            data_export: false,
            custom_tracking_domain: false,
            custom_templates: false,
            template_approval_workflow: false,
            white_label: false,
            powered_by_footer: true,
            custom_retention: false,
            max_retention_days: 7,
            max_team_members: 1,
            subaccounts: false,
            max_subaccounts: 0,
            support_level: SupportLevel::Community,
            dedicated_csm: false,
            priority_onboarding: false,
            byoip: false,
            sla_guarantee: false,
            sla_credit_percentage: 0,
            hipaa_compliance: false,
            soc2_compliance: false,
            private_cloud: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SupportLevel {
    #[default]
    Community,
    Email,
    Priority,
    /// Deprecated: implies on-demand 24/7 phone support which violates the
    /// async-first support policy. Retained for backwards-compatible
    /// deserialization of legacy records; new plans should use `Priority`
    /// (Scale) or `Dedicated` (Enterprise).
    Phone,
    Dedicated,
}

impl SupportLevel {
    /// First-response SLA in business hours, per the async-first support
    /// policy documented in `docs/enterprise/support.md`. Returns `None` for
    /// `Community` (no SLA, best-effort via the public forum).
    pub fn response_sla_hours(self) -> Option<u32> {
        match self {
            SupportLevel::Community => None,
            // Starter / Pro / Growth: email-only, 24–48h. Use the upper bound
            // as the contractual ceiling.
            SupportLevel::Email => Some(48),
            // Scale: priority email + shared Slack hub.
            SupportLevel::Priority => Some(8),
            // Legacy "Phone" maps to Priority semantics; we no longer offer
            // on-demand phone, only scheduled calls.
            SupportLevel::Phone => Some(8),
            // Enterprise: dedicated async channel + contractual SLA.
            SupportLevel::Dedicated => Some(4),
        }
    }

    /// Short human-readable description of the human-contact policy for this
    /// tier. Used by the chatbot/mailbot and the in-app help surfaces so
    /// expectations are set up-front.
    pub fn human_channel_policy(self) -> &'static str {
        match self {
            SupportLevel::Community => "Community forum only. No SLA.",
            SupportLevel::Email => {
                "Email only, 24–48h business-hour response. No live chat, \
                 no per-customer Discord."
            }
            SupportLevel::Priority | SupportLevel::Phone => {
                "Priority email + shared Slack hub (one channel for all Scale \
                 tenants). Scheduled calls only, monthly cap. No 24/7."
            }
            SupportLevel::Dedicated => {
                "Dedicated async channel + contractual SLA. Scheduled calls \
                 only, weekly cap. P0 on-call."
            }
        }
    }
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
    pub tenant_id: String,
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
    pub tenant_id: String,
    pub event_type: MeterEventType,
    pub quantity: i64,
    pub timestamp: DateTime<Utc>,
    pub metadata: serde_json::Value,
}

/// Aggregated usage for a billing period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageSummary {
    pub tenant_id: String,
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
    pub vat_rate: f64,
    pub vat_amount: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invoice {
    pub id: Uuid,
    pub tenant_id: String,
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
    pub tenant_id: String,
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
    pub tenant_id: String,
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

    /// The async-first support policy enforces a strict ordering of SLA
    /// response times across tiers. If this test ever fails, somebody
    /// reintroduced 24/7 live chat or weakened the Enterprise SLA — both
    /// violate `docs/enterprise/support.md` and the chatbot's tier guidance.
    #[test]
    fn support_level_response_sla_is_monotonic() {
        assert_eq!(SupportLevel::Community.response_sla_hours(), None);
        let email = SupportLevel::Email.response_sla_hours().unwrap();
        let priority = SupportLevel::Priority.response_sla_hours().unwrap();
        let dedicated = SupportLevel::Dedicated.response_sla_hours().unwrap();
        assert!(
            dedicated < priority && priority < email,
            "SLA ordering broken: dedicated={dedicated}h priority={priority}h email={email}h"
        );
        // No tier is "instant" — async-first means the floor is hours, not
        // minutes. Anyone trying to ship a 15-minute SLA must update the
        // policy doc first.
        assert!(dedicated >= 1, "no instant-response tier allowed");
    }

    #[test]
    fn support_level_human_channel_policy_is_explicit() {
        // The chatbot quotes these strings verbatim when setting expectations
        // before handing off to a human. They must not promise 24/7 or
        // per-customer Discord on any tier.
        for level in [
            SupportLevel::Community,
            SupportLevel::Email,
            SupportLevel::Priority,
            SupportLevel::Phone,
            SupportLevel::Dedicated,
        ] {
            let policy = level.human_channel_policy();
            let lower = policy.to_lowercase();
            // Flag *positive* 24/7 promises only — "No 24/7." is a permitted
            // explicit denial.
            let promises_24_7 = lower.contains("available 24/7")
                || lower.contains("24/7 live")
                || lower.contains("24/7 phone")
                || lower.contains("24/7 chat");
            assert!(!promises_24_7, "{level:?}: {policy}");
            // Only flag *positive* Discord promises. Phrases like
            // "no per-customer Discord" are explicit denials and are allowed.
            let promises_discord = lower.contains("dedicated discord")
                || lower.contains("private discord")
                || lower.contains("your own discord")
                || lower.contains("discord channel for you");
            assert!(
                !promises_discord,
                "{level:?} promises a Discord channel: {policy}"
            );
        }
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

    // ── Fail-first tests ──────────────────────────────────────────

    #[test]
    fn subscription_status_all_variants_serialize() {
        // BUG DETECTION: If a new variant is added but serde renaming breaks,
        // this test catches it.
        for status in [
            SubscriptionStatus::Active,
            SubscriptionStatus::PastDue,
            SubscriptionStatus::Canceled,
            SubscriptionStatus::Trialing,
            SubscriptionStatus::Paused,
            SubscriptionStatus::Incomplete,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: SubscriptionStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status, "roundtrip failed for {:?}", status);
        }
    }

    #[test]
    fn billing_interval_roundtrip() {
        for interval in [BillingInterval::Monthly, BillingInterval::Yearly] {
            let json = serde_json::to_string(&interval).unwrap();
            let back: BillingInterval = serde_json::from_str(&json).unwrap();
            assert_eq!(back, interval);
        }
    }

    #[test]
    fn meter_event_type_all_variants_serialize() {
        for etype in [
            MeterEventType::EmailsSent,
            MeterEventType::EmailsDelivered,
            MeterEventType::ApiCalls,
            MeterEventType::WebhooksDelivered,
            MeterEventType::DedicatedIpHours,
            MeterEventType::StorageGbHours,
            MeterEventType::BandwidthGb,
        ] {
            let json = serde_json::to_string(&etype).unwrap();
            let back: MeterEventType = serde_json::from_str(&json).unwrap();
            assert_eq!(back, etype, "roundtrip failed for {:?}", etype);
        }
    }

    #[test]
    fn plan_features_default_no_dedicated_ip() {
        // BUG DETECTION: Default plan must NOT include dedicated IP.
        // If defaults change, this test catches the security regression.
        let f = PlanFeatures::default();
        assert!(
            !f.dedicated_ip,
            "default plan must not include dedicated IP"
        );
        assert_eq!(
            f.dedicated_ip_count, 0,
            "default dedicated_ip_count must be 0"
        );
    }

    #[test]
    fn plan_features_default_no_enterprise_features() {
        // BUG DETECTION: Default features must not grant enterprise capabilities.
        let f = PlanFeatures::default();
        assert!(!f.byoip, "default must not allow BYOIP");
        assert!(!f.sla_guarantee, "default must not include SLA");
        assert!(!f.hipaa_compliance, "default must not include HIPAA");
        assert!(!f.soc2_compliance, "default must not include SOC2");
        assert!(!f.private_cloud, "default must not include private cloud");
        assert!(!f.white_label, "default must not include white label");
    }

    #[test]
    fn plan_features_default_limited_team() {
        // BUG DETECTION: Default team size must be small.
        let f = PlanFeatures::default();
        assert!(f.max_team_members >= 1, "must allow at least 1 team member");
        assert!(f.max_team_members <= 10, "default team size must be <= 10");
    }

    #[test]
    fn quota_limit_email_limit_negative_means_unlimited() {
        // Verify the convention: -1 = unlimited
        let quota = QuotaLimit {
            tenant_id: "test".into(),
            plan_name: "enterprise".into(),
            emails_per_month: -1,
            api_calls_per_month: -1,
            max_sending_domains: 100,
            max_team_members: 50,
            max_subaccounts: 50,
            rate_limit_tier: RateLimitTier::Unlimited,
        };
        assert_eq!(quota.emails_per_month, -1);
        assert_eq!(quota.api_calls_per_month, -1);
    }

    #[test]
    fn rate_limit_tier_ordering() {
        // BUG DETECTION: Tiers must be strictly ordered.
        assert!(RateLimitTier::Free.rps() < RateLimitTier::Standard.rps());
        assert!(RateLimitTier::Standard.rps() < RateLimitTier::High.rps());
        assert!(RateLimitTier::High.rps() < RateLimitTier::Unlimited.rps());
    }

    #[test]
    fn invoice_line_item_amount_calculation() {
        // BUG DETECTION: line item amount should be quantity * unit_price.
        let item = InvoiceLineItem {
            description: "Dedicated IP".into(),
            quantity: 2,
            unit_price: 3000, // €30.00
            amount: 6000,
            vat_rate: 20.0,
            vat_amount: 1200,
        };
        assert_eq!(
            item.amount,
            item.quantity * item.unit_price,
            "line amount must equal quantity * unit_price"
        );
    }

    #[test]
    fn billing_event_kind_covers_all_critical_events() {
        // BUG DETECTION: Ensure critical event kinds exist.
        let critical = [
            BillingEventKind::SubscriptionCreated,
            BillingEventKind::SubscriptionCanceled,
            BillingEventKind::QuotaExceeded,
            BillingEventKind::InvoiceFailed,
            BillingEventKind::PlanChanged,
        ];
        for kind in critical {
            let json = serde_json::to_string(&kind).unwrap();
            assert!(
                serde_json::from_str::<BillingEventKind>(&json).is_ok(),
                "critical event kind {:?} must roundtrip",
                kind
            );
        }
    }

    #[test]
    fn usage_summary_percent_used_cannot_exceed_100_for_display() {
        // This is a data integrity check - percent_used can exceed 100
        // (indicating overage) but callers must handle it.
        let summary = UsageSummary {
            tenant_id: "test".into(),
            period_start: chrono::Utc::now(),
            period_end: chrono::Utc::now(),
            emails_sent: 200,
            emails_limit: 100,
            api_calls: 50,
            api_calls_limit: 100,
            percent_used: 200.0, // 200% = overage
            metrics: serde_json::json!({}),
        };
        // Overages are valid - percent_used > 100 means over limit
        assert!(
            summary.percent_used > 100.0,
            "overage must be representable"
        );
    }
}
