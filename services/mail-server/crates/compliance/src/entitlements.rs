//! Tenant entitlement snapshot derived from the authoritative billing
//! model — the same tables api-server and billing-service compute with:
//!
//! - effective plan: `tenants.plan`, overridden by an active, unexpired
//!   `plan_overrides` row, joined to `plans` for limits/features
//!   (mirrors billing-service `TENANT_PLAN_LIMITS_SQL`, migrations
//!   069/093/098 — producers: api-server billing admin routes);
//! - contract window: `enterprise_contracts` active period
//!   (migration 022 — producers: enterprise contracts + billing admin);
//! - subscription state: `stripe_subscriptions` (producer: billing-service
//!   stripe webhooks);
//! - monthly usage: `metering_events` `emails_sent` aggregated over the
//!   SAME window quota enforcement charges — the tenant's anchored billing
//!   cycle when a Stripe subscription defines one, the UTC calendar month
//!   otherwise (F61: mirroring billing-service `check_quota`'s
//!   Redis-outage DB fallback exactly, so a tenant whose cycle starts on
//!   the 15th gets identical usage/remaining from enforcement and here).
//!
//! F61: the previous version joined `subscription_contracts` and
//! `plan_discounts`, which have no migration and no producer — the helper
//! could never answer a request. Every table read here has a producer.
//!
//! F61 (limits parity): batch/attachment limits are no longer an
//! independent hardcoded ladder — they are exposed from the versioned
//! [`EnforcedSendLimits`] contract that reads the same environment
//! variables (and defaults) the send API enforces. The email allowance also
//! mirrors enforcement's free-plan launch allowance.

use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitlementResponse {
    pub active_plan: String,
    pub contract_start: Option<NaiveDate>,
    pub contract_end: Option<NaiveDate>,
    pub monthly_message_allowance: i64,
    pub current_usage: i64,
    pub overage_rate_cents_per_1000: i64,
    pub daily_send_limit: Option<i64>,
    pub hourly_burst_limit: Option<i64>,
    pub sending_domain_limit: i32,
    pub user_limit: i32,
    pub api_key_limit: i32,
    pub smtp_credential_limit: i32,
    pub template_limit: i32,
    pub webhook_endpoint_limit: i32,
    pub event_retention_days: i32,
    pub message_content_retention_days: i32,
    pub attachment_limit_mb: i32,
    pub batch_limit: i32,
    pub scheduling_horizon_days: i32,
    pub inbound_email: bool,
    pub inbox_placement_credits: i32,
    pub grader_credits: i32,
    pub subaccount_limit: i32,
    pub audit_logs: bool,
    pub sso_enabled: bool,
    pub scim_enabled: bool,
    pub dedicated_ip_entitlement: i32,
    pub support_target_hours: Option<u32>,
    pub sla_eligible: bool,
    pub dpa_available: bool,
    pub baa_review_eligible: bool,
    pub dedicated_tenancy_eligible: bool,
    pub byoc_eligible: bool,

    /// F61: version of the limits contract this response was produced
    /// under. Bump whenever an exposed limit changes meaning; consumers can
    /// detect contract drift between API/console/quota/helper surfaces.
    pub limits_contract_version: u32,

    pub discount_type: Option<String>,
    pub discount_percentage: Option<f64>,
    pub founding_customer: bool,
    pub startup_program: bool,
    pub contract_override: bool,
    pub expiring_entitlements_at: Option<DateTime<Utc>>,
    pub suspended: bool,
    pub trial_or_beta: bool,
}

#[derive(sqlx::FromRow)]
struct TenantEntitlementRow {
    /// Selected to preserve the row anchor used by the authoritative
    /// limits statement (billing-service TENANT_PLAN_LIMITS_SQL).
    #[expect(
        dead_code,
        reason = "tenant_id is selected to mirror the authoritative limits SQL"
    )]
    tenant_id: String,
    plan_name: String,
    /// An active, unexpired plan override applies to this tenant.
    has_override: bool,
    override_expires_at: Option<DateTime<Utc>>,
    status: String,
    /// `tenants.created_at` — drives the free-plan launch allowance exactly
    /// as enforcement's `free_launch_allowance_applies` computes it (F61).
    tenant_created_at: Option<DateTime<Utc>>,
    email_limit: Option<i64>,
    /// Selected alongside email_limit for parity with the authoritative
    /// limits statement; the response surface only exposes email allowance.
    #[expect(
        dead_code,
        reason = "api_call_limit is selected to mirror the authoritative limits SQL"
    )]
    api_call_limit: Option<i64>,
    features: Option<serde_json::Value>,
    contract_start: Option<NaiveDate>,
    contract_end: Option<NaiveDate>,
    /// `enterprise_contracts.annual_prepay_discount` (percent, 0 = none).
    annual_prepay_discount: Option<i32>,
    /// Latest stripe subscription status (NULL when never subscribed).
    stripe_status: Option<String>,
}

/// Effective-plan + contract + subscription lookup. Mirrors billing-service
/// `TENANT_PLAN_LIMITS_SQL` (usage.rs): an active, unexpired override wins
/// over the tenant's own plan. $1 = tenant_id.
const TENANT_ENTITLEMENT_SQL: &str = r#"
        SELECT
            t.id                                AS tenant_id,
            COALESCE(po.plan, t.plan)           AS plan_name,
            (po.id IS NOT NULL)                 AS has_override,
            po.expires_at                       AS override_expires_at,
            COALESCE(t.status, 'active')        AS status,
            t.created_at                        AS tenant_created_at,
            p.email_limit,
            p.api_call_limit,
            p.features,
            ec.start_date::date                 AS contract_start,
            ec.end_date::date                   AS contract_end,
            ec.annual_prepay_discount,
            ss.status                           AS stripe_status
        FROM tenants t
        LEFT JOIN plan_overrides po
               ON po.tenant_id = t.id
              AND po.active = true
              AND (po.expires_at IS NULL OR po.expires_at > NOW())
        LEFT JOIN plans p ON p.name = COALESCE(po.plan, t.plan)
        LEFT JOIN LATERAL (
            SELECT start_date, end_date, annual_prepay_discount
            FROM enterprise_contracts
            WHERE tenant_id = t.id
              AND status = 'active'
              AND start_date <= NOW()
              AND end_date > NOW()
            ORDER BY end_date DESC
            LIMIT 1
        ) ec ON true
        LEFT JOIN LATERAL (
            SELECT status
            FROM stripe_subscriptions
            WHERE tenant_id = t.id
            ORDER BY updated_at DESC
            LIMIT 1
        ) ss ON true
        WHERE t.id = $1
        "#;

/// `emails_sent` usage over the ENFORCED window (F61): $1 = tenant,
/// $2 = period start (the tenant's anchored billing-cycle start, or the UTC
/// calendar month for tenants without a subscription — the identical window
/// `check_quota`'s DB fallback aggregates, so the helper and the quota gate
/// can never disagree about which events belong to the current period).
const TENANT_USAGE_SQL: &str = r#"
        SELECT COALESCE(SUM(quantity), 0)::bigint AS current_usage
        FROM metering_events
        WHERE tenant_id = $1
          AND event_type = 'emails_sent'
          AND timestamp >= $2
        "#;

/// The tenant's billing-cycle anchor (F61) — the most recent
/// `billing_cycle_start` of an active/trialing/past-due subscription.
/// Mirrors billing-service `tenant_cycle_anchor` (usage.rs) verbatim so
/// both paths resolve the same anchor for the same tenant.
const TENANT_CYCLE_ANCHOR_SQL: &str = r#"
        SELECT billing_cycle_start
        FROM stripe_subscriptions
        WHERE tenant_id = $1
          AND status IN ('active', 'trialing', 'past_due')
          AND billing_cycle_start IS NOT NULL
        ORDER BY billing_cycle_start DESC
        LIMIT 1
        "#;

/// The most recent anchored billing-cycle start at or before `at` — the
/// same day-of-month walk (clamped to month length, Stripe-style) as
/// billing-service `most_recent_anchored_cycle`/`anchored_date` (usage.rs),
/// mirrored here because the compliance crate does not depend on
/// billing-service. A parity test pins the semantics together.
fn most_recent_anchored_cycle(at: DateTime<Utc>, anchor: NaiveDate) -> DateTime<Utc> {
    let mut year = at.year();
    let mut month = at.month();
    loop {
        let candidate = anchored_date(year, month, anchor.day());
        if let Some(start) = candidate.and_hms_opt(0, 0, 0) {
            let start = DateTime::<Utc>::from_naive_utc_and_offset(start, Utc);
            if start <= at {
                return start;
            }
        }
        if month == 1 {
            month = 12;
            year -= 1;
        } else {
            month -= 1;
        }
    }
}

/// `anchored_date` mirrored from billing-service usage.rs: the anchor's
/// day-of-month clamped to the month's length (a 31st anchor still fires
/// in shorter months).
fn anchored_date(year: i32, month: u32, day: u32) -> NaiveDate {
    let last_day = {
        let next = if month == 12 {
            NaiveDate::from_ymd_opt(year + 1, 1, 1)
        } else {
            NaiveDate::from_ymd_opt(year, month + 1, 1)
        }
        .expect("first of next month is always valid");
        (next - chrono::Duration::days(1)).day()
    };
    NaiveDate::from_ymd_opt(year, month, day.min(last_day)).expect("clamped day is always valid")
}

/// F61: the usage window start for `current_usage` — the enforced window.
/// Anchored tenants aggregate from their billing-cycle start (a cycle that
/// starts on the 15th must NOT reset on the 1st); everyone else from the
/// UTC calendar month. Same rule as `check_quota`'s DB fallback.
fn enforced_usage_window_start(at: DateTime<Utc>, anchor: Option<NaiveDate>) -> DateTime<Utc> {
    match anchor {
        Some(anchor) => most_recent_anchored_cycle(at, anchor),
        None => at
            .date_naive()
            .with_day(1)
            .unwrap_or(at.date_naive())
            .and_hms_opt(0, 0, 0)
            .unwrap_or_default()
            .and_utc(),
    }
}

// ─── F61: versioned enforced send-limits contract ───────────────────

/// Version of the limits contract exposed by this helper. Bump when any
/// exposed limit changes meaning.
pub const SEND_LIMITS_CONTRACT_VERSION: u32 = 2;

/// F61: the send limits ACTUALLY enforced by the API surface
/// (api-server routes/messages.rs). One versioned contract — the helper no
/// longer maintains an independent plan ladder for these dimensions.
///
/// * `batch_limit` reads the SAME environment variable
///   (`API_MESSAGES_MAX_BATCH_SIZE`) with the SAME default (100) the send
///   API's `MAX_BATCH_SIZE` uses — the previous hardcoded ladder (Developer
///   500 / Pro 1 000 / …) advertised batch sizes the API rejects.
/// * `attachment_limit_mb` is the enforced PER-ATTACHMENT decoded ceiling
///   (10 MiB, `MAX_ATTACHMENT_BYTES`). The previous ladder advertised
///   50/100 MB on higher plans — values no accepted request body can carry
///   (the route body limit is 10 MiB).
/// * `aggregate_attachment_limit_mb` / `max_attachments` mirror
///   `MAX_TOTAL_ATTACHMENT_BYTES` / `MAX_ATTACHMENTS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnforcedSendLimits {
    pub batch_limit: i32,
    pub attachment_limit_mb: i32,
    pub aggregate_attachment_limit_mb: i32,
    pub max_attachments: i32,
}

/// Mirrors the api-server constants (routes/messages.rs): per-attachment
/// decoded ceiling, aggregate ceiling, and attachment count ceiling.
const ENFORCED_MAX_ATTACHMENT_BYTES: usize = 10 * 1024 * 1024;
const ENFORCED_MAX_TOTAL_ATTACHMENT_BYTES: usize = 25 * 1024 * 1024;
const ENFORCED_MAX_ATTACHMENTS: usize = 50;
/// Mirrors the api-server default for `API_MESSAGES_MAX_BATCH_SIZE`.
const ENFORCED_DEFAULT_BATCH_SIZE: usize = 100;

pub fn enforced_send_limits() -> EnforcedSendLimits {
    enforced_send_limits_with(std::env::var("API_MESSAGES_MAX_BATCH_SIZE").ok().as_deref())
}

/// [`enforced_send_limits`] with the batch-override knob injected, so the
/// shared-contract behaviour is testable without touching process
/// environment state.
fn enforced_send_limits_with(batch_env: Option<&str>) -> EnforcedSendLimits {
    let batch_limit = batch_env
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(ENFORCED_DEFAULT_BATCH_SIZE);
    EnforcedSendLimits {
        batch_limit: batch_limit as i32,
        attachment_limit_mb: (ENFORCED_MAX_ATTACHMENT_BYTES / (1024 * 1024)) as i32,
        aggregate_attachment_limit_mb: (ENFORCED_MAX_TOTAL_ATTACHMENT_BYTES / (1024 * 1024)) as i32,
        max_attachments: ENFORCED_MAX_ATTACHMENTS as i32,
    }
}

/// Free-plan launch allowance, mirrored from billing-service usage.rs
/// (`FREE_PLAN_LAUNCH_ALLOWANCE`): the standing Free ceiling is widened to
/// 30 000 emails for a tenant's first 30 days. Parity requires the helper
/// to advertise the SAME effective allowance the quota gate enforces.
const FREE_PLAN_LAUNCH_ALLOWANCE: i64 = 30_000;
const FREE_PLAN_LAUNCH_WINDOW_DAYS: i64 = 30;

fn effective_email_allowance(row: &TenantEntitlementRow) -> i64 {
    let base = row.email_limit.unwrap_or(0);
    if row.plan_name != "free" || base < 0 {
        return base;
    }
    match row.tenant_created_at {
        // Same instant comparison as enforcement (`now - created < 30 days`).
        Some(created)
            if (Utc::now() - created) < chrono::Duration::days(FREE_PLAN_LAUNCH_WINDOW_DAYS) =>
        {
            FREE_PLAN_LAUNCH_ALLOWANCE
        }
        _ => base,
    }
}

/// Map the active contract's annual-prepay discount onto the response
/// fields. Only real, producer-backed discounts surface here — the legacy
/// `plan_discounts` notions (founding customer, startup program) have no
/// source and report `false` rather than invented values.
fn contract_discount(annual_prepay_discount: Option<i32>) -> (Option<String>, Option<f64>) {
    match annual_prepay_discount {
        Some(pct) if pct > 0 => (Some("annual_prepay".to_string()), Some(pct as f64)),
        _ => (None, None),
    }
}

pub async fn get_tenant_entitlements(
    pool: &PgPool,
    tenant_id: &str,
) -> Result<EntitlementResponse, anyhow::Error> {
    let row: Option<TenantEntitlementRow> = sqlx::query_as(TENANT_ENTITLEMENT_SQL)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await?;

    let Some(row) = row else {
        return Err(anyhow::anyhow!("Tenant {tenant_id} not found"));
    };

    let suspended = row.status == "suspended";
    let trial_or_beta = row.stripe_status.as_deref() == Some("trialing");
    // Computed before `features` is moved out of the row.
    let effective_allowance = effective_email_allowance(&row);

    // F61: aggregate usage over the SAME window enforcement charges — the
    // anchored billing cycle when a subscription defines one, the UTC
    // calendar month otherwise (mirror of `check_quota`'s DB fallback).
    let now = Utc::now();
    let cycle_anchor: Option<NaiveDate> = sqlx::query_scalar(TENANT_CYCLE_ANCHOR_SQL)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await?
        .flatten();
    let period_start = enforced_usage_window_start(now, cycle_anchor);
    let usage: (i64,) = sqlx::query_as(TENANT_USAGE_SQL)
        .bind(tenant_id)
        .bind(period_start)
        .fetch_one(pool)
        .await?;

    let features: serde_json::Value = row.features.unwrap_or_default();

    let domain_limit = features["max_sending_domains"].as_i64().unwrap_or(1) as i32;
    let user_limit = features["max_team_members"].as_i64().unwrap_or(1) as i32;
    let event_retention = features["max_retention_days"].as_i64().unwrap_or(7) as i32;
    let content_retention = features["max_retention_days"].as_i64().unwrap_or(1) as i32;
    let sso = features["sso_enabled"].as_bool().unwrap_or(false);
    let audit = features["audit_logs"].as_bool().unwrap_or(false);
    let dedicated_ips = features["dedicated_ip_count"].as_i64().unwrap_or(0) as i32;
    let subaccounts = features["max_subaccounts"].as_i64().unwrap_or(0) as i32;
    let sla = features["sla_guarantee"].as_bool().unwrap_or(false);
    let inbound = features["inbound_email"].as_bool().unwrap_or(false);

    let support_target = match row.plan_name.as_str() {
        "free" | "developer" => Some(48u32),
        "pro" | "growth" => Some(24),
        "business" => Some(8),
        "enterprise" => Some(4),
        _ => None,
    };

    let overage_rate = match row.plan_name.as_str() {
        "free" => 0,
        "developer" => 80,
        "pro" => 60,
        "growth" => 35,
        "business" => 35,
        "enterprise" => 35,
        _ => 40,
    };

    let api_key_limit: i32 = match row.plan_name.as_str() {
        "free" => 2,
        "developer" => 5,
        "pro" => 10,
        "growth" => 20,
        "business" => 50,
        "enterprise" => -1,
        _ => 5,
    };

    let smtp_credential_limit: i32 = match row.plan_name.as_str() {
        "free" => 1,
        "developer" => 3,
        "pro" => 5,
        "growth" => 10,
        "business" => 25,
        "enterprise" => -1,
        _ => 3,
    };

    let template_limit: i32 = match row.plan_name.as_str() {
        "free" => 5,
        "developer" => 25,
        "pro" => 100,
        "growth" => 250,
        "business" => -1,
        "enterprise" => -1,
        _ => 25,
    };

    let webhook_limit: i32 = match row.plan_name.as_str() {
        "free" => 0,
        "developer" => 3,
        "pro" => 5,
        "growth" => 10,
        "business" => 25,
        "enterprise" => 50,
        _ => 3,
    };

    // F61: batch and attachment limits are NOT plan-laddered here anymore —
    // see `enforced_send_limits()`; the API enforces one route-level
    // contract for every plan.

    let daily_send = match row.plan_name.as_str() {
        "free" => Some(100i64),
        "developer" => Some(5_000),
        "pro" => Some(15_000),
        _ => None,
    };

    let burst_limit = match row.plan_name.as_str() {
        "free" => Some(10i64),
        "developer" => Some(100),
        "pro" => Some(500),
        _ => None,
    };

    let (discount_type, discount_percentage) = contract_discount(row.annual_prepay_discount);

    // F61: batch/attachment limits come from the ONE versioned enforced
    // contract — no independent plan ladder (the previous Developer-500
    // batch / 50-100 MB attachment values advertised limits the API's
    // route/body limits reject).
    let send_limits = enforced_send_limits();

    // Expiring entitlements: the plan override's expiry timestamp. The
    // active contract's end date is surfaced separately via `contract_end`.
    let expiring_entitlements_at = row.override_expires_at;

    Ok(EntitlementResponse {
        active_plan: row.plan_name.clone(),
        contract_start: row.contract_start,
        contract_end: row.contract_end,
        // Authoritative allowance: the effective plan's email limit with
        // enforcement's free-plan launch allowance applied (F61) — the
        // override path swaps the plan rather than patching the number.
        monthly_message_allowance: effective_allowance,
        current_usage: usage.0,
        overage_rate_cents_per_1000: overage_rate,
        daily_send_limit: daily_send,
        hourly_burst_limit: burst_limit,
        sending_domain_limit: domain_limit,
        user_limit,
        api_key_limit,
        smtp_credential_limit,
        template_limit,
        webhook_endpoint_limit: webhook_limit,
        event_retention_days: event_retention,
        message_content_retention_days: content_retention,
        attachment_limit_mb: send_limits.attachment_limit_mb,
        batch_limit: send_limits.batch_limit,
        scheduling_horizon_days: 30,
        inbound_email: inbound,
        inbox_placement_credits: 0,
        grader_credits: 0,
        subaccount_limit: subaccounts,
        audit_logs: audit,
        sso_enabled: sso,
        scim_enabled: row.plan_name.as_str() == "enterprise",
        dedicated_ip_entitlement: dedicated_ips,
        support_target_hours: support_target,
        sla_eligible: sla,
        dpa_available: true,
        baa_review_eligible: matches!(row.plan_name.as_str(), "enterprise"),
        dedicated_tenancy_eligible: matches!(row.plan_name.as_str(), "enterprise"),
        byoc_eligible: matches!(row.plan_name.as_str(), "enterprise"),
        limits_contract_version: SEND_LIMITS_CONTRACT_VERSION,
        discount_type,
        discount_percentage,
        // No producer-backed source for these legacy plan_discounts flags.
        founding_customer: false,
        startup_program: false,
        // An active plan override is the real "contract override" signal.
        contract_override: row.has_override,
        expiring_entitlements_at,
        suspended,
        trial_or_beta,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entitlement_sql_resolves_effective_plan_via_overrides() {
        // Authoritative pattern (billing-service TENANT_PLAN_LIMITS_SQL):
        // an active, unexpired override wins over tenants.plan.
        assert!(TENANT_ENTITLEMENT_SQL.contains("plan_overrides po"));
        assert!(TENANT_ENTITLEMENT_SQL.contains("po.active = true"));
        assert!(TENANT_ENTITLEMENT_SQL.contains("po.expires_at > NOW()"));
        assert!(TENANT_ENTITLEMENT_SQL.contains("COALESCE(po.plan, t.plan)"));
    }

    #[test]
    fn entitlement_sql_reads_only_producer_backed_tables() {
        for table in [
            "tenants t",
            "plan_overrides po",
            "plans p",
            "enterprise_contracts",
            "stripe_subscriptions",
        ] {
            assert!(
                TENANT_ENTITLEMENT_SQL.contains(table),
                "expected entitlement source {table}"
            );
        }
        // F61: the absent, producer-less tables must be gone.
        assert!(!TENANT_ENTITLEMENT_SQL.contains("subscription_contracts"));
        assert!(!TENANT_ENTITLEMENT_SQL.contains("plan_discounts"));
    }

    #[test]
    fn entitlement_contract_window_requires_active_period() {
        assert!(TENANT_ENTITLEMENT_SQL.contains("status = 'active'"));
        assert!(TENANT_ENTITLEMENT_SQL.contains("start_date <= NOW()"));
        assert!(TENANT_ENTITLEMENT_SQL.contains("end_date > NOW()"));
    }

    #[test]
    fn usage_sql_reads_canonical_metering_counter() {
        // Same counter the quota-enforcement path charges…
        assert!(TENANT_USAGE_SQL.contains("FROM metering_events"));
        assert!(TENANT_USAGE_SQL.contains("event_type = 'emails_sent'"));
        assert!(!TENANT_USAGE_SQL.contains("FROM messages"));
        // …aggregated over the enforced WINDOW passed as a bind (F61): the
        // calendar-month date_trunc is gone, replaced by an anchored
        // billing-cycle start computed by the same rule as `check_quota`.
        assert!(TENANT_USAGE_SQL.contains("timestamp >= $2"));
        assert!(!TENANT_USAGE_SQL.contains("date_trunc"));
    }

    #[test]
    fn usage_window_mirrors_enforcement_anchor_rule() {
        // The anchor SQL mirrors billing-service `tenant_cycle_anchor`.
        for clause in [
            "status IN ('active', 'trialing', 'past_due')",
            "billing_cycle_start IS NOT NULL",
            "ORDER BY billing_cycle_start DESC",
        ] {
            assert!(TENANT_CYCLE_ANCHOR_SQL.contains(clause), "{clause}");
        }
    }

    /// Parity with the enforcement window math: a tenant whose cycle
    /// anchors on the 15th gets a period start on the most recent 15th,
    /// NOT the calendar 1st; without an anchor it is the calendar month
    /// start.
    #[test]
    fn enforced_usage_window_starts_at_the_anchor_day() {
        let at = DateTime::parse_from_rfc3339("2026-09-10T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let anchor = NaiveDate::from_ymd_opt(2026, 3, 15).unwrap();
        // September's 15th is still in the future at Sept 10, so the
        // current cycle started on August 15th — NOT the calendar Sept 1st
        // (which would hand the tenant a fresh quota window mid-cycle).
        let start = enforced_usage_window_start(at, Some(anchor));
        assert_eq!(start.to_rfc3339(), "2026-08-15T00:00:00+00:00");

        // Clamped anchor (31st) still fires in a 30-day month.
        let anchor = NaiveDate::from_ymd_opt(2026, 1, 31).unwrap();
        let start = enforced_usage_window_start(at, Some(anchor));
        assert_eq!(start.to_rfc3339(), "2026-08-31T00:00:00+00:00");

        // No anchor → UTC calendar month start.
        let start = enforced_usage_window_start(at, None);
        assert_eq!(start.to_rfc3339(), "2026-09-01T00:00:00+00:00");
    }

    #[test]
    fn contract_discount_maps_active_prepay_only() {
        assert_eq!(contract_discount(None), (None, None));
        assert_eq!(contract_discount(Some(0)), (None, None));
        assert_eq!(contract_discount(Some(-5)), (None, None));
        let (kind, pct) = contract_discount(Some(20));
        assert_eq!(kind.as_deref(), Some("annual_prepay"));
        assert_eq!(pct, Some(20.0));
    }

    // ── F61: enforced send-limits parity ──────────────────────────

    /// The helper advertises exactly the batch size the send API accepts —
    /// the API default (100), not the previous Developer-500 ladder that
    /// the API would reject with 400.
    #[test]
    fn batch_limit_matches_the_api_default_contract() {
        let limits = enforced_send_limits();
        assert_eq!(
            limits.batch_limit, 100,
            "must match API_MESSAGES_MAX_BATCH_SIZE default"
        );
    }

    /// The environment override the API reads is honoured here too — one
    /// contract, one knob (invalid values keep the default, like the API).
    #[test]
    fn batch_limit_follows_the_shared_env_override() {
        assert_eq!(enforced_send_limits_with(Some("250")).batch_limit, 250);
        assert_eq!(enforced_send_limits_with(Some("0")).batch_limit, 100);
        assert_eq!(
            enforced_send_limits_with(Some("not-a-number")).batch_limit,
            100
        );
        assert_eq!(enforced_send_limits_with(None).batch_limit, 100);
    }

    /// Attachment limits are the enforced transport ceilings (10 MiB per
    /// attachment / 25 MiB aggregate / 50 items) — never a plan ladder that
    /// advertises bodies the 10 MiB route limit cannot carry.
    #[test]
    fn attachment_limits_match_enforced_ceilings() {
        let limits = enforced_send_limits();
        assert_eq!(limits.attachment_limit_mb, 10);
        assert_eq!(limits.aggregate_attachment_limit_mb, 25);
        assert_eq!(limits.max_attachments, 50);
    }

    /// Parity of the effective email allowance: the free-plan launch
    /// allowance applies exactly as enforcement computes it (first 30 days,
    /// free plan only, overrides to other plans never widened, unlimited
    /// plans untouched).
    #[test]
    fn effective_allowance_mirrors_the_launch_rule() {
        fn row(plan: &str, created: Option<DateTime<Utc>>, limit: i64) -> TenantEntitlementRow {
            TenantEntitlementRow {
                tenant_id: "t".into(),
                plan_name: plan.into(),
                has_override: false,
                override_expires_at: None,
                status: "active".into(),
                tenant_created_at: created,
                email_limit: Some(limit),
                api_call_limit: None,
                features: None,
                contract_start: None,
                contract_end: None,
                annual_prepay_discount: None,
                stripe_status: None,
            }
        }
        let now = Utc::now();
        // Fresh free tenant → widened launch allowance.
        assert_eq!(
            effective_email_allowance(&row("free", Some(now - chrono::Duration::days(10)), 3_000)),
            FREE_PLAN_LAUNCH_ALLOWANCE
        );
        // Free tenant past the window → standing ceiling.
        assert_eq!(
            effective_email_allowance(&row("free", Some(now - chrono::Duration::days(40)), 3_000)),
            3_000
        );
        // Unknown creation date → not widened (matches enforcement).
        assert_eq!(effective_email_allowance(&row("free", None, 3_000)), 3_000);
        // Paid plans are never widened.
        assert_eq!(
            effective_email_allowance(&row("developer", Some(now), 10_000)),
            10_000
        );
        // Unlimited plans untouched.
        assert_eq!(
            effective_email_allowance(&row("enterprise", Some(now), -1)),
            -1
        );
    }

    /// The response carries the limits contract version so API, console,
    /// quota and helper surfaces can detect drift.
    #[test]
    fn response_exposes_the_limits_contract_version() {
        // Compile-time pin: the version must exist and be the current one.
        const _: () = assert!(SEND_LIMITS_CONTRACT_VERSION == 2);
        // And it is carried on the response DTO (parsed from a literal so
        // the json! macro does not exhaust the crate's recursion limit).
        let fixture = r#"{
            "active_plan": "free", "contract_start": null, "contract_end": null,
            "monthly_message_allowance": 3000, "current_usage": 10,
            "overage_rate_cents_per_1000": 0, "daily_send_limit": 100,
            "hourly_burst_limit": 10, "sending_domain_limit": 1, "user_limit": 1,
            "api_key_limit": 2, "smtp_credential_limit": 1, "template_limit": 5,
            "webhook_endpoint_limit": 0, "event_retention_days": 7,
            "message_content_retention_days": 1, "attachment_limit_mb": 10,
            "batch_limit": 100, "scheduling_horizon_days": 30, "inbound_email": false,
            "inbox_placement_credits": 0, "grader_credits": 0, "subaccount_limit": 0,
            "audit_logs": false, "sso_enabled": false, "scim_enabled": false,
            "dedicated_ip_entitlement": 0, "support_target_hours": 48,
            "sla_eligible": false, "dpa_available": true, "baa_review_eligible": false,
            "dedicated_tenancy_eligible": false, "byoc_eligible": false,
            "limits_contract_version": 2, "discount_type": null,
            "discount_percentage": null, "founding_customer": false,
            "startup_program": false, "contract_override": false,
            "expiring_entitlements_at": null, "suspended": false, "trial_or_beta": false
        }"#;
        let response: EntitlementResponse =
            serde_json::from_str(fixture).expect("response DTO carries limits_contract_version");
        assert_eq!(
            response.limits_contract_version,
            SEND_LIMITS_CONTRACT_VERSION
        );
        assert_eq!(response.batch_limit, 100);
        assert_eq!(response.attachment_limit_mb, 10);
    }
}
