//! §19 — the revenue attribution chain.
//!
//! The engine must be able to answer: *which discovery source, segment,
//! evidence pattern, offer, message angle and sequence actually created paid
//! revenue?* This module records the outcome ladder into `sales_outcomes` and
//! reports it by joining the canonical tables:
//!
//! ```text
//! discovery source → account/contact → decision → sequence enrollment
//!   → step execution → platform message id → reply → meeting → trial
//!   → subscription → invoice/paid MRR
//! ```
//!
//! Persistence details:
//!
//! * `record_outcome` is idempotent on the documented unique key
//!   `(tenant_id, outcome, step_execution_id)`
//!   (migration 200_sales_autopilot_v2_unification.sql:777): replaying the
//!   same logical outcome updates the existing row instead of adding revenue
//!   a second time. Postgres treats `NULL`s as distinct in a UNIQUE
//!   constraint, so rows recorded **without** a `step_execution_id` have no
//!   database-enforced idempotency — pass the step execution whenever one
//!   exists.
//! * `attribute_revenue` is read-only and tenant-scoped.
//!
//! Units: monetary values are EUR; rates are fractions in `0.0..=1.0` and are
//! documented at each field. A metric whose denominator is zero or whose
//! inputs are entirely missing is `None`, never a misleading `0` or `inf`.
//!
//! **Clicks and opens are secondary.** They are recorded (the outcome ladder
//! includes them) but deliberately excluded from every headline metric here:
//! Apple Mail Privacy Protection and automated image fetching make them too
//! weak to optimize against. They are exposed only through the clearly
//! labelled [`click_metrics`] accessor.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::SalesError;

/// Outcome vocabulary — exact wire strings of the `sales_outcomes.outcome`
/// CHECK constraint (migration 200_sales_autopilot_v2_unification.sql:768-771).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeKind {
    Delivered,
    Open,
    Click,
    Reply,
    PositiveReply,
    MeetingBooked,
    MeetingAttended,
    Trial,
    PaidSubscription,
    RetainedMrr,
    Bounce,
    Complaint,
    Unsubscribe,
}

impl OutcomeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Open => "open",
            Self::Click => "click",
            Self::Reply => "reply",
            Self::PositiveReply => "positive_reply",
            Self::MeetingBooked => "meeting_booked",
            Self::MeetingAttended => "meeting_attended",
            Self::Trial => "trial",
            Self::PaidSubscription => "paid_subscription",
            Self::RetainedMrr => "retained_mrr",
            Self::Bounce => "bounce",
            Self::Complaint => "complaint",
            Self::Unsubscribe => "unsubscribe",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "delivered" => Some(Self::Delivered),
            "open" => Some(Self::Open),
            "click" => Some(Self::Click),
            "reply" => Some(Self::Reply),
            "positive_reply" => Some(Self::PositiveReply),
            "meeting_booked" => Some(Self::MeetingBooked),
            "meeting_attended" => Some(Self::MeetingAttended),
            "trial" => Some(Self::Trial),
            "paid_subscription" => Some(Self::PaidSubscription),
            "retained_mrr" => Some(Self::RetainedMrr),
            "bounce" => Some(Self::Bounce),
            "complaint" => Some(Self::Complaint),
            "unsubscribe" => Some(Self::Unsubscribe),
            _ => None,
        }
    }

    /// The migration's own revenue index predicate
    /// (`idx_sales_outcomes_revenue`, line 783) names exactly these outcomes
    /// as revenue-bearing.
    pub fn is_revenue(self) -> bool {
        matches!(
            self,
            Self::Trial | Self::PaidSubscription | Self::RetainedMrr
        )
    }

    /// Qualified-reply ladder: anything at or above a positive reply implies
    /// the contact engaged commercially.
    pub fn is_qualified_reply(self) -> bool {
        matches!(
            self,
            Self::PositiveReply
                | Self::MeetingBooked
                | Self::MeetingAttended
                | Self::Trial
                | Self::PaidSubscription
                | Self::RetainedMrr
        )
    }

    /// Does this outcome add a paying customer?
    pub fn is_paying_customer(self) -> bool {
        matches!(self, Self::PaidSubscription | Self::RetainedMrr)
    }

    /// Meetings (booked or attended) count toward meeting conversion.
    pub fn is_meeting(self) -> bool {
        matches!(self, Self::MeetingBooked | Self::MeetingAttended)
    }
}

impl std::fmt::Display for OutcomeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One outcome to record. Only `outcome` is mandatory; everything else may be
/// `None` when the platform does not know it yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutcomeRecord {
    pub account_id: Option<Uuid>,
    pub contact_id: Option<Uuid>,
    pub enrollment_id: Option<Uuid>,
    /// The idempotency key component. Supply it for every replayable
    /// outcome; without it the unique constraint cannot dedupe.
    pub step_execution_id: Option<Uuid>,
    /// Where the account originally came from (attribution dimension).
    pub discovery_source: Option<String>,
    pub offer: Option<String>,
    pub outcome: OutcomeKind,
    /// EUR. Finite; negative values are allowed to model corrections, but a
    /// non-finite value is rejected.
    pub value_eur: f64,
    pub message_id: Option<Uuid>,
    pub provider: Option<String>,
    pub occurred_at: Option<DateTime<Utc>>,
}

impl OutcomeRecord {
    pub fn new(outcome: OutcomeKind) -> Self {
        Self {
            account_id: None,
            contact_id: None,
            enrollment_id: None,
            step_execution_id: None,
            discovery_source: None,
            offer: None,
            outcome,
            value_eur: 0.0,
            message_id: None,
            provider: None,
            occurred_at: None,
        }
    }

    pub fn with_value_eur(mut self, value_eur: f64) -> Self {
        self.value_eur = value_eur;
        self
    }
}

/// Record one outcome, idempotent on `(tenant_id, outcome, step_execution_id)`.
///
/// Replaying the same logical outcome returns the original row id and does
/// **not** double-count `value_eur`; the second write refreshes the mutable
/// fields (value, occurred_at, and any previously-null linkage).
pub async fn record_outcome(
    db: &PgPool,
    tenant_id: &str,
    record: &OutcomeRecord,
) -> Result<Uuid, SalesError> {
    if tenant_id.trim().is_empty() {
        return Err(SalesError::InvalidInput("tenant_id is required".into()));
    }
    if !record.value_eur.is_finite() {
        return Err(SalesError::InvalidInput(format!(
            "outcome value_eur must be finite, got {}",
            record.value_eur
        )));
    }

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO sales_outcomes (
            id, tenant_id, account_id, contact_id, enrollment_id, step_execution_id,
            discovery_source, offer, outcome, value_eur, message_id, provider,
            occurred_at, created_at
         ) VALUES (
            $1, $2, $3, $4, $5, $6,
            $7, $8, $9, $10::float8::numeric, $11, $12,
            COALESCE($13, NOW()), NOW()
         )
         ON CONFLICT (tenant_id, outcome, step_execution_id) DO UPDATE SET
            value_eur = EXCLUDED.value_eur,
            occurred_at = EXCLUDED.occurred_at,
            message_id = COALESCE(EXCLUDED.message_id, sales_outcomes.message_id),
            provider = COALESCE(EXCLUDED.provider, sales_outcomes.provider),
            discovery_source = COALESCE(EXCLUDED.discovery_source, sales_outcomes.discovery_source),
            offer = COALESCE(EXCLUDED.offer, sales_outcomes.offer),
            account_id = COALESCE(EXCLUDED.account_id, sales_outcomes.account_id),
            contact_id = COALESCE(EXCLUDED.contact_id, sales_outcomes.contact_id),
            enrollment_id = COALESCE(EXCLUDED.enrollment_id, sales_outcomes.enrollment_id)
         RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(record.account_id)
    .bind(record.contact_id)
    .bind(record.enrollment_id)
    .bind(record.step_execution_id)
    .bind(&record.discovery_source)
    .bind(&record.offer)
    .bind(record.outcome.as_str())
    .bind(record.value_eur)
    .bind(record.message_id)
    .bind(&record.provider)
    .bind(record.occurred_at)
    .fetch_one(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(id)
}

// ---------------------------------------------------------------------------
// Report shape
// ---------------------------------------------------------------------------

/// Half-open reporting window `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributionWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl AttributionWindow {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        Self { start, end }
    }

    /// Zero-length (or inverted) windows are legal: they select no rows and
    /// every metric comes back `None`/zero rather than an error.
    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }

    pub fn duration_days(&self) -> f64 {
        (self.end - self.start).num_seconds() as f64 / 86_400.0
    }
}

/// Revenue split by the dimensions the audit asks about: discovery source,
/// ICP segment, offer and sequence (message angle is carried on the step
/// execution; the sequence name is the stable proxy at report level).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttributionBreakdown {
    pub discovery_source: Option<String>,
    pub icp_segment: Option<String>,
    pub offer: Option<String>,
    pub sequence_name: Option<String>,
    pub contacts: u64,
    pub meetings: u64,
    pub paying_customers: u64,
    pub revenue_eur: f64,
}

/// The headline attribution report. All rates are fractions in `0.0..=1.0`;
/// all monetary values are EUR. `None` means "inputs missing", never zero.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttributionReport {
    pub window: AttributionWindow,
    pub discovered_accounts: u64,
    /// Distinct contacts with a `sent` step execution in the window.
    pub contacted_contacts: u64,
    /// Distinct contacts with an at-or-above-positive-reply outcome.
    pub qualified_reply_contacts: u64,
    /// `sales_meetings` rows created in the window.
    pub meetings_booked: u64,
    pub trials: u64,
    /// Distinct paying customers (paid_subscription or retained_mrr).
    pub paying_customers: u64,
    /// Sum of `value_eur` over the three revenue outcomes.
    pub revenue_created_eur: Option<f64>,
    /// Sum of `value_eur` over `retained_mrr` only.
    pub mrr_created_eur: Option<f64>,
    /// Open/qualified/negotiation/won opportunities created in the window.
    pub pipeline_created_eur: Option<f64>,
    /// Meetings-booked contacts ÷ qualified-reply contacts.
    pub meeting_conversion: Option<f64>,
    /// Qualified-reply contacts ÷ contacted contacts.
    pub qualified_reply_rate: Option<f64>,
    /// Revenue ÷ discovered accounts × 1000; `None` when nothing was
    /// discovered (never `0` or `inf`).
    pub revenue_per_1000_discovered_eur: Option<f64>,
    /// Revenue ÷ contacted contacts × 1000; `None` when nobody was contacted.
    pub revenue_per_1000_contacted_eur: Option<f64>,
    /// Total recorded cost ÷ paying customers; `None` without customers.
    pub cac_eur: Option<f64>,
    pub enrichment_cost_eur: Option<f64>,
    /// Cumulative `sales_provider_stats.total_cost_eur` for provider rows
    /// last touched in the window — a snapshot, not a per-call ledger.
    pub provider_cost_eur: Option<f64>,
    pub total_cost_eur: Option<f64>,
    /// Revenue − total recorded cost; `None` when revenue is unknown.
    pub gross_profit_acquired_eur: Option<f64>,
    pub by_discovery_source: Vec<AttributionBreakdown>,
}

/// `revenue × 1000 ÷ denominator`. `None` when revenue is unknown or the
/// denominator is zero, so a zero-denominator report can never show `0` or
/// `inf` for a per-1000 metric.
pub fn per_1000(revenue_eur: Option<f64>, denominator: u64) -> Option<f64> {
    let revenue = revenue_eur?;
    if denominator == 0 || !revenue.is_finite() {
        return None;
    }
    let value = revenue * 1000.0 / denominator as f64;
    if value.is_finite() {
        Some(value)
    } else {
        None
    }
}

/// Fraction in `0.0..=1.0`; `None` when the denominator is zero.
pub fn fraction(numerator: u64, denominator: u64) -> Option<f64> {
    if denominator == 0 {
        return None;
    }
    Some((numerator as f64 / denominator as f64).clamp(0.0, 1.0))
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

async fn count(
    db: &PgPool,
    sql: &str,
    tenant_id: &str,
    window: &AttributionWindow,
) -> Result<u64, SalesError> {
    let value: i64 = sqlx::query_scalar(sql)
        .bind(tenant_id)
        .bind(window.start)
        .bind(window.end)
        .fetch_one(db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(value.max(0) as u64)
}

async fn sum_cost(
    db: &PgPool,
    sql: &str,
    tenant_id: &str,
    window: &AttributionWindow,
) -> Result<Option<f64>, SalesError> {
    let row: (i64, f64) = sqlx::query_as(sql)
        .bind(tenant_id)
        .bind(window.start)
        .bind(window.end)
        .fetch_one(db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
    if row.0 <= 0 {
        Ok(None)
    } else {
        Ok(Some(row.1))
    }
}

/// Compute the full attribution report for a tenant and window.
///
/// Read-only; joins `sales_outcomes` → `sales_step_executions` →
/// `sales_enrollments` → `sales_sequence_versions` → `sales_sequences` for
/// the breakdown, and `sales_accounts`, `sales_meetings`,
/// `sales_opportunities`, `sales_enrichment_facts`, `sales_provider_stats`
/// for the funnel and cost legs. Tenant scoping is applied on every leg.
pub async fn attribute_revenue(
    db: &PgPool,
    tenant_id: &str,
    window: AttributionWindow,
) -> Result<AttributionReport, SalesError> {
    if tenant_id.trim().is_empty() {
        return Err(SalesError::InvalidInput("tenant_id is required".into()));
    }

    let discovered_accounts = count(
        db,
        "SELECT COUNT(*)::bigint FROM sales_accounts
         WHERE tenant_id = $1 AND created_at >= $2 AND created_at < $3",
        tenant_id,
        &window,
    )
    .await?;

    let contacted_contacts = count(
        db,
        "SELECT COUNT(DISTINCT e.contact_id)::bigint
         FROM sales_step_executions se
         JOIN sales_enrollments e ON e.id = se.enrollment_id AND e.tenant_id = se.tenant_id
         WHERE se.tenant_id = $1 AND se.state = 'sent'
           AND se.executed_at >= $2 AND se.executed_at < $3",
        tenant_id,
        &window,
    )
    .await?;

    let qualified_reply_contacts = count(
        db,
        "SELECT COUNT(DISTINCT contact_id)::bigint FROM sales_outcomes
         WHERE tenant_id = $1 AND occurred_at >= $2 AND occurred_at < $3
           AND outcome IN ('positive_reply', 'meeting_booked', 'meeting_attended',
                           'trial', 'paid_subscription', 'retained_mrr')",
        tenant_id,
        &window,
    )
    .await?;

    let meeting_contacts = count(
        db,
        "SELECT COUNT(DISTINCT contact_id)::bigint FROM sales_outcomes
         WHERE tenant_id = $1 AND occurred_at >= $2 AND occurred_at < $3
           AND outcome IN ('meeting_booked', 'meeting_attended')",
        tenant_id,
        &window,
    )
    .await?;

    let meetings_booked = count(
        db,
        "SELECT COUNT(*)::bigint FROM sales_meetings
         WHERE tenant_id = $1 AND created_at >= $2 AND created_at < $3",
        tenant_id,
        &window,
    )
    .await?;

    let trials = count(
        db,
        "SELECT COUNT(DISTINCT contact_id)::bigint FROM sales_outcomes
         WHERE tenant_id = $1 AND occurred_at >= $2 AND occurred_at < $3 AND outcome = 'trial'",
        tenant_id,
        &window,
    )
    .await?;

    let paying_customers = count(
        db,
        "SELECT COUNT(DISTINCT contact_id)::bigint FROM sales_outcomes
         WHERE tenant_id = $1 AND occurred_at >= $2 AND occurred_at < $3
           AND outcome IN ('paid_subscription', 'retained_mrr')",
        tenant_id,
        &window,
    )
    .await?;

    // Revenue / MRR from the migration's own revenue-outcome set.
    let revenue_row: (i64, f64) = sqlx::query_as(
        "SELECT COUNT(*)::bigint, COALESCE(SUM(value_eur), 0)::float8 FROM sales_outcomes
         WHERE tenant_id = $1 AND occurred_at >= $2 AND occurred_at < $3
           AND outcome IN ('trial', 'paid_subscription', 'retained_mrr')",
    )
    .bind(tenant_id)
    .bind(window.start)
    .bind(window.end)
    .fetch_one(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    let revenue_created_eur = (revenue_row.0 > 0).then_some(revenue_row.1);

    let mrr_row: (i64, f64) = sqlx::query_as(
        "SELECT COUNT(*)::bigint, COALESCE(SUM(value_eur), 0)::float8 FROM sales_outcomes
         WHERE tenant_id = $1 AND occurred_at >= $2 AND occurred_at < $3
           AND outcome = 'retained_mrr'",
    )
    .bind(tenant_id)
    .bind(window.start)
    .bind(window.end)
    .fetch_one(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    let mrr_created_eur = (mrr_row.0 > 0).then_some(mrr_row.1);

    // Pipeline: opportunities created in the window, excluding lost deals.
    let pipeline_row: (i64, f64) = sqlx::query_as(
        "SELECT COUNT(*)::bigint, COALESCE(SUM(amount_eur), 0)::float8 FROM sales_opportunities
         WHERE tenant_id = $1 AND created_at >= $2 AND created_at < $3 AND stage <> 'lost'",
    )
    .bind(tenant_id)
    .bind(window.start)
    .bind(window.end)
    .fetch_one(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    let pipeline_created_eur = (pipeline_row.0 > 0).then_some(pipeline_row.1);

    let enrichment_cost_eur = sum_cost(
        db,
        "SELECT COUNT(*)::bigint, COALESCE(SUM(cost_eur), 0)::float8 FROM sales_enrichment_facts
         WHERE tenant_id = $1 AND created_at >= $2 AND created_at < $3",
        tenant_id,
        &window,
    )
    .await?;
    let provider_cost_eur = sum_cost(
        db,
        "SELECT COUNT(*)::bigint, COALESCE(SUM(total_cost_eur), 0)::float8 FROM sales_provider_stats
         WHERE tenant_id = $1 AND updated_at >= $2 AND updated_at < $3",
        tenant_id,
        &window,
    )
    .await?;
    let total_cost_eur = match (enrichment_cost_eur, provider_cost_eur) {
        (None, None) => None,
        (a, b) => Some(a.unwrap_or(0.0) + b.unwrap_or(0.0)),
    };

    let meeting_conversion = fraction(meeting_contacts, qualified_reply_contacts);
    let qualified_reply_rate = fraction(qualified_reply_contacts, contacted_contacts);
    let revenue_per_1000_discovered_eur = per_1000(revenue_created_eur, discovered_accounts);
    let revenue_per_1000_contacted_eur = per_1000(revenue_created_eur, contacted_contacts);
    let cac_eur = match (total_cost_eur, paying_customers) {
        (Some(cost), customers) if customers > 0 => Some(cost / customers as f64),
        _ => None,
    };
    let gross_profit_acquired_eur =
        revenue_created_eur.map(|revenue| revenue - total_cost_eur.unwrap_or(0.0));

    let by_discovery_source = attribute_breakdown(db, tenant_id, &window).await?;

    Ok(AttributionReport {
        window,
        discovered_accounts,
        contacted_contacts,
        qualified_reply_contacts,
        meetings_booked,
        trials,
        paying_customers,
        revenue_created_eur,
        mrr_created_eur,
        pipeline_created_eur,
        meeting_conversion,
        qualified_reply_rate,
        revenue_per_1000_discovered_eur,
        revenue_per_1000_contacted_eur,
        cac_eur,
        enrichment_cost_eur,
        provider_cost_eur,
        total_cost_eur,
        gross_profit_acquired_eur,
        by_discovery_source,
    })
}

/// Revenue grouped by the attribution chain dimensions.
async fn attribute_breakdown(
    db: &PgPool,
    tenant_id: &str,
    window: &AttributionWindow,
) -> Result<Vec<AttributionBreakdown>, SalesError> {
    use sqlx::Row;

    let rows = sqlx::query(
        "SELECT o.discovery_source,
                a.icp_segment,
                o.offer,
                s.name AS sequence_name,
                COUNT(DISTINCT o.contact_id)::bigint AS contacts,
                COUNT(DISTINCT o.contact_id) FILTER (
                    WHERE o.outcome IN ('meeting_booked', 'meeting_attended')
                )::bigint AS meetings,
                COUNT(DISTINCT o.contact_id) FILTER (
                    WHERE o.outcome IN ('paid_subscription', 'retained_mrr')
                )::bigint AS paying_customers,
                COALESCE(SUM(o.value_eur) FILTER (
                    WHERE o.outcome IN ('trial', 'paid_subscription', 'retained_mrr')
                ), 0)::float8 AS revenue_eur
         FROM sales_outcomes o
         LEFT JOIN sales_accounts a
                ON a.id = o.account_id AND a.tenant_id = o.tenant_id
         LEFT JOIN sales_step_executions se
                ON se.id = o.step_execution_id AND se.tenant_id = o.tenant_id
         LEFT JOIN sales_enrollments e
                ON e.id = COALESCE(o.enrollment_id, se.enrollment_id)
               AND e.tenant_id = o.tenant_id
         LEFT JOIN sales_sequence_versions sv
                ON sv.id = e.sequence_version_id AND sv.tenant_id = o.tenant_id
         LEFT JOIN sales_sequences s
                ON s.id = sv.sequence_id AND s.tenant_id = o.tenant_id
         WHERE o.tenant_id = $1 AND o.occurred_at >= $2 AND o.occurred_at < $3
         GROUP BY o.discovery_source, a.icp_segment, o.offer, s.name
         ORDER BY revenue_eur DESC, contacts DESC",
    )
    .bind(tenant_id)
    .bind(window.start)
    .bind(window.end)
    .fetch_all(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    rows.into_iter()
        .map(|row| {
            Ok(AttributionBreakdown {
                discovery_source: row
                    .try_get("discovery_source")
                    .map_err(|e| SalesError::Database(e.to_string()))?,
                icp_segment: row
                    .try_get("icp_segment")
                    .map_err(|e| SalesError::Database(e.to_string()))?,
                offer: row
                    .try_get("offer")
                    .map_err(|e| SalesError::Database(e.to_string()))?,
                sequence_name: row
                    .try_get("sequence_name")
                    .map_err(|e| SalesError::Database(e.to_string()))?,
                contacts: row
                    .try_get::<i64, _>("contacts")
                    .map_err(|e| SalesError::Database(e.to_string()))?
                    .max(0) as u64,
                meetings: row
                    .try_get::<i64, _>("meetings")
                    .map_err(|e| SalesError::Database(e.to_string()))?
                    .max(0) as u64,
                paying_customers: row
                    .try_get::<i64, _>("paying_customers")
                    .map_err(|e| SalesError::Database(e.to_string()))?
                    .max(0) as u64,
                revenue_eur: row
                    .try_get("revenue_eur")
                    .map_err(|e| SalesError::Database(e.to_string()))?,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Secondary engagement metrics (explicitly NOT part of attribution)
// ---------------------------------------------------------------------------

/// SECONDARY, diagnostic-only engagement metrics.
///
/// Opens and clicks are recorded in `sales_outcomes` but are **not** reward
/// signals and appear in no headline report: Apple Mail Privacy Protection
/// pre-fetches pixels and security scanners fetch links, so neither measures
/// human attention. Use for deliverability diagnostics only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClickMetrics {
    pub delivered: u64,
    pub opens: u64,
    pub clicks: u64,
    /// opens ÷ delivered.
    pub open_rate: Option<f64>,
    /// clicks ÷ delivered.
    pub click_rate: Option<f64>,
}

/// Read the secondary open/click diagnostics for a window. Labelled
/// secondary at the type, function and field level on purpose.
pub async fn click_metrics(
    db: &PgPool,
    tenant_id: &str,
    window: AttributionWindow,
) -> Result<ClickMetrics, SalesError> {
    let delivered = count(
        db,
        "SELECT COUNT(DISTINCT contact_id)::bigint FROM sales_outcomes
         WHERE tenant_id = $1 AND occurred_at >= $2 AND occurred_at < $3 AND outcome = 'delivered'",
        tenant_id,
        &window,
    )
    .await?;
    let opens = count(
        db,
        "SELECT COUNT(DISTINCT contact_id)::bigint FROM sales_outcomes
         WHERE tenant_id = $1 AND occurred_at >= $2 AND occurred_at < $3 AND outcome = 'open'",
        tenant_id,
        &window,
    )
    .await?;
    let clicks = count(
        db,
        "SELECT COUNT(DISTINCT contact_id)::bigint FROM sales_outcomes
         WHERE tenant_id = $1 AND occurred_at >= $2 AND occurred_at < $3 AND outcome = 'click'",
        tenant_id,
        &window,
    )
    .await?;

    Ok(ClickMetrics {
        delivered,
        opens,
        clicks,
        open_rate: fraction(opens, delivered),
        click_rate: fraction(clicks, delivered),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(hours: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 11, 12, 0, 0).unwrap() + chrono::Duration::hours(hours)
    }

    #[test]
    fn outcome_wire_strings_match_the_migration_check() {
        // Exact CHECK values from migration 200 line 768-771.
        let expected = [
            "delivered",
            "open",
            "click",
            "reply",
            "positive_reply",
            "meeting_booked",
            "meeting_attended",
            "trial",
            "paid_subscription",
            "retained_mrr",
            "bounce",
            "complaint",
            "unsubscribe",
        ];
        for wire in expected {
            let outcome = OutcomeKind::parse(wire).unwrap_or_else(|| panic!("parse {wire}"));
            assert_eq!(outcome.as_str(), wire);
        }
        assert_eq!(OutcomeKind::parse("unknown_outcome"), None);
        assert_eq!(
            OutcomeKind::parse("  delivered  "),
            Some(OutcomeKind::Delivered)
        );
    }

    #[test]
    fn outcome_classification_matches_the_revenue_index() {
        // migration 200 line 783: WHERE outcome IN ('trial','paid_subscription','retained_mrr')
        for outcome in [
            OutcomeKind::Trial,
            OutcomeKind::PaidSubscription,
            OutcomeKind::RetainedMrr,
        ] {
            assert!(outcome.is_revenue(), "{outcome}");
            assert!(outcome.is_qualified_reply(), "{outcome}");
        }
        for outcome in [
            OutcomeKind::Delivered,
            OutcomeKind::Open,
            OutcomeKind::Click,
            OutcomeKind::Reply,
            OutcomeKind::Bounce,
            OutcomeKind::Complaint,
            OutcomeKind::Unsubscribe,
        ] {
            assert!(!outcome.is_revenue(), "{outcome} must not be revenue");
            assert!(!outcome.is_paying_customer(), "{outcome}");
        }
        assert!(OutcomeKind::PaidSubscription.is_paying_customer());
        assert!(OutcomeKind::RetainedMrr.is_paying_customer());
        assert!(OutcomeKind::MeetingBooked.is_meeting());
        assert!(!OutcomeKind::Reply.is_qualified_reply());
    }

    #[test]
    fn per_1000_zero_denominator_is_none_never_zero_or_infinity() {
        assert_eq!(per_1000(Some(1_000.0), 0), None);
        assert_eq!(per_1000(None, 100), None);
        assert_eq!(per_1000(Some(f64::NAN), 100), None);
        assert_eq!(per_1000(Some(f64::INFINITY), 100), None);
        assert_eq!(per_1000(Some(500.0), 1_000), Some(500.0));
        // A huge-but-finite ratio stays finite.
        let huge = per_1000(Some(1e300), 1).expect("finite");
        assert!(huge.is_finite());
    }

    #[test]
    fn fraction_zero_denominator_is_none() {
        assert_eq!(fraction(0, 0), None);
        assert_eq!(fraction(5, 10), Some(0.5));
        assert_eq!(fraction(10, 5), Some(1.0), "rates are clamped to 0..=1");
    }

    #[test]
    fn hostile_windows_are_legal_and_do_not_panic() {
        let zero = AttributionWindow::new(at(0), at(0));
        assert!(zero.is_empty());
        assert_eq!(zero.duration_days(), 0.0);

        let inverted = AttributionWindow::new(at(1), at(-1));
        assert!(inverted.is_empty());

        let century = AttributionWindow::new(at(0), at(24 * 365 * 100));
        assert!(!century.is_empty());
        assert!((century.duration_days() - 36_500.0).abs() < 2.0);

        let max_window = AttributionWindow::new(DateTime::<Utc>::MIN_UTC, DateTime::<Utc>::MAX_UTC);
        assert!(!max_window.is_empty());
        assert!(max_window.duration_days() > 0.0);
    }

    #[test]
    fn outcome_record_defaults_are_finite_and_neutral() {
        let mut record = OutcomeRecord::new(OutcomeKind::PaidSubscription);
        record.value_eur = 1_234.5;
        assert!(record.value_eur.is_finite());
        assert!(record.step_execution_id.is_none());
        assert!(record.occurred_at.is_none());
        assert_eq!(record.outcome.as_str(), "paid_subscription");

        let default = OutcomeRecord::new(OutcomeKind::Open);
        assert_eq!(default.value_eur, 0.0);
    }
}
