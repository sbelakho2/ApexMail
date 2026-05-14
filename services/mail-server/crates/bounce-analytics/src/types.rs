//! Shared types for bounce analytics.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── bounce event row (from the database) ────────────────────────────────────

/// Raw bounce event as stored in the `bounce_events` table.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct BounceEventRow {
    pub id: String,
    pub original_message_id: Option<String>,
    pub original_recipient: Option<String>,
    pub bounce_type: String,
    pub bounce_subtype: String,
    pub diagnostic_code: Option<String>,
    pub status_code: String,
    pub created_at: DateTime<Utc>,
}

/// Extended bounce event enriched with tenant and campaign context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedBounceEvent {
    pub id: String,
    pub recipient: Option<String>,
    pub recipient_domain: Option<String>,
    pub tenant_id: Option<String>,
    pub campaign_id: Option<String>,
    pub message_id: Option<String>,
    pub bounce_type: BounceCategory,
    pub bounce_subtype: String,
    pub diagnostic_code: Option<String>,
    pub status_code: String,
    pub timestamp: DateTime<Utc>,
}

// ── bounce category ─────────────────────────────────────────────────────────

/// Normalised bounce classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BounceCategory {
    /// Permanent failure – do not retry.
    Hard,
    /// Temporary failure – may succeed on retry.
    Soft,
    /// Transient – indeterminate, try again.
    Transient,
}

impl std::fmt::Display for BounceCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hard => write!(f, "hard"),
            Self::Soft => write!(f, "soft"),
            Self::Transient => write!(f, "transient"),
        }
    }
}

impl BounceCategory {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "hard" => Self::Hard,
            "soft" => Self::Soft,
            _ => Self::Transient,
        }
    }
}

// ── aggregation results ─────────────────────────────────────────────────────

/// Aggregate bounce metrics for a time window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BounceAggregation {
    /// The tenant these metrics belong to (or "global").
    pub tenant_id: String,
    /// Start of the aggregation window.
    pub window_start: DateTime<Utc>,
    /// End of the aggregation window.
    pub window_end: DateTime<Utc>,
    /// Total bounce count in the window.
    pub total_bounces: i64,
    /// Breakdown by bounce category.
    pub by_category: Vec<CategoryBreakdown>,
    /// Breakdown by bounce subtype (top N).
    pub by_subtype: Vec<SubtypeBreakdown>,
    /// Breakdown by recipient domain (top N).
    pub by_domain: Vec<DomainBreakdown>,
    /// Hourly time series of bounce counts.
    pub hourly_series: Vec<TimeSeriesBucket>,
}

/// Counts per bounce category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryBreakdown {
    pub category: BounceCategory,
    pub count: i64,
    pub percentage: f64,
}

/// Counts per bounce subtype (e.g. "no-mailbox", "mailbox-full").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubtypeBreakdown {
    pub subtype: String,
    pub count: i64,
    pub percentage: f64,
}

/// Counts per recipient domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainBreakdown {
    pub domain: String,
    pub count: i64,
    pub bounce_rate: Option<f64>,
}

/// A single time-series bucket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesBucket {
    pub bucket: String,
    pub count: i64,
}

// ── pattern detection results ───────────────────────────────────────────────

/// A detected bounce burst – unusual spike in bounces from a domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BounceBurst {
    pub domain: String,
    pub tenant_id: Option<String>,
    pub burst_start: DateTime<Utc>,
    pub burst_end: DateTime<Utc>,
    pub bounce_count: i32,
    pub expected_baseline: f64,
    pub burst_factor: f64,
    pub predominant_subtype: String,
}

/// Domain-level reputation derived from bounce history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainReputation {
    pub domain: String,
    pub total_sent: i64,
    pub total_bounces: i64,
    pub bounce_rate: f64,
    pub hard_bounce_rate: f64,
    pub soft_bounce_rate: f64,
    pub risk_level: DomainRiskLevel,
    pub predominant_reason: String,
    pub last_bounce: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainRiskLevel {
    /// Normal bounce rate.
    Normal,
    /// Elevated bounce rate – may indicate list issues.
    Elevated,
    /// High bounce rate – likely problematic list / invalid data.
    High,
    /// Critical bounce rate – potential spam trap or abandoned domain.
    Critical,
}

impl DomainRiskLevel {
    pub fn from_bounce_rate(rate: f64) -> Self {
        if rate >= 0.20 {
            Self::Critical
        } else if rate >= 0.10 {
            Self::High
        } else if rate >= 0.05 {
            Self::Elevated
        } else {
            Self::Normal
        }
    }

    /// Parse the persisted string representation (matches `Display`).
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Self::Critical,
            "high" => Self::High,
            "elevated" => Self::Elevated,
            _ => Self::Normal,
        }
    }
}

impl std::fmt::Display for DomainRiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Normal => write!(f, "normal"),
            Self::Elevated => write!(f, "elevated"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ── analytics report ────────────────────────────────────────────────────────

/// Complete bounce analytics report for a tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BounceAnalyticsReport {
    pub tenant_id: String,
    pub generated_at: DateTime<Utc>,
    pub aggregation: BounceAggregation,
    pub bursts: Vec<BounceBurst>,
    pub problematic_domains: Vec<DomainReputation>,
    pub recommendations: Vec<String>,
}

impl BounceAnalyticsReport {
    /// Generate human-readable recommendations based on the analytics.
    pub fn generate_recommendations(&mut self) {
        let mut recs = Vec::new();

        // Check overall bounce rate
        let total_bounces = self.aggregation.total_bounces;
        if total_bounces > 0 {
            let hard_count = self
                .aggregation
                .by_category
                .iter()
                .find(|c| c.category == BounceCategory::Hard)
                .map(|c| c.count)
                .unwrap_or(0);
            let hard_pct = hard_count as f64 / total_bounces as f64;

            if hard_pct > 0.5 {
                recs.push(
                    "Over 50% of bounces are hard bounces. Review list hygiene practices and \
                     consider implementing a double opt-in to reduce invalid addresses."
                        .to_string(),
                );
            }

            if let Some(domain) = self.aggregation.by_domain.first() {
                if domain.bounce_rate.unwrap_or(0.0) > 0.20 {
                    recs.push(format!(
                        "Domain '{}' has a bounce rate >20%. Verify this domain is still \
                         active and consider suppressing non-responsive recipients.",
                        domain.domain
                    ));
                }
            }
        }

        // Check for bursts
        if !self.bursts.is_empty() {
            let burst_domains: Vec<&str> = self.bursts.iter().map(|b| b.domain.as_str()).collect();
            recs.push(format!(
                "Detected {} bounce burst(s) from domains: {}. Investigate immediately \
                 — this may indicate a spam trap hit or DNS blacklisting.",
                self.bursts.len(),
                burst_domains.join(", ")
            ));
        }

        // Check problematic domains
        let critical_domains: Vec<&str> = self
            .problematic_domains
            .iter()
            .filter(|d| d.risk_level == DomainRiskLevel::Critical)
            .map(|d| d.domain.as_str())
            .collect();
        if !critical_domains.is_empty() {
            recs.push(format!(
                "Critical bounce rate on domains: {}. Consider pausing sends to these \
                 domains and reviewing the recipient list.",
                critical_domains.join(", ")
            ));
        }

        self.recommendations = recs;
    }
}

// ── schema migration ────────────────────────────────────────────────────────

/// DDL for the bounce analytics aggregate tables.
pub const BOUNCE_ANALYTICS_SCHEMA: &str = r#"
-- Raw bounce events populated by the MTA bounce and feedback-loop servers.
CREATE TABLE IF NOT EXISTS bounce_events (
    id                  TEXT PRIMARY KEY,
    original_message_id TEXT,
    original_recipient  TEXT,
    bounce_type         TEXT NOT NULL,
    bounce_subtype      TEXT NOT NULL DEFAULT '',
    diagnostic_code     TEXT,
    status_code         TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_bounce_events_created_at
    ON bounce_events (created_at);
CREATE INDEX IF NOT EXISTS idx_bounce_events_original_message
    ON bounce_events (original_message_id)
    WHERE original_message_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_bounce_events_recipient
    ON bounce_events (original_recipient)
    WHERE original_recipient IS NOT NULL;

-- Aggregated bounce metrics per tenant per day
CREATE TABLE IF NOT EXISTS bounce_analytics_daily (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   VARCHAR(64) NOT NULL,
    date        DATE NOT NULL,
    total_bounces       BIGINT NOT NULL DEFAULT 0,
    hard_bounces        BIGINT NOT NULL DEFAULT 0,
    soft_bounces        BIGINT NOT NULL DEFAULT 0,
    transient_bounces   BIGINT NOT NULL DEFAULT 0,
    top_subtypes        JSONB,
    top_domains         JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, date)
);

-- Domain reputation tracking
CREATE TABLE IF NOT EXISTS bounce_domain_reputation (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain          VARCHAR(255) NOT NULL,
    tenant_id       VARCHAR(64) NOT NULL,
    total_sent      BIGINT NOT NULL DEFAULT 0,
    total_bounces   BIGINT NOT NULL DEFAULT 0,
    hard_bounces    BIGINT NOT NULL DEFAULT 0,
    soft_bounces    BIGINT NOT NULL DEFAULT 0,
    risk_level      VARCHAR(16) NOT NULL DEFAULT 'normal',
    predominant_reason VARCHAR(128),
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_bounce     TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (domain, tenant_id)
);

-- Detected bounce bursts
CREATE TABLE IF NOT EXISTS bounce_bursts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain          VARCHAR(255) NOT NULL,
    tenant_id       VARCHAR(64),
    burst_start     TIMESTAMPTZ NOT NULL,
    burst_end       TIMESTAMPTZ NOT NULL,
    bounce_count    INT NOT NULL,
    expected_baseline   DOUBLE PRECISION,
    burst_factor    DOUBLE PRECISION,
    predominant_subtype VARCHAR(64),
    acknowledged    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_bounce_analytics_daily_tenant_date
    ON bounce_analytics_daily (tenant_id, date DESC);
CREATE INDEX IF NOT EXISTS idx_bounce_domain_reputation_tenant
    ON bounce_domain_reputation (tenant_id, risk_level);
CREATE INDEX IF NOT EXISTS idx_bounce_bursts_domain
    ON bounce_bursts (domain, burst_start DESC);
CREATE INDEX IF NOT EXISTS idx_bounce_bursts_unacknowledged
    ON bounce_bursts (acknowledged, created_at DESC)
    WHERE acknowledged = FALSE;
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bounce_category_from_str() {
        assert_eq!(BounceCategory::from_str("hard"), BounceCategory::Hard);
        assert_eq!(BounceCategory::from_str("SOFT"), BounceCategory::Soft);
        assert_eq!(
            BounceCategory::from_str("transient"),
            BounceCategory::Transient
        );
        assert_eq!(
            BounceCategory::from_str("unknown"),
            BounceCategory::Transient
        );
    }

    #[test]
    fn test_bounce_category_display() {
        assert_eq!(BounceCategory::Hard.to_string(), "hard");
        assert_eq!(BounceCategory::Soft.to_string(), "soft");
    }

    #[test]
    fn test_domain_risk_level_from_rate() {
        assert_eq!(
            DomainRiskLevel::from_bounce_rate(0.01),
            DomainRiskLevel::Normal
        );
        assert_eq!(
            DomainRiskLevel::from_bounce_rate(0.06),
            DomainRiskLevel::Elevated
        );
        assert_eq!(
            DomainRiskLevel::from_bounce_rate(0.12),
            DomainRiskLevel::High
        );
        assert_eq!(
            DomainRiskLevel::from_bounce_rate(0.25),
            DomainRiskLevel::Critical
        );
    }

    #[test]
    fn test_report_recommendations_empty_when_no_bounces() {
        let agg = BounceAggregation {
            tenant_id: "t1".into(),
            window_start: Utc::now(),
            window_end: Utc::now(),
            total_bounces: 0,
            by_category: vec![],
            by_subtype: vec![],
            by_domain: vec![],
            hourly_series: vec![],
        };
        let mut report = BounceAnalyticsReport {
            tenant_id: "t1".into(),
            generated_at: Utc::now(),
            aggregation: agg,
            bursts: vec![],
            problematic_domains: vec![],
            recommendations: vec![],
        };
        report.generate_recommendations();
        assert!(report.recommendations.is_empty());
    }

    #[test]
    fn test_schema_contains_tables() {
        assert!(BOUNCE_ANALYTICS_SCHEMA.contains("bounce_analytics_daily"));
        assert!(BOUNCE_ANALYTICS_SCHEMA.contains("bounce_domain_reputation"));
        assert!(BOUNCE_ANALYTICS_SCHEMA.contains("bounce_bursts"));
    }
}
