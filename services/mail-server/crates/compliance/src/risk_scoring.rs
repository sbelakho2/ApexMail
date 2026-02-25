//! Risk scoring engine — assesses tenant risk profiles using 10 weighted
//! factors computed from parallel DB queries and external blocklist checks.
//!
//! Risk levels: Low (<25), Medium (25–49), High (50–74), Critical (≥75).
//! Sending limits are scaled by a per-level multiplier (1.0 / 0.75 / 0.5 / 0.1).
//! Reassessment cadence adapts: 24h / 6h / 1h / 15min.

use chrono::{Duration, Utc};
use serde_json::json;
use sqlx::PgPool;
use std::collections::HashMap;
use tracing::info;

use crate::config::ComplianceConfig;
use crate::types::*;

/// Collected raw metrics used to compute risk factors.
#[derive(Debug, Default)]
struct TenantMetrics {
    /// Days since tenant was created.
    account_age_days: i64,
    /// Number of verified (DKIM/SPF-confirmed) domains.
    verified_domains: i64,
    /// Number of failed payments in the last 90 days.
    payment_failures: i64,
    /// Total messages sent (lifetime).
    total_messages: i64,
    /// Messages sent in last 24 hours.
    messages_24h: i64,
    /// Messages sent in last 7 days.
    messages_7d: i64,
    /// Average daily sending rate over 7 days.
    avg_daily_7d: f64,
    /// Hard bounce rate (%).
    bounce_rate: f64,
    /// Spam complaint rate (%).
    spam_rate: f64,
    /// Unsubscribe rate (%).
    unsub_rate: f64,
    /// Open rate from campaign stats (%).
    open_rate: f64,
    /// Click rate from campaign stats (%).
    click_rate: f64,
    /// Abuse report count (all time).
    abuse_reports: i64,
    /// Content violations (all time).
    content_violations: i64,
    /// Phishing detections (all time).
    phishing_detections: i64,
    /// Whether the tenant appears on any active blocklist.
    blocklisted: bool,
}

pub struct RiskScoringEngine {
    db: PgPool,
    config: ComplianceConfig,
}

impl RiskScoringEngine {
    pub fn new(db: PgPool, config: ComplianceConfig) -> Self {
        Self { db, config }
    }

    // ── Public API ───────────────────────────────────────────

    /// Full assessment: collect metrics, compute factors & flags, persist.
    pub async fn assess_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<TenantRiskProfile, String> {
        let metrics = self.collect_metrics(tenant_id).await?;
        let factors = self.compute_factors(&metrics);
        let score = weighted_average(&factors);
        let level = RiskLevel::from_score(score);
        let limits = self.compute_limits(level);
        let flags = self.generate_flags(&metrics, level);
        let now = Utc::now();
        let next = now + Duration::seconds(level.reassessment_secs());

        let profile = TenantRiskProfile {
            tenant_id: tenant_id.to_string(),
            risk_score: score,
            risk_level: level,
            factors,
            limits,
            flags,
            last_assessed_at: now,
            next_assessment_at: next,
            created_at: now,
            updated_at: now,
        };

        self.persist_profile(&profile).await?;
        info!(tenant_id, score, %level, "Risk assessment complete");
        Ok(profile)
    }

    /// Retrieve a previously-persisted profile.
    pub async fn get_profile(
        &self,
        tenant_id: &str,
    ) -> Result<Option<TenantRiskProfile>, String> {
        let row = sqlx::query_as::<_, ProfileRow>(
            "SELECT tenant_id, risk_score, risk_level, factors, limits, flags,
                    last_assessed_at, next_assessment_at, created_at, updated_at
             FROM risk_profiles WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        match row {
            Some(r) => Ok(Some(r.into_profile()?)),
            None => Ok(None),
        }
    }

    /// Force reassessment regardless of next_assessment_at.
    pub async fn force_reassessment(
        &self,
        tenant_id: &str,
    ) -> Result<TenantRiskProfile, String> {
        self.assess_tenant(tenant_id).await
    }

    /// Manually update sending limits for a tenant (admin override).
    pub async fn update_limits(
        &self,
        tenant_id: &str,
        limits: &TenantLimits,
    ) -> Result<(), String> {
        let limits_json =
            serde_json::to_value(limits).map_err(|e| format!("JSON error: {e}"))?;

        sqlx::query(
            "UPDATE risk_profiles SET limits = $1, updated_at = NOW()
             WHERE tenant_id = $2",
        )
        .bind(limits_json)
        .bind(tenant_id)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        Ok(())
    }

    /// Resolve a risk flag with a resolution note.
    pub async fn resolve_flag(
        &self,
        tenant_id: &str,
        flag_type: &RiskFlagType,
        resolution: &str,
    ) -> Result<(), String> {
        sqlx::query(
            "INSERT INTO flag_resolutions (tenant_id, flag_type, resolution, resolved_at)
             VALUES ($1, $2, $3, NOW())",
        )
        .bind(tenant_id)
        .bind(flag_type.to_string())
        .bind(resolution)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        // Also update the profile's flags JSONB (mark resolved_at).
        if let Some(mut profile) = self.get_profile(tenant_id).await? {
            for flag in &mut profile.flags {
                if &flag.flag_type == flag_type && flag.resolved_at.is_none() {
                    flag.resolved_at = Some(Utc::now());
                }
            }
            self.persist_profile(&profile).await?;
        }

        Ok(())
    }

    /// All tenants at critical risk level.
    pub async fn get_critical_risk_tenants(
        &self,
    ) -> Result<Vec<TenantRiskProfile>, String> {
        let rows = sqlx::query_as::<_, ProfileRow>(
            "SELECT tenant_id, risk_score, risk_level, factors, limits, flags,
                    last_assessed_at, next_assessment_at, created_at, updated_at
             FROM risk_profiles WHERE risk_level = 'critical'
             ORDER BY risk_score DESC",
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        rows.into_iter().map(|r| r.into_profile()).collect()
    }

    /// Aggregate risk stats.
    pub async fn get_risk_stats(
        &self,
    ) -> Result<serde_json::Value, String> {
        let total: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM risk_profiles")
                .fetch_one(&self.db)
                .await
                .map_err(|e| format!("DB error: {e}"))?;

        let by_level: Vec<(String, i64)> = sqlx::query_as(
            "SELECT risk_level, COUNT(*) FROM risk_profiles GROUP BY risk_level",
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        let avg_score: (Option<f64>,) =
            sqlx::query_as("SELECT AVG(risk_score) FROM risk_profiles")
                .fetch_one(&self.db)
                .await
                .map_err(|e| format!("DB error: {e}"))?;

        let flagged: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM risk_profiles WHERE jsonb_array_length(flags) > 0",
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        let level_map: HashMap<String, i64> = by_level.into_iter().collect();

        Ok(json!({
            "total": total.0,
            "by_level": level_map,
            "avg_score": avg_score.0.unwrap_or(0.0),
            "flagged_tenants": flagged.0,
        }))
    }

    // ── Internal ─────────────────────────────────────────────

    async fn collect_metrics(
        &self,
        tenant_id: &str,
    ) -> Result<TenantMetrics, String> {
        let mut m = TenantMetrics::default();

        let age_fut = sqlx::query_as::<_, (Option<i64>,)>(
            "SELECT EXTRACT(EPOCH FROM (NOW() - created_at))::bigint / 86400
             FROM tenants WHERE id = $1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.db);

        let domains_fut = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM domains WHERE tenant_id = $1 AND verified = true",
        )
        .bind(tenant_id)
        .fetch_one(&self.db);

        let payments_fut = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM payment_events
             WHERE tenant_id = $1 AND event_type = 'failed'
               AND created_at > NOW() - INTERVAL '90 days'",
        )
        .bind(tenant_id)
        .fetch_one(&self.db);

        let messages_fut = sqlx::query_as::<_, (i64, i64, i64)>(
            "SELECT COUNT(*),
                    COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '1 day'),
                    COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '7 days')
             FROM messages WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_one(&self.db);

        let bounce_fut = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM messages WHERE tenant_id = $1 AND status = 'bounced'",
        )
        .bind(tenant_id)
        .fetch_one(&self.db);

        let spam_fut = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM spam_complaints WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_one(&self.db);

        let unsub_fut = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM unsubscribes WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_one(&self.db);

        let engagement_fut = sqlx::query_as::<_, (Option<f64>, Option<f64>)>(
            "SELECT AVG(open_rate), AVG(click_rate)
             FROM campaign_stats WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.db);

        let abuse_fut = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM abuse_reports WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_one(&self.db);

        let violations_fut = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM content_violations WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_one(&self.db);

        let phishing_fut = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM scan_results
             WHERE tenant_id = $1 AND phishing_detected = true",
        )
        .bind(tenant_id)
        .fetch_one(&self.db);

        let blocklist_fut = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM tenant_ips ti
             JOIN blocklist_entries be ON be.ip = ti.ip AND be.active = true
             WHERE ti.tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_one(&self.db);

        let (
            age_row,
            dom_row,
            pay_row,
            msg_row,
            bounce_row,
            spam_row,
            unsub_row,
            eng_row,
            abuse_row,
            cv_row,
            phish_row,
            bl_row,
        ) = tokio::try_join!(
            age_fut,
            domains_fut,
            payments_fut,
            messages_fut,
            bounce_fut,
            spam_fut,
            unsub_fut,
            engagement_fut,
            abuse_fut,
            violations_fut,
            phishing_fut,
            blocklist_fut,
        )
        .map_err(|e| format!("DB error: {e}"))?;

        m.account_age_days = age_row.and_then(|r| r.0).unwrap_or(0);
        m.verified_domains = dom_row.0;
        m.payment_failures = pay_row.0;
        m.total_messages = msg_row.0;
        m.messages_24h = msg_row.1;
        m.messages_7d = msg_row.2;
        m.avg_daily_7d = if m.messages_7d > 0 { m.messages_7d as f64 / 7.0 } else { 0.0 };

        if m.total_messages > 0 {
            m.bounce_rate = (bounce_row.0 as f64 / m.total_messages as f64) * 100.0;
            m.spam_rate = (spam_row.0 as f64 / m.total_messages as f64) * 100.0;
            m.unsub_rate = (unsub_row.0 as f64 / m.total_messages as f64) * 100.0;
        }

        if let Some((open_rate, click_rate)) = eng_row {
            m.open_rate = open_rate.unwrap_or(0.0);
            m.click_rate = click_rate.unwrap_or(0.0);
        }

        m.abuse_reports = abuse_row.0;
        m.content_violations = cv_row.0;
        m.phishing_detections = phish_row.0;
        m.blocklisted = bl_row.0 > 0;

        Ok(m)
    }

    fn compute_factors(&self, m: &TenantMetrics) -> Vec<RiskFactor> {
        let w = &self.config.risk.weights;
        let mut factors = vec![
            factor(
                RiskFactorType::SpamComplaints,
                spam_score(m.spam_rate),
                w.spam_complaints,
                format!("Spam complaint rate: {:.3}%", m.spam_rate),
            ),
            factor(
                RiskFactorType::BounceRate,
                bounce_score(m.bounce_rate),
                w.bounce_rate,
                format!("Bounce rate: {:.2}%", m.bounce_rate),
            ),
            factor(
                RiskFactorType::PhishingDetection,
                phishing_score(m.phishing_detections),
                w.phishing_detection,
                format!("{} phishing detections", m.phishing_detections),
            ),
            factor(
                RiskFactorType::ContentViolation,
                violation_score(m.content_violations),
                w.content_violation,
                format!("{} content violations", m.content_violations),
            ),
            factor(
                RiskFactorType::SendingPattern,
                sending_pattern_score(m.messages_24h, m.avg_daily_7d),
                w.sending_pattern,
                format!(
                    "24h: {}, avg 7d: {:.0}",
                    m.messages_24h, m.avg_daily_7d
                ),
            ),
            factor(
                RiskFactorType::AccountAge,
                account_age_score(m.account_age_days),
                w.account_age,
                format!("{} days old", m.account_age_days),
            ),
            factor(
                RiskFactorType::VerificationStatus,
                verification_score(m.verified_domains),
                w.verification_status,
                format!("{} verified domains", m.verified_domains),
            ),
            factor(
                RiskFactorType::PaymentHistory,
                payment_score(m.payment_failures),
                w.payment_history,
                format!("{} payment failures (90d)", m.payment_failures),
            ),
            factor(
                RiskFactorType::ListQuality,
                list_quality_score(m.bounce_rate, m.spam_rate),
                w.list_quality,
                format!(
                    "Bounce {:.2}% + Spam {:.3}%",
                    m.bounce_rate, m.spam_rate
                ),
            ),
            factor(
                RiskFactorType::EngagementRate,
                engagement_score(m.open_rate, m.click_rate),
                w.engagement_rate,
                format!(
                    "Open {:.1}%, Click {:.1}%",
                    m.open_rate, m.click_rate
                ),
            ),
        ];

        if m.blocklisted {
            factors.push(factor(
                RiskFactorType::BlocklistListing,
                80.0,
                2.0,
                "Tenant IP on active blocklist".into(),
            ));
        }

        factors
    }

    fn compute_limits(&self, level: RiskLevel) -> TenantLimits {
        let base = &self.config.risk.base_limits;
        let mult = level.limit_multiplier();
        let force_doi = matches!(level, RiskLevel::High | RiskLevel::Critical);

        TenantLimits {
            max_daily_emails: (base.max_daily_emails as f64 * mult) as i64,
            max_hourly_emails: (base.max_hourly_emails as f64 * mult) as i64,
            max_recipients: (base.max_recipients as f64 * mult) as i64,
            max_attachment_size_mb: base.max_attachment_size_mb,
            require_double_opt_in: force_doi,
            require_unsubscribe_link: true,
            allowed_domains: vec![],
            blocked_recipient_patterns: vec![],
        }
    }

    fn generate_flags(
        &self,
        m: &TenantMetrics,
        _level: RiskLevel,
    ) -> Vec<RiskFlag> {
        let mut flags = vec![];
        let now = Utc::now();

        if m.bounce_rate > 5.0 {
            flags.push(RiskFlag {
                flag_type: RiskFlagType::HighBounceRate,
                severity: if m.bounce_rate > 10.0 {
                    FlagSeverity::Critical
                } else {
                    FlagSeverity::Alert
                },
                message: format!("Bounce rate {:.2}% exceeds threshold", m.bounce_rate),
                raised_at: now,
                resolved_at: None,
                auto_resolved: false,
            });
        }

        if m.blocklisted {
            flags.push(RiskFlag {
                flag_type: RiskFlagType::BlocklistDetected,
                severity: FlagSeverity::Critical,
                message: "Tenant IP found on active blocklist".into(),
                raised_at: now,
                resolved_at: None,
                auto_resolved: false,
            });
        }

        if m.avg_daily_7d > 0.0 && m.messages_24h as f64 > m.avg_daily_7d * 3.0 {
            flags.push(RiskFlag {
                flag_type: RiskFlagType::UnusualSendingPattern,
                severity: FlagSeverity::Warning,
                message: format!(
                    "24h volume {} is >3x average {:.0}",
                    m.messages_24h, m.avg_daily_7d
                ),
                raised_at: now,
                resolved_at: None,
                auto_resolved: false,
            });
        }

        if m.phishing_detections > 0 {
            flags.push(RiskFlag {
                flag_type: RiskFlagType::PhishingContent,
                severity: FlagSeverity::Critical,
                message: format!(
                    "{} phishing detections found",
                    m.phishing_detections
                ),
                raised_at: now,
                resolved_at: None,
                auto_resolved: false,
            });
        }

        flags
    }

    async fn persist_profile(
        &self,
        p: &TenantRiskProfile,
    ) -> Result<(), String> {
        let factors_json =
            serde_json::to_value(&p.factors).map_err(|e| format!("JSON: {e}"))?;
        let limits_json =
            serde_json::to_value(&p.limits).map_err(|e| format!("JSON: {e}"))?;
        let flags_json =
            serde_json::to_value(&p.flags).map_err(|e| format!("JSON: {e}"))?;

        sqlx::query(
            "INSERT INTO risk_profiles
               (tenant_id, risk_score, risk_level, factors, limits, flags,
                last_assessed_at, next_assessment_at, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
             ON CONFLICT (tenant_id) DO UPDATE SET
               risk_score = EXCLUDED.risk_score,
               risk_level = EXCLUDED.risk_level,
               factors = EXCLUDED.factors,
               limits = EXCLUDED.limits,
               flags = EXCLUDED.flags,
               last_assessed_at = EXCLUDED.last_assessed_at,
               next_assessment_at = EXCLUDED.next_assessment_at,
               updated_at = EXCLUDED.updated_at",
        )
        .bind(&p.tenant_id)
        .bind(p.risk_score)
        .bind(p.risk_level.to_string())
        .bind(&factors_json)
        .bind(&limits_json)
        .bind(&flags_json)
        .bind(p.last_assessed_at)
        .bind(p.next_assessment_at)
        .bind(p.created_at)
        .bind(p.updated_at)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        Ok(())
    }
}

// ─── Scoring Functions (pure, unit-testable) ───────────────────

fn weighted_average(factors: &[RiskFactor]) -> f64 {
    let (sum_sw, sum_w) = factors
        .iter()
        .fold((0.0_f64, 0.0_f64), |(sw, w), f| (sw + f.score * f.weight, w + f.weight));
    if sum_w == 0.0 {
        0.0
    } else {
        (sum_sw / sum_w).round()
    }
}

/// Spam complaint rate → 0-100. Rate ≥1% → 100, 0% → 0, linear in between-ish
/// with extra penalty above threshold.
fn spam_score(rate: f64) -> f64 {
    if rate <= 0.0 {
        0.0
    } else if rate >= 1.0 {
        100.0
    } else {
        (rate * 100.0).clamp(0.0, 100.0)
    }
}

/// Bounce rate → 0-100. >10% → 100, linear otherwise.
fn bounce_score(rate: f64) -> f64 {
    if rate <= 0.0 {
        0.0
    } else if rate >= 10.0 {
        100.0
    } else {
        (rate * 10.0).clamp(0.0, 100.0)
    }
}

/// Phishing detections → 0-100. Any detection is immediately severe.
fn phishing_score(count: i64) -> f64 {
    if count == 0 {
        0.0
    } else {
        (count as f64 * 25.0).min(100.0)
    }
}

/// Content violations → 0-100.
fn violation_score(count: i64) -> f64 {
    (count as f64 * 10.0).min(100.0)
}

/// Sending spike ratio. 3x average in 24h → suspicious.
fn sending_pattern_score(messages_24h: i64, avg_daily: f64) -> f64 {
    if avg_daily <= 0.0 || messages_24h == 0 {
        return 0.0;
    }
    let ratio = messages_24h as f64 / avg_daily;
    if ratio <= 1.5 {
        0.0
    } else if ratio >= 5.0 {
        100.0
    } else {
        ((ratio - 1.5) / 3.5 * 100.0).clamp(0.0, 100.0)
    }
}

/// Newer accounts are riskier (higher score for <30 days).
fn account_age_score(age_days: i64) -> f64 {
    if age_days >= 365 {
        0.0
    } else if age_days <= 1 {
        80.0
    } else {
        let factor = 1.0 - (age_days as f64 / 365.0);
        (factor * 80.0).clamp(0.0, 80.0)
    }
}

/// Zero verified domains → high risk.
fn verification_score(verified: i64) -> f64 {
    match verified {
        0 => 80.0,
        1 => 40.0,
        2 => 20.0,
        _ => 0.0,
    }
}

/// Payment failures → risk.
fn payment_score(failures: i64) -> f64 {
    (failures as f64 * 20.0).min(100.0)
}

/// Combined bounce + spam rates.
fn list_quality_score(bounce_rate: f64, spam_rate: f64) -> f64 {
    let combined = bounce_rate + spam_rate * 10.0;
    combined.clamp(0.0, 100.0)
}

/// Low engagement → higher risk (inverted: high engagement = low risk).
fn engagement_score(open_rate: f64, click_rate: f64) -> f64 {
    if open_rate <= 0.0 && click_rate <= 0.0 {
        50.0 // no data = moderate risk
    } else {
        // Good engagement: open_rate ~20-30%, click ~2-5% → low risk
        let open_factor = if open_rate >= 20.0 { 0.0 } else { (20.0 - open_rate) / 20.0 * 50.0 };
        let click_factor = if click_rate >= 3.0 { 0.0 } else { (3.0 - click_rate) / 3.0 * 50.0 };
        ((open_factor + click_factor) / 2.0).clamp(0.0, 100.0)
    }
}

fn factor(
    factor_type: RiskFactorType,
    score: f64,
    weight: f64,
    details: String,
) -> RiskFactor {
    RiskFactor {
        factor_type,
        score,
        weight,
        details,
        evidence: HashMap::new(),
    }
}

// ─── DB row helper ─────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct ProfileRow {
    tenant_id: String,
    risk_score: f64,
    #[allow(dead_code)]
    risk_level: String,
    factors: serde_json::Value,
    limits: serde_json::Value,
    flags: serde_json::Value,
    last_assessed_at: chrono::DateTime<Utc>,
    next_assessment_at: chrono::DateTime<Utc>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

impl ProfileRow {
    fn into_profile(self) -> Result<TenantRiskProfile, String> {
        Ok(TenantRiskProfile {
            tenant_id: self.tenant_id,
            risk_score: self.risk_score,
            risk_level: RiskLevel::from_score(self.risk_score),
            factors: serde_json::from_value(self.factors)
                .map_err(|e| format!("factors JSON: {e}"))?,
            limits: serde_json::from_value(self.limits)
                .map_err(|e| format!("limits JSON: {e}"))?,
            flags: serde_json::from_value(self.flags)
                .map_err(|e| format!("flags JSON: {e}"))?,
            last_assessed_at: self.last_assessed_at,
            next_assessment_at: self.next_assessment_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spam_score() {
        assert_eq!(spam_score(0.0), 0.0);
        assert_eq!(spam_score(0.5), 50.0);
        assert_eq!(spam_score(1.0), 100.0);
        assert_eq!(spam_score(2.0), 100.0);
    }

    #[test]
    fn test_bounce_score() {
        assert_eq!(bounce_score(0.0), 0.0);
        assert_eq!(bounce_score(5.0), 50.0);
        assert_eq!(bounce_score(10.0), 100.0);
        assert_eq!(bounce_score(15.0), 100.0);
    }

    #[test]
    fn test_phishing_score() {
        assert_eq!(phishing_score(0), 0.0);
        assert_eq!(phishing_score(1), 25.0);
        assert_eq!(phishing_score(4), 100.0);
        assert_eq!(phishing_score(10), 100.0);
    }

    #[test]
    fn test_violation_score() {
        assert_eq!(violation_score(0), 0.0);
        assert_eq!(violation_score(5), 50.0);
        assert_eq!(violation_score(10), 100.0);
    }

    #[test]
    fn test_sending_pattern_score() {
        assert_eq!(sending_pattern_score(0, 0.0), 0.0);
        assert_eq!(sending_pattern_score(100, 100.0), 0.0); // ratio=1.0
        assert_eq!(sending_pattern_score(150, 100.0), 0.0); // ratio=1.5
        assert!(sending_pattern_score(300, 100.0) > 0.0);   // ratio=3.0
        assert_eq!(sending_pattern_score(500, 100.0), 100.0); // ratio=5.0
    }

    #[test]
    fn test_account_age_score() {
        assert_eq!(account_age_score(365), 0.0);
        assert_eq!(account_age_score(1), 80.0);
        let score_30 = account_age_score(30);
        assert!(score_30 > 50.0 && score_30 < 80.0);
    }

    #[test]
    fn test_verification_score() {
        assert_eq!(verification_score(0), 80.0);
        assert_eq!(verification_score(1), 40.0);
        assert_eq!(verification_score(3), 0.0);
    }

    #[test]
    fn test_payment_score() {
        assert_eq!(payment_score(0), 0.0);
        assert_eq!(payment_score(3), 60.0);
        assert_eq!(payment_score(5), 100.0);
    }

    #[test]
    fn test_list_quality_score() {
        assert_eq!(list_quality_score(0.0, 0.0), 0.0);
        assert_eq!(list_quality_score(5.0, 0.5), 10.0); // 5 + 5 = 10
        assert_eq!(list_quality_score(50.0, 10.0), 100.0); // clamped
    }

    #[test]
    fn test_engagement_score() {
        assert_eq!(engagement_score(0.0, 0.0), 50.0); // no data
        assert_eq!(engagement_score(25.0, 5.0), 0.0);  // great engagement
        let low = engagement_score(5.0, 0.5);
        assert!(low > 30.0);
    }

    #[test]
    fn test_weighted_average() {
        let factors = vec![
            factor(RiskFactorType::SpamComplaints, 50.0, 1.5, String::new()),
            factor(RiskFactorType::BounceRate, 30.0, 1.2, String::new()),
        ];
        // (50*1.5 + 30*1.2) / (1.5+1.2) = (75+36)/2.7 = 111/2.7 ≈ 41.11 → 41
        let avg = weighted_average(&factors);
        assert_eq!(avg, 41.0);
    }

    #[test]
    fn test_weighted_average_empty() {
        assert_eq!(weighted_average(&[]), 0.0);
    }

    #[test]
    fn test_risk_level_determines_limits() {
        // Low → multiplier 1.0, no forced DOI
        let cfg = ComplianceConfig::from_env();
        let engine = RiskScoringEngine::new(
            // We only test compute_limits which doesn't touch DB.
            unsafe_dummy_pool(),
            cfg,
        );
        let low = engine.compute_limits(RiskLevel::Low);
        assert_eq!(low.max_daily_emails, 10_000);
        assert!(!low.require_double_opt_in);

        let crit = engine.compute_limits(RiskLevel::Critical);
        assert_eq!(crit.max_daily_emails, 1_000); // 10_000 * 0.1
        assert!(crit.require_double_opt_in);
    }

    #[test]
    fn test_generate_flags_bounce() {
        let cfg = ComplianceConfig::from_env();
        let engine = RiskScoringEngine::new(unsafe_dummy_pool(), cfg);
        let mut m = TenantMetrics::default();
        m.bounce_rate = 8.0;
        let flags = engine.generate_flags(&m, RiskLevel::High);
        assert_eq!(flags.len(), 1);
        assert_eq!(flags[0].flag_type, RiskFlagType::HighBounceRate);
        assert_eq!(flags[0].severity, FlagSeverity::Alert);
    }

    #[test]
    fn test_generate_flags_blocklist() {
        let cfg = ComplianceConfig::from_env();
        let engine = RiskScoringEngine::new(unsafe_dummy_pool(), cfg);
        let mut m = TenantMetrics::default();
        m.blocklisted = true;
        let flags = engine.generate_flags(&m, RiskLevel::High);
        assert!(flags.iter().any(|f| f.flag_type == RiskFlagType::BlocklistDetected));
    }

    #[test]
    fn test_generate_flags_spike() {
        let cfg = ComplianceConfig::from_env();
        let engine = RiskScoringEngine::new(unsafe_dummy_pool(), cfg);
        let mut m = TenantMetrics::default();
        m.messages_24h = 10_000;
        m.avg_daily_7d = 1_000.0;
        let flags = engine.generate_flags(&m, RiskLevel::Medium);
        assert!(flags.iter().any(|f| f.flag_type == RiskFlagType::UnusualSendingPattern));
    }

    #[test]
    fn test_generate_flags_phishing() {
        let cfg = ComplianceConfig::from_env();
        let engine = RiskScoringEngine::new(unsafe_dummy_pool(), cfg);
        let mut m = TenantMetrics::default();
        m.phishing_detections = 2;
        let flags = engine.generate_flags(&m, RiskLevel::Critical);
        assert!(flags.iter().any(|f| f.flag_type == RiskFlagType::PhishingContent));
    }

    /// Shared Tokio runtime for tests that need `connect_lazy` (sqlx 0.8 requires it).
    fn test_runtime() -> &'static tokio::runtime::Runtime {
        use std::sync::OnceLock;
        static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
        RT.get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
        })
    }

    /// Create a dummy PgPool for tests that only exercise non-DB methods.
    fn unsafe_dummy_pool() -> PgPool {
        use sqlx::postgres::PgPoolOptions;
        let _guard = test_runtime().enter();
        PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://fake:fake@localhost:1/fake")
            .unwrap()
    }
}
