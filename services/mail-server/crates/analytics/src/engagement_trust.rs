//! Engagement trust – trust equation, grading, campaign trust metrics.
//!
//! Trust = (C × 0.3 + R × 0.3 + I × 0.25) / (S / 100) × 100
//! - Credibility (C):open_rate + click_rate - spam_rate
//! - Reliability (R):preference compliance + length compliance + recency
//! - Intimacy (I):reply_rate + survey_score + nps + feedback
//! - Self-Orientation (S):lower is better (1 = best)

use chrono::Utc;
use sqlx::PgPool;

use crate::types::*;

/// Trust grade thresholds.
const GRADE_A_THRESHOLD: f64 = 85.0;
const GRADE_B_THRESHOLD: f64 = 70.0;
const GRADE_C_THRESHOLD: f64 = 55.0;
const GRADE_D_THRESHOLD: f64 = 40.0;

pub struct EngagementTrustService {
    pool: PgPool,
}

impl EngagementTrustService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Calculate trust score for a subscriber.
    pub async fn calculate_trust(
        &self,
        tenant_id: &str,
        email: &str,
    ) -> anyhow::Result<TrustScore> {
        let engagement = self.get_subscriber_engagement(tenant_id, email).await?;
        let trust = compute_trust_score(&engagement);
        Ok(trust)
    }

    /// Get campaign-level trust metrics.
    pub async fn campaign_trust(
        &self,
        tenant_id: &str,
        campaign_id: &str,
    ) -> anyhow::Result<CampaignTrustMetrics> {
        let rows = sqlx::query_as::<_, (String,)>(
            "SELECT DISTINCT recipient FROM events \
             WHERE tenant_id = $1 AND campaign_id = $2",
        )
        .bind(tenant_id)
        .bind(campaign_id)
        .fetch_all(&self.pool)
        .await?;

        let mut scores: Vec<f64> = Vec::new();
        let mut grades: std::collections::HashMap<String, i64> = std::collections::HashMap::new();

        for (email,) in &rows {
            if let Ok(trust) = self.calculate_trust(tenant_id, email).await {
                scores.push(trust.score);
                *grades.entry(trust.grade.clone()).or_insert(0) += 1;
            }
        }

        let avg_score = if scores.is_empty() {
            0.0
        } else {
            scores.iter().sum::<f64>() / scores.len() as f64
        };

        let overall_grade = compute_grade(avg_score);
        let risk = compute_risk_level(avg_score);

        Ok(CampaignTrustMetrics {
            campaign_id: campaign_id.into(),
            average_trust_score: avg_score,
            grade: overall_grade,
            risk_level: risk,
            subscriber_count: rows.len() as i64,
            grade_distribution: grades,
        })
    }

    async fn get_subscriber_engagement(
        &self,
        tenant_id: &str,
        email: &str,
    ) -> anyhow::Result<SubscriberEngagement> {
        let since_90d = Utc::now() - chrono::Duration::days(90);

        let counts = sqlx::query_as::<_, (String, i64)>(
            "SELECT event_type, COUNT(*) FROM events \
             WHERE tenant_id = $1 AND recipient = $2 AND timestamp >= $3 \
             GROUP BY event_type",
        )
        .bind(tenant_id)
        .bind(email)
        .bind(since_90d)
        .fetch_all(&self.pool)
        .await?;

        let map: std::collections::HashMap<String, i64> = counts.into_iter().collect();

        let sent = *map.get("sent").unwrap_or(&0);
        let delivered = *map.get("delivered").unwrap_or(&0);
        let opened = *map.get("opened").unwrap_or(&0);
        let clicked = *map.get("clicked").unwrap_or(&0);
        let complained = *map.get("complained").unwrap_or(&0);
        let unsubscribed = *map.get("unsubscribed").unwrap_or(&0);
        let replied = *map.get("replied").unwrap_or(&0);
        let bounced = *map.get("bounced").unwrap_or(&0);

        let safe_rate = |num: i64, den: i64| -> f64 {
            if den > 0 {
                num as f64 / den as f64
            } else {
                0.0
            }
        };

        Ok(SubscriberEngagement {
            email: email.to_string(),
            open_rate: safe_rate(opened, delivered),
            click_rate: safe_rate(clicked, delivered),
            spam_rate: safe_rate(complained, delivered),
            unsubscribe_rate: safe_rate(unsubscribed, delivered),
            reply_rate: safe_rate(replied, sent),
            bounce_rate: safe_rate(bounced, sent),
            total_sent: sent,
            total_delivered: delivered,
            total_opened: opened,
            total_clicked: clicked,
            preference_compliance: 1.0, // Default:fully compliant
            send_frequency_compliance: 1.0,
            recency_score: 1.0,
            nps_score: None,
            survey_score: None,
            feedback_count: 0,
            last_engagement: None,
        })
    }
}

/// Compute trust score from subscriber engagement data.
pub fn compute_trust_score(e: &SubscriberEngagement) -> TrustScore {
    let credibility = compute_credibility(e);
    let reliability = compute_reliability(e);
    let intimacy = compute_intimacy(e);
    let self_orientation = compute_self_orientation(e);

    // Trust = (C × 0.3 + R × 0.3 + I × 0.25) × (1 - S/100) × (100/85)
    // Where S is self-orientation 0-100 (higher = worse)
    // The (100/85) factor normalizes so max score ≈ 100 when S = 0 and C,R,I are max
    let numerator = credibility * 0.3 + reliability * 0.3 + intimacy * 0.25;
    let so_penalty = 1.0 - (self_orientation / 100.0).min(0.99);
    let raw = numerator * so_penalty * (100.0 / 85.0);
    let score = raw.clamp(0.0, 100.0);

    let grade = compute_grade(score);
    let risk = compute_risk_level(score);

    TrustScore {
        score,
        grade,
        risk_level: risk,
        credibility,
        reliability,
        intimacy,
        self_orientation,
    }
}

/// Credibility:open_rate + click_rate - spam_rate, normalized to 0-100.
fn compute_credibility(e: &SubscriberEngagement) -> f64 {
    (e.open_rate * 50.0 + e.click_rate * 50.0 - e.spam_rate * 100.0).clamp(0.0, 100.0)
}

/// Reliability:preference compliance + frequency compliance + recency.
fn compute_reliability(e: &SubscriberEngagement) -> f64 {
    (e.preference_compliance * 33.3 + e.send_frequency_compliance * 33.3 + e.recency_score * 33.4)
        .clamp(0.0, 100.0)
}

/// Intimacy:reply_rate + survey/NPS + feedback.
fn compute_intimacy(e: &SubscriberEngagement) -> f64 {
    let reply_component = (e.reply_rate * 100.0).min(40.0);
    let survey_component = e.survey_score.unwrap_or(0.0) * 0.3;
    let nps_component = e
        .nps_score
        .map(|n| (n + 100.0) / 200.0 * 30.0)
        .unwrap_or(15.0);
    let feedback_component = (e.feedback_count as f64).min(10.0);

    (reply_component + survey_component + nps_component + feedback_component).clamp(0.0, 100.0)
}

/// Self-Orientation:0 = best (not self-oriented), 100 = worst (very self-oriented).
/// Based on spam + unsubscribe + bounce signals.
fn compute_self_orientation(e: &SubscriberEngagement) -> f64 {
    (e.spam_rate * 200.0 + e.unsubscribe_rate * 100.0 + e.bounce_rate * 50.0).clamp(0.0, 100.0)
}

/// Trust grade A-F.
pub fn compute_grade(score: f64) -> String {
    if score >= GRADE_A_THRESHOLD {
        "A".into()
    } else if score >= GRADE_B_THRESHOLD {
        "B".into()
    } else if score >= GRADE_C_THRESHOLD {
        "C".into()
    } else if score >= GRADE_D_THRESHOLD {
        "D".into()
    } else {
        "F".into()
    }
}

/// Risk level from trust score.
pub fn compute_risk_level(score: f64) -> String {
    if score >= 80.0 {
        "low".into()
    } else if score >= 60.0 {
        "medium".into()
    } else if score >= 40.0 {
        "high".into()
    } else {
        "critical".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_engagement() -> SubscriberEngagement {
        SubscriberEngagement {
            email: "test@example.com".into(),
            open_rate: 0.6,
            click_rate: 0.2,
            spam_rate: 0.01,
            unsubscribe_rate: 0.02,
            reply_rate: 0.05,
            bounce_rate: 0.01,
            total_sent: 100,
            total_delivered: 95,
            total_opened: 57,
            total_clicked: 19,
            preference_compliance: 0.9,
            send_frequency_compliance: 0.85,
            recency_score: 0.95,
            nps_score: Some(30.0),
            survey_score: Some(75.0),
            feedback_count: 3,
            last_engagement: None,
        }
    }

    #[test]
    fn test_compute_trust_score_good_engagement() {
        let e = make_engagement();
        let trust = compute_trust_score(&e);
        assert!(trust.score > 50.0);
        assert!(trust.score <= 100.0);
    }

    #[test]
    fn test_credibility() {
        let e = make_engagement();
        let c = compute_credibility(&e);
        // 0.6*50 + 0.2*50 - 0.01*100 = 30 + 10 - 1 = 39
        assert!((c - 39.0).abs() < 0.1);
    }

    #[test]
    fn test_reliability() {
        let e = make_engagement();
        let r = compute_reliability(&e);
        // 0.9*33.3 + 0.85*33.3 + 0.95*33.4 = 29.97 + 28.305 + 31.73 = 90.005
        assert!((r - 90.0).abs() < 0.1);
    }

    #[test]
    fn test_intimacy() {
        let e = make_engagement();
        let i = compute_intimacy(&e);
        // reply:min(5, 40) = 5
        // survey:75 * 0.3 = 22.5
        // nps:(30+100)/200 * 30 = 130/200*30 = 19.5
        // feedback:min(3, 10) = 3
        // Total:5 + 22.5 + 19.5 + 3 = 50
        assert!((i - 50.0).abs() < 0.5);
    }

    #[test]
    fn test_self_orientation() {
        let e = make_engagement();
        let s = compute_self_orientation(&e);
        // 0.01*200 + 0.02*100 + 0.01*50 = 2 + 2 + 0.5 = 4.5
        assert!((s - 4.5).abs() < 0.1);
    }

    #[test]
    fn test_grade_a() {
        assert_eq!(compute_grade(90.0), "A");
    }

    #[test]
    fn test_grade_b() {
        assert_eq!(compute_grade(75.0), "B");
    }

    #[test]
    fn test_grade_c() {
        assert_eq!(compute_grade(60.0), "C");
    }

    #[test]
    fn test_grade_d() {
        assert_eq!(compute_grade(45.0), "D");
    }

    #[test]
    fn test_grade_f() {
        assert_eq!(compute_grade(20.0), "F");
    }

    #[test]
    fn test_risk_level_low() {
        assert_eq!(compute_risk_level(85.0), "low");
    }

    #[test]
    fn test_risk_level_medium() {
        assert_eq!(compute_risk_level(65.0), "medium");
    }

    #[test]
    fn test_risk_level_high() {
        assert_eq!(compute_risk_level(45.0), "high");
    }

    #[test]
    fn test_risk_level_critical() {
        assert_eq!(compute_risk_level(30.0), "critical");
    }

    #[test]
    fn test_zero_engagement() {
        let e = SubscriberEngagement {
            email: "cold@test.com".into(),
            open_rate: 0.0,
            click_rate: 0.0,
            spam_rate: 0.0,
            unsubscribe_rate: 0.0,
            reply_rate: 0.0,
            bounce_rate: 0.0,
            total_sent: 0,
            total_delivered: 0,
            total_opened: 0,
            total_clicked: 0,
            preference_compliance: 1.0,
            send_frequency_compliance: 1.0,
            recency_score: 0.0,
            nps_score: None,
            survey_score: None,
            feedback_count: 0,
            last_engagement: None,
        };
        let trust = compute_trust_score(&e);
        assert!(trust.score >= 0.0);
        assert!(trust.score <= 100.0);
    }

    #[test]
    fn test_high_spam_lowers_trust() {
        let mut e = make_engagement();
        let original = compute_trust_score(&e).score;
        e.spam_rate = 0.3;
        let spammy = compute_trust_score(&e).score;
        assert!(spammy < original);
    }

    #[test]
    fn test_trust_score_struct_fields() {
        let e = make_engagement();
        let trust = compute_trust_score(&e);
        assert!(trust.credibility >= 0.0);
        assert!(trust.reliability >= 0.0);
        assert!(trust.intimacy >= 0.0);
        assert!(trust.self_orientation >= 0.0); // 0 = best, 100 = worst
    }
}
