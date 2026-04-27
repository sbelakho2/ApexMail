//! Churn prediction – RFM signals, sigmoid mapping, engagement velocity.

use chrono::{Duration, Utc};

use crate::types::*;

/// Signal weights.
const COMPLAINT_WEIGHT: f64 = 35.0;
const BOUNCE_WEIGHT: f64 = 25.0;
const INACTIVITY_WEIGHT: f64 = 30.0;
const DECAY_WEIGHT: f64 = 20.0;

/// Sigmoid midpoint and steepness.
const SIGMOID_MIDPOINT: f64 = 50.0;
const SIGMOID_STEEPNESS: f64 = 15.0;

pub struct ChurnPredictionEngine {
    pool: sqlx::PgPool,
    redis: deadpool_redis::Pool,
}

impl ChurnPredictionEngine {
    pub fn new(pool: sqlx::PgPool, redis: deadpool_redis::Pool) -> Self {
        Self { pool, redis }
    }

/// Predict churn probability for a subscriber.
    pub async fn predict(&self, email: &str) -> anyhow::Result<ChurnPrediction> {
        let cache_key = format!("churn:{}", crate::send_time_optimizer::hash_email(email));

// Check cache (6h TTL)
        if let Ok(cached) = self.get_cached(&cache_key).await {
            return Ok(cached);
        }

        let signals = self.compute_signals(email).await?;
        let raw_score = compute_raw_score(&signals);
        let probability = sigmoid(raw_score);
        let risk_tier = RiskTier::from_score(probability);

        let velocity = self.engagement_velocity(email).await?;

        let prediction = ChurnPrediction {
            email: email.to_string(),
            probability,
            risk_tier,
            signals: signals.clone(),
            engagement_velocity: velocity,
            predicted_at: Utc::now(),
        };

        self.set_cached(&cache_key, &prediction, 21600).await.ok();
        Ok(prediction)
    }

/// Compute individual churn signals for a subscriber.
    async fn compute_signals(&self, email: &str) -> anyhow::Result<Vec<ChurnSignal>> {
        let mut signals = Vec::new();

// Complaint signal
        let (complaint_count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM events WHERE recipient = $1 AND event_type = 'complained' AND timestamp >= NOW() - INTERVAL '90 days'",
        )
        .bind(email)
        .fetch_one(&self.pool)
        .await
        .unwrap_or_else(|e| { tracing::warn!(error = %e, email = %mail_common::pii::redact_email(email), "complaint count query failed"); (0,) });
        let complaint_score = (complaint_count as f64).min(3.0) / 3.0;
        signals.push(ChurnSignal {
            name: "complaint".into(),
            value: complaint_score,
            weight: COMPLAINT_WEIGHT,
        });

// Bounce signal
        let (bounce_count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM events WHERE recipient = $1 AND event_type = 'bounced' AND timestamp >= NOW() - INTERVAL '90 days'",
        )
        .bind(email)
        .fetch_one(&self.pool)
        .await
        .unwrap_or_else(|e| { tracing::warn!(error = %e, email = %mail_common::pii::redact_email(email), "bounce count query failed"); (0,) });
        let bounce_score = (bounce_count as f64).min(5.0) / 5.0;
        signals.push(ChurnSignal {
            name: "bounce".into(),
            value: bounce_score,
            weight: BOUNCE_WEIGHT,
        });

// Inactivity signal
        let last_engagement: Option<(chrono::DateTime<Utc>,)> = sqlx::query_as(
            "SELECT MAX(timestamp) FROM events WHERE recipient = $1 AND event_type IN ('opened', 'clicked')",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        let days_inactive = last_engagement.map(|(t,)| (Utc::now() - t).num_days())
            .unwrap_or(365);
        let inactivity_score = (days_inactive as f64 / 90.0).min(1.0);
        signals.push(ChurnSignal {
            name: "inactivity".into(),
            value: inactivity_score,
            weight: INACTIVITY_WEIGHT,
        });

// Decay signal:how quickly engagement is declining
        let decay_score = self.compute_decay(email).await?;
        signals.push(ChurnSignal {
            name: "decay".into(),
            value: decay_score,
            weight: DECAY_WEIGHT,
        });

        Ok(signals)
    }

/// Compute engagement decay rate.
    async fn compute_decay(&self, email: &str) -> anyhow::Result<f64> {
        let now = Utc::now();
        let thirty_ago = now - Duration::days(30);
        let sixty_ago = now - Duration::days(60);

        let (recent_count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM events WHERE recipient = $1 AND event_type IN ('opened','clicked') AND timestamp >= $2",
        )
        .bind(email)
        .bind(thirty_ago)
        .fetch_one(&self.pool)
        .await
        .unwrap_or_else(|e| { tracing::warn!(error = %e, email = %mail_common::pii::redact_email(email), "compute_decay recent_count query failed"); (0,) });

        let (prev_count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM events WHERE recipient = $1 AND event_type IN ('opened','clicked') AND timestamp >= $2 AND timestamp < $3",
        )
        .bind(email)
        .bind(sixty_ago)
        .bind(thirty_ago)
        .fetch_one(&self.pool)
        .await
        .unwrap_or_else(|e| { tracing::warn!(error = %e, email = %mail_common::pii::redact_email(email), "compute_decay prev_count query failed"); (0,) });

        if prev_count == 0 {
            return Ok(if recent_count > 0 { 0.0 } else { 0.5 });
        }

        let decline = 1.0 - (recent_count as f64 / prev_count as f64);
        Ok(decline.max(0.0).min(1.0))
    }

/// Engagement velocity:(current − previous) / previous.
    async fn engagement_velocity(&self, email: &str) -> anyhow::Result<f64> {
        let now = Utc::now();
        let thirty_ago = now - Duration::days(30);
        let sixty_ago = now - Duration::days(60);

        let (current,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM events WHERE recipient = $1 AND event_type IN ('opened','clicked') AND timestamp >= $2",
        )
        .bind(email)
        .bind(thirty_ago)
        .fetch_one(&self.pool)
        .await
        .unwrap_or_else(|e| { tracing::warn!(error = %e, email = %mail_common::pii::redact_email(email), "engagement_velocity current query failed"); (0,) });

        let (previous,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM events WHERE recipient = $1 AND event_type IN ('opened','clicked') AND timestamp >= $2 AND timestamp < $3",
        )
        .bind(email)
        .bind(sixty_ago)
        .bind(thirty_ago)
        .fetch_one(&self.pool)
        .await
        .unwrap_or_else(|e| { tracing::warn!(error = %e, email = %mail_common::pii::redact_email(email), "engagement_velocity previous query failed"); (0,) });

        if previous == 0 {
            return Ok(if current > 0 { 1.0 } else { 0.0 });
        }

        Ok((current as f64 - previous as f64) / previous as f64)
    }

    async fn get_cached(&self, key: &str) -> anyhow::Result<ChurnPrediction> {
        let mut conn = self.redis.get().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        let val: String = redis::cmd("GET")
            .arg(key)
            .query_async(&mut *conn)
            .await?;
        Ok(serde_json::from_str(&val)?)
    }

    async fn set_cached(&self, key: &str, val: &ChurnPrediction, ttl: u64) -> anyhow::Result<()> {
        let mut conn = self.redis.get().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        redis::cmd("SET")
            .arg(key)
            .arg(serde_json::to_string(val)?)
            .arg("EX")
            .arg(ttl)
            .query_async::<()>(&mut *conn)
            .await?;
        Ok(())
    }
}

/// Compute raw churn score from weighted signals.
pub fn compute_raw_score(signals: &[ChurnSignal]) -> f64 {
    signals.iter().map(|s| s.value * s.weight).sum::<f64>()
        / signals.iter().map(|s| s.weight).sum::<f64>().max(1.0)
        * 100.0
}

/// Sigmoid:1 / (1 + exp(-(score - midpoint) / steepness)).
pub fn sigmoid(score: f64) -> f64 {
    1.0 / (1.0 + (-(score - SIGMOID_MIDPOINT) / SIGMOID_STEEPNESS).exp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sigmoid_at_midpoint() {
        let result = sigmoid(50.0);
        assert!((result - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_sigmoid_high_score() {
        let result = sigmoid(80.0);
        assert!(result > 0.85);
    }

    #[test]
    fn test_sigmoid_low_score() {
        let result = sigmoid(20.0);
        assert!(result < 0.15);
    }

    #[test]
    fn test_sigmoid_zero() {
        let result = sigmoid(0.0);
        assert!(result < 0.05);
    }

    #[test]
    fn test_sigmoid_100() {
        let result = sigmoid(100.0);
        assert!(result > 0.95);
    }

    #[test]
    fn test_raw_score_all_zero() {
        let signals = vec![
            ChurnSignal { name: "a".into(), value: 0.0, weight: 35.0 },
            ChurnSignal { name: "b".into(), value: 0.0, weight: 25.0 },
        ];
        let score = compute_raw_score(&signals);
        assert!((score - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_raw_score_all_max() {
        let signals = vec![
            ChurnSignal { name: "complaint".into(), value: 1.0, weight: 35.0 },
            ChurnSignal { name: "bounce".into(), value: 1.0, weight: 25.0 },
            ChurnSignal { name: "inactivity".into(), value: 1.0, weight: 30.0 },
            ChurnSignal { name: "decay".into(), value: 1.0, weight: 20.0 },
        ];
        let score = compute_raw_score(&signals);
        assert!((score - 100.0).abs() < 0.001);
    }

    #[test]
    fn test_raw_score_mixed() {
        let signals = vec![
            ChurnSignal { name: "complaint".into(), value: 0.5, weight: 35.0 },
            ChurnSignal { name: "bounce".into(), value: 0.0, weight: 25.0 },
            ChurnSignal { name: "inactivity".into(), value: 0.8, weight: 30.0 },
            ChurnSignal { name: "decay".into(), value: 0.3, weight: 20.0 },
        ];
        let score = compute_raw_score(&signals);
// (0.5*35 + 0*25 + 0.8*30 + 0.3*20) / 110 * 100
// = (17.5 + 0 + 24 + 6) / 110 * 100 = 43.18
        assert!((score - 43.18).abs() < 0.1);
    }

    #[test]
    fn test_risk_tier_from_score() {
        assert!(matches!(RiskTier::from_score(0.1), RiskTier::Low));
        assert!(matches!(RiskTier::from_score(0.35), RiskTier::Medium));
        assert!(matches!(RiskTier::from_score(0.55), RiskTier::High));
        assert!(matches!(RiskTier::from_score(0.85), RiskTier::Critical));
    }
}
