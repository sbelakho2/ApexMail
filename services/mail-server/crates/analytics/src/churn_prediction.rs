//! Churn prediction – RFM signals, sigmoid mapping, engagement velocity.

use anyhow::Context as _;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::email_hash::hash_for_analytics;
use crate::types::*;

/// Signal weights.
const COMPLAINT_WEIGHT: f64 = 35.0;
const BOUNCE_WEIGHT: f64 = 25.0;
const INACTIVITY_WEIGHT: f64 = 30.0;
const DECAY_WEIGHT: f64 = 20.0;

/// Sigmoid midpoint and steepness.
const SIGMOID_MIDPOINT: f64 = 50.0;
const SIGMOID_STEEPNESS: f64 = 15.0;

/// F10:the Redis-cached form of a churn prediction.
///
/// Redis is an external store, so the cache carries ONLY the salted
/// identifier plus the prediction payload — never the raw email (which the
/// caller already has and gets back on the returned [`ChurnPrediction`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedChurnPrediction {
    email_hash: String,
    tenant_id: String,
    probability: f64,
    risk_tier: RiskTier,
    signals: Vec<ChurnSignal>,
    engagement_velocity: f64,
    predicted_at: chrono::DateTime<Utc>,
}

/// F10:salted, tenant-scoped cache key — the crate's configured-key hash
/// (`ANALYTICS_STO_HMAC_KEY`, see [`crate::email_hash`]) instead of the old
/// unsalted SHA-256 (rainbow-tableable), with no raw email in the key.
fn churn_cache_key(tenant_id: &str, email: &str) -> String {
    format!("churn:{}:{}", tenant_id, hash_for_analytics(email))
}

pub struct ChurnPredictionEngine {
    pool: sqlx::PgPool,
    redis: deadpool_redis::Pool,
}

impl ChurnPredictionEngine {
    pub fn new(pool: sqlx::PgPool, redis: deadpool_redis::Pool) -> Self {
        Self { pool, redis }
    }

    /// Predict churn probability for a subscriber.
    /// `tenant_id` is required to scope all queries to the correct tenant,
    /// preventing cross-tenant data leakage.
    pub async fn predict(&self, tenant_id: &str, email: &str) -> anyhow::Result<ChurnPrediction> {
        // F10:salted hash + tenant scope prevent both cache poisoning and
        // rainbow-table recovery of the raw email from the key.
        let cache_key = churn_cache_key(tenant_id, email);

        // Check cache (6h TTL). The cached form carries no raw email (F10);
        // the caller-supplied address is re-attached on return.
        if let Ok(cached) = self.get_cached(&cache_key).await {
            return Ok(ChurnPrediction {
                email: email.to_string(),
                tenant_id: cached.tenant_id,
                probability: cached.probability,
                risk_tier: cached.risk_tier,
                signals: cached.signals,
                engagement_velocity: cached.engagement_velocity,
                predicted_at: cached.predicted_at,
            });
        }

        let signals = self.compute_signals(tenant_id, email).await?;
        let raw_score = compute_raw_score(&signals);
        let probability = sigmoid(raw_score);
        let risk_tier = RiskTier::from_score(probability);

        let velocity = self.engagement_velocity(tenant_id, email).await?;

        let prediction = ChurnPrediction {
            email: email.to_string(),
            tenant_id: tenant_id.to_string(),
            probability,
            risk_tier,
            signals: signals.clone(),
            engagement_velocity: velocity,
            predicted_at: Utc::now(),
        };

        self.set_cached(&cache_key, &prediction, 21600).await.ok();
        Ok(prediction)
    }

    /// Compute individual churn signals for a subscriber, scoped to `tenant_id`.
    async fn compute_signals(
        &self,
        tenant_id: &str,
        email: &str,
    ) -> anyhow::Result<Vec<ChurnSignal>> {
        let mut signals = Vec::new();

        // Complaint signal — scoped to tenant
        let (complaint_count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM events WHERE tenant_id = $1 AND recipient = $2 AND event_type = 'complained' AND timestamp >= NOW() - INTERVAL '90 days'",
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_one(&self.pool)
        .await
        .with_context(|| churn_query_context("complaint count", email))?;
        let complaint_score = (complaint_count as f64).min(3.0) / 3.0;
        signals.push(ChurnSignal {
            name: "complaint".into(),
            value: complaint_score,
            weight: COMPLAINT_WEIGHT,
        });

        // Bounce signal — scoped to tenant
        let (bounce_count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM events WHERE tenant_id = $1 AND recipient = $2 AND event_type = 'bounced' AND timestamp >= NOW() - INTERVAL '90 days'",
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_one(&self.pool)
        .await
        .with_context(|| churn_query_context("bounce count", email))?;
        let bounce_score = (bounce_count as f64).min(5.0) / 5.0;
        signals.push(ChurnSignal {
            name: "bounce".into(),
            value: bounce_score,
            weight: BOUNCE_WEIGHT,
        });

        // Inactivity signal — scoped to tenant
        let last_engagement: Option<(chrono::DateTime<Utc>,)> = sqlx::query_as(
            "SELECT MAX(timestamp) FROM events WHERE tenant_id = $1 AND recipient = $2 AND event_type IN ('opened', 'clicked')",
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        let days_inactive = last_engagement
            .map(|(t,)| (Utc::now() - t).num_days())
            .unwrap_or(365);
        let inactivity_score = (days_inactive as f64 / 90.0).min(1.0);
        signals.push(ChurnSignal {
            name: "inactivity".into(),
            value: inactivity_score,
            weight: INACTIVITY_WEIGHT,
        });

        // Decay signal — scoped to tenant
        let decay_score = self.compute_decay(tenant_id, email).await?;
        signals.push(ChurnSignal {
            name: "decay".into(),
            value: decay_score,
            weight: DECAY_WEIGHT,
        });

        Ok(signals)
    }

    /// Compute engagement decay rate, scoped to `tenant_id`.
    async fn compute_decay(&self, tenant_id: &str, email: &str) -> anyhow::Result<f64> {
        let now = Utc::now();
        let thirty_ago = now - Duration::days(30);
        let sixty_ago = now - Duration::days(60);

        let (recent_count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM events WHERE tenant_id = $1 AND recipient = $2 AND event_type IN ('opened','clicked') AND timestamp >= $3",
        )
        .bind(tenant_id)
        .bind(email)
        .bind(thirty_ago)
        .fetch_one(&self.pool)
        .await
        .with_context(|| churn_query_context("compute_decay recent count", email))?;

        let (prev_count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM events WHERE tenant_id = $1 AND recipient = $2 AND event_type IN ('opened','clicked') AND timestamp >= $3 AND timestamp < $4",
        )
        .bind(tenant_id)
        .bind(email)
        .bind(sixty_ago)
        .bind(thirty_ago)
        .fetch_one(&self.pool)
        .await
        .with_context(|| churn_query_context("compute_decay previous count", email))?;

        if prev_count == 0 {
            return Ok(if recent_count > 0 { 0.0 } else { 0.5 });
        }

        let decline = 1.0 - (recent_count as f64 / prev_count as f64);
        Ok(decline.clamp(0.0, 1.0))
    }

    /// Engagement velocity:(current − previous) / previous, scoped to `tenant_id`.
    async fn engagement_velocity(&self, tenant_id: &str, email: &str) -> anyhow::Result<f64> {
        let now = Utc::now();
        let thirty_ago = now - Duration::days(30);
        let sixty_ago = now - Duration::days(60);

        let (current,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM events WHERE tenant_id = $1 AND recipient = $2 AND event_type IN ('opened','clicked') AND timestamp >= $3",
        )
        .bind(tenant_id)
        .bind(email)
        .bind(thirty_ago)
        .fetch_one(&self.pool)
        .await
        .with_context(|| churn_query_context("engagement_velocity current count", email))?;

        let (previous,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM events WHERE tenant_id = $1 AND recipient = $2 AND event_type IN ('opened','clicked') AND timestamp >= $3 AND timestamp < $4",
        )
        .bind(tenant_id)
        .bind(email)
        .bind(sixty_ago)
        .bind(thirty_ago)
        .fetch_one(&self.pool)
        .await
        .with_context(|| churn_query_context("engagement_velocity previous count", email))?;

        if previous == 0 {
            return Ok(if current > 0 { 1.0 } else { 0.0 });
        }

        Ok((current as f64 - previous as f64) / previous as f64)
    }

    /// F10:fetches the hashed-identifier cache form (no raw email).
    async fn get_cached(&self, key: &str) -> anyhow::Result<CachedChurnPrediction> {
        let mut conn = self.redis.get().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        let val: String = redis::cmd("GET").arg(key).query_async(&mut *conn).await?;
        Ok(serde_json::from_str(&val)?)
    }

    /// F10:stores the hashed-identifier cache form (no raw email).
    async fn set_cached(&self, key: &str, val: &ChurnPrediction, ttl: u64) -> anyhow::Result<()> {
        let mut conn = self.redis.get().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        let cached = CachedChurnPrediction {
            email_hash: hash_for_analytics(&val.email),
            tenant_id: val.tenant_id.clone(),
            probability: val.probability,
            risk_tier: val.risk_tier,
            signals: val.signals.clone(),
            engagement_velocity: val.engagement_velocity,
            predicted_at: val.predicted_at,
        };
        redis::cmd("SET")
            .arg(key)
            .arg(serde_json::to_string(&cached)?)
            .arg("EX")
            .arg(ttl)
            .query_async::<()>(&mut *conn)
            .await?;
        Ok(())
    }
}

fn churn_query_context(operation: &str, email: &str) -> String {
    format!(
        "{operation} query failed for {}",
        mail_common::pii::redact_email(email)
    )
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
            ChurnSignal {
                name: "a".into(),
                value: 0.0,
                weight: 35.0,
            },
            ChurnSignal {
                name: "b".into(),
                value: 0.0,
                weight: 25.0,
            },
        ];
        let score = compute_raw_score(&signals);
        assert!((score - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_raw_score_all_max() {
        let signals = vec![
            ChurnSignal {
                name: "complaint".into(),
                value: 1.0,
                weight: 35.0,
            },
            ChurnSignal {
                name: "bounce".into(),
                value: 1.0,
                weight: 25.0,
            },
            ChurnSignal {
                name: "inactivity".into(),
                value: 1.0,
                weight: 30.0,
            },
            ChurnSignal {
                name: "decay".into(),
                value: 1.0,
                weight: 20.0,
            },
        ];
        let score = compute_raw_score(&signals);
        assert!((score - 100.0).abs() < 0.001);
    }

    #[test]
    fn test_raw_score_mixed() {
        let signals = vec![
            ChurnSignal {
                name: "complaint".into(),
                value: 0.5,
                weight: 35.0,
            },
            ChurnSignal {
                name: "bounce".into(),
                value: 0.0,
                weight: 25.0,
            },
            ChurnSignal {
                name: "inactivity".into(),
                value: 0.8,
                weight: 30.0,
            },
            ChurnSignal {
                name: "decay".into(),
                value: 0.3,
                weight: 20.0,
            },
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

    // ── F10:cache key + hashed-only cache payload ───────────────────────

    #[test]
    fn test_cache_key_contains_no_raw_email_and_is_tenant_scoped() {
        let key = churn_cache_key("tenant_a", "carol@example.com");
        assert!(!key.contains("carol"), "raw email leaked into key: {key}");
        assert!(key.starts_with("churn:tenant_a:"));
        // Deterministic for the same inputs, different across tenants.
        assert_eq!(key, churn_cache_key("tenant_a", "carol@example.com"));
        assert_ne!(key, churn_cache_key("tenant_b", "carol@example.com"));
    }

    #[test]
    fn test_cache_key_is_salted_not_bare_sha256() {
        // The old key hashed with a bare (unsalted) SHA-256; the configured
        // HMAC key must produce a different digest than the bare hash.
        let bare = crate::email_hash::hash_email("carol@example.com", "");
        let key = churn_cache_key("tenant_a", "carol@example.com");
        assert!(!key.contains(&bare), "cache key must not use the bare hash");
    }

    #[test]
    fn test_cached_payload_roundtrips_without_raw_email() {
        let cached = CachedChurnPrediction {
            email_hash: hash_for_analytics("carol@example.com"),
            tenant_id: "tenant_a".into(),
            probability: 0.42,
            risk_tier: RiskTier::Medium,
            signals: vec![ChurnSignal {
                name: "bounce".into(),
                value: 0.5,
                weight: 25.0,
            }],
            engagement_velocity: -0.25,
            predicted_at: Utc::now(),
        };
        let json = serde_json::to_string(&cached).unwrap();
        assert!(
            !json.contains("carol@example.com"),
            "raw email must not be cached: {json}"
        );
        assert!(!json.contains("\"email\":"), "no raw-email field: {json}");

        let back: CachedChurnPrediction = serde_json::from_str(&json).unwrap();
        assert_eq!(back.probability, 0.42);
        assert_eq!(back.signals.len(), 1);
        assert!(matches!(back.risk_tier, RiskTier::Medium));
    }
}
