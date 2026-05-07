//! Send-time optimizer – Bayesian smoothing, hour/day distributions, optimal windows.
//!
//! # Security (O-11.5)
//! Email hashing uses HMAC-SHA256 with a configurable salt key to prevent
//! rainbow-table attacks on cache keys.

use chrono::Utc;

use crate::types::*;

pub use crate::email_hash::hash_email;

/// Global prior probabilities for hours (24) – peak at 10 AM.
const HOUR_PRIORS: [f64; 24] = [
    0.011, 0.0055, 0.0033, 0.0033, 0.0055, 0.011, 0.022, 0.0439, 0.0768, 0.0988, 0.1207, 0.1098,
    0.0878, 0.0768, 0.0659, 0.0549, 0.0439, 0.0384, 0.0329, 0.0274, 0.022, 0.0165, 0.0132, 0.0088,
];

/// Global prior probabilities for days (Mon=0..Sun=6) – peak on Tuesday.
const DAY_PRIORS: [f64; 7] = [0.16, 0.18, 0.17, 0.16, 0.14, 0.10, 0.09];

/// Cold-start default:Tuesday 10:00 AM UTC.
const COLD_START_HOUR: u32 = 10;
const COLD_START_DAY: u32 = 2; // Tuesday (0=Mon)

pub struct SendTimeOptimizer {
    pool: sqlx::PgPool,
    redis: deadpool_redis::Pool,
    /// HMAC-SHA256 key for salted email hashing (O-11.5).
    /// Empty string disables HMAC (falls back to bare SHA-256).
    hmac_key: String,
}

impl SendTimeOptimizer {
    pub fn new(pool: sqlx::PgPool, redis: deadpool_redis::Pool) -> Self {
        Self {
            pool,
            redis,
            hmac_key: String::new(),
        }
    }

    /// Create a new optimizer with HMAC-salted email hashing (O-11.5).
    pub fn with_hmac_key(
        pool: sqlx::PgPool,
        redis: deadpool_redis::Pool,
        hmac_key: String,
    ) -> Self {
        Self {
            pool,
            redis,
            hmac_key,
        }
    }

    /// Get optimal send window for a recipient, with caching.
    pub async fn get_optimal_window(&self, email: &str) -> anyhow::Result<BulkOptimizationResult> {
        let email_hash = hash_email(email, &self.hmac_key);
        let cache_key = format!("sto:{email_hash}");

        // Check Redis cache
        if let Ok(cached) = self.get_cached(&cache_key).await {
            return Ok(cached);
        }

        let profile = self.build_recipient_profile(email).await?;
        let windows = compute_optimal_windows(&profile);

        let result = BulkOptimizationResult {
            email_hash: email_hash.clone(),
            windows: windows.clone(),
            confidence: profile.total_events as f64 / (profile.total_events as f64 + 100.0),
            profile_age_days: profile.profile_age_days,
        };

        // Cache for 24h
        self.set_cached(&cache_key, &result, 86400).await.ok();

        Ok(result)
    }

    /// Build recipient profile from engagement data.
    async fn build_recipient_profile(&self, email: &str) -> anyhow::Result<RecipientProfile> {
        let rows = sqlx::query_as::<_, (i32, i32, i64)>(
            "SELECT EXTRACT(HOUR FROM timestamp)::int as hour, \
             EXTRACT(DOW FROM timestamp)::int as dow, \
             COUNT(*) as cnt \
             FROM events \
             WHERE recipient = $1 AND event_type IN ('opened', 'clicked') \
             GROUP BY hour, dow",
        )
        .bind(email)
        .fetch_all(&self.pool)
        .await?;

        let mut hour_dist = HourDistribution {
            hours: vec![0.0; 24],
        };
        let mut day_dist = DayDistribution { days: vec![0.0; 7] };
        let mut total: i64 = 0;

        for (hour, dow, cnt) in &rows {
            let h = (*hour as usize).min(23);
            let d = (*dow as usize).min(6);
            hour_dist.hours[h] += *cnt as f64;
            day_dist.days[d] += *cnt as f64;
            total += cnt;
        }

        // Normalize to probabilities
        if total > 0 {
            for h in &mut hour_dist.hours {
                *h /= total as f64;
            }
            for d in &mut day_dist.days {
                *d /= total as f64;
            }
        }

        // Get profile age
        let first_event: Option<(chrono::DateTime<Utc>,)> =
            sqlx::query_as("SELECT MIN(timestamp) FROM events WHERE recipient = $1")
                .bind(email)
                .fetch_optional(&self.pool)
                .await?;

        let age_days = first_event
            .map(|(t,)| (Utc::now() - t).num_days() as u32)
            .unwrap_or(0);

        Ok(RecipientProfile {
            hour_distribution: hour_dist,
            day_distribution: day_dist,
            total_events: total,
            profile_age_days: age_days,
        })
    }

    async fn get_cached(&self, key: &str) -> anyhow::Result<BulkOptimizationResult> {
        let mut conn = self.redis.get().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        let val: String = redis::cmd("GET").arg(key).query_async(&mut *conn).await?;
        Ok(serde_json::from_str(&val)?)
    }

    async fn set_cached(
        &self,
        key: &str,
        val: &BulkOptimizationResult,
        ttl_secs: u64,
    ) -> anyhow::Result<()> {
        let mut conn = self.redis.get().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        let json = serde_json::to_string(val)?;
        redis::cmd("SET")
            .arg(key)
            .arg(&json)
            .arg("EX")
            .arg(ttl_secs)
            .query_async::<()>(&mut *conn)
            .await?;
        Ok(())
    }
}

/// Bayesian smoothing:posterior = (observed + α × prior × N) / (total + α × N).
pub fn bayesian_smooth(observed: f64, total: f64, prior: f64, alpha: f64) -> f64 {
    let n = total + alpha;
    if n == 0.0 {
        return prior;
    }
    (observed + alpha * prior) / n
}

/// Dynamic alpha:decreases as we get more data.
pub fn dynamic_alpha(total: f64) -> f64 {
    (10.0 - (total + 1.0).log10() * 3.0).max(1.0)
}

/// Compute top-3 optimal send windows from a recipient profile.
pub fn compute_optimal_windows(profile: &RecipientProfile) -> Vec<OptimalSendWindow> {
    let alpha = dynamic_alpha(profile.total_events as f64);

    // Cold start:return default Tuesday 10 AM
    if profile.total_events < 5 {
        return vec![OptimalSendWindow {
            hour: COLD_START_HOUR,
            day: COLD_START_DAY,
            score: HOUR_PRIORS[COLD_START_HOUR as usize] * DAY_PRIORS[COLD_START_DAY as usize],
            confidence: 0.0,
        }];
    }

    // Compute smoothed scores for each (hour, day) pair
    let mut windows: Vec<OptimalSendWindow> = Vec::with_capacity(24 * 7);

    for hour in 0..24_usize {
        let hour_posterior = bayesian_smooth(
            profile.hour_distribution.hours[hour],
            profile.total_events as f64,
            HOUR_PRIORS[hour],
            alpha,
        );

        for day in 0..7_usize {
            let day_posterior = bayesian_smooth(
                profile.day_distribution.days[day],
                profile.total_events as f64,
                DAY_PRIORS[day],
                alpha,
            );

            let score = hour_posterior * day_posterior;
            let confidence = profile.total_events as f64 / (profile.total_events as f64 + 100.0);

            windows.push(OptimalSendWindow {
                hour: hour as u32,
                day: day as u32,
                score,
                confidence,
            });
        }
    }

    // Sort by score descending, take top 3
    windows.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    windows.truncate(3);
    windows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bayesian_smooth_with_data() {
        let result = bayesian_smooth(0.1, 100.0, 0.05, 5.0);
        // (0.1 + 5 * 0.05) / (100 + 5) = (0.1 + 0.25) / 105 ≈ 0.00333
        assert!((result - 0.00333).abs() < 0.001);
    }

    #[test]
    fn test_bayesian_smooth_no_data() {
        let result = bayesian_smooth(0.0, 0.0, 0.05, 0.0);
        assert_eq!(result, 0.05);
    }

    #[test]
    fn test_dynamic_alpha_small_total() {
        let alpha = dynamic_alpha(0.0);
        // max(1, 10 - log10(1) * 3) = max(1, 10 - 0) = 10
        assert!((alpha - 10.0).abs() < 0.01);
    }

    #[test]
    fn test_dynamic_alpha_large_total() {
        let alpha = dynamic_alpha(10000.0);
        // max(1, 10 - log10(10001) * 3) = max(1, 10 - 12) = 1
        assert!((alpha - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_cold_start_produces_default() {
        let profile = RecipientProfile {
            hour_distribution: HourDistribution {
                hours: vec![0.0; 24],
            },
            day_distribution: DayDistribution { days: vec![0.0; 7] },
            total_events: 0,
            profile_age_days: 0,
        };
        let windows = compute_optimal_windows(&profile);
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].hour, 10); // Tuesday 10 AM
        assert_eq!(windows[0].day, 2);
    }

    #[test]
    fn test_optimal_windows_with_data() {
        let mut hours = vec![0.0; 24];
        hours[14] = 0.3; // Peak at 2 PM
        hours[10] = 0.2;
        let mut days = vec![0.0; 7];
        days[1] = 0.25; // Tuesday
        days[3] = 0.2; // Thursday

        let profile = RecipientProfile {
            hour_distribution: HourDistribution { hours },
            day_distribution: DayDistribution { days },
            total_events: 50,
            profile_age_days: 30,
        };

        let windows = compute_optimal_windows(&profile);
        assert!(windows.len() <= 3);
        // Should return top windows by score
        assert!(windows[0].score >= windows[windows.len() - 1].score);
    }

    #[test]
    fn test_hour_priors_sum_approximately_one() {
        let sum: f64 = HOUR_PRIORS.iter().sum();
        assert!((sum - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_day_priors_sum_to_one() {
        let sum: f64 = DAY_PRIORS.iter().sum();
        assert!((sum - 1.0).abs() < 0.001);
    }
}
